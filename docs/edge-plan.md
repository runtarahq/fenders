# The run channel off the database, and the edge tier: the plan

Status: E1 to E10 decided on 19 November 2026, as recommended (E7 for
apps); E11 is proposed. Nothing here is built. It follows
[gateway-accounting.md](gateway-accounting.md), which took the gateway's
accounting off the request path. [STATUS.md](STATUS.md) says what is true
today.

## Why

Gateway requests no longer take the mutation lock. Three things still bound
the control plane, and none of them is helped by adding nodes:

| What | Where | Cost today |
|---|---|---|
| Every run-channel call reads the database | `run_channel_authorize`, and per route `run_channel_http`, `run_channel_egress`, `websocket_sender`, `run_channel_output` | An HTTP request is three reads: the shim's `http/next` (authorize, then its queue) and its `http/response` (authorize). At 1,500 requests a second that is 4,500 reads a second through a pool of 16 connections. |
| Every outbound grant renewal is a locked transaction | `egress_budget`, asked by the shim every 3 seconds (`RENEW` in `fenders-shim/src/budget.rs`), a grant lasting 10 | One locked transaction a second for every 3 running executions with a connection, whether they send anything or not. 750 such executions take the whole lock rate stage 0 measured (about 250 a second). |
| One process carries all HTTP-app traffic | The gateway and the run channel meet in one process's memory (`http_exchange.rs`) | Every byte crosses it twice. 16 MiB responses went at 4 a second on the test machine, before and after the accounting change. |

The first two make the database the bound again as the fleet grows; the
third is the bound on traffic. This plan removes the first two and makes the
third a matter of how many edge processes are run.

## Decisions

| # | Decision | Decided |
|---|---|---|
| E1 | How long the run channel may believe what a credential names | 2 seconds, as a gate is believed, and at once after a change this process makes. A node disabled by the operator is refused at the next call to the process the operator spoke to, and within 2 seconds at the others. |
| E2 | Whether a grant renewal is written to the database | No. A renewal (an ask for no more bytes) is answered from memory by the process that serves the run's channel; only a grant of more bytes is a transaction. The database's `expires` is written by the flush, for diagnostics; nothing enforces it. |
| E3 | How a renewal's revision survives a restart | The launcher refuses a deadline unless its revision is higher than the last (`network_budget.inc`). The process that first serves a run's renewals reserves a range of revisions for it in one transaction (2^20 of them: 36 days of renewals every 3 seconds, past the 24 hours a run may live), and issues them from memory. A process that takes the run over reserves the next range. |
| E4 | Whether more bytes for a run come out of the gateway's lease | Not in this plan. A grant of more bytes stays a transaction: they grow by doubling to 16 MiB, so their rate follows bytes sent, not executions. Measure before coupling outbound settlement to leases. |
| E5 | What an edge is | The same binary in a role: `--role control` (management API, scheduler, node peer), `--role edge` (gateway, run channel, flusher), `--role all` (today's single process, and the default). Edges share the control plane's PostgreSQL; they do not call it. |
| E6 | What an edge holds of the control plane's secrets | The database credential and the run channel's derived key, **not** the master encryption key. Stage C1 verifies that nothing an edge serves needs a secret's value; what does is moved to the control process, not given the key. Whether an edge gets a database role of its own, limited to the tables it uses, is open. |
| E7 | What an edge owns | **Apps** (decided). An app's requests, its executions' run channel, its WebSocket connections and the count of its requests in flight are one edge's: they meet in memory and cannot be split. A workspace's apps may be on different edges, so a workspace's limits are shared between them as leases (E10). An app is as large as one edge can serve. |
| E10 | How a workspace's limits are kept across edges | As its transfer allowance already is: each edge holds a share of the workspace's requests in flight, of its requests a minute and of its WebSocket connections, taken in a transaction when it has none and brought to what it used by the flush. Requests in flight and connections stay exact: shares never add up to more than the limit. The rate may be exceeded by what one rebalancing moves, within a minute. |
| E11 | What an edge does while the database cannot be reached | Proposed, to confirm: it goes on serving what it already knows, for up to 10 minutes (an operator's setting), and refuses only what needs the database. Nothing passes that is not already leased or granted, so no allowance is exceeded. Section [D](#d-serving-through-a-database-outage). |
| E8 | How a request reaches its workspace's edge | Any edge takes any request, on the gateway and on the run channel, and forwards it over mutual TLS to the owner. One name for all edges, behind a plain TCP load balancer, on each side. An edge that is lost moves its workspaces to others, and their shims' next calls reach the new owner with no new launch. |
| E9 | How edges see a change made by another process | `LISTEN/NOTIFY` on the changes that decide whether an app serves (`app_http`, `tenants`, executions' state and nodes' `disabled`), with the 2-second freshness behind it, as the gateway plan first had it. |

An execution that belongs to no app (a deployment from before apps) is
owned as an app of its own, keyed by the execution.

E8 had a cheaper alternative: name the owner's own address in each launch
spec, with no forwarding on the run-channel side. It saves a hop for shims,
and costs a new launch of every run of every app an edge that is lost
owned. Forwarding was chosen: losing an edge should cost its in-flight
requests and WebSocket connections, as losing the control plane does today,
not every run of a thousand apps.

## A. What a credential names, believed for two seconds

A **launch** (execution and generation) is read once and kept: its node, the
node's boot and whether it is disabled, whether the execution is reserved and
running, whether it is under the outbound limit, its workspace and project,
and, for an HTTP run, the key of the queue it takes requests from. Every
route of the run channel answers from it.

- Kept per process, keyed by launch, for 2 seconds, and dropped when the
  epoch moves ([E1](#decisions)): the epoch the gates use, so a change this
  process makes under the lock is seen at the next call.
- The credential's own check (it decrypts to the claim of this launch) is
  memory already and stays as it is.
- What reads the database for its own sake still does: an output batch is
  stored in a transaction that checks its launch again, and a grant of more
  bytes is a transaction that checks everything again. Only what was a read
  to decide whether to answer at all is cached.
- What a stale launch costs: an execution that was stopped or moved to a
  new generation may take a request up to 2 seconds after; it is stopping,
  and the request is answered 502 or not at all. That is the same window a
  gate has.

Per HTTP request: three reads become none.

## B. Grant renewals in memory

The process that serves a run's channel keeps, for each run under the
outbound limit, what its row in `execution_egress_budgets` says and what it
has issued since: revision, ceiling, deadline, the last request id and the
answer to it.

- An ask for no bytes renews from memory: if the launch (stage A) is
  current, its node fresh and not disabled, its workspace active, and the
  month the same, the answer is the next revision of the reserved range
  ([E3](#decisions)) with a deadline 10 seconds on. The same request id
  gets the same answer, as now.
- An ask for bytes is the transaction it is now, at the revision memory is
  at. It writes the revision, so that the database is never behind a
  ceiling.
- The flush writes each run's revision and deadline once a second, for
  `egress_budget_status` and diagnostics.
- A process that serves a run it has no state of (it restarted, or took the
  app over) reads the row and reserves a range above both the row's
  revision and the shim's `expected_revision`.
- Settlement does not change: it is the node's final report against the
  row's base and ceiling, which grants of bytes still write.

What changes for a run: a grant still lapses within 10 seconds of the
process that renews it going away. A suspended workspace's runs stop being
renewed within 2 seconds of the suspension, plus the 10 a grant lasts, where
it was the 10 alone.

Per running execution with a connection: one locked transaction every 3
seconds becomes none while it sends nothing new.

## C. The edge tier

### What breaks with two processes, and what this does about it

| Today, in one process | With several edges |
|---|---|
| The gateway offers a request in memory, and the app's shim takes it from the same memory | The app's edge holds both; other edges forward ([E8](#decisions)) |
| A workspace's rate, requests in flight and WebSocket connections are counted in memory | Each edge counts against its share of them ([E10](#decisions)) |
| What an app has in flight decides whether it is idle | Unchanged: the app's edge is the one place that knows |
| A lease is a session's | Unchanged: an edge's process is a session |
| A gate is kept true by an epoch | And by `NOTIFY` from other processes ([E9](#decisions)) |
| The WebSocket sweep finishes every open connection this process does not hold | Scoped to connections of sessions that are gone: each row names its session |
| The run channel's endpoint is one address in every launch spec | One name for all edges, as now |
| Uploaded components and the encryption key are on the control plane's disk | Edges need neither ([E6](#decisions)) |

### What is new

- **Edges are registered, as nodes are.** `POST /v1/edges` with a name, the
  pin of its certificate and its internal address, by the operator; an edge
  that is not registered is not forwarded to. `GET`, `PATCH` (draining) and
  `DELETE` as for nodes.
- **An edge's process is a session**, as a gateway is: it touches its row,
  and one not touched for 15 seconds is gone.
- **Ownership is a row**: `app_edges(app_id, edge_id, revision)`. The
  scheduler gives an app with the HTTP trigger or a running execution to the
  live edge with the least traffic, and moves the apps of an edge that is
  gone or draining. Moving one closes its gate on the old owner (if it is
  alive) before the new one admits; WebSocket connections and requests in
  flight on the old owner are lost.
- **Shares of a workspace's limits** ([E10](#decisions)):
  `edge_limit_shares(session_id, tenant_id, concurrent, per_minute,
  connections)`, counted against the workspace's limits wherever they are
  checked, and settled as a lease is when its session is gone.
- **Forwarding**: an edge that does not own a request's app passes it, head
  and streaming body, to the owner's internal address over mutual TLS, and
  the answer back. On the gateway the app is found from the host name
  (cached as gates are); on the run channel from the launch (stage A).
  A request is forwarded once: an owner that does not own it any more
  answers 503, never forwards again.

### What an operator runs

```text
internet ─▶ TCP LB :443 ─┐                    ┌─ edge-1 ─┐
                          ├─▶ any edge :9092 ──┤  edge-2  ├─ forward (mTLS) to the owner
nodes' shims ─▶ TCP LB ───┘    any edge :9093  └─ edge-3 ─┘
                                     │
control (API, scheduler, node peer) ─┴─ PostgreSQL
```

## D. Serving through a database outage

After stages A and B an edge needs PostgreSQL only to learn something new
or to write something down. Today it stops serving within 2 seconds of
losing it, when what it knows of a host name is too old to believe. This
section makes an outage cost what needs the database, not everything.

What goes on, from memory, while the database is unreachable:

| Goes on | On what |
|---|---|
| Requests to apps that serve | Gates believed past their 2 seconds, since nothing can change them while nothing can be written; requests in flight and rates counted as ever |
| Their bytes | The leases' available bytes, until they run out. No lease is extended |
| Shims taking requests and answering them | Launches believed past their 2 seconds (stage A) |
| Outbound grant renewals | From memory (stage B), on what was last known of the run and its node. The ceiling does not move |
| WebSocket connections and their messages | Messages out of the lease, as requests' bytes |

What is refused, answered 503, until it is back:

- requests to an app that does not serve, or to a host name not known
  before the outage (the cold path);
- a request of a project whose lease has run dry;
- grants of more outbound bytes: a run that needs more is held at its
  ceiling and ended as when its allowance is used up;
- run output batches. What the shim does with a refused batch (a 5xx is
  retried, a 4xx ends capture) is checked in this stage; output is not
  buffered in the edge.

What waits in memory, and is written when it is back: usage (never
dropped), request records (bounded and dropped as now), app activity and
admission audit rows.

How long: up to 10 minutes from the last successful read or flush, then
the edge stops believing what it knows and serves nothing new (E11). An
outage cannot change what an edge knows, but the world can: a node can die
and its runs with it, which the edge learns only from the database. Ten
minutes bounds how long requests go to an execution that may be gone,
answered 503 never having run.

Two things this needs that are easy to get wrong:

- **Readiness is not the database.** `/readyz` now answers 503 when the
  database is unreachable, and an L4 balancer that checks it would take
  every edge out at once. An edge in role `edge` answers ready while it
  serves anything; whether it reaches the database is in
  `GET /v1/control-plane/status` and the log. The control role keeps
  today's meaning.
- **Sessions are not dead because the database was.** No edge can touch
  its session row during an outage, so when the database returns every
  session looks 15 seconds stale, and the scheduler would charge every
  lease whole as a dead session's, on top of what the edges then flush. The
  scheduler does not expire a session until it has itself been reaching the
  database for longer than a session may go untouched: the first pass after
  an outage gives every edge 15 seconds to flush.

Status: `database: {reachable, since}` and `gateway.stale_since` in the
status route, and a log line when an edge starts and stops serving from
memory.

This does not depend on edges: in role `all` it keeps a single control
plane's running apps serving through a database restart.

## Stages

Each lands on its own with the suite green, and is worth having without the
next.

### A. The run channel's reads cached

- What a launch is, cached and dropped with the epoch; every route reads
  it.
- The status route counts run-channel calls and how many read the database.
- Tests: a stopped execution, a new generation and a disabled node are each
  refused at the next call; a call within 2 seconds makes no read.

### B. Renewals in memory

- Migration: `execution_egress_budgets.revision_reserved`.
- Renewal from memory; grants of bytes at memory's revision; the flush
  writes revisions and deadlines.
- Taking over a run: from the row and the shim's revision.
- Tests: renewals advance the revision with no transaction; a restarted
  store renews above anything issued; the launcher's rule held across a
  restart (`verify_egress_limit_live.sh` with the control plane restarted
  mid-run); suspension stops renewal.

### C1. Roles

- `--role control | edge | all`. An edge runs the gateway, the run channel
  and the flusher, and none of the scheduler, the API or the node peer.
- One edge beside one control process, on one host, then on two:
  everything the live scripts check, with the gateway and run channel
  served by the edge. Verify E6 here.

### C2. Serving through a database outage

- Gates, launches and renewals believed past their freshness while the
  database cannot be reached, for up to the configured bound.
- `/readyz` of an edge means it serves; the status route says whether it
  reaches the database.
- The scheduler's grace for sessions after an outage.
- Tests: the database's connections refused (the pool pointed at a closed
  port) for 30 seconds: warm requests are answered, cold ones refused, no
  lease is extended, nothing passes beyond the lease; when it is back, usage
  is written once and no lease is charged as a dead session's; past the
  bound, nothing is served from memory.
- Live: `docker pause` of the local PostgreSQL under `measure_gateway.sh`,
  for 60 seconds.

### C3. Cross-process changes

- `NOTIFY` on what decides whether an app serves; an edge listens and moves
  its epoch.
- WebSocket rows name their session; the sweep finishes only those of
  sessions that are gone.

### C4. Workspace limits as shares

- `edge_limit_shares`; requests in flight, requests a minute and WebSocket
  connections counted against this process's share, which is taken and
  rebalanced as a transfer lease is. With one process it holds the whole
  limit, and nothing changes for a client.
- Tests: two stores sharing a database, each an edge with a share: the
  workspace's requests in flight never exceed its limit between them; a
  share an edge no longer uses moves to the one that does; a dead session's
  share is freed.

### C5. Edges registered, apps owned

- `edges` and `app_edges`; the operator's routes; the contract.
- The scheduler gives and moves apps.
- An edge admits only what it owns; with one edge it owns everything.

### C6. Forwarding

- Gateway and run channel forward to the owner; internal mTLS listener.
- Tests: two stores in one test, each an edge, sharing a database: a
  request to either reaches its app; a shim calling the wrong one is served;
  an edge whose session lapses has its apps moved, and their next requests
  and shim calls reach the new owner; two apps of one workspace on two
  edges are held to the workspace's limits between them.

### C7. Evidence

- `measure_gateway.sh` against two and three edges on separate hosts, with
  the control plane and PostgreSQL on their own: requests a second and large
  bodies, against one edge.
- An edge killed under load: what its clients see, how long until its apps
  serve again.
- STATUS.md, EMBEDDING-API.md (edges in "The pieces"), deploy units for an
  edge.

## Risks

- **A hot app.** E7 puts an app on one edge: one that alone needs more than
  an edge can carry cannot have it. Splitting an app across edges (each
  execution's shim on its own edge, a queue per edge, the client balancer
  spreading the app's requests) is a later change.
- **Shares that do not follow the traffic fast enough.** A workspace whose
  traffic moves from one app's edge to another's may be refused at its
  limit on the new edge for up to a flush while the old edge's share is
  given back.
- **Forwarding doubles a hop** for a request that lands on the wrong edge:
  with N edges behind a plain TCP balancer, (N-1)/N of them do. A balancer
  that routes by host name to the owner removes it on the gateway side; it
  needs the ownership map, and is an optimisation, not a stage.
- **An app moving while a request is forwarded** gets 503 from the old
  owner, never having run, and is not retried.
- **Renewal state lost with a process** costs its runs one round trip to
  re-read and reserve, not their grants: a grant runs to its deadline.
- **Something an edge serves may need a secret's value** (E6): it is then
  moved to the control process, which costs a call from edge to control
  plane where there was none. Stage C1 finds out.
- **Edges hold a database credential.** With the role the control plane
  uses, a compromised edge can write anything, ciphertexts included. A role
  of its own, limited to the tables it uses, is open.

## Not in this plan

- Grants of more outbound bytes out of the gateway's lease (E4).
- An app across several edges (Risks).
- Run output batches, which are still a write each, and are refused while
  the database cannot be reached rather than buffered.
- A control plane of more than one process for the management API and the
  scheduler: their load does not grow with traffic or with runs.
