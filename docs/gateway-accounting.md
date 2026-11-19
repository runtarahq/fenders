# Gateway accounting off the request path: the plan

Status: decided on 19 November 2026 (D1 to D3); nothing here is built.
D4 to D7 are the plan's own choices, and D4 and D5 are numbers that stage 0
may change. [STATUS.md](STATUS.md) says what is true today.

## Why

Every request to an HTTP app is admitted, tracked and settled in PostgreSQL,
in transactions under the one advisory lock all mutations share
(`store.rs`, `begin_transaction`). A request costs:

| Step | Where | What it writes |
|---|---|---|
| Admit | `ingress_begin_request` | Route and limits read; an `ingress_reservations` row holding 1 MiB of the transfer allowance; an `app_http_runs` row; `app_http.last_activity`; an audit row once a minute |
| Dispatch | `ingress_dispatched` | The run row marked `running` |
| Extend | `ingress_extend`, from `Meter::admit` | 1 MiB more held, each time what is held is used up; and a renewal every `GATEWAY_RENEW` while a response streams |
| Complete | `ingress_complete` | The reservation deleted; the run row finished; `traffic_usage` incremented |

That is three locked transactions for a small request and one more for each
MiB. A WebSocket message an app sends is one more (`websocket_sent`).

So the requests a second the whole platform serves, all tenants together,
are bounded by how fast one PostgreSQL connection at a time can commit. No
number of gateways or nodes raises that bound. This plan removes it. It is
the prerequisite for running more than one gateway, and it does not itself
add a second one.

Not measured yet: what the bound is. Stage 0 measures it.

## What the lock is buying today

The plan has to keep each of these, or say that it does not.

1. **The allowance is exact.** A byte passes only when it is reserved
   against the workspace's monthly transfer, in the transaction that checks
   it.
2. **A crash loses no accounting.** What was reserved lapses into usage
   (`expire_ingress`).
3. **Admission is serialised with the reconciler.** An execution that holds
   no reservation is idle, and stays idle while the reconciler stops it
   (`app_http.rs`, `drain_http`, `drain_others`, the idle teardown).
4. **A waiting request wakes its app.** `wake_http` starts an idle app when
   a reservation with no execution is waiting for it.
5. **Requests in flight are counted** against `http_concurrent_requests`,
   as reservation rows.
6. **Suspension cuts in at once.** Every one of those transactions checks
   that the workspace is active.
7. **Every request is a row**, from the moment it is admitted.

## Decisions

D1, D2 and D3 were decided on 19 November 2026.

| # | Decision | Decided |
|---|---|---|
| D1 | Whether the allowance stays exact, or is enforced by sampling with a bounded overshoot | Exact. The gateway holds a **lease** of the allowance for each active workspace and passes bytes only against it. Nothing overshoots. The cost is that the unused part of a lease is unavailable to the workspace's outbound grants until it is returned: the same trade a run's outbound grant already makes. |
| D2 | What becomes of a lease its gateway never settled (the process died) | Counted as used, and recorded as conservative, as an outbound grant is when its shim dies. A clean stop settles exactly. Billing can leave conservative bytes out; the allowance cannot be exceeded either way. |
| D3 | Whether a request record is guaranteed | No. A record is written once, when the request ends, in batches. Under database back-pressure records are dropped and counted, never requests delayed. Usage totals are never dropped: they are sums and wait for the next flush. |
| D4 | How often the gateway flushes | Every second, in one locked transaction for everything it holds. A gateway not seen for 15 seconds is dead. |
| D5 | How large a lease is | What the workspace moved in the last five seconds, between 1 MiB and 64 MiB, and never more than the allowance has left. |
| D6 | Where requests in flight are counted | In memory, as the rate already is. A restart forgets the count. |
| D7 | Scope | Inbound only: the gateway and WebSocket. Outbound grants and the run channel's reads are left as they are (see "Not in this plan"). |

## The design

Four things replace the per-request transactions. All four live in the
gateway process and are written to PostgreSQL by one **flusher**.

### A gateway session

A row for each running gateway process: `gateway_sessions(id, started,
seen)`, touched by every flush. Leases and activity belong to a session. A
session not seen for 15 seconds is dead: the scheduler settles its leases
(D2) and ignores its activity.

Today there is one session, or two during a rolling update. A session is
also what an edge process will be when the gateway is split out; nothing
else in this plan needs to change for that.

### Transfer leases

`gateway_transfer_leases(session_id, tenant_id, period, held_bytes,
expires)`, and added to the `transfer_allowance_accounting` view as held
bytes, so every existing check of the allowance counts them unchanged.

- `Meter::admit` takes bytes from the workspace's lease in memory. It
  touches no database unless the lease is empty.
- The flusher adds what was used to `traffic_usage`, per project, takes
  that much off the lease, and tops the lease up to its target size (D5).
- A workspace that empties its lease between flushes asks for more at once,
  in one transaction for the workspace, and its bodies wait for the answer.
- A lease is granted only what the allowance has left. Granted nothing, the
  workspace is marked exhausted in memory and refused without a
  transaction until the next flush looks again.
- A lease does not cross a UTC month: it expires at the month's end and is
  settled in the month it was held for.
- A workspace with no traffic for 30 seconds returns its lease.

`ingress_extend` and the per-request reserve are deleted. `websocket_sent`
draws on the same lease.

### The gate

For each app, in memory: whether it is serving, its workspace, project,
release and request timeout, the workspace's limits, and how many of its
requests are in flight. This is the warm path's whole admission:

1. Look the host name up (the `Hosts` cache, extended to carry this).
2. Refuse if the workspace is suspended, exhausted, past its rate, or at
   its requests in flight.
3. Enter the gate if the app is serving. Offer the request to the exchange.

No transaction. A gate is kept true by `LISTEN/NOTIFY` on what it mirrors
(`app_http`, `tenants`), the pattern `pickup.rs` already uses, with a
two-second expiry behind it for a notification that was missed.

An app that is not serving takes the **cold path**, which is today's
`ingress_begin_request` nearly as it is: a locked transaction, a
reservation row that holds no bytes and means only "a request waits for
this app", `wake_http`, and the poll until a route appears. Then the
request enters the gate like any other. Cold requests are rare by
construction: an app takes them only while it starts.

The reconciler stops an idle execution by closing its app's gate first.
Closing succeeds only when nothing is in flight, under the gate's own
lock, so a request either entered before the close and is waited for, or
comes after and takes the cold path. That is guarantee 3, kept without the
database. Where the reconciler reads `ingress_reservations` to learn
whether an execution is busy, it asks the exchange (`busy`, `outstanding`),
which already knows for extra executions.

### The request log

A request's record is built in memory and sent to the flusher when the
request ends: one multi-row insert into `app_http_runs` a flush, from a
bounded queue. A request in flight for longer than one flush is written as
`running` and updated when it ends, so a long stream is still seen.
`ingress_dispatched` is deleted. The once-a-minute `ingress.admit` audit
row and `app_http.last_activity` are written by the same flush.

WebSocket connections keep their own rows as they are: one per connection,
written when it opens.

## What changes for someone relying on it

To go into STATUS.md with the stage that makes each true.

| Today | After |
|---|---|
| A request holds 1 MiB of the allowance while in flight | A workspace's gateway holds one lease, 1 to 64 MiB, while it has traffic |
| A request record exists from admission | It exists up to a second after the request ends, or after a second in flight; a gateway that dies leaves no record of what it had in flight |
| Every request has a record | Records are dropped under back-pressure, and `GET /v1/control-plane/status` says how many |
| A crash charges each request what it had reserved | A crash charges each active workspace its lease, as conservative bytes |
| Requests in flight survive a restart as rows | Counted in memory; a restart starts from none |
| A suspended workspace is refused in the next transaction | Refused when the notification arrives, within two seconds at worst; bodies in flight are cut at their next byte |
| `pending` in usage is the sum of reservations | The sum of leases |

Unchanged: the allowance cannot be exceeded; nothing is replayed; the
statuses a client is answered (503, 504, 502, 409, 429) and when.

## Stages

Each lands on its own with the suite green, and is worth having without
the next.

### 0. Measure

- A load script against `scripts/local_env.sh`: small requests to one app
  and to many workspaces, a large body, a WebSocket stream. Requests a
  second, latency at the median and the 99th percentile, locked
  transactions a second.
- Counters in `GET /v1/control-plane/status`: locked transactions, time
  waited for the lock, admissions by path.

Done when the numbers are in this file. They are what stage 4 is compared
with, and they decide whether D4 and D5 are right.

### 1. Sessions, the flusher and the request log

- Migration: `gateway_sessions`.
- The flusher, started with the gateway and flushed on shutdown before the
  listeners finish draining.
- `app_http_runs` written at completion; `ingress_dispatched` removed; the
  audit row and `last_activity` moved to the flush.
- A test hook, `Store::flush_gateway`, so a test asserts on rows without
  waiting.

Per request: three transactions become two.

### 2. Transfer leases

- Migration: `gateway_transfer_leases`; the view replaced by one that
  counts them. The old binary's reservations and the new one's leases are
  both in the view, so the two overlap safely during a rolling update.
- `Meter` on the workspace's lease; `ingress_extend` and the renewal
  removed; usage flushed; `websocket_sent` on the lease.
- The scheduler settles a dead session's leases; `backup.rs` fences leases
  on restore as it does waiting reservations.
- `usage.sql` and `usage_history.sql` read leases as pending.

Per request: two transactions, however large the bodies.

### 3. The gate

- The host cache carries what admission needs; notifications keep it true.
- Warm admission in memory; requests in flight counted there.
- `ingress_reservations` kept only for the cold path, with no bytes.
- The reconciler closes a gate to stop an idle execution, and asks the
  exchange what is busy.

Per warm request: no transaction. Per process: one a second.

### 4. Evidence and documents

- The stage 0 script again, and both sets of numbers here.
- `scripts/verify_http_live.sh`, `verify_gateway_limits_live.sh` and
  `verify_egress_limit_live.sh` pass; the second's "abandoned requests hold
  none of the allowance" now holds because no request holds any.
- STATUS.md: the table above, and the limits below.

## What will need rewriting

About sixty test call sites use `ingress_begin` and `ingress_finish`
directly or read the three tables. Keep those two functions as the way a
test stands in for the gateway, on the gate, so most survive with a
`flush_gateway` before their assertions.

| Tests | Why |
|---|---|
| `cases/app_http.rs`, `cases/http_runs.rs` | Assert a reservation row and a run row per request, and bytes in `traffic_usage` at once |
| `cases/app_on_demand.rs`, `cases/ingress_admission.rs` | Waiting requests and the limits: the cold path stays, the counts move to memory |
| `cases/egress_budget.rs`, `cases/usage.rs`, `cases/accounting_retention.rs` | Held bytes are leases |
| `cases/control_plane_rollout.rs`, `tls_and_backup.rs` | Two processes at once; restore fencing |
| `cases/workspace_lifecycle.rs` | Suspension refuses through the gate |

## Risks

- **Idle teardown during a rolling update.** With two gateway processes,
  one's reconciler cannot close the other's gate. It skips idle teardown of
  an app while another live session reported activity for it in its last
  flush. A request that arrives at the other process in the same second
  that an app idle for a minute is stopped is answered 503, never having
  run. Today that cannot happen; after this it can, in that window only.
  The edge tier removes it: an app then belongs to one gate.
- **A missed notification.** The two-second expiry bounds it. A request
  admitted to an app that stopped serving meanwhile is not taken and is
  answered 503 after `GATEWAY_TAKE`, never having run.
- **Lease starvation near the limit.** With little allowance left, the
  gateway's lease and the runs' outbound grants compete for it. Leases
  shrink to what is left (D5) and are returned after 30 seconds idle;
  stage 2 tests a workspace within one lease of its limit.
- **The flush is one transaction.** With many active workspaces it grows.
  It is batched statements, not a statement a workspace; stage 0's
  many-workspace run is repeated in stage 4 to see where it bends.

## Not in this plan

Each is a transaction rate that does not grow with requests, or is not
locked. They are next, in this order, if stage 4's numbers say so.

- **Outbound grants.** A run with a connection renews its grant at least
  every 10 seconds, one locked transaction each: a rate that grows with
  running executions, not with traffic. The node already measures what a
  run sent and reports it; nothing new is needed on the node.
- **The run channel's reads.** Each `http/next` and `http/response` call
  authenticates with a read transaction, outside the lock. Caching what a
  credential names for a few seconds removes them.
- **Run output.** Batches of output records are written as they arrive.
- **The edge tier.** A gateway and run channel in a process of their own,
  several of them, each app's shims pointed at one. A session, its leases
  and its gates are that process's state already.
