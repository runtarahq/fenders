# Status and limits

What Fenders does today, how that was shown, and every limit known. Update
this file in the same change that alters what works or a limit.

Fenders is pre-1.0. It has **not** been qualified for hostile public
multi-tenant operation, and no release has been cut. Everything under "Works"
was shown end to end on a real KVM node, but on one development machine acting
as both control plane and node.

## How it works (the shim model)

- `fenders-node` is the enrolled agent. It heartbeats to its control peer over
  pinned mTLS, takes assignments, compiles components in a confined worker and
  starts each run as a `fenders-shim` in its own cgroup, with a uid of its own.
- `fenders-shim` owns the run's VM for its whole life. It relays the guest's
  host-bound origin to the **run channel**: an HTTPS endpoint the control plane
  names per launch, with a per-launch bearer credential and trust. It reports
  how the run ended and its outbound byte totals. Shims outlive the agent and
  are reattached when it restarts.
- A launch spec carries `protocol`, `run` and `channel`, and a `mode`:
  `command`, or `http` for an app that serves requests.
- Every further capability is opt-in per launch spec (`output`,
  `egress_budget`, `mode: http`). A launch that does not ask takes the plain
  path: output to `/dev/null`, no extra pipe, socket, task or call.
- Outbound access is the static policy in the launch spec: `tcp_allow`,
  `http_allow`, trust, and for public HTTPS origins the addresses they resolved
  to. It does not change while a run lives; a permission is taken back by
  stopping the run.
- A run makes sockets and connects them at up to 1,000 calls at once and 200
  a second after (a connection is two); past that a call is refused with
  `EAGAIN`. The numbers are the launcher's, not a tenant's to set.
- The node keeps nothing about a run on disk. A lost run is recovered by its
  control plane.

## Works

| Area | What | Repeat it with |
|---|---|---|
| Embedding, two tenants | An operator credential creates tenants and scoped keys; each key uploads, deploys and runs; neither sees the other; no console is served | `scripts/verify_embedding_live.sh` |
| Commands | A command run through the workload API and a manual run of a deployed app, recorded with their exit | `scripts/verify_run_channel_live.sh` |
| Run output | Standard output and error read through `GET …/apps/APP/logs`, with the values of the run's secrets masked | `scripts/verify_output_live.sh` |
| Connections | An app reaches the TCP endpoints and public HTTPS origins it was given and nothing else; removing one stops the runs that hold it | `scripts/verify_connections_live.sh` |
| Outbound byte limit | A run with a connection sends only what the tenant's monthly transfer allowance grants, and is ended when it would send more | `scripts/verify_egress_limit_live.sh` |
| HTTP apps | An app with the HTTP trigger has a URL; bodies stream both ways; it scales between `scale.min` and `scale.max` executions; a new release takes over without failed requests | `scripts/verify_http_live.sh` |
| Gateway limits | A request target too long for a shim is refused and wakes nothing; such requests do not end a starting app's execution; requests their clients abandon hold none of the transfer allowance | `scripts/verify_gateway_limits_live.sh` |
| WebSocket | The gateway holds connections for an app and gives it their events as requests | Shown with a headless browser as the client; that check is not in this repository yet |
| A shim asked to stop | Once its run is over, a shim holding the run's end for its launcher ends at once on SIGTERM | `scripts/verify_shim_stop_live.sh` |
| The shim alone | One component under `fenders-shim` against a stub run channel, with no node or control plane | `scripts/shim_standalone.sh` |
| The control plane | Tenants, projects, members, invitations, API keys, secrets, uploads and inspection, apps and schedules, usage accounting, backup and restore | `make test` |
| Confinement | Confined compilation and the artifact cache; the launcher's Landlock and seccomp; the shim's own (read-only filesystem, its run channel's port, a refusal list); per-run cgroups and uids | `make verify-confinement`, `scripts/verify_network_native.sh`, `cargo test -p fenders-node --test shim_confinement`, `scripts/verify_destinations_live.sh` |

## Does not work

| Feature | State |
|---|---|
| Pause and resume | The node answers 501 and the API refuses the request (`unavailable.rs`); a run can only be stopped |
| Worker host qualification | There is no harness that qualifies a new host for production |
| A user interface | None is included. `Store::with_assets` lets a wrapping binary serve its own |

## Limits

### Embedding and tenancy

- A workspace may have 256 projects, 4096 secrets, 4096 apps and 1024
  credentials that still open anything, and its credentials may make 600
  changes a minute between them (counted in memory, as the gateway's rate
  is). These are constants. Audit records, operations and request receipts
  are kept for good: their growth is bounded by that rate, not by a
  retention.
- The operator credential is one bearer token, written to
  `STATE/operator.token` at first start. It is not scoped; whoever holds it
  can do anything. It is valid for as long as it is that file's: to replace
  one that leaked, delete the file and start the control plane again, which
  writes a new one and revokes the old.
- An API key or tenant credential lives at most 30 days. A host product
  re-issues them with the operator credential. One issued with a tenant
  credential lives no longer than that credential, and ends when it is
  revoked; those a member issued end when the member is removed or stops
  being an owner, or their account is disabled. Credentials issued before
  this was recorded have no issuer and are revoked one by one.
- The OpenAPI contract (`/api/openapi.json`) covers the workspace API. The
  operator calls are described in [EMBEDDING-API.md](EMBEDDING-API.md), not
  yet in the contract.
- The node's control protocol has no written, versioned specification: the
  `fenders-node-protocol` crate and the control plane's `/internal` routes are
  the reference ([EMBEDDING-NODE.md](EMBEDDING-NODE.md)).
- Browser sign-in (OIDC) and invitations remain in the control plane for a
  product that brings a console; without `--browser-auth` they are off. The
  provider's metadata and signing keys are held for five minutes, and
  fetched again at most every ten seconds for a token signed with a key not
  among them: a key the provider withdraws is trusted for up to five minutes
  more. A session lasts eight hours from sign-in, and thirty minutes unused. At most 10,000 sign-ins are held between their start and
  their callback; beyond that the oldest give way, so a sign-in is lost only
  if that many more are started while it is under way.
- `--tailscale-identity` is a **development-only** sign-in that trusts a
  header. The control plane refuses it unless it listens on loopback. Never
  use it in a deployment.

### Run output

- No durable copy on the node. Output not delivered within 5 seconds of a
  run's end, or held when a shim is killed, is lost, and the run's output
  reads as incomplete.
- Output is stored in the control plane's PostgreSQL: at most 1 MiB a run and
  64 MiB a tenant, for 7 days.
- Masking is of literal values; a program that encodes a secret before
  printing it is not caught. A secret is at least 4 bytes, so that masking
  one does not blank its output; one stored before that limit is masked as
  it is. The node is trusted to mask, as it is trusted
  with the secrets themselves.
- Following lags by about 200 ms and polls; nothing is pushed.
- The output of a run that was stopped is not closed by its shim, so it reads
  as still being collected.
- Identical workload executions can reuse a warm shim; app runs never do.

### Connections

- A removal is enforced by the node stopping the run. A node the control
  plane cannot reach keeps its runs, with their access, until it can be
  reached or they end; the removal stays pending meanwhile.
- A run does not follow its origins' DNS: the addresses are those of its
  start.
- Revoking a grant given to a deployment stops all of that deployment's
  running executions, not only those launched after the grant.

### Outbound byte limit

- It is enforced only on a node registered as requiring it
  (`egress_budget_required`) and started with `--egress-budget`. On any other
  node a run with a connection is unlimited. Every node that runs untrusted
  tenants must require it.
- A grant needs the control plane. When it cannot be reached a run's grant
  lapses within 10 seconds and the run ends as `outbound-grant-expired`.
- A run alive across the end of a UTC month cannot renew its grant and ends.
- A running run holds at least 256 KiB of the allowance, and up to 16 MiB
  more than it has sent, until it ends. The control plane holds it to that:
  a shim says what its run has sent with each ask, and is granted no more
  than brings what is unsent to that much.
- A run whose shim is killed with it has no final total: all it held is
  counted as used.
- What is counted is payload handed to sockets the guest opened, not packet
  headers, retransmissions or anything received.
- A new launcher has a new digest, which the operator must approve for a node
  before it is given limited runs.

### HTTP apps and WebSocket

- Every byte of every request, response and WebSocket message passes through
  the control plane, whose gateway and run channel must be one process. Its
  throughput is not measured.
- WebSocket connections and the request exchange live in that process's
  memory: a restart closes every connection, and a second control-plane
  process is not supported.
- A request is handed out once and never replayed: 503 if no execution took
  it in 10 seconds, 504 if taken and not answered, 502 if the app failed.
- A request body is at most 64 MiB and a response 1 GiB; a response may last
  15 minutes and is cut after 60 seconds of silence. These, and the
  connection limits (1000 an app, 4000 a tenant), are constants.
- Scale-out reacts in seconds and by one execution at a time; a burst beyond
  the queue (64 requests an app) is answered 503.
- The rate limit is counted in memory: a restart forgets the last minute.
- Connections are limited per listener and per peer address, with unfinished
  handshakes budgeted apart from served connections: 512 served (128 an
  address) on the management and node-control listeners, 8192 (2048 an
  address) on the gateway and the run channel, where a connection that makes
  no request for two minutes is closed. These are constants. They stop one
  address, or sockets that never complete a handshake, from holding a
  listener; they do not stop many addresses acting together. Put a proxy or
  a firewall in front of a listener that faces the internet, and do not
  expose the node-control and run-channel ports beyond the nodes.
- Executions of one app on two nodes were shown only in tests with stand-in
  nodes.
- A run lives at most 24 hours; a cold start is a full launch.

### The run channel

- Its listener takes no client certificate: a launch's credential is the only
  thing that authenticates a call. The credential is a token under a key
  derived from the control plane's encryption key for this purpose alone
  (nothing else the control plane encrypts, a tenant's secret among it, is
  one), so rotating that key ends the credentials of runs in flight.
- A stored secret's ciphertext names its workspace, project and id, and
  opens only for that row: one copied into another row opens for no run.
  Secrets stored before this are bound once, at the first start after it.
  Whoever can write the database can still insert a credential or an
  execution: the encryption at rest protects against reading the database
  and against moving a secret, not against every write.
- The launcher's control socket also accepts pause and resume; a shim sends
  it only grants and status, over a socket pair nothing else holds.

### Nodes

- Runs are given uids from `--run-uid-base` (600000 by default), one each.
  A node refuses to start when one of them is an account's or within a
  subordinate uid range of its host, or when another node on the host
  already runs from the same base.
- With `--warm-runs`, booted shims wait for runs like the ones they were
  made after, up to 32. Each is counted against the node's instances and
  memory as a run is, and gives way when a run needs its room. Each holds
  the environment (secret values included) of the launch it was made like,
  for up to ten minutes; all are discarded when any run on the node is
  stopped, as a removed connection stops runs.
- A node's compiled-artifact budget (512 MiB by default) is shared by every
  workspace it compiles for. An entry not in use is kept for an hour, but
  one over a minute old gives way when an upload would otherwise be refused:
  a workspace that fills the budget makes the next compile again, it does
  not keep it out. Compiles are taken up in turn among workspaces.
- Any enrolled node may be given any workspace's upload to compile, and its
  verdict is taken: a node is trusted with components as it is with
  secrets.

### Confinement

- A run's shim is confined once it has started its VMM: no new privileges, a
  read-only filesystem, TCP only to its run channel's port and a resolver's,
  and system calls it has no use for refused. That refusal is a list, not
  the allowlist the compiler and the VMM have: a call not on it is allowed.
  A warm shim is confined when it is claimed, not while it waits.
- The kernel holds a VM's cgroup to the run's own destinations (its
  `tcp_allow` pairs and the resolver's port 53, no IPv6) when the shim is
  root, as a node's is. A shim that is not root has the launcher's check
  and Landlock's port numbers only.

### Tests

- Some live harnesses under `crates/fenders-control-plane/tests/cases/`
  (`agent_upgrade_*`, `m2_*`, `m1_live`) were written for the node before
  shims; they compile, cannot pass and are `#[ignore]`d. A few of them start
  browser checks that are not in this repository.
- The control-plane suite is run with `--test-threads=4`; at full parallelism
  a varying handful fail under load and pass when rerun.
- Code kept for features not yet rebuilt on shims (the `freeze` and `settle`
  actions of `egress_budget.rs`, pause and resume in `workloads.rs`, lease
  validation in the node) is exercised only against stand-ins.
