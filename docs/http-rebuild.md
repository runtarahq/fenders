# HTTP apps on shims: the plan

Status: built on 11 November 2026, all four stages; what works, its evidence
and its limits are in [STATUS.md](STATUS.md), which wins where this file
differs. This file is the plan as it was decided, kept for its reasoning;
delete it when that is no longer wanted.

Built differently from what is written below:

- **The run channel did not offer HTTP/2.** The control plane's listeners
  spoke HTTP/1.1 and ended a connection after about 80 seconds, so the
  gateway and the run channel got a listener of their own
  (`stream_listener.rs`).
- **No `FENDERS_API` variable.** An app with WebSocket calls the fixed
  origin `http://fenders.internal`; the guest runtime did not change for it.
- **Extra executions sit beside the first, not in a rewritten reconciler.**
  The single-execution state machine was kept; scale-out adds
  `app_http_extras`, and a new release adds a candidate execution.
- **Limits are constants or per-workspace columns**, not yet a set of
  operator settings: body sizes, stream times and connection counts are
  constants; requests in flight and per minute are set per workspace.
- **Scale `max` is at most 8**, and while a release is replaced the app's
  extra executions are stopped.
- **A release with no room beside the old one** (allowance, or no node
  placing it within 10 seconds) is replaced in turn, as before.
- **No WebSocket subprotocol** is negotiated from the connect answer.
- **A connection's line in Events is a row of its own**, written when the
  app accepts the client and finished when it closes; the connect event,
  like the others, is not listed.

Decided on 11 November:

1. **Routing:** the shim pulls requests over the run channel.
2. **Guest stream:** a socket pair carrying HTTP/2, not a loopback listener.
3. **Scope:** streaming bodies and scale-out are included.
4. **Replacement:** requests are held while an app has nothing ready to
   serve, and a new release is started before the old one is stopped.
5. **WebSocket:** the gateway terminates it and gives the app each event as
   an ordinary request (section 8).

## What the customer gets

An app with the HTTP trigger has a URL (`https://app-APPID.DOMAIN`). A request
to it is answered by the app's component, running as a `wasi:http` handler in
a KVM guest on a shim. Bodies stream in both directions, so a large upload, a
large download and server-sent events work. An app runs on as many executions
as its load needs, between a minimum and a maximum the customer sets. A new
release takes over without a failed request. A browser can hold a WebSocket
to the app: the app is told of each message and can send to any open
connection. The console shows the URL, its
state and how many executions serve it, sends a sample request, and lists
requests with their status in Events. Output, secrets, connections and the
outbound byte limit apply to each execution as they do to a command.

## Where it stands today

| Piece | State |
|---|---|
| Guest runtime (`runtime/guest/src/service.rs`) | Serves `wasi:http` 0.2 and 0.3 handlers, one request at a time, a fresh store per request, on a listening socket. Not started by any shim. |
| Launcher (`launch.c`, `lifecycle.inc`) | Hands the guest an inherited stream socket as `/fenders/listener` (`FENDERS_INGRESS_FD`). No shim passes one. |
| Gateway (`api.rs`, `gateway_dispatch_tracked`) | Checks host and method, buffers a body of at most 1 MiB, admits through `ingress.rs`, then calls the node's `/rpc/ingress`, which was deleted on 10 November. |
| Admission and accounting (`ingress.rs`) | A reservation, an audit row and an `app_http_runs` row per request; 16 held and 600 a minute per workspace; transfer allowance; never replayed. |
| One execution per app (`app_http.rs`) | Start, readiness, sequential replacement, restart limit, idle stop and wake. Its idle stop asks the node to pause, which nodes no longer do. |
| Node and shim | Both refuse any `mode` but `command`. |
| API and console | `unavailable.rs` answers 501 for the HTTP trigger; the console hides it. |

The first step that fails today: `POST …/apps/deploy` with
`triggers.http: true` is answered 501. Under it, the node refuses the launch
("a shim runs commands only"), and the gateway would call an RPC no node has.

## Why the shim pulls

| | Through the agent | Gateway dials the shim | The shim pulls (chosen) |
|---|---|---|---|
| Agent | In every request; a restart drops requests in flight | Not involved | Not involved; apps keep serving while the agent restarts |
| New listener on a node | None | One port, certificate and credential per HTTP run | None |
| Node reachable from the control plane | Required | Required, on a port range | Not required |
| Authentication and fencing | Node mTLS plus a new check of the run in the agent | A new scheme | The run channel's per-launch credential and generation check |
| Scale-out | The gateway picks a node and execution | The gateway picks an execution | Whichever execution has a free slot takes the next request |

## 1. How a launch opts in

`mode: http` in the guest configuration, with one new optional number,
`http_concurrency` (default 1, at most 64).

- `mode: command`: nothing changes. No socket, task or call is added; this is
  every Runtara launch and every command.
- `mode: http`: the shim gives the guest a stream for requests and starts the
  tasks that pull them from the run channel.

The node's `create_scoped` and the shim's spec accept `http` and check, as
now, that the component's inspection has an HTTP entry point, and that
`http_concurrency` stores fit the guest's memory. A node built before this
refuses the launch, so the app reads as failed to start with that reason. No
heartbeat field is added. An HTTP run is never taken from the warm pool.

## 2. Shim to guest: one stream, no port

The shim makes a socket pair and passes one end as `FENDERS_INGRESS_FD`. The
launcher already hands it to the guest as `/fenders/listener`; the launcher
does not change.

The guest runtime changes in `service.rs` only: it serves HTTP/2 on that one
stream, up to `http_concurrency` requests at once, a fresh store for each,
each bounded by its own timeouts. Bodies are streamed, as hyper and the
handlers already do. The runtime stays on one thread: requests interleave,
they do not run in parallel.

- No port exists on the node, so nothing but the app's own shim can send it
  a request, and none can skip the gateway's admission.
- Readiness needs no marker in the output: the guest's HTTP/2 handshake
  arrives only once the component is loaded and serving.
- A request the guest must abandon (timeout, handler trap) resets its own
  HTTP/2 stream and leaves the others alone.

## 3. Shim to control plane: two streaming calls per request

```
POST {channel}/v1/run/http/next
  -> 200, body: HEAD LENGTH | HEAD JSON {id, method, path, headers} | request body bytes…
  -> 204 after 25 s with nothing: call again
  -> 409 the launch is not current, or its release no longer takes requests

POST {channel}/v1/run/http/response/ID
  body: HEAD LENGTH | HEAD JSON {status, headers} or {error} | response body bytes…
  -> 200 when the client has been sent all of it; 410 if the client is gone
```

- The shim keeps as many `next` calls waiting as the guest has free slots, so
  the control plane always knows each execution's free capacity.
- The first `next` call is made when the guest is ready. It is the
  execution's readiness signal.
- Bodies are raw bytes after a length-prefixed JSON head: no base64, nothing
  buffered whole. HTTP/2 flow control carries back-pressure from the client
  to the guest and back.
- Header filtering both ways and weak validators are the gateway's existing
  `application_headers` rules.
- A request is handed out once. If the answer carrying it is lost, the
  request is recorded as `unknown` and the client gets 502; nothing is
  replayed.
- An endpoint that answers the first `next` with 404 or 501 does not serve
  HTTP runs; the shim ends the run as failed.

These calls need a streaming variant of the shim's `Upstream`, used by HTTP
runs only; the buffered one that commands use is left as it is. They need
HTTP/2 on the run channel. The control plane's node-control listener speaks
HTTP/1.1 and ends a connection after some 80 seconds, so the run channel and
the gateway are served by a listener of their own (`stream_listener.rs`):
HTTP/2 and HTTP/1.1, with no connection lifetime.

`wasi:http` has no connection upgrade (its only mention of one is the error
`HTTP-upgrade-failed`), so a component cannot accept a WebSocket itself.
The gateway does it for the app: section 8.

## 4. Control plane: the exchange

The gateway keeps its checks and admission and replaces its transport. In
place of calling a node it hands the request to an in-memory exchange and
streams the response back.

- **Keyed by app and release.** Each app has one queue. Every execution of
  the app's active release that has a `next` call waiting can take from it,
  so load spreads to whichever execution is free, with no balancer.
- **Bounded.** A request waits in the queue at most 10 seconds (the existing
  wake deadline), then gets 503. The queue's length is capped per app.
- **Fenced.** `run_channel_authorize` already refuses a call whose execution
  moved to another generation or released its reservation. The exchange adds
  the release: an execution of a superseded release gets 409 on `next`.
- **Held through gaps.** While an app has no ready execution (first start,
  wake from idle, restart after a failure, replacement) requests wait in the
  queue instead of failing. Clients see a slow request, not an error, unless
  the wait passes 10 seconds.
- **Timeouts.** Time to the response head is bounded by the app's request
  timeout. After the head, a stream is cut when it sends nothing for 60
  seconds or lasts longer than 15 minutes (both operator settings).

## 5. Admission and accounting for streams and volume

The kept admission takes a reservation of the request's size plus 1 MiB, in
a transaction with an audit row, before every request, and caps a workspace
at 16 requests in flight and 600 a minute. That fits neither a stream of
unknown length nor an app on several executions.

- **Bytes are reserved in blocks as they flow**, the way outbound bytes are
  granted: the gateway takes 1 MiB of the transfer allowance in a
  transaction, counts request and response bytes against it, and takes the
  next block before the last is spent. When the allowance cannot cover a
  block the stream is cut. What was not used is released at the end.
  Nothing is sent that was not reserved.
- **Size limits.** A request body is at most 64 MiB and a response at most
  1 GiB by default (operator settings); the transfer allowance bounds both.
- **Rate and concurrency** become limits of the workspace's plan in place of
  the constants, counted in memory in the gateway and not from audit rows.
- **Records.** Each request still gets its `app_http_runs` row (method, path
  without query, status, duration, bytes). Admission is audited per app and
  minute, not per request.

This keeps the quota transactional and removes two of the three writes a
request costs today. Its throughput is to be measured, not assumed.

## 6. Scale-out

An app's configuration gains `scale: {min, max}` in place of `keep_warm`
(`keep_warm: true` reads as `min: 1`, `false` as `min: 0`; `max` defaults
to 1, so an existing app behaves as before).

- **Out:** when requests have waited in the app's queue for more than a
  second, or every execution's slots have been full for 10 seconds, and the
  app is below `max`, one more execution is started. One at a time; the next
  only after the last became ready or failed.
- **In:** an execution that has had no request for 60 seconds is stopped,
  down to `min`. With `min: 0` the last one goes too, and the next request
  starts one and waits for it in the queue.
- **Quota.** Every execution is created through the existing `execution`
  path, so the workspace's compute allowance (CPU, memory, instances) is
  checked in the same transaction. When it is exhausted the app stays at
  its size and says so (`allowance-exhausted`).
- **Placement.** Unchanged: the scheduler places each execution as any
  other. Executions of one app may share a node or not.
- **Failure.** An execution that ends is replaced, with the existing limit
  of three failures in five minutes, counted per app.

The signals come from the exchange, which sees queue wait and free slots
directly; nothing is asked of nodes.

## 7. Replacement without failed requests

A new release, or changed configuration or connections:

1. Executions of the new release are started beside the old ones, as many as
   are serving now (at least one), if the compute allowance has room.
2. When the first is ready, the app's active release switches. From then
   the exchange gives requests to new executions only.
3. Old executions finish what they hold, up to the 30-second drain deadline
   (a stream longer than that is cut), and are stopped.

- If the new release never becomes ready, the old one keeps serving and the
  release is marked failed. Today the old one is stopped first.
- If the allowance has no room for both, it falls back to the sequential
  order (stop old, start new) with requests held in the queue across the gap.
- Removing a connection still stops every execution launched with it at
  once, as item 3 requires; requests are held while replacements start.

Idle stop and drain no longer ask a node to pause: the exchange knows what
each execution holds. The pause branches in `drain_http` are deleted.

## 8. WebSocket, terminated at the gateway

The gateway holds the client's WebSocket. The app never sees a socket: it
gets each event as an ordinary request through the exchange, and sends by a
call. So the shim and the node do not change, the guest by one variable
name (below), and a
connection outlives any one execution: it survives a new release, scaling in
and a restart of the app.

An app opts in with `websocket: true` in its configuration; without it an
upgrade request is refused with 426.

Events, each a `POST` to a reserved path of the app's own handler, with the
connection's id in the `fenders-connection` header:

| Event | Request to the handler | What the answer means |
|---|---|---|
| A client asks to connect | `/_fenders/ws/connect`, with the client's path, query and filtered headers | 2xx accepts (it may name a subprotocol); anything else refuses the upgrade with that status |
| A message arrives | `/_fenders/ws/message`, the message as the body, text or binary by content type | A body in the answer, if any, is sent back on the same connection |
| The connection closes | `/_fenders/ws/disconnect` | Ignored; delivered once, best effort |

A client cannot reach `/_fenders/…` directly: the gateway refuses those
paths from outside.

Sending, from any execution of the same app (a request handler or a
scheduled or manual run), over the host-bound origin, which the shim relays
to the run channel with the launch's credential:

```
POST {host origin}/v1/run/ws/CONNECTION     body: the message     -> 200, or 404 if it is closed
DELETE {host origin}/v1/run/ws/CONNECTION                         closes it
GET {host origin}/v1/run/ws                                       the app's open connection ids
```

Fenders' own launches name no host-bound origin today; only Runtara's do.
A launch of an app with `websocket: true` gets one (`host_origin` in its
guest configuration, which the node, shim and guest already support), and
the app is told its address in a run-context variable, `FENDERS_API`. The
guest runtime's list of visible variables gains that one name.

The run channel checks that the connection belongs to the caller's app. The
list exists because a handler keeps nothing between requests: an app
without a database of its own can still send to everyone.

Rules:

- **Order.** A connection's messages are given to the app one at a time, in
  order: the next waits for the answer to the last, whichever execution
  takes it. Messages of different connections run concurrently.
- **Back-pressure.** While a connection's message waits, the gateway stops
  reading that socket; it buffers at most one message per connection.
- **Limits** (plan or operator settings): a message of at most 1 MiB, open
  connections per app and per workspace, messages a second per connection.
  A connection with no traffic is pinged; one that does not answer is
  closed.
- **Accounting.** Message bytes both ways count against the transfer
  allowance in the same blocks as streams; a connection is closed when a
  block cannot be covered. Events lists a connection once, with its
  duration and message and byte counts, not every message.
- **Idle apps.** An open connection does not keep an execution running.
  With `min: 0` the app can go to none, and the next message starts one and
  waits for it, as a request does.
- **Fencing.** A send is a run-channel call, so one from a superseded
  generation is refused like any other.

## 9. What does not change

- **Runtara's path and commands.** No new thread, pipe, socket or call for a
  launch that is not `mode: http`; shown by the system-call comparison used
  for items 2 to 4.
- **The agent.** It validates and starts the launch and reports its state.
- **The launcher.** No change.
- **Output, connections, byte limit.** Per launch, so they apply as they are.
- **Stop.** Through the node, generation fenced, as any stop.

## 10. Data model

`app_http` holds one `execution_id` and a single-execution state machine.
It becomes: the app's HTTP state and active release in `app_http`, and its
executions in a table of their own (app, release, execution, ready, last
request). The reconciler in `app_http.rs` is rewritten around a set of
executions; its start, restart-limit and wake rules are kept. By an appended
migration, as there are no installations to carry over.

## 11. Limits this plan accepts

- **Gateway and run channel in one process.** The exchange is in memory. A
  second control-plane process would need requests passed between them.
- **WebSocket connections live in the gateway's memory.** A restart of the
  control plane closes them all; clients must reconnect. The app is not
  told of those closes.
- **A WebSocket message is a whole request.** Each costs a handler call
  with a fresh store, so chatty protocols are expensive, and a message is
  not streamed. Components written for these events run only on Fenders.
- **The control plane carries every byte** of every request and response.
  Its throughput on shims is not measured.
- **Concurrency in a guest is interleaving on one thread.** A handler that
  computes without yielding delays the others; fuel yields bound that.
- **A run lives at most 24 hours.** Each execution is replaced at that
  limit; with one execution, requests are held across the gap.
- **Month end with a connection.** An execution under the outbound byte
  limit cannot renew across the end of a UTC month (item 4's limit), so it
  is ended and replaced then. Renewing across a month's end becomes worth
  doing soon after.
- **Each execution with a connection holds at least 256 KiB** of the
  transfer allowance while it runs.
- **Cold start is a full launch**: VM boot and component load, within the
  10-second wait. Not measured.
- **Scale-out reacts in seconds**, by one execution at a time. A sudden
  burst beyond the queue is answered 503.
- **A node the control plane cannot reach serves nothing**: its shims
  cannot pull. Its executions are replaced elsewhere when the node is seen
  as lost.

## 12. Order of work, each step a commit with its tests

A. One execution, buffered bodies, through the pull path:

1. Guest: HTTP mode serves HTTP/2 on the inherited stream.
2. Shim and node: accept `mode: http`; socket pair, readiness, pull tasks;
   the stub endpoint serves the two calls, so `scripts/shim_standalone.sh`
   sends a request with no control plane. Default path compared.
3. Control plane: the exchange, the two run-channel calls, the gateway
   through it; readiness from the first call; idle stop without pause.
4. The HTTP trigger offered again (API, console, local environment's
   application domain). Live: a request answered on a real node.

B. Streaming:

5. Shim's streaming upstream; gateway and exchange stream both ways;
   stream timeouts.
6. Bytes reserved in blocks; size limits; live: an upload and a download
   larger than a block, and a server-sent-events response.

C. Concurrency and scale-out:

7. Guest and shim: `http_concurrency`.
8. Data model and reconciler for several executions; `scale`.
9. Scale out and in from the exchange's signals.
10. Replacement that starts the new release first; requests held in gaps.
11. Rate and concurrency as plan limits counted in memory; admission
    audited per minute.

D. WebSocket:

12. Gateway: accept the upgrade for an app that asks, connect, message and
    disconnect events through the exchange, order and back-pressure per
    connection, ping and limits.
13. Run channel: send, close and list, reached from the guest over the
    host-bound origin; accounting of message bytes; a fixture that echoes
    and broadcasts.
14. Console: the setting, open connections on the app, a connection in
    Events.

E. Evidence and the status document.

Each of A, B, C and D ends with a live run, so the item can stop at any of
them with something that works.

## 13. Evidence that will show it done

On a real node from the API and the console, in the local environment:

- An app with the HTTP trigger is deployed, reads as serving, and a request
  through the gateway returns the component's response and is listed in
  Events.
- A 16 MiB upload and a 16 MiB download pass, counted exactly against the
  transfer allowance; a server-sent-events response arrives event by event.
- A stream is cut when the allowance runs out, with nothing sent beyond it.
- Under load an app with `max: 3` grows to three executions and shrinks
  back; with `min: 0` it goes to none and the next request starts one.
- A new release takes over under steady load with no failed request and no
  response from the old release after the switch; a release that cannot
  start leaves the old one serving.
- A WebSocket client connects, gets its message echoed, and receives a
  message sent by a different request and one sent by a scheduled run; a
  connect the handler refuses is refused to the client; the connection
  stays open across a new release.
- A request to an app whose run was stopped waits, then is refused.
- A command launch makes the same system calls as before.

Not provable on one development host: executions of one app on two nodes,
and throughput. Both need the second machine or the dev node's bench.
