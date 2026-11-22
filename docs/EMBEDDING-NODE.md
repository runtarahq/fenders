# Embedding the node: your own control plane

Use this when you already have a scheduler and a store, and want only the
sandbox: a fleet of machines that run WebAssembly components in kernel-free
KVM virtual machines, each run confined and reporting to you.

You run `fenders-node`, `fenders-shim`, `launch` and `runtime.elf` on each
machine (`make build-node` produces them in `build/node`). You write two
things:

1. **The run channel**: an HTTPS endpoint each run's shim calls, with a
   credential you issue per launch.
2. **The control peer**: the mutual-TLS service a node heartbeats to and takes
   its assignments from.

`fenders-control-plane` implements both and is the reference for both. The
run channel is small and stable enough to implement from this page. The
control peer has no written, versioned specification yet
([status](STATUS.md)): start from the run channel and one machine.

## Start here: one run, no node, no control peer

`fenders-shim` reads a run spec on standard input, owns the VM for the run's
life, and calls the run channel. `fenders-shim-stub` is a run channel in one
file. Together they are the smallest complete system:

```sh
make build-node && cargo build -p fenders-shim       # the stub is a debug binary
sudo install -d -m 0755 /var/lib/fenders-try
sudo cp build/node/{fenders-shim,launch,runtime.elf,compile} /var/lib/fenders-try/
# Compile a component for this runtime, then run it.
build/node/compile build/node/example-command.wasm /var/tmp/example.cwasm
sudo scripts/shim_standalone.sh /var/lib/fenders-try /var/tmp/example.cwasm \
  "$(sha256sum build/node/example-command.wasm | cut -d' ' -f1)"
```

`scripts/shim_standalone.sh` writes the spec, starts the stub and prints
every call the shim made. Read it and `crates/fenders-shim/src/bin/stub.rs`
beside this page: they are short, and they are what is tested.

## The run spec

What a launcher hands a shim (`crates/fenders-shim/src/spec.rs`). It carries
a credential, so nothing logs it.

```json
{
  "protocol": 1,
  "run": {"execution": "your-run-id", "generation": 1, "trace_id": "optional"},
  "channel": {
    "endpoint": "https://control.example:9093/run/your-run-id/1",
    "credential": "the bearer this launch sends",
    "ca_pem": "-----BEGIN CERTIFICATE-----…",
    "server_name": "optional, when the certificate is for another name"
  },
  "artifact": {"component": "/path/to/component.cwasm"},
  "uid": 61000, "gid": 61000,
  "guest": {
    "artifact": "sha256 of the component",
    "mode": "command",
    "cpu_percent": 100,
    "guest_memory_mib": 566, "host_memory_mib": 598, "wasm_memory_mib": 256,
    "lifetime_seconds": 60,
    "env": {"NAME": "value"}
  }
}
```

Everything beyond this is opt-in, and a spec that does not ask takes the
plain path, with no extra pipe, socket, task or call:

| In `guest` | Asks for | The shim then calls |
|---|---|---|
| `"output": {"redact_env": ["TOKEN"]}` | The guest's standard output and error, with those variables' values masked | `POST v1/run/output` |
| `"tcp_allow"`, `"http_allow"`, `"http_public_targets"` | Outbound access: socket addresses, HTTPS origins, and the addresses public origins are pinned to | nothing: it is static for the run's life |
| `"egress_budget"` | An outbound byte limit: the guest sends only bytes it was granted | `POST v1/run/egress` |
| `"mode": "http"` | An app that serves requests on a socket only its shim holds | `POST v1/run/http/next`, `POST v1/run/http/response/ID` |
| `"host_origin": "http://name"` | An origin inside the guest that reaches you; `"host_origin_concurrency"` (1 to 64, default 16) is how many of its calls are relayed at once, further ones waiting | every request to it, relayed |

A warm shim is started with the spec minus `run` and `channel` plus
`"warm": true`, and is later sent `{run, channel}` as its claim.

## The run channel

Each call goes to the spec's `endpoint` with a path appended, over HTTPS
(HTTP/2 when offered), the server verified against `ca_pem`, with
`Authorization: Bearer <credential>`. The shim presents no client
certificate: **the credential is the authentication**. Issue one per launch,
bind it to that execution and generation, and refuse it once the execution
has moved on.

A request that could not be sent is retried with backoff; one that reached
you is never repeated.

A relayed guest call goes on an HTTP/2 connection of its own when you offer
HTTP/2, and its answer is handed to the guest as you send it: no deadline
and no size limit of the shim's, so a call may wait as long as its work
takes and a streamed answer (a model's output) reaches the guest as it is
made. HTTP/2 pings notice an endpoint gone silent; the guest giving up the
call, or its VM ending, resets the stream. Over HTTP/1.1 the answer is read
whole, at most 8 MiB, within a minute. The shim's own calls are bounded in
time either way.

| Call | When | Answer |
|---|---|---|
| `POST v1/run/outcome` | The VM ended without the guest reporting an outcome itself. JSON: how it ended | `204` |
| `POST v1/run/output` | A batch of output records: at most 64 records or 48 KiB, or after 200 ms; one sequence across both streams | `2xx`. A `4xx` or `501` to the first batch ends capture for that run; the run goes on |
| `POST v1/run/egress` | An ask for outbound bytes: `{"bytes", "expected_revision", …}` | `200 {"revision", "state": "active", "ceiling_bytes", "ttl_ms"}`; `429 {"available_bytes"}` when the allowance cannot cover it; `409` for a stale revision |
| `POST v1/run/http/next` | An HTTP run asks for its next request, and waits | `200` with a framed request, or `204` to ask again |
| `POST v1/run/http/response/ID` | The answer to request `ID`, framed | `200` |
| anything else | The guest called its `host_origin`: the request is relayed as it was made, minus authorization, binding and `fenders-*` headers, which a guest cannot set | yours to define |

A framed request or response is a four-byte big-endian length, that many
bytes of JSON head (`id`, `method`, `path`, `headers` for a request; status
and headers for a response), then the body.

An endpoint may refuse any optional call. A run that asked for nothing makes
none of them.

## The control peer

A node is started with its peer's address and certificate pin and its own
certificate (`fenders-node --control URL --control-pin SHA256 --ca … --cert …
--key …`, see `deploy/artifacts/worker/fenders-worker.service`). Both sides
present certificates from one CA; the node pins the peer's.

The node calls, on the peer's mutual-TLS listener:

| Call | Purpose |
|---|---|
| `POST /internal/heartbeat` | Reports of the node's runs (state, reason, exit, CPU, memory, outbound bytes) and its capacity; the answer is the node's assignments |
| `GET /internal/assignments/wait?after=N` | Waits until the node's assignments change, so a run starts without waiting for the next heartbeat. Optional: a peer without it is polled |
| `POST /internal/component-jobs/claim` and `…/ARTIFACT/GENERATION/…` | Claims a component to inspect or compile, and reports the result |
| `POST /internal/certificate` | Renews the node's certificate, for a peer that signs them (`--renew-certificate`) |

An assignment carries the run spec's `protocol`, `run`, `channel` and guest
configuration; the node adds the component, the uid and the cgroup. Every
assignment is fenced by a generation: a report for an older generation is
ignored, and a stop names the generation it stops.

The shapes are in `crates/fenders-node-protocol` (validation of reports and
assignments, identities, limits, the pinned transport) and the peer side is
`api::internal` and `nodes.rs` in `crates/fenders-control-plane`. Treat those
as the specification until one is written, and expect it to change before
1.0.

## What the node guarantees you

- One VM per run, with no kernel in it; the launcher confined by Landlock and
  seccomp; a cgroup and a uid per run.
- The node keeps nothing about a run on disk. Shims outlive the agent and are
  reattached when it restarts; a run the node lost is yours to recover.
- A run can be stopped. It cannot be paused or resumed.
- Outbound access is exactly the launch's policy and does not change while
  the run lives: to take a permission back, stop the run.

Operation, logs, metrics and retention: [node/README.md](../node/README.md).
