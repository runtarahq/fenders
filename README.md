# Fenders

Airtight sandboxes for WebAssembly, made to be built into other products.

Fenders runs WebAssembly components in kernel-free KVM virtual machines: each
run gets a VM of its own with no Linux guest inside it, a cgroup, a uid, and
exactly the outbound access its launch names. Around that sits a multi-tenant
control plane with an HTTP API: tenants with allowances, projects, scoped API
keys, uploads, on-demand and scheduled runs, HTTP-triggered apps, secrets,
outbound connections, run output and usage.

There is no user interface here. Fenders is the part you put behind your own.

## Two ways to build it in

| You want | You run | You write | Guide |
|---|---|---|---|
| Multi-tenant execution behind an API | The control plane, PostgreSQL and one or more nodes | Calls to the REST API: an operator credential creates tenants and keys, a tenant key does the rest | [Embedding the API](docs/EMBEDDING-API.md) |
| Only the sandbox, under your own scheduler | Nodes (`fenders-node`, `fenders-shim`, the launcher) | The node's control peer and the run channel endpoint | [Embedding the node](docs/EMBEDDING-NODE.md) |

For one machine with no control plane at all, `fenders-node-server` is a
loopback, token-authenticated API over the same run backend
([node guide](node/README.md)).

## How it fits together

```text
your product ──REST──▶ fenders-control-plane ──▶ PostgreSQL
                         │  API · scheduler · gateway · run channel
        pinned mTLS      │            ▲
                         ▼            │ HTTPS, a credential per launch
                     fenders-node     │
                         │ starts     │
                         ▼            │
                     fenders-shim ────┘     one per run, owns the VM
                         │
                         ▼
                     launch (KVM) ── runtime.elf (Wasmtime) ── your component
```

- **`fenders-control-plane`** holds every durable fact: tenants, quotas,
  artifacts, apps, schedules, executions, usage. It assigns runs to nodes and
  serves each run's **run channel**.
- **`fenders-node`** is a thin launcher. It heartbeats to its control peer,
  compiles components in a confined worker and starts each run as a shim. It
  keeps nothing about a run on disk.
- **`fenders-shim`** owns one run's VM for its whole life and speaks for it on
  the run channel: how it ended, its output, its outbound byte grants, and,
  for an HTTP app, its requests.
- **`launch`** is the VMM, in C: KVM, Landlock, seccomp. The guest is
  Wasmtime built for a bare machine; there is no kernel in the VM.

Multi-tenancy is in the control plane, not bolted on: a tenant's allowance
(CPU, memory, storage, instances, transfer) is reserved in the same
transaction that admits work, every credential is scoped to one tenant and
optionally one project, and a request for another tenant's resource is
answered as if it did not exist.

## Status

Fenders is pre-1.0 and has not been qualified for hostile public multi-tenant
operation. What works, on what evidence, and every known limit is in
[docs/STATUS.md](docs/STATUS.md). Read it before depending on a protection.

## Build

Rust 1.97.0. The control plane builds anywhere Rust does and needs
PostgreSQL 17. A node needs Linux x86-64 with KVM, cgroup v2, Landlock and
seccomp, plus `cc`, and the `x86_64-unknown-linux-musl` and `wasm32-wasip2`
Rust targets.

```sh
make build            # the control plane and tools
make build-node       # Linux x86-64: build/node with the launcher, runtime, node and shim

export FENDERS_TEST_DATABASE_URL='postgresql://USER:PASSWORD@HOST/TEST_DATABASE'
make test             # needs a disposable PostgreSQL 17 database
make check            # rustfmt and clippy
```

On a Linux x86-64 machine with KVM, Docker and passwordless `sudo`, this runs
the whole thing once, with two tenants, and removes it again:

```sh
make build-node
bash scripts/verify_embedding_live.sh
```

`scripts/local_env.sh up` keeps a local environment running instead.

## Repository map

| Location | Purpose |
|---|---|
| `crates/fenders-control-plane` | The API, scheduler, gateway and run channel |
| `crates/fenders-node`, `crates/fenders-shim` | The node agent and the per-run shim |
| `crates/fenders-node-protocol` | What the node and its control peer say to each other |
| `crates/fenders-component` | The confined compiler and component inspection |
| `runtime/` | The guest runtime, the KVM launcher and the pinned WASI HTTP fork |
| `examples/` | WASM components and runtime fixtures |
| `deploy/` | systemd units for the control plane and the node |
| `scripts/` | Build and live verification entry points |
| `docs/` | Embedding guides, status, recovery |

## Licence

Apache-2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE). Security reports:
[SECURITY.md](SECURITY.md).
