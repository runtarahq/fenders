# Fenders node

`fenders-node` is the enrolled agent on a Linux x86-64/KVM host. It takes
assignments from its control peer over pinned mTLS, compiles components in a
confined worker, and starts each run as a `fenders-shim` in a cgroup of its own.
The shim owns the run's VM for its whole life and talks to the run's control
plane over the **run channel** (HTTPS, a per-launch credential). What Fenders as
a product supports on top of this, and what is not yet rebuilt on shims, is in
[docs/STATUS.md](../docs/STATUS.md).

## Build

```sh
make build-node          # Linux x86-64: build/node with runtime.elf, launch, compile,
                         # fenders-node, fenders-node-server, fendersctl, fenders-shim
```

## What a run is

- A launch spec must carry its run channel (`protocol`, `run`, `channel`) and
  a `mode`: `command`, or `http` for an app that serves requests, which its
  shim takes from the run channel. An outbound byte budget (`egress_budget`)
  is served by a node started with `--egress-budget` and refused by any other.
- Outbound access is the static policy in the launch spec (`tcp_allow`,
  `http_allow`, trust and public targets). It does not change while a run lives.
- The node keeps its runs in memory and reads each one's state from its shim
  over the abstract socket `@fenders/run/<id>`. On start it reattaches to the
  shims it finds under `--cgroup-root`; a shim that does not answer is killed.
- A run can be stopped. It cannot be paused or resumed.
- Guest output is kept only for a launch that asks: with `"output":
  {"redact_env": [...]}` in its guest configuration, the shim sends the
  guest's standard output and error up the run channel
  (`POST …/v1/run/output`), bounded and with those variables' values masked,
  and logs the launcher's own messages as `launcher` lines. Without the field
  the guest's output goes to `/dev/null`. Nothing of it is written on the node.
- The shim reports how the run ended (state, reason, exit code, signal) and
  its outbound byte totals; the agent reports those, with the run cgroup's CPU
  and memory, in its heartbeat.
- `--warm-runs` keeps booted shims per artifact and guest configuration, each
  claimed by one later run.

`scripts/shim_standalone.sh` runs one compiled component under `fenders-shim`
against `fenders-shim-stub`, without a node or a control plane.
`scripts/compare_shim_default_path.sh` runs it under two builds and compares
the system calls each made, to show a change left the default launch alone.

`fenders-node-server` is a loopback, token-authenticated API over the same run
backend, for a single host without a control peer: upload a component
(`POST /v1/artifacts`), launch (`POST /v1/instances`, with `Idempotency-Key`),
list and read runs (`GET /v1/instances[/ID]`) and stop one
(`POST /v1/instances/ID/stop`).

State quotas are described in [PROJECT-QUOTA.md](PROJECT-QUOTA.md), which was
written for the node before shims and still mentions its run directories.

## Logs, metrics and retention

These apply to the enrolled agent, `fenders-node`, and the shims it starts.

**Logs.** The agent and its shims log `tracing` events to standard error, one
line each, at the levels `RUST_LOG` names (`info` when unset; tracing's target
syntax, such as `fenders_node=debug,warn`). `--log-format` (or
`FENDERS_LOG_FORMAT`) chooses how:

* `text`, the default: `LEVEL target: message key=value ...`, without a
  timestamp, as the supervisor's journal stamps each line itself;
* `json`: one object per line, with `timestamp` (RFC 3339, UTC), `level`,
  `target` and `message`, and the event's fields beside them at the top level.

Lines about a run carry, where known, `run` (the node's id for the run, its
shim's), `execution` (the control plane's id for the assignment the run serves)
and `tenant` (the compile scope the control plane names for the assignment, its
isolation unit; absent when it names none). The agent logs each run's start
(`run started`), end (`run ended`, with `state`, `reason` and `exit_code`), loss
and refusal (`run refused`, with `reason`). A shim logs in its agent's format,
with its run's `run` and `execution`, and ends with `run ended` and the end
report's `state`, `reason`, `code`, `exit_code`, `signal` and `outcome`.
`fenders-node-server` logs as text unless `FENDERS_LOG_FORMAT=json`.

**Retention.** A node running its runs as shims keeps nothing about a run on
disk past its end: its cgroup goes once its end is collected, and its
assignment's row once the end is reported and the control plane no longer
assigns it. A node before shims kept every run's directory in
`STATE/node/runs` and archived, instead of deleting, its assignments' rows; an
upgraded node never reads either again. Once a minute the agent removes up to
`--retention-batch` (default 1000; 0 turns the sweep off) of each:

* run directories whose worker process is gone and which were last written at
  least `--retention-min-age-seconds` ago (default 3600), unless an assignment
  not yet archived names the run (it is still reported, and its control plane
  may still recover it);
* archived assignment rows (reported ended and no longer assigned).

When `runs` is empty it goes, with `node.sqlite3`. The log and egress delivery
tables a node before shims kept are dropped when the agent starts, so no
pending delivery remains for a run directory to wait on.

**Metrics.** With `--metrics-listen ADDRESS:PORT` (a loopback address, such as
`127.0.0.1:9464`: the endpoint is unauthenticated, so another is refused) the
agent serves Prometheus' text format at `/metrics`. Off by default.

| Metric | Type | Meaning |
|---|---|---|
| `fenders_node_runs_total{start}` | counter | Runs started; `start` is `cold` (a shim started for it) or `warm` (a warm shim claimed). |
| `fenders_node_admissions_total` | counter | Assignments admitted to start a run. |
| `fenders_node_refusals_total{reason}` | counter | Assignments refused a run: `maintenance`, `unsupported`, `local-capacity`, `node-capacity`, `local-storage`, `artifact-rejected`. |
| `fenders_node_run_start_seconds{start}` | histogram | From the agent starting a run to its shim running it (its VMM started; a warm shim's VM booted before its claim). |
| `fenders_node_retention_removed_total{what}` | counter | What the retention sweep removed: `run_directory`, `assignment`. |
| `fenders_node_run_directories` | gauge | Run directories on disk: run cgroups, plus runs a node before shims left until the sweep removes them. |
| `fenders_node_runs` | gauge | Runs not yet ended. |
| `fenders_node_run_capacity` | gauge | `--max-instances`. |
| `fenders_node_warm_shims` | gauge | Warm shims waiting for a run. |

Counters start from zero when the agent starts.

## Host confinement

The compiler and VMM exec children apply the mandatory
`landlock6-seccomp-v2` policy before executing the trusted native binaries.
The node probes enforcement at startup and refuses a permissive fallback.
The platform requires this capability for placement, artifact/secret assignment,
and public ingress. It is an authenticated node report,
not hardware attestation. Stop commands remain available without issuing another
artifact or secret payload when the capability is missing.

Compiler filesystem access is limited to its input, the pre-created output file,
the compiler/ELF loader and read-only system libraries. It receives a clean
environment and has no socket, subprocess, namespace, ptrace, BPF, perf or
io_uring syscall access. Threads are permitted. A separate cgroup bounds the
compiler to 1 GiB RAM, zero swap, 32 tasks and one CPU. Existing 60-second wall,
45-second CPU, 1.5 GiB address-space and 128 MiB output limits also apply. OOM,
timeout and agent restart cleanup kill the owned compiler group. Compiler output
logs are discarded rather than creating a second unbounded artifact file.

VMM filesystem grants cover its own runtime, component, guest environment,
trusted loader/libraries and `/dev/kvm`. Host state, other tenant inputs and
credential files are not granted. The policy drops process capabilities, uses
no-new-privileges, denies process creation while permitting threads, and limits
ioctl commands to the VMM's KVM operations and nonblocking socket control.
The VMM may set affinity only for its calling thread (`sched_setaffinity(0, …)`),
which its startup path requires. The compiler cannot change affinity. The policy
version participates in compiler cache identity and node placement eligibility;
rebuild both control-plane and node binaries when upgrading this policy.
Landlock signal and abstract-Unix scopes isolate the child domain. These
restrictions build on the kernel's [Landlock interfaces](https://docs.kernel.org/userspace-api/landlock.html)
and [libseccomp rules](https://github.com/seccomp/libseccomp/blob/main/doc/man/man3/seccomp_rule_add.3).

This is **not a complete VMM network jail**. Landlock supplies a static TCP
port ceiling and denies new TCP binds; it cannot express destination IPs here.
UDP creation is disabled unless DNS is configured. The native VMM remains
responsible for destination IPs and DNS restrictions; the policy is fixed at launch. A VMM
compromise could bypass those native checks within its remaining host socket
permissions. Independent host network enforcement, further syscall reduction,
native-ABI fuzzing and full KVM regression are still required before public
hostile-tenant use. Landlock also does not conceal all filesystem metadata, and
deliberately inherited control/ingress descriptors retain their authority.

Stop legacy runs before upgrading: startup refuses to label an existing
unconstrained worker as protected. It does not kill those VMs on its own.
The compiled cache identity includes the confinement policy version, forcing
fresh compilation after this upgrade. Do not change the rules without reviewing
whether the policy version and cache identity must change.

```sh
make verify-confinement
make verify-compiler-confinement CONFINEMENT_CGROUP=/sys/fs/cgroup/fenders-compiler-test
```

The first command checks actual Linux file/syscall/thread/socket boundaries with
a native probe. The second uses the real `Node.upload` and worker path with the
pinned Wasmtime compiler, plus a deliberately adversarial compiler fixture for
PID exhaustion, CPU throttling, OOM cleanup and environment isolation. Its memory
exhaustion case uses a 64 MiB test limit to avoid unnecessary host load. These
tests require an empty dedicated delegated cgroup root; they do not execute KVM.
