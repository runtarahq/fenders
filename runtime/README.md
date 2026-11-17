# Kernel-free WASM runtime

The native guest runs upstream Wasmtime 50.0.0, `wasmtime-wasi` and
`wasmtime-wasi-http`. Application components use the standard `wasi:http`
outgoing interface, `wasi:sockets`, and `wasi:filesystem`, from WASI 0.2 or 0.3:
both are linked, with component-model async, and a WASI 0.3 command's async
`run` runs as a task. HTTP serving remains the 0.2 incoming handler. Hyper and HTTPS certificate verification
execute **inside the VM**. There is no Linux guest, initrd, host HTTP broker,
or replacement HTTP client in WASM.

Production runtime ownership: `guest/` contains the pinned Rust/Wasmtime runtime,
`native/` contains the bounded KVM launcher and native probes, and `vendor/`
contains the maintained WASI HTTP fork. Samples live in `examples/`.

## Execution path

```text
WASM application                     32 MiB-1 GiB VM
  | wasi:http                        |
  +--> upstream Wasmtime HTTP --> Hyper --> rustls/Tokio
  | wasi:sockets                     |              |
  +--> upstream Wasmtime WASI --------+--> native socket ABI
                                     |              |
---------------- VM boundary --------+--------------+-----
VMM: bounded TCP/UDP, readiness, clocks, entropy, memory
  | generic socket bytes
  +--> external HTTPS service / PostgreSQL
```

PostgreSQL protocol, SCRAM and PostgreSQL TLS run in the WASM application using
`tokio-postgres` and rustls over standard WASI sockets. HTTPS uses the separate
standard WASI HTTP interface. Both paths are exercised in the same VM.

The native runtime is built for the x86-64 Linux-musl **ABI**, but its ELF is
loaded directly into KVM. `SYSCALL` enters a small guest stub; an I/O exit asks
the VMM to implement a bounded platform operation. No Linux kernel is loaded.
The platform still has operating-system responsibilities; avoiding Linux does
not eliminate memory management, scheduling, timers or I/O.

Tokio uses a current-thread async executor. Its native blocking DNS worker has
an additional virtual CPU context backed by a host pthread. All VMM threads
are pinned to one allowed host CPU. That is affinity, not reserved capacity or
a CPU-time quota. The launcher permits at most eight thread contexts during
its lifetime; the runtime configures one blocking worker.

## Build and verify

From the repository root on Linux x86-64/KVM:

```sh
bash scripts/build_node.sh
bash scripts/build_service_example.sh
bash scripts/verify_network_native.sh
```

The build keeps Rust 1.97.0, Wasmtime 50.0.0, the musl ABI and existing lockfiles.
It produces the launcher, runtime, compiler, node and fixtures in `build/node`.
See [node operation](../node/README.md). Native socket checks do not
establish VM or tenant-isolation acceptance.

## WASI filesystem

The same upstream `wasmtime-wasi` instance now provides filesystem operations.
Standard WASI components and Rust `std::fs` both work. The guest platform forwards
bounded native filesystem operations to host directory capabilities; it does not
replace the WASI implementation or expose an ambient host root.

Two configurations are required: grant a directory to the VMM, then select its
preopen in the native guest environment. With no preopens, WASM receives no
filesystem directories. A requested preopen without a VMM grant fails startup.

| VMM environment variable | Guest path | Access |
| --- | --- | --- |
| `FENDERS_FS_APP=/host/path/assets` | `/app` | Read-only, independently enforced by the VMM |
| `FENDERS_FS_TMP=/host/path/scratch` | `/tmp` | Read/write |
| `FENDERS_FS_DATA=/host/path/volume` | `/data` | Read/write |

Set `FENDERS_FS_PREOPENS=/app,/tmp,/data` in the NUL-separated native `guest.env`
file to expose those paths through upstream Wasmtime. Use a subset when fewer
directories are needed. Host paths are supplied only in the VMM environment;
the guest receives virtual mount names.

The operator creates and owns these directories. Reuse a `/data` grant to retain
files across fresh VMs. Supply a fresh `/tmp` directory for each sandbox to get
ephemeral storage; the launcher does not automatically erase or provision host
volumes. Byte/inode quotas belong to that host storage provisioning layer and
are not implemented by this PoC. File contents and host page cache are outside
the VM's 32 MiB RAM allocation.

`bash scripts/verify_filesystem.sh` (after `build_node.sh` and
`build_service_example.sh`, on KVM) runs the filesystem probe in fresh VMs:
create, exclusive open, truncate, positioned and streamed I/O, metadata, links,
rename, escape attempts, read-only and cross-mount refusals, persistence across
VMs, no preopens, and a preopen without a grant.

Verified operations include create/exclusive-open/truncate, positioned reads
and writes, sparse growth, flags/types/stat/identity/metadata hashes, file and
symlink timestamps, advice and file/directory sync, mkdir, independent directory
iterators, hard links, relative symlinks, readlink, rename, unlink/rmdir, 128 KiB
streamed reads/writes and append. Rust standard-library create/read/write/copy,
seek, rename, directory iteration and recursive removal are also exercised.

Isolation checks cover read-only data and metadata mutations, absolute paths,
`..`, symlink escapes, NUL paths, cross-mount links/renames, and special-file
opens. `filesystem_probe.c` bypasses Wasmtime and issues native syscalls directly:
it checks the VMM's permissions, including duplicated descriptors, and attempts
2,000 opens while a host thread swaps a directory symlink between permitted and
forbidden targets. Host readback verifies that outside canaries remain intact.

The VMM copies guest path/iovec arguments, retains descriptor references during
each operation, and uses `openat2` with mandatory `RESOLVE_BENEATH`,
`RESOLVE_NO_MAGICLINKS`, and `RESOLVE_NO_XDEV`. Directory-relative calls cannot
switch mounts using absolute paths. Namespace mutations use pinned parent
directories; existing files are inspected with `O_PATH` and reopened using the
VMM's own pinned descriptor. Host mount roots must be trusted, provisioned
directories: preexisting hard links are grants to the linked inode, and the
operator must not alias another tenant's files into a sandbox volume.

Directories are separate virtual mounts: cross-mount hard links/renames return
an error. Nested host mount traversal, devices and FIFO data access are denied.
The pinned upstream Wasmtime 38 implementation itself rejects hard links with
`SYMLINK_FOLLOW`; the probe verifies that error instead of changing upstream
semantics. Optional `pwritev2` currently returns ENOSYS and upstream append falls
back successfully to supported operations.

Run the filesystem API probe (it provisions isolated test directories):

Historical filesystem probe commands are retained in the recovery tag; use the maintained native and Rust node checks for this source tree.

`--case combined --config run/wasi-sockets/config.json` runs the full filesystem
probe, DNS-backed HTTPS, then PostgreSQL TLS/authentication and committed
write/read in one 32 MiB VM. Application readiness is emitted only after all
three phases finish. Final evidence is in `run/wasi-filesystem-verified`: six
filesystem scenarios, host file readback, 35 network regression cases, and an
independent service-side check. Historical HTTP-only timing results above
are not a new filesystem performance measurement.

## Configuration and trust boundaries

The launch command is `launch runtime.elf component.cwasm guest.env`.
`guest.env` contains NUL-separated `NAME=value` records, at most 4096 bytes.
Native runtime settings are supplied by the operator; changing application WASI
environment variables does not grant new native runtime permissions.

| Setting | Scope | Meaning |
| --- | --- | --- |
| `FENDERS_TCP_ALLOW` | VMM process environment | Comma-separated IPv4:port destinations; empty denies all TCP |
| `FENDERS_DNS_SERVER` | VMM process environment | One IPv4 DNS server, UDP port 53; unset or `0.0.0.0` allows none |
| `FENDERS_HTTP_ALLOW` | Native guest environment | Exact lower-case origins including explicit port |
| `FENDERS_HTTP_DENY=1` | Native guest environment | Deny all outgoing HTTP |
| `FENDERS_SOCKET_ALLOW` | Native guest environment | Exact WASI TCP destinations; empty denies all |
| `FENDERS_HTTP_SERVICE_ROOTS` | Native guest environment | Bounded `https://host:port=DERhex` entries separated by semicolons; each origin trusts only its CA, others retain public roots. Empty means public roots throughout. |
| `FENDERS_HTTP_CA_DER_HEX` | Native guest environment | Legacy research-only global CA, used only when `FENDERS_HTTP_SERVICE_ROOTS` is absent; never supplied by the platform node |

Defaults are restricted to the lab endpoints. Production provisioning must
supply explicit per-sandbox policies. HTTP DNS resolution is native runtime
functionality; WASM name-lookup and UDP capabilities are disabled. Numeric-IP
PostgreSQL connections still verify their configured DNS certificate name.
TLS session resumption is disabled for these measurements.

Guest RAM is set per launch by `FENDERS_GUEST_MEMORY_MIB` (32 to 1024 MiB in
2 MiB steps, default 32); page tables sit just below the stack, sized to it.
A node spec's `guest_memory_mib` sets it. Its `wasm_memory_mib` (default 4)
caps aggregate WASM linear memory, at most `(guest - 16) / 2` MiB, since a
growing memory moves and briefly holds both copies. A spec also sets `fuel`
(default 200 million), `fuel_refuel` (`off`, or `yield`: unbounded fuel, so
only the lifetime bounds the run, yielding every 10 million units rather than
every 10,000, as a yield costs far more in the VM), `instances`
(default 32), `table_elements` (default 10,000), `tables` (default 16) and
`memories` (default 32). Native allocations share the
guest RAM. A node sets its compiler's memory, CPU share, CPU time and wall clock
(`--compiler-*`), its upload cap (`--max-upload-mib`, up to 128 MiB) and how
much compiled code it keeps (`--artifact-cache-mib`, default 512).

A spec's `host_origin` names one origin that needs no network grant. The node
gives the VMM one end of a stream (`FENDERS_HOST_ORIGIN_FD`, opened by the guest
as `/fenders/host-origin`). The runtime sends that origin's requests over it as
HTTP/2, with no first-byte cap and no `fenders-*` headers. The run's
`fenders-shim` serves the other end and relays each request to the run channel
over HTTPS with the per-launch credential, dropping any authorization, binding
or `fenders-*` header the guest sent. The VMM
has 61 guest descriptor slots and a 20-second wall-clock deadline. Descriptors
are reference-counted across concurrent syscalls to prevent host descriptor
reuse races. Host I/O receives validated guest memory ranges; `writev` metadata
is copied before use. File access is limited to explicitly granted filesystem
roots, the supplied AOT file, and generated resolver configuration. Stdin is EOF;
application stdout/stderr are inherited.

## Platform scope and limitations

### Outbound transport measurement

The launcher advertises `network_egress_accounting: "socket-payload-v1"` in its
capability response and includes that contract, `network_tx_bytes` and
`network_tx_measured` in management status replies. The byte counter is cumulative
for this VMM process. It counts successful host `write`, `writev`, `send` and
`sendto` results on guest-created outbound sockets, including DNS datagrams.
Duplicating or closing descriptors does not reset it. Failed writes add nothing;
partial writes add only the accepted bytes. Overflow invalidates the measurement
instead of wrapping or pretending a saturated value is exact.

WASI HTTP and WASI sockets share this transport, so the metric includes TLS
records when encryption runs in the guest. It is **socket payload accepted by
the host**, not confirmed remote delivery or wire bytes: packet headers and
retransmissions are excluded. Incoming HTTP response sockets, files, stdout and
management traffic are excluded.

The Rust worker supplies an optional `FENDERS_EGRESS_FD`: a new, zero-filled,
40-byte regular file owned by the host. The VMM maps it outside guest memory,
closes the inherited descriptor and never installs it in the guest descriptor
table. Five lock-free native-endian u64 atomics contain sequence, contract (1),
bytes, in-flight writes and validity (1). Writers publish an odd/even sequence
under the descriptor lock; readers reject uninitialized or interrupted records.
This local ABI requires matching host architecture and is not an archive format.

Before outbound I/O the VMM publishes an in-flight marker; afterward it publishes
the accepted count and clears the marker. The Rust worker reads while running
and after reaping the entire process, flushes the file and persists its final
observation. Thus a short-lived process needs no successful management poll.
Only a valid, stable post-exit record with no in-flight writes is complete. A
kill between the syscall and accounting leaves a lower bound with incomplete
coverage; interrupted publication is unavailable. Same-boot worker recovery
can recover a lower bound but cannot infer that process termination completed.
Absence, old launchers and invalid counters never imply measured zero.

The node ships these observations through the authenticated heartbeat to
generation-fenced control-plane rollups and customer Usage. Monthly outbound charging and fleet accuracy remain outstanding before platform
egress accounting is complete. This does not change transfer
admission or claim a monthly billing meter, host-loss durability or measured
performance overhead.

Run `bash scripts/verify_network_native.sh` on Linux with an x86-64 native or
cross compiler. The sanitizer tests use real host sockets and the production
accounting wrappers, including concurrency, duplicate ownership, partial writes,
denials, DNS, ingress/file exclusions and overflow. The launcher compile check
does not execute a KVM guest or establish live HTTPS behavior.

### Runtime boundaries

This is a tested PoC, not a production multi-tenant VMM or a full Linux ABI/WASI
conformance claim. The platform supports the operations exercised by the native
runtime: anonymous/file-backed memory allocation, page permissions, clocks,
entropy, descriptors, IPv4 sockets, epoll/eventfd, TLS registers, shared-memory
threads and a bounded futex subset. The upstream request transport here is
HTTP/1.1; HTTP/2, incoming HTTP, IPv6, DNS TCP fallback, listening sockets,
ambient filesystem access, fork/exec and arbitrary native applications are not verified
or provided by this launcher. HTTP response status handling and redirects retain
upstream semantics; they are not automatically converted to success/failure.

Signal registration/masks/alternate-stack calls are compatibility no-ops because
this platform does not deliver POSIX signals. Native fatal-signal requests and
unexpected KVM exits terminate the sandbox. Wasmtime uses explicit traps rather
than signal-based traps. `brk` cannot grow; libc uses mmap. `mremap`, rseq and
unimplemented syscalls return ENOSYS. Robust-list registration is a no-op; robust
mutex recovery and reusable long-lived thread IDs are not implemented. These
limitations matter for workloads beyond the tested upstream path.

The guest native runtime executes at guest CPL0. Guest page permissions constrain
normal execution but are not a security boundary against compromised native code.
The VM boundary, bounded host operations and Wasmtime's WASM isolation have
different responsibilities. Production deployment still needs VMM process
confinement, platform fuzzing, resource accounting and a reviewed threat model.

The vendored upstream HTTP changes are limited to CA-root configuration and TLS
resumption settings; see [provenance](vendor/wasmtime-wasi-http/FENDERS-PORT.md).

## Outbound byte admission primitive

The launcher advertises `network_egress_budget: socket-payload-ceiling-v2`.
Explicit `FENDERS_EGRESS_BUDGET=1` starts with no outbound byte authority and
requires the private management socket. Without this option, existing static
and leased networking retains its previous behavior. This primitive is not yet
the tenant transfer-allowance allocator.

The host-only command is `egress REVISION BOOTTIME_DEADLINE_NS CUMULATIVE_BYTES`.
The deadline must be zero (revoke new admissions) or at most 30 seconds ahead.
Live ceilings can only increase. After explicit freeze (zero deadline) and zero
in-flight writes, a newer revision may reduce the ceiling to at least the accepted
byte count. This discards unused authority before a new allowance period without
resetting the counter. V1 lacked that transition; fleet allocation requires v2.
Each renewal/revocation requires a
new revision; an exact live replay is idempotent, and conflicting or older
revisions fail. Expired grants cannot be renewed by replay. A gated launch waits
for both network authorization and an initial live byte grant; a zero-byte grant
can release that gate while permitting no positive outbound payload.

Under the descriptor lock, each outbound `write`, `writev`, `send` and `sendto`
reserves its entire requested payload before entering the host syscall. All
sockets and duplicates share the ceiling. Successful completions consume only
accepted bytes, returning unused reservation after partial/error results.
Insufficient, expired or invalid authority returns `EDQUOT` without calling the
socket; DNS datagrams are never truncated to fit. Large writes may therefore
need a larger grant even when a smaller write would fit. TLS/DNS socket payload
counts; accepted ingress, files, headers and retransmissions retain the existing
metering exclusions. Invalid lifetime measurement denies further admissions.

Expiry/revocation prevents new reservations; already admitted host writes may
complete later. The allocator must retain the full outstanding grant until
settlement or conclusive fencing, including after lost acknowledgments, process
death or host loss. The cumulative counter does not reset at a month boundary.
Source completion-month observations remain separate from admission-period
allowance allocation; this primitive alone makes no monthly enforcement claim.

Management status returns `egress_budget_enabled`, revision, deadline, ceiling,
reserved bytes, accepted bytes, in-flight count and measurement validity from one locked budget
snapshot. These live observations do not add crash durability to the retained
meter ABI. `scripts/verify_network_native.sh` exercises actual host sockets,
concurrent admission, partial/error refunds, replay/expiry, start gating and
integer boundaries under ASan/UBSan, then compiles the x86-64 launcher. It does
not establish guest WASI error handling, KVM execution or tenant-wide quotas.

## Retained UTC-month socket accounting

The optional `FENDERS_EGRESS_PERIOD_FD` supplies a new, private, zero-filled
432-byte regular file. The VMM maps it outside guest RAM, closes the inherited
FD and never adds it to the guest descriptor table. It advertises
`network_egress_periods: socket-payload-utc-month-v1`. The existing 40-byte
`FENDERS_EGRESS_FD` and `socket-payload-v1` lifetime contract remain unchanged.
Old runtimes leave the optional new file uninitialized; that is unavailable,
not measured zero. Approval of a changed runtime digest remains necessary.

Native-endian lock-free atomic u64 words contain sequence, contract (1), total
bytes, in-flight operations, validity, expired bytes, then 24 (month, bytes)
pairs. Month is `year * 12 + month_number` (January is 1), stored in slot
`month % 24`. Odd/changing sequence means an interrupted or concurrent
publication. Only changed slots are republished; ordinary calls do not rewrite
the entire ring. All header and slot accesses use atomic operations.

Accepted outbound socket payload is assigned to the host UTC month when its
successful completion is recorded under the descriptor lock. A syscall spanning
midnight is attributed wholly to the completion month; this is operation
accounting, not the timestamp of each byte on the wire or confirmed delivery.
Partial writes count only the accepted amount. Failed/zero-byte writes, ingress
responses and file I/O add nothing. TLS records and DNS payload follow the same
wrappers. The last 24 months ending at the latest recorded write are retained.
On advancement, older buckets move into `expired_bytes`, preserving the total
without guessing their month once detailed retention expires. No interpolated
split of a lifetime counter is used.

Month reversal, clock-read failure, invalid calendar values or wall-clock drift
exceeding five minutes relative to elapsed CLOCK_BOOTTIME permanently invalidate
monthly attribution for that runtime. Suspend time participates in that clock.
Lifetime measurements remain independent. This requires synchronized, trusted
host clocks; small clock errors around midnight can still change attribution.
Clock qualification and billing accuracy require live operational checks.

The Rust worker creates the second file with mode 0600, samples it into private
`status.json` as `egress_periods`, and persists final evidence after reaping the
VMM. The reader verifies slot placement, the 24-month span, integer arithmetic
and exact conservation (`expired_bytes + sum(periods) == bytes`). Uninitialized,
torn, malformed, overflowed or clock-invalid readings are unavailable. A killed
process with an in-flight write yields partial coverage. Recovery on the same
host boot cannot claim terminal completeness; another boot cannot refresh the
reading. The two meter files have independent snapshots and their totals need
not match within the same worker poll.

The Rust node now transmits optional `egress_periods` through authenticated
heartbeats. Control-plane migration 28 retains idempotent month rows and exposes
scoped customer Usage, with missing historical detail kept unassigned. Deploy
the control plane before the reporter. Outbound reservation/allowance enforcement
remains required; gateway allowance semantics are unchanged. Local native socket tests
and Rust/C ABI tests exercise the production wrappers without claiming KVM or
live guest TLS execution, billing accuracy or measured overhead.
