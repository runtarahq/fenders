# Enforced node state quota

> **Written before the shim model (4 November 2026).** The node now runs each
> run as a `fenders-shim`; parts of this document describe behaviour that is not
> yet rebuilt on it. [docs/STATUS.md](../docs/STATUS.md) states what works today and wins where the
> two differ.

The enrolled node can require an operator-provisioned Linux filesystem project
quota for its entire `--state` tree, including agent journals, run metadata,
compiled artifacts and output. This supplements the existing free-space admission
guard. It does not change workspace billing, resource reservations or log-retention
ownership. Standalone nodes are not enrolled in this policy.

Enable all three options together, for example:

```text
--state /srv/fenders/state
--state-project-id 123
--state-quota-mib 4096
--state-quota-inodes 100000
```

The values are **maximum acceptable existing hard limits**, not commands to create
or enlarge a quota. Both actual limits must be nonzero and no greater than these
ceilings. The node never formats storage, assigns project IDs, enables quotas,
changes limits or deletes files to satisfy this requirement. Without the options,
existing behavior remains available but cannot claim enforced state storage limits.

Provision a dedicated project on ext4 or XFS and assign it to all existing files
and directories before enabling this mode. Directory inheritance must be enabled.
Stop legacy writers first; account for uncertain/orphan processes explicitly.
Use a project exclusive to Fenders. Keep the state root owned by the node UID and
not writable by group/others. Do not put symlinks, devices, FIFOs, sub-filesystems
or XFS realtime data under it. Prefer a dedicated filesystem and reserve space
for its own metadata and other host services. Filesystem setup/migration is an
operator procedure; this feature is not permission to reformat an existing host.

## Verification and privilege behavior

Supported node ABIs are Linux x86_64 and aarch64, with `quotactl_fd`. Startup
requires real filesystem project attributes and accounting **and enforcement**
flags from `Q_XGETQSTATV`; mount-option text is not sufficient. `Q_GETQUOTA`
provides byte/inode hard limits and current usage. The 1 KiB block units of that
interface are converted with checked arithmetic. Unsupported syscalls, absent
flags, incomplete counters and unlimited or oversized limits refuse startup.
The kernel's [quota interface](https://www.kernel.org/doc/html/latest/filesystems/quota.html)
and [UAPI/state conversion](https://github.com/torvalds/linux/blob/master/fs/quota/quota.c)
define these contracts.

Linux's [generic quota implementation](https://github.com/torvalds/linux/blob/master/fs/quota/dquot.c)
permits `CAP_SYS_RESOURCE` to bypass hard limits. Opt-in startup drops that
capability from effective, permitted, inheritable and bounding sets **before
creating workers or async threads**. Dropping permitted also removes its ambient
eligibility. Root exec cannot reacquire it from the bounding set. Other required
host privileges remain unchanged. Library callers must call `drop_quota_bypass`
before creating threads; merely constructing a `ProjectQuota` never changes
privileges and refuses a caller retaining the bypass. Existing recorded worker
and VMM processes must also have clear effective/permitted/inheritable/bounding/
ambient sets for this capability. Unknown process observations refuse adoption;
processes are never killed to make the check pass.

The guard inventories at most 100,000 state entries at startup and before a new
compile/launch. Regular files must carry the project ID; directories must also
inherit it. It rejects symlinks, foreign devices/mounts and realtime flags. Unix
socket leaves are not opened and have no file payload; newly created sockets
inherit from their verified parents. Provisioning must cover pre-existing socket
inodes as well. Tree changes during a check can cause retryable refusal. This is
not protection from a privileged operator changing quota policy or writing into
the project using a separate bypass-capable process.

Admission applies its existing compiler, producer, free-byte and free-inode
headroom to the **remaining project quota** as well as each filesystem. Exhausted
headroom returns 507 before new work is allocated. Unverifiable/drifted quota
configuration returns 503. Existing idempotency receipts, status, stop, log
shipping/cleanup and accepted-work reconciliation stay available. The kernel's
hard limits independently constrain future writes by confined node descendants;
full storage can still prevent journal writes. Do not treat a quota as a recovery
reserve or proof that an operation finished.

Deployment remains opt-in pending fleet qualification. XFS, x86_64, interrupted
writes interrupted by process/host failure at capacity, live compiler/VMM workloads,
fleet recovery and large-inventory admission overhead still require evidence. Local
agent/log journal write failures at a full ext4 quota are qualified below. This
implementation does not close the platform's host-wide disk/recovery release gate.

## Disposable Linux qualification

Use a new disposable VM with no production disks. Install e2fsprogs and quota.
Inside that VM, create a new **fixture file** (never a host block device):

```sh
set -eu
test ! -e /var/tmp/fenders-quota.img
truncate -s 128M /var/tmp/fenders-quota.img
mkfs.ext4 -F -O quota,project -E quotatype=prjquota /var/tmp/fenders-quota.img
mkdir /mnt/fenders-quota
mount -o loop,prjquota /var/tmp/fenders-quota.img /mnt/fenders-quota
mkdir -m 700 /mnt/fenders-quota/state
chattr -p 123 +P /mnt/fenders-quota/state
setquota -P 123 0 4096 0 64 /mnt/fenders-quota
printf 'fenders-disposable-project-quota\n' > /mnt/fenders-quota/state/qualification-only
chmod 600 /mnt/fenders-quota/state/qualification-only
```

Execute sequentially as root and stop if any step fails. Build the Linux Rust
integration executable with `cargo test --locked -p fenders-node --test
project_quota --no-run`, copy it as `qualify-project-quota`, and run:

```sh
FENDERS_TEST_PROJECT_QUOTA_DIR=/mnt/fenders-quota/state \
  ./qualify-project-quota --ignored --nocapture
```

The marker and initially empty directory are mandatory. The fixture changes only
its own file project IDs/inheritance and fills its 4 MiB/64-inode quota. It first
requires refusal while root retains the bypass, drops it, then checks correct
inheritance, wrong project IDs, missing inheritance, symlinks and too-small
configured ceilings. Actual writes and inode creation must fail with `EDQUOT`;
a retained file stays intact and removing the payload restores byte headroom.
Keep failed fixtures for diagnosis and create a new filesystem for a repeat.

On 2026-10-09 this passed in a Debian 13 ARM64 VM, kernel
`6.12.111+deb13-cloud-arm64`, QEMU 11.0.0/HVF. The first attempt correctly exposed
root's bypass by exceeding the hard limit; it was retained. A second filesystem
passed after the implementation dropped the capability. A third fresh fixture
also proves that an exec child retains no quota-bypass capability. Its final test
executable SHA-256 is
`ebdff7a658acaec42d2e9d11b9b3f87b967ef01c02d4401439799f35cf757ae1`.
The VM used e2fsprogs `1.47.2-3+b12` and quota `4.09-1+b1`; it was shut down after
the test. All three filesystem fixtures are retained in the stopped disposable
`run/service-valkey-vm/quota.qcow2`, separate from the Valkey test disks.
Fifty-four native node/CLI cases, all-target Linux compilation and strict host
Clippy also pass. Logs are retained at
`/private/tmp/fenders-quota-{vm-assembly,vm-assembly2,vm-assembly3,vm-test,vm-test2,vm-test3,vm-environment,node-unit,linux-check,clippy}.log`.
This is real kernel quota evidence, not a mock or a full live node admission drill.

### Node admission against a real quota

The Linux-only library test
`core::disk_admission::tests::quota_vm::real_quota_admission_preserves_receipts_and_stop_while_refusing_new_work`
exercises production `Node` methods on a real project filesystem. Build it with
`cargo test --locked -p fenders-node --lib --no-run`. Use a **new** fixture created
as above, with these substitutions:

- A 2 GiB image and its own unassigned mount root.
- Project 123 hard limits of 1048576 KiB and 10000 inodes (both soft limits zero).
- A root-owned mode-0700 `state` directory with project inheritance and only a
  root-owned mode-0600 `qualification-only` marker containing
  `fenders-disposable-node-quota\n`.

Copy the library test executable into a disk-backed location in the disposable
VM; debug executables can exceed a small `/tmp` tmpfs. Run it as root:

```sh
FENDERS_TEST_NODE_QUOTA_DIR=/mnt/fenders-node-quota/state \
  ./qualify-node-quota \
  core::disk_admission::tests::quota_vm::real_quota_admission_preserves_receipts_and_stop_while_refusing_new_work \
  --ignored --exact --nocapture
```

The test allocates a real 768 MiB file to exhaust admission headroom. A cache-miss
upload and two concurrent launch requests return 507 without creating an artifact,
launch receipt, run directory or worker. Constructed durable receipts then verify
exact request retries, conflicting retry rejection, status reads and persistent
stop intent. Cached inspection remains readable. Increasing the fixture quota
above the configured ceiling returns 503 for new work while receipt retries and
stop requests remain usable. Restoring the limit and deleting only the filler
restores admission headroom. Reopening refuses a recorded producer that retains
`CAP_SYS_RESOURCE`, and accepts one spawned after removing that capability.

On 2026-10-09 the test passed on the same Debian 13 ARM64/kernel environment above.
The first admission fixture is retained after a fixture assertion failed:
`statvfs` inside a project directory reports quota-limited availability. The
corrected assertion checks filesystem capacity at the unassigned mount root.
A fresh second fixture passed, with test executable SHA-256
`61c338ff7f84ac45b30e27fa6f947daffe5c625eaa1ee0907ab9efaf5c9bd6d4`.
Both admission fixture files are retained in `quota.qcow2`; the VM was shut down.
Evidence is in `/private/tmp/fenders-quota-admission-{build,assembly2,live,live2,environment,native,clippy}.log`.
All 54 native node/CLI cases and strict host Clippy also passed.

This is actual filesystem pressure and actual node admission, with constructed
artifact metadata and durable receipts. It launches no compiler or VMM and does
not establish workload completion, stop completion, HTTP transport behavior or
recovery with completely full storage. The previous EDQUOT test separately proves
hard byte/inode enforcement; this test deliberately retains journal headroom.

### Journal recovery at the hard limit

The Linux-only library test
`core::disk_admission::tests::quota_vm::full_quota_preserves_agent_sequences_and_incomplete_capture_on_reopen`
uses the same library executable build. Create a fresh 128 MiB filesystem fixture
with project 123 hard limits of 4096 KiB and 10000 inodes, zero soft limits, and
the same root ownership, permissions and inheritance as above. Its marker must
contain `fenders-disposable-quota-recovery\n`. Execute as root:

```sh
FENDERS_TEST_QUOTA_RECOVERY_DIR=/mnt/fenders-quota-recovery/state \
  ./qualify-node-quota-recovery \
  core::disk_admission::tests::quota_vm::full_quota_preserves_agent_sequences_and_incomplete_capture_on_reopen \
  --ignored --exact --nocapture
```

This test constructs accepted node receipts and agent assignments, then uses real
`Agent::reports`, `Capture` and `Node` methods. It commits initial reports and
output before filling the project with allocated blocks until the kernel returns
`EDQUOT`. A checkpointed, truncated agent WAL ensures the next report transaction
needs real storage allocation. At the hard limit:

- Report generation fails without advancing either assignment's sequence,
  generation, backend identity, archive state or action receipt.
- Log append fails without changing committed records, capture identity, sequence
  or total bytes. The failed capture remains open, not successfully completed.
- The existing launch receipt still resolves. A stop request that cannot persist
  its intent returns an error and leaves the run pending.
- After dropping the capture writer, interrupted sealing also fails without
  changing its identity, content or cursor while space is unavailable.

The test removes **only its filler file**, closes/reopens the agent, and verifies
that the next reports advance exactly once from the last committed sequence.
Both accepted launch receipts survive. Stop intent can now be persisted, but the
test never calls that stop completion. Sealing recovers the original log records
with `interrupted=true`; this records lost capture continuity rather than claiming
that all output was captured. No worker is launched or automatically replayed.

This passed on 2026-10-09 in the Debian 13 ARM64 VM described above. The executable
SHA-256 is `4f80f2559383caa27f30c95365336d2b06459d49d45f23b3a2285559ef6b3bb2`.
All 54 native node/CLI regressions and strict host Clippy also passed; the Linux
test executable built without warnings. Evidence is in
`/private/tmp/fenders-quota-recovery-{assembly,build,live,environment,native,clippy}.log`.
The fixture remains in the stopped disposable `quota.qcow2`.

This qualifies real synchronous quota failure and object/connection reopening,
not process termination midway through a write, host power loss, inode exhaustion
during journal updates, a completely full host filesystem or live VMM shutdown.
No API/network peer is contacted. Recovery here requires an operator to recover
headroom safely; automatic deletion of uncertain-owned data or an emergency
reserve is not implemented or implied. The host-wide recovery release gate remains
open.
