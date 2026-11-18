# Rust control-plane service

[`fenders-control-plane.service`](fenders-control-plane.service) supervises the
Rust API, scheduler and TLS gateway on a Linux
systemd host. It does not run WASM in a Linux guest or install a node agent.

## Install

Build the binary for the host architecture with the repository lockfile:

```sh
cargo build --release --locked -p fenders-control-plane --bin fenders-control-plane
sudo install -o root -g root -m 0755 target/release/fenders-control-plane /usr/local/bin/
sudo install -d -o root -g root -m 0755 /etc/sysusers.d
sudo install -o root -g root -m 0644 deploy/systemd/fenders-control.conf /etc/sysusers.d/
sudo systemd-sysusers /etc/sysusers.d/fenders-control.conf
sudo install -d -o root -g fenders-control -m 0750 /etc/fenders/control
sudo install -o root -g root -m 0644 deploy/systemd/fenders-control-plane.service /etc/systemd/system/
```

Prepare these files before starting. Keep original signing keys off the daemon
host. [Embedding the API](../../docs/EMBEDDING-API.md) shows certificates, node
enrollment and the listeners on one machine.

| File under `/etc/fenders/control/` | Content | Owner and mode |
|---|---|---|
| `environment` | `FENDERS_APP_DOMAIN=apps.example.test`, replaced with the actual application domain, and `FENDERS_RUN_CHANNEL_ENDPOINT=https://control.internal:9093`, the name and port at which nodes reach this host's run channel (a name `control.pem` is valid for) | `root:root`, `0600` |
| `database-url` | PostgreSQL URL, optionally followed by a newline | `root:root`, `0600` |
| `ca.pem` | Trusted platform CA certificate | `root:fenders-control`, `0640` |
| `control.pem` | Management/internal listener certificate | `root:fenders-control`, `0640` |
| `gateway.pem` | Certificate matching application hostnames | `root:fenders-control`, `0640` |
| `control.key`, `gateway.key` | Corresponding private keys | `root:root`, `0600` |
| `external-network.json` | Operator-approved IPv4 destination ranges; `{"allowed_cidrs":[],"denied_cidrs":[]}` denies all external TCP destinations | `root:fenders-control`, `0640` |

The environment file contains no passwords. systemd copies the three private
credentials into a per-service credential directory; the daemon receives paths,
not their values in arguments or its environment. `--database-url-file` takes
precedence over `FENDERS_DATABASE_URL`. An unreadable, empty, non-UTF-8, NUL-containing
or larger-than-8192-byte file refuses startup without falling back to the
environment. URL parsing/database connection remain the existing Store behavior.
Without the flag, existing environment-based launches remain supported.

The unit opens TLS listeners on ports 9090 (management), 9091 (mutually authenticated
internal API), 9092 (application gateway) and 9093 (the run channel: each run's
shim calls it with its launch's credential and no client certificate; nodes must
reach it). Configure host/firewall ingress and
DNS for the intended deployment. `network-online.target` ordering does not establish
PostgreSQL readiness. No provider credentials are used. The database role needs schema-creation and runtime permissions. Use a fresh
database and state directory for the WASM-only schema; legacy managed-service
databases are rejected without modification. Schema initialization executes at startup; this unit does not
qualify concurrent mixed-version upgrades.

To allow an external TCP destination, add its IPv4 `/32` address or an explicitly
approved range to `allowed_cidrs`. Keep platform management addresses outside these
ranges; `denied_cidrs` takes precedence. Loopback, link-local and multicast addresses
remain prohibited. Registration resolves the hostname once and pins the selected
address. Workers receive short-lived revocable access only after an app explicitly
selects the endpoint. The WASM client implements the application protocol and, when
using TLS, verifies the hostname and CA. Changing a destination requires registering and connecting a
replacement endpoint. The policy file is read on control-plane startup.

For customer-selected Internet destinations, use
[`external-network-public.json`](external-network-public.json) instead of an
empty allowlist. It permits ordinary public IPv4 addresses and denies private,
shared, loopback, link-local, documentation, benchmark, deprecated relay,
multicast and reserved ranges. The conservative exclusions follow the
[IANA special-purpose registry](https://www.iana.org/assignments/iana-ipv4-special-registry/);
the entire `192.0.0.0/24` protocol-assignment block is excluded, including its
public exceptions. Add any platform-owned public control-plane/worker addresses
to `denied_cidrs` before use, and to `denied_ipv4` of the `--public-egress`
configuration as well: HTTPS origins are checked against that list, not this
one. Denials override allows; IPv6 is not supported here.
This policy controls new registrations, not retroactive revocation of existing
pinned endpoints. Revoke existing app connections explicitly when removing access.

For a customer deployment, extend `ExecStart` with `--browser-auth` and the existing
OIDC configuration; add `--public-egress` when permitting HTTPS destinations.
Use `systemctl edit --full fenders-control-plane.service` to preserve the complete
command and append those explicit flags. Keep configuration read-only to the
service and readable by its group, and review local changes when updating the
shipped unit. The base unit does not enable customer sign-in or outbound access
implicitly. See [browser identity](../../crates/fenders-control-plane/static/customer/README.md#configure-sign-in) for the configuration
contract. No shell wrapper or arbitrary command fragment is executed.

```sh
sudo systemd-analyze verify /etc/systemd/system/fenders-control-plane.service
sudo systemctl daemon-reload
sudo systemctl enable --now fenders-control-plane.service
sudo systemctl status fenders-control-plane.service
```

The first start creates private state under `/var/lib/fenders/control`, owned by
the dedicated `fenders-control` system account. Preserve its encryption keys and
operator credential together with the database and documented backup/recovery
protocol. When moving an existing installation, stop it first and retain its
exact state/database pairing; a fresh directory is not a migration. Do not erase
state to repair a failed start. Backup/restore tools are separate operator commands,
not privileged subprocesses added to this service.

## Restart and shutdown contract

Defaults are five start attempts per 60 seconds and a five-second delay after
failure. Unexpected daemon exit, including detected background-loop termination,
requests a restart. Ordinary reconciliation errors remain handled inside the
daemon and are visible in the operator status endpoint. After the start limit is
hit, the unit stays failed until an operator or external automation requests a
new start; it does not automatically retry when the window expires.

After diagnosing and repairing the cause:

```sh
sudo journalctl -u fenders-control-plane.service --since '-10 minutes'
sudo systemctl reset-failed fenders-control-plane.service
sudo systemctl start fenders-control-plane.service
```

An explicit `systemctl stop` sends SIGTERM and suppresses automatic restart.
The TLS management, internal and gateway listeners stop accepting together, then
finish their accepted connections. Each retains its existing 10-second TLS
handshake and 80-second connection deadline; draining does not extend either.
All three listeners must finish before the daemon exits, and background loops
remain active during this drain. Remove the retiring instance from traffic and
route new requests to a ready replacement before sending SIGTERM. There is no
automatic replay of interrupted HTTP requests.

The whole service cgroup is killed after a 100-second stop deadline if it has not
exited, leaving room beyond the combined 90-second connection bound. This does
not qualify mixed-version rolling upgrades or preservation of arbitrary external
work. Durable journals, generation fences, recovery barriers and uncertain
reservations remain authoritative after interruption. Restart is not permission
to replay side effects, clear claims or release resources. There is no `ExecStop`
cleanup script. Controlled restart rereads configuration and credentials; no
reload or automatic certificate rotation is claimed.

`Type=exec` confirms execution of the binary, not completion of migrations or API
readiness. Check certificate-verified, authorized API observations separately.
`GET /v1/control-plane/status` reports loop activity, not fleet readiness or
independent liveness during database outage. Do not set a watchdog from successful
empty iterations. Alerting, capacity limits and production readiness remain W11
work.

The account has no capabilities or privilege escalation, a read-only system
filesystem, private temporary/device directories, protected kernel/cgroup settings,
restricted namespaces/address families and no writable executable memory. Only
the private state and temporary/credential mounts are available as appropriate.
These settings constrain the control plane; they do not replace node confinement,
network policy or tenant authorization. Compute/memory/task ceilings require
capacity qualification and are deliberately not guessed here.

Semantics are based on the systemd 257 upstream documentation for
[service execution/restarts](https://github.com/systemd/systemd/blob/v257/man/systemd.service.xml),
[credentials and confinement](https://github.com/systemd/systemd/blob/v257/man/systemd.exec.xml),
and [start limits](https://github.com/systemd/systemd/blob/v257/man/systemd.unit.xml).
Qualify the target distribution; do not suppress unknown directives.

## Rolling control-plane updates

The mixed-version check of 20 October 2026, made before the shim model,
used production A `9d4d78c` and B `7183a72`, a real worker and kernel-free WASM
executions. Both exact-source package/install/image gates pass. Schedules,
stateful PostgreSQL TLS, native renewal acknowledgments, two-tenant quotas/logs
and revocation pass through upgrade and rollback. The test front door forwards
TCP bytes; it supplies no production load
balancer. An operator must provide stable management, internal and gateway
endpoints with the same connection-preservation behavior. This is a declared
release overlap, not permission to mix arbitrary binaries or database revisions.

1. Install each verified binary at an immutable release path. Both replicas use
   the same authoritative PostgreSQL database, state/blob directory, encryption
   key, domain, authentication configuration and network policies. Copying only
   the database or starting with a new local state directory cannot preserve
   this pairing. Keep the existing recovery/key-rotation barriers in force.
2. Give each replica a separate service and three backend listener ports. Copy
   the maintained unit for B, preserving its account, credentials, state directory,
   confinement and 100-second stop deadline. Change its binary path and ports in
   the complete `ExecStart`; retain all configured browser/onboarding/email/egress
   flags. For example, A can retain 9090/9091/9092 and B use
   19090/19091/19092. Verify both units before starting B. Starting B runs pending
   migrations inside the existing database mutation lock. B records the frozen
   WASM-only baseline in `control_schema_migrations`; subsequent B startups check
   its checksum and skip applied DDL. Unknown or modified history refuses startup.
   Key identity and recovery checks still execute on every startup/transaction.
   Current source appends HTTP-run metadata as migration 2, retaining the exact
   migration-1 receipt. A binary supporting only version 1 refuses version 2;
   the pinned A/B acceptance does not qualify that additional rollback
   window. Keep rollback targets within their declared schema support.
3. Start B while A serves. Check B directly using a certificate-covered address
   and the Rust CLI's credential-file option, for example:

   ```sh
   sudo fendersctl --url https://control.internal:19090 \
     --ca /etc/fenders/control/ca.pem \
     --token-file /var/lib/fenders/control/operator.token \
     request GET /v1/control-plane/status
   ```

   Use the actual certificate name and port. Require progressing scheduler
   observations without failures, verify shared artifact access, and check all
   listener/TLS configurations. An open port or `Type=exec` alone is insufficient.
4. Move new connections for each stable endpoint to B. The front door must keep
   existing connections attached to A through completion and forward internal
   TLS without bypassing worker certificate/name/pin checks. The qualified flow
   retains the same service leaf and CA on both replicas, so workers keep their
   existing URL and pin. Certificate rotation or a new pin needs its own qualified
   trust transition. Exercise the designated app through the gateway and verify
   worker observations continue through B.
5. Stop A only after it is removed from new traffic. SIGTERM closes admission on
   all its TLS listeners, then drains accepted connections within their original
   10-second handshake / 80-second connection bounds. Background supervision
   stays alive until draining ends. Do not replay ambiguous HTTP requests at the
   front door. Durable command work remains assigned to the existing worker;
   overlapping controllers use the existing transaction locks and receipts.
6. For binary rollback, start the qualified A binary against the **current**
   database/state, verify readiness, move new traffic back and drain B. Retain
   B's migration history and all operation/generation state. Database restore is
   not a binary rollback: it can rewind receipts and repeat external effects.
   Re-upgrading B must retain the same migration receipt. Future schema changes
   must append immutable migrations and qualify their reader/rollback window;
   editing the frozen baseline is refused by its checksum.

The live test verifies an already dispatched gateway request during each
A→B→A→B retirement, a new request through the replacement, advancing worker
heartbeats, unchanged VM identities/configuration, one explicit command start and
completion, and recovered operation receipts. It does not qualify control-host
loss, SMTP exactly-once delivery, identity rotation, cross-host blob storage or
live migration. SMTP retains its documented at-least-once uncertain-outcome
semantics. [docs/STATUS.md](../../docs/STATUS.md) states what is qualified today.

## Disposable Linux qualification

The ignored Rust integration test [`tests/systemd.rs`](../../crates/fenders-control-plane/tests/systemd.rs)
requires a fresh disposable Linux VM with systemd PID 1, PostgreSQL, `timeout`,
`nsenter`, `runuser`, `touch` and root access. It refuses an existing configuration,
state directory, loaded unit or populated fixture database. It installs the exact
embedded unit and sysusers file, generates private fixture certificates and leaves
evidence/state intact with the service stopped. Never install the marker or test
executable on a production host.

Build on Linux for the guest architecture:

```sh
cargo build --locked -p fenders-control-plane --bin fenders-control-plane
cargo test --locked -p fenders-control-plane --test systemd --no-run
```

Install the daemon in `/usr/local/bin/fenders-control-plane` and the emitted test
executable as `/usr/local/bin/qualify-systemd`, root-owned mode 0755. In the guest,
create the empty fixture database and a peer-authenticated role (the test creates
the matching OS account):

```sh
sudo -u postgres createuser fenders-control
sudo -u postgres createdb --owner=fenders-control fenders_systemd
sudo sh -c 'umask 077; printf "%s\n" disposable-control-plane-systemd-only > /etc/fenders-control-qualification'
sudo timeout --signal=KILL 180s /usr/local/bin/qualify-systemd \
  systemd_restart_shutdown_and_confinement --ignored --exact --nocapture
```

The test uses local PostgreSQL peer authentication and real certificate-verified
HTTPS with the WASM scheduler loop. It inspects the actual process UID,
capabilities, no-new-privileges, seccomp and credential exposure; attempts filesystem
writes in its mount namespace; kills the process and observes a fresh instance
with retained authentication; verifies clean stop and no restart; exercises the
unaltered restart limit with an invalid credential; repairs it and verifies
explicit recovery. Public evidence is `/root/fenders-systemd-evidence.json`.
Fixture signing keys, database credentials and state remain private. Diagnose and
retain failed runs; once fixture installation begins, repeat from a new disposable
disk/database. A prerequisite failure before any fixture write can be corrected
and retried while all fresh-installation guards still pass.

This is control-plane service-manager qualification. It does not qualify actual
workloads interrupted during shutdown, OS reboot,
multi-host failover, resource-pressure behavior or production identity/TLS rotation.

Recorded qualification, 2026-10-11: the complete fixture passed in 46.82 seconds
on a disposable Debian 13 ARM64 VM with systemd 257.13 and PostgreSQL 17.11.
The credential unit test, real HTTP/TLS daemon regression and strict Linux Clippy
also passed.
