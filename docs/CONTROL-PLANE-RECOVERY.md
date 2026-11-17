# Control-plane backup and recovery

These Rust tools preserve the WASM control database, referenced component bytes
and encryption key together. They do not back up external PostgreSQL contents,
WASM memory or host processes. The external database operator owns its backups.
Use the same Fenders source version and the `wasm-only-v1` schema for restoration;
legacy managed-service archives have no compatibility migration in this MVP.

## Create an archive

Install compatible PostgreSQL `pg_dump`, `pg_restore` and `psql` tools on the
operator host. Supply the dedicated database URL through `FENDERS_DATABASE_URL`
and use the private state directory belonging to that database. Keep archive
keys separately from backups and retain a protected copy outside the host.

```sh
target/release/fenders-backup key --output /secure/fenders-backup.key
target/release/fenders-backup create \
  --state /srv/fenders/control \
  --key-file /secure/fenders-backup.key \
  --output /backups/fenders.fnd
```

Key and archive creation refuse existing destinations. The result records the
archive identity, size and checksum. Verify the copied archive off-host and
exercise restoration; copying a file alone does not prove recovery.

Creation holds the admission lock, exports a consistent PostgreSQL snapshot,
validates the encryption key and referenced artifact hashes, and stages the
matching state and dump. Running apps are not frozen. Mutations may time out;
recover their original receipts before retrying with the same idempotency key.
Private staging contains plaintext: use an encrypted operator disk and protected
temporary storage. Cleanup is not a secure-erasure guarantee.

Published archives use authenticated AES-GCM chunks with a per-archive derived
key, sequence numbers and final marker. Restore rejects corrupt, reordered or
truncated chunks, trailing data, path escapes, links, duplicate entries and
manifest hash mismatches. The default payload ceiling is 100 GiB and can be
lowered with `--limit-bytes`. WAL/PITR, off-host replication and retention policy
remain the operator's responsibility.

## Restore into isolation

Keep the recovery API, gateway and agents offline. Create an empty dedicated
target database and choose a new state directory under a private operator-owned
parent. Do not restore into a live database or overwrite an existing state path.
For non-default schemas retain the source `search_path` connection option.

Point `FENDERS_DATABASE_URL` at the target, then run:

```sh
target/release/fenders-backup restore \
  --state /srv/fenders/recovered-control \
  --key-file /secure/fenders-backup.key \
  --backup /backups/fenders.fnd
```

Check the backup ID and `mode: fenced`. Database restoration and fencing commit
in one transaction. Old API credentials are revoked, browser sessions/logins are
removed, nodes are disabled and draining, and apps/deployments are stopped.
Reserved executions become unreachable with advanced generations and retain
quota. Pending operations fail explicitly; commands are never replayed.
HTTP serving and scheduled dispatch are disabled. Public HTTPS policy is disabled
and old execution bindings are fenced. Endpoint metadata and encrypted database
credentials survive; restoring them does not authorize a running old worker.

Start only a private recovery API using the matching database/state pair. Bootstrap
creates a new operator credential. Read-only inspection works; scheduling,
heartbeats and other mutations remain barred. The archive contains the database
secret key, and restoring it executes trusted operator SQL. This is not a customer
upload endpoint for arbitrary archives.

If restoration fails before the SQL transaction commits, the target remains
empty. If commit succeeds but state publication fails, the database remains
fenced and a private `.restore-ID` sibling retains staged state and `restore.json`.
Inspect that marker and the database recovery barrier. Do not create a replacement
key, delete staged files or activate until the matching state is recovered and
verified. Use one recovery operator at a time.

## Fence old workers before activation

A snapshot predates external reality. Stop or externally isolate the old API and
all old WASM workers, including work created after the snapshot. A heartbeat
timeout is insufficient. Use verified process/cgroup termination with agent
restart disabled, or host power fencing. Revoke old host identities. Reconcile
external application side effects separately; control-plane recovery cannot undo
writes made to an external PostgreSQL server.

Only after that work is complete:

```sh
target/release/fenders-backup activate --external-resources-fenced
```

This flag records an operator assertion; it does not stop hosts or prove fencing.
Activation marks former reserved executions lost, releases their compute holds
and clears the global mutation barrier. Nodes remain disabled. Known outstanding
outbound grants are conservatively settled in their original admission month;
missing counters do not imply unused credit. Revocations finish under the external
fencing assertion without fabricating worker acknowledgments. Activation cannot
reconstruct traffic or work admitted after the backup.

Re-enroll clean hosts with new identities, preserve old records, explicitly approve
network policy and admit new work. Deployment/start must not invoke a command.
There is no memory/checkpoint continuation or automatic side-effect replay.

## Rotate the control-plane encryption key

Stop all control-plane processes and take a verified backup first. Run as the
account owning the private state directory:

```sh
target/release/fenders-keys generate --output /secure/fenders-control-next.key
target/release/fenders-keys rotate \
  --state /srv/fenders/control \
  --new-key-file /secure/fenders-control-next.key \
  --services-stopped
```

Here `services-stopped` means the control-plane processes, not managed databases.
Rotation covers project secrets, browser CSRF values and pending OIDC nonce/PKCE
values. It preserves plaintext and resource identities; it does not change the
external database password, certificates, host identities or archive encryption key.
A failed database transaction rolls back the complete inventory.

The database commits the new key fingerprint before atomic key-file publication.
If interrupted, repeat the same command with the same new key file. It completes
publication without re-encrypting committed data. Never generate a different key
to recover that state or delete the committed key. Stale processes fail closed;
restart all processes with the published key and verify a fresh archive. Older
archives still require their original archive keys.

## Evidence and limits

The [Rust restore test](../crates/fenders-control-plane/tests/tls_and_backup.rs)
uses disposable real PostgreSQL databases. It checks artifact/secret preservation,
credential revocation, execution/history fences and explicit activation, plus
TLS and archive-integrity failures. Its database role needs `CREATEDB`; worker
observations are protocol fixtures. It does not establish live host-loss recovery.
[STATUS.md](STATUS.md) records current qualification.
