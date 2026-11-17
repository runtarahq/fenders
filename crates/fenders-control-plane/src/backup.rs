//! Encrypted control-plane archives, preserving the existing chunked format.
//! External database contents and guest memory are outside this archive's scope.
pub(crate) mod stream;
use crate::{
    error::{Error, Result},
    model::{identity, uid},
    pki::private_file,
};
use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{Connection, Row};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{Read, Write},
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};
pub const MAGIC: &[u8] = b"FENDERS-BACKUP\x01";
pub const CHUNK: usize = 1024 * 1024;
pub const DEFAULT_LIMIT: u64 = 100 * 1024 * 1024 * 1024;
fn invalid() -> Error {
    Error::invalid("invalid or incomplete backup archive")
}
fn schema_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && s.as_bytes()[0].is_ascii_lowercase()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}
fn hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn key(path: &Path) -> Result<[u8; 32]> {
    fs::read(path)?
        .try_into()
        .map_err(|_| Error::invalid("backup key must contain exactly 32 bytes"))
}
pub fn random_key(path: &Path) -> Result<()> {
    let mut bytes = [0; 32];
    fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(private_file(path, &bytes)?)
}
pub fn checksum(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path)?;
    let mut digest = Sha256::new();
    let mut bytes = [0; CHUNK];
    loop {
        let count = file.read(&mut bytes)?;
        if count == 0 {
            break;
        }
        digest.update(&bytes[..count]);
    }
    Ok(format!("{:x}", digest.finalize()))
}
fn cipher(key: &[u8; 32], salt: &[u8]) -> Result<Aes256Gcm> {
    let mut derived = [0; 32];
    Hkdf::<Sha256>::new(Some(salt), key)
        .expand(MAGIC, &mut derived)
        .map_err(|_| Error::internal())?;
    let cipher = Aes256Gcm::new_from_slice(&derived).map_err(|_| Error::internal())?;
    derived.fill(0);
    Ok(cipher)
}
pub fn encrypt(source: &Path, destination: &Path, key: &[u8; 32]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut source = fs::File::open(source)?;
    let out = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(destination)?;
    let mut encrypted = stream::EncryptWriter::new(out, key, u64::MAX)?;
    std::io::copy(&mut source, &mut encrypted)?;
    let (out, _, _) = encrypted.finish()?;
    out.sync_all()?;
    Ok(())
}

pub fn decrypt(source: &Path, destination: &Path, key: &[u8; 32], limit: u64) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let source = fs::File::open(source)?;
    let mut out = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(destination)?;
    let mut reader = stream::DecryptReader::new(source, key, limit).map_err(|_| invalid())?;
    std::io::copy(&mut reader, &mut out).map_err(|_| invalid())?;
    reader.finish().map_err(|_| invalid())?;
    out.sync_all()?;
    Ok(())
}

fn pg_environment(dsn: &str) -> Result<BTreeMap<String, String>> {
    let url = url::Url::parse(dsn)
        .map_err(|_| Error::invalid("PostgreSQL URL required for backup tools"))?;
    if !matches!(url.scheme(), "postgres" | "postgresql") {
        return Err(Error::invalid("PostgreSQL URL required"));
    }
    fn decode(value: &str) -> Result<String> {
        let encoded = format!("v={}", value.replace('+', "%2B"));
        url::form_urlencoded::parse(encoded.as_bytes())
            .next()
            .map(|(_, v)| v.into_owned())
            .ok_or_else(invalid)
    }
    let mut env = BTreeMap::from([
        ("PGCONNECT_TIMEOUT".to_owned(), "10".to_owned()),
        (
            "PGHOST".to_owned(),
            url.host_str().unwrap_or("localhost").to_owned(),
        ),
        ("PGPORT".to_owned(), url.port().unwrap_or(5432).to_string()),
        (
            "PGDATABASE".to_owned(),
            decode(url.path().trim_start_matches('/'))?,
        ),
        ("PGUSER".to_owned(), decode(url.username())?),
    ]);
    if let Some(password) = url.password() {
        env.insert("PGPASSWORD".to_owned(), decode(password)?);
    }
    for (key, value) in url.query_pairs() {
        let var = match key.as_ref() {
            "host" => "PGHOST",
            "sslmode" => "PGSSLMODE",
            "sslrootcert" => "PGSSLROOTCERT",
            "sslcert" => "PGSSLCERT",
            "sslkey" => "PGSSLKEY",
            "options" => "PGOPTIONS",
            "application_name" => "PGAPPNAME",
            "connect_timeout" => "PGCONNECT_TIMEOUT",
            _ => {
                return Err(Error::invalid(
                    "unsupported PostgreSQL tool connection option",
                ));
            }
        };
        env.insert(var.to_owned(), value.into_owned());
    }
    Ok(env)
}
fn pg_command(program: &str, args: &[String], dsn: &str) -> Result<()> {
    let mut command = Command::new(program);
    command
        .args(args)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .envs(pg_environment(dsn)?)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = command.spawn()?;
    let deadline = Instant::now() + Duration::from_secs(600);
    loop {
        if let Some(status) = child.try_wait()? {
            if status.success() {
                return Ok(());
            }
            return Err(Error::internal());
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(Error::internal());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn copy(source: &Path, dest: &Path) -> Result<()> {
    if !fs::symlink_metadata(source)?.file_type().is_file() {
        return Err(invalid());
    }
    fs::create_dir_all(dest.parent().ok_or_else(invalid)?)?;
    use std::os::unix::fs::OpenOptionsExt;
    let mut out = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(dest)?;
    std::io::copy(&mut fs::File::open(source)?, &mut out)?;
    out.sync_all()?;
    Ok(())
}
pub async fn create(
    dsn: &str,
    state: &Path,
    output: &Path,
    key_path: &Path,
    limit: u64,
) -> Result<Value> {
    if limit == 0 || output.try_exists()? {
        return Err(Error::invalid(
            "backup requires a new output and positive size limit",
        ));
    }
    let key = key(key_path)?;
    let encryption_key = crate::key_rotation::read_key(&state.join("encryption.key"))?;
    let cipher = fernet::Fernet::new(&encryption_key).ok_or_else(invalid)?;
    let temporary = tempfile::tempdir()?;
    let payload = temporary.path().join("payload");
    fs::create_dir(&payload)?;
    let mut connection = sqlx::PgConnection::connect(dsn).await?;
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock(184923781)")
            .fetch_one(&mut connection)
            .await?;
        if acquired {
            break;
        }
        if Instant::now() > deadline {
            return Err(Error::invalid(
                "admission did not quiesce before backup deadline",
            ));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let mut tx = connection.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *tx)
        .await?;
    if sqlx::query_scalar::<_, bool>("SELECT active FROM recovery_barrier WHERE singleton")
        .fetch_one(&mut *tx)
        .await?
    {
        return Err(Error::invalid(
            "activate restored control plane before backup",
        ));
    }
    let row = sqlx::query(
        "SELECT pg_export_snapshot() snapshot,current_schema() schema,now()::text created",
    )
    .fetch_one(&mut *tx)
    .await?;
    let snapshot: String = row.try_get("snapshot")?;
    let schema: String = row.try_get("schema")?;
    let created: String = row.try_get("created")?;
    if !schema_ok(&schema) {
        return Err(invalid());
    }
    let barrier: Value =
        sqlx::query_scalar("SELECT to_jsonb(b) FROM recovery_barrier b WHERE singleton")
            .fetch_one(&mut *tx)
            .await?;
    crate::key_rotation::check_identity(&barrier, &crate::model::digest(&encryption_key))?;
    crate::key_rotation::validate_or_reencrypt(&mut tx, &cipher, None).await?;
    let mut sources = BTreeMap::from([(
        "state/encryption.key".to_owned(),
        state.join("encryption.key"),
    )]);
    for digest in sqlx::query_scalar::<_, String>(
        "SELECT DISTINCT digest FROM artifacts WHERE to_jsonb(artifacts)->>'retired_at' IS NULL",
    )
    .fetch_all(&mut *tx)
    .await?
    {
        if !hex(&digest, 64) {
            return Err(invalid());
        }
        let path = state.join("blobs").join(&digest);
        if checksum(&path)? != digest {
            return Err(invalid());
        }
        sources.insert(format!("state/blobs/{digest}"), path);
    }
    let mut total = 0u64;
    for (relative, source) in &sources {
        total = total
            .checked_add(fs::metadata(source)?.len())
            .ok_or_else(invalid)?;
        if total > limit {
            return Err(invalid());
        }
        copy(source, &payload.join(relative))?;
    }
    pg_command(
        "pg_dump",
        &[
            "--format=custom".into(),
            "--compress=0".into(),
            "--no-owner".into(),
            "--no-acl".into(),
            format!("--schema={schema}"),
            format!("--snapshot={snapshot}"),
            format!("--file={}", payload.join("database.dump").display()),
        ],
        dsn,
    )?;
    tx.commit().await?;
    connection.close().await?;
    let mut files = serde_json::Map::new();
    let mut relative: Vec<_> = sources.into_keys().collect();
    relative.push("database.dump".to_owned());
    let mut total = 0u64;
    for name in &relative {
        let path = payload.join(name);
        let size = fs::metadata(&path)?.len();
        total = total.checked_add(size).ok_or_else(invalid)?;
        if total > limit {
            return Err(invalid());
        }
        files.insert(
            name.clone(),
            json!({"bytes":size,"sha256":checksum(&path)?}),
        );
    }
    let id = uid();
    let manifest = json!({"format":1,"id":id,"created":created,"schema":schema,"files":files,"scope":"control-plane metadata, secrets and referenced WASM blobs; no VM memory or external database contents"});
    private_file(
        &payload.join("manifest.json"),
        &serde_json::to_vec(&manifest).unwrap(),
    )?;
    relative.insert(0, "manifest.json".to_owned());
    let archive = temporary.path().join("plain.tar");
    let mut tar = tar::Builder::new(fs::File::create(&archive)?);
    for name in &relative {
        let path = payload.join(name);
        let mut header = tar::Header::new_ustar();
        header.set_size(fs::metadata(&path)?.len());
        header.set_mode(0o600);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        tar.append_data(&mut header, name, fs::File::open(path)?)?;
    }
    tar.finish()?;
    drop(tar);
    let parent = output.parent().ok_or_else(invalid)?;
    fs::create_dir_all(parent)?;
    let staged = parent.join(format!(".backup-{}", uid()));
    let result = (|| {
        encrypt(&archive, &staged, &key)?;
        fs::hard_link(&staged, output)?;
        fs::File::open(parent)?.sync_all()?;
        Ok(
            json!({"id":id,"path":output,"bytes":fs::metadata(output)?.len(),"sha256":checksum(output)?,"files":files.len()}),
        )
    })();
    let _ = fs::remove_file(staged);
    result
}
fn safe_member(name: &str) -> bool {
    if !name.is_ascii() {
        return false;
    }
    if matches!(
        name,
        "manifest.json" | "database.dump" | "state/encryption.key"
    ) {
        return true;
    }
    let parts: Vec<_> = name.split('/').collect();
    if let ["state", "blobs", digest] = parts.as_slice() {
        return hex(digest, 64);
    }
    false
}
fn unpack(archive: &Path, dest: &Path, limit: u64) -> Result<Value> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut tar = tar::Archive::new(fs::File::open(archive)?);
    let mut seen = BTreeSet::new();
    let mut total = 0u64;
    for member in tar.entries()? {
        let mut member = member?;
        let name = member.path()?.to_str().ok_or_else(invalid)?.to_owned();
        let size = member.size();
        if !member.header().entry_type().is_file()
            || !safe_member(&name)
            || !seen.insert(name.clone())
        {
            return Err(invalid());
        }
        total = total.checked_add(size).ok_or_else(invalid)?;
        if total > limit || name == "manifest.json" && size > 4 * CHUNK as u64 {
            return Err(invalid());
        }
        let path = dest.join(&name);
        fs::create_dir_all(path.parent().unwrap())?;
        let mut out = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        if std::io::copy(&mut member, &mut out)? != size {
            return Err(invalid());
        }
        out.sync_all()?;
    }
    for name in ["manifest.json", "database.dump", "state/encryption.key"] {
        if !seen.contains(name) {
            return Err(invalid());
        }
    }
    let manifest: Value =
        serde_json::from_slice(&fs::read(dest.join("manifest.json"))?).map_err(|_| invalid())?;
    if manifest["format"] != 1 || !schema_ok(manifest["schema"].as_str().unwrap_or("")) {
        return Err(invalid());
    }
    identity(manifest["id"].as_str().ok_or_else(invalid)?)?;
    let files = manifest["files"].as_object().ok_or_else(invalid)?;
    seen.remove("manifest.json");
    if files.keys().cloned().collect::<BTreeSet<_>>() != seen {
        return Err(invalid());
    }
    for (name, expected) in files {
        let path = dest.join(name);
        if Some(fs::metadata(&path)?.len()) != expected["bytes"].as_u64()
            || checksum(&path)? != expected["sha256"]
        {
            return Err(invalid());
        }
    }
    fernet::Fernet::new(fs::read_to_string(dest.join("state/encryption.key"))?.trim())
        .ok_or_else(invalid)?;
    Ok(manifest)
}
async fn empty_database(dsn: &str) -> Result<()> {
    let mut db = sqlx::PgConnection::connect(dsn).await?;
    for query in [
        "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON c.relnamespace=n.oid WHERE n.nspname !~ '^pg_' AND n.nspname<>'information_schema'",
        "SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON p.pronamespace=n.oid WHERE n.nspname !~ '^pg_' AND n.nspname<>'information_schema'",
    ] {
        if sqlx::query_scalar::<_, i64>(query)
            .fetch_one(&mut db)
            .await?
            != 0
        {
            return Err(Error::invalid(
                "restore requires an empty dedicated database",
            ));
        }
    }
    Ok(())
}
pub async fn restore(
    dsn: &str,
    state: &Path,
    backup: &Path,
    key_path: &Path,
    limit: u64,
) -> Result<Value> {
    if limit == 0 || state.symlink_metadata().is_ok() {
        return Err(Error::invalid(
            "restore requires a new state directory and positive limit",
        ));
    }
    empty_database(dsn).await?;
    let temporary = tempfile::tempdir()?;
    let archive = temporary.path().join("plain.tar");
    decrypt(
        backup,
        &archive,
        &key(key_path)?,
        limit.checked_add(16 * CHUNK as u64).ok_or_else(invalid)?,
    )?;
    let payload = temporary.path().join("payload");
    fs::create_dir(&payload)?;
    let manifest = unpack(&archive, &payload, limit)?;
    let schema = manifest["schema"].as_str().unwrap();
    let id = manifest["id"].as_str().unwrap();
    let sql = temporary.path().join("database.sql");
    pg_command(
        "pg_restore",
        &[
            "--no-owner".into(),
            "--no-acl".into(),
            format!("--file={}", sql.display()),
            payload.join("database.dump").display().to_string(),
        ],
        dsn,
    )?;
    let prepare = temporary.path().join("prepare.sql");
    private_file(
        &prepare,
        format!("SELECT pg_advisory_xact_lock(184923781);\nDROP SCHEMA IF EXISTS \"{schema}\";\n")
            .as_bytes(),
    )?;
    let fence = temporary.path().join("fence.sql");
    private_file(&fence,format!(r#"SET search_path TO "{schema}";
-- Only the WASM-only baseline is supported; restoration never replays work.
DO $fenders$ BEGIN
 IF (SELECT format FROM platform_format WHERE singleton) IS DISTINCT FROM 'wasm-only-v1' THEN
  RAISE EXCEPTION 'unsupported backup database format';
 END IF;
END $fenders$;
UPDATE recovery_barrier SET active=true WHERE singleton;
UPDATE credentials SET revoked=true;
UPDATE nodes SET disabled=true,draining=true,observed_runtime_digest=NULL;
UPDATE deployments SET desired='stopped';
UPDATE executions SET desired='stopped',generation=generation+1,state='unreachable' WHERE reserved;
UPDATE executions SET log_ingestion_fenced=true;
UPDATE operations SET state='failed',error='restored-control-plane-requires-reconciliation' WHERE state='pending';
UPDATE public_egress_policy SET enabled=false,revision=revision+1,updated=now();
UPDATE execution_https_bindings SET fenced=true,updated=now();
UPDATE artifact_validations SET state='pending',generation=generation+1,node_id=NULL,node_boot=NULL,lease_until=NULL,available_at=now(),error='compiler-unavailable',updated=now() WHERE state='validating';
UPDATE apps SET desired='stopped',revision=revision+1,updated=now();
UPDATE app_http SET state='disabled',reason='restored-control-plane',blocked=false,execution_id=NULL,generation=LEAST(generation::bigint+1,2147483647)::integer,drain_until=NULL,ready_until=NULL,restart_after=NULL,idle_draining=false,last_activity=now(),updated=now();
UPDATE app_releases SET state='failed',reason='restored-control-plane',updated=now() WHERE state='preparing';
UPDATE app_schedules SET next_at=NULL,updated=now();
UPDATE app_runs SET admission='cancelled',admission_reason='restored-control-plane',admission_updated=now() WHERE admission='pending';
UPDATE app_run_dispatch SET state='cancelled',last_error='restored-control-plane',updated=now() WHERE state='pending';
DO $http_runs$ BEGIN
 IF to_regclass('app_http_runs') IS NOT NULL THEN
  UPDATE app_http_runs SET state=CASE WHEN started_at IS NULL THEN 'failed' ELSE 'unknown' END,finished_at=clock_timestamp() WHERE finished_at IS NULL;
 END IF;
END $http_runs$;
DELETE FROM ingress_reservations WHERE app_id IS NOT NULL AND execution_id IS NULL;
DELETE FROM browser_sessions;
DELETE FROM browser_logins;
UPDATE recovery_barrier SET active=true,backup_id='{id}',restored=now(),activated=NULL WHERE singleton;
INSERT INTO audit(actor,action,detail) VALUES('restore','control.restore','{{"backup_id":"{id}"}}');
"#).as_bytes())?;
    let parent = state.parent().ok_or_else(invalid)?;
    fs::create_dir_all(parent)?;
    let incoming = parent.join(format!(".restore-{}", uid()));
    fs::create_dir(&incoming)?;
    fs::set_permissions(&incoming, fs::Permissions::from_mode(0o700))?;
    // Preserve staged state on any later failure: the database may have committed.
    for name in manifest["files"].as_object().unwrap().keys() {
        if let Some(relative) = name.strip_prefix("state/") {
            copy(&payload.join(name), &incoming.join(relative))?;
        }
    }
    fs::create_dir_all(incoming.join("blobs"))?;
    private_file(
        &incoming.join("restore.json"),
        &serde_json::to_vec(&json!({"backup_id":id,"state":"fenced"})).unwrap(),
    )?;
    fn sync_dirs(path: &Path) -> Result<()> {
        for e in fs::read_dir(path)? {
            let e = e?;
            if e.file_type()?.is_dir() {
                fs::set_permissions(e.path(), fs::Permissions::from_mode(0o700))?;
                sync_dirs(&e.path())?;
            }
        }
        fs::File::open(path)?.sync_all()?;
        Ok(())
    }
    sync_dirs(&incoming)?;
    empty_database(dsn).await?;
    pg_command(
        "psql",
        &[
            "-X".into(),
            "--single-transaction".into(),
            "--set=ON_ERROR_STOP=on".into(),
            format!("--file={}", prepare.display()),
            format!("--file={}", sql.display()),
            format!("--file={}", fence.display()),
        ],
        dsn,
    )?;
    if state.symlink_metadata().is_ok() {
        return Err(Error::invalid(
            "restore destination appeared; fenced database and staged state retained",
        ));
    }
    fs::rename(&incoming, state)?;
    fs::File::open(parent)?.sync_all()?;
    Ok(
        json!({"id":id,"state_directory":state,"mode":"fenced","credentials":"revoked","nodes":"disabled"}),
    )
}
pub async fn activate(dsn: &str, fenced: bool) -> Result<Value> {
    if !fenced {
        return Err(Error::invalid(
            "activation requires explicit external-resource fencing confirmation",
        ));
    }
    let mut db = sqlx::PgConnection::connect(dsn).await?;
    let mut tx = db.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(184923781)")
        .execute(&mut *tx)
        .await?;
    if !sqlx::query_scalar::<_, bool>(
        "SELECT active FROM recovery_barrier WHERE singleton FOR UPDATE",
    )
    .fetch_one(&mut *tx)
    .await?
    {
        return Err(Error::invalid("control plane is not in restore recovery"));
    }
    let format: String = sqlx::query_scalar("SELECT format FROM platform_format WHERE singleton")
        .fetch_one(&mut *tx)
        .await?;
    if format != "wasm-only-v1" {
        return Err(Error::invalid("unsupported backup database format"));
    }
    // The WASM baseline always includes settlement. Never skip outstanding
    // grants before releasing execution reservations and the recovery barrier.
    sqlx::raw_sql(include_str!("egress_restore.sql"))
        .execute(&mut *tx)
        .await?;
    let count = sqlx::query(
        "UPDATE executions SET state='lost',reserved=false,updated=now() WHERE reserved",
    )
    .execute(&mut *tx)
    .await?
    .rows_affected();
    sqlx::query("UPDATE network_grants SET state='revoked' WHERE state='revoking'")
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE recovery_barrier SET active=false,activated=now() WHERE singleton")
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO audit(actor,action,detail) VALUES('restore-operator','control.activate','{\"external_resources_fenced\":true}')").execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(json!({"mode":"active","lost_executions":count,"nodes":"remain disabled"}))
}

#[cfg(test)]
mod connection_tests {
    use super::*;

    #[test]
    fn unix_socket_query_preserves_database_authority_and_rejects_unknown_options() {
        let env = pg_environment("postgresql://fenders-control@localhost/fenders_product?host=%2Fvar%2Frun%2Fpostgresql&sslmode=disable").unwrap();
        assert_eq!(env["PGHOST"], "/var/run/postgresql");
        assert_eq!(env["PGUSER"], "fenders-control");
        assert_eq!(env["PGDATABASE"], "fenders_product");
        assert_eq!(env["PGSSLMODE"], "disable");
        assert!(pg_environment("postgresql://fenders-control@localhost/fenders_product?host=%2Fvar%2Frun%2Fpostgresql&arbitrary_option=ignored").is_err());
    }
}
