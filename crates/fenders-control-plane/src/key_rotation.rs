//! Offline control-plane encryption-key rotation. The database fingerprint is
//! the commit receipt; the supplied new key is also the crash-recovery input.
use crate::{
    error::{Error, Result},
    model::digest,
};
use axum::http::StatusCode;
use fernet::Fernet;
use serde_json::{Value, json};
use sqlx::{Connection, PgPool, Postgres, Transaction};
use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};

pub(crate) fn read_key(path: &Path) -> Result<String> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.len() > 128
        || metadata.mode() & 0o077 != 0
        || metadata.uid() != unsafe { libc::geteuid() }
    {
        return Err(Error::invalid(
            "encryption key must be a private owned regular file",
        ));
    }
    let mut key = String::new();
    file.take(129).read_to_string(&mut key)?;
    let key = key.trim();
    if key.len() > 128 || Fernet::new(key).is_none() {
        return Err(Error::invalid("invalid encryption key"));
    }
    Ok(key.to_owned())
}

pub fn generate(path: &Path) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(Fernet::generate_key().as_bytes())?;
    file.sync_all()?;
    fs::File::open(
        path.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )?
    .sync_all()?;
    Ok(())
}

pub(crate) fn check_identity(barrier: &Value, key_id: &str) -> Result<()> {
    if barrier["encryption_key_id"]
        .as_str()
        .is_some_and(|expected| expected != key_id)
    {
        return Err(Error::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "control-plane encryption key changed; finish rotation and restart services",
        ));
    }
    Ok(())
}

// This inventory covers every persisted Fernet value. Cursors held by clients
// are intentionally invalidated; they are not database records or credentials.
const COLUMNS: &[(&str, &str, &str, bool)] = &[("secrets", "id", "ciphertext", true)];

pub(crate) async fn validate_or_reencrypt(
    tx: &mut Transaction<'_, Postgres>,
    old: &Fernet,
    new: Option<&Fernet>,
) -> Result<u64> {
    let mut count = 0;
    for &(table, id, column, binary) in COLUMNS {
        if new.is_none()
            && sqlx::query_scalar::<_, Option<String>>("SELECT to_regclass($1)::text")
                .bind(table)
                .fetch_one(&mut **tx)
                .await?
                .is_none()
        {
            continue;
        }
        let mut after = String::new();
        let cast = if binary {
            format!("convert_from({column},'UTF8')")
        } else {
            column.into()
        };
        loop {
            // Names come exclusively from the fixed inventory, never operator input.
            let query = format!(
                "SELECT {id},CASE WHEN octet_length({column})<=1048576 THEN {cast} END FROM {table} WHERE {id}>$1 ORDER BY {id} LIMIT 64"
            );
            let rows: Vec<(String, Option<String>)> = sqlx::query_as(&query)
                .bind(&after)
                .fetch_all(&mut **tx)
                .await?;
            if rows.is_empty() {
                break;
            }
            for (identity, token) in rows {
                let plain = old
                    .decrypt(
                        token.as_deref().ok_or_else(|| {
                            Error::invalid("encrypted value exceeds rotation limit")
                        })?,
                    )
                    .map_err(|_| {
                        Error::invalid("stored value cannot be decrypted; rotation rolled back")
                    })?;
                if let Some(new) = new {
                    let token = new.encrypt(&plain);
                    let value = if binary {
                        "convert_to($1,'UTF8')"
                    } else {
                        "$1"
                    };
                    sqlx::query(&format!(
                        "UPDATE {table} SET {column}={value} WHERE {id}=$2"
                    ))
                    .bind(token)
                    .bind(&identity)
                    .execute(&mut **tx)
                    .await?;
                }
                after = identity;
                count += 1;
            }
        }
    }
    Ok(count)
}

fn publish(state: &Path, key: &str) -> Result<()> {
    let mut staged = tempfile::NamedTempFile::new_in(state)?;
    staged
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    staged.write_all(key.as_bytes())?;
    staged.as_file().sync_all()?;
    staged
        .persist(state.join("encryption.key"))
        .map_err(|_| Error::internal())?;
    fs::File::open(state)?.sync_all()?;
    Ok(())
}

/// Operators must stop API, gateway, scheduler and controllers first, including
/// older binaries without key fencing. This flag records an assertion, not proof.
pub async fn rotate(
    pool: &PgPool,
    state: &Path,
    new_key_file: &Path,
    services_stopped: bool,
) -> Result<Value> {
    if !services_stopped {
        return Err(Error::invalid(
            "stop control-plane services and acknowledge services-stopped before rotation",
        ));
    }
    let metadata = fs::symlink_metadata(state)?;
    if !metadata.is_dir()
        || metadata.mode() & 0o077 != 0
        || metadata.uid() != unsafe { libc::geteuid() }
    {
        return Err(Error::invalid(
            "rotation state must be a private owned directory",
        ));
    }
    // An owned connection avoids returning a session advisory lock to the pool.
    // Hold admission through both DB commit and key publication; backup uses it too.
    let mut connection = pool.acquire().await?.detach();
    sqlx::query("SET lock_timeout='5s'")
        .execute(&mut connection)
        .await?;
    sqlx::query("SET statement_timeout='30s'")
        .execute(&mut connection)
        .await?;
    sqlx::query("SELECT pg_advisory_lock(184923781)")
        .execute(&mut connection)
        .await?;
    let current = read_key(&state.join("encryption.key"))?;
    let target = read_key(new_key_file)?;
    let current_id = digest(&current);
    let target_id = digest(&target);
    let mut tx = connection.begin().await?;
    let bound: Option<String> = sqlx::query_scalar(
        "SELECT encryption_key_id FROM recovery_barrier WHERE singleton FOR UPDATE",
    )
    .fetch_one(&mut *tx)
    .await?;
    let bound = bound
        .ok_or_else(|| Error::invalid("migrate control-plane key identity before rotation"))?;
    if bound == target_id {
        tx.commit().await?;
        // This also recovers a lost publication after a committed rotation.
        publish(state, &target)?;
        return Ok(json!({"key_id":target_id,"state":"complete","already_committed":true}));
    }
    if bound != current_id {
        return Err(Error::invalid(
            "key publication is incomplete; resume using the committed new-key file",
        ));
    }
    let values = validate_or_reencrypt(
        &mut tx,
        &Fernet::new(&current).unwrap(),
        Some(&Fernet::new(&target).unwrap()),
    )
    .await?;
    sqlx::query("UPDATE recovery_barrier SET encryption_key_id=$1 WHERE singleton")
        .bind(&target_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO audit(actor,action,resource_id,detail) VALUES('operator-key-tool','control-plane-key.rotate',$1,$2)")
        .bind(&target_id).bind(json!({"previous_key_id":current_id,"key_id":target_id,"encrypted_values":values})).execute(&mut *tx).await?;
    tx.commit().await?;
    publish(state, &target)?;
    Ok(
        json!({"key_id":target_id,"state":"complete","already_committed":false,"encrypted_values":values}),
    )
}
