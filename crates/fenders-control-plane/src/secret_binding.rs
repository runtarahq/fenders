//! A stored secret is its row's alone.
//!
//! What is encrypted for a secret is its value behind a header naming its
//! workspace, project and id. It is opened only for the row it names: a
//! ciphertext copied into another row, of another workspace or the same,
//! opens for no one. Whoever can write the database can still do much else
//! (insert a credential, change what an app runs); what this takes from them
//! is reading one workspace's secret by handing its ciphertext to another's
//! run.
use crate::{
    error::{Error, Result},
    store::Tx,
};

const HEADER: &str = "fenders-secret-v1";

/// Adds the column that says a row's ciphertext names it, and the record of
/// the one time rows stored before it were bound.
pub(crate) const MIGRATION: &str = "ALTER TABLE secrets ADD COLUMN IF NOT EXISTS bound boolean NOT NULL DEFAULT false; CREATE TABLE IF NOT EXISTS secret_binding (singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton), completed timestamptz); INSERT INTO secret_binding(singleton) VALUES(true) ON CONFLICT DO NOTHING";

fn header(tenant: &str, project: &str, id: &str) -> String {
    format!("{HEADER}\n{tenant}\n{project}\n{id}\n")
}

/// `value` encrypted for the secret `id` of `project` in `tenant`.
pub(crate) fn seal(
    cipher: &fernet::Fernet,
    tenant: &str,
    project: &str,
    id: &str,
    value: &[u8],
) -> String {
    let mut bound = header(tenant, project, id).into_bytes();
    bound.extend_from_slice(value);
    cipher.encrypt(&bound)
}

/// The value in `token`, if it was sealed for this very secret.
pub(crate) fn open(
    cipher: &fernet::Fernet,
    tenant: &str,
    project: &str,
    id: &str,
    token: &str,
) -> Result<Vec<u8>> {
    let bound = cipher.decrypt(token).map_err(|_| Error::internal())?;
    bound
        .strip_prefix(header(tenant, project, id).as_bytes())
        .map(<[u8]>::to_vec)
        .ok_or_else(Error::internal)
}

/// Binds the secrets stored before ciphertexts named their rows, once. A row
/// that is unbound after that was not written by this control plane, and is
/// never bound: it stays unreadable.
pub(crate) async fn bind_stored(tx: &mut Tx, cipher: &fernet::Fernet) -> Result<u64> {
    let pending: bool =
        sqlx::query_scalar("SELECT completed IS NULL FROM secret_binding WHERE singleton")
            .fetch_one(&mut **tx)
            .await?;
    if !pending {
        return Ok(0);
    }
    let mut bound = 0;
    let mut after = String::new();
    loop {
        let rows: Vec<(String, String, String, String)> = sqlx::query_as(
            "SELECT id,tenant_id,project_id,convert_from(ciphertext,'UTF8') FROM secrets WHERE NOT bound AND id>$1 ORDER BY id LIMIT 64",
        )
        .bind(&after)
        .fetch_all(&mut **tx)
        .await?;
        let Some(last) = rows.last() else { break };
        after = last.0.clone();
        for (id, tenant, project, token) in rows {
            let value = cipher
                .decrypt(&token)
                .map_err(|_| Error::invalid("a stored secret does not decrypt with this key"))?;
            sqlx::query(
                "UPDATE secrets SET ciphertext=convert_to($2,'UTF8'),bound=true WHERE id=$1",
            )
            .bind(&id)
            .bind(seal(cipher, &tenant, &project, &id, &value))
            .execute(&mut **tx)
            .await?;
            bound += 1;
        }
    }
    sqlx::query("UPDATE secret_binding SET completed=now() WHERE singleton")
        .execute(&mut **tx)
        .await?;
    Ok(bound)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_ciphertext_opens_only_for_the_row_it_was_sealed_for() {
        let cipher = fernet::Fernet::new(&fernet::Fernet::generate_key()).unwrap();
        let token = seal(
            &cipher,
            "tenant-a",
            "project-a",
            "secret-1",
            b"the value\nof it",
        );
        assert_eq!(
            open(&cipher, "tenant-a", "project-a", "secret-1", &token).unwrap(),
            b"the value\nof it"
        );
        // Moved to another workspace, another project, or another row.
        for (tenant, project, id) in [
            ("tenant-b", "project-a", "secret-1"),
            ("tenant-a", "project-b", "secret-1"),
            ("tenant-a", "project-a", "secret-2"),
        ] {
            assert!(open(&cipher, tenant, project, id, &token).is_err());
        }
        // A value stored without a header, as before, opens for no row.
        let unbound = cipher.encrypt(b"the value\nof it");
        assert!(open(&cipher, "tenant-a", "project-a", "secret-1", &unbound).is_err());
        // Nor one whose value was chosen to look like another row's header.
        let forged = cipher.encrypt(b"fenders-secret-v1\ntenant-a\nproject-a\nsecret-1");
        assert!(open(&cipher, "tenant-a", "project-a", "secret-1", &forged).is_err());
        let another = fernet::Fernet::new(&fernet::Fernet::generate_key()).unwrap();
        assert!(open(&another, "tenant-a", "project-a", "secret-1", &token).is_err());
    }
}
