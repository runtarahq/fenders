use super::*;
use fenders_control_plane::key_rotation::{generate, rotate};
use std::{os::unix::fs::PermissionsExt, path::Path};

fn cipher(path: &Path) -> fernet::Fernet {
    fernet::Fernet::new(std::fs::read_to_string(path).unwrap().trim()).unwrap()
}
async fn encrypted(pool: &sqlx::PgPool) -> Vec<(String, String)> {
    sqlx::query_as("SELECT 'secret/'||id,convert_from(ciphertext,'UTF8') FROM secrets UNION ALL SELECT 'session/'||id,csrf_encrypted FROM browser_sessions UNION ALL SELECT 'nonce/'||state_hash,nonce_encrypted FROM browser_logins UNION ALL SELECT 'pkce/'||state_hash,pkce_encrypted FROM browser_logins ORDER BY 1").fetch_all(pool).await.unwrap()
}
async fn identity(pool: &sqlx::PgPool) -> String {
    sqlx::query_scalar("SELECT encryption_key_id FROM recovery_barrier WHERE singleton")
        .fetch_one(pool)
        .await
        .unwrap()
}
async fn seed_browser(l: &Lab) {
    let cipher = cipher(&l.root.path().join("encryption.key"));
    let user = uid();
    sqlx::query("INSERT INTO customer_users(id,issuer,subject) VALUES($1,'https://identity.test','rotation')").bind(&user).execute(&l.store.pool).await.unwrap();
    sqlx::query("INSERT INTO browser_sessions(id,user_id,token_hash,csrf_hash,csrf_encrypted,expires,client_id,provider_iat) VALUES($1,$2,'session','csrf',$3,now()+interval '1 hour','rotation',0)").bind(uid()).bind(user).bind(cipher.encrypt(b"csrf-value")).execute(&l.store.pool).await.unwrap();
    sqlx::query("INSERT INTO browser_logins(state_hash,browser_hash,context_hash,nonce_encrypted,pkce_encrypted) VALUES('state','browser','context',$1,$2)").bind(cipher.encrypt(b"nonce-value")).bind(cipher.encrypt(b"pkce-value")).execute(&l.store.pool).await.unwrap();
}

#[tokio::test]
async fn rotation_preserves_plaintext_authority_and_fences_stale_processes() {
    let l = Lab::new().await;
    seed_browser(&l).await;
    let old_path = l.root.path().join("encryption.key");
    let old = cipher(&old_path);
    sqlx::query("INSERT INTO secrets(id,tenant_id,project_id,name,ciphertext) SELECT md5(n::text),$1,$2,'secret-'||n,convert_to($3,'UTF8') FROM generate_series(1,130) n")
        .bind(&l.tenant).bind(&l.project).bind(old.encrypt(b"unchanged value")).execute(&l.store.pool).await.unwrap();
    let before = encrypted(&l.store.pool).await;
    assert_eq!(before.len(), 133);
    let usage = l.store.usage(&l.operator, &l.tenant, None).await.unwrap();
    let target = l.root.path().join("new.key");
    generate(&target).unwrap();
    let new = cipher(&target);
    assert!(
        rotate(&l.store.pool, l.root.path(), &target, false)
            .await
            .is_err()
    );
    assert_eq!(encrypted(&l.store.pool).await, before);
    let result = rotate(&l.store.pool, l.root.path(), &target, true)
        .await
        .unwrap();
    assert_eq!(result["encrypted_values"], 133);
    let after = encrypted(&l.store.pool).await;
    for ((id, previous), (next_id, next)) in before.iter().zip(&after) {
        assert_eq!(id, next_id);
        assert_ne!(previous, next);
        assert_eq!(old.decrypt(previous).unwrap(), new.decrypt(next).unwrap());
        assert!(old.decrypt(next).is_err());
    }
    assert_eq!(
        std::fs::read(&old_path).unwrap(),
        std::fs::read(&target).unwrap()
    );
    assert_eq!(
        std::fs::metadata(&old_path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        l.store
            .transaction(false, false)
            .await
            .err()
            .unwrap()
            .status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        l.store
            .create_secret(
                &l.operator,
                &l.tenant,
                &l.project,
                json!({"name":"stale","value":"must not commit"})
            )
            .await
            .unwrap_err()
            .status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(l.store.migrate().await.is_err());
    let reopened = Store::from_pool(l.store.pool.clone(), l.root.path()).unwrap();
    reopened.migrate().await.unwrap();
    assert_eq!(
        reopened.usage(&l.operator, &l.tenant, None).await.unwrap()["totals"],
        usage["totals"]
    );
    reopened
        .create_secret(
            &l.operator,
            &l.tenant,
            &l.project,
            json!({"name":"after","value":"new value"}),
        )
        .await
        .unwrap();
    // A secret made after the rotation is under the new key: its value,
    // behind the header that names its row.
    assert!(
        encrypted(&l.store.pool)
            .await
            .into_iter()
            .any(|(_, token)| new.decrypt(&token).unwrap().ends_with(b"\nnew value"))
    );
    l.finish().await;
}

#[tokio::test]
async fn rotation_rolls_back_all_columns_on_corruption_or_late_database_failure() {
    let l = Lab::new().await;
    l.store
        .create_secret(
            &l.operator,
            &l.tenant,
            &l.project,
            json!({"name":"retained","value":"keep"}),
        )
        .await
        .unwrap();
    seed_browser(&l).await;
    let key = std::fs::read(l.root.path().join("encryption.key")).unwrap();
    let key_id = identity(&l.store.pool).await;
    let target = l.root.path().join("new.key");
    generate(&target).unwrap();
    let original: String = sqlx::query_scalar("SELECT pkce_encrypted FROM browser_logins")
        .fetch_one(&l.store.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE browser_logins SET pkce_encrypted='invalid'")
        .execute(&l.store.pool)
        .await
        .unwrap();
    let before = encrypted(&l.store.pool).await;
    assert!(
        rotate(&l.store.pool, l.root.path(), &target, true)
            .await
            .is_err()
    );
    assert_eq!(encrypted(&l.store.pool).await, before);
    assert_eq!(identity(&l.store.pool).await, key_id);
    assert_eq!(
        std::fs::read(l.root.path().join("encryption.key")).unwrap(),
        key
    );
    sqlx::query("UPDATE browser_logins SET pkce_encrypted=$1")
        .bind(original)
        .execute(&l.store.pool)
        .await
        .unwrap();
    let before = encrypted(&l.store.pool).await;
    sqlx::raw_sql("CREATE FUNCTION fail_key_receipt() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected key receipt failure'; END $$; CREATE TRIGGER reject_key_receipt BEFORE UPDATE OF encryption_key_id ON recovery_barrier FOR EACH ROW EXECUTE FUNCTION fail_key_receipt();").execute(&l.store.pool).await.unwrap();
    assert!(
        rotate(&l.store.pool, l.root.path(), &target, true)
            .await
            .is_err()
    );
    assert_eq!(encrypted(&l.store.pool).await, before);
    assert_eq!(identity(&l.store.pool).await, key_id);
    assert_eq!(
        std::fs::read(l.root.path().join("encryption.key")).unwrap(),
        key
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM audit WHERE action='control-plane-key.rotate'"
        )
        .fetch_one(&l.store.pool)
        .await
        .unwrap(),
        0
    );
    l.store
        .create_secret(
            &l.operator,
            &l.tenant,
            &l.project,
            json!({"name":"still-valid","value":"keep"}),
        )
        .await
        .unwrap();
    l.finish().await;
}

#[tokio::test]
async fn committed_rotation_recovers_publication_once_and_preserves_recovery_barrier() {
    let l = Lab::new().await;
    seed_browser(&l).await;
    let path = l.root.path().join("encryption.key");
    let old = std::fs::read(&path).unwrap();
    let target = l.root.path().join("new.key");
    generate(&target).unwrap();
    sqlx::query("UPDATE recovery_barrier SET active=true")
        .execute(&l.store.pool)
        .await
        .unwrap();
    rotate(&l.store.pool, l.root.path(), &target, true)
        .await
        .unwrap();
    let committed = encrypted(&l.store.pool).await;
    // Model process loss after DB commit and before the atomic key publication.
    std::fs::write(&path, &old).unwrap();
    let stale = Store::from_pool(l.store.pool.clone(), l.root.path()).unwrap();
    assert!(stale.migrate().await.is_err());
    let wrong = l.root.path().join("wrong.key");
    generate(&wrong).unwrap();
    assert!(
        rotate(&l.store.pool, l.root.path(), &wrong, true)
            .await
            .is_err()
    );
    assert_eq!(std::fs::read(&path).unwrap(), old);
    let resumed = rotate(&l.store.pool, l.root.path(), &target, true)
        .await
        .unwrap();
    assert_eq!(resumed["already_committed"], true);
    assert_eq!(encrypted(&l.store.pool).await, committed);
    assert_eq!(
        rotate(&l.store.pool, l.root.path(), &target, true)
            .await
            .unwrap(),
        resumed
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM audit WHERE action='control-plane-key.rotate'"
        )
        .fetch_one(&l.store.pool)
        .await
        .unwrap(),
        1
    );
    let reopened = Store::from_pool(l.store.pool.clone(), l.root.path()).unwrap();
    reopened.migrate().await.unwrap();
    assert!(reopened.transaction(false, false).await.is_ok());
    assert_eq!(
        reopened
            .transaction(true, false)
            .await
            .err()
            .unwrap()
            .status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(
        sqlx::query_scalar::<_, bool>("SELECT active FROM recovery_barrier")
            .fetch_one(&l.store.pool)
            .await
            .unwrap()
    );
    l.finish().await;
}

#[tokio::test]
async fn key_files_refuse_overwrite_symlinks_and_broad_permissions() {
    let l = Lab::new().await;
    let target = l.root.path().join("new.key");
    generate(&target).unwrap();
    let key = std::fs::read(&target).unwrap();
    assert!(generate(&target).is_err());
    assert_eq!(std::fs::read(&target).unwrap(), key);
    let link = l.root.path().join("link.key");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert!(
        rotate(&l.store.pool, l.root.path(), &link, true)
            .await
            .is_err()
    );
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(
        rotate(&l.store.pool, l.root.path(), &target, true)
            .await
            .is_err()
    );
    assert_eq!(std::fs::read(&target).unwrap(), key);
    l.finish().await;
}

#[tokio::test]
async fn initial_key_binding_validates_existing_values_before_trusting_state() {
    let l = Lab::new().await;
    seed_browser(&l).await;
    let path = l.root.path().join("encryption.key");
    let previous = std::fs::read(&path).unwrap();
    let contents = encrypted(&l.store.pool).await;
    sqlx::query("UPDATE recovery_barrier SET encryption_key_id=NULL")
        .execute(&l.store.pool)
        .await
        .unwrap();
    std::fs::write(&path, fernet::Fernet::generate_key()).unwrap();
    let wrong = Store::from_pool(l.store.pool.clone(), l.root.path()).unwrap();
    assert!(wrong.migrate().await.is_err());
    assert!(
        sqlx::query_scalar::<_, Option<String>>("SELECT encryption_key_id FROM recovery_barrier")
            .fetch_one(&l.store.pool)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(encrypted(&l.store.pool).await, contents);
    std::fs::write(&path, previous).unwrap();
    l.store.migrate().await.unwrap();
    assert_eq!(encrypted(&l.store.pool).await, contents);
    assert_eq!(
        identity(&l.store.pool).await,
        digest(std::fs::read_to_string(&path).unwrap().trim())
    );
    l.finish().await;
}

#[tokio::test]
async fn rotation_waits_for_admission_and_includes_the_last_committed_secret() {
    let l = Lab::new().await;
    let target = l.root.path().join("new.key");
    generate(&target).unwrap();
    let old = cipher(&l.root.path().join("encryption.key"));
    let mut tx = l.store.transaction(true, false).await.unwrap();
    sqlx::query("INSERT INTO secrets(id,tenant_id,project_id,name,ciphertext) VALUES($1,$2,$3,'last-secret',convert_to($4,'UTF8'))").bind(uid()).bind(&l.tenant).bind(&l.project).bind(old.encrypt(b"last committed value")).execute(&mut *tx).await.unwrap();
    let pool = l.store.pool.clone();
    let state = l.root.path().to_owned();
    let new_key = target.clone();
    let mut pending = tokio::spawn(async move { rotate(&pool, &state, &new_key, true).await });
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(150), &mut pending)
            .await
            .is_err()
    );
    tx.commit().await.unwrap();
    assert_eq!(pending.await.unwrap().unwrap()["encrypted_values"], 1);
    let values = encrypted(&l.store.pool).await;
    assert_eq!(values.len(), 1);
    assert_eq!(
        cipher(&target).decrypt(&values[0].1).unwrap(),
        b"last committed value"
    );
    assert!(old.decrypt(&values[0].1).is_err());
    l.finish().await;
}
