use super::*;
async fn age(l: &Lab, id: &str) {
    sqlx::query("UPDATE artifacts SET last_uploaded_at=now()-interval '8 days' WHERE id=$1")
        .bind(id)
        .execute(&l.store.pool)
        .await
        .unwrap();
}
async fn retired(l: &Lab, id: &str) -> bool {
    sqlx::query_scalar("SELECT retired_at IS NOT NULL FROM artifacts WHERE id=$1")
        .bind(id)
        .fetch_one(&l.store.pool)
        .await
        .unwrap()
}
fn blob(l: &Lab, data: &[u8]) -> std::path::PathBuf {
    l.root.path().join("blobs").join(digest(data))
}
#[tokio::test]
async fn unused_upload_expiry_releases_quota_and_reupload_preserves_identity_with_fresh_inspection()
{
    let l = Lab::new().await;
    let data = b"\0asm\x0d\0\x01\0";
    age(&l, &l.artifact).await;
    l.store.schedule().await.unwrap();
    assert!(retired(&l, &l.artifact).await);
    assert!(!blob(&l, data).exists());
    assert_eq!(
        l.store.usage(&l.operator, &l.tenant, None).await.unwrap()["artifact_bytes"],
        0
    );
    assert_eq!(
        l.store
            .artifact_inspection(&l.operator, &l.tenant, &l.project, &l.artifact)
            .await
            .unwrap_err()
            .status,
        StatusCode::GONE
    );
    assert!(
        l.store
            .resources(
                &l.operator,
                &l.tenant,
                &l.project,
                "artifacts",
                Some(&l.artifact)
            )
            .await
            .is_err()
    );
    assert!(
        l.store
            .create_app(
                &l.operator,
                &l.tenant,
                &l.project,
                json!({"name":"expired","artifact_id":l.artifact}),
                "expired",
            )
            .await
            .is_err()
    );
    l.store.migrate().await.unwrap();
    l.store.migrate().await.unwrap();
    let bytes: i64 = sqlx::query_scalar(
        "SELECT COALESCE(sum(bytes),0)::bigint FROM storage_reservations WHERE tenant_id=$1",
    )
    .bind(&l.tenant)
    .fetch_one(&l.store.pool)
    .await
    .unwrap();
    assert_eq!(bytes, 0, "bootstrap must not restore retired charges");
    let uploaded = l
        .store
        .upload(&l.operator, &l.tenant, &l.project, data)
        .await
        .unwrap();
    assert_eq!(uploaded["id"], l.artifact);
    assert!(uploaded["retired_at"].is_null());
    assert_eq!(std::fs::read(blob(&l, data)).unwrap(), data);
    assert_eq!(
        l.store
            .artifact_inspection(&l.operator, &l.tenant, &l.project, &l.artifact)
            .await
            .unwrap()["state"],
        "pending"
    );
    assert_eq!(
        l.store.usage(&l.operator, &l.tenant, None).await.unwrap()["artifact_bytes"],
        8
    );
    age(&l, &l.artifact).await;
    l.store
        .upload(&l.operator, &l.tenant, &l.project, data)
        .await
        .unwrap();
    l.store.schedule().await.unwrap();
    assert!(
        !retired(&l, &l.artifact).await,
        "a repeated upload renews its grace window"
    );
    l.finish().await;
}
#[tokio::test]
async fn shared_blob_and_app_versions_pin_code_while_unreferenced_copies_expire() {
    let l = Lab::new().await;
    let node = l.node("compiler").await;
    approve_component(&l, &node, true, true).await;
    l.store
        .create_app(
            &l.operator,
            &l.tenant,
            &l.project,
            json!({"name":"retained-code","artifact_id":l.artifact}),
            "app",
        )
        .await
        .unwrap();
    let other = l
        .store
        .create_project(
            &l.operator,
            &l.tenant,
            serde_json::from_value(json!({"name":"other"})).unwrap(),
        )
        .await
        .unwrap();
    let data = b"\0asm\x0d\0\x01\0";
    let copy = l
        .store
        .upload(&l.operator, &l.tenant, s(&other["id"]), data)
        .await
        .unwrap();
    age(&l, &l.artifact).await;
    age(&l, s(&copy["id"])).await;
    l.store.schedule().await.unwrap();
    assert!(!retired(&l, &l.artifact).await);
    assert!(retired(&l, s(&copy["id"])).await);
    assert!(blob(&l, data).exists());
    assert_eq!(
        l.store.usage(&l.operator, &l.tenant, None).await.unwrap()["artifact_bytes"],
        8
    );
    let (viewer, _) = l.credential("viewer", Some(s(&other["id"]))).await;
    assert!(
        l.store
            .upload(&viewer, &l.tenant, s(&other["id"]), data)
            .await
            .is_err()
    );
    assert_eq!(
        l.store
            .artifact_inspection(&viewer, &l.tenant, s(&other["id"]), &l.artifact)
            .await
            .unwrap_err()
            .status,
        StatusCode::NOT_FOUND
    );
    l.finish().await;
}
#[tokio::test]
async fn active_compilers_are_protected_and_expired_claims_cannot_read_or_submit() {
    let l = Lab::new().await;
    let node = l.node("compiler").await;
    let job = l
        .store
        .claim_component(s(&node["id"]), json!({"boot_id":"test-boot"}))
        .await
        .unwrap()["job"]
        .clone();
    age(&l, &l.artifact).await;
    l.store.schedule().await.unwrap();
    assert!(!retired(&l, &l.artifact).await);
    sqlx::query("UPDATE artifact_validations SET lease_until=now()-interval '1 second' WHERE artifact_id=$1").bind(&l.artifact).execute(&l.store.pool).await.unwrap();
    l.store.schedule().await.unwrap();
    assert!(retired(&l, &l.artifact).await);
    assert!(
        l.store
            .component_content(
                s(&node["id"]),
                &l.artifact,
                n(&job["generation"]),
                json!({"boot_id":"test-boot"})
            )
            .await
            .is_err()
    );
    assert!(
        l.store
            .component_result(
                s(&node["id"]),
                &l.artifact,
                n(&job["generation"]),
                json!({"boot_id":"test-boot","inspection":inspection_receipt(&job)})
            )
            .await
            .is_err()
    );
    assert!(
        l.store
            .claim_component(s(&node["id"]), json!({"boot_id":"test-boot"}))
            .await
            .unwrap()["job"]
            .is_null()
    );
    l.finish().await;
}
#[tokio::test]
async fn retirement_rollback_recovery_and_payload_failure_are_safe_to_retry() {
    let l = Lab::new().await;
    let data = b"\0asm\x0d\0\x01\0";
    age(&l, &l.artifact).await;
    sqlx::raw_sql("CREATE FUNCTION reject_expiration() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='artifact.expire' THEN RAISE EXCEPTION 'injected retention failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_expiration BEFORE INSERT ON audit FOR EACH ROW EXECUTE FUNCTION reject_expiration();").execute(&l.store.pool).await.unwrap();
    assert!(l.store.schedule().await.is_err());
    assert!(!retired(&l, &l.artifact).await);
    assert!(blob(&l, data).exists());
    sqlx::raw_sql(
        "DROP TRIGGER reject_expiration ON audit; UPDATE recovery_barrier SET active=true",
    )
    .execute(&l.store.pool)
    .await
    .unwrap();
    assert!(l.store.schedule().await.is_err());
    assert!(!retired(&l, &l.artifact).await);
    sqlx::query("UPDATE recovery_barrier SET active=false")
        .execute(&l.store.pool)
        .await
        .unwrap();
    std::fs::remove_file(blob(&l, data)).unwrap();
    std::fs::create_dir(blob(&l, data)).unwrap();
    l.store.schedule().await.unwrap();
    assert!(retired(&l, &l.artifact).await);
    let error: String = sqlx::query_scalar("SELECT error FROM artifact_blob_garbage")
        .fetch_one(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(error, "blob-cleanup-unavailable");
    std::fs::remove_dir(blob(&l, data)).unwrap();
    sqlx::query("UPDATE artifact_blob_garbage SET next_attempt=now()")
        .execute(&l.store.pool)
        .await
        .unwrap();
    l.store.schedule().await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM artifact_blob_garbage")
            .fetch_one(&l.store.pool)
            .await
            .unwrap(),
        0
    );
    l.finish().await;
}

#[tokio::test]
async fn cleanup_is_bounded_and_concurrent_reupload_keeps_durable_bytes() {
    let l = Lab::new().await;
    for i in 0..69u8 {
        let mut bytes = b"\0asm\x0d\0\x01\0".to_vec();
        bytes.push(i);
        l.store
            .upload(&l.operator, &l.tenant, &l.project, &bytes)
            .await
            .unwrap();
    }
    sqlx::query("UPDATE artifacts SET last_uploaded_at=now()-interval '8 days'")
        .execute(&l.store.pool)
        .await
        .unwrap();
    l.store.schedule().await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM artifacts WHERE retired_at IS NOT NULL")
            .fetch_one(&l.store.pool)
            .await
            .unwrap(),
        64
    );
    assert_eq!(
        std::fs::read_dir(l.root.path().join("blobs"))
            .unwrap()
            .count(),
        54
    );
    let data = b"\0asm\x0d\0\x01\0";
    let (schedule, upload) = tokio::join!(
        l.store.schedule(),
        l.store.upload(&l.operator, &l.tenant, &l.project, data)
    );
    schedule.unwrap();
    assert_eq!(upload.unwrap()["id"], l.artifact);
    for _ in 0..5 {
        l.store.schedule().await.unwrap();
    }
    assert!(!retired(&l, &l.artifact).await);
    assert_eq!(std::fs::read(blob(&l, data)).unwrap(), data);
    assert_eq!(
        std::fs::read_dir(l.root.path().join("blobs"))
            .unwrap()
            .count(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM artifact_blob_garbage")
            .fetch_one(&l.store.pool)
            .await
            .unwrap(),
        0
    );
    l.finish().await;
}

#[tokio::test]
async fn historical_executions_and_stopped_deployments_keep_their_code() {
    let l = Lab::new().await;
    let second = l
        .store
        .upload(
            &l.operator,
            &l.tenant,
            &l.project,
            b"\0asm\x0d\0\x01\0second",
        )
        .await
        .unwrap();
    sqlx::query("INSERT INTO executions(id,tenant_id,project_id,spec,cpu_percent,memory_mib,reserved,state,desired) VALUES($1,$2,$3,$4,1,1,false,'exited','stopped')")
        .bind(uid()).bind(&l.tenant).bind(&l.project).bind(json!({"artifact_id":l.artifact})).execute(&l.store.pool).await.unwrap();
    sqlx::query("INSERT INTO deployments(id,tenant_id,project_id,name,spec,desired) VALUES($1,$2,$3,'old-deployment',$4,'stopped')")
        .bind(uid()).bind(&l.tenant).bind(&l.project).bind(json!({"artifact_id":second["id"]})).execute(&l.store.pool).await.unwrap();
    age(&l, &l.artifact).await;
    age(&l, s(&second["id"])).await;
    l.store.schedule().await.unwrap();
    assert!(!retired(&l, &l.artifact).await);
    assert!(!retired(&l, s(&second["id"])).await);
    l.finish().await;
}

#[tokio::test]
async fn quota_denied_reactivation_keeps_tombstone_and_old_compiler_generation_fenced() {
    let l = Lab::new().await;
    let node = l.node("compiler").await;
    let old = l
        .store
        .claim_component(s(&node["id"]), json!({"boot_id":"test-boot"}))
        .await
        .unwrap()["job"]
        .clone();
    age(&l, &l.artifact).await;
    sqlx::query("UPDATE artifact_validations SET lease_until=now()-interval '1 second'")
        .execute(&l.store.pool)
        .await
        .unwrap();
    l.store.schedule().await.unwrap();
    sqlx::query("UPDATE tenants SET storage_bytes=1 WHERE id=$1")
        .bind(&l.tenant)
        .execute(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(
        l.store
            .upload(&l.operator, &l.tenant, &l.project, b"\0asm\x0d\0\x01\0")
            .await
            .unwrap_err()
            .status,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert!(retired(&l, &l.artifact).await);
    assert!(!blob(&l, b"\0asm\x0d\0\x01\0").exists());
    sqlx::query("UPDATE tenants SET storage_bytes=8 WHERE id=$1")
        .bind(&l.tenant)
        .execute(&l.store.pool)
        .await
        .unwrap();
    l.store
        .upload(&l.operator, &l.tenant, &l.project, b"\0asm\x0d\0\x01\0")
        .await
        .unwrap();
    let new = l
        .store
        .claim_component(s(&node["id"]), json!({"boot_id":"test-boot"}))
        .await
        .unwrap()["job"]
        .clone();
    assert!(n(&new["generation"]) > n(&old["generation"]));
    assert!(
        l.store
            .component_result(
                s(&node["id"]),
                &l.artifact,
                n(&old["generation"]),
                json!({"boot_id":"test-boot","inspection":inspection_receipt(&old)})
            )
            .await
            .is_err()
    );
    l.store
        .component_result(
            s(&node["id"]),
            &l.artifact,
            n(&new["generation"]),
            json!({"boot_id":"test-boot","inspection":inspection_receipt(&new)}),
        )
        .await
        .unwrap();
    l.finish().await;
}

fn age_file(path: &std::path::Path) {
    std::fs::File::open(path)
        .unwrap()
        .set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(25 * 60 * 60))
        .unwrap();
}

#[tokio::test]
async fn failed_upload_payload_is_reclaimed_without_touching_referenced_or_recent_files() {
    let l = Lab::new().await;
    let bytes = b"\0asm\x0d\0\x01\0failed-upload";
    sqlx::raw_sql("CREATE FUNCTION reject_upload() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='artifact.upload' THEN RAISE EXCEPTION 'injected upload failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_upload BEFORE INSERT ON audit FOR EACH ROW EXECUTE FUNCTION reject_upload();").execute(&l.store.pool).await.unwrap();
    assert!(
        l.store
            .upload(&l.operator, &l.tenant, &l.project, bytes)
            .await
            .is_err()
    );
    sqlx::query("DROP TRIGGER reject_upload ON audit")
        .execute(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(std::fs::read(blob(&l, bytes)).unwrap(), bytes);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM artifacts")
            .fetch_one(&l.store.pool)
            .await
            .unwrap(),
        1
    );
    age_file(&blob(&l, bytes));
    let live = blob(&l, b"\0asm\x0d\0\x01\0");
    age_file(&live);
    let dir = l.root.path().join("blobs");
    let temp = dir.join(format!(".upload-{}", uid()));
    std::fs::write(&temp, b"partial").unwrap();
    age_file(&temp);
    let recent = dir.join(digest(b"recent"));
    std::fs::write(&recent, b"recent").unwrap();
    let future = dir.join(digest(b"future"));
    std::fs::write(&future, b"future").unwrap();
    std::fs::File::open(&future)
        .unwrap()
        .set_modified(std::time::SystemTime::now() + std::time::Duration::from_secs(3600))
        .unwrap();
    let unrecognized = dir.join("operator-note");
    std::fs::write(&unrecognized, b"keep").unwrap();
    age_file(&unrecognized);
    let outside = tempfile::NamedTempFile::new().unwrap();
    let link = dir.join(digest(b"link"));
    std::os::unix::fs::symlink(outside.path(), &link).unwrap();
    l.store.schedule().await.unwrap();
    assert!(!blob(&l, bytes).exists());
    assert!(!temp.exists());
    assert!(live.exists());
    assert!(recent.exists());
    assert!(future.exists());
    assert!(unrecognized.exists());
    assert!(link.symlink_metadata().unwrap().file_type().is_symlink());
    assert!(outside.path().exists());
    assert_eq!(
        l.store.usage(&l.operator, &l.tenant, None).await.unwrap()["artifact_bytes"],
        8
    );
    assert!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM audit WHERE action='artifact.expire'")
            .fetch_one(&l.store.pool)
            .await
            .unwrap()
            == 0
    );
    l.finish().await;
}

#[tokio::test]
async fn orphan_cleanup_respects_recovery_and_serializes_with_upload_and_restart() {
    let l = Lab::new().await;
    let data = b"\0asm\x0d\0\x01\0racing";
    std::fs::write(blob(&l, data), data).unwrap();
    age_file(&blob(&l, data));
    sqlx::query("UPDATE recovery_barrier SET active=true")
        .execute(&l.store.pool)
        .await
        .unwrap();
    assert!(l.store.schedule().await.is_err());
    assert!(blob(&l, data).exists());
    sqlx::query("UPDATE recovery_barrier SET active=false")
        .execute(&l.store.pool)
        .await
        .unwrap();
    let (sweep, upload) = tokio::join!(
        l.store.schedule(),
        l.store.upload(&l.operator, &l.tenant, &l.project, data)
    );
    sweep.unwrap();
    let uploaded = upload.unwrap();
    assert_eq!(std::fs::read(blob(&l, data)).unwrap(), data);
    assert!(uploaded["retired_at"].is_null());
    let restarted = Store::from_pool(l.store.pool.clone(), l.root.path()).unwrap();
    restarted.schedule().await.unwrap();
    assert_eq!(std::fs::read(blob(&l, data)).unwrap(), data);
    assert_eq!(
        restarted
            .resources(
                &l.operator,
                &l.tenant,
                &l.project,
                "artifacts",
                Some(s(&uploaded["id"]))
            )
            .await
            .unwrap()["id"],
        uploaded["id"]
    );
    l.finish().await;
}

#[tokio::test]
async fn orphan_cleanup_is_bounded_and_preserves_metadata_owned_garbage() {
    let l = Lab::new().await;
    let dir = l.root.path().join("blobs");
    for i in 0..70 {
        let path = dir.join(digest(format!("orphan-{i}")));
        std::fs::write(&path, b"unused").unwrap();
        age_file(&path);
    }
    // Retired metadata belongs to the durable retry queue, even after file grace.
    sqlx::query("UPDATE artifacts SET retired_at=now()")
        .execute(&l.store.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO artifact_blob_garbage(digest,next_attempt,error) SELECT digest,now()+interval '1 hour','blob-cleanup-unavailable' FROM artifacts").execute(&l.store.pool).await.unwrap();
    age_file(&blob(&l, b"\0asm\x0d\0\x01\0"));
    l.store.schedule().await.unwrap();
    let left = std::fs::read_dir(&dir).unwrap().count();
    assert!(
        (55..71).contains(&left),
        "at most 16 candidates per pass, including pinned entries"
    );
    for _ in 0..8 {
        l.store.schedule().await.unwrap();
    }
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
    assert!(blob(&l, b"\0asm\x0d\0\x01\0").exists());
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM artifact_blob_garbage")
            .fetch_one(&l.store.pool)
            .await
            .unwrap(),
        1
    );
    l.finish().await;
}
