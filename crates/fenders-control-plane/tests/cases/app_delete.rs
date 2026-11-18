//! Deletion against real PostgreSQL and the customer router. Worker reports in
//! these transactional tests are protocol fixtures; live KVM qualification is separate.
use super::*;
use fenders_control_plane::apps::AppPage;

async fn request(l: &Lab, token: &str, app: &str, key: &str, revision: i64) -> (StatusCode, Value) {
    let response = api::router(l.store.clone())
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/v1/workspaces/{}/projects/{}/apps/{app}",
                    l.tenant, l.project
                ))
                .header("authorization", format!("Bearer {token}"))
                .header("Idempotency-Key", key)
                .header("Content-Type", "application/json")
                .body(Body::from(
                    json!({"expected_revision":revision}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    (
        status,
        serde_json::from_slice(&to_bytes(response.into_body(), 8192).await.unwrap()).unwrap(),
    )
}

#[tokio::test]
async fn deletion_is_authorized_atomic_idempotent_and_keeps_a_tombstone() {
    let l = Lab::new().await;
    let node = l.node("delete-validator").await;
    approve_component(&l, &node, false, true).await;
    let deployed = l
        .deploy("delete-target", false, true, &uid())
        .await
        .unwrap();
    let app = s(&deployed["resource_id"]);
    let revision = n(&l
        .store
        .app(&l.operator, &l.tenant, &l.project, app)
        .await
        .unwrap()["revision"]);
    let (_, editor) = l.credential("editor", Some(&l.project)).await;
    let (_, viewer) = l.credential("viewer", Some(&l.project)).await;
    let key = uid();
    assert_eq!(
        request(&l, s(&viewer["token"]), app, &key, revision)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        request(&l, s(&editor["token"]), app, &key, 999).await.0,
        StatusCode::CONFLICT
    );
    sqlx::raw_sql("CREATE FUNCTION reject_app_delete_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='app.delete' THEN RAISE EXCEPTION 'fixture audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_app_delete_audit BEFORE INSERT ON audit FOR EACH ROW EXECUTE FUNCTION reject_app_delete_audit();").execute(&l.store.pool).await.unwrap();
    assert_eq!(
        request(&l, s(&editor["token"]), app, &key, revision)
            .await
            .0,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    let intact = l
        .store
        .app(&l.operator, &l.tenant, &l.project, app)
        .await
        .unwrap();
    assert_eq!(intact["revision"], revision);
    assert_eq!(intact["desired"], "enabled");
    sqlx::query("DROP TRIGGER reject_app_delete_audit ON audit")
        .execute(&l.store.pool)
        .await
        .unwrap();
    let (first, retry) = tokio::join!(
        request(&l, s(&editor["token"]), app, &key, revision),
        request(&l, s(&editor["token"]), app, &key, revision)
    );
    // Nothing of the app was running, so the deletion is made at once:
    // 200, where 202 would say it was still to be.
    assert_eq!(first.0, StatusCode::OK);
    assert_eq!(first, retry);
    assert_eq!(first.1["state"], "succeeded");
    assert_eq!(
        request(&l, s(&editor["token"]), app, &key, revision + 1)
            .await
            .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        request(&l, s(&editor["token"]), app, &uid(), 1).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        l.store
            .app(&l.operator, &l.tenant, &l.project, app)
            .await
            .unwrap_err()
            .status,
        StatusCode::NOT_FOUND
    );
    let page = l
        .store
        .apps(&l.operator, &l.tenant, &l.project, AppPage::default())
        .await
        .unwrap();
    assert_eq!(page["total"], 0);
    assert!(page["items"].as_array().unwrap().is_empty());
    let cursor = l
        .store
        .apps(
            &l.operator,
            &l.tenant,
            &l.project,
            AppPage {
                before: Some(app.into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(cursor["total"], 0);
    let recovered = l
        .store
        .app_action_submission(&l.operator, &l.tenant, &l.project, app, &key)
        .await
        .unwrap();
    assert_eq!(recovered["id"], first.1["id"]);
    assert_eq!(
        l.store
            .run_app(&l.operator, &l.tenant, &l.project, app, &uid())
            .await
            .unwrap_err()
            .status,
        StatusCode::NOT_FOUND
    );
    let tombstone:Value=sqlx::query_scalar("SELECT jsonb_build_object('deleted',deleted,'desired',desired,'revision',revision) FROM apps WHERE id=$1")
        .bind(app).fetch_one(&l.store.pool).await.unwrap();
    assert_eq!(
        tombstone,
        json!({"deleted":true,"desired":"stopped","revision":revision+1})
    );
    assert!(
        sqlx::query("UPDATE apps SET desired='enabled' WHERE id=$1")
            .bind(app)
            .execute(&l.store.pool)
            .await
            .is_err()
    );
    let audits: i64 = sqlx::query_scalar("SELECT count(*) FROM audit WHERE action='app.delete'")
        .fetch_one(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(audits, 1);
    let foreign = l
        .store
        .create_project(
            &l.operator,
            &l.tenant,
            serde_json::from_value(json!({"name":"other"})).unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        l.store
            .delete_app(
                &l.operator,
                &l.tenant,
                s(&foreign["id"]),
                app,
                json!({"expected_revision":revision}),
                &uid()
            )
            .await
            .unwrap_err()
            .status,
        StatusCode::NOT_FOUND
    );
    l.store.migrate().await.unwrap();
    assert_eq!(
        request(&l, s(&editor["token"]), app, &key, revision).await,
        first
    );
    l.finish().await;
}

#[tokio::test]
async fn assigned_deletion_holds_quota_until_current_terminal_report_and_never_replays() {
    let l = Lab::new().await;
    let node = l.node("delete-worker").await;
    approve_component(&l, &node, false, true).await;
    let deployed = l
        .deploy("active-delete", false, true, &uid())
        .await
        .unwrap();
    let app = s(&deployed["resource_id"]);
    let revision = n(&l
        .store
        .app(&l.operator, &l.tenant, &l.project, app)
        .await
        .unwrap()["revision"]);
    let invoked = l
        .store
        .run_app(&l.operator, &l.tenant, &l.project, app, &uid())
        .await
        .unwrap();
    let run = l
        .store
        .app_run(
            &l.operator,
            &l.tenant,
            &l.project,
            app,
            s(&invoked["resource_id"]),
        )
        .await
        .unwrap();
    let execution = s(&run["execution_id"]);
    l.store.schedule().await.unwrap();
    let before = l.execution(execution).await;
    assert_eq!(before["node_id"], node["id"]);
    l.report(&node, &before, "running", 1).await;
    let key = uid();
    let op = l
        .store
        .delete_app(
            &l.operator,
            &l.tenant,
            &l.project,
            app,
            json!({"expected_revision":revision}),
            &key,
        )
        .await
        .unwrap();
    assert_eq!(op["state"], "pending");
    let row = l.execution(execution).await;
    assert_eq!(row["desired"], "stopped");
    assert_eq!(row["generation"], 2);
    assert_eq!(row["reserved"], true);
    l.store.heartbeat(s(&node["id"]),json!({"boot_id":"test-boot","confinement":HOST_CONFINEMENT,
        "reports":[{"id":execution,"generation":1,"sequence":1,"state":"stopped","cpu_usec":0,"memory_bytes":0}]})).await.unwrap();
    assert_eq!(l.execution(execution).await["reserved"], true);
    assert_eq!(l.operation(&op).await["state"], "pending");
    l.store.heartbeat(s(&node["id"]),json!({"boot_id":"test-boot","confinement":HOST_CONFINEMENT,
        "reports":[{"id":execution,"generation":2,"sequence":2,"state":"stopped","cpu_usec":0,"memory_bytes":0}]})).await.unwrap();
    assert_eq!(l.execution(execution).await["reserved"], false);
    assert_eq!(l.operation(&op).await["state"], "succeeded");
    let retry = l
        .store
        .delete_app(
            &l.operator,
            &l.tenant,
            &l.project,
            app,
            json!({"expected_revision":revision}),
            &key,
        )
        .await
        .unwrap();
    assert_eq!(retry["id"], op["id"]);
    assert_eq!(retry["state"], "succeeded");
    assert_eq!(l.execution(execution).await["generation"], 2);
    assert_eq!(
        l.store
            .run_app(&l.operator, &l.tenant, &l.project, app, &uid())
            .await
            .unwrap_err()
            .status,
        StatusCode::NOT_FOUND
    );
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM app_execution_contexts WHERE app_id=$1")
            .bind(app)
            .fetch_one(&l.store.pool)
            .await
            .unwrap();
    assert_eq!(count, 1);
    l.finish().await;
}
