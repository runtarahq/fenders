use super::*;
use fenders_control_plane::{app_events::EventPage, error::Result};
impl Lab {
    async fn events(&self, app: &str, page: Value) -> Result<Value> {
        self.store
            .app_events(
                &self.operator,
                &self.tenant,
                &self.project,
                app,
                serde_json::from_value(page).unwrap(),
            )
            .await
    }
}
#[tokio::test]
async fn lifecycle_events_are_atomic_deduplicated_scoped_observations_not_guest_text() {
    let l = Lab::new().await;
    let node = l.node("worker").await;
    approve_component(&l, &node, false, true).await;
    let op = l.deploy("events", false, true, "deploy").await.unwrap();
    let app = s(&op["resource_id"]);
    let initial = l.events(app, json!({})).await.unwrap()["items"].clone();
    l.deploy("events", false, true, "deploy").await.unwrap();
    assert_eq!(l.events(app, json!({})).await.unwrap()["items"], initial);
    let mut tx = l.store.pool.begin().await.unwrap();
    sqlx::query("UPDATE apps SET desired='stopped' WHERE id=$1")
        .bind(app)
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.rollback().await.unwrap();
    assert_eq!(l.events(app, json!({})).await.unwrap()["items"], initial);
    let run = l
        .store
        .run_app(&l.operator, &l.tenant, &l.project, app, "run")
        .await
        .unwrap();
    let run = l
        .store
        .app_run(
            &l.operator,
            &l.tenant,
            &l.project,
            app,
            s(&run["resource_id"]),
        )
        .await
        .unwrap();
    let execution = s(&run["execution_id"]);
    l.store.schedule().await.unwrap();
    let e = l.execution(execution).await;
    l.report(&node, &e, "running", 1).await;
    let running = l.events(app, json!({"run_id":run["id"]})).await.unwrap();
    assert_eq!(running["items"][0]["state"], "running");
    assert_eq!(running["items"][0]["version"], 1);
    assert_eq!(running["items"][0]["execution_id"], execution);
    l.report(&node, &e, "running", 2).await;
    assert_eq!(
        l.events(app, json!({"run_id":run["id"]})).await.unwrap()["items"],
        running["items"]
    );
    sqlx::query("UPDATE executions SET observation=observation || '{\"reason\":\"private-password<script>\",\"stderr\":\"private-output\"}'::jsonb WHERE id=$1").bind(execution).execute(&l.store.pool).await.unwrap();
    assert_eq!(
        l.events(app, json!({"run_id":run["id"]})).await.unwrap()["items"],
        running["items"]
    );
    sqlx::query("UPDATE executions SET state='failed',observation='{\"reason\":\"worker-lost\"}' WHERE id=$1").bind(execution).execute(&l.store.pool).await.unwrap();
    let unknown = l
        .events(app, json!({"execution_id":execution}))
        .await
        .unwrap();
    assert_eq!(unknown["items"][0]["outcome"], "unknown");
    assert_eq!(unknown["items"][0]["previous_state"], "running");
    assert!(unknown["items"][0]["exit_code"].is_null());
    assert!(!unknown.to_string().contains("private-"));
    let reopened = Store::from_pool(l.store.pool.clone(), l.root.path()).unwrap();
    assert_eq!(
        reopened
            .app_events(
                &l.operator,
                &l.tenant,
                &l.project,
                app,
                serde_json::from_value(json!({"execution_id":execution})).unwrap()
            )
            .await
            .unwrap()["items"],
        unknown["items"]
    );
}
#[tokio::test]
async fn lifecycle_event_pages_enforce_roles_filters_cursors_and_retention() {
    let l = Lab::new().await;
    let node = l.node("worker").await;
    approve_component(&l, &node, false, true).await;
    let op = l.deploy("events", false, true, "deploy").await.unwrap();
    let app = s(&op["resource_id"]);
    let other = l.deploy("other", false, true, "other").await.unwrap();
    let other = s(&other["resource_id"]);
    let first = l.events(app, json!({"limit":1})).await.unwrap();
    assert!(first["next"].is_string());
    let second = l
        .events(app, json!({"limit":1,"before":first["next"]}))
        .await
        .unwrap();
    assert_ne!(first["items"][0]["id"], second["items"][0]["id"]);
    assert_eq!(
        l.events(other, json!({"before":first["next"]}))
            .await
            .unwrap_err()
            .status,
        StatusCode::NOT_FOUND
    );
    for bad in [json!({"limit":0}), json!({"limit":101})] {
        assert_eq!(
            l.events(app, bad).await.unwrap_err().status,
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(
        l.events(app, json!({"before":"bad"}))
            .await
            .unwrap_err()
            .status,
        StatusCode::NOT_FOUND
    );
    let (viewer, credential) = l.credential("viewer", Some(&l.project)).await;
    assert!(
        !l.store
            .app_events(&viewer, &l.tenant, &l.project, app, EventPage::default())
            .await
            .unwrap()["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        l.store
            .app_events(&viewer, &uid(), &l.project, app, EventPage::default())
            .await
            .unwrap_err()
            .status,
        StatusCode::NOT_FOUND
    );
    let project = l
        .store
        .create_project(
            &l.operator,
            &l.tenant,
            serde_json::from_value(json!({"name":"another"})).unwrap(),
        )
        .await
        .unwrap();
    let (foreign, _) = l.credential("viewer", Some(s(&project["id"]))).await;
    assert_eq!(
        l.store
            .app_events(&foreign, &l.tenant, &l.project, app, EventPage::default())
            .await
            .unwrap_err()
            .status,
        StatusCode::NOT_FOUND
    );
    let foreign_release = l
        .store
        .app(&l.operator, &l.tenant, &l.project, other)
        .await
        .unwrap()["target_release_id"]
        .clone();
    assert_eq!(
        l.events(app, json!({"release_id":foreign_release}))
            .await
            .unwrap_err()
            .status,
        StatusCode::NOT_FOUND
    );
    let response = api::router(l.store.clone())
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/workspaces/{}/projects/{}/apps/{app}/events",
                    l.tenant, l.project
                ))
                .header(
                    "Authorization",
                    format!("Bearer {}", s(&credential["token"])),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    sqlx::query(
        "UPDATE app_lifecycle_events SET recorded_at=now()-interval '31 days' WHERE app_id=$1",
    )
    .bind(app)
    .execute(&l.store.pool)
    .await
    .unwrap();
    assert!(
        l.events(app, json!({})).await.unwrap()["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        l.events(app, json!({"before":first["next"]}))
            .await
            .unwrap_err()
            .status,
        StatusCode::NOT_FOUND
    );
    sqlx::query("INSERT INTO app_lifecycle_events(tenant_id,project_id,app_id,kind,state,recorded_at) SELECT $1,$2,$3,'app','enabled',now()-interval '31 days' FROM generate_series(1,600)").bind(&l.tenant).bind(&l.project).bind(app).execute(&l.store.pool).await.unwrap();
    let count =
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM app_lifecycle_events WHERE app_id=$1")
            .bind(app)
            .fetch_one(&l.store.pool)
            .await
            .unwrap();
    sqlx::query("UPDATE recovery_barrier SET active=true")
        .execute(&l.store.pool)
        .await
        .unwrap();
    assert!(l.store.schedule().await.is_err());
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM app_lifecycle_events WHERE app_id=$1")
            .bind(app)
            .fetch_one(&l.store.pool)
            .await
            .unwrap(),
        count
    );
    sqlx::query("UPDATE recovery_barrier SET active=false")
        .execute(&l.store.pool)
        .await
        .unwrap();
    l.store.schedule().await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM app_lifecycle_events WHERE app_id=$1")
            .bind(app)
            .fetch_one(&l.store.pool)
            .await
            .unwrap(),
        count - 512
    );
    assert!(
        !l.events(other, json!({})).await.unwrap()["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn lifecycle_http_attempts_retain_context_and_stop_intent_without_claiming_completion() {
    let l = Lab::new().await;
    let node = l.node("http-worker").await;
    approve_component(&l, &node, true, false).await;
    let op = l.deploy("web", true, false, "web").await.unwrap();
    let app = s(&op["resource_id"]);
    l.store.schedule().await.unwrap();
    let http = l.http(app).await;
    let execution = s(&http["execution_id"]);
    let e = l.execution(execution).await;
    l.report(&node, &e, "running", 1).await;
    l.store.schedule().await.unwrap();
    let page = l
        .events(app, json!({"execution_id":execution}))
        .await
        .unwrap();
    assert!(
        page["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["kind"] == "execution"
                && e["state"] == "running"
                && e["version"] == 1
                && e["source"] == "http")
    );
    assert!(
        page["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["kind"] == "http" && e["state"] == "serving")
    );
    assert!(
        page["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e["outcome"].is_null())
    );
    let summary = l
        .store
        .app(&l.operator, &l.tenant, &l.project, app)
        .await
        .unwrap();
    l.store
        .app_lifecycle(
            &l.operator,
            &l.tenant,
            &l.project,
            app,
            json!({"desired":"stopped","expected_revision":summary["revision"]}),
            "stop",
        )
        .await
        .unwrap();
    let events = l.events(app, json!({})).await.unwrap();
    assert!(
        events["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["kind"] == "app"
                && e["state"] == "stopped"
                && e["previous_state"] == "enabled")
    );
    assert!(
        events["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["kind"] == "http" && e["state"] == "stopping")
    );
    assert_eq!(l.execution(execution).await["reserved"], true);
}
