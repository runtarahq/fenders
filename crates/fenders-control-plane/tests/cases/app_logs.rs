use super::execution_logs::{batch, record};
use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use fenders_control_plane::{app_logs::LogPage, apps::AppSubmission, error::Result};

impl Lab {
    async fn logs(&self, app: &str, page: Value) -> Result<Value> {
        self.store
            .app_logs(
                &self.operator,
                &self.tenant,
                &self.project,
                app,
                serde_json::from_value(page).unwrap(),
            )
            .await
    }
    async fn log_app(&self, name: &str, http: bool) -> (String, String) {
        let op=self.store.deploy_app(&self.operator,&self.tenant,&self.project,AppSubmission{value:json!({"name":name,"artifact_id":self.artifact,"triggers":{"http":http,"manual":!http}}),key:name,domain:"apps.test"}).await.unwrap();
        let app = s(&op["resource_id"]).to_owned();
        let release = self
            .store
            .app(&self.operator, &self.tenant, &self.project, &app)
            .await
            .unwrap()["target_release_id"]
            .as_str()
            .unwrap()
            .to_owned();
        (app, release)
    }
    async fn log_run(&self, app: &str) -> (String, Value) {
        let op = self
            .store
            .run_app(&self.operator, &self.tenant, &self.project, app, &uid())
            .await
            .unwrap();
        let waiting = self
            .logs(app, json!({"run_id":op["resource_id"]}))
            .await
            .unwrap();
        assert_eq!(waiting["collection"]["not_started"], 1);
        self.store.schedule().await.unwrap();
        let run = self
            .store
            .app_run(
                &self.operator,
                &self.tenant,
                &self.project,
                app,
                s(&op["resource_id"]),
            )
            .await
            .unwrap();
        (
            s(&run["id"]).to_owned(),
            self.execution(s(&run["execution_id"])).await,
        )
    }
    async fn log_batch(&self, node: &Value, e: &Value, value: Value) {
        self.store
            .ingest_execution_logs(s(&node["id"]), s(&e["id"]), n(&e["generation"]), value)
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn app_logs_join_manual_http_and_release_context_without_exposing_configuration() {
    let l = Lab::new().await;
    let node = l.node("worker").await;
    approve_component(&l, &node, true, true).await;
    let (app, release) = l.log_app("command", false).await;
    let detail = l
        .store
        .app_release(&l.operator, &l.tenant, &l.project, &app, &release)
        .await
        .unwrap();
    assert_eq!(detail["version"], 1);
    let history = l
        .store
        .app_history(
            &l.operator,
            &l.tenant,
            &l.project,
            &app,
            "releases",
            Default::default(),
        )
        .await
        .unwrap();
    assert_eq!(history["items"][0], detail);
    let empty = l.logs(&app, json!({})).await.unwrap();
    assert!(empty["items"].as_array().unwrap().is_empty());
    assert_eq!(empty["collection"]["executions"], 0);
    let (run, e) = l.log_run(&app).await;
    let awaiting = l.logs(&app, json!({})).await.unwrap();
    assert_eq!(awaiting["collection"]["awaiting"], 1);
    assert_eq!(awaiting["collection"]["complete"], 0);
    let data = b"<script>alert('x')</script>\0\xff";
    l.log_batch(
        &node,
        &e,
        batch(
            &uid(),
            1,
            3,
            true,
            json!([record(1, data), record(2, b"two"), record(3, b"three")]),
        ),
    )
    .await;
    let page = l.logs(&app, json!({"limit":1})).await.unwrap();
    assert_eq!(page["has_more"], true);
    assert_eq!(page["encoding"], "base64");
    assert_eq!(page["collection"]["complete"], 1);
    let entry = &page["items"][0];
    assert_eq!(entry["run_id"], run);
    assert_eq!(entry["execution_id"], e["id"]);
    assert_eq!(entry["release_id"], release);
    assert_eq!(entry["source"], "manual");
    assert_eq!(entry["version"], 1);
    assert!(entry["at_ms"].is_number());
    assert!(entry["received"].is_string());
    assert!(entry.get("cursor").is_none());
    assert!(entry.get("configuration").is_none());
    assert_eq!(STANDARD.decode(s(&entry["bytes"])).unwrap(), data);
    assert!(!page.to_string().contains("<script>"));
    let second = l
        .logs(&app, json!({"after":page["next"],"limit":1}))
        .await
        .unwrap();
    assert_eq!(second["items"][0]["sequence"], 2);
    let reopened = Store::from_pool(l.store.pool.clone(), l.root.path()).unwrap();
    let continued = reopened
        .app_logs(
            &l.operator,
            &l.tenant,
            &l.project,
            &app,
            serde_json::from_value(json!({"after":second["next"]})).unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(continued["items"][0]["sequence"], 3);
    assert_eq!(continued["has_more"], false);
    let caught = l
        .logs(&app, json!({"after":continued["next"]}))
        .await
        .unwrap();
    assert!(caught["items"].as_array().unwrap().is_empty());
    let filtered = l
        .logs(
            &app,
            json!({"release_id":release,"run_id":run,"execution_id":e["id"]}),
        )
        .await
        .unwrap();
    assert_eq!(filtered["items"].as_array().unwrap().len(), 3);
    l.report(&node, &e, "exited", 1).await;
    // Another invocation retains its own event/record identity.
    let (run2, e2) = l.log_run(&app).await;
    l.log_batch(
        &node,
        &e2,
        batch(&uid(), 1, 1, true, json!([record(1, b"second run")])),
    )
    .await;
    let polled = l.logs(&app, json!({"after":caught["next"]})).await.unwrap();
    assert_eq!(polled["items"][0]["run_id"], run2);
    let intersection = l
        .logs(&app, json!({"run_id":run,"execution_id":e2["id"]}))
        .await
        .unwrap();
    assert!(intersection["items"].as_array().unwrap().is_empty());
    assert_eq!(intersection["collection"]["executions"], 0);
    l.report(&node, &e2, "exited", 1).await;
    let (http, http_release) = l.log_app("http", true).await;
    l.store.schedule().await.unwrap();
    let http_execution = l.execution(s(&l.http(&http).await["execution_id"])).await;
    l.log_batch(
        &node,
        &http_execution,
        batch(&uid(), 1, 1, false, json!([record(1, b"request handled")])),
    )
    .await;
    let http_logs = l.logs(&http, json!({})).await.unwrap();
    assert_eq!(http_logs["items"][0]["source"], "http");
    assert!(http_logs["items"][0]["run_id"].is_null());
    assert_eq!(http_logs["items"][0]["release_id"], http_release);
    assert_eq!(http_logs["collection"]["collecting"], 1);
    assert_eq!(
        l.logs(&app, json!({})).await.unwrap()["items"]
            .as_array()
            .unwrap()
            .len(),
        4
    );
    l.finish().await;
}

#[tokio::test]
async fn app_log_authorization_filters_and_cursors_cannot_cross_scopes() {
    let l = Lab::new().await;
    let node = l.node("worker").await;
    approve_component(&l, &node, true, true).await;
    let (app, release) = l.log_app("first", false).await;
    let (run, e) = l.log_run(&app).await;
    l.log_batch(
        &node,
        &e,
        batch(&uid(), 1, 1, true, json!([record(1, b"one")])),
    )
    .await;
    l.report(&node, &e, "exited", 1).await;
    let (other, other_release) = l.log_app("other", false).await;
    let (other_run, other_e) = l.log_run(&other).await;
    l.log_batch(
        &node,
        &other_e,
        batch(&uid(), 1, 1, true, json!([record(1, b"other")])),
    )
    .await;
    for filter in [
        json!({"release_id":other_release}),
        json!({"run_id":other_run}),
        json!({"execution_id":other_e["id"]}),
    ] {
        assert_eq!(
            l.logs(&app, filter).await.unwrap_err().status,
            StatusCode::NOT_FOUND
        );
    }
    let page = l.logs(&app, json!({"run_id":run})).await.unwrap();
    for query in [
        json!({"after":page["next"]}),
        json!({"run_id":run,"release_id":release,"after":page["next"]}),
        json!({"after":"tampered"}),
        json!({"after":"x".repeat(2049)}),
        json!({"limit":0}),
        json!({"limit":101}),
    ] {
        assert_eq!(
            l.logs(&app, query).await.unwrap_err().status,
            StatusCode::BAD_REQUEST
        );
    }
    let other_page = l.logs(&other, json!({})).await.unwrap();
    let low_level = l.create("unowned", json!({"artifact_id":l.artifact})).await;
    assert_eq!(
        l.logs(&app, json!({"execution_id":low_level["resource_id"]}))
            .await
            .unwrap_err()
            .status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        l.logs(&app, json!({"after":other_page["next"]}))
            .await
            .unwrap_err()
            .status,
        StatusCode::BAD_REQUEST
    );
    let other_project = l
        .store
        .create_project(
            &l.operator,
            &l.tenant,
            serde_json::from_value(json!({"name":"other project"})).unwrap(),
        )
        .await
        .unwrap();
    let (foreign, _) = l.credential("viewer", Some(s(&other_project["id"]))).await;
    assert_eq!(
        l.store
            .app_logs(&foreign, &l.tenant, &l.project, &app, LogPage::default())
            .await
            .unwrap_err()
            .status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        l.store
            .app_logs(
                &l.operator,
                &l.tenant,
                s(&other_project["id"]),
                &app,
                LogPage::default()
            )
            .await
            .unwrap_err()
            .status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        l.store
            .app_logs(&l.operator, &uid(), &l.project, &app, LogPage::default())
            .await
            .unwrap_err()
            .status,
        StatusCode::NOT_FOUND
    );
    let (viewer, credential) = l.credential("viewer", Some(&l.project)).await;
    assert_eq!(
        l.store
            .app_logs(&viewer, &l.tenant, &l.project, &app, LogPage::default())
            .await
            .unwrap()["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let router = api::router(l.store.clone());
    let url = format!(
        "/v1/tenants/{}/projects/{}/apps/{}/logs",
        l.tenant, l.project, app
    );
    let req = |suffix: &str| {
        Request::builder()
            .uri(format!("{url}{suffix}"))
            .header(
                "Authorization",
                format!("Bearer {}", s(&credential["token"])),
            )
            .body(Body::empty())
            .unwrap()
    };
    let response = router.clone().oneshot(req("")).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(
        router
            .oneshot(req("?tenant_id=forged"))
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    // Recovery changes the cursor epoch, even though the encryption key persists.
    sqlx::query("UPDATE recovery_barrier SET restored=now(),active=true")
        .execute(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(
        l.logs(&app, json!({"run_id":run,"after":page["next"]}))
            .await
            .unwrap_err()
            .status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        l.logs(&app, json!({})).await.unwrap()["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    l.finish().await;
}

#[tokio::test]
async fn app_log_retention_pagination_and_incomplete_collection_are_explicit() {
    let l = Lab::new().await;
    let node = l.node("worker").await;
    approve_component(&l, &node, true, true).await;
    let (app, _) = l.log_app("logs", false).await;
    let (_, e) = l.log_run(&app).await;
    let capture = uid();
    l.log_batch(
        &node,
        &e,
        batch(
            &capture,
            3,
            11,
            false,
            json!(
                (3..=10)
                    .map(|seq| record(seq, &vec![b'x'; 8192]))
                    .collect::<Vec<_>>()
            ),
        ),
    )
    .await;
    l.log_batch(
        &node,
        &e,
        batch(
            &capture,
            3,
            11,
            false,
            json!([record(11, &vec![b'y'; 8192])]),
        ),
    )
    .await;
    let first = l.logs(&app, json!({"limit":100})).await.unwrap();
    assert_eq!(first["items"].as_array().unwrap().len(), 9);
    assert_eq!(first["has_more"], true);
    assert_eq!(first["items"][0]["stream"], "gap");
    assert_eq!(first["items"][0]["gap_from"], 1);
    assert_eq!(first["items"][0]["sequence"], 2);
    assert_eq!(first["collection"]["source_gaps"], 1);
    let bytes: i64 = first["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| n(&r["byte_count"]))
        .sum();
    assert_eq!(bytes, 65536);
    // Expiration is enforced at read time even when cleanup hasn't run. The
    // cursor still resumes correctly after its former anchor is deleted.
    sqlx::query(
        "UPDATE execution_log_records SET received=now()-interval '8 days' WHERE sequence<=10",
    )
    .execute(&l.store.pool)
    .await
    .unwrap();
    let uncleaned = l.logs(&app, json!({})).await.unwrap();
    assert_eq!(uncleaned["items"].as_array().unwrap().len(), 1);
    assert_eq!(uncleaned["collection"]["truncated_captures"], 1);
    l.store.schedule().await.unwrap();
    let next = l.logs(&app, json!({"after":first["next"]})).await.unwrap();
    assert_eq!(next["items"][0]["sequence"], 11);
    assert_eq!(next["has_more"], false);
    sqlx::query("UPDATE execution_log_sources SET updated=now()-interval '1 minute'")
        .execute(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(
        l.logs(&app, json!({})).await.unwrap()["collection"]["stale"],
        1
    );
    l.report(&node, &e, "exited", 1).await;
    assert_eq!(
        l.logs(&app, json!({})).await.unwrap()["collection"]["incomplete"],
        1
    );
    sqlx::query("UPDATE executions SET log_ingestion_fenced=true")
        .execute(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(
        l.logs(&app, json!({})).await.unwrap()["collection"]["fenced"],
        1
    );
    // A separate terminal execution without a source is unavailable, not empty.
    let (_, missing) = l.log_run(&app).await;
    l.report(&node, &missing, "failed", 1).await;
    sqlx::query("UPDATE executions SET updated=now()-interval '1 minute' WHERE id=$1")
        .bind(s(&missing["id"]))
        .execute(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(
        l.logs(&app, json!({"execution_id":missing["id"]}))
            .await
            .unwrap()["collection"]["unavailable"],
        1
    );
    l.log_batch(&node, &missing, batch(&uid(), 1, 0, true, json!([])))
        .await;
    let empty_complete = l
        .logs(&app, json!({"execution_id":missing["id"]}))
        .await
        .unwrap();
    assert!(empty_complete["items"].as_array().unwrap().is_empty());
    assert_eq!(empty_complete["collection"]["complete"], 1);
    l.finish().await;
}

#[tokio::test]
async fn interrupted_log_closure_is_durable_incomplete_and_never_recovers_execution() {
    let l = Lab::new().await;
    let node = l.node("worker").await;
    approve_component(&l, &node, true, true).await;
    let (app, _) = l.log_app("interrupted", false).await;
    let (_, e) = l.log_run(&app).await;
    let capture = uid();
    let mut body = batch(
        &capture,
        1,
        1,
        false,
        json!([record(1, b"retained before interruption")]),
    );
    body["interrupted"] = json!(true);
    assert!(
        l.store
            .ingest_execution_logs(
                s(&node["id"]),
                s(&e["id"]),
                n(&e["generation"]),
                body.clone()
            )
            .await
            .is_err()
    );
    body["closed"] = json!(true);
    let before = l.execution(s(&e["id"])).await;
    let receipt = l
        .store
        .ingest_execution_logs(
            s(&node["id"]),
            s(&e["id"]),
            n(&e["generation"]),
            body.clone(),
        )
        .await
        .unwrap();
    assert_eq!(
        receipt["cursor"]["complete"], true,
        "delivery is acknowledged"
    );
    assert_eq!(receipt["cursor"]["interrupted"], true);
    assert_eq!(
        l.execution(s(&e["id"])).await,
        before,
        "log closure cannot change execution or reservations"
    );
    let logs = l.logs(&app, json!({})).await.unwrap();
    assert_eq!(logs["collection"]["complete"], 0);
    assert_eq!(logs["collection"]["incomplete"], 1);
    assert_eq!(logs["items"].as_array().unwrap().len(), 1);
    let reopened = Store::from_pool(l.store.pool.clone(), l.root.path()).unwrap();
    reopened.migrate().await.unwrap();
    // An older duplicate receipt cannot erase the fact of interruption.
    body.as_object_mut().unwrap().remove("interrupted");
    let retried = reopened
        .ingest_execution_logs(
            s(&node["id"]),
            s(&e["id"]),
            n(&e["generation"]),
            body.clone(),
        )
        .await
        .unwrap();
    assert_eq!(retried["cursor"], receipt["cursor"]);
    assert!(
        reopened
            .ingest_execution_logs(&uid(), s(&e["id"]), n(&e["generation"]), body.clone())
            .await
            .is_err()
    );
    sqlx::query(
        "UPDATE execution_log_records SET received=now()-interval '8 days' WHERE execution_id=$1",
    )
    .bind(s(&e["id"]))
    .execute(&l.store.pool)
    .await
    .unwrap();
    l.store.schedule().await.unwrap();
    let expired = l.logs(&app, json!({})).await.unwrap();
    assert!(expired["items"].as_array().unwrap().is_empty());
    assert_eq!(expired["collection"]["incomplete"], 1);
    assert_eq!(expired["collection"]["truncated_captures"], 1);
    sqlx::query("UPDATE executions SET log_ingestion_fenced=true WHERE id=$1")
        .bind(s(&e["id"]))
        .execute(&l.store.pool)
        .await
        .unwrap();
    assert!(
        reopened
            .ingest_execution_logs(s(&node["id"]), s(&e["id"]), n(&e["generation"]), body)
            .await
            .is_err()
    );
    l.finish().await;
}
