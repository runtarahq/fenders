//! Atomic customer submissions against PostgreSQL, with trusted-worker protocol
//! receipts. Actual WASM parsing/execution has separate acceptance coverage.
use super::*;
use fenders_control_plane::{apps::AppSubmission, error::Result};

impl Lab {
    pub(super) async fn deploy(
        &self,
        name: &str,
        http: bool,
        manual: bool,
        key: &str,
    ) -> Result<Value> {
        self.store.deploy_app(&self.operator,&self.tenant,&self.project,AppSubmission {
            value:json!({"name":name,"artifact_id":self.artifact,"triggers":{"http":http,"manual":manual}}),key,domain:"apps.test"
        }).await
    }
    async fn app_counts(&self) -> Value {
        sqlx::query_scalar("SELECT jsonb_build_object('apps',(SELECT count(*) FROM apps),'versions',(SELECT count(*) FROM app_versions),'triggers',(SELECT count(*) FROM app_triggers),'releases',(SELECT count(*) FROM app_releases),'http',(SELECT count(*) FROM app_http),'executions',(SELECT count(*) FROM executions),'deployments',(SELECT count(*) FROM deployments),'routes',(SELECT count(*) FROM routes),'operations',(SELECT count(*) FROM operations),'runs',(SELECT count(*) FROM app_runs))").fetch_one(&self.store.pool).await.unwrap()
    }
}

#[tokio::test]
async fn command_wizard_submission_captures_defaults_once_and_waits_for_an_event() {
    let l = Lab::new().await;
    let node = l.node("compiler").await;
    approve_component(&l, &node, false, true).await;
    sqlx::query("UPDATE tenants SET default_app_size='medium'")
        .execute(&l.store.pool)
        .await
        .unwrap();
    let (a, b) = tokio::join!(
        l.deploy("command", false, true, "same"),
        l.deploy("command", false, true, "same")
    );
    let op = a.unwrap();
    assert_eq!(op, b.unwrap());
    assert_eq!(op["state"], "succeeded");
    assert_eq!(op["kind"], "deploy-app");
    let app = s(&op["resource_id"]);
    let summary = l
        .store
        .app(&l.operator, &l.tenant, &l.project, app)
        .await
        .unwrap();
    assert_eq!(summary["desired"], "enabled");
    assert_eq!(summary["state"], "ready");
    assert_eq!(summary["configuration"]["size"], "medium");
    assert_eq!(
        summary["triggers"],
        json!({"manual":true,"http":false,"schedule":false,"revision":1})
    );
    assert_eq!(summary["active_release"]["version"], 1);
    assert_eq!(
        l.app_counts().await,
        json!({"apps":1,"versions":1,"triggers":1,"releases":1,"http":0,"executions":0,"deployments":0,"routes":0,"operations":1,"runs":0})
    );
    assert_eq!(
        l.deploy("command", false, false, "same")
            .await
            .unwrap_err()
            .status,
        StatusCode::CONFLICT
    );
    assert_eq!(
        l.deploy("command", false, true, "different")
            .await
            .unwrap_err()
            .status,
        StatusCode::CONFLICT
    );
    sqlx::query("UPDATE tenants SET default_app_size='large'")
        .execute(&l.store.pool)
        .await
        .unwrap();
    let reopened = Store::from_pool(l.store.pool.clone(), l.root.path()).unwrap();
    assert_eq!(reopened.deploy_app(&l.operator,&l.tenant,&l.project,AppSubmission{value:json!({"name":"command","artifact_id":l.artifact,"triggers":{"http":false,"manual":true}}),key:"same",domain:"new-domain.test"}).await.unwrap(),op);
    assert_eq!(
        reopened
            .app(&l.operator, &l.tenant, &l.project, app)
            .await
            .unwrap()["configuration"]["size"],
        "medium"
    );
    let run = l
        .store
        .run_app(&l.operator, &l.tenant, &l.project, app, "explicit-event")
        .await
        .unwrap();
    assert_eq!(
        l.store
            .app_run(
                &l.operator,
                &l.tenant,
                &l.project,
                app,
                s(&run["resource_id"])
            )
            .await
            .unwrap()["release_id"],
        summary["active_release"]["id"]
    );
    assert_eq!(l.app_counts().await["executions"], 1);
    sqlx::query("UPDATE recovery_barrier SET active=true")
        .execute(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(
        l.deploy("command", false, true, "same")
            .await
            .unwrap_err()
            .status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    l.finish().await;
}

#[tokio::test]
async fn http_wizard_api_returns_one_durable_operation_and_no_implicit_command() {
    let l = Lab::new().await;
    let node = l.node("worker").await;
    approve_component(&l, &node, true, true).await;
    let secret = l
        .store
        .create_secret(
            &l.operator,
            &l.tenant,
            &l.project,
            json!({"name":"api-key","value":"never-in-app-output"}),
        )
        .await
        .unwrap();
    let router = api::management(api::ApiState {
        store: l.store.clone(),
        domain: "sandbox.example.test".into(),
        tls: None,
    });
    let body = json!({"name":"dual","artifact_id":l.artifact,"triggers":{"http":true,"manual":true},"configuration":{"size":"small","env":{"MODE":"production"},"secret_env":{"TOKEN":secret["id"]}}});
    let request = |key: &str| {
        Request::builder()
            .method("POST")
            .uri(format!(
                "/v1/tenants/{}/projects/{}/apps/deploy",
                l.tenant, l.project
            ))
            .header("Authorization", format!("Bearer {}", l.token))
            .header("Idempotency-Key", key)
            .header("Content-Type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    };
    assert_eq!(
        router.clone().oneshot(request("")).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(l.app_counts().await["apps"], 0);
    let response = router.clone().oneshot(request("deploy")).await.unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let op: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 8192).await.unwrap()).unwrap();
    let app = s(&op["resource_id"]);
    assert_eq!(op["state"], "pending");
    let summary = l
        .store
        .app(&l.operator, &l.tenant, &l.project, app)
        .await
        .unwrap();
    assert_eq!(summary["state"], "preparing");
    assert_eq!(summary["configuration"]["env"]["MODE"], "production");
    assert!(!summary.to_string().contains("never-in-app-output"));
    assert_eq!(
        summary["http"]["url"],
        format!("https://app-{app}.sandbox.example.test")
    );
    assert_eq!(l.app_counts().await["executions"], 1);
    assert_eq!(l.app_counts().await["runs"], 0);
    let e = l.http_running(app, &node).await;
    assert_eq!(e["spec"]["mode"], "http");
    assert_eq!(l.operation(&op).await["state"], "succeeded");
    let retry = router.oneshot(request("deploy")).await.unwrap();
    assert_eq!(retry.status(), StatusCode::CREATED);
    let retry: Value =
        serde_json::from_slice(&to_bytes(retry.into_body(), 8192).await.unwrap()).unwrap();
    assert_eq!(retry["id"], op["id"]);
    assert_eq!(l.app_counts().await["executions"], 1);
    l.store
        .run_app(&l.operator, &l.tenant, &l.project, app, "now")
        .await
        .unwrap();
    assert_eq!(
        l.store.usage(&l.operator, &l.tenant, None).await.unwrap()["reserved"]["instances"],
        2
    );
    l.finish().await;
}

#[tokio::test]
async fn wizard_rejects_invalid_scope_capabilities_and_configuration_without_partial_records() {
    let l = Lab::new().await;
    let empty = l.app_counts().await;
    assert_eq!(
        l.deploy("pending", true, false, "pending")
            .await
            .unwrap_err()
            .status,
        StatusCode::CONFLICT
    );
    assert_eq!(l.app_counts().await, empty);
    let node = l.node("compiler").await;
    approve_component(&l, &node, true, false).await;
    assert_eq!(
        l.deploy("bad-command", true, true, "bad-command")
            .await
            .unwrap_err()
            .status,
        StatusCode::CONFLICT
    );
    let base = json!({"name":"candidate","artifact_id":l.artifact,"triggers":{"http":true,"manual":false}});
    let mut cases = Vec::new();
    let mut v = base.clone();
    v["triggers"]["http"] = json!("true");
    cases.push((v, StatusCode::BAD_REQUEST, "apps.test"));
    let mut v = base.clone();
    v["triggers"]["schedule"] = json!("* * * * *");
    cases.push((v, StatusCode::BAD_REQUEST, "apps.test"));
    let mut v = base.clone();
    v["configuration"] = json!({"size":"unlimited"});
    cases.push((v, StatusCode::BAD_REQUEST, "apps.test"));
    let mut v = base.clone();
    v["configuration"] = json!({"secret_env":{"TOKEN":uid()}});
    cases.push((v, StatusCode::NOT_FOUND, "apps.test"));
    let mut v = base.clone();
    v["artifact_id"] = json!(uid());
    cases.push((v, StatusCode::NOT_FOUND, "apps.test"));
    let mut v = base.clone();
    v["runtime"] = json!("customer-claimed");
    cases.push((v, StatusCode::BAD_REQUEST, "apps.test"));
    cases.push((base.clone(), StatusCode::BAD_REQUEST, "invalid/domain"));
    for (value, status, domain) in cases {
        assert_eq!(
            l.store
                .deploy_app(
                    &l.operator,
                    &l.tenant,
                    &l.project,
                    AppSubmission {
                        value,
                        key: "reusable-after-rejection",
                        domain
                    }
                )
                .await
                .unwrap_err()
                .status,
            status
        );
        assert_eq!(l.app_counts().await, empty);
    }
    let (viewer, _) = l.credential("viewer", Some(&l.project)).await;
    assert_eq!(
        l.store
            .deploy_app(
                &viewer,
                &l.tenant,
                &l.project,
                AppSubmission {
                    value: base.clone(),
                    key: "viewer",
                    domain: "apps.test"
                }
            )
            .await
            .unwrap_err()
            .status,
        StatusCode::FORBIDDEN
    );
    let other = l
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
            .deploy_app(
                &l.operator,
                &l.tenant,
                s(&other["id"]),
                AppSubmission {
                    value: base.clone(),
                    key: "foreign",
                    domain: "apps.test"
                }
            )
            .await
            .unwrap_err()
            .status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(l.app_counts().await, empty);
    let valid = l
        .store
        .deploy_app(
            &l.operator,
            &l.tenant,
            &l.project,
            AppSubmission {
                value: base,
                key: "reusable-after-rejection",
                domain: "apps.test",
            },
        )
        .await
        .unwrap();
    assert_eq!(valid["state"], "pending");
    l.finish().await;
}

#[tokio::test]
async fn wizard_rolls_back_late_failure_including_http_reservation_and_can_retry() {
    let l = Lab::new().await;
    let node = l.node("compiler").await;
    approve_component(&l, &node, true, true).await;
    let before = l.app_counts().await;
    // Inject a storage failure after the domain work, at the final audit write.
    sqlx::raw_sql("CREATE FUNCTION fail_app_deploy() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected failure'; END $$; CREATE TRIGGER fail_app_deploy BEFORE INSERT ON audit FOR EACH ROW WHEN (NEW.action='app.deploy') EXECUTE FUNCTION fail_app_deploy()").execute(&l.store.pool).await.unwrap();
    assert_eq!(
        l.deploy("atomic", true, true, "atomic")
            .await
            .unwrap_err()
            .status,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(l.app_counts().await, before);
    assert_eq!(
        l.store.usage(&l.operator, &l.tenant, None).await.unwrap()["reserved"]["instances"],
        0
    );
    sqlx::query("DROP TRIGGER fail_app_deploy ON audit")
        .execute(&l.store.pool)
        .await
        .unwrap();
    let op = l.deploy("atomic", true, true, "atomic").await.unwrap();
    assert_eq!(op["state"], "pending");
    assert_eq!(
        l.app_counts().await,
        json!({"apps":1,"versions":1,"triggers":1,"releases":1,"http":1,"executions":1,"deployments":1,"routes":1,"operations":1,"runs":0})
    );
    l.finish().await;
}

#[tokio::test]
async fn concurrent_wizard_submissions_share_quota_and_expose_capacity_waits() {
    let l = Lab::new().await;
    let node = l.node("compiler").await;
    approve_component(&l, &node, true, true).await;
    sqlx::query("UPDATE tenants SET instances=1")
        .execute(&l.store.pool)
        .await
        .unwrap();
    let (a, b) = tokio::join!(
        l.deploy("first", true, false, "first"),
        l.deploy("second", true, false, "second")
    );
    let (a, b) = (a.unwrap(), b.unwrap());
    assert_eq!(a["state"], "pending");
    assert_eq!(b["state"], "pending");
    let a = l.http(s(&a["resource_id"])).await;
    let b = l.http(s(&b["resource_id"])).await;
    assert_ne!(a["execution_id"].is_null(), b["execution_id"].is_null());
    assert!(a["reason"] == "allowance-exhausted" || b["reason"] == "allowance-exhausted");
    assert_eq!(l.app_counts().await["apps"], 2);
    assert_eq!(l.app_counts().await["executions"], 1);
    assert_eq!(
        l.store.usage(&l.operator, &l.tenant, None).await.unwrap()["reserved"]["instances"],
        1
    );
    l.finish().await;
}

#[tokio::test]
async fn deployment_receipt_recovery_is_scoped_and_catalog_exposes_draft_default() {
    let l = Lab::new().await;
    let node = l.node("compiler").await;
    approve_component(&l, &node, false, true).await;
    let (editor, _) = l.credential("editor", Some(&l.project)).await;
    let (viewer, _) = l.credential("viewer", Some(&l.project)).await;
    sqlx::query("UPDATE tenants SET default_app_size='medium' WHERE id=$1")
        .bind(&l.tenant)
        .execute(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(
        l.store
            .app_sizes(&editor, &l.tenant, &l.project)
            .await
            .unwrap()["default_size"],
        "medium"
    );
    let key = uid();
    assert_eq!(
        l.store
            .app_submission(&viewer, &l.tenant, &l.project, &key)
            .await
            .unwrap_err()
            .status,
        StatusCode::NOT_FOUND
    );
    let op = l.deploy("recoverable", false, true, &key).await.unwrap();
    let recovered = l
        .store
        .app_submission(&viewer, &l.tenant, &l.project, &key)
        .await
        .unwrap();
    assert_eq!(recovered["id"], op["id"]);
    assert_eq!(recovered["resource_id"], op["resource_id"]);
    assert_eq!(recovered["state"], "succeeded");
    assert_eq!(recovered.as_object().unwrap().len(), 7);
    assert!(recovered.get("request_hash").is_none());
    let other = l
        .store
        .create_project(
            &l.operator,
            &l.tenant,
            Named {
                name: "other".into(),
            },
        )
        .await
        .unwrap();
    assert_eq!(
        l.store
            .app_submission(&l.operator, &l.tenant, s(&other["id"]), &key)
            .await
            .unwrap_err()
            .status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        l.store
            .app_submission(&viewer, &l.tenant, s(&other["id"]), &key)
            .await
            .unwrap_err()
            .status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        l.store
            .app_submission(&l.operator, &uid(), &l.project, &key)
            .await
            .unwrap_err()
            .status,
        StatusCode::NOT_FOUND
    );
    let creation_key = uid();
    l.store
        .create_app(
            &l.operator,
            &l.tenant,
            &l.project,
            json!({"name":"code-only","artifact_id":l.artifact}),
            &creation_key,
        )
        .await
        .unwrap();
    assert_eq!(
        l.store
            .app_submission(&l.operator, &l.tenant, &l.project, &creation_key)
            .await
            .unwrap_err()
            .status,
        StatusCode::NOT_FOUND
    );
    let reopened = Store::from_pool(l.store.pool.clone(), l.root.path()).unwrap();
    let response = api::router(reopened)
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/tenants/{}/projects/{}/app-submissions/{}",
                    l.tenant, l.project, key
                ))
                .header("Authorization", format!("Bearer {}", l.token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let value: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 8192).await.unwrap()).unwrap();
    assert_eq!(value, recovered);
    sqlx::query("UPDATE recovery_barrier SET active=true")
        .execute(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(
        l.store
            .app_submission(&viewer, &l.tenant, &l.project, &key)
            .await
            .unwrap(),
        recovered
    );
    assert_eq!(l.app_counts().await["executions"], 0);
    l.finish().await;
}

#[tokio::test]
async fn app_action_receipts_are_scoped_and_busy_state_tracks_reservations() {
    let l = Lab::new().await;
    let node = l.node("compiler").await;
    approve_component(&l, &node, true, true).await;
    let deploy = l.deploy("actions", false, true, &uid()).await.unwrap();
    let app = s(&deploy["resource_id"]);
    let other = l.deploy("other", false, true, &uid()).await.unwrap();
    let (viewer, _) = l.credential("viewer", Some(&l.project)).await;
    let trigger_key = uid();
    let initial = l
        .store
        .app(&viewer, &l.tenant, &l.project, app)
        .await
        .unwrap();
    let trigger_op = l
        .store
        .update_app_triggers(
            &l.operator,
            &l.tenant,
            &l.project,
            app,
            json!({"manual":true,"expected_revision":initial["triggers"]["revision"]}),
            &trigger_key,
        )
        .await
        .unwrap();
    let trigger_receipt = l
        .store
        .app_action_submission(&viewer, &l.tenant, &l.project, app, &trigger_key)
        .await
        .unwrap();
    assert_eq!(trigger_receipt["id"], trigger_op["id"]);
    assert_eq!(trigger_receipt["kind"], "app-triggers");
    assert_eq!(trigger_receipt.as_object().unwrap().len(), 7);
    assert_eq!(
        l.store
            .app_action_submission(
                &viewer,
                &l.tenant,
                &l.project,
                s(&other["resource_id"]),
                &trigger_key
            )
            .await
            .unwrap_err()
            .status,
        StatusCode::NOT_FOUND
    );
    let run_key = uid();
    let op = l
        .store
        .run_app(&l.operator, &l.tenant, &l.project, app, &run_key)
        .await
        .unwrap();
    let receipt = l
        .store
        .app_action_submission(&viewer, &l.tenant, &l.project, app, &run_key)
        .await
        .unwrap();
    assert_eq!(receipt["id"], op["id"]);
    assert_eq!(receipt.as_object().unwrap().len(), 7);
    assert_eq!(
        l.store
            .app(&viewer, &l.tenant, &l.project, app)
            .await
            .unwrap()["command_busy"],
        true
    );
    let items = l
        .store
        .apps(&viewer, &l.tenant, &l.project, Default::default())
        .await
        .unwrap();
    assert_eq!(
        items["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["id"] == app)
            .unwrap()["command_busy"],
        true
    );
    assert_eq!(
        l.store
            .app_action_submission(
                &viewer,
                &l.tenant,
                &l.project,
                s(&other["resource_id"]),
                &run_key
            )
            .await
            .unwrap_err()
            .status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        l.store
            .app_action_submission(&l.operator, &uid(), &l.project, app, &run_key)
            .await
            .unwrap_err()
            .status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        l.store
            .app_action_submission(&l.operator, &l.tenant, &uid(), app, &run_key)
            .await
            .unwrap_err()
            .status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        l.store
            .app_action_submission(&viewer, &l.tenant, &l.project, app, "bad")
            .await
            .unwrap_err()
            .status,
        StatusCode::NOT_FOUND
    );
    let reopened = Store::from_pool(l.store.pool.clone(), l.root.path()).unwrap();
    let response = api::router(reopened)
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/tenants/{}/projects/{}/apps/{}/submissions/{}",
                    l.tenant, l.project, app, run_key
                ))
                .header("Authorization", format!("Bearer {}", l.token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let got: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 8192).await.unwrap()).unwrap();
    assert_eq!(got, receipt);
    assert_eq!(
        l.store
            .run_app(&l.operator, &l.tenant, &l.project, app, &run_key)
            .await
            .unwrap()["resource_id"],
        op["resource_id"]
    );
    // Assigned unknown workers remain busy even if newer skipped occurrences
    // later appear in the run history; this does not derive from latest_run.
    l.store.schedule().await.unwrap();
    let run = l
        .store
        .app_run(&viewer, &l.tenant, &l.project, app, s(&op["resource_id"]))
        .await
        .unwrap();
    let e = l.execution(s(&run["execution_id"])).await;
    assert_eq!(
        l.store
            .app(&viewer, &l.tenant, &l.project, app)
            .await
            .unwrap()["command_busy"],
        true
    );
    l.report(&node, &e, "exited", 1).await;
    let settled = l
        .store
        .app(&viewer, &l.tenant, &l.project, app)
        .await
        .unwrap();
    assert_eq!(settled["command_busy"], false);
    let stop_key = uid();
    let stop = l
        .store
        .app_lifecycle(
            &l.operator,
            &l.tenant,
            &l.project,
            app,
            json!({"desired":"stopped","expected_revision":settled["revision"]}),
            &stop_key,
        )
        .await
        .unwrap();
    assert_eq!(
        l.store
            .app_action_submission(&viewer, &l.tenant, &l.project, app, &stop_key)
            .await
            .unwrap()["id"],
        stop["id"]
    );
    let release_key = uid();
    let stopped = l
        .store
        .app(&viewer, &l.tenant, &l.project, app)
        .await
        .unwrap();
    let release=l.store.activate_app_release(&l.operator,&l.tenant,&l.project,app,json!({"version_id":stopped["latest_code"]["id"],"expected_revision":stopped["revision"]}),&release_key).await.unwrap();
    let receipt = l
        .store
        .app_action_submission(&viewer, &l.tenant, &l.project, app, &release_key)
        .await
        .unwrap();
    assert_eq!(receipt["id"], release["id"]);
    assert_eq!(receipt["kind"], "activate-app-release");
    assert_eq!(receipt.as_object().unwrap().len(), 7);
    assert_eq!(
        l.store
            .app_action_submission(
                &viewer,
                &l.tenant,
                &l.project,
                s(&other["resource_id"]),
                &release_key
            )
            .await
            .unwrap_err()
            .status,
        StatusCode::NOT_FOUND
    );
    let attach_key = uid();
    let current = l
        .store
        .app(&viewer, &l.tenant, &l.project, app)
        .await
        .unwrap();
    let attached = l
        .store
        .attach_app_version(
            &l.operator,
            &l.tenant,
            &l.project,
            app,
            json!({"artifact_id":l.artifact,"expected_revision":current["revision"]}),
            &attach_key,
        )
        .await
        .unwrap();
    let attach_receipt = l
        .store
        .app_action_submission(&viewer, &l.tenant, &l.project, app, &attach_key)
        .await
        .unwrap();
    assert_eq!(attach_receipt["id"], attached["id"]);
    assert_eq!(attach_receipt["kind"], "attach-app-version");
    assert_eq!(attach_receipt["resource_id"], current["latest_code"]["id"]);
    assert_eq!(attach_receipt.as_object().unwrap().len(), 7);
    for (tenant, project, target) in [
        (
            l.tenant.clone(),
            l.project.clone(),
            s(&other["resource_id"]).to_string(),
        ),
        (uid(), l.project.clone(), app.to_string()),
        (l.tenant.clone(), uid(), app.to_string()),
    ] {
        assert_eq!(
            l.store
                .app_action_submission(&l.operator, &tenant, &project, &target, &attach_key)
                .await
                .unwrap_err()
                .status,
            StatusCode::NOT_FOUND
        );
    }
    let excluded_key = uid();
    l.store
        .create_app(
            &l.operator,
            &l.tenant,
            &l.project,
            json!({"name":"code-only-receipt","artifact_id":l.artifact}),
            &excluded_key,
        )
        .await
        .unwrap();
    assert_eq!(
        l.store
            .app_action_submission(&viewer, &l.tenant, &l.project, app, &excluded_key)
            .await
            .unwrap_err()
            .status,
        StatusCode::NOT_FOUND
    );
    sqlx::query("UPDATE recovery_barrier SET active=true")
        .execute(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(
        Store::from_pool(l.store.pool.clone(), l.root.path())
            .unwrap()
            .app_action_submission(&viewer, &l.tenant, &l.project, app, &attach_key)
            .await
            .unwrap(),
        attach_receipt
    );
    assert_eq!(
        l.store
            .app_action_submission(&viewer, &l.tenant, &l.project, app, &stop_key)
            .await
            .unwrap()["id"],
        stop["id"]
    );
    assert_eq!(l.app_counts().await["runs"], 1);
    l.finish().await;
}

#[tokio::test]
async fn referenced_secret_metadata_is_scoped_even_beyond_the_list_bound() {
    let l = Lab::new().await;
    let secret = l
        .store
        .create_secret(
            &l.operator,
            &l.tenant,
            &l.project,
            json!({"name":"original","value":"never-return-this-value"}),
        )
        .await
        .unwrap();
    // Put the referenced secret outside the bounded list without changing it.
    sqlx::query("INSERT INTO secrets(id,tenant_id,project_id,name,ciphertext,created) SELECT md5($1||g::text),tenant_id,project_id,'newer-'||g::text,ciphertext,created+interval '1 second' FROM secrets CROSS JOIN generate_series(1,1000) g WHERE id=$1")
        .bind(s(&secret["id"])).execute(&l.store.pool).await.unwrap();
    let (viewer, credential) = l.credential("viewer", Some(&l.project)).await;
    let list = l
        .store
        .resources(&viewer, &l.tenant, &l.project, "secrets", None)
        .await
        .unwrap();
    assert_eq!(list.as_array().unwrap().len(), 1000);
    assert!(
        !list
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["id"] == secret["id"])
    );
    let router = api::router(l.store.clone());
    let response = router
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/tenants/{}/projects/{}/secrets/{}",
                    l.tenant,
                    l.project,
                    s(&secret["id"])
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
    let metadata: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 8192).await.unwrap()).unwrap();
    assert_eq!(metadata, secret);
    assert_eq!(metadata.as_object().unwrap().len(), 3);
    assert!(!metadata.to_string().contains("never-return-this-value"));
    for (tenant, project) in [(uid(), l.project.clone()), (l.tenant.clone(), uid())] {
        assert_eq!(
            l.store
                .resources(
                    &l.operator,
                    &tenant,
                    &project,
                    "secrets",
                    Some(s(&secret["id"]))
                )
                .await
                .unwrap_err()
                .status,
            StatusCode::NOT_FOUND
        );
    }
    l.finish().await;
}

/// SYN-794: an enabled app's active release is offered to nodes for
/// pre-warming, as a running deployment's component is, so its first manual
/// or scheduled run need not wait for a compile; a stopped app's is not.
#[tokio::test]
async fn an_enabled_apps_active_release_is_offered_for_prewarm() {
    let l = Lab::new().await;
    let node = l.node("compiler").await;
    approve_component(&l, &node, false, true).await;
    let node_id = s(&node["id"]);
    assert!(l.store.prewarm_digests(node_id).await.unwrap().is_empty());
    let op = l.deploy("command", false, true, "prewarm").await.unwrap();
    assert_eq!(op["state"], "succeeded");
    let digest: String = sqlx::query_scalar("SELECT digest FROM artifacts WHERE id=$1")
        .bind(&l.artifact)
        .fetch_one(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(
        l.store.prewarm_digests(node_id).await.unwrap(),
        vec![json!(digest)]
    );
    sqlx::query("UPDATE apps SET desired='stopped'")
        .execute(&l.store.pool)
        .await
        .unwrap();
    assert!(l.store.prewarm_digests(node_id).await.unwrap().is_empty());
}
