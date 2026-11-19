use super::*;
use fenders_control_plane::app_runtime::HistoryPage;

async fn history(
    l: &Lab,
    app: &str,
    trigger: Option<&str>,
    before: Option<&str>,
    limit: i64,
) -> Value {
    l.store
        .app_history(
            &l.operator,
            &l.tenant,
            &l.project,
            app,
            "runs",
            HistoryPage {
                trigger: trigger.map(str::to_owned),
                before: before.map(str::to_owned),
                limit: Some(limit),
            },
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn http_runs_share_history_filters_and_scoped_logs_without_affecting_commands() {
    let l = Lab::new().await;
    let node = l.node("worker").await;
    approve_component(&l, &node, true, true).await;
    let op=l.store.deploy_app(&l.operator,&l.tenant,&l.project,fenders_control_plane::apps::AppSubmission {
        value:json!({"name":"all-runs","artifact_id":l.artifact,"triggers":{"http":true,"manual":true}}),key:"deploy",domain:"apps.test"
    }).await.unwrap();
    let app = s(&op["resource_id"]);
    l.http_running(app, &node).await;
    assert!(
        history(&l, app, None, None, 20).await["items"]
            .as_array()
            .unwrap()
            .is_empty(),
        "deploying HTTP creates no invocation"
    );
    let host = format!("app-{app}.apps.test");
    let (route, request) = l
        .store
        .ingress_wait_request(&host, 0, Some(("GET", "/hello?token=never-retain")))
        .await
        .unwrap();
    l.store.ingress_dispatched(&request);
    // Nothing of it is written until a flush; one that comes while it is
    // in flight writes it as it stands.
    assert!(
        history(&l, app, None, None, 20).await["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    l.store.flush_gateway().await.unwrap();
    assert_eq!(
        history(&l, app, None, None, 20).await["items"][0]["state"],
        "running"
    );
    l.store
        .ingress_complete(&request, Some(3), Some(201))
        .await
        .unwrap();
    // Completion delivery is idempotent; it cannot overwrite an observed response.
    l.store
        .ingress_complete(&request, Some(5), Some(500))
        .await
        .unwrap();
    l.store.flush_gateway().await.unwrap();
    let manual = l
        .store
        .run_app(&l.operator, &l.tenant, &l.project, app, "explicit")
        .await
        .unwrap();
    let first = history(&l, app, None, None, 1).await;
    assert_eq!(first["items"][0]["source"], "manual");
    let second = history(&l, app, None, Some(s(&first["next"])), 1).await;
    let http = &second["items"][0];
    assert_eq!(http["id"], request);
    assert_eq!(http["source"], "http");
    assert_eq!(http["http_status"], 201);
    assert_eq!(http["path"], "/hello");
    assert_eq!(http["state"], "succeeded");
    assert!(n(&http["duration_ms"]) >= 0);
    assert!(second["next"].is_null());
    assert_eq!(
        history(&l, app, Some("http"), None, 20).await["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        history(&l, app, Some("manual"), None, 20).await["items"][0]["id"],
        manual["resource_id"]
    );
    assert!(
        history(&l, app, Some("schedule"), None, 20).await["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        l.store
            .app_history(
                &l.operator,
                &l.tenant,
                &l.project,
                app,
                "runs",
                HistoryPage {
                    trigger: Some("invalid".into()),
                    ..Default::default()
                }
            )
            .await
            .unwrap_err()
            .status,
        StatusCode::BAD_REQUEST
    );
    assert!(
        l.store
            .app_history(
                &l.operator,
                &l.tenant,
                &l.project,
                app,
                "runs",
                HistoryPage {
                    trigger: Some("manual".into()),
                    before: Some(request.clone()),
                    ..Default::default()
                }
            )
            .await
            .is_err()
    );
    let (viewer, _) = l.credential("viewer", Some(&l.project)).await;
    assert_eq!(
        l.store
            .app_run(&viewer, &l.tenant, &l.project, app, &request)
            .await
            .unwrap()["execution_id"],
        route["execution_id"]
    );
    let logs = l
        .store
        .app_logs(
            &viewer,
            &l.tenant,
            &l.project,
            app,
            fenders_control_plane::app_logs::LogPage {
                run_id: Some(request.clone()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(logs["collection"]["executions"], 1);
    let (other, _) = define_app(&l, "other").await;
    assert_eq!(
        l.store
            .app_run(&viewer, &l.tenant, &l.project, &other, &request)
            .await
            .unwrap_err()
            .status,
        StatusCode::NOT_FOUND
    );
    assert!(
        l.store
            .app_logs(
                &viewer,
                &l.tenant,
                &l.project,
                &other,
                fenders_control_plane::app_logs::LogPage {
                    run_id: Some(request),
                    ..Default::default()
                }
            )
            .await
            .is_err()
    );
    l.store.migrate().await.unwrap();
    assert_eq!(
        history(&l, app, None, None, 20).await["items"]
            .as_array()
            .unwrap()
            .len(),
        2,
        "restart migration retains history"
    );
    l.finish().await;
}

#[tokio::test]
async fn http_response_failure_expiry_and_lost_completion_never_invent_success_or_replay() {
    let l = Lab::new().await;
    let node = l.node("worker").await;
    approve_component(&l, &node, true, true).await;
    let op=l.store.deploy_app(&l.operator,&l.tenant,&l.project,fenders_control_plane::apps::AppSubmission {
        value:json!({"name":"http-outcomes","artifact_id":l.artifact,"triggers":{"http":true,"manual":true}}),key:"deploy",domain:"apps.test"
    }).await.unwrap();
    let app = s(&op["resource_id"]);
    l.http_running(app, &node).await;
    let host = format!("app-{app}.apps.test");
    let mut ids = Vec::new();
    for dispatched in [true, false, true, true] {
        let (_, id) = l
            .store
            .ingress_wait_request(&host, 0, Some(("POST", "/")))
            .await
            .unwrap();
        if dispatched {
            l.store.ingress_dispatched(&id);
        }
        ids.push(id);
    }
    l.store
        .ingress_complete(&ids[0], Some(0), Some(503))
        .await
        .unwrap();
    l.store.ingress_finish(&ids[3], None).await.unwrap();
    sqlx::query("UPDATE ingress_reservations SET expires=now()-interval '1 second'")
        .execute(&l.store.pool)
        .await
        .unwrap();
    l.store.schedule().await.unwrap();
    l.store.flush_gateway().await.unwrap();
    let lab = &l;
    let get = |id: String| async move {
        lab.store
            .app_run(&lab.operator, &lab.tenant, &lab.project, app, &id)
            .await
            .unwrap()
    };
    assert_eq!(get(ids[0].clone()).await["state"], "failed");
    assert_eq!(get(ids[1].clone()).await["state"], "failed");
    assert_eq!(get(ids[2].clone()).await["state"], "unknown");
    assert_eq!(get(ids[3].clone()).await["state"], "unknown");
    l.store
        .ingress_complete(&ids[2], Some(0), Some(200))
        .await
        .unwrap();
    l.store.flush_gateway().await.unwrap();
    assert_eq!(
        get(ids[2].clone()).await["state"],
        "unknown",
        "late unfenced completion cannot rewrite expiry"
    );
    l.store.schedule().await.unwrap();
    assert_eq!(
        history(&l, app, None, None, 20).await["items"]
            .as_array()
            .unwrap()
            .len(),
        4
    );
    assert!(
        history(&l, app, Some("manual"), None, 20).await["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    sqlx::query("UPDATE app_http_runs SET created=now()-interval '31 days'")
        .execute(&l.store.pool)
        .await
        .unwrap();
    l.store.schedule().await.unwrap();
    assert!(
        history(&l, app, None, None, 20).await["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    l.finish().await;
}

#[tokio::test]
async fn events_interleave_one_entry_per_invocation_with_lifecycle_and_filter_by_type() {
    let l = Lab::new().await;
    let node = l.node("worker").await;
    approve_component(&l, &node, true, true).await;
    let op=l.store.deploy_app(&l.operator,&l.tenant,&l.project,fenders_control_plane::apps::AppSubmission {
        value:json!({"name":"timeline","artifact_id":l.artifact,"triggers":{"http":true,"manual":true}}),key:"deploy",domain:"apps.test"
    }).await.unwrap();
    let app = s(&op["resource_id"]);
    l.http_running(app, &node).await;
    let events = |page: Value| {
        let store = l.store.clone();
        let (operator, tenant, project) = (l.operator.clone(), l.tenant.clone(), l.project.clone());
        let app = app.to_owned();
        async move {
            store
                .app_events(
                    &operator,
                    &tenant,
                    &project,
                    &app,
                    serde_json::from_value(page).unwrap(),
                )
                .await
        }
    };
    let deployed = events(json!({})).await.unwrap()["items"].clone();
    assert!(
        deployed
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e["entry"] == "lifecycle")
    );
    let host = format!("app-{app}.apps.test");
    let (_, request) = l
        .store
        .ingress_wait_request(&host, 0, Some(("POST", "/orders")))
        .await
        .unwrap();
    l.store.ingress_dispatched(&request);
    l.store
        .ingress_complete(&request, Some(3), Some(202))
        .await
        .unwrap();
    l.store.flush_gateway().await.unwrap();
    let manual = l
        .store
        .run_app(&l.operator, &l.tenant, &l.project, app, "explicit")
        .await
        .unwrap();
    let run = s(&manual["resource_id"]);
    let all = events(json!({})).await.unwrap();
    let items = all["items"].as_array().unwrap();
    let invocations: Vec<_> = items.iter().filter(|e| e["entry"] == "run").collect();
    assert_eq!(invocations.len(), 2, "one entry per invocation");
    assert_eq!(invocations[0]["id"], run);
    assert_eq!(invocations[0]["source"], "manual");
    assert_eq!(invocations[1]["id"], request);
    assert_eq!(invocations[1]["http_status"], 202);
    assert_eq!(invocations[1]["path"], "/orders");
    assert!(
        items
            .iter()
            .all(|e| e["entry"] == "run" || e["run_id"].is_null()),
        "command transitions are summarized by the invocation entry"
    );
    assert!(
        items
            .iter()
            .any(|e| e["entry"] == "lifecycle" && e["kind"] == "http")
    );
    assert_eq!(all["missed_history_pending"], false);
    let steps = invocations[0]["transitions"].as_array().unwrap();
    assert_eq!(steps[0]["kind"], "run", "admission first");
    assert!(steps.iter().all(|e| e["run_id"] == run));
    assert_eq!(invocations[1]["transitions"], json!([]));
    let counts = &all["counts"];
    assert_eq!(
        (
            n(&counts["http"]),
            n(&counts["manual"]),
            n(&counts["schedule"])
        ),
        (1, 1, 0)
    );
    assert_eq!(n(&counts["all"]), items.len() as i64);
    assert_eq!(n(&counts["invocations"]), 2);
    // Every entry is reachable exactly once through single-item pages.
    let mut paged = Vec::new();
    let mut before = Value::Null;
    loop {
        let page = events(json!({"limit":1,"before":before})).await.unwrap();
        paged.push(page["items"][0]["id"].clone());
        if page["next"].is_null() {
            break;
        }
        before = page["next"].clone();
    }
    assert_eq!(
        paged,
        items.iter().map(|e| e["id"].clone()).collect::<Vec<_>>()
    );
    let only = |t: &str| {
        let events = &events;
        let t = t.to_owned();
        async move {
            events(json!({"type":t})).await.unwrap()["items"]
                .as_array()
                .unwrap()
                .clone()
        }
    };
    let http = only("http").await;
    assert_eq!(http.len(), 1);
    assert_eq!(http[0]["id"], request);
    assert_eq!(only("manual").await[0]["id"], run);
    assert!(only("schedule").await.is_empty());
    let lifecycle = only("lifecycle").await;
    assert_eq!(n(&all["counts"]["lifecycle"]), lifecycle.len() as i64);
    assert!(lifecycle.iter().all(|e| e["entry"] == "lifecycle"));
    assert!(
        lifecycle.iter().any(|e| e["run_id"] == run),
        "lifecycle keeps every transition"
    );
    assert!(events(json!({"run_id":run})).await.unwrap()["counts"].is_null());
    let narrowed = events(json!({"run_id":run})).await.unwrap()["items"].clone();
    assert!(!narrowed.as_array().unwrap().is_empty());
    assert!(
        narrowed
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e["entry"] == "lifecycle" && e["run_id"] == run)
    );
    assert_eq!(
        events(json!({"type":"invalid"})).await.unwrap_err().status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        events(json!({"type":"lifecycle","before":request}))
            .await
            .unwrap_err()
            .status,
        StatusCode::NOT_FOUND,
        "a cursor outside the filtered timeline is rejected"
    );
}

/// What the gateway holds is written by its flusher: a session row that
/// each flush touches, and the records of the requests that ended. A flush
/// that fails loses nothing; a session that stops flushing is forgotten.
#[tokio::test]
async fn the_flusher_writes_a_session_and_keeps_what_it_could_not_write() {
    let l = Lab::new().await;
    let node = l.node("worker").await;
    approve_component(&l, &node, true, true).await;
    let op=l.store.deploy_app(&l.operator,&l.tenant,&l.project,fenders_control_plane::apps::AppSubmission {
        value:json!({"name":"flushed","artifact_id":l.artifact,"triggers":{"http":true,"manual":true}}),key:"deploy",domain:"apps.test"
    }).await.unwrap();
    let app = s(&op["resource_id"]);
    l.http_running(app, &node).await;
    let sessions = || async {
        sqlx::query_scalar::<_, Vec<String>>(
            "SELECT COALESCE(array_agg(id),'{}') FROM gateway_sessions",
        )
        .fetch_one(&l.store.pool)
        .await
        .unwrap()
    };
    assert!(sessions().await.is_empty());
    l.store.flush_gateway().await.unwrap();
    assert_eq!(sessions().await, vec![l.store.gateway.session().to_owned()]);

    // A request that ends is one locked transaction to admit and one to
    // settle: being given to its app, and its record, are none.
    let host = format!("app-{app}.apps.test");
    let before = l.store.load.locked_transactions();
    let (_, request) = l
        .store
        .ingress_wait_request(&host, 0, Some(("GET", "/")))
        .await
        .unwrap();
    l.store.ingress_dispatched(&request);
    l.store
        .ingress_complete(&request, Some(0), Some(200))
        .await
        .unwrap();
    assert_eq!(l.store.load.locked_transactions() - before, 2);

    // While no change is admitted the flush fails, and keeps the record.
    sqlx::query("UPDATE recovery_barrier SET active=true")
        .execute(&l.store.pool)
        .await
        .unwrap();
    assert!(l.store.flush_gateway().await.is_err());
    sqlx::query("UPDATE recovery_barrier SET active=false")
        .execute(&l.store.pool)
        .await
        .unwrap();
    assert!(
        history(&l, app, Some("http"), None, 20).await["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    l.store.flush_gateway().await.unwrap();
    let written = history(&l, app, Some("http"), None, 20).await;
    assert_eq!(written["items"][0]["id"], request);
    assert_eq!(written["items"][0]["state"], "succeeded");

    // A session nothing has touched for a while is a process that is gone.
    sqlx::query("UPDATE gateway_sessions SET seen=seen-interval '1 minute'")
        .execute(&l.store.pool)
        .await
        .unwrap();
    l.store.schedule().await.unwrap();
    assert!(sessions().await.is_empty());
    l.finish().await;
}

/// The record of a request whose app is gone by the time of the flush is
/// not written, and does not keep the others from being.
#[tokio::test]
async fn a_record_of_an_app_that_is_gone_is_left_out_of_the_flush() {
    let l = Lab::new().await;
    let node = l.node("worker").await;
    approve_component(&l, &node, true, true).await;
    let op=l.store.deploy_app(&l.operator,&l.tenant,&l.project,fenders_control_plane::apps::AppSubmission {
        value:json!({"name":"kept","artifact_id":l.artifact,"triggers":{"http":true,"manual":true}}),key:"deploy",domain:"apps.test"
    }).await.unwrap();
    let app = s(&op["resource_id"]);
    l.http_running(app, &node).await;
    let (_, request) = l
        .store
        .ingress_wait_request(&format!("app-{app}.apps.test"), 0, Some(("GET", "/")))
        .await
        .unwrap();
    l.store.ingress_dispatched(&request);
    l.store
        .ingress_complete(&request, Some(0), Some(200))
        .await
        .unwrap();
    // One of an app and release that no longer exist, and one of this app
    // on an execution that no longer does.
    let record =
        |app: &str, release: &str, execution: &str| fenders_control_plane::gateway::Opened {
            tenant: l.tenant.clone(),
            project: l.project.clone(),
            app: app.to_owned(),
            release: release.to_owned(),
            execution: Some(execution.to_owned()),
            method: "GET".into(),
            path: "/".into(),
        };
    let release: String = sqlx::query_scalar("SELECT target_release_id FROM apps WHERE id=$1")
        .bind(app)
        .fetch_one(&l.store.pool)
        .await
        .unwrap();
    let (gone, without) = (uid(), uid());
    l.store
        .gateway
        .opened(&gone, record(&uid(), &uid(), &uid()));
    l.store
        .gateway
        .opened(&without, record(app, &release, &uid()));
    l.store.flush_gateway().await.unwrap();
    let written: Vec<(String, Option<String>)> =
        sqlx::query_as("SELECT id,execution_id FROM app_http_runs ORDER BY created")
            .fetch_all(&l.store.pool)
            .await
            .unwrap();
    assert_eq!(written.len(), 2);
    assert_eq!(written[0].0, request);
    assert!(written[0].1.is_some());
    assert_eq!(written[1], (without, None));
    l.finish().await;
}
