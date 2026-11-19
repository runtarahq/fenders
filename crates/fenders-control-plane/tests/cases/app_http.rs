//! HTTP lifecycle protocol tests against PostgreSQL; these do not run a VM.
use super::*;
use fenders_control_plane::app_http::{TriggerUpdate, hostname};

impl Lab {
    pub(super) async fn http(&self, app: &str) -> Value {
        self.store
            .app_http_status(&self.operator, &self.tenant, &self.project, app)
            .await
            .unwrap()
    }
    pub(super) async fn execution(&self, id: &str) -> Value {
        self.store
            .resources(
                &self.operator,
                &self.tenant,
                &self.project,
                "executions",
                Some(id),
            )
            .await
            .unwrap()
    }
    pub(super) async fn operation(&self, op: &Value) -> Value {
        self.store
            .resources(
                &self.operator,
                &self.tenant,
                &self.project,
                "operations",
                Some(s(&op["id"])),
            )
            .await
            .unwrap()
    }
    async fn http_trigger(&self, app: &str, http: bool, manual: bool, key: &str) -> Value {
        let revision = self
            .store
            .app_triggers(&self.operator, &self.tenant, &self.project, app)
            .await
            .unwrap()["revision"]
            .clone();
        self.store
            .update_app_triggers_at(
                &self.operator,
                &self.tenant,
                &self.project,
                app,
                TriggerUpdate {
                    value: json!({"manual":manual,"http":http,"expected_revision":revision}),
                    key,
                    domain: "apps.test",
                },
            )
            .await
            .unwrap()
    }
    async fn release(&self, app: &str, version: &str, key: &str) -> Value {
        let revision = self
            .store
            .app(&self.operator, &self.tenant, &self.project, app)
            .await
            .unwrap()["revision"]
            .clone();
        self.store
            .activate_app_release(
                &self.operator,
                &self.tenant,
                &self.project,
                app,
                json!({"version_id":version,"expected_revision":revision}),
                key,
            )
            .await
            .unwrap()
    }
    async fn lifecycle(&self, app: &str, desired: &str, key: &str) -> Value {
        let revision = self
            .store
            .app(&self.operator, &self.tenant, &self.project, app)
            .await
            .unwrap()["revision"]
            .clone();
        self.store
            .app_lifecycle(
                &self.operator,
                &self.tenant,
                &self.project,
                app,
                json!({"desired":desired,"expected_revision":revision}),
                key,
            )
            .await
            .unwrap()
    }
    /// The lab's nodes hold one execution each, so a candidate has no room
    /// beside the execution that serves: after ten seconds the app is
    /// replaced the old way, stopped and then started.
    pub(super) async fn no_room_for_a_candidate(&self, app: &str) {
        let aged = sqlx::query("UPDATE executions SET created=created-interval '11 seconds' WHERE id=(SELECT candidate_execution_id FROM app_http WHERE app_id=$1)")
            .bind(app)
            .execute(&self.store.pool)
            .await
            .unwrap();
        assert_eq!(aged.rows_affected(), 1, "no candidate was being brought up");
        self.store.schedule().await.unwrap();
    }
    pub(super) async fn http_running(&self, app: &str, node: &Value) -> Value {
        self.store.schedule().await.unwrap();
        let e = self
            .execution(s(&self.http(app).await["execution_id"]))
            .await;
        assert_eq!(e["node_id"], node["id"]);
        self.report(node, &e, "running", 1).await;
        assert_eq!(self.http(app).await["state"], "serving");
        self.execution(s(&e["id"])).await
    }
}

#[tokio::test]
async fn http_publication_drain_and_stable_endpoint_are_observation_based() {
    let l = Lab::new().await;
    let node = l.node("worker").await;
    approve_component(&l, &node, true, true).await;
    let (app, version) = define_app(&l, "http-app").await;
    assert_eq!(
        l.http_trigger(&app, true, true, "enable-http").await["state"],
        "succeeded"
    );
    let url = format!("https://app-{app}.apps.test");
    let host = url.trim_start_matches("https://");
    assert_eq!(l.http(&app).await["url"], url);
    assert_eq!(l.http(&app).await["state"], "disabled");
    let first = l.release(&app, &version, "first").await;
    assert_eq!(first["state"], "pending");
    assert!(
        l.store
            .app(&l.operator, &l.tenant, &l.project, &app)
            .await
            .unwrap()["active_release_id"]
            .is_null()
    );
    assert_eq!(
        l.store.ingress_start(host, 0).await.unwrap_err().status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        l.store
            .run_app(&l.operator, &l.tenant, &l.project, &app, "before-ready")
            .await
            .unwrap_err()
            .status,
        StatusCode::CONFLICT
    );
    let old = l.http_running(&app, &node).await;
    assert_eq!(old["spec"]["mode"], "http");
    assert_eq!(l.operation(&first).await["state"], "succeeded");
    let (_, request) = l.store.ingress_start(host, 1).await.unwrap();
    let repeat = l.lifecycle(&app, "enabled", "already-enabled").await;
    assert_eq!(repeat["state"], "succeeded");
    assert_eq!(l.http(&app).await["execution_id"], old["id"]);
    assert!(
        sqlx::query_scalar::<_, bool>("SELECT ready_until IS NULL FROM app_http WHERE app_id=$1")
            .bind(&app)
            .fetch_one(&l.store.pool)
            .await
            .unwrap()
    );
    sqlx::query("UPDATE nodes SET last_seen=now()-interval '1 minute'")
        .execute(&l.store.pool)
        .await
        .unwrap();
    l.store.schedule().await.unwrap();
    assert_eq!(l.http(&app).await["state"], "unavailable");
    assert_eq!(l.execution(s(&old["id"])).await["reserved"], true);
    l.report(&node, &old, "running", 2).await;
    assert_eq!(l.http(&app).await["state"], "serving");

    // A fresh release of the same code still exercises replacement and preserves identity.
    let next = l.release(&app, &version, "replacement").await;
    assert_eq!(next["state"], "pending");
    // The execution that serves goes on serving while the next release's
    // is brought up beside it.
    let (_, meanwhile) = l.store.ingress_start(host, 0).await.unwrap();
    l.store.ingress_finish(&meanwhile, Some(0)).await.unwrap();
    assert_eq!(l.http(&app).await["state"], "serving");
    // This lab has no room for both, so it is replaced in turn instead.
    l.no_room_for_a_candidate(&app).await;
    assert_eq!(
        l.store.ingress_start(host, 0).await.unwrap_err().status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    // A request that can wait is held across the gap, for the replacement.
    let (nothing_yet, across) = l.store.ingress_begin(host, 0, true).await.unwrap();
    assert!(nothing_yet.is_none());
    assert_eq!(l.execution(s(&old["id"])).await["desired"], "running");
    assert_eq!(
        l.store
            .app(&l.operator, &l.tenant, &l.project, &app)
            .await
            .unwrap()["active_release_id"],
        first["resource_id"]
    );
    l.store.ingress_finish(&request, Some(23)).await.unwrap();
    l.store.schedule().await.unwrap();
    // Its request ended, so it is stopped. Old observations cannot
    // acknowledge the new stop generation.
    l.report(&node, &old, "stopped", 2).await;
    assert_eq!(l.execution(s(&old["id"])).await["reserved"], true);
    assert!(l.http(&app).await["execution_id"].is_null());
    let stop = l.execution(s(&old["id"])).await;
    assert_eq!(stop["desired"], "stopped");
    assert_eq!(stop["reserved"], true);
    l.report(&node, &stop, "stopped", 4).await;
    let replacement = l.http_running(&app, &node).await;
    assert_ne!(replacement["id"], old["id"]);
    let held = l.store.ingress_poll(&across).await.unwrap().unwrap();
    assert_eq!(held["execution_id"], replacement["id"]);
    l.store.ingress_finish(&across, Some(0)).await.unwrap();
    assert_eq!(replacement["deployment_id"], old["deployment_id"]);
    assert_eq!(l.http(&app).await["url"], url);
    assert_eq!(l.operation(&next).await["state"], "succeeded");
    assert_eq!(
        l.store
            .app(&l.operator, &l.tenant, &l.project, &app)
            .await
            .unwrap()["active_release_id"],
        next["resource_id"]
    );
    let (_, request) = l.store.ingress_start(host, 0).await.unwrap();
    l.store.ingress_finish(&request, Some(0)).await.unwrap();
    // The first, the candidate there was no room for, and the replacement.
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM app_http_attempts")
            .fetch_one(&l.store.pool)
            .await
            .unwrap(),
        3
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM app_runs")
            .fetch_one(&l.store.pool)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        l.store
            .usage(&l.operator, &l.tenant, Some(&l.project))
            .await
            .unwrap()["reserved"]["instances"],
        1
    );
    l.finish().await;
}

#[tokio::test]
async fn http_stop_timeout_retains_quota_and_trigger_changes_reuse_code() {
    let l = Lab::new().await;
    let node = l.node("worker").await;
    approve_component(&l, &node, true, true).await;
    let (app, version) = define_app(&l, "http-app").await;
    l.http_trigger(&app, true, false, "http-on").await;
    l.release(&app, &version, "release").await;
    let e = l.http_running(&app, &node).await;
    let before = l.http(&app).await;
    let host = s(&before["url"]).trim_start_matches("https://");
    let (_, inflight) = l.store.ingress_start(host, 0).await.unwrap();
    let stop = l.lifecycle(&app, "stopped", "stop").await;
    let repeat = l.lifecycle(&app, "stopped", "already-stopped").await;
    assert_eq!(repeat["state"], "pending");
    assert_eq!(
        l.store.ingress_start(host, 0).await.unwrap_err().status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    sqlx::query("UPDATE app_http SET drain_until=now()-interval '1 second'")
        .execute(&l.store.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE nodes SET last_seen=now()-interval '1 minute'")
        .execute(&l.store.pool)
        .await
        .unwrap();
    l.store.schedule().await.unwrap();
    let stopping = l.execution(s(&e["id"])).await;
    assert_eq!(stopping["desired"], "stopped");
    assert_eq!(stopping["reserved"], true);
    assert_eq!(l.operation(&stop).await["state"], "pending");
    l.report(&node, &e, "stopped", 2).await;
    assert_eq!(l.operation(&stop).await["state"], "pending");
    l.report(&node, &stopping, "stopped", 3).await;
    assert_eq!(l.operation(&stop).await["state"], "succeeded");
    assert_eq!(l.operation(&repeat).await["state"], "succeeded");
    assert_eq!(l.http(&app).await["state"], "disabled");
    l.store.ingress_finish(&inflight, Some(0)).await.unwrap();
    assert_eq!(
        l.store
            .usage(&l.operator, &l.tenant, Some(&l.project))
            .await
            .unwrap()["reserved"]["instances"],
        0
    );
    assert_eq!(
        l.store
            .app_triggers(&l.operator, &l.tenant, &l.project, &app)
            .await
            .unwrap()["http"],
        true
    );
    assert_eq!(
        l.lifecycle(&app, "enabled", "start").await["state"],
        "pending"
    );
    let e = l.http_running(&app, &node).await;
    let off = l.http_trigger(&app, false, true, "http-off").await;
    assert_eq!(off["state"], "pending");
    let pause = l.execution(s(&e["id"])).await;
    l.report(&node, &pause, "paused", 2).await;
    let stop = l.execution(s(&e["id"])).await;
    l.report(&node, &stop, "stopped", 3).await;
    assert_eq!(l.operation(&off).await["state"], "succeeded");
    assert_eq!(l.http(&app).await["url"], before["url"]);
    let run = l
        .store
        .run_app(&l.operator, &l.tenant, &l.project, &app, "manual")
        .await
        .unwrap();
    assert_eq!(run["state"], "pending");
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(DISTINCT version_id) FROM app_releases")
            .fetch_one(&l.store.pool)
            .await
            .unwrap(),
        1
    );
    l.finish().await;
}

#[tokio::test]
async fn http_startup_disconnect_is_pending_but_failure_is_sticky() {
    let l = Lab::new().await;
    let node = l.node("worker").await;
    approve_component(&l, &node, true, false).await;
    let (app, version) = define_app(&l, "http-only").await;
    l.http_trigger(&app, true, false, "http-on").await;
    let op = l.release(&app, &version, "release").await;
    l.store.schedule().await.unwrap();
    let e = l.execution(s(&l.http(&app).await["execution_id"])).await;
    sqlx::query("UPDATE nodes SET last_seen=now()-interval '1 minute'")
        .execute(&l.store.pool)
        .await
        .unwrap();
    l.store.schedule().await.unwrap();
    assert_eq!(l.http(&app).await["state"], "unavailable");
    assert_eq!(l.operation(&op).await["state"], "pending");
    assert_eq!(l.execution(s(&e["id"])).await["reserved"], true);
    l.report(&node, &e, "failed", 1).await;
    assert_eq!(l.operation(&op).await["state"], "failed");
    assert_eq!(l.operation(&op).await["error"], "http-startup-failed");
    for _ in 0..3 {
        l.store.schedule().await.unwrap();
    }
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM executions")
            .fetch_one(&l.store.pool)
            .await
            .unwrap(),
        1
    );
    assert!(
        l.store
            .app(&l.operator, &l.tenant, &l.project, &app)
            .await
            .unwrap()["active_release_id"]
            .is_null()
    );
    let retry = l.release(&app, &version, "explicit-retry").await;
    l.http_running(&app, &node).await;
    assert_eq!(l.operation(&retry).await["state"], "succeeded");
    assert_eq!(l.operation(&op).await["state"], "failed");
    assert_eq!(
        l.store
            .update_app_triggers(
                &l.operator,
                &l.tenant,
                &l.project,
                &app,
                json!({"manual":true,"http":true,"expected_revision":2}),
                "incompatible"
            )
            .await
            .unwrap_err()
            .status,
        StatusCode::CONFLICT
    );
    l.finish().await;
}

#[tokio::test]
async fn http_readiness_deadline_cancels_queued_work_without_releasing_unknown_workers() {
    let l = Lab::new().await;
    let node = l.node("compiler").await;
    approve_component(&l, &node, true, true).await;
    sqlx::query("UPDATE nodes SET draining=true")
        .execute(&l.store.pool)
        .await
        .unwrap();
    let (app, version) = define_app(&l, "pending-http").await;
    l.http_trigger(&app, true, false, "on").await;
    let op = l.release(&app, &version, "queued").await;
    l.store.schedule().await.unwrap();
    let e = l.execution(s(&l.http(&app).await["execution_id"])).await;
    assert_eq!(e["state"], "queued");
    assert_eq!(e["reserved"], true);
    sqlx::query("UPDATE app_http SET ready_until=now()-interval '1 second'")
        .execute(&l.store.pool)
        .await
        .unwrap();
    l.store.schedule().await.unwrap();
    assert_eq!(l.execution(s(&e["id"])).await["reserved"], false);
    assert_eq!(l.operation(&op).await["error"], "http-readiness-timeout");

    sqlx::query("UPDATE nodes SET draining=false")
        .execute(&l.store.pool)
        .await
        .unwrap();
    let op = l.release(&app, &version, "assigned").await;
    // This fixture has no periodic worker loop. Becoming available includes a
    // fresh heartbeat; time spent exercising the queued timeout must not make
    // this second phase accidentally test the independent stale-worker gate.
    l.store
        .heartbeat(
            s(&node["id"]),
            json!({"boot_id":"test-boot","reports":[],"confinement":HOST_CONFINEMENT}),
        )
        .await
        .unwrap();
    l.store.schedule().await.unwrap();
    let e = l.execution(s(&l.http(&app).await["execution_id"])).await;
    assert_eq!(e["state"], "starting");
    sqlx::query("UPDATE app_http SET ready_until=now()-interval '1 second'")
        .execute(&l.store.pool)
        .await
        .unwrap();
    l.store.schedule().await.unwrap();
    assert_eq!(l.execution(s(&e["id"])).await["reserved"], true);
    assert_eq!(l.operation(&op).await["error"], "http-readiness-timeout");
    l.report(&node, &e, "running", 1).await;
    assert_eq!(l.http(&app).await["reason"], "http-readiness-timeout");
    let stop = l.execution(s(&e["id"])).await;
    l.report(&node, &stop, "stopped", 2).await;
    assert_eq!(l.execution(s(&e["id"])).await["reserved"], false);
    l.finish().await;
}

#[tokio::test]
async fn http_restart_backoff_and_limit_survive_reconciliation_and_keep_history() {
    let l = Lab::new().await;
    let node = l.node("worker").await;
    approve_component(&l, &node, true, true).await;
    let (app, version) = define_app(&l, "http-app").await;
    l.http_trigger(&app, true, false, "on").await;
    let op = l.release(&app, &version, "release").await;
    for failure in 1..=3 {
        let e = l.http_running(&app, &node).await;
        l.report(&node, &e, "failed", 2).await;
        let (a, b) = tokio::join!(l.store.schedule(), l.store.schedule());
        a.unwrap();
        b.unwrap();
        assert_eq!(l.http(&app).await["execution_id"], e["id"]);
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM executions")
                .fetch_one(&l.store.pool)
                .await
                .unwrap(),
            failure
        );
        if failure < 3 {
            assert_eq!(l.http(&app).await["reason"], "restarting-http");
            sqlx::query("UPDATE app_http SET restart_after=now()-interval '1 second'")
                .execute(&l.store.pool)
                .await
                .unwrap();
            l.store.schedule().await.unwrap();
            l.store.schedule().await.unwrap();
        }
    }
    assert_eq!(l.http(&app).await["reason"], "http-restart-limit");
    assert_eq!(l.operation(&op).await["state"], "succeeded");
    sqlx::query("UPDATE app_http SET failure_window=now()-interval '10 minutes'")
        .execute(&l.store.pool)
        .await
        .unwrap();
    l.store.schedule().await.unwrap();
    assert_eq!(l.http(&app).await["reason"], "http-restart-limit");
    let recovery = l.release(&app, &version, "explicit-recovery").await;
    l.http_running(&app, &node).await;
    assert_eq!(l.operation(&recovery).await["state"], "succeeded");
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM app_http_attempts")
            .fetch_one(&l.store.pool)
            .await
            .unwrap(),
        4
    );
    l.finish().await;
}

#[tokio::test]
async fn http_domain_is_server_owned_and_customer_status_is_project_scoped() {
    let l = Lab::new().await;
    let node = l.node("compiler").await;
    approve_component(&l, &node, true, true).await;
    let (app, _) = define_app(&l, "http-app").await;
    let router = api::management(api::ApiState {
        store: l.store.clone(),
        domain: "apps.example.test".into(),
        tls: None,
    });
    let uri = format!(
        "/v1/workspaces/{}/projects/{}/apps/{app}/triggers",
        l.tenant, l.project
    );
    for (body, expected) in [
        (
            json!({"manual":false,"http":true,"expected_revision":1,"domain":"attacker.test"}),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({"manual":false,"http":true,"expected_revision":1}),
            StatusCode::OK,
        ),
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(&uri)
                    .header("Authorization", format!("Bearer {}", l.token))
                    .header("Idempotency-Key", "on")
                    .header("Content-Type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
    }
    assert_eq!(
        l.http(&app).await["url"],
        format!("https://app-{app}.apps.example.test")
    );
    let (viewer, _) = l.credential("viewer", Some(&l.project)).await;
    assert_eq!(
        l.store
            .update_app_triggers(
                &viewer,
                &l.tenant,
                &l.project,
                &app,
                json!({"manual":false,"http":false,"expected_revision":2}),
                "deny"
            )
            .await
            .unwrap_err()
            .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        l.store
            .app_http_status(&viewer, &l.tenant, &uid(), &app)
            .await
            .unwrap_err()
            .status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        l.store
            .app_http_status(&viewer, &uid(), &l.project, &app)
            .await
            .unwrap_err()
            .status,
        StatusCode::NOT_FOUND
    );
    for invalid in [
        "localhost",
        "https://apps.test",
        "apps.test/path",
        "apps..test",
        "-apps.test",
        "APPs.test",
    ] {
        assert!(hostname(&app, invalid).is_err());
    }
    l.http_trigger(&app, false, false, "off").await;
    l.http_trigger(&app, true, false, "back-on").await;
    assert_eq!(
        l.http(&app).await["url"],
        format!("https://app-{app}.apps.example.test")
    );
    l.finish().await;
}

#[tokio::test]
async fn http_admission_and_manual_events_compete_for_the_same_allowance() {
    let l = Lab::new().await;
    let node = l.node("worker").await;
    approve_component(&l, &node, true, true).await;
    sqlx::query("UPDATE tenants SET instances=1")
        .execute(&l.store.pool)
        .await
        .unwrap();
    let (a, av) = define_app(&l, "app-a").await;
    let (b, bv) = define_app(&l, "app-b").await;
    l.http_trigger(&a, true, true, "a-on").await;
    l.http_trigger(&b, true, false, "b-on").await;
    let a_op = l.release(&a, &av, "a-release").await;
    let b_op = l.release(&b, &bv, "b-release").await;
    assert_eq!(a_op["state"], "pending");
    assert_eq!(b_op["state"], "pending");
    assert_eq!(l.http(&b).await["reason"], "allowance-exhausted");
    assert!(l.http(&b).await["execution_id"].is_null());
    let e = l.http_running(&a, &node).await;
    assert_eq!(
        l.store
            .run_app(&l.operator, &l.tenant, &l.project, &a, "second-instance")
            .await
            .unwrap_err()
            .status,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM app_runs")
            .fetch_one(&l.store.pool)
            .await
            .unwrap(),
        0
    );
    let stopped = l.lifecycle(&a, "stopped", "a-stop").await;
    let pause = l.execution(s(&e["id"])).await;
    l.report(&node, &pause, "paused", 2).await;
    assert!(l.http(&b).await["execution_id"].is_null());
    let stop = l.execution(s(&e["id"])).await;
    l.report(&node, &stop, "stopped", 3).await;
    l.http_running(&b, &node).await;
    assert_eq!(l.operation(&stopped).await["state"], "succeeded");
    assert_eq!(l.operation(&b_op).await["state"], "succeeded");
    assert_eq!(
        l.store.usage(&l.operator, &l.tenant, None).await.unwrap()["reserved"]["instances"],
        1
    );
    l.finish().await;
}

#[tokio::test]
async fn http_failed_replacement_keeps_stopping_old_worker_and_preserves_active_release() {
    let l = Lab::new().await;
    let node = l.node("worker").await;
    approve_component(&l, &node, true, true).await;
    let (app, version) = define_app(&l, "http-app").await;
    l.http_trigger(&app, true, false, "on").await;
    let active = l.release(&app, &version, "active").await;
    let old = l.http_running(&app, &node).await;
    let failed = l.release(&app, &version, "replacement").await;
    l.no_room_for_a_candidate(&app).await;
    sqlx::query("UPDATE app_http SET drain_until=now()-interval '1 minute',ready_until=now()-interval '1 second'").execute(&l.store.pool).await.unwrap();
    l.store.schedule().await.unwrap();
    assert_eq!(
        l.operation(&failed).await["error"],
        "previous-worker-not-stopped"
    );
    let stopping = l.execution(s(&old["id"])).await;
    assert_eq!(stopping["desired"], "stopped");
    l.store.heartbeat(s(&node["id"]),json!({"boot_id":"test-boot","confinement":HOST_CONFINEMENT,"reports":[{"id":stopping["id"],"generation":stopping["generation"],"state":"running","sequence":2,"cpu_usec":12,"memory_bytes":512,"action_error":"control-unavailable"}]})).await.unwrap();
    let retry_stop = l.execution(s(&old["id"])).await;
    assert_eq!(retry_stop["desired"], "stopped");
    assert!(n(&retry_stop["generation"]) > n(&stopping["generation"]));
    assert_eq!(retry_stop["reserved"], true);
    l.report(&node, &retry_stop, "stopped", 3).await;
    l.store.schedule().await.unwrap();
    assert_eq!(l.http(&app).await["reason"], "previous-worker-not-stopped");
    assert_eq!(
        l.store
            .app(&l.operator, &l.tenant, &l.project, &app)
            .await
            .unwrap()["active_release_id"],
        active["resource_id"]
    );
    // The old one and the candidate there was no room for: nothing new.
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM executions")
            .fetch_one(&l.store.pool)
            .await
            .unwrap(),
        2
    );
    let retry = l.release(&app, &version, "retry-release").await;
    l.http_running(&app, &node).await;
    assert_eq!(l.operation(&retry).await["state"], "succeeded");
    assert_eq!(l.operation(&failed).await["state"], "failed");
    l.finish().await;
}

#[tokio::test]
async fn customer_app_summaries_keep_code_readiness_availability_and_runs_distinct() {
    use fenders_control_plane::apps::AppPage;
    let l = Lab::new().await;
    let node = l.node("worker").await;
    approve_component(&l, &node, true, true).await;
    let (http, version) = define_app(&l, "http-app").await;
    let draft = l
        .store
        .app(&l.operator, &l.tenant, &l.project, &http)
        .await
        .unwrap();
    assert_eq!(draft["state"], "draft");
    assert_eq!(draft["latest_code"]["number"], 1);
    assert_eq!(
        draft["latest_code"]["capabilities"],
        json!({"http":true,"command":true})
    );
    assert!(draft["active_release"].is_null());
    assert!(draft["target_release"].is_null());
    assert!(draft["latest_run"].is_null());
    // The summary has the status without the count of serving executions.
    let mut status = l.http(&http).await;
    status.as_object_mut().unwrap().remove("executions");
    assert_eq!(draft["http"], status);
    l.http_trigger(&http, true, false, "on").await;
    let release = l.release(&http, &version, "release").await;
    let pending = l
        .store
        .app(&l.operator, &l.tenant, &l.project, &http)
        .await
        .unwrap();
    assert_eq!(pending["state"], "preparing");
    assert_eq!(pending["target_release"]["id"], release["resource_id"]);
    assert!(pending["active_release"].is_null());
    let execution = l.http_running(&http, &node).await;
    let ready = l
        .store
        .app(&l.operator, &l.tenant, &l.project, &http)
        .await
        .unwrap();
    assert_eq!(ready["state"], "ready");
    assert_eq!(ready["active_release"]["version"], 1);
    assert_eq!(ready["http"]["state"], "serving");
    // The read model must reflect liveness even before the scheduler runs.
    sqlx::query("UPDATE nodes SET last_seen=now()-interval '1 minute'")
        .execute(&l.store.pool)
        .await
        .unwrap();
    let stale = l
        .store
        .app(&l.operator, &l.tenant, &l.project, &http)
        .await
        .unwrap();
    assert_eq!(stale["state"], "ready");
    assert_eq!(stale["http"]["state"], "unavailable");
    let mut status = l.http(&http).await;
    status.as_object_mut().unwrap().remove("executions");
    assert_eq!(stale["http"], status);
    l.report(&node, &execution, "running", 2).await;
    // Attaching code does not replace the version that is serving.
    let artifact = l
        .store
        .upload(
            &l.operator,
            &l.tenant,
            &l.project,
            b"\0asm\x0d\0\x01\0summary-v2",
        )
        .await
        .unwrap();
    approve_component(&l, &node, true, true).await;
    l.store
        .attach_app_version(
            &l.operator,
            &l.tenant,
            &l.project,
            &http,
            json!({"artifact_id":artifact["id"],"expected_revision":2}),
            "new-code",
        )
        .await
        .unwrap();
    let attached = l
        .store
        .app(&l.operator, &l.tenant, &l.project, &http)
        .await
        .unwrap();
    assert_eq!(attached["latest_code"]["number"], 2);
    assert_eq!(attached["active_release"]["version"], 1);
    assert_eq!(attached["target_release"]["version"], 1);
    assert_eq!(attached["http"]["execution_id"], execution["id"]);

    let (manual, version) = define_app(&l, "manual-app").await;
    l.http_trigger(&manual, false, true, "manual-on").await;
    l.release(&manual, &version, "manual-release").await;
    let op = l
        .store
        .run_app(&l.operator, &l.tenant, &l.project, &manual, "event")
        .await
        .unwrap();
    let summary = l
        .store
        .app(&l.operator, &l.tenant, &l.project, &manual)
        .await
        .unwrap();
    assert_eq!(summary["state"], "ready");
    assert_eq!(summary["http"]["state"], "disabled");
    assert_eq!(summary["latest_run"]["id"], op["resource_id"]);
    assert_eq!(summary["latest_run"]["state"], "queued");
    assert!(summary["latest_run"]["exit_code"].is_null());
    let (unused, _) = define_app(&l, "no-triggers").await;
    let (viewer, _) = l.credential("viewer", Some(&l.project)).await;
    for (filter, id) in [("http", &http), ("manual", &manual), ("none", &unused)] {
        let page: AppPage = serde_json::from_value(json!({"trigger":filter,"limit":1})).unwrap();
        let listed = l
            .store
            .apps(&viewer, &l.tenant, &l.project, page)
            .await
            .unwrap();
        assert_eq!(listed["items"].as_array().unwrap().len(), 1);
        assert_eq!(listed["items"][0]["id"], *id);
        assert_eq!(
            listed["items"][0],
            l.store
                .app(&viewer, &l.tenant, &l.project, id)
                .await
                .unwrap()
        );
        assert!(listed["next"].is_null());
    }
    let response = api::router(l.store.clone())
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/workspaces/{}/projects/{}/apps?trigger=unsupported",
                    l.tenant, l.project
                ))
                .header("Authorization", format!("Bearer {}", l.token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    l.lifecycle(&http, "stopped", "stop").await;
    let stopped = l
        .store
        .app(&viewer, &l.tenant, &l.project, &http)
        .await
        .unwrap();
    assert_eq!(stopped["state"], "stopped");
    assert_eq!(stopped["http"]["state"], "stopping");
    assert_eq!(stopped["triggers"]["http"], true);
    l.finish().await;
}

/// With a run channel, an app's requests are taken by its shim: no node is
/// called, and the app serves only once the shim has asked for one.
#[tokio::test]
async fn an_app_serves_once_its_shim_asks_and_its_requests_go_through_the_run_channel() {
    use fenders_control_plane::http_exchange::{frame, unframe};
    use fenders_control_plane::run_channel::{self, RunChannel};
    let mut l = Lab::new().await;
    l.store = l.store.clone().with_run_channel(
        RunChannel::new("https://control.test:9093", "fixture ca".into(), None).unwrap(),
    );
    let node = l.node("worker").await;
    approve_component(&l, &node, true, true).await;
    let (app, version) = define_app(&l, "pulled").await;
    l.http_trigger(&app, true, true, "enable-http").await;
    l.release(&app, &version, "first").await;
    l.store.schedule().await.unwrap();
    let e = l.execution(s(&l.http(&app).await["execution_id"])).await;
    let (id, generation) = (s(&e["id"]).to_owned(), n(&e["generation"]));
    let host = format!("app-{app}.apps.test");

    // Its VM is running, but its shim has not asked: not serving.
    l.report(&node, &e, "running", 1).await;
    assert_eq!(l.http(&app).await["state"], "starting");
    assert_eq!(
        l.store.ingress_start(&host, 0).await.unwrap_err().status,
        StatusCode::SERVICE_UNAVAILABLE
    );

    let bearer = s(&l
        .store
        .assignment(s(&node["id"]), &id, generation)
        .await
        .unwrap()["spec"]["channel"]["credential"])
    .to_owned();
    let channel = run_channel::router(l.store.clone());
    let post = |path: String, body: axum::body::Bytes| {
        let (channel, bearer) = (channel.clone(), bearer.clone());
        async move {
            let response = channel
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(path)
                        .header("Authorization", format!("Bearer {bearer}"))
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = response.status();
            (
                status,
                axum::body::to_bytes(response.into_body(), 4 << 20)
                    .await
                    .unwrap(),
            )
        }
    };
    let next_path = format!("/run/{id}/{generation}/v1/run/http/next");
    let next = tokio::spawn(post(next_path.clone(), Default::default()));
    while !l.store.exchange.ready(&id) {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    l.store.schedule().await.unwrap();
    assert_eq!(l.http(&app).await["state"], "serving");

    let gateway = api::gateway(api::ApiState {
        store: l.store.clone(),
        domain: "apps.test".into(),
        tls: None,
    });
    let send = |method: &'static str, path: &'static str, body: &'static str| {
        let (gateway, host) = (gateway.clone(), host.clone());
        tokio::spawn(async move {
            let response = gateway
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(path)
                        .header("Host", host)
                        .header("Content-Type", "text/plain")
                        .header("Cookie", "never-forwarded")
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            let (parts, body) = response.into_parts();
            (parts, axum::body::to_bytes(body, 4 << 20).await.unwrap())
        })
    };

    // A request reaches the shim's ask as it was sent, less what may not
    // cross to an app, and the shim's answer reaches the client likewise.
    let client = send("POST", "/orders?x=1", "hello");
    let (status, request) = next.await.unwrap();
    assert_eq!(status, StatusCode::OK);
    let (head, body) = unframe(&request).unwrap();
    assert_eq!(head["method"], "POST");
    assert_eq!(head["path"], "/orders?x=1");
    assert_eq!(head["headers"]["content-type"], "text/plain");
    assert!(head["headers"].get("cookie").is_none());
    assert_eq!(&body[..], b"hello");
    let request_id = s(&head["id"]).to_owned();
    let answer_path = |id: &str| {
        format!(
            "/run/{}/{generation}/v1/run/http/response/{id}",
            e["id"].as_str().unwrap()
        )
    };
    // An answer to a request that is not out is refused.
    assert_eq!(
        post(
            answer_path("0123456789abcdef0123456789abcdef"),
            frame(&json!({"status":200,"headers":{}}), b"forged")
        )
        .await
        .0,
        StatusCode::GONE
    );
    let answer = frame(
        &json!({"status":201,"headers":{"content-type":"text/plain","set-cookie":"a=b"}}),
        b"made",
    );
    assert_eq!(
        post(answer_path(&request_id), answer.clone()).await.0,
        StatusCode::OK
    );
    assert_eq!(
        post(answer_path(&request_id), answer).await.0,
        StatusCode::GONE
    );
    let (parts, body) = client.await.unwrap();
    assert_eq!(parts.status, StatusCode::CREATED);
    assert_eq!(parts.headers["content-type"], "text/plain");
    assert!(parts.headers.get("set-cookie").is_none());
    assert_eq!(&body[..], b"made");
    // The request is settled once its response has ended, and its record
    // is written by the flush after that.
    let recorded = || async {
        for _ in 0..200 {
            let held: i64 =
                sqlx::query_scalar("SELECT count(*) FROM ingress_reservations WHERE id=$1")
                    .bind(&request_id)
                    .fetch_one(&l.store.pool)
                    .await
                    .unwrap();
            if held == 0 {
                l.store.flush_gateway().await.unwrap();
                return sqlx::query_as::<_, (String, Option<i32>)>(
                    "SELECT state,http_status FROM app_http_runs WHERE id=$1",
                )
                .bind(&request_id)
                .fetch_one(&l.store.pool)
                .await
                .unwrap();
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("the request was never settled");
    };
    assert_eq!(recorded().await, ("succeeded".to_owned(), Some(201)));
    let counted: i64 = sqlx::query_scalar(
        "SELECT COALESCE(sum(bytes),0)::bigint FROM traffic_usage WHERE tenant_id=$1",
    )
    .bind(&l.tenant)
    .fetch_one(&l.store.pool)
    .await
    .unwrap();
    assert_eq!(counted, ("hello".len() + "made".len()) as i64);

    // An app that fails a request: the client gets 502 and it is recorded.
    let client = send("GET", "/boom", "");
    let (_, request) = post(next_path.clone(), Default::default()).await;
    let failed_id = s(&unframe(&request).unwrap().0["id"]).to_owned();
    post(
        answer_path(&failed_id),
        frame(&json!({"error":"the app failed the request"}), b""),
    )
    .await;
    assert_eq!(client.await.unwrap().0.status, StatusCode::BAD_GATEWAY);
    l.store.flush_gateway().await.unwrap();
    let recorded: (String, Option<i32>) =
        sqlx::query_as("SELECT state,http_status FROM app_http_runs WHERE id=$1")
            .bind(&failed_id)
            .fetch_one(&l.store.pool)
            .await
            .unwrap();
    assert_eq!(recorded, ("failed".to_owned(), Some(502)));

    // A sample request is audited as what was asked of the app: its method
    // and its path, without the query.
    l.store
        .app_sample_hostname_for(
            &l.operator,
            &l.tenant,
            &l.project,
            &app,
            "DELETE",
            "/orders/7?token=never-kept",
        )
        .await
        .unwrap();
    let sampled: Value = sqlx::query_scalar(
        "SELECT detail FROM audit WHERE action='app.http-sample' ORDER BY sequence DESC LIMIT 1",
    )
    .fetch_one(&l.store.pool)
    .await
    .unwrap();
    assert_eq!(sampled, json!({"method":"DELETE","path":"/orders/7"}));

    // A target too long to fit a head the shim reads is refused before it is
    // admitted: no reservation, nothing offered to the app.
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM app_http_runs")
        .fetch_one(&l.store.pool)
        .await
        .unwrap();
    for (target, expected) in [
        (format!("/{}", "a".repeat(9000)), StatusCode::URI_TOO_LONG),
        (
            format!("/?q={}", "a".repeat(9000)),
            StatusCode::URI_TOO_LONG,
        ),
        (
            format!("/{}", "a".repeat(8000)),
            StatusCode::SERVICE_UNAVAILABLE,
        ),
    ] {
        let fits = expected != StatusCode::URI_TOO_LONG;
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(if fits { 1 } else { 30 }),
            gateway.clone().oneshot(
                Request::builder()
                    .uri(target)
                    .header("Host", host.clone())
                    .body(Body::empty())
                    .unwrap(),
            ),
        )
        .await;
        match response {
            Ok(response) => assert_eq!(response.unwrap().status(), expected),
            // One that fits is admitted and waits for the app to take it.
            Err(_) => assert!(fits),
        }
    }
    l.store.flush_gateway().await.unwrap();
    let after: i64 = sqlx::query_scalar("SELECT count(*) FROM app_http_runs")
        .fetch_one(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(after, before + 1, "only the target that fits was admitted");
    // That one was abandoned by its client while it waited to be taken. It
    // is settled at once rather than held until its reservation lapses, and
    // nothing is charged for what never passed.
    let mut held = 1i64;
    for _ in 0..200 {
        held = sqlx::query_scalar("SELECT count(*) FROM ingress_reservations WHERE tenant_id=$1")
            .bind(&l.tenant)
            .fetch_one(&l.store.pool)
            .await
            .unwrap();
        if held == 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(held, 0, "an abandoned request keeps no reservation");
    let charged: i64 = sqlx::query_scalar(
        "SELECT COALESCE(sum(bytes),0)::bigint FROM traffic_usage WHERE tenant_id=$1",
    )
    .bind(&l.tenant)
    .fetch_one(&l.store.pool)
    .await
    .unwrap();
    assert_eq!(charged, counted, "an abandoned request is charged nothing");

    // A command's launch takes no requests, and neither does this one once
    // it is stopped: its credential is for a generation that is gone.
    l.lifecycle(&app, "stopped", "stop").await;
    l.store.schedule().await.unwrap();
    let after = post(next_path, Default::default()).await.0;
    assert!(
        matches!(after, StatusCode::CONFLICT | StatusCode::UNAUTHORIZED),
        "{after}"
    );
}

/// A request whose client goes away before it has an answer is settled at
/// once: it keeps no reservation of the workspace's allowance or place among
/// its requests, and nothing is charged for what never passed.
#[tokio::test]
async fn a_request_its_client_abandoned_is_settled_at_once_and_charged_nothing() {
    let l = Lab::new().await;
    let node = l.node("worker").await;
    approve_component(&l, &node, true, true).await;
    let (app, version) = define_app(&l, "abandoned").await;
    l.http_trigger(&app, true, true, "enable-http").await;
    l.release(&app, &version, "first").await;
    l.http_running(&app, &node).await;
    let host = format!("app-{app}.apps.test");
    let gateway = api::gateway(api::ApiState {
        store: l.store.clone(),
        domain: "apps.test".into(),
        tls: None,
    });
    let reservations = || async {
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM ingress_reservations WHERE tenant_id=$1")
            .bind(&l.tenant)
            .fetch_one(&l.store.pool)
            .await
            .unwrap()
    };
    let charged = || async {
        sqlx::query_scalar::<_, i64>(
            "SELECT COALESCE(sum(bytes),0)::bigint FROM traffic_usage WHERE tenant_id=$1",
        )
        .bind(&l.tenant)
        .fetch_one(&l.store.pool)
        .await
        .unwrap()
    };
    assert_eq!((reservations().await, charged().await), (0, 0));
    let admitted = || async {
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM app_http_runs WHERE tenant_id=$1")
            .bind(&l.tenant)
            .fetch_one(&l.store.pool)
            .await
            .unwrap()
    };
    // Three clients ask, one after another. Nothing takes their requests:
    // each waits until its request has been admitted and holds a
    // reservation, then goes away, dropping the request where it stands.
    for n in 0..3 {
        let mut request = Box::pin(
            gateway.clone().oneshot(
                Request::builder()
                    .uri(format!("/orders/{n}"))
                    .header("Host", host.clone())
                    .body(Body::empty())
                    .unwrap(),
            ),
        );
        let mut waited = 0;
        while reservations().await == 0 {
            let answered =
                tokio::time::timeout(std::time::Duration::from_millis(20), &mut request).await;
            assert!(
                answered.is_err(),
                "the request waits for the app to take it"
            );
            waited += 1;
            assert!(waited < 1500, "the request was never admitted");
        }
        assert_eq!(
            reservations().await,
            1,
            "an admitted request holds a reservation"
        );
        drop(request);
        // Settled before the next client asks, not when it would have lapsed.
        let mut held = 1;
        for _ in 0..500 {
            held = reservations().await;
            if held == 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(held, 0, "an abandoned request keeps no reservation");
    }
    // Each has its record, written by a flush: offered to the app and
    // never answered, so whether it ran is not known.
    assert_eq!(admitted().await, 0);
    l.store.flush_gateway().await.unwrap();
    assert_eq!(admitted().await, 3);
    assert_eq!(
        charged().await,
        0,
        "an abandoned request is charged nothing"
    );
    // And the workspace's requests are admitted as before: none of its
    // places is still taken by one nobody waits for.
    let (_, lease) = l.store.ingress_start(&host, 0).await.unwrap();
    l.store
        .ingress_complete(&lease, Some(0), Some(200))
        .await
        .unwrap();
}

/// A request's bytes are reserved against the transfer allowance a block at
/// a time as they pass, and none pass that are not reserved.
#[tokio::test]
async fn a_requests_bytes_are_reserved_in_blocks_and_stop_where_the_allowance_ends() {
    use fenders_control_plane::ingress::{MAX_REQUEST_BYTES, Meter, TRANSFER_BLOCK, Way};
    const MIB: usize = 1024 * 1024;
    let l = Lab::new().await;
    let node = l.node("worker").await;
    approve_component(&l, &node, true, true).await;
    let (app, version) = define_app(&l, "metered").await;
    l.http_trigger(&app, true, true, "enable-http").await;
    l.release(&app, &version, "first").await;
    l.http_running(&app, &node).await;
    let host = format!("app-{app}.apps.test");
    // Room for three blocks and a half.
    sqlx::query("UPDATE tenants SET transfer_bytes=$2 WHERE id=$1")
        .bind(&l.tenant)
        .bind((3 * MIB + MIB / 2) as i64)
        .execute(&l.store.pool)
        .await
        .unwrap();
    let pool = &l.store.pool;
    let reserved = |lease: String| async move {
        sqlx::query_scalar::<_, i64>("SELECT bytes FROM ingress_reservations WHERE id=$1")
            .bind(lease)
            .fetch_one(pool)
            .await
            .unwrap()
    };
    let (_, lease) = l.store.ingress_start(&host, 0).await.unwrap();
    assert_eq!(reserved(lease.clone()).await, TRANSFER_BLOCK);
    let meter = Meter::new(l.store.clone(), &lease);
    // Within the first block nothing more is reserved.
    assert!(meter.admit(Way::In, MIB / 2).await);
    assert!(meter.admit(Way::Out, MIB / 2).await);
    assert_eq!(reserved(lease.clone()).await, TRANSFER_BLOCK);
    // Past it, the next block is reserved before the bytes pass.
    assert!(meter.admit(Way::Out, 1).await);
    assert_eq!(reserved(lease.clone()).await, 2 * TRANSFER_BLOCK);
    assert!(meter.admit(Way::Out, 2 * MIB - 1).await);
    assert_eq!(reserved(lease.clone()).await, 3 * TRANSFER_BLOCK);
    // The allowance has half a block left: a fourth cannot be reserved, so
    // the byte that needs it does not pass, and nothing does after that.
    assert!(!meter.admit(Way::Out, 1).await);
    assert!(!meter.admit(Way::In, 1).await);
    assert_eq!(meter.passed().await, (3 * MIB) as i64);
    assert_eq!(reserved(lease.clone()).await, 3 * TRANSFER_BLOCK);
    l.store
        .ingress_complete(&lease, Some(meter.passed().await), Some(200))
        .await
        .unwrap();
    let counted: i64 = sqlx::query_scalar(
        "SELECT COALESCE(sum(bytes),0)::bigint FROM traffic_usage WHERE tenant_id=$1",
    )
    .bind(&l.tenant)
    .fetch_one(&l.store.pool)
    .await
    .unwrap();
    assert_eq!(counted, (3 * MIB) as i64);

    // A body over its size limit is refused whatever the allowance, and a
    // request whose reservation lapsed passes nothing more.
    sqlx::query("UPDATE tenants SET transfer_bytes=1000000000000 WHERE id=$1")
        .bind(&l.tenant)
        .execute(&l.store.pool)
        .await
        .unwrap();
    let (_, lease) = l.store.ingress_start(&host, 0).await.unwrap();
    let meter = Meter::new(l.store.clone(), &lease);
    assert!(!meter.admit(Way::In, MAX_REQUEST_BYTES as usize + 1).await);
    assert!(meter.admit(Way::In, 10).await);
    meter.renew().await;
    assert!(meter.admit(Way::In, 10).await);
    sqlx::query("UPDATE ingress_reservations SET expires=now()-interval '1 second' WHERE id=$1")
        .bind(&lease)
        .execute(&l.store.pool)
        .await
        .unwrap();
    meter.renew().await;
    assert!(!meter.admit(Way::In, 10).await);
    assert_eq!(meter.passed().await, 20);
}

/// An app is given another execution while its requests wait, within its
/// maximum and the workspace's allowance, and loses it again when it has had
/// nothing to do.
#[tokio::test]
async fn an_app_under_load_gets_more_executions_and_gives_them_back_when_idle() {
    use fenders_control_plane::http_exchange::Message;
    use fenders_control_plane::run_channel::RunChannel;
    use std::time::Duration;
    let mut l = Lab::new().await;
    l.store = l.store.clone().with_run_channel(
        RunChannel::new("https://control.test:9093", "fixture ca".into(), None).unwrap(),
    );
    let node = l.node("worker").await;
    let second = l.node("second-worker").await;
    approve_component(&l, &node, true, true).await;
    let op=l.store.deploy_app(&l.operator,&l.tenant,&l.project,fenders_control_plane::apps::AppSubmission{value:json!({"name":"scaled","artifact_id":l.artifact,"configuration":{"scale":{"min":1,"max":2}},"triggers":{"http":true,"manual":false}}),key:"scaled",domain:"apps.test"}).await.unwrap();
    let app = s(&op["resource_id"]).to_owned();
    l.store.schedule().await.unwrap();
    let first = l.execution(s(&l.http(&app).await["execution_id"])).await;
    let first_node = if first["node_id"] == node["id"] {
        &node
    } else {
        &second
    };
    l.report(first_node, &first, "running", 1).await;
    let exchange = l.store.exchange.clone();
    let short = Duration::from_millis(20);
    let long = Duration::from_secs(60);
    let message = || Message {
        head: json!({}),
        body: Body::empty(),
    };
    // Its shim asks: it serves, alone.
    assert!(exchange.next(&app, s(&first["id"]), short).await.is_none());
    l.store.schedule().await.unwrap();
    assert_eq!(l.http(&app).await["state"], "serving");
    assert_eq!(l.http(&app).await["executions"], 1);
    let executions = || async {
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM executions WHERE reserved AND desired='running'",
        )
        .fetch_one(&l.store.pool)
        .await
        .unwrap()
    };
    assert_eq!(executions().await, 1);

    // One request is taken; a second waits behind it for over a second.
    let offer = |id: &'static str| {
        let (exchange, app) = (exchange.clone(), app.clone());
        tokio::spawn(async move { exchange.offer(&app, id, message(), long, long).await })
    };
    let (held, waiting) = (offer("r1"), offer("r2"));
    tokio::time::sleep(short).await;
    assert!(exchange.next(&app, s(&first["id"]), short).await.is_some());
    exchange.rewind(Duration::from_secs(2));

    // The workspace's allowance has no room for another: it stays at one.
    sqlx::query("UPDATE tenants SET instances=1 WHERE id=$1")
        .bind(&l.tenant)
        .execute(&l.store.pool)
        .await
        .unwrap();
    l.store.schedule().await.unwrap();
    assert_eq!(executions().await, 1);
    // With room, one more is started, on another node; while it starts no
    // third is, whatever the load.
    sqlx::query("UPDATE tenants SET instances=4 WHERE id=$1")
        .bind(&l.tenant)
        .execute(&l.store.pool)
        .await
        .unwrap();
    l.store.schedule().await.unwrap();
    assert_eq!(executions().await, 2);
    let extra: String =
        sqlx::query_scalar("SELECT execution_id FROM app_http_extras WHERE app_id=$1")
            .bind(&app)
            .fetch_one(&l.store.pool)
            .await
            .unwrap();
    let extra = l.execution(&extra).await;
    assert_ne!(extra["node_id"], first["node_id"]);
    assert_eq!(extra["spec"], first["spec"]);
    l.store.schedule().await.unwrap();
    assert_eq!(executions().await, 2);
    assert_eq!(l.http(&app).await["executions"], 1);

    // It runs and its shim asks the app's queue: it takes the waiting
    // request, and the app is served by two.
    let extra_node = [&node, &second]
        .into_iter()
        .find(|n| n["id"] == extra["node_id"]);
    if let Some(extra_node) = extra_node {
        l.report(extra_node, &extra, "running", 1).await;
    } else {
        sqlx::query("UPDATE executions SET state='running' WHERE id=$1")
            .bind(s(&extra["id"]))
            .execute(&l.store.pool)
            .await
            .unwrap();
    }
    assert!(exchange.next(&app, s(&extra["id"]), short).await.is_some());
    assert_eq!(l.http(&app).await["executions"], 2);
    // At its maximum: more load starts nothing.
    exchange.rewind(Duration::from_secs(30));
    l.store.schedule().await.unwrap();
    assert_eq!(executions().await, 2);

    // Both answer. With asks waiting and nothing to do for a minute, the
    // extra one is stopped; the first stays.
    for (taker, id) in [(&first, "r1"), (&extra, "r2")] {
        assert!(exchange.respond(s(&taker["id"]), id, message()));
        exchange.finished(s(&taker["id"]), id);
    }
    held.await.unwrap();
    waiting.await.unwrap();
    let asks: Vec<_> = [&first, &extra]
        .into_iter()
        .map(|taker| {
            let (exchange, app, taker) =
                (exchange.clone(), app.clone(), s(&taker["id"]).to_owned());
            tokio::spawn(async move { exchange.next(&app, &taker, long).await })
        })
        .collect();
    tokio::time::sleep(short).await;
    l.store.schedule().await.unwrap();
    assert_eq!(executions().await, 2);
    exchange.rewind(Duration::from_secs(61));
    l.store.schedule().await.unwrap();
    assert_eq!(executions().await, 1);
    assert_eq!(l.execution(s(&extra["id"])).await["desired"], "stopped");
    assert_eq!(l.execution(s(&first["id"])).await["desired"], "running");
    assert_eq!(l.http(&app).await["state"], "serving");
    for ask in asks {
        ask.abort();
    }
}

/// A new release is brought up beside the execution that serves and takes
/// over once it runs, with no moment at which requests are refused; one that
/// never runs is failed and the app goes on as it was.
#[tokio::test]
async fn a_release_takes_over_beside_the_one_that_serves_or_fails_and_leaves_it() {
    let l = Lab::new().await;
    let nodes = [l.node("worker").await, l.node("second-worker").await];
    let on = |e: &Value| {
        nodes
            .iter()
            .find(|n| n["id"] == e["node_id"])
            .expect("the execution is on a node")
            .clone()
    };
    approve_component(&l, &nodes[0], true, true).await;
    let (app, version) = define_app(&l, "rolling").await;
    l.http_trigger(&app, true, false, "on").await;
    let first = l.release(&app, &version, "first").await;
    l.store.schedule().await.unwrap();
    let old = l.execution(s(&l.http(&app).await["execution_id"])).await;
    l.report(&on(&old), &old, "running", 1).await;
    assert_eq!(l.http(&app).await["state"], "serving");
    let host = format!("app-{app}.apps.test");
    let active = || async {
        l.store
            .app(&l.operator, &l.tenant, &l.project, &app)
            .await
            .unwrap()["active_release_id"]
            .clone()
    };
    let candidate = || async {
        let id: Option<String> =
            sqlx::query_scalar("SELECT candidate_execution_id FROM app_http WHERE app_id=$1")
                .bind(&app)
                .fetch_one(&l.store.pool)
                .await
                .unwrap();
        id
    };

    // The next release: its execution is started on the other node while
    // the old one serves, a request in flight on it.
    let next = l.release(&app, &version, "next").await;
    assert_eq!(next["state"], "pending");
    l.store.schedule().await.unwrap();
    let new = l.execution(&candidate().await.unwrap()).await;
    assert_ne!(new["node_id"], old["node_id"]);
    assert_eq!(l.http(&app).await["state"], "serving");
    assert_eq!(l.http(&app).await["execution_id"], old["id"]);
    assert_eq!(active().await, first["resource_id"]);
    let (route, held) = l.store.ingress_start(&host, 0).await.unwrap();
    assert_eq!(route["execution_id"], old["id"]);
    assert_eq!(l.operation(&next).await["state"], "pending");

    // It runs: it takes over. Requests are routed to it from then on; the
    // old one keeps its request and is stopped when that ends.
    l.report(&on(&new), &new, "running", 1).await;
    assert_eq!(l.http(&app).await["state"], "serving");
    assert_eq!(l.http(&app).await["execution_id"], new["id"]);
    assert_eq!(candidate().await, None);
    assert_eq!(active().await, next["resource_id"]);
    assert_eq!(l.operation(&next).await["state"], "succeeded");
    let (route, after) = l.store.ingress_start(&host, 0).await.unwrap();
    assert_eq!(route["execution_id"], new["id"]);
    l.store.ingress_finish(&after, Some(0)).await.unwrap();
    l.store.schedule().await.unwrap();
    assert_eq!(l.execution(s(&old["id"])).await["desired"], "running");
    l.store.ingress_finish(&held, Some(0)).await.unwrap();
    // Idle now, but for a few seconds after the switch an ask it made
    // before could still be given a request: it is stopped after those.
    l.store.schedule().await.unwrap();
    assert_eq!(l.execution(s(&old["id"])).await["desired"], "running");
    sqlx::query("UPDATE app_http SET drain_until=drain_until-interval '5 seconds' WHERE app_id=$1")
        .bind(&app)
        .execute(&l.store.pool)
        .await
        .unwrap();
    l.store.schedule().await.unwrap();
    let stopping = l.execution(s(&old["id"])).await;
    assert_eq!(stopping["desired"], "stopped");
    l.report(&on(&old), &stopping, "stopped", 2).await;

    // A release whose execution fails: the app goes on with the one it has.
    let bad = l.release(&app, &version, "bad").await;
    l.store.schedule().await.unwrap();
    let failing = l.execution(&candidate().await.unwrap()).await;
    l.report(&on(&failing), &failing, "failed", 1).await;
    l.store.schedule().await.unwrap();
    let failed = l.operation(&bad).await;
    assert_eq!(failed["state"], "failed");
    assert_eq!(failed["error"], "http-startup-failed");
    assert_eq!(candidate().await, None);
    assert_eq!(l.http(&app).await["state"], "serving");
    assert_eq!(l.http(&app).await["execution_id"], new["id"]);
    assert_eq!(active().await, next["resource_id"]);
    let (route, still) = l.store.ingress_start(&host, 0).await.unwrap();
    assert_eq!(route["execution_id"], new["id"]);
    l.store.ingress_finish(&still, Some(0)).await.unwrap();
}

/// An execution of an app that accepts WebSocket connections is given the
/// host-bound origin, and over the run channel sends to, lists and closes
/// that app's connections and no other's; a client cannot ask the gateway
/// for the paths its events go to.
#[tokio::test]
async fn an_apps_executions_send_to_its_websocket_connections_and_no_others() {
    use fenders_control_plane::run_channel::{self, RunChannel};
    use fenders_control_plane::websocket::Push;
    let mut l = Lab::new().await;
    l.store = l.store.clone().with_run_channel(
        RunChannel::new("https://control.test:9093", "fixture ca".into(), None).unwrap(),
    );
    let nodes = [l.node("worker").await, l.node("second-worker").await];
    approve_component(&l, &nodes[0], true, true).await;
    let deploy = |name: &'static str, websocket: bool| {
        let l = &l;
        async move {
            let op=l.store.deploy_app(&l.operator,&l.tenant,&l.project,fenders_control_plane::apps::AppSubmission{value:json!({"name":name,"artifact_id":l.artifact,"configuration":{"websocket":websocket},"triggers":{"http":true,"manual":false}}),key:name,domain:"apps.test"}).await.unwrap();
            let app = s(&op["resource_id"]).to_owned();
            l.store.schedule().await.unwrap();
            let e = l.execution(s(&l.http(&app).await["execution_id"])).await;
            let spec = l
                .store
                .assignment(s(&e["node_id"]), s(&e["id"]), n(&e["generation"]))
                .await
                .unwrap()["spec"]
                .clone();
            (app, e, spec)
        }
    };
    let (sockets, sender, with) = deploy("sockets", true).await;
    let (plain, other, without) = deploy("plain", false).await;
    // Only the app that accepts connections is given the origin to call.
    assert_eq!(
        with["host_origin"],
        fenders_control_plane::websocket::ORIGIN
    );
    assert!(without.get("host_origin").is_none());

    let channel = run_channel::router(l.store.clone());
    let call = |e: &Value, spec: &Value, method: &'static str, rest: &str, body: &'static str| {
        let channel = channel.clone();
        let path = format!(
            "/run/{}/{}/v1/run/ws{rest}",
            s(&e["id"]),
            n(&e["generation"])
        );
        let bearer = s(&spec["channel"]["credential"]).to_owned();
        async move {
            let response = channel
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(path)
                        .header("Authorization", format!("Bearer {bearer}"))
                        .header("Content-Type", "text/plain")
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = response.status();
            let bytes = axum::body::to_bytes(response.into_body(), 65536)
                .await
                .unwrap();
            (
                status,
                serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null),
            )
        }
    };
    // Two clients of the app, and one of the other.
    let open = |id: &str, app: &str| {
        l.store
            .sockets
            .open(id, app, &l.tenant, &l.project)
            .unwrap()
    };
    let (first, second) = ("a".repeat(32), "b".repeat(32));
    let mut to_first = open(&first, &sockets);
    let mut to_second = open(&second, &sockets);
    let foreign = "c".repeat(32);
    let mut to_foreign = open(&foreign, &plain);

    let (status, listed) = call(&sender, &with, "GET", "", "").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(listed["connections"], json!([first, second]));
    let (status, _) = call(&sender, &with, "POST", &format!("/{first}"), "hello").await;
    assert_eq!(status, StatusCode::OK);
    assert!(matches!(to_first.try_recv(), Ok(Push::Text(text)) if text == "hello"));
    assert!(to_second.try_recv().is_err());
    // What it sent is counted against the transfer allowance.
    let counted: i64 = sqlx::query_scalar(
        "SELECT COALESCE(sum(bytes),0)::bigint FROM traffic_usage WHERE tenant_id=$1",
    )
    .bind(&l.tenant)
    .fetch_one(&l.store.pool)
    .await
    .unwrap();
    assert_eq!(counted, 5);
    let (status, _) = call(&sender, &with, "DELETE", &format!("/{second}"), "").await;
    assert_eq!(status, StatusCode::OK);
    assert!(matches!(to_second.try_recv(), Ok(Push::Close)));
    // Not another app's connection, not one that is not open, and nothing
    // at all from an app that accepts none.
    for id in [&foreign, &"d".repeat(32)] {
        let (status, _) = call(&sender, &with, "POST", &format!("/{id}"), "x").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
    assert!(to_foreign.try_recv().is_err());
    for (method, rest) in [("GET", String::new()), ("POST", format!("/{foreign}"))] {
        let (status, _) = call(&other, &without, method, &rest, "x").await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    // Each connection is one of the app's requests: open, with the path
    // its client asked for and no query; then finished, with what passed
    // over it. Its messages are not listed.
    use fenders_control_plane::app_events::EventPage;
    for id in [&first, &second] {
        l.store
            .websocket_opened(id, &sockets, "/room?token=never-kept")
            .await
            .unwrap();
    }
    let shown = l
        .store
        .app_websocket(&l.operator, &l.tenant, &l.project, &sockets)
        .await
        .unwrap();
    assert_eq!(shown["enabled"], true);
    assert_eq!(shown["open"], 2);
    assert_eq!(shown["connections"][0]["path"], "/room");
    let none = l
        .store
        .app_websocket(&l.operator, &l.tenant, &l.project, &plain)
        .await
        .unwrap();
    assert_eq!(none["enabled"], false);
    assert_eq!(none["open"], 1);
    let listed = || async {
        let events = l
            .store
            .app_events(
                &l.operator,
                &l.tenant,
                &l.project,
                &sockets,
                EventPage::default(),
            )
            .await
            .unwrap();
        events["items"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|item| !item["websocket"].is_null())
            .cloned()
            .collect::<Vec<_>>()
    };
    let open = listed().await;
    assert_eq!(open.len(), 2);
    assert!(
        open.iter()
            .all(|c| c["state"] == "running" && c["path"] == "/room" && c["finished_at"].is_null())
    );
    l.store
        .websocket_closed(&first, [3, 30, 2, 20])
        .await
        .unwrap();
    l.store
        .websocket_refused(&"e".repeat(32), &sockets, "/refuse", StatusCode::FORBIDDEN)
        .await
        .unwrap();
    let after = listed().await;
    assert_eq!(after.len(), 3);
    let closed = after.iter().find(|c| c["id"] == json!(first)).unwrap();
    assert_eq!(closed["state"], "succeeded");
    assert_eq!(
        closed["websocket"],
        json!({"messages_in":3,"bytes_in":30,"messages_out":2,"bytes_out":20})
    );
    assert!(closed["duration_ms"].is_number());
    let refused = after.iter().find(|c| c["path"] == "/refuse").unwrap();
    assert_eq!(refused["state"], "failed");
    assert_eq!(refused["http_status"], 403);
    // A connection this process does not hold (a restart closed it) is
    // finished as unknown once it is over a minute old; one it holds stays.
    let lost = "f".repeat(32);
    l.store
        .websocket_opened(&lost, &sockets, "/lost")
        .await
        .unwrap();
    sqlx::query(
        "UPDATE app_http_runs SET created=created-interval '2 minutes' WHERE websocket IS NOT NULL",
    )
    .execute(&l.store.pool)
    .await
    .unwrap();
    l.store.websocket_sweep().await.unwrap();
    let swept = listed().await;
    assert_eq!(
        swept.iter().find(|c| c["path"] == "/lost").unwrap()["state"],
        "unknown"
    );
    assert_eq!(
        swept.iter().find(|c| c["id"] == json!(second)).unwrap()["state"],
        "running"
    );

    // A client cannot ask for an event path, and an app that accepts no
    // connections refuses an upgrade.
    let gateway = api::gateway(api::ApiState {
        store: l.store.clone(),
        domain: "apps.test".into(),
        tls: None,
    });
    let ask = |app: &str, path: &'static str, upgrade: bool| {
        let mut request = Request::builder()
            .method("GET")
            .uri(path)
            .header("Host", format!("app-{app}.apps.test"));
        if upgrade {
            request = request
                .header("Connection", "Upgrade")
                .header("Upgrade", "websocket")
                .header("Sec-WebSocket-Version", "13")
                .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");
        }
        let gateway = gateway.clone();
        async move {
            gateway
                .oneshot(request.body(Body::empty()).unwrap())
                .await
                .unwrap()
                .status()
        }
    };
    // A connection that was opened and never served (its client went away
    // before the upgrade, or recording it failed) gives its place back and
    // its record is closed: it does not count against the app for ever.
    let abandoned = "f".repeat(32);
    let before = l.store.sockets.list(&sockets).len();
    assert!(
        l.store
            .sockets
            .open(&abandoned, &sockets, &l.tenant, &l.project)
            .is_some()
    );
    l.store
        .websocket_opened(&abandoned, &sockets, "/abandoned")
        .await
        .unwrap();
    assert_eq!(l.store.sockets.list(&sockets).len(), before + 1);
    drop(fenders_control_plane::websocket::held(
        api::ApiState {
            store: l.store.clone(),
            domain: "apps.test".into(),
            tls: None,
        },
        &format!("app-{sockets}.apps.test"),
        &abandoned,
    ));
    assert_eq!(l.store.sockets.list(&sockets).len(), before);
    let mut finished = false;
    for _ in 0..200 {
        finished =
            sqlx::query_scalar("SELECT finished_at IS NOT NULL FROM app_http_runs WHERE id=$1")
                .bind(&abandoned)
                .fetch_one(&l.store.pool)
                .await
                .unwrap();
        if finished {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(finished, "an abandoned connection's record is closed");

    assert_eq!(
        ask(&sockets, "/_fenders/ws/message", false).await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        ask(&plain, "/room", true).await,
        StatusCode::UPGRADE_REQUIRED
    );
}
