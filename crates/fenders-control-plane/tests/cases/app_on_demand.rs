//! PostgreSQL lifecycle and gateway admission proofs; no guest is simulated as
//! live KVM evidence by these state-report fixtures.
use super::*;

#[tokio::test]
async fn expired_assigned_wake_retains_quota_until_fenced_and_keep_warm_is_explicit() {
    let l = Lab::new().await;
    let node = l.node("worker").await;
    let app = l.demand_app(&node).await;
    l.idle_http(&app, &node).await;
    let host = format!("app-{app}.apps.test");
    let (_, q) = l.store.ingress_begin(&host, 0, true).await.unwrap();
    l.store.schedule().await.unwrap();
    let starting = l.execution(s(&l.http(&app).await["execution_id"])).await;
    assert_eq!(starting["node_id"], node["id"]);
    sqlx::query("UPDATE app_http SET ready_until=now()-interval '1 second' WHERE app_id=$1")
        .bind(&app)
        .execute(&l.store.pool)
        .await
        .unwrap();
    l.store.schedule().await.unwrap();
    let stopping = l.execution(s(&starting["id"])).await;
    assert_eq!(stopping["desired"], "stopped");
    assert_eq!(stopping["reserved"], true);
    l.report(&node, &starting, "running", 1).await;
    // The wake gave up: the app is not blocked, it goes back to idle once
    // what was started for it has stopped. The request waits on until its
    // own deadline, for a wake that may yet serve it.
    assert_eq!(l.http(&app).await["state"], "stopping");
    assert_eq!(l.http(&app).await["reason"], "wake-timed-out");
    assert!(l.store.ingress_poll(&q).await.unwrap().is_none());
    l.store.ingress_finish(&q, Some(0)).await.unwrap();
    l.report(&node, &stopping, "stopped", 2).await;
    assert_eq!(l.execution(s(&starting["id"])).await["reserved"], false);
    let before = l
        .store
        .app(&l.operator, &l.tenant, &l.project, &app)
        .await
        .unwrap();
    let version = before["active_release"]["version_id"].clone();
    let request = |warm: Value| json!({"version_id":version,"expected_revision":before["revision"],"configuration":{"keep_warm":warm}});
    assert_eq!(
        l.store
            .activate_app_release(
                &l.operator,
                &l.tenant,
                &l.project,
                &app,
                request(json!("false")),
                "invalid"
            )
            .await
            .unwrap_err()
            .status,
        StatusCode::BAD_REQUEST
    );
    let (viewer, _) = l.credential("viewer", Some(&l.project)).await;
    assert_eq!(
        l.store
            .activate_app_release(
                &viewer,
                &l.tenant,
                &l.project,
                &app,
                request(json!(true)),
                "forbidden"
            )
            .await
            .unwrap_err()
            .status,
        StatusCode::FORBIDDEN
    );
    l.store
        .activate_app_release(
            &l.operator,
            &l.tenant,
            &l.project,
            &app,
            request(json!(true)),
            "warm",
        )
        .await
        .unwrap();
    l.http_running(&app, &node).await;
    l.idle_clock(&app).await;
    l.store.schedule().await.unwrap();
    assert_eq!(l.http(&app).await["state"], "serving");
    assert_eq!(
        l.store
            .app(&l.operator, &l.tenant, &l.project, &app)
            .await
            .unwrap()["configuration"]["keep_warm"],
        true
    );
    l.finish().await;
}

impl Lab {
    async fn demand_app(&self, node: &Value) -> String {
        approve_component(self, node, true, true).await;
        let op=self.store.deploy_app(&self.operator,&self.tenant,&self.project,fenders_control_plane::apps::AppSubmission{value:json!({"name":"demand","artifact_id":self.artifact,"configuration":{"keep_warm":false},"triggers":{"http":true,"manual":true}}),key:"demand",domain:"apps.test"}).await.unwrap();
        let app = s(&op["resource_id"]).to_owned();
        self.http_running(&app, node).await;
        app
    }
    async fn idle_clock(&self, app: &str) {
        // What the gateway knows of the app's requests is written first, as
        // its flusher would have by now; then its last activity is made old.
        self.store.flush_gateway().await.unwrap();
        sqlx::query(
            "UPDATE app_http SET last_activity=now()-interval '61 seconds' WHERE app_id=$1",
        )
        .bind(app)
        .execute(&self.store.pool)
        .await
        .unwrap();
    }
    async fn idle_http(&self, app: &str, node: &Value) -> Value {
        self.idle_clock(app).await;
        self.store.schedule().await.unwrap();
        let e = self
            .execution(s(&self.http(app).await["execution_id"]))
            .await;
        // It holds no request, so it is stopped with no acknowledgment asked.
        assert_eq!(e["desired"], "stopped");
        assert_eq!(e["reserved"], true);
        self.report(node, &e, "stopped", 3).await;
        assert_eq!(self.http(app).await["state"], "idle");
        assert!(self.http(app).await["execution_id"].is_null());
        self.execution(s(&e["id"])).await
    }
}

#[tokio::test]
async fn on_demand_idle_ack_and_concurrent_wake_keep_one_generation_and_reservation() {
    let l = Lab::new().await;
    let node = l.node("worker").await;
    let app = l.demand_app(&node).await;
    let host = format!("app-{app}.apps.test");
    let original = l.http(&app).await;
    let (_, inflight) = l.store.ingress_start(&host, 2).await.unwrap();
    l.idle_clock(&app).await;
    l.store.schedule().await.unwrap();
    assert_eq!(l.http(&app).await["state"], "serving");
    l.store.ingress_finish(&inflight, Some(2)).await.unwrap();
    l.store.schedule().await.unwrap();
    assert_eq!(l.http(&app).await["state"], "serving");
    let stopped = l.idle_http(&app, &node).await;
    assert_eq!(stopped["reserved"], false);
    let revision = l
        .store
        .app(&l.operator, &l.tenant, &l.project, &app)
        .await
        .unwrap()["revision"]
        .clone();
    let observed = l
        .store
        .app_lifecycle(
            &l.operator,
            &l.tenant,
            &l.project,
            &app,
            json!({"desired":"enabled","expected_revision":revision}),
            "observe-idle",
        )
        .await
        .unwrap();
    assert_eq!(observed["state"], "succeeded");
    assert_eq!(l.http(&app).await["state"], "idle");
    assert_eq!(
        l.store.usage(&l.operator, &l.tenant, None).await.unwrap()["reserved"]["instances"],
        0
    );
    let (first, second) = tokio::join!(
        l.store.ingress_begin(&host, 1, true),
        l.store.ingress_begin(&host, 2, true)
    );
    let (route, a) = first.unwrap();
    let (route2, b) = second.unwrap();
    assert!(route.is_none() && route2.is_none());
    assert!(l.store.ingress_poll(&a).await.unwrap().is_none());
    let restarted = Store::from_pool(l.store.pool.clone(), l.root.path()).unwrap();
    let (x, y) = tokio::join!(l.store.schedule(), restarted.schedule());
    x.unwrap();
    y.unwrap();
    let e = l.execution(s(&l.http(&app).await["execution_id"])).await;
    assert_ne!(e["id"], original["execution_id"]);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM executions WHERE reserved")
            .fetch_one(&l.store.pool)
            .await
            .unwrap(),
        1
    );
    l.report(&node, &e, "running", 1).await;
    let ar = l.store.ingress_poll(&a).await.unwrap().unwrap();
    let br = restarted.ingress_poll(&b).await.unwrap().unwrap();
    assert_eq!(ar["execution_id"], e["id"]);
    assert_eq!(ar["execution_id"], br["execution_id"]);
    assert_eq!(l.http(&app).await["url"], original["url"]);
    assert_eq!(
        l.store.ingress_poll(&a).await.unwrap_err().status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    l.store.ingress_finish(&a, Some(1)).await.unwrap();
    l.store.ingress_finish(&b, Some(2)).await.unwrap();
    l.finish().await;
}

#[tokio::test]
async fn idle_busy_guest_and_partition_never_force_teardown_or_duplicate_wake() {
    let l = Lab::new().await;
    let node = l.node("worker").await;
    let app = l.demand_app(&node).await;
    let host = format!("app-{app}.apps.test");
    // A request it was given and has not answered keeps it from being
    // stopped as idle, however long ago the app's last activity was, and
    // whether or not its node can be heard.
    let (_, held) = l.store.ingress_start(&host, 0).await.unwrap();
    l.idle_clock(&app).await;
    l.store.schedule().await.unwrap();
    let busy = l.execution(s(&l.http(&app).await["execution_id"])).await;
    assert_eq!(busy["desired"], "running");
    sqlx::query("UPDATE nodes SET last_seen=now()-interval '1 minute'")
        .execute(&l.store.pool)
        .await
        .unwrap();
    l.store.schedule().await.unwrap();
    let busy = l.execution(s(&busy["id"])).await;
    assert_eq!(busy["desired"], "running");
    assert_eq!(busy["reserved"], true);
    l.report(&node, &busy, "running", 2).await;

    // Its request ended: now it is idle, and is stopped without being asked
    // to acknowledge anything.
    l.store.ingress_finish(&held, Some(0)).await.unwrap();
    l.idle_clock(&app).await;
    l.store.schedule().await.unwrap();
    let stop = l.execution(s(&busy["id"])).await;
    assert_eq!(stop["desired"], "stopped");
    assert_eq!(stop["reserved"], true);
    assert!(
        sqlx::query_scalar::<_, bool>("SELECT drain_until IS NULL FROM app_http WHERE app_id=$1")
            .bind(&app)
            .fetch_one(&l.store.pool)
            .await
            .unwrap()
    );

    // A request that arrives while it stops waits; it starts nothing until
    // the old execution is known to have stopped.
    let (_, q) = l.store.ingress_begin(&host, 0, true).await.unwrap();
    let revision = l
        .store
        .app(&l.operator, &l.tenant, &l.project, &app)
        .await
        .unwrap()["revision"]
        .clone();
    let observed = l
        .store
        .app_lifecycle(
            &l.operator,
            &l.tenant,
            &l.project,
            &app,
            json!({"desired":"enabled","expected_revision":revision}),
            "observe-draining",
        )
        .await
        .unwrap();
    assert_eq!(observed["state"], "pending");
    sqlx::query("UPDATE nodes SET last_seen=now()-interval '1 minute'")
        .execute(&l.store.pool)
        .await
        .unwrap();
    l.store.schedule().await.unwrap();
    assert!(l.store.ingress_poll(&q).await.unwrap().is_none());
    assert_eq!(l.execution(s(&stop["id"])).await["reserved"], true);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM executions")
            .fetch_one(&l.store.pool)
            .await
            .unwrap(),
        1
    );
    // An observation of an earlier generation cannot end it.
    l.report(&node, &busy, "stopped", 3).await;
    assert_eq!(l.execution(s(&stop["id"])).await["reserved"], true);
    l.report(&node, &stop, "stopped", 4).await;
    assert_eq!(l.operation(&observed).await["state"], "succeeded");
    l.store.schedule().await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM executions WHERE reserved")
            .fetch_one(&l.store.pool)
            .await
            .unwrap(),
        1
    );
    l.store.ingress_finish(&q, Some(0)).await.unwrap();
    l.finish().await;
}

#[tokio::test]
async fn wake_queue_is_bounded_expires_and_cannot_cross_stop_or_release() {
    let l = Lab::new().await;
    let node = l.node("worker").await;
    let app = l.demand_app(&node).await;
    l.idle_http(&app, &node).await;
    sqlx::query("UPDATE tenants SET transfer_bytes=100000000 WHERE id=$1")
        .bind(&l.tenant)
        .execute(&l.store.pool)
        .await
        .unwrap();
    let host = format!("app-{app}.apps.test");
    let mut leases = Vec::new();
    for _ in 0..16 {
        leases.push(l.store.ingress_begin(&host, 0, true).await.unwrap().1);
    }
    assert_eq!(
        l.store
            .ingress_begin(&host, 0, true)
            .await
            .unwrap_err()
            .status,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        l.store
            .ingress_begin("app-no.apps.test", 0, true)
            .await
            .unwrap_err()
            .status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    sqlx::query("UPDATE ingress_reservations SET expires=now()-interval '1 second' WHERE id=$1")
        .bind(&leases[0])
        .execute(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(
        l.store.ingress_poll(&leases[0]).await.unwrap_err().status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    l.store.ingress_finish(&leases[0], None).await.unwrap();
    assert_eq!(
        l.store.usage(&l.operator, &l.tenant, None).await.unwrap()["ingress_month"]["bytes"],
        0
    );
    let version = l
        .store
        .app_versions(&l.operator, &l.tenant, &l.project, &app, None)
        .await
        .unwrap()["items"][0]["id"]
        .clone();
    let revision = l
        .store
        .app(&l.operator, &l.tenant, &l.project, &app)
        .await
        .unwrap()["revision"]
        .clone();
    l.store
        .activate_app_release(
            &l.operator,
            &l.tenant,
            &l.project,
            &app,
            json!({"version_id":version,"expected_revision":revision}),
            "replace",
        )
        .await
        .unwrap();
    assert_eq!(
        l.store.ingress_poll(&leases[1]).await.unwrap_err().status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    for q in &leases[1..] {
        l.store.ingress_finish(q, Some(0)).await.unwrap();
    }
    let revision = l
        .store
        .app(&l.operator, &l.tenant, &l.project, &app)
        .await
        .unwrap()["revision"]
        .clone();
    l.store
        .app_lifecycle(
            &l.operator,
            &l.tenant,
            &l.project,
            &app,
            json!({"desired":"stopped","expected_revision":revision}),
            "stop",
        )
        .await
        .unwrap();
    assert_eq!(
        l.store
            .ingress_begin(&host, 0, true)
            .await
            .unwrap_err()
            .status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    l.finish().await;
}

#[tokio::test]
async fn on_demand_queue_recovery_and_capacity_failures_preserve_boundaries() {
    let l = Lab::new().await;
    let node = l.node("worker").await;
    let app = l.demand_app(&node).await;
    l.idle_http(&app, &node).await;
    let host = format!("app-{app}.apps.test");
    sqlx::query("UPDATE tenants SET instances=1 WHERE id=$1")
        .bind(&l.tenant)
        .execute(&l.store.pool)
        .await
        .unwrap();
    l.store
        .run_app(&l.operator, &l.tenant, &l.project, &app, "occupy")
        .await
        .unwrap();
    let (_, q) = l.store.ingress_begin(&host, 0, true).await.unwrap();
    l.store.schedule().await.unwrap();
    assert_eq!(l.http(&app).await["reason"], "allowance-exhausted");
    assert!(l.http(&app).await["execution_id"].is_null());
    sqlx::query("UPDATE app_http SET ready_until=now()-interval '1 second' WHERE app_id=$1")
        .bind(&app)
        .execute(&l.store.pool)
        .await
        .unwrap();
    l.store.schedule().await.unwrap();
    // The wake gave up and the app is idle, not blocked; the request is
    // refused once its own deadline passes.
    assert_eq!(l.http(&app).await["state"], "idle");
    assert!(l.http(&app).await["reason"].is_null());
    sqlx::query("UPDATE ingress_reservations SET expires=now()-interval '1 second' WHERE id=$1")
        .bind(&q)
        .execute(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(
        l.store.ingress_poll(&q).await.unwrap_err().status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        l.store.usage(&l.operator, &l.tenant, None).await.unwrap()["reserved"]["instances"],
        1
    );
    sqlx::query("UPDATE recovery_barrier SET active=true")
        .execute(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(
        l.store.ingress_poll(&q).await.unwrap_err().status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        l.store
            .ingress_begin(&host, 0, true)
            .await
            .unwrap_err()
            .status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    l.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn requests_to_an_idle_app_wake_it_once_and_wait_without_the_lock() {
    let l = Lab::new().await;
    let node = l.node("worker").await;
    let app = l.demand_app(&node).await;
    l.idle_http(&app, &node).await;
    let host = format!("app-{app}.apps.test");
    l.store
        .update_http_limits(
            &l.operator,
            &l.tenant,
            json!({"concurrent_requests":100,"requests_per_minute":1000}),
        )
        .await
        .unwrap();
    let locked = || {
        l.store.load.snapshot()["database"]["locked_transactions"]
            .as_u64()
            .unwrap()
    };
    let before = locked();
    let waiting: Vec<_> = (0..20)
        .map(|_| {
            let (store, host) = (l.store.clone(), host.clone());
            tokio::spawn(async move { store.ingress_wait_request(&host, 0, None).await })
        })
        .collect();
    tokio::time::sleep(std::time::Duration::from_millis(600)).await;
    // One of them woke the app; the others follow it, with no reservation
    // of their own; and none asks again under the lock while it waits.
    let reservations: i64 = sqlx::query_scalar("SELECT count(*) FROM ingress_reservations")
        .fetch_one(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(reservations, 1);
    assert!(
        locked() - before <= 2,
        "{} locked transactions while waiting",
        locked() - before
    );
    l.store.schedule().await.unwrap();
    let e = l.execution(s(&l.http(&app).await["execution_id"])).await;
    l.report(&node, &e, "running", 1).await;
    l.store.schedule().await.unwrap();
    assert_eq!(l.http(&app).await["state"], "serving");
    for waited in waiting {
        let (route, lease) = waited.await.unwrap().unwrap();
        assert_eq!(route["execution_id"], e["id"]);
        l.store.ingress_finish(&lease, Some(0)).await.unwrap();
    }
    l.finish().await;
}
