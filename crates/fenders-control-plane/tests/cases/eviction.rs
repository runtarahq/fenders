//! Idle executions give way to work of the same workspace waiting for room:
//! in the workspace's compute allowance, or on a node.
use super::*;
use fenders_control_plane::apps::AppSubmission;

impl Lab {
    /// An app that serves, kept warm as apps are unless they say not to.
    async fn warm_app(&self, name: &str) -> String {
        let op = self.deploy(name, true, false, name).await.unwrap();
        let app = s(&op["resource_id"]).to_owned();
        self.store.schedule().await.unwrap();
        self.running(&app).await;
        assert_eq!(self.http(&app).await["state"], "serving");
        app
    }
    /// The app's execution says it runs, on whichever node it was placed.
    async fn running(&self, app: &str) -> Value {
        let e = self
            .execution(s(&self.http(app).await["execution_id"]))
            .await;
        assert!(!e["node_id"].is_null(), "not placed: {e}");
        self.report(&json!({"id":e["node_id"]}), &e, "running", 1)
            .await;
        self.store.schedule().await.unwrap();
        e
    }
    /// It has handled no request for longer than an execution must be idle
    /// to give way: what the gateway knows is written, then made older.
    async fn quiet(&self, app: &str) {
        self.store.flush_gateway().await.unwrap();
        sqlx::query("UPDATE app_http SET last_activity=now()-interval '6 seconds' WHERE app_id=$1")
            .bind(app)
            .execute(&self.store.pool)
            .await
            .unwrap();
    }
    /// It handled a request just now and is not idle for the coming minute,
    /// however long the steps after take: the counterpart of [`quiet`].
    async fn busy(&self, app: &str) {
        self.store.flush_gateway().await.unwrap();
        sqlx::query("UPDATE app_http SET last_activity=now()+interval '1 minute' WHERE app_id=$1")
            .bind(app)
            .execute(&self.store.pool)
            .await
            .unwrap();
    }
    async fn instances(&self, tenant: &str, instances: i64) {
        sqlx::query("UPDATE tenants SET instances=$1 WHERE id=$2")
            .bind(instances)
            .bind(tenant)
            .execute(&self.store.pool)
            .await
            .unwrap();
    }
    async fn evictions(&self) -> Vec<Value> {
        sqlx::query_scalar("SELECT jsonb_build_object('app',resource_id,'tenant',tenant_id,'detail',detail) FROM audit WHERE action='app.evict' ORDER BY sequence")
            .fetch_all(&self.store.pool)
            .await
            .unwrap()
    }
}

#[tokio::test]
async fn an_idle_app_gives_way_to_one_of_its_workspace_the_allowance_has_no_room_for() {
    let l = Lab::new().await;
    let node = l.node("a").await;
    l.node("b").await;
    approve_component(&l, &node, true, true).await;
    l.instances(&l.tenant, 1).await;
    let warm = l.warm_app("warm").await;
    let held = l.http(&warm).await["execution_id"].clone();

    // It took a request a moment ago: it is not idle long enough to give
    // way, and the new app waits for the allowance as it did.
    l.busy(&warm).await;
    let new = s(&l.deploy("new", true, false, "new").await.unwrap()["resource_id"]).to_owned();
    l.store.schedule().await.unwrap();
    assert_eq!(l.http(&new).await["reason"], "allowance-exhausted");
    assert_eq!(l.http(&warm).await["state"], "serving");

    // Five seconds without one: it is stopped as an idle app is, and the
    // new app waits for it.
    l.quiet(&warm).await;
    l.store.schedule().await.unwrap();
    assert_eq!(l.http(&warm).await["state"], "stopping");
    assert_eq!(l.http(&warm).await["reason"], "evicted");
    let stopping = l.execution(s(&held)).await;
    assert_eq!(stopping["desired"], "stopped");
    assert_eq!(l.http(&new).await["reason"], "making-room");
    assert!(l.http(&new).await["execution_id"].is_null());
    let evictions = l.evictions().await;
    assert_eq!(evictions.len(), 1);
    assert_eq!(evictions[0]["app"], warm);
    assert_eq!(evictions[0]["detail"]["for"]["app_id"], new);

    // Once it has stopped, the new app starts in its room; the old one is
    // idle and wakes on its next request.
    l.report(&json!({"id":stopping["node_id"]}), &stopping, "stopped", 2)
        .await;
    l.store.schedule().await.unwrap();
    assert_eq!(l.http(&warm).await["state"], "idle");
    l.running(&new).await;
    assert_eq!(l.http(&new).await["state"], "serving");
    assert_eq!(l.evictions().await.len(), 1, "no more than was short");
    l.finish().await;
}

#[tokio::test]
async fn an_app_with_a_request_in_flight_does_not_give_way() {
    let l = Lab::new().await;
    let node = l.node("a").await;
    l.node("b").await;
    approve_component(&l, &node, true, true).await;
    l.instances(&l.tenant, 1).await;
    let warm = l.warm_app("warm").await;
    let host = format!("app-{warm}.apps.test");
    let (_, inflight) = l.store.ingress_start(&host, 2).await.unwrap();
    l.quiet(&warm).await;
    let new = s(&l.deploy("new", true, false, "new").await.unwrap()["resource_id"]).to_owned();
    l.store.schedule().await.unwrap();
    assert_eq!(l.http(&warm).await["state"], "serving");
    assert_eq!(l.http(&new).await["reason"], "allowance-exhausted");
    assert!(l.evictions().await.is_empty());

    // Its request ends, and five seconds pass: now it gives way.
    l.store.ingress_finish(&inflight, Some(2)).await.unwrap();
    l.quiet(&warm).await;
    l.store.schedule().await.unwrap();
    assert_eq!(l.http(&warm).await["reason"], "evicted");
    assert_eq!(l.http(&new).await["reason"], "making-room");
    l.finish().await;
}

#[tokio::test]
async fn an_idle_app_gives_way_on_a_full_node_to_one_of_its_workspace_and_no_other() {
    let l = Lab::new().await;
    // The lab's nodes hold one execution each.
    let node = l.node("only").await;
    approve_component(&l, &node, true, true).await;
    let warm = l.warm_app("warm").await;
    let held = l.http(&warm).await["execution_id"].clone();

    // Another workspace's app waits for the node: this workspace's idle app
    // does not give way to it.
    let other = l.store.create_tenant(&l.operator,serde_json::from_value(json!({"name":"other","allowance":{"cpu_percent":400,"memory_mib":4096,"instances":4,"storage_bytes":1000000000i64,"transfer_bytes":1000000}})).unwrap()).await.unwrap();
    let other_project = l
        .store
        .create_project(
            &l.operator,
            s(&other["id"]),
            serde_json::from_value(json!({"name":"app"})).unwrap(),
        )
        .await
        .unwrap();
    let artifact = l
        .store
        .upload(
            &l.operator,
            s(&other["id"]),
            s(&other_project["id"]),
            b"\0asm\x0d\0\x01\0other",
        )
        .await
        .unwrap();
    approve_component(&l, &node, true, true).await;
    l.quiet(&warm).await;
    let theirs = s(&l.store.deploy_app(&l.operator,s(&other["id"]),s(&other_project["id"]),AppSubmission{value:json!({"name":"theirs","artifact_id":artifact["id"],"triggers":{"http":true,"manual":false}}),key:"theirs",domain:"apps.test"}).await.unwrap()["resource_id"]).to_owned();
    // The node is reachable however long the steps above took: what keeps
    // the app is the workspace, not a node gone quiet.
    l.heard(&node).await;
    l.store.schedule().await.unwrap();
    l.store.schedule().await.unwrap();
    assert_eq!(l.http(&warm).await["state"], "serving");
    assert!(l.evictions().await.is_empty());
    let placed: Option<Option<String>> = sqlx::query_scalar(
        "SELECT e.node_id FROM app_http h JOIN executions e ON e.id=h.execution_id WHERE h.app_id=$1",
    )
    .bind(&theirs)
    .fetch_optional(&l.store.pool)
    .await
    .unwrap();
    assert_eq!(
        placed,
        Some(None),
        "the other workspace's app waits for the node"
    );
    let revision = l
        .store
        .app(
            &l.operator,
            s(&other["id"]),
            s(&other_project["id"]),
            &theirs,
        )
        .await
        .unwrap()["revision"]
        .clone();
    l.store
        .app_lifecycle(
            &l.operator,
            s(&other["id"]),
            s(&other_project["id"]),
            &theirs,
            json!({"desired":"stopped","expected_revision":revision}),
            "disable-theirs",
        )
        .await
        .unwrap();
    l.store.schedule().await.unwrap();

    // One of its own waits for the node: the idle app gives way.
    let new = s(&l.deploy("new", true, false, "new").await.unwrap()["resource_id"]).to_owned();
    l.heard(&node).await;
    l.store.schedule().await.unwrap();
    l.store.schedule().await.unwrap();
    assert_eq!(l.http(&warm).await["reason"], "evicted");
    let evictions = l.evictions().await;
    assert_eq!(evictions.len(), 1);
    assert_eq!(evictions[0]["detail"]["for"]["node_id"], node["id"]);
    let stopping = l.execution(s(&held)).await;
    l.report(&node, &stopping, "stopped", 2).await;
    l.store.schedule().await.unwrap();
    let placed = l.running(&new).await;
    assert_eq!(placed["node_id"], node["id"]);
    assert_eq!(l.http(&new).await["state"], "serving");
    assert_eq!(l.http(&warm).await["state"], "idle");
    l.finish().await;
}

#[tokio::test]
async fn apps_waiting_together_are_each_made_room_for_and_not_twice_for_one() {
    let l = Lab::new().await;
    let node = l.node("a").await;
    for name in ["b", "c", "d"] {
        l.node(name).await;
    }
    approve_component(&l, &node, true, true).await;
    l.instances(&l.tenant, 2).await;
    let first = l.warm_app("first").await;
    let second = l.warm_app("second").await;
    // Two wait while both are busy.
    l.busy(&first).await;
    l.busy(&second).await;
    let a = s(&l.deploy("a", true, false, "a").await.unwrap()["resource_id"]).to_owned();
    let b = s(&l.deploy("b", true, false, "b").await.unwrap()["resource_id"]).to_owned();
    l.store.schedule().await.unwrap();
    assert_eq!(l.http(&a).await["reason"], "allowance-exhausted");
    assert_eq!(l.http(&b).await["reason"], "allowance-exhausted");
    // Both go quiet: one pass has each give way, one for each.
    l.quiet(&first).await;
    l.quiet(&second).await;
    l.store.schedule().await.unwrap();
    assert_eq!(l.http(&first).await["reason"], "evicted");
    assert_eq!(l.http(&second).await["reason"], "evicted");
    assert_eq!(l.http(&a).await["reason"], "making-room");
    assert_eq!(l.http(&b).await["reason"], "making-room");
    let mut fors: Vec<String> = l
        .evictions()
        .await
        .iter()
        .map(|e| s(&e["detail"]["for"]["app_id"]).to_owned())
        .collect();
    fors.sort();
    let mut waiting = vec![a.clone(), b.clone()];
    waiting.sort();
    assert_eq!(fors, waiting, "one for each");
    l.finish().await;
}
