//! A control process and an edge on one database: the edge serves the
//! gateway and the run channel, the control process decides from what the
//! edge says its exchange sees.
use super::*;
use fenders_control_plane::run_channel::{self, RunChannel};
use fenders_control_plane::store::Serves;

#[tokio::test]
async fn the_control_process_decides_from_what_the_edge_writes_of_its_exchange() {
    use fenders_control_plane::http_exchange::{frame, unframe};
    let channel = || RunChannel::new("https://edge.test:9093", "fixture ca".into(), None).unwrap();
    let mut l = Lab::new().await;
    l.store = l
        .store
        .clone()
        .with_run_channel(channel())
        .serving(Serves::Control);
    let edge = Store::from_pool(l.store.pool.clone(), l.root.path())
        .unwrap()
        .with_run_channel(channel())
        .serving(Serves::Edge);
    let node = l.node("worker").await;
    approve_component(&l, &node, true, true).await;
    let (app, version) = define_app(&l, "split").await;
    l.http_trigger(&app, true, true, "enable-http").await;
    l.release(&app, &version, "first").await;
    l.store.schedule().await.unwrap();
    let e = l.execution(s(&l.http(&app).await["execution_id"])).await;
    let (id, generation) = (s(&e["id"]).to_owned(), n(&e["generation"]));
    l.report(&node, &e, "running", 1).await;
    l.store.schedule().await.unwrap();
    assert_eq!(l.http(&app).await["state"], "starting");

    // The shim asks the edge for requests. The control process learns it
    // once the edge has flushed, and the app serves.
    let bearer = s(&l
        .store
        .assignment(s(&node["id"]), &id, generation)
        .await
        .unwrap()["spec"]["channel"]["credential"])
    .to_owned();
    let router = run_channel::router(edge.clone());
    let post = |path: String, body: axum::body::Bytes| {
        let (router, bearer) = (router.clone(), bearer.clone());
        async move {
            let response = router
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
                axum::body::to_bytes(response.into_body(), 1 << 20)
                    .await
                    .unwrap(),
            )
        }
    };
    let next = tokio::spawn(post(
        format!("/run/{id}/{generation}/v1/run/http/next"),
        Default::default(),
    ));
    while !edge.exchange.ready(&id) {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    // The control process's own exchange saw nothing.
    assert!(!l.store.exchange.ready(&id));
    l.store.schedule().await.unwrap();
    assert_eq!(l.http(&app).await["state"], "starting", "not flushed yet");
    edge.flush_gateway().await.unwrap();
    l.store.schedule().await.unwrap();
    assert_eq!(l.http(&app).await["state"], "serving");

    // A request through the edge reaches the shim that asked the edge.
    let host = format!("app-{app}.apps.test");
    let (_, lease) = edge.ingress_start(&host, 0).await.unwrap();
    let offered = {
        let edge = edge.clone();
        let lease = lease.clone();
        tokio::spawn(async move {
            edge.exchange
                .offer(
                    &app,
                    &lease,
                    fenders_control_plane::http_exchange::Message {
                        head: json!({"id":lease,"method":"GET","path":"/","headers":{}}),
                        body: Default::default(),
                    },
                    std::time::Duration::from_secs(5),
                    std::time::Duration::from_secs(5),
                )
                .await
        })
    };
    let (status, taken) = next.await.unwrap();
    assert_eq!(status, StatusCode::OK);
    let (head, _) = unframe(&taken).unwrap();
    assert_eq!(head["id"], lease);
    // While it has the request, the control process counts the execution
    // busy, from what the edge wrote.
    edge.flush_gateway().await.unwrap();
    let busy: bool =
        sqlx::query_scalar("SELECT busy FROM gateway_observations WHERE key=$1 AND kind='taker'")
            .bind(&id)
            .fetch_one(&l.store.pool)
            .await
            .unwrap();
    assert!(busy);
    let (status, _) = post(
        format!("/run/{id}/{generation}/v1/run/http/response/{lease}"),
        frame(&json!({"status":204,"headers":{}}), b""),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(matches!(
        offered.await.unwrap(),
        fenders_control_plane::http_exchange::Offer::Answered(_)
    ));
    edge.ingress_complete(&lease, Some(0), Some(204))
        .await
        .unwrap();
    // An edge that stops leaves nothing for the control process to read.
    edge.close_gateway().await.unwrap();
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM gateway_observations")
        .fetch_one(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(left, 0);
    l.finish().await;
}

/// The operator lowers a workspace's allowance below what an edge leases
/// of it: the control process recalls the lease, the edge gives back what
/// is unreserved at its next flush, and the lowering is made.
#[tokio::test]
async fn an_allowance_is_lowered_below_an_edges_lease_once_the_edge_gives_it_back() {
    use fenders_control_plane::lease::{BLOCK, LEAST};
    let l = Lab::new().await;
    let edge = Store::from_pool(l.store.pool.clone(), l.root.path())
        .unwrap()
        .serving(Serves::Edge);
    let node = l.node("lease-worker").await;
    let route = l.web_app("web", "apps.test").await;
    l.store.schedule().await.unwrap();
    let all = l
        .store
        .resources(&l.operator, &l.tenant, &l.project, "executions", None)
        .await
        .unwrap();
    l.report(&node, &all[0], "running", 1).await;
    let host = s(&route["hostname"]);
    // The edge takes a lease with its first request, and keeps a request
    // in flight.
    let (_, flying) = edge.ingress_start(host, 0).await.unwrap();
    edge.flush_gateway().await.unwrap();
    let leased = || async {
        sqlx::query_scalar::<_, i64>(
            "SELECT COALESCE(sum(held_bytes),0)::bigint FROM gateway_transfer_leases",
        )
        .fetch_one(&l.store.pool)
        .await
        .unwrap()
    };
    assert_eq!(leased().await, LEAST);
    // The edge flushes as it does, every 100 ms here.
    let flushing = {
        let edge = edge.clone();
        tokio::spawn(async move {
            loop {
                edge.flush_gateway().await.unwrap();
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        })
    };
    l.store
        .update_allowance(
            &l.operator,
            &l.tenant,
            serde_json::from_value(json!({"allowance":{"cpu_percent":400,"memory_mib":4096,"instances":4,"storage_bytes":20000000000_i64,"transfer_bytes":BLOCK + 100}})).unwrap(),
        )
        .await
        .unwrap();
    flushing.abort();
    // What the request in flight reserved is still held; nothing else.
    assert_eq!(leased().await, BLOCK);
    edge.ingress_finish(&flying, Some(10)).await.unwrap();
    l.finish().await;
}

/// What one process changes of what decides whether an app serves, another
/// hears: its gateway reads what it knows again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_edge_hears_what_another_process_changes() {
    let l = Lab::new().await;
    let edge = Store::from_pool(l.store.pool.clone(), l.root.path())
        .unwrap()
        .serving(Serves::Edge);
    let listening = {
        let edge = edge.clone();
        tokio::spawn(async move { edge.listen_for_gates().await })
    };
    let epoch = || edge.gateway.gates.epoch();
    // Listening: it has heard nothing yet, and reads everything again.
    let mut before = epoch();
    for _ in 0..100 {
        if epoch() > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    before = before.max(epoch());
    // Another process changes a workspace's limits.
    l.store
        .update_http_limits(
            &l.operator,
            &l.tenant,
            json!({"concurrent_requests":3,"requests_per_minute":30}),
        )
        .await
        .unwrap();
    for _ in 0..100 {
        if epoch() > before {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(epoch() > before, "heard");
    listening.abort();
    l.finish().await;
}

/// A WebSocket connection's row is swept by the session that holds it, or
/// when that session is gone: not by another edge, which does not hold it.
#[tokio::test]
async fn an_edge_sweeps_only_its_own_and_dead_sessions_websocket_rows() {
    let l = Lab::new().await;
    let node = l.node("ws-worker").await;
    approve_component(&l, &node, true, true).await;
    let (app, version) = define_app(&l, "sockets").await;
    l.http_trigger(&app, true, true, "enable-http").await;
    l.release(&app, &version, "first").await;
    let edge = Store::from_pool(l.store.pool.clone(), l.root.path())
        .unwrap()
        .serving(Serves::Edge);
    edge.flush_gateway().await.unwrap();
    let (live, dead) = (uid(), uid());
    sqlx::query("INSERT INTO gateway_sessions(id) VALUES($1)")
        .bind(&live)
        .execute(&l.store.pool)
        .await
        .unwrap();
    let row = |id: String, session: Option<String>| {
        let (pool, app) = (l.store.pool.clone(), app.clone());
        async move {
            sqlx::query("INSERT INTO app_http_runs(id,tenant_id,project_id,app_id,release_id,method,path,state,started_at,websocket,session_id,created) SELECT $1,a.tenant_id,a.project_id,a.id,COALESCE(a.active_release_id,a.target_release_id),'GET','/','running',clock_timestamp(),'{}'::jsonb,$3,now()-interval '2 minutes' FROM apps a WHERE a.id=$2")
                .bind(id)
                .bind(app)
                .bind(session)
                .execute(&pool)
                .await
                .unwrap();
        }
    };
    let (mine, others, gone) = (uid(), uid(), uid());
    row(mine.clone(), Some(edge.gateway.session().to_owned())).await;
    row(others.clone(), Some(live)).await;
    row(gone.clone(), Some(dead)).await;
    edge.websocket_sweep().await.unwrap();
    let finished = |id: String| {
        let pool = l.store.pool.clone();
        async move {
            sqlx::query_scalar::<_, bool>(
                "SELECT finished_at IS NOT NULL FROM app_http_runs WHERE id=$1",
            )
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap()
        }
    };
    assert!(finished(mine).await, "its own, which it does not hold");
    assert!(!finished(others).await, "another live edge's");
    assert!(finished(gone).await, "a session that is gone");
    l.finish().await;
}

/// Two edges serve one workspace: each admits against its share of the
/// workspace's limits, the shares follow what each uses, and together they
/// never admit more than the limit.
#[tokio::test]
async fn two_edges_hold_a_workspaces_limits_between_them() {
    let l = Lab::new().await;
    let edge = || {
        Store::from_pool(l.store.pool.clone(), l.root.path())
            .unwrap()
            .serving(Serves::Edge)
    };
    let (a, b) = (edge(), edge());
    let node = l.node("share-worker").await;
    let route = l.web_app("web", "apps.test").await;
    l.store.schedule().await.unwrap();
    let all = l
        .store
        .resources(&l.operator, &l.tenant, &l.project, "executions", None)
        .await
        .unwrap();
    l.report(&node, &all[0], "running", 1).await;
    l.store
        .update_http_limits(
            &l.operator,
            &l.tenant,
            json!({"concurrent_requests":4,"requests_per_minute":1000}),
        )
        .await
        .unwrap();
    let host = s(&route["hostname"]);
    let share = |edge: &Store| edge.gateway.shares.of(&l.tenant).map(|s| s.concurrent);
    // Alone, the first edge takes the whole limit.
    let mut held_a = Vec::new();
    for _ in 0..2 {
        held_a.push(a.ingress_start(host, 0).await.unwrap().1);
    }
    assert_eq!(share(&a), Some(4));
    // The second finds nothing left, and is refused.
    assert_eq!(
        b.ingress_start(host, 0).await.unwrap_err().status,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(share(&b), Some(0));
    // At their flushes they share what is not used: the first keeps its two
    // and half of the two left, the second the other.
    a.flush_gateway().await.unwrap();
    assert_eq!(share(&a), Some(3));
    b.flush_gateway().await.unwrap();
    assert_eq!(share(&b), Some(1));
    let held_b = b.ingress_start(host, 0).await.unwrap().1;
    assert_eq!(
        b.ingress_start(host, 0).await.unwrap_err().status,
        StatusCode::TOO_MANY_REQUESTS
    );
    held_a.push(a.ingress_start(host, 0).await.unwrap().1);
    assert_eq!(
        a.ingress_start(host, 0).await.unwrap_err().status,
        StatusCode::TOO_MANY_REQUESTS
    );
    // Four in flight between them, and no more.
    let shares: i64 = sqlx::query_scalar(
        "SELECT sum(concurrent)::bigint FROM edge_limit_shares WHERE tenant_id=$1",
    )
    .bind(&l.tenant)
    .fetch_one(&l.store.pool)
    .await
    .unwrap();
    assert!(shares <= 4);
    // One edge goes away: its share is freed, and the other takes it.
    for request in held_a {
        a.ingress_finish(&request, Some(0)).await.unwrap();
    }
    a.close_gateway().await.unwrap();
    b.flush_gateway().await.unwrap();
    assert_eq!(share(&b), Some(4));
    b.ingress_finish(&held_b, Some(0)).await.unwrap();
    l.finish().await;
}

/// Registered edges own apps: the scheduler gives each app to the live edge
/// with the fewest, an edge serves only its own, and the apps of one that
/// drains go to another.
#[tokio::test]
async fn the_scheduler_gives_apps_to_live_edges_and_each_serves_its_own() {
    let l = Lab::new().await;
    let register = |name: &'static str, pin: char| {
        let (store, operator) = (l.store.clone(), l.operator.clone());
        async move {
            store
                .register_edge_keyed(
                    &operator,
                    json!({"name":name,"cert_sha256":pin.to_string().repeat(64),"endpoint":format!("https://{name}.internal:9444")}),
                    None,
                )
                .await
                .unwrap()
        }
    };
    let (first, second) = (register("edge-a", 'a').await, register("edge-b", 'b').await);
    let edge = |row: &Value| {
        Store::from_pool(l.store.pool.clone(), l.root.path())
            .unwrap()
            .serving(Serves::Edge)
            .as_edge(s(&row["id"]).to_owned())
    };
    let (a, b) = (edge(&first), edge(&second));
    // Neither is live until it has flushed: no app is placed.
    let node = l.node("owned-worker").await;
    let route = l.web_app("web", "apps.test").await;
    l.store.schedule().await.unwrap();
    let owner = || async {
        sqlx::query_scalar::<_, Option<String>>(
            "SELECT (SELECT edge_id FROM app_edges WHERE app_id=$1)",
        )
        .bind(s(&route["app_id"]))
        .fetch_one(&l.store.pool)
        .await
        .unwrap()
    };
    assert_eq!(owner().await, None);
    a.flush_gateway().await.unwrap();
    b.flush_gateway().await.unwrap();
    l.store.schedule().await.unwrap();
    let all = l
        .store
        .resources(&l.operator, &l.tenant, &l.project, "executions", None)
        .await
        .unwrap();
    l.report(&node, &all[0], "running", 1).await;
    let owned_by = owner().await.unwrap();
    let (mine, other) = if owned_by == s(&first["id"]) {
        (&a, &b)
    } else {
        (&b, &a)
    };
    let host = s(&route["hostname"]);
    let request = mine.ingress_start(host, 0).await.unwrap().1;
    mine.ingress_finish(&request, Some(0)).await.unwrap();
    assert_eq!(
        other.ingress_start(host, 0).await.unwrap_err().status,
        StatusCode::MISDIRECTED_REQUEST
    );
    // The map a balancer may route by.
    let routes = l
        .store
        .edge_routes(&l.operator, Default::default())
        .await
        .unwrap();
    assert_eq!(routes["items"][0]["hostname"], route["hostname"]);
    assert_eq!(routes["items"][0]["edge_id"], owned_by.as_str());
    // The owner drains: the app goes to the other edge.
    l.store
        .edge_mode_keyed(&l.operator, &owned_by, json!({"draining":true}), None)
        .await
        .unwrap();
    l.store.schedule().await.unwrap();
    let moved = owner().await.unwrap();
    assert_ne!(moved, owned_by);
    // Each edge hears of the move, as its listener would; the shares of
    // the workspace's limits follow at their flushes.
    a.gateway.gates.changed();
    b.gateway.gates.changed();
    assert_eq!(
        other.ingress_start(host, 0).await.unwrap_err().status,
        StatusCode::TOO_MANY_REQUESTS,
        "the other edge holds the workspace's limit until it flushes"
    );
    mine.flush_gateway().await.unwrap();
    other.flush_gateway().await.unwrap();
    let request = other.ingress_start(host, 0).await.unwrap().1;
    other.ingress_finish(&request, Some(0)).await.unwrap();
    assert_eq!(
        mine.ingress_start(host, 0).await.unwrap_err().status,
        StatusCode::MISDIRECTED_REQUEST
    );
    // Drained and owning nothing, it may be deleted.
    l.store
        .delete_edge(&l.operator, &owned_by, "delete-edge")
        .await
        .unwrap();
    l.finish().await;
}
