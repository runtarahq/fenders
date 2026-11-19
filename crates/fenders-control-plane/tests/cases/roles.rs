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
