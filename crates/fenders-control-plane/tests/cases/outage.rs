//! An edge whose database goes away: it serves what it knows, refuses what
//! needs the database, and writes what it held when the database is back.
use super::*;
use fenders_control_plane::store::Serves;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

/// A TCP proxy to the test database that can be cut (connections end,
/// none is made), frozen (connections stay, nothing passes: a database
/// that hangs) and restored.
struct Proxy {
    port: u16,
    cut: Arc<AtomicBool>,
    frozen: Arc<AtomicBool>,
    links: Arc<std::sync::Mutex<tokio::task::JoinSet<()>>>,
}

/// Copies `from` to `to` while not frozen.
async fn pump(
    mut from: tokio::net::tcp::OwnedReadHalf,
    mut to: tokio::net::tcp::OwnedWriteHalf,
    frozen: Arc<AtomicBool>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buffer = vec![0u8; 16384];
    loop {
        if frozen.load(Ordering::SeqCst) {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            continue;
        }
        match tokio::time::timeout(std::time::Duration::from_millis(20), from.read(&mut buffer))
            .await
        {
            Err(_) => continue,
            Ok(Ok(0)) | Ok(Err(_)) => return,
            Ok(Ok(n)) => {
                // Read before a freeze, held until it ends.
                while frozen.load(Ordering::SeqCst) {
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
                if to.write_all(&buffer[..n]).await.is_err() {
                    return;
                }
            }
        }
    }
}

impl Proxy {
    async fn to(target: (String, u16)) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let cut = Arc::new(AtomicBool::new(false));
        let frozen = Arc::new(AtomicBool::new(false));
        let links = Arc::new(std::sync::Mutex::new(tokio::task::JoinSet::new()));
        let (accepting, held, freezing) = (cut.clone(), links.clone(), frozen.clone());
        tokio::spawn(async move {
            loop {
                let Ok((client, _)) = listener.accept().await else {
                    return;
                };
                if accepting.load(Ordering::SeqCst) {
                    drop(client);
                    continue;
                }
                let (target, frozen) = (target.clone(), freezing.clone());
                held.lock().unwrap().spawn(async move {
                    if let Ok(server) = tokio::net::TcpStream::connect(target).await {
                        let (client_read, client_write) = client.into_split();
                        let (server_read, server_write) = server.into_split();
                        tokio::join!(
                            pump(client_read, server_write, frozen.clone()),
                            pump(server_read, client_write, frozen)
                        );
                    }
                });
            }
        });
        Self {
            port,
            cut,
            frozen,
            links,
        }
    }
    /// Every connection through it ends, and no other is made.
    fn cut(&self) {
        self.cut.store(true, Ordering::SeqCst);
        self.links.lock().unwrap().abort_all();
    }
    /// Nothing passes, and nothing ends: a database that hangs.
    fn freeze(&self) {
        self.frozen.store(true, Ordering::SeqCst);
    }
    fn restore(&self) {
        self.cut.store(false, Ordering::SeqCst);
        self.frozen.store(false, Ordering::SeqCst);
    }
}

/// A store serving as an edge, on the lab's database through `proxy`.
async fn edge_through(l: &Lab, proxy: &Proxy, bound: std::time::Duration) -> Store {
    let url: url::Url = std::env::var("FENDERS_TEST_DATABASE_URL")
        .unwrap()
        .parse()
        .unwrap();
    let options: PgConnectOptions = url.as_str().parse().unwrap();
    let options = options
        .host("127.0.0.1")
        .port(proxy.port)
        .options([("search_path", l.schema.as_str())]);
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .acquire_timeout(std::time::Duration::from_secs(1))
        .connect_with(options)
        .await
        .unwrap();
    Store::from_pool(pool, l.root.path())
        .unwrap()
        .with_outage_bound(bound)
        .serving(Serves::Edge)
}

fn database() -> (String, u16) {
    let url: url::Url = std::env::var("FENDERS_TEST_DATABASE_URL")
        .unwrap()
        .parse()
        .unwrap();
    (
        url.host_str().unwrap().to_owned(),
        url.port().unwrap_or(5432),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_edge_serves_what_it_knows_while_the_database_is_away() {
    use fenders_control_plane::ingress::{Meter, Way};
    let l = Lab::new().await;
    let proxy = Proxy::to(database()).await;
    let edge = edge_through(&l, &proxy, std::time::Duration::from_secs(4)).await;
    let node = l.node("outage-worker").await;
    let route = l.web_app("web", "apps.test").await;
    l.store.schedule().await.unwrap();
    let all = l
        .store
        .resources(&l.operator, &l.tenant, &l.project, "executions", None)
        .await
        .unwrap();
    l.report(&node, &all[0], "running", 1).await;
    let host = s(&route["hostname"]).to_owned();
    // The edge knows the app, holds a lease, and has flushed.
    let (_, first) = edge.ingress_start(&host, 0).await.unwrap();
    edge.ingress_finish(&first, Some(100)).await.unwrap();
    edge.flush_gateway().await.unwrap();
    let ready = || async {
        fenders_control_plane::api::edge(edge.clone())
            .oneshot(
                Request::builder()
                    .uri("/readyz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
    };
    assert_eq!(ready().await, StatusCode::OK);

    // The database goes away, and what the edge knows is older than it
    // believes for long: the next request finds the database gone, and is
    // admitted on what the edge knew.
    proxy.cut();
    tokio::time::sleep(std::time::Duration::from_millis(2100)).await;
    let (_, during) = edge.ingress_start(&host, 0).await.unwrap();
    let meter = Meter::new(edge.clone(), &during);
    assert!(meter.admit(Way::Out, 500).await);
    edge.ingress_complete(&during, Some(500), Some(200))
        .await
        .unwrap();
    let status = edge.background_status(&l.operator).unwrap();
    assert_eq!(status["database"]["reachable"], false);
    assert_eq!(status["gateway"]["serving_from_memory"], true);
    // Nothing waits for the database: the next requests are answered at
    // once, and the flush fails, keeping what it was to write.
    let started = std::time::Instant::now();
    for _ in 0..5 {
        let (_, request) = edge.ingress_start(&host, 0).await.unwrap();
        edge.ingress_complete(&request, Some(10), Some(200))
            .await
            .unwrap();
    }
    assert!(started.elapsed() < std::time::Duration::from_millis(500));
    assert!(edge.flush_gateway().await.is_err());
    // What needs the database is refused: a host name it never knew.
    assert_eq!(
        edge.ingress_start("app-unknown.apps.test", 0)
            .await
            .unwrap_err()
            .status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(ready().await, StatusCode::OK, "an edge serving is ready");

    // The database is back: the flush writes what waited, once.
    proxy.restore();
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    edge.flush_gateway().await.unwrap();
    let counted: (i64, i64) = sqlx::query_as(
        "SELECT COALESCE(sum(bytes),0)::bigint,COALESCE(sum(requests),0)::bigint FROM traffic_usage",
    )
    .fetch_one(&l.store.pool)
    .await
    .unwrap();
    assert_eq!(counted, (100 + 500 + 5 * 10, 7));
    assert_eq!(
        edge.background_status(&l.operator).unwrap()["database"]["reachable"],
        true
    );

    // Past the bound, nothing is served from memory, and the edge is not
    // ready: what it knows may be wrong by now.
    proxy.cut();
    tokio::time::sleep(std::time::Duration::from_millis(2100)).await;
    assert!(edge.ingress_start(&host, 0).await.is_ok());
    tokio::time::sleep(std::time::Duration::from_millis(4100)).await;
    assert_eq!(
        edge.ingress_start(&host, 0).await.unwrap_err().status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(ready().await, StatusCode::SERVICE_UNAVAILABLE);
    proxy.restore();
    l.finish().await;
}

/// A scheduler that could not reach the database does not take sessions for
/// dead the moment it can again: no edge could touch its session either.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_scheduler_gives_sessions_time_after_it_could_not_reach_the_database() {
    let l = Lab::new().await;
    let proxy = Proxy::to(database()).await;
    let control = edge_through(&l, &proxy, std::time::Duration::from_secs(600))
        .await
        .serving(Serves::Control);
    control.schedule().await.unwrap();
    sqlx::query(
        "INSERT INTO gateway_sessions(id,seen) VALUES($1,clock_timestamp()-interval '1 minute')",
    )
    .bind(uid())
    .execute(&l.store.pool)
    .await
    .unwrap();
    proxy.cut();
    assert!(control.schedule().await.is_err());
    proxy.restore();
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    control.schedule().await.unwrap();
    let sessions = || async {
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM gateway_sessions")
            .fetch_one(&l.store.pool)
            .await
            .unwrap()
    };
    assert_eq!(sessions().await, 1, "not yet: the grace has begun");
    l.finish().await;
}

/// A database that hangs, rather than refusing, is taken for gone after a
/// moment: a request, a shim's call and the flush do not wait on it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_database_that_hangs_is_taken_for_gone_and_served_around() {
    let l = Lab::new().await;
    let proxy = Proxy::to(database()).await;
    let edge = edge_through(&l, &proxy, std::time::Duration::from_secs(600)).await;
    let node = l.node("hang-worker").await;
    let route = l.web_app("web", "apps.test").await;
    l.store.schedule().await.unwrap();
    let all = l
        .store
        .resources(&l.operator, &l.tenant, &l.project, "executions", None)
        .await
        .unwrap();
    l.report(&node, &all[0], "running", 1).await;
    let host = s(&route["hostname"]).to_owned();
    let (_, first) = edge.ingress_start(&host, 0).await.unwrap();
    edge.ingress_finish(&first, Some(1)).await.unwrap();
    edge.flush_gateway().await.unwrap();
    proxy.freeze();
    tokio::time::sleep(std::time::Duration::from_millis(2100)).await;
    // The read of what is known times out, and what is known is served.
    let started = std::time::Instant::now();
    let (_, during) = edge.ingress_start(&host, 0).await.unwrap();
    assert!(started.elapsed() < std::time::Duration::from_secs(4));
    edge.ingress_finish(&during, Some(1)).await.unwrap();
    // And from then on at once.
    let started = std::time::Instant::now();
    let (_, next) = edge.ingress_start(&host, 0).await.unwrap();
    edge.ingress_finish(&next, Some(1)).await.unwrap();
    assert!(started.elapsed() < std::time::Duration::from_millis(200));
    // The flush gives up rather than hang.
    let started = std::time::Instant::now();
    assert!(edge.flush_gateway().await.is_err());
    assert!(started.elapsed() < std::time::Duration::from_secs(7));
    proxy.restore();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    // What waited is written once the database answers again.
    for _ in 0..20 {
        if edge.flush_gateway().await.is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    let counted: i64 =
        sqlx::query_scalar("SELECT COALESCE(sum(requests),0)::bigint FROM traffic_usage")
            .fetch_one(&l.store.pool)
            .await
            .unwrap();
    assert_eq!(counted, 3);
    l.finish().await;
}

#[tokio::test]
async fn a_lock_waited_for_too_long_is_busy_not_broken_nor_the_database_gone() {
    let l = Lab::new().await;
    let mut holder = l.store.pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(184923781)")
        .execute(&mut *holder)
        .await
        .unwrap();
    let mut waiter = l.store.pool.begin().await.unwrap();
    sqlx::query("SET LOCAL lock_timeout='50ms'")
        .execute(&mut *waiter)
        .await
        .unwrap();
    let error: fenders_control_plane::error::Error =
        sqlx::query("SELECT pg_advisory_xact_lock(184923781)")
            .execute(&mut *waiter)
            .await
            .unwrap_err()
            .into();
    assert_eq!(error.status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(!error.is_database_unavailable());
    drop(waiter);
    holder.rollback().await.unwrap();
    l.finish().await;
}

/// A flush that waits for the lock behind other work for longer than it
/// may is not the database being gone: the edge goes on serving as it was,
/// not from memory as in an outage.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_flush_kept_waiting_for_the_lock_is_not_an_outage() {
    let l = Lab::new().await;
    let edge = Store::from_pool(l.store.pool.clone(), l.root.path())
        .unwrap()
        .serving(Serves::Edge);
    let mut holder = l.store.pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(184923781)")
        .execute(&mut *holder)
        .await
        .unwrap();
    assert!(edge.flush_gateway().await.is_err(), "it could not flush");
    assert!(
        edge.gateway.outage.down_for().is_none(),
        "the database answered: no outage"
    );
    holder.rollback().await.unwrap();
    edge.flush_gateway().await.unwrap();
    l.finish().await;
}
