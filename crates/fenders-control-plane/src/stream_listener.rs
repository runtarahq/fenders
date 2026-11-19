//! The listener of the gateway and of the run channel: TLS, HTTP/2 and
//! HTTP/1.1, with bodies that may go on for as long as a response is allowed
//! to.
//!
//! The node-control listener ([`fenders_node_protocol::transport`]) speaks
//! HTTP/1.1 and ends a connection some 80 seconds after it stops taking
//! requests, which bounds how old a peer's certificate handshake can be. That
//! would cut a streamed response short, and these two listeners authenticate
//! no client certificate: a run channel call carries its launch's credential
//! and a gateway request nothing. So they are served here, with no lifetime
//! of their own; the gateway bounds each request and response itself, and a
//! connection that asks for nothing is closed.
use axum::Router;
use fenders_node_protocol::error::Result;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use std::{sync::Arc, time::Duration};

/// Handshakes in progress, connections served, and connections served for
/// one peer address. Unauthenticated sockets hold only a handshake's place,
/// and one address a share: the per-app and per-tenant limits the gateway
/// keeps (1000 and 4000 WebSocket connections) fit under what is served.
const HANDSHAKES: usize = 256;
const CONNECTIONS: usize = 8192;
const CONNECTIONS_PER_PEER: usize = 2048;
/// How long a connection may go without a request before it is closed. One
/// that was upgraded (a WebSocket) is the gateway's to bound, not this.
const IDLE: Duration = Duration::from_secs(120);
/// How long connections in flight are given once shutdown is asked.
const DRAIN: Duration = Duration::from_secs(10);

/// Serves `router` on `listener` until `shutdown`, then gives connections
/// [`DRAIN`] to finish.
pub async fn serve(
    listener: tokio::net::TcpListener,
    config: Arc<rustls::ServerConfig>,
    router: Router,
    shutdown: impl Future<Output = ()>,
) -> Result<()> {
    serve_closing_idle(listener, config, router, shutdown, IDLE).await
}

async fn serve_closing_idle(
    listener: tokio::net::TcpListener,
    config: Arc<rustls::ServerConfig>,
    router: Router,
    shutdown: impl Future<Output = ()>,
    idle_after: Duration,
) -> Result<()> {
    let mut config = (*config).clone();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let admission = fenders_node_protocol::transport::Admission::new(
        HANDSHAKES,
        CONNECTIONS,
        CONNECTIONS_PER_PEER,
    );
    let mut connections = tokio::task::JoinSet::new();
    tokio::pin!(shutdown);
    loop {
        let (socket, peer) = tokio::select! {
            biased;
            _ = &mut shutdown => break,
            _ = connections.join_next(), if !connections.is_empty() => continue,
            accepted = listener.accept() => match accepted {
                Ok(accepted) => accepted,
                // Most often a process out of descriptors: wait, do not end.
                Err(error) => {
                    eprintln!("stream listener: accepting a connection failed: {error}");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
        };
        let Some(mut slot) = admission.handshake(peer.ip()) else {
            continue;
        };
        let _ = socket.set_nodelay(true);
        let acceptor = acceptor.clone();
        let activity = Arc::new(Activity::default());
        let seen = activity.clone();
        let router = router
            .clone()
            .layer(axum::middleware::from_fn(move |request, next| {
                track(seen.clone(), request, next)
            }));
        connections.spawn(async move {
            let Ok(Ok(tls)) =
                tokio::time::timeout(Duration::from_secs(10), acceptor.accept(socket)).await
            else {
                return;
            };
            if !slot.established() {
                return;
            }
            // The peer's certificate, where it showed one: an edge passing
            // a request on to another.
            let pin = tls
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|chain| chain.first())
                .map(|leaf| crate::model::digest(leaf.as_ref()));
            let router = router.layer(axum::Extension(
                fenders_node_protocol::transport::PeerIdentity(pin),
            ));
            let service = hyper_util::service::TowerToHyperService::new(router);
            let mut builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
            builder
                .http1()
                .timer(TokioTimer::new())
                .header_read_timeout(Duration::from_secs(10));
            // A peer that is gone is noticed, whatever it had in flight.
            // As many streams at once as the gateway takes requests: an
            // edge passes another's requests and its shims' asks over one
            // connection to it, hundreds of them waiting together during a
            // burst of wakes; the default 200 queued the rest behind them.
            builder
                .http2()
                .timer(TokioTimer::new())
                .max_concurrent_streams(crate::api::GATEWAY_REQUESTS as u32)
                .keep_alive_interval(Duration::from_secs(20))
                .keep_alive_timeout(Duration::from_secs(20));
            // With upgrades: the gateway accepts WebSocket connections.
            let connection = builder.serve_connection_with_upgrades(TokioIo::new(tls), service);
            tokio::pin!(connection);
            // A connection that answers pings and asks for nothing would
            // otherwise be held for ever. Closing is graceful: a response
            // still being sent is finished.
            let idle = async {
                loop {
                    tokio::time::sleep(idle_after / 4).await;
                    if activity.idle_for(idle_after) {
                        return;
                    }
                }
            };
            tokio::select! {
                _ = connection.as_mut() => return,
                _ = idle => {}
            }
            connection.as_mut().graceful_shutdown();
            let _ = connection.await;
        });
    }
    drop(listener);
    let _ = tokio::time::timeout(DRAIN, async {
        while connections.join_next().await.is_some() {}
    })
    .await;
    Ok(())
}

/// What a connection is doing, for deciding that it does nothing.
#[derive(Default)]
struct Activity {
    /// Requests being handled.
    handling: std::sync::atomic::AtomicUsize,
    /// When the last was taken or answered, in milliseconds since `EPOCH`.
    last: std::sync::atomic::AtomicU64,
    /// Whether a request was answered by switching protocols.
    upgraded: std::sync::atomic::AtomicBool,
}

static EPOCH: std::sync::LazyLock<tokio::time::Instant> =
    std::sync::LazyLock::new(tokio::time::Instant::now);

fn now() -> u64 {
    EPOCH.elapsed().as_millis() as u64
}

impl Activity {
    fn idle_for(&self, idle: Duration) -> bool {
        use std::sync::atomic::Ordering::SeqCst;
        !self.upgraded.load(SeqCst)
            && self.handling.load(SeqCst) == 0
            && now().saturating_sub(self.last.load(SeqCst)) >= idle.as_millis() as u64
    }
}

async fn track(
    activity: Arc<Activity>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use std::sync::atomic::Ordering::SeqCst;
    /// Counts a request as handled however its handling ends.
    struct Handling(Arc<Activity>);
    impl Drop for Handling {
        fn drop(&mut self) {
            self.0.last.store(now(), SeqCst);
            self.0.handling.fetch_sub(1, SeqCst);
        }
    }
    activity.handling.fetch_add(1, SeqCst);
    activity.last.store(now(), SeqCst);
    let handling = Handling(activity);
    let response = next.run(request).await;
    if response.status() == axum::http::StatusCode::SWITCHING_PROTOCOLS {
        handling.0.upgraded.store(true, SeqCst);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A listener with a certificate for 127.0.0.1, and a client that trusts
    /// it and keeps its connection.
    async fn served(
        idle: Duration,
    ) -> (
        String,
        reqwest::Client,
        tokio::sync::oneshot::Sender<()>,
        tokio::task::JoinHandle<Result<()>>,
        tempfile::TempDir,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["127.0.0.1".into()]).unwrap();
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let cert = params.self_signed(&key).unwrap();
        let (certificate, private_key) = (dir.path().join("s.pem"), dir.path().join("s.key"));
        std::fs::write(&certificate, cert.pem()).unwrap();
        crate::pki::private_file(&private_key, key.serialize_pem().as_bytes()).unwrap();
        let config = crate::transport::server_config(&certificate, &private_key, None).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("https://{}", listener.local_addr().unwrap());
        let router = Router::new().route("/", axum::routing::get(|| async { "served" }));
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(serve_closing_idle(
            listener,
            config,
            router,
            async {
                let _ = stopped.await;
            },
            idle,
        ));
        let client = reqwest::Client::builder()
            .add_root_certificate(reqwest::Certificate::from_pem(cert.pem().as_bytes()).unwrap())
            .build()
            .unwrap();
        (origin, client, stop, server, dir)
    }

    #[tokio::test]
    async fn a_connection_that_asks_for_nothing_more_is_closed() {
        let (origin, client, stop, server, _dir) = served(Duration::from_millis(200)).await;
        assert_eq!(
            client
                .get(&origin)
                .send()
                .await
                .unwrap()
                .text()
                .await
                .unwrap(),
            "served"
        );
        // The client keeps its connection and says no more. Once it has been
        // idle the listener has closed it: stopping waits for nothing.
        tokio::time::sleep(Duration::from_millis(600)).await;
        let _ = stop.send(());
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("an idle connection was still held")
            .unwrap()
            .unwrap();
        // And the client is served again, on a new connection.
        drop(client);
    }

    #[tokio::test]
    async fn sockets_that_never_finish_a_handshake_leave_other_peers_served() {
        let (origin, client, _stop, _server, _dir) = served(IDLE).await;
        let address: std::net::SocketAddr = origin.trim_start_matches("https://").parse().unwrap();
        let mut stalled = Vec::new();
        for _ in 0..HANDSHAKES + 32 {
            let socket = tokio::net::TcpSocket::new_v4().unwrap();
            socket.bind("127.0.0.2:0".parse().unwrap()).unwrap();
            stalled.push(socket.connect(address).await.unwrap());
        }
        assert_eq!(
            client
                .get(&origin)
                .send()
                .await
                .unwrap()
                .text()
                .await
                .unwrap(),
            "served"
        );
        drop(stalled);
    }

    #[tokio::test(start_paused = true)]
    async fn a_connection_is_idle_only_when_it_handles_nothing_and_was_not_upgraded() {
        use std::sync::atomic::Ordering::SeqCst;
        let _ = *EPOCH;
        let activity = Activity::default();
        activity.last.store(now(), SeqCst);
        assert!(!activity.idle_for(IDLE));
        tokio::time::advance(IDLE).await;
        assert!(activity.idle_for(IDLE));
        // Handling a request, however long: not idle.
        activity.handling.store(1, SeqCst);
        tokio::time::advance(IDLE * 10).await;
        assert!(!activity.idle_for(IDLE));
        // Done: idle again only after the time has passed anew.
        activity.handling.store(0, SeqCst);
        activity.last.store(now(), SeqCst);
        assert!(!activity.idle_for(IDLE));
        tokio::time::advance(IDLE).await;
        assert!(activity.idle_for(IDLE));
        // A WebSocket's connection is never idle here.
        activity.upgraded.store(true, SeqCst);
        assert!(!activity.idle_for(IDLE));
    }
}
