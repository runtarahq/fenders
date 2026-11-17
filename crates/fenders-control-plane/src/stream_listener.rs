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
//! of their own; the gateway bounds each request and response itself.
use axum::Router;
use fenders_node_protocol::error::Result;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use std::{sync::Arc, time::Duration};

/// Connections served at once.
const CONNECTIONS: usize = 1024;
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
    let mut config = (*config).clone();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let capacity = Arc::new(tokio::sync::Semaphore::new(CONNECTIONS));
    let mut connections = tokio::task::JoinSet::new();
    tokio::pin!(shutdown);
    loop {
        let socket = tokio::select! {
            biased;
            _ = &mut shutdown => break,
            _ = connections.join_next(), if !connections.is_empty() => continue,
            accepted = listener.accept() => match accepted {
                Ok((socket, _)) => socket,
                // Most often a process out of descriptors: wait, do not end.
                Err(error) => {
                    eprintln!("stream listener: accepting a connection failed: {error}");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
        };
        let Ok(permit) = capacity.clone().try_acquire_owned() else {
            continue;
        };
        let _ = socket.set_nodelay(true);
        let acceptor = acceptor.clone();
        let service = hyper_util::service::TowerToHyperService::new(router.clone());
        connections.spawn(async move {
            let _permit = permit;
            let Ok(Ok(tls)) =
                tokio::time::timeout(Duration::from_secs(10), acceptor.accept(socket)).await
            else {
                return;
            };
            let mut builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
            builder
                .http1()
                .timer(TokioTimer::new())
                .header_read_timeout(Duration::from_secs(10));
            // A peer that is gone is noticed, whatever it had in flight.
            builder
                .http2()
                .timer(TokioTimer::new())
                .keep_alive_interval(Duration::from_secs(20))
                .keep_alive_timeout(Duration::from_secs(20));
            // With upgrades: the gateway accepts WebSocket connections.
            let _ = builder
                .serve_connection_with_upgrades(TokioIo::new(tls), service)
                .await;
        });
    }
    drop(listener);
    let _ = tokio::time::timeout(DRAIN, async {
        while connections.join_next().await.is_some() {}
    })
    .await;
    Ok(())
}
