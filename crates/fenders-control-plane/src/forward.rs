//! Passing a request to the edge that owns its app (E8).
//!
//! Any edge takes any request, a client's on the gateway and a shim's on
//! the run channel, behind one name and a plain TCP balancer. One that is
//! not its app's edge's ([`crate::edges`]) passes it, head and streaming
//! body, to the owner's internal port, and the answer back. Edges reach
//! each other over mutual TLS: each presents the certificate it was
//! registered with, and each checks the other's against its registered pin.
//!
//! A request is passed on once: the owner serves it as its own, or answers
//! that it is not its own any more, and never passes it on again.
//!
//! What is passed goes over one HTTP/2 connection to each owner, kept for
//! as long as it lasts. A WebSocket connection, which HTTP/2 does not carry
//! here, is passed over an HTTP/1.1 connection of its own, upgraded at both
//! ends and joined.
use crate::{
    error::{Error, Result},
    model::digest,
};
use axum::{
    body::Body,
    http::{HeaderValue, Request, Response, StatusCode, header},
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::{
    collections::HashMap,
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

/// The header that says a request was passed on, and from which listener:
/// `gateway` or `run-channel`. Only the internal port reads it.
pub const FORWARDED: &str = "fenders-forwarded";
/// How long where an edge is, and its pin, are believed.
const PEER_FRESH: Duration = Duration::from_secs(10);

/// A request that was passed on: whoever serves it does not pass it on
/// again.
#[derive(Clone, Copy, Debug)]
pub struct Forwarded;

/// Which listener a request came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Listener {
    Gateway,
    RunChannel,
}

impl Listener {
    fn name(self) -> &'static str {
        match self {
            Self::Gateway => "gateway",
            Self::RunChannel => "run-channel",
        }
    }
    pub fn of(value: &str) -> Option<Self> {
        match value {
            "gateway" => Some(Self::Gateway),
            "run-channel" => Some(Self::RunChannel),
            _ => None,
        }
    }
}

/// An edge, as another reaches it.
#[derive(Clone)]
struct Peer {
    endpoint: url::Url,
    pin: String,
}

pub struct Forwarder {
    tls: Arc<rustls::ClientConfig>,
    peers: Mutex<HashMap<String, (Peer, Instant)>>,
    connections: Mutex<HashMap<String, hyper::client::conn::http2::SendRequest<Body>>>,
}

impl Forwarder {
    /// Edges are reached with the certificate `cert` and key `key`, and
    /// verified against `ca` and their registered pins.
    pub fn new(ca: &Path, cert: &Path, key: &Path) -> Result<Self> {
        let mut roots = rustls::RootCertStore::empty();
        for certificate in
            rustls_pemfile::certs(&mut std::io::BufReader::new(std::fs::File::open(ca)?))
        {
            roots
                .add(certificate.map_err(|_| Error::invalid("invalid CA certificate"))?)
                .map_err(|_| Error::invalid("invalid CA certificate"))?;
        }
        let chain: Vec<_> =
            rustls_pemfile::certs(&mut std::io::BufReader::new(std::fs::File::open(cert)?))
                .collect::<std::result::Result<_, _>>()
                .map_err(|_| Error::invalid("invalid edge certificate"))?;
        let private =
            rustls_pemfile::private_key(&mut std::io::BufReader::new(std::fs::File::open(key)?))
                .map_err(|_| Error::invalid("invalid edge key"))?
                .ok_or_else(|| Error::invalid("missing edge key"))?;
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| Error::internal())?
        .with_root_certificates(roots)
        .with_client_auth_cert(chain, private)
        .map_err(|_| Error::invalid("invalid edge certificate or key"))?;
        Ok(Self {
            tls: Arc::new(config),
            peers: Mutex::default(),
            connections: Mutex::default(),
        })
    }

    fn known(&self, edge: &str) -> Option<Peer> {
        let peers = self.peers.lock().unwrap_or_else(|e| e.into_inner());
        peers
            .get(edge)
            .filter(|(_, read)| read.elapsed() < PEER_FRESH)
            .map(|(peer, _)| peer.clone())
    }

    fn learn(&self, edge: &str, endpoint: &str, pin: &str) -> Result<Peer> {
        let peer = Peer {
            endpoint: endpoint
                .parse()
                .map_err(|_| Error::invalid("invalid edge endpoint"))?,
            pin: pin.to_owned(),
        };
        self.peers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(edge.to_owned(), (peer.clone(), Instant::now()));
        Ok(peer)
    }

    /// A TLS connection to `peer`, its certificate the one it registered.
    async fn connect(
        &self,
        peer: &Peer,
        alpn: &[u8],
    ) -> Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
        let unreachable =
            || Error::new(StatusCode::BAD_GATEWAY, "the app's edge cannot be reached");
        let host = peer.endpoint.host_str().ok_or_else(unreachable)?.to_owned();
        let port = peer.endpoint.port_or_known_default().unwrap_or(443);
        let mut config = (*self.tls).clone();
        config.alpn_protocols = vec![alpn.to_vec()];
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let name =
            rustls::pki_types::ServerName::try_from(host.clone()).map_err(|_| unreachable())?;
        let socket = tokio::time::timeout(
            Duration::from_secs(5),
            tokio::net::TcpStream::connect((host.as_str(), port)),
        )
        .await
        .map_err(|_| unreachable())?
        .map_err(|_| unreachable())?;
        let _ = socket.set_nodelay(true);
        let tls = tokio::time::timeout(Duration::from_secs(5), connector.connect(name, socket))
            .await
            .map_err(|_| unreachable())?
            .map_err(|_| unreachable())?;
        let leaf = tls
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|chain| chain.first())
            .ok_or_else(unreachable)?;
        if digest(leaf.as_ref()) != peer.pin {
            return Err(Error::new(
                StatusCode::BAD_GATEWAY,
                "the app's edge presented a certificate it was not registered with",
            ));
        }
        Ok(tls)
    }

    /// The HTTP/2 connection to `edge`, made now if there is none.
    async fn sender(
        &self,
        edge: &str,
        peer: &Peer,
    ) -> Result<hyper::client::conn::http2::SendRequest<Body>> {
        if let Some(sender) = self
            .connections
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(edge)
            .filter(|sender| !sender.is_closed())
            .cloned()
        {
            return Ok(sender);
        }
        let tls = self.connect(peer, b"h2").await?;
        let (sender, connection) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
                .await
                .map_err(|_| {
                    Error::new(StatusCode::BAD_GATEWAY, "the app's edge cannot be reached")
                })?;
        tokio::spawn(connection);
        self.connections
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(edge.to_owned(), sender.clone());
        Ok(sender)
    }
}

/// The hop-by-hop headers a request or an answer loses when it is passed on.
const HOP: &[header::HeaderName] = &[
    header::CONNECTION,
    header::TE,
    header::TRAILER,
    header::TRANSFER_ENCODING,
    header::UPGRADE,
    header::PROXY_AUTHORIZATION,
];

impl crate::store::Store {
    /// Where edge `edge` is and its pin: kept for a while.
    async fn peer(&self, forwarder: &Forwarder, edge: &str) -> Result<Peer> {
        if let Some(peer) = forwarder.known(edge) {
            return Ok(peer);
        }
        let mut tx = self.transaction(false, false).await?;
        let row = crate::db::optional(
            &mut tx,
            "SELECT endpoint,cert_sha256 FROM edges WHERE id=$1 AND NOT deleted",
            crate::args![edge],
        )
        .await?
        .ok_or_else(|| Error::new(StatusCode::BAD_GATEWAY, "the app's edge is not registered"))?;
        forwarder.learn(
            edge,
            crate::db::s(&row["endpoint"]),
            crate::db::s(&row["cert_sha256"]),
        )
    }

    /// Passes `request`, which came to `listener`, to edge `edge`, and
    /// gives back its answer as it comes.
    pub(crate) async fn forward(
        &self,
        edge: &str,
        listener: Listener,
        request: Request<Body>,
    ) -> Result<Response<Body>> {
        let forwarder = self.forwarder.as_ref().ok_or_else(|| {
            Error::new(
                StatusCode::MISDIRECTED_REQUEST,
                "another edge serves this app",
            )
        })?;
        let peer = self.peer(forwarder, edge).await?;
        if crate::websocket::wanted(request.headers()) {
            return self
                .forward_upgrade(forwarder, &peer, listener, request)
                .await;
        }
        let (mut parts, body) = request.into_parts();
        // The app's host name goes as the authority: HTTP/2 has no Host.
        let authority = match listener {
            Listener::Gateway => parts
                .headers
                .get(header::HOST)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
                .or_else(|| parts.uri.authority().map(|a| a.to_string())),
            Listener::RunChannel => None,
        }
        .unwrap_or_else(|| peer.endpoint.host_str().unwrap_or("edge").to_owned());
        let target = parts.uri.path_and_query().map_or("/", |p| p.as_str());
        parts.uri = format!("https://{authority}{target}")
            .parse()
            .map_err(|_| Error::invalid("invalid request target"))?;
        parts.version = axum::http::Version::HTTP_2;
        for name in HOP.iter().chain([&header::HOST]) {
            parts.headers.remove(name);
        }
        parts
            .headers
            .insert(FORWARDED, HeaderValue::from_static(listener.name()));
        let sender = forwarder.sender(edge, &peer).await;
        let mut sender = match sender {
            Ok(sender) => sender,
            Err(error) => return Err(error),
        };
        let answer = sender
            .send_request(Request::from_parts(parts, body))
            .await
            .map_err(|_| {
                forwarder
                    .connections
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(edge);
                Error::new(StatusCode::BAD_GATEWAY, "the app's edge did not answer")
            })?;
        let (mut parts, body) = answer.into_parts();
        for name in HOP {
            parts.headers.remove(name);
        }
        Ok(Response::from_parts(parts, Body::new(body)))
    }

    /// Passes a WebSocket connection's opening request over an HTTP/1.1
    /// connection of its own, and, once both ends have upgraded, joins them.
    async fn forward_upgrade(
        &self,
        forwarder: &Forwarder,
        peer: &Peer,
        listener: Listener,
        mut request: Request<Body>,
    ) -> Result<Response<Body>> {
        let client = hyper::upgrade::on(&mut request);
        let tls = forwarder.connect(peer, b"http/1.1").await?;
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .map_err(|_| Error::new(StatusCode::BAD_GATEWAY, "the app's edge cannot be reached"))?;
        tokio::spawn(connection.with_upgrades());
        let (mut parts, body) = request.into_parts();
        let target = parts
            .uri
            .path_and_query()
            .map_or("/", |p| p.as_str())
            .to_owned();
        parts.uri = target
            .parse()
            .map_err(|_| Error::invalid("invalid request target"))?;
        parts.version = axum::http::Version::HTTP_11;
        parts
            .headers
            .insert(FORWARDED, HeaderValue::from_static(listener.name()));
        let mut answer = sender
            .send_request(Request::from_parts(parts, body))
            .await
            .map_err(|_| Error::new(StatusCode::BAD_GATEWAY, "the app's edge did not answer"))?;
        if answer.status() == StatusCode::SWITCHING_PROTOCOLS {
            let owner = hyper::upgrade::on(&mut answer);
            tokio::spawn(async move {
                if let (Ok(client), Ok(owner)) = (client.await, owner.await) {
                    let (mut client, mut owner) = (TokioIo::new(client), TokioIo::new(owner));
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut owner).await;
                }
            });
        }
        let (parts, body) = answer.into_parts();
        Ok(Response::from_parts(parts, Body::new(body)))
    }

    /// Whether a forwarding peer, by the pin of the certificate it showed,
    /// is a registered edge.
    pub(crate) async fn edge_peer(&self, pin: &str) -> Result<()> {
        let mut tx = self.transaction(false, false).await?;
        crate::db::optional(
            &mut tx,
            "SELECT id FROM edges WHERE cert_sha256=$1 AND NOT deleted",
            crate::args![pin],
        )
        .await?
        .map(|_| ())
        .ok_or_else(Error::unauthorized)
    }
}

/// An edge's internal port: what another edge passes on, from a registered
/// edge only, served as the listener it came to would serve it.
pub fn router(state: crate::api::ApiState) -> axum::Router {
    axum::Router::new().fallback(move |request: Request<Body>| {
        let state = state.clone();
        async move {
            use axum::{extract::State, response::IntoResponse};
            let store = state.store.clone();
            let pin = request
                .extensions()
                .get::<fenders_node_protocol::transport::PeerIdentity>()
                .and_then(|identity| identity.0.clone());
            let Some(pin) = pin else {
                return Error::unauthorized().into_response();
            };
            if let Err(error) = store.edge_peer(&pin).await {
                return error.into_response();
            }
            let listener = request
                .headers()
                .get(FORWARDED)
                .and_then(|value| value.to_str().ok())
                .and_then(Listener::of);
            let mut request = request;
            request.extensions_mut().insert(Forwarded);
            match listener {
                Some(Listener::Gateway) => crate::api::gateway_dispatch(State(state), request)
                    .await
                    .into_response(),
                Some(Listener::RunChannel) => crate::run_channel::dispatch(State(store), request)
                    .await
                    .into_response(),
                None => Error::missing().into_response(),
            }
        }
    })
}
