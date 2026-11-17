//! Bounded TLS 1.3 transport. Certificate pins supplement CA/name validation.
use crate::{
    error::{Error, Result},
    model::digest,
};
use axum::{
    Extension, Router,
    body::Bytes,
    http::{Method, StatusCode},
};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
};
use serde_json::Value;
use std::{path::Path, sync::Arc, time::Duration};

struct Driver(tokio::task::JoinHandle<()>);
impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    rustls_pemfile::certs(&mut std::io::BufReader::new(std::fs::File::open(path)?))
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(Into::into)
}
fn private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    rustls_pemfile::private_key(&mut std::io::BufReader::new(std::fs::File::open(path)?))?
        .ok_or_else(|| Error::invalid("missing TLS private key"))
}
fn roots(path: &Path) -> Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    for certificate in certificates(path)? {
        roots
            .add(certificate)
            .map_err(|_| Error::invalid("invalid CA certificate"))?;
    }
    Ok(roots)
}
#[derive(Clone)]
pub struct PeerIdentity(pub Option<String>);
/// The peer certificate's key pin ([`key_pin`]): unlike [`PeerIdentity`],
/// the certificate's own digest, it stays the same when the certificate is
/// renewed over the same key.
#[derive(Clone)]
pub struct PeerKey(pub Option<String>);

/// The SHA-256 of a DER certificate's SubjectPublicKeyInfo, hex.
pub fn key_pin(certificate: &[u8]) -> Option<String> {
    let der = CertificateDer::from(certificate);
    let leaf = webpki::EndEntityCert::try_from(&der).ok()?;
    Some(digest(leaf.subject_public_key_info().as_ref()))
}

/// A certificate and key read from their files, and read again when either
/// changes, so a renewed certificate is presented at the next handshake with
/// nothing restarted. A pair that does not match (one file renewed before the
/// other) is ignored until it does.
#[derive(Debug)]
struct FileIdentity {
    cert: std::path::PathBuf,
    key: std::path::PathBuf,
    current: std::sync::Mutex<([Option<FileVersion>; 2], Arc<rustls::sign::CertifiedKey>)>,
}
/// A file's version as its metadata tells: its modification time, inode and
/// size. A renewal installed by rename within the same clock tick as the
/// last still has another inode.
type FileVersion = (std::time::SystemTime, u64, u64);
impl FileIdentity {
    fn load(cert: &Path, key: &Path) -> Result<Self> {
        let certified =
            Self::read(cert, key).ok_or_else(|| Error::invalid("invalid TLS identity"))?;
        Ok(Self {
            cert: cert.to_owned(),
            key: key.to_owned(),
            current: std::sync::Mutex::new((Self::modified(cert, key), certified)),
        })
    }
    fn modified(cert: &Path, key: &Path) -> [Option<FileVersion>; 2] {
        use std::os::unix::fs::MetadataExt;
        [cert, key].map(|path| {
            let metadata = std::fs::metadata(path).ok()?;
            Some((metadata.modified().ok()?, metadata.ino(), metadata.len()))
        })
    }
    fn read(cert: &Path, key: &Path) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let chain = certificates(cert).ok().filter(|chain| !chain.is_empty())?;
        let key = rustls::crypto::ring::default_provider()
            .key_provider
            .load_private_key(private_key(key).ok()?)
            .ok()?;
        let certified = rustls::sign::CertifiedKey::new(chain, key);
        certified.keys_match().ok()?;
        Some(Arc::new(certified))
    }
    fn current(&self) -> Arc<rustls::sign::CertifiedKey> {
        let mut current = self.current.lock().unwrap_or_else(|e| e.into_inner());
        let modified = Self::modified(&self.cert, &self.key);
        if modified != current.0
            && let Some(renewed) = Self::read(&self.cert, &self.key)
        {
            *current = (modified, renewed);
        }
        current.1.clone()
    }
}
impl rustls::server::ResolvesServerCert for FileIdentity {
    fn resolve(
        &self,
        _: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(self.current())
    }
}
impl rustls::client::ResolvesClientCert for FileIdentity {
    fn resolve(
        &self,
        _: &[&[u8]],
        _: &[rustls::SignatureScheme],
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(self.current())
    }
    fn has_certs(&self) -> bool {
        true
    }
}
/// Has `socket` send a body's last short segment at once, not after the
/// peer's delayed acknowledgement of the one before it (Nagle), which held a
/// call 40 ms by how its size fell into segments. Every connection the
/// transport makes or accepts takes it.
fn send_at_once(socket: &tokio::net::TcpStream) {
    let _ = socket.set_nodelay(true);
}
/// How long after its handshake a connection takes new requests. Those it
/// took then have its lifetime (80 s for the node APIs, more than the 70 s a
/// client waits) to finish, so keeping connections alive bounds a peer's
/// identity to a handshake at most this old.
const REUSE: Duration = Duration::from_secs(60);
/// How long a client sends new requests on a connection: under [`REUSE`],
/// with room for the request to arrive before the server stops reading.
const CLIENT_REUSE: Duration = Duration::from_secs(55);
/// How long a client keeps a connection idle: under the server's 10 s
/// header read timeout, which closes a connection no request arrives on.
const CLIENT_IDLE: Duration = Duration::from_secs(8);
/// Idle connections a client keeps, so a burst does not hold the server's
/// connection slots after it: a node's agent and its forwarder hold at
/// most this many each, which the server closes 10 s after their handshake.
const CLIENT_IDLE_CONNECTIONS: usize = 4;
/// How long a client keeps a connection for more requests: [`CLIENT_REUSE`]
/// where `FENDERS_TRANSPORT_REUSE=1`, else none, one request a connection as
/// before keep-alive, until reuse has run without loss on a live link.
fn reuse_window() -> Duration {
    if std::env::var("FENDERS_TRANSPORT_REUSE").as_deref() == Ok("1") {
        CLIENT_REUSE
    } else {
        Duration::ZERO
    }
}
/// Whether a request on a kept connection failed because the peer closed the
/// connection, rather than because of what it answered.
fn lost(error: &hyper::Error) -> bool {
    error.is_incomplete_message()
        || error.is_canceled()
        || error.is_closed()
        || std::error::Error::source(error).is_some_and(|source| source.is::<std::io::Error>())
}
/// A request's body that records when it has been read to its end.
struct ReadToEnd {
    body: axum::body::Body,
    read: Arc<std::sync::atomic::AtomicBool>,
}
impl hyper::body::Body for ReadToEnd {
    type Data = Bytes;
    type Error = axum::Error;
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<std::result::Result<hyper::body::Frame<Bytes>, Self::Error>>> {
        let polled = std::pin::Pin::new(&mut self.body).poll_frame(cx);
        if matches!(polled, std::task::Poll::Ready(None)) || self.body.is_end_stream() {
            self.read.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        polled
    }
    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }
    fn size_hint(&self) -> hyper::body::SizeHint {
        self.body.size_hint()
    }
}
/// Says `Connection: close` on a response to a request whose body the
/// handler did not read to its end: the server cannot take another request
/// on that connection and closes it, which a client that is not told would
/// only find by losing the request it sends next.
async fn close_unless_read(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let read = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let request = request.map(|body| {
        if hyper::body::Body::is_end_stream(&body) {
            read.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        axum::body::Body::new(ReadToEnd {
            body,
            read: read.clone(),
        })
    });
    let mut response = next.run(request).await;
    if !read.load(std::sync::atomic::Ordering::Relaxed) {
        response.headers_mut().insert(
            hyper::header::CONNECTION,
            hyper::header::HeaderValue::from_static("close"),
        );
    }
    response
}
pub fn server_config(
    cert: &Path,
    key: &Path,
    ca: Option<&Path>,
) -> Result<Arc<rustls::ServerConfig>> {
    let builder = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|_| Error::internal())?;
    let builder = if let Some(ca) = ca {
        builder.with_client_cert_verifier(
            rustls::server::WebPkiClientVerifier::builder_with_provider(
                Arc::new(roots(ca)?),
                Arc::new(rustls::crypto::ring::default_provider()),
            )
            .build()
            .map_err(|_| Error::invalid("invalid client trust store"))?,
        )
    } else {
        builder.with_no_client_auth()
    };
    let mut config = builder.with_cert_resolver(Arc::new(FileIdentity::load(cert, key)?));
    // Full handshakes only: a resumed session would carry a peer's identity
    // past its certificate's renewal or expiry.
    config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    Ok(Arc::new(config))
}
pub async fn serve_tls(
    listener: tokio::net::TcpListener,
    config: Arc<rustls::ServerConfig>,
    router: Router,
) -> Result<()> {
    serve_tls_for(
        listener,
        config,
        router,
        Duration::from_secs(80),
        std::future::pending(),
    )
    .await
}
/// Stop accepting on shutdown, then finish accepted connections within their
/// existing TLS/header/request limits. Callers keep execution renewals alive
/// until this future returns. Listener preservation is a separate hosting contract.
pub async fn serve_tls_until(
    listener: tokio::net::TcpListener,
    config: Arc<rustls::ServerConfig>,
    router: Router,
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<()> {
    serve_tls_for(listener, config, router, Duration::from_secs(80), shutdown).await
}
/// Who may hold a listener's connections.
///
/// A connection is first a handshake, then one that is served. The two are
/// budgeted apart, and each also for every peer address, so that sockets
/// which never finish a handshake (they need no certificate and no credential
/// to open) take nothing from the connections of peers that did, and one
/// address cannot hold a listener's whole capacity. An IPv6 peer is its /64.
#[derive(Clone)]
pub struct Admission(Arc<Budget>);

struct Budget {
    handshakes: usize,
    peer_handshakes: usize,
    serving: usize,
    peer_serving: usize,
    held: std::sync::Mutex<Held>,
}

#[derive(Default)]
struct Held {
    handshakes: usize,
    serving: usize,
    /// Handshakes and served connections of each peer that holds any.
    peers: std::collections::HashMap<std::net::IpAddr, (usize, usize)>,
}

/// One connection's place in a listener's budget, given back when dropped.
pub struct Slot {
    budget: Arc<Budget>,
    peer: std::net::IpAddr,
    served: bool,
}

impl Admission {
    /// At most `handshakes` connections in their handshake and `serving`
    /// served, of which one peer holds at most a quarter and `peer_serving`.
    pub fn new(handshakes: usize, serving: usize, peer_serving: usize) -> Self {
        Self(Arc::new(Budget {
            handshakes,
            peer_handshakes: (handshakes / 4).max(1),
            serving,
            peer_serving,
            held: Default::default(),
        }))
    }

    /// A place for a connection `peer` just opened, or `None` when the
    /// listener, or that peer, has as many handshakes as it may.
    pub fn handshake(&self, peer: std::net::IpAddr) -> Option<Slot> {
        let peer = match peer {
            std::net::IpAddr::V6(address) => match address.to_ipv4_mapped() {
                Some(mapped) => mapped.into(),
                None => {
                    let mut segments = address.segments();
                    segments[4..].fill(0);
                    std::net::Ipv6Addr::from(segments).into()
                }
            },
            v4 => v4,
        };
        let mut held = self.0.held.lock().unwrap_or_else(|e| e.into_inner());
        if held.handshakes >= self.0.handshakes {
            return None;
        }
        let of_peer = held.peers.entry(peer).or_default();
        if of_peer.0 >= self.0.peer_handshakes {
            if *of_peer == (0, 0) {
                held.peers.remove(&peer);
            }
            return None;
        }
        of_peer.0 += 1;
        held.handshakes += 1;
        Some(Slot {
            budget: self.0.clone(),
            peer,
            served: false,
        })
    }
}

impl Slot {
    /// The handshake is done: its place becomes one of a served connection.
    /// False when the listener, or the peer, already has as many as it may.
    pub fn established(&mut self) -> bool {
        if self.served {
            return true;
        }
        let mut held = self.budget.held.lock().unwrap_or_else(|e| e.into_inner());
        let of_peer = held.peers.get(&self.peer).map_or(0, |peer| peer.1);
        if held.serving >= self.budget.serving || of_peer >= self.budget.peer_serving {
            return false;
        }
        held.handshakes -= 1;
        held.serving += 1;
        if let Some(peer) = held.peers.get_mut(&self.peer) {
            peer.0 -= 1;
            peer.1 += 1;
        }
        self.served = true;
        true
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut held = self.budget.held.lock().unwrap_or_else(|e| e.into_inner());
        if self.served {
            held.serving -= 1;
        } else {
            held.handshakes -= 1;
        }
        if let Some(peer) = held.peers.get_mut(&self.peer) {
            if self.served {
                peer.1 -= 1;
            } else {
                peer.0 -= 1;
            }
            if *peer == (0, 0) {
                held.peers.remove(&self.peer);
            }
        }
    }
}

/// Handshakes in progress, connections served and connections served for one
/// peer address, on a node-control or management listener. A node holds a
/// long poll and a few kept connections; many nodes may share an address.
const HANDSHAKES: usize = 128;
const SERVED: usize = 512;
const SERVED_PER_PEER: usize = 128;

/// How long a listener waits after a failed accept before the next.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(50);

/// A connection accepted, or, after a failed accept, `None` once a short
/// backoff has passed. Accepting fails for passing reasons, most often a
/// process out of file descriptors under load; ending the listener on one cut
/// every node off for good while the process went on running, which is what
/// happened to Runtara Cloud's dev fleet at ~60 runs/s.
async fn keep_serving<T>(accepted: std::io::Result<T>) -> Option<T> {
    match accepted {
        Ok(accepted) => Some(accepted),
        Err(error) => {
            eprintln!("node-control transport: accepting a connection failed: {error}");
            tokio::time::sleep(ACCEPT_BACKOFF).await;
            None
        }
    }
}

async fn serve_tls_for(
    listener: tokio::net::TcpListener,
    config: Arc<rustls::ServerConfig>,
    router: Router,
    lifetime: Duration,
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<()> {
    let acceptor = tokio_rustls::TlsAcceptor::from(config);
    let admission = Admission::new(HANDSHAKES, SERVED, SERVED_PER_PEER);
    let mut connections = tokio::task::JoinSet::new();
    let (stopping, stop) = tokio::sync::watch::channel(false);
    tokio::pin!(shutdown);
    loop {
        let (socket, peer) = tokio::select! {
            biased;
            _ = &mut shutdown => break,
            _ = connections.join_next(), if !connections.is_empty() => continue,
            accepted = listener.accept() => match keep_serving(accepted).await {
                Some(accepted) => accepted,
                None => continue,
            },
        };
        let Some(mut slot) = admission.handshake(peer.ip()) else {
            drop(socket);
            continue;
        };
        send_at_once(&socket);
        let acceptor = acceptor.clone();
        let router = router.clone();
        let mut stop = stop.clone();
        connections.spawn(async move {
            let Ok(Ok(tls)) =
                tokio::time::timeout(Duration::from_secs(10), acceptor.accept(socket)).await
            else {
                return;
            };
            // Only a peer that finished its handshake (with its certificate,
            // where one is required) takes a served connection's place.
            if !slot.established() {
                return;
            }
            let leaf = tls.get_ref().1.peer_certificates().and_then(|c| c.first());
            let pin = leaf.map(|c| digest(c.as_ref()));
            let key = leaf.and_then(|c| key_pin(c.as_ref()));
            let (started, mut serving) = tokio::sync::watch::channel(false);
            let started = Arc::new(started);
            let app = router
                .layer(Extension(PeerIdentity(pin)))
                .layer(Extension(PeerKey(key)))
                .layer(axum::middleware::map_request(
                    move |request: axum::extract::Request| {
                        started.send_replace(true);
                        std::future::ready(request)
                    },
                ))
                .layer(axum::middleware::from_fn(close_unless_read));
            let service = hyper_util::service::TowerToHyperService::new(app);
            let mut builder = hyper::server::conn::http1::Builder::new();
            builder
                .keep_alive(true)
                .max_buf_size(64 * 1024)
                .timer(hyper_util::rt::TokioTimer::new())
                .header_read_timeout(Duration::from_secs(10));
            let connection = builder.serve_connection(TokioIo::new(tls), service);
            tokio::pin!(connection);
            // On shutdown, a connection that took a request takes no more: an
            // idle one closes at once and a busy one after its response. One
            // that has taken none still gets its first, as before keep-alive.
            let stopped = async {
                let _ = stop.wait_for(|stopping| *stopping).await;
                let _ = serving.wait_for(|started| *started).await;
            };
            tokio::select! {
                _ = connection.as_mut() => return,
                _ = tokio::time::sleep(REUSE) => {}
                _ = stopped => {}
            }
            connection.as_mut().graceful_shutdown();
            let _ = tokio::time::timeout(lifetime, connection).await;
        });
    }
    drop(listener);
    stopping.send_replace(true);
    while connections.join_next().await.is_some() {}
    Ok(())
}
#[derive(Clone)]
pub struct Client {
    origin: url::Url,
    tls: Arc<rustls::ClientConfig>,
    pin: String,
    server_name: ServerName<'static>,
    identity: Arc<FileIdentity>,
    /// Connections a request may take, shared by the client's clones.
    idle: Arc<std::sync::Mutex<Vec<Connection>>>,
    reuse: Duration,
}
/// A connection to the peer, made with the identity `identity`.
struct Connection {
    sender: hyper::client::conn::http1::SendRequest<Full<Bytes>>,
    _driver: Driver,
    opened: tokio::time::Instant,
    idle_since: tokio::time::Instant,
    identity: Arc<rustls::sign::CertifiedKey>,
}
/// A connection serving one response. Released once the response is read
/// whole, it goes back to the idle connections; dropped, it closes.
struct Lease {
    connection: Connection,
    reusable: bool,
    idle: Arc<std::sync::Mutex<Vec<Connection>>>,
    reuse: Duration,
}
impl Lease {
    fn release(self) {
        let Self {
            mut connection,
            reusable,
            idle,
            reuse,
        } = self;
        if !reusable || connection.sender.is_closed() || connection.opened.elapsed() >= reuse {
            return;
        }
        connection.idle_since = tokio::time::Instant::now();
        let mut idle = idle.lock().unwrap_or_else(|e| e.into_inner());
        idle.retain(|kept| {
            kept.opened.elapsed() < reuse
                && kept.idle_since.elapsed() < CLIENT_IDLE
                && !kept.sender.is_closed()
        });
        if idle.len() < CLIENT_IDLE_CONNECTIONS {
            idle.push(connection);
        }
    }
}
impl Client {
    pub fn new(endpoint: &str, ca: &Path, cert: &Path, key: &Path, pin: &str) -> Result<Self> {
        let origin =
            url::Url::parse(endpoint).map_err(|_| Error::invalid("invalid HTTPS endpoint"))?;
        if origin.scheme() != "https"
            || origin.host_str().is_none()
            || !origin.username().is_empty()
            || origin.password().is_some()
            || origin.query().is_some()
            || origin.fragment().is_some()
            || origin.path() != "/"
        {
            return Err(Error::invalid("HTTPS origin required"));
        }
        if pin.len() != 64
            || !pin
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::invalid("certificate pin required"));
        }
        if certificates(cert)?.is_empty() {
            return Err(Error::invalid("missing client certificate"));
        }
        let identity = Arc::new(
            FileIdentity::load(cert, key).map_err(|_| Error::invalid("invalid client identity"))?,
        );
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| Error::internal())?
        .with_root_certificates(roots(ca)?)
        .with_client_cert_resolver(identity.clone());
        // A full handshake for every connection, so a renewed certificate is
        // presented.
        config.resumption = rustls::client::Resumption::disabled();
        let server_name = ServerName::try_from(origin.host_str().unwrap().to_owned())
            .map_err(|_| Error::invalid("invalid TLS server name"))?;
        Ok(Self {
            origin,
            tls: Arc::new(config),
            pin: pin.to_owned(),
            server_name,
            identity,
            idle: Arc::default(),
            reuse: reuse_window(),
        })
    }
    /// Operator-specified certificate identity when a provider's dial address differs
    /// from its certificate SAN. Chain validation and mandatory pinning still apply.
    pub fn with_server_name(mut self, name: &str) -> Result<Self> {
        self.server_name = ServerName::try_from(name.to_owned())
            .map_err(|_| Error::invalid("invalid TLS server name"))?;
        self.idle = Arc::default();
        Ok(self)
    }
    /// Has a connection ready for the next request, made now if none is idle,
    /// so that request need not wait for the handshake: a run's forwarder warms
    /// one while its VM boots. Does nothing where connections are not kept.
    pub async fn warm(&self) -> Result<()> {
        if self.reuse.is_zero() {
            return Ok(());
        }
        let identity = self.identity.current();
        {
            let idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
            if idle.iter().any(|connection| {
                Arc::ptr_eq(&connection.identity, &identity)
                    && connection.opened.elapsed() < self.reuse
                    && connection.idle_since.elapsed() < CLIENT_IDLE
                    && !connection.sender.is_closed()
            }) {
                return Ok(());
            }
        }
        let connection = self.connect(identity).await?;
        let mut idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
        if idle.len() < CLIENT_IDLE_CONNECTIONS {
            idle.push(connection);
        }
        Ok(())
    }
    /// An idle connection made with `identity` that may take another request,
    /// closing those that may not.
    fn idle_connection(&self, identity: &Arc<rustls::sign::CertifiedKey>) -> Option<Connection> {
        let mut idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
        while let Some(connection) = idle.pop() {
            if Arc::ptr_eq(&connection.identity, identity)
                && connection.opened.elapsed() < self.reuse
                && connection.idle_since.elapsed() < CLIENT_IDLE
                && !connection.sender.is_closed()
            {
                return Some(connection);
            }
        }
        None
    }
    pub async fn request(
        &self,
        method: &str,
        path: &str,
        value: Option<&Value>,
        limit: usize,
    ) -> Result<Vec<u8>> {
        let bytes = value
            .map(serde_json::to_vec)
            .transpose()
            .map_err(|_| Error::internal())?
            .unwrap_or_default();
        self.request_bytes(
            method,
            path,
            &bytes,
            &[("Content-Type", "application/json".into())],
            limit,
        )
        .await
    }
    pub(crate) async fn request_bytes(
        &self,
        method: &str,
        path: &str,
        bytes: &[u8],
        headers: &[(&str, String)],
        limit: usize,
    ) -> Result<Vec<u8>> {
        tokio::time::timeout(
            Duration::from_secs(70),
            self.request_inner(method, path, bytes, headers, limit),
        )
        .await
        .map_err(|_| Error::new(StatusCode::BAD_GATEWAY, "peer request timed out"))?
    }
    async fn request_inner(
        &self,
        method: &str,
        path: &str,
        bytes: &[u8],
        headers: &[(&str, String)],
        limit: usize,
    ) -> Result<Vec<u8>> {
        let (response, lease) = self
            .response(method, path, Bytes::copy_from_slice(bytes), headers)
            .await?;
        let body = Self::read_response(response, limit).await?;
        lease.release();
        Ok(body)
    }
    async fn read_response(
        response: hyper::Response<hyper::body::Incoming>,
        limit: usize,
    ) -> Result<Vec<u8>> {
        let status = response.status();
        let mut body = response.into_body();
        let mut out = Vec::new();
        while let Some(frame) = body.frame().await {
            let frame =
                frame.map_err(|_| Error::new(StatusCode::BAD_GATEWAY, "invalid peer response"))?;
            if let Ok(data) = frame.into_data() {
                if data.len() > limit.saturating_sub(out.len()) {
                    return Err(Error::new(
                        StatusCode::BAD_GATEWAY,
                        "peer response too large",
                    ));
                }
                out.extend_from_slice(&data);
            }
        }
        if status.is_client_error() || status.is_server_error() {
            return Err(Error::new(
                if matches!(status.as_u16(), 400 | 401 | 403 | 404 | 409 | 422) {
                    status
                } else {
                    StatusCode::BAD_GATEWAY
                },
                "peer request failed",
            ));
        }
        Ok(out)
    }
    /// The peer's response to one request, on an idle connection made with
    /// the current identity if there is one, else on a new one.
    async fn response(
        &self,
        method: &str,
        path: &str,
        body: Bytes,
        headers: &[(&str, String)],
    ) -> Result<(hyper::Response<hyper::body::Incoming>, Lease)> {
        if !path.starts_with('/') || path.starts_with("//") || path.contains(['\r', '\n']) {
            return Err(Error::invalid("invalid peer request path"));
        }
        let method =
            Method::from_bytes(method.as_bytes()).map_err(|_| Error::invalid("invalid method"))?;
        let request = || {
            let mut request = hyper::Request::builder()
                .method(method.clone())
                .uri(path)
                .header(
                    "Host",
                    self.origin[url::Position::BeforeHost..url::Position::AfterPort].to_owned(),
                );
            for (name, value) in headers {
                request = request.header(*name, value);
            }
            request
                .body(Full::new(body.clone()))
                .map_err(|_| Error::invalid("invalid peer request"))
        };
        // What failures log: the path without its query, which may carry a
        // credential.
        let logged = path.split('?').next().unwrap_or_default();
        let replayable = matches!(method, Method::GET | Method::HEAD | Method::OPTIONS)
            || headers
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case("idempotency-key"));
        let identity = self.identity.current();
        let mut connection = loop {
            let Some(mut connection) = self.idle_connection(&identity) else {
                break self.connect(identity).await?;
            };
            // A connection the peer closed while it was idle hands the request
            // back unsent, so it goes on another; one that took it does not.
            let ready =
                tokio::time::timeout(Duration::from_secs(1), connection.sender.ready()).await;
            if !matches!(ready, Ok(Ok(()))) {
                continue;
            }
            match connection.sender.try_send_request(request()?).await {
                Ok(response) => return Ok(self.lease(response, connection)),
                Err(mut error) => {
                    if error.take_message().is_some() {
                        continue;
                    }
                    // The peer closed it as the request went out, before any
                    // response. A request that is safe to send twice (a read,
                    // or a write with an idempotency key, whose repeat the
                    // peer answers from its receipt) goes once more, on a
                    // connection of its own; any other might have been taken,
                    // so it fails as before.
                    eprintln!(
                        "node-control transport: {method} {logged} failed on a kept connection ({} ms old, {} ms idle){}: {:?}",
                        connection.opened.elapsed().as_millis(),
                        connection.idle_since.elapsed().as_millis(),
                        if replayable { ", sending it again" } else { "" },
                        error.error()
                    );
                    if !replayable || !lost(error.error()) {
                        return Err(Error::new(StatusCode::BAD_GATEWAY, "peer request failed"));
                    }
                    break self.connect(identity).await?;
                }
            }
        };
        let response = connection
            .sender
            .send_request(request()?)
            .await
            .map_err(|error| {
                eprintln!(
                    "node-control transport: {method} {logged} failed on a new connection: {error:?}"
                );
                Error::new(StatusCode::BAD_GATEWAY, "peer request failed")
            })?;
        Ok(self.lease(response, connection))
    }
    fn lease(
        &self,
        response: hyper::Response<hyper::body::Incoming>,
        connection: Connection,
    ) -> (hyper::Response<hyper::body::Incoming>, Lease) {
        // A peer that closes after this response says so.
        let reusable = !response
            .headers()
            .get_all(hyper::header::CONNECTION)
            .iter()
            .any(|value| {
                value
                    .to_str()
                    .is_ok_and(|value| value.to_ascii_lowercase().contains("close"))
            });
        let lease = Lease {
            connection,
            reusable,
            idle: self.idle.clone(),
            reuse: self.reuse,
        };
        (response, lease)
    }
    /// A new connection to the peer, its certificate checked against the pin,
    /// presenting `identity`.
    async fn connect(&self, identity: Arc<rustls::sign::CertifiedKey>) -> Result<Connection> {
        let host = self.origin.host_str().unwrap();
        let port = self.origin.port_or_known_default().unwrap();
        let socket = tokio::net::TcpStream::connect((host, port))
            .await
            .map_err(|error| {
                eprintln!("node-control transport: connecting: {error}");
                Error::new(StatusCode::BAD_GATEWAY, "peer unavailable")
            })?;
        send_at_once(&socket);
        let tls = tokio_rustls::TlsConnector::from(self.tls.clone())
            .connect(self.server_name.clone(), socket)
            .await
            .map_err(|error| {
                eprintln!("node-control transport: TLS handshake: {error}");
                Error::new(StatusCode::BAD_GATEWAY, "peer TLS identity rejected")
            })?;
        // The pin names the peer's certificate or, so that it survives the
        // peer renewing it over the same key, its key (`key_pin`).
        let leaf = tls.get_ref().1.peer_certificates().and_then(|c| c.first());
        if !leaf.is_some_and(|leaf| {
            digest(leaf.as_ref()) == self.pin
                || key_pin(leaf.as_ref()).as_deref() == Some(self.pin.as_str())
        }) {
            return Err(Error::new(
                StatusCode::BAD_GATEWAY,
                "peer certificate pin mismatch",
            ));
        }
        let (sender, connection) = hyper::client::conn::http1::Builder::new()
            .max_buf_size(64 * 1024)
            .handshake(TokioIo::new(tls))
            .await
            .map_err(|error| {
                eprintln!("node-control transport: HTTP handshake: {error:?}");
                Error::new(StatusCode::BAD_GATEWAY, "peer connection failed")
            })?;
        // Aborting this driver whenever a lease is dropped unreleased closes
        // timed-out or oversized peers.
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        let now = tokio::time::Instant::now();
        Ok(Connection {
            sender,
            _driver: Driver(driver),
            opened: now,
            idle_since: now,
            identity,
        })
    }
    /// Relay one request to the peer and return its status, headers and body
    /// (at most `limit` bytes) whatever the status. Hop-by-hop headers are dropped.
    pub async fn forward(
        &self,
        method: &str,
        path: &str,
        headers: &[(String, String)],
        body: Bytes,
        limit: usize,
    ) -> Result<(u16, Vec<(String, String)>, Vec<u8>)> {
        const HOP: &[&str] = &[
            "connection",
            "host",
            "keep-alive",
            "proxy-connection",
            "te",
            "trailer",
            "transfer-encoding",
            "upgrade",
            "content-length",
        ];
        let kept: Vec<(&str, String)> = headers
            .iter()
            .filter(|(name, _)| !HOP.iter().any(|hop| name.eq_ignore_ascii_case(hop)))
            .map(|(name, value)| (name.as_str(), value.clone()))
            .collect();
        tokio::time::timeout(Duration::from_secs(70), async {
            let (response, lease) = self.response(method, path, body, &kept).await?;
            let status = response.status().as_u16();
            let headers = response
                .headers()
                .iter()
                .filter(|(name, _)| !HOP.contains(&name.as_str()))
                .filter_map(|(name, value)| {
                    Some((name.as_str().to_owned(), value.to_str().ok()?.to_owned()))
                })
                .collect();
            let mut body = response.into_body();
            let mut out = Vec::new();
            while let Some(frame) = body.frame().await {
                let frame = frame
                    .map_err(|_| Error::new(StatusCode::BAD_GATEWAY, "invalid peer response"))?;
                if let Ok(data) = frame.into_data() {
                    if data.len() > limit.saturating_sub(out.len()) {
                        return Err(Error::new(
                            StatusCode::BAD_GATEWAY,
                            "peer response too large",
                        ));
                    }
                    out.extend_from_slice(&data);
                }
            }
            lease.release();
            Ok((status, headers, out))
        })
        .await
        .map_err(|_| Error::new(StatusCode::BAD_GATEWAY, "peer request timed out"))?
    }
    pub async fn json(&self, method: &str, path: &str, value: Option<&Value>) -> Result<Value> {
        serde_json::from_slice(&self.request(method, path, value, 32 * 1024 * 1024).await?)
            .map_err(|_| Error::new(StatusCode::BAD_GATEWAY, "invalid peer JSON"))
    }
}

/// Validate a caller-supplied certificate without trusting it for other origins.
pub fn validate_ca_der(der: &[u8]) -> Result<()> {
    rustls::RootCertStore::empty()
        .add(rustls::pki_types::CertificateDer::from(der.to_vec()))
        .map_err(|_| Error::invalid("invalid CA certificate"))
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn a_failed_accept_is_waited_out_not_the_end_of_the_listener() {
        let started = tokio::time::Instant::now();
        let failed: std::io::Result<u8> = Err(std::io::Error::other("too many open files"));
        assert_eq!(super::keep_serving(failed).await, None);
        assert!(started.elapsed() >= super::ACCEPT_BACKOFF);
        assert_eq!(super::keep_serving(Ok(7u8)).await, Some(7));
    }
    use super::*;

    /// A CA, a server certificate for 127.0.0.1 and a client certificate,
    /// under `dir`: the server certificate's pin.
    fn identities(dir: &Path) -> String {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca = ca_params.self_signed(&ca_key).unwrap();
        std::fs::write(dir.join("ca.pem"), ca.pem()).unwrap();
        let mut pin = String::new();
        for (name, usage) in [
            ("server", rcgen::ExtendedKeyUsagePurpose::ServerAuth),
            ("client", rcgen::ExtendedKeyUsagePurpose::ClientAuth),
        ] {
            let key = rcgen::KeyPair::generate().unwrap();
            let mut params = rcgen::CertificateParams::new(vec!["127.0.0.1".to_owned()]).unwrap();
            params.extended_key_usages = vec![usage];
            let cert = params.signed_by(&key, &ca, &ca_key).unwrap();
            std::fs::write(dir.join(format!("{name}.pem")), cert.pem()).unwrap();
            std::fs::write(dir.join(format!("{name}.key")), key.serialize_pem()).unwrap();
            if name == "server" {
                pin = crate::model::digest(cert.der());
            }
        }
        pin
    }

    /// A TCP relay to `server` that counts the connections made through it
    /// and can cut them all.
    struct Relay {
        address: std::net::SocketAddr,
        server: std::net::SocketAddr,
        connections: Arc<std::sync::atomic::AtomicUsize>,
        live: Arc<std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>>,
    }
    /// Copies `from` to `to`, each read `delay` late, as a link that takes
    /// `delay` one way.
    async fn delayed(
        mut from: tokio::net::tcp::OwnedReadHalf,
        mut to: tokio::net::tcp::OwnedWriteHalf,
        delay: Duration,
    ) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (sent, mut arriving) = tokio::sync::mpsc::unbounded_channel();
        let reader = tokio::spawn(async move {
            let mut buffer = vec![0; 64 * 1024];
            while let Ok(read @ 1..) = from.read(&mut buffer).await {
                let due = tokio::time::Instant::now() + delay;
                if sent.send((due, buffer[..read].to_vec())).is_err() {
                    break;
                }
            }
        });
        while let Some((due, bytes)) = arriving.recv().await {
            tokio::time::sleep_until(due).await;
            if to.write_all(&bytes).await.is_err() {
                break;
            }
        }
        let _ = to.shutdown().await;
        reader.abort();
    }
    impl Relay {
        async fn delaying(server: std::net::SocketAddr, delay: Duration) -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let connections = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let live = Arc::new(std::sync::Mutex::new(Vec::new()));
            let (counted, held) = (connections.clone(), live.clone());
            tokio::spawn(async move {
                while let Ok((mut inbound, _)) = listener.accept().await {
                    counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    held.lock().unwrap().push(tokio::spawn(async move {
                        let mut outbound = tokio::net::TcpStream::connect(server).await.unwrap();
                        if delay.is_zero() {
                            let _ =
                                tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                            return;
                        }
                        send_at_once(&inbound);
                        send_at_once(&outbound);
                        let (inbound_read, inbound_write) = inbound.into_split();
                        let (outbound_read, outbound_write) = outbound.into_split();
                        tokio::join!(
                            delayed(inbound_read, outbound_write, delay),
                            delayed(outbound_read, inbound_write, delay),
                        );
                    }));
                }
            });
            Self {
                address,
                server,
                connections,
                live,
            }
        }
        fn connections(&self) -> usize {
            self.connections.load(std::sync::atomic::Ordering::SeqCst)
        }
        fn cut(&self) {
            for connection in self.live.lock().unwrap().drain(..) {
                connection.abort();
            }
        }
    }

    /// A server answering `/echo` with its body's length behind a [`Relay`],
    /// and a client of it through the relay.
    async fn served(router: Router) -> (Relay, Client, tempfile::TempDir) {
        served_over(router, Duration::ZERO).await
    }
    /// [`served`] over a link that takes `delay` one way.
    async fn served_over(router: Router, delay: Duration) -> (Relay, Client, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let pin = identities(dir.path());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = listener.local_addr().unwrap();
        let config = server_config(
            &dir.path().join("server.pem"),
            &dir.path().join("server.key"),
            Some(&dir.path().join("ca.pem")),
        )
        .unwrap();
        tokio::spawn(serve_tls(listener, config, router));
        let relay = Relay::delaying(server, delay).await;
        let client = Client::new(
            &format!("https://127.0.0.1:{}", relay.address.port()),
            &dir.path().join("ca.pem"),
            &dir.path().join("client.pem"),
            &dir.path().join("client.key"),
            &pin,
        )
        .unwrap();
        let client = Client {
            reuse: CLIENT_REUSE,
            ..client
        };
        (relay, client, dir)
    }

    fn echo() -> Router {
        Router::new().route(
            "/echo",
            axum::routing::post(|body: Bytes| async move { body.len().to_string() }),
        )
    }

    async fn call(client: &Client, size: usize) -> Result<Vec<u8>> {
        client
            .request_bytes("POST", "/echo", &vec![b'x'; size], &[], 1024)
            .await
    }

    #[test]
    fn handshakes_and_served_connections_are_budgeted_apart_and_for_each_peer() {
        let ip = |last: u8| std::net::IpAddr::from([10, 0, 0, last]);
        // 8 handshakes (2 a peer), 4 served (2 a peer).
        let admission = Admission::new(8, 4, 2);
        // One address stalls its handshakes: it gets its share, no more.
        let stalled: Vec<_> = (0..4).filter_map(|_| admission.handshake(ip(1))).collect();
        assert_eq!(stalled.len(), 2);
        // Others are served all the same, up to their own share.
        let mut served = Vec::new();
        for peer in [2, 3] {
            for _ in 0..2 {
                let mut slot = admission.handshake(ip(peer)).unwrap();
                assert!(slot.established());
                served.push(slot);
            }
        }
        let mut over = admission.handshake(ip(2)).unwrap();
        assert!(!over.established(), "a peer's share of served connections");
        drop(over);
        let mut full = admission.handshake(ip(4)).unwrap();
        assert!(!full.established(), "the listener's served connections");
        drop(full);
        // A place given back is there to take, and nothing is left counted.
        served.pop();
        let mut next = admission.handshake(ip(4)).unwrap();
        assert!(next.established());
        drop((stalled, served, next));
        let held = admission.0.held.lock().unwrap();
        assert_eq!((held.handshakes, held.serving, held.peers.len()), (0, 0, 0));
        drop(held);
        // An IPv6 peer is its /64, and a mapped address the IPv4 one.
        let admission = Admission::new(4, 4, 4);
        let v6 = |tail: u16| std::net::IpAddr::from([0x2001, 0xdb8, 0, 1, 0, 0, 0, tail]);
        let _one = admission.handshake(v6(1)).unwrap();
        assert!(admission.handshake(v6(2)).is_none());
        assert!(
            admission
                .handshake("2001:db8:0:2::1".parse().unwrap())
                .is_some()
        );
        let _mapped = admission
            .handshake("::ffff:10.0.0.9".parse().unwrap())
            .unwrap();
        assert!(admission.handshake(ip(9)).is_none());
    }

    #[tokio::test]
    async fn sockets_that_never_finish_a_handshake_leave_other_peers_served() {
        let (relay, client, _dir) = served(echo()).await;
        // More idle sockets than the listener has handshakes for, from another
        // address than the client's: none sends a byte.
        let server = relay.server;
        let mut idle = Vec::new();
        for _ in 0..HANDSHAKES + 32 {
            let socket = tokio::net::TcpSocket::new_v4().unwrap();
            socket.bind("127.0.0.2:0".parse().unwrap()).unwrap();
            idle.push(socket.connect(server).await.unwrap());
        }
        for size in [1, 2, 3] {
            assert_eq!(
                call(&client, size).await.unwrap(),
                size.to_string().as_bytes()
            );
        }
        drop(idle);
    }

    #[tokio::test]
    async fn requests_one_after_another_share_a_connection() {
        let (relay, client, _dir) = served(echo()).await;
        for size in [0, 10, 100_000, 7] {
            assert_eq!(
                call(&client, size).await.unwrap(),
                size.to_string().as_bytes()
            );
        }
        // Clones share their connections, as the agent and its forwarders do.
        assert_eq!(call(&client.clone(), 3).await.unwrap(), b"3");
        assert_eq!(relay.connections(), 1);
    }

    #[tokio::test]
    async fn requests_at_once_each_get_a_connection_and_then_share_them() {
        let (relay, client, _dir) = served(echo()).await;
        let answers = tokio::join!(
            call(&client, 0),
            call(&client, 1),
            call(&client, 2),
            call(&client, 3)
        );
        let answers = [answers.0, answers.1, answers.2, answers.3];
        for (n, answer) in answers.into_iter().enumerate() {
            assert_eq!(answer.unwrap(), n.to_string().as_bytes());
        }
        let opened = relay.connections();
        assert!((1..=4).contains(&opened), "{opened} connections");
        for n in 0..4 {
            assert_eq!(call(&client, n).await.unwrap(), n.to_string().as_bytes());
        }
        assert_eq!(relay.connections(), opened);
    }

    #[tokio::test]
    async fn a_connection_the_peer_closed_is_replaced() {
        let (relay, client, _dir) = served(echo()).await;
        assert_eq!(call(&client, 1).await.unwrap(), b"1");
        relay.cut();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(call(&client, 2).await.unwrap(), b"2");
        assert_eq!(relay.connections(), 2);
    }

    #[tokio::test]
    async fn a_peer_that_closes_after_a_response_gets_a_new_connection_each_time() {
        let router = echo().layer(axum::middleware::map_response(
            |mut response: axum::response::Response| async move {
                response.headers_mut().insert(
                    hyper::header::CONNECTION,
                    hyper::header::HeaderValue::from_static("close"),
                );
                response
            },
        ));
        let (relay, client, _dir) = served(router).await;
        for n in 0..3 {
            assert_eq!(call(&client, n).await.unwrap(), n.to_string().as_bytes());
        }
        assert_eq!(relay.connections(), 3);
    }

    #[tokio::test]
    async fn a_connection_past_its_reuse_window_takes_no_more_requests() {
        let (relay, mut client, _dir) = served(echo()).await;
        client.reuse = Duration::ZERO;
        for n in 0..3 {
            assert_eq!(call(&client, n).await.unwrap(), n.to_string().as_bytes());
        }
        assert_eq!(relay.connections(), 3);
    }

    #[tokio::test]
    async fn shutdown_closes_idle_connections_rather_than_waiting_for_them() {
        let dir = tempfile::tempdir().unwrap();
        let pin = identities(dir.path());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let config = server_config(
            &dir.path().join("server.pem"),
            &dir.path().join("server.key"),
            Some(&dir.path().join("ca.pem")),
        )
        .unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(serve_tls_until(listener, config, echo(), async {
            let _ = stopped.await;
        }));
        let client = Client::new(
            &format!("https://127.0.0.1:{port}"),
            &dir.path().join("ca.pem"),
            &dir.path().join("client.pem"),
            &dir.path().join("client.key"),
            &pin,
        )
        .unwrap();
        let client = Client {
            reuse: CLIENT_REUSE,
            ..client
        };
        assert_eq!(call(&client, 1).await.unwrap(), b"1");
        // The client keeps that connection idle; shutdown need not wait out
        // its reuse window.
        let at = std::time::Instant::now();
        stop.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("shutdown waited for an idle connection")
            .unwrap()
            .unwrap();
        assert!(at.elapsed() < Duration::from_secs(2), "{:?}", at.elapsed());
    }

    /// A handler that answers without reading the request's body leaves the
    /// server unable to take another request on the connection. Over a link
    /// with a round trip, the client sends its next request before the close
    /// arrives, so the server says so in the response.
    #[tokio::test]
    async fn a_request_whose_body_went_unread_ends_its_connection_and_the_next_succeeds() {
        let router = echo().route(
            "/refuse",
            axum::routing::post(|| async { StatusCode::UNAUTHORIZED }),
        );
        let (relay, client, _dir) = served_over(router, Duration::from_millis(12)).await;
        for size in [10, 2_000, 20_000] {
            let (status, _, _) = client
                .forward("POST", "/refuse", &[], Bytes::from(vec![b'x'; size]), 1024)
                .await
                .unwrap();
            assert_eq!(status, 401);
            assert_eq!(
                call(&client, size).await.unwrap(),
                size.to_string().as_bytes()
            );
        }
        assert_eq!(relay.connections(), 4);
    }

    /// A kept connection the peer closes just as the next request goes out
    /// loses that request before any response: one safe to send twice, as a
    /// workflow API write with its idempotency key is, goes again, once, on
    /// a new connection.
    #[tokio::test]
    async fn a_request_a_kept_connection_lost_goes_again_on_a_new_one() {
        let (relay, client, _dir) = served_over(echo(), Duration::from_millis(12)).await;
        for n in 1..=5 {
            let key = [("Idempotency-Key", format!("write-{n}"))];
            let answer = client
                .request_bytes("POST", "/echo", &vec![b'x'; n], &key, 1024)
                .await;
            assert_eq!(answer.unwrap(), n.to_string().as_bytes());
            relay.cut();
        }
        assert_eq!(relay.connections(), 5);
    }

    #[tokio::test]
    async fn a_warmed_client_sends_its_next_request_on_the_connection_it_made() {
        let (relay, client, _dir) = served(echo()).await;
        client.warm().await.unwrap();
        // Warm already: no second connection.
        client.warm().await.unwrap();
        assert_eq!(relay.connections(), 1);
        assert_eq!(call(&client, 5).await.unwrap(), b"5");
        assert_eq!(relay.connections(), 1);
    }

    #[tokio::test]
    async fn requests_without_a_body_keep_their_connection() {
        let router = Router::new().route("/hello", axum::routing::get(|| async { "hello" }));
        let (relay, client, _dir) = served(router).await;
        for _ in 0..3 {
            assert_eq!(
                client.request("GET", "/hello", None, 64).await.unwrap(),
                b"hello"
            );
        }
        assert_eq!(relay.connections(), 1);
    }

    #[tokio::test]
    async fn a_client_keeps_no_connection_unless_reuse_is_on() {
        assert_eq!(reuse_window(), Duration::ZERO);
    }

    #[tokio::test]
    async fn a_failed_response_closes_its_connection() {
        let (relay, client, _dir) = served(echo()).await;
        assert!(
            client
                .request_bytes("GET", "/missing", &[], &[], 1024)
                .await
                .is_err()
        );
        assert_eq!(call(&client, 1).await.unwrap(), b"1");
        assert_eq!(relay.connections(), 2);
    }

    /// Over a link with a 25 ms round trip, as between a node and a control
    /// plane in another datacenter, a request on a connection already made
    /// takes one round trip, where a new connection's also waits for the TLS
    /// handshake (and, over a real link, TCP's). A timing check, so opt-in.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "timing: run with --ignored on an idle host"]
    async fn a_request_on_a_kept_connection_takes_one_round_trip() {
        let rtt = Duration::from_millis(25);
        let median = |mut took: Vec<Duration>| {
            took.sort();
            took[took.len() / 2]
        };
        let timed = |client: Client| async move {
            let mut took = Vec::new();
            for n in 0..10 {
                let at = std::time::Instant::now();
                assert_eq!(call(&client, n).await.unwrap(), n.to_string().as_bytes());
                took.push(at.elapsed());
            }
            took
        };
        let (_relay, mut fresh, _dir) = served_over(echo(), rtt / 2).await;
        fresh.reuse = Duration::ZERO;
        let fresh = median(timed(fresh).await);
        let (relay, kept, _dir) = served_over(echo(), rtt / 2).await;
        let kept = median(timed(kept).await);
        eprintln!(
            "median request: {:.1} ms on a new connection, {:.1} ms on a kept one",
            fresh.as_secs_f64() * 1000.0,
            kept.as_secs_f64() * 1000.0
        );
        assert_eq!(relay.connections(), 1);
        assert!(fresh >= rtt * 2, "{fresh:?}");
        assert!(kept < rtt * 2, "{kept:?}");
        assert!(kept * 2 < fresh, "{kept:?} against {fresh:?}");
    }

    #[tokio::test]
    async fn connections_send_without_waiting_for_an_acknowledgement() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let connected = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (accepted, _) = listener.accept().await.unwrap();
        for socket in [&connected, &accepted] {
            assert!(!socket.nodelay().unwrap());
            send_at_once(socket);
            assert!(socket.nodelay().unwrap());
        }
    }

    /// A request body crosses without waiting on the peer's delayed ACK: a
    /// body that ends in a short segment is not held back until the segment
    /// before it is acknowledged (Nagle), which on Linux costs 40 ms a call.
    /// A timing check, so opt-in: `cargo test -- --ignored` on Linux.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "timing: run with --ignored on an idle Linux host"]
    async fn a_request_body_crosses_without_waiting_for_a_delayed_ack() {
        let dir = tempfile::tempdir().unwrap();
        let pin = identities(dir.path());
        let router = Router::new().route(
            "/echo",
            axum::routing::post(|body: Bytes| async move { body.len().to_string() }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let config = server_config(
            &dir.path().join("server.pem"),
            &dir.path().join("server.key"),
            Some(&dir.path().join("ca.pem")),
        )
        .unwrap();
        tokio::spawn(serve_tls(listener, config, router));
        let client = Client::new(
            &format!("https://127.0.0.1:{port}"),
            &dir.path().join("ca.pem"),
            &dir.path().join("client.pem"),
            &dir.path().join("client.key"),
            &pin,
        )
        .unwrap();
        let mut slowest = Duration::ZERO;
        for size in (1..=40).map(|n| n * 4_000) {
            let body = vec![b'x'; size];
            let at = std::time::Instant::now();
            let answer = client
                .request_bytes("POST", "/echo", &body, &[], 1024)
                .await
                .unwrap();
            let took = at.elapsed();
            assert_eq!(answer, size.to_string().as_bytes());
            eprintln!("{size:>7} bytes: {:.1} ms", took.as_secs_f64() * 1000.0);
            slowest = slowest.max(took);
        }
        assert!(
            slowest < Duration::from_millis(30),
            "a call waited {slowest:?}: a body held back for an acknowledgement"
        );
    }
}
