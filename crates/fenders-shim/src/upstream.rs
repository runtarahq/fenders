//! The run channel's client: HTTPS to the spec's endpoint, the server
//! verified against the spec's trust, every request carrying the per-launch
//! credential as a bearer token.
//!
//! One HTTP/2 connection shared by all calls when the endpoint offers it,
//! else a few kept HTTP/1.1 connections. A request that could not be sent
//! (connect or TLS failure, or a kept connection found closed) is retried with
//! backoff for [`PATIENCE`]; one that reached the endpoint is never repeated.
use crate::spec::Channel;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    Request, Response, StatusCode,
    body::Bytes,
    header::{AUTHORIZATION, HOST, HeaderMap, HeaderValue},
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::ServerName;
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

/// How long a call waits for the endpoint to become reachable before it
/// fails back to the guest as retryable.
pub const PATIENCE: Duration = Duration::from_secs(30);
/// How long connecting to the endpoint may take, its TLS and HTTP handshakes
/// included, and how long one call may take in all.
const CONNECT: Duration = Duration::from_secs(10);
const EXCHANGE: Duration = Duration::from_secs(60);

/// An HTTP/2 connection that notices an endpoint gone silent under a call:
/// a ping every 20 seconds while a request is in flight, answered in 20.
fn http2() -> hyper::client::conn::http2::Builder<TokioExecutor> {
    let mut builder = hyper::client::conn::http2::Builder::new(TokioExecutor::new());
    builder
        .timer(hyper_util::rt::TokioTimer::new())
        .keep_alive_interval(Duration::from_secs(20))
        .keep_alive_timeout(Duration::from_secs(20));
    builder
}
/// Kept HTTP/1.1 connections.
const IDLE: usize = 4;
/// The largest response body relayed.
pub const RESPONSE_LIMIT: usize = 8 * 1024 * 1024;

pub struct Upstream {
    tls: tokio_rustls::TlsConnector,
    server_name: ServerName<'static>,
    host: String,
    port: u16,
    authority: HeaderValue,
    prefix: String,
    pin: Option<String>,
    bearer: HeaderValue,
    h2: tokio::sync::Mutex<Option<hyper::client::conn::http2::SendRequest<Full<Bytes>>>>,
    h1: Mutex<Vec<hyper::client::conn::http1::SendRequest<Full<Bytes>>>>,
}

/// What went wrong sending a request upstream.
pub enum Failure {
    /// Never reached the endpoint within [`PATIENCE`].
    Unreachable,
    /// Reached it, but the exchange broke or the answer was over the limit.
    Broken,
}

enum Sender {
    H2(hyper::client::conn::http2::SendRequest<Full<Bytes>>),
    H1(hyper::client::conn::http1::SendRequest<Full<Bytes>>, bool),
}

impl Upstream {
    pub fn new(channel: &Channel) -> Result<Self, String> {
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut channel.ca_pem.as_bytes()) {
            roots
                .add(cert.map_err(|_| "channel trust: invalid CA PEM".to_owned())?)
                .map_err(|_| "channel trust: invalid CA certificate".to_owned())?;
        }
        if roots.is_empty() {
            return Err("channel trust: no CA certificate".into());
        }
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|_| "TLS configuration".to_owned())?
        .with_root_certificates(roots)
        .with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let host = channel.endpoint.host_str().unwrap_or_default().to_owned();
        let port = channel.endpoint.port_or_known_default().unwrap_or(443);
        let bare = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_owned();
        let server_name = ServerName::try_from(channel.server_name.clone().unwrap_or(bare.clone()))
            .map_err(|_| "channel endpoint: invalid TLS server name".to_owned())?;
        let authority = if channel.endpoint.port().is_some() {
            format!("{host}:{port}")
        } else {
            host.clone()
        };
        let mut bearer = HeaderValue::from_str(&format!("Bearer {}", channel.credential))
            .map_err(|_| "channel credential is not a header value".to_owned())?;
        bearer.set_sensitive(true);
        Ok(Self {
            tls: tokio_rustls::TlsConnector::from(Arc::new(config)),
            server_name,
            host: bare,
            port,
            authority: HeaderValue::from_str(&authority)
                .map_err(|_| "channel endpoint authority".to_owned())?,
            prefix: channel.endpoint.path().trim_end_matches('/').to_owned(),
            pin: channel.pin.clone(),
            bearer,
            h2: tokio::sync::Mutex::new(None),
            h1: Mutex::new(Vec::new()),
        })
    }

    /// A verified TLS connection to the endpoint, and whether it speaks HTTP/2.
    async fn tls(
        &self,
    ) -> Result<(tokio_rustls::client::TlsStream<tokio::net::TcpStream>, bool), ()> {
        // An endpoint that takes the connection and says nothing, or a path
        // to it that drops packets, must not hold a caller for ever: a run
        // that has ended has no other clock running.
        let tls = tokio::time::timeout(CONNECT, async {
            let tcp = tokio::net::TcpStream::connect((self.host.as_str(), self.port))
                .await
                .map_err(|_| ())?;
            let _ = tcp.set_nodelay(true);
            let tls = self
                .tls
                .connect(self.server_name.clone(), tcp)
                .await
                .map_err(|_| ())?;
            Ok::<_, ()>(tls)
        })
        .await
        .map_err(|_| ())??;
        let (_, session) = tls.get_ref();
        if let Some(pin) = &self.pin {
            let leaf = session
                .peer_certificates()
                .and_then(|c| c.first())
                .ok_or(())?;
            if fenders_node_protocol::transport::key_pin(leaf).as_deref() != Some(pin.as_str()) {
                tracing::error!("run channel endpoint does not match its pin");
                return Err(());
            }
        }
        let h2 = session.alpn_protocol() == Some(b"h2");
        Ok((tls, h2))
    }

    async fn connect(&self) -> Result<Sender, ()> {
        let (tls, h2) = self.tls().await?;
        let io = TokioIo::new(tls);
        if h2 {
            let (sender, connection) = tokio::time::timeout(CONNECT, http2().handshake(io))
                .await
                .map_err(|_| ())?
                .map_err(|_| ())?;
            tokio::spawn(connection);
            Ok(Sender::H2(sender))
        } else {
            let (sender, connection) =
                tokio::time::timeout(CONNECT, hyper::client::conn::http1::handshake(io))
                    .await
                    .map_err(|_| ())?
                    .map_err(|_| ())?;
            tokio::spawn(connection);
            Ok(Sender::H1(sender, false))
        }
    }

    /// A connection of its own for requests whose bodies are streamed (an
    /// HTTP run's): HTTP/2 only, `None` when the endpoint does not offer it.
    /// The calls every run makes do not use it.
    pub async fn streaming<B>(
        &self,
    ) -> Result<Option<hyper::client::conn::http2::SendRequest<B>>, ()>
    where
        B: hyper::body::Body + Send + Unpin + 'static,
        B::Data: Send,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let (tls, h2) = self.tls().await?;
        if !h2 {
            return Ok(None);
        }
        let (sender, connection) =
            tokio::time::timeout(CONNECT, http2().handshake(TokioIo::new(tls)))
                .await
                .map_err(|_| ())?
                .map_err(|_| ())?;
        tokio::spawn(connection);
        Ok(Some(sender))
    }

    /// A request to `path_and_query` under the endpoint, for a
    /// [`streaming`](Self::streaming) connection, with the credential added.
    pub fn request(
        &self,
        method: hyper::Method,
        path_and_query: &str,
    ) -> hyper::http::request::Builder {
        Request::builder()
            .method(method)
            .uri(format!(
                "https://{}{}{path_and_query}",
                self.authority.to_str().unwrap_or_default(),
                self.prefix
            ))
            .header(AUTHORIZATION, self.bearer.clone())
    }

    /// A sender ready for a request: the shared HTTP/2 connection, a kept
    /// HTTP/1.1 one (marked reused), or a new connection.
    async fn sender(&self) -> Result<Sender, ()> {
        {
            let mut h2 = self.h2.lock().await;
            if let Some(sender) = h2.as_mut() {
                if !sender.is_closed() && sender.ready().await.is_ok() {
                    return Ok(Sender::H2(sender.clone()));
                }
                *h2 = None;
            }
        }
        loop {
            let kept = self.h1.lock().unwrap_or_else(|e| e.into_inner()).pop();
            let Some(mut sender) = kept else { break };
            if !sender.is_closed() && sender.ready().await.is_ok() {
                return Ok(Sender::H1(sender, true));
            }
        }
        // Hold the HTTP/2 slot while connecting, so concurrent first calls
        // share one connection rather than each making their own.
        let mut h2 = self.h2.lock().await;
        if let Some(sender) = h2.as_ref().filter(|s| !s.is_closed()) {
            return Ok(Sender::H2(sender.clone()));
        }
        let sender = self.connect().await?;
        if let Sender::H2(shared) = &sender {
            *h2 = Some(shared.clone());
        }
        Ok(sender)
    }

    /// Sends `method path` with `headers` and `body` to the endpoint, with the
    /// credential added, and returns the whole answer.
    pub async fn send(
        &self,
        method: &hyper::Method,
        path_and_query: &str,
        headers: &HeaderMap,
        body: Bytes,
    ) -> Result<(StatusCode, HeaderMap, Bytes), Failure> {
        // The runtime's clock, as the waits below are.
        let started = tokio::time::Instant::now();
        let mut delay = Duration::from_millis(100);
        loop {
            let sent = match self.sender().await {
                Err(()) => Err(true),
                Ok(sender) => {
                    self.exchange(sender, method, path_and_query, headers, body.clone())
                        .await
                }
            };
            match sent {
                Ok(answer) => return Ok(answer),
                Err(false) => return Err(Failure::Broken),
                Err(true) if started.elapsed() + delay > PATIENCE => {
                    return Err(Failure::Unreachable);
                }
                Err(true) => {
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(Duration::from_secs(5));
                }
            }
        }
    }

    /// `Err(true)`: the request was not sent and may be retried.
    async fn exchange(
        &self,
        sender: Sender,
        method: &hyper::Method,
        path_and_query: &str,
        headers: &HeaderMap,
        body: Bytes,
    ) -> Result<(StatusCode, HeaderMap, Bytes), bool> {
        let path = format!("{}{}", self.prefix, path_and_query);
        let mut builder = Request::builder().method(method.clone());
        builder = match &sender {
            Sender::H2(_) => builder.uri(format!(
                "https://{}{path}",
                self.authority.to_str().unwrap_or_default()
            )),
            Sender::H1(..) => builder.uri(path).header(HOST, self.authority.clone()),
        };
        let mut request = builder.body(Full::new(body)).map_err(|_| false)?;
        for (name, value) in headers {
            request.headers_mut().append(name, value.clone());
        }
        request
            .headers_mut()
            .insert(AUTHORIZATION, self.bearer.clone());
        // The whole of a call, its answer included, within a bound: these
        // are short calls (a streamed body has a connection of its own).
        let exchanged = tokio::time::timeout(EXCHANGE, async {
            let (response, h1) = match sender {
                Sender::H2(mut sender) => (sender.send_request(request).await, None),
                Sender::H1(mut sender, reused) => match sender.send_request(request).await {
                    // A kept connection the endpoint had closed before taking
                    // the request: send it again on a fresh one.
                    Err(e) if reused && (e.is_canceled() || e.is_closed()) => return Err(true),
                    other => (other, Some(sender)),
                },
            };
            let response: Response<hyper::body::Incoming> =
                response.map_err(|e| e.is_canceled())?;
            let (parts, body) = response.into_parts();
            let body = Limited::new(body, RESPONSE_LIMIT)
                .collect()
                .await
                .map_err(|_| false)?
                .to_bytes();
            if let Some(sender) = h1 {
                let mut idle = self.h1.lock().unwrap_or_else(|e| e.into_inner());
                if idle.len() < IDLE && !sender.is_closed() {
                    idle.push(sender);
                }
            }
            Ok((parts.status, parts.headers, body))
        })
        .await;
        match exchanged {
            Ok(result) => result,
            // It may have reached the endpoint: not sent again. The shared
            // connection is not used again either.
            Err(_) => {
                *self.h2.lock().await = None;
                Err(false)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A certificate to trust; no test completes a handshake with it.
    const CA: &str = "-----BEGIN CERTIFICATE-----
MIIBhTCCASugAwIBAgIUYaF42j7ua7pXavHe0+2yvB08+/UwCgYIKoZIzj0EAwIw
FzEVMBMGA1UEAwwMZmVuZGVycy10ZXN0MCAXDTI2MTExNzE3NDU0OVoYDzIxMjYx
MDI0MTc0NTQ5WjAXMRUwEwYDVQQDDAxmZW5kZXJzLXRlc3QwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAARJp0rgitORJVylAtIos3tDmTHeSJyK4/XKr3qgJePjgVk6
VwZnQ1/b9ZCPKOLzSfTTYngW39Rqhha8sk2qI4ylo1MwUTAdBgNVHQ4EFgQU4wZp
UD0SKi4JiFbNnQdoJNJClpkwHwYDVR0jBBgwFoAU4wZpUD0SKi4JiFbNnQdoJNJC
lpkwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiBN63u7DM2edvt/
9X7mEylZHJsl/kjPGbjkzBfxe3/n1wIhAKLSvUQVCFgxKlqtk7cjWRACSGSGwKtx
9vjajYWSdVJ5
-----END CERTIFICATE-----
";

    #[tokio::test(start_paused = true)]
    async fn an_endpoint_that_accepts_and_says_nothing_does_not_hold_a_call_for_ever() {
        // It takes connections and never answers the TLS hello.
        let silent = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = silent.local_addr().unwrap().port();
        let held = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((socket, _)) = silent.accept().await {
                held.push(socket);
            }
        });
        let upstream = Upstream::new(&crate::spec::Channel {
            endpoint: format!("https://127.0.0.1:{port}").parse().unwrap(),
            credential: "credential".into(),
            ca_pem: CA.into(),
            pin: None,
            server_name: None,
        })
        .unwrap();
        let started = tokio::time::Instant::now();
        let failed = upstream
            .send(
                &hyper::Method::POST,
                "/v1/run/outcome",
                &HeaderMap::new(),
                Bytes::new(),
            )
            .await;
        assert!(matches!(failed, Err(Failure::Unreachable)));
        // Given up within its patience and one more attempt, not never.
        assert!(
            started.elapsed() <= PATIENCE + CONNECT + Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );
        assert!(upstream.streaming::<Full<Bytes>>().await.is_err());
        held.abort();
    }
}
