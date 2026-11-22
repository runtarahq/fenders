//! The guest's host-bound origin: HTTP/2 from the runtime over the stream the
//! VMM holds, each request relayed to the run channel with the credential
//! added. The guest never sees the credential, and nothing it sends can name
//! another run: authorization, binding and `fenders-*` headers are dropped.
//!
//! The answer is handed to the guest as the endpoint sends it, with no
//! deadline of the relay's own, so a call may wait as long as its work
//! takes and a streamed answer reaches the guest as it is made. An endpoint
//! that does not offer HTTP/2 is answered the old way: whole, within a
//! minute, at most [`RESPONSE_LIMIT`](crate::upstream::RESPONSE_LIMIT).
use crate::upstream::{Failure, Upstream};
use http_body_util::{BodyExt, Full, Limited, combinators::UnsyncBoxBody};
use hyper::{
    Method, Request, Response, StatusCode,
    body::{Bytes, Incoming},
    header::{self, HeaderMap, HeaderName, HeaderValue},
    service::service_fn,
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::{
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

type BoxError = Box<dyn std::error::Error + Send + Sync>;
/// An answer's body as the guest is given it.
type Answer = UnsyncBoxBody<Bytes, BoxError>;

const REQUEST_LIMIT: usize = 4 * 1024 * 1024;
/// The guest's calls relayed at once, unless its launch says
/// (`host_origin_concurrency`, 1 to 64). Each holds its request body, at
/// most [`REQUEST_LIMIT`], while it is sent; answers are not held.
pub const CONCURRENCY: usize = 16;
/// Where a guest posts its run's outcome.
pub const OUTCOME_PATH: &str = "/v1/run/outcome";
/// The header that carries a run's trace id on every call.
pub const TRACE_HEADER: &str = "runtara-trace-id";

pub struct Relay {
    pub upstream: Upstream,
    /// Whether the launch gave its guest a host-bound origin. Without one no
    /// component can name the relay, and nothing asked of it is forwarded:
    /// only code that had left the component's sandbox could be asking.
    pub guest: bool,
    pub trace_id: Option<HeaderValue>,
    /// Set once the endpoint accepted the guest's own outcome.
    pub outcome_posted: AtomicBool,
}

/// Headers that belong to one connection, or that only the shim may set.
fn dropped(name: &HeaderName) -> bool {
    let name = name.as_str();
    matches!(
        name,
        "authorization"
            | "proxy-authorization"
            | "cookie"
            | "host"
            | "connection"
            | "keep-alive"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "content-length"
    ) || name.starts_with("fenders-")
        || name.starts_with("runtara-binding-")
        || name == TRACE_HEADER
}

fn filtered(headers: &HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::with_capacity(headers.len());
    for (name, value) in headers {
        if !dropped(name) {
            out.append(name.clone(), value.clone());
        }
    }
    out
}

/// Whether `path` is a call the shim makes for the run and a guest never
/// does: the run's output, its outbound byte grants, and the requests of an
/// HTTP run. With them a guest could close or forge its own output, take
/// the whole of its workspace's transfer allowance, or take requests past
/// the shim. Its own outcome, and whatever else its endpoint serves it, it
/// may reach.
fn shims_own(path: &str) -> bool {
    let path = path.trim_end_matches('/');
    path == crate::output::PATH
        || path == crate::budget::PATH
        || path == "/v1/run/http"
        || path.starts_with("/v1/run/http/")
}

/// Methods a guest's request may have.
fn guest_method(method: &Method) -> bool {
    matches!(
        *method,
        Method::GET | Method::HEAD | Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    )
}

/// Whether a request that came up the relay from the VM is passed on. The
/// relay's socket is made for every launch, since the shim uses the same
/// path for the run's own calls; a launch that did not ask for it
/// (`enabled` false) has nothing answered there, whatever in the guest
/// reached it. One that did has its own calls, by the methods a guest uses,
/// and none of the shim's.
fn guest_may(enabled: bool, method: &Method, path: &str) -> bool {
    enabled && guest_method(method) && !shims_own(path)
}

fn whole(bytes: Bytes) -> Answer {
    Full::new(bytes)
        .map_err(|never| match never {})
        .boxed_unsync()
}

fn status(code: StatusCode) -> Response<Answer> {
    let mut response = Response::new(whole(Bytes::new()));
    *response.status_mut() = code;
    response
}

impl Relay {
    /// Sends a request on the run's behalf (not the guest's), as the host-side
    /// failed outcome is.
    pub async fn send(
        &self,
        method: &Method,
        path: &str,
        mut headers: HeaderMap,
        body: Bytes,
    ) -> Result<(StatusCode, HeaderMap, Bytes), Failure> {
        if let Some(trace) = &self.trace_id {
            headers.insert(HeaderName::from_static(TRACE_HEADER), trace.clone());
        }
        self.upstream.send(method, path, &headers, body).await
    }

    async fn forward(&self, request: Request<Incoming>) -> Response<Answer> {
        let (parts, body) = request.into_parts();
        let path = parts
            .uri
            .path_and_query()
            .map_or("/", |p| p.as_str())
            .to_owned();
        if fenders_node::host_origin::confined(&path).is_err() {
            return status(StatusCode::BAD_REQUEST);
        }
        // The guest speaks to its run channel with the run's credential, and
        // some of what that credential opens is the shim's alone.
        if !guest_may(self.guest, &parts.method, parts.uri.path()) {
            return status(StatusCode::FORBIDDEN);
        }
        // Held whole, so a call that could not be sent can be sent again.
        let Ok(body) = Limited::new(body, REQUEST_LIMIT).collect().await else {
            return status(StatusCode::PAYLOAD_TOO_LARGE);
        };
        let body = body.to_bytes();
        let outcome = parts.method == Method::POST && parts.uri.path() == OUTCOME_PATH;
        let mut headers = filtered(&parts.headers);
        if let Some(trace) = &self.trace_id {
            headers.insert(HeaderName::from_static(TRACE_HEADER), trace.clone());
        }
        let answered = match self
            .upstream
            .stream(&parts.method, &path, &headers, body.clone())
            .await
        {
            Ok(Some(response)) => {
                Ok(response.map(|body| body.map_err(BoxError::from).boxed_unsync()))
            }
            Ok(None) => self
                .upstream
                .send(&parts.method, &path, &headers, body)
                .await
                .map(|(code, headers, body)| {
                    let mut response = Response::new(whole(body));
                    *response.status_mut() = code;
                    *response.headers_mut() = headers;
                    response
                }),
            Err(failure) => Err(failure),
        };
        match answered {
            Ok(mut response) => {
                if outcome && response.status().is_success() {
                    self.outcome_posted.store(true, Ordering::SeqCst);
                }
                *response.headers_mut() = filtered(response.headers());
                response
            }
            Err(Failure::Unreachable) => {
                let mut response = status(StatusCode::SERVICE_UNAVAILABLE);
                response
                    .headers_mut()
                    .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
                response
            }
            Err(Failure::Broken) => status(StatusCode::BAD_GATEWAY),
        }
    }
}

/// The calls relayed at once for a launch's guest configuration.
pub fn concurrency(guest: &serde_json::Value) -> usize {
    guest["host_origin_concurrency"]
        .as_u64()
        .map_or(CONCURRENCY, |n| n as usize)
}

/// Serves the guest's HTTP/2 connection on `stream` until it closes, with
/// `concurrency` calls relayed at once; the guest's further calls wait.
pub async fn serve(stream: tokio::net::UnixStream, relay: Arc<Relay>, concurrency: usize) {
    let permits = Arc::new(tokio::sync::Semaphore::new(concurrency));
    let service = service_fn(move |request| {
        let (relay, permits) = (relay.clone(), permits.clone());
        async move {
            let _permit = permits.acquire_owned().await;
            Ok::<_, Infallible>(relay.forward(request).await)
        }
    });
    let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
        .max_concurrent_streams(concurrency as u32)
        .serve_connection(TokioIo::new(stream), service)
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A run channel endpoint over TLS offering `alpn`, and the channel to
    /// reach it. It answers `GET /slow` with `first`, then, once `go` is
    /// notified, `second`; anything else with `whole`. A call without the
    /// launch's bearer, or with the guest's own, is answered 401.
    async fn endpoint(
        alpn: &[&[u8]],
        go: Arc<tokio::sync::Notify>,
    ) -> (crate::spec::Channel, tokio::task::JoinHandle<()>) {
        let mut params = rcgen::CertificateParams::new(vec![]).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let ca = params.self_signed(&ca_key).unwrap();
        let key = rcgen::KeyPair::generate().unwrap();
        let mut server = rcgen::CertificateParams::new(vec![]).unwrap();
        server
            .subject_alt_names
            .push(rcgen::SanType::IpAddress("127.0.0.1".parse().unwrap()));
        let certificate = server.signed_by(&key, &ca, &ca_key).unwrap();
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        )
        .unwrap();
        tls.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let channel = crate::spec::Channel {
            endpoint: format!("https://{}", listener.local_addr().unwrap())
                .parse()
                .unwrap(),
            credential: "launch".into(),
            ca_pem: ca.pem(),
            pin: None,
            server_name: None,
        };
        let served = tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let (acceptor, go) = (acceptor.clone(), go.clone());
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let service = service_fn(move |request: Request<Incoming>| {
                        let go = go.clone();
                        async move {
                            if request
                                .headers()
                                .get_all(header::AUTHORIZATION)
                                .iter()
                                .count()
                                != 1
                                || request.headers()[header::AUTHORIZATION] != "Bearer launch"
                            {
                                return Ok::<_, Infallible>(status(StatusCode::UNAUTHORIZED));
                            }
                            if request.uri().path() != "/slow" {
                                return Ok(Response::new(whole(Bytes::from_static(b"whole"))));
                            }
                            let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(1);
                            tokio::spawn(async move {
                                let _ = tx.send(Bytes::from_static(b"first")).await;
                                go.notified().await;
                                let _ = tx.send(Bytes::from_static(b"second")).await;
                            });
                            Ok(Response::new(Chunks(rx).boxed_unsync()))
                        }
                    });
                    let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(tls), service)
                        .await;
                });
            }
        });
        (channel, served)
    }

    /// A body of the chunks sent on a channel, ending when it closes.
    struct Chunks(tokio::sync::mpsc::Receiver<Bytes>);

    impl hyper::body::Body for Chunks {
        type Data = Bytes;
        type Error = BoxError;
        fn poll_frame(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, BoxError>>> {
            self.0
                .poll_recv(cx)
                .map(|chunk| chunk.map(|chunk| Ok(hyper::body::Frame::data(chunk))))
        }
    }

    /// The guest's side of the relay: a connection to it as the runtime has.
    async fn guest(relay: Relay) -> hyper::client::conn::http2::SendRequest<Full<Bytes>> {
        let (shim, guest) = tokio::net::UnixStream::pair().unwrap();
        tokio::spawn(serve(shim, Arc::new(relay), CONCURRENCY));
        let (sender, connection) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
            .handshake(TokioIo::new(guest))
            .await
            .unwrap();
        tokio::spawn(connection);
        sender
    }

    fn relay(channel: &crate::spec::Channel) -> Relay {
        Relay {
            upstream: Upstream::new(channel).unwrap(),
            guest: true,
            trace_id: None,
            outcome_posted: Default::default(),
        }
    }

    fn call(path: &str) -> Request<Full<Bytes>> {
        Request::get(format!("http://host{path}"))
            .header(header::AUTHORIZATION, "Bearer guest-made")
            .body(Full::default())
            .unwrap()
    }

    #[tokio::test]
    async fn a_guest_is_handed_an_answer_as_the_endpoint_sends_it() {
        let go = Arc::new(tokio::sync::Notify::new());
        let (channel, served) = endpoint(&[b"h2", b"http/1.1"], go.clone()).await;
        let mut guest = guest(relay(&channel)).await;
        let within = std::time::Duration::from_secs(10);
        let response = tokio::time::timeout(within, guest.send_request(call("/slow")))
            .await
            .expect("the head comes before the body ends")
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let mut body = response.into_body();
        // The first part reaches the guest while the endpoint still holds
        // the rest: nothing waits for the whole answer.
        let first = tokio::time::timeout(within, body.frame())
            .await
            .expect("the first part is passed on as it comes")
            .unwrap()
            .unwrap();
        assert_eq!(first.into_data().unwrap(), "first");
        go.notify_one();
        let rest = tokio::time::timeout(within, body.collect())
            .await
            .unwrap()
            .unwrap()
            .to_bytes();
        assert_eq!(rest, "second");
        served.abort();
    }

    #[tokio::test]
    async fn an_endpoint_without_http2_is_answered_whole() {
        let (channel, served) = endpoint(&[b"http/1.1"], Default::default()).await;
        let mut guest = guest(relay(&channel)).await;
        for _ in 0..2 {
            let response = guest.send_request(call("/other")).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = response.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(body, "whole");
        }
        served.abort();
    }

    #[test]
    fn a_launch_sets_how_many_calls_are_relayed_at_once() {
        assert_eq!(concurrency(&serde_json::json!({})), 16);
        assert_eq!(
            concurrency(&serde_json::json!({"host_origin_concurrency": 3})),
            3
        );
    }

    #[test]
    fn the_guest_reaches_its_outcome_and_not_the_shims_own_calls() {
        for own in [
            "/v1/run/output",
            "/v1/run/output/",
            "/v1/run/egress",
            "/v1/run/http/next",
            "/v1/run/http/response/0123456789abcdef",
            "/v1/run/http",
        ] {
            assert!(shims_own(own), "{own}");
        }
        assert_eq!(crate::ingress::NEXT, "/v1/run/http/next");
        assert!(crate::ingress::RESPONSE.starts_with("/v1/run/http/"));
        for guests in [
            OUTCOME_PATH,
            "/v1/run/ws",
            "/v1/run/ws/0123456789abcdef",
            "/v1/run/outputs",
            "/v1/run/httpx",
            "/anything/else",
        ] {
            assert!(!shims_own(guests), "{guests}");
        }
        for method in [Method::GET, Method::POST, Method::DELETE, Method::PUT] {
            assert!(guest_method(&method));
        }
        for method in [Method::CONNECT, Method::TRACE, Method::OPTIONS] {
            assert!(!guest_method(&method));
        }
    }

    #[test]
    fn a_launch_that_did_not_ask_for_the_relay_is_answered_nothing_there() {
        // Not asked for: nothing is passed on, the guest's own outcome
        // included, by any method.
        for method in [Method::GET, Method::POST, Method::PUT, Method::DELETE] {
            for path in [
                OUTCOME_PATH,
                "/v1/run/ws",
                "/anything/else",
                "/v1/run/egress",
            ] {
                assert!(!guest_may(false, &method, path), "{method} {path}");
            }
        }
        // Asked for: its own calls, and still none of the shim's.
        assert!(guest_may(true, &Method::POST, OUTCOME_PATH));
        assert!(guest_may(true, &Method::GET, "/anything/else"));
        assert!(!guest_may(true, &Method::POST, "/v1/run/egress"));
        assert!(!guest_may(true, &Method::POST, "/v1/run/output"));
        assert!(!guest_may(true, &Method::CONNECT, OUTCOME_PATH));
    }

    #[test]
    fn the_guest_cannot_set_credentials_bindings_or_trace() {
        let mut headers = HeaderMap::new();
        for (name, value) in [
            ("authorization", "Bearer guest-made"),
            ("proxy-authorization", "x"),
            ("runtara-binding-instance", "other-run"),
            ("fenders-execution-identity", "x"),
            ("runtara-trace-id", "spoofed"),
            ("connection", "close"),
            ("runtara-outcome", "completed"),
            ("idempotency-key", "k-1"),
        ] {
            headers.insert(
                HeaderName::from_static(name),
                HeaderValue::from_static(value),
            );
        }
        let kept = filtered(&headers);
        let names: Vec<_> = kept.keys().map(|k| k.as_str()).collect();
        assert_eq!(names.len(), 2, "{names:?}");
        assert!(kept.contains_key("runtara-outcome"));
        assert!(kept.contains_key("idempotency-key"));
    }
}
