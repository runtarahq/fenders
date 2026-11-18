//! The guest's host-bound origin: HTTP/2 from the runtime over the stream the
//! VMM holds, each request relayed to the run channel with the credential
//! added. The guest never sees the credential, and nothing it sends can name
//! another run: authorization, binding and `fenders-*` headers are dropped.
use crate::upstream::{Failure, Upstream};
use http_body_util::{BodyExt, Full, Limited};
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

const REQUEST_LIMIT: usize = 4 * 1024 * 1024;
const CONCURRENCY: usize = 4;
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

fn status(code: StatusCode) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::default());
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

    async fn forward(&self, request: Request<Incoming>) -> Response<Full<Bytes>> {
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
        let Ok(body) = Limited::new(body, REQUEST_LIMIT).collect().await else {
            return status(StatusCode::PAYLOAD_TOO_LARGE);
        };
        let outcome = parts.method == Method::POST && parts.uri.path() == OUTCOME_PATH;
        match self
            .send(
                &parts.method,
                &path,
                filtered(&parts.headers),
                body.to_bytes(),
            )
            .await
        {
            Ok((code, headers, body)) => {
                if outcome && code.is_success() {
                    self.outcome_posted.store(true, Ordering::SeqCst);
                }
                let mut response = Response::new(Full::new(body));
                *response.status_mut() = code;
                *response.headers_mut() = filtered(&headers);
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

/// Serves the guest's HTTP/2 connection on `stream` until it closes.
pub async fn serve(stream: tokio::net::UnixStream, relay: Arc<Relay>) {
    let permits = Arc::new(tokio::sync::Semaphore::new(CONCURRENCY));
    let service = service_fn(move |request| {
        let (relay, permits) = (relay.clone(), permits.clone());
        async move {
            let _permit = permits.acquire_owned().await;
            Ok::<_, Infallible>(relay.forward(request).await)
        }
    });
    let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
        .max_concurrent_streams(CONCURRENCY as u32)
        .serve_connection(TokioIo::new(stream), service)
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;

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
