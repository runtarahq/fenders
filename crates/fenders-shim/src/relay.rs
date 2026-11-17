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
