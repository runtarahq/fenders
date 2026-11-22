//! `fenders-shim-stub`: a small local run channel endpoint for testing
//! `fenders-shim` alone, without Runtara.
//!
//! ```text
//! fenders-shim-stub --dir DIR [--listen 127.0.0.1:0] [--input JSON] [--hold-input SECONDS] [--alpn http/1.1] [--refuse-output] [--allowance BYTES] [--http JSON]
//! ```
//!
//! It makes a CA and a server certificate for 127.0.0.1 and localhost,
//! writes `DIR/ca.pem`, `DIR/credential` (the bearer it accepts),
//! `DIR/endpoint`, `DIR/pin` and `DIR/channel.json` (a run spec's `channel`),
//! then serves HTTPS (HTTP/2 and HTTP/1.1). `scripts/shim_standalone.sh`
//! runs a component under `fenders-shim` against it. Every call is
//! printed as a JSON line on standard output (method, path, status, the
//! outcome kind and body), never the credential. An output batch
//! (`POST /v1/run/output`) is accepted and printed, or answered 404 with
//! `--refuse-output`. With `--allowance BYTES` it grants outbound bytes
//! (`POST /v1/run/egress`) up to that total, for 10 seconds at a time, and
//! answers 429 with what is left once an ask exceeds it; without, such an
//! ask gets 404. With `--http JSON`, an array of requests (`{"method",
//! "path", "headers", "body"}`, all but the path optional, or `"body_bytes"`
//! for a body of that size), it gives an HTTP
//! run those requests one at a time (`POST /v1/run/http/next`) and prints
//! each answer the run posts (`POST /v1/run/http/response/ID`: its head, and
//! its body as text); with none left, or without the flag given requests,
//! `next` waits a second and answers 204. Without `--http` at all `next`
//! gets 404. The workflow API calls a
//! one-step workflow makes are answered as Runtara would for a fresh launch.
//! Two paths stand for slow work, as a guest's relayed calls meet it:
//! `GET /test/slow?seconds=N` answers after N seconds, and
//! `GET /test/stream?chunks=N&every=S` answers at once and sends N lines, S
//! seconds apart. Anything else gets `{}`.
use http_body_util::{BodyExt, Full, combinators::UnsyncBoxBody};
use hyper::{Request, Response, StatusCode, body::Bytes, service::service_fn};
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde_json::json;
use std::{convert::Infallible, path::PathBuf, sync::Arc};

struct Stub {
    bearer: String,
    /// Seconds the input is held back, so a live run can be looked at.
    hold: u64,
    input: Bytes,
    /// Answer output batches with 404, as an endpoint that does not serve them.
    refuse_output: bool,
    /// The outbound bytes it grants in all, if it grants any, with the
    /// revision and ceiling granted so far.
    allowance: Option<u64>,
    granted: std::sync::Mutex<(u64, u64)>,
    /// The requests still to give an HTTP run, if it serves any.
    http: Option<std::sync::Mutex<std::collections::VecDeque<serde_json::Value>>>,
    /// When it started: each printed call says how long after.
    started: std::time::Instant,
}

/// A head and a body as the shim frames them: the head's length, the head
/// as JSON, the body.
fn frame(head: &serde_json::Value, body: &[u8]) -> Bytes {
    let head = head.to_string();
    let mut out = (head.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(head.as_bytes());
    out.extend_from_slice(body);
    out.into()
}

fn unframe(bytes: &[u8]) -> Option<(serde_json::Value, &[u8])> {
    let length = u32::from_be_bytes(bytes.get(..4)?.try_into().ok()?) as usize;
    Some((
        serde_json::from_slice(bytes.get(4..4 + length)?).ok()?,
        bytes.get(4 + length..)?,
    ))
}

fn arg(name: &str) -> Option<String> {
    let args: Vec<String> = std::env::args().collect();
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

type Body = UnsyncBoxBody<Bytes, std::convert::Infallible>;

fn reply(status: StatusCode, body: impl Into<Bytes>) -> Response<Body> {
    let mut response = Response::new(Full::new(body.into()).boxed_unsync());
    *response.status_mut() = status;
    response
}

impl Stub {
    async fn handle(&self, request: Request<hyper::body::Incoming>) -> Response<Body> {
        let (parts, body) = request.into_parts();
        let body = body
            .collect()
            .await
            .map(|b| b.to_bytes())
            .unwrap_or_default();
        let path = parts.uri.path().to_owned();
        let header = |name: &str| {
            parts
                .headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
        };
        let authorized = header("authorization").as_deref() == Some(self.bearer.as_str());
        let mut http_answer = None;
        let mut response = if !authorized {
            reply(StatusCode::UNAUTHORIZED, "")
        } else {
            match (parts.method.as_str(), path.as_str()) {
                ("GET", "/v1/run/input") => {
                    if self.hold > 0 {
                        tokio::time::sleep(std::time::Duration::from_secs(self.hold)).await;
                    }
                    let mut r = reply(StatusCode::OK, self.input.clone());
                    r.headers_mut().insert("runtara-checkpoints", "none".parse().unwrap());
                    r.headers_mut().insert("runtara-lifecycle", "none".parse().unwrap());
                    r
                }
                ("GET", "/v1/run") => reply(
                    StatusCode::OK,
                    json!({"instanceId":"stub-instance","tenantId":"stub-tenant","launchKind":"fresh","debug":false}).to_string(),
                ),
                ("POST", "/v1/run/outcome") => reply(StatusCode::NO_CONTENT, ""),
                ("POST", "/v1/run/output") if self.refuse_output => {
                    reply(StatusCode::NOT_FOUND, "")
                }
                ("POST", "/v1/run/egress") => match self.allowance {
                    None => reply(StatusCode::NOT_FOUND, ""),
                    Some(allowance) => {
                        let ask = serde_json::from_slice::<serde_json::Value>(&body)
                            .unwrap_or_default();
                        let bytes = ask["bytes"].as_u64().unwrap_or(0);
                        let mut granted = self.granted.lock().unwrap();
                        if ask["expected_revision"].as_u64() != Some(granted.0) {
                            reply(StatusCode::CONFLICT, json!({"error":"stale grant revision"}).to_string())
                        } else if granted.1 + bytes > allowance {
                            reply(
                                StatusCode::TOO_MANY_REQUESTS,
                                json!({"error":"transfer allowance exhausted","available_bytes":allowance - granted.1}).to_string(),
                            )
                        } else {
                            *granted = (granted.0 + 1, granted.1 + bytes);
                            reply(
                                StatusCode::OK,
                                json!({"revision":granted.0,"state":"active","ceiling_bytes":granted.1,"ttl_ms":10000}).to_string(),
                            )
                        }
                    }
                },
                ("POST", "/v1/run/http/next") => match &self.http {
                    None => reply(StatusCode::NOT_FOUND, ""),
                    Some(requests) => {
                        let next = requests.lock().unwrap().pop_front();
                        match next {
                            None => {
                                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                                reply(StatusCode::NO_CONTENT, "")
                            }
                            Some(request) => {
                                let id = format!("r{}", requests.lock().unwrap().len());
                                let head = json!({"id": id,
                                    "method": request["method"].as_str().unwrap_or("GET"),
                                    "path": request["path"],
                                    "headers": request.get("headers").cloned().unwrap_or(json!({}))});
                                // `body_bytes` asks for a body of that many bytes.
                                let body = match request["body_bytes"].as_u64() {
                                    Some(bytes) => vec![b'x'; bytes as usize],
                                    None => request["body"].as_str().unwrap_or("").as_bytes().to_vec(),
                                };
                                let mut r = reply(StatusCode::OK, frame(&head, &body));
                                r.headers_mut().insert(
                                    "content-type",
                                    "application/octet-stream".parse().unwrap(),
                                );
                                r
                            }
                        }
                    }
                },
                ("POST", path) if path.starts_with("/v1/run/http/response/") => {
                    http_answer = unframe(&body).map(|(head, body)| {
                        json!({"head": head, "body": String::from_utf8_lossy(&body[..body.len().min(2000)]), "body_bytes": body.len()})
                    });
                    reply(StatusCode::OK, "{}")
                }
                ("GET", "/test/slow") => {
                    let seconds = query(&parts.uri, "seconds").unwrap_or(0).min(600);
                    tokio::time::sleep(std::time::Duration::from_secs(seconds)).await;
                    reply(StatusCode::OK, json!({"waited_seconds": seconds}).to_string())
                }
                ("GET", "/test/stream") => {
                    let chunks = query(&parts.uri, "chunks").unwrap_or(3).min(1000);
                    let every = query(&parts.uri, "every").unwrap_or(1).min(600);
                    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(1);
                    tokio::spawn(async move {
                        for chunk in 0..chunks {
                            if chunk > 0 {
                                tokio::time::sleep(std::time::Duration::from_secs(every)).await;
                            }
                            if tx.send(format!("chunk {chunk}\n").into()).await.is_err() {
                                return;
                            }
                        }
                    });
                    let mut r = Response::new(Lines(rx).boxed_unsync());
                    r.headers_mut().insert("content-type", "text/plain".parse().unwrap());
                    r
                }
                ("GET", "/v1/time") => reply(
                    StatusCode::OK,
                    json!({"nowMs": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64}).to_string(),
                ),
                _ => reply(StatusCode::OK, "{}"),
            }
        };
        if response.headers().get("content-type").is_none()
            && !hyper::body::Body::size_hint(response.body())
                .exact()
                .is_some_and(|n| n == 0)
        {
            response
                .headers_mut()
                .insert("content-type", "application/json".parse().unwrap());
        }
        let line = json!({
            "method": parts.method.as_str(),
            "path": parts.uri.path_and_query().map(|p| p.as_str()),
            "version": format!("{:?}", parts.version),
            "authorized": authorized,
            "status": response.status().as_u16(),
            "outcome": header("runtara-outcome"),
            "trace": header("runtara-trace-id"),
            "body": if path == "/v1/run/outcome" || path == "/v1/run/output" || path == "/v1/run/egress" { serde_json::from_slice::<serde_json::Value>(&body).ok().or_else(|| Some(json!(String::from_utf8_lossy(&body)))) } else { None },
            "body_bytes": body.len(),
            "http_answer": http_answer,
            "at_ms": self.started.elapsed().as_millis() as u64,
        });
        println!("{line}");
        response
    }
}

/// A query parameter as a number.
fn query(uri: &hyper::Uri, name: &str) -> Option<u64> {
    uri.query()?.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        (key == name).then(|| value.parse().ok()).flatten()
    })
}

/// A body of the lines sent on a channel, ending when it closes.
struct Lines(tokio::sync::mpsc::Receiver<Bytes>);

impl hyper::body::Body for Lines {
    type Data = Bytes;
    type Error = std::convert::Infallible;
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, Self::Error>>> {
        self.0
            .poll_recv(cx)
            .map(|line| line.map(|line| Ok(hyper::body::Frame::data(line))))
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let dir = PathBuf::from(arg("--dir").expect("--dir DIR"));
    let listen = arg("--listen").unwrap_or_else(|| "127.0.0.1:0".into());
    let input = arg("--input").unwrap_or_else(|| r#"{"data":{},"variables":{}}"#.into());

    let mut params = rcgen::CertificateParams::new(vec![]).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let ca = params.self_signed(&ca_key).unwrap();
    let server_key = rcgen::KeyPair::generate().unwrap();
    let mut server = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
    server
        .subject_alt_names
        .push(rcgen::SanType::IpAddress("127.0.0.1".parse().unwrap()));
    let certificate = server.signed_by(&server_key, &ca, &ca_key).unwrap();
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![certificate.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(server_key.serialize_der()).into(),
    )
    .unwrap();
    tls.alpn_protocols = match arg("--alpn").as_deref() {
        Some("http/1.1") => vec![b"http/1.1".to_vec()],
        _ => vec![b"h2".to_vec(), b"http/1.1".to_vec()],
    };
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));

    let mut credential = [0u8; 24];
    getrandom(&mut credential);
    let credential: String = credential.iter().map(|b| format!("{b:02x}")).collect();
    let listener = tokio::net::TcpListener::bind(&listen).await.unwrap();
    let endpoint = format!("https://{}", listener.local_addr().unwrap());
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("ca.pem"), ca.pem()).unwrap();
    std::fs::write(dir.join("credential"), &credential).unwrap();
    std::fs::write(dir.join("endpoint"), &endpoint).unwrap();
    std::fs::write(
        dir.join("pin"),
        fenders_node_protocol::transport::key_pin(certificate.der()).unwrap(),
    )
    .unwrap();
    // The spec's `channel`, ready to merge into a run spec (mode 600).
    let channel = json!({
        "endpoint": endpoint,
        "credential": credential,
        "trust": {
            "ca_pem": ca.pem(),
            "pin": fenders_node_protocol::transport::key_pin(certificate.der()).unwrap(),
        },
    });
    {
        use std::{io::Write, os::unix::fs::OpenOptionsExt};
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(dir.join("channel.json"))
            .and_then(|mut f| f.write_all(channel.to_string().as_bytes()))
            .unwrap();
    }
    eprintln!("fenders-shim-stub: serving {endpoint}");

    let stub = Arc::new(Stub {
        bearer: format!("Bearer {credential}"),
        hold: arg("--hold-input")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0),
        input: Bytes::from(input),
        refuse_output: std::env::args().any(|a| a == "--refuse-output"),
        allowance: arg("--allowance").and_then(|s| s.parse().ok()),
        granted: Default::default(),
        started: std::time::Instant::now(),
        http: arg("--http").map(|requests| {
            std::sync::Mutex::new(
                serde_json::from_str::<Vec<serde_json::Value>>(&requests)
                    .expect("--http takes a JSON array of requests")
                    .into(),
            )
        }),
    });
    loop {
        let Ok((tcp, _)) = listener.accept().await else {
            continue;
        };
        let (acceptor, stub) = (acceptor.clone(), stub.clone());
        tokio::spawn(async move {
            let Ok(tls) = acceptor.accept(tcp).await else {
                return;
            };
            let service = service_fn(move |request| {
                let stub = stub.clone();
                async move { Ok::<_, Infallible>(stub.handle(request).await) }
            });
            let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(tls), service)
                .await;
        });
    }
}

fn getrandom(buffer: &mut [u8]) {
    let n = unsafe { libc::getrandom(buffer.as_mut_ptr().cast(), buffer.len(), 0) };
    assert_eq!(n, buffer.len() as isize);
}
