//! Requests for an HTTP run (`guest.mode: http`), pulled over the run
//! channel and handed to the guest.
//!
//! The guest serves HTTP/2 on one end of a socket pair; the shim holds the
//! other, so nothing else on the node can send the app a request. The shim
//! asks the run channel for the next request (`POST …/v1/run/http/next`,
//! which waits), gives it to the guest, and posts the guest's answer
//! (`POST …/v1/run/http/response/ID`). Its first ask is made only once the
//! guest serves, so it is the run's readiness signal. A request is taken
//! once and never repeated.
//!
//! Both bodies are a head and then an HTTP body: the head's length (4 bytes,
//! big endian), the head as JSON (`{id, method, path, headers}` one way,
//! `{status, headers}` or `{error}` the other), then the body's bytes as they
//! are, to its end. Neither body is held whole: each is passed on as it
//! arrives, on an HTTP/2 connection to the run channel that only these calls
//! use. Headers pass through as the guest and the endpoint give them: the
//! endpoint filters both ways.
//!
//! A launch that is not an HTTP run has none of this: no socket, no task,
//! no connection.
use crate::relay::Relay;
use http_body_util::{BodyExt, Empty, combinators::UnsyncBoxBody};
use hyper::{
    Method, Request, StatusCode,
    body::{Body, Bytes, Frame, Incoming},
    header::{HeaderMap, HeaderName, HeaderValue},
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde_json::{Map, Value, json};
use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

/// Where a shim asks for its run's next request.
pub const NEXT: &str = "/v1/run/http/next";
/// Where it posts the answer to request `ID`, with the id appended.
pub const RESPONSE: &str = "/v1/run/http/response/";
/// The largest head read.
const MAX_HEAD: usize = 64 * 1024;
/// How long the shim gives the guest for a response's head beyond the
/// guest's own request timeout.
const MARGIN: Duration = Duration::from_secs(5);
/// How long to wait before asking again after an answer that was not a
/// request, and the longest wait between attempts to reach the endpoint.
const RETRY: Duration = Duration::from_secs(1);
const UNREACHABLE: Duration = Duration::from_secs(5);

type BoxError = Box<dyn std::error::Error + Send + Sync>;
/// A body passed on as it arrives.
type Stream = UnsyncBoxBody<Bytes, BoxError>;
type Channel = hyper::client::conn::http2::SendRequest<Stream>;
type Guest = hyper::client::conn::http2::SendRequest<Stream>;

/// Whether the launch is an HTTP run.
pub fn wanted(guest: &Value) -> bool {
    guest["mode"] == "http"
}

/// Why an HTTP run must end.
#[derive(Debug, PartialEq)]
pub enum Stop {
    /// The run channel's endpoint does not serve HTTP runs.
    Unserved,
}

impl Stop {
    pub fn code(&self) -> &'static str {
        "HTTP_UNSERVED"
    }
    pub fn reason(&self) -> &'static str {
        "the run channel does not serve HTTP runs"
    }
}

/// A head as it is sent before a body: its length, then the head as JSON.
pub fn head_frame(head: &Value) -> Bytes {
    let head = head.to_string();
    let mut out = Vec::with_capacity(4 + head.len());
    out.extend_from_slice(&(head.len() as u32).to_be_bytes());
    out.extend_from_slice(head.as_bytes());
    out.into()
}

/// Bytes, then a body: the rest of a message whose head has been read, or
/// a head before the body it describes.
pub struct Prefixed<B> {
    prefix: Option<Bytes>,
    inner: B,
}

impl<B> Prefixed<B> {
    pub fn new(prefix: Bytes, inner: B) -> Self {
        Self {
            prefix: Some(prefix).filter(|p| !p.is_empty()),
            inner,
        }
    }
}

impl<B: Body<Data = Bytes> + Unpin> Body for Prefixed<B> {
    type Data = Bytes;
    type Error = B::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, B::Error>>> {
        if let Some(prefix) = self.prefix.take() {
            return Poll::Ready(Some(Ok(Frame::data(prefix))));
        }
        Pin::new(&mut self.inner).poll_frame(cx)
    }
    fn is_end_stream(&self) -> bool {
        self.prefix.is_none() && self.inner.is_end_stream()
    }
}

/// What the start of a body turned out to be.
#[derive(Debug)]
pub enum Head {
    /// A head, and what was read past it.
    Message(Value, Bytes),
    /// A framed head longer than this shim takes. Its endpoint frames heads,
    /// so it does serve; this one message is not for the guest.
    Oversized,
    /// Not a head at all.
    Garbage,
}

/// The longest declared head still read as a framed one that is too large.
/// A body of text is not mistaken for one: its first four bytes, read as a
/// length, are over 512 MiB.
const PLAUSIBLE_HEAD: usize = 16 * 1024 * 1024;

/// Reads a message's head from the start of `body`.
pub async fn read_framed<B>(body: &mut B) -> Head
where
    B: Body<Data = Bytes> + Unpin,
{
    let mut read = Vec::new();
    loop {
        if read.len() >= 4 {
            let length = u32::from_be_bytes([read[0], read[1], read[2], read[3]]) as usize;
            if length > PLAUSIBLE_HEAD {
                return Head::Garbage;
            }
            if length > MAX_HEAD {
                return Head::Oversized;
            }
            if read.len() >= 4 + length {
                return match serde_json::from_slice(&read[4..4 + length]) {
                    Ok(head) => Head::Message(head, Bytes::copy_from_slice(&read[4 + length..])),
                    Err(_) => Head::Garbage,
                };
            }
        }
        match body.frame().await {
            Some(Ok(frame)) => {
                if let Ok(data) = frame.into_data() {
                    read.extend_from_slice(&data);
                }
            }
            _ => return Head::Garbage,
        }
    }
}

/// Reads a message's head from the start of `body`: the head, and what was
/// read past it. `None` when the body does not start with a head this shim
/// takes.
#[cfg(test)]
pub async fn read_head<B>(body: &mut B) -> Option<(Value, Bytes)>
where
    B: Body<Data = Bytes> + Unpin,
{
    match read_framed(body).await {
        Head::Message(head, rest) => Some((head, rest)),
        _ => None,
    }
}

fn boxed<B>(body: B) -> Stream
where
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<BoxError>,
{
    body.map_err(Into::into).boxed_unsync()
}

fn empty() -> Stream {
    boxed(Empty::<Bytes>::new())
}

/// The guest's request for a request head and body; `None` when the head
/// names no valid method, path or header.
fn request(head: &Value, body: Stream) -> Option<Request<Stream>> {
    let path = head["path"].as_str().filter(|p| p.starts_with('/'))?;
    let mut request = Request::builder()
        .method(Method::from_bytes(head["method"].as_str()?.as_bytes()).ok()?)
        // HTTP/2 carries the authority in the URI. The guest is told no
        // public name here: the endpoint decides which headers it sees.
        .uri(format!("http://app{path}"))
        .body(body)
        .ok()?;
    for (name, value) in head["headers"].as_object()? {
        request.headers_mut().append(
            HeaderName::from_bytes(name.as_bytes()).ok()?,
            HeaderValue::from_str(value.as_str()?).ok()?,
        );
    }
    Some(request)
}

/// Headers as the JSON map the endpoint reads; values of a repeated name
/// are joined.
fn headers(headers: &HeaderMap) -> Map<String, Value> {
    let mut out = Map::new();
    for name in headers.keys() {
        let values: Vec<&str> = headers
            .get_all(name)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect();
        out.insert(name.as_str().to_owned(), json!(values.join(", ")));
    }
    out
}

/// Gives one request to the guest and returns its answer as a message: the
/// head at once, the guest's body behind it as the guest sends it. `timeout`
/// bounds the wait for the answer's head.
async fn answer(guest: &mut Guest, head: &Value, body: Stream, timeout: Duration) -> Stream {
    let failed = |error: &str| boxed(Prefixed::new(head_frame(&json!({"error": error})), empty()));
    let Some(request) = request(head, body) else {
        return failed("the request could not be given to the app");
    };
    let exchange = async {
        guest.ready().await.map_err(|_| "the app is not serving")?;
        guest
            .send_request(request)
            .await
            .map_err(|_| "the app failed the request")
    };
    match tokio::time::timeout(timeout, exchange).await {
        Ok(Ok(response)) => {
            let (parts, body) = response.into_parts();
            let head = json!({"status": parts.status.as_u16(), "headers": headers(&parts.headers)});
            boxed(Prefixed::new(head_frame(&head), body))
        }
        Ok(Err(error)) => failed(error),
        Err(_) => failed("the app did not answer in time"),
    }
}

/// The run channel as these calls use it: one HTTP/2 connection of their
/// own, made when first needed and again when it is found closed.
struct Calls {
    relay: Arc<Relay>,
    channel: tokio::sync::Mutex<Option<Channel>>,
}

enum Unsent {
    /// The endpoint could not be reached.
    Unreachable,
    /// It does not speak HTTP/2, which these calls need.
    NoHttp2,
    /// The request was sent and the exchange broke.
    Broken,
}

impl Calls {
    async fn send(&self, path: &str, body: Stream) -> Result<hyper::Response<Incoming>, Unsent> {
        let mut channel = {
            let mut slot = self.channel.lock().await;
            match slot.as_ref().filter(|channel| !channel.is_closed()) {
                Some(channel) => channel.clone(),
                None => {
                    let channel = self
                        .relay
                        .upstream
                        .streaming::<Stream>()
                        .await
                        .map_err(|()| Unsent::Unreachable)?
                        .ok_or(Unsent::NoHttp2)?;
                    *slot = Some(channel.clone());
                    channel
                }
            }
        };
        let mut request = self.relay.upstream.request(Method::POST, path);
        if let Some(trace) = &self.relay.trace_id {
            request = request.header(crate::relay::TRACE_HEADER, trace.clone());
        }
        let request = request.body(body).map_err(|_| Unsent::Broken)?;
        channel.ready().await.map_err(|_| Unsent::Unreachable)?;
        channel
            .send_request(request)
            .await
            .map_err(|_| Unsent::Broken)
    }
}

/// Pulls requests for one of the guest's slots until the guest's connection
/// closes, or the endpoint turns out not to serve HTTP runs.
async fn pull(calls: Arc<Calls>, mut guest: Guest, timeout: Duration) -> Option<Stop> {
    let mut served = false;
    let mut unreachable = Duration::from_millis(100);
    while !guest.is_closed() {
        let response = match calls.send(NEXT, empty()).await {
            Ok(response) => response,
            Err(Unsent::NoHttp2) => return Some(Stop::Unserved),
            Err(Unsent::Unreachable) => {
                tokio::time::sleep(unreachable).await;
                unreachable = (unreachable * 2).min(UNREACHABLE);
                continue;
            }
            Err(Unsent::Broken) => {
                tokio::time::sleep(RETRY).await;
                continue;
            }
        };
        unreachable = Duration::from_millis(100);
        let (parts, mut body) = response.into_parts();
        let (head, rest) = match parts.status {
            StatusCode::OK => match read_framed(&mut body).await {
                Head::Message(head, rest) if head["id"].is_string() => (head, rest),
                // A request too large to take is refused, whoever sent it and
                // whenever: it says nothing about whether the endpoint serves,
                // and must never end a run that would have served the next.
                Head::Oversized => {
                    served = true;
                    tokio::time::sleep(RETRY).await;
                    continue;
                }
                // An endpoint that answers anything with 200 is not serving.
                _ if !served => return Some(Stop::Unserved),
                _ => {
                    tokio::time::sleep(RETRY).await;
                    continue;
                }
            },
            StatusCode::NO_CONTENT => {
                served = true;
                continue;
            }
            StatusCode::NOT_FOUND | StatusCode::NOT_IMPLEMENTED if !served => {
                return Some(Stop::Unserved);
            }
            // Not current or refused: the endpoint may yet take the run
            // back, and its launcher stops a run that is not wanted.
            _ => {
                tokio::time::sleep(RETRY).await;
                continue;
            }
        };
        served = true;
        let id = head["id"].as_str().unwrap_or_default().to_owned();
        let answer = answer(&mut guest, &head, boxed(Prefixed::new(rest, body)), timeout).await;
        // The call returns when the endpoint has taken the whole answer, or
        // has no more use for it.
        match calls.send(&format!("{RESPONSE}{id}"), answer).await {
            Ok(response) => {
                let _ = response.into_body().collect().await;
            }
            Err(_) => tracing::warn!(request = id, "an app's response could not be delivered"),
        }
    }
    None
}

/// Serves an HTTP run on `stream`, the shim's end of the guest's request
/// stream: waits for the guest to serve, then pulls requests for each of its
/// `slots`. `request_timeout` is the guest's own.
pub async fn serve(
    stream: tokio::net::UnixStream,
    relay: Arc<Relay>,
    slots: usize,
    request_timeout: Duration,
) -> Option<Stop> {
    // The guest's HTTP/2 server speaks first, once its component is loaded:
    // until then nothing is asked for on its behalf.
    stream.readable().await.ok()?;
    let (guest, connection) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .handshake::<_, Stream>(TokioIo::new(stream))
        .await
        .ok()?;
    tokio::spawn(connection);
    tracing::info!(slots, "the app is serving");
    let calls = Arc::new(Calls {
        relay,
        channel: Default::default(),
    });
    let mut pulls = tokio::task::JoinSet::new();
    for _ in 0..slots.max(1) {
        pulls.spawn(pull(calls.clone(), guest.clone(), request_timeout + MARGIN));
    }
    while let Some(ended) = pulls.join_next().await {
        if let Ok(Some(stop)) = ended {
            return Some(stop);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::Full;

    async fn whole(body: Stream) -> Bytes {
        body.collect().await.unwrap().to_bytes()
    }

    #[tokio::test]
    async fn a_head_is_read_from_the_start_of_a_body_and_the_rest_left_as_it_is() {
        let body = [0u8, 255, b'\n', 1];
        let mut message = head_frame(&json!({"id": "r1", "method": "POST"})).to_vec();
        message.extend_from_slice(&body);
        // Whole, and in pieces that split the length and the head.
        for split in [message.len(), 2, 9] {
            let (first, second) = message.split_at(split);
            let mut stream = Prefixed::new(
                Bytes::copy_from_slice(first),
                Full::new(Bytes::copy_from_slice(second)),
            );
            let (head, rest) = read_head(&mut stream).await.unwrap();
            assert_eq!(head["id"], "r1");
            let rest = whole(boxed(Prefixed::new(rest, stream))).await;
            assert_eq!(&rest[..], &body, "split at {split}");
        }
        for bad in [&b"{}"[..], &[0, 0, 0, 9, b'{'], &[255, 255, 255, 255, 1]] {
            let mut stream = Full::new(Bytes::copy_from_slice(bad));
            assert!(read_head(&mut stream).await.is_none());
        }
        // A framed head over the limit is told apart from what is no head:
        // the first is a request to refuse, the second an endpoint that does
        // not serve.
        let mut long = ((MAX_HEAD + 1) as u32).to_be_bytes().to_vec();
        long.push(b'{');
        let mut stream = Full::new(Bytes::from(long));
        assert!(matches!(read_framed(&mut stream).await, Head::Oversized));
        for garbage in [
            &b"<html>"[..],
            &b"{\"error\":1}"[..],
            &[0, 0, 0, 2, b'n', b'o'],
        ] {
            let mut stream = Full::new(Bytes::copy_from_slice(garbage));
            assert!(matches!(read_framed(&mut stream).await, Head::Garbage));
        }
    }

    #[test]
    fn a_request_head_becomes_the_guests_request_or_is_refused() {
        let head = json!({"id":"r","method":"PUT","path":"/a?b=1","headers":{"content-type":"text/plain"}});
        let made = request(&head, empty()).unwrap();
        assert_eq!(made.method(), Method::PUT);
        assert_eq!(made.uri().path_and_query().unwrap().as_str(), "/a?b=1");
        assert_eq!(made.headers()["content-type"], "text/plain");
        for bad in [
            json!({"method":"GET","path":"no-slash","headers":{}}),
            json!({"method":"G T","path":"/","headers":{}}),
            json!({"method":"GET","path":"/","headers":{"bad name":"v"}}),
            json!({"method":"GET","path":"/"}),
        ] {
            assert!(request(&bad, empty()).is_none(), "{bad}");
        }
    }

    /// A guest that answers with its method, path and the body it was sent,
    /// in two pieces with a pause between them.
    async fn guest(stream: tokio::net::UnixStream) {
        let service = hyper::service::service_fn(|request: Request<Incoming>| async move {
            let text = format!("{} {} ", request.method(), request.uri().path());
            if request.uri().path() == "/slow" {
                tokio::time::sleep(Duration::from_secs(3600)).await;
            }
            let sent = request.into_body().collect().await.unwrap().to_bytes();
            let (tx, rx) = tokio::sync::mpsc::channel::<Result<Frame<Bytes>, BoxError>>(2);
            tokio::spawn(async move {
                let _ = tx.send(Ok(Frame::data(Bytes::from(text)))).await;
                tokio::time::sleep(Duration::from_secs(30)).await;
                let _ = tx.send(Ok(Frame::data(sent))).await;
            });
            Ok::<_, std::convert::Infallible>(
                hyper::Response::builder()
                    .status(201)
                    .header("content-type", "text/plain")
                    .body(Receiver(rx))
                    .unwrap(),
            )
        });
        let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(stream), service)
            .await;
    }

    struct Receiver(tokio::sync::mpsc::Receiver<Result<Frame<Bytes>, BoxError>>);
    impl Body for Receiver {
        type Data = Bytes;
        type Error = BoxError;
        fn poll_frame(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
            self.0.poll_recv(cx)
        }
    }

    #[tokio::test(start_paused = true)]
    async fn the_guests_answer_is_passed_on_as_it_arrives_and_its_failure_named() {
        let (ours, theirs) = tokio::net::UnixStream::pair().unwrap();
        tokio::spawn(guest(theirs));
        let (mut sender, connection) =
            hyper::client::conn::http2::Builder::new(TokioExecutor::new())
                .handshake::<_, Stream>(TokioIo::new(ours))
                .await
                .unwrap();
        tokio::spawn(connection);
        let head = json!({"id":"1","method":"POST","path":"/hello","headers":{}});
        let sent = boxed(Full::new(Bytes::from_static(b"posted")));
        let mut answered = answer(&mut sender, &head, sent, Duration::from_secs(10)).await;
        // The head and the first piece are there before the guest has sent
        // the rest of its body.
        let (head, mut rest) = read_head(&mut answered).await.unwrap();
        assert_eq!(head["status"], 201);
        assert_eq!(head["headers"]["content-type"], "text/plain");
        if rest.is_empty() {
            rest = answered
                .frame()
                .await
                .unwrap()
                .unwrap()
                .into_data()
                .unwrap();
        }
        assert_eq!(&rest[..], b"POST /hello ");
        assert_eq!(&whole(answered).await[..], b"posted");

        let slow = json!({"id":"2","method":"GET","path":"/slow","headers":{}});
        let mut answered = answer(&mut sender, &slow, empty(), Duration::from_secs(10)).await;
        let (head, _) = read_head(&mut answered).await.unwrap();
        assert_eq!(head["error"], "the app did not answer in time");

        let bad = json!({"id":"3","method":"GET","path":"nope","headers":{}});
        let mut answered = answer(&mut sender, &bad, empty(), Duration::from_secs(1)).await;
        assert!(read_head(&mut answered).await.unwrap().0["error"].is_string());
    }
}
