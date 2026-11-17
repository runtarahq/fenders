//! The one host-bound origin. Its requests share one HTTP/2 connection over a
//! stream the node hands the VMM, never a socket, and carry no `fenders-*`
//! header: the node adds the only execution identity the upstream sees.
use http_body_util::BodyExt;
use std::sync::OnceLock;
use tokio::sync::Mutex;
use wasmtime_wasi_http::{Error, WasiBody, io::TokioIo};

type Sender = hyper::client::conn::http2::SendRequest<WasiBody>;
// Opened once per runtime: every open of the virtual path is the same stream.
static CHANNEL: OnceLock<Mutex<Option<Sender>>> = OnceLock::new();

#[derive(Clone)]
struct Spawn;
impl<F> hyper::rt::Executor<F> for Spawn
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    fn execute(&self, future: F) {
        tokio::spawn(future);
    }
}

pub fn origin() -> Option<String> {
    std::env::var("FENDERS_HOST_ORIGIN").ok().filter(|origin| !origin.is_empty())
}

fn unavailable() -> Error {
    Error::InternalError(Some("host-bound origin unavailable".into()))
}

async fn sender() -> Result<Sender, Error> {
    let mut slot = CHANNEL.get_or_init(|| Mutex::new(None)).lock().await;
    if let Some(sender) = slot.as_ref() {
        return if sender.is_closed() { Err(Error::ConnectionTerminated) } else { Ok(sender.clone()) };
    }
    let file = std::fs::File::open("/fenders/host-origin").map_err(|_| unavailable())?;
    let stream = std::os::unix::net::UnixStream::from(std::os::fd::OwnedFd::from(file));
    stream.set_nonblocking(true).map_err(|_| unavailable())?;
    let stream = tokio::net::UnixStream::from_std(stream).map_err(|_| unavailable())?;
    let (sender, connection) = hyper::client::conn::http2::Builder::new(Spawn)
        .handshake(TokioIo::new(stream))
        .await
        .map_err(|_| unavailable())?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    *slot = Some(sender.clone());
    Ok(sender)
}

/// No first-byte cap applies here: the run's lifetime bounds the wait.
pub async fn send(mut request: hyper::Request<WasiBody>) -> Result<hyper::Response<WasiBody>, Error> {
    let reserved: Vec<_> =
        request.headers().keys().filter(|name| name.as_str().starts_with("fenders-")).cloned().collect();
    for name in reserved {
        request.headers_mut().remove(name);
    }
    // HTTP/2 carries the authority in the URI, not a Host header.
    request.headers_mut().remove(hyper::header::HOST);
    *request.version_mut() = hyper::Version::HTTP_2;
    let mut sender = sender().await?;
    sender.ready().await.map_err(|_| Error::ConnectionTerminated)?;
    let response = sender.send_request(request).await.map_err(|_| Error::ConnectionTerminated)?;
    Ok(response.map(|body| body.map_err(|_| Error::ConnectionTerminated).boxed_unsync()))
}
