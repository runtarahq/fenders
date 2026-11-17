//! Standard WASI HTTP handlers (`wasi:http/incoming-handler@0.2` and
//! `wasi:http/handler@0.3`), served as HTTP/2 on the one stream the launch
//! hands in (`/fenders/listener`): the run's shim holds its other end, and
//! nothing else can reach the app. Up to `FENDERS_HTTP_CONCURRENCY` requests
//! at once (one unless the launch says otherwise), each in a fresh Store, on
//! the runtime's one thread. A request has the request timeout to produce
//! its response's head; a response that is then streamed may go on for
//! `FENDERS_HTTP_STREAM_MS` (16 minutes unless set) from the request's start.
use super::*;
use std::cell::Cell;
use std::rc::Rc;
use std::time::Duration;
use wasmtime_wasi_http::p2::bindings::{ProxyPre, http::types::Scheme};
use wasmtime_wasi_http::p3::bindings::ServicePre;
use wasmtime_wasi_http::io::TokioIo;
use http_body_util::BodyExt;
use http_body_util::combinators::UnsyncBoxBody;

type ResponseBody=UnsyncBoxBody<hyper::body::Bytes,anyhow::Error>;

/// The component's handler: 0.3 when it exports `wasi:http/handler@0.3.0`.
#[derive(Clone)]
enum Handler { P2(ProxyPre<State>), P3(ServicePre<State>) }

fn idle(value: bool) {
    // Private native ABI hook; WASM has no import exposing this operation.
    unsafe { libc::syscall(500, value as libc::c_ulong); }
}

/// Runs hyper's connection tasks on this thread: a request's future holds
/// its handler's reply, which is not `Send`.
#[derive(Clone)]
struct Local;
impl<F:Future+'static> hyper::rt::Executor<F> for Local {
    fn execute(&self,future:F) { tokio::task::spawn_local(future); }
}

pub(super) async fn serve(engine: &Engine, linker: &Linker<State>) -> anyhow::Result<()> {
    let path=std::env::args().nth(1).ok_or_else(|| anyhow::anyhow!("missing component"))?;
    let component=unsafe { Component::deserialize_file(engine, path)? };
    let instance=linker.instantiate_pre(&component)?;
    let pre=match ServicePre::new(instance.clone()) {
        Ok(service)=>Handler::P3(service),
        Err(_)=>Handler::P2(ProxyPre::new(instance)?),
    };
    // Verify the component's imports/exports and initialization before ready.
    let mut probe=make_store(engine)?;
    match &pre {
        Handler::P2(pre)=>{pre.instantiate_async(&mut probe).await?;},
        Handler::P3(pre)=>{pre.instantiate_async(&mut probe).await?;},
    }
    drop(probe);
    let file=std::fs::File::open("/fenders/listener")?;
    let stream=std::os::unix::net::UnixStream::from(std::os::fd::OwnedFd::from(file));
    stream.set_nonblocking(true)?;
    let stream=tokio::net::UnixStream::from_std(stream)?;
    let budget=Duration::from_millis(setting("FENDERS_REQUEST_TIMEOUT_MS",10_000));
    let limit=Duration::from_millis(setting("FENDERS_HTTP_STREAM_MS",960_000)).max(budget);
    let concurrency=u32::try_from(setting("FENDERS_HTTP_CONCURRENCY",1).clamp(1,64))?;
    let active=Rc::new(Cell::new(0usize));
    println!("FENDERS_HTTP_READY");
    idle(true);
    let service=hyper::service::service_fn(move |request| {
        let pre=pre.clone();let active=active.clone();
        async move {
            let started=tokio::time::Instant::now();
            let (mut task,response)=match pre {
                Handler::P2(pre)=>handle_p2(pre,request)?,
                Handler::P3(pre)=>handle_p3(pre,request)?,
            };
            active.set(active.get()+1);
            idle(false);
            let answered=Rc::new(Cell::new(false));
            let head=answered.clone();
            // The handler outlives its reply's head: it may still be writing
            // the body. It is reaped here: at the request timeout if it has
            // produced no head by then, else at the stream limit. Aborting
            // it drops its Store, which ends the body.
            tokio::task::spawn_local(async move {
                let mut ended=tokio::time::timeout_at(started+budget,&mut task).await;
                if ended.is_err() && head.get() {
                    ended=tokio::time::timeout_at(started+limit,&mut task).await;
                }
                match ended {
                    Ok(Ok(Ok(())))=>{},
                    Ok(other)=>eprintln!("FENDERS_HTTP_HANDLER {other:?}"),
                    Err(_)=>{task.abort();let _=task.await;eprintln!("FENDERS_HTTP_HANDLER_TIMEOUT");},
                }
                active.set(active.get()-1);
                if active.get()==0 { idle(true); }
            });
            match tokio::time::timeout_at(started+budget,response).await {
                Ok(response)=>{answered.set(response.is_ok());response},
                Err(_)=>Err(anyhow::anyhow!("HTTP handler sent no response in time")),
            }
        }
    });
    // The shim's end closing ends the service, and with it the run.
    let local=tokio::task::LocalSet::new();
    local.run_until(hyper::server::conn::http2::Builder::new(Local)
        .max_concurrent_streams(concurrency)
        .serve_connection(TokioIo::new(stream),service)).await?;
    Ok(())
}

type Handled=(tokio::task::JoinHandle<wasmtime::Result<()>>,
    std::pin::Pin<Box<dyn Future<Output=anyhow::Result<hyper::Response<ResponseBody>>>>>);

fn handle_p2(pre:ProxyPre<State>,request:hyper::Request<hyper::body::Incoming>)->anyhow::Result<Handled> {
    let mut store=make_store(pre.engine())?;
    let (sender,receiver)=tokio::sync::oneshot::channel();
    let input=store.data_mut().http().new_incoming_request(Scheme::Http,request)?;
    let output=store.data_mut().http().new_response_outparam(sender)?;
    let task=tokio::spawn(async move {
        let proxy=pre.instantiate_async(&mut store).await?;
        proxy.wasi_http_incoming_handler().call_handle(&mut store,input,output).await
    });
    Ok((task,Box::pin(async move {
        match receiver.await {
            Ok(Ok(response))=>Ok(response.map(|body| body.map_err(anyhow::Error::from).boxed_unsync())),
            Ok(Err(error))=>Err(anyhow::anyhow!("HTTP handler response: {error:?}")),
            Err(_)=>Err(anyhow::anyhow!("HTTP handler terminated before response")),
        }
    })))
}

/// A 0.3 handler runs in its Store's event loop, which keeps running while
/// hyper sends the response body it streams, until that body is dropped.
fn handle_p3(pre:ServicePre<State>,request:hyper::Request<hyper::body::Incoming>)->anyhow::Result<Handled> {
    let mut store=make_store(pre.engine())?;
    let (sender,receiver)=tokio::sync::oneshot::channel();
    let (sent,body_done)=tokio::sync::oneshot::channel::<()>();
    let task=tokio::spawn(async move {
        let service=pre.instantiate_async(&mut store).await?;
        let (request,io)=wasmtime_wasi_http::p3::Request::from_http(store.data_mut().http().hooks,request);
        store.run_concurrent(async move |store| {
            let respond=async {
                let response=match service.handle(store,request).await? {
                    Ok(response)=>response,
                    Err(error)=>{
                        let _=sender.send(Err(anyhow::anyhow!("HTTP handler response: {error:?}")));
                        return wasmtime::Result::Ok(());
                    },
                };
                let response=store.with(|store| response.into_http(store,async { Ok(()) }))?;
                let response=response.map(|body| DropSignal{body,sent:Some(sent)}.map_err(anyhow::Error::from).boxed_unsync());
                if sender.send(Ok(response)).is_ok() {
                    let _=body_done.await;
                }
                Ok(())
            };
            let consumed=async { io.await.map_err(|error| wasmtime::format_err!("HTTP request body: {error:?}")) };
            tokio::try_join!(respond,consumed).map(|_| ())
        }).await?
    });
    Ok((task,Box::pin(async move {
        receiver.await.unwrap_or_else(|_| Err(anyhow::anyhow!("HTTP handler terminated before response")))
    })))
}

/// A response body that says when hyper has dropped it.
struct DropSignal<B> { body:B, sent:Option<tokio::sync::oneshot::Sender<()>> }

impl<B> Drop for DropSignal<B> {
    fn drop(&mut self) { if let Some(sent)=self.sent.take() { let _=sent.send(()); } }
}

impl<B:hyper::body::Body+Unpin> hyper::body::Body for DropSignal<B> {
    type Data=B::Data;
    type Error=B::Error;
    fn poll_frame(mut self:std::pin::Pin<&mut Self>,cx:&mut std::task::Context<'_>)
        ->std::task::Poll<Option<Result<hyper::body::Frame<B::Data>,B::Error>>> {
        std::pin::Pin::new(&mut self.body).poll_frame(cx)
    }
    fn is_end_stream(&self)->bool { self.body.is_end_stream() }
    fn size_hint(&self)->hyper::body::SizeHint { self.body.size_hint() }
}
