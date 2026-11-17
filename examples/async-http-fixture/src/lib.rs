//! WASI 0.3 HTTP service fixture. It exports `wasi:http/handler@0.3.0`, whose
//! `handle` is an async function, so the runtime must serve it as a 0.3
//! service. It answers with the request body, or `fenders:{path}` when there is
//! none, streamed after `handle` returns; `/wait` holds the request for half a
//! second.
wit_bindgen::generate!({
    path: "wit",
    world: "async-http",
    generate_all,
});

use wasi::http::types::{ErrorCode, Fields, Request, Response};

struct Service;

impl exports::wasi::http::handler::Guest for Service {
    async fn handle(request: Request) -> Result<Response, ErrorCode> {
        let path = request.get_path_with_query().unwrap_or_default();
        if path == "/wait" {
            wasi::clocks::monotonic_clock::wait_for(500_000_000).await;
        }
        let (consumed, consumed_rx) = wit_future::new(|| Ok(()));
        let (body, trailers) = Request::consume_body(request, consumed_rx);
        let mut bytes = body.collect().await;
        let _ = trailers.await;
        let _ = consumed.write(Ok(())).await;
        if bytes.is_empty() {
            bytes = format!("fenders:{path}").into_bytes();
        }
        let headers = Fields::new();
        headers
            .set("content-type", &[b"text/plain".to_vec()])
            .map_err(|_| ErrorCode::InternalError(None))?;
        let (mut contents, contents_rx) = wit_stream::new();
        let (trailers, trailers_rx) = wit_future::new(|| Ok(None));
        let (response, transmitted) = Response::new(headers, Some(contents_rx), trailers_rx);
        // The body is written once the runtime has the response.
        wit_bindgen::spawn_local(async move {
            for chunk in bytes.chunks(4096) {
                contents.write_all(chunk.to_vec()).await;
            }
            drop(contents);
            let _ = trailers.write(Ok(None)).await;
            let _ = transmitted.await;
            println!("request completed: {path}");
        });
        Ok(response)
    }
}

export!(Service);
