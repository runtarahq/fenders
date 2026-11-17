//! Ingress fixture: real valid WASM payload plus pre-encoded representations.
use wasi::http::types::*;
pub fn handle(request: &IncomingRequest, response: ResponseOutparam) {
    let path = request.path_with_query().unwrap_or_default();
    let input = request.headers();
    let headers = Fields::new();
    headers
        .set("content-type", &[b"application/wasm".to_vec()])
        .unwrap();
    let tag = if path == "/compression/weak" {
        b"W/\"fixture-v1\"".to_vec()
    } else {
        b"\"fixture-v1\"".to_vec()
    };
    headers.set("etag", &[tag]).unwrap();
    headers
        .set(
            "last-modified",
            &[b"Wed, 21 Oct 2015 07:28:00 GMT".to_vec()],
        )
        .unwrap();
    headers
        .set("expires", &[b"Mon, 21 Oct 2030 07:28:00 GMT".to_vec()])
        .unwrap();
    headers
        .set("cache-control", &[b"public, max-age=0".to_vec()])
        .unwrap();
    headers
        .set("vary", &[b"Origin".to_vec(), b"Accept-Encoding".to_vec()])
        .unwrap();
    headers
        .set("set-cookie", &[b"bad=1; Domain=apps.example.com".to_vec()])
        .unwrap();
    // If-None-Match uses weak comparison for GET/HEAD and takes precedence
    // over If-Modified-Since. This fixture's opaque tag contains no commas.
    let validators = input.get("if-none-match");
    let unchanged = if validators.is_empty() {
        input
            .get("if-modified-since")
            .iter()
            .any(|v| v == b"Wed, 21 Oct 2015 07:28:00 GMT")
    } else {
        validators.iter().any(|v| {
            String::from_utf8_lossy(v).split(',').any(|tag| {
                let tag = tag.trim();
                tag == "*" || tag.strip_prefix("W/").unwrap_or(tag) == "\"fixture-v1\""
            })
        })
    };
    let bytes = match path.as_str() {
        "/compression/encoded-br" => {
            headers.set("content-encoding", &[b"br".to_vec()]).unwrap();
            include_bytes!("http-assets/asset.wasm.br").to_vec()
        }
        "/compression/encoded-gzip" => {
            headers
                .set("content-encoding", &[b"gzip".to_vec()])
                .unwrap();
            include_bytes!("http-assets/asset.wasm.gz").to_vec()
        }
        "/compression/headers" => {
            headers
                .set("content-type", &[b"text/plain".to_vec()])
                .unwrap();
            format!("{:?}", input.entries()).into_bytes()
        }
        "/compression/large" => vec![0; 1024 * 1024 + 1],
        "/compression/small" => b"small".to_vec(),
        _ => include_bytes!("http-assets/asset.wasm").to_vec(),
    };
    let output = OutgoingResponse::new(headers);
    output
        .set_status_code(if unchanged { 304 } else { 200 })
        .unwrap();
    let body = output.body().unwrap();
    ResponseOutparam::set(response, Ok(output));
    let stream = body.write().unwrap();
    if !unchanged && !matches!(request.method(), Method::Head) {
        for chunk in bytes.chunks(4096) {
            stream.blocking_write_and_flush(chunk).unwrap();
        }
    }
    drop(stream);
    OutgoingBody::finish(body, None).unwrap();
}
