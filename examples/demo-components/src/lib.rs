use wasi::http::types::{
    Fields, IncomingRequest, OutgoingBody, OutgoingResponse, ResponseOutparam,
};
struct Hello;
wasi::http::proxy::export!(Hello);
impl wasi::exports::http::incoming_handler::Guest for Hello {
    fn handle(_request: IncomingRequest, response: ResponseOutparam) {
        let headers = Fields::new();
        headers
            .set("content-type", &[b"text/plain; charset=utf-8".to_vec()])
            .unwrap();
        let output = OutgoingResponse::new(headers);
        output.set_status_code(200).unwrap();
        let body = output.body().unwrap();
        ResponseOutparam::set(response, Ok(output));
        let stream = body.write().unwrap();
        stream
            .blocking_write_and_flush(b"Hello from Fenders.\n")
            .unwrap();
        drop(stream);
        OutgoingBody::finish(body, None).unwrap();
        println!("HTTP request completed.");
    }
}
