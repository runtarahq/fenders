mod http_compression;
use wasi::http::types::*;

/// Calls the run channel over the host-bound origin an app with WebSocket
/// is given: the status and the body.
pub fn platform(method: Method, path: &str, text: Option<&str>) -> (u16, Vec<u8>) {
    let headers = Fields::new();
    if text.is_some() {
        headers.set("content-type", &[b"text/plain".to_vec()]).unwrap();
    }
    let request = OutgoingRequest::new(headers);
    request.set_method(&method).unwrap();
    request.set_scheme(Some(&Scheme::Http)).unwrap();
    request.set_authority(Some("fenders.internal")).unwrap();
    request.set_path_with_query(Some(path)).unwrap();
    let body = request.body().unwrap();
    if let Some(text) = text {
        let stream = body.write().unwrap();
        stream.blocking_write_and_flush(text.as_bytes()).unwrap();
        drop(stream);
    }
    OutgoingBody::finish(body, None).unwrap();
    let future = match wasi::http::outgoing_handler::handle(request, None) {
        Ok(future) => future,
        Err(error) => return (0, format!("{error:?}").into_bytes()),
    };
    future.subscribe().block();
    let response = match future.get().unwrap().unwrap() {
        Ok(response) => response,
        Err(error) => return (0, format!("{error:?}").into_bytes()),
    };
    let status = response.status();
    let incoming = response.consume().unwrap();
    let stream = incoming.stream().unwrap();
    let mut bytes = Vec::new();
    loop {
        match stream.blocking_read(16384) {
            Ok(chunk) => bytes.extend_from_slice(&chunk),
            Err(_) => break,
        }
    }
    (status, bytes)
}

/// The ids in the run channel's list of the app's open connections.
pub fn connections() -> Vec<String> {
    let (_, body) = platform(Method::Get, "/v1/run/ws", None);
    String::from_utf8_lossy(&body)
        .split('"')
        .filter(|part| part.len() == 32 && part.bytes().all(|b| b.is_ascii_hexdigit()))
        .map(str::to_owned)
        .collect()
}

/// Sends `text` to every open connection of the app: how many took it.
pub fn broadcast(text: &str) -> usize {
    connections()
        .iter()
        .filter(|id| platform(Method::Post, &format!("/v1/run/ws/{id}"), Some(text)).0 == 200)
        .count()
}

struct Application;
wasi::http::proxy::export!(Application);
impl wasi::exports::http::incoming_handler::Guest for Application {
    fn handle(request: IncomingRequest, response: ResponseOutparam) {
        let path = request.path_with_query().unwrap_or_default();
        if path.starts_with("/compression/") {
            return http_compression::handle(&request, response);
        }
        let hold_ms: u64 = std::env::var("HTTP_HOLD_MS")
            .unwrap_or_else(|_| "0".into())
            .parse()
            .expect("invalid fixture HTTP hold");
        assert!(hold_ms <= 15_000, "fixture HTTP hold exceeds 15 seconds");
        if hold_ms > 0 {
            println!("FENDERS_HTTP_HOLD_STARTED");
            wasi::clocks::monotonic_clock::subscribe_duration(hold_ms * 1_000_000).block();
        }
        if path == "/spin" {
            loop {
                std::hint::spin_loop();
            }
        }
        if path == "/wait" {
            wasi::clocks::monotonic_clock::subscribe_duration(500_000_000).block();
        }
        // A WebSocket's events, which the gateway sends an app that accepts
        // connections, and requests that send to connections:
        //   connect     refused when the client asked for a path with "refuse";
        //   message     "broadcast:TEXT" goes to every connection, "close"
        //               closes this one, anything else is echoed back;
        //   /push/ID/TEXT   sends TEXT to connection ID;
        //   /connections    lists the open connections.
        if path.starts_with("/_fenders/ws/") || path.starts_with("/push/") || path == "/connections" {
            let header = |name: &str| {
                request
                    .headers()
                    .get(name)
                    .first()
                    .map(|v| String::from_utf8_lossy(v).into_owned())
                    .unwrap_or_default()
            };
            let (connection, asked) = (header("fenders-connection"), header("fenders-path"));
            let input = request.consume().unwrap();
            let stream = input.stream().unwrap();
            let mut sent = Vec::new();
            loop {
                match stream.blocking_read(65536) {
                    Ok(chunk) => sent.extend_from_slice(&chunk),
                    Err(_) => break,
                }
            }
            drop(stream);
            IncomingBody::finish(input);
            let sent = String::from_utf8_lossy(&sent).into_owned();
            let (status, answer) = if path == "/_fenders/ws/connect" {
                (if asked.contains("refuse") { 403 } else { 200 }, String::new())
            } else if path == "/_fenders/ws/message" {
                if let Some(text) = sent.strip_prefix("broadcast:") {
                    (200, format!("broadcast to {}", broadcast(&format!("all:{text}"))))
                } else if sent == "close" {
                    platform(Method::Delete, &format!("/v1/run/ws/{connection}"), None);
                    (200, String::new())
                } else {
                    (200, format!("echo:{sent}"))
                }
            } else if let Some(rest) = path.strip_prefix("/push/") {
                let (id, text) = rest.split_once('/').unwrap_or((rest, ""));
                let (status, _) = platform(Method::Post, &format!("/v1/run/ws/{id}"), Some(&format!("pushed:{text}")));
                (200, format!("pushed:{status}"))
            } else if path == "/connections" {
                (200, connections().join(","))
            } else {
                (200, String::new())
            };
            let headers = Fields::new();
            headers.set("content-type", &[b"text/plain".to_vec()]).unwrap();
            let output = OutgoingResponse::new(headers);
            output.set_status_code(status).unwrap();
            let body = output.body().unwrap();
            ResponseOutparam::set(response, Ok(output));
            let stream = body.write().unwrap();
            if !answer.is_empty() {
                stream.blocking_write_and_flush(answer.as_bytes()).unwrap();
            }
            drop(stream);
            OutgoingBody::finish(body, None).unwrap();
            return;
        }
        // Bodies passed on as they come, never held whole:
        //   /count      reads the request's body and answers `count:BYTES`;
        //   /bytes/N    answers N bytes, a repeating 0..=250 pattern;
        //   /events/N   answers N server-sent events, 300 ms apart.
        if path == "/count" || path.starts_with("/bytes/") || path.starts_with("/events/") {
            let input = request.consume().unwrap();
            let stream = input.stream().unwrap();
            let mut count = 0u64;
            loop {
                match stream.blocking_read(65536) {
                    Ok(chunk) => count += chunk.len() as u64,
                    Err(wasi::io::streams::StreamError::Closed) => break,
                    Err(error) => panic!("{error:?}"),
                }
            }
            drop(stream);
            IncomingBody::finish(input);
            let number = |prefix: &str| -> u64 {
                path[prefix.len()..].parse().expect("fixture path number")
            };
            let events = path.starts_with("/events/");
            let headers = Fields::new();
            let kind: &[u8] = if events { b"text/event-stream" } else { b"text/plain" };
            headers.set("content-type", &[kind.to_vec()]).unwrap();
            let output = OutgoingResponse::new(headers);
            output.set_status_code(200).unwrap();
            let body = output.body().unwrap();
            ResponseOutparam::set(response, Ok(output));
            let stream = body.write().unwrap();
            if path == "/count" {
                stream
                    .blocking_write_and_flush(format!("count:{count}").as_bytes())
                    .unwrap();
            } else if events {
                for event in 1..=number("/events/") {
                    stream
                        .blocking_write_and_flush(format!("data: event {event}\n\n").as_bytes())
                        .unwrap();
                    wasi::clocks::monotonic_clock::subscribe_duration(300_000_000).block();
                }
            } else {
                let pattern: Vec<u8> = (0..4016u32).map(|n| (n % 251) as u8).collect();
                let mut left = number("/bytes/");
                while left > 0 {
                    let part = left.min(pattern.len() as u64) as usize;
                    stream.blocking_write_and_flush(&pattern[..part]).unwrap();
                    left -= part as u64;
                }
            }
            drop(stream);
            OutgoingBody::finish(body, None).unwrap();
            return;
        }
        let input = request.consume().unwrap();
        let stream = input.stream().unwrap();
        let mut bytes = Vec::new();
        loop {
            match stream.blocking_read(16384) {
                Ok(chunk) => bytes.extend_from_slice(&chunk),
                Err(wasi::io::streams::StreamError::Closed) => break,
                Err(error) => panic!("{error:?}"),
            }
        }
        drop(stream);
        IncomingBody::finish(input);
        if path == "/outgoing" {
            let req = OutgoingRequest::new(Fields::new());
            req.set_scheme(Some(&Scheme::Http)).unwrap();
            req.set_authority(Some("127.0.0.1:18081")).unwrap();
            req.set_path_with_query(Some("/fixture")).unwrap();
            bytes = match wasi::http::outgoing_handler::handle(req, None) {
                Ok(future) => {
                    future.subscribe().block();
                    match future.get().unwrap().unwrap() {
                        Ok(reply) => format!("upstream:{}", reply.status()).into_bytes(),
                        Err(error) => format!("denied:{error:?}").into_bytes(),
                    }
                }
                Err(error) => format!("denied:{error:?}").into_bytes(),
            };
        } else if bytes.is_empty() {
            bytes = format!("fenders:{path}").into_bytes();
        }
        let headers = Fields::new();
        headers
            .set("content-type", &[b"text/plain".to_vec()])
            .unwrap();
        let output = OutgoingResponse::new(headers);
        output.set_status_code(200).unwrap();
        let body = output.body().unwrap();
        ResponseOutparam::set(response, Ok(output));
        let stream = body.write().unwrap();
        for chunk in bytes.chunks(4096) {
            stream.blocking_write_and_flush(chunk).unwrap();
        }
        drop(stream);
        OutgoingBody::finish(body, None).unwrap();
        println!("request completed: {path}");
    }
}
