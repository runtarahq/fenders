//! Maintained live-update fixture. TLS and origin checks run in the guest's
//! WASI HTTP implementation; the application cannot supply an IP or trust root.
use wasi::http::{
    outgoing_handler,
    types::{Fields, IncomingBody, OutgoingRequest, RequestOptions, Scheme},
};
use wasi::io::streams::StreamError;

fn fetch() -> Result<(), String> {
    let request = OutgoingRequest::new(Fields::new());
    request.set_scheme(Some(&Scheme::Https)).unwrap();
    request.set_authority(Some("example.com:443")).unwrap();
    request.set_path_with_query(Some("/")).unwrap();
    let options = RequestOptions::new();
    options.set_connect_timeout(Some(3_000_000_000)).unwrap();
    options.set_first_byte_timeout(Some(5_000_000_000)).unwrap();
    options
        .set_between_bytes_timeout(Some(2_000_000_000))
        .unwrap();
    let future = outgoing_handler::handle(request, Some(options))
        .map_err(|error| format!("HTTPS handle: {error:?}"))?;
    future.subscribe().block();
    let response = future
        .get()
        .ok_or("HTTPS response not ready")?
        .map_err(|_| "HTTPS response already consumed")?
        .map_err(|error| format!("HTTPS response: {error:?}"))?;
    if response.status() != 200 {
        return Err(format!("HTTPS status {}", response.status()));
    }
    let body = response
        .consume()
        .map_err(|_| "HTTPS body already consumed")?;
    let input = body.stream().map_err(|_| "HTTPS stream already consumed")?;
    let mut bytes = Vec::new();
    loop {
        match input.blocking_read(4096) {
            Ok(chunk) => {
                if bytes.len() + chunk.len() > 64 * 1024 {
                    return Err("HTTPS body limit".into());
                }
                bytes.extend(chunk);
            }
            Err(StreamError::Closed) => break,
            Err(error) => return Err(format!("HTTPS body: {error:?}")),
        }
    }
    drop(input);
    let trailers = IncomingBody::finish(body);
    trailers.subscribe().block();
    trailers
        .get()
        .ok_or("HTTPS trailers not ready")?
        .map_err(|_| "HTTPS trailers already consumed")?
        .map_err(|error| format!("HTTPS trailers: {error:?}"))?;
    if !bytes
        .windows(b"Example Domain".len())
        .any(|part| part == b"Example Domain")
    {
        return Err("unexpected verified HTTPS body".into());
    }
    Ok(())
}

fn denied() -> Result<(), String> {
    let request = OutgoingRequest::new(Fields::new());
    request.set_scheme(Some(&Scheme::Https)).unwrap();
    request.set_authority(Some("example.com:443")).unwrap();
    request.set_path_with_query(Some("/")).unwrap();
    match outgoing_handler::handle(request, None) {
        Err(wasi::http::types::ErrorCode::HttpRequestDenied) => Ok(()),
        Err(error) => Err(format!("unexpected denial: {error:?}")),
        Ok(future) => {
            future.subscribe().block();
            match future.get() {
                Some(Ok(Err(wasi::http::types::ErrorCode::HttpRequestDenied))) => Ok(()),
                _ => Err("unapproved HTTPS origin was not denied by policy".into()),
            }
        }
    }
}

fn main() {
    if std::env::var("TEST_HTTPS_DENIED").as_deref() == Ok("1") {
        denied().expect("HTTPS policy denial");
        println!("FENDERS_HTTPS_POLICY_DENIED");
        return;
    }
    let finite = std::env::var("TEST_HTTPS_REQUESTS").ok();
    let requests: u64 = finite
        .as_ref()
        .map(|value| value.parse().unwrap())
        .unwrap_or(512);
    assert!((1..=512).contains(&requests));
    #[cfg(target_arch = "wasm32")]
    let maximum = {
        let mib: usize = std::env::var("TEST_MEMORY_MIB")
            .unwrap_or_else(|_| "8".into())
            .parse()
            .expect("invalid fixture memory profile");
        assert!(
            (4..=504).contains(&mib),
            "fixture requires a named-size memory limit"
        );
        mib * 16
    };
    // Every successful response advances guest memory. A restarted invocation
    // repeats the start marker and resets sequence; the harness must reject it.
    println!("FENDERS_HTTPS_STARTED");
    for sequence in 1_u64..=requests {
        if let Err(error) = fetch() {
            eprintln!("FENDERS_HTTPS_FAILED {error}");
            std::process::exit(1);
        }
        #[cfg(target_arch = "wasm32")]
        {
            use core::arch::wasm32::{memory_grow, memory_size};
            // Reject one page beyond the selected profile without consuming the live
            // allocator's spare pages or disturbing the continuing TLS work.
            let current = memory_size::<0>();
            assert!(current <= maximum);
            assert_eq!(memory_grow::<0>(maximum - current + 1), usize::MAX);
            assert_eq!(memory_size::<0>(), current);
            println!(
                "FENDERS_MEMORY_CEILING {{\"sequence\":{sequence},\"maximum_pages\":{maximum},\"beyond_limit_rejected\":true}}"
            );
        }
        println!("FENDERS_HTTPS_PROGRESS sequence={sequence} status=200");
        wasi::clocks::monotonic_clock::subscribe_duration(500_000_000).block();
    }
    if finite.is_some() {
        println!("FENDERS_HTTPS_QUALIFICATION_COMPLETE");
        return;
    }
    panic!("HTTPS fixture outlived its bounded qualification window");
}
