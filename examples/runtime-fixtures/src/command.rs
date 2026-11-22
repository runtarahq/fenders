fn main() {
    println!("FENDERS_COMMAND_FIXTURE");
    match std::env::var("TEST_MODE").as_deref() {
        Ok("run-context") => run_context(),
        Ok("wait") => {
            let seconds: u64 = std::env::var("TEST_WAIT_SECONDS")
                .map(|value| value.parse().expect("TEST_WAIT_SECONDS must be an integer"))
                .unwrap_or(5);
            assert!((1..=600).contains(&seconds));
            wasi::clocks::monotonic_clock::subscribe_duration(seconds * 1_000_000_000).block();
            println!("command complete");
        }
        Ok("spin") => loop {
            std::hint::spin_loop();
        },
        Ok("logs") => {
            for _ in 0..20000 {
                println!("{}", "bounded-log-test".repeat(16));
            }
        }
        // Prints a configured value on both streams and fails.
        Ok("leak") => {
            let secret = std::env::var("TEST_SECRET").unwrap_or_default();
            println!("the secret is {secret}");
            eprintln!("failing with {secret}");
            std::process::exit(1);
        }
        Ok("hostile-logs") => {
            println!(r#"<script>globalThis.fendersHostileLogExecuted=true</script>"#);
            println!(
                r#"<img src="/fenders-hostile-log-probe" onerror="globalThis.fendersHostileLogExecuted=true">"#
            );
            eprintln!(
                r#"</pre><svg onload="globalThis.fendersHostileLogExecuted=true"></svg>& < > \" '"#
            );
            println!("FENDERS_HOSTILE_LOG_COMPLETE");
        }
        Ok("memory") => {
            let mut blocks = Vec::new();
            loop {
                blocks.push(vec![42u8; 1024 * 1024]);
                std::hint::black_box(&blocks);
            }
        }
        Ok("memory-limit") => memory_limit(),
        Ok("host-origin") => host_origin(),
        Ok("host-origin-timed") => host_origin_timed(),
        Ok("connect") => connect(),
        _ => println!("command complete"),
    }
}

/// Opens a TCP connection to the endpoint a connection named in the
/// environment (`HOSTADDR` and `PORT`, after `TEST_CONNECTION_PREFIX`), sends
/// `TEST_CONNECT_SEND` (hex) and prints what came back, `TEST_CONNECT_ROUNDS`
/// times a second apart. `TEST_CONNECT_DENIED` is an address the run was not
/// given: reaching it is a failure. With `TEST_CONNECT_BULK` (bytes) each
/// round then sends that many more, 16 KiB at a time, and says how far it
/// got each mebibyte and if a write fails.
fn connect() {
    use std::io::{Read, Write};
    let variable = |name: &str| {
        let prefix = std::env::var("TEST_CONNECTION_PREFIX").unwrap_or_default();
        std::env::var(format!("{prefix}{name}"))
            .unwrap_or_else(|_| panic!("the connection did not set {prefix}{name}"))
    };
    let address = format!("{}:{}", variable("HOSTADDR"), variable("PORT"));
    let send: Vec<u8> = std::env::var("TEST_CONNECT_SEND")
        .unwrap_or_default()
        .as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
    let rounds: u64 = std::env::var("TEST_CONNECT_ROUNDS")
        .map(|value| {
            value
                .parse()
                .expect("TEST_CONNECT_ROUNDS must be an integer")
        })
        .unwrap_or(1);
    assert!((1..=600).contains(&rounds));
    let bulk: usize = std::env::var("TEST_CONNECT_BULK")
        .map(|value| value.parse().expect("TEST_CONNECT_BULK must be an integer"))
        .unwrap_or(0);
    if let Ok(other) = std::env::var("TEST_CONNECT_DENIED") {
        match std::net::TcpStream::connect(&other) {
            Ok(_) => {
                eprintln!("reached {other}, which this run was not given");
                std::process::exit(1);
            }
            Err(error) => println!("refused {other}: {error}"),
        }
    }
    for round in 1..=rounds {
        let mut stream = match std::net::TcpStream::connect(&address) {
            Ok(stream) => stream,
            Err(error) => {
                eprintln!("connecting to {address} failed: {error}");
                std::process::exit(1);
            }
        };
        stream.write_all(&send).expect("sending to the endpoint");
        let mut reply = [0u8; 64];
        let length = if send.is_empty() {
            0
        } else {
            stream
                .read(&mut reply)
                .expect("reading the endpoint's reply")
        };
        let reply: String = reply[..length].iter().map(|b| format!("{b:02x}")).collect();
        println!("connected {address} round {round} reply {reply}");
        let block = [0u8; 16 * 1024];
        let mut sent = 0;
        while sent < bulk {
            let size = block.len().min(bulk - sent);
            if let Err(error) = stream.write_all(&block[..size]) {
                eprintln!("sending failed after {sent} bytes: {error}");
                std::process::exit(1);
            }
            sent += size;
            if sent % (1024 * 1024) == 0 || sent == bulk {
                println!("sent {sent} bytes");
            }
        }
        if round < rounds {
            wasi::clocks::monotonic_clock::subscribe_duration(1_000_000_000).block();
        }
    }
    println!("command complete");
}

/// Calls the host-bound origin with a forged identity; prints what upstream saw.
fn host_origin() {
    use wasi::http::{
        outgoing_handler,
        types::{Fields, OutgoingRequest, Scheme},
    };
    use wasi::io::streams::StreamError;
    let authority = std::env::var("TEST_HOST_ORIGIN_AUTHORITY").unwrap();
    let headers = Fields::new();
    headers
        .append("fenders-execution-identity", b"forged")
        .unwrap();
    let request = OutgoingRequest::new(headers);
    request.set_scheme(Some(&Scheme::Https)).unwrap();
    request.set_authority(Some(&authority)).unwrap();
    request.set_path_with_query(Some("/v1/run")).unwrap();
    let future = outgoing_handler::handle(request, None).expect("host-bound handle");
    future.subscribe().block();
    let response = future.get().unwrap().unwrap().expect("host-bound response");
    assert_eq!(response.status(), 200, "host-bound status");
    let body = response.consume().unwrap();
    let input = body.stream().unwrap();
    let mut bytes = Vec::new();
    loop {
        match input.blocking_read(4096) {
            Ok(chunk) if bytes.len() + chunk.len() <= 8192 => bytes.extend(chunk),
            Ok(_) => panic!("host-bound body limit"),
            Err(StreamError::Closed) => break,
            Err(error) => panic!("host-bound body: {error:?}"),
        }
    }
    println!("FENDERS_HOST_ORIGIN {}", String::from_utf8(bytes).unwrap());
}

/// Calls `TEST_HOST_ORIGIN_PATH` on the host-bound origin and prints when the
/// answer's head and each part of its body came, in milliseconds from the
/// call: a slow answer, and one streamed, as the guest sees them.
fn host_origin_timed() {
    use wasi::clocks::monotonic_clock::now;
    use wasi::http::{
        outgoing_handler,
        types::{Fields, OutgoingRequest, Scheme},
    };
    use wasi::io::streams::StreamError;
    let authority = std::env::var("TEST_HOST_ORIGIN_AUTHORITY").unwrap();
    let path = std::env::var("TEST_HOST_ORIGIN_PATH").unwrap();
    let started = now();
    let ms = || (now() - started) / 1_000_000;
    let request = OutgoingRequest::new(Fields::new());
    request.set_scheme(Some(&Scheme::Https)).unwrap();
    request.set_authority(Some(&authority)).unwrap();
    request.set_path_with_query(Some(&path)).unwrap();
    let future = outgoing_handler::handle(request, None).expect("host-bound handle");
    future.subscribe().block();
    let response = future.get().unwrap().unwrap().expect("host-bound response");
    println!("FENDERS_TIMED head {} at {} ms", response.status(), ms());
    let body = response.consume().unwrap();
    let input = body.stream().unwrap();
    loop {
        match input.blocking_read(65536) {
            Ok(chunk) if chunk.is_empty() => continue,
            Ok(chunk) => println!(
                "FENDERS_TIMED {:?} at {} ms",
                String::from_utf8_lossy(&chunk),
                ms()
            ),
            Err(StreamError::Closed) => break,
            Err(error) => panic!("host-bound body: {error:?}"),
        }
    }
    println!("FENDERS_TIMED end at {} ms", ms());
}

fn run_context() {
    const PUBLIC: &[&str] = &[
        "FENDERS_TRIGGER",
        "FENDERS_TRIGGER_TIME",
        "FENDERS_RUN_ID",
        "FENDERS_SCHEDULE",
        "FENDERS_SCHEDULE_TIMEZONE",
    ];
    assert_eq!(
        std::env::var("APP_CONFIG").unwrap(),
        "runtime-qualification"
    );
    for (name, _) in std::env::vars().filter(|(name, _)| name.starts_with("FENDERS_")) {
        assert!(
            PUBLIC.contains(&name.as_str()),
            "runtime policy leaked: {name}"
        );
    }
    for name in PUBLIC {
        let expected = std::env::var(format!("EXPECTED_{name}")).ok();
        assert_eq!(
            std::env::var(name).ok(),
            expected,
            "run context mismatch: {name}"
        );
    }
    println!("FENDERS_RUN_CONTEXT_PRIVATE_COMPLETE");
}

#[cfg(target_arch = "wasm32")]
fn memory_limit() {
    use core::arch::wasm32::{memory_grow, memory_size};
    let mib: usize = std::env::var("TEST_MEMORY_MIB").unwrap().parse().unwrap();
    assert!((2..=504).contains(&mib));
    let maximum = mib * 16;
    let initial = memory_size::<0>();
    assert!(
        initial < maximum,
        "fixture starts at or above tested ceiling"
    );
    // In steps when asked, so a growth that moves the memory briefly holds
    // the old and the new copy, as an application growing gradually does.
    let step = std::env::var("TEST_MEMORY_STEP_MIB")
        .map(|step| step.parse::<usize>().unwrap() * 16)
        .unwrap_or(maximum - initial)
        .max(1);
    let mut size = initial;
    while size < maximum {
        let grow = step.min(maximum - size);
        assert_eq!(
            memory_grow::<0>(grow),
            size,
            "growth to configured ceiling failed"
        );
        size += grow;
    }
    assert_eq!(memory_size::<0>(), maximum);
    // These pages were just created beyond every existing Rust allocation.
    // Touch and read one byte in each page; never access prior allocator pages.
    for page in initial..maximum {
        let address = (page * 65536) as *mut u8;
        unsafe {
            address.write_volatile(0x5a);
            assert_eq!(address.read_volatile(), 0x5a);
        }
    }
    assert_eq!(
        memory_grow::<0>(1),
        usize::MAX,
        "growth beyond configured ceiling was permitted"
    );
    assert_eq!(memory_size::<0>(), maximum);
    println!(
        "FENDERS_MEMORY_LIMIT {{\"initial_pages\":{initial},\"maximum_pages\":{maximum},\"touched_pages\":{},\"beyond_limit_rejected\":true}}",
        maximum - initial
    );
}

#[cfg(not(target_arch = "wasm32"))]
fn memory_limit() {
    panic!("memory-limit fixture requires wasm32");
}
