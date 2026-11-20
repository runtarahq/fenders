use fenders_guest_http::platform::{platform_root_store, request_target};

#[test]
fn outgoing_requests_use_exact_pinned_origins_without_dns_fallback() {
    let policy = "https://api.example.com:443=1.1.1.1,8.8.8.8";
    let allowed = "https://api.example.com:443,http://10.50.0.2:8080";
    assert_eq!(
        request_target(policy, allowed, "API.EXAMPLE.COM", true)
            .unwrap()
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        ["1.1.1.1:443", "8.8.8.8:443"]
    );
    assert_eq!(
        request_target(policy, allowed, "10.50.0.2:8080", false).unwrap()[0].to_string(),
        "10.50.0.2:8080"
    );
    for (host, tls) in [
        ("api.example.com", false),
        ("api.example.com:8443", true),
        ("other.example.com", true),
        ("1.1.1.1:443", true),
        ("169.254.169.254", true),
        ("api.example.com.", true),
        ("user@api.example.com", true),
        ("[::ffff:1.1.1.1]", true),
    ] {
        assert!(
            request_target(policy, allowed, host, tls).is_err(),
            "{host}"
        );
    }
    // A redirect that the component follows is a new request and needs its own
    // origin permission. Same-IP hosting does not grant another origin access.
    assert!(request_target(policy, allowed, "redirect.example.com", true).is_err());
    assert!(request_target("", allowed, "api.example.com", true).is_err());
    assert!(request_target(policy, "", "api.example.com", true).is_err());
    assert!(
        request_target(
            "https://api.example.com:443=1.1.1.1,127.0.0.1",
            allowed,
            "api.example.com",
            true
        )
        .is_err()
    );
    // Parse the entire policy, including unrelated entries, before connecting.
    assert!(
        request_target(
            &format!("{policy};https://evil.example.com:443=10.0.0.1"),
            allowed,
            "api.example.com",
            true
        )
        .is_err()
    );
}

#[test]
fn public_https_cannot_replace_public_roots_with_service_roots() {
    let policy = "https://api.example.com:443=1.1.1.1";
    let public = platform_root_store(policy, "", "API.EXAMPLE.COM").unwrap();
    assert!(public.len() > 1);
    let mut params = rcgen::CertificateParams::new(vec![]).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
    let key = rcgen::KeyPair::generate().unwrap();
    let ca = params.self_signed(&key).unwrap();
    let private_roots = format!(
        "https://api.example.com:443={}",
        ca.der()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    assert_eq!(
        platform_root_store("", &private_roots, "api.example.com")
            .unwrap()
            .len(),
        1
    );
    assert!(platform_root_store(policy, &private_roots, "api.example.com").is_err());
    assert!(
        platform_root_store(policy, "https://api.example.com:443=00", "api.example.com").is_err()
    );
    assert!(
        platform_root_store(
            "https://api.example.com:443=10.0.0.1",
            "",
            "api.example.com"
        )
        .is_err()
    );
}

// Environment is part of the actual embedding contract. Run each adapter
// request in a fresh process instead of mutating process-global environment
// alongside parallel Rust tests. No public network or guest is involved.
#[test]
fn real_adapter_enforces_pins_returns_redirects_and_bounds_tls_setup() {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        process::Command,
        time::Duration,
    };
    for scenario in [
        "redirect",
        "tls-stall",
        "response-stall",
        "unmapped-name",
        "private-answer",
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let tls = scenario == "tls-stall";
        let origin = format!("{}://{address}", if tls { "https" } else { "http" });
        let denied = matches!(scenario, "unmapped-name" | "private-answer");
        listener.set_nonblocking(true).unwrap();
        let server = std::thread::spawn(move || {
            let until = std::time::Instant::now() + Duration::from_secs(2);
            let mut connected = false;
            while std::time::Instant::now() < until {
                match listener.accept() {
                    Ok((mut socket, _)) => {
                        socket.set_nonblocking(false).unwrap();
                        assert!(!denied, "forbidden request reached the server");
                        assert!(!connected, "adapter followed a redirect");
                        connected = true;
                        if scenario == "redirect" {
                            socket
                                .set_read_timeout(Some(Duration::from_secs(1)))
                                .unwrap();
                            let mut input = [0; 4096];
                            assert!(socket.read(&mut input).unwrap() > 0);
                            write!(socket, "HTTP/1.1 302 Found\r\nLocation: http://{address}/follow\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
                        } else {
                            // A timeout must occur before EOF or a TLS error.
                            std::thread::sleep(Duration::from_millis(500));
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5))
                    }
                    Err(error) => panic!("{error}"),
                }
            }
            assert_eq!(connected, !denied);
        });
        let request_uri = if scenario == "unmapped-name" {
            format!("https://unmapped.invalid:{}/", address.port())
        } else {
            format!("{origin}/")
        };
        let allowed = if scenario == "unmapped-name" {
            format!("https://unmapped.invalid:{}", address.port())
        } else {
            origin
        };
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "transport_child", "--nocapture"])
            .env("FENDERS_ADAPTER_SCENARIO", scenario)
            .env("FENDERS_ADAPTER_URI", request_uri)
            .env("FENDERS_HTTP_ALLOW", allowed)
            .env("FENDERS_HTTP_SERVICE_ROOTS", "")
            .env(
                "FENDERS_HTTP_PUBLIC_TARGETS",
                if scenario == "private-answer" {
                    "https://api.example.com:443=127.0.0.1"
                } else {
                    ""
                },
            )
            .output()
            .unwrap();
        server.join().unwrap();
        assert!(
            output.status.success(),
            "{scenario}: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[tokio::test]
async fn transport_child() {
    use fenders_guest_http::send_request;
    use http_body_util::BodyExt;
    use wasmtime_wasi_http::{Error as ErrorCode, RequestOptions};
    let Ok(scenario) = std::env::var("FENDERS_ADAPTER_SCENARIO") else {
        return;
    };
    let uri = std::env::var("FENDERS_ADAPTER_URI").unwrap();
    let request = hyper::Request::builder()
        .uri(&uri)
        .body(
            http_body_util::Empty::<bytes::Bytes>::new()
                .map_err(|_| unreachable!())
                .boxed(),
        )
        .unwrap();
    let result = send_request(
        request,
        Some(RequestOptions {
            connect_timeout: Some(std::time::Duration::from_millis(150)),
            first_byte_timeout: Some(std::time::Duration::from_millis(150)),
            between_bytes_timeout: Some(std::time::Duration::from_secs(600)),
        }),
    )
    .await
    .map(|(response, _io)| response);
    match scenario.as_str() {
        "redirect" => {
            let response = result.unwrap();
            assert_eq!(response.status(), 302);
            // The application's ten-minute between-bytes wait is capped.
            assert_eq!(
                fenders_guest_http::platform::response_wait(std::time::Duration::from_secs(600)),
                std::time::Duration::from_secs(10)
            );
        }
        "tls-stall" => assert!(matches!(result, Err(ErrorCode::ConnectionTimeout))),
        "response-stall" => assert!(matches!(result, Err(ErrorCode::ConnectionReadTimeout))),
        "unmapped-name" | "private-answer" => {
            assert!(matches!(result, Err(ErrorCode::HttpRequestDenied)))
        }
        _ => panic!("unknown fixture"),
    }
}
