use super::*;
use std::{process::Stdio, time::Duration};

async fn status(client: &reqwest::Client, origin: &str, token: &str) -> Value {
    let response = client
        .get(format!("{origin}/v1/control-plane/status"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    serde_json::from_slice(&response.bytes().await.unwrap()).unwrap()
}
async fn observe(
    client: &reqwest::Client,
    origin: &str,
    token: &str,
    predicate: impl Fn(&Value) -> bool,
) -> Value {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let snapshot = status(client, origin, token).await;
            if predicate(&snapshot) {
                break snapshot;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("daemon loop did not reach the expected observation")
}
fn scheduler(snapshot: &Value) -> &Value {
    snapshot["components"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["component"] == "scheduler")
        .unwrap()
}
fn component_names(snapshot: &Value) -> Vec<&str> {
    let mut names: Vec<_> = snapshot["components"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| s(&value["component"]))
        .collect();
    names.sort_unstable();
    names
}
pub(super) fn database_url(l: &Lab) -> String {
    use sqlx::ConnectOptions;
    let mut dsn = l.admin.connect_options().to_url_lossy();
    // sqlx 0.8 serializes CertificateInput::File using its display form
    // ("file: PATH"), while its URL parser expects the actual path. Preserve
    // verify-full and the original trust file when passing options to a daemon.
    let parameters: Vec<(String, String)> = dsn
        .query_pairs()
        .map(|(name, value)| {
            let value = if matches!(name.as_ref(), "sslrootcert" | "sslcert" | "sslkey") {
                value.strip_prefix("file: ").unwrap_or(&value).to_owned()
            } else {
                value.into_owned()
            };
            (name.into_owned(), value)
        })
        .collect();
    dsn.query_pairs_mut().clear().extend_pairs(parameters);
    dsn.query_pairs_mut()
        .append_pair("options", &format!("-c search_path={}", l.schema));
    dsn.to_string()
}
async fn start(
    l: &Lab,
    external_policy: bool,
    tls: bool,
) -> (tokio::process::Child, String, reqwest::Client) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let dsn = database_url(l);
    let binary = std::env::var_os("FENDERS_TEST_CONTROL_PLANE_BIN")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_fenders-control-plane").into());
    let mut command = tokio::process::Command::new(binary);
    command
        .args(["--port", &port.to_string(), "--state"])
        .arg(l.root.path())
        .env("FENDERS_DATABASE_URL", &dsn)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    if external_policy {
        let path = l.root.path().join("external-network.json");
        if !path.exists() {
            std::fs::write(&path, br#"{"allowed_cidrs":[],"denied_cidrs":[]}"#).unwrap();
        }
        command.arg("--external-network").arg(path);
    }
    let mut client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(2));
    if tls {
        let database_url = l.root.path().join(format!("database-url-{}", uid()));
        fenders_control_plane::pki::private_file(&database_url, format!("{dsn}\n").as_bytes())
            .unwrap();
        command.arg("--database-url-file").arg(database_url).env(
            "FENDERS_DATABASE_URL",
            "deliberately-invalid-file-takes-precedence",
        );
        let pki = l.root.path().join("daemon-pki");
        if !pki.exists() {
            fenders_control_plane::pki::create(
                &pki,
                &std::collections::BTreeMap::from([("control".into(), vec!["127.0.0.1".into()])]),
            )
            .unwrap();
        }
        command
            .arg("--ca")
            .arg(pki.join("ca.pem"))
            .arg("--cert")
            .arg(pki.join("control.pem"))
            .arg("--key")
            .arg(pki.join("control.key"))
            .args(["--internal-port", "0", "--gateway-port", "0"]);
        client = client.add_root_certificate(
            reqwest::Certificate::from_pem(&std::fs::read(pki.join("ca.pem")).unwrap()).unwrap(),
        );
    } else {
        command.arg("--dev-http");
    }
    let mut child = command.spawn().unwrap();
    let origin = format!("{}://127.0.0.1:{port}", if tls { "https" } else { "http" });
    let client = client.build().unwrap();
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            assert!(
                child.try_wait().unwrap().is_none(),
                "daemon exited during startup"
            );
            if let Ok(response) = client
                .get(format!("{origin}/v1/control-plane/status"))
                .bearer_auth(&l.token)
                .send()
                .await
                && response.status() == StatusCode::OK
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("daemon did not expose its authenticated status");
    (child, origin, client)
}
async fn terminate(child: &mut tokio::process::Child) {
    let pid = child.id().expect("owned running daemon");
    assert_eq!(
        unsafe { libc::kill(pid.try_into().unwrap(), libc::SIGTERM) },
        0
    );
    assert!(
        tokio::time::timeout(Duration::from_secs(5), child.wait())
            .await
            .unwrap()
            .unwrap()
            .success()
    );
}

// A real process exit must drain every TLS listener. Selecting the first idle
// listener to finish would cancel this request on the busy management listener.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn overlapping_tls_daemons_drain_an_accepted_request_and_share_its_receipt() {
    let l = Lab::new().await;
    overlap(l).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "dedicated Linux dev host, pinned Docker PostgreSQL TLS fixture and private test credentials required"]
async fn dev_overlapping_tls_daemons_preserve_accepted_request() {
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(std::env::consts::OS, "linux");
    assert_eq!(unsafe { libc::geteuid() }, 0);
    let output =
        std::path::PathBuf::from(std::env::var_os("FENDERS_CONTROL_OVERLAP_OUTPUT").unwrap());
    assert_eq!(
        std::fs::metadata(&output).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let credentials: Value = serde_json::from_slice(
        &std::fs::read(std::env::var_os("FENDERS_CONTROL_OVERLAP_CREDENTIALS").unwrap()).unwrap(),
    )
    .unwrap();
    let pg = super::agent_upgrade_live::Postgres::start(&output, &credentials).await;
    let l = Lab::with_options(pg.options.clone()).await;
    let tls: bool = sqlx::query_scalar(
        "SELECT ssl AND version='TLSv1.3' FROM pg_stat_ssl WHERE pid=pg_backend_pid()",
    )
    .fetch_one(&l.store.pool)
    .await
    .unwrap();
    assert!(tls);
    overlap(l).await;
    drop(pg);
    std::fs::write(
        output.join("result.json"),
        serde_json::to_vec_pretty(&json!({
            "test_complete":true,"verified_postgres_tls":true,"real_tls_daemons":2,
            "accepted_request_completed_without_replay":true,"durable_receipt_recovered":true,
            "mutation_audit_count":1,"restart_receipt_recovered":true,
            "mixed_versions":false,"stage_b_accepted":false
        }))
        .unwrap(),
    )
    .unwrap();
}

async fn overlap(l: Lab) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    std::fs::write(
        l.root.path().join("external-network.json"),
        br#"{"allowed_cidrs":["192.0.2.0/24"],"denied_cidrs":[]}"#,
    )
    .unwrap();
    let (_, editor) = l.credential("editor", Some(&l.project)).await;
    let token = s(&editor["token"]);
    let (mut a, origin_a, client_a) = start(&l, true, true).await;
    let (mut b, origin_b, client_b) = start(&l, true, true).await;
    let initial_a = status(&client_a, &origin_a, &l.token).await;
    let initial_b = status(&client_b, &origin_b, &l.token).await;
    assert_ne!(initial_a["process_id"], initial_b["process_id"]);

    let ca = std::fs::read(l.root.path().join("daemon-pki/ca.pem")).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut &ca[..]) {
        roots.add(cert.unwrap()).unwrap();
    }
    let config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let address = origin_a.strip_prefix("https://").unwrap();
    let socket = tokio::net::TcpStream::connect(address).await.unwrap();
    let mut stream = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config))
        .connect("127.0.0.1".try_into().unwrap(), socket)
        .await
        .unwrap();
    let path = format!(
        "/v1/tenants/{}/projects/{}/external-endpoints",
        l.tenant, l.project
    );
    // Only permission metadata is created; no connection to this address occurs.
    let body = json!({"name":"rolling-once","host":"192.0.2.10","port":5432}).to_string();
    let key = uid();
    let headers = format!(
        "POST {path} HTTP/1.1\r\nHost: {address}\r\nAuthorization: Bearer {token}\r\nIdempotency-Key: {key}\r\nContent-Length: {}\r\nContent-Type: application/json\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(headers.as_bytes()).await.unwrap();
    let mut accepted = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), async {
        while !accepted.ends_with(b"\r\n\r\n") {
            accepted.push(stream.read_u8().await.unwrap());
            assert!(accepted.len() < 8192);
        }
    })
    .await
    .unwrap();
    // Dispatch authenticates and authorizes before reading the request body.
    assert_eq!(accepted, b"HTTP/1.1 100 Continue\r\n\r\n");
    let split = body.len() / 2;
    stream.write_all(&body.as_bytes()[..split]).await.unwrap();
    assert_eq!(
        unsafe { libc::kill(a.id().unwrap() as i32, libc::SIGTERM) },
        0
    );
    tokio::time::timeout(Duration::from_secs(3), async {
        while tokio::net::TcpStream::connect(address).await.is_ok() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("retiring daemon did not stop admission");
    assert!(
        a.try_wait().unwrap().is_none(),
        "daemon exited with an accepted request pending"
    );
    assert_eq!(
        status(&client_b, &origin_b, &l.token).await["process_id"],
        initial_b["process_id"]
    );
    stream.write_all(&body.as_bytes()[split..]).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), async {
        while !response.ends_with(b"\r\n\r\n") {
            response.push(stream.read_u8().await.unwrap());
            assert!(response.len() < 8192);
        }
        let header = std::str::from_utf8(&response).unwrap();
        let length: usize = header
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length: ")
                    .map(|value| value.parse().unwrap())
            })
            .expect("bounded JSON response has a content length");
        assert!(length <= 64 * 1024);
        let offset = response.len();
        response.resize(offset + length, 0);
        stream.read_exact(&mut response[offset..]).await.unwrap();
    })
    .await
    .unwrap();
    let response = std::str::from_utf8(&response).unwrap();
    assert!(
        response.starts_with("HTTP/1.1 202 Accepted\r\n"),
        "{response}"
    );
    let (_, payload) = response.split_once("\r\n\r\n").unwrap();
    let receipt: Value = serde_json::from_str(payload).unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(5), a.wait())
            .await
            .unwrap()
            .unwrap()
            .success()
    );

    let retry = client_b
        .post(format!("{origin_b}{path}"))
        .bearer_auth(token)
        .header("Idempotency-Key", &key)
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(retry.status(), StatusCode::ACCEPTED);
    let replay: Value = serde_json::from_slice(&retry.bytes().await.unwrap()).unwrap();
    assert_eq!(receipt, replay);
    let effects: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit WHERE action='endpoint.create' AND resource_id=$1",
    )
    .bind(s(&receipt["resource_id"]))
    .fetch_one(&l.store.pool)
    .await
    .unwrap();
    assert_eq!(effects, 1);
    assert_eq!(
        status(&client_b, &origin_b, &l.token).await["process_id"],
        initial_b["process_id"]
    );
    // Reintroduce a process with fresh pools/monitor, then retire the survivor.
    // This is restart coverage; two copies of one binary do not prove rollback.
    let (mut restarted, origin, client) = start(&l, true, true).await;
    terminate(&mut b).await;
    let recovered = client
        .post(format!("{origin}{path}"))
        .bearer_auth(token)
        .header("Idempotency-Key", &key)
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(recovered.status(), StatusCode::ACCEPTED);
    let recovered: Value = serde_json::from_slice(&recovered.bytes().await.unwrap()).unwrap();
    assert_eq!(recovered, receipt);
    terminate(&mut restarted).await;
    l.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_daemon_reports_recovery_failures_resumes_and_resets_observations_on_restart() {
    let l = Lab::new().await;
    let (_, owner) = l.credential("owner", None).await;
    let (mut child, origin, client) = start(&l, true, false).await;
    let initial = observe(&client, &origin, &l.token, |v| {
        // The pickup listener runs continuously; every other loop has iterated.
        v["components"].as_array().unwrap().len() == 2
            && v["components"].as_array().unwrap().iter().all(|c| {
                if c["component"] == "pickup_listener" {
                    c["state"] == "running"
                } else {
                    c["iterations"].as_u64().unwrap() > 0
                }
            })
    })
    .await;
    assert_eq!(
        component_names(&initial),
        vec!["pickup_listener", "scheduler"]
    );
    assert_eq!(
        client
            .get(format!("{origin}/v1/control-plane/status"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        client
            .get(format!("{origin}/v1/control-plane/status"))
            .bearer_auth(s(&owner["token"]))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert!(!initial.to_string().contains(&l.token));
    assert!(
        !initial
            .to_string()
            .contains(l.root.path().to_str().unwrap())
    );
    sqlx::query("UPDATE recovery_barrier SET active=true")
        .execute(&l.store.pool)
        .await
        .unwrap();
    let failed = observe(&client, &origin, &l.token, |v| {
        scheduler(v)["consecutive_failures"].as_u64().unwrap() > 0
    })
    .await;
    assert_eq!(initial["process_id"], failed["process_id"]);
    assert_eq!(
        client
            .post(format!("{origin}/v1/tenants/{}/projects", l.tenant))
            .bearer_auth(&l.token)
            .body(json!({"name":"recovery-refused"}).to_string())
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    sqlx::query("UPDATE recovery_barrier SET active=false")
        .execute(&l.store.pool)
        .await
        .unwrap();
    let recovered = observe(&client, &origin, &l.token, |v| {
        scheduler(v)["consecutive_failures"] == 0
            && scheduler(v)["iterations"].as_u64().unwrap()
                > scheduler(&failed)["iterations"].as_u64().unwrap()
    })
    .await;
    assert!(scheduler(&recovered)["failures"].as_u64().unwrap() > 0);
    assert!(scheduler(&recovered)["last_success_age_ms"].is_u64());
    drop(client);
    terminate(&mut child).await;
    let (mut child, origin, client) = start(&l, false, true).await;
    let restarted = observe(&client, &origin, &l.token, |v| {
        scheduler(v)["iterations"].as_u64().unwrap() > 0
    })
    .await;
    assert_ne!(restarted["process_id"], initial["process_id"]);
    assert_eq!(
        restarted["components"].as_array().unwrap().len(),
        2,
        "only the WASM scheduler and its pickup listener run"
    );
    assert_eq!(scheduler(&restarted)["failures"], 0);
    assert_eq!(
        component_names(&restarted),
        vec!["pickup_listener", "scheduler"]
    );
    drop(client);
    terminate(&mut child).await;
    l.finish().await;
}
