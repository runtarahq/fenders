//! Opt-in customer acceptance with the production node subprocess and actual KVM.
//! Only identity is a local signing provider. No synthetic worker observations.
use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use fenders_control_plane::{
    pki,
    supervision::{Background, Component},
    transport,
};
use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::Duration,
};

struct Worker {
    child: Child,
    cgroup: PathBuf,
}
impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        // This UUID subtree is created exclusively by this test. Never kill
        // the delegated parent or another test's workers, including on panic.
        let _ = fs::write(self.cgroup.join("cgroup.kill"), "1");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real Linux x86_64 KVM, delegated cgroups, PostgreSQL, built node and Chromium required"]
async fn customer_m1_against_kernel_free_workers() {
    assert_eq!(
        (std::env::consts::OS, std::env::consts::ARCH),
        ("linux", "x86_64")
    );
    assert!(std::path::Path::new("/dev/kvm").exists());
    let build = PathBuf::from(std::env::var("FENDERS_M1_BUILD").expect("FENDERS_M1_BUILD"))
        .canonicalize()
        .unwrap();
    let output =
        PathBuf::from(std::env::var("FENDERS_M1_OUTPUT").expect("new FENDERS_M1_OUTPUT directory"));
    fs::create_dir(&output).expect("evidence directory must be new");
    let output = output.canonicalize().unwrap();
    let cgroup =
        PathBuf::from(std::env::var("FENDERS_M1_CGROUP_PARENT").expect("delegated cgroup parent"))
            .join(format!("m1-{}", uid()));
    fs::create_dir(&cgroup).unwrap();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let l = IdentityLab::at_origin(&origin).await;
    let owner = l.login("console-owner").await;
    l.member(&owner, "owner", None).await;
    // Register a customer with access only to another workspace, for ID probing.
    let outsider = l.login("m1-outsider").await;
    let other = l
        .lab
        .store
        .create_tenant(
            &l.lab.operator,
            serde_json::from_value(json!({
                "name":"m1-other", "allowance":{"cpu_percent":100,"memory_mib":512,
                "instances":2,"storage_bytes":10000000,"transfer_bytes":1000000}
            }))
            .unwrap(),
        )
        .await
        .unwrap();
    l.lab
        .store
        .add_member(
            &l.lab.operator,
            s(&other["id"]),
            json!({"user_id":outsider.user,"role":"owner"}),
        )
        .await
        .unwrap();

    let pki_dir = l.lab.root.path().join("m1-pki");
    let pins = pki::create(
        &pki_dir,
        &BTreeMap::from([
            ("control".into(), vec!["127.0.0.1".into()]),
            ("node".into(), vec!["127.0.0.1".into()]),
        ]),
    )
    .unwrap();
    let internal = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let control = format!("https://{}", internal.local_addr().unwrap());
    let node_socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let node_port = node_socket.local_addr().unwrap().port();
    drop(node_socket);
    let node = l
        .lab
        .store
        .register_node(
            &l.lab.operator,
            json!({
                "name":"m1-real-worker", "cert_sha256":pins["node"],
                "endpoint":format!("https://127.0.0.1:{node_port}"),"backend":"wasm",
                "architecture":"x86_64","runtime":"wasmtime-50.0.0-fenders-v1",
                "cpu_percent":200,"memory_mib":1024,"instances":4
            }),
        )
        .await
        .unwrap();
    let tls = api::PeerCredentials {
        ca: pki_dir.join("ca.pem"),
        cert: pki_dir.join("control.pem"),
        key: pki_dir.join("control.key"),
    };
    let config = transport::server_config(&tls.cert, &tls.key, Some(&tls.ca)).unwrap();
    let internal_server = tokio::spawn(transport::serve_tls(
        internal,
        config,
        api::internal(l.lab.store.clone()),
    ));
    let management = api::management(api::ApiState {
        store: l.lab.store.clone(),
        domain: "apps.localhost".into(),
        tls: Some(tls),
    });
    let server = tokio::spawn(async move { axum::serve(listener, management).await.unwrap() });
    let mut background = Background::new(l.lab.store.background_monitor());
    let scheduler = l.lab.store.clone();
    background
        .periodic(
            Component::Scheduler,
            Duration::ZERO,
            Duration::from_secs(1),
            move || {
                let scheduler = scheduler.clone();
                async move { scheduler.schedule().await }
            },
        )
        .unwrap();
    let stderr = fs::File::create(output.join("node.log")).unwrap();
    let child = Command::new(build.join("fenders-node"))
        .arg("--state")
        .arg(output.join("node-state"))
        .arg("--build")
        .arg(&build)
        .arg("--cgroup-root")
        .arg(&cgroup)
        .arg("--control")
        .arg(&control)
        .arg("--control-pin")
        .arg(s(&pins["control"]))
        .arg("--ca")
        .arg(pki_dir.join("ca.pem"))
        .arg("--cert")
        .arg(pki_dir.join("node.pem"))
        .arg("--key")
        .arg(pki_dir.join("node.key"))
        .args([
            "--cpu-percent",
            "200",
            "--memory-mib",
            "1024",
            "--max-instances",
            "4",
        ])
        .arg("--port")
        .arg(node_port.to_string())
        .stdout(Stdio::null())
        .stderr(stderr)
        .spawn()
        .unwrap();
    let mut worker = Worker { child, cgroup };
    // Wait for a real authenticated heartbeat, not a test-written capability.
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        assert!(
            worker.child.try_wait().unwrap().is_none(),
            "node exited; inspect node.log"
        );
        let live: bool = sqlx::query_scalar("SELECT last_seen IS NOT NULL FROM nodes WHERE id=$1")
            .bind(s(&node["id"]))
            .fetch_one(&l.lab.store.pool)
            .await
            .unwrap();
        if live {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "no real worker heartbeat"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let mut hashes = serde_json::Map::new();
    for name in [
        "runtime.elf",
        "launch",
        "compile",
        "fenders-node",
        "example-command.wasm",
        "example-dual.wasm",
        "example-http.wasm",
    ] {
        hashes.insert(
            name.into(),
            json!(digest(fs::read(build.join(name)).unwrap())),
        );
    }
    let environment = json!({"revision":std::env::var("FENDERS_M1_REVISION").expect("tested revision"),
        "kernel":fs::read_to_string("/proc/sys/kernel/osrelease").unwrap().trim(),
        "architecture":std::env::consts::ARCH,"hashes":hashes,"node_id":node["id"],
        "identity":"local signing provider; not production identity qualification",
        "worker":"production Rust node subprocess, kernel-free KVM",
        "console":"loopback development HTTP; worker RPC uses pinned mTLS"});
    fs::write(
        output.join("environment.json"),
        serde_json::to_vec_pretty(&environment).unwrap(),
    )
    .unwrap();
    // Valid HTTP contract, with an actual instantiation trap. Inspection succeeds
    // but the runtime must fail the deployment; no status is injected by the test.
    let failing = wat::parse_str(
        r#"(component
      (import "wasi:http/types@0.2.6" (instance $types
        (export "incoming-request" (type (sub resource)))
        (export "response-outparam" (type (sub resource)))))
      (alias export $types "incoming-request" (type $request))
      (alias export $types "response-outparam" (type $response))
      (core module $h (func $start unreachable) (start $start)
        (func (export "handle") (param i32 i32)))
      (core instance $hi (instantiate $h))
      (func $handle (param "request" (own $request)) (param "response" (own $response))
        (canon lift (core func $hi "handle")))
      (instance $http (export "handle" (func $handle)))
      (export "wasi:http/incoming-handler@0.2.6" (instance $http)))"#,
    )
    .unwrap();
    let fixture = json!({"origin":origin,"tenant":l.lab.tenant,"project":l.lab.project,
        "outsiderCookie":outsider.cookie,"output":output,
        "components":{"command":STANDARD.encode(fs::read(build.join("example-command.wasm")).unwrap()),
        "dual":STANDARD.encode(fs::read(build.join("example-dual.wasm")).unwrap()),
        "http":STANDARD.encode(fs::read(build.join("example-http.wasm")).unwrap()),
        "failing":STANDARD.encode(failing)}});
    let passed = run_console_browser("tests/verify_m1_live.cjs", fixture).await;
    let observations: Vec<Value> = sqlx::query_scalar("SELECT jsonb_build_object('id',id,'generation',generation,'state',state,'desired',desired,'node_id',node_id,'reason',observation->>'reason') FROM executions ORDER BY created")
        .fetch_all(&l.lab.store.pool).await.unwrap();
    fs::write(
        output.join("executions.json"),
        serde_json::to_vec_pretty(&observations).unwrap(),
    )
    .unwrap();
    drop(worker);
    drop(background);
    server.abort();
    internal_server.abort();
    l.finish().await;
    assert!(
        passed,
        "M1 failed; inspect retained evidence in {}",
        output.display()
    );
}
