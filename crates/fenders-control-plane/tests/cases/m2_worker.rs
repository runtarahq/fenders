//! Actual kernel-free worker for the M2 console journey, using the M1 setup.
use super::*;
use fenders_control_plane::{
    pki,
    supervision::{Background, Component},
    transport,
};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::Duration,
};

pub(super) struct Worker {
    pub node_id: String,
    child: Child,
    cgroup: PathBuf,
    server: tokio::task::JoinHandle<fenders_node_protocol::error::Result<()>>,
    _background: Background,
    pub tls: api::PeerCredentials,
}
impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::write(self.cgroup.join("cgroup.kill"), "1");
        self.server.abort();
    }
}

#[path = "m2_worker_faults.rs"]
mod faults;
impl Worker {
    pub(super) fn fault_control(&self, output: &Path) -> tokio::task::JoinHandle<()> {
        tokio::spawn(faults::run(
            self.child.id(),
            output.to_owned(),
            self.cgroup.clone(),
        ))
    }
}

pub(super) async fn start_with_scheduler(
    l: &IdentityLab,
    output: &Path,
    build: &Path,
    in_process: bool,
) -> Worker {
    assert_eq!(
        (std::env::consts::OS, std::env::consts::ARCH),
        ("linux", "x86_64")
    );
    assert!(Path::new("/dev/kvm").exists());
    let cgroup =
        PathBuf::from(std::env::var("FENDERS_M2_CGROUP_PARENT").expect("delegated cgroup parent"))
            .join(format!("m2-{}", uid()));
    fs::create_dir(&cgroup).unwrap();
    let resume = std::env::var("FENDERS_M2_RESUME_WORKER")
        .ok()
        .map(PathBuf::from);
    let state_output = resume.as_deref().unwrap_or(output);
    let pki_dir = state_output.join("worker-pki");
    let pins = if resume.is_some() {
        let mut pins = serde_json::Map::new();
        for name in ["control", "node"] {
            let cert = rustls_pemfile::certs(&mut std::io::BufReader::new(
                fs::File::open(pki_dir.join(format!("{name}.pem"))).unwrap(),
            ))
            .next()
            .unwrap()
            .unwrap();
            pins.insert(name.into(), json!(digest(&cert)));
        }
        json!(pins)
    } else {
        pki::create(
            &pki_dir,
            &BTreeMap::from([
                ("control".into(), vec!["127.0.0.1".into()]),
                ("node".into(), vec!["127.0.0.1".into()]),
            ]),
        )
        .unwrap()
    };
    let internal = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let control = format!("https://{}", internal.local_addr().unwrap());
    let (node, port) = if resume.is_some() {
        let saved: Value = serde_json::from_slice(
            &fs::read(state_output.join("worker-environment.json")).unwrap(),
        )
        .unwrap();
        let node: Value = sqlx::query_scalar("SELECT to_jsonb(n) FROM nodes n WHERE id=$1")
            .bind(s(&saved["node_id"]))
            .fetch_one(&l.lab.store.pool)
            .await
            .unwrap();
        assert_eq!(node["cert_sha256"], pins["node"]);
        let port = url::Url::parse(s(&node["endpoint"]))
            .unwrap()
            .port()
            .unwrap();
        (node, port)
    } else {
        let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = socket.local_addr().unwrap().port();
        drop(socket);
        let node = l
            .lab
            .store
            .register_node(
                &l.lab.operator,
                json!({
                    "name":format!("m2-real-worker-{}", uid()), "cert_sha256":pins["node"],
                    "endpoint":format!("https://127.0.0.1:{port}"), "backend":"wasm",
                    "architecture":"x86_64", "runtime":"wasmtime-50.0.0-fenders-v1",
                    "cpu_percent":200, "memory_mib":1024, "instances":4, "network_leases":true
                }),
            )
            .await
            .unwrap();
        (node, port)
    };
    let tls = api::PeerCredentials {
        ca: pki_dir.join("ca.pem"),
        cert: pki_dir.join("control.pem"),
        key: pki_dir.join("control.key"),
    };
    let mut internal_router = api::internal(l.lab.store.clone());
    if std::env::var("FENDERS_M2_LOCAL_RETENTION").as_deref() == Ok("1") {
        let fault_dir = output.to_owned();
        fs::write(fault_dir.join("hold-log-delivery"), "").unwrap();
        internal_router = internal_router.layer(axum::middleware::from_fn(
            move |request: axum::extract::Request, next: axum::middleware::Next| {
                let fault_dir = fault_dir.clone();
                async move {
                    use axum::response::IntoResponse;
                    let path = request.uri().path();
                    if path.starts_with("/internal/executions/")
                        && path.ends_with("/logs")
                        && fault_dir.join("hold-log-delivery").exists()
                    {
                        fs::write(fault_dir.join("log-upload-rejected"), path).unwrap();
                        return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
                    }
                    next.run(request).await
                }
            },
        ));
    }
    let server = tokio::spawn(transport::serve_tls(
        internal,
        transport::server_config(&tls.cert, &tls.key, Some(&tls.ca)).unwrap(),
        internal_router,
    ));
    let mut background = Background::new(l.lab.store.background_monitor());
    let scheduler = l.lab.store.clone();
    if in_process {
        // As in the daemon: commits wake the scheduler and nodes' long polls.
        background
            .periodic_woken(
                Component::Scheduler,
                Duration::ZERO,
                Duration::from_secs(1),
                Some(l.lab.store.pickup()),
                move || {
                    let scheduler = scheduler.clone();
                    async move { scheduler.schedule().await }
                },
            )
            .unwrap();
        let pickup = l.lab.store.clone();
        background
            .periodic(
                Component::PickupListener,
                Duration::ZERO,
                Duration::from_secs(1),
                move || {
                    let pickup = pickup.clone();
                    async move { pickup.listen_for_pickup().await }
                },
            )
            .unwrap();
    }
    let child = Command::new(build.join("fenders-node"))
        .arg("--state")
        .arg(state_output.join("node-state"))
        .arg("--build")
        .arg(build)
        .arg("--cgroup-root")
        .arg(&cgroup)
        .arg("--control")
        .arg(control)
        .arg("--control-pin")
        .arg(s(&pins["control"]))
        .arg("--ca")
        .arg(&tls.ca)
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
            "--port",
        ])
        .arg(port.to_string())
        .stdout(Stdio::null())
        .stderr(fs::File::create(output.join("node.log")).unwrap())
        .spawn()
        .unwrap();
    let mut worker = Worker {
        node_id: s(&node["id"]).to_owned(),
        child,
        cgroup,
        server,
        _background: background,
        tls,
    };
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
    for name in ["runtime.elf", "launch", "compile", "fenders-node"] {
        hashes.insert(
            name.into(),
            json!(digest(fs::read(build.join(name)).unwrap())),
        );
    }
    fs::write(
        output.join("worker-environment.json"),
        serde_json::to_vec_pretty(&json!({
            "resumed_from":resume,"revision":std::env::var("FENDERS_M2_REVISION").expect("tested revision"),
            "kernel":fs::read_to_string("/proc/sys/kernel/osrelease").unwrap().trim(),
            "hashes":hashes,"node_id":node["id"],"worker":"production Rust node; kernel-free KVM"
        }))
        .unwrap(),
    )
    .unwrap();
    worker
}
