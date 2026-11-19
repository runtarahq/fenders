//! Dedicated Linux/KVM acceptance. The byte-forwarding front door is test
//! infrastructure: TLS remains end-to-end, with no replay or synthetic worker.
use super::agent_upgrade_live::{Postgres, Worker, ownership, running};
use super::*;
use fenders_control_plane::{pki, transport};
use std::{
    collections::BTreeMap,
    fs,
    net::SocketAddr,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Stdio,
    sync::{Arc, Mutex},
    time::Duration,
};
#[path = "control_plane_rollout_checks.rs"]
mod checks;
#[path = "control_plane_rollout_network.rs"]
mod network;
static HTTP_SAMPLES: Mutex<Vec<f64>> = Mutex::new(Vec::new());

fn input(name: &str) -> PathBuf {
    PathBuf::from(std::env::var_os(name).unwrap_or_else(|| panic!("missing {name}")))
        .canonicalize()
        .unwrap()
}
fn address() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}
fn read(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

struct Control {
    child: tokio::process::Child,
    addresses: [SocketAddr; 3],
    process: Value,
}
impl Control {
    async fn start(l: &Lab, binary: &Path, pki: &Path, output: &Path, phase: &str) -> Self {
        let sockets: Vec<_> = (0..3)
            .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
            .collect();
        let addresses = std::array::from_fn(|i| sockets[i].local_addr().unwrap());
        let credential = output.join(format!("{phase}-database-url"));
        pki::private_file(&credential, super::supervision::database_url(l).as_bytes()).unwrap();
        let log = output.join(format!("{phase}-control.log"));
        pki::private_file(&log, b"").unwrap();
        drop(sockets);
        let mut child = tokio::process::Command::new(binary)
            .arg("--state")
            .arg(l.root.path())
            .arg("--database-url-file")
            .arg(credential)
            .args([
                "--port",
                &addresses[0].port().to_string(),
                "--internal-port",
                &addresses[1].port().to_string(),
                "--gateway-port",
                &addresses[2].port().to_string(),
                "--domain",
                "apps.test",
            ])
            .arg("--ca")
            .arg(pki.join("ca.pem"))
            .arg("--cert")
            .arg(pki.join("control.pem"))
            .arg("--key")
            .arg(pki.join("control.key"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(fs::OpenOptions::new().append(true).open(log).unwrap())
            .kill_on_drop(true)
            .arg("--external-network")
            .arg(l.root.path().join("external-network.json"))
            .spawn()
            .unwrap();
        let client = client(pki);
        let process = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                assert!(
                    child.try_wait().unwrap().is_none(),
                    "{phase}: daemon exited; inspect private control log"
                );
                if let Ok(response) = client
                    .get(format!("https://{}/v1/control-plane/status", addresses[0]))
                    .bearer_auth(&l.token)
                    .send()
                    .await
                    && response.status() == StatusCode::OK
                {
                    let value: Value =
                        serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
                    if value["components"].as_array().unwrap().iter().all(|c| {
                        c["iterations"].as_u64().unwrap() > 0 && c["consecutive_failures"] == 0
                    }) {
                        break value["process_id"].clone();
                    }
                }
                tokio::time::sleep(Duration::from_millis(30)).await;
            }
        })
        .await
        .expect("control plane did not become ready");
        Self {
            child,
            addresses,
            process,
        }
    }
    fn signal(&mut self) {
        assert!(self.child.try_wait().unwrap().is_none());
        assert_eq!(
            unsafe { libc::kill(self.child.id().unwrap() as i32, libc::SIGTERM) },
            0
        );
    }
    async fn stopped(&mut self) {
        assert!(
            tokio::time::timeout(Duration::from_secs(5), self.child.wait())
                .await
                .unwrap()
                .unwrap()
                .success()
        );
    }
}
fn client(pki: &Path) -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(10))
        .add_root_certificate(
            reqwest::Certificate::from_pem(&fs::read(pki.join("ca.pem")).unwrap()).unwrap(),
        )
        .build()
        .unwrap()
}

struct FrontDoor {
    addresses: [SocketAddr; 3],
    selected: Arc<Mutex<[SocketAddr; 3]>>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}
impl FrontDoor {
    async fn start(backends: [SocketAddr; 3]) -> Self {
        let selected = Arc::new(Mutex::new(backends));
        let mut addresses = backends;
        let mut tasks = Vec::new();
        for (i, address) in addresses.iter_mut().enumerate() {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            *address = listener.local_addr().unwrap();
            let selected = selected.clone();
            tasks.push(tokio::spawn(async move {
                use tokio::io::copy_bidirectional;
                let mut streams = tokio::task::JoinSet::new();
                loop {
                    tokio::select! {
                        accepted = listener.accept() => {
                            let (mut socket, _) = accepted.unwrap();
                            let destination = selected.lock().unwrap()[i];
                            assert!(streams.len() < 128, "test front door capacity");
                            streams.spawn(async move {
                                let mut backend = tokio::net::TcpStream::connect(destination).await.unwrap();
                                let _ = copy_bidirectional(&mut socket, &mut backend).await;
                            });
                        }
                        result = streams.join_next(), if !streams.is_empty() => { result.unwrap().unwrap(); }
                    }
                }
            }));
        }
        Self {
            addresses,
            selected,
            tasks,
        }
    }
    fn select(&self, control: &Control) {
        *self.selected.lock().unwrap() = control.addresses;
    }
}
impl Drop for FrontDoor {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

async fn json_request(
    l: &Lab,
    client: &reqwest::Client,
    door: &FrontDoor,
    method: &str,
    path: &str,
    key: &str,
    body: Option<Value>,
) -> Value {
    let mut request = client
        .request(
            method.parse::<reqwest::Method>().unwrap(),
            format!("https://{}{}", door.addresses[0], path),
        )
        .bearer_auth(&l.token)
        .header("Idempotency-Key", key);
    if let Some(body) = body {
        request = request
            .header("Content-Type", "application/json")
            .body(body.to_string());
    }
    let response = request.send().await.unwrap();
    let status = response.status();
    let bytes = response.bytes().await.unwrap();
    assert!(status.is_success(), "{method} {path}: {status}");
    serde_json::from_slice(&bytes).unwrap()
}
async fn upload(l: &Lab, client: &reqwest::Client, door: &FrontDoor, path: &Path) -> String {
    let response = client
        .post(format!(
            "https://{}/v1/workspaces/{}/projects/{}/artifacts",
            door.addresses[0], l.tenant, l.project
        ))
        .bearer_auth(&l.token)
        .header("Content-Type", "application/wasm")
        .body(fs::read(path).unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let artifact: Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    let id = s(&artifact["id"]).to_owned();
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let state: String =
                sqlx::query_scalar("SELECT state FROM artifact_validations WHERE artifact_id=$1")
                    .bind(&id)
                    .fetch_one(&l.store.pool)
                    .await
                    .unwrap();
            assert_ne!(state, "invalid", "real compiler rejected fixture");
            if state == "valid" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    id
}
async fn gateway(client: reqwest::Client, address: SocketAddr, hostname: String) {
    let started = std::time::Instant::now();
    let response = client
        .get(format!("https://{address}/hello"))
        .header("Host", hostname)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(&response.bytes().await.unwrap()[..], b"fenders:/hello");
    let mut samples = HTTP_SAMPLES.lock().unwrap();
    assert!(samples.len() < 1024);
    samples.push(started.elapsed().as_secs_f64() * 1000.0);
}
fn hold_count(backend: &Path) -> usize {
    fs::read_to_string(backend.join("output.log"))
        .unwrap()
        .lines()
        .filter(|line| *line == "FENDERS_HTTP_HOLD_STARTED")
        .count()
}
#[allow(clippy::too_many_arguments)]
async fn handover(
    l: &Lab,
    client: &reqwest::Client,
    door: &FrontDoor,
    retiring: &mut Control,
    next: &Control,
    backend: &Path,
    hostname: &str,
    node: &str,
) -> Value {
    let before = hold_count(backend);
    let old = tokio::spawn(gateway(
        client.clone(),
        door.addresses[2],
        hostname.to_owned(),
    ));
    tokio::time::timeout(Duration::from_secs(5), async {
        while hold_count(backend) == before {
            assert!(
                !old.is_finished(),
                "request finished before observed guest dispatch"
            );
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .unwrap();
    assert!(!old.is_finished());
    let held: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM ingress_reservations WHERE execution_id IS NOT NULL",
    )
    .fetch_one(&l.store.pool)
    .await
    .unwrap();
    assert_eq!(held, 1);
    let heartbeat: String = sqlx::query_scalar("SELECT last_seen::text FROM nodes WHERE id=$1")
        .bind(node)
        .fetch_one(&l.store.pool)
        .await
        .unwrap();
    door.select(next);
    retiring.signal();
    let new = tokio::spawn(gateway(
        client.clone(),
        door.addresses[2],
        hostname.to_owned(),
    ));
    old.await.unwrap();
    new.await.unwrap();
    retiring.stopped().await;
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let fresh: bool = sqlx::query_scalar("SELECT last_seen>$2::timestamptz AND last_seen>now()-interval '5 seconds' FROM nodes WHERE id=$1")
                .bind(node).bind(&heartbeat).fetch_one(&l.store.pool).await.unwrap();
            if fresh { break; }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }).await.unwrap();
    let held: i64 = sqlx::query_scalar("SELECT count(*) FROM ingress_reservations")
        .fetch_one(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(held, 0, "completed gateway reservations were not settled");
    json!({"from":retiring.process,"to":next.process,"dispatched_request_completed":true,
        "new_request_completed":true,"settled_ingress_reservations":true,"worker_heartbeat_advanced":true})
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "dedicated Linux/KVM host, distinct production control-plane binaries, real worker and private PostgreSQL TLS fixture required"]
async fn mixed_versions_preserve_worker_dispatch_schema_and_rollback() {
    assert_eq!(
        (std::env::consts::OS, std::env::consts::ARCH),
        ("linux", "x86_64")
    );
    assert_eq!(unsafe { libc::geteuid() }, 0);
    let original = input("FENDERS_ROLLOUT_ORIGINAL_CONTROL");
    let candidate = input("FENDERS_ROLLOUT_CANDIDATE_CONTROL");
    let agent = input("FENDERS_ROLLOUT_WORKER");
    let build = input("FENDERS_ROLLOUT_BUILD");
    assert_ne!(
        digest(fs::read(&original).unwrap()),
        digest(fs::read(&candidate).unwrap())
    );
    let output = PathBuf::from(std::env::var_os("FENDERS_ROLLOUT_OUTPUT").unwrap());
    fs::create_dir(&output).expect("new isolated output required");
    fs::set_permissions(&output, fs::Permissions::from_mode(0o700)).unwrap();
    let credentials = read(&input("FENDERS_ROLLOUT_POSTGRES_JSON_FILE"));
    let postgres = Postgres::start(&output, &credentials).await;
    let mut l = Lab::with_options(postgres.options.clone()).await;
    let network_address =
        std::env::var("FENDERS_ROLLOUT_ADDRESS").expect("explicit test relay IPv4 address");
    let allowed = fenders_control_plane::external_endpoints::ExternalNetworkPolicy {
        allowed_cidrs: vec![format!("{network_address}/32").parse().unwrap()],
        denied_cidrs: vec![],
    };
    pki::private_file(
        &l.root.path().join("external-network.json"),
        &serde_json::to_vec(
            &json!({"allowed_cidrs":[format!("{network_address}/32")],"denied_cidrs":[]}),
        )
        .unwrap(),
    )
    .unwrap();
    l.store = l.store.with_external_network(allowed);
    // Identical pre-ledger WASM-only schema. The actual old executable starts
    // against it before the candidate performs the additive ledger migration.
    sqlx::query("DROP TABLE control_schema_migrations")
        .execute(&l.store.pool)
        .await
        .unwrap();
    let pki_dir = output.join("pki");
    let pins = pki::create(
        &pki_dir,
        &BTreeMap::from([
            (
                "control".into(),
                vec!["127.0.0.1".into(), "*.apps.test".into()],
            ),
            ("node".into(), vec!["127.0.0.1".into()]),
        ]),
    )
    .unwrap();
    let mut a = Control::start(&l, &original, &pki_dir, &output, "original").await;
    let door = FrontDoor::start(a.addresses).await;
    let client = client(&pki_dir);
    assert!(
        client
            .get(format!("https://{}/rpc/heartbeat", door.addresses[1]))
            .send()
            .await
            .is_err(),
        "internal front door accepted a client without its certificate"
    );
    let wrong_pin = transport::Client::new(
        &format!("https://{}", door.addresses[1]),
        &pki_dir.join("ca.pem"),
        &pki_dir.join("node.pem"),
        &pki_dir.join("node.key"),
        &"f".repeat(64),
    )
    .unwrap();
    assert!(
        wrong_pin.json("GET", "/rpc/heartbeat", None).await.is_err(),
        "service certificate pin was bypassed"
    );
    let no_ledger: bool =
        sqlx::query_scalar("SELECT to_regclass('control_schema_migrations') IS NULL")
            .fetch_one(&l.store.pool)
            .await
            .unwrap();
    assert!(
        no_ledger,
        "original executable unexpectedly initialized candidate history"
    );
    let worker_address = address();
    let node = l
        .store
        .register_node(
            &l.operator,
            json!({"name":"control-rollout", "cert_sha256":pins["node"],
        "endpoint":format!("https://{worker_address}"),"backend":"wasm","architecture":"x86_64",
        "runtime":"wasmtime-50.0.0-fenders-v1","cpu_percent":200,"memory_mib":1024,"instances":4,
        "egress_budget_launcher":digest(fs::read(build.join("launch")).unwrap()),
        "egress_budget_required":true}),
        )
        .await
        .unwrap();
    let cgroup = input("FENDERS_ROLLOUT_CGROUP_PARENT").join(format!("rollout-{}", uid()));
    fs::create_dir(&cgroup).unwrap();
    let mut command = std::process::Command::new("unused");
    command
        .arg("--state")
        .arg(output.join("state"))
        .arg("--build")
        .arg(&build)
        .arg("--cgroup-root")
        .arg(&cgroup)
        .arg("--control")
        .arg(format!("https://{}", door.addresses[1]))
        .arg("--control-pin")
        .arg(s(&pins["control"]))
        .arg("--ca")
        .arg(pki_dir.join("ca.pem"))
        .arg("--cert")
        .arg(pki_dir.join("node.pem"))
        .arg("--key")
        .arg(pki_dir.join("node.key"))
        .args([
            "--port",
            &worker_address.port().to_string(),
            "--cpu-percent",
            "200",
            "--memory-mib",
            "1024",
            "--max-instances",
            "4",
        ]);
    let mut worker = Worker::for_control_rollout(
        output.clone(),
        cgroup.clone(),
        command.get_args().map(ToOwned::to_owned).collect(),
    );
    worker.start(&agent, "rollout", &build);
    let worker_pid = worker.pid();
    let http_artifact = upload(&l, &client, &door, &build.join("example-http.wasm")).await;
    let dual_artifact = upload(&l, &client, &door, &build.join("example-dual.wasm")).await;
    let base = format!("/v1/workspaces/{}/projects/{}", l.tenant, l.project);
    let http = json_request(&l, &client, &door, "POST", &format!("{base}/apps/deploy"), "http-deploy",
        Some(json!({"name":"rollout-http","artifact_id":http_artifact,"configuration":{"size":"medium","keep_warm":true,"env":{"HTTP_HOLD_MS":"1000"}},"triggers":{"http":true,"manual":false}}))).await;
    let http_app = s(&http["resource_id"]);
    let http_execution: String = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let value = json_request(
                &l,
                &client,
                &door,
                "GET",
                &format!("{base}/apps/{http_app}/http"),
                "",
                None,
            )
            .await;
            if let Some(id) = value["execution_id"].as_str() {
                break id.to_owned();
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    let http_backend = running(&l, &mut worker, &http_execution).await;
    let http_status = json_request(
        &l,
        &client,
        &door,
        "GET",
        &format!("{base}/apps/{http_app}/http"),
        "",
        None,
    )
    .await;
    let hostname = s(&http_status["url"])
        .strip_prefix("https://")
        .unwrap()
        .to_owned();
    gateway(client.clone(), door.addresses[2], hostname.clone()).await;
    let mut beta = checks::Tenant::start(&l, &client, &door, &build, &mut worker).await;
    let mut network = network::Network::start(
        &l,
        &client,
        &door,
        &postgres.config,
        &network_address,
        &mut worker,
    )
    .await;
    let mut b = Control::start(&l, &candidate, &pki_dir, &output, "candidate").await;
    assert_ne!(a.process, b.process);
    let migration: Value = sqlx::query_scalar(
        "SELECT jsonb_agg(to_jsonb(m) ORDER BY version) FROM control_schema_migrations m",
    )
    .fetch_one(&l.store.pool)
    .await
    .unwrap();
    let schedule = checks::Schedule::start(
        &l,
        &client,
        &door,
        &dual_artifact,
        &mut worker,
        &hostname,
        &beta.hostname,
    )
    .await;
    let command_app = json_request(&l, &client, &door, "POST", &format!("{base}/apps/deploy"), "command-deploy",
        Some(json!({"name":"rollout-command","artifact_id":dual_artifact,"configuration":{"size":"medium","env":{"COMMAND_HOLD_MS":"60000"}},"triggers":{"http":false,"manual":true}}))).await;
    let run_path = format!("{base}/apps/{}/runs", s(&command_app["resource_id"]));
    let receipt = json_request(&l, &client, &door, "POST", &run_path, "one-command", None).await;
    let command_execution: String =
        sqlx::query_scalar("SELECT execution_id FROM app_runs WHERE id=$1")
            .bind(s(&receipt["resource_id"]))
            .fetch_one(&l.store.pool)
            .await
            .unwrap();
    let command_backend = running(&l, &mut worker, &command_execution).await;
    let initial = json!({"http":ownership(&http_backend),"command":ownership(&command_backend)});
    let configurations = [
        digest(fs::read(http_backend.join("config.json")).unwrap()),
        digest(fs::read(command_backend.join("config.json")).unwrap()),
    ];
    let kernels = [
        super::agent_upgrade_live::kernel_controls(&http_backend),
        super::agent_upgrade_live::kernel_controls(&command_backend),
    ];
    let alpha_app_path = format!("{base}/apps/{http_app}");
    let mut alpha_logs = super::agent_upgrade_live::logs::RollingLogs::new(
        &l,
        &l.tenant,
        &l.project,
        http_app,
        &http_execution,
        &http_backend,
    )
    .await;
    let mut beta_logs = beta.log_reader(&l).await;
    let mut log_phases = Vec::new();
    beta.observe(&l, &client, &door, &alpha_app_path, "overlap-A")
        .await;
    network.observe(&l, "overlap-A").await;
    log_phases.push(
        super::agent_upgrade_live::logs::RollingLogs::observe_pair(
            &l,
            &client,
            &format!("https://{}", door.addresses[0]),
            &mut alpha_logs,
            &mut beta_logs,
            "overlap-A",
        )
        .await,
    );
    let first = handover(
        &l,
        &client,
        &door,
        &mut a,
        &b,
        &http_backend,
        &hostname,
        s(&node["id"]),
    )
    .await;
    schedule.observe(&l).await;
    beta.observe(&l, &client, &door, &alpha_app_path, "B-only")
        .await;
    network.observe(&l, "B-only").await;
    log_phases.push(
        super::agent_upgrade_live::logs::RollingLogs::observe_pair(
            &l,
            &client,
            &format!("https://{}", door.addresses[0]),
            &mut alpha_logs,
            &mut beta_logs,
            "B-only",
        )
        .await,
    );
    assert_eq!(
        json_request(&l, &client, &door, "POST", &run_path, "one-command", None).await,
        receipt
    );
    let mut rollback = Control::start(&l, &original, &pki_dir, &output, "rollback").await;
    let second = handover(
        &l,
        &client,
        &door,
        &mut b,
        &rollback,
        &http_backend,
        &hostname,
        s(&node["id"]),
    )
    .await;
    schedule.observe(&l).await;
    beta.observe(&l, &client, &door, &alpha_app_path, "rollback-A-only")
        .await;
    network.observe(&l, "rollback-A-only").await;
    log_phases.push(
        super::agent_upgrade_live::logs::RollingLogs::observe_pair(
            &l,
            &client,
            &format!("https://{}", door.addresses[0]),
            &mut alpha_logs,
            &mut beta_logs,
            "rollback-A-only",
        )
        .await,
    );
    assert_eq!(
        json_request(&l, &client, &door, "POST", &run_path, "one-command", None).await,
        receipt
    );
    let mut final_control = Control::start(&l, &candidate, &pki_dir, &output, "reupgrade").await;
    let retained: Value = sqlx::query_scalar(
        "SELECT jsonb_agg(to_jsonb(m) ORDER BY version) FROM control_schema_migrations m",
    )
    .fetch_one(&l.store.pool)
    .await
    .unwrap();
    assert_eq!(
        retained, migration,
        "binary rollback rewrote migration history"
    );
    network.revoke(&l, &client, &door).await;
    let third = handover(
        &l,
        &client,
        &door,
        &mut rollback,
        &final_control,
        &http_backend,
        &hostname,
        s(&node["id"]),
    )
    .await;
    schedule.observe(&l).await;
    beta.observe(&l, &client, &door, &alpha_app_path, "reupgrade-B-only")
        .await;
    let network_result = network.finish(&l, &client, &door).await;
    log_phases.push(
        super::agent_upgrade_live::logs::RollingLogs::observe_pair(
            &l,
            &client,
            &format!("https://{}", door.addresses[0]),
            &mut alpha_logs,
            &mut beta_logs,
            "reupgrade-B-only",
        )
        .await,
    );
    assert_eq!(worker.pid(), worker_pid);
    assert!(worker.alive());
    assert_eq!(
        json!({"http":ownership(&http_backend),"command":ownership(&command_backend)}),
        initial
    );
    assert_eq!(
        digest(fs::read(http_backend.join("config.json")).unwrap()),
        configurations[0]
    );
    assert_eq!(
        digest(fs::read(command_backend.join("config.json")).unwrap()),
        configurations[1]
    );
    assert_eq!(
        [
            super::agent_upgrade_live::kernel_controls(&http_backend),
            super::agent_upgrade_live::kernel_controls(&command_backend)
        ],
        kernels
    );
    tokio::time::timeout(Duration::from_secs(75), async {
        loop {
            let terminal: bool = sqlx::query_scalar(
                "SELECT state='exited' AND NOT reserved FROM executions WHERE id=$1",
            )
            .bind(&command_execution)
            .fetch_one(&l.store.pool)
            .await
            .unwrap();
            if terminal {
                break;
            }
            assert!(worker.alive());
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap();
    let command_output = fs::read_to_string(command_backend.join("output.log")).unwrap();
    assert_eq!(
        command_output
            .lines()
            .filter(|l| *l == "FENDERS_DUAL_COMMAND_HOLD_STARTED")
            .count(),
        1
    );
    assert_eq!(
        command_output
            .lines()
            .filter(|l| *l == "FENDERS_DUAL_COMMAND_COMPLETE")
            .count(),
        1
    );
    let assignments: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit WHERE action='execution.assign' AND resource_id=$1",
    )
    .bind(&command_execution)
    .fetch_one(&l.store.pool)
    .await
    .unwrap();
    assert_eq!(assignments, 1);
    assert_eq!(
        json_request(&l, &client, &door, "POST", &run_path, "one-command", None).await["id"],
        receipt["id"]
    );
    // Keep the stopped app visible for final customer-log collection. Deletion
    // intentionally hides app endpoints, including their scoped log route.
    let app = json_request(
        &l,
        &client,
        &door,
        "GET",
        &format!("{base}/apps/{http_app}"),
        "",
        None,
    )
    .await;
    beta.stop(&l, &client, &door).await;
    json_request(
        &l,
        &client,
        &door,
        "PATCH",
        &format!("{base}/apps/{http_app}"),
        "cleanup-http",
        Some(json!({"desired":"stopped","expected_revision":app["revision"]})),
    )
    .await;
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let held: i64 = sqlx::query_scalar("SELECT count(*) FROM executions WHERE reserved")
                .fetch_one(&l.store.pool)
                .await
                .unwrap();
            if held == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    assert!(
        door.tasks.iter().all(|task| !task.is_finished()),
        "front door forwarding task failed"
    );
    log_phases.push(
        super::agent_upgrade_live::logs::RollingLogs::observe_pair(
            &l,
            &client,
            &format!("https://{}", door.addresses[0]),
            &mut alpha_logs,
            &mut beta_logs,
            "closed",
        )
        .await,
    );
    drop(worker);
    tokio::time::timeout(Duration::from_secs(5), async {
        while !fs::read_to_string(cgroup.join("cgroup.events"))
            .unwrap()
            .lines()
            .any(|line| line == "populated 0")
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    fn remove_scopes(path: &Path) {
        for entry in fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                remove_scopes(&entry.path());
            }
        }
        fs::remove_dir(path).unwrap();
    }
    remove_scopes(&cgroup);
    final_control.signal();
    final_control.stopped().await;
    l.finish().await;
    drop(postgres);
    let http_samples = HTTP_SAMPLES.lock().unwrap().clone();
    fs::write(output.join("result.json"), serde_json::to_vec_pretty(&json!({
        "test_complete":true,"real_kvm_worker":true,"real_postgres_verified_tls":true,
        "original_control_sha256":digest(fs::read(original).unwrap()),"candidate_control_sha256":digest(fs::read(candidate).unwrap()),
        "migration_receipt":migration,"binary_rollback_without_database_rewind":true,
        "phases":[first,second,third],"worker_pid":worker_pid,"worker_pid_unchanged":true,"vm_identities_and_configurations_unchanged":true,
        "original_native_identities":initial,"configuration_sha256":configurations,"kernel_controls":kernels,
        "schedule":schedule.evidence,"tenant_isolation_and_quotas":beta.phases,
        "network":network_result,"customer_log_phases":log_phases,
        "command_entrypoint_starts":1,"command_completions":1,"command_assignment_count":assignments,
        "gateway_requests":http_samples.len(),"gateway_max_milliseconds":http_samples.iter().copied().fold(0.0_f64, f64::max),
        "gateway_failures":0,"cleanup_reservations":0,"test_cgroups_removed":true,
        "internal_mtls_and_service_pin_refusals":true,
        "front_door":"test-only TCP byte forwarding; end-to-end TLS, fixed service pin, no replay"
    })).unwrap()).unwrap();
}
