//! Stateful backend fixtures exercise the real Rust journal, TLS protocol and PostgreSQL authority.
//! These tests do not execute a guest or establish host isolation.
use fenders_node::durable::atomic_json;
#[cfg(target_os = "linux")]
const BUDGET_LAUNCHER: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
use axum::http::StatusCode;
use fenders_control_plane::{api, db::s, model::*, pki, store::Store, transport};
use fenders_node::{
    agent::{Agent, Backend},
    core::{load, private_dir},
};
use fenders_node_protocol::error::{Error, Result};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU8, Ordering},
    },
};

struct Fixture {
    root: PathBuf,
    guard: Mutex<()>,
    fail_after_commit: AtomicBool,
    storage_fault: AtomicU8,
    busy: AtomicBool,
    inspection_mode: AtomicU8,
    compile_scopes: Mutex<Vec<Option<String>>>,
    /// Milliseconds each create takes before it commits, outside `guard`,
    /// as a real node's durable writes and spawn do.
    create_delay_ms: std::sync::atomic::AtomicU64,
    /// Creates within that delay now, and the most there were at once.
    creating: std::sync::atomic::AtomicUsize,
    most_creating: std::sync::atomic::AtomicUsize,
    /// Set when the backend serves the outbound byte limit: its launcher.
    budget_launcher: std::sync::OnceLock<String>,
}
impl Fixture {
    fn run_dir(&self, id: &str) -> Result<PathBuf> {
        Ok(self.root.join(id))
    }
    fn new(root: &Path) -> Self {
        private_dir(root).unwrap();
        Self {
            root: root.to_owned(),
            guard: Mutex::new(()),
            fail_after_commit: AtomicBool::new(false),
            storage_fault: AtomicU8::new(0),
            busy: AtomicBool::new(false),
            inspection_mode: AtomicU8::new(0),
            compile_scopes: Mutex::new(Vec::new()),
            create_delay_ms: std::sync::atomic::AtomicU64::new(0),
            creating: Default::default(),
            most_creating: Default::default(),
            budget_launcher: std::sync::OnceLock::new(),
        }
    }
}
impl Backend for Fixture {
    fn egress_budget_launcher(&self) -> Option<&str> {
        self.budget_launcher.get().map(String::as_str)
    }
    fn status(&self, id: &str) -> Result<Value> {
        // A run the backend does not hold is not found, as a node's says.
        let dir = self.run_dir(id)?;
        if !dir.exists() {
            return Err(Error::missing());
        }
        load(&dir.join("status.json"))
    }
    fn lookup_key(&self, key: &str) -> Result<Option<String>> {
        for v in self.list()? {
            if load(&self.run_dir(s(&v["id"]))?.join("config.json"))?["key"] == key {
                return Ok(Some(s(&v["id"]).into()));
            }
        }
        Ok(None)
    }
    fn action(&self, id: &str, action: &str) -> Result<Value> {
        if action == "pause" && self.busy.load(Ordering::SeqCst) {
            return Err(Error::new(StatusCode::CONFLICT, "fixture application busy"));
        }
        let mut status = self.status(id)?;
        status["state"] = json!(match action {
            "pause" => "paused",
            "resume" => "running",
            "stop" => "stopped",
            _ => return Err(Error::missing()),
        });
        atomic_json(&self.run_dir(id)?.join("status.json"), &status)?;
        Ok(status)
    }

    fn list(&self) -> Result<Vec<Value>> {
        std::fs::read_dir(&self.root)?
            .map(|e| self.status(e?.file_name().to_str().unwrap()))
            .collect()
    }
    fn upload_scoped(&self, data: &[u8], scope: Option<&str>) -> Result<Value> {
        self.compile_scopes
            .lock()
            .unwrap()
            .push(scope.map(str::to_owned));
        self.upload(data)
    }
    fn upload(&self, data: &[u8]) -> Result<Value> {
        match self.inspection_mode.load(Ordering::SeqCst) {
            1 => Err(Error::new(
                StatusCode::INSUFFICIENT_STORAGE,
                "fixture compiler disk full",
            )),
            2 => {
                // Real pinned inspection, inside a local test backend. This does
                // not test the production confined compiler worker or KVM.
                let info = fenders_component::inspect(data).map_err(|error| {
                    match fenders_component::rejection_code(&error) {
                        Some(code) => Error::new(StatusCode::UNPROCESSABLE_ENTITY, code),
                        None => Error::new(StatusCode::SERVICE_UNAVAILABLE, "compiler unavailable"),
                    }
                })?;
                Ok(json!({"artifact":digest(data),"inspection":info}))
            }
            _ => Ok(json!({"artifact":digest(data)})),
        }
    }
    fn create(&self, spec: &Value, key: &str) -> Result<Value> {
        let delay = self.create_delay_ms.load(Ordering::SeqCst);
        if delay > 0 {
            let now = self.creating.fetch_add(1, Ordering::SeqCst) + 1;
            self.most_creating.fetch_max(now, Ordering::SeqCst);
            std::thread::sleep(std::time::Duration::from_millis(delay));
            self.creating.fetch_sub(1, Ordering::SeqCst);
        }
        let _guard = self.guard.lock().unwrap();
        if let Some(id) = self.lookup_key(key)? {
            return self.status(&id);
        }
        if self.storage_fault.load(Ordering::SeqCst) == 1 {
            return Err(Error::new(
                StatusCode::INSUFFICIENT_STORAGE,
                "fixture storage refusal",
            ));
        }
        let id = uid();
        let dir = self.root.join(&id);
        private_dir(&dir)?;
        atomic_json(&dir.join("config.json"), &json!({"spec":spec,"key":key}))?;
        let mut status =
            json!({"id":id,"state":"running","cpu_stat":"usage_usec 100\n","memory_current":1024});
        if spec["egress_budget"] == true {
            status["egress_boot_id"] = json!("fixture-boot");
            status["egress_authority"] = json!({"boot_id":"fixture-boot","contract":fenders_control_plane::egress_budget::CONTRACT,"launcher_digest":BUDGET_LAUNCHER});
            for (key, value) in [
                ("enabled", json!(true)),
                ("measured", json!(true)),
                ("revision", json!(0)),
                ("deadline_ns", json!(0)),
                ("ceiling", json!(0)),
                ("bytes", json!(0)),
                ("reserved", json!(0)),
                ("in_flight", json!(0)),
            ] {
                status[format!("egress_budget_{key}")] = value;
            }
        }
        atomic_json(&dir.join("status.json"), &status)?;
        if self.storage_fault.load(Ordering::SeqCst) == 2 {
            return Err(Error::new(
                StatusCode::INSUFFICIENT_STORAGE,
                "fixture post-commit failure",
            ));
        }
        if self.fail_after_commit.swap(false, Ordering::SeqCst) {
            return Err(Error::internal());
        }
        Ok(status)
    }
    fn reconcile(&self) -> Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn component_inspection_over_mtls_persists_real_capabilities_without_execution() {
    let l = Lab::new().await;
    let a = l.agent(400, 4096);
    // A malformed trusted-worker receipt remains retryable, not a customer error.
    a.inspect_component().await.unwrap();
    let pending = l
        .store
        .artifact_inspection(&l.op, &l.tenant, &l.project, &l.artifact)
        .await
        .unwrap();
    assert_eq!(pending["state"], "pending");
    assert_eq!(pending["error"], "compiler-unavailable");
    l.fixture.inspection_mode.store(1, Ordering::SeqCst);
    sqlx::query("UPDATE artifact_validations SET available_at=now()")
        .execute(&l.store.pool)
        .await
        .unwrap();
    a.inspect_component().await.unwrap();
    assert_eq!(
        l.store
            .artifact_inspection(&l.op, &l.tenant, &l.project, &l.artifact)
            .await
            .unwrap()["state"],
        "pending"
    );
    l.fixture.inspection_mode.store(2, Ordering::SeqCst);
    sqlx::query("UPDATE artifact_validations SET available_at=now()")
        .execute(&l.store.pool)
        .await
        .unwrap();
    a.inspect_component().await.unwrap();
    // The empty header fixture actually fails inspection: there is no entry point.
    assert_eq!(
        l.store
            .artifact_inspection(&l.op, &l.tenant, &l.project, &l.artifact)
            .await
            .unwrap()["error"],
        "incompatible-entry-points"
    );
    assert_eq!(
        l.store
            .artifact_inspection(&l.op, &l.tenant, &l.project, &l.artifact)
            .await
            .unwrap()["state"],
        "rejected"
    );
    let wasm = wat::parse_str(
        r#"(component
        (core module $m (func $start unreachable) (start $start)
          (func (export "run") (result i32) i32.const 0))
        (core instance $i (instantiate $m))
        (func $run (result (result)) (canon lift (core func $i "run")))
        (instance $cli (export "run" (func $run)))
        (export "wasi:cli/run@0.2.0" (instance $cli)))"#,
    )
    .unwrap();
    let uploaded = l
        .store
        .upload(&l.op, &l.tenant, &l.project, &wasm)
        .await
        .unwrap();
    // Lose the claim response to a restart; the next agent resumes the same job.
    let first = a
        .client
        .json(
            "POST",
            "/internal/component-jobs/claim",
            Some(&json!({"boot_id":a.boot})),
        )
        .await
        .unwrap();
    assert_eq!(first["job"]["artifact_id"], uploaded["id"]);
    // A compile uses the compile cache of the component's tenant only.
    assert_eq!(first["job"]["compile_scope"], json!(l.tenant));
    drop(a);
    let a = l.agent(400, 4096);
    a.inspect_component().await.unwrap();
    assert_eq!(
        l.fixture.compile_scopes.lock().unwrap().last(),
        Some(&Some(l.tenant.clone()))
    );
    let validated = l
        .store
        .artifact_inspection(&l.op, &l.tenant, &l.project, s(&uploaded["id"]))
        .await
        .unwrap();
    assert_eq!(validated["state"], "valid");
    assert_eq!(validated["inspection"]["command"], true);
    assert_eq!(validated["inspection"]["http"], false);
    assert_eq!(validated["inspection"]["digest"], digest(&wasm));
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT generation FROM artifact_validations WHERE artifact_id=$1"
        )
        .bind(s(&uploaded["id"]))
        .fetch_one(&l.store.pool)
        .await
        .unwrap(),
        1
    );
    a.inspect_component().await.unwrap();
    assert!(l.fixture.list().unwrap().is_empty());
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM executions")
            .fetch_one(&l.store.pool)
            .await
            .unwrap(),
        0
    );
    drop(a);
    l.finish().await;
}
struct Lab {
    root: tempfile::TempDir,
    store: Store,
    admin: sqlx::PgPool,
    schema: String,
    op: Principal,
    tenant: String,
    project: String,
    artifact: String,
    endpoint: String,
    pin: String,
    server: tokio::task::JoinHandle<Result<()>>,
    fixture: Arc<Fixture>,
    blocked_assignment: Arc<Mutex<Option<String>>>,
}
impl Lab {
    async fn new() -> Self {
        let dsn = std::env::var("FENDERS_TEST_DATABASE_URL").unwrap();
        let admin = sqlx::PgPool::connect(&dsn).await.unwrap();
        let schema = format!("rust_agent_{}", uid());
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&admin)
            .await
            .unwrap();
        let options: sqlx::postgres::PgConnectOptions = dsn.parse().unwrap();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_with(options.options([("search_path", schema.as_str())]))
            .await
            .unwrap();
        let root = tempfile::tempdir().unwrap();
        let store = Store::from_pool(pool, &root.path().join("control")).unwrap();
        store.migrate().await.unwrap();
        let token = std::fs::read_to_string(store.bootstrap().await.unwrap()).unwrap();
        let op = store.authenticate(&token).await.unwrap();
        let pins = pki::create(
            &root.path().join("pki"),
            &BTreeMap::from([
                ("control".into(), vec!["127.0.0.1".into()]),
                ("node".into(), vec!["127.0.0.1".into()]),
            ]),
        )
        .unwrap();
        let node=store.register_node(&op,json!({"name":"fixture","cert_sha256":pins["node"],"endpoint":"https://127.0.0.1:9443","backend":"wasm","architecture":"x86_64","runtime":"wasmtime-50.0.0-fenders-v1","cpu_percent":400,"memory_mib":4096,"instances":8})).await.unwrap();
        store
            .heartbeat(
                s(&node["id"]),
                json!({"boot_id":"fixture-boot","reports":[],"confinement":HOST_CONFINEMENT}),
            )
            .await
            .unwrap();
        let t=store.create_tenant(&op,serde_json::from_value(json!({"name":"test","allowance":{"cpu_percent":400,"memory_mib":4096,"instances":8,"storage_bytes":1000000,"transfer_bytes":10000000}})).unwrap()).await.unwrap();
        let tenant = s(&t["id"]).to_owned();
        let p = store
            .create_project(
                &op,
                &tenant,
                serde_json::from_value(json!({"name":"app"})).unwrap(),
            )
            .await
            .unwrap();
        let project = s(&p["id"]).to_owned();
        let a = store
            .upload(&op, &tenant, &project, b"\0asm\x0d\0\x01\0")
            .await
            .unwrap();
        let tls = transport::server_config(
            &root.path().join("pki/control.pem"),
            &root.path().join("pki/control.key"),
            Some(&root.path().join("pki/ca.pem")),
        )
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("https://{}", listener.local_addr().unwrap());
        let log_fault = Arc::new(AtomicU8::new(0));
        let heartbeat_fault = Arc::new(AtomicU8::new(0));
        let blocked_assignment = Arc::new(Mutex::new(None::<String>));
        let egress_fault = Arc::new(AtomicU8::new(0));
        let log_waiting = Arc::new(tokio::sync::Notify::new());
        let log_release = Arc::new(tokio::sync::Notify::new());
        let (fault, waiting, release) =
            (log_fault.clone(), log_waiting.clone(), log_release.clone());
        let heartbeat = heartbeat_fault.clone();
        let blocked = blocked_assignment.clone();
        let egress = egress_fault.clone();
        let router = api::internal(store.clone()).layer(axum::middleware::from_fn(move |request:axum::extract::Request, next:axum::middleware::Next| {
            let (fault, waiting, release) = (fault.clone(),waiting.clone(),release.clone());
            let heartbeat=heartbeat.clone();
            let blocked=blocked.clone();
            let egress=egress.clone();
            async move {
                use axum::response::IntoResponse;
                if request.method()=="GET" && blocked.lock().unwrap().as_ref().is_some_and(|id| request.uri().path()==format!("/internal/executions/{id}/1/assignment")) {
                    return StatusCode::SERVICE_UNAVAILABLE.into_response();
                }
                let logs = request.method()=="POST" && request.uri().path().ends_with("/logs");
                let mode = if logs {fault.swap(0,Ordering::SeqCst)} else {0};
                if mode==5 {return StatusCode::SERVICE_UNAVAILABLE.into_response();}
                let budget = request.method()=="POST" && request.uri().path().ends_with("/egress");
                let budget_mode=if budget {egress.swap(0,Ordering::SeqCst)} else {0};
                let lose_reply=request.uri().path()=="/internal/heartbeat" && matches!(heartbeat.fetch_update(Ordering::SeqCst,Ordering::SeqCst,|n|n.checked_sub(1)),Ok(1));
                let response=next.run(request).await;
                if budget_mode==1 {return StatusCode::SERVICE_UNAVAILABLE.into_response();}
                if budget_mode==4 {waiting.notify_one();release.notified().await;}
                if matches!(budget_mode,2|3) {
                    let bytes=axum::body::to_bytes(response.into_body(),4096).await.unwrap();
                    let mut reply:Value=serde_json::from_slice(&bytes).unwrap();
                    if budget_mode==2 {reply["ttl_ms"]=json!(0);}
                    else {reply["revision"]=json!(999);}
                    return axum::Json(reply).into_response();
                }
                if lose_reply {return StatusCode::SERVICE_UNAVAILABLE.into_response();}
                if mode==1 {return StatusCode::SERVICE_UNAVAILABLE.into_response();}
                if mode==2 {return axum::Json(json!({"accepted":true,"cursor":{"capture_id":uid(),"acknowledged":999999,"complete":true}})).into_response();}
                if mode==3 {waiting.notify_one();release.notified().await;}
                response
            }
        }));
        let server = tokio::spawn(transport::serve_tls(listener, tls, router));
        let fixture = Arc::new(Fixture::new(&root.path().join("fixture")));
        Self {
            root,
            store,
            admin,
            schema,
            op,
            tenant,
            project,
            artifact: s(&a["id"]).into(),
            endpoint,
            pin: s(&pins["control"]).into(),
            server,
            fixture,
            blocked_assignment,
        }
    }
    fn agent(&self, cpu: i64, memory: i64) -> Agent {
        let p = self.root.path().join("pki");
        let client = transport::Client::new(
            &self.endpoint,
            &p.join("ca.pem"),
            &p.join("node.pem"),
            &p.join("node.key"),
            &self.pin,
        )
        .unwrap();
        Agent::with_boot(
            self.fixture.clone(),
            client,
            &self.root.path().join("journal"),
            cpu,
            memory,
            "fixture-boot".into(),
        )
        .unwrap()
    }
    /// A run of an app made for it, started as a tenant starts one. No node
    /// here inspects components: the lab says of its own what one would.
    async fn create(&self) -> String {
        sqlx::query("ALTER TABLE artifact_validations DROP CONSTRAINT IF EXISTS artifact_validations_check2")
            .execute(&self.store.pool)
            .await
            .unwrap();
        sqlx::query("UPDATE artifact_validations v SET state='valid',lease_until=NULL,updated=now(),inspection=jsonb_build_object('format_version',1,'runtime',$2::text,'digest',a.digest,'bytes',a.size,'http',true,'command',true,'imports','[]'::jsonb,'exports','[]'::jsonb) FROM artifacts a WHERE a.id=v.artifact_id AND a.id=$1 AND v.state<>'valid'")
            .bind(&self.artifact)
            .bind(fenders_control_plane::artifacts::RUNTIME)
            .execute(&self.store.pool)
            .await
            .unwrap();
        let (p, t, project) = (&self.op, &self.tenant, &self.project);
        let name = format!("run-{}", &uid()[..12]);
        let op = self
            .store
            .create_app(
                p,
                t,
                project,
                json!({"name":name,"artifact_id":self.artifact}),
                &uid(),
            )
            .await
            .unwrap();
        let app = s(&op["resource_id"]).to_owned();
        let versions = self
            .store
            .app_versions(p, t, project, &app, None)
            .await
            .unwrap();
        self.store
            .update_app_triggers(
                p,
                t,
                project,
                &app,
                json!({"manual":true,"expected_revision":1}),
                &uid(),
            )
            .await
            .unwrap();
        self.store
            .activate_app_release(
                p,
                t,
                project,
                &app,
                json!({"version_id":versions["items"][0]["id"],"expected_revision":1}),
                &uid(),
            )
            .await
            .unwrap();
        let op = self
            .store
            .run_app(p, t, project, &app, &uid())
            .await
            .unwrap();
        let run = self
            .store
            .app_run(p, t, project, &app, s(&op["resource_id"]))
            .await
            .unwrap();
        self.store.schedule().await.unwrap();
        s(&run["execution_id"]).into()
    }
    async fn execution(&self, id: &str) -> Value {
        self.store
            .resources(
                &self.op,
                &self.tenant,
                &self.project,
                "executions",
                Some(id),
            )
            .await
            .unwrap()
    }
    /// Stops a run through its app, as a tenant does.
    async fn stop(&self, id: &str) {
        let (app, run): (String, String) =
            sqlx::query_as("SELECT app_id,id FROM customer_app_runs WHERE execution_id=$1")
                .bind(id)
                .fetch_one(&self.store.pool)
                .await
                .unwrap();
        self.store
            .cancel_app_run(&self.op, &self.tenant, &self.project, &app, &run, &uid())
            .await
            .unwrap();
    }
    async fn finish(self) {
        self.server.abort();
        self.store.pool.close().await;
        sqlx::query(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .execute(&self.admin)
            .await
            .unwrap();
        self.admin.close().await;
    }
}
/// A node not told to serve the outbound byte limit sends the heartbeat it
/// always sent; one told to names the contract and its launcher.
#[tokio::test]
async fn the_heartbeat_names_the_outbound_byte_limit_only_when_the_node_serves_it() {
    let l = Lab::new().await;
    let agent = l.agent(400, 4096);
    let observed = || async {
        sqlx::query_as::<_, (Option<String>, Option<String>)>(
            "SELECT observed_egress_budget,observed_launcher_digest FROM nodes",
        )
        .fetch_one(&l.store.pool)
        .await
        .unwrap()
    };
    agent.step().await.unwrap();
    assert_eq!(observed().await, (None, None));
    l.fixture
        .budget_launcher
        .set(BUDGET_LAUNCHER.into())
        .unwrap();
    agent.step().await.unwrap();
    assert_eq!(
        observed().await,
        (
            Some(fenders_control_plane::egress_budget::CONTRACT.to_owned()),
            Some(BUDGET_LAUNCHER.to_owned())
        )
    );
    drop(agent);
    l.finish().await;
}

#[tokio::test]
async fn unavailable_assignment_does_not_starve_later_work_or_release_its_reservation() {
    let l = Lab::new().await;
    let blocked = l.create().await;
    let ready = l.create().await;
    *l.blocked_assignment.lock().unwrap() = Some(blocked.clone());
    let agent = l.agent(400, 4096);
    // The real transport maps this 503 to 502. It must remain an error without
    // stopping delivery of the next independently authorized assignment.
    for _ in 0..2 {
        assert_eq!(
            agent.step().await.unwrap_err().status,
            StatusCode::BAD_GATEWAY
        );
    }
    assert_eq!(l.execution(&blocked).await["state"], "starting");
    assert_eq!(l.execution(&blocked).await["reserved"], true);
    assert_eq!(l.execution(&ready).await["state"], "running");
    assert_eq!(l.fixture.list().unwrap().len(), 1);
    drop(agent);
    let agent = l.agent(400, 4096);
    assert!(agent.step().await.is_err());
    assert_eq!(l.fixture.list().unwrap().len(), 1, "No replay on restart");
    *l.blocked_assignment.lock().unwrap() = None;
    agent.step().await.unwrap();
    agent.step().await.unwrap();
    assert_eq!(l.fixture.list().unwrap().len(), 2);
    assert_eq!(l.execution(&blocked).await["state"], "running");
    drop(agent);
    l.finish().await;
}

#[tokio::test]
async fn restart_recovers_backend_commit_gap_without_duplicate_launch() {
    let l = Lab::new().await;
    let id = l.create().await;
    l.fixture.fail_after_commit.store(true, Ordering::SeqCst);
    let agent = l.agent(400, 4096);
    assert!(agent.step().await.is_err());
    assert_eq!(l.fixture.list().unwrap().len(), 1);
    drop(agent);
    let agent = l.agent(400, 4096);
    agent.step().await.unwrap();
    agent.step().await.unwrap();
    assert_eq!(l.fixture.list().unwrap().len(), 1);
    assert_eq!(l.execution(&id).await["state"], "running");
    assert_eq!(agent.reports().unwrap()[0]["cpu_usec"], 100);
    drop(agent);
    l.finish().await;
}

#[tokio::test]
async fn storage_refusal_settles_without_later_launch_and_recovers_committed_backend() {
    let l = Lab::new().await;
    let id = l.create().await;
    l.fixture.storage_fault.store(1, Ordering::SeqCst);
    let agent = l.agent(400, 4096);
    agent.step().await.unwrap();
    agent.step().await.unwrap();
    let failed = l.execution(&id).await;
    assert_eq!(failed["state"], "failed");
    assert_eq!(failed["observation"]["reason"], "local-storage");
    assert_eq!(failed["reserved"], false);
    assert!(l.fixture.list().unwrap().is_empty());
    l.fixture.storage_fault.store(0, Ordering::SeqCst);
    drop(agent);
    let agent = l.agent(400, 4096);
    agent.step().await.unwrap();
    agent.step().await.unwrap();
    assert!(
        l.fixture.list().unwrap().is_empty(),
        "Restart/space recovery cannot invoke refused work"
    );
    assert_eq!(l.execution(&id).await["state"], "failed");
    let next = l.create().await;
    // A backend that committed before returning a storage error must not be
    // declared unstarted or release its reservation.
    l.fixture.storage_fault.store(2, Ordering::SeqCst);
    agent.step().await.unwrap();
    agent.step().await.unwrap();
    assert_eq!(l.fixture.list().unwrap().len(), 1);
    assert_eq!(l.execution(&next).await["state"], "running");
    assert_eq!(l.execution(&next).await["reserved"], true);
    drop(agent);
    l.finish().await;
}

#[tokio::test]
async fn stop_in_commit_gap_cleans_up_before_releasing_reservation() {
    let l = Lab::new().await;
    let id = l.create().await;
    l.fixture.fail_after_commit.store(true, Ordering::SeqCst);
    let agent = l.agent(400, 4096);
    assert!(agent.step().await.is_err());
    drop(agent);
    l.stop(&id).await;
    assert_eq!(l.execution(&id).await["reserved"], true);
    let agent = l.agent(400, 4096);
    agent.step().await.unwrap();
    assert_eq!(l.fixture.list().unwrap()[0]["state"], "stopped");
    assert_eq!(l.execution(&id).await["reserved"], true);
    agent.step().await.unwrap();
    assert_eq!(l.execution(&id).await["reserved"], false);
    assert!(agent.reports().unwrap().as_array().unwrap().is_empty());
    drop(agent);
    l.finish().await;
}

#[tokio::test]
async fn local_capacity_rejects_assignment_before_launch() {
    let l = Lab::new().await;
    let id = l.create().await;
    // Less of a CPU than the smallest app takes.
    let agent = l.agent(10, 4096);
    agent.step().await.unwrap();
    agent.step().await.unwrap();
    assert!(l.fixture.list().unwrap().is_empty());
    let e = l.execution(&id).await;
    assert_eq!(e["state"], "failed");
    assert_eq!(e["reserved"], false);
    // Counted among the refusals, by its reason.
    assert!(
        fenders_node::metrics::render(Default::default())
            .contains("fenders_node_refusals_total{reason=\"local-capacity\"} ")
    );
    drop(agent);
    l.finish().await;
}

#[tokio::test]
async fn assignments_apply_at_once_so_slow_creations_overlap() {
    let l = Lab::new().await;
    let ids = [
        l.create().await,
        l.create().await,
        l.create().await,
        l.create().await,
    ];
    l.fixture.create_delay_ms.store(250, Ordering::SeqCst);
    let agent = l.agent(400, 4096);
    agent.step().await.unwrap();
    assert_eq!(
        l.fixture.list().unwrap().len(),
        ids.len(),
        "every run created"
    );
    // Counted, not timed: how long four creations take depends on what else
    // the machine is doing, and whether they were under way at once does not.
    let at_once = l.fixture.most_creating.load(Ordering::SeqCst);
    assert!(
        at_once > 1,
        "four 250 ms creations ran one after another (most at once: {at_once})"
    );
    drop(agent);
    l.finish().await;
}
#[tokio::test]
async fn applies_at_once_cannot_admit_past_local_capacity() {
    let l = Lab::new().await;
    let ids = [
        l.create().await,
        l.create().await,
        l.create().await,
        l.create().await,
    ];
    let per_run = l.execution(&ids[0]).await["cpu_percent"]
        .as_i64()
        .expect("an execution records its CPU");
    l.fixture.create_delay_ms.store(200, Ordering::SeqCst);
    // Room for two of the four, which apply at once.
    let agent = l.agent(2 * per_run, 1 << 20);
    agent.step().await.unwrap();
    assert_eq!(
        l.fixture.list().unwrap().len(),
        2,
        "only as many runs as fit were created"
    );
    // The refusals reach the control plane with the next heartbeat.
    agent.step().await.unwrap();
    let mut failed = 0;
    for id in &ids {
        if l.execution(id).await["state"] == "failed" {
            failed += 1;
        }
    }
    assert_eq!(failed, 2, "the rest were refused for local capacity");
    drop(agent);
    l.finish().await;
}

#[tokio::test]
async fn report_sequences_keep_rising_across_a_restart_without_a_write_per_heartbeat() {
    let l = Lab::new().await;
    let id = l.create().await;
    let journal = || {
        let db = rusqlite::Connection::open(l.root.path().join("journal/agent.sqlite3")).unwrap();
        db.query_row("SELECT sequence FROM assignments", [], |r| {
            r.get::<_, i64>(0)
        })
        .unwrap()
    };
    let observed = async || {
        l.execution(&id).await["observation"]["sequence"]
            .as_i64()
            .unwrap_or(-1)
    };
    let agent = l.agent(400, 4096);
    for _ in 0..3 {
        agent.step().await.unwrap();
    }
    let (reserved, seen) = (journal(), observed().await);
    assert!(
        seen >= 1 && reserved >= seen,
        "journal {reserved} covers report {seen}"
    );
    for _ in 0..3 {
        agent.step().await.unwrap();
    }
    assert_eq!(
        journal(),
        reserved,
        "heartbeats within the block write nothing"
    );
    let before = observed().await;
    assert!(before > seen);
    // A restarted agent reports past everything the last one may have sent.
    drop(agent);
    let agent = l.agent(400, 4096);
    agent.step().await.unwrap();
    let after = observed().await;
    assert!(
        after > reserved && after > before,
        "{after} after {before} (reserved {reserved})"
    );
    drop(agent);
    l.finish().await;
}

#[tokio::test]
async fn on_demand_http_idle_and_wake_survive_agent_restart_without_duplicate_workers() {
    let l = Lab::new().await;
    l.fixture.inspection_mode.store(2, Ordering::SeqCst);
    let a = l.agent(400, 4096);
    a.inspect_component().await.unwrap();
    let wasm = wat::parse_str(
        r#"(component
      (import "wasi:http/types@0.2.6" (instance $types
        (export "incoming-request" (type (sub resource)))
        (export "response-outparam" (type (sub resource)))))
      (alias export $types "incoming-request" (type $request))
      (alias export $types "response-outparam" (type $response))
      (core module $m (func (export "handle") (param i32 i32)))
      (core instance $i (instantiate $m))
      (func $handle (param "request" (own $request)) (param "response" (own $response))
        (canon lift (core func $i "handle")))
      (instance $http (export "handle" (func $handle)))
      (export "wasi:http/incoming-handler@0.2.6" (instance $http)))"#,
    )
    .unwrap();
    let artifact = l
        .store
        .upload(&l.op, &l.tenant, &l.project, &wasm)
        .await
        .unwrap();
    a.inspect_component().await.unwrap();
    let deployed=l.store.deploy_app(&l.op,&l.tenant,&l.project,fenders_control_plane::apps::AppSubmission{value:json!({"name":"demand","artifact_id":artifact["id"],"configuration":{"keep_warm":false},"triggers":{"http":true,"manual":false}}),key:"demand",domain:"apps.test"}).await.unwrap();
    let app = s(&deployed["resource_id"]);
    l.store.schedule().await.unwrap();
    a.step().await.unwrap();
    a.step().await.unwrap();
    let first = l
        .store
        .app_http_status(&l.op, &l.tenant, &l.project, app)
        .await
        .unwrap();
    assert_eq!(first["state"], "serving");
    sqlx::query("UPDATE app_http SET last_activity=now()-interval '61 seconds' WHERE app_id=$1")
        .bind(app)
        .execute(&l.store.pool)
        .await
        .unwrap();
    l.store.schedule().await.unwrap();
    // It holds no request, so it is stopped with no pause asked first.
    a.step().await.unwrap();
    assert_eq!(l.fixture.list().unwrap()[0]["state"], "stopped");
    assert_eq!(
        l.execution(s(&first["execution_id"])).await["reserved"],
        true
    );
    a.step().await.unwrap();
    assert_eq!(
        l.execution(s(&first["execution_id"])).await["reserved"],
        false
    );
    assert_eq!(
        l.store
            .app_http_status(&l.op, &l.tenant, &l.project, app)
            .await
            .unwrap()["state"],
        "idle"
    );
    let host = s(&first["url"]).trim_start_matches("https://");
    let (_, q1) = l.store.ingress_begin(host, 0, true).await.unwrap();
    let (_, q2) = l.store.ingress_begin(host, 0, true).await.unwrap();
    l.store.schedule().await.unwrap();
    a.step().await.unwrap();
    drop(a);
    let a = l.agent(400, 4096);
    a.step().await.unwrap();
    assert_eq!(l.fixture.list().unwrap().len(), 2);
    let one = l.store.ingress_poll(&q1).await.unwrap().unwrap();
    let two = l.store.ingress_poll(&q2).await.unwrap().unwrap();
    assert_eq!(one["execution_id"], two["execution_id"]);
    assert_ne!(one["execution_id"], first["execution_id"]);
    l.store.ingress_finish(&q1, Some(0)).await.unwrap();
    l.store.ingress_finish(&q2, Some(0)).await.unwrap();
    drop(a);
    l.finish().await;
}
#[tokio::test]
async fn archived_assignments_go_in_batches_and_runs_still_reported_are_retained() {
    let l = Lab::new().await;
    let agent = l.agent(400, 4096);
    {
        // Rows as a node before shims left them: archived once reported
        // ended and no longer assigned.
        let db = rusqlite::Connection::open(l.root.path().join("journal/agent.sqlite3")).unwrap();
        for (id, backend, archived) in [
            ("e1", Some("r1"), 1),
            ("e2", Some("r2"), 1),
            ("e3", None, 1),
            ("e4", Some("r4"), 0),
            ("e5", None, 0),
        ] {
            db.execute(
                "INSERT INTO assignments(id,generation,backend_id,archived) VALUES(?,1,?,?)",
                rusqlite::params![id, backend, archived],
            )
            .unwrap();
        }
    }
    assert_eq!(
        agent.retained_runs().unwrap(),
        std::collections::HashSet::from(["r4".to_owned()])
    );
    assert_eq!(agent.delete_archived(2).unwrap(), 2);
    assert_eq!(agent.delete_archived(2).unwrap(), 1);
    assert_eq!(agent.delete_archived(2).unwrap(), 0);
    let db = rusqlite::Connection::open(l.root.path().join("journal/agent.sqlite3")).unwrap();
    let left: Vec<String> = db
        .prepare("SELECT id FROM assignments ORDER BY id")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<std::result::Result<_, _>>()
        .unwrap();
    assert_eq!(left, ["e4", "e5"]);
    drop(agent);
    l.finish().await;
}

#[tokio::test]
async fn a_run_lost_while_reports_are_made_is_recorded_in_their_transaction_at_once() {
    let l = Lab::new().await;
    let first = l.create().await;
    let second = l.create().await;
    let agent = l.agent(400, 4096);
    for _ in 0..2 {
        agent.step().await.unwrap();
    }
    drop(agent);
    let journal = l.root.path().join("journal/agent.sqlite3");
    // The run reported last is the one lost: the other's next block of
    // sequences is written, in the reports' transaction, before it is
    // reached, as a restarted agent writes it.
    let (lost, backend): (String, String) = rusqlite::Connection::open(&journal)
        .unwrap()
        .query_row(
            "SELECT id,backend_id FROM assignments ORDER BY rowid DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    let alive = if lost == first { second } else { first };
    // Its run is gone, as one is after its node restarts without it.
    std::fs::remove_dir_all(l.fixture.run_dir(&backend).unwrap()).unwrap();
    let agent = l.agent(400, 4096);
    let started = std::time::Instant::now();
    agent.step().await.unwrap();
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "reports took {:?}",
        started.elapsed()
    );
    assert_eq!(
        l.execution(&lost).await["state"],
        "lost",
        "the lost run is reported"
    );
    assert!(!l.execution(&alive).await["observation"].is_null());
    drop(agent);
    l.finish().await;
}
