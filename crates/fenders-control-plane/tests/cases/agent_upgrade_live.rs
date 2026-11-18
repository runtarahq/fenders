//! Opt-in real-process upgrade acceptance. No fabricated worker observations.
//! Runs only in a dedicated delegated test scope and dedicated PostgreSQL database.
use super::*;
use fenders_control_plane::{external_endpoints::ExternalNetworkPolicy, pki, transport};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::{
            fs::{MetadataExt, PermissionsExt},
            net::UnixStream,
            process::CommandExt,
        },
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[path = "agent_upgrade_compatibility.rs"]
mod compatibility;
#[path = "agent_upgrade_https.rs"]
mod https;
#[path = "agent_upgrade_limits.rs"]
mod limits;
#[path = "agent_upgrade_logs.rs"]
pub(super) mod logs;
#[path = "agent_upgrade_publication.rs"]
mod publication;
#[path = "agent_upgrade_recovery.rs"]
mod recovery;
#[path = "agent_upgrade_revocation.rs"]
mod revocation;
#[path = "agent_upgrade_service.rs"]
mod service;
#[path = "agent_upgrade_stop.rs"]
mod stop;
#[path = "agent_upgrade_suspension.rs"]
mod suspension;

fn input(name: &str) -> PathBuf {
    PathBuf::from(std::env::var(name).unwrap_or_else(|_| panic!("required input: {name}")))
        .canonicalize()
        .unwrap()
}
fn json_file(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}
fn named_size(name: &str) -> Value {
    fenders_control_plane::app_runtime::sizes()
        .as_array()
        .unwrap()
        .iter()
        .find(|size| size["id"] == name)
        .cloned()
        .expect("unsupported handover qualification size")
}
fn assert_named_spec(spec: &Value, name: &str) -> Value {
    let profile = named_size(name);
    for (field, expected) in [
        ("cpu_percent", &profile["cpu_percent"]),
        ("guest_memory_mib", &profile["guest_memory_mib"]),
        ("host_memory_mib", &profile["vm_memory_mib"]),
        ("wasm_memory_mib", &profile["wasm_linear_memory_mib"]),
    ] {
        assert_eq!(
            &spec[field], expected,
            "guest differs from its named size contract"
        );
    }
    profile
}
fn evidence(path: &Path, value: &Value) {
    fs::write(path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
}

pub(super) struct Postgres {
    name: String,
    pub(super) options: PgConnectOptions,
    pub(super) config: Value,
}
impl Postgres {
    pub(super) async fn start(output: &Path, credentials: &Value) -> Self {
        use sqlx::postgres::PgSslMode;
        let directory = output.join("postgres");
        let pki_dir = directory.join("pki");
        pki::create(
            &pki_dir,
            &BTreeMap::from([("server".into(), vec!["127.0.0.1".into()])]),
        )
        .unwrap();
        // The pinned image runs PostgreSQL as UID/GID 999. Only its test key changes ownership.
        std::os::unix::fs::chown(pki_dir.join("server.key"), Some(999), Some(999)).unwrap();
        // Public certificate may be read by the server; private key stays mode 0600.
        fs::set_permissions(
            pki_dir.join("server.pem"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        let password = directory.join("password");
        pki::private_file(&password, s(&credentials["password"]).as_bytes()).unwrap();
        let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = socket.local_addr().unwrap().port();
        drop(socket);
        let options = PgConnectOptions::new()
            .host("127.0.0.1")
            .port(port)
            .username(s(&credentials["user"]))
            .password(s(&credentials["password"]))
            .database("fenders_upgrade")
            .ssl_mode(PgSslMode::VerifyFull)
            .ssl_root_cert(pki_dir.join("ca.pem"));
        let fixture = Self {
            name: format!("fenders-upgrade-postgres-{}", uid()),
            options,
            config: json!({"host":"127.0.0.1","port":port,"database":"fenders_upgrade",
                "user":credentials["user"],"password":credentials["password"],"ca":fs::read_to_string(pki_dir.join("ca.pem")).unwrap()}),
        };
        let image = "docker.io/library/postgres:17@sha256:2d2b8998d31037bf721cfdf764d76ba74171b4fab3431b7f72c27c56ddbdf9e3";
        let mut command = Command::new("docker");
        command
            .args(["run", "--detach", "--pull=never", "--name"])
            .arg(&fixture.name)
            .args([
                "--network",
                "host",
                "--memory",
                "256m",
                "--cpus",
                "1",
                "--pids-limit",
                "128",
                "--security-opt",
                "no-new-privileges",
                "--tmpfs",
                "/var/lib/postgresql/data:rw,size=128m",
                "--env",
                "POSTGRES_DB=fenders_upgrade",
                "--env",
                "POSTGRES_PASSWORD_FILE=/run/pg-password",
                "--env",
                "POSTGRES_HOST_AUTH_METHOD=scram-sha-256",
                "--env",
                "POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256",
            ])
            .arg("--env")
            .arg(format!("POSTGRES_USER={}", s(&credentials["user"])));
        for (source, target) in [
            (&password, "/run/pg-password"),
            (&pki_dir.join("server.pem"), "/run/pg-server.pem"),
            (&pki_dir.join("server.key"), "/run/pg-server.key"),
        ] {
            command.arg("--mount").arg(format!(
                "type=bind,source={},destination={target},readonly",
                source.display()
            ));
        }
        let started = command
            .arg(image)
            .args(["postgres", "-c", "listen_addresses=127.0.0.1", "-c"])
            .arg(format!("port={port}"))
            .args([
                "-c",
                "ssl=on",
                "-c",
                "ssl_cert_file=/run/pg-server.pem",
                "-c",
                "ssl_key_file=/run/pg-server.key",
                "-c",
                "ssl_min_protocol_version=TLSv1.3",
            ])
            .output()
            .unwrap();
        fs::write(directory.join("start.log"), &started.stderr).unwrap();
        assert!(
            started.status.success(),
            "isolated PostgreSQL fixture did not start"
        );
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Ok(pool) = PgPoolOptions::new()
                .acquire_timeout(Duration::from_millis(500))
                .connect_with(fixture.options.clone())
                .await
            {
                pool.close().await;
                break;
            }
            if Instant::now() >= deadline {
                let logs = Command::new("docker")
                    .args(["logs", &fixture.name])
                    .output()
                    .unwrap();
                let mut diagnostic = logs.stdout;
                diagnostic.extend_from_slice(&logs.stderr);
                fs::write(directory.join("postgres.log"), diagnostic).unwrap();
                panic!(
                    "PostgreSQL TLS fixture did not become ready; inspect private postgres/postgres.log"
                );
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        fixture
    }
}
impl Drop for Postgres {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "--force", "--volumes", &self.name])
            .output();
    }
}

async fn command_output(
    mut command: Command,
    output: &Path,
    name: &str,
) -> (std::process::ExitStatus, PathBuf) {
    let report = output.join(format!("{name}.json"));
    let errors = output.join(format!("{name}.log"));
    let file_limit = if command
        .get_args()
        .next()
        .is_some_and(|arg| arg == "release-stage")
    {
        1024 * 1024 * 1024
    } else {
        65536
    };
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    unsafe {
        command.pre_exec(move || {
            let limit = libc::rlimit {
                rlim_cur: file_limit,
                rlim_max: file_limit,
            };
            if libc::setrlimit(libc::RLIMIT_FSIZE, &limit) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn().unwrap();
    // Output has its own bound. RLIMIT_FSIZE must allow the stager's bounded
    // component writes; it cannot also serve as a 64 KiB stdout/stderr limit.
    fn capture(
        reader: impl Read + Send + 'static,
        path: PathBuf,
    ) -> std::thread::JoinHandle<std::io::Result<u64>> {
        std::thread::spawn(move || {
            let mut file = fs::File::create(path)?;
            std::io::copy(&mut reader.take(65537), &mut file)
        })
    }
    let stdout = capture(child.stdout.take().unwrap(), report.clone());
    let stderr = capture(child.stderr.take().unwrap(), errors);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(
                stdout.join().unwrap().unwrap() <= 65536,
                "release probe stdout exceeded its bound"
            );
            assert!(
                stderr.join().unwrap().unwrap() <= 65536,
                "release probe stderr exceeded its bound"
            );
            return (status, report);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("release probe exceeded its deadline; source was not stopped");
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn incoming(binary: &Path, build: &Path, output: &Path, name: &str) -> (PathBuf, String) {
    let directory = output.join(format!("incoming-{name}"));
    fs::create_dir(&directory).unwrap();
    fs::copy(binary, directory.join("fenders-node")).unwrap();
    for file in ["compile", "launch", "runtime.elf"] {
        fs::copy(build.join(file), directory.join(file)).unwrap();
    }
    let mut command = Command::new(binary);
    command.arg("release-manifest").arg("--build").arg(build);
    let (status, path) = command_output(command, output, &format!("{name}-manifest")).await;
    assert!(status.success(), "release manifest generation failed");
    let bytes = fs::read(path).unwrap();
    let pin = digest(&bytes);
    fs::write(directory.join("worker-release.json"), bytes).unwrap();
    (directory, pin)
}

async fn stage_release(
    tool: &Path,
    source: &Path,
    store: &Path,
    pin: &str,
    output: &Path,
    name: &str,
) -> Value {
    let mut command = Command::new(tool);
    command
        .arg("release-stage")
        .arg("--source")
        .arg(source)
        .arg("--releases")
        .arg(store)
        .arg("--expected-manifest-sha256")
        .arg(pin);
    let (status, report) = command_output(command, output, name).await;
    json!({"case":name,"success":status.success(),"exit_code":status.code(),
        "receipt":if status.success(){json_file(&report)}else{Value::Null}})
}

fn release_files(path: &Path) -> Value {
    json!(["fenders-node","compile","launch","runtime.elf","worker-release.json"].map(|name| {
        let file=path.join(name);let metadata=fs::symlink_metadata(&file).unwrap();
        assert!(metadata.is_file());
        json!({"name":name,"inode":metadata.ino(),"mode":metadata.mode() & 0o7777,"links":metadata.nlink(),
            "mtime_seconds":metadata.mtime(),"mtime_nanoseconds":metadata.mtime_nsec(),"sha256":digest(fs::read(file).unwrap())})
    }))
}

pub(super) struct Worker {
    child: Option<Child>,
    cgroup: PathBuf,
    arguments: Vec<std::ffi::OsString>,
    output: PathBuf,
    listener: Option<std::net::TcpListener>,
    service: Option<service::Service>,
}
impl Worker {
    pub(super) fn for_control_rollout(
        output: PathBuf,
        cgroup: PathBuf,
        arguments: Vec<std::ffi::OsString>,
    ) -> Self {
        Self {
            child: None,
            cgroup,
            arguments,
            output,
            listener: None,
            service: None,
        }
    }
    pub(super) fn pid(&self) -> u32 {
        if let Some(service) = &self.service {
            service.pid().expect("worker service exited")
        } else {
            self.child.as_ref().unwrap().id()
        }
    }
    pub(super) fn alive(&mut self) -> bool {
        if let Some(service) = &self.service {
            service.pid().is_some()
        } else {
            self.child.as_mut().unwrap().try_wait().unwrap().is_none()
        }
    }
    async fn preflight(
        &mut self,
        binary: &Path,
        build: &Path,
        expected_hash: &str,
        phase: &str,
        maintenance: Option<&Value>,
    ) -> Value {
        let source_pid = self.pid();
        let mut command = Command::new(binary);
        command
            .arg("upgrade-preflight")
            .arg("--state")
            .arg(self.output.join("state"))
            .arg("--build")
            .arg(build)
            .arg("--expected-agent-sha256")
            .arg(expected_hash);
        if let Some(receipt) = maintenance {
            command
                .arg("--maintenance-epoch")
                .arg(n(&receipt["epoch"]).to_string())
                .arg("--maintenance-operation")
                .arg(s(&receipt["operation"]));
        }
        let (status, report) =
            command_output(command, &self.output, &format!("{phase}-preflight")).await;
        assert!(self.alive(), "source exited during preflight");
        assert_eq!(self.pid(), source_pid);
        json!({"phase":phase,"success":status.success(),"exit_code":status.code(),
            "source_agent_pid":source_pid,"source_agent_still_running":true,
            "report":if status.success() { json_file(&report) } else { Value::Null }})
    }
    pub(super) fn start(&mut self, binary: &Path, phase: &str, build: &Path) {
        if let Some(service) = &mut self.service {
            service.start();
            return;
        }
        assert!(self.child.is_none());
        let index = self
            .arguments
            .iter()
            .position(|argument| argument == "--build")
            .unwrap();
        self.arguments[index + 1] = build.as_os_str().to_owned();
        let mut command = Command::new(binary);
        command
            .args(&self.arguments)
            .stdout(Stdio::null())
            .stderr(fs::File::create(self.output.join(format!("{phase}-agent.log"))).unwrap());
        if let Some(listener) = &self.listener {
            let fd = listener.as_raw_fd();
            command
                .args(["--listen-fd", "3"])
                .env_remove("LISTEN_PID")
                .env_remove("LISTEN_FDS")
                .env_remove("LISTEN_FDNAMES");
            // The parent retains the listener throughout both replacements. Only
            // async-signal-safe syscalls run between fork and exec. dup2 clears
            // CLOEXEC except when source == destination, handled explicitly.
            unsafe {
                command.pre_exec(move || {
                    if libc::dup2(fd, 3) < 0 || libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
        self.child = Some(command.spawn().unwrap());
    }
    async fn stop_agent(&mut self) {
        if let Some(service) = &self.service {
            service.stop();
            return;
        }
        let child = self.child.as_mut().unwrap();
        assert!(
            child.try_wait().unwrap().is_none(),
            "agent unexpectedly exited"
        );
        // This Child remains owned/unreaped; do not signal a PID read from a stale file.
        assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGTERM) }, 0);
        let deadline = Instant::now() + Duration::from_secs(10);
        while child.try_wait().unwrap().is_none() {
            assert!(
                Instant::now() < deadline,
                "agent did not stop within the handover deadline"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        self.child.take();
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        if let Some(service) = &mut self.service {
            service.cleanup();
        }
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
        // Only this UUID scope is ours. Never kill the installed worker's cgroup.
        let _ = fs::write(self.cgroup.join("cgroup.kill"), "1");
    }
}

struct Task<T>(tokio::task::JoinHandle<T>);
impl<T> Drop for Task<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn upload(l: &Lab, path: &Path) -> String {
    let artifact = l
        .store
        .upload(&l.operator, &l.tenant, &l.project, &fs::read(path).unwrap())
        .await
        .unwrap();
    let id = s(&artifact["id"]).to_owned();
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let state: String =
            sqlx::query_scalar("SELECT state FROM artifact_validations WHERE artifact_id=$1")
                .bind(&id)
                .fetch_one(&l.store.pool)
                .await
                .unwrap();
        if state == "valid" {
            return id;
        }
        assert!(
            state != "invalid" && Instant::now() < deadline,
            "component did not validate: {state}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn backend(output: &Path, execution: &str) -> Option<PathBuf> {
    let path = output.join("state/agent/agent.sqlite3");
    let db =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .ok()?;
    db.busy_timeout(Duration::from_secs(1)).unwrap();
    use rusqlite::OptionalExtension;
    let id: Option<String> = db
        .query_row(
            "SELECT backend_id FROM assignments WHERE id=?",
            [execution],
            |row| row.get(0),
        )
        .optional()
        .unwrap()
        .flatten();
    id.map(|id| {
        identity(&id).unwrap();
        output.join("state/node/runs").join(id)
    })
}

pub(super) async fn running(l: &Lab, worker: &mut Worker, execution: &str) -> PathBuf {
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        assert!(worker.alive(), "agent exited; inspect phase log");
        let state: String = sqlx::query_scalar("SELECT state FROM executions WHERE id=$1")
            .bind(execution)
            .fetch_one(&l.store.pool)
            .await
            .unwrap();
        if state == "running"
            && let Some(path) = backend(&worker.output, execution)
        {
            return path;
        }
        assert!(
            !matches!(state.as_str(), "failed" | "lost" | "exited" | "stopped")
                && Instant::now() < deadline,
            "execution did not run: {state}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

pub(super) fn ownership(path: &Path) -> Value {
    let status = json_file(&path.join("status.json"));
    json!({"id":status["id"],"worker_pid":status["worker_pid"],"worker_identity":status["worker_identity"],
        "vmm_pid":status["vmm_pid"],"vmm_identity":status["vmm_identity"]})
}

pub(super) fn kernel_controls(path: &Path) -> Value {
    limits::kernel(path)
}

pub(super) fn native_status(path: &Path) -> Value {
    let mut stream = UnixStream::connect(path.join("control.sock")).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    stream.write_all(b"status\n").unwrap();
    let mut bytes = Vec::new();
    stream.take(4096).read_to_end(&mut bytes).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

async fn wait_for_active_request(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let status = native_status(path);
        if status["idle"] == false {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "no in-flight HTTP request at handover"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

pub(super) async fn proxy(
    mut source: tokio::net::TcpStream,
    target: String,
    transferred: Arc<AtomicU64>,
) {
    let mut destination = tokio::net::TcpStream::connect(target).await.unwrap();
    let (mut from_guest, mut to_guest) = source.split();
    let (mut from_database, mut to_database) = destination.split();
    let upstream = async {
        let mut buffer = [0_u8; 8192];
        loop {
            let count = from_guest.read(&mut buffer).await?;
            if count == 0 {
                to_database.shutdown().await?;
                return Ok::<_, std::io::Error>(());
            }
            to_database.write_all(&buffer[..count]).await?;
            transferred.fetch_add(count as u64, Ordering::SeqCst);
        }
    };
    let downstream = async {
        tokio::io::copy(&mut from_database, &mut to_guest)
            .await
            .map(|_| ())
    };
    let _ = tokio::try_join!(upstream, downstream);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "dedicated Linux/KVM dev scope, PostgreSQL TLS fixture and original/candidate agent binaries required"]
async fn agent_upgrade_and_rollback_preserve_vms_connections_and_http() {
    assert_eq!(
        (std::env::consts::OS, std::env::consts::ARCH),
        ("linux", "x86_64")
    );
    assert!(Path::new("/dev/kvm").exists());
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "dev runner needs root for its isolated cgroup and Docker fixture"
    );
    let build = input("FENDERS_UPGRADE_BUILD");
    let candidate_build = if std::env::var_os("FENDERS_UPGRADE_CANDIDATE_BUILD").is_some() {
        input("FENDERS_UPGRADE_CANDIDATE_BUILD")
    } else {
        build.clone()
    };
    let original = input("FENDERS_UPGRADE_ORIGINAL_AGENT");
    let candidate = input("FENDERS_UPGRADE_CANDIDATE_AGENT");
    let preserve_listener = match std::env::var("FENDERS_UPGRADE_PRESERVE_LISTENER").as_deref() {
        Ok("1") => true,
        Ok("0") | Err(std::env::VarError::NotPresent) => false,
        _ => panic!("FENDERS_UPGRADE_PRESERVE_LISTENER must be 0 or 1"),
    };
    let require_preflight = match std::env::var("FENDERS_UPGRADE_REQUIRE_PREFLIGHT").as_deref() {
        Ok("1") => true,
        Ok("0") | Err(std::env::VarError::NotPresent) => false,
        _ => panic!("FENDERS_UPGRADE_REQUIRE_PREFLIGHT must be 0 or 1"),
    };
    let require_quiescence = match std::env::var("FENDERS_UPGRADE_REQUIRE_QUIESCENCE").as_deref() {
        Ok("1") => true,
        Ok("0") | Err(std::env::VarError::NotPresent) => false,
        _ => panic!("FENDERS_UPGRADE_REQUIRE_QUIESCENCE must be 0 or 1"),
    };
    assert!(
        !require_quiescence || require_preflight,
        "quiescence qualification requires preflight"
    );
    let require_staging = match std::env::var("FENDERS_UPGRADE_STAGE_RELEASES").as_deref() {
        Ok("1") => true,
        Ok("0") | Err(std::env::VarError::NotPresent) => false,
        _ => panic!("FENDERS_UPGRADE_STAGE_RELEASES must be 0 or 1"),
    };
    let use_service = match std::env::var("FENDERS_UPGRADE_SYSTEMD_SERVICE").as_deref() {
        Ok("1") => true,
        Ok("0") | Err(std::env::VarError::NotPresent) => false,
        _ => panic!("FENDERS_UPGRADE_SYSTEMD_SERVICE must be 0 or 1"),
    };
    let require_https = match std::env::var("FENDERS_UPGRADE_PUBLIC_HTTPS").as_deref() {
        Ok("1") => true,
        Ok("0") | Err(std::env::VarError::NotPresent) => false,
        _ => panic!("FENDERS_UPGRADE_PUBLIC_HTTPS must be 0 or 1"),
    };
    let require_logs = match std::env::var("FENDERS_UPGRADE_CUSTOMER_LOGS").as_deref() {
        Ok("1") => true,
        Ok("0") | Err(std::env::VarError::NotPresent) => false,
        _ => panic!("FENDERS_UPGRADE_CUSTOMER_LOGS must be 0 or 1"),
    };
    let require_limits = match std::env::var("FENDERS_UPGRADE_ENFORCEMENT").as_deref() {
        Ok("1") => true,
        Ok("0") | Err(std::env::VarError::NotPresent) => false,
        _ => panic!("FENDERS_UPGRADE_ENFORCEMENT must be 0 or 1"),
    };
    let require_recovery = match std::env::var("FENDERS_UPGRADE_STARTUP_RECOVERY").as_deref() {
        Ok("1") => true,
        Ok("0") | Err(std::env::VarError::NotPresent) => false,
        _ => panic!("FENDERS_UPGRADE_STARTUP_RECOVERY must be 0 or 1"),
    };
    assert!(
        !require_recovery || (use_service && require_limits),
        "startup recovery requires the maintained service, logs, HTTPS and enforcement journey"
    );
    let recovery_stage = recovery::Stage::from_env(require_recovery);
    let publication_failure =
        match std::env::var("FENDERS_UPGRADE_RECOVERY_PUBLICATION_FAILURE").as_deref() {
            Ok("1") => true,
            Ok("0") | Err(std::env::VarError::NotPresent) => false,
            _ => panic!("FENDERS_UPGRADE_RECOVERY_PUBLICATION_FAILURE must be 0 or 1"),
        };
    assert!(
        !publication_failure
            || (require_recovery && recovery_stage == recovery::Stage::AfterAdoption),
        "publication failure requires post-adoption startup recovery"
    );
    let rollback_recovery =
        match std::env::var("FENDERS_UPGRADE_ROLLBACK_STARTUP_RECOVERY").as_deref() {
            Ok("1") => true,
            Ok("0") | Err(std::env::VarError::NotPresent) => false,
            _ => panic!("FENDERS_UPGRADE_ROLLBACK_STARTUP_RECOVERY must be 0 or 1"),
        };
    assert!(
        !rollback_recovery || publication_failure,
        "rollback recovery requires post-adoption startup and publication failures"
    );
    let require_stop = match std::env::var("FENDERS_UPGRADE_CUSTOMER_STOP").as_deref() {
        Ok("1") => true,
        Ok("0") | Err(std::env::VarError::NotPresent) => false,
        _ => panic!("FENDERS_UPGRADE_CUSTOMER_STOP must be 0 or 1"),
    };
    assert!(
        !require_stop || publication_failure,
        "customer stop race requires interrupted publication recovery"
    );
    let paused_stop = match std::env::var("FENDERS_UPGRADE_CUSTOMER_PAUSED_STOP").as_deref() {
        Ok("1") => true,
        Ok("0") | Err(std::env::VarError::NotPresent) => false,
        _ => panic!("FENDERS_UPGRADE_CUSTOMER_PAUSED_STOP must be 0 or 1"),
    };
    assert!(
        !paused_stop || require_stop,
        "paused stop requires customer-stop qualification"
    );
    let require_suspension = match std::env::var("FENDERS_UPGRADE_WORKSPACE_SUSPENSION").as_deref()
    {
        Ok("1") => true,
        Ok("0") | Err(std::env::VarError::NotPresent) => false,
        _ => panic!("FENDERS_UPGRADE_WORKSPACE_SUSPENSION must be 0 or 1"),
    };
    assert!(
        !require_suspension || (publication_failure && !require_stop),
        "workspace suspension requires publication recovery and its own auxiliary VM slot"
    );
    let require_deletion = match std::env::var("FENDERS_UPGRADE_APP_DELETION").as_deref() {
        Ok("1") => true,
        Ok("0") | Err(std::env::VarError::NotPresent) => false,
        _ => panic!("FENDERS_UPGRADE_APP_DELETION must be 0 or 1"),
    };
    assert!(
        !require_deletion || (publication_failure && !require_stop && !require_suspension),
        "app deletion requires publication recovery and its own auxiliary VM slot"
    );
    let require_revocation = match std::env::var("FENDERS_UPGRADE_TCP_REVOCATION").as_deref() {
        Ok("1") => true,
        Ok("0") | Err(std::env::VarError::NotPresent) => false,
        _ => panic!("FENDERS_UPGRADE_TCP_REVOCATION must be 0 or 1"),
    };
    assert!(
        !require_revocation
            || (publication_failure && !require_stop && !require_suspension && !require_deletion),
        "TCP revocation requires publication recovery and its own auxiliary VM slot"
    );
    assert!(
        !require_limits || require_logs,
        "enforcement qualification requires the two-tenant customer-log journey"
    );
    let requested_size = match std::env::var("FENDERS_UPGRADE_SIZE") {
        Ok(size) => Some(size),
        Err(std::env::VarError::NotPresent) => None,
        Err(_) => panic!("FENDERS_UPGRADE_SIZE must be a named UTF-8 size"),
    };
    assert!(
        requested_size.is_none() || require_limits,
        "named-size qualification requires enforcement coverage"
    );
    let public_size = requested_size.as_deref().unwrap_or("medium");
    let public_profile = named_size(public_size);
    // Leave room for explicit new-work probes without changing enrollment or
    // stopping any continuity VM. The original public guest keeps its full size.
    let http_size = if public_size == "large" {
        "small"
    } else {
        "medium"
    };
    let probe_size = if requested_size.is_some() {
        "small"
    } else {
        "medium"
    };
    let probe_cpu = if requested_size.is_some() {
        n(&named_size(probe_size)["cpu_percent"])
    } else if require_https {
        50
    } else {
        100
    };
    if requested_size.is_some() {
        let continuity_cpu =
            n(&public_profile["cpu_percent"]) + n(&named_size(http_size)["cpu_percent"]) + 50;
        assert!(
            continuity_cpu + probe_cpu <= 200 && continuity_cpu + 100 > 200,
            "named-size fixture must retain VMs and preserve a CPU-capacity refusal case"
        );
    }
    assert!(
        !require_logs || require_https,
        "customer-log qualification requires the changed-runtime HTTPS journey"
    );
    assert!(
        !require_https || use_service,
        "public HTTPS qualification requires maintained systemd handover"
    );
    let runtimes = require_https.then(|| {
        let original = digest(fs::read(build.join("runtime.elf")).unwrap());
        let candidate = digest(fs::read(candidate_build.join("runtime.elf")).unwrap());
        assert_ne!(
            original, candidate,
            "public HTTPS qualification requires different guest-runtime bytes"
        );
        (original, candidate)
    });
    let https_component = require_https.then(|| input("FENDERS_UPGRADE_HTTPS_COMPONENT"));
    assert!(
        !use_service || require_staging,
        "service qualification requires staged releases"
    );
    assert!(
        !require_staging || require_quiescence,
        "staging qualification requires sealed handover"
    );
    let unsupported = require_preflight.then(|| input("FENDERS_UPGRADE_UNSUPPORTED_AGENT"));
    assert!(
        std::env::var_os("FENDERS_UPGRADE_LEGACY_MANAGEMENT_AGENT").is_none()
            || (require_staging && require_https),
        "legacy management refusal requires staging and three-VM HTTPS continuity"
    );
    assert!(
        !require_preflight || preserve_listener,
        "preflight acceptance requires preserved listener mode"
    );
    if preserve_listener {
        for binary in [&original, &candidate] {
            let help = Command::new(binary).arg("--help").output().unwrap();
            assert!(
                help.status.success()
                    && String::from_utf8_lossy(&help.stdout).contains("--listen-fd"),
                "listener handover requires two compatible agents; bootstrap legacy agents explicitly"
            );
        }
    }
    assert_ne!(
        digest(fs::read(&original).unwrap()),
        digest(fs::read(&candidate).unwrap()),
        "test requires different agent bytes"
    );
    let pg_component = input("FENDERS_UPGRADE_POSTGRES_WASM");
    let credentials = json_file(&input("FENDERS_UPGRADE_POSTGRES_JSON_FILE"));
    assert!(
        !s(&credentials["user"]).is_empty() && s(&credentials["password"]).len() >= 16,
        "protected fixture credentials required"
    );
    let address =
        std::env::var("FENDERS_UPGRADE_ADDRESS").expect("explicit test-only host IPv4 address");
    let output =
        PathBuf::from(std::env::var("FENDERS_UPGRADE_OUTPUT").expect("new private output"));
    fs::create_dir(&output).expect("output must not exist");
    fs::set_permissions(&output, fs::Permissions::from_mode(0o700)).unwrap();
    let output = output.canonicalize().unwrap();
    let postgres = Postgres::start(&output, &credentials).await;
    let pg = &postgres.config;
    let cgroup = input("FENDERS_UPGRADE_CGROUP_PARENT").join(format!("upgrade-{}", uid()));
    fs::create_dir(&cgroup).unwrap();
    let mut worker = Worker {
        child: None,
        cgroup,
        arguments: vec![],
        output: output.clone(),
        listener: None,
        service: None,
    };
    let mut l = Lab::with_options(postgres.options.clone()).await;
    l.store = l.store.with_external_network(ExternalNetworkPolicy {
        allowed_cidrs: vec![format!("{address}/32").parse().unwrap()],
        denied_cidrs: vec![],
    });
    if require_https {
        https::configure(&mut l).await;
    }
    let pki_dir = output.join("pki");
    let pins = pki::create(
        &pki_dir,
        &BTreeMap::from([
            ("control".into(), vec!["127.0.0.1".into()]),
            ("node".into(), vec!["127.0.0.1".into()]),
        ]),
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let control = format!("https://{}", listener.local_addr().unwrap());
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    if preserve_listener && !use_service {
        worker.listener = Some(socket);
    } else {
        drop(socket);
    }
    let node_url = format!("https://127.0.0.1:{port}");
    let launcher = digest(fs::read(build.join("launch")).unwrap());
    let candidate_launcher = digest(fs::read(candidate_build.join("launch")).unwrap());
    let node = l
        .store
        .register_node(
            &l.operator,
            json!({
                "name":"upgrade-test", "cert_sha256":pins["node"],"endpoint":node_url,
                "backend":"wasm","architecture":"x86_64","runtime":"wasmtime-50.0.0-fenders-v1",
                "cpu_percent":200,"memory_mib":1024,"instances":4,
                "egress_budget_launcher":launcher,"egress_budget_required":true
                ,"public_https_runtime":runtimes.as_ref().map(|(original,_)|original)
            }),
        )
        .await
        .unwrap();
    let tls = transport::server_config(
        &pki_dir.join("control.pem"),
        &pki_dir.join("control.key"),
        Some(&pki_dir.join("ca.pem")),
    )
    .unwrap();
    let _server = Task(tokio::spawn(transport::serve_tls(
        listener,
        tls,
        api::internal(l.store.clone()),
    )));
    let scheduler = l.store.clone();
    let _scheduler = Task(tokio::spawn(async move {
        loop {
            scheduler.schedule().await.unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }));
    let mut arguments = Command::new("unused");
    arguments
        .arg("--state")
        .arg(output.join("state"))
        .arg("--build")
        .arg(&build)
        .arg("--cgroup-root")
        .arg(&worker.cgroup)
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
            "--port",
        ])
        .arg(port.to_string());
    worker.arguments = arguments.get_args().map(ToOwned::to_owned).collect();
    let release_store = output.join("releases");
    let mut staging = Vec::new();
    let mut staged_candidate: Option<Value> = None;
    let staged_original = if require_staging {
        fs::create_dir(&release_store).unwrap();
        let (directory, pin) = incoming(&original, &build, &output, "original").await;
        let observation = stage_release(
            &original,
            &directory,
            &release_store,
            &pin,
            &output,
            "stage-original",
        )
        .await;
        assert_eq!(
            observation["success"], true,
            "original release staging failed"
        );
        assert_eq!(observation["receipt"]["created"], true);
        let receipt = observation["receipt"].clone();
        staging.push(observation);
        Some(receipt)
    } else {
        None
    };
    let original_build = staged_original
        .as_ref()
        .map(|r| PathBuf::from(s(&r["path"])))
        .unwrap_or_else(|| build.clone());
    let original_binary = if require_staging {
        original_build.join("fenders-node")
    } else {
        original.clone()
    };
    let retained_files = require_staging.then(|| release_files(&original_build));
    if use_service {
        let service = service::Service::new(
            &output,
            &original_binary,
            &original_build,
            &release_store,
            port,
            &worker.arguments,
        );
        fs::remove_dir(&worker.cgroup).unwrap();
        worker.cgroup = service.cgroup();
        worker.service = Some(service);
    }
    worker.start(&original_binary, "original", &original_build);
    let http_artifact = upload(&l, &build.join("example-http.wasm")).await;
    let pg_artifact = upload(&l, &pg_component).await;
    let relay = tokio::net::TcpListener::bind((address.as_str(), 0))
        .await
        .unwrap();
    let relay_port = relay.local_addr().unwrap().port();
    let connections = Arc::new(AtomicU64::new(0));
    let transferred = Arc::new(AtomicU64::new(0));
    let (accepted, bytes) = (connections.clone(), transferred.clone());
    let target = format!("{}:{}", s(&pg["host"]), n(&pg["port"]));
    let _relay = Task(tokio::spawn(async move {
        while let Ok((stream, _)) = relay.accept().await {
            accepted.fetch_add(1, Ordering::SeqCst);
            // This test uses exactly one connection. Keep the task attached to its listener lifetime.
            proxy(stream, target.clone(), bytes.clone()).await;
        }
    }));
    let endpoint = l
        .store
        .create_endpoint(
            &l.operator,
            &l.tenant,
            &l.project,
            json!({"name":"postgres-tls-fixture","host":address,"port":relay_port}),
            &uid(),
        )
        .await
        .unwrap();
    let endpoint = l
        .store
        .resources(
            &l.operator,
            &l.tenant,
            &l.project,
            "external-endpoints",
            Some(s(&endpoint["resource_id"])),
        )
        .await
        .unwrap();
    let username = l
        .store
        .create_secret(
            &l.operator,
            &l.tenant,
            &l.project,
            json!({"name":"pg-user","value":pg["user"]}),
        )
        .await
        .unwrap();
    let password = l
        .store
        .create_secret(
            &l.operator,
            &l.tenant,
            &l.project,
            json!({"name":"pg-password","value":pg["password"]}),
        )
        .await
        .unwrap();
    let mut customer_logs = if require_logs {
        Some(logs::Logs::start(&l, &pki_dir).await)
    } else {
        None
    };
    let http = if let Some(logs) = customer_logs.as_mut() {
        logs.http(&l, &build.join("example-http.wasm"), http_size)
            .await
    } else {
        l
        .create(
            "upgrade-http",
            json!({"artifact_id":http_artifact,"mode":"http","cpu_percent":if require_quiescence {50}else{100},"lifetime_seconds":180,"env":{"HTTP_HOLD_MS":"200"}}),
        )
        .await
    };
    let pg_key = uid();
    let mut pg_spec = json!({"artifact_id":pg_artifact,"cpu_percent":if require_quiescence {50}else{100},"wasm_memory_mib":8,"fuel":2000000000,
        "lifetime_seconds":180,"network_id":endpoint["network_id"],"endpoint_ids":[endpoint["id"]],
        "env":{"HTTP_CASE":"postgres","PGHOST":pg["host"],"PGHOSTADDR":address,"PGPORT":relay_port.to_string(),
            "PGDATABASE":pg["database"],"PGSSLROOTCERT_PEM":pg["ca"],"PGOPTIONS":format!("-csearch_path={}",l.schema),
            "RUN_ID":"upgrade-once","PG_CREATE_TABLE":"1","PG_HOLD":"1"},
        "secret_env":{"PGUSER":username["id"],"PGPASSWORD":password["id"]}});
    if require_logs {
        pg_spec["env"]["PG_HOLD_SECONDS"] = json!("150");
    }
    let command = l.create(&pg_key, pg_spec.clone()).await;
    let http_id = s(&http["resource_id"]);
    let command_id = s(&command["resource_id"]);
    let http_backend = running(&l, &mut worker, http_id).await;
    let pg_backend = running(&l, &mut worker, command_id).await;
    let initial_http = ownership(&http_backend);
    let initial_pg = ownership(&pg_backend);
    let http_config = fs::read(http_backend.join("config.json")).unwrap();
    let pg_config = fs::read(pg_backend.join("config.json")).unwrap();
    if require_staging {
        assert_eq!(
            json_file(&http_backend.join("config.json"))["build"],
            original_build.to_str().unwrap()
        );
        assert_eq!(
            json_file(&pg_backend.join("config.json"))["build"],
            original_build.to_str().unwrap()
        );
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    while !fs::read_to_string(pg_backend.join("output.log"))
        .unwrap()
        .contains("FENDERS_PG_HOLD_OPEN")
    {
        assert!(
            Instant::now() < deadline,
            "PostgreSQL TLS fixture did not authenticate and hold"
        );
        assert_eq!(
            json_file(&pg_backend.join("status.json"))["state"],
            "running"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(connections.load(Ordering::SeqCst), 1);
    let mut public_https = if let Some(component) = https_component {
        Some(
            https::Https::start(
                &l,
                &mut worker,
                &component,
                &runtimes.as_ref().unwrap().0,
                public_size,
                probe_size,
            )
            .await,
        )
    } else {
        None
    };
    if let Some(logs) = customer_logs.as_mut() {
        logs.bind_alpha(&l, &public_https.as_ref().unwrap().execution)
            .await;
    }
    let mut resource_limits = if require_limits {
        Some(
            limits::Limits::start(
                &l,
                s(&node["id"]),
                http_id,
                &[
                    &http_backend,
                    &pg_backend,
                    &public_https.as_ref().unwrap().backend,
                ],
                http_size,
                public_size,
            )
            .await,
        )
    } else {
        None
    };
    let client = transport::Client::new(
        &node_url,
        &pki_dir.join("ca.pem"),
        &pki_dir.join("control.pem"),
        &pki_dir.join("control.key"),
        s(&pins["node"]),
    )
    .unwrap();
    let maintenance_client = client.clone();
    let samples = Arc::new(Mutex::new(Vec::<Value>::new()));
    let observed = samples.clone();
    let execution = http_id.to_owned();
    let _traffic = Task(tokio::spawn(async move {
        loop {
            let started = Instant::now();
            let result = client
                .json(
                    "POST",
                    "/rpc/ingress",
                    Some(&json!({"id":execution,"generation":1,
                "request":{"method":"GET","path":"/hello","headers":{},"body":""}})),
                )
                .await;
            let ok = result
                .as_ref()
                .is_ok_and(|r| r["status"] == 200 && r["body"] == "ZmVuZGVyczovaGVsbG8=");
            observed
                .lock()
                .unwrap()
                .push(json!({"ok":ok,"milliseconds":started.elapsed().as_secs_f64()*1000.0}));
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }));
    let mut phases = Vec::new();
    let mut preflights = Vec::new();
    let mut receipt_compatibility = Vec::new();
    let mut handovers = Vec::new();
    let mut startup_recovery = Value::Null;
    let mut rollback_startup_recovery = Value::Null;
    let mut legacy_management_refusal = Value::Null;
    let mut customer_stop = None;
    let mut workspace_suspension = None;
    let mut tcp_revocation = None;
    for (phase, binary) in [
        ("baseline", None),
        ("upgrade", Some(&candidate)),
        ("rollback", Some(&original)),
    ] {
        let mut bytes_before = transferred.load(Ordering::SeqCst);
        let mut https_before = public_https.as_ref().map(|h| h.sequence());
        let mut cutover_revision = None;
        let started = Instant::now();
        if require_staging && phase == "baseline" {
            if std::env::var_os("FENDERS_UPGRADE_LEGACY_MANAGEMENT_AGENT").is_some() {
                legacy_management_refusal = compatibility::refuse_legacy(
                    &original_binary,
                    &input("FENDERS_UPGRADE_LEGACY_MANAGEMENT_AGENT"),
                    &build,
                    &release_store,
                    &output,
                    &maintenance_client,
                    &[
                        &http_backend,
                        &pg_backend,
                        &public_https.as_ref().unwrap().backend,
                    ],
                )
                .await;
            }
            let (directory, pin) =
                incoming(&candidate, &candidate_build, &output, "candidate").await;
            let wrong = stage_release(
                &original_binary,
                &directory,
                &release_store,
                &"0".repeat(64),
                &output,
                "stage-rejected-pin",
            )
            .await;
            assert_eq!(wrong["success"], false);
            staging.push(wrong);
            let refused = stage_release(
                &original_binary,
                &directory,
                &original_build,
                &pin,
                &output,
                "stage-rejected-retained-store",
            )
            .await;
            assert_eq!(
                refused["success"], false,
                "retained release was accepted as a writable store"
            );
            assert_eq!(
                release_files(&original_build),
                *retained_files.as_ref().unwrap()
            );
            assert_eq!(
                fs::read_dir(&original_build).unwrap().count(),
                5,
                "retained release contents changed"
            );
            staging.push(refused);
            let bad = output.join("incoming-tampered");
            fs::create_dir(&bad).unwrap();
            for file in [
                "fenders-node",
                "compile",
                "launch",
                "runtime.elf",
                "worker-release.json",
            ] {
                fs::copy(directory.join(file), bad.join(file)).unwrap();
            }
            fs::write(bad.join("compile"), "tampered incoming compiler").unwrap();
            let refused = stage_release(
                &original_binary,
                &bad,
                &release_store,
                &pin,
                &output,
                "stage-rejected-bytes",
            )
            .await;
            assert_eq!(refused["success"], false);
            staging.push(refused);
            let conflict = release_store.join(&pin);
            fs::create_dir(&conflict).unwrap();
            let inode = fs::metadata(&conflict).unwrap().ino();
            let refused = stage_release(
                &original_binary,
                &directory,
                &release_store,
                &pin,
                &output,
                "stage-rejected-conflict",
            )
            .await;
            assert_eq!(refused["success"], false);
            assert_eq!(fs::metadata(&conflict).unwrap().ino(), inode);
            assert_eq!(fs::read_dir(&conflict).unwrap().count(), 0);
            fs::remove_dir(&conflict).unwrap();
            staging.push(refused);
            let created = stage_release(
                &original_binary,
                &directory,
                &release_store,
                &pin,
                &output,
                "stage-candidate",
            )
            .await;
            assert_eq!(created["success"], true, "candidate release staging failed");
            assert_eq!(created["receipt"]["created"], true);
            let receipt = created["receipt"].clone();
            staging.push(created);
            let before = release_files(Path::new(s(&receipt["path"])));
            let repeated = stage_release(
                &original_binary,
                &directory,
                &release_store,
                &pin,
                &output,
                "stage-candidate-repeat",
            )
            .await;
            assert_eq!(repeated["success"], true);
            assert_eq!(repeated["receipt"]["created"], false);
            assert_eq!(release_files(Path::new(s(&receipt["path"]))), before);
            staging.push(repeated);
            assert_eq!(
                release_files(&original_build),
                *retained_files.as_ref().unwrap()
            );
            assert!(worker.alive(), "staging stopped the source agent");
            staged_candidate = Some(receipt);
        }
        if require_preflight && phase == "baseline" {
            for (label, binary, hash) in [
                ("rejected-hash", &candidate, "0".repeat(64)),
                (
                    "rejected-legacy",
                    unsupported.as_ref().unwrap(),
                    digest(fs::read(unsupported.as_ref().unwrap()).unwrap()),
                ),
            ] {
                let observation = worker.preflight(binary, &build, &hash, label, None).await;
                assert_eq!(
                    observation["success"], false,
                    "incompatible candidate was accepted"
                );
                preflights.push(observation);
            }
        }
        if require_recovery && phase == "upgrade" {
            if require_revocation {
                let internal = transport::Client::new(
                    &control,
                    &pki_dir.join("ca.pem"),
                    &pki_dir.join("node.pem"),
                    &pki_dir.join("node.key"),
                    s(&pins["control"]),
                )
                .unwrap();
                tcp_revocation = Some(
                    revocation::Revocation::start(
                        &l,
                        &mut worker,
                        pg,
                        &pg_spec,
                        &address,
                        customer_logs.as_ref().unwrap().customer_client(),
                        internal,
                        probe_cpu,
                    )
                    .await,
                );
            }
            if require_suspension || require_deletion {
                let internal = transport::Client::new(
                    &control,
                    &pki_dir.join("ca.pem"),
                    &pki_dir.join("node.pem"),
                    &pki_dir.join("node.key"),
                    s(&pins["control"]),
                )
                .unwrap();
                workspace_suspension = Some(
                    suspension::Suspension::start(
                        &l,
                        &mut worker,
                        &input("FENDERS_UPGRADE_HTTPS_COMPONENT"),
                        customer_logs.as_ref().unwrap().customer_client(),
                        internal,
                        require_deletion,
                    )
                    .await,
                );
            }
            if require_stop {
                customer_stop = Some(
                    stop::Stop::start(
                        &l,
                        &mut worker,
                        &http_artifact,
                        customer_logs.as_ref().unwrap().customer_client(),
                        paused_stop,
                    )
                    .await,
                );
            }
            startup_recovery = recovery::run(
                &l,
                &mut worker,
                &maintenance_client,
                &candidate,
                Path::new(s(&staged_candidate.as_ref().unwrap()["path"])),
                &original_build,
                s(&node["id"]),
                [
                    &http_backend,
                    &pg_backend,
                    &public_https.as_ref().unwrap().backend,
                ],
                recovery_stage,
                recovery::Direction::Upgrade,
                publication_failure,
                customer_stop.as_mut(),
                workspace_suspension.as_mut(),
                tcp_revocation.as_mut(),
            )
            .await;
            public_https
                .as_mut()
                .unwrap()
                .observe(&l, "startup_recovery", https_before.unwrap())
                .await;
            customer_logs
                .as_mut()
                .unwrap()
                .observe(
                    &l,
                    "startup_recovery",
                    &public_https.as_ref().unwrap().backend,
                    &http_backend,
                )
                .await;
        }
        if rollback_recovery && phase == "rollback" {
            rollback_startup_recovery = recovery::run(
                &l,
                &mut worker,
                &maintenance_client,
                &original,
                &original_build,
                Path::new(s(&staged_candidate.as_ref().unwrap()["path"])),
                s(&node["id"]),
                [
                    &http_backend,
                    &pg_backend,
                    &public_https.as_ref().unwrap().backend,
                ],
                recovery::Stage::AfterAdoption,
                recovery::Direction::Rollback,
                true,
                None,
                None,
                None,
            )
            .await;
            if let Some(stop) = customer_stop.as_mut() {
                stop.observe(&l, &worker, "rollback_recovery").await;
            }
            if let Some(suspension) = workspace_suspension.as_mut() {
                suspension.observe(&l, &worker, "rollback_recovery").await;
            }
            if let Some(revocation) = tcp_revocation.as_mut() {
                revocation.observe(&l, &worker, "rollback_recovery").await;
            }
            public_https
                .as_mut()
                .unwrap()
                .observe(&l, "rollback_recovery", https_before.unwrap())
                .await;
            customer_logs
                .as_mut()
                .unwrap()
                .observe(
                    &l,
                    "rollback_recovery",
                    &public_https.as_ref().unwrap().backend,
                    &http_backend,
                )
                .await;
            // Final rollback must show new progress after the reverse recovery,
            // rather than count traffic already observed during that probe.
            bytes_before = transferred.load(Ordering::SeqCst);
            https_before = public_https.as_ref().map(|h| h.sequence());
        }
        if let Some(binary) = binary {
            let staged = if phase == "upgrade" {
                staged_candidate.as_ref()
            } else {
                staged_original.as_ref()
            };
            let target_build = staged
                .map(|r| PathBuf::from(s(&r["path"])))
                .unwrap_or_else(|| {
                    if phase == "upgrade" {
                        candidate_build.clone()
                    } else {
                        build.clone()
                    }
                });
            let binary = if staged.is_some() {
                target_build.join("fenders-node")
            } else {
                binary.to_path_buf()
            };
            let mut sealed = Value::Null;
            let mut deferred = None;
            if require_quiescence {
                l.store
                    .node_mode(&l.operator, s(&node["id"]), json!({"draining":true}))
                    .await
                    .unwrap();
                let before = maintenance_client
                    .json("POST", "/rpc/maintenance/status", Some(&json!({})))
                    .await
                    .unwrap();
                let request = json!({"expected_epoch":before["epoch"],"operation":uid(),"candidate_sha256":digest(fs::read(&binary).unwrap())});
                sealed = maintenance_client
                    .json("POST", "/rpc/maintenance/prepare", Some(&request))
                    .await
                    .unwrap();
                assert_eq!(sealed["mode"], "sealed");
                assert_eq!(sealed["epoch"], before["epoch"]);
                assert_eq!(
                    maintenance_client
                        .json("POST", "/rpc/maintenance/prepare", Some(&request))
                        .await
                        .unwrap(),
                    sealed
                );
                let forbidden = maintenance_client.json("POST","/rpc/maintenance/resume",Some(&json!({"expected_epoch":sealed["epoch"],"operation":sealed["operation"]}))).await.unwrap_err();
                assert_eq!(forbidden.status, StatusCode::CONFLICT);
                let pending = l.create(&uid(),json!({"artifact_id":http_artifact,"mode":"http","cpu_percent":probe_cpu,"lifetime_seconds":180})).await;
                let id = s(&pending["resource_id"]).to_owned();
                tokio::time::sleep(Duration::from_millis(400)).await;
                let assigned: Option<String> =
                    sqlx::query_scalar("SELECT node_id FROM executions WHERE id=$1")
                        .bind(&id)
                        .fetch_one(&l.store.pool)
                        .await
                        .unwrap();
                assert!(
                    assigned.is_none(),
                    "scheduler assigned new work to a drained node"
                );
                // Exercise the local barrier with an actual assignment, independent
                // of the scheduler's drain flag. Existing requests keep running.
                l.store
                    .node_mode(&l.operator, s(&node["id"]), json!({"draining":false}))
                    .await
                    .unwrap();
                let deadline = Instant::now() + Duration::from_secs(5);
                loop {
                    let assigned: Option<String> =
                        sqlx::query_scalar("SELECT node_id FROM executions WHERE id=$1")
                            .bind(&id)
                            .fetch_one(&l.store.pool)
                            .await
                            .unwrap();
                    if assigned.as_deref() == Some(s(&node["id"])) {
                        break;
                    }
                    assert!(
                        Instant::now() < deadline,
                        "probe did not receive a real assignment"
                    );
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                l.store
                    .node_mode(&l.operator, s(&node["id"]), json!({"draining":true}))
                    .await
                    .unwrap();
                tokio::time::sleep(Duration::from_secs(2)).await;
                assert!(
                    backend(&output, &id).is_none(),
                    "quiesced source admitted a new backend"
                );
                let db = rusqlite::Connection::open_with_flags(
                    output.join("state/node/node.sqlite3"),
                    rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
                )
                .unwrap();
                let count: i64 = db
                    .query_row(
                        "SELECT count(*) FROM runs WHERE request_key=?",
                        [format!("platform-{id}")],
                        |row| row.get(0),
                    )
                    .unwrap();
                assert_eq!(count, 0, "quiescence hid a committed but unmapped backend");
                deferred = Some(id);
            }
            if require_preflight {
                let hash = digest(fs::read(&binary).unwrap());
                let observation = worker
                    .preflight(
                        &binary,
                        &target_build,
                        &hash,
                        phase,
                        require_quiescence.then_some(&sealed),
                    )
                    .await;
                assert_eq!(
                    observation["success"], true,
                    "candidate preflight failed before source shutdown"
                );
                assert_eq!(observation["report"]["candidate"]["agent_sha256"], hash);
                assert_eq!(observation["report"]["schema"], 1);
                assert_eq!(
                    observation["report"]["admission_quiescence_required"],
                    !require_quiescence
                );
                if require_quiescence {
                    assert_eq!(observation["report"]["maintenance"], sealed);
                }
                assert_eq!(observation["report"]["rollout_authorized"], false);
                let mut checked: Vec<&str> = observation["report"]["checked_execution_ids"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(s)
                    .collect();
                checked.sort();
                let mut expected = vec![s(&initial_http["id"]), s(&initial_pg["id"])];
                if let Some(h) = &public_https {
                    expected.push(h.backend_id());
                }
                expected.sort();
                assert_eq!(checked, expected);
                preflights.push(observation);
            }
            let target_launcher = if phase == "upgrade" {
                &candidate_launcher
            } else {
                &launcher
            };
            // This is an explicit operator action, never an approval inferred
            // from a worker heartbeat. Preserve the source approval during overlap.
            if candidate_launcher != launcher {
                l.store
                    .node_mode(
                        &l.operator,
                        s(&node["id"]),
                        json!({
                            "egress_budget_launcher":target_launcher,
                            "retained_egress_launchers":[launcher, candidate_launcher]
                        }),
                    )
                    .await
                    .unwrap();
            }
            if let Some((original, candidate)) = &runtimes {
                let target = if phase == "upgrade" {
                    candidate
                } else {
                    original
                };
                l.store.node_mode(&l.operator,s(&node["id"]),json!({
                    "public_https_runtime":target,"retained_https_runtimes":[original,candidate]
                })).await.unwrap();
            }
            let selected = if let Some(service) = &worker.service {
                Some(service.select(&target_build, &sealed, phase).await)
            } else {
                None
            };
            wait_for_active_request(&http_backend).await;
            worker.stop_agent().await;
            // Capture after the source is dead, excluding its final in-flight
            // renewal from the replacement's acknowledgement requirement.
            cutover_revision = Some(
                native_status(&pg_backend)["egress_budget_revision"]
                    .as_i64()
                    .unwrap(),
            );
            if let Some(h) = public_https.as_mut() {
                h.cutover();
            }
            worker.start(&binary, phase, &target_build);
            if require_quiescence {
                let adopted = maintenance_client
                    .json("POST", "/rpc/maintenance/status", Some(&json!({})))
                    .await
                    .unwrap();
                assert_eq!(n(&adopted["epoch"]), n(&sealed["epoch"]) + 1);
                assert_eq!(adopted["mode"], "sealed");
                assert_eq!(adopted["operation"], sealed["operation"]);
                tokio::time::sleep(Duration::from_secs(2)).await;
                let id = deferred.as_ref().unwrap();
                assert!(
                    backend(&output, id).is_none(),
                    "adoption reopened admission implicitly"
                );
                let stale=maintenance_client.json("POST","/rpc/maintenance/resume",Some(&json!({"expected_epoch":sealed["epoch"],"operation":sealed["operation"]}))).await.unwrap_err();
                assert_eq!(stale.status, StatusCode::CONFLICT);
                let opened=maintenance_client.json("POST","/rpc/maintenance/resume",Some(&json!({"expected_epoch":adopted["epoch"],"operation":adopted["operation"]}))).await.unwrap();
                assert_eq!(opened["mode"], "open");
                let probe = running(&l, &mut worker, id).await;
                if require_staging {
                    assert_eq!(
                        json_file(&probe.join("config.json"))["build"],
                        target_build.to_str().unwrap()
                    );
                }
                let identity = ownership(&probe);
                l.stop(id, &uid()).await.unwrap();
                let deadline = Instant::now() + Duration::from_secs(10);
                loop {
                    let reserved: bool =
                        sqlx::query_scalar("SELECT reserved FROM executions WHERE id=$1")
                            .bind(id)
                            .fetch_one(&l.store.pool)
                            .await
                            .unwrap();
                    if !reserved {
                        break;
                    }
                    assert!(
                        Instant::now() < deadline,
                        "deferred probe reservation did not settle"
                    );
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                handovers.push(json!({"phase":phase,"source":sealed,"adopted":adopted,"opened":opened,
                    "stale_resume_refused":true,"source_resume_refused":true,"deferred_execution":id,
                    "scheduler_drain_verified":true,"source_admission_blocked":true,"adoption_admission_blocked":true,
                    "deferred_backend_after_explicit_resume":identity,"service_selection":selected}));
                l.store
                    .node_mode(&l.operator, s(&node["id"]), json!({"draining":false}))
                    .await
                    .unwrap();
            }
            if candidate_launcher != launcher {
                // A fresh networked execution must use and acknowledge the new
                // current launcher while the original database VM stays on A.
                let op = l
                    .create(
                        &uid(),
                        json!({"artifact_id":http_artifact,"mode":"http",
                    "cpu_percent":probe_cpu,"lifetime_seconds":180,"network_id":endpoint["network_id"]}),
                    )
                    .await;
                let id = s(&op["resource_id"]);
                let probe = running(&l, &mut worker, id).await;
                let deadline = Instant::now() + Duration::from_secs(10);
                let acknowledged = loop {
                    let status = native_status(&probe);
                    if n(&status["egress_budget_revision"]) > 0 {
                        break status;
                    }
                    assert!(
                        Instant::now() < deadline,
                        "new launcher did not acknowledge byte authority"
                    );
                    tokio::time::sleep(Duration::from_millis(50)).await;
                };
                assert_eq!(
                    json_file(&probe.join("status.json"))["egress_authority"]["launcher_digest"],
                    *target_launcher
                );
                let pinned: String = sqlx::query_scalar(
                    "SELECT launcher_digest FROM execution_egress_budgets WHERE execution_id=$1",
                )
                .bind(id)
                .fetch_one(&l.store.pool)
                .await
                .unwrap();
                assert_eq!(pinned, *target_launcher);
                // Exercise lifecycle delivery while this real runtime is retained
                // rather than current, as during rollout preparation. The idle
                // HTTP probe has no traffic to interrupt; continuity probes run on.
                let other_launcher = if phase == "upgrade" {
                    &launcher
                } else {
                    &candidate_launcher
                };
                l.store
                    .node_mode(
                        &l.operator,
                        s(&node["id"]),
                        json!({"egress_budget_launcher":other_launcher}),
                    )
                    .await
                    .unwrap();
                l.store
                    .node_mode(
                        &l.operator,
                        s(&node["id"]),
                        json!({"egress_budget_launcher":target_launcher}),
                    )
                    .await
                    .unwrap();
                if phase == "upgrade" && require_staging {
                    // Exercise the real A reader against a live B-created
                    // receipt before stopping this existing probe. This is a
                    // read-only observation, not permission to roll back.
                    let config = json_file(&probe.join("config.json"));
                    let receipt = &config["worker_release"];
                    let manifest = json_file(&target_build.join("worker-release.json"));
                    assert_eq!(manifest["management_protocol"], 1);
                    assert!(receipt.get("management_protocol").is_none());
                    assert_eq!(receipt["agent_sha256"], manifest["agent_sha256"]);
                    assert_eq!(receipt["runtime"], manifest["runtime"]);
                    let check = worker
                        .preflight(
                            &original_binary,
                            &original_build,
                            &digest(fs::read(&original_binary).unwrap()),
                            "a-reads-live-b-receipt",
                            None,
                        )
                        .await;
                    assert_eq!(check["success"], true);
                    assert!(
                        check["report"]["checked_execution_ids"]
                            .as_array()
                            .unwrap()
                            .contains(&config["id"])
                    );
                    assert_eq!(check["report"]["rollout_authorized"], false);
                    receipt_compatibility.push(
                        json!({"phase":phase,"execution":id,"backend":config["id"],
                        "creator_receipt":receipt,"activation_manifest":manifest,"old_reader":check,
                        "live_candidate_execution":true,"activation_contract_retained":true}),
                    );
                }
                l.stop(id, &uid()).await.unwrap();
                let deadline = Instant::now() + Duration::from_secs(10);
                loop {
                    let reserved: bool =
                        sqlx::query_scalar("SELECT reserved FROM executions WHERE id=$1")
                            .bind(id)
                            .fetch_one(&l.store.pool)
                            .await
                            .unwrap();
                    if !reserved {
                        break;
                    }
                    assert!(
                        Instant::now() < deadline,
                        "new launcher probe did not settle"
                    );
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                handovers.push(json!({"phase":phase,"new_runtime_budget_probe":id,
                    "launcher_digest":pinned,"acknowledged_revision":acknowledged["egress_budget_revision"],
                    "retained_pause_resume_verified":true,"reservation_settled":true}));
            }
            if let Some(h) = &public_https {
                let pair = runtimes.as_ref().unwrap();
                let runtime = if phase == "upgrade" { &pair.1 } else { &pair.0 };
                handovers.push(h.probe(&l, &mut worker, phase, runtime).await);
            }
        }
        // Observe traffic without retrying failed HTTP requests. Each replacement
        // must itself acknowledge a newer budget, not merely coast on source TTL.
        if let Some(revision) = cutover_revision {
            let deadline = Instant::now() + Duration::from_secs(15);
            loop {
                let status = native_status(&pg_backend);
                if n(&status["egress_budget_revision"]) > revision {
                    break;
                }
                assert!(
                    Instant::now() < deadline,
                    "replacement did not renew retained byte authority"
                );
                assert_eq!(
                    json_file(&pg_backend.join("status.json"))["state"],
                    "running"
                );
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert!(worker.alive(), "replacement exited");
        assert_eq!(ownership(&http_backend), initial_http);
        assert_eq!(ownership(&pg_backend), initial_pg);
        if require_staging {
            assert_eq!(
                release_files(&original_build),
                *retained_files.as_ref().unwrap()
            );
            // Configurations include credentials: never print their bytes on failure.
            assert!(
                fs::read(http_backend.join("config.json")).unwrap() == http_config,
                "HTTP configuration changed"
            );
            assert!(
                fs::read(pg_backend.join("config.json")).unwrap() == pg_config,
                "command configuration changed"
            );
        }
        assert_eq!(
            json_file(&pg_backend.join("status.json"))["state"],
            "running"
        );
        assert_eq!(
            connections.load(Ordering::SeqCst),
            1,
            "database connection was replaced"
        );
        assert!(
            transferred.load(Ordering::SeqCst) > bytes_before,
            "database traffic stopped"
        );
        let retried = l.create(&pg_key, pg_spec.clone()).await;
        assert_eq!(retried["resource_id"], command["resource_id"]);
        let reserved: i64 = sqlx::query_scalar("SELECT count(*) FROM executions WHERE reserved")
            .fetch_one(&l.store.pool)
            .await
            .unwrap();
        assert_eq!(reserved, if require_https { 3 } else { 2 });
        if let Some(stop) = customer_stop.as_mut() {
            stop.observe(&l, &worker, phase).await;
        }
        if let Some(suspension) = workspace_suspension.as_mut() {
            suspension.observe(&l, &worker, phase).await;
        }
        if let Some(revocation) = tcp_revocation.as_mut() {
            revocation.observe(&l, &worker, phase).await;
        }
        if let Some(h) = public_https.as_mut() {
            h.observe(&l, phase, https_before.unwrap()).await;
        }
        if let Some(logs) = customer_logs.as_mut() {
            logs.observe(
                &l,
                phase,
                &public_https.as_ref().unwrap().backend,
                &http_backend,
            )
            .await;
        }
        if let Some(limits) = resource_limits.as_mut() {
            limits
                .observe(
                    &l,
                    phase,
                    &output,
                    &public_https.as_ref().unwrap().backend,
                    &http_artifact,
                )
                .await;
        }
        let authority: Value = sqlx::query_scalar("SELECT jsonb_build_object('launcher_digest',launcher_digest,'revision',revision,'held_bytes',held_bytes,'state',state,'unexpired',expires>clock_timestamp()) FROM execution_egress_budgets WHERE execution_id=$1")
            .bind(command_id).fetch_one(&l.store.pool).await.unwrap();
        assert_eq!(authority["launcher_digest"], launcher);
        assert_eq!(authority["state"], "active");
        assert_eq!(authority["unexpired"], true);
        phases.push(json!({"phase":phase,"milliseconds":started.elapsed().as_secs_f64()*1000.0,
            "guest_to_database_bytes":transferred.load(Ordering::SeqCst),"connections":connections.load(Ordering::SeqCst),
            "http_identity":ownership(&http_backend),"command_identity":ownership(&pg_backend),"reserved":reserved,
            "byte_authority":authority,"cutover_budget_revision":cutover_revision}));
        phases.last_mut().unwrap()["public_https"] =
            json!(public_https.as_ref().and_then(|h| h.phases.last()));
        let observed = samples.lock().unwrap().clone();
        evidence(
            &output.join("handover-observations.json"),
            &json!({
                "complete":false,"preserved_rpc_listener":preserve_listener,"preflights":preflights,"handovers":handovers,"staging":staging,
                "startup_recovery":startup_recovery,"phases":phases,"customer_log_phases":customer_logs.as_ref().map(|logs|&logs.phases),
                "enforcement_phases":resource_limits.as_ref().map(|limits|&limits.phases),
                "http_failures":observed.iter().filter(|sample|sample["ok"]!=true).count(),
                "http_samples":observed,"revocation_verified":false
            }),
        );
    }
    drop(_traffic);
    let samples = samples.lock().unwrap().clone();
    let failures = samples.iter().filter(|s| s["ok"] != true).count();
    // Confirm a run that kept its connection through rollback still stops.
    l.stop(command_id, &uid()).await.unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let status = json_file(&pg_backend.join("status.json"));
        if matches!(s(&status["state"]), "exited" | "failed") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "connection did not close after revocation"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let logs = fs::read_to_string(pg_backend.join("output.log")).unwrap();
    assert_eq!(logs.matches("FENDERS_AUTHENTICATED").count(), 1);
    assert!(logs.contains("FENDERS_TLS_SERVER TLSv1.3"));
    assert!(logs.contains("FENDERS_PG_CONNECTION_CLOSED"));
    if let Some(h) = &public_https {
        h.revoke(&l, s(&node["id"])).await;
    }
    let customer_log_result = if let Some(logs) = customer_logs.as_mut() {
        logs.stop_http(&l).await;
        Some(
            logs.finish(&public_https.as_ref().unwrap().backend, &http_backend)
                .await,
        )
    } else {
        None
    };
    let mut result = json!({"real_kvm":true,"real_postgres_verified_tls":true,"test_complete":false,
        "preserved_rpc_listener":preserve_listener,
        "systemd_service":use_service,"systemd_unit":worker.service.as_ref().map(|s|&s.name),
        "preflight_required":require_preflight,"preflights":preflights,
        "quiescence_required":require_quiescence,"handovers":handovers,"startup_recovery":startup_recovery,
        "staged_releases":require_staging,"staging":staging,"retained_files":retained_files,
        "continuity_configurations_unchanged":require_staging,
        "postgres_execution_cpu_percent":if require_quiescence {50}else{100},
        "named_size_qualification":requested_size,"public_https_profile":require_https.then_some(&public_profile),
        "post_preservation_large_probe_required":requested_size.as_deref()==Some("large"),
        "http_continuity_size":require_logs.then_some(http_size),"auxiliary_probe_size":probe_size,"auxiliary_probe_cpu_percent":probe_cpu,
        "original_sha256":digest(fs::read(&original).unwrap()),"candidate_sha256":digest(fs::read(&candidate).unwrap()),
        "original_launcher_sha256":launcher,"candidate_launcher_sha256":candidate_launcher,
        "distinct_launcher_bytes":launcher!=candidate_launcher,
        "guest_runtimes":runtimes,"public_https":public_https.as_ref().map(|h|json!({
            "execution":h.execution,"phases":h.phases,"runtime_revocation_verified":true,
            "single_invocation_verified":true})),
        "customer_logs":customer_log_result,
        "customer_stop":customer_stop.as_ref().map(|stop|stop.report()),
        "enforcement_phases":resource_limits.as_ref().map(|limits|&limits.phases),
        "node_id":node["id"],"http_execution":http_id,"command_execution":command_id,"phases":phases,
        "http_samples":samples,"http_failures":failures,"revocation_closed_connection":true,
        "single_database_authentication":true,"qualification":"dev handover only; no cross-host migration acceptance"});
    if rollback_recovery {
        recovery::verify_bidirectional(
            &startup_recovery,
            &rollback_startup_recovery,
            &handovers,
            s(&result["original_sha256"]),
            s(&result["candidate_sha256"]),
        )
        .expect("bidirectional recovery proof did not match its releases and ownership path");
    }
    result["rollback_startup_recovery"] = rollback_startup_recovery;
    result["receipt_compatibility"] = json!(receipt_compatibility);
    result["tcp_revocation"] = json!(tcp_revocation.as_ref().map(|r| r.report()));
    result["bidirectional_recovery_verified"] = json!(rollback_recovery);
    result["legacy_management_refusal"] = legacy_management_refusal;
    result[if require_deletion {
        "app_deletion"
    } else {
        "workspace_suspension"
    }] = json!(workspace_suspension.as_ref().map(|s| s.report()));
    evidence(&output.join("results.json"), &result);
    if !require_logs {
        l.stop(http_id, &uid()).await.unwrap();
    }
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let reserved: i64 = sqlx::query_scalar("SELECT count(*) FROM executions WHERE reserved")
            .fetch_one(&l.store.pool)
            .await
            .unwrap();
        if reserved == 0 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "test reservations did not settle"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    if requested_size.as_deref() == Some("large") {
        // Primary A→B→A preservation and intentional revocation are complete.
        // With zero reservations, qualify a fresh large VM on B through the
        // same maintained service, preflight and fenced selection path.
        let target = PathBuf::from(s(&staged_candidate.as_ref().unwrap()["path"]));
        let binary = target.join("fenders-node");
        let runtime = &runtimes.as_ref().unwrap().1;
        l.store
            .node_mode(
                &l.operator,
                s(&node["id"]),
                json!({"draining":true,
            "public_https_runtime":runtime,"retained_https_runtimes":[],
            "egress_budget_launcher":candidate_launcher}),
            )
            .await
            .unwrap();
        let before = maintenance_client
            .json("POST", "/rpc/maintenance/status", Some(&json!({})))
            .await
            .unwrap();
        let sealed=maintenance_client.json("POST","/rpc/maintenance/prepare",Some(&json!({
            "expected_epoch":before["epoch"],"operation":uid(),"candidate_sha256":digest(fs::read(&binary).unwrap())}))).await.unwrap();
        assert_eq!(sealed["mode"], "sealed");
        assert_eq!(sealed["epoch"], before["epoch"]);
        let preflight = worker
            .preflight(
                &binary,
                &target,
                &digest(fs::read(&binary).unwrap()),
                "fresh-large",
                Some(&sealed),
            )
            .await;
        assert_eq!(preflight["success"], true);
        assert_eq!(preflight["report"]["maintenance"], sealed);
        let selected = worker
            .service
            .as_ref()
            .unwrap()
            .select(&target, &sealed, "fresh-large")
            .await;
        worker.stop_agent().await;
        worker.start(&binary, "fresh-large", &target);
        let adopted = maintenance_client
            .json("POST", "/rpc/maintenance/status", Some(&json!({})))
            .await
            .unwrap();
        assert_eq!(n(&adopted["epoch"]), n(&sealed["epoch"]) + 1);
        assert_eq!(adopted["mode"], "sealed");
        assert_eq!(adopted["operation"], sealed["operation"]);
        let opened = maintenance_client
            .json(
                "POST",
                "/rpc/maintenance/resume",
                Some(&json!({
            "expected_epoch":adopted["epoch"],"operation":adopted["operation"]})),
            )
            .await
            .unwrap();
        assert_eq!(opened["mode"], "open");
        l.store
            .node_mode(&l.operator, s(&node["id"]), json!({"draining":false}))
            .await
            .unwrap();
        let probe = public_https
            .as_ref()
            .unwrap()
            .probe_at_size(&l, &mut worker, "fresh-large", runtime, "large")
            .await;
        let original = l.execution(&public_https.as_ref().unwrap().execution).await;
        assert_eq!(original["desired"], "stopped");
        assert_eq!(original["generation"], 2);
        assert_eq!(original["reserved"], false);
        let state: String = sqlx::query_scalar(
            "SELECT state FROM network_grants WHERE execution_id=$1 ORDER BY state DESC LIMIT 1",
        )
        .bind(command_id)
        .fetch_one(&l.store.pool)
        .await
        .unwrap();
        assert_eq!(state, "revoked");
        let reserved: i64 = sqlx::query_scalar("SELECT count(*) FROM executions WHERE reserved")
            .fetch_one(&l.store.pool)
            .await
            .unwrap();
        assert_eq!(reserved, 0);
        result["post_preservation_large_probe"] = json!({"source":sealed,"adopted":adopted,"opened":opened,
            "preflight":preflight,"selection":selected,"probe":probe,
            "original_runtime_withdrawal_still_effective":true,"original_private_grant_still_revoked":true,
            "all_reservations_settled":true});
        evidence(&output.join("results.json"), &result);
    }
    drop(worker);
    drop(_scheduler);
    drop(_server);
    drop(_relay);
    l.finish().await;
    assert!(
        samples.len() >= 20,
        "insufficient continuous HTTP observations"
    );
    assert_eq!(
        failures, 0,
        "HTTP failed during handover; inspect retained results.json"
    );
    result["test_complete"] = json!(true);
    evidence(&output.join("results.json"), &result);
}
