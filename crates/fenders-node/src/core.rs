use crate::durable::atomic_json;
use axum::http::StatusCode;
use fenders_node_protocol::{
    error::{Error, Result},
    model::{HOST_CONFINEMENT, MAX_UPLOAD, digest, identity, uid},
    value::*,
    workloads::{run_context, terminal, wasm_spec},
};
use serde_json::{Value, json};
mod artifact_cache;
mod compile_cache;
mod compiler_limits;
pub use compiler_limits::CompilerLimits;
mod disk_admission;
mod shims;

fn compiler_failure(status: Option<i32>, receipt: &[u8], digest: &str, size: usize) -> Error {
    use fenders_node_protocol::artifacts::{MAX_INSPECTION_BYTES, validate_rejection};
    if status == Some(2)
        && receipt.len() <= MAX_INSPECTION_BYTES
        && let Ok(value) = serde_json::from_slice::<Value>(receipt)
        && let Ok(code) = validate_rejection(&value, digest, size)
    {
        return Error::new(StatusCode::UNPROCESSABLE_ENTITY, code);
    }
    Error::new(StatusCode::SERVICE_UNAVAILABLE, "compiler unavailable")
}
use std::{
    fs,
    io::{Read, Write},
    os::unix::{
        fs::{OpenOptionsExt, PermissionsExt},
        net::UnixStream,
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Mutex, MutexGuard},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
pub fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs_f64()
}
pub fn lock<T>(mutex: &Mutex<T>) -> Result<MutexGuard<'_, T>> {
    mutex.lock().map_err(|_| Error::internal())
}
pub fn load(path: &Path) -> Result<Value> {
    serde_json::from_slice(&fs::read(path)?).map_err(|_| Error::internal())
}
/// Makes `path` a directory of this user's alone. One that is already there
/// must be this user's own and no link: a directory someone else made, or a
/// link to one, would be theirs to fill whatever its mode was set to.
pub fn private_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    fs::create_dir_all(path)?;
    let found = fs::symlink_metadata(path)?;
    if !found.is_dir() || found.uid() != unsafe { libc::geteuid() } {
        return Err(Error::invalid(
            "a state directory must be a directory of the user the node runs as, not a link",
        ));
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

/// The contents of `path`, a secret this user keeps: a regular file, no
/// link, this user's own, that no one else can read.
pub fn private_text(path: &Path) -> Result<String> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let found = file.metadata()?;
    if !found.is_file() || found.uid() != unsafe { libc::geteuid() } || found.mode() & 0o077 != 0 {
        return Err(Error::invalid(
            "a secret file must be a regular file of the user the node runs as, with no group or other access",
        ));
    }
    let mut text = String::new();
    (&mut file).take(4096).read_to_string(&mut text)?;
    Ok(text)
}
pub fn flock(path: &Path) -> Result<fs::File> {
    use std::os::fd::AsRawFd;
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(conflict("state is already owned by another process"));
    }
    Ok(file)
}
pub fn boot_id() -> Result<String> {
    Ok(fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .to_owned())
}
pub fn process_identity(pid: i64) -> Result<Option<Value>> {
    let stat = match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(v) => v,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let stat = stat
        .rsplit_once(')')
        .ok_or_else(Error::internal)?
        .1
        .split_whitespace()
        .collect::<Vec<_>>();
    if stat.first() == Some(&"Z") {
        return Ok(None);
    }
    Ok(Some(json!([
        boot_id()?,
        stat.get(19).ok_or_else(Error::internal)?
    ])))
}
pub fn clock_ns() -> Result<i64> {
    #[cfg(target_os = "linux")]
    {
        let mut t = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut t) } != 0 {
            return Err(Error::internal());
        }
        Ok(t.tv_sec * 1000000000 + t.tv_nsec)
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(Error::invalid("node requires Linux CLOCK_BOOTTIME"))
    }
}
pub fn control(path: &Path, command: &str) -> Result<Value> {
    let mut stream = UnixStream::connect(path).map_err(|_| {
        Error::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "execution control unavailable",
        )
    })?;
    stream.set_read_timeout(Some(Duration::from_secs(4)))?;
    stream.set_write_timeout(Some(Duration::from_secs(4)))?;
    stream.write_all(format!("{command}\n").as_bytes())?;
    let mut data = Vec::new();
    let mut buffer = [0; 1024];
    while !data.contains(&b'\n') {
        let len = stream.read(&mut buffer)?;
        if len == 0 || data.len() + len > 4096 {
            return Err(Error::internal());
        }
        data.extend_from_slice(&buffer[..len]);
    }
    let value: Value = serde_json::from_slice(&data).map_err(|_| Error::internal())?;
    if !value["error"].is_null() {
        return Err(conflict("runtime rejected lifecycle command"));
    }
    Ok(value)
}
pub fn validate_boot(config: &Value) -> Result<()> {
    if config["spec"].get("network_deadline_ns").is_some()
        && config["network_boot_id"] != boot_id()?
    {
        return Err(conflict(
            "network authorization belongs to a different host boot",
        ));
    }
    Ok(())
}
pub fn normalize_origin(origin: &Value) -> Result<String> {
    let u = url::Url::parse(text(origin)?).map_err(|_| Error::invalid("invalid HTTP origin"))?;
    if !matches!(u.scheme(), "http" | "https")
        || u.host_str().is_none()
        || !u.username().is_empty()
        || u.password().is_some()
        || u.path() != "/"
        || u.query().is_some()
        || u.fragment().is_some()
        || u.host_str().unwrap().contains(':')
    {
        return Err(Error::invalid("invalid HTTP origin"));
    }
    Ok(format!(
        "{}://{}:{}",
        u.scheme(),
        u.host_str().unwrap(),
        u.port_or_known_default().unwrap()
    ))
}
/// A launch that asks for its guest's output to be kept (`output`): the
/// environment variables whose values are masked in it, sorted, each a string
/// variable of `env`. A spec without the field captures nothing.
fn output_capture(value: &Value, env: &Value) -> Result<Value> {
    fields(value, &["redact_env"], &[])?;
    let names = get(value, "redact_env", json!([]));
    let names = names
        .as_array()
        .filter(|v| v.len() <= 32)
        .ok_or_else(|| Error::invalid("invalid output redaction variables"))?;
    let mut redact = std::collections::BTreeSet::new();
    for name in names {
        let name = text(name)?;
        if !env.get(name).is_some_and(Value::is_string) {
            return Err(Error::invalid(
                "output redaction variable is not in the environment",
            ));
        }
        redact.insert(name);
    }
    Ok(json!({"redact_env": redact}))
}

pub fn validate_spec(value: &Value) -> Result<Value> {
    fields(
        value,
        &[
            "artifact",
            "mode",
            "cpu_percent",
            "guest_memory_mib",
            "host_memory_mib",
            "wasm_memory_mib",
            "fuel",
            "fuel_refuel",
            "instances",
            "table_elements",
            "tables",
            "memories",
            "wasm_stack_kib",
            "lifetime_seconds",
            "request_timeout_ms",
            "http_concurrency",
            "tcp_allow",
            "http_allow",
            "host_origin",
            "http_trust",
            "http_public_targets",
            "http_runtime_digest",
            "dns_server",
            "env",
            "network_deadline_ns",
            "network_start_blocked",
            "egress_budget",
            "run_context",
            "output",
        ],
        &["artifact"],
    )?;
    let artifact = text(&value["artifact"])?;
    if artifact.len() != 64
        || !artifact
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::invalid("artifact must be a SHA-256 digest"));
    }
    let mut base = json!({"artifact_id":"0".repeat(32)});
    for key in [
        "mode",
        "cpu_percent",
        "guest_memory_mib",
        "host_memory_mib",
        "wasm_memory_mib",
        "fuel",
        "fuel_refuel",
        "instances",
        "table_elements",
        "tables",
        "memories",
        "wasm_stack_kib",
        "lifetime_seconds",
        "request_timeout_ms",
        "http_concurrency",
        "env",
    ] {
        if let Some(v) = value.get(key) {
            base[key] = v.clone();
        }
    }
    if base.get("lifetime_seconds").is_none() {
        base["lifetime_seconds"] = json!(300);
    }
    let mut out = wasm_spec(&base, false)?;
    for key in [
        "artifact_id",
        "secret_env",
        "architecture",
        "runtime",
        "restart_policy",
    ] {
        out.as_object_mut().unwrap().remove(key);
    }
    out["artifact"] = json!(artifact);
    let endpoints = get(value, "tcp_allow", json!([]));
    let endpoints = endpoints
        .as_array()
        .filter(|v| v.len() <= 32)
        .ok_or_else(|| Error::invalid("invalid TCP endpoints"))?;
    let mut tcp = std::collections::BTreeSet::new();
    for endpoint in endpoints {
        let string = text(endpoint)?;
        let parsed = string
            .parse::<std::net::SocketAddrV4>()
            .map_err(|_| Error::invalid("invalid TCP endpoint"))?;
        if parsed.port() == 0 || parsed.to_string() != string {
            return Err(Error::invalid("invalid TCP endpoint"));
        }
        tcp.insert(string.to_owned());
    }
    out["tcp_allow"] = json!(tcp);
    let origins = get(value, "http_allow", json!([]));
    let origins = origins
        .as_array()
        .filter(|v| v.len() <= 32)
        .ok_or_else(|| Error::invalid("invalid HTTP origins"))?;
    let mut http = std::collections::BTreeSet::new();
    for origin in origins {
        http.insert(normalize_origin(origin)?);
    }
    // The host-bound origin reaches the node alone, so it may not also be a network grant.
    if let Some(origin) = value.get("host_origin") {
        let origin = normalize_origin(origin)?;
        if http.contains(&origin) {
            return Err(Error::invalid(
                "the host-bound origin cannot also be an HTTP grant",
            ));
        }
        out["host_origin"] = json!(origin);
    }
    out["http_allow"] = json!(http);
    if let Some(trust) = value.get("http_trust") {
        out["http_trust"] = trust.clone();
    }
    if let Some(targets) = value.get("http_public_targets") {
        out["http_public_targets"] = targets.clone();
        if targets != "" {
            let runtime = text(&value["http_runtime_digest"])?;
            if runtime.len() != 64
                || !runtime
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(Error::invalid(
                    "public HTTPS requires an approved runtime digest",
                ));
            }
            out["http_runtime_digest"] = json!(runtime);
        }
    }
    out["dns_server"] = value["dns_server"].clone();
    if !out["dns_server"].is_null() {
        text(&out["dns_server"])?
            .parse::<std::net::Ipv4Addr>()
            .map_err(|_| Error::invalid("invalid DNS server"))?;
    }
    if let Some(deadline) = value.get("network_deadline_ns") {
        let deadline = integer(deadline, 0, i64::MAX)?;
        if deadline > clock_ns()?.saturating_add(30000000000) {
            return Err(Error::invalid("network lease cannot exceed 30 seconds"));
        }
        out["network_deadline_ns"] = json!(deadline);
    }
    if let Some(gate) = value.get("network_start_blocked") {
        if *gate != true || out["network_deadline_ns"] != 0 {
            return Err(Error::invalid(
                "network start gate requires an initially expired lease",
            ));
        }
        out["network_start_blocked"] = json!(true);
    }
    // The run's outbound bytes are admitted against grants its shim asks
    // for over the run channel, and not at all without one.
    if let Some(budget) = value.get("egress_budget") {
        if *budget != true {
            return Err(Error::invalid("invalid egress budget"));
        }
        out["egress_budget"] = json!(true);
    }
    if let Some(context) = value.get("run_context") {
        out["run_context"] = run_context(context)?;
    }
    if let Some(output) = value.get("output") {
        out["output"] = output_capture(output, &out["env"])?;
    }
    crate::guest_env::encode(&out)?;
    Ok(out)
}

pub struct Node {
    pub state: PathBuf,
    pub build: PathBuf,
    pub cgroup_root: PathBuf,
    pub compiler_cgroup: PathBuf,
    pub compiler_id: String,
    pub runtime_digest: String,
    pub launcher_digest: String,
    pub max_instances: usize,
    compiler_limits: CompilerLimits,
    max_upload: usize,
    artifact_cache_bytes: u64,
    compile_cache_bytes: u64,
    disk_free_bytes: u64,
    state_quota: Option<crate::project_quota::ProjectQuota>,
    pub confinement: Value,
    pub admission: Mutex<()>,
    compilation: Mutex<()>,
    cache_access: Mutex<()>,
    cache_check: Mutex<Option<Instant>>,
    children: Mutex<Vec<Child>>,
    /// The node's runs, by id: in memory only ([`shims`]).
    runs: Mutex<std::collections::HashMap<String, shims::Run>>,
    /// The first of the uids runs drop to, one per live run.
    run_uid_base: u32,
    /// Notified as a run the node started ends (its shim says so).
    endings: std::sync::Arc<tokio::sync::Notify>,
    /// Each live run's outbound totals, as its shim streams them.
    meters: std::sync::Arc<Mutex<std::collections::HashMap<String, Value>>>,
    /// Runs admitted and still being created, by idempotency key, with the
    /// compiled artifact each uses: counted against instance and disk
    /// capacity and pinned in the artifact cache until they are in `runs`.
    creating: Mutex<std::collections::HashMap<String, PathBuf>>,
    /// Warm shims kept per artifact and guest configuration (0: none).
    warm_runs: usize,
    /// Whether runs may ask for the outbound byte limit (`egress_budget`).
    egress_budget: bool,
    /// Shims started before their runs ([`shims::Warm`]).
    warm: Mutex<shims::WarmPool>,
    _lock: fs::File,
}
/// A run being created: counted and pinned in [`Node::creating`] until the
/// creation ends, however it ends.
struct Creating<'a> {
    node: &'a Node,
    key: &'a str,
}
impl Drop for Creating<'_> {
    fn drop(&mut self) {
        if let Ok(mut creating) = self.node.creating.lock() {
            creating.remove(self.key);
        }
    }
}
impl Node {
    /// Artifacts of runs still being created, which the cache must keep.
    pub(crate) fn creating_artifacts(&self) -> Result<Vec<PathBuf>> {
        Ok(lock(&self.creating)?.values().cloned().collect())
    }
}
/// Held while the node starts a child process, so a descriptor made
/// inheritable for one child (see [`Node::spawn`]) is inherited by no other.
static SPAWNING: Mutex<()> = Mutex::new(());

/// The host CPU the next run's VMM is confined to. A VMM pins all its threads
/// to the first host CPU it may use, so that one run's virtual CPUs share one
/// host CPU and its CPUID topology is that CPU's; started with the node's
/// whole set, every VMM picked the same first CPU, and every run on the node
/// shared one host CPU (CPU 0 on Runtara Cloud's dev node, which capped it
/// near 27 runs/s with the other eleven half idle). Runs are dealt the CPUs
/// the node may use in turn.
fn next_vm_cpu() -> Option<usize> {
    static CPUS: std::sync::OnceLock<Vec<usize>> = std::sync::OnceLock::new();
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let cpus = CPUS.get_or_init(|| {
        let mut allowed = unsafe { std::mem::zeroed::<libc::cpu_set_t>() };
        if unsafe {
            libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut allowed)
        } != 0
        {
            return Vec::new();
        }
        (0..libc::CPU_SETSIZE as usize)
            .filter(|&cpu| unsafe { libc::CPU_ISSET(cpu, &allowed) })
            .collect()
    });
    (!cpus.is_empty())
        .then(|| cpus[NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % cpus.len()])
}
fn probe(command: &mut Command) -> Result<std::process::Output> {
    let mut child = {
        let _spawning = lock(&SPAWNING)?;
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?
    };
    let stdout = child.stdout.take().ok_or_else(Error::internal)?;
    let reader = std::thread::spawn(move || {
        let mut data = Vec::new();
        stdout.take(65537).read_to_end(&mut data).map(|_| data)
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let _ = reader.join();
            return Err(Error::invalid("capability probe timed out"));
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let data = reader.join().map_err(|_| Error::internal())??;
    if data.len() > 65536 {
        return Err(Error::invalid("capability response too large"));
    }
    Ok(std::process::Output {
        status,
        stdout: data,
        stderr: Vec::new(),
    })
}
impl Node {
    /// A node over `root` with no runtime, for tests of its caches and
    /// admission.
    #[cfg(test)]
    pub(crate) fn for_tests(root: &Path) -> Self {
        Self {
            state: root.into(),
            build: root.into(),
            cgroup_root: root.into(),
            compiler_cgroup: root.into(),
            compiler_id: "a".repeat(64),
            runtime_digest: String::new(),
            launcher_digest: String::new(),
            max_instances: 1,
            compiler_limits: Default::default(),
            max_upload: MAX_UPLOAD,
            artifact_cache_bytes: artifact_cache::BUDGET,
            compile_cache_bytes: compile_cache::BUDGET,
            disk_free_bytes: disk_admission::DEFAULT_FREE_BYTES,
            state_quota: None,
            confinement: Value::Null,
            admission: Mutex::new(()),
            compilation: Mutex::new(()),
            cache_access: Mutex::new(()),
            cache_check: Mutex::new(None),
            children: Mutex::new(vec![]),
            runs: Mutex::default(),
            run_uid_base: 600_000,
            endings: Default::default(),
            meters: Default::default(),
            creating: Default::default(),
            warm_runs: 0,
            egress_budget: false,
            warm: Default::default(),
            _lock: flock(&root.join("node.lock")).unwrap(),
        }
    }
    pub fn new(state: &Path, build: &Path, cgroup: &Path, max_instances: usize) -> Result<Self> {
        if !cfg!(target_os = "linux") {
            return Err(Error::invalid("node requires Linux with KVM and cgroup v2"));
        }
        private_dir(state)?;
        let state = state.canonicalize()?;
        let lock = flock(&state.join("node.lock"))?;
        private_dir(&state.join("artifacts"))?;
        let build = build.canonicalize()?;
        for name in ["launch", "runtime.elf", "compile", "fenders-shim"] {
            if !build.join(name).is_file() {
                return Err(Error::invalid("missing runtime build artifact"));
            }
        }
        let launcher_digest = digest(fs::read(build.join("launch"))?);
        let output = probe(Command::new(build.join("launch")).arg("--capabilities"))?;
        let capability: Value = serde_json::from_slice(&output.stdout).unwrap_or(Value::Null);
        // A shim passes launch its files as descriptors.
        if !output.status.success() || capability["inherited_files"] != true {
            return Err(Error::invalid("launch lacks inherited file support"));
        }
        let output = probe(
            Command::new(std::env::current_exe()?)
                .arg("confinement-probe")
                .env_clear()
                .env("PATH", "/usr/bin:/bin"),
        )?;
        let confinement: Value = serde_json::from_slice(&output.stdout)
            .map_err(|_| Error::invalid("host confinement probe failed"))?;
        if !output.status.success()
            || confinement["version"] != HOST_CONFINEMENT
            || n(&confinement["landlock_abi"]) < 6
            || confinement["seccomp"] != true
        {
            return Err(Error::invalid("mandatory host confinement unavailable"));
        }
        fs::create_dir_all(cgroup)?;
        let cgroup_root = cgroup.canonicalize()?;
        fs::write(
            cgroup_root.join("cgroup.subtree_control"),
            "+cpu +memory +pids",
        )?;
        let compiler_cgroup = cgroup_root.join(format!(
            "compiler-{}",
            &digest(state.as_os_str().as_encoded_bytes())[..16]
        ));
        fs::create_dir_all(&compiler_cgroup)?;
        fs::write(compiler_cgroup.join("cgroup.kill"), "1")?;
        for (file, value) in [
            ("memory.swap.max", "0"),
            ("pids.max", "32"),
            ("memory.oom.group", "1"),
        ] {
            fs::write(compiler_cgroup.join(file), value)?;
        }
        CompilerLimits::default().apply(&compiler_cgroup)?;
        let compiler_id = digest(format!(
            "{}:{HOST_CONFINEMENT}:inspection-v1",
            digest(fs::read(build.join("compile"))?)
        ));
        // Seed the release digest cache so the first launch does not rehash it.
        crate::release::WorkerRelease::capture(&build, &std::env::current_exe()?)?;
        let runtime_digest = digest(fs::read(build.join("runtime.elf"))?);
        let node = Self {
            runtime_digest,
            launcher_digest,
            state,
            build,
            cgroup_root,
            compiler_cgroup,
            compiler_id,
            max_instances,
            compiler_limits: CompilerLimits::default(),
            max_upload: MAX_UPLOAD,
            artifact_cache_bytes: artifact_cache::BUDGET,
            compile_cache_bytes: compile_cache::BUDGET,
            disk_free_bytes: disk_admission::DEFAULT_FREE_BYTES,
            state_quota: None,
            confinement,
            admission: Mutex::new(()),
            compilation: Mutex::new(()),
            cache_access: Mutex::new(()),
            cache_check: Mutex::new(None),
            children: Mutex::new(Vec::new()),
            runs: Mutex::default(),
            run_uid_base: 600_000,
            endings: Default::default(),
            meters: Default::default(),
            creating: Default::default(),
            warm_runs: 0,
            egress_budget: false,
            warm: Default::default(),
            _lock: lock,
        };
        // The runs a previous agent started, from their shims.
        node.reattach()?;
        Ok(node)
    }
    /// Keeps `runs` warm shims for each artifact and guest configuration a
    /// run used here: each boots its VM and loads its component before its
    /// run is known, and serves one run.
    pub fn with_warm_runs(mut self, runs: usize) -> Result<Self> {
        if runs > shims::MAX_WARM_RUNS {
            return Err(Error::invalid("too many warm runs"));
        }
        self.warm_runs = runs;
        Ok(self)
    }
    /// Serves the outbound byte limit: a run whose spec says `egress_budget`
    /// sends only what its shim was granted over the run channel, and the
    /// agent says so to its control peer. Off, such a run is refused and the
    /// agent says nothing new.
    pub fn with_egress_budget(mut self, serve: bool) -> Self {
        self.egress_budget = serve;
        self
    }
    /// The launcher's digest when this node serves the outbound byte limit.
    pub fn egress_budget_launcher(&self) -> Option<&str> {
        self.egress_budget.then_some(self.launcher_digest.as_str())
    }
    pub fn artifact_dir(&self, digest: &str) -> Result<PathBuf> {
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::invalid("invalid artifact digest"));
        }
        Ok(self
            .state
            .join("artifacts")
            .join(&self.compiler_id)
            .join(digest))
    }
    /// Where a compile that used `scope`'s compile cache lives. Code a
    /// tenant's cache shaped stays that tenant's: only an uncached compile, in
    /// [`artifact_dir`](Self::artifact_dir), serves every tenant.
    fn scoped_artifact_dir(&self, digest: &str, scope: &str) -> Result<PathBuf> {
        let shared = self.artifact_dir(digest)?;
        Ok(shared.with_file_name(format!(
            "{digest}-{}",
            fenders_node_protocol::model::digest(scope)
        )))
    }
    /// The compiled artifact of `digest` a run in `scope` may use: an
    /// uncached compile, else one in its own scope.
    pub fn compiled_dir(&self, digest: &str, scope: Option<&str>) -> Result<Option<PathBuf>> {
        let shared = self.artifact_dir(digest)?;
        let scoped = scope
            .map(|scope| self.scoped_artifact_dir(digest, scope))
            .transpose()?;
        Ok([Some(shared), scoped]
            .into_iter()
            .flatten()
            .find(|dir| dir.join("artifact.json").is_file()))
    }
    pub fn upload(&self, data: &[u8]) -> Result<Value> {
        self.upload_scoped(data, None)
    }
    /// [`upload`](Self::upload), compiling with the compile cache of `scope`
    /// (the isolation unit the control plane names, its tenant) when given.
    pub fn upload_scoped(&self, data: &[u8], scope: Option<&str>) -> Result<Value> {
        if !(8..=self.max_upload).contains(&data.len()) || &data[..8] != b"\0asm\x0d\0\x01\0" {
            return Err(Error::invalid(
                "upload must be a WASM component within the node's upload cap",
            ));
        }
        let digest = digest(data);
        let _guard = lock(&self.compilation)?;
        let cache_access = lock(&self.cache_access)?;
        if let Some(target) = self.compiled_dir(&digest, scope)? {
            let cached = load(&target.join("artifact.json"))?;
            fenders_node_protocol::artifacts::validate_inspection(
                &cached["inspection"],
                &digest,
                data.len(),
            )?;
            artifact_cache::touch(&target)?;
            return Ok(cached);
        }
        let _admission = lock(&self.admission)?;
        // Reserve bounded inspection and manifest payloads as well as native code.
        let required = 128 * 1024 * 1024
            + data.len() as u64
            + 2 * fenders_node_protocol::artifacts::MAX_INSPECTION_BYTES as u64
            + 4096;
        let cache = artifact_cache::collect(self, required)?;
        if !cache.fits {
            return Err(Error::new(
                StatusCode::INSUFFICIENT_STORAGE,
                "node artifact storage budget exhausted",
            ));
        }
        self.check_disk_capacity(0)?;
        drop(_admission);
        drop(cache_access);
        let store = scope
            .filter(|_| self.compile_cache_bytes > 0)
            .and_then(|scope| {
                compile_cache::store(self, scope)
                    .map(|store| (scope, store))
                    .inspect_err(|e| tracing::warn!(error = %e.message, "compiling uncached"))
                    .ok()
            });
        let target = match store {
            Some((scope, _)) => self.scoped_artifact_dir(&digest, scope)?,
            None => self.artifact_dir(&digest)?,
        };
        let store = store.map(|(_, store)| store);
        private_dir(target.parent().unwrap())?;
        let stage = target.parent().unwrap().join(format!(".compile-{}", uid()));
        private_dir(&stage)?;
        let result = (|| {
            fs::write(stage.join("input.wasm"), data)?;
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(stage.join("component.cwasm"))?;
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(stage.join("inspection.json"))?;
            if store.is_some() {
                for (_, name) in compile_cache::RECORDS {
                    fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(stage.join(name))?;
                }
            }
            let mut worker = Command::new(std::env::current_exe()?);
            worker.env_clear();
            if let Some(store) = &store {
                worker.env("FENDERS_COMPILE_CACHE", store);
                for (var, name) in compile_cache::RECORDS {
                    worker.env(var, stage.join(name));
                }
            }
            let _spawning = lock(&SPAWNING)?;
            let mut child = worker
                .arg("compile-worker")
                .arg(&self.compiler_cgroup)
                .arg(self.build.join("compile"))
                .arg(stage.join("input.wasm"))
                .arg(stage.join("component.cwasm"))
                .arg(stage.join("inspection.json"))
                .env("PATH", "/usr/bin:/bin")
                .env(
                    "RAYON_NUM_THREADS",
                    self.compiler_limits.threads().to_string(),
                )
                .env(
                    "FENDERS_COMPILER_CPU_SECONDS",
                    self.compiler_limits.cpu_seconds.to_string(),
                )
                .env(
                    "FENDERS_COMPILER_ADDRESS_MIB",
                    self.compiler_limits.address_space_mib().to_string(),
                )
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?;
            drop(_spawning);
            let deadline = Instant::now() + Duration::from_secs(self.compiler_limits.wall_seconds);
            let status = loop {
                if let Some(status) = child.try_wait()? {
                    break Some(status);
                }
                if Instant::now() >= deadline {
                    break None;
                }
                std::thread::sleep(Duration::from_millis(20));
            };
            fs::write(self.compiler_cgroup.join("cgroup.kill"), "1")?;
            if status.is_none() {
                let _ = child.kill();
            }
            let _ = child.wait();
            let mut receipt = Vec::new();
            fs::File::open(stage.join("inspection.json"))?
                .take((fenders_node_protocol::artifacts::MAX_INSPECTION_BYTES + 1) as u64)
                .read_to_end(&mut receipt)?;
            if !status.is_some_and(|s| s.success()) {
                return Err(compiler_failure(
                    status.and_then(|s| s.code()),
                    &receipt,
                    &digest,
                    data.len(),
                ));
            }
            let compiled = fs::read(stage.join("component.cwasm"))?;
            let inspection: Value = serde_json::from_slice(&receipt).map_err(|_| {
                Error::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "compiler did not return a valid inspection",
                )
            })?;
            fenders_node_protocol::artifacts::validate_inspection(&inspection, &digest, data.len())
                .map_err(|_| {
                    Error::new(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "compiler returned incompatible inspection metadata",
                    )
                })?;
            if let Some(store) = &store {
                let mut merge = compile_cache::Merge::default();
                for (_, name) in compile_cache::RECORDS {
                    if let Err(e) =
                        compile_cache::store_records(store, &stage.join(name), &mut merge)
                    {
                        tracing::warn!(error = %e.message, "compile cache not updated");
                    }
                }
                if let Err(e) = compile_cache::prune(self) {
                    tracing::warn!(error = %e.message, "compile cache not pruned");
                }
            }
            for (_, name) in compile_cache::RECORDS {
                let _ = fs::remove_file(stage.join(name));
            }
            let info = json!({"artifact":digest,"compiler":self.compiler_id,"wasm_bytes":data.len(),"compiled_bytes":compiled.len(),"compiled_sha256":fenders_node_protocol::model::digest(&compiled),"inspection":inspection});
            for file in ["input.wasm", "component.cwasm", "inspection.json"] {
                fs::File::open(stage.join(file))?.sync_all()?;
            }
            atomic_json(&stage.join("artifact.json"), &info)?;
            fs::rename(&stage, &target)?;
            fs::File::open(target.parent().unwrap())?.sync_all()?;
            Ok(info)
        })();
        if stage.exists() {
            let _ = fs::remove_dir_all(stage);
        }
        result
    }
    pub fn create(&self, value: &Value, key: &str) -> Result<Value> {
        self.create_scoped(value, key, None)
    }
    /// [`create`](Self::create) for a run in `scope`, which may also use an
    /// artifact compiled with that scope's compile cache.
    pub fn create_scoped(&self, value: &Value, key: &str, scope: Option<&str>) -> Result<Value> {
        if key.is_empty() || key.len() > 128 {
            return Err(Error::invalid("Idempotency-Key is required"));
        }
        let (run, guest) = shims::split(value)?;
        let spec = validate_spec(&guest)?;
        if !matches!(s(&spec["mode"]), "command" | "http") {
            return Err(Error::invalid("a shim runs commands and HTTP apps only"));
        }
        if spec.get("network_deadline_ns").is_some() || spec.get("network_start_blocked").is_some()
        {
            return Err(Error::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "runtime lacks network lease and start-gate support",
            ));
        }
        if spec["egress_budget"] == true && !self.egress_budget {
            return Err(Error::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "this node does not serve the outbound byte limit",
            ));
        }
        let id = shims::run_id(key);
        let (artifact, _creating) = {
            let _cache = lock(&self.cache_access)?;
            let _guard = lock(&self.admission)?;
            // One key, one run: a run already started for it answers.
            if self.lookup_key(key)?.is_some() {
                drop(_guard);
                drop(_cache);
                return self.status(&id);
            }
            if lock(&self.creating)?.contains_key(key) {
                return Err(Error::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "a launch with this idempotency key is being created",
                ));
            }
            let artifact = self
                .compiled_dir(s(&spec["artifact"]), scope)?
                .ok_or_else(Error::missing)?;
            let metadata = load(&artifact.join("artifact.json"))?;
            if metadata["inspection"][s(&spec["mode"])] != true {
                return Err(Error::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "component does not support the requested entry point",
                ));
            }
            artifact_cache::touch(&artifact)?;
            let in_flight = lock(&self.creating)?.len();
            if self.live_count()? + in_flight >= self.max_instances {
                return Err(quota("node capacity exhausted"));
            }
            lock(&self.creating)?.insert(key.to_owned(), artifact.clone());
            (artifact, Creating { node: self, key })
        };
        self.start_shim(&id, key, run, &spec, &artifact)?;
        self.status(&id)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn state_and_secrets_are_this_users_own_and_never_a_link() {
        use super::*;
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        // Made, or found as this user's: private from then on.
        let state = root.path().join("state/inner");
        private_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o777)).unwrap();
        private_dir(&state).unwrap();
        assert_eq!(
            fs::metadata(&state).unwrap().permissions().mode() & 0o777,
            0o700
        );
        // A link, even to a directory of this user's, is not a state directory.
        let link = root.path().join("link");
        std::os::unix::fs::symlink(&state, &link).unwrap();
        assert!(private_dir(&link).is_err());
        assert!(private_dir(&root.path().join("state/file")).is_ok());
        fs::write(root.path().join("plain"), "x").unwrap();
        assert!(private_dir(&root.path().join("plain")).is_err());

        // A secret: this user's regular file that nobody else can read.
        let token = state.join("token");
        fenders_node_protocol::pki::private_file(&token, b"a-token-of-this-users-own").unwrap();
        assert_eq!(private_text(&token).unwrap(), "a-token-of-this-users-own");
        let linked = state.join("linked-token");
        std::os::unix::fs::symlink(&token, &linked).unwrap();
        assert!(private_text(&linked).is_err());
        fs::set_permissions(&token, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(private_text(&token).is_err());
        // The lock file is not followed through a link either.
        let lock = state.join("lock");
        std::os::unix::fs::symlink(root.path().join("elsewhere"), &lock).unwrap();
        assert!(flock(&lock).is_err());
        assert!(!root.path().join("elsewhere").exists());
    }

    #[test]
    fn compiler_failure_requires_explicit_exit_and_matching_bounded_receipt() {
        use super::*;

        let hash = "a".repeat(64);
        let receipt = json!({"format_version":1,"runtime":fenders_node_protocol::artifacts::RUNTIME,"digest":hash,"bytes":8,"error":"unsupported-imports"});
        let bytes = serde_json::to_vec(&receipt).unwrap();
        let rejected = compiler_failure(Some(2), &bytes, &hash, 8);
        assert_eq!(rejected.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(rejected.message, "unsupported-imports");
        for exit in [None, Some(1), Some(0), Some(137)] {
            assert_eq!(
                compiler_failure(exit, &bytes, &hash, 8).status,
                StatusCode::SERVICE_UNAVAILABLE
            );
        }
        for (key, value) in [
            ("digest", json!("b".repeat(64))),
            ("bytes", json!(9)),
            ("runtime", json!("other")),
            ("error", json!("<script>secret stderr</script>")),
            ("extra", json!("private")),
        ] {
            let mut invalid = receipt.clone();
            invalid[key] = value;
            assert_eq!(
                compiler_failure(Some(2), &serde_json::to_vec(&invalid).unwrap(), &hash, 8).status,
                StatusCode::SERVICE_UNAVAILABLE
            );
        }
        assert_eq!(
            compiler_failure(Some(2), &vec![b' '; 65537], &hash, 8).status,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            compiler_failure(Some(2), b"", &hash, 8).status,
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
    use super::*;

    #[test]
    fn guest_memory_sets_the_host_default_and_the_wasm_ceiling() {
        let base = json!({"artifact":"a".repeat(64)});
        let spec = validate_spec(&base).unwrap();
        assert!(spec.get("guest_memory_mib").is_none());
        assert_eq!(spec["host_memory_mib"], 64);
        let mut large = base.clone();
        large["guest_memory_mib"] = json!(512);
        large["wasm_memory_mib"] = json!(248);
        let spec = validate_spec(&large).unwrap();
        assert_eq!(spec["guest_memory_mib"], 512);
        assert_eq!(spec["host_memory_mib"], 544);
        assert_eq!(spec["wasm_memory_mib"], 248);
    }

    #[test]
    fn structural_limits_and_refuelling_reach_the_guest_only_when_set() {
        let base = json!({"artifact":"a".repeat(64)});
        let plain =
            String::from_utf8(crate::guest_env::encode(&validate_spec(&base).unwrap()).unwrap())
                .unwrap();
        for name in [
            "FENDERS_INSTANCES=",
            "FENDERS_TABLE_ELEMENTS=",
            "FENDERS_FUEL_REFUEL=",
            "FENDERS_WASM_STACK_BYTES=",
        ] {
            assert!(!plain.contains(name), "{name}");
        }
        let mut set = base.clone();
        set["instances"] = json!(40);
        set["table_elements"] = json!(20_000);
        set["tables"] = json!(200);
        set["memories"] = json!(100);
        set["fuel_refuel"] = json!("yield");
        set["wasm_stack_kib"] = json!(4096);
        let env =
            String::from_utf8(crate::guest_env::encode(&validate_spec(&set).unwrap()).unwrap())
                .unwrap();
        for entry in [
            "FENDERS_INSTANCES=40\0",
            "FENDERS_TABLE_ELEMENTS=20000\0",
            "FENDERS_TABLES=200\0",
            "FENDERS_MEMORIES=100\0",
            "FENDERS_FUEL_REFUEL=yield\0",
            "FENDERS_WASM_STACK_BYTES=4194304\0",
        ] {
            assert!(env.contains(entry), "{entry}");
        }
    }

    #[test]
    fn launch_rejects_unbounded_resources_and_reserved_environment() {
        let base = json!({"artifact":"a".repeat(64)});
        for patch in [
            json!({"cpu_percent":0}),
            json!({"cpu_percent":101}),
            json!({"host_memory_mib":1024}),
            json!({"wasm_memory_mib":32}),
            json!({"guest_memory_mib":30}),
            json!({"guest_memory_mib":1026}),
            json!({"guest_memory_mib":97}),
            json!({"guest_memory_mib":96,"host_memory_mib":111}),
            json!({"guest_memory_mib":96,"wasm_memory_mib":41}),
            json!({"instances":0}),
            json!({"instances":1001}),
            json!({"table_elements":0}),
            json!({"tables":0}),
            json!({"tables":1001}),
            json!({"memories":0}),
            json!({"memories":1001}),
            json!({"wasm_stack_kib":511}),
            json!({"wasm_stack_kib":65537}),
            json!({"fuel_refuel":"always"}),
            json!({"fuel_refuel":true}),
            json!({"env":{"FENDERS_TOKEN":"override"}}),
            json!({"env":{"FENDERS_TRIGGER":"manual"}}),
            json!({"run_context":{"trigger":"http","trigger_time":"2026-10-21T09:00:00Z","run_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}),
            json!({"run_context":{"trigger":"manual","trigger_time":"2026-10-21T09:00:00Z"}}),
            json!({"run_context":{"trigger":"manual","trigger_time":"yesterday","run_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}),
            json!({"run_context":{"trigger":"manual","trigger_time":"2026-10-21T09:00:00Z","run_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","schedule":"* * * * *"}}),
            json!({"run_context":{"trigger":"schedule","trigger_time":"2026-10-21T09:00:00Z","run_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}),
            json!({"run_context":{"trigger":"schedule","trigger_time":"2026-10-21T09:00:00Z","run_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","schedule":"* * * * *","schedule_timezone":"Mars/Base"}}),
            json!({"tcp_allow":["example.test:5432"]}),
            json!({"tcp_allow":["127.0.0.1:0"]}),
            json!({"http_allow":["https://user:pass@example.test/"]}),
            json!({"http_allow":["https://example.test/path"]}),
            json!({"surprise":true}),
            json!({"output":true}),
            json!({"output":{"redact_env":["MISSING"]}}),
            json!({"output":{"redact_env":[1]}}),
            json!({"output":{"redact_env":[],"stream":"stdout"}}),
        ] {
            let mut input = base.clone();
            for (k, v) in patch.as_object().unwrap() {
                input[k] = v.clone();
            }
            assert!(validate_spec(&input).is_err(), "accepted {patch}");
        }
        assert_eq!(
            validate_spec(
                &json!({"artifact":"a".repeat(64),"http_allow":["https://example.test"]})
            )
            .unwrap()["http_allow"],
            json!(["https://example.test:443"])
        );
        // Output capture is asked for, never assumed: the names are kept
        // sorted and once, and a spec that does not ask carries no field.
        let asked = validate_spec(&json!({"artifact":"a".repeat(64),
            "env":{"TOKEN":"t","DB":"d"},"output":{"redact_env":["TOKEN","DB","TOKEN"]}}))
        .unwrap();
        assert_eq!(asked["output"], json!({"redact_env":["DB","TOKEN"]}));
        assert_eq!(
            validate_spec(&json!({"artifact":"a".repeat(64),"output":{}})).unwrap()["output"],
            json!({"redact_env":[]})
        );
        assert!(
            validate_spec(&json!({"artifact":"a".repeat(64)}))
                .unwrap()
                .get("output")
                .is_none()
        );
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn leased_launch_requires_bounded_clock_and_same_boot() {
        let spec =
            json!({"artifact":"a".repeat(64),"network_deadline_ns":0,"network_start_blocked":true});
        assert_eq!(validate_spec(&spec).unwrap()["network_start_blocked"], true);
        for deadline in [
            json!(true),
            json!(-1),
            json!("123"),
            json!(clock_ns().unwrap() + 60000000000),
        ] {
            let mut bad = spec.clone();
            bad["network_deadline_ns"] = deadline;
            assert!(validate_spec(&bad).is_err());
        }
        assert!(validate_boot(&json!({"spec":spec,"network_boot_id":"other-boot"})).is_err());
        assert!(validate_boot(&json!({"spec":spec,"network_boot_id":boot_id().unwrap()})).is_ok());
        assert!(validate_boot(&json!({"spec":{}})).is_ok());
        let mut budget = spec.clone();
        budget["egress_budget"] = json!(true);
        assert_eq!(validate_spec(&budget).unwrap()["egress_budget"], true);
        for bad in [json!(false), json!(1), json!("true"), Value::Null] {
            budget["egress_budget"] = bad;
            assert!(validate_spec(&budget).is_err());
        }
        // A budget needs no start gate: its shim holds the guest itself
        // until the first grant.
        assert_eq!(
            validate_spec(&json!({"artifact":"a".repeat(64),"egress_budget":true})).unwrap()["egress_budget"],
            true
        );
    }
}
