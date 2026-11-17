//! Runs as shims (file-less runs plan, "On a fenders node"). Each run is a
//! `fenders-shim` started into `<cgroup_root>/<run id>`, outside the agent's
//! own cgroup, so stopping or restarting the agent cannot end it. The node
//! keeps its run table in memory and learns each run's state from its shim
//! over the shim's abstract socket `@fenders/run/<id>`; nothing about a run
//! is written to disk. On start the node lists `<cgroup_root>/*` and asks
//! each run's shim for its status to rebuild the table; a run whose shim does
//! not answer is killed and removed.
use super::*;
use std::collections::HashMap;
use std::io::{Read as _, Write as _};
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, UnixStream};
use std::sync::Arc;

/// How long the node waits for a shim's answer.
const ASK_TIMEOUT: Duration = Duration::from_secs(2);
/// How long an ended, collected run stays in the table for its status.
const KEEP_ENDED: Duration = Duration::from_secs(900);
/// How long a started shim may take to answer for the first time (it reads
/// its spec, binds its socket) before its run counts as lost.
const FIRST_ANSWER: Duration = Duration::from_secs(30);
/// The run protocol's fields of a launch spec, which go to the shim as they
/// are; the rest is the guest's configuration.
const RUN_FIELDS: [&str; 3] = ["protocol", "run", "channel"];

/// Most warm shims kept for one artifact and guest configuration.
pub(crate) const MAX_WARM_RUNS: usize = 8;
/// Most warm shims kept in all.
const MAX_WARM_TOTAL: usize = 32;
/// How long a warm shim waits for a run before it is discarded.
const WARM_IDLE: Duration = Duration::from_secs(600);
/// Warm shims' cgroups are named `warm-<n>` until they are claimed.
const WARM_PREFIX: &str = "warm-";

/// A shim started before its run (`fenders-shim warm`): its VM boots and
/// loads its component, then waits. It is claimed for one run of the same
/// artifact and guest configuration, which it then serves like a shim
/// started for it; nothing of a run is ever in a warm shim before its claim.
pub(crate) struct Warm {
    /// Its cgroup's name until claimed.
    name: String,
    uid: u32,
    artifact: PathBuf,
    /// Takes its claim; closing it discards the shim.
    stdin: std::process::ChildStdin,
    /// The run it serves, once claimed, for its output stream.
    serving: Arc<Mutex<Option<String>>>,
    /// Its pipe's end signal ([`Run::signalled`]).
    signalled: Arc<std::sync::atomic::AtomicBool>,
    since: Instant,
}

/// The warm shims, by artifact and guest configuration ([`warm_key`]).
#[derive(Default)]
pub(crate) struct WarmPool {
    shims: HashMap<String, Vec<Warm>>,
    /// The uids and cgroups of warm shims still starting.
    reserved: Vec<(u32, String)>,
    next: u64,
}

impl WarmPool {
    fn len(&self) -> usize {
        self.shims.values().map(Vec::len).sum::<usize>() + self.reserved.len()
    }
    fn holds_uid(&self, uid: u32) -> bool {
        self.reserved.iter().any(|(reserved, _)| *reserved == uid)
            || self.shims.values().flatten().any(|warm| warm.uid == uid)
    }
}

/// What a warm shim must match to serve a run: the artifact and the whole
/// guest configuration.
fn warm_key(artifact: &Path, guest: &Value) -> String {
    format!("{}\n{guest}", artifact.display())
}

fn new_run(
    key: &str,
    artifact: &Path,
    uid: u32,
    guest: &Value,
    signalled: Arc<std::sync::atomic::AtomicBool>,
    warm: bool,
) -> Run {
    Run {
        key: key.to_owned(),
        artifact: artifact.to_owned(),
        uid,
        shape: (n(&guest["cpu_percent"]), n(&guest["host_memory_mib"])),
        ended: None,
        unanswered_since: Some(Instant::now()),
        asking: Arc::default(),
        cgroup: None,
        signalled: Some(signalled),
        last_running: None,
        start: Some((now(), warm)),
    }
}

/// What a shim's standard output reports to: the run it serves (set when a
/// warm shim is claimed) and whether its run ended or its pipe closed.
struct ShimPipe {
    serving: Arc<Mutex<Option<String>>>,
    signalled: Arc<std::sync::atomic::AtomicBool>,
}

/// A run the node started or reattached.
pub(crate) struct Run {
    pub(crate) key: String,
    /// The compiled artifact it runs, pinned in the cache while it lives.
    pub(crate) artifact: PathBuf,
    pub(crate) uid: u32,
    /// Its CPU percent and host memory MiB.
    pub(crate) shape: (i64, i64),
    /// Its status once collected from its ended shim, and when.
    ended: Option<(Value, Instant)>,
    /// When it was started here, until its shim first answered.
    unanswered_since: Option<Instant>,
    /// Held while its shim is asked: one read collects an ended run, and no
    /// other then finds its shim gone and takes the run for lost.
    asking: Arc<Mutex<()>>,
    /// Its cgroup's name when not its id: a warm shim's, which it keeps
    /// (cgroup v2 cannot rename one).
    cgroup: Option<String>,
    /// Set when its shim says on its pipe that the run ended, or the pipe
    /// closes; none for a run reattached from a previous agent (no pipe).
    signalled: Option<Arc<std::sync::atomic::AtomicBool>>,
    /// Its shim's last `running` answer, given again until `signalled`.
    last_running: Option<Value>,
    /// When the node started it (Unix seconds) and whether a warm shim
    /// serves it, until its shim is seen running it
    /// (`fenders_node_run_start_seconds`); none for a reattached run.
    start: Option<(f64, bool)>,
}

/// The extended attribute naming the run a claimed warm shim's cgroup holds.
const RUN_ATTRIBUTE: &std::ffi::CStr = c"trusted.fenders.run";

fn set_run_attribute(cgroup: &Path, id: &str) -> std::io::Result<()> {
    let path = std::ffi::CString::new(cgroup.as_os_str().as_encoded_bytes())
        .map_err(|_| std::io::ErrorKind::InvalidInput)?;
    let rc = unsafe {
        libc::setxattr(
            path.as_ptr(),
            RUN_ATTRIBUTE.as_ptr(),
            id.as_ptr().cast(),
            id.len(),
            0,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn run_attribute(cgroup: &Path) -> Option<String> {
    let path = std::ffi::CString::new(cgroup.as_os_str().as_encoded_bytes()).ok()?;
    let mut value = [0u8; 64];
    let n = unsafe {
        libc::getxattr(
            path.as_ptr(),
            RUN_ATTRIBUTE.as_ptr(),
            value.as_mut_ptr().cast(),
            value.len(),
        )
    };
    let id = std::str::from_utf8(value.get(..usize::try_from(n).ok()?)?).ok()?;
    is_run_id(id).then(|| id.to_owned())
}

/// The run id for an idempotency key: one key, one run, one shim.
pub(crate) fn run_id(key: &str) -> String {
    digest(key)[..32].to_owned()
}

fn is_run_id(name: &str) -> bool {
    name.len() == 32 && name.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The CPU time a run's shim may use in each 100 ms beyond its VM's share.
const SHIM_CPU_USEC: u64 = 50_000;
/// The limits on a run's cgroup, which holds its shim and its VM.
fn run_limits(host_memory_mib: i64, cpu_percent: i64) -> [(&'static str, String); 5] {
    // The run as a whole: the VM's memory and the shim's own.
    let host = host_memory_mib.max(32) as u64 + 64;
    // Its CPU likewise: the VM's share, which the shim sets on the VM's
    // leaf, and half a CPU for the shim's own work (the run's output, its
    // requests, its calls). Without it the shim's threads ran unthrottled,
    // on a uid the guest's work drives.
    let cpu = (cpu_percent.max(1) as u64) * 1000 + SHIM_CPU_USEC;
    [
        ("memory.max", (host * 1024 * 1024).to_string()),
        ("memory.swap.max", "0".into()),
        // Out of memory as a whole, the run ends as a whole: a shim killed
        // alone would leave its VM running unwatched.
        ("memory.oom.group", "1".into()),
        ("cpu.max", format!("{cpu} 100000")),
        ("pids.max", "64".into()),
    ]
}

/// The SHA-256 of the compiled component in artifact directory `artifact`,
/// as its `artifact.json` recorded it.
fn compiled_digest(artifact: &Path) -> Option<String> {
    let recorded: Value =
        serde_json::from_slice(&fs::read(artifact.join("artifact.json")).ok()?).ok()?;
    let digest = recorded["compiled_sha256"].as_str()?;
    (digest.len() == 64
        && digest
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
    .then(|| digest.to_owned())
}

/// The longest line a shim's standard output is read for: `ended`, or
/// `meter` and a few counters.
const MAX_SHIM_LINE: usize = 1024;

/// The next line of `input`, without its newline: `Some(None)` for one over
/// `max` bytes or not UTF-8, which is read past and not kept, and `None` at
/// the end of input.
fn bounded_line(
    input: &mut impl std::io::BufRead,
    max: usize,
) -> std::io::Result<Option<Option<String>>> {
    let mut line = Vec::new();
    let mut over = false;
    loop {
        let buffered = match input.fill_buf() {
            Ok(buffered) => buffered,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        if buffered.is_empty() {
            // The end: a last line without a newline counts if it fits.
            return Ok((!line.is_empty() || over)
                .then(|| (!over).then(|| String::from_utf8(line).ok()).flatten()));
        }
        let newline = buffered.iter().position(|byte| *byte == b'\n');
        let taken = newline.unwrap_or(buffered.len());
        if !over && line.len() + taken <= max {
            line.extend_from_slice(&buffered[..taken]);
        } else {
            over = true;
            line = Vec::new();
        }
        input.consume(taken + usize::from(newline.is_some()));
        if newline.is_some() {
            return Ok(Some(
                (!over).then(|| String::from_utf8(line).ok()).flatten(),
            ));
        }
    }
}

/// The abstract address of run `id`'s link.
fn link_address(id: &str) -> std::io::Result<SocketAddr> {
    SocketAddr::from_abstract_name(format!("fenders/run/{id}").as_bytes())
}

/// Whether the process listening at the other end of `stream` is in run
/// cgroup `cgroup` (or its `shim` or `vm` leaf): the run's own shim.
///
/// An abstract socket name has no owner: any process in the node's network
/// namespace may bind one. Only the node puts a process in a run's cgroup,
/// so membership is what makes an answer the run's.
fn peer_in_cgroup(stream: &UnixStream, cgroup: &Path) -> bool {
    use std::os::fd::AsRawFd;
    let mut peer = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut size = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut peer).cast(),
            &raw mut size,
        )
    };
    if rc != 0 || peer.pid <= 0 {
        return false;
    }
    let pid = peer.pid.to_string();
    [cgroup.to_path_buf(), cgroup.join("shim"), cgroup.join("vm")]
        .iter()
        .filter_map(|group| fs::read_to_string(group.join("cgroup.procs")).ok())
        .any(|procs| procs.lines().any(|line| line == pid))
}

/// Asks run `id`'s shim, a process of run cgroup `cgroup`, `request`
/// (`status`, `stop` or `collect`). `None` when no shim holds the run: also
/// when something that is not its shim answers at its name.
pub(crate) fn ask(cgroup: &Path, id: &str, request: &str) -> Result<Option<Value>> {
    let address = link_address(id)?;
    let mut stream = match UnixStream::connect_addr(&address) {
        Ok(stream) => stream,
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
            ) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error.into()),
    };
    if !peer_in_cgroup(&stream, cgroup) {
        tracing::error!(
            run = id,
            "its name is held by a process outside its cgroup: not its shim"
        );
        return Ok(None);
    }
    stream.set_read_timeout(Some(ASK_TIMEOUT))?;
    stream.set_write_timeout(Some(ASK_TIMEOUT))?;
    let mut answer = Vec::new();
    let asked = stream
        .write_all(format!("{request}\n").as_bytes())
        .and_then(|()| stream.take(1 << 20).read_to_end(&mut answer));
    match asked {
        Ok(_) => {}
        // The shim exited as it was asked: not there.
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::UnexpectedEof
            ) =>
        {
            return Ok(None);
        }
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) =>
        {
            tracing::warn!(run = id, request, "its shim did not answer in time");
            return Err(Error::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "a run's shim did not answer in time",
            ));
        }
        Err(error) => {
            tracing::warn!(run = id, request, %error, "asking its shim failed");
            return Err(error.into());
        }
    }
    // A shim that exits as it is asked answers nothing: not there.
    if answer.is_empty() {
        return Ok(None);
    }
    serde_json::from_slice(&answer)
        .map(Some)
        .map_err(|_| Error::invalid("a shim answered with an invalid status"))
}

/// Splits a launch spec into its run protocol fields and the guest's
/// configuration. A run without its run channel cannot reach anything.
pub(crate) fn split(value: &Value) -> Result<(serde_json::Map<String, Value>, Value)> {
    let mut guest = value
        .as_object()
        .ok_or_else(|| Error::invalid("expected object"))?
        .clone();
    let mut run = serde_json::Map::new();
    for field in RUN_FIELDS {
        let value = guest.remove(field).ok_or_else(|| {
            Error::invalid("a run needs its run channel (protocol, run, channel)")
        })?;
        run.insert(field.to_owned(), value);
    }
    // Every run is ephemeral now: nothing about it is on disk.
    guest.remove("durability");
    Ok((run, Value::Object(guest)))
}

/// A shim's status as the agent reads a run's: its state, its exit, the
/// cgroup's CPU and memory, and its outbound totals.
fn as_status(id: &str, shim: &Value, cgroup: &Path, boot: &str, streamed: Option<Value>) -> Value {
    let state = shim["state"]
        .as_str()
        .filter(|state| {
            matches!(
                *state,
                "starting" | "running" | "exited" | "failed" | "stopped"
            )
        })
        .unwrap_or("failed");
    let mut status = json!({"id": id, "state": state, "created": shim["created"],
        "started": shim["started"], "finished": shim["finished"],
        "exit_code": shim["exit_code"], "outcome": shim["outcome"]});
    let reason = match shim["code"].as_str() {
        Some("LIFETIME_EXCEEDED") => Some("lifetime-limit"),
        Some("STOPPED") => Some("requested-stop"),
        // Ended by its shim under the outbound byte limit.
        Some("EGRESS_LIMIT") => Some("outbound-allowance-denied"),
        Some("EGRESS_EXPIRED") => Some("outbound-grant-expired"),
        Some("EGRESS_UNMEASURED") => Some("outbound-accounting-unavailable"),
        _ if state == "failed" => Some("execution-failed"),
        _ => None,
    };
    if let Some(reason) = reason {
        status["reason"] = json!(reason);
    }
    let vm = cgroup.join("vm");
    if let Ok(stat) = fs::read_to_string(vm.join("cpu.stat")) {
        status["cpu_stat"] = json!(stat);
    }
    if let Some(memory) = fs::read_to_string(vm.join("memory.current"))
        .ok()
        .and_then(|m| m.trim().parse::<u64>().ok())
    {
        status["memory_current"] = json!(memory);
    }
    // The totals the shim streamed, else those it answered with.
    let egress = &streamed.unwrap_or_else(|| shim["egress"].clone());
    if egress.is_object() {
        status["egress"] = json!({"contract":"socket-payload-v1","bytes":egress["bytes"],
            "in_flight":egress["in_flight"],"complete":egress["complete"] == true,
            "observed":now()});
        status["egress_boot_id"] = json!(boot);
    }
    // A run under the outbound byte limit names the launcher that admits
    // its bytes, under this boot.
    if let Some(launcher) = shim["egress_launcher"]
        .as_str()
        .filter(|digest| fenders_node_protocol::egress_budget::valid_digest(digest))
    {
        status["egress_authority"] = json!({"contract":fenders_node_protocol::egress_budget::CONTRACT,"boot_id":boot,"launcher_digest":launcher});
    }
    status
}

/// Kills and removes run cgroup `cgroup`: its shim and VMM with it.
fn remove_cgroup(cgroup: &Path) {
    let _ = fs::write(cgroup.join("cgroup.kill"), "1");
    for leaf in ["vm", "shim"] {
        let _ = fs::remove_dir(cgroup.join(leaf));
    }
    let _ = fs::remove_dir(cgroup);
}

impl Node {
    fn run_cgroup(&self, id: &str) -> PathBuf {
        self.cgroup_root.join(id)
    }

    /// Rebuilds the run table from the runs' cgroups: each whose shim
    /// answers is the node's again; the others are killed and removed.
    pub(super) fn reattach(&self) -> Result<()> {
        let mut table = lock(&self.runs)?;
        for entry in fs::read_dir(&self.cgroup_root)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            // A warm cgroup holds the run recorded on it, if it was claimed;
            // an unclaimed one's shim went with the previous agent's pipe.
            let (id, cgroup) = if name.starts_with(WARM_PREFIX) && entry.path().is_dir() {
                match run_attribute(&entry.path()) {
                    Some(id) => (id, Some(name.clone())),
                    None => {
                        remove_cgroup(&entry.path());
                        continue;
                    }
                }
            } else if is_run_id(&name) && entry.path().is_dir() {
                (name.clone(), None)
            } else {
                continue;
            };
            let name = id;
            match ask(&entry.path(), &name, "status") {
                Ok(Some(status)) => {
                    let artifact = Path::new(s(&status["component"]))
                        .parent()
                        .map(Path::to_path_buf)
                        .unwrap_or_default();
                    table.insert(
                        name.clone(),
                        Run {
                            key: s(&status["key"]).to_owned(),
                            artifact,
                            uid: status["uid"].as_u64().unwrap_or(0) as u32,
                            shape: (n(&status["cpu_percent"]), n(&status["host_memory_mib"])),
                            ended: None,
                            unanswered_since: None,
                            asking: Arc::default(),
                            cgroup,
                            signalled: None,
                            last_running: None,
                            start: None,
                        },
                    );
                    tracing::info!(run = %name, "reattached run");
                }
                _ => {
                    tracing::warn!(run = %name, "run has no shim: killed and removed");
                    remove_cgroup(&entry.path());
                }
            }
        }
        Ok(())
    }

    /// A uid for a new run or warm shim, no live run's or warm shim's.
    fn free_uid(&self, table: &HashMap<String, Run>) -> Result<u32> {
        let warm = lock(&self.warm)?;
        let slots = self.max_instances
            + if self.warm_runs > 0 {
                MAX_WARM_TOTAL
            } else {
                0
            };
        (0..slots as u32 + 1)
            .map(|slot| self.run_uid_base + slot)
            .find(|uid| {
                !warm.holds_uid(*uid)
                    && !table
                        .values()
                        .any(|run| run.ended.is_none() && run.uid == *uid)
            })
            .ok_or_else(|| quota("node capacity exhausted"))
    }

    /// Serves run `id` with a warm shim from `pool`: renames its cgroup for
    /// the run and hands it the run (`run`, `channel`, `launcher`). False
    /// when there is none to take.
    fn claim_warm(
        &self,
        pool: &str,
        id: &str,
        key: &str,
        run: &serde_json::Map<String, Value>,
        guest: &Value,
    ) -> Result<bool> {
        // A warm shim speaks the shim's protocol; anything else starts cold.
        if run.get("protocol") != Some(&json!(1)) {
            return Ok(false);
        }
        let Some(mut warm) = lock(&self.warm)?.shims.get_mut(pool).and_then(Vec::pop) else {
            return Ok(false);
        };
        let mut entry = new_run(
            key,
            &warm.artifact,
            warm.uid,
            guest,
            warm.signalled.clone(),
            true,
        );
        entry.cgroup = Some(warm.name.clone());
        lock(&self.runs)?.insert(id.to_owned(), entry);
        let claimed = (|| -> Result<()> {
            // Its cgroup keeps its name; the run it holds is recorded on it,
            // so a restarted agent finds the run there.
            if let Err(error) = set_run_attribute(&self.run_cgroup(&warm.name), id) {
                tracing::warn!(run = id, %error, "recording the run on its warm cgroup failed");
            }
            *warm.serving.lock().unwrap_or_else(|e| e.into_inner()) = Some(id.to_owned());
            let claim = json!({
                "run": run.get("run"),
                "channel": run.get("channel"),
                "launcher": {"id": id, "key": key, "uid": unsafe { libc::geteuid() }},
            });
            let mut line = serde_json::to_vec(&claim).map_err(|_| Error::internal())?;
            line.push(b'\n');
            warm.stdin.write_all(&line)?;
            line.fill(0);
            Ok(())
        })();
        if let Err(error) = claimed {
            lock(&self.runs)?.remove(id);
            remove_cgroup(&self.run_cgroup(&warm.name));
            return Err(error);
        }
        // Its standard input closes as it is dropped: the claim is all.
        drop(warm);
        crate::metrics::run_started(true);
        Ok(true)
    }

    /// Starts warm shims for `pool` until it holds `warm_runs` (within the
    /// node's total). A shim that fails to start is not retried here.
    fn fill_warm(&self, pool: &str, guest: &Value, artifact: &Path) {
        loop {
            let (name, uid) = {
                let Ok(table) = lock(&self.runs) else { return };
                let Ok(uid) = self.free_uid(&table) else {
                    return;
                };
                let Ok(mut warm) = lock(&self.warm) else {
                    return;
                };
                let held = warm.shims.get(pool).map_or(0, Vec::len);
                if held >= self.warm_runs || warm.len() >= MAX_WARM_TOTAL {
                    return;
                }
                warm.next += 1;
                // Named for this agent: a previous one's may still be leaving.
                let name = format!("{WARM_PREFIX}{}-{}", std::process::id(), warm.next);
                warm.reserved.push((uid, name.clone()));
                (name, uid)
            };
            let mut spec = serde_json::Map::new();
            spec.insert("protocol".into(), json!(1));
            spec.insert("warm".into(), json!(true));
            self.machine(&mut spec, uid, guest, artifact);
            let started = serde_json::to_vec(&Value::Object(spec))
                .map_err(|_| Error::internal())
                .and_then(|mut line| {
                    line.push(b'\n');
                    let serving = Arc::new(Mutex::new(None));
                    let signalled = Arc::new(std::sync::atomic::AtomicBool::new(false));
                    self.spawn_shim(
                        &name,
                        guest,
                        &["warm"],
                        &line,
                        ShimPipe {
                            serving: serving.clone(),
                            signalled: signalled.clone(),
                        },
                        true,
                    )
                    .map(|stdin| (stdin, serving, signalled))
                });
            let Ok(mut warm) = lock(&self.warm) else {
                return;
            };
            warm.reserved.retain(|(reserved, _)| *reserved != uid);
            match started {
                Ok((Some(stdin), serving, signalled)) => {
                    warm.shims.entry(pool.to_owned()).or_default().push(Warm {
                        name,
                        uid,
                        artifact: artifact.to_owned(),
                        stdin,
                        serving,
                        signalled,
                        since: Instant::now(),
                    })
                }
                Ok((None, _, _)) => return,
                Err(error) => {
                    tracing::warn!(shim = %name, error = %error.message, "warm shim did not start");
                    return;
                }
            }
        }
    }

    /// Discards warm shims that waited too long for a run, and removes the
    /// cgroups of discarded ones that have exited.
    fn tidy_warm(&self) -> Result<()> {
        let held: Vec<String> = {
            let mut warm = lock(&self.warm)?;
            let root = self.cgroup_root.clone();
            for shims in warm.shims.values_mut() {
                // Dropping one closes its standard input: it ends itself.
                // One whose cgroup emptied (its shim died) goes too.
                shims.retain(|shim| {
                    shim.since.elapsed() < WARM_IDLE
                        && fs::read_to_string(root.join(&shim.name).join("cgroup.events"))
                            .is_ok_and(|events| events.contains("populated 1"))
                });
            }
            warm.shims.retain(|_, shims| !shims.is_empty());
            // Those still starting are empty until their shim joins.
            warm.shims
                .values()
                .flatten()
                .map(|shim| shim.name.clone())
                .chain(warm.reserved.iter().map(|(_, name)| name.clone()))
                .collect()
        };
        for entry in fs::read_dir(&self.cgroup_root)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with(WARM_PREFIX)
                && !held.contains(&name)
                && fs::read_to_string(entry.path().join("cgroup.events"))
                    .is_ok_and(|events| events.contains("populated 0"))
            {
                remove_cgroup(&entry.path());
            }
        }
        Ok(())
    }

    /// The artifacts warm shims hold, which the cache must keep.
    fn warm_artifacts(&self) -> Vec<PathBuf> {
        lock(&self.warm)
            .map(|warm| {
                warm.shims
                    .values()
                    .flatten()
                    .map(|shim| shim.artifact.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn shape(&self, id: &str) -> Option<(i64, i64)> {
        lock(&self.runs)
            .ok()?
            .get(id)
            .filter(|run| run.ended.is_none())
            .map(|run| run.shape)
    }

    /// Puts a run of `artifact` in the table, ended or not, for tests.
    #[cfg(test)]
    pub(crate) fn insert_test_run(&self, artifact: &Path, ended: bool) {
        let id = run_id(&uid());
        lock(&self.runs).unwrap().insert(
            id.clone(),
            Run {
                key: id,
                artifact: artifact.to_owned(),
                uid: 0,
                shape: (0, 0),
                ended: ended.then(|| (json!({"state":"exited"}), Instant::now())),
                unanswered_since: None,
                asking: Arc::default(),
                cgroup: None,
                signalled: None,
                last_running: None,
                start: None,
            },
        );
    }

    /// Notified as a run this node started ends.
    pub fn endings(&self) -> std::sync::Arc<tokio::sync::Notify> {
        self.endings.clone()
    }

    /// The latest outbound totals run `id`'s shim streamed, if any.
    fn streamed(&self, id: &str) -> Option<Value> {
        self.meters.lock().ok()?.get(id).cloned()
    }

    pub(crate) fn live_count(&self) -> Result<usize> {
        Ok(lock(&self.runs)?
            .values()
            .filter(|run| run.ended.is_none())
            .count())
    }

    /// The artifacts of the runs not yet ended, which the cache must keep.
    pub(crate) fn run_artifacts(&self) -> Result<Vec<PathBuf>> {
        let mut artifacts: Vec<PathBuf> = lock(&self.runs)?
            .values()
            .filter(|run| run.ended.is_none())
            .map(|run| run.artifact.clone())
            .collect();
        artifacts.extend(self.warm_artifacts());
        Ok(artifacts)
    }

    pub fn lookup_key(&self, key: &str) -> Result<Option<String>> {
        let id = run_id(key);
        Ok(lock(&self.runs)?
            .get(&id)
            .filter(|run| run.key == key)
            .map(|_| id))
    }

    /// Starts run `id` for `key`: its shim, in its own cgroup, with its spec
    /// (credential included) on the shim's standard input only. A warm shim
    /// of the same artifact and guest configuration serves it when there is
    /// one ([`Warm`]); the pool is refilled after.
    pub(super) fn start_shim(
        &self,
        id: &str,
        key: &str,
        run: serde_json::Map<String, Value>,
        guest: &Value,
        artifact: &Path,
    ) -> Result<()> {
        if self.warm_runs == 0 {
            return self.start_cold(id, key, run, guest, artifact);
        }
        let pool = warm_key(artifact, guest);
        let started = match self.claim_warm(&pool, id, key, &run, guest) {
            Ok(true) => Ok(()),
            Ok(false) => self.start_cold(id, key, run, guest, artifact),
            Err(error) => {
                tracing::warn!(
                    run = id,
                    error = %error.message,
                    "claiming a warm shim failed; starting one"
                );
                self.start_cold(id, key, run, guest, artifact)
            }
        };
        self.fill_warm(&pool, guest, artifact);
        started
    }

    fn start_cold(
        &self,
        id: &str,
        key: &str,
        run: serde_json::Map<String, Value>,
        guest: &Value,
        artifact: &Path,
    ) -> Result<()> {
        let signalled = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let uid = {
            let mut table = lock(&self.runs)?;
            let uid = self.free_uid(&table)?;
            table.insert(
                id.to_owned(),
                new_run(key, artifact, uid, guest, signalled.clone(), false),
            );
            uid
        };
        let mut spec = run;
        spec.insert(
            "launcher".into(),
            json!({"id": id, "key": key, "uid": unsafe { libc::geteuid() }}),
        );
        self.machine(&mut spec, uid, guest, artifact);
        let spec = serde_json::to_vec(&Value::Object(spec)).map_err(|_| Error::internal())?;
        let serving = Arc::new(Mutex::new(Some(id.to_owned())));
        if let Err(error) = self.spawn_shim(
            id,
            guest,
            &[],
            &spec,
            ShimPipe { serving, signalled },
            false,
        ) {
            lock(&self.runs)?.remove(id);
            return Err(error);
        }
        crate::metrics::run_started(false);
        Ok(())
    }

    /// The machine part of a shim's spec: what it runs and as whom.
    fn machine(
        &self,
        spec: &mut serde_json::Map<String, Value>,
        uid: u32,
        guest: &Value,
        artifact: &Path,
    ) {
        // The digest recorded when the component was compiled: the shim
        // checks what it opens against it, so that what the guest loads as
        // native code is what the compiler wrote, not only what the cache's
        // file permissions kept.
        let mut component = json!({"component": artifact.join("component.cwasm")});
        if let Some(digest) = compiled_digest(artifact) {
            component["component_sha256"] = json!(digest);
        }
        spec.insert("artifact".into(), component);
        spec.insert("runtime".into(), json!({"dir": self.build}));
        spec.insert("uid".into(), json!(uid));
        spec.insert("gid".into(), json!(uid));
        if let Some(cpu) = next_vm_cpu() {
            spec.insert("cpu".into(), json!(cpu));
        }
        spec.insert("guest".into(), guest.clone());
    }

    /// Starts a shim in cgroup `name` with `args`, writing `input` to its
    /// standard input: closed after it, or kept open and returned with
    /// `keep_stdin` (a warm shim's, for its claim). The shim's standard
    /// output streams its meters and its end for the run `serving` names.
    fn spawn_shim(
        &self,
        name: &str,
        guest: &Value,
        args: &[&str],
        input: &[u8],
        pipe: ShimPipe,
        keep_stdin: bool,
    ) -> Result<Option<std::process::ChildStdin>> {
        let ShimPipe { serving, signalled } = pipe;
        let cgroup = self.run_cgroup(name);
        // The node's errors carry no OS detail: say what failed here.
        let io = |what: &'static str| {
            move |error: std::io::Error| {
                tracing::warn!(shim = name, %error, "{what} failed");
                Error::from(error)
            }
        };
        // A run's link is bound here, before its cgroup shows its id to the
        // host, and handed to the shim: no other process can take the name
        // first. A warm shim has no run yet; it binds when it is claimed, and
        // a claimed run's id is on its cgroup only as a `trusted.` attribute.
        let link = if is_run_id(name) {
            Some(
                std::os::unix::net::UnixListener::bind_addr(&link_address(name)?)
                    .map_err(io("binding its link"))?,
            )
        } else {
            None
        };
        let started = (|| -> Result<Option<std::process::ChildStdin>> {
            fs::create_dir(&cgroup).map_err(io("creating its cgroup"))?;
            for (file, value) in run_limits(n(&guest["host_memory_mib"]), n(&guest["cpu_percent"]))
            {
                fs::write(cgroup.join(file), value).map_err(io("limiting its cgroup"))?;
            }
            let procs =
                std::ffi::CString::new(cgroup.join("cgroup.procs").as_os_str().as_encoded_bytes())
                    .map_err(|_| Error::internal())?;
            let mut command = Command::new(self.build.join("fenders-shim"));
            command
                .args(args)
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                // It logs as the node does.
                .envs(crate::log::child_env())
                .stdin(Stdio::piped())
                // The shim says `ended` here when its run ends.
                .stdout(Stdio::piped())
                // The shim logs to the agent's standard error (its journal).
                .stderr(Stdio::inherit());
            let link_fd = link.as_ref().map(|link| {
                use std::os::fd::AsRawFd;
                link.as_raw_fd()
            });
            if let Some(fd) = link_fd {
                command.env("FENDERS_SHIM_LINK_FD", fd.to_string());
            }
            unsafe {
                use std::os::unix::process::CommandExt;
                // In the child, before exec: its own session and the run's
                // cgroup, so it outlives the agent. Only async-signal-safe calls.
                command.pre_exec(move || {
                    libc::setsid();
                    // The link keeps its descriptor number across the exec.
                    if let Some(fd) = link_fd
                        && libc::fcntl(fd, libc::F_SETFD, 0) != 0
                    {
                        return Err(std::io::Error::last_os_error());
                    }
                    let fd = libc::open(procs.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
                    if fd < 0 || libc::write(fd, b"0".as_ptr().cast(), 1) != 1 {
                        return Err(std::io::Error::last_os_error());
                    }
                    libc::close(fd);
                    Ok(())
                });
            }
            let mut child = {
                let _spawning = lock(&SPAWNING)?;
                command.spawn().map_err(io("starting it"))?
            };
            let mut stdin = child.stdin.take().ok_or_else(Error::internal)?;
            stdin.write_all(input).map_err(io("writing its spec"))?;
            let stdin = if keep_stdin {
                Some(stdin)
            } else {
                drop(stdin);
                None
            };
            if let Some(stdout) = child.stdout.take() {
                let (endings, meters) = (self.endings.clone(), self.meters.clone());
                std::thread::Builder::new()
                    .name("run-stream".into())
                    .stack_size(64 * 1024)
                    .spawn(move || {
                        // The shim streams its outbound totals as they change
                        // and says when its run ended; its pipe closing (the
                        // shim gone) is looked into as an end too.
                        let run = || serving.lock().unwrap_or_else(|e| e.into_inner()).clone();
                        // A shim runs as its run's uid and may be anything by
                        // the time it writes here: a line is read up to a
                        // bound, and one over it is passed by, not held.
                        let mut stdout = std::io::BufReader::new(stdout);
                        while let Ok(Some(line)) = bounded_line(&mut stdout, MAX_SHIM_LINE) {
                            let Some(line) = line else { continue };
                            if let Some(totals) = line.strip_prefix("meter ") {
                                if let (Ok(totals), Some(run)) =
                                    (serde_json::from_str::<Value>(totals), run())
                                    && totals.is_object()
                                {
                                    meters
                                        .lock()
                                        .unwrap_or_else(|e| e.into_inner())
                                        .insert(run, totals);
                                }
                            } else if line == "ended" {
                                signalled.store(true, std::sync::atomic::Ordering::SeqCst);
                                endings.notify_one();
                            }
                        }
                        signalled.store(true, std::sync::atomic::Ordering::SeqCst);
                        if run().is_some() {
                            endings.notify_one();
                        }
                    })?;
            }
            lock(&self.children)?.push(child);
            Ok(stdin)
        })();
        if started.is_err() {
            remove_cgroup(&cgroup);
        }
        started
    }

    /// Run `id`'s status: from its shim while it lives; once it ended, the
    /// end report collected from it, its cgroup then removed.
    pub fn status(&self, id: &str) -> Result<Value> {
        let boot = boot_id()?;
        let asking = {
            let table = lock(&self.runs)?;
            let run = table.get(id).ok_or_else(Error::missing)?;
            if let Some((status, _)) = &run.ended {
                return Ok(status.clone());
            }
            run.asking.clone()
        };
        let _asking = lock(&asking)?;
        // Another read may have ended it while this one waited.
        let unanswered_since = {
            let table = lock(&self.runs)?;
            let run = table.get(id).ok_or_else(Error::missing)?;
            if let Some((status, _)) = &run.ended {
                return Ok(status.clone());
            }
            // Running, and its pipe has not said otherwise since: its shim's
            // last answer stands, without asking it again.
            if let (Some(signalled), Some(last)) = (&run.signalled, &run.last_running)
                && !signalled.load(std::sync::atomic::Ordering::SeqCst)
            {
                let cgroup = self.run_cgroup(run.cgroup.as_deref().unwrap_or(id));
                let last = last.clone();
                drop(table);
                return Ok(as_status(id, &last, &cgroup, &boot, self.streamed(id)));
            }
            (run.unanswered_since, run.cgroup.clone())
        };
        let (unanswered_since, cgroup) = unanswered_since;
        let cgroup = self.run_cgroup(cgroup.as_deref().unwrap_or(id));
        let ended = match ask(&cgroup, id, "status")? {
            Some(shim) => {
                if let Some(run) = lock(&self.runs)?.get_mut(id) {
                    if unanswered_since.is_some() {
                        run.unanswered_since = None;
                    }
                    // Seen running for the first time: how long it took.
                    if let Some(started) = shim["started"].as_f64()
                        && let Some((at, warm)) = run.start.take()
                    {
                        crate::metrics::run_start_seconds(warm, started - at);
                    }
                }
                let status = as_status(id, &shim, &cgroup, &boot, self.streamed(id));
                if !terminal(s(&status["state"])) {
                    if shim["state"] == "running"
                        && let Some(run) = lock(&self.runs)?.get_mut(id)
                    {
                        run.last_running = Some(shim);
                    }
                    return Ok(status);
                }
                // Ended: its end report is the run's; the shim may exit.
                match ask(&cgroup, id, "collect")? {
                    Some(last) => as_status(id, &last, &cgroup, &boot, None),
                    None => status,
                }
            }
            // Its shim has yet to answer for the first time: starting.
            None if unanswered_since.is_some_and(|at| at.elapsed() < FIRST_ANSWER) => {
                return Ok(json!({"id": id, "state": "starting", "created": now()}));
            }
            // Its shim is gone without being collected: the run is lost.
            None => json!({"id": id, "state": "lost", "reason": "worker-lost", "finished": now()}),
        };
        remove_cgroup(&cgroup);
        // Another read may have collected the run meanwhile (its shim then
        // exits, and this one found none): the first end recorded stands.
        let mut table = lock(&self.runs)?;
        let run = table.get_mut(id).ok_or_else(Error::missing)?;
        if let Some((recorded, _)) = &run.ended {
            return Ok(recorded.clone());
        }
        run.ended = Some((ended.clone(), Instant::now()));
        Ok(ended)
    }

    /// The ids of the runs not yet seen ended.
    pub fn live_ids(&self) -> Result<Vec<String>> {
        Ok(lock(&self.runs)?
            .iter()
            .filter(|(_, run)| run.ended.is_none())
            .map(|(id, _)| id.clone())
            .collect())
    }

    pub fn live_run_ids(&self) -> Result<Vec<String>> {
        Ok(self
            .list_live()?
            .iter()
            .map(|status| s(&status["id"]).to_owned())
            .collect())
    }

    /// The statuses of the runs not yet ended.
    pub fn list_live(&self) -> Result<Vec<Value>> {
        let mut live = Vec::new();
        for id in self.live_ids()? {
            match self.status(&id) {
                Ok(status) if !terminal(s(&status["state"])) => live.push(status),
                Ok(_) => {}
                Err(error) if error.status == StatusCode::NOT_FOUND => {}
                Err(error) => return Err(error),
            }
        }
        Ok(live)
    }

    pub fn list(&self) -> Result<Vec<Value>> {
        let ids: Vec<String> = lock(&self.runs)?.keys().cloned().collect();
        ids.iter().map(|id| self.status(id)).collect()
    }

    /// Reaps exited shims, forgets runs ended long enough ago, and prunes
    /// the artifact cache.
    pub fn reconcile(&self) -> Result<()> {
        let mut children = lock(&self.children)?;
        let mut i = 0;
        while i < children.len() {
            if children[i].try_wait()?.is_some() {
                children.swap_remove(i).wait()?;
            } else {
                i += 1
            }
        }
        drop(children);
        if self.warm_runs > 0
            && let Err(error) = self.tidy_warm()
        {
            tracing::warn!(error = %error.message, "tidying warm shims failed");
        }
        let forgotten: Vec<String> = {
            let mut table = lock(&self.runs)?;
            let old: Vec<String> = table
                .iter()
                .filter(|(_, run)| {
                    run.ended
                        .as_ref()
                        .is_some_and(|(_, at)| at.elapsed() >= KEEP_ENDED)
                })
                .map(|(id, _)| id.clone())
                .collect();
            let mut meters = lock(&self.meters)?;
            for id in &old {
                table.remove(id);
                meters.remove(id);
            }
            old
        };
        drop(forgotten);
        // A run's cgroup goes once its run ended; one its shim was still
        // leaving when the run was collected goes on a later pass.
        let live: std::collections::HashSet<String> = self.live_ids()?.into_iter().collect();
        for entry in fs::read_dir(&self.cgroup_root)? {
            let name = entry?.file_name().to_string_lossy().into_owned();
            if is_run_id(&name) && !live.contains(&name) {
                remove_cgroup(&self.run_cgroup(&name));
            }
        }
        self.prune_artifacts()?;
        Ok(())
    }

    /// The node's gauges, for its metrics ([`crate::metrics`]).
    pub fn gauges(&self) -> crate::metrics::Gauges {
        let run_cgroups = fs::read_dir(&self.cgroup_root)
            .map(|entries| {
                entries
                    .flatten()
                    .filter(|entry| {
                        let name = entry.file_name();
                        let name = name.to_string_lossy();
                        (is_run_id(&name) || name.starts_with(WARM_PREFIX)) && entry.path().is_dir()
                    })
                    .count()
            })
            .unwrap_or(0);
        crate::metrics::Gauges {
            run_directories: (run_cgroups + crate::retention::legacy_run_count(&self.state)) as u64,
            runs: self.live_count().unwrap_or(0) as u64,
            run_capacity: self.max_instances as u64,
            warm_shims: lock(&self.warm)
                .map(|warm| warm.shims.values().map(Vec::len).sum::<usize>())
                .unwrap_or(0) as u64,
        }
    }

    pub fn action(&self, id: &str, action: &str) -> Result<Value> {
        if action != "stop" {
            return Err(Error::new(
                StatusCode::NOT_IMPLEMENTED,
                "a shim's run can only be stopped",
            ));
        }
        let status = self.status(id)?;
        if !terminal(s(&status["state"])) {
            let cgroup = lock(&self.runs)?.get(id).and_then(|run| run.cgroup.clone());
            let cgroup = self.run_cgroup(cgroup.as_deref().unwrap_or(id));
            ask(&cgroup, id, "stop")?;
        }
        self.status(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_spec_splits_into_the_run_protocol_and_the_guest() {
        let (run, guest) = split(
            &json!({"artifact":"a","mode":"command","durability":"ephemeral",
            "protocol":1,"run":{"execution":"e"},"channel":{"endpoint":"https://x"}}),
        )
        .unwrap();
        assert_eq!(run["protocol"], 1);
        assert_eq!(guest, json!({"artifact":"a","mode":"command"}));
        assert!(split(&json!({"artifact":"a","protocol":1,"run":{}})).is_err());
    }

    #[test]
    fn a_warm_shim_serves_only_its_artifact_and_guest_configuration() {
        let guest = json!({"mode": "command", "guest_memory_mib": 64});
        let other = json!({"mode": "command", "guest_memory_mib": 128});
        let (a, b) = (Path::new("/cache/a"), Path::new("/cache/b"));
        assert_eq!(warm_key(a, &guest), warm_key(a, &guest.clone()));
        assert_ne!(warm_key(a, &guest), warm_key(a, &other));
        assert_ne!(warm_key(a, &guest), warm_key(b, &guest));
        // A warm shim still starting holds its uid already.
        let mut pool = WarmPool::default();
        pool.reserved.push((600_007, "warm-1-1".into()));
        assert!(pool.holds_uid(600_007));
        assert!(!pool.holds_uid(600_008));
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn one_key_names_one_run() {
        assert_eq!(run_id("platform-e1"), run_id("platform-e1"));
        assert_ne!(run_id("platform-e1"), run_id("platform-e2"));
        assert!(is_run_id(&run_id("k")));
        assert!(!is_run_id("compiler-0123456789abcdef"));
    }

    #[test]
    fn a_shims_status_reads_as_a_runs() {
        let status = as_status(
            "r",
            &json!({"state":"failed","code":"LIFETIME_EXCEEDED","exit_code":null,
                "egress":{"bytes":7,"in_flight":0,"complete":true}}),
            Path::new("/nonexistent"),
            "boot",
            None,
        );
        assert_eq!(status["reason"], "lifetime-limit");
        assert_eq!(status["egress"]["bytes"], 7);
        assert_eq!(status["egress_boot_id"], "boot");
        let exited = as_status(
            "r",
            &json!({"state":"exited","exit_code":0}),
            Path::new("/x"),
            "b",
            None,
        );
        assert!(exited.get("reason").is_none());
        assert_eq!(
            as_status("r", &json!({}), Path::new("/x"), "b", None)["state"],
            "failed"
        );
        // Streamed totals win over the shim's answer.
        let streamed = as_status(
            "r",
            &json!({"state":"running","egress":{"bytes":1,"in_flight":0,"complete":false}}),
            Path::new("/x"),
            "b",
            Some(json!({"bytes":9,"in_flight":0,"complete":false})),
        );
        assert_eq!(streamed["egress"]["bytes"], 9);
        // A run under the outbound byte limit names its launcher, and one
        // its shim ended for the limit says why.
        assert!(streamed.get("egress_authority").is_none());
        for (code, reason) in [
            ("EGRESS_LIMIT", "outbound-allowance-denied"),
            ("EGRESS_EXPIRED", "outbound-grant-expired"),
            ("EGRESS_UNMEASURED", "outbound-accounting-unavailable"),
        ] {
            let limited = as_status(
                "r",
                &json!({"state":"failed","code":code,"egress_launcher":"c".repeat(64),
                    "egress":{"bytes":3,"in_flight":0,"complete":true}}),
                Path::new("/x"),
                "boot",
                None,
            );
            assert_eq!(limited["reason"], reason);
            assert_eq!(
                limited["egress_authority"],
                json!({"contract":"socket-payload-ceiling-v2","boot_id":"boot","launcher_digest":"c".repeat(64)})
            );
        }
        let unnamed = as_status(
            "r",
            &json!({"state":"running","egress_launcher":"not a digest"}),
            Path::new("/x"),
            "boot",
            None,
        );
        assert!(unnamed.get("egress_authority").is_none());
    }

    #[test]
    fn asking_a_run_without_a_shim_finds_none() {
        assert!(
            ask(
                Path::new("/nowhere"),
                &run_id("nobody-holds-this"),
                "status"
            )
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn a_runs_cgroup_limits_its_shim_as_well_as_its_vm() {
        let limits: std::collections::HashMap<_, _> = run_limits(256, 100).into_iter().collect();
        // The VM's whole CPU and half a CPU for the shim, of a 100 ms period:
        // never without a limit, which is what "max" would be.
        assert_eq!(limits["cpu.max"], "150000 100000");
        assert_eq!(limits["memory.max"], ((256 + 64) * 1024 * 1024).to_string());
        assert_eq!(limits["memory.swap.max"], "0");
        assert_eq!(limits["memory.oom.group"], "1");
        assert_eq!(limits["pids.max"], "64");
        // The least a run is given still has both.
        assert_eq!(run_limits(0, 0)[3].1, "51000 100000");
    }

    #[test]
    fn a_launch_names_the_digest_its_component_was_compiled_to() {
        let artifact = tempfile::tempdir().unwrap();
        assert_eq!(compiled_digest(artifact.path()), None);
        let digest = "ab".repeat(32);
        for (recorded, expected) in [
            (json!({"compiled_sha256": digest}), Some(digest.clone())),
            (json!({"compiled_sha256": "AB".repeat(32)}), None),
            (json!({"compiled_sha256": "abc"}), None),
            (json!({"compiled_bytes": 1}), None),
        ] {
            std::fs::write(artifact.path().join("artifact.json"), recorded.to_string()).unwrap();
            assert_eq!(compiled_digest(artifact.path()), expected, "{recorded}");
        }
    }

    #[test]
    fn a_shims_output_is_read_a_bounded_line_at_a_time() {
        let mut input = Vec::new();
        input.extend_from_slice(b"meter {\"bytes\":1}\n");
        // A megabyte with no newline, then one: never held, and passed by.
        input.extend(std::iter::repeat_n(b'x', 1 << 20));
        input.extend_from_slice(b"\nended\n");
        input.extend_from_slice(&[0xff, 0xfe, b'\n']);
        input.extend_from_slice(b"\n");
        input.extend_from_slice(b"last");
        // Read through a small buffer, so lines span several fills.
        let mut reader = std::io::BufReader::with_capacity(7, &input[..]);
        let mut lines = Vec::new();
        while let Some(line) = bounded_line(&mut reader, 32).unwrap() {
            lines.push(line);
        }
        assert_eq!(
            lines,
            [
                Some("meter {\"bytes\":1}".to_owned()),
                None,
                Some("ended".to_owned()),
                None,
                Some(String::new()),
                Some("last".to_owned()),
            ]
        );
        // Exactly the bound fits; one byte more does not.
        let mut reader = &b"abcd\nabcde\n"[..];
        assert_eq!(
            bounded_line(&mut reader, 4).unwrap(),
            Some(Some("abcd".into()))
        );
        assert_eq!(bounded_line(&mut reader, 4).unwrap(), Some(None));
        assert_eq!(bounded_line(&mut reader, 4).unwrap(), None);
    }

    #[test]
    fn an_answer_at_a_runs_name_from_outside_its_cgroup_is_not_its_shims() {
        // This test process holds the name, answers as a shim would, and is
        // in no cgroup of the run's: what a local process squatting the name
        // looks like to the node.
        let id = run_id(&format!("squatted-{}", std::process::id()));
        let listener =
            std::os::unix::net::UnixListener::bind_addr(&link_address(&id).unwrap()).unwrap();
        let answering = std::thread::spawn(move || {
            // Only a caller that trusted the name would read this.
            for _ in 0..2 {
                if let Ok((mut stream, _)) = listener.accept() {
                    let mut asked = [0u8; 16];
                    let _ = stream.read(&mut asked);
                    let _ = stream.write_all(b"{\"state\":\"exited\",\"exit_code\":0}\n");
                }
            }
        });
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("cgroup.procs"), "1\n").unwrap();
        assert!(ask(outside.path(), &id, "status").unwrap().is_none());

        // The same answer from a member of the cgroup is the run's.
        let inside = tempfile::tempdir().unwrap();
        std::fs::create_dir(inside.path().join("shim")).unwrap();
        std::fs::write(
            inside.path().join("shim/cgroup.procs"),
            format!("1\n{}\n", std::process::id()),
        )
        .unwrap();
        let status = ask(inside.path(), &id, "status").unwrap().unwrap();
        assert_eq!(status["state"], "exited");
        answering.join().unwrap();
    }
}
