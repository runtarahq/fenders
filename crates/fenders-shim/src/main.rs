//! `fenders-shim`: one per run. Reads the run's spec on standard input, starts
//! and owns the VMM, and relays the guest's workflow and connections API calls
//! to the run channel's endpoint over HTTPS with the per-launch credential.
//! For a launch that asks (`guest.output`), it also sends the guest's standard
//! output and error up the channel ([`output`]). Nothing is written to disk.
//!
//! ```text
//! fenders-shim < spec.json          the run, in the cgroup it was started in
//!   └─ launch                       the VMM, in <cgroup>/vm, confined
//! ```
//!
//! The shim logs to standard error, which it shares with its launcher, in
//! the launcher's format (`FENDERS_LOG_FORMAT`, `text` or `json`; levels
//! from `RUST_LOG`), one write per line so shims' lines do not interleave:
//! see [`fenders_node::log`]. Its lines about a run carry the run's `run`
//! (its id on its launcher) and `execution`. It reports how the run ended
//! as one line, `run ended`, with the end report's fields. It never logs
//! the spec or the credential.

mod budget;
mod ingress;
mod link;
mod output;
mod relay;
mod spec;
mod upstream;

use hyper::{
    Method,
    body::Bytes,
    header::{CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue},
};
use serde_json::{Value, json};
use spec::{Machine, Spec};
use std::{
    fs,
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        unix::{fs::MetadataExt, net::UnixStream, process::CommandExt},
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

type Result<T> = std::result::Result<T, String>;

fn os(what: &str) -> impl FnOnce(std::io::Error) -> String + '_ {
    move |e| format!("{what}: {e}")
}

fn check(rc: libc::c_int, what: &str) -> Result<()> {
    if rc < 0 {
        Err(format!("{what}: {}", std::io::Error::last_os_error()))
    } else {
        Ok(())
    }
}

fn main() {
    unsafe {
        libc::umask(0o077);
    }
    fenders_node::log::init(fenders_node::log::Format::from_env());
    let code = match std::env::args().nth(1).as_deref() {
        // Internal: the fresh process that becomes the VMM.
        Some("vmm") => match vmm() {
            Ok(()) => unreachable!(),
            Err(error) => {
                // With output captured, standard error here is the guest's: the
                // failure goes where the launcher's own messages go.
                match env_number::<RawFd>("FENDERS_DIAGNOSTICS_FD") {
                    Ok(fd) => {
                        let mut pipe =
                            std::mem::ManuallyDrop::new(unsafe { fs::File::from_raw_fd(fd) });
                        let _ = pipe.write_all(format!("vmm failed: {error}\n").as_bytes());
                    }
                    Err(_) => tracing::error!(%error, "vmm failed"),
                }
                3
            }
        },
        None => run(),
        Some("warm") => warm(),
        Some(_) => {
            std::eprintln!("usage: fenders-shim [warm] < spec.json");
            2
        }
    };
    std::process::exit(code);
}

/// The run's cgroup: the one the shim was started in.
fn own_cgroup() -> Result<PathBuf> {
    let text = fs::read_to_string("/proc/self/cgroup").map_err(os("reading /proc/self/cgroup"))?;
    let path = text
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or("cgroup v2 required")?;
    if path == "/" {
        return Err("the shim must be started in its run's own cgroup, not the root".into());
    }
    Ok(Path::new("/sys/fs/cgroup").join(path.trim_start_matches('/')))
}

/// Makes `<cgroup>/shim` (holding the shim) and `<cgroup>/vm` (for the VMM,
/// with the run's limits). The run's cgroup must hold nothing else.
fn cgroup_leaves(cgroup: &Path, guest: &Value) -> Result<PathBuf> {
    let (shim, vm) = (cgroup.join("shim"), cgroup.join("vm"));
    fs::create_dir(&shim).map_err(os("creating the shim cgroup (one shim per run)"))?;
    fs::write(shim.join("cgroup.procs"), std::process::id().to_string())
        .map_err(os("joining the shim cgroup"))?;
    let available = fs::read_to_string(cgroup.join("cgroup.controllers")).unwrap_or_default();
    let wanted: Vec<String> = ["cpu", "memory", "pids"]
        .iter()
        .filter(|c| available.split_whitespace().any(|a| a == **c))
        .map(|c| format!("+{c}"))
        .collect();
    if wanted.len() != 3 {
        return Err(format!(
            "the run's cgroup has controllers `{}`: cpu, memory and pids are all required",
            available.trim()
        ));
    }
    fs::write(cgroup.join("cgroup.subtree_control"), wanted.join(" ")).map_err(os(
        "enabling controllers (is the shim alone in its run's cgroup?)",
    ))?;
    fs::create_dir(&vm).map_err(os("creating the vm cgroup"))?;
    let mib = |field: &str| guest[field].as_i64().unwrap_or(0) * 1024 * 1024;
    for (name, value) in [
        (
            "cpu.max",
            format!(
                "{} 100000",
                guest["cpu_percent"].as_i64().unwrap_or(100) * 1000
            ),
        ),
        ("memory.max", mib("host_memory_mib").to_string()),
        ("memory.swap.max", "0".to_owned()),
        ("memory.oom.group", "1".to_owned()),
        ("pids.max", "16".to_owned()),
    ] {
        // A limit that cannot be set is not skipped: a VM would otherwise
        // start with none, and nothing would say so.
        fs::write(vm.join(name), value).map_err(|error| {
            format!("limiting the vm cgroup ({name}): {error}; its cpu, memory and pids controllers must be enabled")
        })?;
    }
    Ok(vm)
}

fn inheritable(fd: RawFd) -> Result<()> {
    check(unsafe { libc::fcntl(fd, libc::F_SETFD, 0) }, "fcntl")
}

/// The guest environment in a sealed memfd: never a file.
fn environment(bytes: &[u8]) -> Result<OwnedFd> {
    let fd = unsafe {
        libc::memfd_create(
            c"guest-env".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    check(fd, "memfd_create")?;
    let mut file = unsafe { fs::File::from_raw_fd(fd) };
    file.write_all(bytes)
        .map_err(os("writing the guest environment"))?;
    check(
        unsafe {
            libc::fcntl(
                fd,
                libc::F_ADD_SEALS,
                libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE,
            )
        },
        "sealing the guest environment",
    )?;
    Ok(file.into())
}

fn sha256_of(file: &fs::File) -> Result<String> {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    let mut reader = file;
    let mut buffer = vec![0; 1 << 20];
    loop {
        let n = reader
            .read(&mut buffer)
            .map_err(os("reading the component"))?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

/// Drops to `uid`/`gid` with only `groups`, for good.
fn drop_to(uid: u32, gid: u32, groups: &[libc::gid_t]) -> Result<()> {
    unsafe {
        check(libc::setgroups(groups.len(), groups.as_ptr()), "setgroups")?;
        check(libc::setresgid(gid, gid, gid), "setresgid")?;
        check(libc::setresuid(uid, uid, uid), "setresuid")?;
        if libc::setuid(0) == 0 {
            return Err("privileges were not dropped".into());
        }
    }
    Ok(())
}

/// No core dumps and no ptrace or /proc/<pid>/mem access by the same uid.
fn undumpable() -> Result<()> {
    let none = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    check(
        unsafe { libc::setrlimit(libc::RLIMIT_CORE, &none) },
        "RLIMIT_CORE",
    )?;
    check(
        unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) },
        "PR_SET_DUMPABLE",
    )
}

fn env_number<T: std::str::FromStr>(name: &str) -> Result<T> {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| format!("{name} missing"))
}

/// The internal `vmm` step, in a fresh single-threaded process: join the vm
/// cgroup, drop to the run's uid, confine, and become `launch`.
fn vmm() -> Result<()> {
    let parent: libc::pid_t = env_number("FENDERS_SHIM_PARENT")?;
    let vm =
        PathBuf::from(std::env::var("FENDERS_SHIM_VM_CGROUP").map_err(|_| "vm cgroup missing")?);
    fs::write(vm.join("cgroup.procs"), std::process::id().to_string())
        .map_err(os("joining the vm cgroup"))?;
    let files = libc::rlimit {
        rlim_cur: 128,
        rlim_max: 128,
    };
    check(
        unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &files) },
        "RLIMIT_NOFILE",
    )?;
    if let (Ok(uid), Ok(gid)) = (
        env_number::<u32>("FENDERS_SHIM_UID"),
        env_number::<u32>("FENDERS_SHIM_GID"),
    ) {
        let kvm: Vec<libc::gid_t> = std::env::var("FENDERS_SHIM_KVM_GID")
            .ok()
            .and_then(|g| g.parse().ok())
            .into_iter()
            .collect();
        drop_to(uid, gid, &kvm)?;
    }
    undumpable()?;
    // Set after the uid change, which clears it: the VMM dies with its shim.
    check(
        unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) },
        "PR_SET_PDEATHSIG",
    )?;
    if unsafe { libc::getppid() } != parent {
        return Err("the shim exited".into());
    }
    if let Ok(cpu) = env_number::<usize>("FENDERS_VMM_CPU") {
        unsafe {
            let mut set = std::mem::zeroed::<libc::cpu_set_t>();
            libc::CPU_SET(cpu, &mut set);
            libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set);
        }
    }
    let launch = PathBuf::from(std::env::var("FENDERS_SHIM_LAUNCH").map_err(|_| "launch missing")?);
    let ports: Vec<u16> = std::env::var("FENDERS_SHIM_PORTS")
        .unwrap_or_default()
        .split(',')
        .filter_map(|p| p.parse().ok())
        .collect();
    let dns = std::env::var("FENDERS_SHIM_DNS").as_deref() == Ok("1");
    let args: Vec<String> = [
        "FENDERS_SHIM_RUNTIME_FD",
        "FENDERS_SHIM_COMPONENT_FD",
        "FENDERS_SHIM_ENV_FD",
    ]
    .iter()
    .map(|name| env_number::<RawFd>(name).map(|fd| format!("fd:{fd}")))
    .collect::<Result<_>>()?;
    fenders_node::confinement::apply("vmm", &launch, &[], &[], &ports, dns, true)
        .map_err(|e| format!("confinement: {}", e.message))?;
    let mut command = Command::new(&launch);
    command.args(&args);
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("FENDERS_SHIM_") {
            command.env_remove(name);
        }
    }
    Err(format!("exec launch: {}", command.exec()))
}

/// The gid owning /dev/kvm, which the run needs as a supplementary group.
fn kvm_gid() -> Option<u32> {
    fs::metadata("/dev/kvm").ok().map(|m| m.gid())
}

/// The shim's ends of a capturing VM's output pipes ([`output`]), taken by
/// [`finish`]: set only for a launch that asked for its output.
static OUTPUT: std::sync::Mutex<Option<output::Pipes>> = std::sync::Mutex::new(None);

/// The read end of the VMM's meter pipe (cumulative outbound totals), taken
/// by [`finish`] once the shim is unprivileged.
static METER: std::sync::Mutex<Option<OwnedFd>> = std::sync::Mutex::new(None);

/// The shim's end of the control socket of a VM under the outbound byte
/// limit ([`budget`]), taken by [`finish`]: set only for a launch that asked
/// for the limit. With it, the digest of the launcher that admits the VM's
/// bytes, which the run's status names (`egress_launcher`).
static CONTROL: std::sync::Mutex<Option<(UnixStream, String)>> = std::sync::Mutex::new(None);

/// The shim's end of an HTTP run's request stream ([`ingress`]), taken by
/// [`finish`]: set only for a launch whose mode is `http`.
static INGRESS: std::sync::Mutex<Option<UnixStream>> = std::sync::Mutex::new(None);

/// The last totals line launch wrote: `meter|final BYTES IN_FLIGHT MEASURED
/// REFUSALS`, and `WANTED` after them from a launch under the outbound byte
/// limit, as a report field.
fn meter_report(line: &str) -> Value {
    let mut parts = line.split(' ');
    let kind = parts.next();
    let numbers: Vec<u64> = parts.filter_map(|p| p.parse().ok()).collect();
    match (kind, numbers.as_slice()) {
        (
            Some(kind @ ("meter" | "final")),
            [bytes, in_flight, 1, refusals] | [bytes, in_flight, 1, refusals, _],
        ) => json!({
            "bytes": bytes,
            "in_flight": in_flight,
            "refusals": refusals,
            "complete": kind == "final" && *in_flight == 0,
        }),
        _ => Value::Null,
    }
}

/// A meter line as the outbound byte limit reads it: only a line with
/// `WANTED`, which a launch under the limit writes.
fn budget_meter(line: &str) -> Option<budget::Meter> {
    let numbers: Vec<u64> = line
        .split(' ')
        .skip(1)
        .filter_map(|p| p.parse().ok())
        .collect();
    match numbers.as_slice() {
        [bytes, _, _, refusals, wanted] => Some(budget::Meter {
            bytes: *bytes,
            wanted: *wanted,
            refusals: *refusals,
        }),
        _ => None,
    }
}

/// Reads the meter pipe to its end (the VMM's exit) on a thread, keeping
/// the last line. `limit` is given each line of a launch under the outbound
/// byte limit.
fn read_meter(
    link: Option<Arc<link::Link>>,
    limit: Option<tokio::sync::watch::Sender<budget::Meter>>,
) -> Option<std::thread::JoinHandle<String>> {
    let read = METER.lock().ok()?.take()?;
    Some(std::thread::spawn(move || {
        let mut last = String::new();
        let mut meter = std::io::BufReader::new(fs::File::from(read));
        loop {
            match launcher_line(&mut meter) {
                // One longer than a meter line is: passed by, not kept.
                Ok(Some(None)) => continue,
                Ok(None) => break,
                Ok(Some(Some(line))) => {
                    if let (Some(limit), Some(meter)) = (&limit, budget_meter(&line)) {
                        let _ = limit.send(meter);
                    }
                    // The launcher has the latest totals while the run lives:
                    // streamed on stdout as they change, and in its status.
                    if let Some(link) = &link {
                        let egress = meter_report(&line);
                        tell_launcher(&format!("meter {egress}"));
                        link.update(|status| {
                            status.insert("egress".into(), egress);
                        });
                    }
                    last = line;
                }
                Err(_) => break,
            }
        }
        last
    }))
}

/// The longest line read from the VMM: a meter line, or a control answer.
const MAX_LAUNCHER_LINE: usize = 4096;

/// The next line of what the VMM writes, without its newline. The VMM runs
/// the guest and is trusted with less than the shim: a line is read up to
/// [`MAX_LAUNCHER_LINE`], and one over it, or not UTF-8, is read past and
/// not kept (`Some(None)`). `None` at the end.
fn launcher_line(input: &mut impl std::io::BufRead) -> std::io::Result<Option<Option<String>>> {
    use std::io::{BufRead as _, Read as _};
    let mut line = Vec::new();
    let read = input
        .by_ref()
        .take(MAX_LAUNCHER_LINE as u64 + 1)
        .read_until(b'\n', &mut line)?;
    if read == 0 {
        return Ok(None);
    }
    if line.last() == Some(&b'\n') {
        line.pop();
        return Ok(Some(String::from_utf8(line).ok()));
    }
    if line.len() <= MAX_LAUNCHER_LINE {
        // The end, without a newline.
        return Ok(Some(String::from_utf8(line).ok()));
    }
    // Over the bound: pass by the rest of it, a piece at a time.
    loop {
        line.clear();
        let read = input
            .by_ref()
            .take(MAX_LAUNCHER_LINE as u64)
            .read_until(b'\n', &mut line)?;
        if read == 0 || line.last() == Some(&b'\n') {
            return Ok(Some(None));
        }
    }
}

/// One line to the launcher on stdout (a pipe to it, when it has one):
/// `meter {totals}` as outbound totals change, `ended` once the run ended.
fn tell_launcher(line: &str) {
    use std::io::Write as _;
    let mut stdout = std::io::stdout().lock();
    let _ = stdout.write_all(format!("{line}\n").as_bytes());
    let _ = stdout.flush();
}

fn unix_now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// How the run ended, as the shim reports it.
struct End {
    state: &'static str,
    code: &'static str,
    reason: String,
    category: &'static str,
    exit_code: Option<i32>,
    signal: Option<i32>,
}

/// Confines the shim for the rest of its life
/// ([`fenders_node::confinement::apply_shim`]): it may connect to its run
/// channel's port, and to a resolver's.
fn confine(spec: &Spec) -> Result<()> {
    let channel = spec.channel.endpoint.port_or_known_default().unwrap_or(443);
    fenders_node::confinement::apply_shim(&[channel, 53])
        .map(|_| ())
        .map_err(|error| format!("confining the shim: {}", error.message))
}

/// Drops the shim to the run's uid (when started as root) and makes it
/// non-dumpable: it holds the credential.
fn unprivileged(machine: &Machine) -> Result<()> {
    if unsafe { libc::geteuid() } == 0
        && let (Some(uid), Some(gid)) = (machine.uid, machine.gid)
    {
        drop_to(uid, gid, &[])?;
    }
    undumpable()
}

fn run() -> i32 {
    let mut bytes = Vec::new();
    if let Err(error) = std::io::stdin()
        .take(spec::MAX_SPEC_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
    {
        tracing::error!(%error, "reading the spec failed");
        return 2;
    }
    if bytes.len() > spec::MAX_SPEC_BYTES {
        tracing::error!("spec over {} bytes", spec::MAX_SPEC_BYTES);
        return 2;
    }
    let spec = match Spec::parse(&bytes) {
        Ok(spec) => spec,
        Err(error) => {
            tracing::error!("{error}");
            return 2;
        }
    };
    // The spec carries the credential; keep only the parsed form.
    bytes.fill(0);
    drop(bytes);
    let _span = run_span(&spec);
    // The launcher's link binds first: a second shim for the same run stops
    // here, before it touches the run or posts anything for it.
    let link = match bind_link(&spec) {
        Ok(link) => link,
        Err(code) => return code,
    };
    // A launch under the outbound byte limit holds its guest, as a warm
    // launch does, until its first grant is in place.
    let hold = if budget::wanted(&spec.machine.guest) {
        match hold_pipe() {
            Ok(hold) => Some(hold),
            Err(error) => {
                tracing::error!("{error}");
                return 1;
            }
        }
    } else {
        None
    };
    let (child, channel, vm) = match start(&spec.machine, hold.as_ref().map(|(read, _)| read)) {
        Ok(started) => started,
        Err(error) => {
            tracing::error!("{error}");
            // A launch that never started still ends its run, with the
            // reason, posted unprivileged like any other.
            if let Err(error) = unprivileged(&spec.machine) {
                tracing::error!("{error}");
                return 1;
            }
            return finish(&spec, None, None, Some(error), link, None);
        }
    };
    finish(
        &spec,
        Some(child),
        Some((channel, vm)),
        None,
        link,
        hold.map(|(_, write)| write),
    )
}

/// A pipe whose read end a VMM holds its guest on until the write end closes.
fn hold_pipe() -> Result<(OwnedFd, OwnedFd)> {
    let mut pipe = [0; 2];
    check(
        unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) },
        "hold pipe",
    )?;
    Ok(unsafe { (OwnedFd::from_raw_fd(pipe[0]), OwnedFd::from_raw_fd(pipe[1])) })
}

/// Fields naming `spec`'s run on every line logged while it is entered.
fn run_span(spec: &Spec) -> tracing::span::EnteredSpan {
    tracing::error_span!(
        "run",
        run = spec.launcher.as_ref().map(|launcher| launcher.id.as_str()),
        execution = spec.run.execution.as_str(),
    )
    .entered()
}

/// The launcher's link for `spec`'s run, bound: none without a launcher, and
/// exit code 3 when another shim holds the run.
#[allow(clippy::type_complexity)]
fn bind_link(
    spec: &Spec,
) -> std::result::Result<Option<(std::os::unix::net::UnixListener, Arc<link::Link>)>, i32> {
    let Some(launcher) = &spec.launcher else {
        return Ok(None);
    };
    // A launcher that bound the run's name itself passes the socket on; one
    // that did not leaves the shim to bind it.
    let bound = match std::env::var(link::INHERITED) {
        Ok(fd) => {
            // Not for the VMM, which inherits this environment.
            unsafe { std::env::remove_var(link::INHERITED) };
            fd.parse()
                .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))
                .and_then(|fd| link::inherited(&launcher.id, fd))
        }
        Err(_) => link::bind(&launcher.id),
    };
    match bound {
        Ok(listener) => Ok(Some((
            listener,
            link::Link::new(
                link::initial(
                    &launcher.id,
                    &launcher.key,
                    &spec.machine.component.to_string_lossy(),
                    spec.machine.uid,
                    spec.machine.cpu,
                    &spec.machine.guest,
                ),
                launcher.uid,
            ),
        ))),
        Err(error) => {
            tracing::error!(%error, "the run is held by another shim");
            Err(3)
        }
    }
}

/// One line of standard input, at most a spec's size; `None` at its end.
fn spec_line(input: &mut impl std::io::BufRead) -> Result<Option<Vec<u8>>> {
    use std::io::BufRead;
    let mut line = Vec::new();
    (&mut *input)
        .take(spec::MAX_SPEC_BYTES as u64 + 1)
        .read_until(b'\n', &mut line)
        .map_err(os("reading the spec"))?;
    if line.len() > spec::MAX_SPEC_BYTES {
        line.fill(0);
        return Err(format!("spec over {} bytes", spec::MAX_SPEC_BYTES));
    }
    if line.last() == Some(&b'\n') {
        line.pop();
    } else if !line.is_empty() {
        line.fill(0);
        return Err("spec line not terminated".into());
    }
    Ok((!line.is_empty()).then_some(line))
}

/// `fenders-shim warm`: a shim started before its run. The first line on its
/// standard input is a warm spec (the machine alone): it starts the VM, which
/// boots and loads its component and then waits. The second line claims it
/// for one run (`run`, `channel` and `launcher`), and the VM goes on as that
/// run; standard input closing first discards it. A warm shim serves one run,
/// like any other: nothing of a run outlives it.
fn warm() -> i32 {
    let mut input = std::io::BufReader::new(std::io::stdin().lock());
    let machine = match spec_line(&mut input).and_then(|line| {
        let line = line.ok_or("no warm spec")?;
        Spec::parse_warm(&line)
    }) {
        Ok(machine) => machine,
        Err(error) => {
            tracing::error!("{error}");
            return 2;
        }
    };
    let (hold_read, hold_write) = match hold_pipe() {
        Ok(hold) => hold,
        Err(error) => {
            tracing::error!("{error}");
            return 1;
        }
    };
    let (mut child, channel, vm) = match start(&machine, Some(&hold_read)) {
        Ok(started) => started,
        Err(error) => {
            tracing::error!("{error}");
            return 1;
        }
    };
    drop(hold_read);
    tell_launcher("warm");
    let discard = |child: &mut std::process::Child| {
        let _ = child.kill();
        let _ = child.wait();
    };
    let mut claim = match spec_line(&mut input) {
        Ok(Some(claim)) => claim,
        Ok(None) => {
            discard(&mut child);
            return 0;
        }
        Err(error) => {
            tracing::error!("{error}");
            discard(&mut child);
            return 2;
        }
    };
    drop(input);
    let spec = Spec::claim(machine, &claim);
    // The claim carries the credential; keep only the parsed form.
    claim.fill(0);
    drop(claim);
    let spec = match spec {
        Ok(spec) => spec,
        Err(error) => {
            tracing::error!("{error}");
            discard(&mut child);
            return 2;
        }
    };
    let _span = run_span(&spec);
    let link = match bind_link(&spec) {
        Ok(link) => link,
        Err(code) => {
            discard(&mut child);
            return code;
        }
    };
    // Its launcher renamed the run's cgroup for the run before claiming it:
    // the VM's leaf is found again where the shim now is.
    let vm = own_cgroup()
        .ok()
        .and_then(|shim| shim.parent().map(|run| run.join("vm")))
        .unwrap_or(vm);
    // Closing the hold lets the guest go on as this run: now, or for a run
    // under the outbound byte limit once its first grant is in place.
    let hold = budget::wanted(&spec.machine.guest).then_some(hold_write);
    finish(&spec, Some(child), Some((channel, vm)), None, link, hold)
}

/// The root phase: cgroup leaves, descriptors, the VMM started, then the
/// shim itself dropped to the run's uid. With `hold`, the VMM holds its guest
/// until the other end of that pipe closes.
fn start(
    machine: &Machine,
    hold: Option<&OwnedFd>,
) -> Result<(std::process::Child, UnixStream, PathBuf)> {
    let spec = machine;
    let root = unsafe { libc::geteuid() } == 0;
    if root && spec.uid.is_none() {
        return Err("spec: uid and gid are required when started as root".into());
    }
    let runtime_dir = match &spec.runtime_dir {
        Some(dir) => dir.clone(),
        None => std::env::current_exe()
            .map_err(os("locating the shim"))?
            .parent()
            .ok_or("locating the shim")?
            .to_owned(),
    };
    let launch = runtime_dir.join("launch");
    let runtime =
        fs::File::open(runtime_dir.join("runtime.elf")).map_err(os("opening runtime.elf"))?;
    let component = fs::File::open(&spec.component).map_err(os("opening the component"))?;
    if let Some(expected) = &spec.component_sha256
        && &sha256_of(&component)? != expected
    {
        return Err("the component does not match its digest".into());
    }
    let env = environment(
        &fenders_node::guest_env::encode(&spec.guest)
            .map_err(|e| format!("guest environment: {}", e.message))?,
    )?;
    let (guest_end, shim_end) = UnixStream::pair().map_err(os("socketpair"))?;
    let mut pipe = [0; 2];
    check(
        unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) },
        "meter pipe",
    )?;
    let (meter_read, meter_write) =
        unsafe { (OwnedFd::from_raw_fd(pipe[0]), OwnedFd::from_raw_fd(pipe[1])) };
    let vm = cgroup_leaves(&own_cgroup()?, &spec.guest)?;

    let guest = &spec.guest;
    let list = |field: &str| -> Vec<String> {
        guest[field]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    };
    let tcp = list("tcp_allow");
    let mut ports: Vec<String> = tcp
        .iter()
        .filter_map(|a| a.rsplit_once(':').map(|(_, p)| p.to_owned()))
        .collect();
    let dns = guest["dns_server"].is_string();
    if dns {
        ports.push("53".into());
    }
    let mut command = Command::new("/proc/self/exe");
    command
        .arg("vmm")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("FENDERS_SHIM_PARENT", std::process::id().to_string())
        .env("FENDERS_SHIM_VM_CGROUP", &vm)
        .env("FENDERS_SHIM_LAUNCH", &launch)
        .env("FENDERS_SHIM_PORTS", ports.join(","))
        .env("FENDERS_SHIM_DNS", if dns { "1" } else { "0" })
        .env("FENDERS_SHIM_RUNTIME_FD", runtime.as_raw_fd().to_string())
        .env(
            "FENDERS_SHIM_COMPONENT_FD",
            component.as_raw_fd().to_string(),
        )
        .env("FENDERS_SHIM_ENV_FD", env.as_raw_fd().to_string())
        .env("FENDERS_HOST_ORIGIN_FD", guest_end.as_raw_fd().to_string())
        .env("FENDERS_METER_FD", meter_write.as_raw_fd().to_string())
        .env("FENDERS_TCP_ALLOW", tcp.join(","))
        .env(
            "FENDERS_DNS_SERVER",
            guest["dns_server"].as_str().unwrap_or("0.0.0.0"),
        )
        // The shim keeps the lifetime; the VMM keeps no alarm of its own.
        .env("FENDERS_LIFETIME_SECONDS", "0")
        .stdin(Stdio::null());
    // The guest's output goes nowhere unless the launch asked for it: then to
    // two pipes, with a third for the launcher's own messages.
    let captured = if output::wanted(guest) {
        let (pipes, vm_ends) = output::pipes()?;
        inheritable(vm_ends.diagnostics.as_raw_fd())?;
        command
            .env(
                "FENDERS_DIAGNOSTICS_FD",
                vm_ends.diagnostics.as_raw_fd().to_string(),
            )
            .stdout(Stdio::from(vm_ends.stdout))
            .stderr(Stdio::from(vm_ends.stderr));
        Some((pipes, vm_ends.diagnostics))
    } else {
        command.stdout(Stdio::null()).stderr(Stdio::null());
        None
    };
    // Under the outbound byte limit the VMM admits only granted bytes, and
    // is told its grants over a socket pair. No other launch has either.
    let control = if budget::wanted(guest) {
        let (vm_end, shim_end) = UnixStream::pair().map_err(os("control socketpair"))?;
        inheritable(vm_end.as_raw_fd())?;
        command
            .env("FENDERS_EGRESS_BUDGET", "1")
            .env("FENDERS_EGRESS_WAIT_MS", budget::WAIT_MS.to_string())
            .env("FENDERS_CONTROL_FD", vm_end.as_raw_fd().to_string());
        let launcher = sha256_of(&fs::File::open(&launch).map_err(os("opening launch"))?)?;
        Some((vm_end, shim_end, launcher))
    } else {
        None
    };
    // An HTTP run's guest serves requests on a socket pair only the shim
    // holds the other end of. No other launch has one.
    let ingress = if ingress::wanted(guest) {
        let (vm_end, shim_end) = UnixStream::pair().map_err(os("request socketpair"))?;
        inheritable(vm_end.as_raw_fd())?;
        command.env("FENDERS_INGRESS_FD", vm_end.as_raw_fd().to_string());
        Some((vm_end, shim_end))
    } else {
        None
    };
    if let Some(mib) = guest["guest_memory_mib"].as_i64() {
        command.env("FENDERS_GUEST_MEMORY_MIB", mib.to_string());
    }
    if let Some(cpu) = spec.cpu {
        command.env("FENDERS_VMM_CPU", cpu.to_string());
    }
    if let Some(hold) = hold {
        inheritable(hold.as_raw_fd())?;
        command.env("FENDERS_HOLD_FD", hold.as_raw_fd().to_string());
    }
    if let (true, Some(uid), Some(gid)) = (root, spec.uid, spec.gid) {
        command
            .env("FENDERS_SHIM_UID", uid.to_string())
            .env("FENDERS_SHIM_GID", gid.to_string());
        if let Some(kvm) = kvm_gid() {
            command.env("FENDERS_SHIM_KVM_GID", kvm.to_string());
        }
    }
    for fd in [
        runtime.as_raw_fd(),
        component.as_raw_fd(),
        env.as_raw_fd(),
        guest_end.as_raw_fd(),
        meter_write.as_raw_fd(),
    ] {
        inheritable(fd)?;
    }
    let mut child = command.spawn().map_err(os("starting the VMM"))?;
    // Only the VMM keeps the meter's write end, so the pipe ends with it.
    drop((runtime, component, env, guest_end, meter_write));
    if let Some((pipes, vm_diagnostics)) = captured {
        // Only the VMM keeps the pipes' write ends, so they end with it.
        drop(vm_diagnostics);
        if let Ok(mut slot) = OUTPUT.lock() {
            *slot = Some(pipes);
        }
    }
    if let Ok(mut slot) = METER.lock() {
        *slot = Some(meter_read);
    }
    if let Some((vm_end, shim_end, launcher)) = control {
        // Only the VMM keeps its end, so the socket ends with it.
        drop(vm_end);
        if let Ok(mut slot) = CONTROL.lock() {
            *slot = Some((shim_end, launcher));
        }
    }
    if let Some((vm_end, shim_end)) = ingress {
        // Only the VMM keeps its end, so the stream ends with it.
        drop(vm_end);
        if let Ok(mut slot) = INGRESS.lock() {
            *slot = Some(shim_end);
        }
    }
    if let Err(error) = unprivileged(spec) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }
    Ok((child, shim_end, vm))
}

/// The unprivileged phase: relay the guest's calls until the VMM exits, then
/// end the run with a failed outcome if the guest did not post one.
fn finish(
    spec: &Spec,
    child: Option<std::process::Child>,
    started: Option<(UnixStream, PathBuf)>,
    start_error: Option<String>,
    link: Option<(std::os::unix::net::UnixListener, Arc<link::Link>)>,
    hold: Option<OwnedFd>,
) -> i32 {
    // From here the shim relays for the guest and reports for the run: it
    // is confined to that before it starts a thread or reads anything the
    // guest sent.
    if let Err(error) = confine(spec) {
        tracing::error!("{error}");
        if let Some(mut child) = child {
            let _ = child.kill();
            let _ = child.wait();
        }
        return 1;
    }
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            tracing::error!(%error, "starting the runtime failed");
            return 1;
        }
    };
    runtime.block_on(async move {
        let link = link.map(|(listener, link)| {
            tokio::spawn(link::serve(listener, link.clone()));
            link
        });
        let relay = match upstream::Upstream::new(&spec.channel) {
            Ok(upstream) => Arc::new(relay::Relay {
                upstream,
                trace_id: spec
                    .run
                    .trace_id
                    .as_deref()
                    .and_then(|t| HeaderValue::from_str(t).ok()),
                outcome_posted: Default::default(),
            }),
            Err(error) => {
                tracing::error!("{error}");
                if let Some(mut child) = child {
                    let _ = child.kill();
                    let _ = child.wait();
                }
                return 1;
            }
        };
        let mut egress = Value::Null;
        let end = match (child, started) {
            (Some(child), Some((channel, vm))) => {
                let (limit, limit_meter) = match limit_outbound(&relay, hold) {
                    Some((limit, meter, launcher)) => {
                        // Its status names the launcher admitting its bytes.
                        if let Some(link) = &link {
                            link.update(|status| {
                                status.insert("egress_launcher".into(), json!(launcher));
                            });
                        }
                        (Some(limit), Some(meter))
                    }
                    None => (None, None),
                };
                let meter = read_meter(link.clone(), limit_meter);
                let captured = capture_output(spec, &relay);
                let requests = serve_requests(spec, &relay);
                if let Some(link) = &link {
                    link.update(|status| {
                        status.insert("state".into(), json!("running"));
                        status.insert("started".into(), json!(unix_now()));
                        status.insert(
                            "cgroup".into(),
                            json!(vm.parent().map(|p| p.to_string_lossy().into_owned())),
                        );
                    });
                }
                let limited = limit.is_some();
                let (mut end, sent) = supervise(
                    spec,
                    child,
                    channel,
                    &vm,
                    relay.clone(),
                    link.clone(),
                    limit,
                    requests,
                )
                .await;
                if let Some(captured) = captured {
                    close_output(captured).await;
                }
                if let Some(meter) = meter {
                    egress = tokio::task::spawn_blocking(move || meter.join().unwrap_or_default())
                        .await
                        .map(|line| meter_report(&line))
                        .unwrap_or(Value::Null);
                }
                // A VM that was killed wrote no last meter line; its total
                // is the one read as its authority to send was taken away.
                if let (Some(sent), true) = (sent, egress.is_object()) {
                    egress["bytes"] = json!(sent);
                    egress["in_flight"] = json!(0);
                    egress["complete"] = json!(true);
                }
                // A guest that failed after the launcher refused it a write
                // failed for the limit, though it ended before the shim
                // ended it.
                if limited
                    && end.code == "GUEST_FAILED"
                    && let Some(stop) =
                        budget::Stop::of(egress["refusals"].as_u64().unwrap_or(0), false)
                {
                    end.code = stop.code();
                    end.reason = stop.reason().to_owned();
                }
                end
            }
            _ => End {
                state: "failed",
                code: "LAUNCH_FAILED",
                reason: format!(
                    "the run could not be started: {}",
                    start_error.unwrap_or_default()
                ),
                category: "permanent",
                exit_code: None,
                signal: None,
            },
        };
        let guest_outcome = relay.outcome_posted.load(Ordering::SeqCst);
        let outcome = if guest_outcome {
            "guest"
        } else if post_failed(spec, &relay, &end).await {
            "host"
        } else {
            "none"
        };
        // A run whose guest posted its outcome ended as the guest said; the
        // VMM's exit is only reported.
        let (state, reason) = if guest_outcome && end.code == "NO_OUTCOME" {
            ("exited", None)
        } else {
            (end.state, Some(end.reason.as_str()))
        };
        let report = json!({
            "execution": spec.run.execution,
            "generation": spec.run.generation,
            "state": state,
            "reason": reason,
            "code": if guest_outcome { None } else { Some(end.code) },
            "exit_code": end.exit_code,
            "signal": end.signal,
            "outcome": outcome,
            "egress": egress,
        });
        tracing::info!(
            state,
            reason,
            code = report["code"].as_str(),
            exit_code = end.exit_code,
            signal = end.signal,
            outcome,
            "run ended"
        );
        // Its launcher hears the run ended at once, on the shim's stdout.
        tell_launcher("ended");
        if let Some(link) = &link {
            link.update(|status| {
                for (field, value) in report.as_object().into_iter().flatten() {
                    if field != "execution"
                        && field != "generation"
                        && !(field == "egress" && value.is_null())
                    {
                        status.insert(field.clone(), value.clone());
                    }
                }
                status.insert("finished".into(), json!(unix_now()));
            });
            // Held until the launcher has the end report.
            link.collected().await;
        }
        if guest_outcome { 0 } else { 1 }
    })
}

#[allow(clippy::too_many_arguments)]
async fn supervise(
    spec: &Spec,
    child: std::process::Child,
    channel: UnixStream,
    vm: &Path,
    relay: Arc<relay::Relay>,
    link: Option<Arc<link::Link>>,
    limit: Option<Limit>,
    requests: Option<tokio::task::JoinHandle<Option<ingress::Stop>>>,
) -> (End, Option<u64>) {
    use std::os::unix::process::ExitStatusExt;
    if channel.set_nonblocking(true).is_ok()
        && let Ok(stream) = tokio::net::UnixStream::from_std(channel)
    {
        tokio::spawn(relay::serve(stream, relay.clone()));
    }
    let pid = child.id() as libc::pid_t;
    // The VMM's exit, collected on a blocking thread: waitid needs no SIGCHLD
    // handling and the std child is not tokio's.
    let mut waited = tokio::task::spawn_blocking(move || {
        let mut child = child;
        child.wait()
    });
    let lifetime = Duration::from_secs(
        spec.machine.guest["lifetime_seconds"]
            .as_u64()
            .unwrap_or(300),
    );
    let mut terminate =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
    let mut interrupt =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()).ok();
    let kill = || unsafe {
        libc::kill(pid, libc::SIGKILL);
    };
    let mut stopped = None;
    let mut limit = limit;
    // Under the outbound byte limit, a VM about to be killed first loses its
    // authority to send and has its total read ([`budget::close`]).
    let control = limit.as_ref().map(|limit| limit.control.clone());
    let close = || async {
        match &control {
            Some(control) => control.close().await,
            None => None,
        }
    };
    let mut sent = None;
    let mut requests = requests;
    let status = tokio::select! {
        status = &mut waited => status,
        // An HTTP run whose endpoint will never give it a request. Its task
        // ending for any other reason (the guest closed its stream) is the
        // VMM's exit, which is waited for above.
        stop = async { match requests.as_mut() { Some(task) => match task.await { Ok(Some(stop)) => stop, _ => std::future::pending().await }, None => std::future::pending().await } } => {
            sent = close().await;
            kill();
            stopped = Some((stop.code(), "permanent", stop.reason().to_owned()));
            (&mut waited).await
        }
        stop = async { match limit.as_mut() { Some(limit) => (&mut limit.task).await.ok(), None => std::future::pending().await } } => {
            sent = close().await;
            kill();
            if let Some(stop) = stop {
                stopped = Some((stop.code(), "permanent", stop.reason().to_owned()));
            }
            (&mut waited).await
        }
        _ = tokio::time::sleep(lifetime) => {
            sent = close().await;
            kill();
            stopped = Some(("LIFETIME_EXCEEDED", "timeout", format!("the run reached its lifetime limit of {}s", lifetime.as_secs())));
            (&mut waited).await
        }
        _ = async { match terminate.as_mut() { Some(s) => { s.recv().await; } None => std::future::pending().await } } => {
            sent = close().await;
            kill();
            stopped = Some(("STOPPED", "permanent", "the run was stopped by its launcher".to_owned()));
            (&mut waited).await
        }
        _ = async { match &link { Some(link) => link.stop.notified().await, None => std::future::pending().await } } => {
            sent = close().await;
            kill();
            stopped = Some(("STOPPED", "permanent", "the run was stopped by its launcher".to_owned()));
            (&mut waited).await
        }
        _ = async { match interrupt.as_mut() { Some(s) => { s.recv().await; } None => std::future::pending().await } } => {
            sent = close().await;
            kill();
            stopped = Some(("STOPPED", "permanent", "the run was stopped by its launcher".to_owned()));
            (&mut waited).await
        }
    };
    if let Some(limit) = limit {
        limit.task.abort();
    }
    if let Some(requests) = requests {
        requests.abort();
    }
    let status = status.ok().and_then(|s| s.ok());
    let exit_code = status.and_then(|s| s.code());
    let signal = status.and_then(|s| s.signal());
    let oom = fs::read_to_string(vm.join("memory.events"))
        .ok()
        .and_then(|events| {
            events.lines().find_map(|l| {
                l.strip_prefix("oom_kill ")
                    .and_then(|n| n.trim().parse::<u64>().ok())
            })
        })
        .is_some_and(|n| n > 0);
    let (state, code, category, reason) = if let Some((code, category, reason)) = stopped {
        (
            if code == "STOPPED" {
                "stopped"
            } else {
                "failed"
            },
            code,
            category,
            reason,
        )
    } else if oom {
        (
            "failed",
            "OUT_OF_MEMORY",
            "permanent",
            "the run ran out of memory".to_owned(),
        )
    } else if let Some(signal) = signal {
        (
            "failed",
            "GUEST_KILLED",
            "permanent",
            format!("the VMM was killed by signal {signal}"),
        )
    } else if exit_code == Some(0) {
        (
            "exited",
            "NO_OUTCOME",
            "permanent",
            "the guest exited without posting an outcome".to_owned(),
        )
    } else if exit_code == Some(2) {
        (
            "failed",
            "LAUNCH_FAILED",
            "permanent",
            "the VMM refused the run's configuration (exit 2)".to_owned(),
        )
    } else {
        (
            "failed",
            "GUEST_FAILED",
            "permanent",
            format!(
                "the guest trapped or failed before posting an outcome (exit {})",
                exit_code.map_or("unknown".into(), |c| c.to_string())
            ),
        )
    };
    (
        End {
            state,
            code,
            reason,
            category,
            exit_code,
            signal,
        },
        sent,
    )
}

/// Starts pulling an HTTP run's requests ([`ingress`]): `None` for any other
/// launch.
fn serve_requests(
    spec: &Spec,
    relay: &Arc<relay::Relay>,
) -> Option<tokio::task::JoinHandle<Option<ingress::Stop>>> {
    let stream = INGRESS.lock().ok()?.take()?;
    stream.set_nonblocking(true).ok()?;
    let stream = tokio::net::UnixStream::from_std(stream).ok()?;
    let guest = &spec.machine.guest;
    let slots = guest["http_concurrency"].as_u64().unwrap_or(1) as usize;
    let timeout = Duration::from_millis(guest["request_timeout_ms"].as_u64().unwrap_or(10_000));
    Some(tokio::spawn(ingress::serve(
        stream,
        relay.clone(),
        slots,
        timeout,
    )))
}

/// The control socket of a VM under the outbound byte limit: one command at
/// a time, a line each way.
struct Control {
    /// The socket, and how many answers are still owed to commands that
    /// stopped waiting for theirs.
    socket: tokio::sync::Mutex<(tokio::io::BufReader<tokio::net::UnixStream>, usize)>,
    /// Set once the run is ending: no grant is passed on after that.
    closing: std::sync::atomic::AtomicBool,
}

impl Control {
    /// Sends `command` and gives the launcher's status, unless it names an
    /// error. A grant (`closing` false) is not sent once the run is ending.
    async fn command(&self, command: &str, closing: bool) -> std::result::Result<Value, String> {
        use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
        let mut held = self.socket.lock().await;
        if !closing && self.closing.load(Ordering::SeqCst) {
            return Err("the run is ending".into());
        }
        let (socket, owed) = &mut *held;
        // Answers come in the order of their commands. One that arrives
        // after its command stopped waiting is that command's, not the next
        // one's: it is read past here, never taken for this command's.
        let exchange = async {
            socket.get_mut().write_all(command.as_bytes()).await?;
            loop {
                let mut line = Vec::new();
                let read = (&mut *socket)
                    .take(MAX_LAUNCHER_LINE as u64 + 1)
                    .read_until(b'\n', &mut line)
                    .await?;
                if read == 0 {
                    return Err(std::io::ErrorKind::UnexpectedEof.into());
                }
                if line.last() != Some(&b'\n') {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "the launcher's answer was too long",
                    ));
                }
                if *owed == 0 {
                    return Ok::<_, std::io::Error>(line);
                }
                *owed -= 1;
            }
        };
        match tokio::time::timeout(Duration::from_secs(2), exchange).await {
            Ok(Ok(line)) => budget::applied(&line),
            Ok(Err(error)) => Err(error.to_string()),
            Err(_) => {
                *owed += 1;
                Err("the launcher did not answer".into())
            }
        }
    }

    /// Takes the VM's authority to send away and reads its total
    /// ([`budget::close`]).
    async fn close(&self) -> Option<u64> {
        self.closing.store(true, Ordering::SeqCst);
        budget::close(|command| async move { self.command(&command, true).await }).await
    }
}

/// A launch's outbound byte limit: the task keeping its VM's allowance
/// granted, which ends when the run must end for the limit, and the VM's
/// control socket.
struct Limit {
    task: tokio::task::JoinHandle<budget::Stop>,
    control: Arc<Control>,
}

/// For a launch under the outbound byte limit: its [`Limit`]
/// ([`budget::enforce`]) and where that reads the VM's meter. `None` for any
/// other launch, whose `hold` (there is none) is dropped.
fn limit_outbound(
    relay: &Arc<relay::Relay>,
    hold: Option<OwnedFd>,
) -> Option<(Limit, tokio::sync::watch::Sender<budget::Meter>, String)> {
    let (control, launcher) = CONTROL.lock().ok()?.take()?;
    control.set_nonblocking(true).ok()?;
    let control = Arc::new(Control {
        socket: tokio::sync::Mutex::new((
            tokio::io::BufReader::new(tokio::net::UnixStream::from_std(control).ok()?),
            0,
        )),
        closing: Default::default(),
    });
    let (meter, seen) = tokio::sync::watch::channel(budget::Meter::default());
    let relay = relay.clone();
    // Distinct from any other shim's asks for this run.
    let id = format!("{:x}-{:x}", std::process::id(), budget::boottime_ns());
    let ask = move |body: Value| {
        let relay = relay.clone();
        async move {
            let mut headers = HeaderMap::new();
            headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            let sent = tokio::time::timeout(
                Duration::from_secs(5),
                relay.send(
                    &Method::POST,
                    budget::PATH,
                    headers,
                    Bytes::from(body.to_string()),
                ),
            )
            .await;
            match sent {
                Ok(Ok((code, _, body))) => {
                    if !code.is_success() && code.as_u16() != 429 {
                        tracing::warn!(status = code.as_u16(), "the endpoint gave no grant");
                    }
                    budget::answer(code.as_u16(), &body)
                }
                _ => budget::Answer::Retry,
            }
        }
    };
    let granting = control.clone();
    let apply = move |revision: u64, deadline: u64, ceiling: u64| {
        let control = granting.clone();
        async move {
            control
                .command(&format!("egress {revision} {deadline} {ceiling}\n"), false)
                .await
                .map(|_| ())
        }
    };
    let task = tokio::spawn(async move {
        let stop = budget::enforce(&id, seen, ask, apply, move || drop(hold)).await;
        tracing::warn!(
            code = stop.code(),
            "the run is ended for its outbound byte limit"
        );
        stop
    });
    Some((Limit { task, control }, meter, launcher))
}

/// For a launch that asked for its output: the tasks delivering it to the run
/// channel and logging the launcher's own messages. `None` for any other.
fn capture_output(
    spec: &Spec,
    relay: &Arc<relay::Relay>,
) -> Option<(
    tokio::task::JoinHandle<output::Summary>,
    tokio::task::JoinHandle<()>,
)> {
    let pipes = OUTPUT.lock().ok()?.take()?;
    let (names, redactor) = output::redaction(&spec.machine.guest);
    let relay = relay.clone();
    let send = move |body: Bytes| {
        let relay = relay.clone();
        async move {
            let mut headers = HeaderMap::new();
            headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            match relay.send(&Method::POST, output::PATH, headers, body).await {
                Ok((code, _, _)) if code.is_success() => output::Sent::Accepted,
                // It does not serve output, or this launch may send none:
                // asking again would change nothing.
                Ok((code, _, _)) if code.is_client_error() || code.as_u16() == 501 => {
                    output::Sent::Refused(code.as_u16())
                }
                _ => output::Sent::Retry,
            }
        }
    };
    Some((
        tokio::spawn(output::capture(
            pipes.stdout,
            pipes.stderr,
            redactor,
            names,
            send,
        )),
        tokio::spawn(output::diagnostics(pipes.diagnostics)),
    ))
}

/// At the VM's exit: waits, within [`output::CLOSE_WAIT`], for the rest of
/// its output to be delivered, and logs what was not.
async fn close_output(
    (mut capture, diagnostics): (
        tokio::task::JoinHandle<output::Summary>,
        tokio::task::JoinHandle<()>,
    ),
) {
    match tokio::time::timeout(output::CLOSE_WAIT, &mut capture).await {
        Ok(Ok(summary)) => {
            if let Some(status) = summary.refused {
                tracing::warn!(status, "the endpoint refused the run's output");
            } else if summary.dropped > 0 {
                tracing::warn!(
                    dropped = summary.dropped,
                    delivered = summary.delivered,
                    "output was dropped unsent to stay within the memory bound"
                );
            }
        }
        _ => {
            capture.abort();
            tracing::warn!("the run's last output could not be delivered in time");
        }
    }
    let _ = tokio::time::timeout(Duration::from_secs(1), diagnostics).await;
}

/// Posts the run's failed outcome from the host side, with the run's
/// credential, retrying while the endpoint is unreachable or failing.
async fn post_failed(spec: &Spec, relay: &relay::Relay, end: &End) -> bool {
    let body = json!({
        "code": end.code,
        "message": end.reason,
        "category": end.category,
        "severity": "error",
        "retryable": false,
        "attributes": {
            "source": "fenders-shim",
            "exitCode": end.exit_code,
            "signal": end.signal,
        },
    });
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static("runtara-outcome"),
        HeaderValue::from_static("failed"),
    );
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    if let Ok(key) = HeaderValue::from_str(&format!(
        "fenders-shim-outcome-{}-{}",
        spec.run.execution, spec.run.generation
    )) {
        headers.insert(HeaderName::from_static("idempotency-key"), key);
    }
    let body = Bytes::from(body.to_string());
    for attempt in 0..4u32 {
        match relay
            .send(
                &Method::POST,
                relay::OUTCOME_PATH,
                headers.clone(),
                body.clone(),
            )
            .await
        {
            Ok((code, _, _)) if code.is_success() => return true,
            // The endpoint refused it for good (an outcome was already
            // posted, or the launch was fenced): nothing to retry.
            Ok((code, _, _)) if code.is_client_error() => {
                tracing::warn!(
                    code = code.as_u16(),
                    "the endpoint refused the run's failed outcome"
                );
                return false;
            }
            _ => tokio::time::sleep(Duration::from_secs(1 << attempt)).await,
        }
    }
    tracing::warn!("could not post the run's failed outcome");
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_vm_is_not_started_without_its_limits() {
        let guest = json!({"cpu_percent": 150, "host_memory_mib": 96});
        // A cgroup without the cpu controller: refused, nothing skipped.
        let partial = tempfile::tempdir().unwrap();
        fs::write(partial.path().join("cgroup.controllers"), "memory pids\n").unwrap();
        let refused = cgroup_leaves(partial.path(), &guest).unwrap_err();
        assert!(
            refused.contains("cpu, memory and pids are all required"),
            "{refused}"
        );
        assert!(!partial.path().join("vm").exists());

        // With all three, every limit is written to the VM's leaf.
        let whole = tempfile::tempdir().unwrap();
        fs::write(
            whole.path().join("cgroup.controllers"),
            "cpuset cpu io memory pids\n",
        )
        .unwrap();
        let vm = cgroup_leaves(whole.path(), &guest).unwrap();
        let read = |name: &str| fs::read_to_string(vm.join(name)).unwrap();
        assert_eq!(read("cpu.max"), "150000 100000");
        assert_eq!(read("memory.max"), (96 * 1024 * 1024).to_string());
        assert_eq!(read("memory.swap.max"), "0");
        assert_eq!(read("pids.max"), "16");
        assert_eq!(
            fs::read_to_string(whole.path().join("cgroup.subtree_control")).unwrap(),
            "+cpu +memory +pids"
        );

        // A second shim in the same cgroup is refused.
        assert!(cgroup_leaves(whole.path(), &guest).is_err());
    }

    #[test]
    fn a_line_from_the_vmm_is_read_up_to_a_bound() {
        let mut input = b"{\"bytes\":1}\n".to_vec();
        input.extend(std::iter::repeat_n(b'x', 3 * MAX_LAUNCHER_LINE + 7));
        input.extend_from_slice(b"\nnext\n");
        input.extend(std::iter::repeat_n(b'y', MAX_LAUNCHER_LINE));
        input.extend_from_slice(b"\n\xff\nlast");
        let mut reader = std::io::BufReader::with_capacity(64, &input[..]);
        let mut lines = Vec::new();
        while let Some(line) = launcher_line(&mut reader).unwrap() {
            lines.push(line.map(|line| line.len()));
        }
        // The first, the one over the bound (passed by), the next, one of
        // exactly the bound, one that is not text, and a last without newline.
        assert_eq!(
            lines,
            [
                Some(11),
                None,
                Some(4),
                Some(MAX_LAUNCHER_LINE),
                None,
                Some(4)
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_late_answer_from_the_launcher_is_not_taken_for_the_next_commands() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
        let (ours, theirs) = tokio::net::UnixStream::pair().unwrap();
        let control = Control {
            socket: tokio::sync::Mutex::new((tokio::io::BufReader::new(ours), 0)),
            closing: Default::default(),
        };
        // A launcher that answers its first command after the shim stopped
        // waiting, and the rest at once, each with the command it answers.
        let launcher = tokio::spawn(async move {
            let (read, mut write) = theirs.into_split();
            let mut commands = tokio::io::BufReader::new(read).lines();
            let mut first = true;
            while let Ok(Some(command)) = commands.next_line().await {
                if std::mem::take(&mut first) {
                    tokio::time::sleep(Duration::from_secs(3)).await;
                }
                let answer = format!("{{\"error\":null,\"answers\":\"{command}\"}}\n");
                if write.write_all(answer.as_bytes()).await.is_err() {
                    break;
                }
            }
        });
        assert_eq!(
            control.command("one\n", false).await.unwrap_err(),
            "the launcher did not answer"
        );
        // The answer to `one` arrives now. `two` gets its own.
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert_eq!(
            control.command("two\n", false).await.unwrap()["answers"],
            "two"
        );
        assert_eq!(
            control.command("three\n", false).await.unwrap()["answers"],
            "three"
        );
        // An answer longer than any is: refused, not held.
        launcher.abort();
        let (ours, mut theirs) = tokio::net::UnixStream::pair().unwrap();
        let control = Control {
            socket: tokio::sync::Mutex::new((tokio::io::BufReader::new(ours), 0)),
            closing: Default::default(),
        };
        let flood = tokio::spawn(async move {
            let _ = theirs.write_all(&vec![b'x'; 4 * MAX_LAUNCHER_LINE]).await;
            theirs
        });
        assert_eq!(
            control.command("status\n", false).await.unwrap_err(),
            "the launcher's answer was too long"
        );
        drop(flood);
    }

    #[test]
    fn the_meter_report_is_the_last_totals_and_complete_only_when_final() {
        assert_eq!(
            meter_report("final 12 0 1 0"),
            json!({"bytes":12,"in_flight":0,"refusals":0,"complete":true})
        );
        assert_eq!(meter_report("meter 12 0 1 0")["complete"], false);
        assert_eq!(meter_report("final 12 1 1 0")["complete"], false);
        assert!(meter_report("final 12 0 0 0").is_null());
        assert!(meter_report("").is_null());
    }
}
