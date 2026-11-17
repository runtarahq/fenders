//! Explicit staged-release selection and a stable systemd exec bootstrap.
//! Selection never stops an agent, starts a VM or reopens sealed admission.
use crate::{
    maintenance::{self, Mode, Snapshot},
    staging,
};
use axum::http::StatusCode;
use clap::Parser;
use fenders_node_protocol::{
    error::{Error, Result},
    model::{digest, identity},
};
use rusqlite::{Connection, OpenFlags, TransactionBehavior};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom},
    os::{
        fd::AsRawFd,
        unix::{
            fs::{MetadataExt, OpenOptionsExt},
            process::CommandExt,
        },
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

mod recovery;
#[cfg(test)]
mod tests;
const MAX_RECORD: u64 = 64 * 1024;
fn invalid() -> Error {
    Error::invalid("worker release selection unavailable or incompatible")
}
fn conflict() -> Error {
    Error::new(
        StatusCode::CONFLICT,
        "stale or conflicting worker release selection",
    )
}
fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Canonical paths prevent mutable parent aliases from changing the exec target.
/// Root-owned sticky ancestors permit private /tmp fixtures, not writable stores.
fn directory(path: &Path) -> Result<PathBuf> {
    if !fs::symlink_metadata(path)?.is_dir() {
        return Err(invalid());
    }
    let canonical = path.canonicalize()?;
    for ancestor in canonical.ancestors() {
        let m = fs::symlink_metadata(ancestor)?;
        if !m.is_dir()
            || ![0, unsafe { libc::geteuid() }].contains(&m.uid())
            || (m.mode() & 0o022 != 0 && !(m.uid() == 0 && m.mode() & 0o1000 != 0))
        {
            return Err(invalid());
        }
    }
    // The actual directory, unlike a shared sticky ancestor, is protected.
    let m = fs::metadata(&canonical)?;
    if m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o022 != 0 {
        return Err(invalid());
    }
    Ok(canonical)
}
fn record_path(path: &Path) -> Result<PathBuf> {
    let name = path.file_name().ok_or_else(invalid)?;
    Ok(directory(path.parent().ok_or_else(invalid)?)?.join(name))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Selection {
    schema: u32,
    state: PathBuf,
    manifest_sha256: String,
    source_epoch: i64,
    operation: String,
}
fn read(path: &Path) -> Result<Option<(Selection, String)>> {
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let m = file.metadata()?;
    if !m.is_file()
        || m.uid() != unsafe { libc::geteuid() }
        || m.nlink() != 1
        || m.mode() & 0o077 != 0
        || m.len() > MAX_RECORD
    {
        return Err(invalid());
    }
    let mut bytes = Vec::new();
    file.by_ref().take(MAX_RECORD + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_RECORD {
        return Err(invalid());
    }
    let selection: Selection = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    if selection.schema != 1
        || !selection.state.is_absolute()
        || !hash(&selection.manifest_sha256)
        || selection.source_epoch < 1
        || identity(&selection.operation).is_err()
    {
        return Err(invalid());
    }
    Ok(Some((selection, digest(bytes))))
}
fn selection_lock(path: &Path) -> Result<File> {
    let name = path
        .file_name()
        .ok_or_else(invalid)?
        .to_str()
        .ok_or_else(invalid)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path.with_file_name(format!(".{name}.lock")))?;
    let m = file.metadata()?;
    if !m.is_file()
        || m.uid() != unsafe { libc::geteuid() }
        || m.nlink() != 1
        || m.mode() & 0o077 != 0
    {
        return Err(invalid());
    }
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(conflict());
    }
    Ok(file)
}
#[derive(Parser)]
#[command(
    name = "fenders-node release-select",
    about = "Select a verified staged release under sealed admission; does not restart or resume"
)]
struct SelectArgs {
    #[arg(long)]
    state: PathBuf,
    #[arg(long)]
    releases: PathBuf,
    #[arg(long)]
    selection: PathBuf,
    #[arg(long)]
    manifest_sha256: String,
    #[arg(long,value_parser=clap::value_parser!(i64).range(1..))]
    maintenance_epoch: i64,
    #[arg(long)]
    maintenance_operation: String,
    #[arg(
        long,
        required_unless_present = "expect_unselected",
        conflicts_with = "expect_unselected"
    )]
    expected_selection_sha256: Option<String>,
    #[arg(long)]
    expect_unselected: bool,
}

/// A short writer transaction excludes ownership changes during pointer commit.
/// It modifies no journal rows and always rolls back its coordination transaction.
fn fenced<T>(state: &Path, expected: &Snapshot, publish: impl FnOnce() -> Result<T>) -> Result<T> {
    let state = directory(state)?;
    let mut db = Connection::open_with_flags(
        state.join("agent/agent.sqlite3"),
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|_| invalid())?;
    db.busy_timeout(Duration::from_millis(250))
        .map_err(|_| invalid())?;
    let tx = db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| conflict())?;
    if maintenance::read(&tx)? != *expected {
        return Err(conflict());
    }
    let result = publish();
    tx.rollback().map_err(|_| invalid())?;
    result
}
fn select_with(
    args: &SelectArgs,
    check: impl FnOnce(&staging::Receipt, &Snapshot) -> Result<Value>,
) -> Result<Value> {
    if !hash(&args.manifest_sha256)
        || args.maintenance_epoch < 1
        || identity(&args.maintenance_operation).is_err()
        || args
            .expected_selection_sha256
            .as_ref()
            .is_some_and(|v| !hash(v))
        || args.expect_unselected == args.expected_selection_sha256.is_some()
    {
        return Err(invalid());
    }
    let state = directory(&args.state)?;
    let store = directory(&args.releases)?;
    let target = staging::retained(&store, &args.manifest_sha256)?;
    target.release.validate_management()?;
    let path = record_path(&args.selection)?;
    let _lock = selection_lock(&path)?;
    let old = read(&path)?;
    let desired = Selection {
        schema: 1,
        state: state.clone(),
        manifest_sha256: args.manifest_sha256.clone(),
        source_epoch: args.maintenance_epoch,
        operation: args.maintenance_operation.clone(),
    };
    let value = serde_json::to_value(&desired).map_err(|_| invalid())?;
    let selected_hash = digest(serde_json::to_vec(&value).map_err(|_| invalid())?);
    let receipt = |changed| {
        json!({"schema":1,"selection_sha256":selected_hash,"selected":desired,
        "path":target.path,"changed":changed,"activation_verified":false,"admission_resumed":false})
    };
    if old
        .as_ref()
        .is_some_and(|(selection, _)| *selection == desired)
    {
        // Read-only retry, including after a replacement has advanced the epoch.
        return Ok(receipt(false));
    }
    if old.as_ref().map(|(_, pin)| pin) != args.expected_selection_sha256.as_ref() {
        return Err(conflict());
    }
    let snapshot = crate::upgrade::management(&state)?;
    if snapshot.mode != Mode::Sealed
        || snapshot.epoch != args.maintenance_epoch
        || snapshot.operation.as_deref() != Some(&args.maintenance_operation)
        || snapshot.candidate_sha256.as_deref() != Some(&target.release.agent_sha256)
    {
        return Err(conflict());
    }
    let report = check(&target, &snapshot)?;
    validate_report(&report, &target, &snapshot, false)?;
    // Recheck retained bytes after executing the candidate's read-only preflight.
    staging::retained(&store, &args.manifest_sha256)?;
    fenced(&state, &snapshot, || {
        if read(&path)? != old {
            return Err(conflict());
        }
        crate::durable::atomic_json(&path, &value)?;
        Ok(receipt(true))
    })
}

fn validate_report(
    report: &Value,
    target: &staging::Receipt,
    snapshot: &Snapshot,
    unbound: bool,
) -> Result<()> {
    let checked = report["checked_execution_ids"]
        .as_array()
        .filter(|ids| ids.len() <= 256)
        .ok_or_else(invalid)?;
    let mut ids = std::collections::BTreeSet::new();
    for id in checked {
        let id = id.as_str().ok_or_else(invalid)?;
        identity(id)?;
        if !ids.insert(id) {
            return Err(invalid());
        }
    }
    if report["schema"] != 1
        || report["terminal_executions"]
            .as_u64()
            .is_none_or(|n| n > 100_000)
        || report["candidate"] != serde_json::to_value(&target.release).map_err(|_| invalid())?
        || report["maintenance"] != serde_json::to_value(snapshot).map_err(|_| invalid())?
        || report["admission_quiescence_required"] != unbound
        || report["rollout_authorized"] != false
    {
        return Err(invalid());
    }
    Ok(())
}

fn candidate_preflight(
    target: &staging::Receipt,
    state: &Path,
    snapshot: Option<&Snapshot>,
) -> Result<Value> {
    let mut stdout = tempfile::tempfile()?;
    let stderr = tempfile::tempfile()?;
    let mut command = Command::new(target.path.join("fenders-node"));
    command
        .arg("upgrade-preflight")
        .arg("--state")
        .arg(state)
        .arg("--build")
        .arg(&target.path)
        .arg("--expected-agent-sha256")
        .arg(&target.release.agent_sha256)
        .env_remove("LISTEN_PID")
        .env_remove("LISTEN_FDS")
        .env_remove("LISTEN_FDNAMES")
        .stdin(Stdio::null())
        .stdout(stdout.try_clone()?)
        .stderr(stderr);
    if let Some(snapshot) = snapshot {
        command
            .arg("--maintenance-epoch")
            .arg(snapshot.epoch.to_string())
            .arg("--maintenance-operation")
            .arg(snapshot.operation.as_ref().ok_or_else(invalid)?);
    }
    #[cfg(target_os = "linux")]
    let parent = std::process::id() as libc::pid_t;
    unsafe {
        command.pre_exec(move || {
            #[cfg(target_os = "linux")]
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0
                || libc::getppid() != parent
            {
                return Err(std::io::Error::other("preflight parent unavailable"));
            }
            let limit = libc::rlimit {
                rlim_cur: MAX_RECORD,
                rlim_max: MAX_RECORD,
            };
            if libc::setrlimit(libc::RLIMIT_FSIZE, &limit) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn()?;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let status = match child.try_wait() {
            Ok(status) => status,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error.into());
            }
        };
        if let Some(status) = status {
            if !status.success() {
                return Err(invalid());
            }
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(invalid());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    stdout.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    stdout.take(MAX_RECORD + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_RECORD {
        return Err(invalid());
    }
    serde_json::from_slice(&bytes).map_err(|_| invalid())
}

#[derive(Parser)]
#[command(
    name = "fenders-node service-run",
    about = "Verify a selected staged release and exec its worker agent"
)]
struct RunArgs {
    #[arg(long)]
    state: PathBuf,
    #[arg(long)]
    releases: PathBuf,
    #[arg(long)]
    selection: PathBuf,
    #[arg(long)]
    package_build: PathBuf,
    #[arg(last = true, required = true)]
    agent_args: Vec<OsString>,
}
struct Plan {
    executable: PathBuf,
    state: PathBuf,
    build: PathBuf,
}
fn plan(args: &RunArgs, bootstrap: &Path) -> Result<Plan> {
    if args.agent_args.iter().any(|a| {
        let a = a.to_string_lossy();
        a == "--build" || a.starts_with("--build=") || a == "--state" || a.starts_with("--state=")
    }) {
        return Err(invalid());
    }
    let state = match fs::symlink_metadata(&args.state) {
        Ok(_) => directory(&args.state)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => record_path(&args.state)?,
        Err(error) => return Err(error.into()),
    };
    let selection = read(&record_path(&args.selection)?)?;
    if let Some((selection, _)) = selection {
        if selection.state != state {
            return Err(conflict());
        }
        let store = directory(&args.releases)?;
        let target = staging::retained(&store, &selection.manifest_sha256)?;
        target.release.validate_management()?;
        // A recovery intent commits before its pointer. A crash between those
        // writes must never execute the stale selected candidate.
        let snapshot = crate::upgrade::management(&state)?;
        if snapshot
            .candidate_sha256
            .as_deref()
            .is_some_and(|pin| pin != target.release.agent_sha256)
        {
            return Err(conflict());
        }
        Ok(Plan {
            executable: target.path.join("fenders-node"),
            state,
            build: target.path,
        })
    } else {
        // Preserve ordinary package startup until coordinated selection is opted in.
        Ok(Plan {
            executable: bootstrap.to_owned(),
            state,
            build: directory(&args.package_build)?,
        })
    }
}
pub fn dispatch(args: &[String]) -> Option<Result<()>> {
    let mode = args.get(1)?.as_str();
    if !matches!(mode, "release-select" | "release-recover" | "service-run") {
        return None;
    }
    Some((|| {
        fn parse<T: Parser>(args: &[String]) -> Result<Option<T>> {
            match T::try_parse_from(&args[1..]) {
                Ok(value) => Ok(Some(value)),
                Err(error) if error.kind() == clap::error::ErrorKind::DisplayHelp => {
                    print!("{error}");
                    Ok(None)
                }
                Err(_) => Err(invalid()),
            }
        }
        if mode == "release-recover" {
            let Some(args) = parse::<recovery::Args>(args)? else {
                return Ok(());
            };
            if !cfg!(target_os = "linux") || unsafe { libc::geteuid() } != 0 {
                return Err(invalid());
            }
            let report = recovery::recover_with(
                &args,
                &crate::release::file_digest(&std::env::current_exe()?)?,
                |target, _| candidate_preflight(target, &args.state, None),
                crate::durable::atomic_json,
            )?;
            println!(
                "{}",
                serde_json::to_string_pretty(&report).map_err(|_| invalid())?
            );
            Ok(())
        } else if mode == "release-select" {
            let Some(args) = parse::<SelectArgs>(args)? else {
                return Ok(());
            };
            if !cfg!(target_os = "linux") || unsafe { libc::geteuid() } != 0 {
                return Err(invalid());
            }
            let report = select_with(&args, |target, snapshot| {
                candidate_preflight(target, &args.state, Some(snapshot))
            })?;
            println!(
                "{}",
                serde_json::to_string_pretty(&report).map_err(|_| invalid())?
            );
            Ok(())
        } else {
            let Some(args) = parse::<RunArgs>(args)? else {
                return Ok(());
            };
            if !cfg!(target_os = "linux") || unsafe { libc::geteuid() } != 0 {
                return Err(invalid());
            }
            let plan = plan(&args, &std::env::current_exe()?)?;
            // exec preserves systemd's PID and listener descriptor. Only the agent
            // adopts the listener; normal CLOEXEC file handles never reach it.
            Err(Command::new(plan.executable)
                .arg("--state")
                .arg(plan.state)
                .arg("--build")
                .arg(plan.build)
                .args(args.agent_args)
                .exec()
                .into())
        }
    })())
}
