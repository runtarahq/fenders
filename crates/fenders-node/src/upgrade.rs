//! Candidate-side checks before disturbing the current agent. Never initialize
//! Node/Agent here: startup performs reconciliation and journal writes.
use crate::{
    maintenance::{self, Mode, Snapshot},
    release::WorkerRelease,
};
use clap::Parser;
use fenders_node_protocol::{
    error::{Error, Result},
    model::identity,
};
use rusqlite::{Connection, OpenFlags};
use serde::Serialize;
use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

fn invalid() -> Error {
    // Configurations contain credentials. Never include paths, SQL or payloads.
    Error::invalid("upgrade preflight metadata unavailable or incompatible")
}
fn directory(path: &Path) -> Result<()> {
    if !fs::symlink_metadata(path).map_err(|_| invalid())?.is_dir() {
        return Err(invalid());
    }
    Ok(())
}

fn journal(path: &Path, max_version: i64) -> Result<Connection> {
    // Resolve operator-supplied parent aliases (macOS /var, for example), but
    // leave the database name unresolved so NOFOLLOW still guards the file.
    let path = path
        .parent()
        .ok_or_else(invalid)?
        .canonicalize()
        .map_err(|_| invalid())?
        .join(path.file_name().ok_or_else(invalid)?);
    for suffix in ["", "-wal", "-shm"] {
        let mut sidecar = path.as_os_str().to_owned();
        sidecar.push(suffix);
        let path = PathBuf::from(sidecar);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_file() => (),
            Err(error) if !suffix.is_empty() && error.kind() == std::io::ErrorKind::NotFound => (),
            _ => return Err(invalid()),
        }
    }
    let db = Connection::open_with_flags(
        &path,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|_| invalid())?;
    db.busy_timeout(Duration::from_millis(250))
        .map_err(|_| invalid())?;
    let version: i64 = db
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|_| invalid())?;
    // Existing journals have no version marker; do not accept an unknown future one.
    if !(0..=max_version).contains(&version) {
        return Err(invalid());
    }
    Ok(db)
}

fn agent_journal(state: &Path) -> Result<Option<Snapshot>> {
    let db = journal(&state.join("agent.sqlite3"), maintenance::JOURNAL_VERSION)?;
    db.prepare(
        "SELECT id,generation,backend_id,sequence,error,archived,terminal,action_generation FROM assignments LIMIT 0",
    )
    .map_err(|_| invalid())?;
    let version: i64 = db
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|_| invalid())?;
    if version == 0 {
        let exists: bool = db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='agent_management')",
                [],
                |row| row.get(0),
            )
            .map_err(|_| invalid())?;
        if exists {
            return Err(invalid());
        }
        Ok(None)
    } else {
        Ok(Some(maintenance::read(&db)?))
    }
}

pub(crate) fn management(state: &Path) -> Result<Snapshot> {
    directory(&state.join("agent"))?;
    agent_journal(&state.join("agent"))?.ok_or_else(invalid)
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub schema: u32,
    pub candidate: WorkerRelease,
    pub checked_execution_ids: Vec<String>,
    pub terminal_executions: usize,
    pub admission_quiescence_required: bool,
    pub rollout_authorized: bool,
    pub maintenance: Option<Snapshot>,
}

/// Read-only compatibility observation. Admission can change after this returns;
/// a rollout must quiesce it and recheck under exclusive management ownership.
pub fn preflight(
    state: &Path,
    build: &Path,
    executable: &Path,
    expected_agent: &str,
) -> Result<Report> {
    preflight_bound(state, build, executable, expected_agent, None)
}

pub fn preflight_bound(
    state: &Path,
    build: &Path,
    executable: &Path,
    expected_agent: &str,
    required: Option<(i64, &str)>,
) -> Result<Report> {
    let candidate = WorkerRelease::capture(build, executable)?;
    candidate.validate()?;
    if candidate.agent_sha256 != expected_agent {
        return Err(Error::invalid(
            "upgrade candidate hash does not match staged release",
        ));
    }
    for path in [state.to_owned(), state.join("node"), state.join("agent")] {
        directory(&path)?;
    }
    let management = agent_journal(&state.join("agent"))?;
    if let Some((epoch, operation)) = required {
        identity(operation)?;
        if !management.as_ref().is_some_and(|snapshot| {
            snapshot.epoch == epoch
                && snapshot.mode == Mode::Sealed
                && snapshot.operation.as_deref() == Some(operation)
                && snapshot.candidate_sha256.as_deref() == Some(expected_agent)
        }) {
            return Err(Error::invalid(
                "candidate preflight requires its sealed source epoch and operation",
            ));
        }
    }
    // Runs are shims, each with its own shim and launch binaries: a new
    // agent applies to new runs only, and no running one needs checking.
    if agent_journal(&state.join("agent"))? != management {
        return Err(invalid());
    }
    let (checked, finished): (Vec<String>, usize) = (Vec::new(), 0);
    Ok(Report {
        schema: 1,
        candidate,
        checked_execution_ids: checked,
        terminal_executions: finished,
        admission_quiescence_required: required.is_none(),
        rollout_authorized: false,
        maintenance: management,
    })
}

#[derive(Parser)]
#[command(
    name = "fenders-node upgrade-preflight",
    about = "Read-only candidate compatibility checks; does not authorize cutover"
)]
struct Args {
    #[arg(long)]
    state: PathBuf,
    #[arg(long)]
    build: PathBuf,
    #[arg(long)]
    expected_agent_sha256: String,
    #[arg(long,requires="maintenance_operation",value_parser=clap::value_parser!(i64).range(1..))]
    maintenance_epoch: Option<i64>,
    #[arg(long, requires = "maintenance_epoch")]
    maintenance_operation: Option<String>,
}
pub fn dispatch(args: &[String]) -> Option<Result<()>> {
    if args.get(1).map(String::as_str) != Some("upgrade-preflight") {
        return None;
    }
    Some((|| {
        let args = Args::try_parse_from(&args[1..]).map_err(|_| {
            Error::invalid("upgrade-preflight requires state, build and expected agent hash")
        })?;
        let report = preflight_bound(
            &args.state,
            &args.build,
            &std::env::current_exe()?,
            &args.expected_agent_sha256,
            args.maintenance_epoch
                .zip(args.maintenance_operation.as_deref()),
        )?;
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|_| Error::internal())?
        );
        Ok(())
    })())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fenders_node_protocol::model::uid;
    use serde_json::json;
    use std::{collections::BTreeMap, os::unix::fs::symlink};

    struct Fixture {
        _root: tempfile::TempDir,
        state: PathBuf,
        retained: PathBuf,
        candidate: PathBuf,
        id: String,
    }
    impl Fixture {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            let state = root.path().join("state");
            let retained = root.path().join("retained");
            let candidate = root.path().join("candidate");
            for directory in [
                state.join("node/runs"),
                state.join("agent"),
                retained.clone(),
                candidate.clone(),
            ] {
                fs::create_dir_all(directory).unwrap();
            }
            // Different retained/candidate bytes with the same supported ABI.
            for path in [&retained, &candidate] {
                for name in ["runtime.elf", "launch", "compile", "agent"] {
                    fs::write(path.join(name), format!("{} {name}", path.display())).unwrap();
                }
            }
            Connection::open(state.join("node/node.sqlite3")).unwrap().execute_batch(
                "CREATE TABLE runs(id TEXT PRIMARY KEY,request_key TEXT UNIQUE NOT NULL,spec TEXT NOT NULL,created REAL NOT NULL);"
            ).unwrap();
            Connection::open(state.join("agent/agent.sqlite3")).unwrap().execute_batch(
                "CREATE TABLE assignments(id TEXT PRIMARY KEY,generation INTEGER,backend_id TEXT,sequence INTEGER,error TEXT,archived INTEGER,terminal TEXT,action_generation INTEGER);"
            ).unwrap();
            let result = Self {
                _root: root,
                state,
                retained,
                candidate,
                id: uid(),
            };
            result.add(&result.id);
            result
        }
        /// Runs leave nothing on disk: an agent journal row is all a run adds.
        fn add(&self, id: &str) {
            Connection::open(self.state.join("agent/agent.sqlite3"))
                .unwrap()
                .execute(
                    "INSERT INTO assignments(id,generation,backend_id,sequence,archived,action_generation) VALUES(?,1,?,0,0,0)",
                    [id, id],
                )
                .unwrap();
        }
        fn check(&self) -> Result<Report> {
            let candidate = WorkerRelease::capture(&self.candidate, &self.candidate.join("agent"))?;
            preflight(
                &self.state,
                &self.candidate,
                &self.candidate.join("agent"),
                &candidate.agent_sha256,
            )
        }
    }
    fn snapshot(path: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
        let mut result = BTreeMap::new();
        for entry in fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                result.extend(snapshot(&entry.path()));
            } else {
                result.insert(entry.path(), fs::read(entry.path()).unwrap());
            }
        }
        result
    }
    #[test]
    fn compatible_candidate_checks_retained_bytes_without_startup_or_secret_output() {
        let fixture = Fixture::new();
        let before = snapshot(&fixture.state);
        let report = fixture.check().unwrap();
        // Runs keep their own binaries: none needs checking.
        assert!(report.checked_execution_ids.is_empty());
        assert_ne!(
            report.candidate.runtime,
            WorkerRelease::capture(&fixture.retained, &fixture.retained.join("agent"))
                .unwrap()
                .runtime
        );
        assert!(report.admission_quiescence_required);
        assert!(!report.rollout_authorized);
        assert!(
            !serde_json::to_string(&report)
                .unwrap()
                .contains("must-not-be-emitted")
        );
        assert_eq!(snapshot(&fixture.state), before);
        assert!(!fixture.state.join("node/node.lock").exists());
        assert!(!fixture.state.join("agent/agent.lock").exists());
    }
    #[test]
    fn a_hash_mismatch_refuses_before_changing_state() {
        let fixture = Fixture::new();
        let before = snapshot(&fixture.state);
        let result = preflight(
            &fixture.state,
            &fixture.candidate,
            &fixture.candidate.join("agent"),
            &"0".repeat(64),
        );
        assert!(result.is_err());
        assert_eq!(snapshot(&fixture.state), before);
    }

    #[test]
    fn a_symlinked_journal_is_refused() {
        let fixture = Fixture::new();
        let path = fixture.state.join("agent/agent.sqlite3");
        let destination = path.with_extension("retained");
        fs::rename(&path, &destination).unwrap();
        symlink(&destination, &path).unwrap();
        assert!(fixture.check().is_err());
    }

    #[test]
    fn missing_installation_is_not_created_by_preflight() {
        let fixture = Fixture::new();
        let missing = fixture.state.join("absent");
        let candidate =
            WorkerRelease::capture(&fixture.candidate, &fixture.candidate.join("agent")).unwrap();
        assert!(
            preflight(
                &missing,
                &fixture.candidate,
                &fixture.candidate.join("agent"),
                &candidate.agent_sha256
            )
            .is_err()
        );
        assert!(!missing.exists());
    }

    #[tokio::test]
    async fn bound_preflight_requires_the_exact_sealed_epoch_operation_and_candidate() {
        let fixture = Fixture::new();
        let owner = maintenance::Maintenance::open(&fixture.state.join("agent"), "boot").unwrap();
        let candidate =
            WorkerRelease::capture(&fixture.candidate, &fixture.candidate.join("agent")).unwrap();
        let operation = uid();
        let check = |epoch, operation: &str| {
            preflight_bound(
                &fixture.state,
                &fixture.candidate,
                &fixture.candidate.join("agent"),
                &candidate.agent_sha256,
                Some((epoch, operation)),
            )
        };
        assert!(check(1, &operation).is_err());
        owner
            .prepare(&json!({"expected_epoch":1,"operation":operation,
            "candidate_sha256":candidate.agent_sha256}))
            .await
            .unwrap();
        let before = snapshot(&fixture.state);
        let report = check(1, &operation).unwrap();
        assert!(!report.admission_quiescence_required);
        assert!(!report.rollout_authorized);
        assert_eq!(report.maintenance.unwrap().mode, Mode::Sealed);
        assert_eq!(snapshot(&fixture.state), before);
        assert!(check(2, &operation).is_err());
        assert!(check(1, &uid()).is_err());
        drop(owner);
        let next = maintenance::Maintenance::open(&fixture.state.join("agent"), "boot").unwrap();
        assert!(check(1, &operation).is_err());
        assert!(check(2, &operation).is_ok());
        next.resume(&json!({"expected_epoch":2,"operation":operation}))
            .await
            .unwrap();
        assert!(check(2, &operation).is_err());
    }
}
