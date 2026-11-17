//! Retention: removes what finished runs leave behind on a node, a batch at
//! a time, once they are old enough.
//!
//! A node running its runs as shims keeps nothing about a run on disk past
//! its end: its cgroup goes once its end is collected, and its assignment's
//! row once the end is reported and the control plane no longer assigns it.
//! A node before shims kept every run's directory in `<node state>/runs`
//! (listed in `node.sqlite3`) and archived, rather than deleted, the rows of
//! assignments reported ended and no longer assigned. A node upgraded from
//! one never reads either again and, without this sweep, never removes
//! them; they count against the state tree's inode quota and inventory.
//!
//! Each pass removes at most `batch` of each:
//!
//! - a run directory in `<node state>/runs` whose run is over (its worker
//!   process is gone, whatever its last recorded state) and was last
//!   written at least `min_age` ago, unless an assignment not yet archived
//!   names it (that assignment is still reported, and its control plane may
//!   still recover its run: it goes once that row does);
//! - a row of `assignments` archived by a node before shims: archived means
//!   reported ended and no longer assigned, as a row the node deletes now.
//!
//! When `runs` is empty it goes, with `node.sqlite3` and its journal files.
//! The log and egress delivery tables a node before shims kept are dropped
//! by the agent on start ([`crate::agent`]), so no pending delivery remains
//! for a run directory to wait on.
use crate::core::{load, process_identity};
use fenders_node_protocol::{error::Result, value::*, workloads::terminal};
use serde_json::Value;
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime};

/// What a retention pass may remove, and when.
#[derive(Clone, Copy, Debug)]
pub struct Policy {
    /// How long ago a run directory must last have been written.
    pub min_age: Duration,
    /// The most of each kind removed in one pass; 0 removes nothing.
    pub batch: usize,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            min_age: Duration::from_secs(3600),
            batch: 1000,
        }
    }
}

/// A run directory a node before shims left, as far as retention needs it.
#[derive(Debug)]
pub struct LegacyRun {
    pub id: String,
    /// Its last recorded status, if it can be read.
    pub status: Option<Value>,
    /// When it or its status was last written.
    pub modified: SystemTime,
    /// Whether the worker its status names is still the same process.
    pub worker_alive: bool,
}

/// Whether `run` may be removed at `now`: over, old enough, and not named
/// by an assignment still reported (`kept`).
pub fn removable(
    run: &LegacyRun,
    now: SystemTime,
    min_age: Duration,
    kept: &HashSet<String>,
) -> bool {
    !run.worker_alive
        && !kept.contains(&run.id)
        && now
            .duration_since(run.modified)
            .is_ok_and(|age| age >= min_age)
}

/// Whether the worker `status` names is still the process it recorded.
fn worker_alive(status: &Value) -> bool {
    if terminal(s(&status["state"])) || status["worker_pid"].is_null() {
        return false;
    }
    let pid = n(&status["worker_pid"]);
    // An identity that cannot be read is taken as alive: kept for a later
    // pass, never removed under a run that may still be writing it.
    pid <= 0
        || process_identity(pid).map_or(true, |identity| {
            identity.is_some_and(|identity| identity == status["worker_identity"])
        })
}

fn read(dir: &Path, id: &str) -> Option<LegacyRun> {
    let metadata = fs::symlink_metadata(dir).ok()?;
    if !metadata.is_dir() {
        return None;
    }
    let status_path = dir.join("status.json");
    let status = load(&status_path).ok();
    let modified = [
        metadata.modified().ok(),
        fs::symlink_metadata(&status_path)
            .and_then(|m| m.modified())
            .ok(),
    ]
    .into_iter()
    .flatten()
    .max()?;
    Some(LegacyRun {
        id: id.to_owned(),
        worker_alive: status.as_ref().is_some_and(worker_alive),
        status,
        modified,
    })
}

/// How many run directories a node before shims left in `node_state`.
pub fn legacy_run_count(node_state: &Path) -> usize {
    fs::read_dir(node_state.join("runs"))
        .map(|entries| entries.count())
        .unwrap_or(0)
}

/// Removes up to `policy.batch` run directories from `<node_state>/runs`
/// that [`removable`] allows at `now`; then, if none is left, the directory
/// and `node.sqlite3`. Returns how many it removed.
pub fn sweep_runs(
    node_state: &Path,
    kept: &HashSet<String>,
    policy: Policy,
    now: SystemTime,
) -> Result<usize> {
    let runs = node_state.join("runs");
    let entries = match fs::read_dir(&runs) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error.into()),
    };
    if policy.batch == 0 {
        return Ok(0);
    }
    let mut removed = 0;
    for entry in entries {
        if removed >= policy.batch {
            break;
        }
        let entry = entry?;
        let Some(id) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        // Only names a run could have had; anything else is not ours.
        if fenders_node_protocol::model::identity(&id).is_err() {
            continue;
        }
        let Some(run) = read(&entry.path(), &id) else {
            continue;
        };
        if removable(&run, now, policy.min_age, kept) {
            fs::remove_dir_all(entry.path())?;
            removed += 1;
        }
    }
    if fs::read_dir(&runs)?.next().is_none() {
        fs::remove_dir(&runs)?;
        for file in ["node.sqlite3", "node.sqlite3-wal", "node.sqlite3-shm"] {
            match fs::remove_file(node_state.join(file)) {
                Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                    return Err(error.into());
                }
                _ => {}
            }
        }
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const HOUR: Duration = Duration::from_secs(3600);

    /// A run last written `age` before [`SystemTime::UNIX_EPOCH`] + a day.
    fn run(id: &str, age: Duration, worker_alive: bool) -> LegacyRun {
        LegacyRun {
            id: id.into(),
            status: None,
            modified: SystemTime::UNIX_EPOCH + 24 * HOUR - age,
            worker_alive,
        }
    }

    #[test]
    fn only_an_old_enough_run_no_worker_holds_and_no_assignment_names_goes() {
        let now = SystemTime::UNIX_EPOCH + 24 * HOUR;
        let none = HashSet::new();
        assert!(removable(&run("a", 2 * HOUR, false), now, HOUR, &none));
        assert!(removable(&run("a", HOUR, false), now, HOUR, &none));
        // Too recent.
        assert!(!removable(&run("a", HOUR / 2, false), now, HOUR, &none));
        // Written after `now` (a clock step): not old.
        let mut future = run("a", Duration::ZERO, false);
        future.modified = now + HOUR;
        assert!(!removable(&future, now, HOUR, &none));
        // Its worker still runs.
        assert!(!removable(&run("a", 2 * HOUR, true), now, HOUR, &none));
        // An assignment still reported names it.
        let kept = HashSet::from(["a".to_owned()]);
        assert!(!removable(&run("a", 2 * HOUR, false), now, HOUR, &kept));
        assert!(removable(&run("b", 2 * HOUR, false), now, HOUR, &kept));
        // No minimum age: any finished one.
        assert!(removable(
            &run("a", Duration::ZERO, false),
            now,
            Duration::ZERO,
            &none
        ));
    }

    #[test]
    fn a_worker_is_alive_while_its_recorded_process_is() {
        let me = std::process::id() as i64;
        let identity = process_identity(me).unwrap().unwrap();
        let running = json!({"state":"running","worker_pid":me,"worker_identity":identity});
        assert!(worker_alive(&running));
        // Ended, whatever process has its pid now.
        let mut ended = running.clone();
        ended["state"] = json!("exited");
        assert!(!worker_alive(&ended));
        // Another process with the pid (another boot or start time).
        let mut reused = running.clone();
        reused["worker_identity"] = json!(["another-boot", "1"]);
        assert!(!worker_alive(&reused));
        // Never started.
        assert!(!worker_alive(&json!({"state":"pending","worker_pid":null})));
    }

    fn legacy_run(state: &Path, id: &str, status: Value) {
        let dir = state.join("runs").join(id);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("config.json"), "{}").unwrap();
        fs::write(dir.join("status.json"), status.to_string()).unwrap();
        fs::write(dir.join("worker.log"), "log").unwrap();
    }

    #[test]
    fn a_sweep_removes_a_batch_keeps_the_rest_and_then_the_old_journal() {
        let id = |n: u32| format!("{n:032x}");
        let state = tempfile::tempdir().unwrap();
        let state = state.path();
        fs::write(state.join("node.sqlite3"), "").unwrap();
        for i in 0..5 {
            legacy_run(state, &id(i), json!({"state":"exited"}));
        }
        let me = std::process::id() as i64;
        let (running, assigned) = (id(100), id(101));
        legacy_run(
            state,
            &running,
            json!({"state":"running","worker_pid":me,
                "worker_identity":process_identity(me).unwrap().unwrap()}),
        );
        legacy_run(state, &assigned, json!({"state":"exited"}));
        // Not a run's name.
        fs::create_dir_all(state.join("runs").join("not-a-run")).unwrap();
        let kept = HashSet::from([assigned.clone()]);
        let later = SystemTime::now() + 2 * HOUR;
        let policy = Policy {
            min_age: HOUR,
            batch: 3,
        };
        // Nothing is an hour old yet.
        assert_eq!(
            sweep_runs(state, &kept, policy, SystemTime::now()).unwrap(),
            0
        );
        assert_eq!(legacy_run_count(state), 8);
        assert_eq!(sweep_runs(state, &kept, policy, later).unwrap(), 3);
        assert_eq!(sweep_runs(state, &kept, policy, later).unwrap(), 2);
        assert_eq!(sweep_runs(state, &kept, policy, later).unwrap(), 0);
        let left: HashSet<String> = fs::read_dir(state.join("runs"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            left,
            HashSet::from([running.clone(), assigned.clone(), "not-a-run".into()])
        );
        assert!(state.join("node.sqlite3").exists());
        // A batch of 0 removes nothing.
        let none = Policy { batch: 0, ..policy };
        assert_eq!(sweep_runs(state, &HashSet::new(), none, later).unwrap(), 0);
        // Once nothing is left, the directory and the old journal go.
        fs::remove_dir(state.join("runs").join("not-a-run")).unwrap();
        fs::remove_dir_all(state.join("runs").join(&running)).unwrap();
        assert_eq!(
            sweep_runs(state, &HashSet::new(), policy, later).unwrap(),
            1
        );
        assert!(!state.join("runs").exists());
        assert!(!state.join("node.sqlite3").exists());
        // A node that never had runs here has nothing to sweep.
        assert_eq!(
            sweep_runs(state, &HashSet::new(), policy, later).unwrap(),
            0
        );
        assert_eq!(legacy_run_count(state), 0);
    }
}
