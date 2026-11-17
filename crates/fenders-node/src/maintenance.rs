//! Durable admission quiescence. The existing agent flock remains owned by every
//! admitted operation, including blocking work whose async waiter was canceled.
use crate::core::flock;
use axum::http::StatusCode;
use fenders_node_protocol::{
    error::{Error, Result},
    model::identity,
};
use rusqlite::{Connection, OpenFlags, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fs::File,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::sync::{Mutex, OwnedRwLockReadGuard, RwLock};

#[cfg(test)]
mod tests;

pub(crate) const JOURNAL_VERSION: i64 = 1;
fn unavailable() -> Error {
    Error::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "maintenance journal unavailable",
    )
}
fn conflict() -> Error {
    Error::new(
        StatusCode::CONFLICT,
        "stale or conflicting maintenance operation",
    )
}
fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Open,
    Quiescing,
    Sealed,
}
impl Mode {
    fn name(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Quiescing => "quiescing",
            Self::Sealed => "sealed",
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub epoch: i64,
    pub owner_boot: String,
    pub owner_pid: i64,
    pub mode: Mode,
    pub operation: Option<String>,
    pub candidate_sha256: Option<String>,
    pub origin_epoch: Option<i64>,
}
pub(crate) fn read(db: &Connection) -> Result<Snapshot> {
    let version: i64 = db
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|_| unavailable())?;
    if version != JOURNAL_VERSION {
        return Err(unavailable());
    }
    let (epoch, boot, pid, mode, operation, candidate, origin): (i64,String,i64,String,Option<String>,Option<String>,Option<i64>) = db.query_row(
        "SELECT epoch,owner_boot,owner_pid,mode,operation,candidate_sha256,origin_epoch FROM agent_management WHERE singleton=1", [],
        |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?))).map_err(|_| unavailable())?;
    let mode = match mode.as_str() {
        "open" => Mode::Open,
        "quiescing" => Mode::Quiescing,
        "sealed" => Mode::Sealed,
        _ => return Err(unavailable()),
    };
    if epoch < 1 || pid < 1 || boot.is_empty() || boot.len() > 128 {
        return Err(unavailable());
    }
    match (&operation, &candidate, origin) {
        (None, None, None) if mode == Mode::Open => (),
        (Some(op), Some(candidate), Some(origin))
            if identity(op).is_ok() && hash(candidate) && (1..=epoch).contains(&origin) => {}
        _ => return Err(unavailable()),
    }
    Ok(Snapshot {
        epoch,
        owner_boot: boot,
        owner_pid: pid,
        mode,
        operation,
        candidate_sha256: candidate,
        origin_epoch: origin,
    })
}
fn connection(path: &Path, create: bool) -> Result<Connection> {
    let mut flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_NOFOLLOW;
    if create {
        flags |= OpenFlags::SQLITE_OPEN_CREATE;
    }
    let db = Connection::open_with_flags(path, flags).map_err(|_| unavailable())?;
    db.busy_timeout(Duration::from_millis(250))
        .map_err(|_| unavailable())?;
    db.execute_batch("PRAGMA synchronous=FULL")
        .map_err(|_| unavailable())?;
    Ok(db)
}
struct Owner {
    path: PathBuf,
    epoch: i64,
    _lock: File,
}
pub struct Permit {
    _owner: Arc<Owner>,
    _gate: OwnedRwLockReadGuard<()>,
}
pub struct Maintenance {
    owner: Arc<Owner>,
    admission: Arc<RwLock<()>>,
    transition: Mutex<()>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fence {
    expected_epoch: i64,
    operation: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Prepare {
    expected_epoch: i64,
    operation: String,
    candidate_sha256: String,
}
impl Maintenance {
    /// Claim only while holding the same agent.lock used before maintenance
    /// support. Unknown future journals are refused, never reset or downgraded.
    pub fn open(state: &Path, boot: &str) -> Result<Self> {
        Self::open_inner(state, boot, None)
    }
    /// Production adoption is bound to the prepared executable before any
    /// ownership or node-state mutation. A failed selection stays sealed.
    pub(crate) fn open_bound(state: &Path, boot: &str, agent_sha256: &str) -> Result<Self> {
        if !hash(agent_sha256) {
            return Err(unavailable());
        }
        Self::open_inner(state, boot, Some(agent_sha256))
    }
    fn open_inner(state: &Path, boot: &str, agent_sha256: Option<&str>) -> Result<Self> {
        if boot.is_empty() || boot.len() > 128 {
            return Err(Error::invalid("invalid management boot identity"));
        }
        let state = state.canonicalize()?;
        let guard = flock(&state.join("agent.lock"))?;
        let path = state.join("agent.sqlite3");
        let mut db = connection(&path, true)?;
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| unavailable())?;
        let version: i64 = tx
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(|_| unavailable())?;
        let epoch = match version {
            0 => {
                let exists: bool = tx
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='agent_management')",
                        [],
                        |r| r.get(0),
                    )
                    .map_err(|_| unavailable())?;
                if exists {
                    return Err(unavailable());
                }
                tx.execute_batch("CREATE TABLE agent_management(singleton INTEGER PRIMARY KEY CHECK(singleton=1),epoch INTEGER NOT NULL,owner_boot TEXT NOT NULL,owner_pid INTEGER NOT NULL,mode TEXT NOT NULL CHECK(mode IN ('open','quiescing','sealed')),operation TEXT,candidate_sha256 TEXT,origin_epoch INTEGER);").map_err(|_| unavailable())?;
                tx.execute(
                    "INSERT INTO agent_management VALUES(1,1,?,?,'open',NULL,NULL,NULL)",
                    params![boot, std::process::id()],
                )
                .map_err(|_| unavailable())?;
                tx.pragma_update(None, "user_version", JOURNAL_VERSION)
                    .map_err(|_| unavailable())?;
                1
            }
            JOURNAL_VERSION => {
                let previous = read(&tx)?;
                if agent_sha256.is_some_and(|pin| {
                    previous
                        .candidate_sha256
                        .as_deref()
                        .is_some_and(|candidate| candidate != pin)
                }) {
                    return Err(conflict());
                }
                let epoch = previous.epoch.checked_add(1).ok_or_else(unavailable)?;
                tx.execute("UPDATE agent_management SET epoch=?,owner_boot=?,owner_pid=? WHERE singleton=1", params![epoch,boot,std::process::id()]).map_err(|_| unavailable())?;
                epoch
            }
            _ => return Err(unavailable()),
        };
        tx.commit().map_err(|_| unavailable())?;
        Ok(Self {
            owner: Arc::new(Owner {
                path,
                epoch,
                _lock: guard,
            }),
            admission: Arc::new(RwLock::new(())),
            transition: Mutex::new(()),
        })
    }
    pub(crate) fn validate_owner(&self, state: &Path, boot: &str) -> Result<()> {
        let snapshot = self.status()?;
        if state.canonicalize()?.join("agent.sqlite3") != self.owner.path
            || snapshot.owner_boot != boot
            || snapshot.owner_pid != i64::from(std::process::id())
        {
            return Err(conflict());
        }
        Ok(())
    }
    pub fn status(&self) -> Result<Snapshot> {
        let snapshot = read(&connection(&self.owner.path, false)?)?;
        if snapshot.epoch != self.owner.epoch {
            return Err(conflict());
        }
        Ok(snapshot)
    }
    pub fn admit(&self) -> Result<Permit> {
        let owner = self.owner.clone();
        // Defer new work instead of parking heartbeat/reconciliation behind a
        // waiting quiescence writer. Independent renewals remain runnable.
        let guard = self.admission.clone().try_read_owned().map_err(|_| {
            Error::new(StatusCode::SERVICE_UNAVAILABLE, "worker admission quiesced")
        })?;
        if self.status()?.mode != Mode::Open {
            return Err(Error::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "worker admission quiesced",
            ));
        }
        Ok(Permit {
            _owner: owner,
            _gate: guard,
        })
    }
    fn fence(&self, epoch: i64, operation: &str) -> Result<Snapshot> {
        identity(operation)?;
        let snapshot = self.status()?;
        if epoch != self.owner.epoch {
            return Err(conflict());
        }
        Ok(snapshot)
    }
    fn persist(&self, previous: &Snapshot, next: &Snapshot) -> Result<()> {
        let mut db = connection(&self.owner.path, false)?;
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| unavailable())?;
        if read(&tx)? != *previous || previous.epoch != self.owner.epoch {
            return Err(conflict());
        }
        tx.execute("UPDATE agent_management SET mode=?,operation=?,candidate_sha256=?,origin_epoch=? WHERE singleton=1 AND epoch=?",
            params![next.mode.name(),next.operation,next.candidate_sha256,next.origin_epoch,self.owner.epoch]).map_err(|_| unavailable())?;
        tx.commit().map_err(|_| unavailable())
    }
    pub async fn prepare(&self, value: &Value) -> Result<Snapshot> {
        let request: Prepare = serde_json::from_value(value.clone())
            .map_err(|_| Error::invalid("invalid maintenance prepare"))?;
        if !hash(&request.candidate_sha256) {
            return Err(Error::invalid("invalid candidate hash"));
        }
        let _transition = self.transition.lock().await;
        let mut current = self.fence(request.expected_epoch, &request.operation)?;
        if current.mode == Mode::Open {
            if current.operation.as_deref() == Some(&request.operation) {
                return Err(conflict());
            }
            let mut next = current.clone();
            next.mode = Mode::Quiescing;
            next.operation = Some(request.operation.clone());
            next.candidate_sha256 = Some(request.candidate_sha256.clone());
            next.origin_epoch = Some(self.owner.epoch);
            self.persist(&current, &next)?;
            current = next;
        } else if current.operation.as_deref() != Some(&request.operation)
            || current.candidate_sha256.as_deref() != Some(&request.candidate_sha256)
        {
            return Err(conflict());
        }
        if current.mode == Mode::Sealed {
            return Ok(current);
        }
        // This waits for actual blocking work, even when its async caller was
        // canceled. Network renewals and existing execution control do not use it.
        let _admission = self.admission.write().await;
        let mut sealed = current.clone();
        sealed.mode = Mode::Sealed;
        sealed.origin_epoch = Some(self.owner.epoch);
        self.persist(&current, &sealed)?;
        Ok(sealed)
    }
    pub async fn resume(&self, value: &Value) -> Result<Snapshot> {
        let request: Fence = serde_json::from_value(value.clone())
            .map_err(|_| Error::invalid("invalid maintenance resume"))?;
        let _transition = self.transition.lock().await;
        let current = self.fence(request.expected_epoch, &request.operation)?;
        if current.operation.as_deref() != Some(&request.operation) {
            return Err(conflict());
        }
        // Once sealed, the source cannot reopen between candidate preflight and
        // process replacement. A new exclusively locked owner must adopt first.
        if current.mode == Mode::Sealed && current.origin_epoch == Some(self.owner.epoch) {
            return Err(conflict());
        }
        if current.mode == Mode::Open {
            return Ok(current);
        }
        let _admission = self.admission.write().await;
        let mut next = current.clone();
        next.mode = Mode::Open;
        self.persist(&current, &next)?;
        Ok(next)
    }
}
