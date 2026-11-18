use crate::core::*;
use axum::http::StatusCode;
use fenders_node_protocol::{
    error::{Error, Result},
    model::HOST_CONFINEMENT,
    transport::Client,
    value::*,
    workloads::terminal,
};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
pub trait Backend: Send + Sync {
    fn runtime_digest(&self) -> Option<&str> {
        None
    }
    /// The launcher's digest when this backend enforces the outbound byte
    /// limit (`egress_budget`); none when it does not.
    fn egress_budget_launcher(&self) -> Option<&str> {
        None
    }
    fn status(&self, id: &str) -> Result<Value>;
    fn list(&self) -> Result<Vec<Value>>;
    /// The runs not yet in a terminal state.
    fn list_live(&self) -> Result<Vec<Value>> {
        Ok(self
            .list()?
            .into_iter()
            .filter(|status| !terminal(s(&status["state"])))
            .collect())
    }
    /// The ids of at least every run not yet in a terminal state, perhaps
    /// with some that ended: cheaper than [`Backend::list_live`].
    fn live_ids(&self) -> Result<Vec<String>> {
        Ok(self
            .list_live()?
            .iter()
            .map(|status| s(&status["id"]).to_owned())
            .collect())
    }
    /// The ids of the runs not yet in a terminal state, without asking their
    /// VMs for live fields: what watching for runs' ends needs.
    fn live_run_ids(&self) -> Result<Vec<String>> {
        Ok(self
            .list_live()?
            .iter()
            .map(|status| s(&status["id"]).to_owned())
            .collect())
    }
    /// Notified as runs end, when the backend can say so; otherwise the
    /// agent polls for runs' ends.
    fn endings(&self) -> Option<std::sync::Arc<tokio::sync::Notify>> {
        None
    }
    /// A live run's CPU percent and host memory MiB, as it was created.
    fn shape(&self, id: &str) -> Option<(i64, i64)> {
        let _ = id;
        None
    }
    /// The host memory of shims that wait for a run, and their discarding.
    fn warm_memory_mib(&self) -> i64 {
        0
    }
    fn discard_warm(&self) {}
    fn lookup_key(&self, key: &str) -> Result<Option<String>>;
    fn upload(&self, data: &[u8]) -> Result<Value>;
    /// [`upload`](Self::upload) for a compile in `scope`, the isolation unit
    /// (tenant) whose compile cache it may use.
    fn upload_scoped(&self, data: &[u8], scope: Option<&str>) -> Result<Value> {
        let _ = scope;
        self.upload(data)
    }
    /// The largest component this backend accepts.
    fn max_upload(&self) -> usize {
        fenders_node_protocol::model::MAX_UPLOAD
    }
    /// Whether a component with this digest is already compiled locally, for
    /// a run in `scope`.
    fn compiled(&self, digest: &str, scope: Option<&str>) -> bool {
        let _ = (digest, scope);
        false
    }
    fn create(&self, spec: &Value, key: &str) -> Result<Value>;
    /// [`create`](Self::create) for a run in `scope`.
    fn create_scoped(&self, spec: &Value, key: &str, scope: Option<&str>) -> Result<Value> {
        let _ = scope;
        self.create(spec, key)
    }
    fn action(&self, id: &str, action: &str) -> Result<Value>;
    fn reconcile(&self) -> Result<()>;
}
impl Backend for Node {
    fn runtime_digest(&self) -> Option<&str> {
        Some(&self.runtime_digest)
    }
    fn egress_budget_launcher(&self) -> Option<&str> {
        Node::egress_budget_launcher(self)
    }
    fn status(&self, id: &str) -> Result<Value> {
        Node::status(self, id)
    }
    fn list(&self) -> Result<Vec<Value>> {
        Node::list(self)
    }
    fn list_live(&self) -> Result<Vec<Value>> {
        Node::list_live(self)
    }
    fn live_ids(&self) -> Result<Vec<String>> {
        Node::live_ids(self)
    }
    fn live_run_ids(&self) -> Result<Vec<String>> {
        Node::live_run_ids(self)
    }
    fn shape(&self, id: &str) -> Option<(i64, i64)> {
        Node::shape(self, id)
    }
    fn warm_memory_mib(&self) -> i64 {
        Node::warm_memory_mib(self)
    }
    fn discard_warm(&self) {
        Node::discard_warm(self)
    }
    fn endings(&self) -> Option<std::sync::Arc<tokio::sync::Notify>> {
        Some(Node::endings(self))
    }
    fn lookup_key(&self, key: &str) -> Result<Option<String>> {
        Node::lookup_key(self, key)
    }
    fn upload(&self, data: &[u8]) -> Result<Value> {
        Node::upload(self, data)
    }
    fn upload_scoped(&self, data: &[u8], scope: Option<&str>) -> Result<Value> {
        Node::upload_scoped(self, data, scope)
    }
    fn max_upload(&self) -> usize {
        Node::max_upload(self)
    }
    fn compiled(&self, digest: &str, scope: Option<&str>) -> bool {
        self.compiled_dir(digest, scope)
            .is_ok_and(|dir| dir.is_some())
    }
    fn create(&self, spec: &Value, key: &str) -> Result<Value> {
        Node::create(self, spec, key)
    }
    fn create_scoped(&self, spec: &Value, key: &str, scope: Option<&str>) -> Result<Value> {
        Node::create_scoped(self, spec, key, scope)
    }
    fn action(&self, id: &str, action: &str) -> Result<Value> {
        Node::action(self, id, action)
    }
    fn reconcile(&self) -> Result<()> {
        Node::reconcile(self)
    }
}
pub struct Agent {
    pub node: Arc<dyn Backend>,
    pub client: Client,
    state: PathBuf,
    pub cpu_percent: i64,
    pub memory_mib: i64,
    pub boot: String,
    journal: Mutex<()>,
    inspection: tokio::sync::Mutex<()>,
    pub maintenance: crate::maintenance::Maintenance,
    wake: tokio::sync::Notify,
    /// Digests to compile ahead of their runs, each with its compile scope.
    prewarm: Mutex<Vec<(String, Option<String>)>>,
    /// Assignments as fetched, by execution, at their generation: what an
    /// assignment says changes only with a new generation, so a held run is
    /// not fetched again on every pass.
    assigned: Mutex<std::collections::HashMap<String, (i64, Value)>>,
    /// One lock per assignment, held while it is applied: a wake and a pass
    /// may each bring the same one. Different assignments apply at once.
    applying: Mutex<std::collections::HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    /// CPU percent and memory MiB of runs admitted against local capacity
    /// and not yet created, so applies running at once cannot admit past it.
    admitting: Mutex<(i64, i64)>,
    /// When the control peer last took a heartbeat, in Unix milliseconds.
    heartbeat_at: std::sync::atomic::AtomicI64,
    /// Held open for the agent's life: closing the journal's last connection
    /// checkpoints it and deletes its WAL file, which the next open makes
    /// again, two extra file and directory syncs per short-lived connection.
    /// Commits still sync their WAL as before.
    _journal_keeper: Mutex<Option<rusqlite::Connection>>,
    /// Report sequences handed out and reserved, by assignment; see
    /// [`Agent::reports`].
    sequences: Mutex<std::collections::HashMap<String, (i64, i64)>>,
    /// Connections to the journal, kept open between uses.
    journal_pool: crate::pool::Pool,
    /// Each live run's CPU percent and memory MiB, from its configuration.
    run_shapes: Mutex<std::collections::HashMap<String, (i64, i64)>>,
    /// The runs seen ended, by assignment, with their last status.
    ended: Mutex<std::collections::HashMap<String, Value>>,
    /// Turns to apply an assignment, shared by every pass and wake.
    starts: Arc<tokio::sync::Semaphore>,
    /// Assignments a wake's task is applying.
    starting: Mutex<std::collections::HashSet<String>>,
}
fn sql(_: rusqlite::Error) -> Error {
    Error::internal()
}
/// How many assignments a node applies at once.
const APPLY_AT_ONCE: usize = 32;

/// Counts and logs an assignment refused a run for `reason`.
fn refused(execution: &str, tenant: Option<&str>, reason: &'static str) {
    crate::metrics::refused(reason);
    if reason == "maintenance" {
        // Every pass while the node is quiesced: not news.
        tracing::debug!(execution, tenant, reason, "run refused");
    } else {
        tracing::warn!(execution, tenant, reason, "run refused");
    }
}
/// Runs `f`, which blocks, letting the runtime move this worker's other
/// tasks elsewhere meanwhile. Applying runs blocks on the node's files,
/// databases and locks; done on the agent's few runtime threads, it held up
/// the tasks that drive its connections: on Runtara Cloud's dev node the
/// assignment poll's answers waited 0.6-1.5 s in the socket under load.
fn blocking<T>(f: impl FnOnce() -> T) -> T {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(f)
        }
        _ => f(),
    }
}
/// Awaits `future`, which blocks between its awaits, as [`blocking`] does.
async fn blocking_async<F: std::future::Future>(future: F) -> F::Output {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(|| handle.block_on(future))
        }
        _ => future.await,
    }
}
/// Report sequences an assignment's journal entry reserves at a time.
const SEQUENCE_BLOCK: i64 = 1024;
/// How often [`Agent::watch_endings`] looks for runs that ended.
const ENDING_POLL: std::time::Duration = std::time::Duration::from_millis(20);
/// A wake's apply of `id` in flight, removed from [`Agent::starting`] when it
/// ends however it ends.
struct Started<'a> {
    agent: &'a Agent,
    id: &'a str,
}
impl Drop for Started<'_> {
    fn drop(&mut self) {
        if let Ok(mut starting) = self.agent.starting.lock() {
            starting.remove(self.id);
        }
    }
}
/// An apply's claim on local capacity, given back once its run exists.
struct Admitted<'a> {
    admitting: &'a Mutex<(i64, i64)>,
    need: (i64, i64),
}
impl Drop for Admitted<'_> {
    fn drop(&mut self) {
        if let Ok(mut admitting) = self.admitting.lock() {
            admitting.0 -= self.need.0;
            admitting.1 -= self.need.1;
        }
    }
}
/// Runs `futures` at once on this task and returns their outputs in order.
async fn join_all<F: std::future::Future>(futures: Vec<F>) -> Vec<F::Output> {
    let mut futures: Vec<std::pin::Pin<Box<F>>> = futures.into_iter().map(Box::pin).collect();
    let mut outputs: Vec<Option<F::Output>> = futures.iter().map(|_| None).collect();
    std::future::poll_fn(|cx| {
        let mut pending = false;
        for (future, output) in futures.iter_mut().zip(outputs.iter_mut()) {
            if output.is_none() {
                match future.as_mut().poll(cx) {
                    std::task::Poll::Ready(value) => *output = Some(value),
                    std::task::Poll::Pending => pending = true,
                }
            }
        }
        if pending {
            std::task::Poll::Pending
        } else {
            std::task::Poll::Ready(())
        }
    })
    .await;
    outputs.into_iter().flatten().collect()
}
impl Agent {
    pub fn new(
        node: Arc<dyn Backend>,
        client: Client,
        state: &Path,
        cpu_percent: i64,
        memory_mib: i64,
    ) -> Result<Self> {
        Self::with_boot(node, client, state, cpu_percent, memory_mib, boot_id()?)
    }
    pub fn with_boot(
        node: Arc<dyn Backend>,
        client: Client,
        state: &Path,
        cpu_percent: i64,
        memory_mib: i64,
        boot: String,
    ) -> Result<Self> {
        let maintenance = Self::claim(state, &boot)?;
        Self::from_claim(
            node,
            client,
            state,
            cpu_percent,
            memory_mib,
            boot,
            maintenance,
        )
    }
    /// Claim before constructing Node: Node startup reconciles persistent runs.
    pub fn claim(state: &Path, boot: &str) -> Result<crate::maintenance::Maintenance> {
        private_dir(state)?;
        crate::maintenance::Maintenance::open_bound(
            state,
            boot,
            &crate::release::file_digest(&std::env::current_exe()?)?,
        )
    }
    pub fn from_claim(
        node: Arc<dyn Backend>,
        client: Client,
        state: &Path,
        cpu_percent: i64,
        memory_mib: i64,
        boot: String,
        maintenance: crate::maintenance::Maintenance,
    ) -> Result<Self> {
        maintenance.validate_owner(state, &boot)?;
        let agent = Self {
            node,
            client,
            state: state.to_owned(),
            cpu_percent,
            memory_mib,
            boot,
            wake: tokio::sync::Notify::new(),
            prewarm: Mutex::new(Vec::new()),
            assigned: Mutex::new(std::collections::HashMap::new()),
            applying: Mutex::default(),
            admitting: Mutex::default(),
            heartbeat_at: std::sync::atomic::AtomicI64::new(0),
            journal: Mutex::new(()),
            inspection: tokio::sync::Mutex::new(()),
            maintenance,
            _journal_keeper: Mutex::new(None),
            sequences: Mutex::default(),
            journal_pool: Default::default(),
            run_shapes: Mutex::default(),
            ended: Mutex::default(),
            starts: Arc::new(tokio::sync::Semaphore::new(APPLY_AT_ONCE)),
            starting: Mutex::default(),
        };
        agent.db()?.execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE IF NOT EXISTS assignments(id TEXT PRIMARY KEY,generation INTEGER NOT NULL,backend_id TEXT,sequence INTEGER NOT NULL DEFAULT 0,error TEXT,archived INTEGER NOT NULL DEFAULT 0,terminal TEXT,action_generation INTEGER NOT NULL DEFAULT 0); CREATE INDEX IF NOT EXISTS assignments_active ON assignments(id) WHERE archived=0; DROP TABLE IF EXISTS log_deliveries; DROP TABLE IF EXISTS log_retention_scan; DROP TABLE IF EXISTS egress_deliveries;").map_err(sql)?;
        *lock(&agent._journal_keeper)? =
            Some(rusqlite::Connection::open(agent.state.join("agent.sqlite3")).map_err(sql)?);
        Ok(agent)
    }
    /// Validate code without creating an execution or holding the journal lock.
    /// Node::upload owns the bounded, confined compiler and its digest cache.
    pub async fn inspect_component(&self) -> Result<()> {
        let _guard = self.inspection.lock().await;
        let admission = match self.maintenance.admit() {
            Ok(permit) => permit,
            Err(error) if error.status == StatusCode::SERVICE_UNAVAILABLE => return Ok(()),
            Err(error) => return Err(error),
        };
        let identity = json!({"boot_id":self.boot});
        let claimed = self
            .client
            .json("POST", "/internal/component-jobs/claim", Some(&identity))
            .await?;
        let job = &claimed["job"];
        if job.is_null() {
            return Ok(());
        }
        let artifact = id(&job["artifact_id"])?;
        let generation = integer(&job["generation"], 1, i64::MAX)?;
        let size = integer(&job["size"], 8, self.node.max_upload() as i64)? as usize;
        if job["runtime"] != fenders_node_protocol::artifacts::RUNTIME {
            return Err(Error::invalid("unsupported component inspection runtime"));
        }
        let path = format!("/internal/component-jobs/{artifact}/{generation}");
        let content = self
            .client
            .request(
                "POST",
                &format!("{path}/content"),
                Some(&identity),
                self.node.max_upload(),
            )
            .await?;
        if content.len() != size
            || fenders_node_protocol::model::digest(&content) != s(&job["digest"])
        {
            return Err(Error::invalid("component inspection digest mismatch"));
        }
        let node = self.node.clone();
        let scope = job["compile_scope"].as_str().map(str::to_owned);
        let (compiled, _admission) = tokio::task::spawn_blocking(move || {
            (node.upload_scoped(&content, scope.as_deref()), admission)
        })
        .await
        .map_err(|_| Error::internal())?;
        let result = match compiled {
            Ok(compiled)
                if fenders_node_protocol::artifacts::validate_inspection(
                    &compiled["inspection"],
                    s(&job["digest"]),
                    size,
                )
                .is_ok() =>
            {
                json!({"boot_id":self.boot,"inspection":compiled["inspection"]})
            }
            // Only the compiler rejection is permanent. Missing/malformed receipts,
            // disk limits and unavailable workers remain retryable infrastructure errors.
            Err(error)
                if error.status == StatusCode::UNPROCESSABLE_ENTITY
                    && fenders_node_protocol::artifacts::component_rejection(error.message)
                        .is_some() =>
            {
                json!({"boot_id":self.boot,"error":error.message})
            }
            other => {
                // The control peer is told only "unavailable"; the node's log says why.
                match &other {
                    Err(error) => tracing::warn!(
                        status = error.status.as_u16(),
                        error = %error.message,
                        "component could not be compiled for inspection"
                    ),
                    Ok(_) => tracing::warn!("component inspection receipt was not valid"),
                }
                json!({"boot_id":self.boot,"error":"compiler-unavailable"})
            }
        };
        self.client
            .json("POST", &format!("{path}/result"), Some(&result))
            .await?;
        Ok(())
    }
    fn db(&self) -> Result<crate::pool::Pooled<'_>> {
        self.db_with(true)
    }
    /// A journal connection whose commits sync the WAL when `durable`, and
    /// otherwise do not (`synchronous=NORMAL`, which in WAL mode cannot
    /// corrupt the journal): an ephemeral run's entries.
    fn db_with(&self, durable: bool) -> Result<crate::pool::Pooled<'_>> {
        self.journal_pool
            .get(
                &self.state.join("agent.sqlite3"),
                std::time::Duration::from_secs(10),
                if durable {
                    "PRAGMA synchronous=FULL"
                } else {
                    "PRAGMA synchronous=NORMAL"
                },
            )
            .map_err(sql)
    }
    /// The assignments not yet archived: every pass reads them, and the
    /// journal keeps archived ones, so reading those too made each pass cost
    /// as much as every run the node ever had.
    fn rows(&self) -> Result<Vec<Value>> {
        self.select_rows("WHERE archived=0 ORDER BY rowid", [])
    }
    fn select_rows<P: rusqlite::Params>(&self, filter: &str, params: P) -> Result<Vec<Value>> {
        let db = self.db()?;
        let mut stmt=db.prepare(&format!("SELECT id,generation,backend_id,sequence,error,archived,terminal,action_generation FROM assignments {filter}")).map_err(sql)?;
        stmt.query_map(params,|row|Ok(json!({"id":row.get::<_,String>(0)?,"generation":row.get::<_,i64>(1)?,"backend_id":row.get::<_,Option<String>>(2)?,"sequence":row.get::<_,i64>(3)?,"error":row.get::<_,Option<String>>(4)?,"archived":row.get::<_,i64>(5)?!=0,"terminal":row.get::<_,Option<String>>(6)?,"action_generation":row.get::<_,i64>(7)?}))).map_err(sql)?.collect::<std::result::Result<Vec<_>,_>>().map_err(sql)
    }
    fn row(&self, id: &str) -> Result<Option<Value>> {
        Ok(self.select_rows("WHERE id=?", [id])?.into_iter().next())
    }
    fn status(&self, row: &Value) -> Result<Value> {
        if let Some(terminal) = row["terminal"].as_str() {
            serde_json::from_str(terminal).map_err(|_| Error::internal())
        } else if let Some(ended) = lock(&self.ended)?.get(s(&row["id"])).cloned() {
            Ok(ended)
        } else if let Some(backend) = row["backend_id"].as_str() {
            // An ephemeral run an OS crash lost, which the node forgot on
            // starting: lost, so its control plane recovers it. Recorded so,
            // later passes and renewals no longer look for it.
            // A run its node no longer holds (the node restarted and its
            // shim was gone): lost, so its control plane recovers it.
            match self.node.status(backend) {
                Err(error) if error.status == StatusCode::NOT_FOUND => {
                    tracing::warn!(
                        execution = s(&row["id"]),
                        run = backend,
                        tenant = self.tenant(s(&row["id"])).as_deref(),
                        "run lost: the node no longer holds it"
                    );
                    self.set_terminal_with(false, s(&row["id"]), "lost", "run-lost")?;
                    Ok(json!({"state":"lost","reason":"run-lost"}))
                }
                Ok(status) if terminal(s(&status["state"])) => {
                    // Its end is kept here, in memory: the node forgets a
                    // run a while after it ended. (Not in the journal: this
                    // is read inside the reports' transaction.)
                    lock(&self.ended)?.insert(s(&row["id"]).to_owned(), status.clone());
                    tracing::info!(
                        execution = s(&row["id"]),
                        run = backend,
                        tenant = self.tenant(s(&row["id"])).as_deref(),
                        state = s(&status["state"]),
                        reason = status["reason"].as_str(),
                        exit_code = status["exit_code"].as_i64(),
                        "run ended"
                    );
                    Ok(status)
                }
                other => other,
            }
        } else {
            Ok(json!({"state":"starting"}))
        }
    }
    pub fn reports(&self) -> Result<Value> {
        let _guard = lock(&self.journal)?;
        let mut out = Vec::new();
        let mut db = self.db()?;
        let tx = db.transaction().map_err(sql)?;
        let rows = self.rows()?;
        let mut sequences = lock(&self.sequences)?;
        sequences.retain(|id, _| rows.iter().any(|row| row["id"] == id.as_str()));
        lock(&self.ended)?.retain(|id, _| rows.iter().any(|row| row["id"] == id.as_str()));
        for row in rows.iter().filter(|r| r["archived"] != true) {
            // One run whose state cannot be read now is reported next time;
            // the others are reported now.
            let status = match self.status(row) {
                Ok(status) => status,
                Err(error) => {
                    tracing::warn!(
                        execution = s(&row["id"]),
                        run = row["backend_id"].as_str(),
                        status = error.status.as_u16(),
                        error = %error.message,
                        "run not reported"
                    );
                    continue;
                }
            };
            let (cpu, memory) = usage_measurements(&status);
            // Sequences are handed out from a block whose end is journaled
            // first: after a restart they continue past that end, so a report
            // never repeats or goes back, but a heartbeat no longer commits
            // (and syncs) a write for every assignment it reports.
            let journaled = n(&row["sequence"]);
            let (next, reserved) = sequences
                .entry(s(&row["id"]).to_owned())
                .or_insert((journaled + 1, journaled));
            if *reserved < journaled {
                (*next, *reserved) = (journaled + 1, journaled);
            }
            let sequence = *next;
            *next += 1;
            if sequence > *reserved {
                *reserved = sequence + SEQUENCE_BLOCK - 1;
                tx.execute(
                    "UPDATE assignments SET sequence=? WHERE id=?",
                    rusqlite::params![*reserved, s(&row["id"])],
                )
                .map_err(sql)?;
            }
            let mut report = json!({"id":row["id"],"generation":row["generation"],"sequence":sequence,"state":if status["state"]=="pending"{"starting"}else{s(&status["state"])},"cpu_usec":cpu.unwrap_or(0),"memory_bytes":memory.unwrap_or(0),"cpu_measured":cpu.is_some(),"memory_measured":memory.is_some()});
            if !status["exit_code"].is_null() {
                report["exit_code"] = status["exit_code"].clone();
            }
            if let Some(egress) = egress_measurement(&status, &self.boot) {
                report["egress"] = egress;
            }
            if let Some(periods) = egress_period_measurement(&status, &self.boot) {
                report["egress_periods"] = periods;
            }
            // A run under the outbound byte limit says which launcher
            // admitted its bytes, under this boot.
            if fenders_node_protocol::egress_budget::validate_authority(
                &status["egress_authority"],
                &self.boot,
            )
            .is_ok()
            {
                report["egress_authority"] = status["egress_authority"].clone();
            }
            if fenders_node_protocol::app_https::validate_runtime_authority(
                &status["runtime_authority"],
                &self.boot,
            )
            .is_ok()
            {
                report["runtime_authority"] = status["runtime_authority"].clone();
            }
            if let Some(reason) = status["reason"].as_str() {
                report["reason"] = json!(if matches!(
                    reason,
                    "requested-stop"
                        | "worker-lost"
                        | "host-origin-lost"
                        | "lifetime-limit"
                        | "artifact-rejected"
                        | "local-capacity"
                        | "local-storage"
                        | "outbound-allowance-denied"
                        | "outbound-grant-expired"
                        | "outbound-accounting-unavailable"
                ) {
                    reason
                } else {
                    "execution-failed"
                });
            }
            if !row["error"].is_null() {
                report["action_error"] = row["error"].clone();
            }
            out.push(report);
        }
        tx.commit().map_err(sql)?;
        Ok(json!(out))
    }
    /// The runs that assignments not yet archived name: still reported,
    /// so retention keeps what is theirs ([`crate::retention`]).
    pub fn retained_runs(&self) -> Result<std::collections::HashSet<String>> {
        let db = self.db()?;
        let mut stmt = db
            .prepare(
                "SELECT backend_id FROM assignments WHERE archived=0 AND backend_id IS NOT NULL",
            )
            .map_err(sql)?;
        stmt.query_map([], |row| row.get::<_, String>(0))
            .map_err(sql)?
            .collect::<std::result::Result<_, _>>()
            .map_err(sql)
    }
    /// Deletes up to `batch` rows a node before shims archived (reported
    /// ended and no longer assigned, which the agent now deletes at once
    /// instead), returning how many it deleted.
    pub fn delete_archived(&self, batch: usize) -> Result<usize> {
        let _guard = lock(&self.journal)?;
        self.db_with(false)?
            .execute(
                "DELETE FROM assignments WHERE rowid IN (SELECT rowid FROM assignments WHERE archived=1 LIMIT ?)",
                [batch as i64],
            )
            .map_err(sql)
    }
    /// The tenant (compile scope) the control plane named for `execution`'s
    /// assignment, while it is assigned here.
    fn tenant(&self, execution: &str) -> Option<String> {
        lock(&self.assigned)
            .ok()?
            .get(execution)
            .and_then(|(_, kept)| kept["compile_scope"].as_str().map(str::to_owned))
    }
    /// Refuses `execution`'s assignment a run for `reason`, which ends it.
    fn refuse(
        &self,
        durable: bool,
        execution: &str,
        tenant: Option<&str>,
        reason: &'static str,
    ) -> Result<()> {
        refused(execution, tenant, reason);
        self.set_terminal_with(durable, execution, "failed", reason)
    }
    fn set_terminal_with(&self, durable: bool, id: &str, state: &str, reason: &str) -> Result<()> {
        self.db_with(durable)?
            .execute(
                "UPDATE assignments SET terminal=? WHERE id=?",
                [
                    serde_json::to_string(&json!({"state":state,"reason":reason})).unwrap(),
                    id.to_owned(),
                ],
            )
            .map_err(sql)?;
        Ok(())
    }
    /// Records the run created for `execution` and that its output is to
    /// be delivered, so the delivery pass need not look through every
    /// assignment the node ever had to learn of it.
    fn record_backend(&self, durable: bool, execution: &str, backend: &str) -> Result<()> {
        let mut db = self.db_with(durable)?;
        let tx = db.transaction().map_err(sql)?;
        tx.execute(
            "UPDATE assignments SET backend_id=? WHERE id=?",
            [backend, execution],
        )
        .map_err(sql)?;
        tx.commit().map_err(sql)
    }
    pub async fn apply(&self, summary: &Value) -> Result<()> {
        self.apply_with(summary, true).await
    }
    /// Applies `summary`; unless `wait`, not if another apply holds it, which
    /// then does the same work.
    async fn apply_with(&self, summary: &Value, wait: bool) -> Result<()> {
        let execution = id(&summary["id"])?;
        let held = lock(&self.applying)?
            .entry(execution.to_owned())
            .or_default()
            .clone();
        let _applying = if wait {
            held.lock().await
        } else {
            match held.try_lock() {
                Ok(guard) => guard,
                Err(_) => return Ok(()),
            }
        };
        let generation = integer(&summary["generation"], 1, i64::MAX)?;
        // The control plane may send a new assignment whole with its summary,
        // which saves fetching it.
        let inline = summary
            .get("assignment")
            .filter(|assignment| {
                assignment["id"] == summary["id"]
                    && assignment["generation"] == summary["generation"]
                    && assignment["desired"] == summary["desired"]
            })
            .cloned();
        // A run launched already needs no fresh word on what it runs: what
        // its assignment says changes only with a new generation. One yet to
        // launch is launched from what the control plane says now.
        let cached = lock(&self.assigned)?
            .get(execution)
            .filter(|(at, kept)| *at == generation && kept["desired"] == summary["desired"])
            .map(|(_, kept)| kept.clone());
        let assignment = match cached.or(inline) {
            Some(assignment) => assignment,
            None => {
                self.client
                    .json(
                        "GET",
                        &format!("/internal/executions/{execution}/{generation}/assignment"),
                        None,
                    )
                    .await?
            }
        };
        // Every run is ephemeral: its journal entry is written without
        // syncing it, and its control plane recovers the run if an OS crash
        // loses both.
        let durable = false;
        let mut old = self.row(execution)?;
        {
            let _guard = lock(&self.journal)?;
            if old
                .as_ref()
                .is_some_and(|r| n(&r["generation"]) > generation)
            {
                return Ok(());
            }
            self.db_with(durable)?.execute("INSERT INTO assignments(id,generation) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET error=CASE WHEN generation<excluded.generation THEN NULL ELSE error END,generation=excluded.generation,archived=0",rusqlite::params![execution,generation]).map_err(sql)?;
        }
        if old
            .as_ref()
            .is_none_or(|r| r["backend_id"].is_null() && r["terminal"].is_null())
            && let Some(committed) = self.node.lookup_key(&format!("platform-{execution}"))?
        {
            self.record_backend(durable, execution, &committed)?;
            old = self.row(execution)?;
        }
        if old
            .as_ref()
            .is_none_or(|r| r["backend_id"].is_null() && r["terminal"].is_null())
        {
            if assignment["desired"] == "stopped" {
                self.set_terminal_with(durable, execution, "stopped", "requested-stop")?;
                return Ok(());
            }
            let tenant = assignment["compile_scope"].as_str();
            let admission = self
                .maintenance
                .admit()
                .inspect_err(|_| refused(execution, tenant, "maintenance"))?;
            let spec = &assignment["spec"];
            // A run under the outbound byte limit is taken only by a node
            // told to serve it, and only for the launcher it has.
            let budget = &assignment["egress"];
            if (spec["egress_budget"] == true || !budget.is_null())
                && !(spec["egress_budget"] == true
                    && budget["contract"] == fenders_node_protocol::egress_budget::CONTRACT
                    && budget["launcher_digest"].as_str().is_some()
                    && budget["launcher_digest"].as_str() == self.node.egress_budget_launcher())
            {
                refused(execution, tenant, "unsupported");
                return Err(Error::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "local runtime lacks outbound byte admission support",
                ));
            }
            if !assignment["network"].is_null() {
                refused(execution, tenant, "unsupported");
                return Err(Error::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "local runtime lacks network lease support",
                ));
            }
            // Live runs and those admitted but not yet created, read and
            // extended under one lock, so applies running at once cannot both
            // take the last of the node's capacity. The admission is held
            // until the run is created, and so counted among the live ones.
            let need = (n(&spec["cpu_percent"]), n(&spec["host_memory_mib"]) + 24);
            let _admitted = {
                let mut admitting = lock(&self.admitting)?;
                let (mut cpu, mut memory) = *admitting;
                // A run's CPU and memory are fixed by its configuration:
                // read once, not on every admission while it lives.
                let mut shapes = lock(&self.run_shapes)?;
                let mut used = |live: &[String]| -> Result<(i64, i64)> {
                    shapes.retain(|id, _| live.contains(id));
                    let (mut cpu, mut memory) = (cpu, memory);
                    for id in live {
                        let (run_cpu, run_memory) = match shapes.get(id) {
                            Some(shape) => *shape,
                            None => {
                                let (cpu, memory) = self.node.shape(id).unwrap_or((0, 0));
                                let shape = (cpu, memory + 24);
                                shapes.insert(id.to_owned(), shape);
                                shape
                            }
                        };
                        cpu += run_cpu;
                        memory += run_memory;
                    }
                    Ok((cpu, memory))
                };
                let fits = |(cpu, memory): (i64, i64)| {
                    cpu + need.0 <= self.cpu_percent && memory + need.1 <= self.memory_mib
                };
                // The cheap ids may include runs that ended unseen: they can
                // only overstate what is in use, so only a refusal is checked
                // against every live run's status.
                let mut usage = used(&self.node.live_ids()?)?;
                if !fits(usage) {
                    let live: Vec<String> = self
                        .node
                        .list_live()?
                        .iter()
                        .map(|status| s(&status["id"]).to_owned())
                        .collect();
                    usage = used(&live)?;
                }
                drop(shapes);
                (cpu, memory) = usage;
                // Shims that wait for a run hold a VM's memory each. A run
                // that fits only without them has them discarded: they are
                // there to start runs sooner, not to keep runs out.
                if memory + need.1 + self.node.warm_memory_mib() > self.memory_mib {
                    self.node.discard_warm();
                }
                if cpu + need.0 > self.cpu_percent || memory + need.1 > self.memory_mib {
                    drop(admitting);
                    self.refuse(durable, execution, tenant, "local-capacity")?;
                    return Ok(());
                }
                crate::metrics::admitted();
                admitting.0 += need.0;
                admitting.1 += need.1;
                Admitted {
                    admitting: &self.admitting,
                    need,
                }
            };
            // A component compiled here already (pre-warmed or run before) needs
            // no fetch; launching checks the cached compilation against its digest.
            let scope = assignment["compile_scope"].as_str().map(str::to_owned);
            let bytes = if self.node.compiled(s(&spec["artifact"]), scope.as_deref()) {
                None
            } else {
                let bytes = self
                    .client
                    .request(
                        "GET",
                        &format!("/internal/executions/{execution}/{generation}/artifact"),
                        None,
                        self.node.max_upload(),
                    )
                    .await?;
                if fenders_node_protocol::model::digest(&bytes) != spec["artifact"] {
                    return Err(Error::new(
                        StatusCode::BAD_GATEWAY,
                        "artifact digest mismatch",
                    ));
                }
                Some(bytes)
            };
            let node = self.node.clone();
            let spec = spec.clone();
            let key = format!("platform-{execution}");
            let (launched, _admission) = tokio::task::spawn_blocking(move || {
                let result = (|| {
                    if let Some(bytes) = bytes {
                        node.upload_scoped(&bytes, scope.as_deref())?;
                    }
                    node.create_scoped(&spec, &key, scope.as_deref())
                })();
                (result, admission)
            })
            .await
            .map_err(|_| Error::internal())?;
            let status = match launched {
                Ok(v) => v,
                Err(e) if e.status == StatusCode::INSUFFICIENT_STORAGE => {
                    // A storage admission refusal must not silently become a
                    // later command invocation when space returns. Recover any
                    // committed backend first; only proven non-creation settles.
                    if let Some(committed) =
                        self.node.lookup_key(&format!("platform-{execution}"))?
                    {
                        self.node.status(&committed)?
                    } else {
                        self.refuse(durable, execution, tenant, "local-storage")?;
                        return Ok(());
                    }
                }
                Err(e) if matches!(e.status.as_u16(), 400 | 413 | 422) => {
                    self.refuse(durable, execution, tenant, "artifact-rejected")?;
                    return Ok(());
                }
                Err(e) => {
                    if e.status == StatusCode::TOO_MANY_REQUESTS {
                        refused(execution, tenant, "node-capacity");
                    }
                    return Err(e);
                }
            };
            self.record_backend(durable, execution, s(&status["id"]))?;
            tracing::info!(
                execution,
                run = s(&status["id"]),
                tenant,
                generation,
                "run started"
            );
        }
        let row = self.row(execution)?.ok_or_else(Error::internal)?;
        if !row["terminal"].is_null() || row["backend_id"].is_null() {
            return Ok(());
        }
        // Launched: later passes go on what decides them, without its spec.
        // (An assignment with a network lease is refused above.)
        {
            let kept = json!({"id": assignment["id"], "generation": assignment["generation"], "desired": assignment["desired"], "network": null, "egress": null, "spec": {"durability": assignment["spec"]["durability"]}, "compile_scope": assignment["compile_scope"]});
            lock(&self.assigned)?.insert(execution.to_owned(), (generation, kept));
        }
        let backend = s(&row["backend_id"]);
        // A run desired running that has never been given an action needs
        // none whatever its live state: whether it ended is in its status
        // file. Asking its VM, which a run just launched is still booting,
        // held the apply (and its turn) for the boot, ~0.8 s under load on
        // Runtara Cloud's dev node.
        let status = self.node.status(backend)?;
        if terminal(s(&status["state"])) {
            return Ok(());
        }
        let action = match (s(&assignment["desired"]), s(&status["state"])) {
            ("stopped", _) => Some("stop"),
            ("paused", "running") => Some("pause"),
            ("running", "paused") => Some("resume"),
            _ => None,
        };
        if let Some(action) = action
            && n(&row["action_generation"]) != generation
        {
            let error = match self.node.action(backend, action) {
                Ok(_) => None,
                Err(e) if e.status == StatusCode::CONFLICT => Some("application-busy"),
                Err(e) if e.status == StatusCode::SERVICE_UNAVAILABLE => {
                    Some("control-unavailable")
                }
                Err(e) => return Err(e),
            };
            self.db_with(durable)?
                .execute(
                    "UPDATE assignments SET action_generation=?,error=? WHERE id=?",
                    rusqlite::params![generation, error, execution],
                )
                .map_err(sql)?;
        }
        Ok(())
    }
    /// Compiles deployed components the node lacks, one at a time and apart
    /// from reconciliation, so their first launch skips compilation.
    pub async fn prewarm(&self) {
        loop {
            self.prewarm_one().await;
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    }
    async fn prewarm_one(&self) {
        let wanted = match lock(&self.prewarm) {
            Ok(wanted) => wanted.clone(),
            Err(_) => return,
        };
        let Some((digest, scope)) = wanted
            .into_iter()
            .find(|(d, scope)| !self.node.compiled(d, scope.as_deref()))
        else {
            return;
        };
        let Ok(bytes) = self
            .client
            .request(
                "GET",
                &format!("/internal/prewarm/{digest}"),
                None,
                self.node.max_upload(),
            )
            .await
        else {
            return;
        };
        if fenders_node_protocol::model::digest(&bytes) != digest {
            return;
        }
        let node = self.node.clone();
        let _ =
            tokio::task::spawn_blocking(move || node.upload_scoped(&bytes, scope.as_deref())).await;
    }
    /// Notified when the control peer reports a change to this node's assignments.
    pub fn woken(&self) -> &tokio::sync::Notify {
        &self.wake
    }
    /// Long-polls the control peer and wakes reconciliation on each change, so
    /// an assignment starts without waiting for the next heartbeat. A peer
    /// without the route is retried slowly; the heartbeat interval still applies.
    /// A wake may list the runs the node has yet to start, each as a heartbeat
    /// summary carrying its assignment whole: those start before the pass it
    /// wakes, which saves its heartbeat's round trip.
    pub async fn watch_assignments(self: Arc<Self>) {
        let mut after = 0u64;
        loop {
            match self
                .client
                .json(
                    "GET",
                    &format!("/internal/assignments/wait?after={after}"),
                    None,
                )
                .await
            {
                Ok(reply) => match reply["wake"].as_u64() {
                    Some(wake) if wake != after => {
                        after = wake;
                        // Each run starts in a task of its own, and the next
                        // wake is awaited meanwhile: applying a whole wake's
                        // runs before polling again held back the runs
                        // assigned meanwhile, ~2 s on Runtara Cloud's dev
                        // node at 40 runs/s.
                        for summary in reply["starting"]
                            .as_array()
                            .into_iter()
                            .flatten()
                            .filter(|summary| summary.get("assignment").is_some())
                        {
                            // A wake lists every run yet to start, again on each
                            // wake: one apply each is enough. Starting another
                            // per listing queued ~9 duplicates per run for the
                            // apply turns (3,168 for 355 runs at 40/s).
                            let Some(id) = summary["id"].as_str().map(str::to_owned) else {
                                continue;
                            };
                            if !lock(&self.starting)
                                .is_ok_and(|mut starting| starting.insert(id.clone()))
                            {
                                continue;
                            }
                            let agent = self.clone();
                            let summary = summary.clone();
                            tokio::spawn(async move {
                                let _started = Started {
                                    agent: &agent,
                                    id: &id,
                                };
                                let Ok(_turn) = agent.starts.clone().acquire_owned().await else {
                                    return;
                                };
                                if blocking_async(agent.apply(&summary)).await.is_err()
                                    && let Some(id) = summary["id"].as_str()
                                    && let Ok(mut assigned) = lock(&agent.assigned)
                                {
                                    assigned.remove(id);
                                }
                            });
                        }
                        self.wake.notify_one();
                    }
                    Some(_) => (),
                    None => tokio::time::sleep(std::time::Duration::from_secs(1)).await,
                },
                Err(error) if error.status == StatusCode::NOT_FOUND => {
                    tokio::time::sleep(std::time::Duration::from_secs(30)).await
                }
                Err(_) => tokio::time::sleep(std::time::Duration::from_secs(1)).await,
            }
        }
    }
    /// Reports a live run's end to the control peer as soon as it happens,
    /// not with the next reconciliation pass, which may be a heartbeat
    /// interval away or busy creating runs. The peer frees the run's capacity only then:
    /// on Runtara Cloud's dev node, under load, a finished run held its slot
    /// ~530 ms more, longer than the run itself. It looks only at the node's
    /// own run status files, whose finished runs are not read again.
    pub async fn watch_endings(&self) {
        // A node hears its runs end from their shims: report each at once.
        if let Some(endings) = self.node.endings() {
            loop {
                endings.notified().await;
                let _ = self.keepalive(std::time::Duration::ZERO).await;
                self.wake.notify_one();
            }
        }
        let mut live = std::collections::HashSet::<String>::new();
        loop {
            tokio::time::sleep(ENDING_POLL).await;
            let node = self.node.clone();
            // Status files and worker processes only: asking every running
            // VM over its control socket each 20 ms kept the VMs and the
            // admission waiting on the scan busy (~5000 asks a second with
            // ~100 runs live on Runtara Cloud's dev node).
            let Ok(Ok(now)) = tokio::task::spawn_blocking(move || node.live_run_ids()).await else {
                continue;
            };
            let now: std::collections::HashSet<String> = now.into_iter().collect();
            if live.iter().any(|id| !now.contains(id)) {
                // Report it now: a heartbeat carries only reports, and does
                // not wait behind a pass that is applying (creating) runs.
                // The pass it wakes reaps the run and applies what changed.
                let _ = self.keepalive(std::time::Duration::ZERO).await;
                self.wake.notify_one();
            }
            live = now;
        }
    }
    pub async fn step(&self) -> Result<()> {
        match self.maintenance.admit() {
            Ok(_permit) => blocking(|| self.node.reconcile())?,
            Err(error) if error.status == StatusCode::SERVICE_UNAVAILABLE => (),
            Err(error) => return Err(error),
        }
        let reports = blocking(|| self.reports())?;
        let response = self.heartbeat(&reports).await?;
        let assignments = response["assignments"]
            .as_array()
            .ok_or_else(Error::internal)?;
        if let Some(digests) = response["prewarm"].as_array() {
            let scopes = &response["prewarm_scopes"];
            *lock(&self.prewarm)? = digests
                .iter()
                .filter_map(Value::as_str)
                .filter(|d| d.len() == 64 && d.bytes().all(|b| b.is_ascii_hexdigit()))
                .map(|d| (d.to_owned(), scopes[d].as_str().map(str::to_owned)))
                .collect();
        }
        for report in reports.as_array().unwrap() {
            if terminal(s(&report["state"])) && !assignments.iter().any(|a| a["id"] == report["id"])
            {
                // Gone from the fleet's assignments and reported ended: the
                // run's row goes; nothing about it stays on the node.
                self.db_with(false)?
                    .execute("DELETE FROM assignments WHERE id=?", [s(&report["id"])])
                    .map_err(sql)?;
            }
        }
        lock(&self.assigned)?.retain(|id, _| assignments.iter().any(|a| a["id"] == id.as_str()));
        let mut failure = None;
        let assignments: Vec<&Value> = assignments.iter().collect();
        for (summary, applied) in self.apply_all(&assignments).await {
            if applied.is_err()
                && let Some(id) = summary["id"].as_str()
            {
                lock(&self.assigned)?.remove(id);
            }
            if let Err(e) = applied
                && !matches!(e.status.as_u16(), 403 | 404 | 409 | 503)
            {
                // One unavailable assignment must not starve unrelated work.
                // Keep its journal/reservation unchanged and still report the
                // error after giving each independently fenced assignment a turn.
                failure.get_or_insert(e);
            }
        }
        // Locks of assignments nothing is applying now.
        lock(&self.applying)?.retain(|_, held| Arc::strong_count(held) > 1);
        failure.map_or(Ok(()), Err)
    }
    /// Applies `summaries` at once, up to [`APPLY_AT_ONCE`] at a time, each
    /// with its result. Different assignments do not wait on one another:
    /// one's artifact fetch or run creation no longer holds back the next
    /// start, so a node starts runs as fast as it can create them.
    async fn apply_all<'a>(&self, summaries: &[&'a Value]) -> Vec<(&'a Value, Result<()>)> {
        // At most APPLY_AT_ONCE applies at a time across the node, the next
        // starting as soon as one ends. An assignment another apply (a
        // wake's) is applying is left to it rather than waited for.
        let applied = join_all(
            summaries
                .iter()
                .map(|summary| async {
                    let _turn = self.starts.acquire().await;
                    self.apply_with(summary, false).await
                })
                .collect(),
        )
        .await;
        summaries.iter().copied().zip(applied).collect()
    }
    async fn heartbeat(&self, reports: &Value) -> Result<Value> {
        let mut response = Value::Null;
        for batch in heartbeat_batches(reports)? {
            let mut body = json!({"boot_id":self.boot,"reports":batch,"network_leases":false,"confinement":HOST_CONFINEMENT,"runtime_digest":self.node.runtime_digest()});
            // Said only by a node told to serve the outbound byte limit: any
            // other sends the heartbeat it always sent.
            if let Some(launcher) = self.node.egress_budget_launcher() {
                body["egress_budget_contract"] =
                    json!(fenders_node_protocol::egress_budget::CONTRACT);
                body["launcher_digest"] = json!(launcher);
            }
            response = self
                .client
                .json("POST", "/internal/heartbeat", Some(&body))
                .await?;
        }
        self.heartbeat_at.store(
            clock_ns()? / 1_000_000,
            std::sync::atomic::Ordering::Relaxed,
        );
        Ok(response)
    }
    /// Heartbeats when reconciliation has not for `quiet`, as while it
    /// compiles a component: the peer keeps seeing the node and its runs'
    /// state. It applies nothing; the reconcile loop owns assignments.
    pub async fn keepalive(&self, quiet: std::time::Duration) -> Result<()> {
        let last = self.heartbeat_at.load(std::sync::atomic::Ordering::Relaxed);
        if clock_ns()? / 1_000_000 - last < quiet.as_millis() as i64 {
            return Ok(());
        }
        let reports = blocking(|| self.reports())?;
        self.heartbeat(&reports).await.map(|_| ())
    }
}

// Missing cgroup files (starting, lost, or already cleaned up) are not measured
// zero consumption. Wire zeros are retained only for older protocol shape.
fn usage_measurements(status: &Value) -> (Option<i64>, Option<i64>) {
    let cpu = s(&status["cpu_stat"]).lines().find_map(|line| {
        line.strip_prefix("usage_usec ")
            .and_then(|value| value.parse::<i64>().ok())
            .filter(|value| *value >= 0)
    });
    let memory = status["memory_current"]
        .as_i64()
        .filter(|value| *value >= 0);
    (cpu, memory)
}

fn egress_measurement(status: &Value, boot: &str) -> Option<Value> {
    if status["egress_boot_id"] != boot {
        return None;
    }
    let mut value = status["egress"].as_object()?.clone();
    value.insert("boot_id".into(), json!(boot));
    let value = Value::Object(value);
    fenders_node_protocol::egress_usage::validate(&value, s(&status["state"]), boot).ok()?;
    Some(value)
}

// Leave half the API's 1 MiB body limit for the bounded identity/capability
// envelope. Failed later batches do not archive reports: the next step retries
// cumulative counters with newer sequences, and uses the final assignment view.
fn heartbeat_batches(reports: &Value) -> Result<Vec<&[Value]>> {
    const LIMIT: usize = 512 * 1024;
    let reports = reports.as_array().ok_or_else(Error::internal)?;
    let mut batches = Vec::new();
    let mut start = 0;
    let mut bytes = 2;
    for (index, report) in reports.iter().enumerate() {
        let length = serde_json::to_vec(report)
            .map_err(|_| Error::internal())?
            .len()
            + 1;
        if length > LIMIT - 2 {
            return Err(Error::invalid(
                "execution report exceeds heartbeat batch limit",
            ));
        }
        if bytes + length > LIMIT || index - start == 1024 {
            batches.push(&reports[start..index]);
            start = index;
            bytes = 2;
        }
        bytes += length;
    }
    batches.push(&reports[start..]);
    Ok(batches)
}

fn egress_period_measurement(status: &Value, boot: &str) -> Option<Value> {
    if status["egress_boot_id"] != boot {
        return None;
    }
    let mut value = status["egress_periods"].as_object()?.clone();
    value.insert("boot_id".into(), json!(boot));
    let value = Value::Object(value);
    fenders_node_protocol::egress_periods::validate(&value, s(&status["state"]), boot).ok()?;
    Some(value)
}

#[cfg(test)]
mod measurement_tests {
    use super::*;
    #[test]
    fn heartbeat_batches_bound_bytes_and_count_without_losing_order_or_empty_poll() {
        let reports = json!(
            (0..1100)
                .map(|i| json!({"id":i,"text":"é".repeat(2000)}))
                .collect::<Vec<_>>()
        );
        let batches = heartbeat_batches(&reports).unwrap();
        assert!(batches.len() > 1);
        let mut ids = Vec::new();
        for batch in batches {
            assert!(batch.len() <= 1024);
            assert!(serde_json::to_vec(batch).unwrap().len() <= 512 * 1024);
            ids.extend(batch.iter().map(|v| v["id"].as_u64().unwrap()));
        }
        assert_eq!(ids, (0..1100).collect::<Vec<_>>());
        assert_eq!(heartbeat_batches(&json!([])).unwrap().len(), 1);
        assert_eq!(
            heartbeat_batches(&json!(vec![json!({}); 1025]))
                .unwrap()
                .len(),
            2
        );
        assert!(heartbeat_batches(&json!([{"oversized":"x".repeat(512*1024)}])).is_err());
    }
    #[test]
    fn monthly_reports_preserve_source_time_and_boot_without_relabeling_periods() {
        let mut status = json!({"state":"running","egress_boot_id":"boot","egress_periods":{"contract":"socket-payload-utc-month-v1","bytes":9,"expired_bytes":0,"periods":[{"period":"2026-10-01","bytes":9}],"in_flight":0,"complete":false,"observed":1791300000.0}});
        assert!(egress_period_measurement(&status, "other").is_none());
        let report = egress_period_measurement(&status, "boot").unwrap();
        assert_eq!(report["observed"], 1791300000.0);
        assert_eq!(report["periods"], status["egress_periods"]["periods"]);
        assert_eq!(report["boot_id"], "boot");
        status["egress_periods"]["complete"] = json!(true);
        assert!(egress_period_measurement(&status, "boot").is_none());
        status["state"] = json!("exited");
        assert_eq!(
            egress_period_measurement(&status, "boot").unwrap()["complete"],
            true
        );
        status["egress_periods"]["bytes"] = json!(10);
        assert!(egress_period_measurement(&status, "boot").is_none());
    }
    #[test]
    fn egress_reports_preserve_source_time_and_refuse_old_boot_or_invalid_coverage() {
        let mut status = json!({"state":"running","egress_boot_id":"boot-a","egress":{"contract":"socket-payload-v1","bytes":0,"in_flight":0,"complete":false,"observed":1791300000.0}});
        assert!(egress_measurement(&status, "boot-b").is_none());
        let sample = egress_measurement(&status, "boot-a").unwrap();
        assert_eq!(sample["bytes"], 0);
        assert_eq!(sample["observed"], 1791300000.0);
        assert_eq!(sample["boot_id"], "boot-a");
        status["egress"]["complete"] = json!(true);
        assert!(egress_measurement(&status, "boot-a").is_none());
        status["state"] = json!("exited");
        assert_eq!(
            egress_measurement(&status, "boot-a").unwrap()["complete"],
            true
        );
        status["egress"]["in_flight"] = json!(1);
        assert!(egress_measurement(&status, "boot-a").is_none());
        status["egress"] = Value::Null;
        assert!(egress_measurement(&status, "boot-a").is_none());
    }
    #[test]
    fn absent_cgroup_counters_are_distinct_from_measured_zero() {
        for status in [
            json!({"state":"starting"}),
            json!({"state":"stopped","cpu_stat":"","memory_current":null}),
            json!({"cpu_stat":"usage_usec invalid","memory_current":-1}),
        ] {
            assert_eq!(usage_measurements(&status), (None, None));
        }
        assert_eq!(
            usage_measurements(&json!({"cpu_stat":"usage_usec 0\nuser_usec 0","memory_current":0})),
            (Some(0), Some(0))
        );
        assert_eq!(
            usage_measurements(
                &json!({"cpu_stat":"usage_usec 120\nuser_usec 90\nsystem_usec 30","memory_current":4096})
            ),
            (Some(120), Some(4096))
        );
        assert_eq!(
            usage_measurements(&json!({"cpu_stat":"usage_usec -5","memory_current":4096})),
            (None, Some(4096))
        );
    }
}
