//! What the gateway knows of its requests in memory, and the one
//! transaction a second that writes it down.
//!
//! A request used to be written as it went: a row when it was admitted,
//! that row marked when it was given to its app and again when it ended,
//! each a transaction under the lock all mutations share. So the requests a
//! second of a whole control plane were bounded by that lock
//! (`docs/gateway-accounting.md`).
//!
//! A request's record is now kept here until it ends and written then, with
//! every other that ended in the same second, by the **flusher**
//! ([`Store::flush_gateway`]). One still in flight when a flush comes is
//! written as it stands and finished by a later one, so a long request is
//! seen while it runs.
//!
//! What is here belongs to a **session**: this process's gateway, a row of
//! `gateway_sessions` that each flush touches. One not touched for
//! [`SESSION_DEAD`] is a process that is gone.
//!
//! Records are not guaranteed. A process that dies takes the records of
//! what it had in flight with it, and when the database is too slow to take
//! them the oldest waiting are dropped and counted, never a request delayed.
use crate::{
    args,
    db::exec,
    error::Result,
    model::uid,
    store::{Store, Tx},
};
use serde_json::{Value, json};
use std::{
    collections::{HashMap, VecDeque},
    sync::Mutex,
    time::{Duration, Instant},
};

pub(crate) const LEASES_MIGRATION: &str = include_str!("../sql/gateway_transfer_leases.sql");
pub(crate) const MIGRATION: &str = "CREATE TABLE IF NOT EXISTS gateway_sessions (
    id text PRIMARY KEY CHECK(id ~ '^[a-f0-9]{32}$'),
    started timestamptz NOT NULL DEFAULT clock_timestamp(),
    seen timestamptz NOT NULL DEFAULT clock_timestamp())";

/// How often the flusher runs.
pub const FLUSH_EVERY: Duration = Duration::from_secs(1);
/// How long a session with nothing to write goes without touching its row.
const SESSION_TOUCH: Duration = Duration::from_secs(5);
/// A session not touched for this long is a process that is gone.
pub(crate) const SESSION_DEAD: &str = "15 seconds";
/// The same, for the scheduler's grace after it could not reach the
/// database.
pub(crate) const SESSION_GRACE: std::time::Duration = std::time::Duration::from_secs(15);
/// Ended requests waiting to be written. Past this the oldest is dropped.
const MOST_WAITING: usize = 16384;
/// Records written by one flush.
const MOST_A_FLUSH: usize = 4096;

/// A request the gateway admitted, as its record will say.
pub struct Opened {
    pub tenant: String,
    pub project: String,
    pub app: String,
    pub release: String,
    pub execution: Option<String>,
    pub method: String,
    pub path: String,
}

struct Record {
    id: String,
    request: Opened,
    created: Instant,
    started: Option<Instant>,
    /// How it ended: its state, the status answered, and when.
    ended: Option<(&'static str, Option<u16>, Instant)>,
}

impl Record {
    fn row(&self, now: Instant) -> Value {
        let ago = |at: Instant| now.saturating_duration_since(at).as_micros() as u64;
        let (state, status, finished) = match self.ended {
            Some((state, status, at)) => (state, status, Some(at)),
            None if self.started.is_some() => ("running", None, None),
            None => ("queued", None, None),
        };
        json!({
            "id": self.id, "tenant_id": self.request.tenant, "project_id": self.request.project,
            "app_id": self.request.app, "release_id": self.request.release,
            "execution_id": self.request.execution, "method": self.request.method,
            "path": self.request.path, "state": state, "http_status": status,
            "created_ago": ago(self.created), "started_ago": self.started.map(ago),
            "finished_ago": finished.map(ago),
        })
    }
}

/// An admission to be audited: the request, its workspace and host name.
struct Admitted {
    request: String,
    tenant: String,
    hostname: String,
}

#[derive(Default)]
struct Inner {
    /// Requests in flight, and whether each has changed since it was last
    /// written.
    open: HashMap<String, (Record, bool)>,
    ended: VecDeque<Record>,
    admitted: Vec<Admitted>,
    dropped: u64,
    touched: Option<Instant>,
}

/// What one flush writes, taken out of the gateway's memory.
#[derive(Default)]
struct Batch {
    rows: Vec<Value>,
    ended: Vec<Record>,
    open: Vec<String>,
    admitted: Vec<Admitted>,
    leases: crate::lease::Taken,
    /// Apps with a request in flight, or one since the last flush.
    active: Vec<String>,
    /// Outbound grants renewed from memory.
    renewed: Vec<crate::renewal::Renewed>,
    /// What the exchange shows, for a control process to read; only an
    /// edge writes it.
    observed: Option<Vec<Value>>,
}

/// What a flush did for the leases, to be told to their budgets once it
/// has committed.
#[derive(Default)]
struct Written {
    /// Shares of workspaces' limits brought to their size, or given back.
    shares: Vec<(
        String,
        Option<(crate::shares::Limits, crate::shares::Limits)>,
    )>,
    /// Leases that were not there to be taken from.
    lost: Vec<crate::lease::Key>,
    /// What each lease asked for was granted: the key, the bytes granted
    /// and the bytes asked.
    granted: Vec<(crate::lease::Key, i64, i64)>,
}

pub struct Gateway {
    session: String,
    inner: Mutex<Inner>,
    /// What this session holds of each project's transfer allowance.
    pub budgets: crate::lease::Budgets,
    /// What is known of the apps it serves and its requests in flight.
    pub gates: crate::gate::Gates,
    /// What is known of the launches whose shims call its run channel.
    pub launches: crate::launch::Launches,
    /// The outbound grants it renews from memory.
    pub renewals: crate::renewal::Renewals,
    /// One ask to extend a lease at a time: the others wait, and find it
    /// extended.
    extending: tokio::sync::Mutex<()>,
    /// Whether the database can be reached ([`crate::outage`]).
    pub outage: crate::outage::Outage,
    /// Its shares of workspaces' limits ([`crate::shares`]).
    pub shares: crate::shares::Shares,
    /// The registered edge this process serves as, if any: it then owns
    /// only the apps the scheduler gives it ([`crate::edges`]).
    pub edge: Option<String>,
    /// Requests waiting together for an app to start ([`crate::wakes`]).
    pub wakes: std::sync::Arc<crate::wakes::Wakes>,
}

impl Default for Gateway {
    fn default() -> Self {
        Self {
            session: uid(),
            inner: Default::default(),
            budgets: Default::default(),
            gates: Default::default(),
            launches: Default::default(),
            renewals: Default::default(),
            outage: Default::default(),
            shares: Default::default(),
            edge: None,
            wakes: Default::default(),
            extending: Default::default(),
        }
    }
}

impl Gateway {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// This process's gateway session.
    pub fn session(&self) -> &str {
        &self.session
    }

    /// Request records dropped because the database did not take them.
    pub fn dropped(&self) -> u64 {
        self.lock().dropped
    }

    /// A request was admitted and is to have a record. Public for tests
    /// that stand in for the gateway.
    #[doc(hidden)]
    pub fn opened(&self, id: &str, request: Opened) {
        let record = Record {
            id: id.to_owned(),
            request,
            created: Instant::now(),
            started: None,
            ended: None,
        };
        self.lock().open.insert(id.to_owned(), (record, true));
    }

    /// An admission to be audited by the next flush.
    pub(crate) fn admitted(&self, request: &str, tenant: &str, hostname: &str) {
        self.lock().admitted.push(Admitted {
            request: request.to_owned(),
            tenant: tenant.to_owned(),
            hostname: hostname.to_owned(),
        });
    }

    /// The request will be served by `execution`: learnt when an app that
    /// was starting has one.
    pub(crate) fn bound(&self, id: &str, execution: &str) {
        if let Some((record, changed)) = self.lock().open.get_mut(id) {
            record.request.execution = Some(execution.to_owned());
            *changed = true;
        }
    }

    /// The request is being offered to its app.
    pub(crate) fn dispatched(&self, id: &str) {
        if let Some((record, changed)) = self.lock().open.get_mut(id) {
            record.started.get_or_insert_with(Instant::now);
            *changed = true;
        }
    }

    /// The request ended, answered `status` if it is known to have been.
    /// One that is not known and was given to its app may have run:
    /// `unknown`. Ending a request twice ends it once.
    pub(crate) fn ended(&self, id: &str, status: Option<u16>) {
        let mut inner = self.lock();
        let Some((mut record, _)) = inner.open.remove(id) else {
            return;
        };
        let state = match status {
            Some(status) if status < 400 => "succeeded",
            Some(_) => "failed",
            None if record.started.is_none() => "failed",
            None => "unknown",
        };
        record.ended = Some((state, status, Instant::now()));
        if inner.ended.len() >= MOST_WAITING {
            inner.ended.pop_front();
            inner.dropped += 1;
        }
        inner.ended.push_back(record);
    }

    /// Whether a flush has anything to do: something to write, or a session
    /// row to touch.
    fn due(&self) -> bool {
        if self.budgets.due() || self.gates.due() || self.renewals.due() {
            return true;
        }
        let inner = self.lock();
        !inner.ended.is_empty()
            || !inner.admitted.is_empty()
            || inner.open.values().any(|(_, changed)| *changed)
            || inner.touched.is_none_or(|at| at.elapsed() >= SESSION_TOUCH)
    }

    fn take(&self) -> Batch {
        let mut inner = self.lock();
        let now = Instant::now();
        let mut batch = Batch::default();
        let count = inner.ended.len().min(MOST_A_FLUSH);
        batch.ended = inner.ended.drain(..count).collect();
        batch.rows = batch.ended.iter().map(|record| record.row(now)).collect();
        for (id, (record, changed)) in inner.open.iter_mut() {
            if *changed && batch.rows.len() < 2 * MOST_A_FLUSH {
                *changed = false;
                batch.rows.push(record.row(now));
                batch.open.push(id.clone());
            }
        }
        batch.admitted = std::mem::take(&mut inner.admitted);
        batch
    }

    /// Puts back what a flush took and could not write.
    fn restore(&self, batch: Batch) {
        self.budgets.restore(batch.leases);
        self.gates.touch(&batch.active);
        self.renewals.restore(batch.renewed);
        let mut inner = self.lock();
        for id in batch.open {
            if let Some((_, changed)) = inner.open.get_mut(&id) {
                *changed = true;
            }
        }
        for record in batch.ended.into_iter().rev() {
            if inner.ended.len() >= MOST_WAITING {
                inner.dropped += 1;
            } else {
                inner.ended.push_front(record);
            }
        }
        let mut admitted = batch.admitted;
        admitted.append(&mut inner.admitted);
        inner.admitted = admitted;
    }

    fn flushed(&self) {
        self.lock().touched = Some(Instant::now());
    }
}

/// The UTC month a lease taken now is for, as the database has it.
const PERIOD: &str = "date_trunc('month',now() AT TIME ZONE 'UTC')::date";

impl Store {
    /// Writes what the gateway holds in memory: its session, the records of
    /// requests that ended or changed, the admissions to be audited, and
    /// what was used of its leases, which it then brings to their size.
    /// One transaction, whatever it holds. What cannot be written is kept
    /// for the next flush.
    pub async fn flush_gateway(&self) -> Result<()> {
        let flushed = crate::outage::within(crate::outage::FLUSH_WITHIN, self.flush(false)).await;
        // The flush is what notices that the database is back: it tries
        // every second, outage or not.
        match &flushed {
            Ok(()) => self.gateway.outage.reached(),
            // A flush that ran out of time may have waited for the lock
            // behind other work: the database is gone only if it does not
            // answer a question that takes none.
            Err(error) if error.is_database_unavailable() && self.reachable().await => {}
            Err(error) => {
                self.gateway.outage.failed(error);
            }
        }
        flushed
    }

    /// Whether the database answers, in [`crate::outage::READ_WITHIN`], a
    /// question that takes no lock.
    pub(crate) async fn reachable(&self) -> bool {
        crate::outage::within(crate::outage::READ_WITHIN, async {
            sqlx::query("SELECT 1").execute(&self.pool).await?;
            Ok(())
        })
        .await
        .is_ok()
    }

    /// The last flush of a gateway that is stopping: as any other, and
    /// every lease is given back, so that none is left to be charged as a
    /// dead session's.
    pub async fn close_gateway(&self) -> Result<()> {
        self.flush(true).await
    }

    async fn flush(&self, closing: bool) -> Result<()> {
        // An edge writes what its exchange shows every time: the control
        // process decides on it.
        if !closing && self.serves != crate::store::Serves::Edge && !self.gateway.due() {
            return Ok(());
        }
        let mut tx = self.flush_transaction().await?;
        let period: String = sqlx::query_scalar(&format!("SELECT {PERIOD}::text"))
            .fetch_one(&mut *tx)
            .await?;
        // Leases the operator recalled give back what is not reserved.
        let recalled = self.answer_recalls(&mut tx).await?;
        // Taken once the lock is held: a record's times are written as how
        // long ago they were, by the database's clock.
        let mut batch = self.gateway.take();
        batch.leases = self.gateway.budgets.take(&period, closing);
        batch.active = self.gateway.gates.take_active();
        batch.renewed = self.gateway.renewals.take();
        if self.serves == crate::store::Serves::Edge && !closing {
            batch.observed = Some(self.exchange.observe().rows());
        }
        let written = match self.write_gateway(&mut tx, &batch, closing).await {
            Ok(written) => written,
            Err(error) => {
                self.gateway.restore(batch);
                self.gateway.budgets.give_back(recalled);
                return Err(error);
            }
        };
        if let Err(error) = tx.commit().await {
            self.gateway.restore(batch);
            self.gateway.budgets.give_back(recalled);
            return Err(error.into());
        }
        let budgets = &self.gateway.budgets;
        for key in &written.lost {
            budgets.lost(key);
        }
        for (key, granted, asked) in &written.granted {
            budgets.granted(key, &period, *granted, *asked);
        }
        for (tenant, share) in &written.shares {
            match share {
                Some(share) => self.gateway.shares.set(tenant, *share),
                None => self.gateway.shares.drop_share(tenant),
            }
        }
        self.gateway.flushed();
        Ok(())
    }

    /// Gives back what this session's recalled leases hold unreserved, in
    /// memory and in `tx`. What was taken, to be put back if `tx` is not
    /// committed.
    async fn answer_recalls(&self, tx: &mut Tx) -> Result<Vec<(crate::lease::Key, String, i64)>> {
        use crate::db::rows;
        let mut tenants: Vec<String> = rows(tx,"UPDATE gateway_transfer_leases SET recalled=false WHERE session_id=$1 AND recalled RETURNING tenant_id",args![self.gateway.session()]).await?
            .iter()
            .filter_map(|row| row["tenant_id"].as_str().map(str::to_owned))
            .collect();
        tenants.sort();
        tenants.dedup();
        let withheld: Vec<_> = tenants
            .iter()
            .flat_map(|tenant| self.gateway.budgets.withhold(tenant))
            .collect();
        for (key, period, bytes) in &withheld {
            if let Err(error) = exec(tx,"UPDATE gateway_transfer_leases SET held_bytes=GREATEST(0,held_bytes-$5),updated=clock_timestamp() WHERE session_id=$1 AND tenant_id=$2 AND project_id=$3 AND period=$4::date",args![self.gateway.session(),key.0,key.1,period,bytes]).await {
                self.gateway.budgets.give_back(withheld);
                return Err(error);
            }
        }
        Ok(withheld)
    }

    /// Recalls the leases other processes hold of `tenant`'s transfer
    /// allowance, and waits, up to three seconds, for them to give back
    /// what they hold unreserved: for the operator to change the
    /// allowance, which the leases would otherwise keep from being lowered.
    pub(crate) async fn recall_leases(&self, tenant: &str) -> Result<()> {
        let mut tx = self.gateway_transaction().await?;
        let recalled = exec(&mut tx,"UPDATE gateway_transfer_leases SET recalled=true WHERE tenant_id=$1 AND session_id<>$2 AND held_bytes>0",args![tenant,self.gateway.session()]).await?;
        tx.commit().await?;
        if recalled == 0 {
            return Ok(());
        }
        let until = tokio::time::Instant::now() + std::time::Duration::from_secs(3);
        while tokio::time::Instant::now() < until {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM gateway_transfer_leases WHERE tenant_id=$1 AND recalled)",
            )
            .bind(tenant)
            .fetch_one(&self.pool)
            .await?;
            if !waiting {
                return Ok(());
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        Ok(())
    }

    async fn write_gateway(&self, tx: &mut Tx, batch: &Batch, closing: bool) -> Result<Written> {
        let session = self.gateway.session();
        // The edge is heard from, closing or not: one that restarts is not
        // taken for gone, nor its apps given to another.
        if self.gateway.edge.is_some() {
            exec(
                tx,
                "UPDATE edges SET seen=clock_timestamp() WHERE id=$1",
                args![self.gateway.edge],
            )
            .await?;
        }
        if closing {
            exec(
                tx,
                "DELETE FROM gateway_sessions WHERE id=$1",
                args![session],
            )
            .await?;
            exec(
                tx,
                "DELETE FROM gateway_observations WHERE session_id=$1",
                args![session],
            )
            .await?;
        } else {
            exec(
                tx,
                "INSERT INTO gateway_sessions(id,edge_id) VALUES($1,$2) ON CONFLICT(id) DO UPDATE SET seen=clock_timestamp(),edge_id=excluded.edge_id",
                args![session, self.gateway.edge],
            )
            .await?;
        }
        if !batch.rows.is_empty() {
            // A record of an app or release that is gone meanwhile is not
            // written; one whose execution is gone is written without it. A
            // record that was finished is not changed again.
            exec(tx,"INSERT INTO app_http_runs(id,tenant_id,project_id,app_id,release_id,execution_id,method,path,state,http_status,created,started_at,finished_at)
                SELECT r.id,r.tenant_id,r.project_id,r.app_id,r.release_id,e.id,r.method,r.path,r.state,r.http_status,
                    t.now-r.created_ago*interval '1 microsecond',t.now-r.started_ago*interval '1 microsecond',t.now-r.finished_ago*interval '1 microsecond'
                FROM jsonb_to_recordset($1) AS r(id text,tenant_id text,project_id text,app_id text,release_id text,execution_id text,method text,path text,state text,http_status integer,created_ago bigint,started_ago bigint,finished_ago bigint)
                CROSS JOIN (SELECT clock_timestamp() AS now) t
                JOIN app_releases l ON l.tenant_id=r.tenant_id AND l.project_id=r.project_id AND l.app_id=r.app_id AND l.id=r.release_id
                LEFT JOIN executions e ON e.tenant_id=r.tenant_id AND e.project_id=r.project_id AND e.id=r.execution_id
                ON CONFLICT(id) DO UPDATE SET state=excluded.state,http_status=excluded.http_status,
                    execution_id=COALESCE(excluded.execution_id,app_http_runs.execution_id),
                    started_at=COALESCE(app_http_runs.started_at,excluded.started_at),finished_at=excluded.finished_at
                WHERE app_http_runs.finished_at IS NULL",args![Value::Array(batch.rows.clone())]).await?;
        }
        for admitted in &batch.admitted {
            Self::audit_system(
                tx,
                "gateway",
                "ingress.admit",
                &json!(admitted.request),
                &json!(admitted.tenant),
                json!({"hostname": admitted.hostname}),
            )
            .await?;
        }
        if let Some(observed) = &batch.observed {
            exec(
                tx,
                "DELETE FROM gateway_observations WHERE session_id=$1",
                args![session],
            )
            .await?;
            if !observed.is_empty() {
                exec(tx,"INSERT INTO gateway_observations(session_id,key,kind,ready,busy,idle_ms,waiting_ms,saturated_ms)
                    SELECT $1,o.key,o.kind,COALESCE(o.ready,false),COALESCE(o.busy,false),o.idle_ms,o.waiting_ms,o.saturated_ms
                    FROM jsonb_to_recordset($2) AS o(key text,kind text,ready boolean,busy boolean,idle_ms bigint,waiting_ms bigint,saturated_ms bigint)",args![session,Value::Array(observed.clone())]).await?;
            }
        }
        if !batch.renewed.is_empty() {
            // What renewals from memory issued, for the status a run's
            // grant is read with. Never a revision or a deadline back.
            let renewed: Vec<Value> = batch.renewed.iter().map(|r| json!({"execution":r.execution,"generation":r.generation,"revision":r.revision,"deadline_ms":r.deadline_ms})).collect();
            exec(tx,"UPDATE execution_egress_budgets b SET revision=GREATEST(b.revision,r.revision),expires=GREATEST(b.expires,to_timestamp(r.deadline_ms/1000.0)),updated=now()
                FROM jsonb_to_recordset($1) AS r(execution text,generation bigint,revision bigint,deadline_ms bigint)
                WHERE b.execution_id=r.execution AND b.generation=r.generation AND b.state='active' AND r.revision<=GREATEST(b.revision,b.revision_reserved)",args![Value::Array(renewed)]).await?;
        }
        if !batch.active.is_empty() {
            // An app with a request in flight, or one since the last flush,
            // is not idle: what stops an idle app reads this.
            exec(tx,"UPDATE app_http SET last_activity=clock_timestamp() WHERE app_id IN (SELECT jsonb_array_elements_text($1))",args![json!(batch.active)]).await?;
        }
        let mut written = self.write_leases(tx, &batch.leases).await?;
        written.shares = self.write_shares(tx, closing).await?;
        Ok(written)
    }

    /// What this process uses of `tenant`'s limits now.
    fn share_used(&self, tenant: &str) -> crate::shares::Limits {
        crate::shares::Limits {
            concurrent: self.gateway.gates.in_flight_of(tenant) as i64,
            per_minute: self.http_rates.count(tenant),
            connections: self.sockets.count(tenant),
        }
    }

    /// Takes, or brings to its size, this process's share of `tenant`'s
    /// limits ([`crate::shares::fair`]), in `tx`, which holds the lock.
    pub(crate) async fn take_share(
        &self,
        tx: &mut Tx,
        tenant: &str,
        concurrent: i64,
        per_minute: i64,
    ) -> Result<(crate::shares::Limits, crate::shares::Limits)> {
        use crate::{
            db::{n, one},
            shares::{Limits, fair},
        };
        let session = self.gateway.session();
        let others = one(tx,&format!("SELECT COALESCE(sum(s.concurrent),0)::bigint AS concurrent,COALESCE(sum(s.per_minute),0)::bigint AS per_minute,COALESCE(sum(s.connections),0)::bigint AS connections,
            COALESCE(sum(s.used_concurrent),0)::bigint AS used_concurrent,COALESCE(sum(s.used_per_minute),0)::bigint AS used_per_minute,COALESCE(sum(s.used_connections),0)::bigint AS used_connections,count(*) AS holders
            FROM edge_limit_shares s JOIN gateway_sessions g ON g.id=s.session_id AND g.seen>clock_timestamp()-interval '{SESSION_DEAD}' WHERE s.tenant_id=$1 AND s.session_id<>$2"),args![tenant,session]).await?;
        let limit = Limits {
            concurrent,
            per_minute,
            connections: crate::websocket::MAX_PER_WORKSPACE as i64,
        };
        let used = self.share_used(tenant);
        let hold = Limits {
            concurrent: n(&others["concurrent"]),
            per_minute: n(&others["per_minute"]),
            connections: n(&others["connections"]),
        };
        let others_use = Limits {
            concurrent: n(&others["used_concurrent"]),
            per_minute: n(&others["used_per_minute"]),
            connections: n(&others["used_connections"]),
        };
        let share = fair(limit, used, hold, others_use, n(&others["holders"]) + 1);
        let room = crate::shares::room(limit, used, others_use);
        exec(
            tx,
            "INSERT INTO gateway_sessions(id) VALUES($1) ON CONFLICT(id) DO NOTHING",
            args![session],
        )
        .await?;
        exec(tx,"INSERT INTO edge_limit_shares(session_id,tenant_id,concurrent,per_minute,connections,used_concurrent,used_per_minute,used_connections) VALUES($1,$2,$3,$4,$5,$6,$7,$8)
            ON CONFLICT(session_id,tenant_id) DO UPDATE SET concurrent=excluded.concurrent,per_minute=excluded.per_minute,connections=excluded.connections,used_concurrent=excluded.used_concurrent,used_per_minute=excluded.used_per_minute,used_connections=excluded.used_connections,updated=clock_timestamp()",
            args![session,tenant,share.concurrent,share.per_minute,share.connections,used.concurrent,used.per_minute,used.connections]).await?;
        Ok((share, room))
    }

    /// This process's share of `tenant`'s limits, taken now if it holds
    /// none: in a transaction under the lock, which the workspace's first
    /// request here makes.
    pub(crate) async fn share(
        &self,
        tenant: &str,
        concurrent: i64,
        per_minute: i64,
    ) -> Result<crate::shares::Limits> {
        if let Some(share) = self.gateway.shares.of(tenant) {
            return Ok(share);
        }
        if self.gateway.outage.down_for().is_some() {
            return Err(crate::error::Error::database_unavailable());
        }
        let taken = crate::outage::within_locked(crate::outage::READ_WITHIN, async {
            let mut tx = self.gateway_transaction().await?;
            let share = self
                .take_share(&mut tx, tenant, concurrent, per_minute)
                .await?;
            tx.commit().await?;
            Ok(share)
        })
        .await;
        match taken {
            Ok(taken) => {
                self.gateway.shares.set(tenant, taken);
                Ok(taken.0)
            }
            Err(error) => {
                self.gateway.outage.failed(&error);
                Err(error)
            }
        }
    }

    /// This process's share of `tenant`'s limits, when it has not room for
    /// one more request and the workspace has: other processes hold what it
    /// does not use, and give it back at their next flush. Waits up to two
    /// seconds for that, taking its share again as they do. `None` when the
    /// workspace has no room, or none came.
    /// This process's share of `tenant`'s limits, and the room the
    /// workspace had, taken again under the lock for requests short of it:
    /// at most every [`crate::shares::RETAKE`], however many requests ask.
    /// The others have the share as it last was, without the lock. The
    /// limits are read when not given. `None` when it could not be taken.
    pub(crate) async fn retake_share(
        &self,
        tenant: &str,
        limits: Option<(i64, i64)>,
    ) -> Option<(crate::shares::Limits, crate::shares::Limits)> {
        let mut retaken = self.gateway.shares.retaken.lock().await;
        if retaken
            .get(tenant)
            .is_some_and(|at| at.elapsed() < crate::shares::RETAKE)
        {
            drop(retaken);
            return Some((
                self.gateway.shares.of(tenant)?,
                self.gateway.shares.room_of(tenant)?,
            ));
        }
        let taken = crate::outage::within_locked(crate::outage::READ_WITHIN, async {
            let mut tx = self.gateway_transaction().await?;
            let (concurrent, per_minute) = match limits {
                Some(limits) => limits,
                None => {
                    let row = crate::db::one(&mut tx,"SELECT http_concurrent_requests concurrent,http_requests_per_minute per_minute FROM tenants WHERE id=$1",args![tenant]).await?;
                    (crate::db::n(&row["concurrent"]), crate::db::n(&row["per_minute"]))
                }
            };
            let share = self
                .take_share(&mut tx, tenant, concurrent, per_minute)
                .await?;
            tx.commit().await?;
            Ok::<_, crate::error::Error>(share)
        })
        .await
        .ok()?;
        self.gateway.shares.set(tenant, taken);
        retaken.insert(tenant.to_owned(), std::time::Instant::now());
        Some(taken)
    }

    pub(crate) async fn grow_share(
        &self,
        tenant: &str,
        concurrent: i64,
        per_minute: i64,
        enough: impl Fn(crate::shares::Limits) -> bool,
    ) -> Option<crate::shares::Limits> {
        let until = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            let room = self.gateway.shares.room_of(tenant)?;
            if room.concurrent < 1 && room.per_minute < 1
                || self.gateway.outage.down_for().is_some()
            {
                return None;
            }
            if tokio::time::Instant::now() >= until {
                return None;
            }
            tokio::time::sleep(crate::shares::RETAKE).await;
            let taken = self
                .retake_share(tenant, Some((concurrent, per_minute)))
                .await?;
            if enough(taken.0) {
                return Some(taken.0);
            }
        }
    }

    /// Brings each share to its size, or gives back one nothing has used
    /// for a while, or every one when closing.
    async fn write_shares(
        &self,
        tx: &mut Tx,
        closing: bool,
    ) -> Result<
        Vec<(
            String,
            Option<(crate::shares::Limits, crate::shares::Limits)>,
        )>,
    > {
        use crate::db::{n, optional};
        let mut written = Vec::new();
        for (tenant, idle) in self.gateway.shares.held(std::time::Duration::from_secs(30)) {
            let used = self.share_used(&tenant);
            if closing || idle && used.is_zero() {
                exec(
                    tx,
                    "DELETE FROM edge_limit_shares WHERE session_id=$1 AND tenant_id=$2",
                    args![self.gateway.session(), tenant],
                )
                .await?;
                written.push((tenant, None));
                continue;
            }
            let Some(limits) = optional(
                tx,
                "SELECT http_concurrent_requests,http_requests_per_minute FROM tenants WHERE id=$1",
                args![tenant],
            )
            .await?
            else {
                written.push((tenant, None));
                continue;
            };
            let share = self
                .take_share(
                    tx,
                    &tenant,
                    n(&limits["http_concurrent_requests"]),
                    n(&limits["http_requests_per_minute"]),
                )
                .await?;
            written.push((tenant, Some(share)));
        }
        Ok(written)
    }

    /// What was used is recorded and comes off the leases; what is given
    /// back comes off them too; and each lease that is short of its size
    /// is granted what the allowance has for it.
    async fn write_leases(&self, tx: &mut Tx, taken: &crate::lease::Taken) -> Result<Written> {
        use crate::db::rows;
        let session = self.gateway.session();
        let mut written = Written::default();
        const LEASE: &str =
            "(tenant_id text,project_id text,period date,bytes bigint,requests bigint)";
        if !taken.used.is_empty() {
            let used: Vec<Value> = taken.used.iter().map(|used| json!({"tenant_id":used.key.0,"project_id":used.key.1,"period":used.period,"bytes":used.bytes,"requests":used.requests})).collect();
            exec(tx,&format!("INSERT INTO traffic_usage(tenant_id,project_id,period,bytes,requests)
                SELECT tenant_id,project_id,period,bytes,requests FROM jsonb_to_recordset($1) AS u{LEASE}
                ON CONFLICT(tenant_id,project_id,period) DO UPDATE SET bytes=traffic_usage.bytes+excluded.bytes,requests=traffic_usage.requests+excluded.requests"),args![Value::Array(used)]).await?;
        }
        // Off the leases: what was used, and what is given back.
        let mut off: Vec<Value> = taken.used.iter().filter(|used| used.bytes > 0).map(|used| json!({"tenant_id":used.key.0,"project_id":used.key.1,"period":used.period,"bytes":used.bytes})).collect();
        off.extend(taken.gives.iter().map(|(key, period, bytes)| json!({"tenant_id":key.0,"project_id":key.1,"period":period,"bytes":bytes})));
        if !off.is_empty() {
            let found = rows(tx,&format!("UPDATE gateway_transfer_leases l SET held_bytes=GREATEST(0,l.held_bytes-u.bytes),updated=clock_timestamp()
                FROM (SELECT tenant_id,project_id,period,sum(bytes)::bigint bytes FROM jsonb_to_recordset($2) AS u{LEASE} GROUP BY tenant_id,project_id,period) u
                WHERE l.session_id=$1 AND l.tenant_id=u.tenant_id AND l.project_id=u.project_id AND l.period=u.period
                RETURNING l.tenant_id,l.project_id,l.period::text AS period"),args![session,Value::Array(off)]).await?;
            // A lease that is not there was charged as a dead session's:
            // this process did not flush for too long.
            for used in taken.used.iter().filter(|used| used.bytes > 0) {
                if !found.iter().any(|row| {
                    row["tenant_id"] == used.key.0
                        && row["project_id"] == used.key.1
                        && row["period"] == used.period
                }) {
                    written.lost.push(used.key.clone());
                }
            }
        }
        for (key, period) in &taken.returns {
            exec(tx,"DELETE FROM gateway_transfer_leases WHERE session_id=$1 AND tenant_id=$2 AND project_id=$3 AND period=$4::date",args![session,key.0,key.1,period]).await?;
        }
        for (key, want) in &taken.asks {
            let (_, granted) = self.lease_grant(tx, key, *want).await?;
            written.granted.push((key.clone(), granted, *want));
        }
        exec(
            tx,
            "DELETE FROM gateway_transfer_leases WHERE session_id=$1 AND held_bytes=0",
            args![session],
        )
        .await?;
        Ok(written)
    }

    /// Adds to this session's lease for `key` what the workspace's
    /// allowance has of the `want` bytes asked for, in this month: none
    /// when the workspace is not active. Says the month and what was
    /// granted. The caller holds the mutation lock, and tells the budget
    /// once its transaction has committed.
    pub(crate) async fn lease_grant(
        &self,
        tx: &mut Tx,
        key: &crate::lease::Key,
        want: i64,
    ) -> Result<(String, i64)> {
        use crate::db::{n, one, s};
        let room = one(tx,&format!("SELECT cur.period::text AS period,CASE WHEN t.lifecycle_state='active' THEN LEAST($2::numeric,GREATEST(0,t.transfer_bytes-COALESCE((SELECT sum(used_bytes+held_bytes) FROM transfer_allowance_accounting a WHERE a.tenant_id=t.id AND a.period=cur.period),0))) ELSE 0 END::bigint AS granted FROM tenants t,(SELECT {PERIOD} AS period) cur WHERE t.id=$1"),args![key.0,want.max(0)]).await?;
        let (period, granted) = (s(&room["period"]).to_owned(), n(&room["granted"]));
        if granted > 0 {
            let session = self.gateway.session();
            // A lease is some session's: one that has not flushed yet has
            // its row from here.
            exec(
                tx,
                "INSERT INTO gateway_sessions(id) VALUES($1) ON CONFLICT(id) DO NOTHING",
                args![session],
            )
            .await?;
            exec(tx,"INSERT INTO gateway_transfer_leases(session_id,tenant_id,project_id,period,held_bytes) VALUES($1,$2,$3,$4::date,$5)
                ON CONFLICT(session_id,tenant_id,project_id,period) DO UPDATE SET held_bytes=gateway_transfer_leases.held_bytes+excluded.held_bytes,updated=clock_timestamp()",args![session,key.0,key.1,period,granted]).await?;
        }
        Ok((period, granted))
    }

    /// Extends the lease of `key` by up to `want` bytes, now: for a request
    /// that found it without the `need` bytes it was about to pass, between
    /// flushes. Whether it has them after.
    pub async fn lease_extend(&self, key: &crate::lease::Key, need: i64, want: i64) -> bool {
        let _one = self.gateway.extending.lock().await;
        // Another request asked while this one waited.
        if self.gateway.budgets.has(key, need) {
            return true;
        }
        if self.gateway.budgets.exhausted(key) {
            return false;
        }
        // Not while the database cannot be reached: nothing is extended, and
        // nothing waits for a connection that will not come.
        if self.gateway.outage.down_for().is_some() {
            return false;
        }
        let want = want.max(need);
        let granted = crate::outage::within_locked(crate::outage::READ_WITHIN, async {
            let mut tx = self.gateway_transaction().await?;
            let granted = self.lease_grant(&mut tx, key, want).await?;
            tx.commit().await?;
            Ok::<_, crate::error::Error>(granted)
        })
        .await;
        match granted {
            Ok((period, granted)) => {
                self.gateway.budgets.granted(key, &period, granted, want);
                self.gateway.budgets.has(key, need)
            }
            Err(error) => {
                self.gateway.outage.failed(&error);
                false
            }
        }
    }

    /// Forgets the sessions of processes that are gone. What such a
    /// session held of a transfer allowance is counted as used: how much of
    /// it the process passed before it went is not known, so all of it is
    /// charged, and said to be conservative. A lease whose session has no
    /// row is one of those too.
    pub(crate) async fn expire_gateway_sessions(tx: &mut Tx) -> Result<()> {
        exec(
            tx,
            &format!(
                "WITH gone AS (DELETE FROM gateway_transfer_leases l WHERE NOT EXISTS(SELECT 1 FROM gateway_sessions s WHERE s.id=l.session_id AND s.seen>=clock_timestamp()-interval '{SESSION_DEAD}') RETURNING l.tenant_id,l.project_id,l.period,l.held_bytes)
                INSERT INTO traffic_usage(tenant_id,project_id,period,bytes,requests,conservative_bytes)
                SELECT tenant_id,project_id,period,sum(held_bytes)::bigint,0,sum(held_bytes)::bigint FROM gone GROUP BY tenant_id,project_id,period HAVING sum(held_bytes)>0
                ON CONFLICT(tenant_id,project_id,period) DO UPDATE SET bytes=traffic_usage.bytes+excluded.bytes,conservative_bytes=traffic_usage.conservative_bytes+excluded.conservative_bytes"
            ),
            args![],
        )
        .await?;
        exec(
            tx,
            &format!(
                "WITH gone AS (DELETE FROM gateway_sessions WHERE seen<clock_timestamp()-interval '{SESSION_DEAD}' RETURNING id),
                shares AS (DELETE FROM edge_limit_shares WHERE session_id IN (SELECT id FROM gone) OR NOT EXISTS(SELECT 1 FROM gateway_sessions s WHERE s.id=edge_limit_shares.session_id))
                DELETE FROM gateway_observations WHERE session_id IN (SELECT id FROM gone) OR NOT EXISTS(SELECT 1 FROM gateway_sessions s WHERE s.id=gateway_observations.session_id)"
            ),
            args![],
        )
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opened() -> Opened {
        Opened {
            tenant: "t".into(),
            project: "p".into(),
            app: "a".into(),
            release: "r".into(),
            execution: None,
            method: "GET".into(),
            path: "/".into(),
        }
    }

    #[test]
    fn a_request_is_written_as_it_stands_and_once_when_it_ends() {
        let gateway = Gateway::default();
        gateway.opened("one", opened());
        let first = gateway.take();
        assert_eq!(first.rows[0]["state"], "queued");
        // Nothing changed: nothing to write again.
        assert!(gateway.take().rows.is_empty());
        gateway.bound("one", "e");
        gateway.dispatched("one");
        let second = gateway.take();
        assert_eq!(second.rows[0]["state"], "running");
        assert_eq!(second.rows[0]["execution_id"], "e");
        gateway.ended("one", Some(204));
        // Ending it again does not end it otherwise.
        gateway.ended("one", Some(500));
        let third = gateway.take();
        assert_eq!(third.rows.len(), 1);
        assert_eq!(third.rows[0]["state"], "succeeded");
        assert_eq!(third.rows[0]["http_status"], 204);
        assert!(third.rows[0]["finished_ago"].is_u64());
        assert!(gateway.take().rows.is_empty());
    }

    #[test]
    fn how_a_request_ended_is_what_is_known_of_it() {
        let gateway = Gateway::default();
        let state = |dispatched: bool, status: Option<u16>| {
            gateway.opened("r", opened());
            if dispatched {
                gateway.dispatched("r");
            }
            gateway.ended("r", status);
            gateway.take().rows[0]["state"].clone()
        };
        assert_eq!(state(true, Some(200)), "succeeded");
        assert_eq!(state(true, Some(502)), "failed");
        // Never given to its app: it did not run.
        assert_eq!(state(false, None), "failed");
        // Given to it and not answered: it may have.
        assert_eq!(state(true, None), "unknown");
    }

    #[test]
    fn what_a_flush_could_not_write_is_written_by_the_next() {
        let gateway = Gateway::default();
        gateway.opened("open", opened());
        gateway.opened("done", opened());
        gateway.ended("done", Some(200));
        gateway.admitted("done", "t", "app.example");
        let batch = gateway.take();
        assert_eq!(batch.rows.len(), 2);
        gateway.restore(batch);
        let again = gateway.take();
        assert_eq!(again.rows.len(), 2);
        assert_eq!(again.admitted.len(), 1);
    }

    #[test]
    fn records_the_database_does_not_take_are_dropped_oldest_first_and_counted() {
        let gateway = Gateway::default();
        for index in 0..MOST_WAITING + 3 {
            let id = index.to_string();
            gateway.opened(&id, opened());
            gateway.ended(&id, Some(200));
        }
        assert_eq!(gateway.dropped(), 3);
        assert_eq!(gateway.take().rows[0]["id"], "3");
    }
}
