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
}

pub struct Gateway {
    session: String,
    inner: Mutex<Inner>,
}

impl Default for Gateway {
    fn default() -> Self {
        Self {
            session: uid(),
            inner: Default::default(),
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

impl Store {
    /// Writes what the gateway holds in memory: its session, the records of
    /// requests that ended or changed, and the admissions to be audited.
    /// One transaction, whatever it holds. What cannot be written is kept
    /// for the next flush.
    pub async fn flush_gateway(&self) -> Result<()> {
        if !self.gateway.due() {
            return Ok(());
        }
        let mut tx = self.transaction(true, false).await?;
        // Taken once the lock is held: a record's times are written as how
        // long ago they were, by the database's clock.
        let batch = self.gateway.take();
        match self.write_gateway(&mut tx, &batch).await {
            Ok(()) => match tx.commit().await {
                Ok(()) => {
                    self.gateway.flushed();
                    Ok(())
                }
                Err(error) => {
                    self.gateway.restore(batch);
                    Err(error.into())
                }
            },
            Err(error) => {
                self.gateway.restore(batch);
                Err(error)
            }
        }
    }

    async fn write_gateway(&self, tx: &mut Tx, batch: &Batch) -> Result<()> {
        exec(
            tx,
            "INSERT INTO gateway_sessions(id) VALUES($1) ON CONFLICT(id) DO UPDATE SET seen=clock_timestamp()",
            args![self.gateway.session()],
        )
        .await?;
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
        Ok(())
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
                "DELETE FROM gateway_sessions WHERE seen<clock_timestamp()-interval '{SESSION_DEAD}'"
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
