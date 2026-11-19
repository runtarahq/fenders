//! What the request exchange shows of HTTP runs, as the reconciler reads it.
//!
//! The reconciler decides from what the exchange sees: that a run's shim
//! asks for requests (so the app serves on it), that it is busy with one
//! (so it is not stopped yet), that it has been idle (so an extra execution
//! is given back), that requests wait or no shim is free (so another is
//! started). The exchange is in the memory of the process that serves the
//! gateway and the run channel.
//!
//! In one process the reconciler reads that memory. When the gateway and
//! the run channel are an edge's ([`crate::store::Serves`]), the edge's flush
//! writes what its exchange sees once a second (`gateway_observations`),
//! and the control process reads it, a second old at most. Read from the
//! database, a run counts as busy for two seconds after it last took or
//! finished a request: what it took since the flush is not known.
use crate::http_exchange::Pressure;
use serde_json::{Value, json};
use std::{collections::HashMap, time::Duration};

pub(crate) const MIGRATION: &str = "CREATE TABLE IF NOT EXISTS gateway_observations (
    session_id text NOT NULL, key text NOT NULL, kind text NOT NULL CHECK(kind IN ('taker','queue')),
    ready boolean NOT NULL DEFAULT false, busy boolean NOT NULL DEFAULT false,
    idle_ms bigint, waiting_ms bigint, saturated_ms bigint,
    observed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(session_id, kind, key))";

/// How long after it last took or finished a request a run read from the
/// database counts as busy.
const SETTLING: Duration = Duration::from_secs(2);

/// One run's shim, as the exchange saw it.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Taker {
    pub ready: bool,
    pub busy: bool,
    /// For how long it has had nothing to do; `None` while busy.
    pub idle: Option<Duration>,
}

#[derive(Clone, Debug, Default)]
pub struct Observed {
    takers: HashMap<String, Taker>,
    queues: HashMap<String, Pressure>,
}

impl Observed {
    pub(crate) fn new(takers: HashMap<String, Taker>, queues: HashMap<String, Pressure>) -> Self {
        Self { takers, queues }
    }

    pub fn ready(&self, execution: &str) -> bool {
        self.takers.get(execution).is_some_and(|t| t.ready)
    }

    pub fn busy(&self, execution: &str) -> bool {
        self.takers.get(execution).is_some_and(|t| t.busy)
    }

    pub fn idle(&self, execution: &str) -> Option<Duration> {
        self.takers.get(execution).and_then(|t| t.idle)
    }

    pub fn pressure(&self, key: &str) -> Pressure {
        self.queues.get(key).cloned().unwrap_or_default()
    }

    /// Rows for `gateway_observations`, as the flush writes them.
    pub(crate) fn rows(&self) -> Vec<Value> {
        let ms = |d: Option<Duration>| d.map(|d| d.as_millis() as u64);
        let mut rows: Vec<Value> = self
            .takers
            .iter()
            .map(|(key, t)| json!({"key":key,"kind":"taker","ready":t.ready,"busy":t.busy,"idle_ms":ms(t.idle)}))
            .collect();
        rows.extend(self.queues.iter().map(|(key, p)| {
            json!({"key":key,"kind":"queue","waiting_ms":ms(p.waiting),"saturated_ms":ms(p.saturated)})
        }));
        rows
    }

    /// What the rows of live sessions say, each aged by how long ago it
    /// was written (`age_ms`). Two sessions that saw the same run (one
    /// taking over from the other) are taken together: ready if either saw
    /// it so, busy if either did.
    pub(crate) fn from_rows(rows: &[Value]) -> Self {
        let mut observed = Self::default();
        let at = |row: &Value, key: &str| {
            row[key]
                .as_u64()
                .map(|ms| Duration::from_millis(ms + row["age_ms"].as_u64().unwrap_or(0)))
        };
        for row in rows {
            let key = row["key"].as_str().unwrap_or_default().to_owned();
            if row["kind"] == "taker" {
                let idle = at(row, "idle_ms");
                let seen = Taker {
                    ready: row["ready"] == true,
                    busy: row["busy"] == true || idle.is_none_or(|idle| idle < SETTLING),
                    idle,
                };
                let taker = observed.takers.entry(key).or_default();
                taker.ready |= seen.ready;
                taker.busy |= seen.busy;
                taker.idle = match (taker.idle, seen.idle) {
                    (Some(a), Some(b)) => Some(a.min(b)),
                    (a, b) => a.or(b),
                };
                if taker.busy {
                    taker.idle = None;
                }
            } else {
                let seen = Pressure {
                    waiting: at(row, "waiting_ms"),
                    saturated: at(row, "saturated_ms"),
                };
                let pressure = observed.queues.entry(key).or_default();
                pressure.waiting = pressure.waiting.max(seen.waiting);
                pressure.saturated = match (pressure.saturated, seen.saturated) {
                    (Some(a), Some(b)) => Some(a.min(b)),
                    (a, b) => a.or(b),
                };
            }
        }
        observed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_was_written_reads_back_older_and_busy_while_it_settles() {
        let mut takers = HashMap::new();
        takers.insert(
            "quiet".to_owned(),
            Taker {
                ready: true,
                busy: false,
                idle: Some(Duration::from_secs(70)),
            },
        );
        takers.insert(
            "fresh".to_owned(),
            Taker {
                ready: true,
                busy: false,
                idle: Some(Duration::from_millis(500)),
            },
        );
        let mut queues = HashMap::new();
        queues.insert(
            "app".to_owned(),
            Pressure {
                waiting: Some(Duration::from_secs(3)),
                saturated: None,
            },
        );
        let observed = Observed::new(takers, queues);
        let rows: Vec<Value> = observed
            .rows()
            .into_iter()
            .map(|mut row| {
                row["age_ms"] = json!(1000);
                row
            })
            .collect();
        let read = Observed::from_rows(&rows);
        assert!(read.ready("quiet") && !read.busy("quiet"));
        assert_eq!(read.idle("quiet"), Some(Duration::from_secs(71)));
        // Idle a moment ago: what it did since is not known.
        assert!(read.busy("fresh"));
        assert_eq!(read.idle("fresh"), None);
        assert_eq!(read.pressure("app").waiting, Some(Duration::from_secs(4)));
        assert!(!read.ready("nobody"));
    }

    #[test]
    fn two_sessions_that_saw_one_run_are_taken_together() {
        let row = |ready: bool, busy: bool, idle: Option<u64>| json!({"key":"e","kind":"taker","ready":ready,"busy":busy,"idle_ms":idle,"age_ms":0});
        let read = Observed::from_rows(&[
            row(false, false, Some(90_000)),
            row(true, false, Some(80_000)),
        ]);
        assert!(read.ready("e"));
        assert_eq!(read.idle("e"), Some(Duration::from_secs(80)));
        let read = Observed::from_rows(&[row(true, true, None), row(true, false, Some(80_000))]);
        assert!(read.busy("e"));
    }
}
