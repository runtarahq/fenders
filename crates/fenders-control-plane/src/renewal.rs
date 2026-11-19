//! Outbound grants renewed from memory.
//!
//! A run under the outbound byte limit asks the run channel every few
//! seconds to renew its grant: the launcher lets it send only until a
//! deadline, so a run whose control plane goes away stops sending. Each
//! renewal was a transaction under the mutation lock, so their rate grew
//! with the number of running runs, whether they sent anything or not.
//!
//! A renewal (an ask for no more bytes) is now answered from what this
//! process keeps of the run's grant: the next revision and a deadline ten
//! seconds on. Only a grant of more bytes is a transaction.
//!
//! The launcher refuses a deadline unless its revision is higher than the
//! last, and this memory goes with the process. So the transaction that
//! grants a run its bytes also **reserves** revisions above the one it
//! writes ([`RESERVED`] of them), and a renewal takes the next of those. A
//! process that has nothing of a run in memory (it restarted, or took the
//! run over) goes to the database, which accepts any revision a renewal
//! could have issued and reserves the next range.
//!
//! The flush writes each renewed run's revision and deadline, for the
//! status a run's grant is read with; nothing enforces the deadline but the
//! launcher.
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

/// Revisions reserved for renewals at a time: renewed every three seconds,
/// 36 days of them, past the 24 hours a run lives.
pub const RESERVED: i64 = 1 << 20;
/// How long a renewal lasts.
pub const LASTS: Duration = Duration::from_secs(10);
/// A run not renewed for this long is forgotten.
const FORGOTTEN: Duration = Duration::from_secs(60);

/// What this process keeps of one run's grant.
#[derive(Clone, Debug)]
struct Grant {
    generation: i64,
    boot: String,
    revision: i64,
    reserved: i64,
    /// The answer's other fields, as the database last gave them.
    answer: Value,
    /// When the month the grant is for ends, in milliseconds since the
    /// epoch: no renewal lasts past it.
    period_end_ms: u64,
    /// The last renewal asked, and its answer, for a repeated ask.
    last: Option<(String, Value, Value)>,
    /// The deadline of the last renewal, in milliseconds since the epoch,
    /// when the flush has yet to write it.
    unwritten: Option<u64>,
    touched: Instant,
}

/// A renewal to write: the run, its generation, revision and deadline.
#[derive(Clone, Debug, PartialEq)]
pub struct Renewed {
    pub execution: String,
    pub generation: i64,
    pub revision: i64,
    pub deadline_ms: u64,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

#[derive(Default)]
pub struct Renewals {
    inner: Mutex<HashMap<String, Grant>>,
}

impl Renewals {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Grant>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// What the database answered a grant or a renewal of `execution` with,
    /// and the revisions it reserved: kept, when the grant is active.
    pub fn granted(
        &self,
        execution: &str,
        generation: i64,
        answer: &Value,
        reserved: i64,
        period_end_ms: u64,
    ) {
        let mut inner = self.lock();
        let (Some(revision), Some(boot)) =
            (answer["revision"].as_i64(), answer["boot_id"].as_str())
        else {
            inner.remove(execution);
            return;
        };
        if answer["state"] != "active" {
            inner.remove(execution);
            return;
        }
        inner.insert(
            execution.to_owned(),
            Grant {
                generation,
                boot: boot.to_owned(),
                revision,
                reserved,
                answer: answer.clone(),
                period_end_ms,
                last: None,
                unwritten: None,
                touched: Instant::now(),
            },
        );
    }

    /// Renews the grant of `execution` from memory, when this process has
    /// it, for this launch, at the revision the shim says it has, with a
    /// revision left in the range and the month not over. `None` when the
    /// database is to be asked instead.
    pub fn renew(
        &self,
        execution: &str,
        generation: i64,
        boot: &str,
        expected: i64,
        request: &str,
        body: &Value,
    ) -> Option<Value> {
        let mut inner = self.lock();
        let grant = inner.get_mut(execution)?;
        if grant.generation != generation || grant.boot != boot {
            return None;
        }
        if let Some((id, asked, answer)) = &grant.last
            && id == request
        {
            // Asked again, as it was: answered as it was. Asked otherwise
            // under the same id: the database says what that is.
            return (asked == body).then(|| answer.clone());
        }
        let now = now_ms();
        if expected != grant.revision
            || grant.revision >= grant.reserved
            || now >= grant.period_end_ms
        {
            return None;
        }
        let deadline = (now + LASTS.as_millis() as u64).min(grant.period_end_ms);
        grant.revision += 1;
        let mut answer = grant.answer.clone();
        answer["revision"] = json!(grant.revision);
        answer["ttl_ms"] = json!(deadline - now);
        grant.last = Some((request.to_owned(), body.clone(), answer.clone()));
        grant.unwritten = Some(deadline);
        grant.touched = Instant::now();
        Some(answer)
    }

    /// The run's grant is not this process's to renew any more.
    pub fn forget(&self, execution: &str) {
        self.lock().remove(execution);
    }

    /// Renewals the flush is to write, and runs not renewed for a while
    /// forgotten.
    pub fn take(&self) -> Vec<Renewed> {
        let mut inner = self.lock();
        inner.retain(|_, grant| grant.unwritten.is_some() || grant.touched.elapsed() < FORGOTTEN);
        inner
            .iter_mut()
            .filter_map(|(execution, grant)| {
                grant.unwritten.take().map(|deadline_ms| Renewed {
                    execution: execution.clone(),
                    generation: grant.generation,
                    revision: grant.revision,
                    deadline_ms,
                })
            })
            .collect()
    }

    /// What a flush took and could not write.
    pub fn restore(&self, renewed: Vec<Renewed>) {
        let mut inner = self.lock();
        for renewal in renewed {
            if let Some(grant) = inner.get_mut(&renewal.execution)
                && grant.unwritten.is_none()
            {
                grant.unwritten = Some(renewal.deadline_ms);
            }
        }
    }

    /// Whether a flush has renewals to write.
    pub fn due(&self) -> bool {
        self.lock().values().any(|grant| grant.unwritten.is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answer(revision: i64) -> Value {
        json!({"revision":revision,"state":"active","boot_id":"b","ceiling_bytes":"4096","ttl_ms":10000})
    }
    fn far() -> u64 {
        now_ms() + 86_400_000
    }

    #[test]
    fn a_renewal_takes_the_next_reserved_revision_and_lasts_ten_seconds() {
        let renewals = Renewals::default();
        let body = json!({"bytes":0});
        assert_eq!(renewals.renew("e", 1, "b", 4, "r1", &body), None);
        renewals.granted("e", 1, &answer(4), 6, far());
        let first = renewals.renew("e", 1, "b", 4, "r1", &body).unwrap();
        assert_eq!(first["revision"], 5);
        assert_eq!(first["ceiling_bytes"], "4096");
        assert!(first["ttl_ms"].as_u64().unwrap() <= 10_000);
        // Asked again: the same answer, and nothing more is issued.
        assert_eq!(renewals.renew("e", 1, "b", 4, "r1", &body), Some(first));
        // The same id with another ask is the database's to say.
        assert_eq!(
            renewals.renew("e", 1, "b", 4, "r1", &json!({"bytes":1})),
            None
        );
        // At a revision the shim does not have: the database.
        assert_eq!(renewals.renew("e", 1, "b", 4, "r2", &body), None);
        assert_eq!(
            renewals.renew("e", 1, "b", 5, "r2", &body).unwrap()["revision"],
            6
        );
        // The range is used up: the database, which reserves more.
        assert_eq!(renewals.renew("e", 1, "b", 6, "r3", &body), None);
        // Another launch, another boot: the database.
        renewals.granted("e", 1, &answer(6), 100, far());
        assert_eq!(renewals.renew("e", 2, "b", 6, "r4", &body), None);
        assert_eq!(renewals.renew("e", 1, "x", 6, "r4", &body), None);
    }

    #[test]
    fn no_renewal_lasts_past_the_month_or_is_made_after_it() {
        let renewals = Renewals::default();
        let body = json!({});
        let end = now_ms() + 2_000;
        renewals.granted("e", 1, &answer(1), 100, end);
        let renewed = renewals.renew("e", 1, "b", 1, "r", &body).unwrap();
        assert!(renewed["ttl_ms"].as_u64().unwrap() <= 2_000);
        renewals.granted("e", 1, &answer(2), 100, now_ms());
        assert_eq!(renewals.renew("e", 1, "b", 2, "s", &body), None);
    }

    #[test]
    fn a_grant_that_is_not_active_is_not_kept() {
        let renewals = Renewals::default();
        renewals.granted("e", 1, &answer(1), 100, far());
        let mut frozen = answer(2);
        frozen["state"] = json!("frozen");
        renewals.granted("e", 1, &frozen, 100, far());
        assert_eq!(renewals.renew("e", 1, "b", 2, "r", &json!({})), None);
    }

    #[test]
    fn renewals_are_written_by_the_flush_and_kept_if_it_fails() {
        let renewals = Renewals::default();
        renewals.granted("e", 1, &answer(1), 100, far());
        assert!(!renewals.due());
        renewals.renew("e", 1, "b", 1, "r", &json!({})).unwrap();
        assert!(renewals.due());
        let taken = renewals.take();
        assert_eq!(taken.len(), 1);
        assert_eq!(taken[0].revision, 2);
        assert!(!renewals.due());
        renewals.restore(taken);
        assert_eq!(renewals.take()[0].revision, 2);
    }
}
