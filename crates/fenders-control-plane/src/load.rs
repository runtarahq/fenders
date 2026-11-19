//! What this process has done since it started, counted: the transactions
//! it made under the lock all mutations share and how long they waited for
//! it, and what its gateway admitted. Read by the operator in
//! `GET /v1/control-plane/status`.
//!
//! The requests a second a control plane serves are bounded by how fast
//! those transactions commit, one at a time. These are the numbers that say
//! how near that bound a process is.
use serde_json::{Value, json};
use std::{
    sync::atomic::{AtomicU64, Ordering::Relaxed},
    time::Duration,
};

#[derive(Default)]
pub struct Load {
    locked: AtomicU64,
    lock_wait_micros: AtomicU64,
    admitted: AtomicU64,
    refused: AtomicU64,
    cold: AtomicU64,
}

impl Load {
    /// A transaction took the mutation lock, having waited `waited` for it.
    pub(crate) fn locked(&self, waited: Duration) {
        self.locked.fetch_add(1, Relaxed);
        self.lock_wait_micros
            .fetch_add(waited.as_micros().try_into().unwrap_or(u64::MAX), Relaxed);
    }

    /// The gateway admitted a request, or refused one.
    pub(crate) fn admission(&self, admitted: bool) {
        if admitted {
            &self.admitted
        } else {
            &self.refused
        }
        .fetch_add(1, Relaxed);
    }

    /// A request took the cold path: admission under the mutation lock.
    pub(crate) fn cold(&self) {
        self.cold.fetch_add(1, Relaxed);
    }

    /// Transactions made under the mutation lock.
    pub fn locked_transactions(&self) -> u64 {
        self.locked.load(Relaxed)
    }

    pub fn snapshot(&self) -> Value {
        json!({
            "database": {
                "locked_transactions": self.locked.load(Relaxed),
                "lock_wait_ms": self.lock_wait_micros.load(Relaxed) / 1000,
            },
            "gateway": {
                "admitted": self.admitted.load(Relaxed),
                "refused": self.refused.load(Relaxed),
                "cold": self.cold.load(Relaxed),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_was_counted_is_what_is_read() {
        let load = Load::default();
        load.locked(Duration::from_micros(1500));
        load.locked(Duration::from_micros(600));
        load.admission(true);
        load.admission(false);
        load.admission(false);
        assert_eq!(load.locked_transactions(), 2);
        assert_eq!(
            load.snapshot(),
            json!({
                "database": {"locked_transactions": 2, "lock_wait_ms": 2},
                "gateway": {"admitted": 1, "refused": 2, "cold": 0},
            })
        );
    }
}
