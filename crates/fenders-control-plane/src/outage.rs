//! Whether the database can be reached, as the gateway and the run channel
//! need to know it to go on serving without it.
//!
//! What an edge serves from memory (gates, launches, leases, renewals) it
//! believes for two seconds, then reads again. While the database cannot be
//! reached, reading again cannot be done, and nothing can be changed either:
//! what was known when it went away is still what the database says. So
//! for up to [`Outage::bound`] after the first failure, what is known is
//! believed however old it is, and only what needs the database is refused
//! (`docs/edge-plan.md`, section D).
//!
//! An outage is noticed by a call that fails for want of the database, and
//! is over when a call succeeds; the flush makes one every second. While it
//! lasts, the request path does not ask the database at all: each ask would
//! wait for a connection that will not come.
use std::{
    sync::Mutex,
    time::{Duration, Instant},
};

/// How long what is known is believed while the database cannot be reached
/// (E11), unless the operator says otherwise.
pub const BOUND: Duration = Duration::from_secs(600);

pub struct Outage {
    since: Mutex<Option<Instant>>,
    bound: Duration,
}

impl Default for Outage {
    fn default() -> Self {
        Self::new(BOUND)
    }
}

impl Outage {
    pub fn new(bound: Duration) -> Self {
        Self {
            since: Mutex::new(None),
            bound,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Option<Instant>> {
        self.since.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A call failed: if for want of the database, an outage began, unless
    /// one already had. Whether it was.
    pub fn failed(&self, error: &crate::error::Error) -> bool {
        if !unreachable(error) {
            return false;
        }
        self.lock().get_or_insert_with(Instant::now);
        true
    }

    /// A call succeeded: the database is there.
    pub fn reached(&self) {
        self.lock().take();
    }

    /// For how long the database has not been reached; `None` when it has.
    pub fn down_for(&self) -> Option<Duration> {
        self.lock().map(|since| since.elapsed())
    }

    /// Whether what is known is to be believed however old it is: the
    /// database cannot be reached, and has not been for less than the bound.
    pub fn serving_stale(&self) -> bool {
        self.down_for().is_some_and(|down| down < self.bound)
    }

    /// Whether this process has stopped believing what it knows: the
    /// database has not been reached for longer than the bound.
    pub fn past_bound(&self) -> bool {
        self.down_for().is_some_and(|down| down >= self.bound)
    }

    pub fn bound(&self) -> Duration {
        self.bound
    }
}

/// How long the request path waits for the database before it takes it
/// for gone: a database that hangs, rather than refusing, would otherwise
/// keep a request, or the flush, waiting for as long as it hangs.
pub const READ_WITHIN: Duration = Duration::from_secs(2);
pub const FLUSH_WITHIN: Duration = Duration::from_secs(5);

/// `work`, or the database taken for gone if it has not answered `within`.
pub async fn within<T>(
    within: Duration,
    work: impl std::future::Future<Output = crate::error::Result<T>>,
) -> crate::error::Result<T> {
    tokio::time::timeout(within, work)
        .await
        .unwrap_or_else(|_| Err(crate::error::Error::database_unavailable()))
}

/// Whether `error` is the database not being there.
pub fn unreachable(error: &crate::error::Error) -> bool {
    error.is_database_unavailable()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;

    #[test]
    fn an_outage_is_noticed_by_a_failure_for_want_of_the_database_and_ends_with_a_success() {
        let outage = Outage::new(Duration::from_millis(50));
        assert!(!outage.failed(&Error::internal()));
        assert_eq!(outage.down_for(), None);
        let unavailable = Error::database_unavailable();
        assert!(outage.failed(&unavailable));
        assert!(outage.serving_stale());
        std::thread::sleep(Duration::from_millis(60));
        assert!(!outage.serving_stale());
        assert!(outage.past_bound());
        outage.reached();
        assert!(!outage.serving_stale() && !outage.past_bound());
    }
}
