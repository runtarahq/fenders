//! Requests waiting together for an app to start.
//!
//! The first request to an app that does not serve is admitted under the
//! mutation lock: it holds a reservation that has the app woken, and it
//! waits for the app to serve. Others to the same host name that come
//! meanwhile follow it: they wait, in memory, without the lock and without
//! a reservation of their own, until it is done, and then are admitted as
//! any request is, warm if the app serves by then. A thousand requests to
//! an idle app take the lock once, not a thousand times.
//!
//! Only one process's requests follow one another: another edge's are its
//! own, and a request passed on to the app's edge is that edge's.
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tokio::sync::watch;

#[derive(Default)]
pub struct Wakes {
    waking: Mutex<HashMap<String, (u64, watch::Receiver<()>)>>,
    next: std::sync::atomic::AtomicU64,
    /// The reservations of requests waking apps, asked about together:
    /// one query a round for all of them, not one each ([`Rounds`]).
    pub rounds: Rounds,
    /// When the scheduler was last told of a wake ([`Self::tell_scheduler`]).
    told: Mutex<Option<std::time::Instant>>,
}

/// Whether waiting requests' apps serve, asked in rounds: whichever
/// waiting request finds none running and the last one old enough runs
/// the next, for every reservation waiting; the others read its answer.
/// However many requests wait, the database is asked a few times a second.
#[derive(Default)]
pub struct Rounds {
    waiting: Mutex<std::collections::HashSet<String>>,
    settled: Mutex<(
        Option<std::time::Instant>,
        std::collections::HashSet<String>,
    )>,
    running: tokio::sync::Mutex<()>,
}

/// How often the scheduler is told of wakes at most.
pub const TELL_EVERY: std::time::Duration = std::time::Duration::from_millis(50);

/// How often a round is run at most.
pub const ROUND: std::time::Duration = std::time::Duration::from_millis(100);

impl Rounds {
    fn waiting(&self) -> std::sync::MutexGuard<'_, std::collections::HashSet<String>> {
        self.waiting.lock().unwrap_or_else(|e| e.into_inner())
    }
    fn settled_lock(
        &self,
    ) -> std::sync::MutexGuard<
        '_,
        (
            Option<std::time::Instant>,
            std::collections::HashSet<String>,
        ),
    > {
        self.settled.lock().unwrap_or_else(|e| e.into_inner())
    }
    /// `reservation` waits, until [`Self::done`].
    pub fn wait(&self, reservation: &str) {
        self.waiting().insert(reservation.to_owned());
    }
    pub fn done(&self, reservation: &str) {
        self.waiting().remove(reservation);
        self.settled_lock().1.remove(reservation);
    }
    /// Whether the last round found `reservation`'s app serving, or its
    /// wake ended or changed.
    pub fn settled(&self, reservation: &str) -> bool {
        self.settled_lock().1.contains(reservation)
    }
    /// The reservations to ask about, when this caller is to run the next
    /// round: none is running and the last is at least [`ROUND`] old. The
    /// guard is held while it runs.
    pub fn take_turn(&self) -> Option<(tokio::sync::MutexGuard<'_, ()>, Vec<String>)> {
        let guard = self.running.try_lock().ok()?;
        if self.settled_lock().0.is_some_and(|at| at.elapsed() < ROUND) {
            return None;
        }
        Some((guard, self.waiting().iter().cloned().collect()))
    }
    /// What a round found settled.
    pub fn answer(&self, settled: std::collections::HashSet<String>) {
        let mut last = self.settled_lock();
        *last = (Some(std::time::Instant::now()), settled);
    }
}

/// What a request to a host name that does not serve does: wake its app,
/// or follow the one that is.
pub enum Wake {
    /// It wakes the app, until this is dropped.
    Lead(Leading),
    /// Another does: this resolves when it is done.
    Follow(watch::Receiver<()>),
}

/// Held by the request waking an app. Its followers are told when it is
/// dropped, however the wake ended.
pub struct Leading {
    wakes: Arc<Wakes>,
    hostname: String,
    id: u64,
    _done: watch::Sender<()>,
}

impl Drop for Leading {
    fn drop(&mut self) {
        let mut waking = self.wakes.lock();
        if waking
            .get(&self.hostname)
            .is_some_and(|(id, _)| *id == self.id)
        {
            waking.remove(&self.hostname);
        }
    }
}

impl Wakes {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, (u64, watch::Receiver<()>)>> {
        self.waking.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Leads the wake of `hostname`'s app, or follows the request that does.
    pub fn join(self: &Arc<Self>, hostname: &str) -> Wake {
        let mut waking = self.lock();
        if let Some((_, done)) = waking.get(hostname) {
            return Wake::Follow(done.clone());
        }
        let id = self.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let (sender, receiver) = watch::channel(());
        waking.insert(hostname.to_owned(), (id, receiver));
        Wake::Lead(Leading {
            wakes: self.clone(),
            hostname: hostname.to_owned(),
            id,
            _done: sender,
        })
    }

    /// Whether to tell the scheduler of a wake now: at most every
    /// [`TELL_EVERY`]. Each telling is a NOTIFY, and the commits of
    /// transactions that notify are made one at a time; one telling stands
    /// for every wake recorded before the scheduler's next pass, and the
    /// scheduler runs a pass every second besides.
    pub fn tell_scheduler(&self) -> bool {
        let mut told = self.told.lock().unwrap_or_else(|e| e.into_inner());
        if told.is_some_and(|at| at.elapsed() < TELL_EVERY) {
            return false;
        }
        *told = Some(std::time::Instant::now());
        true
    }

    /// How many apps' wakes are led now.
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Resolves when the request followed is done.
pub async fn followed(mut done: watch::Receiver<()>) {
    // The sender is never sent on: it is dropped when the leader is.
    while done.changed().await.is_ok() {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn one_leads_the_others_follow_until_it_is_done() {
        let wakes = Arc::new(Wakes::default());
        let Wake::Lead(lead) = wakes.join("a.apps.test") else {
            panic!("the first leads")
        };
        let Wake::Follow(follow) = wakes.join("a.apps.test") else {
            panic!("the second follows")
        };
        assert!(
            matches!(wakes.join("b.apps.test"), Wake::Lead(_)),
            "another host is its own"
        );
        let waiting = tokio::spawn(followed(follow));
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert!(!waiting.is_finished());
        drop(lead);
        waiting.await.unwrap();
        // Done: the next leads again.
        assert!(matches!(wakes.join("a.apps.test"), Wake::Lead(_)));
    }

    #[tokio::test]
    async fn one_round_at_a_time_and_not_more_often_than_a_round() {
        let rounds = Rounds::default();
        rounds.wait("a");
        rounds.wait("b");
        let (turn, mut waiting) = rounds.take_turn().expect("the first takes a turn");
        waiting.sort();
        assert_eq!(waiting, ["a", "b"]);
        assert!(rounds.take_turn().is_none(), "one is running");
        rounds.answer(["a".to_owned()].into());
        drop(turn);
        assert!(rounds.settled("a") && !rounds.settled("b"));
        assert!(rounds.take_turn().is_none(), "the last is too recent");
        tokio::time::sleep(ROUND).await;
        assert!(rounds.take_turn().is_some());
        rounds.done("a");
        assert!(!rounds.settled("a"));
    }
}
