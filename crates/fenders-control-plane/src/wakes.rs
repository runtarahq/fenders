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
}
