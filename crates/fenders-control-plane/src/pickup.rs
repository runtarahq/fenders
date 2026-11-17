//! Fast pickup. Postgres triggers notify at commit when an execution needs
//! placing or a node's assignments change. The scheduler wakes on the first
//! and each node's long poll on the second, instead of only on their intervals.
use crate::{error::Result, store::Store};
use std::{collections::HashMap, sync::Mutex, time::Duration};
use tokio::sync::{Notify, watch};

pub(crate) const MIGRATION: &str = include_str!("pickup_notify.sql");
/// The longest a node's assignment poll waits for a change.
pub const LONG_POLL: Duration = Duration::from_secs(25);

#[derive(Default)]
pub struct Pickup {
    schedule: Notify,
    nodes: Mutex<HashMap<String, watch::Sender<u64>>>,
}
impl Pickup {
    pub fn schedule(&self) -> &Notify {
        &self.schedule
    }
    fn sender(&self, node: &str) -> watch::Sender<u64> {
        let mut nodes = self.nodes.lock().unwrap_or_else(|e| e.into_inner());
        nodes
            .entry(node.to_owned())
            .or_insert_with(|| watch::channel(0).0)
            .clone()
    }
    fn assigned(&self, node: &str) {
        self.sender(node).send_modify(|wake| *wake += 1);
    }
    /// After a delivery gap nothing is known, so every waiter re-reads.
    fn wake_all(&self) {
        self.schedule.notify_one();
        let nodes = self.nodes.lock().unwrap_or_else(|e| e.into_inner());
        for sender in nodes.values() {
            sender.send_modify(|wake| *wake += 1);
        }
    }
    /// The node's wake count once it differs from `after`, or after `timeout`.
    pub async fn wait(&self, node: &str, after: u64, timeout: Duration) -> u64 {
        let mut receiver = self.sender(node).subscribe();
        if *receiver.borrow_and_update() == after {
            let _ = tokio::time::timeout(timeout, receiver.changed()).await;
        }
        *receiver.borrow()
    }
}
impl Store {
    pub fn pickup(&self) -> std::sync::Arc<Pickup> {
        self.pickup.clone()
    }
    /// Runs until the listener fails; the supervisor restarts it.
    pub async fn listen_for_pickup(&self) -> Result<()> {
        let mut listener = sqlx::postgres::PgListener::connect_with(&self.pool).await?;
        listener
            .listen_all(["fenders_schedule", "fenders_assignment"])
            .await?;
        // Changes made before this listener existed were not delivered.
        self.pickup.wake_all();
        loop {
            match listener.try_recv().await? {
                Some(notice) if notice.channel() == "fenders_schedule" => {
                    self.pickup.schedule.notify_one()
                }
                Some(notice) => self.pickup.assigned(notice.payload()),
                // The connection was lost and re-established.
                None => self.pickup.wake_all(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn a_wait_returns_on_a_change_it_has_not_seen() {
        let pickup = std::sync::Arc::new(Pickup::default());
        assert_eq!(pickup.wait("n", 0, Duration::from_millis(10)).await, 0);
        pickup.assigned("n");
        // A change made before the wait began is not lost.
        assert_eq!(pickup.wait("n", 0, LONG_POLL).await, 1);
        let waiter = {
            let pickup = pickup.clone();
            tokio::spawn(async move { pickup.wait("n", 1, LONG_POLL).await })
        };
        tokio::time::sleep(Duration::from_millis(10)).await;
        pickup.assigned("other");
        pickup.assigned("n");
        assert_eq!(waiter.await.unwrap(), 2);
    }
}
