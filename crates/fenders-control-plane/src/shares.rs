//! A workspace's limits, shared between the processes that serve its apps.
//!
//! A workspace may have so many requests in flight at once, be admitted so
//! many a minute, and hold so many WebSocket connections. One process
//! counted all of them in memory. When a workspace's apps are served by
//! several edges, each counts its own, against its **share** of each limit
//! (`edge_limit_shares`), as it passes bytes against its lease of the
//! transfer allowance.
//!
//! A share is taken in a transaction under the lock, with the workspace's
//! first request, and brought at each flush to what the process uses plus
//! an even part of what the workspace does not use, among the processes
//! that hold shares of it; never to more than the other processes' shares
//! leave. So the shares never add up to more than the limit, and requests
//! in flight and connections are held to it exactly. The rate may pass it
//! by what moves between processes within a minute. A process alone holds
//! the whole limit, and nothing changes for a client.
use std::{collections::HashMap, sync::Mutex, time::Instant};

pub(crate) const MIGRATION: &str = "CREATE TABLE IF NOT EXISTS edge_limit_shares (
    session_id text NOT NULL, tenant_id text NOT NULL,
    concurrent bigint NOT NULL CHECK(concurrent>=0), per_minute bigint NOT NULL CHECK(per_minute>=0),
    connections bigint NOT NULL CHECK(connections>=0),
    used_concurrent bigint NOT NULL DEFAULT 0, used_per_minute bigint NOT NULL DEFAULT 0,
    used_connections bigint NOT NULL DEFAULT 0,
    updated timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(session_id, tenant_id))";

/// A share, or what is used of one: requests in flight, requests in the
/// last minute, WebSocket connections.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Limits {
    pub concurrent: i64,
    pub per_minute: i64,
    pub connections: i64,
}

impl Limits {
    fn zip(self, other: Self, f: impl Fn(i64, i64) -> i64) -> Self {
        Self {
            concurrent: f(self.concurrent, other.concurrent),
            per_minute: f(self.per_minute, other.per_minute),
            connections: f(self.connections, other.connections),
        }
    }
    pub fn is_zero(&self) -> bool {
        *self == Self::default()
    }
}

/// What this process's share of a workspace's limits is to be: what it
/// uses, and an even part (of `holders` processes, itself among them) of
/// what the workspace does not use, but no more than the other processes'
/// shares leave of the limit.
pub fn fair(
    limit: Limits,
    used: Limits,
    others_hold: Limits,
    others_use: Limits,
    holders: i64,
) -> Limits {
    let holders = holders.max(1);
    let free = limit
        .zip(used, |l, u| l - u)
        .zip(others_use, |r, o| (r - o).max(0));
    let wanted = used.zip(free, |u, f| u + f / holders);
    let left = limit.zip(others_hold, |l, o| (l - o).max(0));
    wanted.zip(left, i64::min)
}

struct Held {
    share: Limits,
    /// When it was last used: a share nothing uses for a while is given
    /// back.
    used: Instant,
}

#[derive(Default)]
pub struct Shares {
    inner: Mutex<HashMap<String, Held>>,
}

impl Shares {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Held>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// This process's share of `tenant`'s limits, when it holds one.
    pub fn of(&self, tenant: &str) -> Option<Limits> {
        let mut inner = self.lock();
        let held = inner.get_mut(tenant)?;
        held.used = Instant::now();
        Some(held.share)
    }

    /// The share of `tenant` is now `share`.
    pub fn set(&self, tenant: &str, share: Limits) {
        let mut inner = self.lock();
        let held = inner.entry(tenant.to_owned()).or_insert(Held {
            share,
            used: Instant::now(),
        });
        held.share = share;
    }

    /// The workspaces it holds shares of, and whether each has gone unused
    /// for `idle`.
    pub fn held(&self, idle: std::time::Duration) -> Vec<(String, bool)> {
        self.lock()
            .iter()
            .map(|(tenant, held)| (tenant.clone(), held.used.elapsed() >= idle))
            .collect()
    }

    /// The share of `tenant` is given back.
    pub fn drop_share(&self, tenant: &str) {
        self.lock().remove(tenant);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn l(concurrent: i64) -> Limits {
        Limits {
            concurrent,
            per_minute: concurrent * 10,
            connections: concurrent,
        }
    }

    #[test]
    fn a_process_alone_holds_the_whole_limit() {
        assert_eq!(fair(l(16), l(0), l(0), l(0), 1), l(16));
        assert_eq!(fair(l(16), l(5), l(0), l(0), 1), l(16));
    }

    #[test]
    fn two_processes_share_what_is_unused_evenly_and_never_more_than_the_limit() {
        // The other holds the whole limit: nothing is left until it gives.
        assert_eq!(fair(l(16), l(0), l(16), l(0), 2), l(0));
        // It gave back to what it uses and its even part: 0 + 16/2.
        let other = fair(l(16), l(0), l(0), l(0), 2);
        assert_eq!(other, l(8));
        assert_eq!(fair(l(16), l(0), other, l(0), 2), l(8));
        // One busy with 10, the other with 2: each its use and 2 of the 4
        // left.
        let busy = fair(l(16), l(10), l(8), l(2), 2);
        assert_eq!(busy, l(8), "no more than the other leaves");
        let quiet = fair(l(16), l(2), busy, l(10), 2);
        assert_eq!(quiet, l(4));
        assert_eq!(fair(l(16), l(10), quiet, l(2), 2), l(12));
    }

    #[test]
    fn a_share_is_never_below_what_is_used_when_there_is_room_for_it() {
        // 4 at once, 3 in flight here, 1 free between two: 3 and nothing
        // of the free one, which an odd count does not split.
        assert_eq!(fair(l(4), l(3), l(0), l(0), 2).concurrent, 3);
    }
}
