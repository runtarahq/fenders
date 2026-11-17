//! A small pool of SQLite connections to one database file.
//!
//! The node and its agent opened a connection for each statement or two:
//! opening reads the schema and, in WAL mode, maps the shared memory index,
//! about a dozen system calls each time. On Runtara Cloud's dev node that came
//! to ~540 opens a second under load, all on the path that starts runs.
use std::ops::{Deref, DerefMut};
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use rusqlite::Connection;

/// How many idle connections a pool keeps.
const IDLE: usize = 16;
/// How long a connection waits between tries for a locked database.
const BUSY_SLEEP: Duration = Duration::from_micros(200);
/// How many tries a connection makes for a locked database.
static BUSY_TRIES: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(50_000);

fn busy_retry(tries: i32) -> bool {
    std::thread::sleep(BUSY_SLEEP);
    tries < BUSY_TRIES.load(std::sync::atomic::Ordering::Relaxed)
}

#[derive(Default)]
pub struct Pool {
    idle: Mutex<Vec<Connection>>,
}

/// A connection taken from a [`Pool`], given back when dropped unless a
/// transaction is still open on it.
pub struct Pooled<'a> {
    connection: Option<Connection>,
    pool: &'a Pool,
}

impl Pool {
    /// A connection to `path` with `busy` as its busy timeout and `pragmas`
    /// applied, an idle one when there is one.
    pub fn get(&self, path: &Path, busy: Duration, pragmas: &str) -> rusqlite::Result<Pooled<'_>> {
        let idle = self.idle.lock().ok().and_then(|mut idle| idle.pop());
        let connection = match idle {
            Some(connection) => connection,
            None => {
                let connection = Connection::open(path)?;
                connection.busy_timeout(busy)?;
                // SQLite's own wait backs off to tens of milliseconds between
                // tries, so a writer that loses a race for the lock sleeps far
                // longer than the lock is held: ~30 ms per run's registry
                // insert under load on Runtara Cloud's dev node. Retry every
                // 200 µs instead, for as long in all.
                BUSY_TRIES.store(
                    (busy.as_micros() / BUSY_SLEEP.as_micros())
                        .try_into()
                        .unwrap_or(i32::MAX),
                    std::sync::atomic::Ordering::Relaxed,
                );
                connection.busy_handler(Some(busy_retry))?;
                connection
            }
        };
        connection.execute_batch(pragmas)?;
        Ok(Pooled {
            connection: Some(connection),
            pool: self,
        })
    }
}

impl Deref for Pooled<'_> {
    type Target = Connection;
    fn deref(&self) -> &Connection {
        self.connection
            .as_ref()
            .expect("a pooled connection is held until dropped")
    }
}

impl DerefMut for Pooled<'_> {
    fn deref_mut(&mut self) -> &mut Connection {
        self.connection
            .as_mut()
            .expect("a pooled connection is held until dropped")
    }
}

impl Drop for Pooled<'_> {
    fn drop(&mut self) {
        if let Some(connection) = self.connection.take()
            && connection.is_autocommit()
            && let Ok(mut idle) = self.pool.idle.lock()
            && idle.len() < IDLE
        {
            idle.push(connection);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_writer_waiting_on_the_lock_gets_it_soon_after_it_is_released() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("db.sqlite3");
        let pool = Pool::default();
        {
            let db = pool
                .get(&path, Duration::from_secs(10), "PRAGMA journal_mode=WAL")
                .unwrap();
            db.execute_batch("CREATE TABLE t(x INTEGER)").unwrap();
        }
        let holder = Pool::default();
        let mut held = holder.get(&path, Duration::from_secs(10), "").unwrap();
        let tx = held
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        let path_for_waiter = path.clone();
        let waiter = std::thread::spawn(move || {
            let pool = Pool::default();
            // No fsync on commit: the test measures the lock handoff, not
            // the disk.
            let db = pool
                .get(
                    &path_for_waiter,
                    Duration::from_secs(10),
                    "PRAGMA synchronous=OFF",
                )
                .unwrap();
            db.execute("INSERT INTO t VALUES(1)", []).unwrap();
            std::time::Instant::now()
        });
        std::thread::sleep(Duration::from_millis(60));
        let released = std::time::Instant::now();
        tx.commit().unwrap();
        let inserted = waiter.join().unwrap();
        let waited = inserted.saturating_duration_since(released);
        assert!(
            waited < Duration::from_millis(8),
            "waited {waited:?} after the lock was released"
        );
    }

    #[test]
    fn a_connection_is_reused_once_given_back_but_not_mid_transaction() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("db.sqlite3");
        let pool = Pool::default();
        {
            let db = pool
                .get(&path, Duration::from_secs(1), "PRAGMA journal_mode=WAL")
                .unwrap();
            db.execute_batch("CREATE TABLE t(x INTEGER)").unwrap();
        }
        assert_eq!(pool.idle.lock().unwrap().len(), 1);
        {
            let mut db = pool
                .get(&path, Duration::from_secs(1), "PRAGMA synchronous=FULL")
                .unwrap();
            assert_eq!(pool.idle.lock().unwrap().len(), 0, "the idle one was taken");
            let tx = db.transaction().unwrap();
            tx.execute("INSERT INTO t VALUES(1)", []).unwrap();
            tx.commit().unwrap();
        }
        assert_eq!(pool.idle.lock().unwrap().len(), 1);
        {
            let db = pool
                .get(&path, Duration::from_secs(1), "PRAGMA synchronous=NORMAL")
                .unwrap();
            db.execute_batch("BEGIN; INSERT INTO t VALUES(2)").unwrap();
            // Dropped with its transaction open: closed, not given back.
        }
        assert_eq!(pool.idle.lock().unwrap().len(), 0);
        let db = pool.get(&path, Duration::from_secs(1), "").unwrap();
        let rows: i64 = db
            .query_row("SELECT count(*) FROM t", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, 1, "the abandoned transaction rolled back");
    }
}
