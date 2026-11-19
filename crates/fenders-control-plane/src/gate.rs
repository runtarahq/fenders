//! Who may come in: what the gateway knows, in memory, of the apps it
//! serves and of the requests it has in flight.
//!
//! A request used to be admitted in a transaction under the lock all
//! mutations share, which read whose host name it asked for, whether that
//! app was serving, and how many of its workspace's requests were in
//! flight (`docs/gateway-accounting.md`). For an app that is serving, that
//! is now read here.
//!
//! A **gate** is what was read of one host name: its workspace and project,
//! the app and release, the route to give the gateway, and the workspace's
//! limits. A request for a host name whose gate is open and fresh comes in
//! with no transaction at all: the **warm** path. Any other takes the
//! **cold** path, which is the transaction it always was, and which is
//! what starts an app that is idle and holds a request while one starts.
//!
//! A gate is kept true three ways:
//!
//! - it is read again once it is [`FRESH`] no longer, without the lock;
//! - the reconciler **closes** an app's gate before it takes the app out of
//!   service, in the transaction that does it. A closed gate sends every
//!   request to the cold path, which waits for that transaction: so a
//!   request either came in before the gate closed, and is waited for, or
//!   comes after and sees what the reconciler did. Only the cold path opens
//!   a closed gate again, until it has been closed for [`HELD`];
//! - a request admitted to an app that stopped serving meanwhile is not
//!   taken, and is answered 503 never having run. That is what a stale gate
//!   costs, for as long as it is stale.
//!
//! Requests in flight are counted here too, for each workspace against its
//! limit and for each app so that one with a request is not thought idle. A
//! restart forgets the counts, as it forgets the requests.
use serde_json::Value;
use std::{
    collections::HashMap,
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

/// How long what was read of a host name is believed.
pub const FRESH: Duration = Duration::from_secs(2);
/// How long a closed gate is opened by the cold path alone: longer than the
/// transaction that closed it can last.
pub const HELD: Duration = Duration::from_secs(15);

/// What was read of a host name whose app is serving.
#[derive(Clone, Debug)]
pub struct Gate {
    pub tenant: String,
    pub project: String,
    /// The app and the release it serves; `None` for a route of no app.
    pub app: Option<String>,
    pub release: Option<String>,
    /// The host name requests are audited under.
    pub hostname: String,
    /// What the gateway is given: the execution, the app and its timeout.
    pub route: Value,
    /// The workspace's requests in flight at once, and in a minute.
    pub concurrent: i64,
    pub per_minute: i64,
    /// The registered edge that owns the app, if one does.
    pub owner: Option<String>,
}

/// What to do with a request for a host name.
pub enum Look {
    /// Its gate is open and fresh.
    Warm(Gate),
    /// Nothing fresh is known of it: read it, without the lock.
    Unknown,
    /// Its app's gate is closed: the cold path.
    Closed,
}

/// A request in flight.
pub struct Entered {
    pub tenant: String,
    pub app: Option<String>,
    /// Whether it has a reservation row, as one that waited for its app to
    /// start has.
    pub row: bool,
    /// Whether it has an execution to go to: one that waits for its app to
    /// start has none yet, and keeps no execution busy.
    pub bound: bool,
}

#[derive(Default)]
struct App {
    in_flight: usize,
    /// Of those, the ones that have an execution to go to.
    bound: usize,
    /// A request came in or ended since the last flush.
    touched: bool,
}

#[derive(Default)]
struct Inner {
    /// What was read of each host name, when, and at which epoch.
    gates: HashMap<String, (Gate, Instant, u64)>,
    /// Apps whose gates are closed, and since when.
    closed: HashMap<String, Instant>,
    flights: HashMap<String, Entered>,
    tenants: HashMap<String, usize>,
    apps: HashMap<String, App>,
}

impl Inner {
    fn held(&self, app: Option<&String>) -> bool {
        app.and_then(|app| self.closed.get(app))
            .is_some_and(|at| at.elapsed() < HELD)
    }
}

#[derive(Default)]
pub struct Gates {
    inner: Mutex<Inner>,
    /// Advanced by every transaction of this process that may have changed
    /// whether an app serves. What was read before it is not believed after
    /// it: a change made here is seen by the next request. One made by
    /// another process is seen once what was read is no longer [`FRESH`].
    epoch: AtomicU64,
}

impl Gates {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Something that may change whether an app serves is being changed.
    pub fn changed(&self) {
        self.epoch.fetch_add(1, Ordering::SeqCst);
    }

    /// The epoch to pass to [`read`](Self::read) or [`open`](Self::open):
    /// taken before what they are given is read.
    pub fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::SeqCst)
    }

    pub fn look(&self, hostname: &str) -> Look {
        let epoch = self.epoch();
        let inner = self.lock();
        match inner.gates.get(hostname) {
            Some((gate, _, _)) if inner.held(gate.app.as_ref()) => Look::Closed,
            Some((gate, read, at)) if *at == epoch && read.elapsed() < FRESH => {
                Look::Warm(gate.clone())
            }
            _ => Look::Unknown,
        }
    }

    /// What was read of `hostname` without the lock, from `epoch` on:
    /// believed unless its app's gate is closed, which only the cold path
    /// may open. Whether it is.
    pub fn read(&self, hostname: &str, gate: Gate, epoch: u64) -> bool {
        let mut inner = self.lock();
        if inner.held(gate.app.as_ref()) {
            return false;
        }
        inner
            .gates
            .insert(hostname.to_owned(), (gate, Instant::now(), epoch));
        true
    }

    /// What the cold path read of `hostname` under the lock, from `epoch`
    /// on: its app serves, whatever was closed before.
    pub fn open(&self, hostname: &str, gate: Gate, epoch: u64) {
        let mut inner = self.lock();
        if let Some(app) = &gate.app {
            inner.closed.remove(app);
        }
        inner
            .gates
            .insert(hostname.to_owned(), (gate, Instant::now(), epoch));
    }

    /// What was last read of `hostname`, however old, unless its app's gate
    /// is closed: for while the database cannot be reached.
    pub fn stale(&self, hostname: &str) -> Option<Gate> {
        let inner = self.lock();
        let (gate, _, _) = inner.gates.get(hostname)?;
        (!inner.held(gate.app.as_ref())).then(|| gate.clone())
    }

    /// Nothing is known of `hostname` any more.
    pub fn forget(&self, hostname: &str) {
        self.lock().gates.remove(hostname);
    }

    /// Nothing is known of any host name: for a change to what gates hold
    /// (a workspace's limits), and for tests that change it underneath.
    pub fn forget_all(&self) {
        self.lock().gates.clear();
    }

    /// The app is being taken out of service: its requests take the cold
    /// path from here.
    pub fn close(&self, app: &str) {
        let mut inner = self.lock();
        inner.closed.retain(|_, at| at.elapsed() < HELD);
        inner.closed.insert(app.to_owned(), Instant::now());
    }

    /// Closes the app's gate if it has no request in flight and none came
    /// in or ended since the last flush wrote that down. Whether it did:
    /// the app may then be stopped as idle.
    pub fn close_if_idle(&self, app: &str) -> bool {
        let mut inner = self.lock();
        if inner
            .apps
            .get(app)
            .is_some_and(|app| app.in_flight > 0 || app.touched)
        {
            return false;
        }
        inner.closed.retain(|_, at| at.elapsed() < HELD);
        inner.closed.insert(app.to_owned(), Instant::now());
        true
    }

    /// Counts request `id` as in flight, unless its workspace already has
    /// `concurrent` of them. Whether it came in.
    pub fn enter(&self, id: &str, entered: Entered, concurrent: i64) -> bool {
        let mut inner = self.lock();
        let held = inner.tenants.get(&entered.tenant).copied().unwrap_or(0);
        if held as i64 >= concurrent {
            return false;
        }
        *inner.tenants.entry(entered.tenant.clone()).or_default() += 1;
        if let Some(app) = &entered.app {
            let app = inner.apps.entry(app.clone()).or_default();
            app.in_flight += 1;
            app.bound += usize::from(entered.bound);
            app.touched = true;
        }
        inner.flights.insert(id.to_owned(), entered);
        true
    }

    /// The request has an execution to go to.
    pub fn bound(&self, id: &str) {
        let mut inner = self.lock();
        let inner = &mut *inner;
        let Some(entered) = inner.flights.get_mut(id) else {
            return;
        };
        if !std::mem::replace(&mut entered.bound, true)
            && let Some(app) = entered.app.as_ref().and_then(|app| inner.apps.get_mut(app))
        {
            app.bound += 1;
        }
    }

    /// The request is no longer in flight. What it was, the first time.
    pub fn leave(&self, id: &str) -> Option<Entered> {
        let mut inner = self.lock();
        let entered = inner.flights.remove(id)?;
        if let Some(held) = inner.tenants.get_mut(&entered.tenant) {
            *held = held.saturating_sub(1);
            if *held == 0 {
                inner.tenants.remove(&entered.tenant);
            }
        }
        if let Some(app) = entered.app.as_ref().and_then(|app| inner.apps.get_mut(app)) {
            app.in_flight = app.in_flight.saturating_sub(1);
            app.bound = app.bound.saturating_sub(usize::from(entered.bound));
            app.touched = true;
        }
        Some(entered)
    }

    /// Whether request `id` is in flight with a reservation row.
    pub fn has_row(&self, id: &str) -> Option<bool> {
        self.lock().flights.get(id).map(|entered| entered.row)
    }

    /// The workspace of request `id`, while it is in flight.
    pub fn tenant_of(&self, id: &str) -> Option<String> {
        self.lock()
            .flights
            .get(id)
            .map(|entered| entered.tenant.clone())
    }

    /// The app's requests in flight.
    pub fn in_flight(&self, app: &str) -> usize {
        self.lock().apps.get(app).map_or(0, |app| app.in_flight)
    }

    /// The app's requests in flight that have an execution to go to: while
    /// there are any, its executions are not idle.
    pub fn serving(&self, app: &str) -> usize {
        self.lock().apps.get(app).map_or(0, |app| app.bound)
    }

    /// Every request in flight.
    pub fn in_flight_total(&self) -> usize {
        self.lock().flights.len()
    }

    /// The workspace's requests in flight.
    pub fn in_flight_of(&self, tenant: &str) -> usize {
        self.lock().tenants.get(tenant).copied().unwrap_or(0)
    }

    /// Whether a flush has an app's activity to write.
    pub fn due(&self) -> bool {
        self.lock()
            .apps
            .values()
            .any(|app| app.touched || app.in_flight > 0)
    }

    /// The apps a request came in for or ended in since the last flush,
    /// and those with one in flight: the flush writes that they are active,
    /// and puts them back with [`touch`](Self::touch) if it fails. One with
    /// nothing in flight is then forgotten.
    pub fn take_active(&self) -> Vec<String> {
        let mut inner = self.lock();
        let active: Vec<String> = inner
            .apps
            .iter()
            .filter(|(_, app)| app.touched || app.in_flight > 0)
            .map(|(id, _)| id.clone())
            .collect();
        inner.apps.retain(|_, app| {
            app.touched = false;
            app.in_flight > 0
        });
        active
    }

    /// The flush that took these could not write them.
    pub fn touch(&self, apps: &[String]) {
        let mut inner = self.lock();
        for app in apps {
            inner.apps.entry(app.clone()).or_default().touched = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gate(app: &str) -> Gate {
        Gate {
            tenant: "t".into(),
            project: "p".into(),
            app: Some(app.into()),
            release: Some("r".into()),
            hostname: format!("{app}.example"),
            route: Value::Null,
            concurrent: 2,
            per_minute: 600,
            owner: None,
        }
    }
    fn entered(app: &str) -> Entered {
        Entered {
            tenant: "t".into(),
            app: Some(app.into()),
            row: false,
            bound: true,
        }
    }

    #[test]
    fn a_gate_that_was_read_is_warm_until_its_app_is_closed() {
        let gates = Gates::default();
        assert!(matches!(gates.look("a.example"), Look::Unknown));
        assert!(gates.read("a.example", gate("a"), gates.epoch()));
        assert!(matches!(gates.look("a.example"), Look::Warm(_)));
        gates.close("a");
        assert!(matches!(gates.look("a.example"), Look::Closed));
        // What is read without the lock does not open it.
        assert!(!gates.read("a.example", gate("a"), gates.epoch()));
        assert!(matches!(gates.look("a.example"), Look::Closed));
        // Another app's is its own.
        assert!(gates.read("b.example", gate("b"), gates.epoch()));
        assert!(matches!(gates.look("b.example"), Look::Warm(_)));
        // The cold path does.
        gates.open("a.example", gate("a"), gates.epoch());
        assert!(matches!(gates.look("a.example"), Look::Warm(_)));
        gates.forget_all();
        assert!(matches!(gates.look("a.example"), Look::Unknown));
    }

    #[test]
    fn what_was_read_before_a_change_is_not_believed_after_it() {
        let gates = Gates::default();
        // Read from an epoch, and something changed while it was read.
        let epoch = gates.epoch();
        gates.changed();
        assert!(gates.read("a.example", gate("a"), epoch));
        assert!(matches!(gates.look("a.example"), Look::Unknown));
        assert!(gates.read("a.example", gate("a"), gates.epoch()));
        assert!(matches!(gates.look("a.example"), Look::Warm(_)));
        gates.changed();
        assert!(matches!(gates.look("a.example"), Look::Unknown));
    }

    #[test]
    fn an_app_closed_before_anything_was_read_of_it_stays_closed() {
        let gates = Gates::default();
        assert!(gates.close_if_idle("a"));
        assert!(!gates.read("a.example", gate("a"), gates.epoch()));
        assert!(matches!(gates.look("a.example"), Look::Unknown));
    }

    #[test]
    fn requests_in_flight_are_counted_for_the_workspace_and_the_app() {
        let gates = Gates::default();
        assert!(gates.enter("1", entered("a"), 2));
        assert!(gates.enter("2", entered("b"), 2));
        assert!(!gates.enter("3", entered("a"), 2), "two at once");
        assert_eq!((gates.in_flight("a"), gates.in_flight_of("t")), (1, 2));
        assert_eq!(gates.has_row("1"), Some(false));
        assert!(gates.leave("1").is_some());
        assert!(gates.leave("1").is_none(), "left once");
        assert_eq!((gates.in_flight("a"), gates.in_flight_of("t")), (0, 1));
        assert!(gates.enter("3", entered("a"), 2));
        // One that waits for its app to start keeps no execution busy until
        // it has one to go to.
        gates.leave("2");
        let waiting = Entered {
            bound: false,
            ..entered("w")
        };
        assert!(gates.enter("4", waiting, 2));
        assert_eq!((gates.in_flight("w"), gates.serving("w")), (1, 0));
        gates.bound("4");
        gates.bound("4");
        assert_eq!(gates.serving("w"), 1);
        gates.leave("4");
        assert_eq!((gates.in_flight("w"), gates.serving("w")), (0, 0));
    }

    #[test]
    fn an_app_is_idle_only_once_its_last_request_is_written_down() {
        let gates = Gates::default();
        assert!(gates.enter("1", entered("a"), 2));
        assert!(!gates.close_if_idle("a"), "a request is in flight");
        gates.leave("1");
        assert!(!gates.close_if_idle("a"), "it ended since the last flush");
        assert_eq!(gates.take_active(), vec!["a".to_owned()]);
        assert!(gates.close_if_idle("a"));
        assert!(matches!(gates.look("a.example"), Look::Unknown));
        assert!(!gates.read("a.example", gate("a"), gates.epoch()));
        // A flush that failed leaves it as it was.
        let gates = Gates::default();
        assert!(gates.enter("1", entered("a"), 2));
        gates.leave("1");
        let active = gates.take_active();
        gates.touch(&active);
        assert!(!gates.close_if_idle("a"));
        assert!(gates.due());
    }

    #[test]
    fn an_app_with_a_request_in_flight_is_active_at_every_flush() {
        let gates = Gates::default();
        assert!(gates.enter("1", entered("a"), 2));
        assert_eq!(gates.take_active(), vec!["a".to_owned()]);
        assert_eq!(gates.take_active(), vec!["a".to_owned()]);
        gates.leave("1");
        assert_eq!(gates.take_active(), vec!["a".to_owned()]);
        assert!(gates.take_active().is_empty());
        assert!(!gates.due());
    }
}
