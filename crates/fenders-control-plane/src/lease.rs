//! What this gateway may pass of each workspace's transfer allowance
//! without asking: its leases, as it holds them in memory.
//!
//! A request's bytes used to be reserved against the allowance a megabyte
//! at a time, each time in a transaction under the lock all mutations
//! share. The gateway now holds a **lease** of the allowance for each
//! project with traffic (`gateway_transfer_leases`), and a byte passes when
//! the lease has room for it, which is decided here, in memory. Nothing
//! passes that is not leased, so the allowance is still never exceeded.
//!
//! A lease's bytes are in one of three places:
//!
//! - **available**: leased, and nobody's yet;
//! - **reserved**: drawn by a request in flight, a [`BLOCK`] at a time, for
//!   the bytes it passes. What it did not pass goes back when it ends;
//! - **used**: passed by requests that have ended, until the next flush
//!   writes them to `traffic_usage` and takes them off the lease.
//!
//! The flush ([`crate::gateway`]) also brings each lease to its size: what
//! the project drew in the last five flushes, between [`LEAST`] and
//! [`MOST`], and no more than the allowance has left. A lease with no
//! traffic for [`IDLE`] is given back whole. A request that finds its lease
//! empty between flushes asks for more at once
//! ([`crate::store::Store::lease_extend`]).
//!
//! A lease is for one UTC month. When the month turns, what was used is
//! recorded in the month it was leased in and a new lease is taken, which
//! must first cover what requests in flight had reserved.
use std::{
    collections::{HashMap, VecDeque},
    sync::Mutex,
    time::{Duration, Instant},
};

/// What a request draws from its lease at a time.
pub const BLOCK: i64 = 16 * 1024;
/// The least and the most a lease is brought to.
pub const LEAST: i64 = 1024 * 1024;
pub const MOST: i64 = 64 * 1024 * 1024;
/// A lease no request has drawn on for this long is given back.
pub const IDLE: Duration = Duration::from_secs(30);
/// The flushes whose draws size a lease.
const SIZED_BY: usize = 5;

/// A workspace and one of its projects.
pub type Key = (String, String);

/// Which way a body's bytes go.
#[derive(Clone, Copy)]
pub enum Way {
    /// The request, to the app.
    In,
    /// The response, from it.
    Out,
}

/// Whether bytes may pass.
#[derive(Debug, PartialEq)]
pub enum Pass {
    Passed,
    /// The lease has not the `need` bytes these take: ask for `want`, which
    /// brings it to its size, and try again.
    Short {
        key: Key,
        need: i64,
        want: i64,
    },
    /// Past the body's size limit, refused before, or no such request.
    Refused,
}

struct Budget {
    period: String,
    /// May be less than nothing after the month turns or a lease is lost:
    /// what is reserved has then to be covered again first.
    available: i64,
    reserved: i64,
    used: i64,
    requests: i64,
    /// Drawn since the last flush, and in each of the flushes before it.
    drawn: i64,
    drew: VecDeque<i64>,
    active: Instant,
    /// The allowance had nothing more to give when it was last asked.
    exhausted: bool,
}

impl Budget {
    fn new(period: &str) -> Self {
        Self {
            period: period.to_owned(),
            available: 0,
            reserved: 0,
            used: 0,
            requests: 0,
            drawn: 0,
            drew: VecDeque::new(),
            active: Instant::now(),
            exhausted: false,
        }
    }

    /// What the lease is brought to.
    fn size(&self) -> i64 {
        (self.drew.iter().sum::<i64>() + self.drawn).clamp(LEAST, MOST)
    }

    fn draw(&mut self, bytes: i64) -> i64 {
        let drawn = bytes.min(self.available).max(0);
        self.available -= drawn;
        self.reserved += drawn;
        self.drawn += drawn;
        self.active = Instant::now();
        drawn
    }
}

struct Flight {
    key: Key,
    reserved: i64,
    passed: [u64; 2],
    /// Whether it was given to an execution: one that waited for an app to
    /// start and never had one passed nothing to it.
    bound: bool,
    refused: bool,
}

/// Bytes and requests used in a month, to be written.
#[derive(Clone, Debug, PartialEq)]
pub struct Used {
    pub key: Key,
    pub period: String,
    pub bytes: i64,
    pub requests: i64,
}

/// What a flush is to do for the leases, taken out of memory.
#[derive(Default, Debug)]
pub struct Taken {
    /// To add to `traffic_usage` and take off the leases.
    pub used: Vec<Used>,
    /// Leases to bring to their size: the key and how much to ask for.
    pub asks: Vec<(Key, i64)>,
    /// Bytes of leases to give back: of ones that are idle.
    pub gives: Vec<(Key, String, i64)>,
    /// Leases to give back whole: of a month that is over.
    pub returns: Vec<(Key, String)>,
}

#[derive(Default)]
struct Inner {
    budgets: HashMap<Key, Budget>,
    flights: HashMap<String, Flight>,
    /// Used in a month that turned before it was written.
    late: Vec<Used>,
    /// Leases of a month that turned, to be given back.
    over: Vec<(Key, String)>,
}

impl Inner {
    /// The month turned: what was used is the old month's, the old lease
    /// goes back, and what is reserved has to be covered by the new one.
    fn turn(&mut self, key: &Key, period: &str) {
        let Some(budget) = self.budgets.get_mut(key) else {
            return;
        };
        if budget.period == period {
            return;
        }
        if budget.used != 0 || budget.requests != 0 {
            self.late.push(Used {
                key: key.clone(),
                period: budget.period.clone(),
                bytes: budget.used,
                requests: budget.requests,
            });
        }
        self.over.push((key.clone(), budget.period.clone()));
        budget.period = period.to_owned();
        budget.available = -budget.reserved;
        budget.used = 0;
        budget.requests = 0;
    }
}

#[derive(Default)]
pub struct Budgets {
    inner: Mutex<Inner>,
}

impl Budgets {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// How much to ask for, when the lease has not a block to give a new
    /// request. `None` when it has.
    pub fn short(&self, key: &Key) -> Option<i64> {
        let inner = self.lock();
        match inner.budgets.get(key) {
            Some(budget) if budget.available >= BLOCK => None,
            Some(budget) => Some(budget.size() - budget.available),
            None => Some(LEAST),
        }
    }

    /// Whether the lease has `bytes` to give.
    pub fn has(&self, key: &Key, bytes: i64) -> bool {
        self.lock()
            .budgets
            .get(key)
            .is_some_and(|budget| budget.available >= bytes)
    }

    /// Whether the allowance had nothing to give when last asked, and the
    /// lease has nothing either: a request would pass no byte.
    pub fn exhausted(&self, key: &Key) -> bool {
        self.lock()
            .budgets
            .get(key)
            .is_some_and(|budget| budget.exhausted && budget.available < 1)
    }

    /// The allowance granted `bytes` more, in the month `period`, of the
    /// `asked` for.
    pub fn granted(&self, key: &Key, period: &str, bytes: i64, asked: i64) {
        let mut inner = self.lock();
        inner.turn(key, period);
        let budget = inner
            .budgets
            .entry(key.clone())
            .or_insert_with(|| Budget::new(period));
        budget.available += bytes;
        budget.exhausted = bytes < asked;
    }

    /// A request was admitted: it draws its first block. `bound` when it
    /// has an execution to go to.
    pub fn take_off(&self, id: &str, key: &Key, bound: bool) {
        let mut inner = self.lock();
        let reserved = inner
            .budgets
            .get_mut(key)
            .map_or(0, |budget| budget.draw(BLOCK));
        inner.flights.insert(
            id.to_owned(),
            Flight {
                key: key.clone(),
                reserved,
                passed: [0, 0],
                bound,
                refused: false,
            },
        );
    }

    /// The request has an execution to go to.
    pub fn bound(&self, id: &str) {
        if let Some(flight) = self.lock().flights.get_mut(id) {
            flight.bound = true;
        }
    }

    /// Whether `bytes` more of request `id` may pass `way`, of at most
    /// `limit` that way. They are drawn from the lease, in blocks.
    pub fn pass(&self, id: &str, way: Way, bytes: usize, limit: u64) -> Pass {
        let mut inner = self.lock();
        let inner = &mut *inner;
        let Some(flight) = inner.flights.get_mut(id) else {
            return Pass::Refused;
        };
        let index = match way {
            Way::In => 0,
            Way::Out => 1,
        };
        if flight.refused || flight.passed[index] + bytes as u64 > limit {
            return Pass::Refused;
        }
        let total = (flight.passed[0] + flight.passed[1] + bytes as u64) as i64;
        if total > flight.reserved {
            let need = total - flight.reserved;
            let block = (need + BLOCK - 1) / BLOCK * BLOCK;
            let Some(budget) = inner.budgets.get_mut(&flight.key) else {
                return Pass::Short {
                    key: flight.key.clone(),
                    need,
                    want: block.max(LEAST),
                };
            };
            // A whole number of blocks when the lease has them, and what it
            // has when it has at least what is needed.
            let drawn = if budget.available >= block {
                budget.draw(block)
            } else if budget.available >= need {
                budget.draw(budget.available)
            } else {
                return Pass::Short {
                    key: flight.key.clone(),
                    need,
                    want: (budget.size().max(block) - budget.available).min(MOST),
                };
            };
            flight.reserved += drawn;
        }
        flight.passed[index] += bytes as u64;
        Pass::Passed
    }

    /// Nothing more of the request passes: its lease could not be extended.
    pub fn refuse(&self, id: &str) {
        if let Some(flight) = self.lock().flights.get_mut(id) {
            flight.refused = true;
        }
    }

    /// The bytes of request `id` that passed, both ways.
    pub fn passed(&self, id: &str) -> i64 {
        self.lock()
            .flights
            .get(id)
            .map_or(0, |flight| (flight.passed[0] + flight.passed[1]) as i64)
    }

    /// The request ended, having used `used` bytes: all it reserved when
    /// that is not known, and none if it never had an execution. The rest
    /// of what it reserved is available again. `counted` when the request
    /// is to be counted among the month's.
    pub fn land(&self, id: &str, used: Option<i64>, counted: bool) {
        let mut inner = self.lock();
        let Some(flight) = inner.flights.remove(id) else {
            return;
        };
        let Some(budget) = inner.budgets.get_mut(&flight.key) else {
            return;
        };
        let used = if flight.bound {
            used.unwrap_or(flight.reserved).clamp(0, flight.reserved)
        } else {
            0
        };
        budget.reserved -= flight.reserved;
        budget.available += flight.reserved - used;
        budget.used += used;
        budget.requests += i64::from(counted);
        budget.active = Instant::now();
    }

    /// Takes `bytes` of the lease as used, at once: for what is sent
    /// outside any request. `false` when the lease has not that much.
    pub fn spend(&self, key: &Key, bytes: i64) -> bool {
        let mut inner = self.lock();
        match inner.budgets.get_mut(key) {
            Some(budget) if budget.available >= bytes => {
                budget.available -= bytes;
                budget.used += bytes;
                budget.drawn += bytes;
                budget.active = Instant::now();
                true
            }
            _ => false,
        }
    }

    /// Whether a flush has anything to do for the leases.
    pub fn due(&self) -> bool {
        let inner = self.lock();
        !inner.budgets.is_empty() || !inner.late.is_empty() || !inner.over.is_empty()
    }

    /// What a flush is to write and ask, in the month `period`. With
    /// `closing`, every lease no request has reserved of is given back.
    pub fn take(&self, period: &str, closing: bool) -> Taken {
        let mut inner = self.lock();
        let keys: Vec<Key> = inner.budgets.keys().cloned().collect();
        for key in &keys {
            inner.turn(key, period);
        }
        let mut taken = Taken {
            used: std::mem::take(&mut inner.late),
            returns: std::mem::take(&mut inner.over),
            ..Default::default()
        };
        for key in keys {
            let budget = inner.budgets.get_mut(&key).expect("a budget just listed");
            if budget.used != 0 || budget.requests != 0 {
                taken.used.push(Used {
                    key: key.clone(),
                    period: budget.period.clone(),
                    bytes: std::mem::take(&mut budget.used),
                    requests: std::mem::take(&mut budget.requests),
                });
            }
            let drawn = std::mem::take(&mut budget.drawn);
            budget.drew.push_back(drawn);
            if budget.drew.len() > SIZED_BY {
                budget.drew.pop_front();
            }
            budget.exhausted = false;
            if budget.reserved == 0 && (closing || budget.active.elapsed() >= IDLE) {
                // Given back, and forgotten by the flush after the one that
                // gave it back: this one may yet fail.
                if budget.available > 0 {
                    let given = std::mem::take(&mut budget.available);
                    taken
                        .gives
                        .push((key.clone(), budget.period.clone(), given));
                } else {
                    inner.budgets.remove(&key);
                }
            } else if !closing && budget.available < budget.size() / 2 {
                taken
                    .asks
                    .push((key.clone(), budget.size() - budget.available));
            }
        }
        taken
    }

    /// The flush that took this could not write it: what was used is used
    /// still, and what was to be given back is held still.
    pub fn restore(&self, taken: Taken) {
        let mut inner = self.lock();
        for used in taken.used {
            match inner.budgets.get_mut(&used.key) {
                Some(budget) if budget.period == used.period => {
                    budget.used += used.bytes;
                    budget.requests += used.requests;
                }
                _ => inner.late.push(used),
            }
        }
        for (key, period, bytes) in taken.gives {
            if let Some(budget) = inner.budgets.get_mut(&key)
                && budget.period == period
            {
                budget.available += bytes;
            }
        }
        inner.over.extend(taken.returns);
    }

    /// The lease of `key` is not in the database any more: a process that
    /// did not flush for too long is taken for gone, and its leases were
    /// charged. What is reserved has to be leased again.
    pub fn lost(&self, key: &Key) {
        if let Some(budget) = self.lock().budgets.get_mut(key) {
            budget.available = -budget.reserved;
        }
    }

    /// What the lease of `key` holds: available, reserved and used.
    #[doc(hidden)]
    pub fn holds(&self, key: &Key) -> Option<(i64, i64, i64)> {
        self.lock()
            .budgets
            .get(key)
            .map(|budget| (budget.available, budget.reserved, budget.used))
    }

    /// Makes every lease `by` older: for tests of what idleness does.
    #[doc(hidden)]
    pub fn rewind(&self, by: Duration) {
        for budget in self.lock().budgets.values_mut() {
            budget.active = budget.active.checked_sub(by).unwrap_or(budget.active);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> Key {
        ("t".into(), "p".into())
    }
    const MIB: i64 = 1024 * 1024;

    #[test]
    fn a_request_draws_blocks_and_gives_back_what_it_did_not_pass() {
        let budgets = Budgets::default();
        assert_eq!(budgets.short(&key()), Some(LEAST));
        budgets.granted(&key(), "2026-11-01", MIB, MIB);
        assert_eq!(budgets.short(&key()), None);
        budgets.take_off("r", &key(), true);
        assert_eq!(budgets.holds(&key()), Some((MIB - BLOCK, BLOCK, 0)));
        // Within its block: nothing more is drawn.
        assert_eq!(budgets.pass("r", Way::In, 100, 1000), Pass::Passed);
        assert_eq!(budgets.holds(&key()), Some((MIB - BLOCK, BLOCK, 0)));
        // Past it: whole blocks.
        assert_eq!(
            budgets.pass("r", Way::Out, 2 * BLOCK as usize, u64::MAX),
            Pass::Passed
        );
        assert_eq!(budgets.holds(&key()), Some((MIB - 3 * BLOCK, 3 * BLOCK, 0)));
        assert_eq!(budgets.passed("r"), 100 + 2 * BLOCK);
        // Past the size limit of its way: refused, and nothing drawn.
        assert_eq!(budgets.pass("r", Way::In, 901, 1000), Pass::Refused);
        budgets.land("r", Some(100 + 2 * BLOCK), true);
        assert_eq!(
            budgets.holds(&key()),
            Some((MIB - 100 - 2 * BLOCK, 0, 100 + 2 * BLOCK))
        );
        // Ending it again ends nothing.
        budgets.land("r", Some(5), true);
        let taken = budgets.take("2026-11-01", false);
        assert_eq!(
            taken.used,
            vec![Used {
                key: key(),
                period: "2026-11-01".into(),
                bytes: 100 + 2 * BLOCK,
                requests: 1
            }]
        );
    }

    #[test]
    fn a_lease_that_is_short_says_how_much_to_ask_for_and_passes_nothing_meanwhile() {
        let budgets = Budgets::default();
        budgets.granted(&key(), "2026-11-01", BLOCK + 10, LEAST);
        assert!(budgets.exhausted(&key()) || budgets.has(&key(), 1));
        budgets.take_off("r", &key(), true);
        // Ten bytes are left: enough for ten more, not for eleven.
        assert_eq!(
            budgets.pass("r", Way::Out, BLOCK as usize + 10, u64::MAX),
            Pass::Passed
        );
        match budgets.pass("r", Way::Out, 1, u64::MAX) {
            Pass::Short {
                key: short,
                need,
                want,
            } => {
                assert_eq!(short, key());
                assert_eq!(need, 1);
                assert!(want >= BLOCK);
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(budgets.passed("r"), BLOCK + 10);
        // Asked, and nothing was granted: the allowance is exhausted.
        budgets.granted(&key(), "2026-11-01", 0, LEAST);
        assert!(budgets.exhausted(&key()));
        budgets.refuse("r");
        assert_eq!(budgets.pass("r", Way::Out, 1, u64::MAX), Pass::Refused);
    }

    #[test]
    fn how_a_request_ended_is_what_it_is_charged() {
        let budgets = Budgets::default();
        budgets.granted(&key(), "2026-11-01", MIB, MIB);
        // Not known: all it had reserved.
        budgets.take_off("unknown", &key(), true);
        budgets.land("unknown", None, false);
        assert_eq!(budgets.holds(&key()), Some((MIB - BLOCK, 0, BLOCK)));
        // More than it reserved cannot have passed.
        budgets.take_off("over", &key(), true);
        budgets.land("over", Some(10 * BLOCK), true);
        assert_eq!(budgets.holds(&key()), Some((MIB - 2 * BLOCK, 0, 2 * BLOCK)));
        // Never given to an execution: nothing, whatever is said.
        budgets.take_off("waited", &key(), false);
        budgets.land("waited", Some(500), true);
        assert_eq!(budgets.holds(&key()), Some((MIB - 2 * BLOCK, 0, 2 * BLOCK)));
        let taken = budgets.take("2026-11-01", false);
        // Two were counted as requests; the lapsed one is counted elsewhere.
        assert_eq!(taken.used[0].requests, 2);
    }

    #[test]
    fn a_lease_is_sized_by_what_was_drawn_and_given_back_when_idle() {
        let budgets = Budgets::default();
        budgets.granted(&key(), "2026-11-01", LEAST, LEAST);
        // Nothing drawn: at its least, and full.
        assert!(budgets.take("2026-11-01", false).asks.is_empty());
        // Three megabytes drawn in a flush: it is brought to three.
        assert!(budgets.spend(&key(), LEAST));
        assert!(!budgets.spend(&key(), 1));
        budgets.granted(&key(), "2026-11-01", 2 * MIB, 2 * MIB);
        assert!(budgets.spend(&key(), 2 * MIB));
        let taken = budgets.take("2026-11-01", false);
        assert_eq!(taken.used[0].bytes, 3 * MIB);
        assert_eq!(taken.asks, vec![(key(), 3 * MIB)]);
        // Idle, with nothing reserved: what it has is given back, and the
        // flush after that forgets it.
        budgets.granted(&key(), "2026-11-01", 3 * MIB, 3 * MIB);
        budgets.rewind(IDLE);
        let taken = budgets.take("2026-11-01", false);
        assert_eq!(taken.gives, vec![(key(), "2026-11-01".to_owned(), 3 * MIB)]);
        assert!(!budgets.has(&key(), 1));
        assert!(budgets.due());
        let taken = budgets.take("2026-11-01", false);
        assert!(taken.gives.is_empty() && taken.asks.is_empty());
        assert!(!budgets.due());
        assert_eq!(budgets.short(&key()), Some(LEAST));
    }

    #[test]
    fn a_request_in_flight_keeps_its_lease_from_being_given_back() {
        let budgets = Budgets::default();
        budgets.granted(&key(), "2026-11-01", LEAST, LEAST);
        budgets.take_off("r", &key(), true);
        budgets.rewind(IDLE);
        assert!(budgets.take("2026-11-01", false).gives.is_empty());
        assert!(budgets.take("2026-11-01", true).gives.is_empty());
        budgets.land("r", Some(0), true);
        // Closing gives back what is left whatever its age.
        assert_eq!(
            budgets.take("2026-11-01", true).gives,
            vec![(key(), "2026-11-01".to_owned(), LEAST)]
        );
    }

    #[test]
    fn when_the_month_turns_what_was_used_is_the_old_months() {
        let budgets = Budgets::default();
        budgets.granted(&key(), "2026-11-01", MIB, MIB);
        budgets.take_off("done", &key(), true);
        budgets.land("done", Some(700), true);
        budgets.take_off("flying", &key(), true);
        let taken = budgets.take("2026-12-01", false);
        assert_eq!(
            taken.used,
            vec![Used {
                key: key(),
                period: "2026-11-01".into(),
                bytes: 700,
                requests: 1
            }]
        );
        assert_eq!(taken.returns, vec![(key(), "2026-11-01".to_owned())]);
        // The new lease has first to cover what is in flight.
        assert_eq!(budgets.holds(&key()), Some((-BLOCK, BLOCK, 0)));
        assert_eq!(taken.asks, vec![(key(), LEAST + BLOCK)]);
        budgets.granted(&key(), "2026-12-01", LEAST + BLOCK, LEAST + BLOCK);
        assert_eq!(budgets.holds(&key()), Some((LEAST, BLOCK, 0)));
        budgets.land("flying", Some(BLOCK), true);
        assert_eq!(
            budgets.take("2026-12-01", false).used[0].period,
            "2026-12-01"
        );
    }

    #[test]
    fn what_a_failed_flush_took_is_used_still() {
        let budgets = Budgets::default();
        budgets.granted(&key(), "2026-11-01", MIB, MIB);
        assert!(budgets.spend(&key(), 300));
        let taken = budgets.take("2026-11-01", false);
        budgets.restore(taken);
        assert_eq!(budgets.take("2026-11-01", false).used[0].bytes, 300);
        // What was to be given back is held still, and may be drawn on.
        assert!(budgets.spend(&key(), 40));
        let taken = budgets.take("2026-11-01", true);
        assert_eq!(taken.gives[0].2, MIB - 340);
        assert!(!budgets.has(&key(), 1));
        budgets.restore(taken);
        assert!(budgets.has(&key(), MIB - 340));
        assert_eq!(budgets.take("2026-11-01", false).used[0].bytes, 40);
        // A month that turned and a flush that failed: the old lease is
        // still to be given back, and what was used in it still written.
        assert!(budgets.spend(&key(), 7));
        let taken = budgets.take("2026-12-01", false);
        assert_eq!(taken.returns.len(), 1);
        budgets.restore(taken);
        let again = budgets.take("2026-12-01", false);
        assert_eq!(again.returns, vec![(key(), "2026-11-01".to_owned())]);
        assert_eq!(again.used[0].period, "2026-11-01");
        assert_eq!(again.used[0].bytes, 7);
    }
}
