//! The outbound byte limit, for a launch that asked for it
//! (`guest.egress_budget`): the VM sends only bytes it was granted, and the
//! grants come from the run channel (`POST /v1/run/egress`).
//!
//! A launch that did not ask has none of this: no socket, task or call.
//!
//! The launcher enforces it. It admits a write only under a ceiling (the
//! run's total outbound bytes) and a deadline, both of which it is told over
//! its control socket; a write short of allowance waits [`WAIT_MS`] for a
//! grant and is then refused. This task keeps the launcher told: it asks the
//! endpoint for bytes before the guest runs (the guest is held until the
//! first grant is in place), renews the grant every [`RENEW`] (a grant
//! lasts seconds, so a shim that cannot reach its endpoint loses the
//! authority to send), and asks for more as the meter shows the allowance
//! running low or a write waiting.
//!
//! It ends the run, by returning a [`Stop`], when a write is waiting and the
//! endpoint says the allowance has nothing left, or when the launcher
//! refused a write. Nothing is sent without a grant in any case: an
//! unreachable endpoint stops the guest's sending, not the limit.
use serde_json::{Value, json};
use std::{future::Future, time::Duration};
use tokio::{sync::watch, time::Instant};

/// Where grants are asked for, under the launch's endpoint.
pub const PATH: &str = "/v1/run/egress";
/// How long the launcher lets a write wait for a grant, in milliseconds.
pub const WAIT_MS: u64 = 5000;
/// The first ask, and the least asked for at a time.
const FIRST: u64 = 256 * 1024;
/// The most asked for at a time (the endpoint's own bound).
const MOST: u64 = 16 * 1024 * 1024;
/// How often a grant is renewed. The endpoint's last 10 seconds.
const RENEW: Duration = Duration::from_secs(3);
/// How long before an ask that got no usable answer is made again.
const RETRY: Duration = Duration::from_millis(500);
/// How long the guest is held for its first grant before it runs without
/// one (it then cannot send, and is ended when it tries).
const HOLD_LIMIT: Duration = Duration::from_secs(10);
/// Asks for more this soon after the last grow what is asked for.
const BUSY: Duration = Duration::from_secs(1);

/// The launcher's meter, as far as the limit needs it.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Meter {
    /// Bytes sent so far.
    pub bytes: u64,
    /// The total its waiting writes need the ceiling to reach; 0 when none
    /// waits.
    pub wanted: u64,
    /// The classes of refusal seen (1 over the ceiling, 2 no authority,
    /// 4 unmeasurable).
    pub refusals: u64,
}

/// The endpoint's answer to an ask.
#[derive(Debug, PartialEq)]
pub enum Answer {
    /// The grant now in force: its revision, the ceiling, and how long it
    /// lasts from when it was asked for.
    Granted {
        revision: u64,
        ceiling: u64,
        ttl_ms: u64,
    },
    /// The allowance cannot cover what was asked; this much is left.
    Short { available: u64 },
    /// No usable answer: ask again as it was.
    Retry,
}

/// Why the limit ended the run.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Stop {
    /// A write needed more than the allowance has.
    Limit,
    /// A write was refused for want of a grant in force.
    Expired,
    /// A write was refused because the total could not be measured.
    Unmeasured,
}

impl Stop {
    /// The run's end code, as the node maps it to a reason.
    pub fn code(self) -> &'static str {
        match self {
            Self::Limit => "EGRESS_LIMIT",
            Self::Expired => "EGRESS_EXPIRED",
            Self::Unmeasured => "EGRESS_UNMEASURED",
        }
    }

    pub fn reason(self) -> &'static str {
        match self {
            Self::Limit => "the run reached its outbound transfer allowance",
            Self::Expired => "an outbound write was refused: the run had no grant in force",
            Self::Unmeasured => {
                "an outbound write was refused: outbound bytes could not be measured"
            }
        }
    }

    /// The stop for the launcher's refusals, if it refused any. `spent` says
    /// the endpoint had nothing more to grant.
    pub fn of(refusals: u64, spent: bool) -> Option<Self> {
        if refusals & 4 != 0 {
            Some(Self::Unmeasured)
        } else if refusals & 3 != 0 {
            Some(if spent { Self::Limit } else { Self::Expired })
        } else {
            None
        }
    }
}

/// Whether a guest configuration asks for the outbound byte limit.
pub fn wanted(guest: &Value) -> bool {
    guest["egress_budget"] == true
}

/// Nanoseconds on the clock the launcher's deadlines are on.
pub fn boottime_ns() -> u64 {
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut now) };
    now.tv_sec as u64 * 1_000_000_000 + now.tv_nsec as u64
}

/// Keeps the launcher's allowance granted until the run must end for it.
///
/// `ask` posts one ask to the endpoint. `apply` tells the launcher a grant
/// (revision, deadline on [`boottime_ns`]'s clock, ceiling). `release` lets
/// the held guest run. `id` makes this shim's asks distinct from any other's
/// for the run. Never returns while the limit has nothing to end the run for:
/// drop it when the run ends.
pub async fn enforce<A, AF, P, PF>(
    id: &str,
    mut meter: watch::Receiver<Meter>,
    ask: A,
    apply: P,
    release: impl FnOnce(),
) -> Stop
where
    A: Fn(Value) -> AF,
    AF: Future<Output = Answer>,
    P: Fn(u64, u64, u64) -> PF,
    PF: Future<Output = Result<(), String>>,
{
    let started = Instant::now();
    let mut release = Some(release);
    let mut serial = 0u64;
    let (mut revision, mut ceiling) = (0u64, 0u64);
    // What is asked for at a time, and what the next ask asks for.
    let (mut chunk, mut bytes) = (FIRST, FIRST);
    // An ask whose answer never came: sent again as it was, so that the
    // endpoint answers it once however often it arrives.
    let mut unanswered: Option<Value> = None;
    // The allowance had nothing more at the last ask for more.
    let mut spent = false;
    let mut grew: Option<Instant> = None;
    loop {
        let body = unanswered.take().unwrap_or_else(|| {
            serial += 1;
            json!({"expected_revision": revision, "request_id": format!("{id}-{serial}"), "bytes": bytes})
        });
        let asked = body["bytes"].as_u64().unwrap_or(0);
        let asked_at = boottime_ns();
        let mut next = RENEW;
        match ask(body.clone()).await {
            Answer::Granted {
                revision: granted,
                ceiling: now,
                ttl_ms,
            } => {
                (revision, ceiling) = (granted, now);
                if asked > 0 {
                    spent = false;
                }
                match apply(granted, asked_at + ttl_ms * 1_000_000, now).await {
                    Ok(()) => {
                        if let Some(release) = release.take() {
                            release();
                        }
                    }
                    Err(error) => {
                        tracing::warn!(%error, "the launcher did not take a grant");
                        next = RETRY;
                    }
                }
            }
            // Less is left than was asked: take what is left.
            Answer::Short { available } if asked > 0 && available > 0 => {
                bytes = available.min(asked);
                continue;
            }
            Answer::Short { .. } => {
                spent = true;
                if asked > 0 {
                    if meter.borrow().wanted > ceiling {
                        return Stop::Limit;
                    }
                    // Nothing more to have: keep what was granted in force.
                    bytes = 0;
                    continue;
                }
                // Not even what it has may be renewed: the guest runs, and
                // is ended when it sends.
                if let Some(release) = release.take() {
                    release();
                }
            }
            Answer::Retry => {
                unanswered = Some(body);
                next = RETRY;
            }
        }
        if started.elapsed() >= HOLD_LIMIT
            && let Some(release) = release.take()
        {
            tracing::warn!("no grant came for the held guest: it runs without one");
            release();
        }
        let until = Instant::now() + next;
        loop {
            let seen = *meter.borrow_and_update();
            if let Some(stop) = Stop::of(seen.refusals, spent) {
                return stop;
            }
            let waiting = seen.wanted > ceiling;
            let low = ceiling.saturating_sub(seen.bytes) < chunk / 2;
            if unanswered.is_none() && (waiting || low && !spent) {
                if grew.is_some_and(|at| at.elapsed() < BUSY) {
                    chunk = (chunk * 2).min(MOST);
                }
                grew = Some(Instant::now());
                bytes = chunk.max(seen.wanted.saturating_sub(ceiling)).min(MOST);
                break;
            }
            tokio::select! {
                _ = tokio::time::sleep_until(until) => {
                    bytes = 0;
                    break;
                }
                changed = meter.changed() => if changed.is_err() {
                    // The meter ended with the VM: nothing more to grant.
                    std::future::pending::<()>().await;
                }
            }
        }
    }
}

/// Reads the endpoint's answer to an ask.
pub fn answer(status: u16, body: &[u8]) -> Answer {
    let value: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
    let number = |field: &str| {
        value[field]
            .as_u64()
            .or_else(|| value[field].as_str().and_then(|text| text.parse().ok()))
    };
    match status {
        200..=299 => match (
            number("revision"),
            number("ceiling_bytes"),
            number("ttl_ms"),
        ) {
            (Some(revision), Some(ceiling), Some(ttl_ms)) if value["state"] == "active" => {
                Answer::Granted {
                    revision,
                    ceiling,
                    ttl_ms,
                }
            }
            _ => Answer::Retry,
        },
        429 => Answer::Short {
            available: number("available_bytes").unwrap_or(0),
        },
        _ => Answer::Retry,
    }
}

/// The launcher's answer to a control command (its status), unless it names
/// an error.
pub fn applied(line: &[u8]) -> Result<Value, String> {
    let value: Value =
        serde_json::from_slice(line).map_err(|_| "the launcher's answer was not JSON")?;
    match value.get("error") {
        Some(Value::Null) => Ok(value),
        Some(Value::String(error)) => Err(error.clone()),
        _ => Err("the launcher's answer named no result".into()),
    }
}

/// How long [`close`] waits for writes already admitted to finish.
const SETTLE: Duration = Duration::from_millis(500);

/// Before a VM under the limit is killed: takes its authority to send away
/// and reads how many bytes it sent in all. A VM that is killed writes no
/// last meter line, so without this its total would be a moment old and the
/// run's whole grant, rather than what it sent, would count as used.
///
/// `command` sends the launcher one control command and gives its status.
/// `None` when the total cannot be known for certain: the launcher did not
/// answer, or a write it admitted earlier is still under way.
pub async fn close<C, CF>(command: C) -> Option<u64>
where
    C: Fn(String) -> CF,
    CF: Future<Output = Result<Value, String>>,
{
    let number = |status: &Value, field: &str| status[field].as_u64();
    let status = command("status\n".into()).await.ok()?;
    // A revision of its own, past any grant, and no deadline: nothing more is
    // admitted, whatever was granted.
    let mut status = command(format!(
        "egress {} 0 {}\n",
        number(&status, "egress_budget_revision")?.checked_add(1)?,
        number(&status, "egress_budget_ceiling")?
    ))
    .await
    .ok()?;
    let until = Instant::now() + SETTLE;
    loop {
        if status["egress_budget_measured"] != true
            || number(&status, "egress_budget_deadline_ns") != Some(0)
        {
            return None;
        }
        if number(&status, "egress_budget_in_flight") == Some(0)
            && number(&status, "egress_budget_reserved") == Some(0)
        {
            return number(&status, "egress_budget_bytes");
        }
        if Instant::now() >= until {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
        status = command("status\n".into()).await.ok()?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        cell::RefCell,
        collections::VecDeque,
        rc::Rc,
        sync::atomic::{AtomicBool, Ordering},
    };

    /// An endpoint with `allowance` bytes to grant, a launcher that records
    /// what it is told, and the asks made.
    #[derive(Default)]
    struct World {
        allowance: u64,
        granted: u64,
        revision: u64,
        asks: Vec<Value>,
        applied: Vec<(u64, u64)>,
        /// Answers given before the endpoint answers for itself.
        scripted: VecDeque<Answer>,
    }

    fn world(allowance: u64) -> Rc<RefCell<World>> {
        Rc::new(RefCell::new(World {
            allowance,
            ..World::default()
        }))
    }

    async fn run(
        world: &Rc<RefCell<World>>,
        meter: watch::Receiver<Meter>,
        released: &AtomicBool,
    ) -> Stop {
        enforce(
            "t",
            meter,
            |body: Value| {
                let world = world.clone();
                async move {
                    let mut world = world.borrow_mut();
                    world.asks.push(body.clone());
                    if let Some(answer) = world.scripted.pop_front() {
                        return answer;
                    }
                    let bytes = body["bytes"].as_u64().unwrap();
                    assert_eq!(body["expected_revision"], world.revision);
                    if world.granted + bytes > world.allowance {
                        return Answer::Short {
                            available: world.allowance - world.granted,
                        };
                    }
                    world.granted += bytes;
                    world.revision += 1;
                    Answer::Granted {
                        revision: world.revision,
                        ceiling: world.granted,
                        ttl_ms: 10_000,
                    }
                }
            },
            |revision, _deadline, ceiling| {
                world.borrow_mut().applied.push((revision, ceiling));
                async { Ok(()) }
            },
            || released.store(true, Ordering::SeqCst),
        )
        .await
    }

    /// Lets the limit run for a time, expecting it not to end the run.
    macro_rules! goes_on {
        ($limit:expr, $time:expr) => {
            tokio::select! {
                stop = &mut $limit => panic!("ended: {stop:?}"),
                _ = tokio::time::sleep($time) => {}
            }
        };
    }

    #[tokio::test(start_paused = true)]
    async fn the_guest_is_held_for_its_first_grant_which_is_then_renewed() {
        let world = world(10 * FIRST);
        let (_send, meter) = watch::channel(Meter::default());
        let released = AtomicBool::new(false);
        let limit = run(&world, meter, &released);
        tokio::pin!(limit);
        goes_on!(limit, Duration::from_secs(7));
        let world = world.borrow();
        assert!(released.load(Ordering::SeqCst));
        // The first ask is for bytes; the renewals, every 3 s, for none.
        assert_eq!(world.asks[0]["bytes"], FIRST);
        assert_eq!(world.asks[0]["expected_revision"], 0);
        assert_eq!(world.asks.len(), 3);
        assert!(world.asks[1..].iter().all(|ask| ask["bytes"] == 0));
        assert_eq!(world.applied, [(1, FIRST), (2, FIRST), (3, FIRST)]);
        let ids: std::collections::HashSet<_> = world
            .asks
            .iter()
            .map(|ask| ask["request_id"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(ids.len(), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn more_is_asked_for_as_the_allowance_runs_low_and_for_what_a_write_waits_on() {
        let world = world(100 * MOST);
        let (send, meter) = watch::channel(Meter::default());
        let released = AtomicBool::new(false);
        let limit = run(&world, meter, &released);
        tokio::pin!(limit);
        goes_on!(limit, Duration::from_millis(10));
        assert_eq!(world.borrow().granted, FIRST);
        // Over half of what was granted is sent: more is asked for at once.
        send.send(Meter {
            bytes: FIRST / 2 + 1,
            ..Meter::default()
        })
        .unwrap();
        goes_on!(limit, Duration::from_millis(10));
        assert_eq!(world.borrow().granted, 2 * FIRST);
        // A write waits on more than is asked for at a time: all of it is
        // asked for, and asks this close together grow.
        send.send(Meter {
            bytes: 2 * FIRST,
            wanted: 9 * FIRST,
            refusals: 0,
        })
        .unwrap();
        goes_on!(limit, Duration::from_millis(10));
        assert_eq!(world.borrow().granted, 9 * FIRST);
        send.send(Meter {
            bytes: 9 * FIRST,
            ..Meter::default()
        })
        .unwrap();
        goes_on!(limit, Duration::from_millis(10));
        assert_eq!(world.borrow().granted, 13 * FIRST);
    }

    #[tokio::test(start_paused = true)]
    async fn what_is_left_is_taken_and_a_write_waiting_on_more_ends_the_run() {
        let world = world(1000);
        let (send, meter) = watch::channel(Meter::default());
        let released = AtomicBool::new(false);
        let limit = run(&world, meter, &released);
        tokio::pin!(limit);
        goes_on!(limit, Duration::from_secs(4));
        {
            let world = world.borrow();
            // Asked for the first amount, told 1000 were left, took them, and
            // went on renewing them.
            assert_eq!(world.asks[0]["bytes"], FIRST);
            assert_eq!(world.asks[1]["bytes"], 1000);
            assert_eq!(world.applied[0], (1, 1000));
            assert!(released.load(Ordering::SeqCst));
        }
        // All of it sent: nothing ends the run until a write needs more.
        send.send(Meter {
            bytes: 1000,
            ..Meter::default()
        })
        .unwrap();
        goes_on!(limit, Duration::from_secs(4));
        assert_eq!(world.borrow().applied.last().unwrap().1, 1000);
        send.send(Meter {
            bytes: 1000,
            wanted: 1008,
            refusals: 0,
        })
        .unwrap();
        let stop = tokio::time::timeout(Duration::from_secs(1), &mut limit)
            .await
            .expect("a waiting write with nothing left ends the run");
        assert_eq!(stop, Stop::Limit);
        assert_eq!(world.borrow().granted, 1000);
    }

    #[tokio::test(start_paused = true)]
    async fn an_ask_without_an_answer_is_made_again_as_it_was() {
        let world = world(10 * FIRST);
        world
            .borrow_mut()
            .scripted
            .extend([Answer::Retry, Answer::Retry]);
        let (_send, meter) = watch::channel(Meter::default());
        let released = AtomicBool::new(false);
        let limit = run(&world, meter, &released);
        tokio::pin!(limit);
        goes_on!(limit, Duration::from_secs(2));
        let world = world.borrow();
        assert_eq!(world.asks[0], world.asks[1]);
        assert_eq!(world.asks[1], world.asks[2]);
        assert_eq!(world.applied, [(1, FIRST)]);
        assert!(released.load(Ordering::SeqCst));
    }

    #[tokio::test(start_paused = true)]
    async fn a_guest_no_grant_came_for_runs_after_a_while_and_is_ended_when_refused() {
        let world = world(0);
        world
            .borrow_mut()
            .scripted
            .extend(std::iter::repeat_with(|| Answer::Retry).take(1000));
        let (send, meter) = watch::channel(Meter::default());
        let released = AtomicBool::new(false);
        let limit = run(&world, meter, &released);
        tokio::pin!(limit);
        goes_on!(limit, Duration::from_secs(9));
        assert!(!released.load(Ordering::SeqCst));
        goes_on!(limit, Duration::from_secs(2));
        assert!(released.load(Ordering::SeqCst));
        assert!(world.borrow().applied.is_empty());
        // The launcher refused its write for want of a grant.
        send.send(Meter {
            bytes: 0,
            wanted: 0,
            refusals: 2,
        })
        .unwrap();
        let stop = tokio::time::timeout(Duration::from_secs(1), &mut limit)
            .await
            .unwrap();
        assert_eq!(stop, Stop::Expired);
    }

    fn status(revision: u64, deadline: u64, in_flight: u64, bytes: u64) -> Value {
        json!({"egress_budget_enabled":true,"egress_budget_revision":revision,
            "egress_budget_deadline_ns":deadline,"egress_budget_ceiling":4096,
            "egress_budget_reserved":in_flight,"egress_budget_bytes":bytes,
            "egress_budget_in_flight":in_flight,"egress_budget_measured":true,"error":null})
    }

    #[tokio::test(start_paused = true)]
    async fn closing_takes_the_authority_away_and_reads_the_total_once_nothing_is_under_way() {
        // The launcher: a grant in force at revision 7 and one write under
        // way, which finishes two status reads after the authority goes.
        let sent = RefCell::new(Vec::new());
        let total = close(|command: String| {
            sent.borrow_mut().push(command.clone());
            let asked = sent.borrow().len();
            async move {
                Ok(match asked {
                    1 => status(7, 99, 1, 100),
                    2 | 3 => status(8, 0, 1, 100),
                    _ => status(8, 0, 0, 164),
                })
            }
        })
        .await;
        assert_eq!(total, Some(164));
        assert_eq!(
            *sent.borrow(),
            ["status\n", "egress 8 0 4096\n", "status\n", "status\n"]
        );
        // A write still under way after the wait, an authority still in
        // force, or no answer: the total is not known.
        assert_eq!(close(|_| async { Ok(status(8, 0, 1, 100)) }).await, None);
        assert_eq!(close(|_| async { Ok(status(8, 99, 0, 100)) }).await, None);
        assert_eq!(
            close(|_| async { Err::<Value, _>("gone".to_owned()) }).await,
            None
        );
    }

    #[test]
    fn refusals_name_the_stop_and_answers_are_read_strictly() {
        assert_eq!(Stop::of(0, true), None);
        assert_eq!(Stop::of(1, true), Some(Stop::Limit));
        assert_eq!(Stop::of(1, false), Some(Stop::Expired));
        assert_eq!(Stop::of(2, false), Some(Stop::Expired));
        assert_eq!(Stop::of(7, true), Some(Stop::Unmeasured));
        assert_eq!(
            answer(
                200,
                br#"{"revision":4,"state":"active","ceiling_bytes":4096,"ttl_ms":9990}"#
            ),
            Answer::Granted {
                revision: 4,
                ceiling: 4096,
                ttl_ms: 9990
            }
        );
        // A grant not in force, or an answer missing a number, grants nothing.
        assert_eq!(
            answer(
                200,
                br#"{"revision":4,"state":"frozen","ceiling_bytes":4096,"ttl_ms":0}"#
            ),
            Answer::Retry
        );
        assert_eq!(answer(200, b"{}"), Answer::Retry);
        assert_eq!(
            answer(429, br#"{"available_bytes":12}"#),
            Answer::Short { available: 12 }
        );
        assert_eq!(answer(429, b"no"), Answer::Short { available: 0 });
        assert_eq!(answer(409, b"{}"), Answer::Retry);
        assert_eq!(answer(503, b""), Answer::Retry);
        assert!(applied(br#"{"paused":false,"error":null}"#).is_ok());
        assert_eq!(
            applied(br#"{"error":"stale-egress-budget"}"#).unwrap_err(),
            "stale-egress-budget"
        );
        assert!(applied(b"{}").is_err());
    }
}
