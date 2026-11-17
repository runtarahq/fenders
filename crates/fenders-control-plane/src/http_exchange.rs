//! Where the gateway meets the run channel: requests for HTTP apps, held in
//! memory until the app's shim takes them.
//!
//! No node is called. A shim serving an HTTP run asks the run channel for its
//! next request and posts the answer; the gateway offers each admitted
//! request here and waits for that answer. So the gateway and the run channel
//! must be served by one process.
//!
//! A request is handed out once. One that no shim took in time was never
//! given to an app ([`Offer::NotTaken`]); one that was taken and not answered
//! may have run ([`Offer::Lost`]). Nothing is replayed.
//!
//! A request and an answer are each a [`Message`]: a JSON head and the HTTP
//! body, which is passed on as it arrives and never held whole. On the run
//! channel a message is the head's length, the head, then the body's bytes
//! ([`head_frame`], [`read_head`]).
use axum::body::{Body, Bytes};
use http_body::Frame;
use http_body_util::BodyExt;
use serde_json::Value;
use std::{
    collections::{HashMap, VecDeque},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::sync::{Notify, mpsc, oneshot};

type BoxError = Box<dyn std::error::Error + Send + Sync>;
/// The largest head read from a run channel call.
const MAX_HEAD: usize = 64 * 1024;

/// A request on its way to an app, or an app's answer: the head (`{id,
/// method, path, headers}`, or `{status, headers}` or `{error}`) and the
/// HTTP body.
#[derive(Debug)]
pub struct Message {
    pub head: Value,
    pub body: Body,
}

/// Whether `head` is one a reader of this framing accepts: the shim, like
/// `read_head` here, refuses a head over `MAX_HEAD`.
pub fn head_fits(head: &Value) -> bool {
    head.to_string().len() <= MAX_HEAD
}

/// A head as it is sent before a body: its length (4 bytes, big endian),
/// then the head as JSON.
pub fn head_frame(head: &Value) -> Bytes {
    let head = head.to_string();
    let mut out = Vec::with_capacity(4 + head.len());
    out.extend_from_slice(&(head.len() as u32).to_be_bytes());
    out.extend_from_slice(head.as_bytes());
    out.into()
}

/// Reads a message's head from the start of `body`: the head, and what was
/// read past it. `None` when the body does not start with a head.
pub async fn read_head(body: &mut Body) -> Option<(Value, Bytes)> {
    let mut read = Vec::new();
    loop {
        if read.len() >= 4 {
            let length = u32::from_be_bytes(read[..4].try_into().ok()?) as usize;
            if length > MAX_HEAD {
                return None;
            }
            if read.len() >= 4 + length {
                let head = serde_json::from_slice(&read[4..4 + length]).ok()?;
                return Some((head, Bytes::copy_from_slice(&read[4 + length..])));
            }
        }
        match body.frame().await?.ok()?.into_data() {
            Ok(data) => read.extend_from_slice(&data),
            Err(_) => continue,
        }
    }
}

/// Bytes, then a body.
pub struct Prefixed {
    prefix: Option<Bytes>,
    inner: Body,
}

impl Prefixed {
    pub fn new(prefix: Bytes, inner: Body) -> Self {
        Self {
            prefix: Some(prefix).filter(|p| !p.is_empty()),
            inner,
        }
    }
}

impl http_body::Body for Prefixed {
    type Data = Bytes;
    type Error = axum::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, axum::Error>>> {
        if let Some(prefix) = self.prefix.take() {
            return Poll::Ready(Some(Ok(Frame::data(prefix))));
        }
        Pin::new(&mut self.inner).poll_frame(cx)
    }
}

/// The receiving end of a [`pipe`], as a body.
struct Piped(mpsc::Receiver<Result<Bytes, BoxError>>);

impl http_body::Body for Piped {
    type Data = Bytes;
    type Error = BoxError;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        self.0
            .poll_recv(cx)
            .map(|next| next.map(|chunk| chunk.map(Frame::data)))
    }
}

/// A body fed through a bounded channel: a few chunks are held at most, so
/// whoever feeds it goes no faster than whoever reads it.
pub fn pipe() -> (mpsc::Sender<Result<Bytes, BoxError>>, Body) {
    let (tx, rx) = mpsc::channel(8);
    (tx, Body::new(Piped(rx)))
}

/// Why a body stopped being passed on before its end.
#[derive(Debug, PartialEq)]
pub enum Cut {
    /// Whoever was reading it went away.
    Unread,
    /// It broke, or sent nothing for too long.
    Broken,
    /// Its bytes were not admitted (`admit` refused).
    Refused,
}

/// Passes `source` on into a [`pipe`] as it arrives, asking `admit` for each
/// chunk's bytes first: the bytes passed on, and why it stopped early if it
/// did. A body cut short ends in an error for its reader, never as if it
/// were whole. `idle` bounds the wait for each chunk.
pub async fn pump<A, F>(
    mut source: Body,
    tx: mpsc::Sender<Result<Bytes, BoxError>>,
    idle: Option<Duration>,
    mut admit: A,
) -> (u64, Option<Cut>)
where
    A: FnMut(usize) -> F,
    F: Future<Output = bool>,
{
    let mut passed = 0u64;
    let cut = loop {
        let next = match idle {
            Some(idle) => match tokio::time::timeout(idle, source.frame()).await {
                Ok(next) => next,
                Err(_) => break Some(Cut::Broken),
            },
            None => source.frame().await,
        };
        let data = match next {
            None => break None,
            Some(Err(_)) => break Some(Cut::Broken),
            Some(Ok(frame)) => match frame.into_data() {
                Ok(data) => data,
                Err(_) => continue,
            },
        };
        if !admit(data.len()).await {
            break Some(Cut::Refused);
        }
        passed += data.len() as u64;
        if tx.send(Ok(data)).await.is_err() {
            break Some(Cut::Unread);
        }
    };
    if matches!(cut, Some(Cut::Broken | Cut::Refused)) {
        let _ = tx.send(Err("the body was cut short".into())).await;
    }
    (passed, cut)
}

/// Requests one app may have waiting for a shim.
const MAX_QUEUED: usize = 64;
/// A queue nothing asked of for this long is forgotten.
const FORGET: Duration = Duration::from_secs(600);
/// A taker counts as present for this long after its last ask.
const PRESENT: Duration = Duration::from_secs(60);

/// A head and a whole body as one message on the wire.
pub fn frame(head: &Value, body: &[u8]) -> Bytes {
    let head = head.to_string();
    let mut out = Vec::with_capacity(4 + head.len() + body.len());
    out.extend_from_slice(&(head.len() as u32).to_be_bytes());
    out.extend_from_slice(head.as_bytes());
    out.extend_from_slice(body);
    out.into()
}

/// The head and body of a [`frame`]; `None` when it is not one.
pub fn unframe(bytes: &Bytes) -> Option<(Value, Bytes)> {
    let length = u32::from_be_bytes(bytes.get(..4)?.try_into().ok()?) as usize;
    let head = serde_json::from_slice(bytes.get(4..4usize.checked_add(length)?)?).ok()?;
    Some((head, bytes.slice(4 + length..)))
}

/// What became of a request the gateway offered.
#[derive(Debug)]
pub enum Offer {
    /// The app's answer.
    Answered(Message),
    /// No shim took it: the app never saw it.
    NotTaken,
    /// A shim took it and no answer came: it may have run.
    Lost,
}

/// How pressed a queue is: what scaling an app out is decided on.
#[derive(Debug, Default, PartialEq)]
pub struct Pressure {
    /// How long its oldest request has waited for a taker, if one waits.
    pub waiting: Option<Duration>,
    /// For how long no taker has been free to take a request.
    pub saturated: Option<Duration>,
}

/// The requests of one app (or one execution that belongs to none), in
/// order, for whichever of its takers is free.
#[derive(Default)]
struct Queue {
    requests: VecDeque<(String, Message, Instant)>,
    wake: Arc<Notify>,
    /// Asks waiting for a request now, from any taker.
    waiting: usize,
    /// Since when none has been waiting.
    saturated: Option<Instant>,
    /// Asks waiting on it are told to ask again ([`Exchange::close`]).
    closed: bool,
}

impl Queue {
    fn asks_changed(&mut self) {
        if self.waiting > 0 {
            self.saturated = None;
        } else if self.saturated.is_none() {
            self.saturated = Some(Instant::now());
        }
    }
}

/// One execution's shim, as the exchange has seen it.
struct Taker {
    /// Its asks waiting now.
    waiting: usize,
    /// When it last asked.
    asked: Instant,
    /// The requests it took and has not finished answering.
    busy: std::collections::HashSet<String>,
    /// When it last took or finished one, or first asked.
    active: Instant,
}

struct Out {
    key: String,
    /// Who took it, once taken.
    taker: Option<String>,
    answer: oneshot::Sender<Message>,
}

#[derive(Default)]
struct Inner {
    queues: HashMap<String, Queue>,
    takers: HashMap<String, Taker>,
    out: HashMap<String, Out>,
}

#[derive(Default)]
pub struct Exchange {
    inner: Mutex<Inner>,
}

/// Withdraws a request when the gateway stops waiting for it, however.
struct Withdraw<'a> {
    exchange: &'a Exchange,
    key: &'a str,
    id: &'a str,
}
impl Drop for Withdraw<'_> {
    fn drop(&mut self) {
        let mut inner = self.exchange.lock();
        inner.out.remove(self.id);
        if let Some(queue) = inner.queues.get_mut(self.key) {
            queue.requests.retain(|(id, ..)| id != self.id);
        }
    }
}

/// Counts an ask as waiting for as long as it waits.
struct Waiting<'a> {
    exchange: &'a Exchange,
    key: &'a str,
    taker: &'a str,
}
impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        let mut inner = self.exchange.lock();
        if let Some(queue) = inner.queues.get_mut(self.key) {
            queue.waiting = queue.waiting.saturating_sub(1);
            queue.asks_changed();
        }
        if let Some(taker) = inner.takers.get_mut(self.taker) {
            taker.waiting = taker.waiting.saturating_sub(1);
        }
    }
}

impl Exchange {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Offers request `id` to whoever takes from `key`, and waits for the
    /// answer's head: `take_within` for a taker, then `answer_within` more.
    pub async fn offer(
        &self,
        key: &str,
        id: &str,
        request: Message,
        take_within: Duration,
        answer_within: Duration,
    ) -> Offer {
        let (answer, mut answered) = oneshot::channel();
        {
            let mut inner = self.lock();
            let queue = inner.queues.entry(key.to_owned()).or_default();
            if queue.requests.len() >= MAX_QUEUED {
                return Offer::NotTaken;
            }
            queue
                .requests
                .push_back((id.to_owned(), request, Instant::now()));
            queue.wake.notify_one();
            inner.out.insert(
                id.to_owned(),
                Out {
                    key: key.to_owned(),
                    taker: None,
                    answer,
                },
            );
        }
        let _withdraw = Withdraw {
            exchange: self,
            key,
            id,
        };
        if let Ok(frame) = tokio::time::timeout(take_within, &mut answered).await {
            return frame.map_or(Offer::Lost, Offer::Answered);
        }
        if !self
            .lock()
            .out
            .get(id)
            .is_some_and(|out| out.taker.is_some())
        {
            return Offer::NotTaken;
        }
        match tokio::time::timeout(answer_within, answered).await {
            Ok(Ok(frame)) => Offer::Answered(frame),
            _ => Offer::Lost,
        }
    }

    /// The next request of `key` for `taker`, waiting up to `wait` for one.
    /// Asking marks the taker as present; a request it is given counts it
    /// busy until it says it has [`finished`](Self::finished) it.
    pub async fn next(&self, key: &str, taker: &str, wait: Duration) -> Option<Message> {
        let deadline = tokio::time::Instant::now() + wait;
        let _waiting = {
            let mut inner = self.lock();
            let now = Instant::now();
            inner.takers.retain(|name, seen| {
                name == taker || seen.waiting > 0 || now - seen.asked < FORGET
            });
            let Inner { queues, takers, .. } = &mut *inner;
            queues.retain(|name, queue| {
                name == key || !queue.requests.is_empty() || queue.waiting > 0
            });
            let queue = queues.entry(key.to_owned()).or_default();
            queue.waiting += 1;
            queue.closed = false;
            queue.asks_changed();
            let seen = takers.entry(taker.to_owned()).or_insert_with(|| Taker {
                waiting: 0,
                asked: now,
                busy: Default::default(),
                active: now,
            });
            seen.waiting += 1;
            seen.asked = now;
            Waiting {
                exchange: self,
                key,
                taker,
            }
        };
        loop {
            let wake = {
                let mut inner = self.lock();
                let Inner {
                    queues,
                    takers,
                    out,
                } = &mut *inner;
                let queue = queues.entry(key.to_owned()).or_default();
                if queue.closed {
                    return None;
                }
                while let Some((id, request, _)) = queue.requests.pop_front() {
                    // One the gateway stopped waiting for is not handed out.
                    if let Some(out) = out.get_mut(&id) {
                        out.taker = Some(taker.to_owned());
                        if let Some(seen) = takers.get_mut(taker) {
                            seen.busy.insert(id);
                            seen.active = Instant::now();
                        }
                        return Some(request);
                    }
                }
                queue.wake.clone()
            };
            if tokio::time::timeout_at(deadline, wake.notified())
                .await
                .is_err()
            {
                return None;
            }
        }
    }

    /// Gives the gateway the answer to request `id`, which `taker` took.
    /// False when it is not such a request, or the gateway is gone.
    pub fn respond(&self, taker: &str, id: &str, answer: Message) -> bool {
        let out = {
            let mut inner = self.lock();
            if inner
                .out
                .get(id)
                .is_none_or(|out| out.taker.as_deref() != Some(taker))
            {
                return false;
            }
            inner.out.remove(id)
        };
        out.is_some_and(|out| out.answer.send(answer).is_ok())
    }

    /// `taker` has no more to do with request `id`: its answer has ended, or
    /// nobody wanted it.
    pub fn finished(&self, taker: &str, id: &str) {
        if let Some(seen) = self.lock().takers.get_mut(taker)
            && seen.busy.remove(id)
        {
            seen.active = Instant::now();
        }
    }

    /// Tells the asks waiting on `key` to ask again: what they take from may
    /// have changed.
    pub fn close(&self, key: &str) {
        if let Some(queue) = self.lock().queues.get_mut(key) {
            queue.closed = true;
            queue.wake.notify_waiters();
        }
    }

    /// Whether `taker` is taking requests: an ask of its is waiting, or it
    /// made one in the last minute (it is busy with what it took).
    pub fn ready(&self, taker: &str) -> bool {
        self.lock()
            .takers
            .get(taker)
            .is_some_and(|seen| seen.waiting > 0 || seen.asked.elapsed() < PRESENT)
    }

    /// For how long `taker` has had no request: `None` while it has one, or
    /// when it has never asked.
    pub fn idle(&self, taker: &str) -> Option<Duration> {
        let inner = self.lock();
        let seen = inner.takers.get(taker)?;
        seen.busy.is_empty().then(|| seen.active.elapsed())
    }

    /// Whether `taker` has a request it has not finished answering.
    pub fn busy(&self, taker: &str) -> bool {
        self.lock()
            .takers
            .get(taker)
            .is_some_and(|seen| !seen.busy.is_empty())
    }

    /// How pressed `key`'s queue is.
    pub fn pressure(&self, key: &str) -> Pressure {
        let inner = self.lock();
        let Some(queue) = inner.queues.get(key) else {
            return Pressure::default();
        };
        Pressure {
            waiting: queue.requests.front().map(|(.., since)| since.elapsed()),
            saturated: queue.saturated.map(|since| since.elapsed()),
        }
    }

    /// Makes everything the exchange has timed `by` older: for tests of what
    /// is decided on those times, which would otherwise have to wait them out.
    #[doc(hidden)]
    pub fn rewind(&self, by: Duration) {
        let mut inner = self.lock();
        let back = |at: &mut Instant| *at = at.checked_sub(by).unwrap_or(*at);
        for queue in inner.queues.values_mut() {
            queue.saturated.iter_mut().for_each(back);
            queue
                .requests
                .iter_mut()
                .for_each(|(.., since)| back(since));
        }
        for taker in inner.takers.values_mut() {
            back(&mut taker.active);
        }
    }

    /// Requests offered for `key` and not answered yet, waiting or taken.
    pub fn outstanding(&self, key: &str) -> usize {
        self.lock()
            .out
            .values()
            .filter(|out| out.key == key)
            .count()
    }
}

#[cfg(test)]
mod tests {
    /// A head its reader would refuse does not fit, and so is never sent.
    #[test]
    fn a_head_its_reader_would_refuse_does_not_fit() {
        let head = |target: usize| serde_json::json!({"method":"GET","path":"a".repeat(target),"headers":{}});
        assert!(super::head_fits(&head(1024)));
        assert!(super::head_fits(&head(super::MAX_HEAD - 64)));
        assert!(!super::head_fits(&head(super::MAX_HEAD)));
        // The same bound as the one a head is read under.
        let frame = super::head_frame(&head(super::MAX_HEAD));
        assert!(u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize > super::MAX_HEAD);
    }

    use super::*;
    use serde_json::json;

    const LONG: Duration = Duration::from_secs(30);

    fn message(body: &'static [u8]) -> Message {
        Message {
            head: json!({"body": String::from_utf8_lossy(body)}),
            body: Body::from(body),
        }
    }
    async fn text(message: Message) -> Vec<u8> {
        axum::body::to_bytes(message.body, 1 << 20)
            .await
            .unwrap()
            .to_vec()
    }

    #[tokio::test]
    async fn a_head_is_read_from_the_start_of_a_body_and_garbage_is_refused() {
        let framed = frame(&json!({"id":"a"}), &[1, 2, 3]);
        let (head, body) = unframe(&framed).unwrap();
        assert_eq!(head["id"], "a");
        assert_eq!(&body[..], &[1, 2, 3]);
        assert!(unframe(&Bytes::from_static(b"{}")).is_none());
        assert!(unframe(&Bytes::from_static(&[255, 255, 255, 255, 1])).is_none());

        // In pieces that split the length and the head, with the body after.
        for split in [framed.len(), 2, 7] {
            let (tx, piped) = pipe();
            tx.send(Ok(framed.slice(..split))).await.unwrap();
            tx.send(Ok(framed.slice(split..))).await.unwrap();
            drop(tx);
            let mut body = piped;
            let (head, rest) = read_head(&mut body).await.unwrap();
            assert_eq!(head["id"], "a");
            let whole = axum::body::to_bytes(Body::new(Prefixed::new(rest, body)), 100)
                .await
                .unwrap();
            assert_eq!(&whole[..], &[1, 2, 3], "split at {split}");
        }
        assert!(read_head(&mut Body::from("{}")).await.is_none());
        assert!(
            read_head(&mut Body::from(vec![255, 255, 255, 255, 1]))
                .await
                .is_none()
        );
        assert_eq!(&head_frame(&json!({}))[..], &[0, 0, 0, 2, b'{', b'}']);
        // A head a reader would refuse is known before it is sent.
        assert!(head_fits(&json!({"path": "a".repeat(MAX_HEAD - 16)})));
        assert!(!head_fits(&json!({"path": "a".repeat(MAX_HEAD)})));
        let long = head_frame(&json!({"path": "a".repeat(MAX_HEAD)}));
        assert!(read_head(&mut Body::from(long)).await.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn a_body_is_passed_on_as_it_arrives_and_one_cut_short_ends_in_an_error() {
        // Whole: every byte admitted and passed on.
        let (tx, piped) = pipe();
        let admitted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = admitted.clone();
        let pumped = tokio::spawn(pump(Body::from("0123456789"), tx, None, move |n| {
            let count = count.clone();
            async move {
                count.fetch_add(n, std::sync::atomic::Ordering::SeqCst);
                true
            }
        }));
        assert_eq!(
            &axum::body::to_bytes(piped, 100).await.unwrap()[..],
            b"0123456789"
        );
        assert_eq!(pumped.await.unwrap(), (10, None));
        assert_eq!(admitted.load(std::sync::atomic::Ordering::SeqCst), 10);

        // Refused: nothing is passed on and the reader gets an error.
        let (tx, piped) = pipe();
        let pumped = tokio::spawn(pump(Body::from("secret"), tx, None, |_| async { false }));
        assert!(axum::body::to_bytes(piped, 100).await.is_err());
        assert_eq!(pumped.await.unwrap(), (0, Some(Cut::Refused)));

        // Silent for too long: cut, as an error.
        let (source, silent) = pipe();
        let (tx, piped) = pipe();
        let pumped = tokio::spawn(pump(silent, tx, Some(Duration::from_secs(60)), |_| async {
            true
        }));
        source.send(Ok(Bytes::from_static(b"first"))).await.unwrap();
        assert!(axum::body::to_bytes(piped, 100).await.is_err());
        assert_eq!(pumped.await.unwrap(), (5, Some(Cut::Broken)));

        // The reader went away: the pump stops.
        let (tx, piped) = pipe();
        drop(piped);
        let cut = pump(Body::from("x"), tx, None, |_| async { true }).await;
        assert_eq!(cut, (1, Some(Cut::Unread)));
    }

    #[tokio::test(start_paused = true)]
    async fn a_request_goes_to_one_taker_and_its_answer_back() {
        let exchange = Arc::new(Exchange::default());
        assert!(!exchange.ready("e1"));
        let taker = tokio::spawn({
            let exchange = exchange.clone();
            async move { exchange.next("e1", "e1", LONG).await }
        });
        tokio::task::yield_now().await;
        assert!(exchange.ready("e1"));
        let gateway = tokio::spawn({
            let exchange = exchange.clone();
            async move {
                exchange
                    .offer("e1", "r1", message(b"request"), LONG, LONG)
                    .await
            }
        });
        assert_eq!(text(taker.await.unwrap().unwrap()).await, b"request");
        assert_eq!(exchange.outstanding("e1"), 1);
        // Another run cannot answer it, nor can it be answered twice.
        assert!(!exchange.respond("e2", "r1", message(b"forged")));
        assert!(exchange.respond("e1", "r1", message(b"answer")));
        assert!(!exchange.respond("e1", "r1", message(b"again")));
        let Offer::Answered(answer) = gateway.await.unwrap() else {
            panic!("not answered")
        };
        assert_eq!(text(answer).await, b"answer");
        assert_eq!(exchange.outstanding("e1"), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn an_untaken_request_never_ran_and_a_taken_one_without_answer_is_lost() {
        let exchange = Arc::new(Exchange::default());
        let untaken = exchange
            .offer("e1", "r1", message(b""), Duration::from_secs(10), LONG)
            .await;
        assert!(matches!(untaken, Offer::NotTaken));
        // It is not handed out afterwards.
        assert!(
            exchange
                .next("e1", "e1", Duration::from_secs(1))
                .await
                .is_none()
        );

        let gateway = tokio::spawn({
            let exchange = exchange.clone();
            async move {
                exchange
                    .offer("e1", "r2", message(b""), Duration::from_secs(10), LONG)
                    .await
            }
        });
        assert!(exchange.next("e1", "e1", LONG).await.is_some());
        assert!(matches!(gateway.await.unwrap(), Offer::Lost));
        // The answer comes too late for anyone.
        assert!(!exchange.respond("e1", "r2", message(b"")));
    }

    #[tokio::test(start_paused = true)]
    async fn requests_queue_in_order_up_to_a_bound_and_a_gone_gateway_withdraws_its_own() {
        let exchange = Arc::new(Exchange::default());
        let mut offers = Vec::new();
        for n in 0..MAX_QUEUED {
            let exchange = exchange.clone();
            offers.push(tokio::spawn(async move {
                let id = format!("r{n}");
                let request = Message {
                    head: json!({"id": id}),
                    body: Body::empty(),
                };
                exchange.offer("e1", &id, request, LONG, LONG).await
            }));
            tokio::task::yield_now().await;
        }
        let over = exchange.offer("e1", "over", message(b""), LONG, LONG).await;
        assert!(matches!(over, Offer::NotTaken));
        // The first gateway goes away; the second request is next.
        offers.remove(0).abort();
        tokio::task::yield_now().await;
        assert_eq!(
            exchange.next("e1", "e1", LONG).await.unwrap().head["id"],
            "r1"
        );
        assert_eq!(
            exchange.next("e1", "e1", LONG).await.unwrap().head["id"],
            "r2"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn an_apps_requests_go_to_whichever_of_its_takers_is_free() {
        let exchange = Arc::new(Exchange::default());
        // Two executions of one app, each with one ask waiting.
        let asks: Vec<_> = ["first", "second"]
            .into_iter()
            .map(|taker| {
                let exchange = exchange.clone();
                tokio::spawn(async move { exchange.next("app", taker, LONG).await })
            })
            .collect();
        tokio::task::yield_now().await;
        assert!(exchange.ready("first") && exchange.ready("second"));
        assert_eq!(exchange.pressure("app"), Pressure::default());
        let offers: Vec<_> = ["r1", "r2", "r3"]
            .into_iter()
            .map(|id| {
                let exchange = exchange.clone();
                tokio::spawn(
                    async move { exchange.offer("app", id, message(b""), LONG, LONG).await },
                )
            })
            .collect();
        for ask in asks {
            assert!(ask.await.unwrap().is_some());
        }
        // Both are busy, neither idle, and a third request waits: pressed.
        assert_eq!(exchange.idle("first"), None);
        assert_eq!(exchange.idle("second"), None);
        tokio::task::yield_now().await;
        let pressed = exchange.pressure("app");
        assert!(pressed.waiting.is_some() && pressed.saturated.is_some());
        // Each answers what it took, and only that.
        let taken = |taker: &str| {
            ["r1", "r2"]
                .into_iter()
                .find(|id| exchange.respond(taker, id, message(b"done")))
                .unwrap()
        };
        let (one, two) = (taken("first"), taken("second"));
        assert_ne!(one, two);
        // Busy until it says its answer has ended.
        assert_eq!(exchange.idle("first"), None);
        exchange.finished("first", one);
        assert!(exchange.idle("first").is_some());
        // The free one takes the third.
        assert!(exchange.next("app", "first", LONG).await.is_some());
        assert_eq!(exchange.pressure("app").waiting, None);
        drop(offers);
    }

    #[tokio::test(start_paused = true)]
    async fn asks_waiting_on_a_closed_queue_are_told_to_ask_again() {
        let exchange = Arc::new(Exchange::default());
        let ask = tokio::spawn({
            let exchange = exchange.clone();
            async move { exchange.next("candidate", "e2", LONG).await }
        });
        tokio::task::yield_now().await;
        assert!(exchange.ready("e2"));
        exchange.close("candidate");
        assert!(ask.await.unwrap().is_none());
        // Its next ask waits as any other.
        let again = tokio::time::timeout(Duration::from_secs(1), exchange.next("app", "e2", LONG));
        assert!(again.await.is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn a_taker_that_stops_asking_is_no_longer_ready() {
        let exchange = Exchange::default();
        assert!(
            exchange
                .next("e1", "e1", Duration::from_secs(25))
                .await
                .is_none()
        );
        assert!(exchange.ready("e1"));
        std::thread::sleep(Duration::from_millis(1));
        assert!(!exchange.ready("other"));
    }
}
