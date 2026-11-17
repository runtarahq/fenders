//! Guest output, for a launch that asked for it (`guest.output`): the VM's
//! standard output and error are read from two pipes, the values of the
//! named environment variables masked, and the result sent up the run channel
//! in bounded batches (`POST /v1/run/output`).
//!
//! A launch that did not ask has none of this: no pipe, task or call.
//!
//! The guest never waits on delivery. The pipes are read whatever the network
//! does; what cannot be sent is held in memory up to [`UNSENT_BYTES`], then
//! the oldest is dropped, which the next batch shows as a jump in sequence.
//! Nothing is written to disk, so output not delivered when the shim exits is
//! lost. An endpoint that refuses the call (it does not serve output, or the
//! launch is no longer current) ends capture for the run; the run goes on.
//!
//! Masking is of literal values: a program that encodes or transforms a
//! secret before printing it is not caught.
use base64::{Engine, engine::general_purpose::STANDARD};
use hyper::body::Bytes;
use serde_json::{Value, json};
use std::{
    collections::VecDeque,
    future::Future,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{io::AsyncReadExt, net::unix::pipe::Receiver, sync::Notify};

/// Where batches are posted, under the launch's endpoint.
pub const PATH: &str = "/v1/run/output";
/// The masking applied, as every batch names it.
pub const REDACTION: &str = "literal-v1";
/// The largest record, cut at a line end where there is one.
const RECORD_BYTES: usize = 8192;
/// The most output held unsent; beyond it the oldest is dropped.
const UNSENT_BYTES: usize = 256 * 1024;
const BATCH_RECORDS: usize = 64;
const BATCH_BYTES: usize = 48 * 1024;
/// How long a record waits for a fuller batch.
const FLUSH: Duration = Duration::from_millis(200);
/// How long a line without its end waits before it is sent as it is.
const PARTIAL_LINE: Duration = Duration::from_millis(100);
/// How long a run's end waits for its last output to be delivered.
pub const CLOSE_WAIT: Duration = Duration::from_secs(5);

/// Whether a guest configuration asks for its output.
pub fn wanted(guest: &Value) -> bool {
    guest.get("output").is_some_and(Value::is_object)
}

/// The names a guest configuration asks to be masked, and a redactor for
/// their values.
pub fn redaction(guest: &Value) -> (Vec<String>, Redactor) {
    let names: Vec<String> = guest["output"]["redact_env"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|name| name.as_str().map(str::to_owned))
        .collect();
    let values = names
        .iter()
        .filter_map(|name| guest["env"][name].as_str())
        .map(|value| value.as_bytes().to_vec());
    let redactor = Redactor::new(values);
    (names, redactor)
}

/// The shim's ends of a capturing VM's pipes.
pub struct Pipes {
    pub stdout: OwnedFd,
    pub stderr: OwnedFd,
    /// The launcher's own messages, kept apart from the guest's.
    pub diagnostics: OwnedFd,
}

/// The VM's ends: its standard output and error, and the launcher's
/// `FENDERS_DIAGNOSTICS_FD`.
pub struct VmEnds {
    pub stdout: OwnedFd,
    pub stderr: OwnedFd,
    pub diagnostics: OwnedFd,
}

fn pipe() -> Result<(OwnedFd, OwnedFd), String> {
    let mut ends = [0; 2];
    if unsafe { libc::pipe2(ends.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return Err(format!("output pipe: {}", std::io::Error::last_os_error()));
    }
    let (read, write) = unsafe { (OwnedFd::from_raw_fd(ends[0]), OwnedFd::from_raw_fd(ends[1])) };
    // Only the shim's end: the VM's writes stay blocking.
    let flags = unsafe { libc::fcntl(read.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(read.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return Err(format!("output pipe: {}", std::io::Error::last_os_error()));
    }
    Ok((read, write))
}

pub fn pipes() -> Result<(Pipes, VmEnds), String> {
    let (stdout, vm_stdout) = pipe()?;
    let (stderr, vm_stderr) = pipe()?;
    let (diagnostics, vm_diagnostics) = pipe()?;
    Ok((
        Pipes {
            stdout,
            stderr,
            diagnostics,
        },
        VmEnds {
            stdout: vm_stdout,
            stderr: vm_stderr,
            diagnostics: vm_diagnostics,
        },
    ))
}

#[derive(Clone)]
struct Pattern {
    bytes: Vec<u8>,
    prefix: Vec<usize>,
    matched: usize,
}

/// Replaces each occurrence of a value with `[REDACTED]` in a stream given
/// piece by piece. Bytes that may still turn out to begin a value are held
/// back until they cannot, so a value split across two reads is masked and
/// no part of one is let out early.
#[derive(Clone)]
pub struct Redactor {
    patterns: Vec<Pattern>,
    pending: VecDeque<u8>,
    ranges: VecDeque<(u64, u64)>,
    position: u64,
    emitted: u64,
    masked: bool,
}

impl Redactor {
    pub fn new(values: impl IntoIterator<Item = Vec<u8>>) -> Self {
        let mut patterns = Vec::new();
        for bytes in values {
            if bytes.is_empty() {
                continue;
            }
            let mut prefix = vec![0; bytes.len()];
            for i in 1..bytes.len() {
                let mut j = prefix[i - 1];
                while j > 0 && bytes[i] != bytes[j] {
                    j = prefix[j - 1];
                }
                if bytes[i] == bytes[j] {
                    j += 1;
                }
                prefix[i] = j;
            }
            patterns.push(Pattern {
                bytes,
                prefix,
                matched: 0,
            });
        }
        Self {
            patterns,
            pending: VecDeque::new(),
            ranges: VecDeque::new(),
            position: 0,
            emitted: 0,
            masked: false,
        }
    }

    pub fn push(&mut self, bytes: &[u8]) -> Vec<u8> {
        let mut output = Vec::new();
        for &byte in bytes {
            self.pending.push_back(byte);
            self.position += 1;
            let mut start = None;
            let mut hold = 0;
            for pattern in &mut self.patterns {
                while pattern.matched > 0 && byte != pattern.bytes[pattern.matched] {
                    pattern.matched = pattern.prefix[pattern.matched - 1];
                }
                if byte == pattern.bytes[pattern.matched] {
                    pattern.matched += 1;
                }
                if pattern.matched == pattern.bytes.len() {
                    let begin = self.position - pattern.bytes.len() as u64;
                    start = Some(start.map_or(begin, |old: u64| old.min(begin)));
                    pattern.matched = pattern.prefix[pattern.matched - 1];
                }
                hold = hold.max(pattern.matched);
            }
            if let Some(mut start) = start {
                while let Some(range) = self.ranges.back().filter(|range| range.1 >= start) {
                    start = start.min(range.0);
                    self.ranges.pop_back();
                }
                self.ranges.push_back((start, self.position));
            }
            while self.pending.len() > hold {
                self.emit(&mut output);
            }
        }
        output
    }

    fn emit(&mut self, output: &mut Vec<u8>) {
        while self
            .ranges
            .front()
            .is_some_and(|range| range.1 <= self.emitted)
        {
            self.ranges.pop_front();
        }
        let masked = self
            .ranges
            .front()
            .is_some_and(|range| range.0 <= self.emitted);
        let Some(byte) = self.pending.pop_front() else {
            return;
        };
        if masked {
            if !self.masked {
                output.extend_from_slice(b"[REDACTED]");
            }
        } else {
            output.push(byte);
        }
        self.masked = masked;
        self.emitted += 1;
    }

    /// What was held back, at the stream's end.
    pub fn finish(&mut self) -> Vec<u8> {
        let mut output = Vec::new();
        while !self.pending.is_empty() {
            self.emit(&mut output);
        }
        output
    }
}

/// Cuts a stream into records of at most [`RECORD_BYTES`], at a line end
/// where there is one.
#[derive(Default)]
struct Cutter {
    pending: Vec<u8>,
}

impl Cutter {
    fn push(&mut self, bytes: &[u8], mut emit: impl FnMut(Vec<u8>)) {
        self.pending.extend_from_slice(bytes);
        loop {
            let window = &self.pending[..self.pending.len().min(RECORD_BYTES)];
            let cut = match window.iter().rposition(|byte| *byte == b'\n') {
                Some(end) => end + 1,
                None if window.len() == RECORD_BYTES => RECORD_BYTES,
                None => break,
            };
            emit(self.pending.drain(..cut).collect());
        }
    }

    /// The line still waiting for its end, as it is.
    fn flush(&mut self, mut emit: impl FnMut(Vec<u8>)) {
        if !self.pending.is_empty() {
            emit(std::mem::take(&mut self.pending));
        }
    }
}

struct Record {
    sequence: i64,
    at_ms: i64,
    stream: &'static str,
    bytes: Vec<u8>,
}

#[derive(Default)]
struct Queue {
    records: VecDeque<Record>,
    bytes: usize,
    /// The last sequence given to a record.
    assigned: i64,
    dropped: u64,
    /// Both streams reached their end.
    ended: bool,
    /// The endpoint refused output: nothing more is kept.
    refused: bool,
}

impl Queue {
    fn full(&self) -> bool {
        self.records.len() >= BATCH_RECORDS || self.bytes >= BATCH_BYTES
    }
}

#[derive(Default)]
struct Shared {
    queue: Mutex<Queue>,
    changed: Notify,
}

impl Shared {
    fn queue(&self) -> std::sync::MutexGuard<'_, Queue> {
        self.queue.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn push(&self, stream: &'static str, bytes: Vec<u8>) {
        if bytes.is_empty() {
            return;
        }
        let mut queue = self.queue();
        if queue.refused {
            return;
        }
        queue.assigned += 1;
        queue.bytes += bytes.len();
        let record = Record {
            sequence: queue.assigned,
            at_ms: now_ms(),
            stream,
            bytes,
        };
        queue.records.push_back(record);
        while queue.bytes > UNSENT_BYTES {
            let Some(oldest) = queue.records.pop_front() else {
                break;
            };
            queue.bytes -= oldest.bytes.len();
            queue.dropped += 1;
        }
        drop(queue);
        self.changed.notify_waiters();
    }

    fn end(&self) {
        self.queue().ended = true;
        self.changed.notify_waiters();
    }

    async fn until(&self, ready: impl Fn(&Queue) -> bool) {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if ready(&self.queue()) {
                return;
            }
            changed.await;
        }
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// 32 hex characters naming this shim's capture.
fn capture_id() -> String {
    let mut bytes = [0u8; 16];
    unsafe { libc::getrandom(bytes.as_mut_ptr().cast(), bytes.len(), 0) };
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

async fn read(fd: OwnedFd, stream: &'static str, mut redactor: Redactor, shared: Arc<Shared>) {
    let Ok(mut pipe) = Receiver::from_owned_fd(fd) else {
        return;
    };
    let mut cutter = Cutter::default();
    let mut buffer = vec![0; 16 * 1024];
    let emit = |bytes| shared.push(stream, bytes);
    loop {
        let read = if cutter.pending.is_empty() {
            pipe.read(&mut buffer).await
        } else {
            match tokio::time::timeout(PARTIAL_LINE, pipe.read(&mut buffer)).await {
                Ok(read) => read,
                Err(_) => {
                    cutter.flush(emit);
                    continue;
                }
            }
        };
        match read {
            Ok(0) | Err(_) => break,
            // Refused output is still read, so the guest's writes never block.
            Ok(_) if shared.queue().refused => {}
            Ok(n) => cutter.push(&redactor.push(&buffer[..n]), emit),
        }
    }
    cutter.push(&redactor.finish(), emit);
    cutter.flush(emit);
}

/// What the endpoint made of a batch.
pub enum Sent {
    Accepted,
    /// Refused for good, with the status: capture ends.
    Refused(u16),
    /// Not delivered, or failed there: the same batch is sent again.
    Retry,
}

/// How a run's capture went.
#[derive(Debug, Default, PartialEq)]
pub struct Summary {
    /// Records the endpoint accepted.
    pub delivered: u64,
    /// Records dropped unsent, to stay within the memory bound.
    pub dropped: u64,
    /// The status with which the endpoint refused output, if it did.
    pub refused: Option<u16>,
}

/// Reads the VM's output to its end and delivers it with `send`, which takes
/// a batch's JSON. Returns once the closing batch is accepted or output is
/// refused.
pub async fn capture<F, Fut>(
    stdout: OwnedFd,
    stderr: OwnedFd,
    redactor: Redactor,
    redacted_env: Vec<String>,
    send: F,
) -> Summary
where
    F: Fn(Bytes) -> Fut,
    Fut: Future<Output = Sent>,
{
    let shared = Arc::new(Shared::default());
    let out = tokio::spawn(read(stdout, "stdout", redactor.clone(), shared.clone()));
    let err = tokio::spawn(read(stderr, "stderr", redactor, shared.clone()));
    {
        let shared = shared.clone();
        tokio::spawn(async move {
            let _ = out.await;
            let _ = err.await;
            shared.end();
        });
    }
    let capture_id = capture_id();
    let mut summary = Summary::default();
    loop {
        shared.until(|q| !q.records.is_empty() || q.ended).await;
        let _ = tokio::time::timeout(FLUSH, shared.until(|q| q.ended || q.full())).await;
        let (records, closed, assigned) = {
            let mut queue = shared.queue();
            let mut records = Vec::new();
            let mut bytes = 0;
            while let Some(next) = queue.records.front().map(|next| next.bytes.len()) {
                if records.len() == BATCH_RECORDS
                    || (!records.is_empty() && bytes + next > BATCH_BYTES)
                {
                    break;
                }
                bytes += next;
                queue.bytes -= next;
                records.extend(queue.records.pop_front());
            }
            let closed = queue.ended && queue.records.is_empty();
            summary.dropped = queue.dropped;
            (records, closed, queue.assigned)
        };
        if records.is_empty() && !closed {
            continue;
        }
        let body = Bytes::from(
            json!({
                "format_version": 1,
                "capture_id": capture_id,
                // With no record, the closing batch of a capture whose every
                // record was delivered: it begins after the last one.
                "first_sequence": records.first().map_or(assigned + 1, |r| r.sequence),
                "last_sequence": records.last().map_or(assigned, |r| r.sequence),
                "closed": closed,
                "interrupted": false,
                "redaction": REDACTION,
                "redacted_env": redacted_env,
                "records": records.iter().map(|r| json!({
                    "sequence": r.sequence,
                    "at_ms": r.at_ms,
                    "stream": r.stream,
                    "bytes": STANDARD.encode(&r.bytes),
                })).collect::<Vec<_>>(),
            })
            .to_string(),
        );
        let mut delay = Duration::from_millis(500);
        loop {
            match send(body.clone()).await {
                Sent::Accepted => break,
                Sent::Refused(status) => {
                    let mut queue = shared.queue();
                    queue.refused = true;
                    queue.records.clear();
                    queue.bytes = 0;
                    summary.refused = Some(status);
                    return summary;
                }
                Sent::Retry => {
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(Duration::from_secs(5));
                }
            }
        }
        summary.delivered += records.len() as u64;
        if closed {
            summary.dropped = shared.queue().dropped;
            return summary;
        }
    }
}

/// The launcher's own messages, one log line each, until its pipe ends.
///
/// A guest decides how many there are (each system call the launcher does
/// not have is one), so they are bounded: the first [`DIAGNOSTICS_FIRST`]
/// bytes of them are logged as they come, and after that only the last
/// [`DIAGNOSTICS_LAST`] lines, when the pipe ends. The pipe is read to its
/// end either way: what the launcher says as it stops (an exit it did not
/// expect, a pointer outside the guest) is the last of it, and is never the
/// part that is lost.
pub async fn diagnostics(fd: OwnedFd) {
    let Ok(pipe) = Receiver::from_owned_fd(fd) else {
        return;
    };
    let (omitted, last) = diagnostics_from(pipe, |line| {
        tracing::info!(line, "launcher");
    })
    .await;
    if omitted > 0 {
        tracing::warn!(omitted, "launcher messages left out");
    }
    for line in last {
        tracing::info!(line = line.as_str(), "launcher");
    }
}
const DIAGNOSTICS_FIRST: usize = 64 * 1024;
const DIAGNOSTICS_LAST: usize = 16;
const DIAGNOSTICS_LINE: u64 = 4096;

/// Reads `pipe` to its end, giving `first` each of the first lines; returns
/// how many later lines were left out and the last ones, in order.
async fn diagnostics_from(
    pipe: impl tokio::io::AsyncRead + Unpin,
    mut first: impl FnMut(&str),
) -> (u64, Vec<String>) {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt};
    let mut reader = tokio::io::BufReader::new(pipe);
    let (mut taken, mut later) = (0usize, 0u64);
    let mut last = std::collections::VecDeque::with_capacity(DIAGNOSTICS_LAST);
    loop {
        // A line is read in pieces of at most DIAGNOSTICS_LINE: one without
        // an end is many short ones, never one that fills memory.
        let mut line = Vec::new();
        match (&mut reader)
            .take(DIAGNOSTICS_LINE)
            .read_until(b'\n', &mut line)
            .await
        {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let text = String::from_utf8_lossy(&line);
        let text = text.trim_end_matches('\n');
        if taken < DIAGNOSTICS_FIRST {
            taken += line.len();
            first(text);
        } else {
            later += 1;
            if last.len() == DIAGNOSTICS_LAST {
                last.pop_front();
            }
            last.push_back(text.to_owned());
        }
    }
    (later - last.len() as u64, last.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn matcher(values: &[&str]) -> Redactor {
        Redactor::new(values.iter().map(|v| v.as_bytes().to_vec()))
    }

    #[test]
    fn redaction_masks_values_across_every_split_binary_and_overlaps() {
        let input = b"before abcdef after \xff\xc3\xa9-token last";
        let expected = b"before [REDACTED] after \xff[REDACTED] last";
        for split in 0..=input.len() {
            let mut r = matcher(&["abc", "cdef", "é-token", ""]);
            let mut output = r.push(&input[..split]);
            output.extend(r.push(&input[split..]));
            output.extend(r.finish());
            assert_eq!(output, expected, "split {split}");
        }
        let mut r = matcher(&["ababa", "bab"]);
        let mut output = Vec::new();
        for byte in b"abababa!" {
            output.extend(r.push(&[*byte]));
        }
        output.extend(r.finish());
        assert_eq!(output, b"[REDACTED]!");
    }

    #[test]
    fn the_start_of_a_value_is_never_let_out_before_the_match_is_decided() {
        let mut r = matcher(&["sensitive-value"]);
        assert!(r.push(b"sensitive-").is_empty());
        let mut output = r.push(b"value");
        output.extend(r.finish());
        assert_eq!(output, b"[REDACTED]");
        let mut r = matcher(&[&"x".repeat(1024)]);
        let mut output = Vec::new();
        for _ in 0..4096 {
            output.extend(r.push(b"x"));
            assert!(r.pending.len() <= 1023);
            assert!(r.ranges.len() <= 1);
        }
        output.extend(r.finish());
        assert_eq!(output, b"[REDACTED]");
        assert_eq!(matcher(&[]).push(b"immediate"), b"immediate");
    }

    #[test]
    fn streaming_redaction_equals_masking_the_whole_input() {
        for patterns in [
            &["a"][..],
            &["aba", "bab"][..],
            &["a", "baaa"][..],
            &["aaab", "aab"][..],
            &["aaa", "aaaa"][..],
        ] {
            for bits in 0..1024 {
                let input: Vec<u8> = (0..10)
                    .map(|i| if bits & (1 << i) == 0 { b'a' } else { b'b' })
                    .collect();
                let mut mask = vec![false; input.len()];
                for pattern in patterns {
                    for start in 0..=input.len() - pattern.len() {
                        if &input[start..start + pattern.len()] == pattern.as_bytes() {
                            mask[start..start + pattern.len()].fill(true);
                        }
                    }
                }
                let mut expected = Vec::new();
                let mut previous = false;
                for (byte, masked) in input.iter().zip(mask) {
                    if masked {
                        if !previous {
                            expected.extend_from_slice(b"[REDACTED]");
                        }
                    } else {
                        expected.push(*byte);
                    }
                    previous = masked;
                }
                for chunk in [1, 3, 7, 10] {
                    let mut redactor = matcher(patterns);
                    let mut actual = Vec::new();
                    for bytes in input.chunks(chunk) {
                        actual.extend(redactor.push(bytes));
                    }
                    actual.extend(redactor.finish());
                    assert_eq!(actual, expected);
                }
            }
        }
    }

    #[test]
    fn records_are_cut_at_line_ends_and_never_exceed_the_bound() {
        let mut records: Vec<Vec<u8>> = Vec::new();
        let mut cutter = Cutter::default();
        cutter.push(b"one\ntwo\nthr", |r| records.push(r));
        assert_eq!(records, [b"one\ntwo\n".to_vec()]);
        cutter.push(b"ee\n", |r| records.push(r));
        assert_eq!(records[1], b"three\n");
        // A line longer than a record is cut at the bound; its end closes
        // the last piece.
        let long = [vec![b'x'; RECORD_BYTES * 2 + 10], b"\ntail".to_vec()].concat();
        cutter.push(&long, |r| records.push(r));
        assert_eq!(records[2].len(), RECORD_BYTES);
        assert_eq!(records[3].len(), RECORD_BYTES);
        assert_eq!(records[4], [vec![b'x'; 10], b"\n".to_vec()].concat());
        assert_eq!(records.len(), 5);
        cutter.flush(|r| records.push(r));
        assert_eq!(records[5], b"tail");
        assert!(records.iter().all(|r| r.len() <= RECORD_BYTES));
    }

    #[test]
    fn only_a_guest_configuration_with_output_asks_for_it() {
        assert!(!wanted(&json!({"mode":"command","env":{}})));
        assert!(wanted(&json!({"output":{"redact_env":[]}})));
        let (names, mut redactor) = redaction(&json!({
            "env": {"TOKEN": "hunter2", "PLAIN": "visible"},
            "output": {"redact_env": ["TOKEN"]},
        }));
        assert_eq!(names, ["TOKEN"]);
        let mut output = redactor.push(b"hunter2 visible");
        output.extend(redactor.finish());
        assert_eq!(output, b"[REDACTED] visible");
    }

    type Batches = Arc<Mutex<Vec<Value>>>;

    fn text(batches: &Batches, stream: &str) -> String {
        let mut out = Vec::new();
        for batch in batches.lock().unwrap().iter() {
            for record in batch["records"].as_array().unwrap() {
                if record["stream"] == stream {
                    out.extend(STANDARD.decode(record["bytes"].as_str().unwrap()).unwrap());
                }
            }
        }
        String::from_utf8(out).unwrap()
    }

    /// A sender that keeps every batch and accepts it.
    fn accepting(batches: Batches) -> impl Fn(Bytes) -> std::future::Ready<Sent> {
        move |body| {
            batches
                .lock()
                .unwrap()
                .push(serde_json::from_slice(&body).unwrap());
            std::future::ready(Sent::Accepted)
        }
    }

    #[tokio::test]
    async fn both_streams_are_delivered_masked_in_one_sequence_and_closed() {
        let (pipes, vm) = pipes().unwrap();
        let batches = Batches::default();
        let (names, redactor) = redaction(&json!({
            "env": {"TOKEN": "hunter2"}, "output": {"redact_env": ["TOKEN"]},
        }));
        let writer = std::thread::spawn(move || {
            let (mut out, mut err) = (
                std::fs::File::from(vm.stdout),
                std::fs::File::from(vm.stderr),
            );
            // The value arrives in two writes.
            out.write_all(b"token is hun").unwrap();
            out.flush().unwrap();
            std::thread::sleep(Duration::from_millis(20));
            out.write_all(b"ter2\nno line end").unwrap();
            err.write_all(b"failed: hunter2\n").unwrap();
        });
        let summary = capture(
            pipes.stdout,
            pipes.stderr,
            redactor,
            names,
            accepting(batches.clone()),
        )
        .await;
        writer.join().unwrap();
        assert_eq!(summary.refused, None);
        assert_eq!(summary.dropped, 0);
        assert_eq!(text(&batches, "stdout"), "token is [REDACTED]\nno line end");
        assert_eq!(text(&batches, "stderr"), "failed: [REDACTED]\n");
        let batches = batches.lock().unwrap();
        let mut expected = 1;
        for batch in batches.iter() {
            assert_eq!(batch["format_version"], 1);
            assert_eq!(batch["redaction"], REDACTION);
            assert_eq!(batch["redacted_env"], json!(["TOKEN"]));
            assert_eq!(batch["capture_id"], batches[0]["capture_id"]);
            assert_eq!(batch["capture_id"].as_str().unwrap().len(), 32);
            for record in batch["records"].as_array().unwrap() {
                assert_eq!(record["sequence"], expected);
                expected += 1;
            }
        }
        assert_eq!(summary.delivered, expected as u64 - 1);
        let last = batches.last().unwrap();
        assert_eq!(last["closed"], true);
        assert_eq!(last["last_sequence"], expected - 1);
        assert!(
            batches[..batches.len() - 1]
                .iter()
                .all(|b| b["closed"] == false)
        );
    }

    #[tokio::test]
    async fn a_run_that_prints_nothing_sends_one_empty_closing_batch() {
        let (pipes, vm) = pipes().unwrap();
        drop(vm);
        let batches = Batches::default();
        let summary = capture(
            pipes.stdout,
            pipes.stderr,
            matcher(&[]),
            vec![],
            accepting(batches.clone()),
        )
        .await;
        assert_eq!(summary, Summary::default());
        let batches = batches.lock().unwrap();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0]["first_sequence"], 1);
        assert_eq!(batches[0]["last_sequence"], 0);
        assert_eq!(batches[0]["closed"], true);
        assert_eq!(batches[0]["records"], json!([]));
    }

    #[tokio::test]
    async fn output_that_cannot_be_sent_is_bounded_and_shows_as_a_gap() {
        let (pipes, vm) = pipes().unwrap();
        let batches = Batches::default();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        // The endpoint fails until the guest has written everything: 1 MiB,
        // four times what may be held.
        let written = Arc::new(std::sync::atomic::AtomicBool::new(false));
        drop(vm.stderr);
        let writer = {
            let written = written.clone();
            std::thread::spawn(move || {
                let mut out = std::fs::File::from(vm.stdout);
                let line = [vec![b'x'; 1023], b"\n".to_vec()].concat();
                for _ in 0..1024 {
                    out.write_all(&line).unwrap();
                }
                written.store(true, std::sync::atomic::Ordering::SeqCst);
            })
        };
        let send = {
            let (batches, calls, written) = (batches.clone(), calls.clone(), written.clone());
            move |body: Bytes| {
                calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let accept = written.load(std::sync::atomic::Ordering::SeqCst);
                if accept {
                    batches
                        .lock()
                        .unwrap()
                        .push(serde_json::from_slice(&body).unwrap());
                }
                std::future::ready(if accept { Sent::Accepted } else { Sent::Retry })
            }
        };
        let summary = capture(pipes.stdout, pipes.stderr, matcher(&[]), vec![], send).await;
        // The guest wrote all of it although nothing was being accepted.
        writer.join().unwrap();
        assert!(summary.dropped > 0, "{summary:?}");
        let batches = batches.lock().unwrap();
        // What was delivered is the newest output, within the bound (and at
        // most one batch that was already taken to be sent); the sequence
        // jumps over what was dropped, and each batch begins at its first
        // record, which is how the gap is seen where it is stored.
        let records: Vec<&Value> = batches
            .iter()
            .flat_map(|b| b["records"].as_array().unwrap())
            .collect();
        let kept: usize = records
            .iter()
            .map(|r| STANDARD.decode(r["bytes"].as_str().unwrap()).unwrap().len())
            .sum();
        assert!(kept <= UNSENT_BYTES + BATCH_BYTES, "{kept}");
        assert!(kept > UNSENT_BYTES / 2, "{kept}");
        let sequences: Vec<i64> = records
            .iter()
            .map(|r| r["sequence"].as_i64().unwrap())
            .collect();
        assert!(sequences.windows(2).all(|pair| pair[1] > pair[0]));
        assert!(sequences[0] > 1 || sequences.windows(2).any(|pair| pair[1] > pair[0] + 1));
        for batch in batches.iter() {
            let records = batch["records"].as_array().unwrap();
            assert_eq!(batch["first_sequence"], records[0]["sequence"]);
            assert_eq!(
                batch["last_sequence"],
                records[records.len() - 1]["sequence"]
            );
            assert!(records.len() <= BATCH_RECORDS);
        }
        assert_eq!(batches.last().unwrap()["closed"], true);
        assert_eq!(
            summary.delivered + summary.dropped,
            *sequences.last().unwrap() as u64
        );
    }

    #[tokio::test]
    async fn an_endpoint_that_refuses_output_is_asked_once_and_the_guest_never_blocks() {
        let (pipes, vm) = pipes().unwrap();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let writer = std::thread::spawn(move || {
            let mut out = std::fs::File::from(vm.stdout);
            out.write_all(b"first\n").unwrap();
            std::thread::sleep(Duration::from_millis(400));
            // Far more than a pipe holds: it must still be read.
            out.write_all(&vec![b'y'; 512 * 1024]).unwrap();
        });
        let send = {
            let calls = calls.clone();
            move |_: Bytes| {
                calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                std::future::ready(Sent::Refused(404))
            }
        };
        let summary = capture(pipes.stdout, pipes.stderr, matcher(&[]), vec![], send).await;
        assert_eq!(summary.refused, Some(404));
        assert_eq!(summary.delivered, 0);
        tokio::task::spawn_blocking(move || writer.join().unwrap())
            .await
            .unwrap();
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_runs_end_waits_for_its_output_no_longer_than_the_closing_bound() {
        let (pipes, vm) = pipes().unwrap();
        std::fs::File::from(vm.stdout)
            .write_all(b"last words\n")
            .unwrap();
        drop(vm.stderr);
        let started = tokio::time::Instant::now();
        let never = |_: Bytes| std::future::ready(Sent::Retry);
        let waited = tokio::time::timeout(
            CLOSE_WAIT,
            capture(pipes.stdout, pipes.stderr, matcher(&[]), vec![], never),
        )
        .await;
        assert!(waited.is_err());
        assert_eq!(started.elapsed(), CLOSE_WAIT);
    }

    #[tokio::test]
    async fn the_launchers_last_words_are_kept_whatever_came_before() {
        let (mut write, read) = tokio::io::duplex(1 << 16);
        let writer = tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            for n in 0..100_000 {
                let line = format!("unsupported syscall {n}\n");
                write.write_all(line.as_bytes()).await.unwrap();
            }
            write
                .write_all(b"unexpected KVM exit 8 tid=1 rip=80006\n")
                .await
                .unwrap();
        });
        let mut first = Vec::new();
        let (omitted, last) = diagnostics_from(read, |line| first.push(line.to_owned())).await;
        writer.await.unwrap();
        assert_eq!(first[0], "unsupported syscall 0");
        assert!(first.iter().map(|l| l.len() + 1).sum::<usize>() < DIAGNOSTICS_FIRST + 64);
        assert_eq!(last.len(), DIAGNOSTICS_LAST);
        assert_eq!(
            last.last().unwrap(),
            "unexpected KVM exit 8 tid=1 rip=80006"
        );
        assert_eq!(first.len() as u64 + omitted + last.len() as u64, 100_001);
        // A line with no end is taken in bounded pieces.
        let endless = vec![b'x'; 3 * DIAGNOSTICS_LINE as usize];
        let mut pieces = Vec::new();
        diagnostics_from(&endless[..], |line| pieces.push(line.len())).await;
        assert_eq!(pieces, vec![DIAGNOSTICS_LINE as usize; 3]);
    }
}
