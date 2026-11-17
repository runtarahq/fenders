//! The node's metrics in Prometheus' text exposition format, served on a
//! loopback address when the node is given `--metrics-listen` (the endpoint
//! is unauthenticated, so it is never served on another).
//!
//! Counters (since the agent started):
//! - `fenders_node_runs_total{start}`: runs started, `start` `cold` (a
//!   shim started for the run) or `warm` (a warm shim claimed for it);
//! - `fenders_node_admissions_total`: assignments admitted to start a run;
//! - `fenders_node_refusals_total{reason}`: assignments refused a run, by
//!   reason (`maintenance`, `unsupported`, `local-capacity`,
//!   `node-capacity`, `local-storage`, `artifact-rejected`);
//! - `fenders_node_retention_removed_total{what}`: what the retention sweep
//!   removed (`run_directory`, `assignment`), see [`crate::retention`].
//!
//! Gauges (read as they are scraped):
//! - `fenders_node_run_directories`: run directories on disk, the run
//!   cgroups under the cgroup root and run directories a node before shims
//!   left in its state, until the retention sweep removes them;
//! - `fenders_node_runs`: runs not yet ended; `fenders_node_run_capacity`:
//!   the most the node runs at once; `fenders_node_warm_shims`: warm shims
//!   waiting for a run.
//!
//! Histogram:
//! - `fenders_node_run_start_seconds{start}`: from the node starting a run
//!   to its shim running it (its VMM started; for a warm shim, booted
//!   before the run, from its claim).
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

/// The upper bounds of `fenders_node_run_start_seconds`' buckets.
const START_BUCKETS: [f64; 12] = [
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0,
];

struct Histogram {
    buckets: [AtomicU64; START_BUCKETS.len()],
    count: AtomicU64,
    /// The sum in microseconds.
    sum_micros: AtomicU64,
}

impl Histogram {
    const fn new() -> Self {
        Self {
            buckets: [const { AtomicU64::new(0) }; START_BUCKETS.len()],
            count: AtomicU64::new(0),
            sum_micros: AtomicU64::new(0),
        }
    }
    fn observe(&self, seconds: f64) {
        let seconds = seconds.max(0.0);
        for (bucket, bound) in self.buckets.iter().zip(START_BUCKETS) {
            if seconds <= bound {
                bucket.fetch_add(1, Ordering::Relaxed);
            }
        }
        self.count.fetch_add(1, Ordering::Relaxed);
        self.sum_micros
            .fetch_add((seconds * 1e6) as u64, Ordering::Relaxed);
    }
    fn render(&self, out: &mut String, name: &str, labels: &str) {
        for (bucket, bound) in self.buckets.iter().zip(START_BUCKETS) {
            let _ = writeln!(
                out,
                "{name}_bucket{{{labels},le=\"{bound}\"}} {}",
                bucket.load(Ordering::Relaxed)
            );
        }
        let count = self.count.load(Ordering::Relaxed);
        let _ = writeln!(out, "{name}_bucket{{{labels},le=\"+Inf\"}} {count}");
        let _ = writeln!(
            out,
            "{name}_sum{{{labels}}} {}",
            self.sum_micros.load(Ordering::Relaxed) as f64 / 1e6
        );
        let _ = writeln!(out, "{name}_count{{{labels}}} {count}");
    }
}

/// The process's counters and histograms.
struct Counters {
    cold_runs: AtomicU64,
    warm_runs: AtomicU64,
    admissions: AtomicU64,
    refusals: Mutex<BTreeMap<&'static str, u64>>,
    removed_run_directories: AtomicU64,
    removed_assignments: AtomicU64,
    cold_start: Histogram,
    warm_start: Histogram,
}

static COUNTERS: Counters = Counters {
    cold_runs: AtomicU64::new(0),
    warm_runs: AtomicU64::new(0),
    admissions: AtomicU64::new(0),
    refusals: Mutex::new(BTreeMap::new()),
    removed_run_directories: AtomicU64::new(0),
    removed_assignments: AtomicU64::new(0),
    cold_start: Histogram::new(),
    warm_start: Histogram::new(),
};

/// A run started, by a warm shim or a cold one.
pub fn run_started(warm: bool) {
    if warm {
        &COUNTERS.warm_runs
    } else {
        &COUNTERS.cold_runs
    }
    .fetch_add(1, Ordering::Relaxed);
}

/// How long a run took from its start to its shim running it.
pub fn run_start_seconds(warm: bool, seconds: f64) {
    if warm {
        &COUNTERS.warm_start
    } else {
        &COUNTERS.cold_start
    }
    .observe(seconds);
}

/// An assignment admitted to start a run.
pub fn admitted() {
    COUNTERS.admissions.fetch_add(1, Ordering::Relaxed);
}

/// An assignment refused a run, for `reason`.
pub fn refused(reason: &'static str) {
    if let Ok(mut refusals) = COUNTERS.refusals.lock() {
        *refusals.entry(reason).or_default() += 1;
    }
}

/// What a retention sweep removed.
pub fn retention_removed(run_directories: u64, assignments: u64) {
    COUNTERS
        .removed_run_directories
        .fetch_add(run_directories, Ordering::Relaxed);
    COUNTERS
        .removed_assignments
        .fetch_add(assignments, Ordering::Relaxed);
}

/// The node's gauges, read as they are scraped.
#[derive(Clone, Copy, Debug, Default)]
pub struct Gauges {
    pub run_directories: u64,
    pub runs: u64,
    pub run_capacity: u64,
    pub warm_shims: u64,
}

fn family(out: &mut String, name: &str, kind: &str, help: &str) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} {kind}");
}

/// The exposition of every metric, with `gauges`.
pub fn render(gauges: Gauges) -> String {
    let mut out = String::new();
    let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
    family(
        &mut out,
        "fenders_node_runs_total",
        "counter",
        "Runs started.",
    );
    let _ = writeln!(
        out,
        "fenders_node_runs_total{{start=\"cold\"}} {}",
        load(&COUNTERS.cold_runs)
    );
    let _ = writeln!(
        out,
        "fenders_node_runs_total{{start=\"warm\"}} {}",
        load(&COUNTERS.warm_runs)
    );
    family(
        &mut out,
        "fenders_node_admissions_total",
        "counter",
        "Assignments admitted to start a run.",
    );
    let _ = writeln!(
        out,
        "fenders_node_admissions_total {}",
        load(&COUNTERS.admissions)
    );
    family(
        &mut out,
        "fenders_node_refusals_total",
        "counter",
        "Assignments refused a run, by reason.",
    );
    if let Ok(refusals) = COUNTERS.refusals.lock() {
        for (reason, count) in refusals.iter() {
            let _ = writeln!(
                out,
                "fenders_node_refusals_total{{reason=\"{reason}\"}} {count}"
            );
        }
    }
    family(
        &mut out,
        "fenders_node_retention_removed_total",
        "counter",
        "Finished runs' leftovers the retention sweep removed.",
    );
    let _ = writeln!(
        out,
        "fenders_node_retention_removed_total{{what=\"run_directory\"}} {}",
        load(&COUNTERS.removed_run_directories)
    );
    let _ = writeln!(
        out,
        "fenders_node_retention_removed_total{{what=\"assignment\"}} {}",
        load(&COUNTERS.removed_assignments)
    );
    family(
        &mut out,
        "fenders_node_run_start_seconds",
        "histogram",
        "Seconds from the node starting a run to its shim running it.",
    );
    COUNTERS
        .cold_start
        .render(&mut out, "fenders_node_run_start_seconds", "start=\"cold\"");
    COUNTERS
        .warm_start
        .render(&mut out, "fenders_node_run_start_seconds", "start=\"warm\"");
    for (name, help, value) in [
        (
            "fenders_node_run_directories",
            "Run directories on disk: run cgroups and runs left by a node before shims.",
            gauges.run_directories,
        ),
        ("fenders_node_runs", "Runs not yet ended.", gauges.runs),
        (
            "fenders_node_run_capacity",
            "The most runs the node runs at once.",
            gauges.run_capacity,
        ),
        (
            "fenders_node_warm_shims",
            "Warm shims waiting for a run.",
            gauges.warm_shims,
        ),
    ] {
        family(&mut out, name, "gauge", help);
        let _ = writeln!(out, "{name} {value}");
    }
    out
}

/// Serves the exposition at `/metrics` on `listener`, with the gauges
/// `gauges` reads, until the task is dropped.
pub async fn serve<F>(listener: tokio::net::TcpListener, gauges: F) -> std::io::Result<()>
where
    F: Fn() -> Gauges + Send + Sync + 'static,
{
    use axum::{http::header::CONTENT_TYPE, routing::get};
    let gauges = std::sync::Arc::new(gauges);
    let router = axum::Router::new().route(
        "/metrics",
        get(move || {
            let gauges = gauges.clone();
            async move {
                let body = tokio::task::spawn_blocking(move || render(gauges()))
                    .await
                    .unwrap_or_default();
                ([(CONTENT_TYPE, "text/plain; version=0.0.4")], body)
            }
        }),
    );
    axum::serve(listener, router).await
}

/// The address `--metrics-listen` names, which must be a loopback one.
pub fn listen_address(text: &str) -> Result<std::net::SocketAddr, String> {
    let address: std::net::SocketAddr = text
        .parse()
        .map_err(|_| format!("{text} is not an address and port"))?;
    if !address.ip().is_loopback() {
        return Err(format!(
            "{text} is not a loopback address: the metrics endpoint is unauthenticated"
        ));
    }
    Ok(address)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_exposition_names_each_metric_once_with_its_type() {
        run_started(false);
        admitted();
        refused("local-capacity");
        run_start_seconds(false, 0.3);
        let text = render(Gauges {
            run_directories: 7,
            runs: 2,
            run_capacity: 16,
            warm_shims: 1,
        });
        for name in [
            "fenders_node_runs_total",
            "fenders_node_admissions_total",
            "fenders_node_refusals_total",
            "fenders_node_run_start_seconds",
            "fenders_node_run_directories",
            "fenders_node_runs",
        ] {
            assert_eq!(
                text.matches(&format!("# TYPE {name} ")).count(),
                1,
                "{name}"
            );
        }
        assert!(text.contains("fenders_node_run_directories 7\n"));
        assert!(text.contains("fenders_node_refusals_total{reason=\"local-capacity\"} "));
        // 0.3 s is in the 0.5 s bucket and those above, not the 0.25 s one.
        let bucket = |le: &str| {
            text.lines()
                .find(|line| {
                    line.starts_with(&format!(
                        "fenders_node_run_start_seconds_bucket{{start=\"cold\",le=\"{le}\"}}"
                    ))
                })
                .and_then(|line| line.rsplit(' ').next())
                .and_then(|n| n.parse::<u64>().ok())
                .unwrap()
        };
        assert_eq!(bucket("0.5") - bucket("0.25"), 1);
        assert_eq!(bucket("+Inf"), bucket("30"));
        // Every sample line is a name, optional labels and a number.
        for line in text.lines().filter(|line| !line.starts_with('#')) {
            let (_, value) = line.rsplit_once(' ').unwrap();
            assert!(value.parse::<f64>().is_ok(), "{line}");
        }
    }

    #[tokio::test]
    async fn the_endpoint_serves_the_exposition_at_metrics() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(serve(listener, || Gauges {
            run_directories: 3,
            ..Gauges::default()
        }));
        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        stream
            .write_all(b"GET /metrics HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        server.abort();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.contains("text/plain; version=0.0.4"));
        assert!(response.contains("\nfenders_node_run_directories 3\n"));
    }

    #[test]
    fn the_endpoint_listens_only_on_loopback() {
        assert!(listen_address("127.0.0.1:9464").is_ok());
        assert!(listen_address("[::1]:9464").is_ok());
        assert!(listen_address("0.0.0.0:9464").is_err());
        assert!(listen_address("10.0.0.5:9464").is_err());
        assert!(listen_address("localhost").is_err());
    }
}
