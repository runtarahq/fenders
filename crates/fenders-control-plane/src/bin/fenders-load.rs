//! A load generator for the gateway: so many clients, each on a connection
//! of its own, asking the given URLs in turn for so many seconds. Prints
//! what was answered and how fast, as JSON.
//!
//! For measuring a local environment (`scripts/measure_gateway.sh`), not for
//! anything that faces a network: with `--insecure` it verifies no
//! certificate, as the local gateway's is not one for an app's host name.
use clap::Parser;
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    time::{Duration, Instant},
};

#[derive(Parser)]
#[command(about = "Load the gateway and say what it answered")]
struct Args {
    /// The URLs asked, in turn by each client.
    #[arg(required = true)]
    urls: Vec<String>,
    /// Where every URL's host is, whatever its name resolves to.
    #[arg(long)]
    connect: Option<SocketAddr>,
    #[arg(long)]
    insecure: bool,
    #[arg(long, default_value_t = 16)]
    clients: usize,
    #[arg(long, default_value_t = 10)]
    seconds: u64,
    /// POST a body of this many bytes instead of a GET.
    #[arg(long)]
    post_bytes: Option<usize>,
}

#[derive(Default)]
struct Seen {
    statuses: BTreeMap<String, u64>,
    micros: Vec<u64>,
    received: u64,
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let urls: Vec<reqwest::Url> = args
        .urls
        .iter()
        .map(|url| url.parse())
        .collect::<Result<_, _>>()?;
    let body = args.post_bytes.map(|bytes| vec![b'x'; bytes]);
    let deadline = Instant::now() + Duration::from_secs(args.seconds);
    let started = Instant::now();
    let mut clients = tokio::task::JoinSet::new();
    for client in 0..args.clients.max(1) {
        let mut builder = reqwest::Client::builder()
            .danger_accept_invalid_certs(args.insecure)
            .timeout(Duration::from_secs(120));
        if let Some(address) = args.connect {
            for url in &urls {
                builder = builder.resolve(url.host_str().unwrap_or_default(), address);
            }
        }
        let http = builder.build()?;
        let (urls, body) = (urls.clone(), body.clone());
        clients.spawn(async move {
            let mut seen = Seen::default();
            let mut turn = client;
            while Instant::now() < deadline {
                let url = urls[turn % urls.len()].clone();
                turn += 1;
                let request = match &body {
                    Some(body) => http.post(url).body(body.clone()),
                    None => http.get(url),
                };
                let asked = Instant::now();
                let answered = match request.send().await {
                    Ok(response) => {
                        let status = response.status().as_u16().to_string();
                        match response.bytes().await {
                            Ok(bytes) => {
                                seen.received += bytes.len() as u64;
                                status
                            }
                            Err(_) => "cut".to_owned(),
                        }
                    }
                    Err(_) => "error".to_owned(),
                };
                seen.micros.push(asked.elapsed().as_micros() as u64);
                *seen.statuses.entry(answered).or_default() += 1;
            }
            seen
        });
    }
    let mut all = Seen::default();
    while let Some(seen) = clients.join_next().await {
        let seen = seen?;
        for (status, count) in seen.statuses {
            *all.statuses.entry(status).or_default() += count;
        }
        all.micros.extend(seen.micros);
        all.received += seen.received;
    }
    let elapsed = started.elapsed().as_secs_f64();
    all.micros.sort_unstable();
    let at = |part: f64| {
        let index = ((all.micros.len() as f64 * part) as usize).min(all.micros.len().max(1) - 1);
        all.micros.get(index).copied().unwrap_or(0) as f64 / 1000.0
    };
    let requests = all.micros.len() as f64;
    println!(
        "{}",
        serde_json::json!({
            "clients": args.clients,
            "seconds": (elapsed * 100.0).round() / 100.0,
            "requests": all.micros.len(),
            "requests_a_second": (requests / elapsed).round(),
            "received_bytes": all.received,
            "statuses": all.statuses,
            "latency_ms": {"median": at(0.5), "p99": at(0.99), "longest": at(1.0)},
        })
    );
    Ok(())
}
