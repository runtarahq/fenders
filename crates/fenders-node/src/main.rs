use axum::{
    Json, Router,
    body::to_bytes,
    extract::{Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use clap::Parser;
use fenders_node::{agent::Agent, core::Node};
use fenders_node_protocol::{
    error::{Error, Result},
    transport::{Client, PeerIdentity, serve_tls_until, server_config},
};
use serde_json::Value;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
#[derive(Parser)]
#[command(name = "fenders-node", version = option_env!("FENDERS_BUILD_ID").unwrap_or(env!("CARGO_PKG_VERSION")))]
struct Args {
    #[arg(long)]
    state: PathBuf,
    #[arg(long)]
    build: PathBuf,
    #[arg(long)]
    cgroup_root: PathBuf,
    #[arg(long, default_value_t = 16)]
    max_instances: usize,
    /// The first of the uids runs are given, one each. None may be an
    /// account's or in a subordinate uid range on this host, and two nodes
    /// on one host need different bases.
    #[arg(long, default_value_t = 600_000)]
    run_uid_base: u32,
    /// Warm shims (VM booted, component loaded, each for one run) kept per
    /// artifact and guest configuration a run used.
    #[arg(long, default_value_t = 0)]
    warm_runs: usize,
    /// Serve the outbound byte limit: take runs whose launch asks for it
    /// (their shims send only what the run channel grants) and tell the
    /// control peer so in the heartbeat. Without it such runs are refused
    /// and the heartbeat is unchanged.
    #[arg(long)]
    egress_budget: bool,
    /// Free filesystem headroom for journals and existing work, before admission.
    #[arg(long, default_value_t = 256)]
    disk_free_mib: u64,
    /// Confined compiler cgroup memory ceiling.
    #[arg(long, default_value_t = 1024)]
    compiler_memory_mib: u64,
    /// Confined compiler CPU ceiling, in percent of one CPU.
    #[arg(long, default_value_t = 100)]
    compiler_cpu_percent: u64,
    /// Confined compiler CPU time ceiling.
    #[arg(long, default_value_t = 45)]
    compiler_cpu_seconds: u64,
    /// Confined compiler wall-clock ceiling.
    #[arg(long, default_value_t = 60)]
    compiler_wall_seconds: u64,
    /// Largest component the node accepts, up to 128 MiB.
    #[arg(long, default_value_t = 16)]
    max_upload_mib: u64,
    /// Compiled code the node keeps, 64 MiB to 1 TiB.
    #[arg(long, default_value_t = 512)]
    artifact_cache_mib: u64,
    /// What the per-function compile cache keeps across a tenant's compiles,
    /// 64 MiB to 1 TiB, or 0 to compile uncached.
    #[arg(long, default_value_t = 1024)]
    compile_cache_mib: u64,
    /// Require an already provisioned Linux project quota for the whole state tree.
    #[arg(long, requires_all = ["state_quota_mib", "state_quota_inodes"])]
    state_project_id: Option<u32>,
    /// Maximum acceptable enforced hard byte limit; does not change host quotas.
    #[arg(long, requires_all = ["state_project_id", "state_quota_inodes"])]
    state_quota_mib: Option<u64>,
    #[arg(long, requires_all = ["state_project_id", "state_quota_mib"])]
    state_quota_inodes: Option<u64>,
    #[arg(long)]
    control: String,
    #[arg(long)]
    control_pin: String,
    #[arg(long)]
    ca: PathBuf,
    #[arg(long)]
    cert: PathBuf,
    #[arg(long)]
    key: PathBuf,
    #[arg(long, default_value = "127.0.0.1")]
    host: String,
    #[arg(long, default_value_t = 9443)]
    port: u16,
    /// Adopt one RPC listener supplied by the hosting supervisor (systemd uses fd 3).
    #[arg(long, value_parser=clap::value_parser!(i32).range(3..))]
    listen_fd: Option<i32>,
    #[arg(long)]
    cpu_percent: i64,
    #[arg(long)]
    memory_mib: i64,
    /// Renew the node's certificate through its control peer when it is due
    /// (a peer that signs node certificates, such as runtara-cloud's fleet);
    /// the renewed file is presented with nothing restarted.
    #[arg(long)]
    renew_certificate: bool,
    /// How log lines on standard error are written: `text` (level, target,
    /// message and fields) or `json` (one object per line). Levels come from
    /// RUST_LOG (`info` when unset). Shims log in the same format.
    #[arg(long, env = fenders_node::log::FORMAT_VARIABLE, value_enum, default_value_t)]
    log_format: fenders_node::log::Format,
    /// Serve Prometheus metrics at http://ADDRESS/metrics, a loopback
    /// address and port such as 127.0.0.1:9464. Off when not given.
    #[arg(long, value_parser = fenders_node::metrics::listen_address)]
    metrics_listen: Option<std::net::SocketAddr>,
    /// Remove what finished runs a node before shims left (run directories,
    /// archived assignments) once they were last written this long ago.
    #[arg(long, default_value_t = 3600)]
    retention_min_age_seconds: u64,
    /// The most of each the retention sweep removes a minute; 0 turns it off.
    #[arg(long, default_value_t = 1000)]
    retention_batch: usize,
}
fn main() {
    if let Err(error) = entry() {
        if fenders_node::log::installed() {
            tracing::error!(status = error.status.as_u16(), error = %error.message, "fenders-node failed");
        } else {
            eprintln!("{error}");
        }
        std::process::exit(1)
    }
}
fn entry() -> Result<()> {
    unsafe {
        libc::umask(0o077);
    }
    let args: Vec<String> = std::env::args().collect();
    if let Some(result) = fenders_node::release::dispatch(&args) {
        return result;
    }
    if let Some(result) = fenders_node::upgrade::dispatch(&args) {
        return result;
    }
    if let Some(result) = fenders_node::staging::dispatch(&args) {
        return result;
    }
    if let Some(result) = fenders_node::service::dispatch(&args) {
        return result;
    }
    #[cfg(target_os = "linux")]
    match args.get(1).map(String::as_str) {
        Some("confinement-probe") => {
            println!("{}", fenders_node::confinement::probe()?);
            return Ok(());
        }
        Some("compile-worker") => return fenders_node::worker::compile(&args[2..]),
        _ => (),
    }
    let _ = (&args, Path::new(""));
    let args = Args::parse();
    fenders_node::log::init(args.log_format);
    let inherited_listener = fenders_node::activation::descriptor(args.listen_fd)?
        .map(|fd| {
            // Fresh exec: no Rust wrapper owns the inherited descriptor, and no
            // node/runtime threads have started. Adoption consumes this fd once.
            unsafe { fenders_node::activation::take_listener(fd, &args.host, args.port) }
        })
        .transpose()?;
    if !(1..=256).contains(&args.max_instances) || args.cpu_percent < 1 || args.memory_mib < 88 {
        return Err(Error::invalid("invalid node capacity"));
    }
    // Validate TLS and take exclusive, candidate-bound ownership before Node
    // initializes journals or reconciles any preserved execution.
    let client = Client::new(
        &args.control,
        &args.ca,
        &args.cert,
        &args.key,
        &args.control_pin,
    )?;
    let config = server_config(&args.cert, &args.key, Some(&args.ca))?;
    let boot = fenders_node::core::boot_id()?;
    let maintenance = Agent::claim(&args.state.join("agent"), &boot)?;
    let quota = args
        .state_project_id
        .map(|project| {
            fenders_node::project_quota::drop_quota_bypass()?;
            let bytes = args
                .state_quota_mib
                .unwrap()
                .checked_mul(1024 * 1024)
                .ok_or_else(|| Error::invalid("state quota byte ceiling overflow"))?;
            fenders_node::project_quota::ProjectQuota::open(
                &args.state,
                project,
                bytes,
                args.state_quota_inodes.unwrap(),
            )
        })
        .transpose()?;
    let mut node = Node::new(
        &args.state.join("node"),
        &args.build,
        &args.cgroup_root,
        args.max_instances,
    )?
    .with_disk_free_mib(args.disk_free_mib)?
    .with_run_uids(args.run_uid_base)?
    .with_warm_runs(args.warm_runs)?
    .with_egress_budget(args.egress_budget)
    .with_compiler_limits(fenders_node::core::CompilerLimits {
        memory_mib: args.compiler_memory_mib,
        cpu_percent: args.compiler_cpu_percent,
        cpu_seconds: args.compiler_cpu_seconds,
        wall_seconds: args.compiler_wall_seconds,
    })?
    .with_max_upload_mib(args.max_upload_mib)?
    .with_artifact_cache_mib(args.artifact_cache_mib)?
    .with_compile_cache_mib(args.compile_cache_mib)?;
    if let Some(quota) = quota {
        node = node.with_state_quota(quota)?;
    }
    let node = Arc::new(node);
    let metrics = args
        .metrics_listen
        .map(|address| -> Result<_> {
            let listener = std::net::TcpListener::bind(address)?;
            listener.set_nonblocking(true)?;
            Ok((listener, node.clone()))
        })
        .transpose()?;
    let retention = fenders_node::retention::Policy {
        min_age: std::time::Duration::from_secs(args.retention_min_age_seconds),
        batch: args.retention_batch,
    };
    let node_state = node.state.clone();
    let renewal = args
        .renew_certificate
        .then(|| (client.clone(), args.cert.clone(), args.key.clone()));
    let agent = Agent::from_claim(
        node,
        client,
        &args.state.join("agent"),
        args.cpu_percent,
        args.memory_mib,
        boot,
        maintenance,
    )?;
    let agent = Arc::new(agent);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()?;
    let result = runtime.block_on(async move {
        let worker = agent.clone();
        let reconcile = tokio::spawn(async move {
            loop {
                if let Err(error) = worker.step().await {
                    tracing::warn!(
                        status = error.status.as_u16(),
                        error = %error.message,
                        "agent reconciliation failed"
                    );
                }
                // A changed assignment ends the wait early.
                let _ = tokio::time::timeout(
                    std::time::Duration::from_secs(1),
                    worker.woken().notified(),
                )
                .await;
            }
        });
        let worker = agent.clone();
        // Reconciliation heartbeats, but not while it compiles a component.
        let keepalive = tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                let _ = worker.keepalive(std::time::Duration::from_secs(3)).await;
            }
        });
        let worker = agent.clone();
        let assignments = tokio::spawn(async move { worker.watch_assignments().await });
        let worker = agent.clone();
        // A run's end is reported as it happens, freeing its capacity.
        let _endings = tokio::spawn(async move { worker.watch_endings().await });
        let renewal = renewal.map(|(peer, cert, key)| {
            tokio::spawn(fenders_node::renewal::keep_renewed(peer, cert, key))
        });
        let worker = agent.clone();
        let prewarm = tokio::spawn(async move { worker.prewarm().await });
        let worker = agent.clone();
        let inspection = tokio::spawn(async move {
            loop {
                if let Err(error) = worker.inspect_component().await {
                    tracing::warn!(
                        status = error.status.as_u16(),
                        error = %error.message,
                        "component inspection reconciliation failed"
                    );
                }
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        });
        let metrics = metrics
            .map(|(listener, node)| -> Result<_> {
                let listener = tokio::net::TcpListener::from_std(listener)?;
                tracing::info!(address = %args.metrics_listen.unwrap(), "serving metrics");
                Ok(tokio::spawn(async move {
                    if let Err(error) =
                        fenders_node::metrics::serve(listener, move || node.gauges()).await
                    {
                        tracing::error!(%error, "the metrics endpoint stopped");
                    }
                }))
            })
            .transpose()?;
        let worker = agent.clone();
        let retention = tokio::spawn(async move {
            if retention.batch == 0 {
                return;
            }
            loop {
                let (agent, state) = (worker.clone(), node_state.clone());
                let swept =
                    tokio::task::spawn_blocking(move || sweep(&agent, &state, retention)).await;
                if let Ok(Err(error)) = swept {
                    tracing::warn!(error = %error.message, "retention sweep failed");
                }
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            }
        });
        let router = Router::new()
            .fallback(rpc)
            .with_state((agent, args.control_pin));
        let listener = match inherited_listener {
            Some(listener) => tokio::net::TcpListener::from_std(listener)?,
            None => tokio::net::TcpListener::bind((args.host.as_str(), args.port)).await?,
        };
        let result = serve_tls_until(listener, config, router, shutdown_signal()).await;
        reconcile.abort();
        keepalive.abort();
        if let Some(renewal) = renewal {
            renewal.abort();
        }
        assignments.abort();
        prewarm.abort();
        inspection.abort();
        retention.abort();
        if let Some(metrics) = metrics {
            metrics.abort();
        }
        result
    });
    // This daemon exits immediately after entry returns. Do not wait for an
    // interrupted compiler's blocking task after renewals have stopped: the
    // compiler has parent-death fencing, and inspection/launch journals remain
    // authoritative on adoption, just as after the previous default SIGTERM.
    runtime.shutdown_background();
    result
}
/// One retention pass ([`fenders_node::retention`]).
fn sweep(agent: &Agent, node_state: &Path, policy: fenders_node::retention::Policy) -> Result<()> {
    let kept = agent.retained_runs()?;
    let runs = fenders_node::retention::sweep_runs(
        node_state,
        &kept,
        policy,
        std::time::SystemTime::now(),
    )?;
    let assignments = agent.delete_archived(policy.batch)?;
    fenders_node::metrics::retention_removed(runs as u64, assignments as u64);
    if runs + assignments > 0 {
        tracing::info!(
            run_directories = runs,
            assignments,
            "removed finished runs' leftovers"
        );
    }
    Ok(())
}
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("install node termination handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = terminate.recv() => {},
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}
async fn rpc(State((agent, pin)): State<(Arc<Agent>, String)>, req: Request) -> Result<Response> {
    let (parts, body) = req.into_parts();
    if parts
        .extensions
        .get::<PeerIdentity>()
        .and_then(|p| p.0.as_deref())
        != Some(pin.as_str())
    {
        return Err(Error::new(
            StatusCode::FORBIDDEN,
            "control-plane identity required",
        ));
    }
    if parts.method != "POST" {
        return Err(Error::missing());
    }
    let body = to_bytes(body, 2 * 1024 * 1024)
        .await
        .map_err(|_| Error::new(StatusCode::PAYLOAD_TOO_LARGE, "request too large"))?;
    let value: Value = serde_json::from_slice(&body).map_err(|_| Error::invalid("invalid JSON"))?;
    match parts.uri.path() {
        "/rpc/maintenance/status" => Ok(Json(agent.maintenance.status()?).into_response()),
        "/rpc/maintenance/prepare" => {
            Ok(Json(agent.maintenance.prepare(&value).await?).into_response())
        }
        "/rpc/maintenance/resume" => {
            Ok(Json(agent.maintenance.resume(&value).await?).into_response())
        }
        _ => Err(Error::missing()),
    }
}

#[cfg(test)]
mod quota_args_tests {
    use super::*;
    fn arguments() -> Vec<&'static str> {
        vec![
            "fenders-node",
            "--state",
            "/state",
            "--build",
            "/build",
            "--cgroup-root",
            "/cg",
            "--control",
            "https://control",
            "--control-pin",
            "pin",
            "--ca",
            "ca",
            "--cert",
            "cert",
            "--key",
            "key",
            "--cpu-percent",
            "100",
            "--memory-mib",
            "128",
        ]
    }
    #[test]
    fn quota_flags_require_all_three_and_legacy_invocation_stays_explicitly_unqualified() {
        assert!(
            Args::try_parse_from(arguments())
                .unwrap()
                .state_project_id
                .is_none()
        );
        for pair in [
            ["--state-project-id", "123"],
            ["--state-quota-mib", "4096"],
            ["--state-quota-inodes", "100000"],
        ] {
            let mut args = arguments();
            args.extend(pair);
            assert!(Args::try_parse_from(args).is_err());
        }
        let mut args = arguments();
        args.extend([
            "--state-project-id",
            "123",
            "--state-quota-mib",
            "4096",
            "--state-quota-inodes",
            "100000",
        ]);
        let parsed = Args::try_parse_from(args).unwrap();
        assert_eq!(parsed.state_project_id, Some(123));
        assert_eq!(parsed.state_quota_mib, Some(4096));
        assert_eq!(parsed.state_quota_inodes, Some(100000));
    }
}
