//! The `fenders-control-plane` program, as a function a wrapping binary can call.
use crate::{
    api,
    store::{Serves, Store},
    supervision::{Background, Component, shutdown_signal},
    transport,
};
use clap::Parser;
use std::{net::IpAddr, path::PathBuf};

#[derive(Parser)]
#[command(name = "fenders-control-plane", version = option_env!("FENDERS_BUILD_ID").unwrap_or(env!("CARGO_PKG_VERSION")))]
#[command(about = "Fenders Rust control plane")]
struct Args {
    #[arg(long, default_value = "run/platform-rust")]
    state: PathBuf,
    /// Read the database URL from a credential file instead of the environment.
    #[arg(long)]
    database_url_file: Option<PathBuf>,
    #[arg(long, default_value_t = 19091)]
    port: u16,
    #[arg(long, default_value = "127.0.0.1")]
    host: IpAddr,
    #[arg(long)]
    dev_http: bool,
    #[arg(long, default_value_t = 9091)]
    internal_port: u16,
    #[arg(long, default_value_t = 9092)]
    gateway_port: u16,
    /// Where runs' shims call the control plane (the run channel). Served
    /// with --cert and --key, without client certificates.
    #[arg(long, default_value_t = 9093)]
    run_channel_port: u16,
    /// The run channel as nodes reach it, `https://host[:port]`. Without it
    /// no assignment names a run channel and no shim node starts a run.
    #[arg(long)]
    run_channel_endpoint: Option<String>,
    /// The name --cert is for, when it is not the endpoint's host.
    #[arg(long, requires = "run_channel_endpoint")]
    run_channel_server_name: Option<String>,
    #[arg(long, default_value = "apps.fenders.local")]
    domain: String,
    #[arg(long)]
    ca: Option<PathBuf>,
    #[arg(long)]
    cert: Option<PathBuf>,
    #[arg(long)]
    key: Option<PathBuf>,
    #[arg(long)]
    gateway_cert: Option<PathBuf>,
    #[arg(long)]
    gateway_key: Option<PathBuf>,
    /// Operator DNS-over-TLS and denied management range configuration.
    #[arg(long)]
    public_egress: Option<PathBuf>,
    /// Operator-approved IPv4 ranges for customer-owned external databases.
    #[arg(long)]
    external_network: Option<PathBuf>,
    /// The edges' gateway, `https://host[:port]`, as a control process
    /// reaches it to send an app the sample requests the API is asked for.
    #[arg(long)]
    gateway_endpoint: Option<String>,
    /// The CA the edges' gateway certificate leads to, when not --ca.
    #[arg(long)]
    gateway_ca: Option<PathBuf>,
    /// The registered edge this process serves as (an edge's name, as
    /// `POST /v1/edges` registered it): it then serves the apps it owns and
    /// passes others' requests to their owners. Without it an edge owns
    /// every app.
    #[arg(long)]
    edge_name: Option<String>,
    /// Where a named edge takes what other edges pass it, over mutual TLS
    /// with --cert and --key: the port its registered endpoint names.
    #[arg(long, default_value_t = 9096)]
    forward_port: u16,
    /// How long the gateway and the run channel serve what they know while
    /// the database cannot be reached, in seconds.
    #[arg(long, default_value_t = 600)]
    serve_stale_seconds: u64,
    /// Connections to the database this process holds at most. Four of
    /// them may wait for the mutation lock at once; the others are for the
    /// reads requests make.
    #[arg(long, default_value_t = crate::store::CONNECTIONS, value_parser = clap::value_parser!(u32).range(8..=512))]
    database_connections: u32,
    /// What this process serves: everything (`all`), the management API,
    /// the scheduler and the nodes' peer (`control`), or the gateway and
    /// the run channel (`edge`, with `--state` holding what `fenders-keys
    /// edge` wrote).
    #[arg(long, value_enum, default_value = "all")]
    role: Role,
    /// Resolve and validate an origin, then exit without serving or assigning work.
    #[arg(long)]
    check_public_egress: Vec<String>,
}
/// The control plane's whole program: parse the command line, serve until a
/// signal.
pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let public_egress = args
        .public_egress
        .as_deref()
        .map(crate::public_egress::PublicEgressConfig::read)
        .transpose()?;
    if !args.check_public_egress.is_empty() {
        let resolver = crate::public_egress::PublicEgress::new(
            public_egress.ok_or("--check-public-egress requires --public-egress")?,
        )?;
        let resolved = resolver.resolve(&args.check_public_egress).await?;
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "public_targets": resolved.launch_policy()?,
                "remaining_ttl_ms": resolved.remaining_ttl().as_millis(),
                "policy_digest": resolved.policy_digest(),
                "grants_access": false
            }))?
        );
        return Ok(());
    }
    if args.dev_http && !args.host.is_loopback() {
        return Err("development HTTP requires a loopback address".into());
    }
    if !args.domain.contains('.')
        || args.domain.contains("..")
        || !args
            .domain
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b".-".contains(&b))
    {
        return Err("invalid application domain".into());
    }
    crate::app_http::hostname(&"0".repeat(32), &args.domain)?;
    let tls = if args.dev_http {
        None
    } else {
        Some(api::PeerCredentials {
            ca: args.ca.ok_or("--ca is required")?,
            cert: args.cert.ok_or("--cert is required")?,
            key: args.key.ok_or("--key is required")?,
        })
    };
    let dsn = database_url(args.database_url_file.as_deref())?;
    let role = args.role;
    let serves = |part: Part| part.served_by(role);
    let mut store = if role == Role::Edge {
        if tls.is_none() {
            return Err("an edge serves over TLS: --ca, --cert and --key are required".into());
        }
        Store::connect_edge_with(&dsn, &args.state, args.database_connections).await?
    } else {
        Store::connect_with(&dsn, &args.state, args.database_connections)
            .await?
            .serving(if role == Role::Control {
                Serves::Control
            } else {
                Serves::All
            })
    };
    store = store.with_outage_bound(std::time::Duration::from_secs(args.serve_stale_seconds));
    if let Some(endpoint) = &args.run_channel_endpoint {
        let tls = tls
            .as_ref()
            .ok_or("--run-channel-endpoint requires TLS (--ca, --cert, --key)")?;
        store = store.with_run_channel(crate::run_channel::RunChannel::new(
            endpoint,
            std::fs::read_to_string(&tls.ca)?,
            args.run_channel_server_name.clone(),
        )?);
    } else if role == Role::Control {
        return Err(
            "a control process names the edges' run channel: --run-channel-endpoint".into(),
        );
    }
    if role == Role::Control {
        let endpoint = args.gateway_endpoint.as_deref().ok_or(
            "a control process sends sample requests to the edges' gateway: --gateway-endpoint",
        )?;
        let ca = args
            .gateway_ca
            .clone()
            .or_else(|| tls.as_ref().map(|tls| tls.ca.clone()))
            .ok_or("--gateway-ca or --ca is required")?;
        store = store.with_edge_gateway(endpoint, &std::fs::read(ca)?)?;
    }
    if let Some(path) = args.external_network {
        store = store.with_external_network(
            crate::external_endpoints::ExternalNetworkPolicy::read(&path)?,
        );
    }
    if let Some(config) = public_egress {
        store = store.with_public_egress(config)?;
    }
    // A control process migrates the schema; an edge only checks that it is
    // the one it was built for, and is started after.
    let credential = if role == Role::Edge {
        store.check_schema().await?;
        if let Some(name) = &args.edge_name {
            let edge = store.edge_named(name).await?;
            let tls = tls.as_ref().ok_or("an edge serves over TLS")?;
            store = store
                .as_edge(edge)
                .with_forwarder(crate::forward::Forwarder::new(
                    &tls.ca, &tls.cert, &tls.key,
                )?);
        }
        None
    } else {
        store.migrate().await?;
        Some(store.bootstrap().await?)
    };
    let listener = tokio::net::TcpListener::bind((args.host, args.port)).await?;
    match &credential {
        Some(credential) => eprintln!(
            "Fenders Rust management API: {}://{}; credential file: {}",
            if args.dev_http { "http" } else { "https" },
            listener.local_addr()?,
            credential.display()
        ),
        None => eprintln!(
            "Fenders edge: probes and status on https://{}, gateway on {}, run channel on {}",
            listener.local_addr()?,
            args.gateway_port,
            args.run_channel_port
        ),
    }
    let mut background = Background::new(store.background_monitor());
    let delay = std::time::Duration::from_secs(1);
    if serves(Part::Scheduler) {
        let scheduler = store.clone();
        // Work to place wakes the scheduler at commit; the interval still sweeps.
        background.periodic_woken(
            Component::Scheduler,
            delay,
            delay,
            Some(store.pickup()),
            move || {
                let scheduler = scheduler.clone();
                async move { scheduler.schedule().await }
            },
        )?;
        let pickup = store.clone();
        background.periodic(
            Component::PickupListener,
            std::time::Duration::ZERO,
            delay,
            move || {
                let pickup = pickup.clone();
                async move { pickup.listen_for_pickup().await }
            },
        )?;
    }
    if serves(Part::Gateway) {
        // What other processes change is heard, and what the gateway and
        // the run channel know of it read again.
        let listener = store.clone();
        background.periodic(
            Component::GateListener,
            std::time::Duration::ZERO,
            delay,
            move || {
                let listener = listener.clone();
                async move { listener.listen_for_gates().await }
            },
        )?;
        // What the gateway holds in memory is written once a second.
        let flusher = store.clone();
        background.periodic(
            Component::GatewayFlusher,
            crate::gateway::FLUSH_EVERY,
            crate::gateway::FLUSH_EVERY,
            move || {
                let flusher = flusher.clone();
                async move { flusher.flush_gateway().await }
            },
        )?;
    }
    if role == Role::Edge {
        // The scheduler sweeps WebSocket connections where it holds them; an
        // edge holds them without a scheduler.
        let sweeper = store.clone();
        background.periodic(Component::WebSocketSweep, delay, delay, move || {
            let sweeper = sweeper.clone();
            async move { sweeper.websocket_sweep().await }
        })?;
    }
    let state = api::ApiState {
        store: store.clone(),
        domain: args.domain,
        tls: tls.clone(),
    };
    if let Some(tls) = tls {
        let management = transport::server_config(&tls.cert, &tls.key, None)?;
        let internal = transport::server_config(&tls.cert, &tls.key, Some(&tls.ca))?;
        let gateway = transport::server_config(
            args.gateway_cert.as_deref().unwrap_or(&tls.cert),
            args.gateway_key.as_deref().unwrap_or(&tls.key),
            None,
        )?;
        let (shutdown, _) = tokio::sync::watch::channel(false);
        let mut servers = tokio::task::JoinSet::new();
        let mut listeners = vec![(
            listener,
            management.clone(),
            if role == Role::Edge {
                api::edge(store.clone())
            } else {
                api::management(state.clone())
            },
        )];
        if serves(Part::NodePeer) {
            listeners.push((
                tokio::net::TcpListener::bind((args.host, args.internal_port)).await?,
                internal,
                api::internal(store.clone()),
            ));
        }
        // The gateway and the run channel carry bodies that last as long as
        // a response may: HTTP/2 as well, and no connection lifetime.
        let mut streaming = Vec::new();
        if serves(Part::Gateway) {
            streaming.push((
                tokio::net::TcpListener::bind((args.host, args.gateway_port)).await?,
                gateway,
                api::gateway(state.clone()),
            ));
            if role == Role::Edge && args.edge_name.is_some() {
                // Other edges pass this one requests of the apps it owns,
                // showing the certificates they were registered with.
                streaming.push((
                    tokio::net::TcpListener::bind((args.host, args.forward_port)).await?,
                    transport::server_config(&tls.cert, &tls.key, Some(&tls.ca))?,
                    crate::forward::router(state.clone()),
                ));
            }
            if role == Role::Edge || args.run_channel_endpoint.is_some() {
                // The management configuration: this certificate, no client one.
                streaming.push((
                    tokio::net::TcpListener::bind((args.host, args.run_channel_port)).await?,
                    management,
                    crate::run_channel::router(store.clone()),
                ));
            }
        }
        for (listener, config, router) in listeners {
            let mut stopping = shutdown.subscribe();
            servers.spawn(transport::serve_tls_until(
                listener,
                config,
                router,
                async move {
                    let _ = stopping.wait_for(|value| *value).await;
                },
            ));
        }
        for (listener, config, router) in streaming {
            let mut stopping = shutdown.subscribe();
            servers.spawn(crate::stream_listener::serve(
                listener,
                config,
                router,
                async move {
                    let _ = stopping.wait_for(|value| *value).await;
                },
            ));
        }
        let mut result: Result<(), Box<dyn std::error::Error>> = tokio::select! {
            result=shutdown_signal()=>result.map_err(Into::into),
            error=background.failure()=>Err(error.into()),
            finished=servers.join_next()=>match finished {
                Some(Ok(Err(error)))=>Err(error.into()),
                Some(Err(error))=>Err(error.into()),
                _=>Err("TLS listener unexpectedly exited".into()),
            },
        };
        shutdown.send_replace(true);
        // Drain every listener together. An idle listener finishing must
        // not cancel requests on another; background work stays alive until
        // the existing bounded connection deadlines finish.
        while let Some(finished) = servers.join_next().await {
            match finished {
                Ok(Ok(())) => {}
                Ok(Err(error)) if result.is_ok() => result = Err(error.into()),
                Err(error) if result.is_ok() => result = Err(error.into()),
                _ => {}
            }
        }
        // The listeners have drained: what their last requests left in
        // memory is written before the process ends.
        if serves(Part::Gateway)
            && let Err(error) = store.close_gateway().await
        {
            eprintln!("the gateway's last flush failed: {}", error.message);
        }
        result?;
    } else {
        tokio::select! {
            result=axum::serve(listener, api::management(state))
                .with_graceful_shutdown(async { let _ = shutdown_signal().await; })=>result?,
            error=background.failure()=>return Err(error.into()),
        }
    }
    drop(background);
    Ok(())
}

/// What a process serves, by `--role`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum Role {
    /// Everything, in one process.
    All,
    /// The management API, the scheduler and the nodes' peer.
    Control,
    /// The gateway and the run channel.
    Edge,
}

/// The parts of the control plane a role serves.
#[derive(Clone, Copy)]
enum Part {
    Scheduler,
    NodePeer,
    Gateway,
}

impl Part {
    fn served_by(self, role: Role) -> bool {
        matches!(
            (self, role),
            (_, Role::All)
                | (Self::Scheduler | Self::NodePeer, Role::Control)
                | (Self::Gateway, Role::Edge)
        )
    }
}

fn database_url(path: Option<&std::path::Path>) -> Result<String, &'static str> {
    use std::io::Read;
    let Some(path) = path else {
        return std::env::var("FENDERS_DATABASE_URL")
            .map_err(|_| "set FENDERS_DATABASE_URL or --database-url-file");
    };
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .and_then(|file| file.take(8193).read_to_end(&mut bytes))
        .map_err(|_| "cannot read database URL credential file")?;
    if bytes.len() > 8192 {
        return Err("database URL credential file exceeds 8192 bytes");
    }
    let value = std::str::from_utf8(&bytes)
        .map_err(|_| "database URL credential file is not UTF-8")?
        .trim();
    if value.is_empty() || value.contains('\0') {
        return Err("database URL credential file is empty or contains NUL");
    }
    Ok(value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn database_credential_is_bounded_and_fails_closed() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("database-url");
        assert_eq!(
            database_url(Some(&path)),
            Err("cannot read database URL credential file")
        );
        for input in [&b"\n  "[..], &b"postgresql://secret\0"[..]] {
            std::fs::write(&path, input).unwrap();
            assert!(database_url(Some(&path)).is_err());
        }
        std::fs::write(&path, [255]).unwrap();
        assert_eq!(
            database_url(Some(&path)),
            Err("database URL credential file is not UTF-8")
        );
        std::fs::write(&path, vec![b'x'; 8193]).unwrap();
        assert_eq!(
            database_url(Some(&path)),
            Err("database URL credential file exceeds 8192 bytes")
        );
        std::fs::write(&path, "postgresql://user:secret@localhost/fenders\n").unwrap();
        assert_eq!(
            database_url(Some(&path)).unwrap(),
            "postgresql://user:secret@localhost/fenders"
        );
        std::fs::write(&path, vec![b'x'; 8192]).unwrap();
        assert_eq!(database_url(Some(&path)).unwrap().len(), 8192);
    }
}
