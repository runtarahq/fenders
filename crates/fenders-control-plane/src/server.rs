//! The `fenders-control-plane` program, as a function a wrapping binary can call.
use crate::{
    api,
    store::Store,
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
    let mut store = Store::connect(&dsn, &args.state).await?;
    if let Some(endpoint) = &args.run_channel_endpoint {
        let tls = tls
            .as_ref()
            .ok_or("--run-channel-endpoint requires TLS (--ca, --cert, --key)")?;
        store = store.with_run_channel(crate::run_channel::RunChannel::new(
            endpoint,
            std::fs::read_to_string(&tls.ca)?,
            args.run_channel_server_name.clone(),
        )?);
    }
    if let Some(path) = args.external_network {
        store = store.with_external_network(
            crate::external_endpoints::ExternalNetworkPolicy::read(&path)?,
        );
    }
    if let Some(config) = public_egress {
        store = store.with_public_egress(config)?;
    }
    store.migrate().await?;
    let credential = store.bootstrap().await?;
    let listener = tokio::net::TcpListener::bind((args.host, args.port)).await?;
    eprintln!(
        "Fenders Rust management API: {}://{}; credential file: {}",
        if args.dev_http { "http" } else { "https" },
        listener.local_addr()?,
        credential.display()
    );
    let mut background = Background::new(store.background_monitor());
    let delay = std::time::Duration::from_secs(1);
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
        let internal_listener =
            tokio::net::TcpListener::bind((args.host, args.internal_port)).await?;
        let gateway_listener =
            tokio::net::TcpListener::bind((args.host, args.gateway_port)).await?;
        let (shutdown, _) = tokio::sync::watch::channel(false);
        let mut servers = tokio::task::JoinSet::new();
        let listeners = vec![
            (listener, management.clone(), api::management(state.clone())),
            (internal_listener, internal, api::internal(store.clone())),
        ];
        // The gateway and the run channel carry bodies that last as long as
        // a response may: HTTP/2 as well, and no connection lifetime.
        let mut streaming = vec![(gateway_listener, gateway, api::gateway(state))];
        if args.run_channel_endpoint.is_some() {
            // The management configuration: this certificate, no client one.
            streaming.push((
                tokio::net::TcpListener::bind((args.host, args.run_channel_port)).await?,
                management,
                crate::run_channel::router(store.clone()),
            ));
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
        // Drain all three listeners together. An idle listener finishing must
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
        if let Err(error) = store.close_gateway().await {
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
