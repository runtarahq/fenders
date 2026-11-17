//! Independently deployed private management process. No customer routers,
//! browser login, scheduler, node enrollment or worker dispatch runs here.
use clap::Parser;
use fenders_control_plane::{operator_api, store::Store, supervision::shutdown_signal, transport};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "fenders-operator-bridge", version = option_env!("FENDERS_BUILD_ID").unwrap_or(env!("CARGO_PKG_VERSION")))]
struct Args {
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    database_url_file: PathBuf,
    #[arg(long)]
    state: PathBuf,
    /// Apply only the compatible private-operator schema changes, then exit.
    #[arg(long)]
    migrate: bool,
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
    let config: operator_api::Config = serde_json::from_slice(&std::fs::read(args.config)?)?;
    // The bridge attaches to an initialized authoritative platform. It never
    // bootstraps a workspace, initializes the platform schema or generates a key.
    if !args.state.join("encryption.key").is_file() {
        return Err("operator bridge requires initialized platform state".into());
    }
    let dsn = std::fs::read_to_string(args.database_url_file)?;
    let store = Store::connect(dsn.trim(), &args.state).await?;
    let initialized: bool = sqlx::query_scalar("SELECT to_regclass('platform_format') IS NOT NULL")
        .fetch_one(&store.pool)
        .await?;
    if !initialized {
        return Err("operator bridge requires an initialized platform database".into());
    }
    if args.migrate {
        store.migrate_operator().await?;
        return Ok(());
    }
    let router =
        operator_api::router_with_controls(store, config.service_pin, config.workspace_controls)?;
    let tls = transport::server_config(&config.cert_file, &config.key_file, Some(&config.ca_file))?;
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    eprintln!(
        "Private operator bridge listening on {}",
        listener.local_addr()?
    );
    tokio::select! {
        result=transport::serve_tls(listener,tls,router)=>result?,
        result=shutdown_signal()=>result?,
    }
    Ok(())
}
