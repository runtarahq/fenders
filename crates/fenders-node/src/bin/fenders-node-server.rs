use clap::Parser;
use fenders_node::core::{Node, private_dir};
use std::{path::PathBuf, sync::Arc};
#[derive(Parser)]
#[command(about = "Standalone loopback node API; Linux KVM required")]
struct Args {
    #[arg(long)]
    state: PathBuf,
    #[arg(long)]
    build: PathBuf,
    #[arg(long)]
    cgroup_root: PathBuf,
    #[arg(long, default_value_t = 9080)]
    port: u16,
    #[arg(long, default_value_t = 16)]
    max_instances: usize,
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
}
fn main() {
    if let Err(e) = entry() {
        eprintln!("{e}");
        std::process::exit(1)
    }
}
fn entry() -> Result<(), Box<dyn std::error::Error>> {
    unsafe {
        libc::umask(0o077);
    }
    #[cfg(target_os = "linux")]
    if let Some(result) = fenders_node::worker::dispatch(&std::env::args().collect::<Vec<_>>()) {
        return result.map_err(Into::into);
    }
    let args = Args::parse();
    // Text unless FENDERS_LOG_FORMAT=json; levels from RUST_LOG.
    fenders_node::log::init(fenders_node::log::Format::from_env());
    if !(1..=256).contains(&args.max_instances) {
        return Err("invalid max instances".into());
    }
    private_dir(&args.state)?;
    let node = Arc::new(
        Node::new(
            &args.state,
            &args.build,
            &args.cgroup_root,
            args.max_instances,
        )?
        .with_compiler_limits(fenders_node::core::CompilerLimits {
            memory_mib: args.compiler_memory_mib,
            cpu_percent: args.compiler_cpu_percent,
            cpu_seconds: args.compiler_cpu_seconds,
            wall_seconds: args.compiler_wall_seconds,
        })?
        .with_max_upload_mib(args.max_upload_mib)?,
    );
    let token_file = args.state.join("token");
    if !token_file.exists() {
        fenders_node_protocol::pki::private_file(
            &token_file,
            format!(
                "{}{}",
                fenders_node_protocol::model::uid(),
                fenders_node_protocol::model::uid()
            )
            .as_bytes(),
        )?;
    }
    let token = std::fs::read_to_string(&token_file)?;
    if token.trim().len() < 32 {
        return Err("invalid token file".into());
    }
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()?
        .block_on(async move {
            let worker = node.clone();
            let task = tokio::spawn(async move {
                loop {
                    if worker.reconcile().is_err() {
                        tracing::warn!("node reconciliation failed");
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            });
            let listener =
                tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, args.port)).await?;
            tracing::info!(
                "Fenders node: http://{}; token file: {}",
                listener.local_addr()?,
                token_file.display()
            );
            let result = axum::serve(
                listener,
                fenders_node::standalone::router(node, token.trim()),
            )
            .with_graceful_shutdown(async {
                let _ = tokio::signal::ctrl_c().await;
            })
            .await;
            task.abort();
            result
        })?;
    Ok(())
}
