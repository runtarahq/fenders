use clap::{Parser, Subcommand};
use fenders_control_plane::key_rotation;
use std::path::PathBuf;

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "FENDERS_DATABASE_URL")]
    dsn_env: String,
    #[command(subcommand)]
    command: Action,
}
#[derive(Subcommand)]
enum Action {
    Generate {
        #[arg(long)]
        output: PathBuf,
    },
    /// Writes what an edge is given of the control plane's encryption key:
    /// the run channel's derived key and which key it is from, not the key.
    Edge {
        /// The control plane's state directory, which holds the key.
        #[arg(long)]
        state: PathBuf,
        /// The file to write: the edge's `STATE/edge.key`.
        #[arg(long)]
        output: PathBuf,
    },
    Rotate {
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        new_key_file: PathBuf,
        #[arg(long)]
        services_stopped: bool,
    },
}
#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
async fn run() -> Result<(), Box<dyn std::error::Error>> {
    // Everything these tools write is a key or holds one.
    unsafe {
        libc::umask(0o077);
    }
    let args = Args::parse();
    let result = match args.command {
        Action::Generate { output } => {
            key_rotation::generate(&output)?;
            serde_json::json!({"key_file":output})
        }
        Action::Edge { state, output } => {
            fenders_control_plane::store::write_edge_key(&state, &output)?
        }
        Action::Rotate {
            state,
            new_key_file,
            services_stopped,
        } => {
            let dsn =
                std::env::var(args.dsn_env).map_err(|_| "database environment variable missing")?;
            // Map driver errors to the platform's redacted error type.
            fenders_control_plane::db::database_url(&dsn)?;
            let pool = sqlx::PgPool::connect(&dsn)
                .await
                .map_err(fenders_control_plane::error::Error::from)?;
            key_rotation::rotate(&pool, &state, &new_key_file, services_stopped).await?
        }
    };
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}
