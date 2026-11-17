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
    let args = Args::parse();
    let result = match args.command {
        Action::Generate { output } => {
            key_rotation::generate(&output)?;
            serde_json::json!({"key_file":output})
        }
        Action::Rotate {
            state,
            new_key_file,
            services_stopped,
        } => {
            let dsn =
                std::env::var(args.dsn_env).map_err(|_| "database environment variable missing")?;
            // Map driver errors to the platform's redacted error type.
            let pool = sqlx::PgPool::connect(&dsn)
                .await
                .map_err(fenders_control_plane::error::Error::from)?;
            key_rotation::rotate(&pool, &state, &new_key_file, services_stopped).await?
        }
    };
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}
