use clap::{Parser, Subcommand};
use fenders_control_plane::backup;
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
    Key {
        #[arg(long)]
        output: PathBuf,
    },
    Create {
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        key_file: PathBuf,
        #[arg(long,default_value_t=backup::DEFAULT_LIMIT)]
        limit_bytes: u64,
    },
    Restore {
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        backup: PathBuf,
        #[arg(long)]
        key_file: PathBuf,
        #[arg(long,default_value_t=backup::DEFAULT_LIMIT)]
        limit_bytes: u64,
    },
    Activate {
        #[arg(long)]
        external_resources_fenced: bool,
    },
}
#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("{error}");
        std::process::exit(1)
    }
}
async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    if let Action::Key { output } = args.command {
        backup::random_key(&output)?;
        println!("{}", serde_json::json!({"key_file":output,"bytes":32}));
        return Ok(());
    }
    let dsn = std::env::var(args.dsn_env).map_err(|_| "database environment variable missing")?;
    let result = match args.command {
        Action::Create {
            state,
            output,
            key_file,
            limit_bytes,
        } => backup::create(&dsn, &state, &output, &key_file, limit_bytes).await?,
        Action::Restore {
            state,
            backup,
            key_file,
            limit_bytes,
        } => backup::restore(&dsn, &state, &backup, &key_file, limit_bytes).await?,
        Action::Activate {
            external_resources_fenced,
        } => backup::activate(&dsn, external_resources_fenced).await?,
        Action::Key { .. } => unreachable!(),
    };
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}
