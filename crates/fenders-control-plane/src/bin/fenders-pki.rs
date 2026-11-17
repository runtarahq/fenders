use clap::Parser;
use std::{collections::BTreeMap, path::PathBuf};
#[derive(Parser)]
struct Args {
    #[arg(long)]
    output: PathBuf,
    #[arg(long, required = true)]
    identity: Vec<String>,
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1)
    }
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let mut names = BTreeMap::new();
    for identity in args.identity {
        let (name, hosts) = identity.split_once('=').ok_or("use name=host,IP")?;
        if names
            .insert(
                name.to_owned(),
                hosts.split(',').map(str::to_owned).collect(),
            )
            .is_some()
        {
            return Err("duplicate identity name".into());
        }
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&fenders_control_plane::pki::create(&args.output, &names)?)?
    );
    Ok(())
}
