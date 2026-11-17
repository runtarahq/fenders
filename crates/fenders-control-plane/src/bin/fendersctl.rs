use clap::{Parser, Subcommand};
use std::{io::Write, path::PathBuf};
#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "http://127.0.0.1:19091")]
    url: String,
    #[arg(long)]
    token_file: PathBuf,
    #[arg(long)]
    ca: Option<PathBuf>,
    #[command(subcommand)]
    command: Action,
}
#[derive(Subcommand)]
enum Action {
    Request {
        method: String,
        path: String,
        #[arg(long)]
        body_file: Option<PathBuf>,
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    Upload {
        tenant: String,
        project: String,
        wasm: PathBuf,
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
    let url = url::Url::parse(&args.url)?;
    if url.path() != "/"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("use a management origin URL".into());
    }
    if url.scheme() != "https"
        && !(url.scheme() == "http"
            && url.host_str().is_some_and(|h| {
                h == "localhost" || h.parse::<std::net::IpAddr>().is_ok_and(|i| i.is_loopback())
            }))
    {
        return Err("HTTPS is required outside loopback development".into());
    }
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(70));
    if let Some(ca) = args.ca {
        builder =
            builder.add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(ca)?)?);
    }
    let client = builder.build()?;
    let token = std::fs::read_to_string(args.token_file)?;
    let token = token.trim();
    if token.len() > 256 {
        return Err("invalid credential file".into());
    }
    let (method, path, body, key) = match args.command {
        Action::Request {
            method,
            path,
            body_file,
            idempotency_key,
        } => (
            method,
            path,
            body_file
                .map(std::fs::read)
                .transpose()?
                .unwrap_or_default(),
            idempotency_key,
        ),
        Action::Upload {
            tenant,
            project,
            wasm,
        } => {
            fenders_control_plane::model::identity(&tenant)?;
            fenders_control_plane::model::identity(&project)?;
            (
                "POST".to_owned(),
                format!("/v1/tenants/{tenant}/projects/{project}/artifacts"),
                std::fs::read(wasm)?,
                None,
            )
        }
    };
    if !path.starts_with('/') || path.starts_with("//") || path.contains(['\r', '\n']) {
        return Err("invalid API path".into());
    }
    if body.len() > 16 * 1024 * 1024 {
        return Err("request body exceeds 16 MiB".into());
    }
    let mut request = client
        .request(
            reqwest::Method::from_bytes(method.as_bytes())?,
            format!("{}{path}", args.url.trim_end_matches('/')),
        )
        .bearer_auth(token)
        .header("Content-Type", "application/json")
        .body(body);
    if let Some(key) = key {
        request = request.header("Idempotency-Key", key);
    }
    // Errors deliberately omit reqwest's URL to avoid logging sensitive query strings.
    let mut response = request
        .send()
        .await
        .map_err(|_| "management request failed")?;
    let status = response.status();
    let mut data = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "invalid management response")?
    {
        if chunk.len() > 32 * 1024 * 1024 - data.len() {
            return Err("response too large".into());
        }
        data.extend_from_slice(&chunk);
    }
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&data) {
        println!("{}", serde_json::to_string_pretty(&value)?)
    } else {
        std::io::stdout().write_all(&data)?;
    }
    if !status.is_success() {
        return Err(format!("API returned {status}").into());
    }
    Ok(())
}
