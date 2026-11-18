#[tokio::main]
async fn main() {
    if let Err(error) = fenders_control_plane::server::run().await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
