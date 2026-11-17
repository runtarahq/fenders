// The same component exports the HTTP handler and WASI CLI run entry point.
// Including the shared handler keeps the HTTP assertions identical across fixtures.
include!("lib.rs");
fn main() {
    let hold_ms: u64 = std::env::var("COMMAND_HOLD_MS")
        .unwrap_or_else(|_| "0".into())
        .parse()
        .expect("invalid fixture hold duration");
    assert!(hold_ms <= 90_000, "fixture hold exceeds 90 seconds");
    if hold_ms > 0 {
        println!("FENDERS_DUAL_COMMAND_HOLD_STARTED");
        wasi::clocks::monotonic_clock::subscribe_duration(hold_ms * 1_000_000).block();
    }
    // A command of an app that accepts WebSocket connections can send to
    // them: with WS_BROADCAST, its text goes to every open connection.
    if let Ok(text) = std::env::var("WS_BROADCAST") {
        println!("broadcast to {}", broadcast(&text));
    }
    println!("FENDERS_DUAL_COMMAND_COMPLETE");
}
