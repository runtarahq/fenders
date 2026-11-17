// Acceptance probe: demonstrate current secret delivery without embedding or
// printing the credential. The expected digest is public configuration.
use sha2::{Digest, Sha256};

fn main() {
    let credential = std::env::var("ACCESS_CREDENTIAL").unwrap_or_default();
    let expected = std::env::var("EXPECTED_CREDENTIAL_SHA256").unwrap_or_default();
    let actual = format!("{:x}", Sha256::digest(credential.as_bytes()));
    if credential.is_empty() || actual != expected {
        eprintln!("CREDENTIAL_MISMATCH");
        std::process::exit(1);
    }
    let revision = std::env::var("CREDENTIAL_REVISION").unwrap_or_default();
    if !matches!(revision.as_str(), "first" | "replacement") {
        eprintln!("CREDENTIAL_REVISION_INVALID");
        std::process::exit(1);
    }
    println!(
        "CREDENTIAL_OK revision={revision} code={}",
        option_env!("FENDERS_CREDENTIAL_PROBE_CODE").unwrap_or("1")
    );
}
