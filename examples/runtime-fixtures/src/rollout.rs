// Real recovery probe: HTTP uses the shared handler; only an explicit command
// checks current inputs and attempts the previously authorized destination.
include!("lib.rs");
fn main() {
    assert_eq!(std::env::var("CONFIG_REVISION").unwrap(), "current");
    let secret = std::env::var("RECOVERY_SECRET").unwrap();
    assert_eq!(secret, "rollout-current-fixture-secret");
    println!("FENDERS_RECOVERY_CURRENT_INPUTS");
    println!("secret-redaction-probe:{secret}");
    let request = OutgoingRequest::new(Fields::new());
    request.set_scheme(Some(&Scheme::Https)).unwrap();
    request.set_authority(Some("example.com")).unwrap();
    request.set_path_with_query(Some("/")).unwrap();
    let error = match wasi::http::outgoing_handler::handle(request, None) {
        Err(error) => error,
        Ok(future) => loop {
            future.subscribe().block();
            if let Some(result) = future.get() {
                break result
                    .unwrap()
                    .err()
                    .expect("rollback restored revoked HTTPS access");
            }
        },
    };
    assert!(matches!(error, ErrorCode::HttpRequestDenied), "{error:?}");
    println!("FENDERS_RECOVERY_REVOKED_HTTPS_DENIED");
}
