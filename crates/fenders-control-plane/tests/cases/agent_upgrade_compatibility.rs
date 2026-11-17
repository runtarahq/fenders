//! Refuse a real pre-contract agent while the source still serves its VMs.
use super::*;

pub(super) async fn refuse_legacy(
    tool: &Path,
    legacy: &Path,
    build: &Path,
    store: &Path,
    output: &Path,
    client: &transport::Client,
    backends: &[&Path],
) -> Value {
    let status = client
        .json("POST", "/rpc/maintenance/status", Some(&json!({})))
        .await
        .unwrap();
    assert_eq!(
        status["mode"], "open",
        "refusal must precede source sealing"
    );
    let before: Vec<_> = backends
        .iter()
        .map(|b| {
            (
                ownership(b),
                limits::kernel(b),
                fs::read(b.join("config.json")).unwrap(),
            )
        })
        .collect();
    let (source, pin) = incoming(legacy, build, output, "legacy-management").await;
    let manifest = json_file(&source.join("worker-release.json"));
    assert!(
        manifest.get("management_protocol").is_none(),
        "input is not a pre-contract release"
    );
    let refused = stage_release(
        tool,
        &source,
        store,
        &pin,
        output,
        "stage-rejected-legacy-management",
    )
    .await;
    assert_eq!(refused["success"], false);
    assert!(!store.join(&pin).exists(), "legacy candidate was published");
    assert_eq!(
        client
            .json("POST", "/rpc/maintenance/status", Some(&json!({})))
            .await
            .unwrap(),
        status
    );
    for (backend, (identity, kernel, config)) in backends.iter().zip(before) {
        assert_eq!(ownership(backend), identity);
        assert_eq!(limits::kernel(backend), kernel);
        assert_eq!(fs::read(backend.join("config.json")).unwrap(), config);
    }
    json!({"candidate":manifest,"manifest_sha256":pin,"refusal":refused,
        "source_management":status,"source_not_sealed":true,
        "original_identities_configuration_and_kernel_controls_unchanged":true,
        "candidate_not_published":true})
}
