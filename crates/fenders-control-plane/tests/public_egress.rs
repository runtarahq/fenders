//! Real DNS-over-TLS exchanges against a local recursive-resolver fixture.
use axum::http::StatusCode;
use fenders_control_plane::public_egress::{PublicEgress, PublicEgressConfig};
use std::time::{Duration, Instant};
#[path = "common/dns.rs"]
mod dns;
use dns::DnsLab;
async fn resolve(
    resolver: &PublicEgress,
    name: &str,
) -> fenders_control_plane::error::Result<fenders_control_plane::public_egress::ResolvedTargets> {
    resolver.resolve(&[format!("https://{name}")]).await
}

#[tokio::test]
async fn authenticated_absolute_a_queries_preserve_cname_ttls_and_original_origin() {
    let lab = DnsLab::new().await;
    let resolver = lab.resolver();
    let result = resolve(&resolver, "API.TEST:8443").await.unwrap();
    assert_eq!(
        result.launch_policy().unwrap(),
        "https://api.test:8443=1.1.1.1"
    );
    assert_eq!(result.policy_digest(), resolver.policy_digest());
    assert!(result.remaining_ttl() <= Duration::from_secs(60));
    for host in ["alias.test", "chain.test"] {
        let result = resolve(&resolver, host).await.unwrap();
        assert_eq!(
            result.launch_policy().unwrap(),
            format!("https://{host}:443=1.1.1.1")
        );
        assert!(result.remaining_ttl() <= Duration::from_secs(2));
    }
    assert!(
        lab.queries
            .lock()
            .await
            .iter()
            .any(|(name, _)| name == "target.test.")
    );
    let capped = resolve(&resolver, "cap.test").await.unwrap();
    assert!(capped.remaining_ttl() <= Duration::from_secs(300));
}

#[tokio::test]
async fn mixed_private_management_metadata_and_excessive_answers_never_make_partial_grants() {
    let lab = DnsLab::new().await;
    let resolver = lab.resolver();
    for host in [
        "mixed.test",
        "metadata.test",
        "managed.test",
        "evil-alias.test",
        "many.test",
    ] {
        let error = resolve(&resolver, host).await.err().unwrap();
        assert_eq!(error.status, StatusCode::FORBIDDEN, "{host}");
    }
    assert!(
        resolver
            .resolve(&["https://api.test".into(), "https://mixed.test".into()])
            .await
            .is_err()
    );
    assert!(resolve(&resolver, "rebinding.test").await.is_ok());
    assert!(resolve(&resolver, "rebinding.test").await.is_err());
    assert_eq!(
        lab.queries
            .lock()
            .await
            .iter()
            .filter(|(n, _)| n == "rebinding.test.")
            .count(),
        2
    );
}

#[tokio::test]
async fn zero_expired_and_missing_answers_fail_closed_without_ttl_inflation() {
    let lab = DnsLab::new().await;
    let resolver = lab.resolver();
    for name in ["zero.test", "empty.test", "nxdomain.test"] {
        assert!(resolve(&resolver, name).await.is_err(), "{name}");
    }
    let result = resolve(&resolver, "ttl.test").await.unwrap();
    assert!(result.remaining_ttl() <= Duration::from_secs(1));
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert!(result.remaining_ttl().is_zero());
    assert!(result.launch_policy().is_err());
}

#[tokio::test]
async fn resolver_tls_name_and_ca_are_verified_without_plaintext_fallback() {
    let lab = DnsLab::new().await;
    let other = DnsLab::new().await;
    for change in [0, 1, 2] {
        let mut config = lab.config.clone();
        match change {
            0 => config.dns_server_name = "wrong.test".into(),
            1 => config.dns_ca_pem = other.config.dns_ca_pem.clone(),
            _ => config.dns_ca_pem = None,
        };
        assert!(
            resolve(&PublicEgress::new(config).unwrap(), "api.test")
                .await
                .is_err()
        );
    }
    assert!(lab.queries.lock().await.is_empty());
    assert!(resolve(&lab.resolver(), "api.test").await.is_ok());
}

#[tokio::test]
async fn wrong_dns_transaction_or_question_and_stalls_are_bounded() {
    let lab = DnsLab::new().await;
    for name in [
        "wrong-id.test",
        "wrong-question.test",
        "unrelated.test",
        "deep.test",
        "ambiguous.test",
        "stall.test",
    ] {
        let started = Instant::now();
        assert!(resolve(&lab.resolver(), name).await.is_err(), "{name}");
        assert!(started.elapsed() < Duration::from_secs(6));
    }
}

#[tokio::test]
async fn cancelled_callers_hold_dns_capacity_until_their_bounded_work_stops() {
    let lab = DnsLab::new().await;
    let resolver = lab.resolver();
    let mut callers = Vec::new();
    for i in 0..16 {
        let resolver = resolver.clone();
        callers.push(tokio::spawn(async move {
            resolve(&resolver, &format!("stall{i}.test")).await
        }));
    }
    tokio::time::timeout(Duration::from_secs(1), async {
        while lab.queries.lock().await.len() < 16 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    for caller in callers {
        caller.abort();
    }
    let error = resolve(&resolver, "8.8.8.8").await.err().unwrap();
    assert_eq!(error.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(error.message, "public HTTPS resolver capacity exhausted");
    tokio::time::timeout(Duration::from_secs(6), async {
        loop {
            if resolve(&resolver, "8.8.8.8").await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn operator_policy_is_explicit_bounded_and_applies_to_ip_literals_without_dns() {
    let lab = DnsLab::new().await;
    let resolver = lab.resolver();
    assert!(resolve(&resolver, "9.9.9.9").await.is_err());
    assert!(resolve(&resolver, "1.1.1.1").await.is_ok());
    let mut config = lab.config.clone();
    config.dns_address = "1.1.1.1:853".parse().unwrap();
    assert!(
        resolve(&PublicEgress::new(config).unwrap(), "1.1.1.1")
            .await
            .is_err()
    );
    for bad in [
        vec![],
        vec!["https://api.test".into(), "HTTPS://API.TEST:443/".into()],
        vec!["http://api.test".into()],
        vec!["https://api.test/path".into()],
        (0..17).map(|i| format!("https://h{i}.test")).collect(),
    ] {
        assert_eq!(
            resolver.resolve(&bad).await.err().unwrap().status,
            StatusCode::BAD_REQUEST
        );
    }
    assert!(lab.queries.lock().await.is_empty());
    let mut changed = lab.config.clone();
    changed.denied_ipv4.push("8.8.8.0/24".into());
    assert_ne!(
        resolver.policy_digest(),
        PublicEgress::new(changed).unwrap().policy_digest()
    );
    for field in [
        "denied_ipv4",
        "dns_server_name",
        "dns_address",
        "dns_ca_pem",
    ] {
        let mut value = serde_json::to_value(&lab.config).unwrap();
        value[field] = match field {
            "denied_ipv4" => serde_json::json!(["8.8.8.1/24"]),
            "dns_server_name" => serde_json::json!("user@resolver.test"),
            "dns_address" => serde_json::json!("0.0.0.0:853"),
            _ => serde_json::json!("invalid"),
        };
        assert!(
            PublicEgress::new(serde_json::from_value(value).unwrap()).is_err(),
            "{field}"
        );
    }
}

#[tokio::test]
async fn operator_diagnostic_resolves_without_database_state_or_access_grants() {
    let lab = DnsLab::new().await;
    let root = tempfile::tempdir().unwrap();
    let config = root.path().join("egress.json");
    std::fs::write(&config, serde_json::to_vec(&lab.config).unwrap()).unwrap();
    let state = root.path().join("must-not-create");
    let config_clone = config.clone();
    let state_clone = state.clone();
    let output = tokio::task::spawn_blocking(move || {
        std::process::Command::new(env!("CARGO_BIN_EXE_fenders-control-plane"))
            .args([
                "--public-egress",
                config_clone.to_str().unwrap(),
                "--state",
                state_clone.to_str().unwrap(),
                "--check-public-egress",
                "https://api.test",
            ])
            .env_remove("FENDERS_DATABASE_URL")
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["public_targets"], "https://api.test:443=1.1.1.1");
    assert_eq!(result["grants_access"], false);
    assert!(!state.exists());
    let config_clone = config.clone();
    let denied = tokio::task::spawn_blocking(move || {
        std::process::Command::new(env!("CARGO_BIN_EXE_fenders-control-plane"))
            .args([
                "--public-egress",
                config_clone.to_str().unwrap(),
                "--check-public-egress",
                "https://169.254.169.254",
            ])
            .env_remove("FENDERS_DATABASE_URL")
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(!denied.status.success());
    assert!(denied.stdout.is_empty());
    std::fs::write(&config, "x".repeat(65537)).unwrap();
    assert!(PublicEgressConfig::read(&config).is_err());
    std::fs::write(&config, r#"{"dns_address":"127.0.0.1:853","dns_server_name":"resolver.test","denied_ipv4":[],"unexpected":true}"#).unwrap();
    assert!(PublicEgressConfig::read(&config).is_err());
    let mut missing = serde_json::to_value(&lab.config).unwrap();
    missing.as_object_mut().unwrap().remove("denied_ipv4");
    std::fs::write(&config, serde_json::to_vec(&missing).unwrap()).unwrap();
    assert!(PublicEgressConfig::read(&config).is_err());
}

#[tokio::test]
async fn store_resolution_is_disabled_until_operator_configuration_is_loaded() {
    use fenders_control_plane::store::Store;
    let lab = DnsLab::new().await;
    let root = tempfile::tempdir().unwrap();
    // No database connection is made during DNS; integration into assignment
    // must revalidate authority in a fresh transaction after this returns.
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgresql://postgres@127.0.0.1:1/unused")
        .unwrap();
    let store = Store::from_pool(pool.clone(), root.path()).unwrap();
    let origins = vec!["https://api.test".into()];
    assert_eq!(
        store
            .resolve_public_origins(&origins)
            .await
            .err()
            .unwrap()
            .status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    let configured = store.with_public_egress(lab.config.clone()).unwrap();
    let result = configured
        .clone()
        .resolve_public_origins(&origins)
        .await
        .unwrap();
    assert_eq!(
        result.launch_policy().unwrap(),
        "https://api.test:443=1.1.1.1"
    );
    let reopened = Store::from_pool(pool, root.path()).unwrap();
    assert!(reopened.resolve_public_origins(&origins).await.is_err());
}

#[tokio::test]
async fn fresh_lookups_follow_public_address_changes_and_a_held_response() {
    let lab = DnsLab::new().await;
    let resolver = lab.resolver();
    assert_eq!(
        resolve(&resolver, "changing.test")
            .await
            .unwrap()
            .launch_policy()
            .unwrap(),
        "https://changing.test:443=1.1.1.1"
    );
    lab.answer_mode
        .store(1, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        resolve(&resolver, "changing.test")
            .await
            .unwrap()
            .launch_policy()
            .unwrap(),
        "https://changing.test:443=8.8.8.8"
    );
    let release = async {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if lab
                    .queries
                    .lock()
                    .await
                    .iter()
                    .any(|(name, _)| name == "held.test.")
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        lab.gate.add_permits(1);
    };
    let (answer, ()) = tokio::join!(resolve(&resolver, "held.test"), release);
    assert!(answer.is_ok());
}
