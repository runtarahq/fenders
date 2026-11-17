//! Opt-in customer HTTPS journey with a real kernel-free worker and Web PKI.
use super::*;
#[path = "m2_local_retention.rs"]
mod local_retention;
#[path = "m2_log_expiry.rs"]
mod log_expiry;
#[path = "m2_outbound_live.rs"]
mod outbound;
use super::worker;
use crate::durable::atomic_json;
use base64::{Engine, engine::general_purpose::STANDARD};
use fenders_control_plane::public_egress::PublicEgressConfig;
use std::{fs, path::PathBuf};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real Linux KVM worker, public HTTPS/DoT, PostgreSQL and Chromium required"]
async fn customer_m2_public_https() {
    let output = PathBuf::from(std::env::var("FENDERS_M2_OUTPUT").expect("new evidence directory"));
    fs::create_dir(&output).expect("evidence directory must be new");
    let output = output.canonicalize().unwrap();
    let build = PathBuf::from(std::env::var("FENDERS_M2_BUILD").expect("real worker build"));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let mut l = IdentityLab::at_origin(&origin).await;
    let state = std::mem::replace(&mut l.lab.root, tempfile::tempdir().unwrap()).keep();
    atomic_json(&output.join("retained-state.json"), &json!({
        "schema":l.lab.schema,"state_directory":state,"tenant":l.lab.tenant,"project":l.lab.project
    })).unwrap();
    let config = PublicEgressConfig {
        dns_address: "1.1.1.1:853".parse().unwrap(),
        dns_server_name: "cloudflare-dns.com".into(),
        dns_ca_pem: None,
        // Shared management is private/Tailscale special-use space, which the
        // production public-target validator already denies. No policy bypass.
        denied_ipv4: vec![],
    };
    atomic_json(
        &output.join("egress-policy.json"),
        &serde_json::to_value(&config).unwrap(),
    )
    .unwrap();
    l.lab.store = l.lab.store.with_public_egress(config).unwrap();
    let owner = l.login("console-owner").await;
    l.member(&owner, "owner", None).await;
    let outsider = l.login("m2-rollout-outsider").await;
    let worker = worker::start_with_scheduler(&l, &output, &build, true).await;
    let faults = (std::env::var("FENDERS_M2_PRESSURE").as_deref() == Ok("1"))
        .then(|| worker.fault_control(&output));
    let expiry = (std::env::var("FENDERS_M2_LOG_EXPIRY").as_deref() == Ok("1"))
        .then(|| log_expiry::control(&l, output.clone()));
    let local_retention = (std::env::var("FENDERS_M2_LOCAL_RETENTION").as_deref() == Ok("1"))
        .then(|| local_retention::control(&l, output.clone()));
    let outbound = if std::env::var("FENDERS_M2_OUTBOUND").as_deref() == Ok("1") {
        Some(outbound::start(&l, &worker.node_id, &build, output.clone()).await)
    } else {
        None
    };
    // Candidate runtime approval exists only in this isolated test database.
    // A recorded digest is not a public-runtime qualification claim.
    let runtime = digest(fs::read(build.join("runtime.elf")).unwrap());
    l.lab
        .store
        .node_mode(
            &l.lab.operator,
            &worker.node_id,
            json!({"public_https_runtime":runtime}),
        )
        .await
        .unwrap();
    let policy = l
        .lab
        .store
        .public_egress_policy(&l.lab.operator)
        .await
        .unwrap();
    l.lab.store.activate_public_egress(&l.lab.operator,json!({
        "expected_revision":policy["revision"],"enabled":true,"digest":policy["configured_digest"]
    })).await.unwrap();
    let bytes =
        fs::read(std::env::var("FENDERS_M2_COMPONENT").expect("real HTTPS component")).unwrap();
    atomic_json(
        &output.join("component.json"),
        &json!({"sha256":digest(&bytes)}),
    )
    .unwrap();
    let router = api::management(api::ApiState {
        store: l.lab.store.clone(),
        domain: "apps.localhost".into(),
        tls: Some(worker.tls.clone()),
    });
    let http = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    // Server inspection accepts this HTTP contract; actual instantiation traps.
    let failing = wat::parse_str(
        r#"(component
      (import "wasi:http/types@0.2.6" (instance $types
        (export "incoming-request" (type (sub resource)))
        (export "response-outparam" (type (sub resource)))))
      (alias export $types "incoming-request" (type $request))
      (alias export $types "response-outparam" (type $response))
      (core module $h (func $start unreachable) (start $start)
        (func (export "handle") (param i32 i32)))
      (core instance $hi (instantiate $h))
      (func $handle (param "request" (own $request)) (param "response" (own $response))
        (canon lift (core func $hi "handle")))
      (instance $http (export "handle" (func $handle)))
      (export "wasi:http/incoming-handler@0.2.6" (instance $http)))"#,
    )
    .unwrap();
    let passed = run_console_browser(
        "tests/verify_m2_https_live.cjs",
        json!({
            "origin":origin,"tenant":l.lab.tenant,"project":l.lab.project,
            "output":output,"component":STANDARD.encode(bytes),
            "failing":STANDARD.encode(failing),"outsiderCookie":outsider.cookie
        }),
    )
    .await;
    if let Some(faults) = faults {
        fs::write(output.join("finish-worker-faults"), "").unwrap();
        faults.await.unwrap();
    }
    if let Some(expiry) = expiry {
        fs::write(output.join("finish-log-expiry"), "").unwrap();
        expiry.await.unwrap();
    }
    if let Some(retention) = local_retention {
        fs::write(output.join("finish-local-retention"), "").unwrap();
        retention.await.unwrap();
    }
    if let Some(outbound) = outbound {
        fs::write(output.join("finish-outbound-control"), "").unwrap();
        outbound.await.unwrap();
    }
    drop(worker);
    http.abort();
    assert!(
        passed,
        "real HTTPS journey failed; inspect retained evidence"
    );
}
