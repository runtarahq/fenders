//! One unchanged dual-export component, customer trigger edits, real clock/worker.
use super::worker;
use super::*;
#[path = "m2_scheduler.rs"]
mod scheduler;
use crate::durable::atomic_json;
use base64::{Engine, engine::general_purpose::STANDARD};
use std::{fs, path::PathBuf};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires approved Linux KVM worker, PostgreSQL and Chromium"]
async fn customer_m2_trigger_edits() {
    let output = PathBuf::from(std::env::var("FENDERS_M2_OUTPUT").expect("new evidence directory"));
    fs::create_dir(&output).unwrap();
    let output = output.canonicalize().unwrap();
    let build = PathBuf::from(std::env::var("FENDERS_M2_BUILD").expect("real worker build"));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let mut l = IdentityLab::at_origin(&origin).await;
    let state = std::mem::replace(&mut l.lab.root, tempfile::tempdir().unwrap()).keep();
    atomic_json(&output.join("retained-state.json"),&json!({"schema":l.lab.schema,"state_directory":state,"tenant":l.lab.tenant,"project":l.lab.project})).unwrap();
    let owner = l.login("console-owner").await;
    l.member(&owner, "owner", None).await;
    let outage = std::env::var("FENDERS_M2_OUTAGE").as_deref() == Ok("1");
    let worker = worker::start_with_scheduler(&l, &output, &build, !outage).await;
    let worker_faults = (std::env::var("FENDERS_M2_UNCERTAIN").as_deref() == Ok("1"))
        .then(|| worker.fault_control(&output));
    let scheduler = if outage {
        Some(tokio::spawn(scheduler::run(
            l.lab.schema.clone(),
            state.clone(),
            output.clone(),
            l.lab.token.clone(),
        )))
    } else {
        None
    };
    let placement = if std::env::var("FENDERS_M2_SCHEDULE_CANCEL").as_deref() == Ok("1") {
        let (store, operator, node, output) = (
            l.lab.store.clone(),
            l.lab.operator.clone(),
            worker.node_id.clone(),
            output.clone(),
        );
        Some(tokio::spawn(async move {
            let mut sequence = 0;
            while !output.join("finish-placement-control").exists() {
                if let Ok(bytes) = fs::read(output.join("placement-request.json")) {
                    let request: Value = serde_json::from_slice(&bytes).unwrap();
                    if request["sequence"].as_u64().unwrap() > sequence {
                        assert!(request["draining"].is_boolean());
                        let observed = store
                            .node_mode(&operator, &node, json!({"draining":request["draining"]}))
                            .await
                            .unwrap();
                        sequence = request["sequence"].as_u64().unwrap();
                        atomic_json(&output.join("placement-observed.json"), &json!({"sequence":sequence,"observed_at":chrono::Utc::now().to_rfc3339(),"node":observed})).unwrap();
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }))
    } else {
        None
    };
    let component_path = std::env::var("FENDERS_M2_COMPONENT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| build.join("example-dual.wasm"));
    let component = fs::read(component_path).unwrap();
    atomic_json(
        &output.join("component.json"),
        &json!({"sha256":digest(&component)}),
    )
    .unwrap();
    let router = api::management(api::ApiState {
        store: l.lab.store.clone(),
        domain: "apps.localhost".into(),
        tls: Some(worker.tls.clone()),
    });
    let http = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let passed=run_console_browser("tests/verify_m2_triggers_live.cjs",json!({"origin":origin,"tenant":l.lab.tenant,"project":l.lab.project,"component":STANDARD.encode(component),"output":output})).await;
    if let Some(scheduler) = scheduler {
        fs::write(output.join("finish-schedulers"), "").unwrap();
        scheduler.await.unwrap();
    }
    if let Some(placement) = placement {
        fs::write(output.join("finish-placement-control"), "").unwrap();
        placement.await.unwrap();
    }
    if let Some(faults) = worker_faults {
        fs::write(output.join("finish-worker-faults"), "").unwrap();
        faults.await.unwrap();
    }
    drop(worker);
    http.abort();
    assert!(
        passed,
        "real trigger journey failed; inspect retained evidence"
    );
}
