//! Exercise the shipped entry point before any Node reconciliation can run.
#![cfg(target_os = "linux")]
use fenders_control_plane::{model::uid, pki};
use fenders_node::{core, maintenance::Maintenance};
use serde_json::json;
use std::{
    collections::BTreeMap,
    fs,
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

fn attempt(root: &Path) -> String {
    let mut child = Command::new(env!("CARGO_BIN_EXE_fenders-node"))
        .arg("--state")
        .arg(root.join("state"))
        .arg("--build")
        .arg(root.join("missing-build"))
        .arg("--cgroup-root")
        .arg(root.join("cgroup"))
        .args([
            "--control",
            "https://127.0.0.1:1",
            "--control-pin",
            &"a".repeat(64),
        ])
        .arg("--ca")
        .arg(root.join("pki/ca.pem"))
        .arg("--cert")
        .arg(root.join("pki/node.pem"))
        .arg("--key")
        .arg(root.join("pki/node.key"))
        .args(["--cpu-percent", "100", "--memory-mib", "128"])
        // What is tested is who owns the state, on any host: one whose KVM
        // has nested virtualization enabled is refused for that first.
        .arg("--nested-virtualization")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("startup refusal exceeded deadline");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert!(
        !root.join("state/node").exists(),
        "refused startup initialized Node"
    );
    assert!(
        !root.join("cgroup").exists(),
        "refused startup touched kernel scope"
    );
    String::from_utf8(output.stderr).unwrap()
}
#[tokio::test]
async fn live_owner_and_wrong_candidate_refuse_before_node_initialization() {
    let root = tempfile::tempdir().unwrap();
    pki::create(
        &root.path().join("pki"),
        &BTreeMap::from([("node".into(), vec!["127.0.0.1".into()])]),
    )
    .unwrap();
    let agent = root.path().join("state/agent");
    core::private_dir(&agent).unwrap();
    let owner = Maintenance::open(&agent, &core::boot_id().unwrap()).unwrap();
    let initial = owner.status().unwrap();
    assert!(attempt(root.path()).contains("already owned"));
    assert_eq!(owner.status().unwrap(), initial);
    owner
        .prepare(&json!({"expected_epoch":1,"operation":uid(),"candidate_sha256":"b".repeat(64)}))
        .await
        .unwrap();
    let sealed = owner.status().unwrap();
    drop(owner);
    let before = fs::read(agent.join("agent.sqlite3")).unwrap();
    assert!(attempt(root.path()).contains("conflicting maintenance"));
    assert_eq!(fs::read(agent.join("agent.sqlite3")).unwrap(), before);
    let readback = Maintenance::open(&agent, &core::boot_id().unwrap())
        .unwrap()
        .status()
        .unwrap();
    assert_eq!(readback.epoch, sealed.epoch + 1); // Only this explicit test readback claims an epoch.
    assert_eq!(readback.mode, sealed.mode);
}
