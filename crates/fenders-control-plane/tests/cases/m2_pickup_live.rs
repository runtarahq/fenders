//! Fast pickup on a real KVM worker. A deployment's component compiles on the
//! node while no execution can be placed; once one can, assignment to VM launch
//! is measured from the scheduler's assignment audit to the node's run record.
use super::worker;
use super::*;
use crate::durable::atomic_json;
use std::{
    fs,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

fn compiled(node_state: &Path, digest: &str) -> bool {
    let Ok(compilers) = fs::read_dir(node_state.join("node/artifacts")) else {
        return false;
    };
    compilers
        .flatten()
        .any(|compiler| compiler.path().join(digest).join("artifact.json").is_file())
}
/// A started run of the component other than the ones already `seen`.
fn launched(node_state: &Path, digest: &str, seen: &[String]) -> Option<(String, Value)> {
    for run in fs::read_dir(node_state.join("node/runs")).ok()?.flatten() {
        let id = run.file_name().to_string_lossy().into_owned();
        if seen.contains(&id) {
            continue;
        }
        let config: Value =
            serde_json::from_slice(&fs::read(run.path().join("config.json")).ok()?).ok()?;
        let status: Value =
            serde_json::from_slice(&fs::read(run.path().join("status.json")).ok()?).ok()?;
        if config["spec"]["artifact"] == digest && status["started"].is_number() {
            return Some((id, status));
        }
    }
    None
}
/// Milliseconds from the deployment's assignment audit to the node's run record
/// and to its VM launch.
async fn latency(pool: &sqlx::PgPool, deployment: &str, status: &Value) -> (f64, f64) {
    let assigned: f64 = sqlx::query_scalar(
        "SELECT extract(epoch FROM a.created)::float8 FROM audit a JOIN executions e ON e.id=a.resource_id WHERE a.action='execution.assign' AND e.deployment_id=$1 ORDER BY a.sequence LIMIT 1",
    )
    .bind(deployment)
    .fetch_one(pool)
    .await
    .unwrap();
    let ms = |at: &Value| (at.as_f64().unwrap() - assigned) * 1000.0;
    (ms(&status["created"]), ms(&status["started"]))
}
async fn deploy(l: &IdentityLab, artifact: &Value, name: &str) -> String {
    let operation = l
        .lab
        .store
        .create_workload(
            &l.lab.operator,
            &l.lab.tenant,
            &l.lab.project,
            json!({"name":name,"spec":{"artifact_id":artifact["id"],"mode":"http","restart_policy":"never","lifetime_seconds":60}}),
            &uid(),
            true,
        )
        .await
        .unwrap();
    // The call returns its operation; the deployment is the operation's resource.
    let deployment = s(&operation["resource_id"]).to_owned();
    assert!(
        !deployment.is_empty(),
        "operation names no deployment: {operation}"
    );
    deployment
}
async fn until<T>(what: &str, mut probe: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        if let Some(value) = probe() {
            return value;
        }
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires approved Linux KVM worker and PostgreSQL"]
async fn m2_fast_pickup() {
    let output = PathBuf::from(std::env::var("FENDERS_M2_OUTPUT").expect("new evidence directory"));
    fs::create_dir(&output).unwrap();
    let output = output.canonicalize().unwrap();
    let build = PathBuf::from(std::env::var("FENDERS_M2_BUILD").expect("real worker build"));
    let l = IdentityLab::at_origin("http://127.0.0.1:9").await;
    let worker = worker::start_with_scheduler(&l, &output, &build, true).await;
    let (store, operator) = (&l.lab.store, &l.lab.operator);
    let node_state = output.join("node-state");
    // A draining node is offered no placement but still heartbeats.
    store
        .node_mode(operator, &worker.node_id, json!({"draining":true}))
        .await
        .unwrap();
    let component = fs::read(build.join("example-http.wasm")).unwrap();
    let artifact = store
        .upload(operator, &l.lab.tenant, &l.lab.project, &component)
        .await
        .unwrap();
    let digest = s(&artifact["digest"]).to_owned();
    let deployment = deploy(&l, &artifact, "pickup").await;
    let started = Instant::now();
    until("pre-warm compilation", || {
        compiled(&node_state, &digest).then_some(())
    })
    .await;
    let prewarm_ms = started.elapsed().as_millis();
    let placed: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM executions WHERE deployment_id=$1 AND node_id IS NOT NULL",
    )
    .bind(&deployment)
    .fetch_one(&store.pool)
    .await
    .unwrap();
    assert_eq!(
        placed, 0,
        "the component compiled through an assignment, not pre-warm"
    );
    store
        .node_mode(operator, &worker.node_id, json!({"draining":false}))
        .await
        .unwrap();
    let (first, status) = until("VM launch", || launched(&node_state, &digest, &[])).await;
    let (to_node_ms, to_launch_ms) = latency(&store.pool, &deployment, &status).await;
    // A steady-state launch: the node is placed directly and nothing compiles.
    let steady = deploy(&l, &artifact, "pickup-steady").await;
    let (_, status) = until("second VM launch", || {
        launched(&node_state, &digest, std::slice::from_ref(&first))
    })
    .await;
    let (steady_node_ms, steady_launch_ms) = latency(&store.pool, &steady, &status).await;
    let evidence = json!({
        "format_version":1,"kvm_execution":true,"component_sha256":digest,
        "prewarm_compiled_before_assignment":true,"prewarm_ms_after_deploy":prewarm_ms,
        "first_after_prewarm":{"assignment_to_node_run_ms":to_node_ms,"assignment_to_vm_launch_ms":to_launch_ms},
        "steady_state":{"assignment_to_node_run_ms":steady_node_ms,"assignment_to_vm_launch_ms":steady_launch_ms},
        "clock":"one host; the assignment instant is the scheduler transaction's start (PostgreSQL now() in the audit row), so the scheduler pass is included",
    });
    atomic_json(&output.join("pickup.json"), &evidence).unwrap();
    println!("FENDERS_PICKUP {evidence}");
    // The evidence records the measurement. This bound only catches a return to
    // polling or rehashing (hundreds of ms); traced runs on the dev node vary.
    assert!(
        (0.0..250.0).contains(&steady_launch_ms),
        "steady-state assignment to VM launch took {steady_launch_ms:.1} ms"
    );
}
