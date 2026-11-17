use super::*;
use fenders_node_protocol::model::uid;
use serde_json::json;

fn prepare(epoch: i64, operation: &str) -> Value {
    json!({"expected_epoch":epoch,"operation":operation,"candidate_sha256":"a".repeat(64)})
}
fn resume(epoch: i64, operation: &str) -> Value {
    json!({"expected_epoch":epoch,"operation":operation})
}
async fn quiescing(maintenance: &Maintenance) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while maintenance.status().unwrap().mode != Mode::Quiescing {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn executable_mismatch_refuses_adoption_without_advancing_or_reopening() {
    let root = tempfile::tempdir().unwrap();
    let owner = Maintenance::open_bound(root.path(), "boot", &"a".repeat(64)).unwrap();
    let op = uid();
    let before = owner.prepare(&prepare(1, &op)).await.unwrap();
    drop(owner);
    assert!(Maintenance::open_bound(root.path(), "boot", &"b".repeat(64)).is_err());
    assert_eq!(
        read(
            &connection(
                &root.path().canonicalize().unwrap().join("agent.sqlite3"),
                false
            )
            .unwrap()
        )
        .unwrap(),
        before
    );
    let candidate = Maintenance::open_bound(root.path(), "boot", &"a".repeat(64)).unwrap();
    assert_eq!(candidate.status().unwrap().epoch, 2);
    assert_eq!(candidate.status().unwrap().mode, Mode::Sealed);
    candidate.resume(&resume(2, &op)).await.unwrap();
    drop(candidate);
    assert!(Maintenance::open_bound(root.path(), "boot", &"b".repeat(64)).is_err());
}

#[tokio::test]
async fn prepare_waits_for_admitted_work_and_sealed_source_cannot_reopen() {
    let root = tempfile::tempdir().unwrap();
    let maintenance = Arc::new(Maintenance::open(root.path(), "boot").unwrap());
    let permit = maintenance.admit().unwrap();
    let operation = uid();
    let worker = maintenance.clone();
    let request = prepare(1, &operation);
    let preparing = tokio::spawn(async move { worker.prepare(&request).await });
    quiescing(&maintenance).await;
    assert!(!preparing.is_finished());
    assert!(maintenance.admit().is_err());
    drop(permit);
    let sealed = preparing.await.unwrap().unwrap();
    assert_eq!(sealed.mode, Mode::Sealed);
    assert_eq!(sealed.origin_epoch, Some(1));
    assert!(maintenance.admit().is_err());
    assert!(maintenance.resume(&resume(1, &operation)).await.is_err());
    assert_eq!(
        maintenance.prepare(&prepare(1, &operation)).await.unwrap(),
        sealed
    );
}

#[tokio::test]
async fn canceled_waiter_keeps_blocking_admission_and_ownership_until_work_finishes() {
    let root = tempfile::tempdir().unwrap();
    let maintenance = Arc::new(Maintenance::open(root.path(), "boot").unwrap());
    let permit = maintenance.admit().unwrap();
    let (release, finish) = std::sync::mpsc::channel();
    let (started, ready) = tokio::sync::oneshot::channel();
    let blocking = tokio::task::spawn_blocking(move || {
        started.send(()).unwrap();
        finish.recv().unwrap();
        permit
    });
    let waiter = tokio::spawn(async move {
        let _permit = blocking.await.unwrap();
    });
    ready.await.unwrap();
    waiter.abort();
    let _ = waiter.await;
    let worker = maintenance.clone();
    let request = prepare(1, &uid());
    let mut preparing = tokio::spawn(async move { worker.prepare(&request).await });
    quiescing(&maintenance).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut preparing)
            .await
            .is_err()
    );
    assert!(Maintenance::open(root.path(), "second-boot").is_err());
    release.send(()).unwrap();
    assert_eq!(preparing.await.unwrap().unwrap().mode, Mode::Sealed);
    drop(maintenance);
    assert_eq!(
        Maintenance::open(root.path(), "second-boot")
            .unwrap()
            .status()
            .unwrap()
            .epoch,
        2
    );
}

#[test]
fn admitted_operation_retains_the_exclusive_process_lock_after_manager_drop() {
    let root = tempfile::tempdir().unwrap();
    let owner = Maintenance::open(root.path(), "boot").unwrap();
    let permit = owner.admit().unwrap();
    drop(owner);
    assert!(Maintenance::open(root.path(), "boot").is_err());
    drop(permit);
    assert_eq!(
        Maintenance::open(root.path(), "boot")
            .unwrap()
            .status()
            .unwrap()
            .epoch,
        2
    );
}

#[tokio::test]
async fn adoption_retains_seal_advances_epoch_and_fences_stale_requests() {
    let root = tempfile::tempdir().unwrap();
    let first = Maintenance::open(root.path(), "first-boot").unwrap();
    let operation = uid();
    let sealed = first.prepare(&prepare(1, &operation)).await.unwrap();
    assert!(first.prepare(&prepare(1, &uid())).await.is_err());
    let mut different = prepare(1, &operation);
    different["candidate_sha256"] = json!("b".repeat(64));
    assert!(first.prepare(&different).await.is_err());
    assert!(Maintenance::open(root.path(), "second-boot").is_err());
    drop(first);
    let next = Maintenance::open(root.path(), "second-boot").unwrap();
    let status = next.status().unwrap();
    assert_eq!(status.epoch, 2);
    assert_eq!(status.mode, Mode::Sealed);
    assert_eq!(status.operation, sealed.operation);
    assert_eq!(status.origin_epoch, Some(1));
    assert!(next.admit().is_err());
    assert!(next.resume(&resume(1, &operation)).await.is_err());
    assert!(next.prepare(&prepare(1, &operation)).await.is_err());
    assert!(next.resume(&resume(2, &uid())).await.is_err());
    let open = next.resume(&resume(2, &operation)).await.unwrap();
    assert_eq!(open.mode, Mode::Open);
    assert_eq!(next.resume(&resume(2, &operation)).await.unwrap(), open);
    assert!(next.admit().is_ok());
    assert!(next.prepare(&prepare(2, &operation)).await.is_err());
    assert_eq!(
        next.prepare(&prepare(2, &uid()))
            .await
            .unwrap()
            .origin_epoch,
        Some(2)
    );
}

#[tokio::test]
async fn interrupted_prepare_persists_closed_admission_and_can_be_retried() {
    let root = tempfile::tempdir().unwrap();
    let owner = Arc::new(Maintenance::open(root.path(), "boot").unwrap());
    let permit = owner.admit().unwrap();
    let worker = owner.clone();
    let operation = uid();
    let request = prepare(1, &operation);
    let preparing = tokio::spawn(async move { worker.prepare(&request).await });
    quiescing(&owner).await;
    preparing.abort();
    let _ = preparing.await;
    assert!(owner.admit().is_err());
    assert_eq!(owner.status().unwrap().mode, Mode::Quiescing);
    drop(permit);
    drop(owner);
    let next = Maintenance::open(root.path(), "boot").unwrap();
    assert_eq!(next.status().unwrap().mode, Mode::Quiescing);
    assert!(next.admit().is_err());
    assert_eq!(
        next.prepare(&prepare(2, &operation)).await.unwrap().mode,
        Mode::Sealed
    );
    assert!(next.resume(&resume(2, &operation)).await.is_err());
}

#[test]
fn future_or_malformed_management_journal_is_never_reset() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("agent.sqlite3");
    Connection::open(&path).unwrap().execute_batch("PRAGMA user_version=2; CREATE TABLE retained(value TEXT); INSERT INTO retained VALUES('keep');").unwrap();
    let before = std::fs::read(&path).unwrap();
    assert!(Maintenance::open(root.path(), "boot").is_err());
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let db = Connection::open(&path).unwrap();
    assert_eq!(
        db.query_row("SELECT value FROM retained", [], |r| r.get::<_, String>(0))
            .unwrap(),
        "keep"
    );
}
