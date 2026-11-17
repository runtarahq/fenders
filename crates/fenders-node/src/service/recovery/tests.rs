use super::*;
use crate::service::tests::Fixture;

async fn fixture() -> (Fixture, Args) {
    let mut f = Fixture::new().await;
    let fallback = f.args.manifest_sha256.clone();
    f.select().unwrap();
    f.next().await;
    f.select().unwrap();
    let s = crate::upgrade::management(&f.args.state).unwrap();
    let args = Args {
        state: f.args.state.clone(),
        releases: f.args.releases.clone(),
        selection: f.args.selection.clone(),
        manifest_sha256: fallback,
        expected_selection_sha256: read(&f.args.selection).unwrap().unwrap().1,
        maintenance_epoch: s.epoch,
        maintenance_operation: s.operation.unwrap(),
        failed_candidate_sha256: s.candidate_sha256.unwrap(),
        recovery_operation: fenders_node_protocol::model::uid(),
    };
    (f, args)
}
fn dead_owner(f: &mut Fixture) {
    f.owner.take();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .arg("--list")
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let pid = child.id();
    assert!(child.wait().unwrap().success());
    Connection::open(f.args.state.join("agent/agent.sqlite3"))
        .unwrap()
        .execute(
            "UPDATE agent_management SET owner_boot=?,owner_pid=?",
            params![crate::core::boot_id().unwrap(), pid],
        )
        .unwrap();
}
fn report(target: &staging::Receipt, snapshot: &Snapshot) -> Result<Value> {
    let mut r = crate::service::tests::report(target, snapshot)?;
    r["admission_quiescence_required"] = json!(true);
    Ok(r)
}
fn recover(args: &Args) -> Result<Value> {
    recover_with(
        args,
        &args.failed_candidate_sha256,
        report,
        crate::durable::atomic_json,
    )
}

#[tokio::test]
async fn recovery_refuses_unadvertised_fallback_before_intent_or_pointer_changes() {
    let (mut f, mut args) = fixture().await;
    dead_owner(&mut f);
    args.manifest_sha256 = f.retain_legacy(&args.manifest_sha256);
    let before = crate::upgrade::management(&args.state).unwrap();
    let pointer = fs::read(&args.selection).unwrap();
    assert!(
        recover_with(
            &args,
            &args.failed_candidate_sha256,
            |_, _| panic!("unqualified fallback must not run preflight"),
            |_, _| panic!("unqualified fallback must not publish")
        )
        .is_err()
    );
    assert_eq!(crate::upgrade::management(&args.state).unwrap(), before);
    assert_eq!(fs::read(&args.selection).unwrap(), pointer);
}

#[tokio::test]
async fn recovery_requires_both_exclusive_lock_and_dead_previous_owner() {
    let (mut f, args) = fixture().await;
    let before = crate::upgrade::management(&args.state).unwrap();
    assert!(recover(&args).is_err());
    f.owner.take(); // A released lock alone does not prove the source has exited.
    assert!(recover(&args).is_err());
    assert_eq!(crate::upgrade::management(&args.state).unwrap(), before);
    assert_eq!(
        read(&args.selection).unwrap().unwrap().1,
        args.expected_selection_sha256
    );
    dead_owner(&mut f);
    let result = recover(&args).unwrap();
    assert_eq!(result["changed"], true);
    assert_eq!(result["admission_resumed"], false);
    let intent = crate::upgrade::management(&args.state).unwrap();
    assert_eq!(intent.epoch, args.maintenance_epoch + 1);
    assert_eq!(intent.origin_epoch, Some(intent.epoch));
    assert_eq!(intent.mode, Mode::Sealed);
    assert_eq!(
        intent.operation.as_deref(),
        Some(args.recovery_operation.as_str())
    );
    assert_eq!(recover(&args).unwrap()["changed"], false);
    let owner = crate::maintenance::Maintenance::open_bound(
        &args.state.join("agent"),
        &intent.owner_boot,
        intent.candidate_sha256.as_ref().unwrap(),
    )
    .unwrap();
    assert_eq!(owner.status().unwrap().mode, Mode::Sealed);
    assert!(
        owner
            .resume(&json!({"expected_epoch":intent.epoch,"operation":args.maintenance_operation}))
            .await
            .is_err()
    );
    owner
        .resume(&json!({"expected_epoch":intent.epoch+1,"operation":args.recovery_operation}))
        .await
        .unwrap();
    let opened = owner.status().unwrap();
    assert_eq!(recover(&args).unwrap()["changed"], false);
    assert_eq!(owner.status().unwrap(), opened);
}

#[tokio::test]
async fn interrupted_publication_stays_sealed_and_retries_only_the_committed_intent() {
    let (mut f, mut args) = fixture().await;
    dead_owner(&mut f);
    let before = crate::upgrade::management(&args.state).unwrap();
    assert!(
        recover_with(&args, &args.failed_candidate_sha256, report, |_, _| Err(
            invalid()
        ))
        .is_err()
    );
    let intent = crate::upgrade::management(&args.state).unwrap();
    assert_eq!(intent.epoch, before.epoch + 1);
    assert_eq!(intent.mode, Mode::Sealed);
    assert_eq!(
        read(&args.selection).unwrap().unwrap().1,
        args.expected_selection_sha256
    );
    assert!(plan(&f.run(), Path::new("unused")).is_err());
    assert!(
        crate::maintenance::Maintenance::open_bound(
            &args.state.join("agent"),
            &intent.owner_boot,
            &args.failed_candidate_sha256
        )
        .is_err()
    );
    let operation = args.recovery_operation.clone();
    args.recovery_operation = fenders_node_protocol::model::uid();
    assert!(recover(&args).is_err());
    args.recovery_operation = operation;
    assert_eq!(recover(&args).unwrap()["changed"], true);
    assert_eq!(crate::upgrade::management(&args.state).unwrap(), intent);
    assert_eq!(
        plan(&f.run(), Path::new("unused")).unwrap().build,
        staging::retained(&args.releases, &args.manifest_sha256)
            .unwrap()
            .path
    );
}

#[tokio::test]
async fn stale_or_unsafe_recovery_never_changes_the_selection_or_intent() {
    for fault in [
        "cas",
        "epoch",
        "operation",
        "helper",
        "boot",
        "unsealed",
        "future",
        "report",
        "owner-change",
        "bytes",
        "symlink-lock",
    ] {
        let (mut f, mut args) = fixture().await;
        dead_owner(&mut f);
        let db = Connection::open(args.state.join("agent/agent.sqlite3")).unwrap();
        match fault {
            "cas" => args.expected_selection_sha256 = "f".repeat(64),
            "epoch" => args.maintenance_epoch += 1,
            "operation" => args.maintenance_operation = fenders_node_protocol::model::uid(),
            "helper" => args.failed_candidate_sha256 = "f".repeat(64),
            "boot" => {
                db.execute("UPDATE agent_management SET owner_boot='other-boot'", [])
                    .unwrap();
            }
            "unsealed" => {
                db.execute("UPDATE agent_management SET mode='open'", [])
                    .unwrap();
            }
            "future" => {
                db.pragma_update(None, "user_version", 999).unwrap();
            }
            "symlink-lock" => {
                let lock = args.state.join("agent/agent.lock");
                fs::rename(&lock, lock.with_extension("old")).unwrap();
                std::os::unix::fs::symlink(lock.with_extension("old"), lock).unwrap();
            }
            _ => (),
        }
        let pointer = fs::read(&args.selection).unwrap();
        let epoch: i64 = db
            .query_row("SELECT epoch FROM agent_management", [], |r| r.get(0))
            .unwrap();
        let result = recover_with(
            &args,
            &args.failed_candidate_sha256,
            |target, snapshot| {
                let mut value = report(target, snapshot)?;
                match fault {
                    "report" => value["admission_quiescence_required"] = json!(false),
                    "owner-change" => {
                        db.execute("UPDATE agent_management SET epoch=epoch+1", [])
                            .unwrap();
                    }
                    "bytes" => {
                        use std::os::unix::fs::PermissionsExt;
                        let file = target.path.join("launch");
                        fs::set_permissions(&file, fs::Permissions::from_mode(0o755)).unwrap();
                        fs::write(file, b"changed").unwrap();
                    }
                    _ => (),
                }
                Ok(value)
            },
            crate::durable::atomic_json,
        );
        assert!(result.is_err(), "{fault}");
        assert_eq!(fs::read(&args.selection).unwrap(), pointer, "{fault}");
        let after: i64 = db
            .query_row("SELECT epoch FROM agent_management", [], |r| r.get(0))
            .unwrap();
        assert_eq!(after, epoch + i64::from(fault == "owner-change"), "{fault}");
    }
}
