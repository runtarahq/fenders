use super::*;
use crate::{maintenance::Maintenance, release::WorkerRelease};
use fenders_node_protocol::model::uid;
use std::os::unix::fs::{PermissionsExt, symlink};

/// Opens maintenance for `state` again once the previous owner was dropped.
/// The owner's `agent.lock` is a `flock` on an open file, which a process
/// another test forks at that moment holds too until it execs; so under a
/// full test run the lock can stay taken for a moment after the drop. Retry
/// only that refusal, for a bounded time (SYN-795).
async fn reopen(state: &Path) -> Maintenance {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        match Maintenance::open(state, "boot") {
            Ok(owner) => return owner,
            Err(error)
                if error.status == StatusCode::CONFLICT && std::time::Instant::now() < deadline =>
            {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            Err(error) => panic!("reopening maintenance: {error:?}"),
        }
    }
}

pub(super) struct Fixture {
    root: tempfile::TempDir,
    source: PathBuf,
    pub(super) args: SelectArgs,
    pub(super) owner: Option<Maintenance>,
}
impl Fixture {
    // Model a release retained by a pre-contract installation. Current staging
    // refuses it, but selection/recovery/exec must also guard existing stores.
    pub(super) fn retain_legacy(&self, pin: &str) -> String {
        let old = self.args.releases.join(pin);
        let mut manifest: Value =
            serde_json::from_slice(&fs::read(old.join("worker-release.json")).unwrap()).unwrap();
        manifest
            .as_object_mut()
            .unwrap()
            .remove("management_protocol");
        let bytes = serde_json::to_vec_pretty(&manifest).unwrap();
        let legacy_pin = digest(&bytes);
        let path = self.args.releases.join(&legacy_pin);
        fs::create_dir(&path).unwrap();
        for name in ["fenders-node", "compile", "launch", "runtime.elf"] {
            fs::copy(old.join(name), path.join(name)).unwrap();
            fs::set_permissions(path.join(name), fs::Permissions::from_mode(0o555)).unwrap();
        }
        fs::write(path.join("worker-release.json"), bytes).unwrap();
        fs::set_permissions(
            path.join("worker-release.json"),
            fs::Permissions::from_mode(0o444),
        )
        .unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o555)).unwrap();
        legacy_pin
    }
    pub(super) async fn new() -> Self {
        // As the binary does at start. Selection refuses a store that group or
        // others may write, which a developer's 002 umask would make of the
        // directories created here.
        unsafe {
            libc::umask(0o077);
        }
        let root = tempfile::tempdir().unwrap();
        let state = root.path().join("state");
        let source = root.path().join("incoming");
        let store = root.path().join("releases");
        for path in [state.join("agent"), source.clone(), store.clone()] {
            fs::create_dir_all(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let owner = Maintenance::open(&state.join("agent"), "boot").unwrap();
        Connection::open(state.join("agent/agent.sqlite3")).unwrap().execute_batch(
            "CREATE TABLE assignments(id,generation,backend_id,sequence,error,archived,terminal,action_generation);
            CREATE TABLE log_deliveries(execution_id,capture_id,acknowledged,complete,source_last,last_attempt,last_success,last_error,next_attempt,pruned_at,prune_attempt,prune_error,sealed_at,expired_at,retention_backend);
            CREATE TABLE log_retention_scan(singleton,after_id);
            CREATE TABLE egress_deliveries(execution_id,boot_id,generation,request,started_ns,reply,policy,outcome);"
        ).unwrap();
        for name in ["fenders-node", "compile", "launch", "runtime.elf"] {
            fs::write(source.join(name), format!("fixture {name}")).unwrap();
        }
        let release = WorkerRelease::capture(&source, &source.join("fenders-node")).unwrap();
        let bytes = serde_json::to_vec_pretty(&release).unwrap();
        let pin = digest(&bytes);
        fs::write(source.join("worker-release.json"), bytes).unwrap();
        staging::stage(&source, &store, &pin).unwrap();
        let operation = uid();
        owner.prepare(&json!({"expected_epoch":1,"operation":operation,"candidate_sha256":release.agent_sha256})).await.unwrap();
        Self {
            source,
            args: SelectArgs {
                state,
                releases: store,
                selection: root.path().join("selected.json"),
                manifest_sha256: pin,
                maintenance_epoch: 1,
                maintenance_operation: operation,
                expected_selection_sha256: None,
                expect_unselected: true,
            },
            root,
            owner: Some(owner),
        }
    }
    pub(super) fn select(&self) -> Result<Value> {
        select_with(&self.args, report)
    }
    pub(super) fn run(&self) -> RunArgs {
        RunArgs {
            state: self.args.state.clone(),
            releases: self.args.releases.clone(),
            selection: self.args.selection.clone(),
            package_build: self.source.clone(),
            agent_args: vec!["--help".into()],
        }
    }
    pub(super) async fn next(&mut self) -> String {
        let previous = read(&self.args.selection).unwrap().unwrap().1;
        self.owner.take();
        let owner = reopen(&self.args.state.join("agent")).await;
        owner
            .resume(&json!({"expected_epoch":2,"operation":self.args.maintenance_operation}))
            .await
            .unwrap();
        fs::write(self.source.join("fenders-node"), b"new agent bytes").unwrap();
        let release =
            WorkerRelease::capture(&self.source, &self.source.join("fenders-node")).unwrap();
        let bytes = serde_json::to_vec_pretty(&release).unwrap();
        let pin = digest(&bytes);
        fs::write(self.source.join("worker-release.json"), bytes).unwrap();
        staging::stage(&self.source, &self.args.releases, &pin).unwrap();
        let operation = uid();
        owner.prepare(&json!({"expected_epoch":2,"operation":operation,"candidate_sha256":release.agent_sha256})).await.unwrap();
        self.args.manifest_sha256 = pin;
        self.args.maintenance_epoch = 2;
        self.args.maintenance_operation = operation;
        self.args.expected_selection_sha256 = Some(previous.clone());
        self.args.expect_unselected = false;
        self.owner = Some(owner);
        previous
    }
}

#[tokio::test]
async fn unadvertised_management_never_selects_or_executes_a_retained_legacy_agent() {
    let mut f = Fixture::new().await;
    let before = f.owner.as_ref().unwrap().status().unwrap();
    let legacy = f.retain_legacy(&f.args.manifest_sha256);
    f.args.manifest_sha256 = legacy.clone();
    assert!(
        select_with(&f.args, |_, _| panic!(
            "legacy target must fail before preflight"
        ))
        .is_err()
    );
    assert!(!f.args.selection.exists());
    assert_eq!(f.owner.as_ref().unwrap().status().unwrap(), before);
    // Simulate an old installer having already published this pointer.
    let pointer = json!({"schema":1,"state":f.args.state.canonicalize().unwrap(),
        "manifest_sha256":legacy,"source_epoch":before.epoch,"operation":before.operation});
    crate::durable::atomic_json(&f.args.selection, &pointer).unwrap();
    let bytes = fs::read(&f.args.selection).unwrap();
    assert!(plan(&f.run(), Path::new("unused")).is_err());
    assert_eq!(fs::read(&f.args.selection).unwrap(), bytes);
    assert_eq!(f.owner.as_ref().unwrap().status().unwrap(), before);
}
pub(super) fn report(target: &staging::Receipt, snapshot: &Snapshot) -> Result<Value> {
    Ok(
        json!({"schema":1,"candidate":target.release,"maintenance":snapshot,
        "admission_quiescence_required":false,"rollout_authorized":false,"checked_execution_ids":[],"terminal_executions":0}),
    )
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fn writable(path: &Path) {
            if fs::symlink_metadata(path).is_ok_and(|m| m.is_dir()) {
                fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
                for entry in fs::read_dir(path).unwrap() {
                    writable(&entry.unwrap().path());
                }
            }
        }
        writable(self.root.path());
    }
}

#[tokio::test]
async fn selected_exec_uses_exact_retained_build_and_never_reopens_admission() {
    let f = Fixture::new().await;
    let before = f.owner.as_ref().unwrap().status().unwrap();
    let fallback = plan(&f.run(), &f.source.join("fenders-node")).unwrap();
    assert_eq!(fallback.build, f.source.canonicalize().unwrap());
    let result = f.select().unwrap();
    assert_eq!(result["changed"], true);
    assert_eq!(result["admission_resumed"], false);
    assert_eq!(result["activation_verified"], false);
    assert_eq!(f.owner.as_ref().unwrap().status().unwrap(), before);
    let selected = plan(&f.run(), &f.source.join("fenders-node")).unwrap();
    assert_eq!(
        selected.build,
        f.args
            .releases
            .join(&f.args.manifest_sha256)
            .canonicalize()
            .unwrap()
    );
    assert_eq!(selected.executable, selected.build.join("fenders-node"));
    assert_eq!(selected.state, f.args.state.canonicalize().unwrap());
    let bytes = fs::read(&f.args.selection).unwrap();
    assert_eq!(result["selection_sha256"], digest(&bytes));
    let metadata = fs::metadata(&f.args.selection).unwrap();
    let retry = select_with(&f.args, |_, _| {
        panic!("retry must not perform a new preflight")
    })
    .unwrap();
    assert_eq!(retry["changed"], false);
    assert_eq!(
        fs::metadata(&f.args.selection).unwrap().ino(),
        metadata.ino()
    );
    assert_eq!(fs::read(&f.args.selection).unwrap(), bytes);
}

#[tokio::test]
async fn selection_cas_preserves_previous_release_and_refuses_stale_reversal() {
    let mut f = Fixture::new().await;
    let old_pin = f.args.manifest_sha256.clone();
    f.select().unwrap();
    let previous = f.next().await;
    f.args.expected_selection_sha256 = Some("f".repeat(64));
    assert!(select_with(&f.args, |_, _| panic!("CAS must fail before preflight")).is_err());
    assert_eq!(read(&f.args.selection).unwrap().unwrap().1, previous);
    f.args.expected_selection_sha256 = Some(previous);
    f.select().unwrap();
    staging::retained(&f.args.releases, &old_pin).unwrap();
    let now = fs::read(&f.args.selection).unwrap();
    f.args.manifest_sha256 = old_pin;
    f.args.maintenance_epoch = 1;
    f.args.expect_unselected = true;
    f.args.expected_selection_sha256 = None;
    assert!(f.select().is_err());
    assert_eq!(fs::read(&f.args.selection).unwrap(), now);
}

#[tokio::test]
async fn idempotent_selection_retry_after_owner_resume_does_not_mutate_journal_or_pointer() {
    let mut f = Fixture::new().await;
    f.select().unwrap();
    let before = fs::read(&f.args.selection).unwrap();
    f.owner.take();
    let owner = reopen(&f.args.state.join("agent")).await;
    let open = owner
        .resume(&json!({"expected_epoch":2,"operation":f.args.maintenance_operation}))
        .await
        .unwrap();
    let retried = f.select().unwrap();
    assert_eq!(retried["changed"], false);
    assert_eq!(retried["activation_verified"], false);
    assert!(retried.get("restart_required").is_none());
    assert_eq!(owner.status().unwrap(), open);
    assert_eq!(fs::read(&f.args.selection).unwrap(), before);
}

#[tokio::test]
async fn stale_or_incompatible_candidate_never_publishes() {
    for fault in [
        "epoch",
        "operation",
        "candidate",
        "unsealed",
        "report",
        "inventory",
        "report-shape",
        "owner-change",
        "bytes",
    ] {
        let mut f = Fixture::new().await;
        match fault {
            "epoch" => f.args.maintenance_epoch += 1,
            "operation" => f.args.maintenance_operation = uid(),
            "candidate" => {
                Connection::open(f.args.state.join("agent/agent.sqlite3"))
                    .unwrap()
                    .execute(
                        "UPDATE agent_management SET candidate_sha256=?",
                        ["b".repeat(64)],
                    )
                    .unwrap();
            }
            "unsealed" => {
                Connection::open(f.args.state.join("agent/agent.sqlite3"))
                    .unwrap()
                    .execute("UPDATE agent_management SET mode='quiescing'", [])
                    .unwrap();
            }
            _ => (),
        }
        let result = select_with(&f.args, |target, snapshot| {
            let mut value = report(target, snapshot)?;
            match fault {
                "report" => value["candidate"]["agent_sha256"] = json!("c".repeat(64)),
                "inventory" => {
                    let id = uid();
                    value["checked_execution_ids"] = json!([id, id]);
                }
                "report-shape" => value["terminal_executions"] = json!(-1),
                "owner-change" => {
                    Connection::open(f.args.state.join("agent/agent.sqlite3"))
                        .unwrap()
                        .execute("UPDATE agent_management SET epoch=epoch+1", [])
                        .unwrap();
                }
                "bytes" => {
                    let file = target.path.join("launch");
                    fs::set_permissions(&file, fs::Permissions::from_mode(0o755)).unwrap();
                    fs::write(file, b"tampered").unwrap();
                }
                _ => (),
            }
            Ok(value)
        });
        assert!(result.is_err(), "{fault}");
        assert!(!f.args.selection.exists(), "{fault}");
    }
}

#[tokio::test]
async fn publication_fence_excludes_owner_changes_without_writing_journal_rows() {
    let f = Fixture::new().await;
    let snapshot = f.owner.as_ref().unwrap().status().unwrap();
    fenced(&f.args.state, &snapshot, || {
        let other = Connection::open(f.args.state.join("agent/agent.sqlite3")).unwrap();
        other.busy_timeout(Duration::ZERO).unwrap();
        assert!(
            other
                .execute("UPDATE agent_management SET epoch=epoch+1", [])
                .is_err()
        );
        Ok(())
    })
    .unwrap();
    assert_eq!(f.owner.as_ref().unwrap().status().unwrap(), snapshot);
}

#[tokio::test]
async fn concurrent_selection_is_excluded_without_changing_the_record() {
    let f = Fixture::new().await;
    let path = record_path(&f.args.selection).unwrap();
    let owner = selection_lock(&path).unwrap();
    assert!(
        select_with(&f.args, |_, _| panic!(
            "concurrent selector must not run candidate"
        ))
        .is_err()
    );
    assert!(!path.exists());
    drop(owner);
    assert_eq!(f.select().unwrap()["changed"], true);
}

#[tokio::test]
async fn unsafe_selection_paths_and_state_or_build_overrides_fail_closed() {
    let f = Fixture::new().await;
    f.select().unwrap();
    for args in [
        vec!["--state=elsewhere".into()],
        vec!["--build".into(), "elsewhere".into()],
    ] {
        let mut run = f.run();
        run.agent_args = args;
        assert!(plan(&run, &f.source.join("fenders-node")).is_err());
    }
    let mut run = f.run();
    run.state = f.source.clone();
    assert!(plan(&run, &f.source.join("fenders-node")).is_err());
    fs::set_permissions(&f.args.selection, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(plan(&f.run(), &f.source.join("fenders-node")).is_err());
    fs::rename(&f.args.selection, f.root.path().join("other.json")).unwrap();
    symlink(f.root.path().join("other.json"), &f.args.selection).unwrap();
    assert!(plan(&f.run(), &f.source.join("fenders-node")).is_err());
    fs::remove_file(&f.args.selection).unwrap();
    fs::write(&f.args.selection, b"partial JSON").unwrap();
    assert!(plan(&f.run(), &f.source.join("fenders-node")).is_err());
}
