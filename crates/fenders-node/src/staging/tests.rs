use super::*;
use std::os::unix::fs::symlink;

struct Fixture {
    _root: tempfile::TempDir,
    source: PathBuf,
    store: PathBuf,
    pin: String,
}
impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("incoming");
        let store = root.path().join("releases");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&store).unwrap();
        fs::set_permissions(&store, fs::Permissions::from_mode(0o700)).unwrap();
        for name in COMPONENTS {
            fs::write(source.join(name), format!("fixture {name}")).unwrap();
        }
        let mut fixture = Self {
            _root: root,
            source,
            store,
            pin: String::new(),
        };
        fixture.refresh();
        fixture
    }
    fn refresh(&mut self) {
        let manifest =
            WorkerRelease::capture(&self.source, &self.source.join("fenders-node")).unwrap();
        let bytes = serde_json::to_vec_pretty(&manifest).unwrap();
        fs::write(self.source.join(MANIFEST), &bytes).unwrap();
        self.pin = digest(&bytes);
    }
    fn stage(&self) -> Result<Receipt> {
        stage(&self.source, &self.store, &self.pin)
    }
}
fn writable_tree(path: &Path) {
    if fs::symlink_metadata(path).is_ok_and(|m| m.is_dir()) {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        for entry in fs::read_dir(path).unwrap() {
            writable_tree(&entry.unwrap().path());
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        writable_tree(self._root.path());
    }
}
fn fingerprint(path: &Path) -> Vec<(std::ffi::OsString, u64, u32, i64, i64, String)> {
    let mut files = Vec::new();
    for entry in fs::read_dir(path).unwrap() {
        let entry = entry.unwrap();
        let m = entry.metadata().unwrap();
        files.push((
            entry.file_name(),
            m.ino(),
            m.mode(),
            m.mtime(),
            m.mtime_nsec(),
            file_digest(&entry.path()).unwrap(),
        ));
    }
    files.sort();
    files
}

#[test]
fn publication_is_readonly_exact_and_idempotent_without_source_hardlinks() {
    let fixture = Fixture::new();
    fs::write(fixture.source.join("not-a-release-file"), "not copied").unwrap();
    let receipt = fixture.stage().unwrap();
    assert!(receipt.created);
    assert_eq!(receipt.path.file_name().unwrap(), fixture.pin.as_str());
    assert_eq!(fs::metadata(&receipt.path).unwrap().mode() & 0o7777, 0o555);
    assert_eq!(fs::read_dir(&receipt.path).unwrap().count(), 5);
    for name in COMPONENTS {
        let m = fs::metadata(receipt.path.join(name)).unwrap();
        assert_eq!(m.mode() & 0o7777, 0o555);
        assert_ne!(
            m.ino(),
            fs::metadata(fixture.source.join(name)).unwrap().ino()
        );
        assert_eq!(m.nlink(), 1);
    }
    assert_eq!(
        fs::metadata(receipt.path.join(MANIFEST)).unwrap().mode() & 0o7777,
        0o444
    );
    let before = fingerprint(&receipt.path);
    assert!(!fixture.stage().unwrap().created);
    assert_eq!(fingerprint(&receipt.path), before);
    fs::write(fixture.source.join("runtime.elf"), "mutable incoming file").unwrap();
    assert_eq!(fingerprint(&receipt.path), before);
}

#[test]
fn a_new_version_preserves_the_exact_retained_release_and_execution_receipt() {
    let mut fixture = Fixture::new();
    let first = fixture.stage().unwrap();
    let before = fingerprint(&first.path);
    for name in COMPONENTS {
        fs::write(fixture.source.join(name), format!("new fixture {name}")).unwrap();
    }
    fixture.refresh();
    let second = fixture.stage().unwrap();
    assert_ne!(first.path, second.path);
    assert_eq!(fingerprint(&first.path), before);
    WorkerRelease::verify_execution(
        &serde_json::json!({"build":first.path,"worker_release":first.release}),
    )
    .unwrap();
    verify(&second.path, &second.manifest_sha256, &second.release).unwrap();
}

#[test]
fn wrong_pins_tampering_links_and_unsupported_contracts_never_publish() {
    for fault in [
        "pin",
        "bytes",
        "symlink",
        "manifest-symlink",
        "contract",
        "legacy-management",
        "future-management",
        "empty",
        "fifo",
        "oversized",
        "manifest-oversized",
    ] {
        let mut fixture = Fixture::new();
        match fault {
            "pin" => fixture.pin = "0".repeat(64),
            "bytes" => fs::write(fixture.source.join("compile"), "tampered").unwrap(),
            "symlink" => {
                fs::remove_file(fixture.source.join("launch")).unwrap();
                symlink(
                    fixture.source.join("compile"),
                    fixture.source.join("launch"),
                )
                .unwrap();
            }
            "manifest-symlink" => {
                fs::rename(
                    fixture.source.join(MANIFEST),
                    fixture.source.join("manifest-input"),
                )
                .unwrap();
                symlink(
                    fixture.source.join("manifest-input"),
                    fixture.source.join(MANIFEST),
                )
                .unwrap();
            }
            "contract" | "legacy-management" | "future-management" => {
                let mut value: serde_json::Value =
                    serde_json::from_slice(&fs::read(fixture.source.join(MANIFEST)).unwrap())
                        .unwrap();
                match fault {
                    "legacy-management" => {
                        value.as_object_mut().unwrap().remove("management_protocol");
                    }
                    "future-management" => value["management_protocol"] = serde_json::json!(2),
                    _ => value["runtime"]["control_protocol"] = serde_json::json!(2),
                }
                let bytes = serde_json::to_vec(&value).unwrap();
                fixture.pin = digest(&bytes);
                fs::write(fixture.source.join(MANIFEST), bytes).unwrap();
            }
            "empty" => fs::write(fixture.source.join("runtime.elf"), "").unwrap(),
            "oversized" => fs::File::create(fixture.source.join("compile"))
                .unwrap()
                .set_len(MAX_BINARY_BYTES + 1)
                .unwrap(),
            "manifest-oversized" => fs::File::create(fixture.source.join(MANIFEST))
                .unwrap()
                .set_len(MAX_MANIFEST + 1)
                .unwrap(),
            "fifo" => {
                let path = fixture.source.join("compile");
                fs::remove_file(&path).unwrap();
                let path = CString::new(path.as_os_str().as_bytes()).unwrap();
                assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
            }
            _ => unreachable!(),
        }
        assert!(fixture.stage().is_err(), "{fault}");
        for entry in fs::read_dir(&fixture.store).unwrap() {
            assert_eq!(entry.unwrap().file_name(), ".stage.lock", "{fault}");
        }
    }
}

#[test]
fn existing_destinations_are_never_overwritten_or_repaired() {
    let fixture = Fixture::new();
    let target = fixture.store.join(&fixture.pin);
    fs::create_dir(&target).unwrap();
    fs::write(target.join("keep"), "existing destination").unwrap();
    assert!(fixture.stage().is_err());
    assert_eq!(
        fs::read_to_string(target.join("keep")).unwrap(),
        "existing destination"
    );
    fs::remove_file(target.join("keep")).unwrap();
    fs::remove_dir(&target).unwrap();
    let receipt = fixture.stage().unwrap();
    let path = receipt.path.join("compile");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&path, "changed published file").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o555)).unwrap();
    assert!(fixture.stage().is_err());
    assert_eq!(fs::read_to_string(path).unwrap(), "changed published file");
}

#[test]
fn untrusted_roots_and_lock_or_release_symlinks_are_refused() {
    for fault in [
        "writable-root",
        "readonly-root",
        "root-symlink",
        "lock-symlink",
        "release-symlink",
    ] {
        let fixture = Fixture::new();
        match fault {
            "writable-root" => {
                fs::set_permissions(&fixture.store, fs::Permissions::from_mode(0o777)).unwrap()
            }
            "readonly-root" => {
                fs::set_permissions(&fixture.store, fs::Permissions::from_mode(0o555)).unwrap()
            }
            "root-symlink" => {
                let alias = fixture._root.path().join("alias");
                symlink(&fixture.store, &alias).unwrap();
                assert!(stage(&fixture.source, &alias, &fixture.pin).is_err());
                continue;
            }
            "lock-symlink" => {
                fs::write(fixture._root.path().join("keep"), "keep").unwrap();
                symlink(
                    fixture._root.path().join("keep"),
                    fixture.store.join(".stage.lock"),
                )
                .unwrap();
            }
            "release-symlink" => {
                symlink(&fixture.source, fixture.store.join(&fixture.pin)).unwrap()
            }
            _ => unreachable!(),
        }
        assert!(fixture.stage().is_err(), "{fault}");
    }
}

#[test]
fn atomic_publication_refuses_an_existing_even_empty_target() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("source");
    let target = root.path().join("target");
    fs::create_dir(&source).unwrap();
    fs::create_dir(&target).unwrap();
    fs::write(source.join("keep"), "source").unwrap();
    assert!(publish(&source, &target).is_err());
    assert!(source.join("keep").exists());
    assert_eq!(fs::read_dir(target).unwrap().count(), 0);
}

#[test]
fn concurrent_stagers_publish_once_and_never_leave_owned_partial_directories() {
    let fixture = Fixture::new();
    let barrier = std::sync::Barrier::new(2);
    std::thread::scope(|scope| {
        let run = || {
            barrier.wait();
            fixture.stage()
        };
        let one = scope.spawn(run);
        let two = scope.spawn(run);
        let results = [one.join().unwrap(), two.join().unwrap()];
        assert_eq!(
            results
                .iter()
                .filter(|r| r.as_ref().is_ok_and(|r| r.created))
                .count(),
            1
        );
        for result in results {
            if let Err(error) = result {
                assert_eq!(error.status, StatusCode::CONFLICT);
            }
        }
    });
    let receipt = fixture.stage().unwrap();
    assert!(!receipt.created);
    assert_eq!(fs::read_dir(&fixture.store).unwrap().count(), 2);
}

#[test]
fn abandoned_unpublished_directories_are_neither_adopted_nor_deleted() {
    let fixture = Fixture::new();
    let abandoned = fixture.store.join(format!(".stage-{}", uid()));
    fs::create_dir(&abandoned).unwrap();
    fs::write(abandoned.join("fenders-node"), "partial").unwrap();
    let receipt = fixture.stage().unwrap();
    assert!(receipt.created);
    assert_eq!(
        fs::read_to_string(abandoned.join("fenders-node")).unwrap(),
        "partial"
    );
    assert_ne!(receipt.path, abandoned);
}
