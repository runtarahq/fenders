//! Opt-in only on a dedicated, operator-provisioned disposable quota filesystem.
#![cfg(target_os = "linux")]
use fenders_node::project_quota::ProjectQuota;
use std::{
    fs,
    io::Write,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::PathBuf,
    process::Command,
};
#[test]
#[ignore = "requires a disposable ext4/XFS project 123 tree: 4 MiB hard bytes and 64 hard inodes"]
fn real_project_quota_enforces_bytes_and_refuses_uncovered_entries() {
    assert_eq!(unsafe { libc::geteuid() }, 0);
    let root = PathBuf::from(
        std::env::var_os("FENDERS_TEST_PROJECT_QUOTA_DIR")
            .expect("explicit disposable quota directory"),
    );
    let marker = root.join("qualification-only");
    let meta = fs::symlink_metadata(&marker).unwrap();
    assert!(meta.is_file() && meta.uid() == 0 && meta.mode() & 0o7777 == 0o600);
    assert_eq!(
        fs::read(&marker).unwrap(),
        b"fenders-disposable-project-quota\n"
    );
    assert_eq!(
        fs::read_dir(&root).unwrap().count(),
        1,
        "never reuse a fixture"
    );
    assert!(
        ProjectQuota::open(&root, 123, 4 * 1024 * 1024, 64).is_err(),
        "root fixture begins with quota bypass"
    );
    fenders_node::project_quota::drop_quota_bypass().unwrap();
    let child = Command::new("/usr/bin/cat")
        .arg("/proc/self/status")
        .output()
        .unwrap();
    assert!(child.status.success());
    let status = String::from_utf8(child.stdout).unwrap();
    for field in ["CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"] {
        let value = status
            .lines()
            .find_map(|line| line.strip_prefix(field))
            .unwrap();
        assert_eq!(
            u64::from_str_radix(value.trim(), 16).unwrap() & (1 << 24),
            0,
            "exec child must not regain quota bypass"
        );
    }
    let quota = ProjectQuota::open(&root, 123, 4 * 1024 * 1024, 64).unwrap();
    assert!(quota.contains(&root).unwrap());
    assert!(!quota.contains(root.parent().unwrap()).unwrap());
    assert!(ProjectQuota::open(&root, 124, 4 * 1024 * 1024, 64).is_err());
    assert!(ProjectQuota::open(&root, 123, 3 * 1024 * 1024, 64).is_err());
    assert!(ProjectQuota::open(&root, 123, 4 * 1024 * 1024, 63).is_err());
    let nested = root.join("nested");
    fs::create_dir(&nested).unwrap();
    fs::write(nested.join("small"), b"retained").unwrap();
    let initial = quota.remaining().unwrap();
    assert!(initial.bytes > 0 && initial.inodes > 0);
    // Existing files with a different project and missing directory inheritance
    // must fail even though the root's own quota looks correct.
    let status = Command::new("/usr/bin/chattr")
        .args(["-p", "124"])
        .arg(nested.join("small"))
        .status()
        .unwrap();
    assert!(status.success());
    assert!(quota.remaining().is_err());
    assert!(
        Command::new("/usr/bin/chattr")
            .args(["-p", "123"])
            .arg(nested.join("small"))
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("/usr/bin/chattr")
            .arg("-P")
            .arg(&nested)
            .status()
            .unwrap()
            .success()
    );
    assert!(quota.remaining().is_err());
    assert!(
        Command::new("/usr/bin/chattr")
            .arg("+P")
            .arg(&nested)
            .status()
            .unwrap()
            .success()
    );
    let link = root.join("outside");
    std::os::unix::fs::symlink("/tmp", &link).unwrap();
    assert!(quota.remaining().is_err());
    fs::remove_file(link).unwrap();
    let payload = nested.join("payload");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&payload)
        .unwrap();
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .unwrap();
    let mut failure = None;
    for _ in 0..80 {
        if let Err(error) = file.write_all(&[42; 65536]).and_then(|()| file.sync_all()) {
            failure = Some(error);
            break;
        }
    }
    let error = failure.expect("the kernel must reject writes below 5 MiB");
    assert_eq!(error.raw_os_error(), Some(libc::EDQUOT));
    drop(file);
    let left = quota.remaining().unwrap();
    assert!(left.bytes < initial.bytes);
    assert_eq!(fs::read(nested.join("small")).unwrap(), b"retained");
    fs::remove_file(payload).unwrap();
    assert!(quota.remaining().unwrap().bytes > left.bytes);
    // Test inode enforcement independently after releasing the large payload.
    let mut inode_error = None;
    for n in 0..80 {
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(nested.join(format!("inode-{n}")))
        {
            Ok(_) => (),
            Err(error) => {
                inode_error = Some(error);
                break;
            }
        }
    }
    assert_eq!(
        inode_error
            .expect("kernel must enforce inode hard limit")
            .raw_os_error(),
        Some(libc::EDQUOT)
    );
    assert_eq!(quota.remaining().unwrap().inodes, 0);
    println!(
        "project quota enforced byte/inode limits; misbound entries and symlinks refused; retained file unchanged"
    );
}
