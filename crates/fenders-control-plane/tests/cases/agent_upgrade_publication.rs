//! Real publication I/O failure after a journal commit, confined to fixture paths
//! and the helper child. No production hook, global capability or journal edit.
use super::*;

pub(super) struct Fault {
    directory: PathBuf,
    original: fs::Permissions,
    restored: bool,
}
impl Fault {
    pub fn install(directory: &Path) -> Self {
        let metadata = fs::symlink_metadata(directory).unwrap();
        assert!(metadata.is_dir() && metadata.uid() == unsafe { libc::geteuid() });
        assert_eq!(metadata.mode() & 0o7777, 0o700);
        for name in ["selected-release.json", ".selected-release.json.lock"] {
            let m = fs::symlink_metadata(directory.join(name)).unwrap();
            assert!(m.is_file() && m.uid() == unsafe { libc::geteuid() } && m.nlink() == 1);
            assert_eq!(m.mode() & 0o7777, 0o600);
        }
        let fault = Self {
            directory: directory.into(),
            original: metadata.permissions(),
            restored: false,
        };
        fs::set_permissions(directory, fs::Permissions::from_mode(0o500)).unwrap();
        fault
    }
    pub fn restore(&mut self) -> Value {
        assert_eq!(
            fs::metadata(&self.directory).unwrap().mode() & 0o7777,
            0o500
        );
        fs::set_permissions(&self.directory, self.original.clone()).unwrap();
        assert_eq!(
            fs::metadata(&self.directory).unwrap().mode() & 0o7777,
            0o700
        );
        self.restored = true;
        json!({"original_mode":0o700,"fault_mode":0o500,"restored_mode":0o700,
            "only_helper_loses_dac_bypass":true,"new_privileges_blocked_in_helper":true})
    }
}
impl Drop for Fault {
    fn drop(&mut self) {
        if !self.restored {
            let _ = fs::set_permissions(&self.directory, self.original.clone());
        }
    }
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct Header {
    version: u32,
    pid: i32,
}
#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Caps {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

pub(super) fn restrict_helper(command: &mut Command) {
    #[cfg(target_os = "linux")]
    unsafe {
        command.pre_exec(|| {
            let mut header = Header {
                version: 0x20080522,
                pid: 0,
            };
            let mut caps = [Caps::default(); 2];
            if libc::syscall(libc::SYS_capget, &mut header, caps.as_mut_ptr()) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            // Linux UAPI CAP_DAC_OVERRIDE=1 and CAP_DAC_READ_SEARCH=2. Retain
            // root identity and all unrelated capabilities; prevent exec regain.
            for capability in [1, 2] {
                if libc::prctl(libc::PR_CAPBSET_READ, capability, 0, 0, 0) != 0
                    && libc::prctl(libc::PR_CAPBSET_DROP, capability, 0, 0, 0) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                caps[0].effective &= !(1 << capability);
                caps[0].permitted &= !(1 << capability);
                caps[0].inheritable &= !(1 << capability);
            }
            if libc::syscall(libc::SYS_capset, &header, caps.as_ptr()) != 0
                || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = command;
        panic!("publication I/O fault requires Linux");
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    #[test]
    #[ignore = "explicit Linux-root filesystem fault qualification"]
    fn real_publication_fault_keeps_lock_and_journal_writable() {
        assert_eq!(unsafe { libc::geteuid() }, 0, "requires Linux root");
        let root = tempfile::tempdir().unwrap();
        let config = root.path().join("config");
        fs::create_dir(&config).unwrap();
        fs::set_permissions(&config, fs::Permissions::from_mode(0o700)).unwrap();
        for name in ["selected-release.json", ".selected-release.json.lock"] {
            pki::private_file(&config.join(name), b"original").unwrap();
        }
        let db = rusqlite::Connection::open(root.path().join("intent.sqlite3")).unwrap();
        db.execute_batch("CREATE TABLE intent(epoch INTEGER); INSERT INTO intent VALUES(2);")
            .unwrap();
        drop(db);
        let mut fault = Fault::install(&config);
        let mut child = Command::new(std::env::current_exe().unwrap());
        child
            .args([
                "--ignored",
                "--exact",
                "agent_upgrade_live::publication::tests::publication_fault_child",
                "--test-threads=1",
            ])
            .env("FENDERS_PUBLICATION_FAULT_CHILD_ROOT", root.path())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        restrict_helper(&mut child);
        let output = child.output().unwrap();
        assert!(
            output.status.success(),
            "restricted child failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            fs::read(config.join("selected-release.json")).unwrap(),
            b"original"
        );
        let db = rusqlite::Connection::open(root.path().join("intent.sqlite3")).unwrap();
        assert_eq!(
            db.query_row("SELECT epoch FROM intent", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            3
        );
        fault.restore();
        pki::private_file(&config.join("restored-write"), b"writable").unwrap();
    }
    #[test]
    #[ignore = "child of explicit filesystem fault qualification"]
    fn publication_fault_child() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let mut header = Header {
            version: 0x20080522,
            pid: 0,
        };
        let mut caps = [Caps::default(); 2];
        assert_eq!(
            unsafe { libc::syscall(libc::SYS_capget, &mut header, caps.as_mut_ptr()) },
            0
        );
        assert_eq!(
            (caps[0].effective | caps[0].permitted | caps[0].inheritable) & 6,
            0
        );
        for cap in [1, 2] {
            assert_eq!(
                unsafe { libc::prctl(libc::PR_CAPBSET_READ, cap, 0, 0, 0) },
                0
            );
        }
        assert_eq!(
            unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) },
            1
        );
        let root = PathBuf::from(std::env::var("FENDERS_PUBLICATION_FAULT_CHILD_ROOT").unwrap());
        let lock = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(root.join("config/.selected-release.json.lock"))
            .unwrap();
        assert_eq!(
            unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        let mut db = rusqlite::Connection::open(root.join("intent.sqlite3")).unwrap();
        db.execute_batch("PRAGMA synchronous=FULL").unwrap();
        let tx = db.transaction().unwrap();
        tx.execute("UPDATE intent SET epoch=3", []).unwrap();
        tx.commit().unwrap();
        let denied = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(root.join("config/.write-fault"));
        assert_eq!(
            denied.err().unwrap().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            fs::read(root.join("config/selected-release.json")).unwrap(),
            b"original"
        );
    }
}
