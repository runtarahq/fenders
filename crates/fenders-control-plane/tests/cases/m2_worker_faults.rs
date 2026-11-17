//! Acceptance-only faults to owned processes. Never synthesize worker reports.
use super::*;
use crate::durable::atomic_json;

fn observed(pid: u32) -> Option<Value> {
    let stat = match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(v) => v,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => panic!("process observation failed: {e}"),
    };
    let parts: Vec<_> = stat
        .rsplit_once(')')
        .unwrap()
        .1
        .split_whitespace()
        .collect();
    if parts[0] == "Z" {
        return None;
    }
    Some(
        json!({"pid":pid,"state":parts[0],"identity":[fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap().trim(),parts[19]]}),
    )
}

#[cfg(target_os = "linux")]
fn signal(pid: u32, identity: &Value, signal: i32) {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    assert!(fd >= 0, "pidfd_open: {}", std::io::Error::last_os_error());
    let fd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
    assert_eq!(
        &observed(pid).unwrap()["identity"],
        identity,
        "process identity changed"
    );
    assert_eq!(
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                fd.as_raw_fd(),
                signal,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        },
        0
    );
}
#[cfg(not(target_os = "linux"))]
fn signal(_: u32, _: &Value, _: i32) {
    panic!("Linux acceptance only")
}

async fn wait_process(pid: u32, done: impl Fn(&Option<Value>) -> bool) -> Option<Value> {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let value = observed(pid);
        if done(&value) {
            return value;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "process transition not observed: {value:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

pub(super) async fn run(agent: u32, output: PathBuf, cgroup: PathBuf) {
    let agent_identity = observed(agent).unwrap()["identity"].clone();
    let mut sequence = 0;
    while !output.join("finish-worker-faults").exists() {
        if let Ok(bytes) = fs::read(output.join("worker-fault-request.json")) {
            let request: Value = serde_json::from_slice(&bytes).unwrap();
            if request["sequence"].as_u64().unwrap() > sequence {
                let action = s(&request["action"]);
                let evidence = match action {
                    "fill-disk" | "release-disk" => disk_pressure(&output, action),
                    "pause-agent" | "resume-agent" => {
                        let pause = action == "pause-agent";
                        signal(
                            agent,
                            &agent_identity,
                            if pause { libc::SIGSTOP } else { libc::SIGCONT },
                        );
                        wait_process(agent, |v| {
                            v.as_ref().is_some_and(|v| (v["state"] == "T") == pause)
                        })
                        .await
                        .unwrap()
                    }
                    "kill-command" => {
                        assert_eq!(observed(agent).unwrap()["state"], "T");
                        let runs = output.join("node-state/node/runs");
                        let active: Vec<_> = fs::read_dir(&runs)
                            .unwrap()
                            .map(|e| e.unwrap().path())
                            .filter_map(|p| {
                                let status: Value = serde_json::from_slice(
                                    &fs::read(p.join("status.json")).unwrap(),
                                )
                                .unwrap();
                                (status["state"] == "running").then_some((p, status))
                            })
                            .collect();
                        assert_eq!(active.len(), 1, "fault only one owned active command");
                        let (dir, status) = &active[0];
                        let pid = u32::try_from(n(&status["worker_pid"])).unwrap();
                        let args = fs::read(format!("/proc/{pid}/cmdline")).unwrap();
                        let args: Vec<_> =
                            args.split(|b| *b == 0).filter(|v| !v.is_empty()).collect();
                        assert_eq!(args[1], b"run-worker");
                        assert_eq!(args[2], dir.as_os_str().as_encoded_bytes());
                        signal(pid, &status["worker_identity"], libc::SIGKILL);
                        wait_process(pid, Option::is_none).await;
                        let config: Value =
                            serde_json::from_slice(&fs::read(dir.join("config.json")).unwrap())
                                .unwrap();
                        let command_cgroup = PathBuf::from(s(&config["cgroup"]));
                        assert!(command_cgroup.starts_with(&cgroup));
                        let deadline = std::time::Instant::now() + Duration::from_secs(10);
                        let events = loop {
                            let events =
                                fs::read_to_string(command_cgroup.join("cgroup.events")).unwrap();
                            if events.lines().any(|line| line == "populated 0") {
                                break events;
                            }
                            assert!(
                                std::time::Instant::now() < deadline,
                                "command processes remain live"
                            );
                            tokio::time::sleep(Duration::from_millis(50)).await;
                        };
                        json!({"backend_id":status["id"],"pid":pid,"identity":status["worker_identity"],"exited":true,"cgroup_events":events})
                    }
                    _ => panic!("unsupported fault"),
                };
                sequence = request["sequence"].as_u64().unwrap();
                atomic_json(&output.join("worker-fault-observed.json"),&json!({"sequence":sequence,"action":action,"observed_at":chrono::Utc::now().to_rfc3339(),"evidence":evidence})).unwrap();
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[cfg(target_os = "linux")]
fn disk_pressure(output: &Path, action: &str) -> Value {
    use std::io::Write;
    // Never fill a shared filesystem. This opt-in journey requires its own
    // 768 MiB tmpfs, mounted externally for only this acceptance run.
    let path = std::ffi::CString::new(output.as_os_str().as_encoded_bytes()).unwrap();
    let space = || {
        let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
        assert_eq!(unsafe { libc::statfs(path.as_ptr(), stat.as_mut_ptr()) }, 0);
        let stat = unsafe { stat.assume_init() };
        assert_eq!(stat.f_type, libc::TMPFS_MAGIC);
        let total = stat.f_blocks * stat.f_bsize as u64;
        assert_eq!(total, 768 * 1024 * 1024);
        json!({"total_bytes":total,"available_bytes":stat.f_bavail * stat.f_bsize as u64})
    };
    let before = space();
    let filler = output.join("acceptance-pressure.fill");
    if action == "fill-disk" {
        assert!(n(&before["available_bytes"]) > 600 * 1024 * 1024);
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&filler)
            .unwrap();
        let chunk = vec![0_u8; 1024 * 1024];
        for _ in 0..400 {
            file.write_all(&chunk).unwrap();
        }
        file.sync_all().unwrap();
    } else {
        fs::remove_file(&filler).unwrap();
    }
    json!({"before":before,"after":space(),"filler_bytes":400 * 1024 * 1024})
}
#[cfg(not(target_os = "linux"))]
fn disk_pressure(_: &Path, _: &str) -> Value {
    panic!("Linux acceptance only")
}
