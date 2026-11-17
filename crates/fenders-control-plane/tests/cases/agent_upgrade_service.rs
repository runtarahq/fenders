//! Same maintained units, with only isolated fixture paths/address substituted.
use super::*;

pub(super) struct Service {
    pub name: String,
    output: PathBuf,
    bootstrap: PathBuf,
    store: PathBuf,
    config: PathBuf,
    unit_text: String,
    socket_text: String,
    created: Vec<PathBuf>,
}
/// Change only this fixture's next ExecStart. Existing kernel scopes and all
/// maintained service protections remain intact. Always restore on unwinding.
pub(super) struct CgroupStartupFault {
    unit: PathBuf,
    original: Vec<u8>,
    blocker: PathBuf,
    faulted_sha256: String,
    restored: bool,
}
impl CgroupStartupFault {
    pub fn restore(&mut self) -> Value {
        fs::write(&self.unit, &self.original).unwrap();
        command(&["daemon-reload"]);
        fs::remove_file(&self.blocker).unwrap();
        assert_eq!(fs::read(&self.unit).unwrap(), self.original);
        assert!(!self.blocker.exists());
        self.restored = true;
        json!({"original_unit_sha256":digest(&self.original),"faulted_unit_sha256":self.faulted_sha256,
            "restored_unit_sha256":digest(fs::read(&self.unit).unwrap()),"blocker_removed":true,
            "only_cgroup_argument_changed":true})
    }
}
impl Drop for CgroupStartupFault {
    fn drop(&mut self) {
        if !self.restored {
            let _ = fs::write(&self.unit, &self.original);
            let _ = Command::new("timeout")
                .args(["15", "systemctl", "daemon-reload"])
                .status();
            let _ = fs::remove_file(&self.blocker);
        }
    }
}
fn command(args: &[&str]) -> String {
    let result = Command::new("timeout")
        .args(["15", "systemctl"])
        .args(args)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "systemctl failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    String::from_utf8(result.stdout).unwrap().trim().into()
}
impl Service {
    pub fn new(
        output: &Path,
        bootstrap: &Path,
        build: &Path,
        store: &Path,
        port: u16,
        args: &[std::ffi::OsString],
    ) -> Self {
        let name = format!("fenders-upgrade-{}", uid());
        let config = output.join("service");
        fs::create_dir(&config).unwrap();
        fs::set_permissions(&config, fs::Permissions::from_mode(0o700)).unwrap();
        let value = |key: &str| {
            args[args.iter().position(|arg| arg == key).unwrap() + 1]
                .to_str()
                .unwrap()
                .to_owned()
        };
        for (key, name) in [
            ("--ca", "ca.pem"),
            ("--cert", "node.pem"),
            ("--key", "node.key"),
        ] {
            fs::copy(value(key), config.join(name)).unwrap();
        }
        let env = format!(
            "FENDERS_CONTROL_URL={}\nFENDERS_CONTROL_PIN={}\nFENDERS_NODE_HOST=127.0.0.1\nFENDERS_NODE_PORT={port}\nFENDERS_CPU_PERCENT={}\nFENDERS_MEMORY_MIB={}\nFENDERS_MAX_INSTANCES={}\n",
            value("--control"),
            value("--control-pin"),
            value("--cpu-percent"),
            value("--memory-mib"),
            value("--max-instances")
        );
        pki::private_file(&config.join("environment"), env.as_bytes()).unwrap();
        for path in [output, bootstrap, build, store, &config] {
            assert!(
                path.to_str()
                    .unwrap()
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"/_-.".contains(&b)),
                "fixture unit paths must not need escaping"
            );
        }
        let unit_text = include_str!("../../../../deploy/artifacts/worker/fenders-worker.service")
            .replace("/usr/lib/fenders/worker/fenders-node", bootstrap.to_str().unwrap())
            .replace("/usr/lib/fenders/worker", build.to_str().unwrap())
            .replace("/etc/fenders/worker", config.to_str().unwrap())
            .replace("/var/lib/fenders/worker", output.join("state").to_str().unwrap())
            .replace("/var/lib/fenders/releases", store.to_str().unwrap())
            // The fixture's private output owns state; never provision the installed worker's directory.
            .replace("StateDirectory=fenders/worker\n", "")
            .replace("[Service]\n", "[Service]\nRuntimeMaxSec=300\nCPUQuota=200%\nMemoryMax=4G\nTasksMax=512\nStandardOutput=null\n");
        let unit_text = unit_text.replace(
            "Restart=on-failure",
            &format!(
                "StandardError=append:{}/service-agent.log\nRestart=on-failure",
                output.display()
            ),
        );
        let socket_text = include_str!("../../../../deploy/artifacts/worker/fenders-worker.socket")
            .replace("127.0.0.1:9443", &format!("127.0.0.1:{port}"))
            .replace("fenders-worker.service", &format!("{name}.service"));
        Self {
            name,
            output: output.into(),
            bootstrap: bootstrap.into(),
            store: store.into(),
            config,
            unit_text,
            socket_text,
            created: vec![],
        }
    }
    pub fn cgroup(&self) -> PathBuf {
        PathBuf::from(format!(
            "/sys/fs/cgroup/system.slice/{}.service/workloads",
            self.name
        ))
    }
    pub fn pid(&self) -> Option<u32> {
        command(&[
            "show",
            &format!("{}.service", self.name),
            "--property=MainPID",
            "--value",
        ])
        .parse::<u32>()
        .ok()
        .filter(|n| *n > 0)
    }
    pub fn start(&mut self) {
        if self.created.is_empty() {
            for suffix in ["service", "socket"] {
                assert_eq!(
                    command(&[
                        "show",
                        &format!("{}.{suffix}", self.name),
                        "--property=LoadState",
                        "--value"
                    ]),
                    "not-found"
                );
            }
            for (suffix, text) in [
                ("service", self.unit_text.as_str()),
                ("socket", self.socket_text.as_str()),
            ] {
                let path = PathBuf::from(format!("/run/systemd/system/{}.{suffix}", self.name));
                pki::private_file(&path, text.as_bytes()).unwrap();
                self.created.push(path);
            }
            command(&["daemon-reload"]);
            command(&["start", &format!("{}.socket", self.name)]);
        }
        command(&["start", &format!("{}.service", self.name)]);
        assert!(self.pid().is_some());
    }
    pub fn stop(&self) {
        let old = self.pid().expect("source service is not running");
        command(&["stop", &format!("{}.service", self.name)]);
        // The retained socket may already have activated the selected replacement.
        assert_ne!(self.pid(), Some(old));
    }
    pub async fn select(&self, target: &Path, sealed: &Value, phase: &str) -> Value {
        let manifest = digest(fs::read(target.join("worker-release.json")).unwrap());
        let selection = self.config.join("selected-release.json");
        let mut call = Command::new(&self.bootstrap);
        call.arg("release-select")
            .arg("--state")
            .arg(self.output.join("state"))
            .arg("--releases")
            .arg(&self.store)
            .arg("--selection")
            .arg(&selection)
            .arg("--manifest-sha256")
            .arg(&manifest)
            .arg("--maintenance-epoch")
            .arg(n(&sealed["epoch"]).to_string())
            .arg("--maintenance-operation")
            .arg(s(&sealed["operation"]));
        if selection.exists() {
            call.arg("--expected-selection-sha256")
                .arg(digest(fs::read(&selection).unwrap()));
        } else {
            call.arg("--expect-unselected");
        }
        let (status, path) =
            command_output(call, &self.output, &format!("{phase}-release-select")).await;
        assert!(status.success(), "service release selection failed");
        let value = json_file(&path);
        assert_eq!(value["changed"], true);
        assert_eq!(value["admission_resumed"], false);
        assert_eq!(value["selected"]["manifest_sha256"], manifest);
        value
    }
    pub fn selection(&self) -> PathBuf {
        self.config.join("selected-release.json")
    }
    pub fn fail_cgroup_startup(&self) -> CgroupStartupFault {
        let unit = PathBuf::from(format!("/run/systemd/system/{}.service", self.name));
        assert!(
            self.created.contains(&unit),
            "unit is not owned by this fixture"
        );
        assert!(fs::symlink_metadata(&unit).unwrap().is_file());
        let original = fs::read(&unit).unwrap();
        assert_eq!(original, self.unit_text.as_bytes());
        let blocker = self.output.join("startup-cgroup-blocker");
        pki::private_file(&blocker, b"test-owned cgroup startup failure\n").unwrap();
        let argument = "--cgroup-root /sys/fs/cgroup/system.slice/%n/workloads";
        assert_eq!(self.unit_text.matches(argument).count(), 1);
        let changed = self
            .unit_text
            .replace(argument, &format!("--cgroup-root {}", blocker.display()));
        let fault = CgroupStartupFault {
            unit,
            original,
            blocker,
            faulted_sha256: digest(changed.as_bytes()),
            restored: false,
        };
        fs::write(&fault.unit, changed).unwrap();
        command(&["daemon-reload"]);
        fault
    }
    #[allow(clippy::too_many_arguments)]
    pub async fn recover(
        &self,
        helper: &Path,
        fallback: &Path,
        sealed: &Value,
        operation: &str,
        expected_pin: &str,
        phase: &str,
        deny_publication: bool,
    ) -> Value {
        let mut call = Command::new(helper);
        call.arg("release-recover")
            .arg("--state")
            .arg(self.output.join("state"))
            .arg("--releases")
            .arg(&self.store)
            .arg("--selection")
            .arg(self.selection())
            .arg("--manifest-sha256")
            .arg(digest(
                fs::read(fallback.join("worker-release.json")).unwrap(),
            ))
            .arg("--expected-selection-sha256")
            .arg(expected_pin)
            .arg("--maintenance-epoch")
            .arg(n(&sealed["epoch"]).to_string())
            .arg("--maintenance-operation")
            .arg(s(&sealed["operation"]))
            .arg("--failed-candidate-sha256")
            .arg(s(&sealed["candidate_sha256"]))
            .arg("--recovery-operation")
            .arg(operation);
        if deny_publication {
            publication::restrict_helper(&mut call);
        }
        let (status, path) = command_output(call, &self.output, phase).await;
        json!({"success":status.success(),"exit_code":status.code(),"report":if status.success(){json_file(&path)}else{Value::Null}})
    }
    pub fn fail_publication(&self) -> publication::Fault {
        assert!(!self.created.is_empty());
        assert_eq!(self.config, self.output.join("service"));
        publication::Fault::install(&self.config)
    }
    pub async fn rejected_stale_start(&self) -> Value {
        let unit = format!("{}.service", self.name);
        let previous = command(&["show", &unit, "--property=ExecMainPID", "--value"]);
        let attempt = Command::new("timeout")
            .args(["15", "systemctl", "start", &unit])
            .output()
            .unwrap();
        let result = self.failed_start().await;
        let attempted = command(&["show", &unit, "--property=ExecMainPID", "--value"]);
        assert!(
            attempted.parse::<u32>().unwrap() > 0 && attempted != previous,
            "stale candidate did not actually execute"
        );
        json!({"start_command_success":attempt.status.success(),"previous_exec_main_pid":previous,
            "attempted_exec_main_pid":attempted,"failure":result})
    }
    pub async fn failed_start(&self) -> Value {
        let unit = format!("{}.service", self.name);
        // Continuous ingress activates the retained socket. Observe its actual
        // process exit without issuing an extra start during RestartSec, which
        // could cause another ownership claim before recovery fences the failure.
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let status = command(&["show", &unit, "--property=ExecMainStatus", "--value"]);
            if status != "0" && self.pid().is_none() {
                return json!({"activation":"retained socket","exec_main_status":status,
                    "main_pid":0,"active_state":command(&["show",&unit,"--property=ActiveState","--value"]),
                    "sub_state":command(&["show",&unit,"--property=SubState","--value"])});
            }
            assert!(
                Instant::now() < deadline,
                "selected candidate did not fail to start"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    pub fn reset_failed(&self) {
        // Explicit operator recovery of this test-owned unit after a verified
        // fallback is published; retain the maintained unit's normal rate limit.
        command(&["reset-failed", &format!("{}.service", self.name)]);
    }
    pub fn cleanup(&mut self) {
        if self.created.is_empty() {
            return;
        }
        // Stop activation first, including on panic, before retiring the source.
        let _ = Command::new("timeout")
            .args(["15", "systemctl", "stop", &format!("{}.socket", self.name)])
            .status();
        let _ = Command::new("timeout")
            .args(["15", "systemctl", "stop", &format!("{}.service", self.name)])
            .status();
        // Only the marked fixture cgroup is ours; detached VMs must not outlive the test.
        let _ = fs::write(self.cgroup().join("cgroup.kill"), "1");
        for path in self.created.drain(..) {
            fs::remove_file(path).unwrap();
        }
        let _ = Command::new("timeout")
            .args(["15", "systemctl", "daemon-reload"])
            .status();
    }
}
