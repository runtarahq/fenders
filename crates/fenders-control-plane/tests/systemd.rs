//! Opt-in destructive fixture: only a fresh, explicitly marked disposable VM.
#![cfg(target_os = "linux")]

use fenders_control_plane::{model::digest, pki};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
    process::{Command, Output},
    time::{Duration, Instant},
};

const UNIT: &str = "fenders-control-plane.service";
const CONFIG: &str = "/etc/fenders/control";
const STATE: &str = "/var/lib/fenders/control";
const UNIT_TEXT: &str = include_str!("../../../deploy/systemd/fenders-control-plane.service");
const USER_TEXT: &str = include_str!("../../../deploy/systemd/fenders-control.conf");

fn output(program: &str, args: &[&str]) -> Output {
    Command::new("timeout")
        .args(["--signal=KILL", "40s", program])
        .args(args)
        .output()
        .unwrap()
}
fn command(program: &str, args: &[&str]) -> String {
    let result = output(program, args);
    assert!(result.status.success(), "{program}: {:?}", result);
    String::from_utf8(result.stdout).unwrap().trim().into()
}
fn property(name: &str) -> String {
    command("systemctl", &["show", UNIT, "--property", name, "--value"])
}
fn private(path: &str, data: &[u8]) {
    pki::private_file(Path::new(path), data)
        .unwrap_or_else(|error| panic!("cannot create fixture file {path}: {error}"));
}
struct Stop;
impl Drop for Stop {
    fn drop(&mut self) {
        let _ = output("systemctl", &["stop", UNIT]);
    }
}
async fn observe(client: &reqwest::Client, token: &str, previous: Option<&Value>) -> Value {
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        if let Ok(response) = client
            .get("https://127.0.0.1:9090/v1/control-plane/status")
            .bearer_auth(token)
            .send()
            .await
            && response.status().is_success()
        {
            let value: Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
            let loops = value["components"].as_array().unwrap();
            if loops.len() == 1
                && loops.iter().all(|v| v["iterations"].as_u64().unwrap() > 0)
                && previous.is_none_or(|p| p["process_id"] != value["process_id"])
            {
                return value;
            }
        }
        assert!(
            Instant::now() < deadline,
            "daemon did not become observable"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test]
#[ignore = "requires root, systemd PID 1, PostgreSQL and a fresh marked disposable Linux VM"]
async fn systemd_restart_shutdown_and_confinement() {
    assert_eq!(unsafe { libc::geteuid() }, 0);
    assert_eq!(
        fs::read_to_string("/proc/1/comm").unwrap().trim(),
        "systemd"
    );
    let marker = "/etc/fenders-control-qualification";
    let metadata = fs::symlink_metadata(marker).unwrap();
    assert!(metadata.is_file());
    assert_eq!(metadata.uid(), 0);
    assert_eq!(metadata.mode() & 0o777, 0o600);
    assert_eq!(
        fs::read_to_string(marker).unwrap(),
        "disposable-control-plane-systemd-only\n"
    );
    for path in [
        CONFIG,
        STATE,
        "/etc/systemd/system/fenders-control-plane.service",
    ] {
        assert!(!Path::new(path).exists(), "refusing existing installation");
    }
    assert_eq!(property("LoadState"), "not-found");
    // The assembly creates only this empty database and peer-authenticated role.
    let dsn = "postgresql:///fenders_systemd?host=/var/run/postgresql&user=fenders-control";
    let count = command(
        "runuser",
        &[
            "-u",
            "postgres",
            "--",
            "psql",
            "-XAt",
            "-d",
            "fenders_systemd",
            "-c",
            "SELECT count(*) FROM pg_tables WHERE schemaname='public'",
        ],
    );
    assert_eq!(count, "0", "refusing populated qualification database");
    fs::create_dir_all("/etc/sysusers.d").unwrap();
    private("/etc/sysusers.d/fenders-control.conf", USER_TEXT.as_bytes());
    command(
        "systemd-sysusers",
        &["/etc/sysusers.d/fenders-control.conf"],
    );
    fs::create_dir_all(CONFIG).unwrap();
    pki::create(
        Path::new(CONFIG),
        &BTreeMap::from([
            ("control".into(), vec!["127.0.0.1".into()]),
            ("gateway".into(), vec!["*.apps.example.test".into()]),
        ]),
    )
    .unwrap();
    fs::set_permissions(CONFIG, fs::Permissions::from_mode(0o755)).unwrap();
    for name in ["ca.pem", "control.pem", "gateway.pem"] {
        fs::set_permissions(
            format!("{CONFIG}/{name}"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
    }
    private(&format!("{CONFIG}/database-url"), dsn.as_bytes());
    private(
        &format!("{CONFIG}/environment"),
        b"FENDERS_APP_DOMAIN=apps.example.test\nFENDERS_RUN_CHANNEL_ENDPOINT=https://127.0.0.1:9093\n",
    );
    private(
        &format!("{CONFIG}/external-network.json"),
        br#"{"allowed_cidrs":[],"denied_cidrs":[]}"#,
    );
    fs::set_permissions(
        format!("{CONFIG}/external-network.json"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    private(
        "/etc/systemd/system/fenders-control-plane.service",
        UNIT_TEXT.as_bytes(),
    );
    command(
        "systemd-analyze",
        &[
            "verify",
            "/etc/systemd/system/fenders-control-plane.service",
        ],
    );
    command("systemctl", &["daemon-reload"]);
    let _stop = Stop;
    command("systemctl", &["start", UNIT]);
    let deadline = Instant::now() + Duration::from_secs(45);
    let token = loop {
        if let Ok(value) = fs::read_to_string(format!("{STATE}/operator.token")) {
            break value;
        }
        assert!(Instant::now() < deadline, "no bootstrap credential");
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(2))
        .add_root_certificate(
            reqwest::Certificate::from_pem(&fs::read(format!("{CONFIG}/ca.pem")).unwrap()).unwrap(),
        )
        .build()
        .unwrap();
    let first = observe(&client, token.trim(), None).await;
    let first_pid = property("MainPID");
    let uid = command("id", &["-u", "fenders-control"]);
    let gid = command("id", &["-g", "fenders-control"]);
    assert_ne!(uid, "0");
    let process_status = fs::read_to_string(format!("/proc/{first_pid}/status")).unwrap();
    assert!(process_status.contains(&format!("Uid:\t{uid}\t{uid}\t{uid}\t{uid}")));
    assert!(process_status.contains("NoNewPrivs:\t1"));
    assert!(process_status.contains("CapEff:\t0000000000000000"));
    assert!(process_status.contains("CapBnd:\t0000000000000000"));
    assert!(process_status.contains("Seccomp:\t2"));
    assert_eq!(property("ProtectSystem"), "strict");
    let environment = fs::read(format!("/proc/{first_pid}/environ")).unwrap();
    assert!(!environment.windows(dsn.len()).any(|v| v == dsn.as_bytes()));
    assert!(
        !environment
            .windows(b"FENDERS_DATABASE_URL=".len())
            .any(|v| v == b"FENDERS_DATABASE_URL=")
    );
    let cmdline = fs::read(format!("/proc/{first_pid}/cmdline")).unwrap();
    assert!(!cmdline.windows(dsn.len()).any(|v| v == dsn.as_bytes()));
    let state = fs::metadata(STATE).unwrap();
    assert_eq!(state.uid().to_string(), uid);
    assert_eq!(state.mode() & 0o777, 0o700);
    // A DAC-writable directory is still read-only inside the service mount namespace.
    fs::create_dir("/opt/fenders-systemd-probe").unwrap();
    fs::set_permissions(
        "/opt/fenders-systemd-probe",
        fs::Permissions::from_mode(0o777),
    )
    .unwrap();
    let denied = output(
        "nsenter",
        &[
            "--target",
            &first_pid,
            "--mount",
            "--setuid",
            &uid,
            "--setgid",
            &gid,
            "touch",
            "/opt/fenders-systemd-probe/denied",
        ],
    );
    assert!(!denied.status.success());
    assert!(String::from_utf8_lossy(&denied.stderr).contains("Read-only file system"));
    command(
        "nsenter",
        &[
            "--target",
            &first_pid,
            "--mount",
            "--setuid",
            &uid,
            "--setgid",
            &gid,
            "touch",
            "/var/lib/fenders/control/allowed",
        ],
    );
    assert!(
        !output(
            "runuser",
            &[
                "-u",
                "fenders-control",
                "--",
                "test",
                "-r",
                "/etc/fenders/control/database-url"
            ]
        )
        .status
        .success()
    );
    command(
        "systemctl",
        &["kill", "--signal=SIGKILL", "--kill-whom=main", UNIT],
    );
    let restart_started = Instant::now();
    let restarted = observe(&client, token.trim(), Some(&first)).await;
    assert!(restart_started.elapsed() >= Duration::from_secs(4));
    assert_ne!(property("MainPID"), first_pid);
    assert_eq!(property("NRestarts"), "1");
    assert_eq!(
        fs::read_to_string(format!("{STATE}/operator.token")).unwrap(),
        token
    );
    // Reset while loaded: after a clean stop systemd may garbage-collect the unit.
    command("systemctl", &["reset-failed", UNIT]);
    command("systemctl", &["stop", UNIT]);
    assert_eq!(property("ExecMainStatus"), "0");
    assert_eq!(property("Result"), "success");
    tokio::time::sleep(Duration::from_secs(6)).await;
    assert_eq!(property("ActiveState"), "inactive");
    assert_eq!(property("MainPID"), "0");
    assert!(
        client
            .get("https://127.0.0.1:9090/v1/control-plane/status")
            .send()
            .await
            .is_err()
    );
    // Exercise the real configured 5 starts / 60 seconds, not an accelerated override.
    fs::write(format!("{CONFIG}/database-url"), b"\n").unwrap();
    command("systemctl", &["start", UNIT]);
    let deadline = Instant::now() + Duration::from_secs(40);
    while property("ActiveState") != "failed" || property("NRestarts") != "5" {
        assert!(
            Instant::now() < deadline,
            "restart limiter did not stop invalid startup"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert_eq!(property("ActiveState"), "failed");
    assert_eq!(property("MainPID"), "0");
    // systemd 257 retains Result=exit-code when limiting automatic restarts.
    // Verify actual attempts and refusal, rather than assuming a Result label.
    let limited_result = property("Result");
    assert!(matches!(
        limited_result.as_str(),
        "exit-code" | "start-limit-hit"
    ));
    let journal = command("journalctl", &["-u", UNIT, "--no-pager", "--output=cat"]);
    assert_eq!(
        journal
            .matches("database URL credential file is empty or contains NUL")
            .count(),
        5
    );
    assert!(journal.contains("Start request repeated too quickly."));
    assert!(!output("systemctl", &["start", UNIT]).status.success());
    let limited_restarts = property("NRestarts");
    tokio::time::sleep(Duration::from_secs(6)).await;
    assert_eq!(property("NRestarts"), limited_restarts);
    fs::write(format!("{CONFIG}/database-url"), dsn).unwrap();
    command("systemctl", &["reset-failed", UNIT]);
    command("systemctl", &["start", UNIT]);
    let recovered = observe(&client, token.trim(), Some(&restarted)).await;
    assert_eq!(
        fs::read_to_string(format!("{STATE}/operator.token")).unwrap(),
        token
    );
    command("systemctl", &["stop", UNIT]);
    assert_eq!(property("ExecMainStatus"), "0");
    let report = json!({
        "unit_sha256": digest(UNIT_TEXT),
        "kernel": command("uname", &["-r"]),
        "systemd": command("systemctl", &["--version"]).lines().next(),
        "first": first, "restarted": restarted, "recovered": recovered,
        "limited_restarts": limited_restarts,
        "limited_result": limited_result,
        "checks": ["verified TLS and four loops", "unprivileged UID and zero capabilities",
            "no-new-privileges and seccomp", "read-only system and writable private state",
            "credential absent from argv/environment", "SIGKILL restart with retained token",
            "SIGTERM clean stop without restart", "invalid startup rate-limited",
            "explicit repair and reset recovery"]
    });
    private(
        "/root/fenders-systemd-evidence.json",
        &serde_json::to_vec_pretty(&report).unwrap(),
    );
    println!("{}", serde_json::to_string_pretty(&report).unwrap());
}
