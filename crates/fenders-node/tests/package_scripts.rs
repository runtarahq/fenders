//! The worker package's pre-installation guard: a package is not changed
//! under runs that are still alive.
use std::process::Command;

const PREINST: &str = include_str!("../../../deploy/artifacts/worker/preinst");
const UNIT: &str = include_str!("../../../deploy/artifacts/worker/fenders-worker.service");

/// Runs the guard against `runs` as the cgroup root, without its question to
/// systemd about the service (there is none here).
fn guard(runs: &std::path::Path) -> bool {
    let start = PREINST.find("if [ -d /run/systemd/system ]").unwrap();
    let end = start + PREINST[start..].find("\nfi\n").unwrap() + 4;
    let script = format!("{}{}", &PREINST[..start], &PREINST[end..]);
    Command::new("sh")
        .args(["-c", &script])
        .env("FENDERS_RUN_CGROUP", runs)
        .output()
        .unwrap()
        .status
        .success()
}

#[test]
fn a_package_is_not_changed_while_runs_remain_in_the_agents_cgroup_root() {
    let root = tempfile::tempdir().unwrap();
    // No such cgroup: nothing was ever run here.
    assert!(guard(&root.path().join("absent")));
    let events = root.path().join("cgroup.events");
    std::fs::write(&events, "populated 0\nfrozen 0\n").unwrap();
    assert!(guard(root.path()));
    // A shim or a VMM is still in it.
    std::fs::write(&events, "populated 1\nfrozen 0\n").unwrap();
    assert!(!guard(root.path()));
}

#[test]
fn the_guard_looks_where_the_unit_puts_its_runs() {
    let root = UNIT
        .split_whitespace()
        .skip_while(|word| *word != "--cgroup-root")
        .nth(1)
        .unwrap();
    assert!(
        PREINST.contains(&format!("runs=${{FENDERS_RUN_CGROUP:-{root}}}")),
        "the unit runs under {root}"
    );
}
