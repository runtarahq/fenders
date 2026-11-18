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

#[test]
fn the_worker_unit_takes_away_what_the_agent_has_no_use_for() {
    let directives: Vec<&str> = UNIT.lines().map(str::trim).collect();
    for wanted in [
        "NoNewPrivileges=yes",
        "ProtectHome=yes",
        "ProtectKernelModules=yes",
        "ProtectKernelLogs=yes",
        "ProtectHostname=yes",
        "RestrictSUIDSGID=yes",
        "RestrictRealtime=yes",
        "LockPersonality=yes",
        "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK",
        "UMask=0077",
        "LimitCORE=0",
    ] {
        assert!(directives.contains(&wanted), "{wanted}");
    }
    // And not what it needs: its runs' cgroups, /dev/kvm, its capabilities.
    for kept in [
        "ProtectControlGroups",
        "PrivateDevices",
        "CapabilityBoundingSet",
        "ProtectKernelTunables",
    ] {
        assert!(!directives.iter().any(|d| d.starts_with(kept)), "{kept}");
    }
    // An operator's own flags reach the node.
    assert!(UNIT.contains("$FENDERS_NODE_OPTIONS"));
}

#[test]
fn ci_names_its_actions_by_commit_and_checks_advisories() {
    let ci = include_str!("../../../.github/workflows/ci.yml");
    let uses: Vec<&str> = ci
        .lines()
        .filter_map(|line| line.trim().strip_prefix("- uses: "))
        .collect();
    assert!(!uses.is_empty());
    for action in uses {
        let reference = action
            .split_once('@')
            .unwrap()
            .1
            .split_whitespace()
            .next()
            .unwrap();
        assert!(
            reference.len() == 40 && reference.bytes().all(|b| b.is_ascii_hexdigit()),
            "{action} is not named by a commit"
        );
    }
    assert!(ci.contains("cargo audit --file"));
    assert!(ci.contains("schedule:"));
}

/// The version and source of `name` in the workspace lockfile.
fn locked(name: &str) -> Vec<(String, bool)> {
    let lock = include_str!("../../../Cargo.lock");
    lock.split("[[package]]")
        .filter(|package| package.contains(&format!("\nname = \"{name}\"\n")))
        .map(|package| {
            let version = package.split("version = \"").nth(1).unwrap();
            (
                version[..version.find('"').unwrap()].to_owned(),
                package.contains("\nsource = "),
            )
        })
        .collect()
}
fn at_least(version: &str, wanted: [u64; 3]) -> bool {
    let parts: Vec<u64> = version.split('.').map(|p| p.parse().unwrap()).collect();
    parts.as_slice() >= wanted.as_slice()
}

#[test]
fn the_lockfile_holds_no_release_with_an_advisory_this_audit_found() {
    // Each is in the lockfile, at or past the release that fixed it.
    for (name, fixed) in [
        ("wasmtime", [50, 0, 1]),
        ("rustls", [0, 23, 46]),
        ("libsqlite3-sys", [0, 39, 0]),
    ] {
        let found = locked(name);
        assert!(!found.is_empty(), "{name}");
        for (version, _) in found {
            assert!(at_least(&version, fixed), "{name} {version}");
        }
    }
    // SQLx's SQLite and MySQL drivers, never built here, are empty crates
    // from the workspace's own tree: the first would hold SQLite back, the
    // second lists `rsa`.
    for name in ["sqlx-sqlite", "sqlx-mysql"] {
        assert_eq!(
            locked(name)
                .iter()
                .map(|(_, registry)| *registry)
                .collect::<Vec<_>>(),
            [false],
            "{name}"
        );
    }
    // What only signing people in and mailing them needed is not built at
    // all: an identity-provider client, an SMTP client, and the RSA under
    // the first.
    for gone in ["openidconnect", "lettre", "rsa", "oauth2", "crypto-bigint"] {
        assert!(locked(gone).is_empty(), "{gone}");
    }
    // Nothing is listed as an advisory that cannot be acted on.
    let listed = include_str!("../../../.cargo/audit.toml");
    assert!(listed.lines().any(|line| line.trim() == "ignore = []"));
}

#[test]
fn the_launcher_is_built_with_its_hardening_named() {
    let build = include_str!("../../../scripts/build_node.sh");
    let line = build
        .lines()
        .skip_while(|line| !line.starts_with("cc "))
        .take(2)
        .collect::<String>();
    for flag in [
        "-fstack-protector-strong",
        "-D_FORTIFY_SOURCE=2",
        "-fPIE",
        "-pie",
        "-z,relro,-z,now,-z,noexecstack",
        "-Werror",
    ] {
        assert!(line.contains(flag), "{flag}");
    }
}
