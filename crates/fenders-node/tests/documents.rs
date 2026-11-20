//! The documents an operator reads say what is there: the launcher's README
//! describes the launcher there is, and the status page names checks that
//! exist and says what a node is trusted with.

/// Every file under `directory` (relative to the repository), as one text.
fn sources(directory: &str) -> String {
    fn walk(path: &std::path::Path, text: &mut String) {
        for entry in std::fs::read_dir(path).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, text);
            } else if let Ok(file) = std::fs::read_to_string(&path) {
                text.push_str(&file);
            }
        }
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut text = String::new();
    walk(&root.join(directory), &mut text);
    text
}
/// The words of `text` that begin with `prefix` and go on in `more`.
fn named<'a>(text: &'a str, prefix: &str, more: impl Fn(char) -> bool) -> Vec<&'a str> {
    let mut found: Vec<&str> = text
        .match_indices(prefix)
        .map(|(start, _)| {
            let rest = &text[start..];
            &rest[..rest.find(|c| !more(c)).unwrap_or(rest.len())]
        })
        .collect();
    found.sort();
    found.dedup();
    found
}

#[test]
fn the_launchers_readme_describes_the_launcher_there_is() {
    let readme = include_str!("../../../runtime/README.md");
    // Every setting it names is one some source reads or sets, and every
    // launcher source file it names exists.
    let code = sources("runtime/native")
        + &sources("runtime/guest/src")
        + &sources("crates/fenders-guest-http/src")
        + &sources("crates/fenders-shim/src")
        + &sources("crates/fenders-node/src");
    let settings = named(readme, "FENDERS_", |c| {
        c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'
    });
    assert!(settings.len() > 10);
    for setting in settings {
        assert!(code.contains(setting), "{setting} is in no source");
    }
    let native = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../runtime/native");
    for file in readme
        .split('`')
        .filter(|word| word.ends_with(".inc") && !word.contains(' '))
    {
        assert!(native.join(file).is_file(), "{file} does not exist");
    }
    // The meter files, leases and start gate of earlier launchers appear
    // only where it says they are gone, as the launcher refuses them.
    for gone in ["FENDERS_EGRESS_FD", "FENDERS_EGRESS_PERIOD_FD"] {
        assert_eq!(readme.matches(gone).count(), 1, "{gone}");
    }
    assert!(readme.contains("are gone"));
    assert!(sources("runtime/native").contains("are no longer supported"));
    // And what the launcher now does is in it.
    for present in ["cpuid.inc", "guest_args.inc", "MSR filter"] {
        assert!(readme.contains(present), "{present}");
    }
}

#[test]
fn every_check_the_status_page_names_exists() {
    let status = include_str!("../../../docs/STATUS.md");
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let scripts = named(status, "scripts/", |c| {
        c.is_ascii_alphanumeric() || "_-./".contains(c)
    });
    assert!(scripts.len() > 10);
    for script in scripts {
        let script = script.trim_end_matches('.');
        assert!(root.join(script).is_file(), "{script} does not exist");
    }
}

#[test]
fn the_status_page_says_what_a_node_is_trusted_with() {
    // Any enrolled node may be given any workspace's upload to compile and
    // its verdict is taken. That is a decision, written down where an
    // operator reads the limits, beside what was done about it: uploads
    // are taken up in turn among workspaces.
    let status = include_str!("../../../docs/STATUS.md");
    let flat = status.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(flat.contains("Any enrolled node may be given any workspace's upload to compile"));
    assert!(flat.contains("a node is trusted with components as it is with secrets"));
    assert!(flat.contains("Compiles are taken up in turn among workspaces"));
}
