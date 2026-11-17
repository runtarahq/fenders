#[cfg(target_os = "linux")]
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1)
    }
}
#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("compiler verification requires Linux");
    std::process::exit(1)
}
#[cfg(target_os = "linux")]
fn run() -> fenders_node_protocol::error::Result<()> {
    use fenders_node_protocol::{error::Error, model::digest};
    use std::{
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
    };
    let args: Vec<_> = std::env::args().collect();
    if let Some(result) = fenders_node::worker::dispatch(&args) {
        return result;
    }
    if args.len() < 4 {
        return Err(Error::invalid(
            "usage: fenders-compiler-test COMPILER DELEGATED_CGROUP COMPONENT...",
        ));
    }
    let root = tempfile::tempdir()?;
    let build = root.path().join("build");
    std::fs::create_dir(&build)?;
    // Copies, not symlinks: the node opens its build artifacts without following links.
    std::fs::copy(Path::new(&args[1]), build.join("compile"))?;
    // Trusted capability fixture only. No VMM is launched in this compiler test.
    std::fs::write(
        build.join("launch"),
        "#!/bin/sh\nprintf '{\"network_leases\":1,\"network_clock\":\"boottime\",\"network_start_gate\":true}\\n'\n",
    )?;
    std::fs::set_permissions(build.join("launch"), std::fs::Permissions::from_mode(0o700))?;
    std::fs::write(build.join("runtime.elf"), b"test fixture; never executed")?;
    let node = fenders_node::core::Node::new(
        &root.path().join("node"),
        &build,
        &PathBuf::from(&args[2]),
        1,
    )?;
    let mut results = Vec::new();
    for path in &args[3..] {
        let bytes = std::fs::read(path)?;
        let started = std::time::Instant::now();
        let result = node.upload(&bytes)?;
        let elapsed = started.elapsed().as_secs_f64() * 1000.0;
        if result["artifact"] != digest(&bytes)
            || result["compiled_bytes"].as_u64().unwrap_or(0) == 0
        {
            return Err(Error::internal());
        }
        if node.upload(&bytes)? != result {
            return Err(Error::internal());
        }
        results.push(serde_json::json!({"input":path,"result":result,"compile_ms":elapsed}));
    }
    if node.upload(b"\0asm\x0d\0\x01\0invalid").is_ok() {
        return Err(Error::internal());
    }
    let events = std::fs::read_to_string(node.compiler_cgroup.join("cgroup.events"))?;
    if !events.lines().any(|l| l == "populated 0") {
        return Err(Error::internal());
    }
    let resource_build = root.path().join("resource-build");
    std::fs::create_dir(&resource_build)?;
    std::fs::write(
        resource_build.join("probe.c"),
        include_str!("../../../../node/compiler_resource_test.c"),
    )?;
    let status = std::process::Command::new("cc")
        .args(["-pthread", "-O2", "-Wall", "-Wextra", "-Werror"])
        .arg(resource_build.join("probe.c"))
        .arg("-o")
        .arg(resource_build.join("compile"))
        .status()?;
    if !status.success() {
        return Err(Error::internal());
    }
    std::fs::copy(build.join("launch"), resource_build.join("launch"))?;
    std::fs::write(resource_build.join("runtime.elf"), b"unused fixture")?;
    let limited = fenders_node::core::Node::new(
        &root.path().join("limits"),
        &resource_build,
        &PathBuf::from(&args[2]),
        1,
    )?;
    // Reduce only this private test cgroup; production compiler limit remains 1 GiB.
    std::fs::write(limited.compiler_cgroup.join("memory.max"), "67108864")?;
    for marker in *b"PC" {
        // The native resource probe runs under confinement but deliberately does
        // not emit a valid WASM inspection; its output must never enter the cache.
        let result = limited.upload(&[b"\0asm\x0d\0\x01\0".as_slice(), &[marker]].concat());
        if result.err().is_none_or(|e| e.status.as_u16() != 422) {
            return Err(Error::internal());
        }
    }
    // Killed by the cgroup's memory limit: a compiler that does not exit with
    // a rejection receipt is unavailable, not a verdict on the component.
    if limited
        .upload(b"\0asm\x0d\0\x01\0M")
        .err()
        .is_none_or(|e| e.status.as_u16() != 503)
    {
        return Err(Error::internal());
    }
    let mut metrics = serde_json::Map::new();
    for (file, field) in [
        ("memory.events", "oom_kill"),
        ("pids.events", "max"),
        ("cpu.stat", "nr_throttled"),
        ("cgroup.events", "populated"),
    ] {
        let contents = std::fs::read_to_string(limited.compiler_cgroup.join(file))?;
        let value = contents
            .lines()
            .find_map(|l| {
                l.strip_prefix(&format!("{field} "))
                    .and_then(|n| n.parse::<u64>().ok())
            })
            .ok_or_else(Error::internal)?;
        if (field == "populated" && value != 0) || (field != "populated" && value == 0) {
            return Err(Error::internal());
        }
        metrics.insert(file.into(), serde_json::json!(contents));
    }
    std::fs::remove_dir(&limited.compiler_cgroup)?;
    let ceilings = time_ceilings(root.path(), &build, Path::new(&args[2]), &node)?;
    std::fs::remove_dir(&node.compiler_cgroup)?;
    println!(
        "{}",
        serde_json::json!({"resource_tests":metrics,"test_memory_mib":64,"passed":true})
    );
    println!("{ceilings}");
    println!(
        "{}",
        serde_json::json!
({"passed":true,"compiler":results,"cgroup_events":events,"kvm_execution":false})
    );
    Ok(())
}

/// A component whose compile takes over ten seconds of CPU: every function
/// keeps a thousand values live through five thousand dependent operations,
/// none of which constant-fold.
#[cfg(target_os = "linux")]
fn slow_compile() -> fenders_node_protocol::error::Result<Vec<u8>> {
    use std::fmt::Write;
    const FUNCTIONS: usize = 40;
    const LOCALS: usize = 1000;
    const OPERATIONS: usize = 5000;
    let mut source =
        String::from("(component (core module $slow (global $g (mut i32) (i32.const 1))");
    for f in 0..FUNCTIONS {
        let _ = write!(
            source,
            "(func (export \"f{f}\") (param i32) (result i32) (local"
        );
        source.push_str(&" i32".repeat(LOCALS));
        source.push(')');
        for k in 0..LOCALS {
            let seed = (k as u64 * 2_654_435_761) % (1 << 31);
            let _ = write!(
                source,
                " global.get $g i32.const {seed} i32.mul local.set {}",
                k + 1
            );
        }
        for i in 0..OPERATIONS {
            let a = 1 + (i * 7919 + f) % LOCALS;
            let b = 1 + (i * 104_729 + 3) % LOCALS;
            let c = 1 + (i * 31 + f * 17) % LOCALS;
            let op = ["i32.add", "i32.mul", "i32.xor", "i32.sub"][i % 4];
            let _ = write!(source, " local.get {a} local.get {b} {op} local.set {c}");
        }
        source.push_str(" local.get 1");
        for k in 2..=LOCALS {
            let _ = write!(source, " local.get {k} i32.add");
        }
        source.push(')');
    }
    source.push_str(
        r#"(func (export "run") (result i32) i32.const 0))
  (core instance $runner (instantiate $slow))
  (func $run (result (result)) (canon lift (core func $runner "run")))
  (instance $cli (export "run" (func $run)))
  (export "wasi:cli/run@0.2.0" (instance $cli)))"#,
    );
    wat::parse_str(&source)
        .map_err(|_| fenders_node_protocol::error::Error::invalid("invalid slow-compile fixture"))
}

/// The compiler's CPU-time and wall-clock ceilings each stop a compile that
/// the default ceilings let finish.
#[cfg(target_os = "linux")]
fn time_ceilings(
    root: &std::path::Path,
    build: &std::path::Path,
    cgroups: &std::path::Path,
    defaults: &fenders_node::core::Node,
) -> fenders_node_protocol::error::Result<serde_json::Value> {
    use fenders_node::core::{CompilerLimits, Node};
    use fenders_node_protocol::error::Error;
    use std::time::Instant;
    let slow = slow_compile()?;
    let cpu_used = |node: &Node| -> fenders_node_protocol::error::Result<f64> {
        let stat = std::fs::read_to_string(node.compiler_cgroup.join("cpu.stat"))?;
        stat.lines()
            .find_map(|l| l.strip_prefix("usage_usec ")?.parse::<f64>().ok())
            .map(|usec| usec / 1e6)
            .ok_or_else(Error::internal)
    };
    let started = Instant::now();
    let compiled = defaults.upload(&slow)?;
    let control = serde_json::json!({"compile_s":started.elapsed().as_secs_f64(),"compiled_bytes":compiled["compiled_bytes"]});

    let mut stopped = Vec::new();
    for (name, limits) in [
        (
            "cpu-time",
            CompilerLimits {
                cpu_seconds: 5,
                wall_seconds: 3600,
                ..CompilerLimits::default()
            },
        ),
        (
            "wall-clock",
            CompilerLimits {
                cpu_percent: 10,
                cpu_seconds: 3600,
                wall_seconds: 5,
                ..CompilerLimits::default()
            },
        ),
    ] {
        let node = Node::new(&root.join(name), build, cgroups, 1)?.with_compiler_limits(limits)?;
        let started = Instant::now();
        let refused = node.upload(&slow).err().map(|e| e.status.as_u16());
        let elapsed = started.elapsed().as_secs_f64();
        let cpu = cpu_used(&node)?;
        std::fs::remove_dir(&node.compiler_cgroup)?;
        // Each limit, and only it, ends the compile at about five seconds:
        // CPU time near five with no wall deadline in reach, or wall time
        // near five with the CPU throttled to a tenth.
        let bound = match name {
            "cpu-time" => (4.5..7.0).contains(&cpu) && elapsed < 60.0,
            _ => (5.0..8.0).contains(&elapsed) && cpu < 2.0,
        };
        if refused != Some(503) || !bound {
            eprintln!(
                "{name} ceiling: refused {refused:?}, {elapsed:.2} s elapsed, {cpu:.2} s CPU"
            );
            return Err(Error::internal());
        }
        stopped.push(
            serde_json::json!({"ceiling":name,"refused":refused,"elapsed_s":elapsed,"cpu_s":cpu}),
        );
    }
    Ok(
        serde_json::json!({"time_ceilings":stopped,"default_ceilings_compile":control,"fixture_bytes":slow.len(),"passed":true}),
    )
}
