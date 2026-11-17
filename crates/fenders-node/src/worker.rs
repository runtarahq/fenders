use crate::confinement;
use fenders_node_protocol::error::{Error, Result};
use std::{
    fs,
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::Command,
};
pub fn dispatch(args: &[String]) -> Option<Result<()>> {
    match args.get(1).map(String::as_str) {
        Some("confinement-probe") => Some(confinement::probe().map(|v| println!("{v}"))),
        Some("compile-worker") => Some(compile(&args[2..])),
        _ => None,
    }
}
fn limit(resource: libc::__rlimit_resource_t, value: u64) -> Result<()> {
    let limit = libc::rlimit {
        rlim_cur: value,
        rlim_max: value,
    };
    if unsafe { libc::setrlimit(resource, &limit) } != 0 {
        return Err(Error::internal());
    }
    Ok(())
}
fn parent_death() -> Result<()> {
    unsafe {
        let parent = libc::getppid();
        if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0
            || parent == 1
            || libc::getppid() != parent
        {
            return Err(Error::internal());
        }
    }
    Ok(())
}
pub fn compile(args: &[String]) -> Result<()> {
    if args.len() != 5 {
        return Err(Error::invalid(
            "compile-worker requires cgroup, compiler, input, output and inspection",
        ));
    }
    parent_death()?;
    fs::write(
        Path::new(&args[0]).join("cgroup.procs"),
        std::process::id().to_string(),
    )?;
    // The node passes its configured ceilings; a direct invocation keeps the defaults.
    let setting = |name: &str, default: u64, high: u64| -> Result<u64> {
        match std::env::var(name) {
            Ok(value) => value
                .parse()
                .ok()
                .filter(|n| (1..=high).contains(n))
                .ok_or_else(|| Error::invalid("invalid compiler limit")),
            Err(_) => Ok(default),
        }
    };
    limit(
        libc::RLIMIT_AS,
        setting("FENDERS_COMPILER_ADDRESS_MIB", 1536, 16_896)? * 1024 * 1024,
    )?;
    limit(
        libc::RLIMIT_CPU,
        setting("FENDERS_COMPILER_CPU_SECONDS", 45, 3600)?,
    )?;
    limit(libc::RLIMIT_FSIZE, 128 * 1024 * 1024)?;
    limit(libc::RLIMIT_NOFILE, 64)?;
    limit(libc::RLIMIT_CORE, 0)?;
    let mut reads = vec![PathBuf::from(&args[2])];
    let mut writes = vec![PathBuf::from(&args[3]), PathBuf::from(&args[4])];
    // The node's compile cache for this compile: its scope's store, read-only,
    // and the record files the node merges after the compile.
    if let Some(store) = std::env::var_os("FENDERS_COMPILE_CACHE") {
        reads.push(PathBuf::from(store));
        for var in [
            "FENDERS_COMPILE_CACHE_INSPECTION",
            "FENDERS_COMPILE_CACHE_CODE",
        ] {
            writes.push(
                std::env::var_os(var)
                    .map(PathBuf::from)
                    .ok_or_else(|| Error::invalid("compile cache requires its record files"))?,
            );
        }
    }
    confinement::apply(
        "compiler",
        Path::new(&args[1]),
        &reads,
        &writes,
        &[],
        false,
        false,
    )?;
    Err(Command::new(&args[1]).args(&args[2..]).exec().into())
}
