#[cfg(target_os = "linux")]
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1)
    }
}
#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("confinement verification requires Linux");
    std::process::exit(1)
}
#[cfg(target_os = "linux")]
fn run() -> fenders_node_protocol::error::Result<()> {
    use fenders_node_protocol::error::Error;
    use std::{
        os::unix::process::CommandExt,
        path::{Path, PathBuf},
        process::Command,
    };
    let args: Vec<_> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("child") {
        let profile = &args[2];
        let binary = Path::new(&args[3]);
        let source = PathBuf::from(&args[4]);
        let output = PathBuf::from(&args[6]);
        let port = args[9]
            .parse::<u16>()
            .map_err(|_| Error::invalid("invalid port"))?;
        fenders_node::confinement::apply(
            profile,
            binary,
            &[source],
            if profile == "compiler" {
                std::slice::from_ref(&output)
            } else {
                &[]
            },
            if profile == "vmm" {
                std::slice::from_ref(&port)
            } else {
                &[]
            },
            false,
            false,
        )?;
        return Err(Command::new(binary)
            .arg(profile)
            .args(&args[4..])
            .exec()
            .into());
    }
    let root = tempfile::tempdir()?;
    let binary = root.path().join("check");
    let source = root.path().join("check.c");
    std::fs::write(&source, include_str!("../../../../node/confinement_test.c"))?;
    if !Command::new("cc")
        .args(["-pthread", "-O2", "-Wall", "-Wextra", "-Werror"])
        .arg(&source)
        .arg("-o")
        .arg(&binary)
        .status()?
        .success()
    {
        return Err(Error::internal());
    }
    let input = root.path().join("input");
    let secret = root.path().join("secret");
    let output = root.path().join("output");
    let forbidden = root.path().join("escape");
    std::fs::write(&input, b"test")?;
    std::fs::write(&secret, b"host-secret")?;
    std::fs::write(&output, b"")?;
    let allowed = std::net::TcpListener::bind("127.0.0.1:0")?;
    let denied = std::net::TcpListener::bind("127.0.0.1:0")?;
    for profile in ["compiler", "vmm"] {
        let result = Command::new(std::env::current_exe()?)
            .arg("child")
            .arg(profile)
            .arg(&binary)
            .arg(&input)
            .arg(&secret)
            .arg(&output)
            .arg(&forbidden)
            .arg(std::process::id().to_string())
            .arg(allowed.local_addr()?.port().to_string())
            .arg(denied.local_addr()?.port().to_string())
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .status()?;
        if !result.success() {
            return Err(Error::internal());
        }
    }
    if std::fs::read(output)? != b"compiled"
        || std::fs::read(input)? != b"test"
        || std::fs::read(secret)? != b"host-secret"
        || forbidden.exists()
    {
        return Err(Error::internal());
    }
    println!(
        "{}",
        serde_json::json!({"passed":true,"profiles":["compiler","vmm"],"landlock_abi":fenders_node::confinement::abi()?,"wasmtime_compilation":false,"kvm_execution":false})
    );
    Ok(())
}
