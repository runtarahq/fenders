//! What a run's shim can and cannot do once it is confined
//! (`confinement::apply_shim`), shown in a process of its own: this test has
//! no harness, because confinement is applied by a single-threaded process.
//!
//! Skipped, saying so, on a kernel without Landlock ABI 6.
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

const CHILD: &str = "FENDERS_SHIM_CONFINEMENT_CHILD";

fn main() {
    if let Ok(ports) = std::env::var(CHILD) {
        let mut ports = ports.split(',').map(|port| port.parse::<u16>().unwrap());
        std::process::exit(confined(ports.next().unwrap(), ports.next().unwrap()));
    }
    if fenders_node::confinement::abi().is_err() {
        println!("skipped: Landlock ABI 6 is not available on this kernel");
        return;
    }
    // Two listeners: the shim's run channel, and something else on the host.
    let channel = TcpListener::bind("127.0.0.1:0").unwrap();
    let other = TcpListener::bind("127.0.0.1:0").unwrap();
    let ports = format!(
        "{},{}",
        channel.local_addr().unwrap().port(),
        other.local_addr().unwrap().port()
    );
    let scratch = tempfile::tempdir().unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .env(CHILD, ports)
        .env("FENDERS_SHIM_CONFINEMENT_SCRATCH", scratch.path())
        .output()
        .unwrap();
    print!("{}", String::from_utf8_lossy(&output.stdout));
    eprint!("{}", String::from_utf8_lossy(&output.stderr));
    assert!(output.status.success(), "the confined process found a gap");
    // Nothing was left behind.
    assert_eq!(std::fs::read_dir(scratch.path()).unwrap().count(), 0);
    println!("test result: ok. the shim's confinement holds");
}

/// Runs confined, as a shim does after it has started its VMM. 0 when
/// everything a shim needs works and everything it is refused fails.
fn confined(channel: u16, other: u16) -> i32 {
    let scratch = std::env::var("FENDERS_SHIM_CONFINEMENT_SCRATCH").unwrap();
    // A descriptor it already holds stays usable: its VMM's pipes are such.
    let (mut held_read, mut held_write) = std::io::pipe().unwrap();
    // A child started before confinement, as the VMM is.
    let mut earlier = std::process::Command::new("/bin/sleep")
        .arg("60")
        .spawn()
        .unwrap();
    if let Err(error) = fenders_node::confinement::apply_shim(&[channel]) {
        eprintln!("confinement was not applied: {}", error.message);
        let _ = earlier.kill();
        let _ = earlier.wait();
        return 2;
    }
    let mut gaps = Vec::new();
    let mut expect = |what: &str, held: bool| {
        if !held {
            gaps.push(what.to_owned());
        }
    };
    let errno = || std::io::Error::last_os_error().raw_os_error().unwrap_or(0);

    // What it needs.
    expect("reading a file", std::fs::read("/proc/self/status").is_ok());
    expect(
        "listing a directory",
        std::fs::read_dir("/proc/self").is_ok(),
    );
    expect(
        "connecting to its run channel",
        TcpStream::connect(("127.0.0.1", channel)).is_ok(),
    );
    expect(
        "a descriptor it held",
        held_write.write_all(b"x").is_ok() && held_read.read(&mut [0u8; 1]).is_ok_and(|n| n == 1),
    );
    expect(
        "starting a thread",
        std::thread::spawn(|| 7).join().is_ok_and(|n| n == 7),
    );
    expect(
        "a Unix socket pair",
        std::os::unix::net::UnixStream::pair().is_ok(),
    );
    expect(
        "a UDP socket",
        std::net::UdpSocket::bind("127.0.0.1:0").is_ok(),
    );
    expect("ending the child it started", earlier.kill().is_ok());
    expect("reaping it", earlier.wait().is_ok());

    // What it is refused.
    expect(
        "connecting to another port",
        TcpStream::connect(("127.0.0.1", other)).is_err(),
    );
    expect("listening", TcpListener::bind("127.0.0.1:0").is_err());
    for path in [
        format!("{scratch}/left-behind"),
        "/dev/shm/fenders-left-behind".into(),
    ] {
        expect(
            &format!("creating {path}"),
            std::fs::File::create(&path).is_err(),
        );
    }
    expect(
        "creating a directory",
        std::fs::create_dir(format!("{scratch}/directory")).is_err(),
    );
    expect(
        "opening a file for writing",
        std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/null")
            .is_err(),
    );
    expect(
        "running a program",
        std::process::Command::new("/bin/true").status().is_err(),
    );
    unsafe {
        expect(
            "a packet socket",
            libc::socket(libc::AF_PACKET, libc::SOCK_RAW, 0) < 0 && errno() == libc::EPERM,
        );
        expect(
            "a netlink socket other than routing",
            libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_AUDIT) < 0
                && errno() == libc::EPERM,
        );
        let routing = libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE);
        expect("netlink routing, for the resolver", routing >= 0);
        expect(
            "a new namespace",
            libc::unshare(libc::CLONE_NEWUSER) < 0 && errno() == libc::EPERM,
        );
        expect(
            "tracing a process",
            libc::ptrace(libc::PTRACE_ATTACH, libc::getppid(), 0, 0) < 0 && errno() == libc::EPERM,
        );
        expect(
            "shared memory that outlives it",
            libc::shmget(libc::IPC_PRIVATE, 4096, libc::IPC_CREAT | 0o600) < 0
                && errno() == libc::EPERM,
        );
        expect(
            "changing its uid",
            libc::setuid(libc::getuid()) < 0 && errno() == libc::EPERM,
        );
        expect(
            "privileges of a setuid program",
            libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1,
        );
    }
    for gap in &gaps {
        eprintln!("not as confined: {gap}");
    }
    i32::from(!gaps.is_empty())
}
