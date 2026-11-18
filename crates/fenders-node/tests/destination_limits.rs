//! A cgroup under `destinations::limit` reaches its listed destinations and
//! no other, shown with real sockets in a process moved into such a cgroup.
//!
//! Loading the programs takes root: without it the test says it skipped.
//! `scripts/verify_destinations_live.sh` runs it as root.
use std::io::ErrorKind::PermissionDenied;
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream, UdpSocket};

const CHILD: &str = "FENDERS_DESTINATION_LIMITS_CHILD";

fn main() {
    if let Ok(ports) = std::env::var(CHILD) {
        let ports: Vec<u16> = ports.split(',').map(|p| p.parse().unwrap()).collect();
        std::process::exit(limited(&ports));
    }
    if unsafe { libc::geteuid() } != 0 {
        println!("skipped: loading cgroup programs takes root");
        return;
    }
    // Two TCP listeners and two UDP sockets on loopback addresses: one of
    // each is the run's, the other something else on the host. The resolver
    // must be on port 53, which is the only datagram port a run has.
    let listed = TcpListener::bind("127.0.0.1:0").unwrap();
    let other = TcpListener::bind("127.0.0.1:0").unwrap();
    // The same port on another address: what Landlock alone cannot tell apart.
    let same_port = TcpListener::bind(("127.0.0.2", listed.local_addr().unwrap().port())).unwrap();
    let resolver = UdpSocket::bind("127.0.0.53:53")
        .or_else(|_| UdpSocket::bind("127.0.0.77:53"))
        .unwrap();
    let stray = UdpSocket::bind("127.0.0.78:53").unwrap();
    let resolver_ip = match resolver.local_addr().unwrap() {
        std::net::SocketAddr::V4(address) => *address.ip(),
        _ => unreachable!(),
    };
    let cgroup = std::path::PathBuf::from(format!(
        "/sys/fs/cgroup/fenders-destination-limits-{}",
        std::process::id()
    ));
    std::fs::create_dir(&cgroup).unwrap();
    let listed_address =
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, listed.local_addr().unwrap().port());
    fenders_node::destinations::limit(&cgroup, &[listed_address], Some(resolver_ip)).unwrap();
    let ports = format!(
        "{},{}",
        listed.local_addr().unwrap().port(),
        other.local_addr().unwrap().port()
    );
    let mut child = std::process::Command::new(std::env::current_exe().unwrap());
    child.env(CHILD, ports).env(
        "FENDERS_DESTINATION_LIMITS_RESOLVER",
        resolver_ip.to_string(),
    );
    use std::os::unix::process::CommandExt;
    let procs = cgroup.join("cgroup.procs");
    unsafe {
        child.pre_exec(move || std::fs::write(&procs, std::process::id().to_string()));
    }
    let status = child.status().unwrap();
    // What was allowed arrived; what was refused never did.
    resolver.set_nonblocking(true).unwrap();
    stray.set_nonblocking(true).unwrap();
    let mut buffer = [0; 16];
    let asked = resolver.recv(&mut buffer).map(|n| buffer[..n].to_vec());
    let strayed = stray.recv(&mut buffer).is_ok();
    drop(same_port);
    std::fs::remove_dir(&cgroup).unwrap();
    assert!(status.success(), "the limited process found a gap");
    assert_eq!(asked.unwrap(), b"ask");
    assert!(!strayed);
    // Outside the cgroup nothing changed.
    TcpStream::connect(other.local_addr().unwrap()).unwrap();
    println!("test result: ok. a limited cgroup reaches its destinations and no other");
}

/// In the limited cgroup: 0 when everything outside the list was refused.
fn limited(ports: &[u16]) -> i32 {
    let resolver: Ipv4Addr = std::env::var("FENDERS_DESTINATION_LIMITS_RESOLVER")
        .unwrap()
        .parse()
        .unwrap();
    let mut gaps = 0;
    let mut expect = |what: &str, refused: bool, wanted: bool| {
        if refused != wanted {
            eprintln!("{what}: {}", if refused { "refused" } else { "allowed" });
            gaps += 1;
        }
    };
    let denied = |r: std::io::Result<()>| matches!(r, Err(e) if e.kind() == PermissionDenied);
    let tcp = |address: (&str, u16)| denied(TcpStream::connect(address).map(drop));
    expect(
        "the listed address and port",
        tcp(("127.0.0.1", ports[0])),
        false,
    );
    expect(
        "the listed port on another address",
        tcp(("127.0.0.2", ports[0])),
        true,
    );
    expect(
        "another port on the listed address",
        tcp(("127.0.0.1", ports[1])),
        true,
    );
    expect("an IPv6 address", tcp(("::1", ports[0])), true);
    let udp = UdpSocket::bind("0.0.0.0:0").unwrap();
    let send = |address: (&str, u16)| denied(udp.send_to(b"ask", address).map(drop));
    expect(
        "a datagram to the resolver",
        send((&resolver.to_string(), 53)),
        false,
    );
    expect("a datagram elsewhere", send(("127.0.0.78", 53)), true);
    expect(
        "a datagram to the resolver's other ports",
        send((&resolver.to_string(), 5353)),
        true,
    );
    expect(
        "a datagram socket connected elsewhere",
        denied(
            UdpSocket::bind("0.0.0.0:0")
                .unwrap()
                .connect("127.0.0.78:53"),
        ),
        true,
    );
    expect(
        "a datagram socket connected to the resolver",
        denied(
            UdpSocket::bind("0.0.0.0:0")
                .unwrap()
                .connect((resolver, 53)),
        ),
        false,
    );
    if let Ok(six) = UdpSocket::bind("[::]:0") {
        expect(
            "an IPv6 datagram",
            denied(six.send_to(b"ask", "[::1]:53").map(drop)),
            true,
        );
    }
    gaps
}
