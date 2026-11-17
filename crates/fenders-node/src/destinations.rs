//! A run's outbound destinations, held by the kernel.
//!
//! The launcher checks every connection a guest asks for against the launch
//! spec's addresses. Landlock, its backstop, knows port numbers only, and
//! nothing of datagrams: a launcher that had been taken over could connect
//! to any host on a listed port, and send datagrams anywhere. [`limit`]
//! attaches programs to the VM's cgroup that let its processes connect a
//! TCP socket to the listed address and port pairs, connect or send a UDP
//! socket to the resolver's port 53, and nothing else, IPv6 included. They
//! stay for as long as the cgroup does and are not the launcher's to remove:
//! it has no `bpf` call, and no privilege.
//!
//! Loading them takes root. A shim that is not root (a developer's own run)
//! has the launcher's check and Landlock's ports, as before.
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;

/// `struct bpf_insn`.
#[repr(C)]
#[derive(Clone, Copy)]
struct Insn {
    code: u8,
    registers: u8,
    offset: i16,
    immediate: i32,
}
const fn insn(code: u8, dst: u8, src: u8, offset: i16, immediate: i32) -> Insn {
    Insn {
        code,
        registers: dst | src << 4,
        offset,
        immediate,
    }
}
/// `r[dst] = *(u32 *)(r1 + offset)`: a field of `struct bpf_sock_addr`.
const fn field(dst: u8, offset: i16) -> Insn {
    insn(0x61, dst, 1, offset, 0)
}
/// Skip `skip` instructions unless the low 32 bits of `r[dst]` are `value`.
const fn unless(dst: u8, value: u32, skip: i16) -> Insn {
    insn(0x56, dst, 0, skip, value as i32)
}
const fn answer(allowed: bool) -> [Insn; 2] {
    [insn(0xb7, 0, 0, 0, allowed as i32), insn(0x95, 0, 0, 0, 0)]
}
// Offsets in `struct bpf_sock_addr` (linux/bpf.h).
const USER_IP4: i16 = 4;
const USER_PORT: i16 = 24;
const TYPE: i16 = 32;
const STREAM: u32 = 1;
const DATAGRAM: u32 = 2;

/// The program: allow a socket of `kind` to `address`, for each pair; refuse
/// the rest.
fn program(allowed: &[(u32, SocketAddrV4)]) -> Vec<Insn> {
    let mut code = vec![field(2, TYPE), field(3, USER_IP4), field(4, USER_PORT)];
    for (kind, address) in allowed {
        // Both fields are in network byte order, as the address is in memory.
        let ip = u32::from_ne_bytes(address.ip().octets());
        let port = u16::from_ne_bytes(address.port().to_be_bytes()) as u32;
        code.extend([unless(2, *kind, 4), unless(3, ip, 3), unless(4, port, 2)]);
        code.extend(answer(true));
    }
    code.extend(answer(false));
    code
}

const PROG_LOAD: libc::c_long = 5;
const PROG_ATTACH: libc::c_long = 8;
const CGROUP_SOCK_ADDR: u32 = 18;
const INET4_CONNECT: u32 = 10;
const INET6_CONNECT: u32 = 11;
const UDP4_SENDMSG: u32 = 14;
const UDP6_SENDMSG: u32 = 15;

fn bpf(command: libc::c_long, attr: &[u8; 128]) -> std::io::Result<i32> {
    match unsafe { libc::syscall(libc::SYS_bpf, command, attr.as_ptr(), attr.len()) } {
        -1 => Err(std::io::Error::last_os_error()),
        value => Ok(value as i32),
    }
}
fn load(code: &[Insn], attach: u32) -> std::io::Result<OwnedFd> {
    // `union bpf_attr` for BPF_PROG_LOAD: the fields used, the rest zero.
    let mut attr = [0u8; 128];
    attr[0..4].copy_from_slice(&CGROUP_SOCK_ADDR.to_ne_bytes());
    attr[4..8].copy_from_slice(&(code.len() as u32).to_ne_bytes());
    attr[8..16].copy_from_slice(&(code.as_ptr() as u64).to_ne_bytes());
    attr[16..24].copy_from_slice(&(c"GPL".as_ptr() as u64).to_ne_bytes());
    attr[68..72].copy_from_slice(&attach.to_ne_bytes());
    bpf(PROG_LOAD, &attr).map(|fd| unsafe { OwnedFd::from_raw_fd(fd) })
}

/// From now on, a process in `cgroup` connects a TCP socket only to one of
/// `tcp`, reaches `resolver`'s port 53 alone with a UDP socket, and has no
/// IPv6 destination at all.
pub fn limit(
    cgroup: &Path,
    tcp: &[SocketAddrV4],
    resolver: Option<Ipv4Addr>,
) -> std::io::Result<()> {
    let directory = std::fs::File::open(cgroup)?;
    let resolver = resolver.map(|ip| (DATAGRAM, SocketAddrV4::new(ip, 53)));
    let connect: Vec<_> = tcp
        .iter()
        .map(|address| (STREAM, *address))
        .chain(resolver)
        .collect();
    let send: Vec<_> = resolver.into_iter().collect();
    for (code, attach) in [
        (program(&connect), INET4_CONNECT),
        (program(&send), UDP4_SENDMSG),
        (answer(false).to_vec(), INET6_CONNECT),
        (answer(false).to_vec(), UDP6_SENDMSG),
    ] {
        let loaded = load(&code, attach)?;
        // BPF_PROG_ATTACH: target_fd, attach_bpf_fd, attach_type.
        let mut attr = [0u8; 128];
        attr[0..4].copy_from_slice(&directory.as_raw_fd().to_ne_bytes());
        attr[4..8].copy_from_slice(&loaded.as_raw_fd().to_ne_bytes());
        attr[8..12].copy_from_slice(&attach.to_ne_bytes());
        bpf(PROG_ATTACH, &attr)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_program_allows_each_pair_and_ends_refusing() {
        let code = program(&[
            (STREAM, "192.0.2.7:443".parse().unwrap()),
            (DATAGRAM, "10.0.0.2:53".parse().unwrap()),
        ]);
        assert_eq!(code.len(), 3 + 2 * 5 + 2);
        // The address and port as they sit in memory, high bit and all.
        assert_eq!(code[4].immediate as u32, u32::from_ne_bytes([192, 0, 2, 7]));
        assert_eq!(
            code[5].immediate as u32,
            u16::from_ne_bytes([1, 187]) as u32
        );
        // A mismatch skips to the next pair; the last falls to the refusal.
        assert_eq!((code[3].offset, code[4].offset, code[5].offset), (4, 3, 2));
        assert_eq!((code[6].immediate, code[11].immediate), (1, 1));
        assert_eq!((code[13].immediate, code[14].code), (0, 0x95));
        assert_eq!(program(&[]).len(), 5);
    }
}
