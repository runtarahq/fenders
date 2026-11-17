//! Preserve the RPC listening socket outside the replaceable agent process.
//! Ownership/authentication of requests remains with the ordinary pinned mTLS server.
use fenders_node_protocol::error::{Error, Result};
use std::{
    net::{IpAddr, SocketAddr, TcpListener},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

fn select_descriptor(
    explicit: Option<i32>,
    owner: Option<&str>,
    count: Option<&str>,
    pid: u32,
) -> Result<Option<i32>> {
    if explicit.is_some_and(|fd| fd < 3) {
        return Err(Error::invalid("RPC listener descriptor must be at least 3"));
    }
    if let Some(owner) = owner {
        let owner: u32 = owner
            .parse()
            .map_err(|_| Error::invalid("invalid socket activation owner"))?;
        if owner != pid {
            return if explicit.is_none() {
                Ok(None)
            } else {
                Err(Error::invalid(
                    "socket activation belongs to another process",
                ))
            };
        }
        if count != Some("1") || explicit.is_some_and(|fd| fd != 3) {
            return Err(Error::invalid(
                "node requires exactly one inherited RPC listener",
            ));
        }
        return Ok(Some(3));
    }
    if count.is_some() {
        return Err(Error::invalid("socket activation owner missing"));
    }
    Ok(explicit)
}

pub fn descriptor(explicit: Option<i32>) -> Result<Option<i32>> {
    let read = |key| match std::env::var(key) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(_) => Err(Error::invalid("invalid socket activation environment")),
    };
    let owner = read("LISTEN_PID")?;
    let count = read("LISTEN_FDS")?;
    select_descriptor(
        explicit,
        owner.as_deref(),
        count.as_deref(),
        std::process::id(),
    )
}

#[cfg(target_os = "linux")]
fn socket_option(fd: i32, option: i32) -> Result<i32> {
    let mut value: libc::c_int = 0;
    let mut length = std::mem::size_of_val(&value) as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            option,
            (&mut value as *mut libc::c_int).cast(),
            &mut length,
        )
    } != 0
    {
        return Err(Error::invalid(
            "inherited RPC descriptor is not a listening TCP socket",
        ));
    }
    Ok(value)
}

#[cfg(target_os = "linux")]
fn validate_listener(fd: i32) -> Result<()> {
    if socket_option(fd, libc::SO_TYPE)? != libc::SOCK_STREAM
        || socket_option(fd, libc::SO_ACCEPTCONN)? != 1
    {
        return Err(Error::invalid(
            "inherited RPC descriptor is not a listening TCP socket",
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn validate_listener(_fd: i32) -> Result<()> {
    Err(Error::invalid("RPC socket activation requires Linux"))
}

/// Adopt an OS-supplied descriptor before node initialization or runtime threads.
///
/// # Safety
/// The caller must transfer exclusive Rust ownership of the descriptor, with no
/// other Rust object or thread able to close/reuse it. This is the fresh-exec
/// socket-activation contract. An open descriptor is consumed even on failure.
pub unsafe fn take_listener(fd: i32, host: &str, port: u16) -> Result<TcpListener> {
    if fd < 3 || unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
        return Err(Error::invalid("inherited RPC listener is not open"));
    }
    // Open-ness and exclusive ownership are established above/by the caller.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    validate_listener(owned.as_raw_fd())?;
    let address = SocketAddr::new(
        host.parse::<IpAddr>()
            .map_err(|_| Error::invalid("activated RPC host must be an IP literal"))?,
        port,
    );
    let listener = TcpListener::from(owned);
    if port == 0 || listener.local_addr()? != address {
        return Err(Error::invalid(
            "inherited RPC listener does not match configured address",
        ));
    }
    let flags = unsafe { libc::fcntl(listener.as_raw_fd(), libc::F_GETFD) };
    if flags < 0
        || unsafe {
            libc::fcntl(
                listener.as_raw_fd(),
                libc::F_SETFD,
                flags | libc::FD_CLOEXEC,
            )
        } < 0
    {
        return Err(Error::invalid("cannot confine inherited RPC listener"));
    }
    listener.set_nonblocking(true)?;
    Ok(listener)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "linux")]
    use std::io::{Read, Write};
    #[cfg(target_os = "linux")]
    use std::net::{TcpStream, UdpSocket};

    fn duplicate(fd: i32) -> i32 {
        let duplicated = unsafe { libc::dup(fd) };
        assert!(duplicated >= 3);
        duplicated
    }

    #[test]
    fn activation_ownership_and_single_listener_are_explicit() {
        assert_eq!(select_descriptor(None, None, None, 42).unwrap(), None);
        assert_eq!(select_descriptor(Some(7), None, None, 42).unwrap(), Some(7));
        assert_eq!(
            select_descriptor(None, Some("42"), Some("1"), 42).unwrap(),
            Some(3)
        );
        assert_eq!(
            select_descriptor(None, Some("41"), Some("1"), 42).unwrap(),
            None
        );
        for (fd, owner, count) in [
            (Some(2), None, None),
            (Some(3), Some("41"), Some("1")),
            (None, Some("bad"), Some("1")),
            (None, None, Some("1")),
            (None, Some("42"), None),
            (None, Some("42"), Some("2")),
            (Some(4), Some("42"), Some("1")),
        ] {
            assert!(select_descriptor(fd, owner, count, 42).is_err());
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn a_request_queued_between_agents_survives_listener_handover() {
        let master = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = master.local_addr().unwrap();
        let first =
            unsafe { take_listener(duplicate(master.as_raw_fd()), "127.0.0.1", address.port()) }
                .unwrap();
        assert_ne!(
            unsafe { libc::fcntl(first.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
        drop(first);
        let mut client = TcpStream::connect(address).unwrap();
        client.write_all(b"queued-once").unwrap();
        let replacement =
            unsafe { take_listener(duplicate(master.as_raw_fd()), "127.0.0.1", address.port()) }
                .unwrap();
        let (mut accepted, _) = replacement.accept().unwrap();
        accepted
            .set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .unwrap();
        let mut bytes = [0; 11];
        accepted.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"queued-once");
        assert_eq!(
            replacement.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn wrong_addresses_and_nonlisteners_are_rejected_before_adoption() {
        let master = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = master.local_addr().unwrap().port();
        for (host, port) in [("127.0.0.2", port), ("127.0.0.1", 0), ("localhost", port)] {
            assert!(unsafe { take_listener(duplicate(master.as_raw_fd()), host, port) }.is_err());
        }
        let datagram = UdpSocket::bind("127.0.0.1:0").unwrap();
        assert!(
            unsafe { take_listener(duplicate(datagram.as_raw_fd()), "127.0.0.1", port) }.is_err()
        );
        let connected = TcpStream::connect(master.local_addr().unwrap()).unwrap();
        assert!(
            unsafe { take_listener(duplicate(connected.as_raw_fd()), "127.0.0.1", port) }.is_err()
        );
        let file = tempfile::tempfile().unwrap();
        assert!(unsafe { take_listener(duplicate(file.as_raw_fd()), "127.0.0.1", port) }.is_err());
        assert!(unsafe { take_listener(-1, "127.0.0.1", port) }.is_err());
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn unsupported_hosts_reject_activation() {
        let master = TcpListener::bind("127.0.0.1:0").unwrap();
        assert!(
            unsafe {
                take_listener(
                    duplicate(master.as_raw_fd()),
                    "127.0.0.1",
                    master.local_addr().unwrap().port(),
                )
            }
            .unwrap_err()
            .to_string()
            .contains("requires Linux")
        );
    }
}
