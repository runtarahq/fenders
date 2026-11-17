//! Protocol-independent socket acceptance: echo, denied destination and revocation.
use crate::pg::{Socket, expect_socket_denied};
use std::{
    future::Future,
    io,
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn drive<T>(future: impl Future<Output = io::Result<T>>) -> io::Result<T> {
    let mut future = std::pin::pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Poll::Ready(value) = future.as_mut().poll(&mut cx) {
            return value;
        }
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        wasi::clocks::monotonic_clock::subscribe_duration(50_000).block();
    }
}

pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    let host = std::env::var("HOSTADDR")?;
    let port = std::env::var("PORT")?.parse()?;
    if std::env::var("TCP_DENIED").as_deref() == Ok("1") {
        expect_socket_denied(&host, port)?;
        println!("FENDERS_TCP_ACCESS_DENIED {host}:{port} AccessDenied");
        return Ok(());
    }
    let mut socket = Socket::connect(&host, port)?;
    if let Ok(denied_port) = std::env::var("TCP_DENY_PORT") {
        expect_socket_denied(&host, denied_port.parse()?)?;
        println!("FENDERS_TCP_OTHER_PORT_DENIED {host}:{denied_port} AccessDenied");
    }
    if std::env::var("TCP_HTTP").as_deref() == Ok("1") {
        let name = std::env::var("HOST")?;
        let request = format!("GET / HTTP/1.1\r\nHost: {name}\r\nConnection: close\r\n\r\n");
        let status = drive(async {
            socket.write_all(request.as_bytes()).await?;
            socket.flush().await?;
            let mut status = Vec::new();
            while status.len() < 256 {
                let byte = socket.read_u8().await?;
                status.push(byte);
                if byte == b'\n' { break; }
            }
            Ok(status)
        })?;
        let status = String::from_utf8(status)?;
        if !status.starts_with("HTTP/1.") { return Err("expected actual HTTP response over raw TCP".into()); }
        println!("FENDERS_TCP_HTTP_VERIFIED {host}:{port} {}",status.trim());
        return Ok(());
    }
    let exchange = |socket: &mut Socket| {
        drive(async {
            let payload = b"fenders-raw-tcp\n";
            socket.write_all(payload).await?;
            socket.flush().await?;
            let mut reply = [0; 16];
            socket.read_exact(&mut reply[..payload.len()]).await?;
            if &reply[..payload.len()] != payload {
                return Err(io::Error::other("echo mismatch"));
            }
            Ok(())
        })
    };
    exchange(&mut socket)?;
    println!("FENDERS_TCP_ECHO_VERIFIED {host}:{port}");
    if std::env::var("TCP_HOLD").as_deref() != Ok("1") {
        return Ok(());
    }
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        if let Err(error) = exchange(&mut socket) {
            if !matches!(
                error.kind(),
                io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
            ) {
                return Err(error.into());
            }
            println!("FENDERS_TCP_CONNECTION_CLOSED {error}");
            // Revocation must also prevent opening a new socket.
            expect_socket_denied(&host, port)?;
            println!("FENDERS_TCP_RECONNECT_DENIED {host}:{port} AccessDenied");
            return Ok(());
        }
        wasi::clocks::monotonic_clock::subscribe_duration(100_000_000).block();
    }
    Err("TCP connection remained usable after revocation deadline".into())
}
