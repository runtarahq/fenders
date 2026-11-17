//! Real TLS RESP probe; same WASI socket transport as the PostgreSQL driver.
use crate::pg::{Socket, tls::{Connector, Stream}};
use base64::Engine;
use rustls::pki_types::{CertificateDer, pem::PemObject};
use std::{future::Future, task::{Context, Poll, Waker}, time::{Duration, Instant}};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
type Error = Box<dyn std::error::Error>;

fn drive<T>(future: impl Future<Output=Result<T, std::io::Error>>) -> std::io::Result<T> {
    let mut future = std::pin::pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Poll::Ready(value) = future.as_mut().poll(&mut cx) {return Ok(value?);}
        if Instant::now() >= deadline {return Err(std::io::Error::new(std::io::ErrorKind::TimedOut,"Valkey I/O deadline exceeded"));}
        wasi::clocks::monotonic_clock::subscribe_duration(50_000).block();
    }
}
fn command(stream: &mut Stream, args: &[&str], expected: &[u8]) -> std::io::Result<()> {
    let mut request = format!("*{}\r\n", args.len());
    for arg in args {request.push_str(&format!("${}\r\n{}\r\n",arg.len(),arg));}
    drive(async {
        stream.write_all(request.as_bytes()).await?;
        stream.flush().await?;
        // Exact known replies bound allocation and reject server errors.
        let mut reply = vec![0;expected.len()];
        stream.read_exact(&mut reply).await?;
        if reply != expected {return Err(std::io::Error::other("unexpected Valkey response"));}
        Ok(())
    })
}
pub fn run() -> Result<(), Error> {
    let env = |name| std::env::var(name);
    let host = env("VALKEY_HOST")?;
    let port = env("VALKEY_PORT")?.parse()?;
    println!("FENDERS_VALKEY_TARGET {host}:{port}");
    let socket = Socket::connect(&host,port)?;
    let cert = CertificateDer::from_pem_slice(env("VALKEY_CA_PEM")?.as_bytes())?;
    let tls = Connector::from_config(&base64::engine::general_purpose::STANDARD.encode(cert.as_ref()),host)?;
    let mut stream = drive(tls.handshake(socket))?;
    println!("FENDERS_TLS_SERVER TLSv1.3");
    command(&mut stream,&["AUTH",&env("VALKEY_USERNAME")?,&env("VALKEY_PASSWORD")?],b"+OK\r\n")?;
    println!("FENDERS_AUTHENTICATED");
    let key = format!("fenders:{}",env("RUN_ID")?);
    let value = "hello-from-wasi-sockets";
    command(&mut stream,&["SET",&key,value],b"+OK\r\n")?;
    command(&mut stream,&["GET",&key],format!("${}\r\n{value}\r\n",value.len()).as_bytes())?;
    println!("FENDERS_QUERY_VERIFIED");
    if env("SERVICE_HOLD").as_deref() == Ok("1") {
        let deadline = Instant::now()+Duration::from_secs(60);
        let mut heartbeat = false;
        while Instant::now() < deadline {
            if let Err(error) = command(&mut stream,&["PING"],b"+PONG\r\n") {
                use std::io::ErrorKind;
                if !matches!(error.kind(),ErrorKind::UnexpectedEof|ErrorKind::BrokenPipe|ErrorKind::ConnectionReset|ErrorKind::ConnectionAborted) {
                    return Err(error.into());
                }
                println!("FENDERS_VALKEY_CONNECTION_CLOSED {error}");return Ok(());
            }
            if !heartbeat {println!("FENDERS_VALKEY_HEARTBEAT");heartbeat=true;}
            wasi::clocks::monotonic_clock::subscribe_duration(100_000_000).block();
        }
        return Err("Valkey connection remained usable past revocation deadline".into());
    }
    Ok(())
}
