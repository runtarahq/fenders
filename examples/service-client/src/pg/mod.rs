use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll, Waker},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use wasi::{
    io::streams::{InputStream, OutputStream, StreamError},
    sockets::{
        instance_network::instance_network,
        network::{ErrorCode, IpAddressFamily, IpSocketAddress, Ipv4SocketAddress},
        tcp::TcpSocket,
        tcp_create_socket::create_tcp_socket,
    },
};
pub(crate) mod tls;

pub(crate) struct Socket {
    input: InputStream,
    output: OutputStream,
    _socket: TcpSocket,
}
fn stream_error(error: StreamError) -> io::Error {
    // WASI specifies LastOperationFailed is terminal: subsequent operations
    // return Closed. Preserve that distinction from a local polling timeout.
    let detail = match error {
        StreamError::Closed => "WASI stream closed".into(),
        StreamError::LastOperationFailed(error) => format!(
            "WASI stream closed after failed operation: {}",
            error.to_debug_string()
        ),
    };
    io::Error::new(io::ErrorKind::BrokenPipe, detail)
}
impl Socket {
    pub(crate) fn connect(host: &str, port: u16) -> Result<Self, Box<dyn std::error::Error>> {
        let ip: std::net::Ipv4Addr = host.parse()?;
        let bytes = ip.octets();
        let socket = create_tcp_socket(IpAddressFamily::Ipv4)
            .map_err(|e| format!("create socket: {e:?}"))?;
        socket
            .start_connect(
                &instance_network(),
                IpSocketAddress::Ipv4(Ipv4SocketAddress {
                    port,
                    address: (bytes[0], bytes[1], bytes[2], bytes[3]),
                }),
            )
            .map_err(|e| format!("start connect: {e:?}"))?;
        let pollable = socket.subscribe();
        let (input, output) = loop {
            match socket.finish_connect() {
                Ok(streams) => break streams,
                Err(ErrorCode::WouldBlock) => pollable.block(),
                Err(e) => return Err(format!("connect: {e:?}").into()),
            }
        };
        Ok(Self {
            input,
            output,
            _socket: socket,
        })
    }
}
impl AsyncRead for Socket {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        match self.input.read(buf.remaining().min(4096) as u64) {
            Ok(bytes) if bytes.is_empty() => Poll::Pending,
            Ok(bytes) => {
                buf.put_slice(&bytes);
                Poll::Ready(Ok(()))
            }
            Err(StreamError::Closed) => Poll::Ready(Ok(())),
            Err(e) => Poll::Ready(Err(stream_error(e))),
        }
    }
}
impl AsyncWrite for Socket {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.output.check_write() {
            Ok(0) => Poll::Pending,
            Ok(cap) => {
                let count = bytes.len().min(cap as usize);
                Poll::Ready(
                    self.output
                        .write(&bytes[..count])
                        .map(|()| count)
                        .map_err(stream_error),
                )
            }
            Err(e) => Poll::Ready(Err(stream_error(e))),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(self.output.flush().map_err(stream_error))
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}

pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    let env = |name| std::env::var(name).expect("missing runtime configuration");
    println!("FENDERS_PG_TARGET {}:{}", env("PGHOST"), env("PGPORT"));
    // Use the granted address for the socket and retain PGHOST for TLS identity.
    let address = std::env::var("PGHOSTADDR").unwrap_or_else(|_| env("PGHOST"));
    let socket = Socket::connect(&address, env("PGPORT").parse()?)?;
    let mut config = tokio_postgres::Config::new();
    config
        .user(&env("PGUSER"))
        .password(&env("PGPASSWORD"))
        .dbname(&env("PGDATABASE"));
    if let Ok(options) = std::env::var("PGOPTIONS") {
        config.options(&options);
    }
    let connector = {
        config.ssl_mode(tokio_postgres::config::SslMode::Require);
        tls::Connector::from_env()?
    };
    // During authentication the driver owns the socket; poll drives WASI I/O.
    let mut cx = Context::from_waker(Waker::noop());
    let mut connect = std::pin::pin!(config.connect_raw(socket, connector));
    let (client, connection) = loop {
        if let Poll::Ready(result) = connect.as_mut().poll(&mut cx) {
            break result?;
        }
        // This yields to the host socket poller without requiring guest threads.
        wasi::clocks::monotonic_clock::subscribe_duration(50_000).block();
    };
    println!("FENDERS_AUTHENTICATED");
    let run_id = env("RUN_ID");
    let payload = "hello-from-wasi-sockets";
    let query = async {
        let read_only = std::env::var("PG_READ_ONLY").as_deref() == Ok("1");
        if !read_only && std::env::var("PG_CREATE_TABLE").as_deref() == Ok("1") {
            client.batch_execute("CREATE TABLE IF NOT EXISTS poc_runs (run_id text PRIMARY KEY, payload text NOT NULL)").await?;
        }
        if !read_only {
            client
                .execute(
                    "INSERT INTO poc_runs(run_id,payload) VALUES ($1,$2)",
                    &[&run_id, &payload],
                )
                .await?;
        }
        let sql = "SELECT payload,ssl,version,cipher FROM poc_runs CROSS JOIN pg_stat_ssl WHERE run_id=$1 AND pid=pg_backend_pid()";
        let row = client.query_one(sql, &[&run_id]).await?;
        let returned: &str = row.get(0);
        assert_eq!(returned, payload);
        if read_only {
            println!("FENDERS_RETAINED_DATA_VERIFIED {run_id}");
        }
        {
            assert!(row.get::<_, bool>(1));
            let version: &str = row.get(2);
            let cipher: &str = row.get(3);
            assert_eq!(version, "TLSv1.3");
            println!("FENDERS_TLS_SERVER {version} {cipher}");
        }
        Ok::<(), tokio_postgres::Error>(())
    };
    let mut query = std::pin::pin!(query);
    let mut connection = std::pin::pin!(connection);
    loop {
        if let Poll::Ready(result) = query.as_mut().poll(&mut cx) {
            result?;
            break;
        }
        if let Poll::Ready(result) = connection.as_mut().poll(&mut cx) {
            result?;
            return Err("connection closed before query completed".into());
        }
        // Query completion may have woken its future. Poll it before sleeping.
        if let Poll::Ready(result) = query.as_mut().poll(&mut cx) {
            result?;
            break;
        }
        wasi::clocks::monotonic_clock::subscribe_duration(50_000).block();
    }
    println!("FENDERS_QUERY_VERIFIED");
    if std::env::var("PG_HOLD").as_deref() == Ok("1") {
        println!("FENDERS_PG_HOLD_OPEN");
        // Longer maintenance journeys need an explicit fixture window. Keep
        // the existing default and a hard bound; this never changes VM leases.
        let hold_seconds = std::env::var("PG_HOLD_SECONDS")
            .unwrap_or_else(|_| "60".into())
            .parse::<u64>()
            .map_err(|_| "invalid PG_HOLD_SECONDS")?;
        if !(1..=240).contains(&hold_seconds) {
            return Err("PG_HOLD_SECONDS must be between 1 and 240".into());
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(hold_seconds);
        let mut heartbeat = false;
        while std::time::Instant::now() < deadline {
            let mut query = std::pin::pin!(client.simple_query("SELECT 1"));
            loop {
                if let Poll::Ready(result) = query.as_mut().poll(&mut cx) {
                    match result {
                        Ok(_) => break,
                        Err(error) => {
                            println!("FENDERS_PG_CONNECTION_CLOSED query: {error}");
                            return Ok(());
                        }
                    }
                }
                if let Poll::Ready(result) = connection.as_mut().poll(&mut cx) {
                    println!("FENDERS_PG_CONNECTION_CLOSED transport: {result:?}");
                    return Ok(());
                }
                wasi::clocks::monotonic_clock::subscribe_duration(50_000).block();
            }
            if !heartbeat {
                println!("FENDERS_PG_HEARTBEAT");
                heartbeat = true;
            }
            wasi::clocks::monotonic_clock::subscribe_duration(100_000_000).block();
        }
        return Err(
            "PostgreSQL connection remained usable past the revocation test deadline".into(),
        );
    }
    Ok(())
}

pub fn expect_denied() -> Result<(), Box<dyn std::error::Error>> {
    let host = std::env::var("PGHOSTADDR").or_else(|_| std::env::var("PGHOST"))?;
    let port: u16 = std::env::var("PGPORT")?.parse()?;
    expect_socket_denied(&host, port)?;
    println!("FENDERS_SOCKET_ACCESS_DENIED {host}:{port} AccessDenied");
    Ok(())
}

pub(crate) fn expect_socket_denied(host: &str, port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let ip: std::net::Ipv4Addr = host.parse()?;
    let bytes = ip.octets();
    let socket =
        create_tcp_socket(IpAddressFamily::Ipv4).map_err(|e| format!("create socket: {e:?}"))?;
    let denied = match socket.start_connect(
        &instance_network(),
        IpSocketAddress::Ipv4(Ipv4SocketAddress {
            port,
            address: (bytes[0], bytes[1], bytes[2], bytes[3]),
        }),
    ) {
        Err(error) => error == ErrorCode::AccessDenied,
        Ok(()) => {
            let pollable = socket.subscribe();
            loop {
                match socket.finish_connect() {
                    Err(ErrorCode::WouldBlock) => pollable.block(),
                    Err(error) => break error == ErrorCode::AccessDenied,
                    Ok(_) => break false,
                }
            }
        }
    };
    if !denied {
        return Err("socket attempt did not return the required AccessDenied policy result".into());
    }
    Ok(())
}
