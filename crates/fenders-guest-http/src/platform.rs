//! Where a guest's request may connect, and which roots it trusts there.
use fenders_egress::{Origin, PublicTargets};
use std::{net::SocketAddrV4, time::Duration};
use wasmtime_wasi_http::Error as ErrorCode;

pub(crate) const CONNECT_LIMIT: Duration = Duration::from_secs(5);
pub(crate) const RESPONSE_WAIT_LIMIT: Duration = Duration::from_secs(10);

/// The first-byte or between-bytes wait a request gets: the application's
/// option, capped by the platform.
pub fn response_wait(requested: Duration) -> Duration {
    requested.min(RESPONSE_WAIT_LIMIT)
}

/// Resolve only from the immutable launch binding. No guest DNS lookup, even
/// for names which happen to resolve to another already allowed TCP endpoint.
/// Each WASI request, including a component's follow-up to a redirect, calls
/// this again. The HTTP adapter itself does not follow redirects.
pub fn request_target(
    policy: &str,
    allowed: &str,
    authority: &str,
    tls: bool,
) -> Result<Vec<SocketAddrV4>, ErrorCode> {
    let denied = || ErrorCode::HttpRequestDenied;
    let origin = Origin::parse(&format!(
        "{}://{authority}",
        if tls { "https" } else { "http" }
    ))
    .map_err(|_| denied())?;
    let targets = PublicTargets::parse(policy).map_err(|_| denied())?;
    if !allowed.split(',').any(|entry| entry == origin.to_string())
        || targets
            .iter()
            .any(|(name, _)| !allowed.split(',').any(|entry| entry == name.to_string()))
    {
        return Err(denied());
    }
    if let Some(addresses) = targets.get(&origin) {
        return Ok(addresses.to_vec());
    }
    // Private managed services use numeric IPv4 bindings. Public names must
    // have an explicit pinned map, with no fallback to native name resolution.
    let ip = origin.host().parse().map_err(|_| denied())?;
    Ok(vec![SocketAddrV4::new(ip, origin.port())])
}

pub(crate) async fn connect(
    authority: &str,
    tls: bool,
) -> Result<tokio::net::TcpStream, ErrorCode> {
    match std::env::var("FENDERS_HTTP_PUBLIC_TARGETS") {
        Ok(policy) => {
            let allowed =
                std::env::var("FENDERS_HTTP_ALLOW").map_err(|_| ErrorCode::HttpRequestDenied)?;
            let addresses = request_target(&policy, &allowed, authority, tls)?;
            for address in addresses {
                if let Ok(stream) = tokio::net::TcpStream::connect(address).await {
                    return Ok(stream);
                }
            }
            Err(ErrorCode::ConnectionRefused)
        }
        // Standalone research launch compatibility. Platform nodes always
        // supply the variable, including an empty policy.
        Err(std::env::VarError::NotPresent) => tokio::net::TcpStream::connect(authority)
            .await
            .map_err(|_| ErrorCode::ConnectionRefused),
        Err(_) => Err(ErrorCode::HttpRequestDenied),
    }
}

/// Choose per-origin service trust without permitting private roots to replace
/// Web PKI verification for a public HTTPS binding.
pub fn platform_root_store(
    targets: &str,
    roots: &str,
    authority: &str,
) -> Result<rustls::RootCertStore, ErrorCode> {
    let targets = PublicTargets::parse(targets).map_err(|_| ErrorCode::TlsProtocolError)?;
    let origin =
        Origin::parse(&format!("https://{authority}")).map_err(|_| ErrorCode::TlsProtocolError)?;
    let entries = fenders_service_trust::parse(roots).map_err(|_| ErrorCode::TlsProtocolError)?;
    if targets.get(&origin).is_some() && entries.iter().any(|(name, _)| *name == origin.to_string())
    {
        return Err(ErrorCode::TlsProtocolError);
    }
    service_root_store(roots, &origin.authority())
}
/// Select trust for an explicit host:port from native guest configuration.
pub fn root_store(authority: &str) -> Result<rustls::RootCertStore, ErrorCode> {
    // Platform launches always supply this variable, including an empty policy.
    // An origin-specific root replaces public trust for that origin only.
    match std::env::var("FENDERS_HTTP_SERVICE_ROOTS") {
        Ok(policy) => {
            return match std::env::var("FENDERS_HTTP_PUBLIC_TARGETS") {
                Ok(targets) => platform_root_store(&targets, &policy, authority),
                Err(std::env::VarError::NotPresent) => service_root_store(&policy, authority),
                Err(_) => Err(ErrorCode::TlsProtocolError),
            };
        }
        Err(std::env::VarError::NotPresent) => {}
        Err(_) => return Err(ErrorCode::TlsProtocolError),
    }
    // A partial platform environment must not fall back to research-wide CA
    // injection. The node always supplies both policy variables.
    if std::env::var_os("FENDERS_HTTP_PUBLIC_TARGETS").is_some() {
        return Err(ErrorCode::TlsProtocolError);
    }
    // Retained for standalone research launches; never combined with a platform
    // policy and never passed through from customer environment configuration.
    let Ok(hex) = std::env::var("FENDERS_HTTP_CA_DER_HEX") else {
        return Ok(rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.into(),
        });
    };
    let der = fenders_service_trust::decode_der(&hex).map_err(|_| ErrorCode::TlsProtocolError)?;
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(der))
        .map_err(|_| ErrorCode::TlsProtocolError)?;
    Ok(roots)
}

/// Validate a complete bounded policy and select this origin's CA, or the
/// standard public roots when the origin has no private trust entry.
pub fn service_root_store(
    policy: &str,
    authority: &str,
) -> Result<rustls::RootCertStore, ErrorCode> {
    let entries = fenders_service_trust::parse(policy).map_err(|_| ErrorCode::TlsProtocolError)?;
    let origin = format!("https://{authority}");
    let mut selected = None;
    for (name, der) in entries {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(rustls::pki_types::CertificateDer::from(der))
            .map_err(|_| ErrorCode::TlsProtocolError)?;
        if name == origin {
            selected = Some(roots);
        }
    }
    Ok(selected.unwrap_or_else(|| rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.into(),
    }))
}
