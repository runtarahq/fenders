//! Exercise the trust selection the guest's HTTP sends use, over real rustls.
//! This is native TLS transport coverage, not kernel-free VM qualification.
use fenders_guest_http::platform::service_root_store;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Identity {
    ca: String,
    cert: CertificateDer<'static>,
    key: Vec<u8>,
}
fn identity() -> Identity {
    let mut params = rcgen::CertificateParams::new(vec![]).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
    let signing = rcgen::KeyPair::generate().unwrap();
    let ca = params.self_signed(&signing).unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["127.0.0.1".into(), "private.test".into()])
        .unwrap()
        .signed_by(&key, &ca, &signing)
        .unwrap();
    Identity {
        ca: ca.der().iter().map(|b| format!("{b:02x}")).collect(),
        cert: cert.der().clone(),
        key: key.serialize_der(),
    }
}
async fn handshake(server: &Identity, policy: &str, authority: &str, name: &str) -> bool {
    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![server.cert.clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server.key.clone())),
        )
        .unwrap();
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(service_root_store(policy, authority).unwrap())
        .with_no_client_auth();
    let (client, socket) = tokio::io::duplex(8192);
    let task = tokio::spawn(async move {
        if let Ok(mut stream) = tokio_rustls::TlsAcceptor::from(Arc::new(server_config))
            .accept(socket)
            .await
        {
            let _ = stream.write_all(b"ok").await;
        }
    });
    let result = tokio_rustls::TlsConnector::from(Arc::new(client_config))
        .connect(ServerName::try_from(name.to_owned()).unwrap(), client)
        .await;
    let passed = if let Ok(mut stream) = result {
        let mut response = [0; 2];
        stream.read_exact(&mut response).await.is_ok() && &response == b"ok"
    } else {
        false
    };
    task.await.unwrap();
    passed
}

#[tokio::test]
async fn private_origin_roots_are_isolated_and_public_trust_is_preserved() {
    let a = identity();
    let b = identity();
    let policy = format!(
        "https://127.0.0.1:8443={};https://private.test:9443={}",
        a.ca, b.ca
    );
    assert!(handshake(&a, &policy, "127.0.0.1:8443", "127.0.0.1").await);
    assert!(handshake(&b, &policy, "private.test:9443", "private.test").await);
    // Both certificates contain both SANs; rejection proves origin-specific
    // trust, rather than only hostname checking.
    assert!(!handshake(&a, &policy, "private.test:9443", "private.test").await);
    assert!(!handshake(&b, &policy, "127.0.0.1:8443", "127.0.0.1").await);
    assert!(!handshake(&a, &policy, "127.0.0.1:8443", "wrong.test").await);
    assert!(!handshake(&a, &policy, "127.0.0.1:443", "127.0.0.1").await);
    let public = service_root_store("", "public.test:443").unwrap();
    let alongside_private = service_root_store(&policy, "public.test:443").unwrap();
    assert!(public.len() > 1);
    assert_eq!(public.roots, alongside_private.roots);
    assert_eq!(
        service_root_store(&policy, "127.0.0.1:8443").unwrap().len(),
        1
    );
    assert!(
        service_root_store(
            &format!("{policy};https://broken.test:443=00"),
            "public.test:443"
        )
        .is_err()
    );
    assert!(
        service_root_store(
            &format!("{policy};https://127.0.0.1:8443={}", b.ca),
            "127.0.0.1:8443"
        )
        .is_err()
    );
}
