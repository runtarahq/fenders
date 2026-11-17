//! A certificate renewed over the same key is presented at the next handshake
//! with nothing rebuilt, and a key pin survives the renewal (SYN-912).
use axum::{Extension, Router, routing::get};
use fenders_node_protocol::{
    model::digest,
    transport::{self, PeerIdentity, PeerKey, key_pin},
};
use rcgen::{BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair};
use std::path::Path;

struct Ca {
    cert: rcgen::Certificate,
    key: KeyPair,
}

fn ca() -> Ca {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(DnType::CommonName, "test CA");
    let cert = params.self_signed(&key).unwrap();
    Ca { cert, key }
}

/// A certificate for 127.0.0.1 over `key`, from `ca`.
fn leaf(ca: &Ca, key: &KeyPair, name: &str) -> String {
    let mut params = CertificateParams::new(vec!["127.0.0.1".to_owned()]).unwrap();
    params.distinguished_name.push(DnType::CommonName, name);
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    params.signed_by(key, &ca.cert, &ca.key).unwrap().pem()
}

/// Replaces a file whole, as a renewal does.
fn install(path: &Path, contents: &str) {
    let staged = path.with_extension("staged");
    std::fs::write(&staged, contents).unwrap();
    std::fs::rename(&staged, path).unwrap();
}

fn der(pem: &str) -> Vec<u8> {
    rustls_pemfile::certs(&mut pem.as_bytes())
        .next()
        .unwrap()
        .unwrap()
        .to_vec()
}

async fn whoami(
    Extension(PeerIdentity(cert)): Extension<PeerIdentity>,
    Extension(PeerKey(key)): Extension<PeerKey>,
) -> String {
    format!("{} {}", cert.unwrap(), key.unwrap())
}

#[tokio::test]
async fn renewed_certificates_are_presented_and_keep_their_key_pins() {
    let dir = tempfile::tempdir().unwrap();
    let path = |name: &str| dir.path().join(name);
    let ca = ca();
    std::fs::write(path("ca.pem"), ca.cert.pem()).unwrap();
    let (server_key, client_key) = (KeyPair::generate().unwrap(), KeyPair::generate().unwrap());
    let server_first = leaf(&ca, &server_key, "control");
    install(&path("control.pem"), &server_first);
    install(&path("control.key"), &server_key.serialize_pem());
    let client_first = leaf(&ca, &client_key, "node");
    install(&path("node.pem"), &client_first);
    install(&path("node.key"), &client_key.serialize_pem());

    let tls = transport::server_config(
        &path("control.pem"),
        &path("control.key"),
        Some(&path("ca.pem")),
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("https://{}", listener.local_addr().unwrap());
    tokio::spawn(transport::serve_tls(
        listener,
        tls,
        Router::new().route("/whoami", get(whoami)),
    ));
    let server_pin = key_pin(&der(&server_first)).unwrap();
    let client = transport::Client::new(
        &endpoint,
        &path("ca.pem"),
        &path("node.pem"),
        &path("node.key"),
        &server_pin,
    )
    .unwrap();
    let whoami = |client: transport::Client| async move {
        let body = client.request("GET", "/whoami", None, 1024).await?;
        Ok::<_, fenders_node_protocol::error::Error>(String::from_utf8(body).unwrap())
    };
    let client_pin = key_pin(&der(&client_first)).unwrap();
    assert_eq!(
        whoami(client.clone()).await.unwrap(),
        format!("{} {client_pin}", digest(der(&client_first)))
    );

    // The client's certificate renewed over its key: presented next time,
    // its key pin unchanged.
    let client_renewed = leaf(&ca, &client_key, "node renewed");
    install(&path("node.pem"), &client_renewed);
    assert_eq!(
        whoami(client.clone()).await.unwrap(),
        format!("{} {client_pin}", digest(der(&client_renewed)))
    );

    // The server's renewed over its key: a client pinned to the key still
    // reaches it, one pinned to the old certificate does not.
    install(
        &path("control.pem"),
        &leaf(&ca, &server_key, "control renewed"),
    );
    assert!(whoami(client.clone()).await.is_ok());
    let by_certificate = transport::Client::new(
        &endpoint,
        &path("ca.pem"),
        &path("node.pem"),
        &path("node.key"),
        &digest(der(&server_first)),
    )
    .unwrap();
    assert!(whoami(by_certificate).await.is_err());

    // Half a renewal (a certificate for another key) changes nothing.
    install(
        &path("node.pem"),
        &leaf(&ca, &KeyPair::generate().unwrap(), "stray"),
    );
    assert_eq!(
        whoami(client).await.unwrap(),
        format!("{} {client_pin}", digest(der(&client_renewed)))
    );
}
