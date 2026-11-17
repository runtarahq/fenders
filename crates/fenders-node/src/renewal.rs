//! Renewing the node's own certificate through its control peer (SYN-912).
//!
//! A control peer that signs node certificates (runtara-cloud's fleet) is
//! asked for a new one over the node's existing key once two thirds of the
//! current one's lifetime have passed, or it is [`MAX_AGE`] old. The new
//! certificate replaces the file whole, and the transport presents it at the
//! next handshake; the peer knows the node by its key, so it stays enrolled.
use crate::core::now;
use fenders_node_protocol::{
    error::{Error, Result},
    transport::Client,
};
use serde_json::json;
use std::{path::Path, time::Duration};

/// How often the node looks whether its certificate is due.
pub const CHECK_EVERY: Duration = Duration::from_secs(60);
/// The oldest a certificate gets before it is renewed, whatever its lifetime.
pub const MAX_AGE: Duration = Duration::from_secs(8 * 60 * 60);

/// The first certificate in a PEM chain, DER.
fn first_certificate(pem: &str) -> Option<Vec<u8>> {
    x509_parser::pem::Pem::iter_from_buffer(pem.as_bytes())
        .filter_map(|pem| pem.ok())
        .find(|pem| pem.label == "CERTIFICATE")
        .map(|pem| pem.contents)
}

/// When `cert_pem` is due for renewal, in Unix seconds.
pub fn due(cert_pem: &str) -> Option<i64> {
    let der = first_certificate(cert_pem)?;
    let (_, certificate) = x509_parser::parse_x509_certificate(&der).ok()?;
    let validity = certificate.validity();
    let (before, after) = (
        validity.not_before.timestamp(),
        validity.not_after.timestamp(),
    );
    Some((before + (after - before) * 2 / 3).min(before + MAX_AGE.as_secs() as i64))
}

/// A request for a certificate over `key_pem` naming the IP addresses
/// `cert_pem` names.
pub fn request(cert_pem: &str, key_pem: &str) -> Result<String> {
    let der = first_certificate(cert_pem).ok_or_else(|| Error::invalid("no node certificate"))?;
    let (_, certificate) = x509_parser::parse_x509_certificate(&der)
        .map_err(|_| Error::invalid("invalid node certificate"))?;
    let mut params = rcgen::CertificateParams::default();
    if let Ok(Some(names)) = certificate.subject_alternative_name() {
        for name in &names.value.general_names {
            if let x509_parser::extensions::GeneralName::IPAddress(bytes) = name {
                let address = match bytes.len() {
                    4 => std::net::IpAddr::from(<[u8; 4]>::try_from(*bytes).unwrap()),
                    16 => std::net::IpAddr::from(<[u8; 16]>::try_from(*bytes).unwrap()),
                    _ => continue,
                };
                params
                    .subject_alt_names
                    .push(rcgen::SanType::IpAddress(address));
            }
        }
    }
    let key = rcgen::KeyPair::from_pem(key_pem).map_err(|_| Error::invalid("invalid node key"))?;
    params
        .serialize_request(&key)
        .and_then(|request| request.pem())
        .map_err(|_| Error::internal())
}

/// Replaces `path` with `contents` whole, keeping its mode.
fn replace(path: &Path, contents: &str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let staged = path.with_extension("renewing");
    let mode = std::fs::metadata(path)?.permissions().mode();
    std::fs::write(&staged, contents)?;
    std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(mode))?;
    std::fs::rename(&staged, path)?;
    Ok(())
}

/// Renews the certificate in `cert` (over the key in `key`) through `peer`
/// when it is due; answers whether it did.
pub async fn renew_if_due(peer: &Client, cert: &Path, key: &Path) -> Result<bool> {
    let current = std::fs::read_to_string(cert)?;
    let due = due(&current).ok_or_else(|| Error::invalid("invalid node certificate"))?;
    if (now() as i64) < due {
        return Ok(false);
    }
    let key_pem = std::fs::read_to_string(key)?;
    let answer = peer
        .json(
            "POST",
            "/internal/certificate",
            Some(&json!({"request": request(&current, &key_pem)?})),
        )
        .await?;
    let renewed = answer["certificate"]
        .as_str()
        .ok_or_else(|| Error::invalid("the control peer returned no certificate"))?;
    let key_of = |pem: &str| {
        first_certificate(pem).and_then(|der| fenders_node_protocol::transport::key_pin(&der))
    };
    if key_of(&current).is_none() || key_of(renewed) != key_of(&current) {
        return Err(Error::invalid(
            "the control peer returned a certificate for another key",
        ));
    }
    replace(cert, renewed)?;
    Ok(true)
}

/// Keeps the node's certificate renewed through `peer` until the process ends.
pub async fn keep_renewed(peer: Client, cert: std::path::PathBuf, key: std::path::PathBuf) {
    loop {
        if let Err(error) = renew_if_due(&peer, &cert, &key).await {
            tracing::warn!(error = %error.message, "node certificate renewal failed");
        }
        tokio::time::sleep(CHECK_EVERY).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::PublicKeyData;

    fn certificate(key: &rcgen::KeyPair, hours: i64) -> String {
        let mut params = rcgen::CertificateParams::new(vec!["10.0.0.7".to_owned()]).unwrap();
        let now = ::time::OffsetDateTime::now_utc();
        params.not_before = now;
        params.not_after = now + ::time::Duration::hours(hours);
        params.self_signed(key).unwrap().pem()
    }

    #[test]
    fn a_certificate_is_due_at_two_thirds_or_eight_hours() {
        let key = rcgen::KeyPair::generate().unwrap();
        let start = now() as i64;
        let short = due(&certificate(&key, 3)).unwrap() - start;
        assert!((7190..=7210).contains(&short), "two thirds of 3 h: {short}");
        let long = due(&certificate(&key, 24 * 90)).unwrap() - start;
        assert!((28790..=28810).contains(&long), "eight hours: {long}");
    }

    #[test]
    fn a_request_keeps_the_key_and_the_addresses() {
        let key = rcgen::KeyPair::generate().unwrap();
        let csr = request(&certificate(&key, 3), &key.serialize_pem()).unwrap();
        let parsed = rcgen::CertificateSigningRequestParams::from_pem(&csr).unwrap();
        assert_eq!(parsed.public_key.der_bytes(), key.public_key_raw());
        assert_eq!(
            parsed.params.subject_alt_names,
            vec![rcgen::SanType::IpAddress("10.0.0.7".parse().unwrap())]
        );
    }
}
