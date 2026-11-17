use crate::{
    error::{Error, Result},
    model::{digest, name},
};
pub use fenders_node_protocol::pki::private_file;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use serde_json::{Value, json};
use std::{collections::BTreeMap, path::Path};
pub fn create(path: &Path, names: &BTreeMap<String, Vec<String>>) -> Result<Value> {
    std::fs::create_dir_all(path)?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    if std::fs::read_dir(path)?.next().is_some() {
        return Err(Error::invalid(
            "PKI directory must be empty; refusing identity rotation",
        ));
    }
    for key in names.keys() {
        name(key)?;
    }
    let now = time::OffsetDateTime::now_utc();
    let mut ca = CertificateParams::new(Vec::<String>::new()).map_err(|_| Error::internal())?;
    ca.distinguished_name
        .push(DnType::CommonName, "Fenders lab CA");
    ca.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca.not_before = now - time::Duration::minutes(5);
    ca.not_after = now + time::Duration::days(365);
    let ca_key = KeyPair::generate().map_err(|_| Error::internal())?;
    let ca = ca.self_signed(&ca_key).map_err(|_| Error::internal())?;
    private_file(&path.join("ca.pem"), ca.pem().as_bytes())?;
    private_file(&path.join("ca.key"), ca_key.serialize_pem().as_bytes())?;
    let mut pins = serde_json::Map::new();
    for (name, hosts) in names {
        let key = KeyPair::generate().map_err(|_| Error::internal())?;
        let mut params = CertificateParams::new(hosts.clone())
            .map_err(|_| Error::invalid("invalid certificate host"))?;
        params.distinguished_name.push(DnType::CommonName, name);
        params.not_before = now - time::Duration::minutes(5);
        params.not_after = now + time::Duration::days(30);
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ClientAuth,
            ExtendedKeyUsagePurpose::ServerAuth,
        ];
        params.use_authority_key_identifier_extension = true;
        let certificate = params
            .signed_by(&key, &ca, &ca_key)
            .map_err(|_| Error::internal())?;
        private_file(
            &path.join(format!("{name}.pem")),
            certificate.pem().as_bytes(),
        )?;
        private_file(
            &path.join(format!("{name}.key")),
            key.serialize_pem().as_bytes(),
        )?;
        pins.insert(name.clone(), json!(digest(certificate.der())));
    }
    Ok(json!(pins))
}
