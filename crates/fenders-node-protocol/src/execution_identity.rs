//! The execution identity a node adds to every request a run sends to its
//! host-bound origin. Guests cannot set it: the runtime and the node both strip
//! reserved headers before the node signs. Upstreams verify it with the node's
//! public key.
use crate::error::{Error, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::{
    rand::SecureRandom,
    signature::{ECDSA_P256_SHA256_FIXED, EcdsaKeyPair, UnparsedPublicKey},
};
use serde_json::{Value, json};

pub const HEADER: &str = "fenders-execution-identity";

const VERSION: &str = "v1";

/// Prefix of every header name the node reserves on host-bound requests.
pub fn reserved(name: &str) -> bool {
    name.len() >= 8 && name[..8].eq_ignore_ascii_case("fenders-")
}

/// `v1.<claims>.<signature>`, both base64url; the signature covers `v1.<claims>`.
/// `run` is the node's run; `execution` is what the node was assigned, which an
/// upstream checks is still current for the signing node.
pub fn sign(
    key: &EcdsaKeyPair,
    rng: &dyn SecureRandom,
    run: &str,
    execution: &str,
    origin: &str,
    issued_at: u64,
    ttl_seconds: u64,
) -> Result<String> {
    let claims = json!({"run":run,"execution":execution,"origin":origin,"issued_at":issued_at,"expires_at":issued_at + ttl_seconds});
    let signed = format!(
        "{VERSION}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).map_err(|_| Error::internal())?)
    );
    let signature = key
        .sign(rng, signed.as_bytes())
        .map_err(|_| Error::internal())?;
    Ok(format!(
        "{signed}.{}",
        URL_SAFE_NO_PAD.encode(signature.as_ref())
    ))
}

/// The claims of a token signed by `public_key` (an uncompressed P-256 point),
/// current at `now` and issued for `expected_origin`, so an upstream cannot
/// replay a token it received against another origin.
pub fn verify(token: &str, public_key: &[u8], expected_origin: &str, now: u64) -> Result<Value> {
    let invalid = || Error::invalid("invalid execution identity");
    let (signed, signature) = token.rsplit_once('.').ok_or_else(invalid)?;
    let (version, claims) = signed.split_once('.').ok_or_else(invalid)?;
    if version != VERSION {
        return Err(invalid());
    }
    let signature = URL_SAFE_NO_PAD.decode(signature).map_err(|_| invalid())?;
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, public_key)
        .verify(signed.as_bytes(), &signature)
        .map_err(|_| invalid())?;
    let claims: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(claims).map_err(|_| invalid())?)
            .map_err(|_| invalid())?;
    let current = claims["issued_at"].as_u64().is_some_and(|at| at <= now)
        && claims["expires_at"].as_u64().is_some_and(|at| now < at);
    if !current
        || !claims["run"].is_string()
        || !claims["execution"].is_string()
        || claims["origin"] != expected_origin
    {
        return Err(invalid());
    }
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::{rand::SystemRandom, signature::KeyPair};

    const ORIGIN: &str = "https://runtara.internal:443";

    fn key(rng: &SystemRandom) -> EcdsaKeyPair {
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING, rng)
                .unwrap();
        EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            pkcs8.as_ref(),
            rng,
        )
        .unwrap()
    }

    #[test]
    fn only_the_signing_key_and_a_current_token_verify() {
        let rng = SystemRandom::new();
        let (node, other) = (key(&rng), key(&rng));
        let token = sign(&node, &rng, "run-1", "exec-1", ORIGIN, 100, 60).unwrap();
        let claims = verify(&token, node.public_key().as_ref(), ORIGIN, 120).unwrap();
        assert_eq!(claims["run"], "run-1");
        assert_eq!(claims["execution"], "exec-1");
        assert!(verify(&token, other.public_key().as_ref(), ORIGIN, 120).is_err());
        assert!(verify(&token, node.public_key().as_ref(), ORIGIN, 160).is_err());
        assert!(verify(&token, node.public_key().as_ref(), ORIGIN, 99).is_err());
        let (signed, signature) = token.rsplit_once('.').unwrap();
        let forged = format!("{}x.{signature}", signed);
        assert!(verify(&forged, node.public_key().as_ref(), ORIGIN, 120).is_err());
        assert!(verify("forged", node.public_key().as_ref(), ORIGIN, 120).is_err());
        let elsewhere = verify(
            &token,
            node.public_key().as_ref(),
            "https://other.internal:443",
            120,
        );
        assert!(elsewhere.is_err());
        assert!(reserved("Fenders-Execution-Identity") && !reserved("x-fenders"));
    }
}
