//! The `rsa` the workspace builds (runtime/vendor/rsa-verify-only) verifies
//! signatures and performs no private-key operation.
use rsa::pkcs8::DecodePublicKey;
use rsa::{Pkcs1v15Encrypt, Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};

/// A 2048-bit public key and its owner's PKCS#1 v1.5 SHA-256 signature of
/// `MESSAGE`, made with OpenSSL.
const PUBLIC_DER: &str = "30820122300d06092a864886f70d01010105000382010f003082010a0282010100a8586f6892e5b9387764eac191d40d7ce0816fc67b9b4378f8c119ab0cf485fc7309971d49546eed49681d4f5c937006939a89dddc896ff255e5c87502c42204796f0fe4db63e4c93c99c93e35528201d89e6cffd5635d32093e6c1e0093b6cdac5f2d58f4c48d30af1d688accdda0de87e0be0ce863a6778d863fc4a75adcceaeec492131e9b2a1def7a89223ca3e95e7d92836fad448fa6e1b2e066b8b0277161dda297bb4d46f02ec2926136d2c975a00ac7749f8449688968042e8779c5b2cc292a5e984aaa1b61b288b9efa1f81dd2a6b665b3d24bf2f9898d9a392f2385b13b86089b4ccda08b596d9cf82bc76a17aad85d104e49af2601f88417c7a1d0203010001";
const SIGNATURE: &str = "147814fe4f34074f61027ee05f8f7b79d5be559a07d5ad13fb492ea1b5339bc12124f2771323deb9204f655c0427eb8237f2293d03c02412f200de64191e6c2278b131a19287c8feae82c0c19fd39956e56714e4f7892ef9a7b3c5b0ab510e7659a03ba435c0a23fd6ced4ac2e72eacf81f7c495b1949630115441f8f71d33be15dbfc01992d507ba97a91e12b649c4e2214bbd5fc1ce1fe0cbab6edebdf502cb1ebf2dcb344cfdee7cbd569bdf3ecd868c3a090a3b5038751fecf0638b09e0e8d9fee1a1bd00987d002b3a8f73f350c98cba2df339e31d963054b21ef5f134eaa742b285b86a2f0c74a606c26788ba21415aaabc932d16ba67e26fe060ff8cc";
const MESSAGE: &[u8] = b"fenders verifies and never signs";

fn bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn a_signature_verifies_and_a_forged_one_does_not() {
    let key = RsaPublicKey::from_public_key_der(&bytes(PUBLIC_DER)).unwrap();
    let scheme = Pkcs1v15Sign::new::<Sha256>;
    let signature = bytes(SIGNATURE);
    key.verify(scheme(), &Sha256::digest(MESSAGE), &signature)
        .unwrap();
    assert!(
        key.verify(scheme(), &Sha256::digest(b"another message"), &signature)
            .is_err()
    );
    let mut forged = signature.clone();
    forged[40] ^= 1;
    assert!(
        key.verify(scheme(), &Sha256::digest(MESSAGE), &forged)
            .is_err()
    );
}

#[test]
fn no_private_key_operation_is_performed() {
    let mut rng = rsa::rand_core::OsRng;
    let key = RsaPrivateKey::new(&mut rng, 1024).unwrap();
    // Signing, with and without blinding, and decryption all refuse.
    let digest = Sha256::digest(MESSAGE);
    assert!(key.sign(Pkcs1v15Sign::new::<Sha256>(), &digest).is_err());
    assert!(
        key.sign_with_rng(&mut rng, Pkcs1v15Sign::new::<Sha256>(), &digest)
            .is_err()
    );
    let sealed = RsaPublicKey::from(&key)
        .encrypt(&mut rng, Pkcs1v15Encrypt, MESSAGE)
        .unwrap();
    assert!(key.decrypt(Pkcs1v15Encrypt, &sealed).is_err());
}
