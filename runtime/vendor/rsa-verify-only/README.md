# rsa 0.9.10, verifying only

The `rsa` crate, release 0.9.10, with its private-key operation removed.

Fenders verifies an identity provider's RSA signatures through
`openidconnect`, which depends on `rsa` 0.9. Every 0.9 release has
RUSTSEC-2023-0071 against it: its private-key exponentiation runs in time
that depends on the key (the Marvin attack). The fix is in 0.10, which no
released `openidconnect` accepts. Fenders holds no RSA private key and never
decrypts or signs with one, so the operation is not fixed here but taken out:
`algorithms::rsa::rsa_decrypt`, through which every decryption and signature
of the crate goes, returns an error. Verification is untouched.

The only change from the published source is that function, and two lines at
the top of `src/lib.rs`. `crates/fenders-control-plane/tests/rsa_verify_only.rs`
shows that a signature still verifies and that signing and decryption
refuse. The workspace `Cargo.toml` patches `rsa` with this copy; remove both
when `openidconnect` moves to a fixed `rsa`.

Licensed as the original: MIT or Apache-2.0 (`LICENSE-MIT`, `LICENSE-APACHE`).
