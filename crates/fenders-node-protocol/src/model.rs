use crate::error::{Error, Result};
use sha2::{Digest, Sha256};

pub const MAX_UPLOAD: usize = 16 * 1024 * 1024;
/// The largest upload cap a node may be configured with; `MAX_UPLOAD` is the default.
pub const MAX_UPLOAD_CEILING: usize = 128 * 1024 * 1024;
pub const HOST_CONFINEMENT: &str = "landlock6-seccomp-v2";
pub const LOG_REDACTION: &str = "literal-v1";
pub const WORKER_OVERHEAD_MIB: i64 = 24;

pub fn uid() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}
pub fn digest(bytes: impl AsRef<[u8]>) -> String {
    format!("{:x}", Sha256::digest(bytes.as_ref()))
}
/// Stable request identity, including the original ASCII-escaped JSON format.
pub fn fingerprint(value: &serde_json::Value) -> String {
    let encoded = serde_json::to_string(value).expect("JSON values serialize");
    let mut canonical = String::new();
    for character in encoded.chars() {
        if character.is_ascii() && character != '\u{7f}' {
            canonical.push(character)
        } else {
            for unit in character.encode_utf16(&mut [0; 2]) {
                canonical.push_str(&format!("\\u{unit:04x}"));
            }
        }
    }
    digest(canonical)
}
pub fn identity(value: &str) -> Result<()> {
    if value.len() != 32
        || !value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(Error::missing());
    }
    Ok(())
}
pub fn name(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 63
        || !value.as_bytes()[0].is_ascii_lowercase()
        || !value
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
    {
        return Err(Error::invalid(
            "name must start with a lowercase letter and contain 1–63 lowercase letters, digits or hyphens",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn legacy_idempotency_fingerprint_preserves_unicode_escape_format() {
        let input = json!({"z":"é🙂\u{7f}","a":1});
        assert_eq!(
            fingerprint(&input),
            digest(r#"{"a":1,"z":"\u00e9\ud83d\ude42\u007f"}"#)
        );
    }
}
