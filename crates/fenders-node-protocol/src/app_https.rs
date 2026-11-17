//! Execution-bound runtime authority a node reports for public HTTPS.
use crate::{
    error::{Error, Result},
    value::*,
};
use serde_json::Value;

pub const RUNTIME_AUTHORITY: &str = "execution-runtime-v1";
pub fn validate_runtime_authority(value: &Value, boot: &str) -> Result<()> {
    fields(
        value,
        &["contract", "boot_id", "runtime_digest"],
        &["contract", "boot_id", "runtime_digest"],
    )?;
    if value["contract"] != RUNTIME_AUTHORITY
        || value["boot_id"] != boot
        || !value["runtime_digest"].as_str().is_some_and(runtime_digest)
    {
        return Err(Error::invalid("invalid execution runtime authority"));
    }
    Ok(())
}
pub fn runtime_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
