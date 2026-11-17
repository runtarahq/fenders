//! Execution egress-budget authority a node reports under its boot identity.
use crate::{
    error::{Error, Result},
    value::*,
};
use serde_json::Value;

pub const CONTRACT: &str = "socket-payload-ceiling-v2";
pub fn valid_digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn validate_authority(value: &Value, boot: &str) -> Result<()> {
    fields(
        value,
        &["contract", "boot_id", "launcher_digest"],
        &["contract", "boot_id", "launcher_digest"],
    )?;
    if value["contract"] != CONTRACT
        || value["boot_id"] != boot
        || !value["launcher_digest"].as_str().is_some_and(valid_digest)
    {
        return Err(Error::invalid("invalid execution egress authority"));
    }
    Ok(())
}
