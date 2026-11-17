//! Cumulative socket-payload observations, not monthly transfer billing.
use crate::{
    error::{Error, Result},
    value::*,
};
use serde_json::Value;

pub fn validate(value: &Value, state: &str, boot: &str) -> Result<()> {
    fields(
        value,
        &[
            "contract",
            "bytes",
            "in_flight",
            "complete",
            "observed",
            "boot_id",
        ],
        &[
            "contract",
            "bytes",
            "in_flight",
            "complete",
            "observed",
            "boot_id",
        ],
    )?;
    let observed = value["observed"]
        .as_f64()
        .filter(|n| n.is_finite() && *n > 0.0 && *n < 253402300800.0);
    if value["contract"] != "socket-payload-v1"
        || value["boot_id"] != boot
        || value["bytes"].as_u64().is_none()
        || observed.is_none()
        || !value["complete"].is_boolean()
    {
        return Err(Error::invalid("invalid egress measurement"));
    }
    let inflight = integer(&value["in_flight"], 0, 128)?;
    if value["complete"] == true
        && (inflight != 0 || !matches!(state, "exited" | "stopped" | "failed"))
    {
        return Err(Error::invalid(
            "egress completeness requires confirmed terminal coverage",
        ));
    }
    Ok(())
}
