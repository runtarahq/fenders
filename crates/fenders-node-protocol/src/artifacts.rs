//! Metadata accepted only from an operator-owned compiler through an authenticated
//! node. Customers submit component bytes, never an inspection result.
use crate::{
    error::{Error, Result},
    model::MAX_UPLOAD_CEILING,
    value::*,
};
use serde_json::Value;

pub const RUNTIME: &str = "wasmtime-50.0.0-fenders-v1";
pub const MAX_INSPECTION_BYTES: usize = 65536;

pub fn component_rejection(code: &str) -> Option<&'static str> {
    match code {
        "component-not-accepted" => Some("component-not-accepted"),
        "invalid-component" => Some("invalid-component"),
        "unsupported-imports" => Some("unsupported-imports"),
        "incompatible-entry-points" => Some("incompatible-entry-points"),
        "interface-limits" => Some("interface-limits"),
        _ => None,
    }
}

/// Accept only bounded, identity-bound compiler receipts, never stderr text.
pub fn validate_rejection(value: &Value, digest: &str, size: usize) -> Result<&'static str> {
    let keys = ["format_version", "runtime", "digest", "bytes", "error"];
    fields(value, &keys, &keys)?;
    if value["format_version"] != 1
        || value["runtime"] != RUNTIME
        || value["digest"] != digest
        || value["bytes"].as_u64() != Some(size as u64)
        || !(8..=MAX_UPLOAD_CEILING).contains(&size)
        || component_rejection(s(&value["error"])).is_none()
    {
        return Err(Error::invalid("invalid component rejection receipt"));
    }
    component_rejection(s(&value["error"])).ok_or_else(|| Error::invalid("unknown rejection code"))
}

pub fn validate_inspection(value: &Value, digest: &str, size: usize) -> Result<()> {
    fields(
        value,
        &[
            "format_version",
            "runtime",
            "digest",
            "bytes",
            "http",
            "command",
            "imports",
            "exports",
        ],
        &[
            "format_version",
            "runtime",
            "digest",
            "bytes",
            "http",
            "command",
            "imports",
            "exports",
        ],
    )?;
    if value["format_version"] != 1
        || value["runtime"] != RUNTIME
        || value["digest"] != digest
        || value["bytes"].as_u64() != Some(size as u64)
        || !(8..=MAX_UPLOAD_CEILING).contains(&size)
        || !value["http"].is_boolean()
        || !value["command"].is_boolean()
        || (value["http"] != true && value["command"] != true)
        || serde_json::to_vec(value)
            .map_err(|_| Error::internal())?
            .len()
            > MAX_INSPECTION_BYTES
    {
        return Err(Error::invalid(
            "invalid component inspection identity or capabilities",
        ));
    }
    for key in ["imports", "exports"] {
        let names = value[key]
            .as_array()
            .filter(|v| v.len() <= 128)
            .ok_or_else(|| Error::invalid("invalid component interfaces"))?;
        if names.iter().any(|name| {
            name.as_str().is_none_or(|name| {
                name.is_empty() || name.len() > 256 || name.chars().any(char::is_control)
            })
        }) || names.windows(2).any(|pair| s(&pair[0]) >= s(&pair[1]))
        {
            return Err(Error::invalid(
                "component interfaces must be bounded and sorted uniquely",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn rejects_forged_or_unbounded_inspection_receipts() {
        let value = json!({"format_version":1,"runtime":RUNTIME,"digest":"a".repeat(64),"bytes":100,"http":false,"command":true,"imports":[],"exports":["wasi:cli/run@0.2.3"]});
        validate_inspection(&value, &"a".repeat(64), 100).unwrap();
        assert!(validate_inspection(&value, &"b".repeat(64), 100).is_err());
        assert!(validate_inspection(&value, &"a".repeat(64), 101).is_err());
        for (key, changed) in [
            ("format_version", json!(2)),
            ("runtime", json!("different-runtime")),
            ("http", json!("true")),
            ("command", json!(false)),
            ("exports", json!(["duplicate", "duplicate"])),
            ("imports", json!(["x".repeat(257)])),
            ("imports", json!(null)),
        ] {
            let mut invalid = value.clone();
            invalid[key] = changed;
            assert!(
                validate_inspection(&invalid, &"a".repeat(64), 100).is_err(),
                "accepted {key}"
            );
        }
    }
}
