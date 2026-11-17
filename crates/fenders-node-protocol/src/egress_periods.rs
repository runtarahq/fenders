//! Source-month socket observations. Never infer a month from receipt time or
//! split a cumulative counter by elapsed time. Gateway admission is separate.
use crate::{
    error::{Error, Result},
    value::*,
};
use chrono::{DateTime, Datelike, NaiveDate, Utc};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub fn invalid() -> Error {
    Error::invalid("invalid monthly egress measurement")
}
pub fn month(date: NaiveDate) -> i32 {
    date.year() * 12 + date.month() as i32
}
pub fn observed(value: &Value) -> Result<DateTime<Utc>> {
    DateTime::from_timestamp(value["observed"].as_f64().ok_or_else(invalid)? as i64, 0)
        .ok_or_else(invalid)
}
pub fn periods(value: &Value) -> Result<BTreeMap<NaiveDate, u64>> {
    let entries = value["periods"]
        .as_array()
        .filter(|p| p.len() <= 24)
        .ok_or_else(invalid)?;
    let mut result = BTreeMap::new();
    for entry in entries {
        fields(entry, &["period", "bytes"], &["period", "bytes"])?;
        let text = entry["period"].as_str().ok_or_else(invalid)?;
        let date = NaiveDate::parse_from_str(text, "%Y-%m-%d").map_err(|_| invalid())?;
        if date.day() != 1
            || !(1970..=9999).contains(&date.year())
            || date.format("%Y-%m-%d").to_string() != text
        {
            return Err(invalid());
        }
        if result
            .insert(date, entry["bytes"].as_u64().ok_or_else(invalid)?)
            .is_some()
        {
            return Err(invalid());
        }
    }
    Ok(result)
}

pub fn validate(value: &Value, state: &str, boot: &str) -> Result<()> {
    fields(
        value,
        &[
            "contract",
            "bytes",
            "expired_bytes",
            "periods",
            "in_flight",
            "complete",
            "observed",
            "boot_id",
        ],
        &[
            "contract",
            "bytes",
            "expired_bytes",
            "periods",
            "in_flight",
            "complete",
            "observed",
            "boot_id",
        ],
    )?;
    if value["contract"] != "socket-payload-utc-month-v1" {
        return Err(invalid());
    }
    crate::egress_usage::validate(
        &json!({"contract":"socket-payload-v1","bytes":value["bytes"],
        "in_flight":value["in_flight"],"complete":value["complete"],"observed":value["observed"],"boot_id":value["boot_id"]}),
        state,
        boot,
    )?;
    let entries = periods(value)?;
    let expired = value["expired_bytes"].as_u64().ok_or_else(invalid)?;
    let total = entries
        .values()
        .try_fold(expired, |sum, n| sum.checked_add(*n))
        .ok_or_else(invalid)?;
    if Some(total) != value["bytes"].as_u64() || (expired > 0 && entries.is_empty()) {
        return Err(invalid());
    }
    if let (Some(first), Some(last)) = (entries.keys().next(), entries.keys().next_back())
        && (month(*last) - month(*first) >= 24
            || month(*last) > month(observed(value)?.date_naive()))
    {
        return Err(invalid());
    }
    Ok(())
}
