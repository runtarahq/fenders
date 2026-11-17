//! Bounded JSON field accessors and validators shared by both protocol peers.
use crate::error::{Error, Result};
use serde_json::Value;

pub fn s(value: &Value) -> &str {
    value.as_str().unwrap_or("")
}
pub fn n(value: &Value) -> i64 {
    value.as_i64().unwrap_or(0)
}
pub fn b(value: &Value) -> bool {
    value.as_bool().unwrap_or(false)
}
pub fn fields(value: &Value, allowed: &[&str], required: &[&str]) -> Result<()> {
    let o = value
        .as_object()
        .ok_or_else(|| Error::invalid("expected object"))?;
    if o.keys().any(|k| !allowed.contains(&k.as_str()))
        || required.iter().any(|k| !o.contains_key(*k))
    {
        return Err(Error::invalid("invalid or missing fields"));
    }
    Ok(())
}
pub fn integer(value: &Value, low: i64, high: i64) -> Result<i64> {
    value
        .as_i64()
        .filter(|n| (low..=high).contains(n))
        .ok_or_else(|| Error::invalid("integer outside supported bounds"))
}
pub fn text(value: &Value) -> Result<&str> {
    value
        .as_str()
        .ok_or_else(|| Error::invalid("expected string"))
}
pub fn named(value: &Value) -> Result<&str> {
    let v = text(value)?;
    crate::model::name(v)?;
    Ok(v)
}
pub fn id(value: &Value) -> Result<&str> {
    let v = value.as_str().ok_or_else(Error::missing)?;
    crate::model::identity(v)?;
    Ok(v)
}
pub fn get(value: &Value, key: &str, default: Value) -> Value {
    value.get(key).cloned().unwrap_or(default)
}
pub fn conflict(message: &'static str) -> Error {
    Error::new(axum::http::StatusCode::CONFLICT, message)
}
pub fn quota(message: &'static str) -> Error {
    Error::new(axum::http::StatusCode::TOO_MANY_REQUESTS, message)
}
