//! Application HTTP boundary shared by the public gateway and node.
//! Keep an allowlist: cookies, forwarding identity, framing and arbitrary headers
//! must not cross tenants. In particular, Set-Cookie could target apps.example.com.
use crate::error::{Error, Result};
use axum::http::{HeaderMap, HeaderName, HeaderValue};
use serde_json::{Map, Value};

const REQUEST: &[&str] = &[
    "content-type",
    "accept",
    "x-request-id",
    "authorization",
    "accept-encoding",
    "if-none-match",
    "if-modified-since",
];
const RESPONSE: &[&str] = &[
    "content-type",
    "location",
    "cache-control",
    "content-encoding",
    "vary",
    "etag",
    "last-modified",
    "expires",
];
const MAX_BYTES: usize = 8192;

/// Decode the internal wire map without trusting the sending hop's filtering.
pub fn from_json(value: &Value) -> Result<HeaderMap> {
    let mut headers = HeaderMap::new();
    let mut bytes = 0;
    for (name, value) in value
        .as_object()
        .ok_or_else(|| Error::invalid("invalid headers"))?
    {
        let value = value
            .as_str()
            .ok_or_else(|| Error::invalid("invalid header value"))?;
        bytes += name.len() + value.len();
        if bytes > MAX_BYTES {
            return Err(Error::invalid("application headers too large"));
        }
        headers.append(
            HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| Error::invalid("invalid header name"))?,
            HeaderValue::from_str(value).map_err(|_| Error::invalid("invalid header value"))?,
        );
    }
    Ok(headers)
}

pub fn request(headers: &HeaderMap, forward_authorization: bool) -> Result<Map<String, Value>> {
    select(headers, REQUEST, forward_authorization)
}

pub fn response(headers: &HeaderMap) -> Result<Map<String, Value>> {
    select(headers, RESPONSE, false)
}

fn select(
    headers: &HeaderMap,
    allowed: &[&str],
    forward_authorization: bool,
) -> Result<Map<String, Value>> {
    // Reject Connection nominations of application headers rather than silently
    // losing encoding/validator metadata while forwarding the associated body.
    for value in headers.get_all("connection") {
        let value = value
            .to_str()
            .map_err(|_| Error::invalid("invalid Connection header"))?;
        if value.split(',').any(|token| {
            allowed
                .iter()
                .any(|name| token.trim().eq_ignore_ascii_case(name))
        }) {
            return Err(Error::invalid("Connection nominates an application header"));
        }
    }
    let mut result = Map::new();
    let mut bytes = 0;
    for &name in allowed {
        if name == "authorization" && !forward_authorization {
            continue;
        }
        let values = headers
            .get_all(name)
            .iter()
            .map(|v| {
                v.to_str()
                    .map_err(|_| Error::invalid("invalid application header"))
            })
            .collect::<Result<Vec<_>>>()?;
        if values.is_empty() {
            continue;
        }
        // Preserve repeated list-valued fields (especially Vary and validators).
        if values.len() > 1
            && !matches!(
                name,
                "accept"
                    | "accept-encoding"
                    | "if-none-match"
                    | "vary"
                    | "cache-control"
                    | "content-encoding"
            )
        {
            return Err(Error::invalid("duplicate application header"));
        }
        let value = values.join(", ");
        if name == "authorization"
            && value.split_once(' ').is_some_and(|(scheme, token)| {
                scheme.eq_ignore_ascii_case("bearer") && token.trim_start().starts_with("fnd_")
            })
        {
            continue;
        }
        bytes += name.len() + value.len();
        if bytes > MAX_BYTES {
            return Err(Error::invalid("application headers too large"));
        }
        result.insert(name.to_owned(), Value::String(value));
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn encoding_and_validators_survive_both_boundaries() {
        let request_json = json!({"Accept-Encoding":"br, gzip", "If-None-Match":"W/\"one\", \"two\"", "If-Modified-Since":"Wed, 21 Oct 2015 07:28:00 GMT", "cookie":"secret", "forwarded":"for=internal", "connection":"close"});
        let first = request(&from_json(&request_json).unwrap(), true).unwrap();
        let second = request(&from_json(&Value::Object(first.clone())).unwrap(), true).unwrap();
        assert_eq!(first, second);
        assert_eq!(second.len(), 3);
        assert_eq!(second["accept-encoding"], "br, gzip");
        let response_json = json!({"Content-Encoding":"br", "ETag":"\"one\"", "Last-Modified":"Wed, 21 Oct 2015 07:28:00 GMT", "Expires":"Wed, 21 Oct 2030 07:28:00 GMT", "Vary":"Accept-Encoding", "Set-Cookie":"session=bad; Domain=apps.example.com", "Content-Length":"100", "Transfer-Encoding":"chunked"});
        let first = response(&from_json(&response_json).unwrap()).unwrap();
        assert_eq!(first.len(), 5);
        assert_eq!(
            response(&from_json(&Value::Object(first.clone())).unwrap()).unwrap(),
            first
        );
    }
    #[test]
    fn repeated_lists_survive_and_credentials_do_not_leak() {
        let mut headers = HeaderMap::new();
        headers.append("vary", HeaderValue::from_static("Origin"));
        headers.append("vary", HeaderValue::from_static("Accept-Encoding"));
        assert_eq!(
            response(&headers).unwrap()["vary"],
            "Origin, Accept-Encoding"
        );
        for credential in [
            "Bearer fnd_secret",
            "bearer fnd_secret",
            "Bearer customer-token",
        ] {
            headers.insert("authorization", HeaderValue::from_str(credential).unwrap());
            assert!(
                !request(&headers, false)
                    .unwrap()
                    .contains_key("authorization")
            );
            assert_eq!(
                request(&headers, true)
                    .unwrap()
                    .contains_key("authorization"),
                credential.ends_with("customer-token")
            );
        }
    }
    #[test]
    fn reject_ambiguous_encoding_and_oversized_headers() {
        assert!(
            response(
                &from_json(&json!({"connection":"Content-Encoding", "content-encoding":"br"}))
                    .unwrap()
            )
            .is_err()
        );
        assert!(from_json(&json!({"etag":"a".repeat(MAX_BYTES)})).is_err());
        assert!(from_json(&json!({"etag":"x\r\nSet-Cookie: bad"})).is_err());
    }
}
