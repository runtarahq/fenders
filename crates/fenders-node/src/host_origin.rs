//! The guest's host-bound origin: the path check the run channel's relay
//! (fenders-shim) applies to every request the guest sends.
use fenders_node_protocol::error::{Error, Result};

/// A guest path that cannot leave the route's prefix on the peer, however the
/// peer decodes it. Decoded once, it must be rooted and hold no `%` (so no
/// double encoding), `;` (no path parameters), backslash or control character,
/// and no `.` or `..` segment; an encoded `/` is refused outright.
pub fn confined(path_and_query: &str) -> Result<&str> {
    let invalid = || Error::invalid("host-bound request path escapes its route");
    let path = path_and_query.split('?').next().unwrap_or_default();
    if path.to_ascii_lowercase().contains("%2f") {
        return Err(invalid());
    }
    let mut decoded = Vec::with_capacity(path.len());
    let mut bytes = path.bytes();
    while let Some(byte) = bytes.next() {
        if byte != b'%' {
            decoded.push(byte);
            continue;
        }
        let hex = [bytes.next(), bytes.next()];
        let [Some(high), Some(low)] = hex else {
            return Err(invalid());
        };
        let value = std::str::from_utf8(&[high, low])
            .ok()
            .and_then(|hex| u8::from_str_radix(hex, 16).ok())
            .ok_or_else(invalid)?;
        decoded.push(value);
    }
    if decoded.first() != Some(&b'/')
        || decoded
            .iter()
            .any(|b| matches!(b, b'%' | b';' | b'\\') || b.is_ascii_control())
        || decoded
            .split(|b| *b == b'/')
            .any(|segment| segment == b"." || segment == b"..")
    {
        return Err(invalid());
    }
    Ok(path_and_query)
}

#[cfg(test)]
mod tests {
    use super::confined;
    #[test]
    fn paths_cannot_leave_their_route() {
        for good in [
            "/",
            "/v1/run",
            "/v1/run?step=1&next=..%2Fx",
            "/a.b/c..d",
            "/a%20b",
        ] {
            assert!(confined(good).is_ok(), "{good}");
        }
        for bad in [
            "v1",
            "/..",
            "/v1/../x",
            "/v1/./x",
            "/%2e%2e/x",
            "/.%2E/x",
            "/v1%2fx",
            "/v1%5Cx",
            "/v1\\x",
            "/x%00",
            "/..;/x",
            "/v1/..;jsessionid=1/x",
            "/%252e%252e/x",
            "/%2e%2e%3b/x",
            "/x%2",
            "/x%zz",
            "/x\tx",
        ] {
            assert!(confined(bad).is_err(), "{bad}");
        }
    }
}
