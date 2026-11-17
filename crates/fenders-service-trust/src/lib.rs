//! Bounded origin-specific CA transport shared by the node and kernel-free
//! runtime. This selects trust; it does not authorize destinations or skip TLS.
pub const MAX_POLICY_BYTES: usize = 2048;
pub const MAX_GUEST_ENV_BYTES: usize = 4096;

#[derive(Debug, PartialEq, Eq)]
pub struct InvalidPolicy;

fn origin(value: &str) -> bool {
    let Some(authority) = value.strip_prefix("https://") else {
        return false;
    };
    let Some((host, port)) = authority.split_once(':') else {
        return false;
    };
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
        && port
            .parse::<u16>()
            .is_ok_and(|p| p != 0 && p.to_string() == port)
}

pub fn decode_der(hex: &str) -> Result<Vec<u8>, InvalidPolicy> {
    if hex.is_empty() || hex.len() > 8192 || !hex.len().is_multiple_of(2) {
        return Err(InvalidPolicy);
    }
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            if !pair.iter().all(u8::is_ascii_hexdigit) {
                return Err(InvalidPolicy);
            }
            u8::from_str_radix(std::str::from_utf8(pair).map_err(|_| InvalidPolicy)?, 16)
                .map_err(|_| InvalidPolicy)
        })
        .collect()
}

/// Canonical origin=DER-hex entries separated by semicolons. Malformed policy
/// fails as a whole, even when the requested origin has no private trust entry.
pub fn parse(policy: &str) -> Result<Vec<(&str, Vec<u8>)>, InvalidPolicy> {
    if policy.len() > MAX_POLICY_BYTES {
        return Err(InvalidPolicy);
    }
    if policy.is_empty() {
        return Ok(Vec::new());
    }
    let mut entries = Vec::new();
    for entry in policy.split(';') {
        let (name, hex) = entry.split_once('=').ok_or(InvalidPolicy)?;
        if entries.len() == 32 || !origin(name) || entries.iter().any(|(n, _)| *n == name) {
            return Err(InvalidPolicy);
        }
        entries.push((name, decode_der(hex)?));
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn distinct_explicit_https_origins_and_empty_public_policy() {
        assert_eq!(parse("").unwrap().len(), 0);
        assert_eq!(
            parse("https://10.0.0.2:443=dead;https://service.test:8443=BEEF").unwrap(),
            vec![
                ("https://10.0.0.2:443", vec![0xde, 0xad]),
                ("https://service.test:8443", vec![0xbe, 0xef])
            ]
        );
    }
    #[test]
    fn policy_rejects_ambiguous_unbounded_and_malformed_entries() {
        for invalid in [
            "http://a:443=aa",
            "https://a=aa",
            "https://A:443=aa",
            "https://a:0=aa",
            "https://a:0443=aa",
            "https://a:65536=aa",
            "https://a:443/=aa",
            "https://u@a:443=aa",
            "https://a:443?x=aa",
            "https://[::1]:443=aa",
            "https://a:443=aa;https://a:443=bb",
            "https://a:443=",
            "https://a:443=abc",
            "https://a:443=zz",
            "https://a:443=aa;",
            "https://a:443=aa\n",
            "https://a..b:443=aa",
            "https://-a:443=aa",
        ] {
            assert!(parse(invalid).is_err(), "{invalid}");
        }
        assert!(parse(&format!("https://a:443={}", "aa".repeat(MAX_POLICY_BYTES))).is_err());
        let too_many = (0..33)
            .map(|i| format!("https://h{i}:443=aa"))
            .collect::<Vec<_>>()
            .join(";");
        assert!(parse(&too_many).is_err());
    }
}
