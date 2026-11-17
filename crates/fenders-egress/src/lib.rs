//! Shared, dependency-free policy for the IPv4 native transport. DNS belongs to
//! the control plane: a guest receives immutable, numeric destination bindings.
use std::{
    collections::BTreeMap,
    net::{Ipv4Addr, SocketAddrV4},
};

pub const MAX_ORIGINS: usize = 16;
pub const MAX_ADDRESSES: usize = 4;
pub const MAX_ENDPOINTS: usize = 32;
pub const MAX_POLICY_BYTES: usize = 2048;
pub type Result<T> = std::result::Result<T, &'static str>;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Origin {
    tls: bool,
    host: String,
    port: u16,
}

impl Origin {
    /// Normalize an ASCII origin, optionally with a single trailing slash.
    /// Credentials, URL paths, escapes, IPv6 and ambiguous numeric names fail.
    pub fn parse(input: &str) -> Result<Self> {
        if input.len() > 280 || !input.is_ascii() {
            return Err("invalid origin");
        }
        let (scheme, authority) = input.split_once("://").ok_or("invalid origin")?;
        let tls = if scheme.eq_ignore_ascii_case("https") {
            true
        } else if scheme.eq_ignore_ascii_case("http") {
            false
        } else {
            return Err("invalid origin scheme");
        };
        let authority = authority.strip_suffix('/').unwrap_or(authority);
        let (host, port) = match authority.split_once(':') {
            Some((host, port)) => {
                if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
                    return Err("invalid origin port");
                }
                (
                    host,
                    port.parse::<u16>().map_err(|_| "invalid origin port")?,
                )
            }
            None => (authority, if tls { 443 } else { 80 }),
        };
        if port == 0 || host.is_empty() || host.len() > 253 {
            return Err("invalid origin");
        }
        let host = host.to_ascii_lowercase();
        if !host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        }) {
            return Err("invalid origin hostname");
        }
        let last = host.rsplit('.').next().unwrap();
        let numeric = last.bytes().all(|b| b.is_ascii_digit())
            || last
                .strip_prefix("0x")
                .is_some_and(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_hexdigit()));
        if numeric
            && host
                .parse::<Ipv4Addr>()
                .ok()
                .is_none_or(|ip| ip.to_string() != host)
        {
            return Err("ambiguous numeric hostname");
        }
        Ok(Self { tls, host, port })
    }
    pub fn host(&self) -> &str {
        &self.host
    }
    pub fn port(&self) -> u16 {
        self.port
    }
    pub fn tls(&self) -> bool {
        self.tls
    }
    pub fn authority(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
    pub fn public_https(input: &str) -> Result<Self> {
        let origin = Self::parse(input)?;
        if !origin.tls || !origin.host.contains('.') || origin.host.ends_with(".localhost") {
            return Err("public destination requires HTTPS");
        }
        if let Ok(ip) = origin.host.parse::<Ipv4Addr>()
            && !is_public_v4(ip)
        {
            return Err("non-public destination");
        }
        Ok(origin)
    }
}
impl std::fmt::Display for Origin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}://{}:{}",
            if self.tls { "https" } else { "http" },
            self.host,
            self.port
        )
    }
}

/// Conservative policy: deny whole special-use blocks, including their narrow
/// globally reachable exceptions. Also deny multicast and reserved addresses.
/// Source: https://www.iana.org/assignments/iana-ipv4-special-registry/
pub fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(ip.octets() == [168, 63, 129, 16] // Azure host platform/WireServer.
        || matches!(a, 0 | 10 | 127 | 224..=255)
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192
            && (b == 168
                || (b == 0 && matches!(c, 0 | 2))
                || (b == 88 && c == 99)
                || (b == 31 && c == 196)
                || (b == 52 && c == 193)
                || (b == 175 && c == 48)))
        || (a == 198 && (matches!(b, 18 | 19) || (b == 51 && c == 100)))
        || (a == 203 && b == 0 && c == 113))
}

/// Operator-owned management/fabric ranges must be denied even if globally
/// routed. Parsing requires canonical networks, so a typo cannot widen access.
#[derive(Clone, Debug)]
pub struct DeniedRange {
    network: u32,
    mask: u32,
}
impl DeniedRange {
    pub fn parse(input: &str) -> Result<Self> {
        let (address, prefix) = input.split_once('/').ok_or("invalid denied range")?;
        let ip = address
            .parse::<Ipv4Addr>()
            .map_err(|_| "invalid denied range")?;
        let bits = prefix.parse::<u32>().map_err(|_| "invalid denied range")?;
        if bits > 32 || bits.to_string() != prefix || ip.to_string() != address {
            return Err("invalid denied range");
        }
        let mask = if bits == 0 {
            0
        } else {
            u32::MAX << (32 - bits)
        };
        let network = u32::from(ip);
        if network & mask != network {
            return Err("denied range has host bits");
        }
        Ok(Self { network, mask })
    }
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        u32::from(ip) & self.mask == self.network
    }
}

#[derive(Clone, Debug, Default)]
pub struct PublicTargets(BTreeMap<Origin, Vec<SocketAddrV4>>);
impl PublicTargets {
    /// Validate every answer, before deduplication/truncation. A mixed public
    /// and private response is an error, never a partially accepted grant.
    pub fn insert(
        &mut self,
        origin: Origin,
        answers: &[Ipv4Addr],
        denied: &[DeniedRange],
    ) -> Result<()> {
        Origin::public_https(&origin.to_string())?;
        if self.0.len() >= MAX_ORIGINS
            || self.0.contains_key(&origin)
            || answers.is_empty()
            || answers.len() > MAX_ADDRESSES
        {
            return Err("invalid public destination count");
        }
        let mut endpoints = Vec::new();
        for ip in answers {
            if !is_public_v4(*ip)
                || denied.iter().any(|r| r.contains(*ip))
                || origin
                    .host
                    .parse::<Ipv4Addr>()
                    .is_ok_and(|host| host != *ip)
            {
                return Err("non-public or mismatched destination");
            }
            let endpoint = SocketAddrV4::new(*ip, origin.port);
            if endpoints.contains(&endpoint) {
                return Err("duplicate public address");
            }
            endpoints.push(endpoint);
        }
        endpoints.sort();
        if self.0.values().map(Vec::len).sum::<usize>() + endpoints.len() > MAX_ENDPOINTS {
            return Err("too many public endpoints");
        }
        // Check without changing the previous policy on failure.
        let added_bytes = origin.to_string().len()
            + 1
            + endpoints
                .iter()
                .map(|s| s.ip().to_string().len())
                .sum::<usize>()
            + endpoints.len()
            - 1
            + usize::from(!self.0.is_empty());
        if self.encode().len() + added_bytes > MAX_POLICY_BYTES {
            return Err("public policy too large");
        }
        self.0.insert(origin, endpoints);
        Ok(())
    }
    /// Wire format is canonical HTTPS origin=IPv4,IPv4;origin=IPv4. Ports
    /// come exclusively from the origin and cannot be changed by DNS answers.
    pub fn parse(policy: &str) -> Result<Self> {
        if policy.len() > MAX_POLICY_BYTES {
            return Err("public policy too large");
        }
        let mut parsed = Self::default();
        if policy.is_empty() {
            return Ok(parsed);
        }
        for entry in policy.split(';') {
            let (name, addresses) = entry.split_once('=').ok_or("invalid public policy")?;
            let origin = Origin::public_https(name)?;
            if origin.to_string() != name {
                return Err("noncanonical public origin");
            }
            let mut answers = Vec::new();
            for address in addresses.split(',') {
                let ip = address
                    .parse::<Ipv4Addr>()
                    .map_err(|_| "invalid public address")?;
                if ip.to_string() != address {
                    return Err("noncanonical public address");
                }
                answers.push(ip);
                if answers.len() > MAX_ADDRESSES {
                    return Err("too many public addresses");
                }
            }
            parsed.insert(origin, &answers, &[])?;
        }
        Ok(parsed)
    }
    pub fn encode(&self) -> String {
        self.0
            .iter()
            .map(|(o, a)| {
                format!(
                    "{o}={}",
                    a.iter()
                        .map(|s| s.ip().to_string())
                        .collect::<Vec<_>>()
                        .join(",")
                )
            })
            .collect::<Vec<_>>()
            .join(";")
    }
    pub fn get(&self, origin: &Origin) -> Option<&[SocketAddrV4]> {
        self.0.get(origin).map(Vec::as_slice)
    }
    pub fn iter(&self) -> impl Iterator<Item = (&Origin, &[SocketAddrV4])> {
        self.0.iter().map(|(o, a)| (o, a.as_slice()))
    }
}
