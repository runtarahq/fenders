//! Operator-owned DNS-over-TLS resolution for immutable public HTTPS bindings.
//! Resolution is deliberately outside database admission transactions. Callers
//! must recheck scoped intent and recovery/generation fences before using it.
use crate::error::{Error, Result};
use axum::http::StatusCode;
use fenders_egress::{DeniedRange, Origin, PublicTargets};
use hickory_resolver::{
    Resolver, TokioResolver,
    config::{ConnectionConfig, NameServerConfig, ResolveHosts, ResolverConfig, ResolverOpts},
    lookup::Lookup,
    net::runtime::TokioRuntimeProvider,
    proto::rr::{DNSClass, Name, RData, RecordType},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    io::Read,
    net::{Ipv4Addr, SocketAddrV4},
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};

const CONFIG_BYTES: usize = 64 * 1024;
const MAX_CONCURRENT_BATCHES: usize = 16;
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(2);
const BATCH_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_TTL: Duration = Duration::from_secs(300);

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicEgressConfig {
    pub dns_address: SocketAddrV4,
    pub dns_server_name: String,
    /// Optional private CA for the operator's resolver, never for app HTTPS.
    pub dns_ca_pem: Option<String>,
    /// Required explicitly, even if all management addresses are special-use.
    pub denied_ipv4: Vec<String>,
}
impl PublicEgressConfig {
    pub fn read(path: &Path) -> Result<Self> {
        let mut bytes = Vec::new();
        std::fs::File::open(path)?
            .take(CONFIG_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > CONFIG_BYTES {
            return Err(Error::invalid("public egress configuration is too large"));
        }
        serde_json::from_slice(&bytes)
            .map_err(|_| Error::invalid("invalid public egress configuration"))
    }
}

#[derive(Clone)]
pub struct PublicEgress {
    resolver: TokioResolver,
    denied: Arc<Vec<DeniedRange>>,
    policy_digest: String,
    slots: Arc<tokio::sync::Semaphore>,
}

pub struct ResolvedTargets {
    targets: PublicTargets,
    expires: Instant,
    policy_digest: String,
}
impl ResolvedTargets {
    /// Recompute after acquiring admission locks; never persist the original
    /// TTL as if no time had elapsed while a result waited to be consumed.
    pub fn remaining_ttl(&self) -> Duration {
        self.expires.saturating_duration_since(Instant::now())
    }
    pub fn policy_digest(&self) -> &str {
        &self.policy_digest
    }
    pub fn launch_policy(&self) -> Result<String> {
        if self.remaining_ttl().is_zero() {
            return Err(unavailable("public HTTPS resolution expired"));
        }
        Ok(self.targets.encode())
    }
}

fn unavailable(message: &'static str) -> Error {
    Error::new(StatusCode::SERVICE_UNAVAILABLE, message)
}

fn resolved_addresses(lookup: &Lookup, origin: &Origin) -> Result<Vec<Ipv4Addr>> {
    let invalid = || unavailable("public HTTPS DNS answer is invalid");
    let message = lookup.message();
    if message.queries.len() != 1 || lookup.answers().len() > 32 {
        return Err(invalid());
    }
    let question = &message.queries[0];
    if question.query_type() != RecordType::A || question.query_class() != DNSClass::IN {
        return Err(invalid());
    }
    let mut terminal = Name::from_ascii(format!("{}.", origin.host())).map_err(|_| invalid())?;
    let mut chain = BTreeSet::new();
    loop {
        if !chain.insert(terminal.clone()) || chain.len() > 9 {
            return Err(invalid());
        }
        let mut next = None;
        let mut has_address = false;
        for record in lookup.answers().iter().filter(|r| r.name == terminal) {
            if record.dns_class != DNSClass::IN {
                return Err(invalid());
            }
            match &record.data {
                RData::CNAME(name) => {
                    if next.replace(name.0.clone()).is_some() {
                        return Err(invalid());
                    }
                }
                RData::A(_) => has_address = true,
                _ => {}
            }
        }
        match next {
            Some(_) if has_address => return Err(invalid()),
            Some(name) => terminal = name,
            None => break,
        }
    }
    // A multi-query CNAME lookup retains the last query's question. It must
    // still belong to this original name's validated chain.
    if !chain.contains(question.name()) {
        return Err(invalid());
    }
    let mut addresses = Vec::new();
    for record in lookup.answers() {
        match &record.data {
            RData::A(ip) => {
                if record.name != terminal || record.dns_class != DNSClass::IN {
                    return Err(invalid());
                }
                addresses.push(ip.0);
            }
            RData::CNAME(_) if !chain.contains(&record.name) => return Err(invalid()),
            _ => {}
        }
    }
    Ok(addresses)
}

impl PublicEgress {
    pub fn new(mut config: PublicEgressConfig) -> Result<Self> {
        if config.dns_address.port() == 0
            || config.dns_address.ip().is_unspecified()
            || config.dns_address.ip().is_multicast()
            || config.dns_address.ip().is_broadcast()
            || config.denied_ipv4.len() > 256
            || config
                .dns_ca_pem
                .as_ref()
                .is_some_and(|v| v.len() > 32 * 1024)
        {
            return Err(Error::invalid("invalid public egress configuration"));
        }
        let name = Origin::parse(&format!("https://{}", config.dns_server_name))
            .map_err(|_| Error::invalid("invalid DNS TLS server name"))?;
        if !name.host().eq_ignore_ascii_case(&config.dns_server_name) {
            return Err(Error::invalid("invalid DNS TLS server name"));
        }
        config.dns_server_name = name.host().to_owned();
        // Never allow applications to reach the resolver itself, including a
        // globally routed operator DNS address, on any port.
        config
            .denied_ipv4
            .push(format!("{}/32", config.dns_address.ip()));
        config.denied_ipv4.sort();
        config.denied_ipv4.dedup();
        let denied = config
            .denied_ipv4
            .iter()
            .map(|range| {
                DeniedRange::parse(range)
                    .map_err(|_| Error::invalid("invalid public egress denied IPv4 range"))
            })
            .collect::<Result<Vec<_>>>()?;
        let mut roots = rustls::RootCertStore::empty();
        if let Some(pem) = &config.dns_ca_pem {
            let certificates = rustls_pemfile::certs(&mut pem.as_bytes())
                .collect::<std::io::Result<Vec<_>>>()
                .map_err(|_| Error::invalid("invalid DNS CA"))?;
            if certificates.is_empty() || certificates.len() > 16 {
                return Err(Error::invalid("invalid DNS CA"));
            }
            for certificate in certificates {
                roots
                    .add(certificate)
                    .map_err(|_| Error::invalid("invalid DNS CA"))?;
            }
        } else {
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|_| Error::internal())?
        .with_root_certificates(roots)
        .with_no_client_auth();
        tls.resumption = rustls::client::Resumption::disabled();
        let mut connection = ConnectionConfig::tls(Arc::from(config.dns_server_name.as_str()));
        connection.port = config.dns_address.port();
        let server =
            NameServerConfig::new((*config.dns_address.ip()).into(), true, vec![connection]);
        let mut options = ResolverOpts::default();
        options.timeout = LOOKUP_TIMEOUT;
        options.attempts = 1;
        options.num_concurrent_reqs = 1;
        options.max_active_requests = MAX_CONCURRENT_BATCHES;
        options.cache_size = 0;
        options.use_hosts_file = ResolveHosts::Never;
        options.positive_min_ttl = Some(Duration::ZERO);
        options.positive_max_ttl = Some(MAX_TTL);
        options.negative_min_ttl = Some(Duration::ZERO);
        options.negative_max_ttl = Some(Duration::ZERO);
        options.preserve_intermediates = true;
        // Do not use Hickory's answer filters: dropping bad answers here would
        // hide a mixed rebinding response from the all-or-nothing policy check.
        options.allow_answers.clear();
        options.deny_answers.clear();
        let resolver = Resolver::builder_with_config(
            ResolverConfig::from_name_servers(vec![server]),
            TokioRuntimeProvider::default(),
        )
        .with_options(options)
        .with_tls_config(tls)
        .build()
        .map_err(|_| Error::invalid("invalid DNS resolver configuration"))?;
        let mut digest = Sha256::new();
        digest.update(b"fenders-public-egress-v1\0");
        digest.update(serde_json::to_vec(&config).map_err(|_| Error::internal())?);
        let policy_digest = format!("{:x}", digest.finalize());
        Ok(Self {
            resolver,
            denied: Arc::new(denied),
            policy_digest,
            slots: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_BATCHES)),
        })
    }

    pub fn policy_digest(&self) -> &str {
        &self.policy_digest
    }

    pub async fn resolve(&self, origins: &[String]) -> Result<ResolvedTargets> {
        if origins.is_empty() || origins.len() > fenders_egress::MAX_ORIGINS {
            return Err(Error::invalid("invalid public HTTPS origin count"));
        }
        let mut normalized = BTreeSet::new();
        for value in origins {
            let origin = Origin::public_https(value)
                .map_err(|_| Error::invalid("invalid public HTTPS origin"))?;
            if !normalized.insert(origin) {
                return Err(Error::invalid("duplicate public HTTPS origin"));
            }
        }
        let permit = self
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| unavailable("public HTTPS resolver capacity exhausted"))?;
        let this = self.clone();
        // Hold the slot until bounded DNS work actually stops, even if the
        // caller disconnects. Cancellation cannot create an unbounded queue
        // of detached lookups or release admission capacity prematurely.
        tokio::spawn(async move {
            let _permit = permit;
            tokio::time::timeout(BATCH_TIMEOUT, this.resolve_batch(normalized))
                .await
                .map_err(|_| unavailable("public HTTPS DNS resolution timed out"))?
        })
        .await
        .map_err(|_| Error::internal())?
    }

    async fn resolve_batch(&self, origins: BTreeSet<Origin>) -> Result<ResolvedTargets> {
        let mut targets = PublicTargets::default();
        let mut expires = Instant::now() + MAX_TTL;
        for origin in origins {
            let addresses = if let Ok(ip) = origin.host().parse() {
                vec![ip]
            } else {
                // Absolute A queries: no libc resolution, search suffixes,
                // hosts-file lookup, AAAA fallback or guest DNS access.
                let lookup = self
                    .resolver
                    .lookup(format!("{}.", origin.host()), RecordType::A)
                    .await
                    .map_err(|_| unavailable("public HTTPS DNS resolution failed"))?;
                expires = expires.min(lookup.valid_until());
                resolved_addresses(&lookup, &origin)?
            };
            targets
                .insert(origin, &addresses, &self.denied)
                .map_err(|_| {
                    Error::new(
                        StatusCode::FORBIDDEN,
                        "public HTTPS destination is not allowed",
                    )
                })?;
        }
        let resolved = ResolvedTargets {
            targets,
            expires,
            policy_digest: self.policy_digest.clone(),
        };
        resolved.launch_policy()?;
        Ok(resolved)
    }
}

impl crate::store::Store {
    pub fn with_public_egress(mut self, config: PublicEgressConfig) -> Result<Self> {
        self.public_egress = Some(Arc::new(PublicEgress::new(config)?));
        Ok(self)
    }
    /// Resolution alone is not permission or assignment. The caller must
    /// check current scoped grants, ownership and recovery before committing
    /// these bindings, and must not hold a database transaction during DNS.
    pub async fn resolve_public_origins(&self, origins: &[String]) -> Result<ResolvedTargets> {
        self.public_egress
            .as_ref()
            .ok_or_else(|| unavailable("public HTTPS egress is not configured"))?
            .resolve(origins)
            .await
    }
}
