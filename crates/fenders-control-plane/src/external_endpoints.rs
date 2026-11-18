//! Typed, reusable outbound TCP and HTTPS destinations. Fenders grants access, never
//! administers the remote service. DNS is resolved once into an immutable
//! endpoint; replacing an endpoint requires explicit app connection replacement.
use crate::{
    args,
    db::*,
    error::{Error, Result},
    model::*,
    store::Store,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr},
    path::Path,
    time::Duration,
};

pub(crate) fn connection_fields(endpoint: &Value) -> Vec<(String, Value)> {
    if s(&endpoint["database"]).is_empty() {
        return vec![
            (
                "HOST".into(),
                json!({"kind":"configuration","value":endpoint["host"]}),
            ),
            (
                "HOSTADDR".into(),
                json!({"kind":"configuration","value":s(&endpoint["address"]).split('/').next().unwrap_or("")}),
            ),
            (
                "PORT".into(),
                json!({"kind":"configuration","value":n(&endpoint["port"]).to_string()}),
            ),
        ];
    }
    // Preserve existing lab endpoint bindings. New console registrations use
    // only name/host/port; credentials belong to the app's configuration.
    let mut fields = vec![
        (
            "PGHOST".into(),
            json!({"kind":"configuration","value":endpoint["host"]}),
        ),
        (
            "PGHOSTADDR".into(),
            json!({"kind":"configuration","value":s(&endpoint["address"]).split('/').next().unwrap_or("")}),
        ),
        (
            "PGPORT".into(),
            json!({"kind":"configuration","value":n(&endpoint["port"]).to_string()}),
        ),
        (
            "PGDATABASE".into(),
            json!({"kind":"configuration","value":endpoint["database"]}),
        ),
        (
            "PGSSLMODE".into(),
            json!({"kind":"configuration","value":"verify-full"}),
        ),
        (
            "PGUSER".into(),
            json!({"kind":"secret","id":endpoint["username_secret_id"]}),
        ),
        (
            "PGPASSWORD".into(),
            json!({"kind":"secret","id":endpoint["password_secret_id"]}),
        ),
    ];
    if !s(&endpoint["ca_certificate"]).is_empty() {
        fields.push((
            "PGSSLROOTCERT_PEM".into(),
            json!({"kind":"configuration","value":endpoint["ca_certificate"]}),
        ));
    }
    fields
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalNetworkPolicy {
    pub allowed_cidrs: Vec<ipnet::Ipv4Net>,
    #[serde(default)]
    pub denied_cidrs: Vec<ipnet::Ipv4Net>,
}
impl ExternalNetworkPolicy {
    pub fn read(path: &Path) -> Result<Self> {
        let value: Self = serde_json::from_slice(&std::fs::read(path)?)
            .map_err(|_| Error::invalid("invalid external network policy"))?;
        if value.allowed_cidrs.len() > 64 || value.denied_cidrs.len() > 64 {
            return Err(Error::invalid(
                "external network policy allows at most 64 allowed and 64 denied ranges",
            ));
        }
        Ok(value)
    }
    pub(crate) fn permits(&self, address: Ipv4Addr) -> bool {
        address.octets()[0] != 0
            // The address a cloud platform answers its own guests on (Azure's
            // WireServer): never an externally operated service, whatever a
            // broad range allows, as it is never one for an HTTPS origin.
            && address.octets() != [168, 63, 129, 16]
            && !address.is_loopback()
            && !address.is_link_local()
            && !address.is_multicast()
            && !address.is_broadcast()
            && address.octets()[0] < 240
            && self
                .allowed_cidrs
                .iter()
                .any(|range| range.contains(&address))
            && !self
                .denied_cidrs
                .iter()
                .any(|range| range.contains(&address))
    }
    /// The address `host` is pinned to: itself when it is an IPv4 address,
    /// else the first of its permitted IPv4 addresses.
    ///
    /// A name is looked up as it is written, absolute: this host's search
    /// domains do not apply, and a name of one label is not looked up at
    /// all, so a tenant cannot ask after the names of the operator's own
    /// network. Whatever goes wrong is answered alike, so the answer does
    /// not say whether a name exists. Lookups in progress are bounded: each
    /// holds a thread that a slow name server keeps until it answers.
    async fn resolve(&self, host: &str, port: u16) -> Result<Ipv4Addr> {
        let refused = || {
            Error::invalid(
                "external endpoint host did not resolve to an address the operator permits",
            )
        };
        if let Ok(address) = host.parse::<Ipv4Addr>() {
            return if self.permits(address) {
                Ok(address)
            } else {
                Err(refused())
            };
        }
        if !host.contains('.') || host.ends_with('.') {
            return Err(Error::invalid(
                "external endpoint host must be an IPv4 address or a fully qualified DNS name",
            ));
        }
        static LOOKUPS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(8);
        let lookup = LOOKUPS
            .try_acquire()
            .map_err(|_| quota("too many endpoint lookups in progress"))?;
        // The lookup keeps its place until it has an answer, though the
        // caller stops waiting after five seconds.
        let name = format!("{host}.");
        let looked_up = tokio::spawn(async move {
            let _lookup = lookup;
            tokio::net::lookup_host((name.as_str(), port))
                .await
                .map(|addresses| addresses.take(65).collect::<Vec<_>>())
        });
        let addresses = tokio::time::timeout(Duration::from_secs(5), looked_up)
            .await
            .map_err(|_| refused())?
            .map_err(|_| refused())?
            .map_err(|_| refused())?;
        if addresses.len() > 64 {
            return Err(refused());
        }
        let mut ipv4 = BTreeSet::new();
        for address in addresses {
            if let IpAddr::V4(ip) = address.ip() {
                if !self.permits(ip) {
                    return Err(refused());
                }
                ipv4.insert(ip);
            }
        }
        if ipv4.len() > 16 {
            return Err(refused());
        }
        ipv4.into_iter().next().ok_or_else(refused)
    }
}

impl Store {
    pub(crate) async fn external_connections(
        &self,
        p: &Principal,
        tenant: &str,
        project: &str,
        id: Option<&str>,
    ) -> Result<Value> {
        if let Some(id) = id {
            identity(id)?;
        }
        let mut tx = self.transaction(false, false).await?;
        Self::project(&mut tx, p, tenant, project, false).await?;
        let mut items = sqlx::query_scalar::<_,Value>("SELECT value FROM (
            SELECT to_jsonb(e)||jsonb_build_object('type','tcp') value,created,id FROM external_endpoints e WHERE tenant_id=$1 AND project_id=$2
            UNION ALL
            SELECT to_jsonb(e)||jsonb_build_object('type','https') value,created,id FROM external_https_endpoints e WHERE tenant_id=$1 AND project_id=$2
            ) catalog WHERE ($3::text IS NULL OR id=$3) ORDER BY created DESC LIMIT 1000")
            .bind(tenant).bind(project).bind(id).fetch_all(&mut *tx).await?;
        if id.is_some() {
            items.pop().ok_or_else(Error::missing)
        } else {
            Ok(json!(items))
        }
    }

    async fn check_endpoint_catalog(
        tx: &mut crate::store::Tx,
        tenant: &str,
        project: &str,
        name: &Value,
    ) -> Result<()> {
        let existing = one(tx,"SELECT EXISTS(SELECT 1 FROM external_endpoints WHERE tenant_id=$1 AND project_id=$2 AND name=$3) OR EXISTS(SELECT 1 FROM external_https_endpoints WHERE tenant_id=$1 AND project_id=$2 AND name=$3) AS present",args![tenant,project,name]).await?;
        if b(&existing["present"]) {
            return Err(conflict("a connection with this name already exists"));
        }
        let count = one(tx,"SELECT (SELECT count(*) FROM external_endpoints WHERE tenant_id=$1)+(SELECT count(*) FROM external_https_endpoints WHERE tenant_id=$1) n",args![tenant]).await?;
        if n(&count["n"]) >= 256 {
            return Err(quota("external endpoint limit reached"));
        }
        Ok(())
    }

    async fn create_https_endpoint(
        &self,
        p: &Principal,
        tenant: &str,
        project: &str,
        value: Value,
        key: &str,
    ) -> Result<Value> {
        fields(
            &value,
            &["name", "type", "origin"],
            &["name", "type", "origin"],
        )?;
        named(&value["name"])?;
        let origin = crate::app_https::origins(&json!([value["origin"]]))?.remove(0);
        let request = json!({"kind":"create-external-endpoint","endpoint":value});
        let mut tx = self.transaction(true, false).await?;
        Self::project(&mut tx, p, tenant, project, true).await?;
        if let Some(op) = Self::idem(&mut tx, tenant, project, key, &request).await? {
            return Ok(op);
        }
        Self::check_endpoint_catalog(&mut tx, tenant, project, &value["name"]).await?;
        let endpoint = uid();
        exec(&mut tx,"INSERT INTO external_https_endpoints(id,tenant_id,project_id,name,origin) VALUES($1,$2,$3,$4,$5)",args![endpoint,tenant,project,value["name"],origin]).await?;
        let mut op = Self::operation(
            &mut tx,
            tenant,
            project,
            key,
            &request,
            &endpoint,
            "create-external-endpoint",
        )
        .await?;
        Self::complete_operation(&mut tx, &mut op).await?;
        Self::audit(
            &mut tx,
            p,
            "endpoint.create",
            &endpoint,
            tenant,
            json!({"type":"https","origin":origin}),
        )
        .await?;
        tx.commit().await?;
        Ok(op)
    }
    pub async fn endpoint_submission(
        &self,
        p: &Principal,
        tenant: &str,
        project: &str,
        key: &str,
    ) -> Result<Value> {
        crate::customer_api::submitted_key(key)?;
        let mut tx = self.transaction(false, false).await?;
        Self::project(&mut tx, p, tenant, project, false).await?;
        one(&mut tx, "SELECT id,resource_id,kind,state,error,created,updated FROM operations WHERE tenant_id=$1 AND project_id=$2 AND request_key=$3 AND kind IN ('create-external-endpoint','remove-external-endpoint')", args![tenant,project,key]).await
    }

    pub async fn remove_endpoint(
        &self,
        p: &Principal,
        tenant: &str,
        project: &str,
        endpoint: &str,
        key: &str,
    ) -> Result<Value> {
        identity(endpoint)?;
        let request = json!({"kind":"remove-external-endpoint","endpoint_id":endpoint});
        let mut tx = self.transaction(true, false).await?;
        Self::project(&mut tx, p, tenant, project, true).await?;
        if let Some(op) = Self::idem(&mut tx, tenant, project, key, &request).await? {
            return Ok(op);
        }
        if let Some(https) = optional(&mut tx,"SELECT origin FROM external_https_endpoints WHERE id=$1 AND tenant_id=$2 AND project_id=$3",args![endpoint,tenant,project]).await? {
            let in_use = one(&mut tx,"SELECT EXISTS(SELECT 1 FROM app_https_connections WHERE tenant_id=$1 AND project_id=$2 AND origin=$3 AND state<>'revoked') blocked",args![tenant,project,https["origin"]]).await?;
            if b(&in_use["blocked"]) { return Err(conflict("disconnect this endpoint from apps and wait for access removal before removing it")); }
            exec(&mut tx,"UPDATE external_https_endpoints SET deleted=true WHERE id=$1",args![endpoint]).await?;
            let mut op = Self::operation(&mut tx,tenant,project,key,&request,endpoint,"remove-external-endpoint").await?;
            Self::complete_operation(&mut tx,&mut op).await?;
            Self::audit(&mut tx,p,"endpoint.remove",endpoint,tenant,json!({"type":"https"})).await?;
            tx.commit().await?;
            return Ok(op);
        }
        one(
            &mut tx,
            "SELECT id FROM external_endpoints WHERE id=$1 AND tenant_id=$2 AND project_id=$3",
            args![endpoint, tenant, project],
        )
        .await?;
        let in_use = one(&mut tx, "SELECT EXISTS(SELECT 1 FROM app_endpoint_connections WHERE endpoint_id=$1 AND state<>'revoked') OR EXISTS(SELECT 1 FROM network_grants WHERE endpoint_id=$1 AND state<>'revoked') AS blocked", args![endpoint]).await?;
        if b(&in_use["blocked"]) {
            return Err(conflict(
                "disconnect this endpoint from apps and wait for access removal before removing it",
            ));
        }
        exec(
            &mut tx,
            "UPDATE external_endpoints SET deleted=true WHERE id=$1",
            args![endpoint],
        )
        .await?;
        let mut op = Self::operation(
            &mut tx,
            tenant,
            project,
            key,
            &request,
            endpoint,
            "remove-external-endpoint",
        )
        .await?;
        Self::complete_operation(&mut tx, &mut op).await?;
        Self::audit(&mut tx, p, "endpoint.remove", endpoint, tenant, json!({})).await?;
        tx.commit().await?;
        Ok(op)
    }

    pub fn with_external_network(mut self, policy: ExternalNetworkPolicy) -> Self {
        self.external_network = Some(std::sync::Arc::new(policy));
        self
    }

    pub async fn create_endpoint(
        &self,
        p: &Principal,
        tenant: &str,
        project: &str,
        value: Value,
        key: &str,
    ) -> Result<Value> {
        match value.get("type").and_then(Value::as_str) {
            Some("https") => {
                return self
                    .create_https_endpoint(p, tenant, project, value, key)
                    .await;
            }
            Some("tcp") | None if !value.get("type").is_some_and(|v| !v.is_string()) => {}
            _ => return Err(Error::invalid("connection type must be tcp or https")),
        }
        fields(
            &value,
            &[
                "name",
                "type",
                "host",
                "port",
                "database",
                "username_secret_id",
                "password_secret_id",
                "ca_certificate",
            ],
            &["name", "host", "port"],
        )?;
        named(&value["name"])?;
        let host = text(&value["host"])?;
        if host.is_empty()
            || host.len() > 253
            || !host
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b".-".contains(&c))
        {
            return Err(Error::invalid(
                "external endpoint host must be an IPv4 address or DNS hostname",
            ));
        }
        let host = host.to_ascii_lowercase();
        let port = integer(&value["port"], 1, 65535)?;
        // Accept the old complete binding group for existing API clients. It is
        // optional metadata, never a requirement for a TCP permission.
        let legacy = value.get("database").is_some()
            || value.get("username_secret_id").is_some()
            || value.get("password_secret_id").is_some()
            || value.get("ca_certificate").is_some();
        let database = if legacy {
            text(&value["database"])?
        } else {
            ""
        };
        if (legacy && database.is_empty()) || database.len() > 128 || database.contains('\0') {
            return Err(Error::invalid("invalid database name"));
        }
        if legacy {
            for field in ["username_secret_id", "password_secret_id"] {
                id(&value[field])?;
            }
        }
        let ca = value
            .get("ca_certificate")
            .map(text)
            .transpose()?
            .unwrap_or("");
        if ca.len() > 4096 {
            return Err(Error::invalid("CA certificate exceeds 4096 bytes"));
        }
        if !ca.is_empty() {
            let certs =
                rustls_pemfile::certs(&mut ca.as_bytes()).collect::<std::io::Result<Vec<_>>>()?;
            if certs.is_empty() {
                return Err(Error::invalid("CA certificate must be PEM"));
            }
            let mut roots = rustls::RootCertStore::empty();
            for cert in certs {
                roots
                    .add(cert)
                    .map_err(|_| Error::invalid("invalid CA certificate"))?;
            }
        }
        let request = json!({"kind":"create-external-endpoint","endpoint":value});
        // Authorize and recover a committed receipt before DNS or any mutation.
        {
            let mut tx = self.transaction(false, false).await?;
            Self::project(&mut tx, p, tenant, project, true).await?;
            if let Some(op) = Self::idem(&mut tx, tenant, project, key, &request).await? {
                return Ok(op);
            }
            // A project that has its endpoints, or one of this name, is told
            // so before anything is looked up for it.
            Self::check_endpoint_catalog(&mut tx, tenant, project, &value["name"]).await?;
        }
        let policy = self.external_network.as_ref().ok_or_else(|| {
            Error::invalid("external endpoint access has not been enabled by the operator")
        })?;
        let address = policy.resolve(&host, port as u16).await?;
        let mut tx = self.transaction(true, false).await?;
        Self::project(&mut tx, p, tenant, project, true).await?;
        if let Some(op) = Self::idem(&mut tx, tenant, project, key, &request).await? {
            return Ok(op);
        }
        for field in if legacy {
            vec!["username_secret_id", "password_secret_id"]
        } else {
            vec![]
        } {
            one(
                &mut tx,
                "SELECT id FROM secrets WHERE tenant_id=$1 AND project_id=$2 AND id=$3",
                args![tenant, project, value[field]],
            )
            .await?;
        }
        Self::check_endpoint_catalog(&mut tx, tenant, project, &value["name"]).await?;
        let network = if let Some(row)=optional(&mut tx,"SELECT id FROM networks WHERE tenant_id=$1 AND project_id=$2 ORDER BY created,id LIMIT 1",args![tenant,project]).await? {s(&row["id"]).to_owned()} else {
            let id=uid(); exec(&mut tx,"INSERT INTO networks(id,tenant_id,project_id,name) VALUES($1,$2,$3,'external')",args![id,tenant,project]).await?; id
        };
        let endpoint = uid();
        exec(&mut tx,"INSERT INTO external_endpoints(id,tenant_id,project_id,network_id,name,host,address,port,database,username_secret_id,password_secret_id,ca_certificate) VALUES($1,$2,$3,$4,$5,$6,$7::inet,$8,$9,$10,$11,$12)",args![endpoint,tenant,project,network,value["name"],host,address.to_string(),port,database,value["username_secret_id"],value["password_secret_id"],ca]).await?;
        let mut op = Self::operation(
            &mut tx,
            tenant,
            project,
            key,
            &request,
            &endpoint,
            "create-external-endpoint",
        )
        .await?;
        Self::complete_operation(&mut tx, &mut op).await?;
        Self::audit(
            &mut tx,
            p,
            "endpoint.create",
            &endpoint,
            tenant,
            json!({"address":address.to_string(),"port":port}),
        )
        .await?;
        tx.commit().await?;
        Ok(op)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shipped_public_policy_allows_internet_and_denies_special_use_ranges() {
        let policy: ExternalNetworkPolicy = serde_json::from_str(include_str!(
            "../../../deploy/systemd/external-network-public.json"
        ))
        .unwrap();
        for ip in ["93.184.216.34", "1.1.1.1", "8.8.8.8"] {
            assert!(policy.permits(ip.parse().unwrap()), "{ip}");
        }
        for range in &policy.denied_cidrs {
            assert!(!policy.permits(range.network()), "{range}");
            assert!(!policy.permits(range.broadcast()), "{range}");
        }
        for ip in [
            "10.20.30.40",
            "192.168.10.2",
            "169.254.169.254",
            "100.100.100.200",
            "168.63.129.16",
        ] {
            assert!(!policy.permits(ip.parse().unwrap()), "{ip}");
        }
        // What is not public for an HTTPS origin is not for a TCP endpoint
        // under the shipped policy either: the two cannot drift apart.
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                for (c, d) in [
                    (0u8, 1u8),
                    (99, 7),
                    (100, 9),
                    (113, 2),
                    (129, 16),
                    (193, 4),
                    (196, 3),
                    (48, 5),
                    (2, 8),
                ] {
                    let ip = Ipv4Addr::new(a, b, c, d);
                    assert_eq!(policy.permits(ip), fenders_egress::is_public_v4(ip), "{ip}");
                }
            }
        }
    }

    #[tokio::test]
    async fn a_host_is_pinned_without_asking_after_the_operators_own_names() {
        let policy = ExternalNetworkPolicy {
            allowed_cidrs: vec!["0.0.0.0/0".parse().unwrap()],
            denied_cidrs: vec!["10.0.0.0/8".parse().unwrap()],
        };
        // An address is itself, if permitted; no lookup.
        assert_eq!(
            policy.resolve("203.0.113.9", 5432).await.unwrap(),
            Ipv4Addr::new(203, 0, 113, 9)
        );
        let denied = policy.resolve("10.1.2.3", 5432).await.unwrap_err();
        // A name of one label, as this host's search domains would complete
        // it, and an already absolute one, are not looked up.
        for name in ["db", "localhost", "intranet", "db.internal."] {
            let refused = policy.resolve(name, 5432).await.unwrap_err();
            assert!(refused.message.contains("fully qualified"), "{name}");
        }
        // A name that does not exist is answered as a denied address is.
        let missing = policy
            .resolve("no-such-host.fenders.invalid", 5432)
            .await
            .unwrap_err();
        assert_eq!(missing.message, denied.message);
        assert_eq!(missing.status, denied.status);
    }

    #[test]
    fn the_cloud_platforms_own_address_is_never_a_destination() {
        // Azure's WireServer, on an address that is public by its range: an
        // operator who allows everything and denies nothing still does not
        // allow it, and the shipped policy denies it by name.
        let open = ExternalNetworkPolicy {
            allowed_cidrs: vec!["0.0.0.0/0".parse().unwrap()],
            denied_cidrs: vec![],
        };
        assert!(!open.permits("168.63.129.16".parse().unwrap()));
        assert!(open.permits("168.63.129.17".parse().unwrap()));
        let shipped = include_str!("../../../deploy/systemd/external-network-public.json");
        assert!(shipped.contains("168.63.129.16/32"));
    }

    #[test]
    fn operator_ranges_never_allow_local_control_or_denied_destinations() {
        let policy = ExternalNetworkPolicy {
            allowed_cidrs: vec!["0.0.0.0/0".parse().unwrap()],
            denied_cidrs: vec!["10.0.0.0/8".parse().unwrap()],
        };
        for ip in [
            "127.0.0.1",
            "0.0.0.0",
            "169.254.169.254",
            "224.0.0.1",
            "255.255.255.255",
            "10.20.30.40",
            // Whatever an operator allows.
            "168.63.129.16",
        ] {
            assert!(!policy.permits(ip.parse().unwrap()), "{ip}");
        }
        assert!(policy.permits("192.168.10.2".parse().unwrap()));
    }
}
