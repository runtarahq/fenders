use crate::{
    args,
    db::*,
    error::{Error, Result},
    model::*,
    store::{Store, Tx},
};
use axum::http::StatusCode;
use serde_json::{Value, json};
use std::collections::BTreeSet;

impl Store {
    pub(crate) async fn network_limit(
        tx: &mut Tx,
        tenant: &str,
        table: &str,
        limit: i64,
    ) -> Result<()> {
        assert!(matches!(
            table,
            "networks" | "external_endpoints" | "network_grants"
        ));
        let count = one(
            tx,
            &format!("SELECT count(*) n FROM {table} WHERE tenant_id=$1"),
            args![tenant],
        )
        .await?;
        if n(&count["n"]) >= limit {
            return Err(quota("tenant network metadata limit exhausted"));
        }
        Ok(())
    }
    pub(crate) async fn network_ref(
        tx: &mut Tx,
        tenant: &str,
        project: &str,
        network: &str,
    ) -> Result<Value> {
        identity(network)?;
        one(
            tx,
            "SELECT * FROM networks WHERE tenant_id=$1 AND project_id=$2 AND id=$3",
            args![tenant, project, network],
        )
        .await
    }
    pub(crate) async fn complete_operation(tx: &mut Tx, op: &mut Value) -> Result<()> {
        exec(
            tx,
            "UPDATE operations SET state='succeeded' WHERE id=$1",
            args![op["id"]],
        )
        .await?;
        op["state"] = json!("succeeded");
        Ok(())
    }
    pub(crate) async fn check_network_refs(
        tx: &mut Tx,
        tenant: &str,
        project: &str,
        spec: &Value,
    ) -> Result<()> {
        if spec["network_id"].is_null() {
            return Ok(());
        }
        Self::network_ref(tx, tenant, project, s(&spec["network_id"])).await?;
        for service in spec["endpoint_ids"].as_array().into_iter().flatten() {
            let row=one(tx,"SELECT s.id,'tcp' AS protocol FROM external_endpoints s WHERE s.tenant_id=$1 AND s.project_id=$2 AND s.network_id=$3 AND s.id=$4 AND NOT s.deleted",args![tenant,project,spec["network_id"],service]).await?;
            if row["protocol"] == "tcp"
                && spec["endpoint_env"].as_object().is_some_and(|v| {
                    v.values()
                        .any(|b| b["endpoint_id"] == *service && b["field"] == "url")
                })
            {
                return Err(Error::invalid(
                    "URL bindings require an HTTP or HTTPS service",
                ));
            }
            if spec["endpoint_env"].as_object().is_some_and(|bindings| {
                bindings
                    .values()
                    .any(|b| b["endpoint_id"] == *service && b["field"] == "ca_certificate")
            }) && optional(
                tx,
                "SELECT id FROM external_endpoints WHERE id=$1 AND ca_certificate<>''",
                args![service],
            )
            .await?
            .is_none()
            {
                return Err(Error::invalid("CA bindings require a managed TLS service"));
            }
        }
        Ok(())
    }
    async fn insert_grant(
        tx: &mut Tx,
        tenant: &str,
        project: &str,
        kind: &str,
        source: &str,
        network: &str,
        service: &str,
    ) -> Result<String> {
        if optional(
            tx,
            "SELECT id FROM external_endpoints WHERE id=$1 AND deleted",
            args![service],
        )
        .await?
        .is_some()
        {
            return Err(conflict("deleted service cannot receive new access"));
        }
        let column = match kind {
            "deployment" => "deployment_id",
            "execution" => "execution_id",
            _ => return Err(Error::invalid("invalid grant source")),
        };
        if let Some(existing)=optional(tx,&format!("SELECT * FROM network_grants WHERE {column}=$1 AND endpoint_id=$2 AND state<>'revoked'"),args![source,service]).await? {
            if existing["state"]=="revoking" {return Err(conflict("previous access revocation is not yet enforced"))}
            return Ok(s(&existing["id"]).to_owned())
        }
        Self::network_limit(tx, tenant, "network_grants", 4096).await?;
        let resource = uid();
        exec(tx,&format!("INSERT INTO network_grants(id,tenant_id,project_id,network_id,endpoint_id,{column}) VALUES($1,$2,$3,$4,$5,$6)"),args![resource,tenant,project,network,service,source]).await?;
        Ok(resource)
    }
    pub(crate) async fn initial_grants(
        tx: &mut Tx,
        tenant: &str,
        project: &str,
        kind: &str,
        source: &str,
        spec: &Value,
    ) -> Result<()> {
        for service in spec["endpoint_ids"].as_array().into_iter().flatten() {
            Self::insert_grant(
                tx,
                tenant,
                project,
                kind,
                source,
                s(&spec["network_id"]),
                s(service),
            )
            .await?;
        }
        Ok(())
    }
    /// Stops an execution that is still wanted: the way a permission it was
    /// launched with is taken back, since a launch's policy never changes.
    pub(crate) async fn stop_reserved(tx: &mut Tx, execution: &str) -> Result<()> {
        exec(tx,"UPDATE executions SET desired='stopped',generation=generation+1,state=CASE WHEN node_id IS NULL THEN 'stopped' ELSE state END,reserved=node_id IS NOT NULL,finished_at=CASE WHEN node_id IS NULL THEN now() ELSE finished_at END,updated=now() WHERE id=$1 AND reserved AND desired<>'stopped'",args![execution]).await?;
        Ok(())
    }
    /// Stops `execution` because `operation` removed a connection it holds.
    /// The operation is finished when every such execution has ended.
    pub(crate) async fn revoke_execution(
        tx: &mut Tx,
        operation: &str,
        execution: &str,
    ) -> Result<()> {
        exec(tx,"INSERT INTO connection_revocations(operation_id,execution_id) VALUES($1,$2) ON CONFLICT DO NOTHING",args![operation,execution]).await?;
        Self::stop_reserved(tx, execution).await
    }
    pub(crate) async fn network_reconcile(tx: &mut Tx) -> Result<()> {
        for row in rows(tx,"UPDATE operations o SET state='succeeded',updated=now() WHERE kind='revoke-grant' AND state='pending' AND NOT EXISTS(SELECT 1 FROM connection_revocations r JOIN executions e ON e.id=r.execution_id WHERE r.operation_id=o.id AND e.reserved) RETURNING resource_id",args![]).await? {exec(tx,"UPDATE network_grants SET state='revoked' WHERE id=$1",args![row["resource_id"]]).await?;}
        Self::reconcile_app_connections(tx).await?;
        Ok(())
    }
    /// Writes into `spec` what the execution may reach: the addresses of the
    /// endpoints it holds grants for, the public HTTPS origins it was given
    /// with the addresses they were resolved to, and the variables that name
    /// them. This is the launch's whole outbound policy. It is fixed here and
    /// does not change while the run lives; taking a permission back stops
    /// the run ([`revoke_execution`](Self::revoke_execution)).
    pub(crate) async fn launch_policy(
        &self,
        tx: &mut Tx,
        e: &Value,
        node: &Value,
        spec: &mut Value,
    ) -> Result<()> {
        let unavailable = |message| Error::new(StatusCode::SERVICE_UNAVAILABLE, message);
        let mut tcp = BTreeSet::new();
        let mut http = BTreeSet::new();
        let mut endpoints = Vec::new();
        if !e["spec"]["network_id"].is_null() {
            let app_http = !e["deployment_id"].is_null()
                && optional(
                    tx,
                    "SELECT app_id FROM app_http_attempts WHERE execution_id=$1",
                    args![e["id"]],
                )
                .await?
                .is_some();
            let (column, source) = if e["deployment_id"].is_null() || app_http {
                ("execution_id", &e["id"])
            } else {
                ("deployment_id", &e["deployment_id"])
            };
            endpoints=rows(tx,&format!("SELECT s.id endpoint_id,s.port,host(s.address) address,s.deleted,s.ca_certificate FROM network_grants g JOIN external_endpoints s ON s.id=g.endpoint_id WHERE g.{column}=$1 AND g.state='active' AND g.network_id=$2 AND s.id IN (SELECT jsonb_array_elements_text($3)) ORDER BY s.id"),args![source,e["spec"]["network_id"],get(&e["spec"],"endpoint_ids",json!([]))]).await?;
            if endpoints.len() > 32 {
                return Err(conflict("execution has too many connections"));
            }
            for endpoint in &endpoints {
                // The operator's ranges are checked again at each launch.
                let permitted = s(&endpoint["address"]).parse().ok().is_some_and(|address| {
                    self.external_network
                        .as_ref()
                        .is_some_and(|policy| policy.permits(address))
                });
                if b(&endpoint["deleted"]) || !permitted {
                    return Err(unavailable("a connection's destination is not available"));
                }
                tcp.insert(format!(
                    "{}:{}",
                    s(&endpoint["address"]),
                    n(&endpoint["port"])
                ));
            }
        }
        if !Self::https_connections(tx, s(&e["id"])).await?.is_empty() {
            let binding = Self::https_transport(tx, s(&e["id"]))
                .await?
                .ok_or_else(|| unavailable("public HTTPS resolution is unavailable"))?;
            let targets = Self::public_targets(&binding)?;
            // The node checks the digest's form only: the guest runtime it
            // reported is the one that will pin these origins to addresses.
            if node["observed_runtime_digest"].is_null() {
                return Err(unavailable("node has not reported its guest runtime"));
            }
            for (origin, addresses) in targets.iter() {
                http.insert(origin.to_string());
                tcp.extend(addresses.iter().map(ToString::to_string));
            }
            if tcp.len() > 32 || http.len() > 32 {
                return Err(conflict(
                    "connections and HTTPS origins together exceed the launch limit",
                ));
            }
            spec["http_public_targets"] = json!(targets.encode());
            spec["http_runtime_digest"] = node["observed_runtime_digest"].clone();
        }
        spec["tcp_allow"] = json!(tcp);
        spec["http_allow"] = json!(http);
        for (variable, binding) in e["spec"]["endpoint_env"].as_object().into_iter().flatten() {
            let target = endpoints
                .iter()
                .find(|b| b["endpoint_id"] == binding["endpoint_id"])
                .ok_or_else(|| conflict("a connection named by the environment is not held"))?;
            spec["env"][variable] = json!(match s(&binding["field"]) {
                "host" => s(&target["address"]).to_owned(),
                "port" => n(&target["port"]).to_string(),
                "ca_certificate" => s(&target["ca_certificate"]).to_owned(),
                _ =>
                    return Err(Error::invalid(
                        "URL bindings require an HTTP or HTTPS service"
                    )),
            });
        }
        Ok(())
    }
}
