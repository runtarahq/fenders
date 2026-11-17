//! Customer automation uses the same handlers and transactions as the console.
//! This allowlist also applies on legacy paths: aliases must not widen access.
use crate::{
    error::{Error, Result},
    model::*,
    store::{Store, Tx},
};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub const PERMISSIONS: &[&str] = &[
    "read",
    "apps:write",
    "runs:write",
    "projects:write",
    "connections:write",
    "secrets:write",
];

/// Paths are normalized to the existing control-plane names before authorization.
pub fn permission(method: &str, path: &[&str]) -> Option<&'static str> {
    match (method, path) {
        ("GET", ["v1", "me"] | ["v1", "tenants"]) => Some("read"),
        ("GET", ["v1", "tenants", _, "projects"]) => Some("read"),
        ("POST", ["v1", "tenants", _, "projects"]) => Some("projects:write"),
        ("GET", ["v1", "tenants", _, "usage"])
        | ("GET", ["v1", "tenants", _, "usage", "history"]) => Some("read"),
        (_, ["v1", "tenants", _, "projects", _, tail @ ..]) => match (method, tail) {
            (
                "GET",
                ["apps"]
                | ["apps", _]
                | ["app-sizes"]
                | ["https-access"]
                | ["usage"]
                | ["usage", "history"],
            ) => Some("read"),
            (
                "GET",
                [
                    "apps",
                    _,
                    "versions" | "releases" | "runs" | "triggers" | "connections" | "http"
                    | "websocket" | "logs" | "events",
                ],
            ) => Some("read"),
            ("GET", ["apps", _, "versions" | "releases" | "runs", _]) => Some("read"),
            ("GET", ["artifacts" | "external-endpoints" | "secrets" | "operations"])
            | (
                "GET",
                [
                    "artifacts" | "external-endpoints" | "secrets" | "operations",
                    _,
                ],
            )
            | ("GET", ["artifacts", _, "inspection"]) => Some("read"),
            (
                "POST",
                ["artifacts"]
                | ["apps"]
                | ["apps", "deploy"]
                | ["apps", _, "versions" | "releases"],
            )
            | ("PATCH", ["apps", _])
            | ("PUT", ["apps", _, "triggers" | "connections"]) => Some("apps:write"),
            ("POST", ["apps", _, "runs"]) => Some("runs:write"),
            ("POST", ["schedules", "preview"] | ["https-access", "validate"]) => Some("read"),
            ("POST", ["external-endpoints"]) | ("DELETE", ["external-endpoints", _]) => {
                Some("connections:write")
            }
            ("POST", ["secrets"]) => Some("secrets:write"),
            _ => None,
        },
        _ => None,
    }
}

pub fn authorize(p: &Principal, method: &str, path: &[&str]) -> Result<()> {
    if let Some(permissions) = &p.api_permissions {
        let required = permission(method, path).ok_or_else(|| {
            Error::new(StatusCode::FORBIDDEN, "API key cannot access this endpoint")
        })?;
        if !permissions.iter().any(|v| v == required) {
            return Err(Error::new(
                StatusCode::FORBIDDEN,
                "API key lacks the required permission",
            ));
        }
    }
    Ok(())
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateApiKey {
    pub name: String,
    pub project_id: Option<String>,
    pub permissions: Vec<String>,
    pub ttl_seconds: u32,
}

pub(crate) const MIGRATION: &str = "
ALTER TABLE credentials ADD COLUMN IF NOT EXISTS api_permissions jsonb;
ALTER TABLE credentials ADD COLUMN IF NOT EXISTS created_by text;
ALTER TABLE credentials ADD COLUMN IF NOT EXISTS prefix text;
ALTER TABLE credentials ADD COLUMN IF NOT EXISTS last_used timestamptz;
CREATE TABLE IF NOT EXISTS customer_request_receipts (
 tenant_id text NOT NULL REFERENCES tenants(id),
 request_key text NOT NULL, request_hash text NOT NULL, response jsonb NOT NULL,
 created timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(tenant_id,request_key));
";

// Only non-secret synchronous requests use these receipts. App operations retain
// their existing durable operations and fencing. No credential plaintext is saved.
pub(crate) async fn receipt(
    tx: &mut Tx,
    tenant: &str,
    key: &str,
    request: &Value,
) -> Result<Option<Value>> {
    if key.is_empty() || key.len() > 128 {
        return Err(Error::invalid(
            "Idempotency-Key is required (1–128 characters)",
        ));
    }
    let previous: Option<Value> = sqlx::query_scalar("SELECT jsonb_build_object('hash',request_hash,'response',response) FROM customer_request_receipts WHERE tenant_id=$1 AND request_key=$2")
        .bind(tenant).bind(key).fetch_optional(&mut **tx).await?;
    if let Some(previous) = previous {
        if previous["hash"] != fingerprint(request) {
            return Err(Error::new(
                StatusCode::CONFLICT,
                "idempotency key has different arguments",
            ));
        }
        return Ok(Some(previous["response"].clone()));
    }
    Ok(None)
}
pub(crate) async fn save_receipt(
    tx: &mut Tx,
    tenant: &str,
    key: &str,
    request: &Value,
    response: &Value,
) -> Result<()> {
    sqlx::query("INSERT INTO customer_request_receipts(tenant_id,request_key,request_hash,response) VALUES($1,$2,$3,$4)")
        .bind(tenant).bind(key).bind(fingerprint(request)).bind(response).execute(&mut **tx).await?;
    Ok(())
}

impl Store {
    pub async fn api_keys(&self, p: &Principal, tenant: &str) -> Result<Value> {
        p.scope(tenant, None, false, true)?;
        let mut tx = self.transaction(false, false).await?;
        Self::live_principal(&mut tx, p).await?;
        let rows: Vec<Value> = sqlx::query_scalar("SELECT jsonb_build_object('id',id,'name',name,'project_id',project_id,'permissions',api_permissions,'prefix',prefix,'created_by',created_by,'expires',expires,'revoked',revoked,'created',created,'last_used',last_used) FROM credentials WHERE tenant_id=$1 AND api_permissions IS NOT NULL ORDER BY created DESC,id")
            .bind(tenant).fetch_all(&mut *tx).await?;
        Ok(json!({"items":rows}))
    }
    pub async fn create_api_key(
        &self,
        p: &Principal,
        tenant: &str,
        mut value: CreateApiKey,
        key: &str,
    ) -> Result<Value> {
        p.scope(tenant, None, false, true)?;
        name(&value.name)?;
        value.permissions.sort();
        value.permissions.dedup();
        if !(60..=2592000).contains(&value.ttl_seconds)
            || value.permissions.is_empty()
            || value
                .permissions
                .iter()
                .any(|v| !PERMISSIONS.contains(&v.as_str()))
            || (value.project_id.is_some()
                && value.permissions.iter().any(|v| v == "projects:write"))
        {
            return Err(Error::invalid(
                "invalid API key permissions, project scope or lifetime (maximum 30 days)",
            ));
        }
        let mut tx = self.transaction(true, false).await?;
        Self::live_principal(&mut tx, p).await?;
        if let Some(project) = &value.project_id {
            Self::project(&mut tx, p, tenant, project, false).await?;
        }
        let request = json!({"kind":"api-key.create","value":value});
        if let Some(row) = receipt(&mut tx, tenant, key, &request).await? {
            return Ok(row);
        }
        let id = uid();
        let secret = crate::store::token("fnd_tok_")?;
        let prefix = &secret[..16];
        let role = if value.permissions.iter().any(|v| v.ends_with(":write")) {
            "editor"
        } else {
            "viewer"
        };
        let row: Value = sqlx::query_scalar("INSERT INTO credentials(id,token_hash,tenant_id,project_id,name,role,expires,api_permissions,created_by,prefix) VALUES($1,$2,$3,$4,$5,$6,LEAST(now()+make_interval(secs=>$7::double precision),COALESCE((SELECT expires FROM credentials WHERE id=$9 AND tenant_id IS NOT NULL),'infinity'::timestamptz)),$8,$9,$10) RETURNING jsonb_build_object('id',id,'name',name,'project_id',project_id,'permissions',api_permissions,'prefix',prefix,'expires',expires,'created',created,'created_by',created_by)")
            .bind(&id).bind(digest(&secret)).bind(tenant).bind(&value.project_id).bind(&value.name).bind(role).bind(value.ttl_seconds as f64).bind(json!(value.permissions)).bind(&p.id).bind(prefix).fetch_one(&mut *tx).await?;
        save_receipt(&mut tx, tenant, key, &request, &row).await?;
        Self::audit(
            &mut tx,
            p,
            "api-key.create",
            &id,
            tenant,
            json!({"permissions":value.permissions,"project_id":value.project_id}),
        )
        .await?;
        tx.commit().await?;
        let mut row = row;
        row["token"] = json!(secret);
        Ok(row)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn documented_routes_are_reachable_through_the_customer_boundary() {
        let spec: Value = serde_json::from_str(include_str!("../static/api/openapi.json")).unwrap();
        for (path, methods) in spec["paths"].as_object().unwrap() {
            let full = format!("/v1{path}");
            let mut segments: Vec<_> = full.trim_matches('/').split('/').collect();
            if segments.get(1) == Some(&"workspaces") {
                segments[1] = "tenants";
            }
            if segments.get(5) == Some(&"connections") {
                segments[5] = "external-endpoints";
            }
            if segments.get(3) == Some(&"api-keys") {
                continue;
            }
            for method in methods.as_object().unwrap().keys() {
                assert!(
                    permission(&method.to_uppercase(), &segments).is_some(),
                    "undocumented authorization boundary: {method} {path}"
                );
            }
        }
    }
}
