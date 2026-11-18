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

/// Every route a tenant's key may be given, with the permission it takes.
/// `*` stands for one segment. Paths are in the control plane's own names:
/// the public `/v1/workspaces` and `…/connections` are rewritten to them
/// before a route is looked for.
///
/// This table is the routes: the contract is held to it by a test, both
/// ways, and a path that is not in it or in [`OPERATOR_ROUTES`] is answered
/// `404` to everyone.
pub const KEY_ROUTES: &[(&str, &str, &str)] = &[
    ("GET", "/v1/me", "read"),
    ("GET", "/v1/tenants", "read"),
    ("GET", "/v1/tenants/*/projects", "read"),
    ("POST", "/v1/tenants/*/projects", "projects:write"),
    ("GET", "/v1/tenants/*/usage", "read"),
    ("GET", "/v1/tenants/*/usage/history", "read"),
    ("GET", "/v1/tenants/*/projects/*/usage", "read"),
    ("GET", "/v1/tenants/*/projects/*/usage/history", "read"),
    ("GET", "/v1/tenants/*/projects/*/app-sizes", "read"),
    ("GET", "/v1/tenants/*/projects/*/https-access", "read"),
    (
        "POST",
        "/v1/tenants/*/projects/*/https-access/validate",
        "read",
    ),
    ("POST", "/v1/tenants/*/projects/*/schedules/preview", "read"),
    ("GET", "/v1/tenants/*/projects/*/apps", "read"),
    ("POST", "/v1/tenants/*/projects/*/apps", "apps:write"),
    ("POST", "/v1/tenants/*/projects/*/apps/deploy", "apps:write"),
    ("GET", "/v1/tenants/*/projects/*/app-submissions/*", "read"),
    ("GET", "/v1/tenants/*/projects/*/apps/*", "read"),
    ("PATCH", "/v1/tenants/*/projects/*/apps/*", "apps:write"),
    ("DELETE", "/v1/tenants/*/projects/*/apps/*", "apps:write"),
    (
        "GET",
        "/v1/tenants/*/projects/*/apps/*/submissions/*",
        "read",
    ),
    ("GET", "/v1/tenants/*/projects/*/apps/*/versions", "read"),
    (
        "POST",
        "/v1/tenants/*/projects/*/apps/*/versions",
        "apps:write",
    ),
    ("GET", "/v1/tenants/*/projects/*/apps/*/versions/*", "read"),
    ("GET", "/v1/tenants/*/projects/*/apps/*/releases", "read"),
    (
        "POST",
        "/v1/tenants/*/projects/*/apps/*/releases",
        "apps:write",
    ),
    ("GET", "/v1/tenants/*/projects/*/apps/*/releases/*", "read"),
    ("GET", "/v1/tenants/*/projects/*/apps/*/runs", "read"),
    ("POST", "/v1/tenants/*/projects/*/apps/*/runs", "runs:write"),
    ("GET", "/v1/tenants/*/projects/*/apps/*/runs/*", "read"),
    (
        "POST",
        "/v1/tenants/*/projects/*/apps/*/runs/*/cancel",
        "runs:write",
    ),
    ("GET", "/v1/tenants/*/projects/*/apps/*/triggers", "read"),
    (
        "PUT",
        "/v1/tenants/*/projects/*/apps/*/triggers",
        "apps:write",
    ),
    ("GET", "/v1/tenants/*/projects/*/apps/*/connections", "read"),
    (
        "PUT",
        "/v1/tenants/*/projects/*/apps/*/connections",
        "apps:write",
    ),
    ("GET", "/v1/tenants/*/projects/*/apps/*/http", "read"),
    ("GET", "/v1/tenants/*/projects/*/apps/*/websocket", "read"),
    ("GET", "/v1/tenants/*/projects/*/apps/*/logs", "read"),
    ("GET", "/v1/tenants/*/projects/*/apps/*/events", "read"),
    (
        "POST",
        "/v1/tenants/*/projects/*/apps/*/http-sample",
        "runs:write",
    ),
    ("GET", "/v1/tenants/*/projects/*/artifacts", "read"),
    ("POST", "/v1/tenants/*/projects/*/artifacts", "apps:write"),
    ("GET", "/v1/tenants/*/projects/*/artifacts/*", "read"),
    (
        "GET",
        "/v1/tenants/*/projects/*/artifacts/*/inspection",
        "read",
    ),
    ("GET", "/v1/tenants/*/projects/*/external-endpoints", "read"),
    (
        "POST",
        "/v1/tenants/*/projects/*/external-endpoints",
        "connections:write",
    ),
    (
        "GET",
        "/v1/tenants/*/projects/*/external-endpoints/*",
        "read",
    ),
    (
        "DELETE",
        "/v1/tenants/*/projects/*/external-endpoints/*",
        "connections:write",
    ),
    (
        "GET",
        "/v1/tenants/*/projects/*/endpoint-submissions/*",
        "read",
    ),
    ("GET", "/v1/tenants/*/projects/*/secrets", "read"),
    ("POST", "/v1/tenants/*/projects/*/secrets", "secrets:write"),
    ("GET", "/v1/tenants/*/projects/*/secrets/*", "read"),
    ("GET", "/v1/tenants/*/projects/*/operations", "read"),
    ("GET", "/v1/tenants/*/projects/*/operations/*", "read"),
];

/// The operator's own routes: what no tenant's key is ever given. Tenants
/// and their keys, what a tenant is allowed, suspending one, the nodes, the
/// public egress policy, and how this control plane's own loops are doing.
pub const OPERATOR_ROUTES: &[(&str, &str)] = &[
    ("POST", "/v1/tenants"),
    ("PATCH", "/v1/tenants/*"),
    ("PATCH", "/v1/tenants/*/http-limits"),
    ("POST", "/v1/tenants/*/lifecycle"),
    ("GET", "/v1/tenants/*/api-keys"),
    ("POST", "/v1/tenants/*/api-keys"),
    ("DELETE", "/v1/tenants/*/api-keys/*"),
    ("GET", "/v1/nodes"),
    ("POST", "/v1/nodes"),
    ("PATCH", "/v1/nodes/*"),
    ("GET", "/v1/public-egress-policy"),
    ("PUT", "/v1/public-egress-policy"),
    ("GET", "/v1/control-plane/status"),
];

/// Whether `path` is the route `pattern` describes.
fn is_route(pattern: &str, path: &[&str]) -> bool {
    let mut pattern = pattern.trim_start_matches('/').split('/');
    path.iter()
        .all(|segment| pattern.next().is_some_and(|p| p == "*" || p == *segment))
        && pattern.next().is_none()
}

/// The permission a key needs for a request, if it is one a key may make.
pub fn permission(method: &str, path: &[&str]) -> Option<&'static str> {
    KEY_ROUTES
        .iter()
        .find(|(m, pattern, _)| *m == method && is_route(pattern, path))
        .map(|(_, _, permission)| *permission)
}

/// Whether a request is one of the operator's own.
pub fn operators(method: &str, path: &[&str]) -> bool {
    OPERATOR_ROUTES
        .iter()
        .any(|(m, pattern)| *m == method && is_route(pattern, path))
}
pub fn authorize(p: &Principal, method: &str, path: &[&str]) -> Result<()> {
    if let Some(permissions) = &p.api_permissions {
        let required = permission(method, path).ok_or_else(|| {
            Error::new(StatusCode::FORBIDDEN, "API key cannot access this endpoint")
                .coded("permission_denied")
        })?;
        if !permissions.iter().any(|v| v == required) {
            return Err(Error::new(
                StatusCode::FORBIDDEN,
                "API key lacks the required permission",
            )
            .coded("permission_denied"));
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
    /// Whatever its issuer wants recorded with what the key does: the user
    /// of a console it was issued for, a pipeline, a ticket. Opaque here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}
/// A label is one line of at most 128 bytes: text to find later, not data.
fn label_fits(label: &str) -> bool {
    (1..=128).contains(&label.len()) && !label.chars().any(char::is_control)
}

pub(crate) const MIGRATION: &str = "
ALTER TABLE credentials ADD COLUMN IF NOT EXISTS api_permissions jsonb;
ALTER TABLE credentials ADD COLUMN IF NOT EXISTS label text;
ALTER TABLE audit ADD COLUMN IF NOT EXISTS actor_label text;
ALTER TABLE credentials ADD COLUMN IF NOT EXISTS created_by text;
ALTER TABLE credentials ADD COLUMN IF NOT EXISTS prefix text;
ALTER TABLE credentials ADD COLUMN IF NOT EXISTS last_used timestamptz;
CREATE TABLE IF NOT EXISTS customer_request_receipts (
 tenant_id text NOT NULL REFERENCES tenants(id),
 request_key text NOT NULL, request_hash text NOT NULL, response jsonb NOT NULL,
 created timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(tenant_id,request_key));
";

/// A request key is what its caller chose: 1 to 128 bytes, nothing more.
pub(crate) fn request_key(key: &str) -> Result<()> {
    if key.is_empty() || key.len() > 128 {
        return Err(
            Error::invalid("Idempotency-Key is required (1–128 characters)")
                .coded("idempotency_key_required"),
        );
    }
    Ok(())
}

/// A key named in a path, to ask what became of the request made with it.
/// One that no request could have been made with names nothing.
pub(crate) fn submitted_key(key: &str) -> Result<()> {
    request_key(key).map_err(|_| Error::missing())
}

/// Receipts of the operator's own changes, which may have no tenant (a
/// node's registration has none).
pub(crate) const OPERATOR_RECEIPTS_MIGRATION: &str =
    "ALTER TABLE operator_request_receipts ALTER COLUMN tenant_id DROP NOT NULL";

/// What an operator's change answered when it was first made with `key`:
/// a retry is given that again, and the same key with other arguments is
/// refused. Keys are the actor's own; another operator credential's are
/// nothing to it.
pub(crate) async fn operator_receipt(
    tx: &mut Tx,
    actor: &str,
    key: &str,
    request: &Value,
) -> Result<Option<Value>> {
    request_key(key)?;
    let previous: Option<Value> = sqlx::query_scalar("SELECT jsonb_build_object('hash',request_hash,'response',response) FROM operator_request_receipts WHERE actor=$1 AND request_key=$2")
        .bind(actor).bind(key).fetch_optional(&mut **tx).await?;
    if let Some(previous) = previous {
        if previous["hash"] != fingerprint(request) {
            return Err(Error::new(
                StatusCode::CONFLICT,
                "idempotency key has different arguments",
            )
            .coded("idempotency_key_reused"));
        }
        return Ok(Some(previous["response"].clone()));
    }
    Ok(None)
}
pub(crate) async fn save_operator_receipt(
    tx: &mut Tx,
    actor: &str,
    key: &str,
    tenant: Option<&str>,
    request: &Value,
    response: &Value,
) -> Result<()> {
    sqlx::query("INSERT INTO operator_request_receipts(actor,request_key,tenant_id,request_hash,response) VALUES($1,$2,$3,$4,$5)")
        .bind(actor).bind(key).bind(tenant).bind(fingerprint(request)).bind(response).execute(&mut **tx).await?;
    Ok(())
}

// Only non-secret synchronous requests use these receipts. App operations retain
// their existing durable operations and fencing. No credential plaintext is saved.
pub(crate) async fn receipt(
    tx: &mut Tx,
    tenant: &str,
    key: &str,
    request: &Value,
) -> Result<Option<Value>> {
    request_key(key)?;
    let previous: Option<Value> = sqlx::query_scalar("SELECT jsonb_build_object('hash',request_hash,'response',response) FROM customer_request_receipts WHERE tenant_id=$1 AND request_key=$2")
        .bind(tenant).bind(key).fetch_optional(&mut **tx).await?;
    if let Some(previous) = previous {
        if previous["hash"] != fingerprint(request) {
            return Err(Error::new(
                StatusCode::CONFLICT,
                "idempotency key has different arguments",
            )
            .coded("idempotency_key_reused"));
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
        let rows: Vec<Value> = sqlx::query_scalar("SELECT jsonb_build_object('id',id,'name',name,'project_id',project_id,'permissions',api_permissions,'label',label,'prefix',prefix,'created_by',created_by,'expires',expires,'revoked',revoked,'created',created,'last_used',last_used) FROM credentials WHERE tenant_id=$1 AND api_permissions IS NOT NULL ORDER BY created DESC,id")
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
            || value
                .label
                .as_deref()
                .is_some_and(|label| !label_fits(label))
            || value.permissions.is_empty()
            || value
                .permissions
                .iter()
                .any(|v| !PERMISSIONS.contains(&v.as_str()))
            || (value.project_id.is_some()
                && value.permissions.iter().any(|v| v == "projects:write"))
        {
            return Err(Error::invalid(
                "invalid API key permissions, project scope, label or lifetime (maximum 30 days)",
            ));
        }
        let mut tx = self.transaction(true, false).await?;
        Self::live_principal(&mut tx, p).await?;
        if let Some(project) = &value.project_id {
            Self::project(&mut tx, p, tenant, project, false).await?;
        }
        let request = json!({"kind":"api-key.create","value":value});
        // The token is not kept, so a retry cannot be given it. It is told
        // so: the key it asked for exists and nobody holds it, to be revoked
        // by its id and issued again.
        if let Some(mut row) = receipt(&mut tx, tenant, key, &request).await? {
            row["token"] = Value::Null;
            row["replayed"] = json!(true);
            return Ok(row);
        }
        Self::metadata_limit(
            &mut tx,
            tenant,
            "credentials",
            crate::store::MAX_CREDENTIALS,
        )
        .await?;
        let id = uid();
        let secret = crate::store::token("fnd_tok_")?;
        let prefix = &secret[..16];
        let role = crate::model::Role::Key.as_str();
        let row: Value = sqlx::query_scalar("INSERT INTO credentials(id,token_hash,tenant_id,project_id,name,role,expires,api_permissions,created_by,prefix,label) VALUES($1,$2,$3,$4,$5,$6,now()+make_interval(secs=>$7::double precision),$8,$9,$10,$11) RETURNING jsonb_build_object('id',id,'name',name,'project_id',project_id,'permissions',api_permissions,'prefix',prefix,'expires',expires,'created',created,'created_by',created_by,'label',label)")
            .bind(&id).bind(digest(&secret)).bind(tenant).bind(&value.project_id).bind(&value.name).bind(role).bind(value.ttl_seconds as f64).bind(json!(value.permissions)).bind(&p.id).bind(prefix).bind(&value.label).fetch_one(&mut *tx).await?;
        save_receipt(&mut tx, tenant, key, &request, &row).await?;
        Self::audit(
            &mut tx,
            p,
            "api-key.create",
            &id,
            tenant,
            json!({"permissions":value.permissions,"project_id":value.project_id,"label":value.label}),
        )
        .await?;
        tx.commit().await?;
        let mut row = row;
        row["token"] = json!(secret);
        row["replayed"] = json!(false);
        Ok(row)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// A route as the contract writes it: a method, and a path under `/v1`
    /// in the public names, with `*` for each parameter.
    fn public(method: &str, pattern: &str) -> (String, String) {
        let mut segments: Vec<&str> = pattern.trim_start_matches("/v1/").split('/').collect();
        if segments[0] == "tenants" {
            segments[0] = "workspaces";
        }
        if segments.get(4) == Some(&"external-endpoints") {
            segments[4] = "connections";
        }
        (method.to_owned(), format!("/{}", segments.join("/")))
    }
    fn documented() -> BTreeSet<(String, String)> {
        let spec: Value = serde_json::from_str(include_str!("../static/api/openapi.json")).unwrap();
        let mut routes = BTreeSet::new();
        for (path, methods) in spec["paths"].as_object().unwrap() {
            let pattern: Vec<&str> = path
                .split('/')
                .map(|segment| {
                    if segment.starts_with('{') {
                        "*"
                    } else {
                        segment
                    }
                })
                .collect();
            for method in methods.as_object().unwrap().keys() {
                routes.insert((method.to_uppercase(), pattern.join("/")));
            }
        }
        routes
    }

    #[test]
    fn the_contract_and_the_router_describe_the_same_routes() {
        // The operator's routes are under the names the control plane has
        // for them, and nowhere else.
        let routed: BTreeSet<_> = KEY_ROUTES
            .iter()
            .map(|(method, pattern, _)| public(method, pattern))
            .chain(OPERATOR_ROUTES.iter().map(|(method, pattern)| {
                (
                    method.to_string(),
                    pattern.trim_start_matches("/v1").to_owned(),
                )
            }))
            .collect();
        let documented = documented();
        let undocumented: Vec<_> = routed.difference(&documented).collect();
        assert!(
            undocumented.is_empty(),
            "routed and not in the contract: {undocumented:?}"
        );
        let unrouted: Vec<_> = documented.difference(&routed).collect();
        assert!(
            unrouted.is_empty(),
            "in the contract and not routed: {unrouted:?}"
        );
    }

    #[test]
    fn the_operators_routes_are_marked_as_the_operators_and_no_others() {
        let spec: Value = serde_json::from_str(include_str!("../static/api/openapi.json")).unwrap();
        let operators: BTreeSet<_> = OPERATOR_ROUTES
            .iter()
            .map(|(method, pattern)| {
                (
                    method.to_string(),
                    pattern.trim_start_matches("/v1").to_owned(),
                )
            })
            .collect();
        for (path, methods) in spec["paths"].as_object().unwrap() {
            let pattern: Vec<&str> = path
                .split('/')
                .map(|segment| {
                    if segment.starts_with('{') {
                        "*"
                    } else {
                        segment
                    }
                })
                .collect();
            for (method, operation) in methods.as_object().unwrap() {
                let route = (method.to_uppercase(), pattern.join("/"));
                let marked = operation["security"] == json!([{"operator":[]}]);
                assert_eq!(marked, operators.contains(&route), "{route:?}");
                let tag = if marked { "operator" } else { "workspace" };
                assert_eq!(operation["tags"], json!([tag]), "{route:?}");
            }
        }
    }

    #[test]
    fn a_route_is_one_thing() {
        // No two rows for one request, and none that is both a key's and
        // the operator's by the same method.
        let mut seen = BTreeSet::new();
        for (method, pattern, permission) in KEY_ROUTES {
            assert!(seen.insert((method, pattern)), "twice: {method} {pattern}");
            assert!(PERMISSIONS.contains(permission), "{permission}");
        }
        for (method, pattern) in OPERATOR_ROUTES {
            assert!(seen.insert((method, pattern)), "twice: {method} {pattern}");
        }
        // A pattern is its own path, and no longer or shorter one.
        let path = ["v1", "tenants", "t", "projects", "p", "apps", "a"];
        assert_eq!(permission("GET", &path), Some("read"));
        assert_eq!(permission("PATCH", &path), Some("apps:write"));
        assert_eq!(permission("PUT", &path), None);
        assert_eq!(permission("GET", &path[..6]), Some("read"));
        assert_eq!(permission("GET", &path[..5]), None);
        assert_eq!(permission("GET", &[&path[..], &["nothing"]].concat()), None);
        assert!(operators("POST", &["v1", "tenants"]));
        assert!(!operators("POST", &["v1", "tenants", "t"]));
        assert!(!operators("GET", &["v1", "tenants"]));
    }
}
