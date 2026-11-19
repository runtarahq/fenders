//! What a credential may ask for: the routes a workspace's key may be
//! given, the operator's own, and the keys themselves. There is one API,
//! and these tables are its routes: nothing is reached that is not in one.
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
/// `*` stands for one segment. These are the paths as they are asked for:
/// nothing is rewritten on the way to them.
///
/// This table is the routes: the contract is held to it by a test, both
/// ways, and a path that is not in it or in [`OPERATOR_ROUTES`] is answered
/// `404` to everyone.
pub const KEY_ROUTES: &[(&str, &str, &str)] = &[
    ("GET", "/v1/me", "read"),
    ("GET", "/v1/workspaces", "read"),
    ("GET", "/v1/workspaces/*", "read"),
    ("GET", "/v1/workspaces/*/projects", "read"),
    ("POST", "/v1/workspaces/*/projects", "projects:write"),
    ("PATCH", "/v1/workspaces/*/projects/*", "projects:write"),
    ("DELETE", "/v1/workspaces/*/projects/*", "projects:write"),
    ("GET", "/v1/workspaces/*/audit", "read"),
    ("GET", "/v1/workspaces/*/usage", "read"),
    ("GET", "/v1/workspaces/*/usage/history", "read"),
    ("GET", "/v1/workspaces/*/projects/*/usage", "read"),
    ("GET", "/v1/workspaces/*/projects/*/usage/history", "read"),
    ("GET", "/v1/workspaces/*/projects/*/app-sizes", "read"),
    ("GET", "/v1/workspaces/*/projects/*/https-access", "read"),
    (
        "POST",
        "/v1/workspaces/*/projects/*/https-access/validate",
        "read",
    ),
    (
        "POST",
        "/v1/workspaces/*/projects/*/schedules/preview",
        "read",
    ),
    ("GET", "/v1/workspaces/*/projects/*/apps", "read"),
    ("POST", "/v1/workspaces/*/projects/*/apps", "apps:write"),
    (
        "POST",
        "/v1/workspaces/*/projects/*/apps/deploy",
        "apps:write",
    ),
    (
        "GET",
        "/v1/workspaces/*/projects/*/app-submissions/*",
        "read",
    ),
    ("GET", "/v1/workspaces/*/projects/*/apps/*", "read"),
    ("PATCH", "/v1/workspaces/*/projects/*/apps/*", "apps:write"),
    ("DELETE", "/v1/workspaces/*/projects/*/apps/*", "apps:write"),
    (
        "GET",
        "/v1/workspaces/*/projects/*/apps/*/submissions/*",
        "read",
    ),
    ("GET", "/v1/workspaces/*/projects/*/apps/*/versions", "read"),
    (
        "POST",
        "/v1/workspaces/*/projects/*/apps/*/versions",
        "apps:write",
    ),
    (
        "GET",
        "/v1/workspaces/*/projects/*/apps/*/versions/*",
        "read",
    ),
    ("GET", "/v1/workspaces/*/projects/*/apps/*/releases", "read"),
    (
        "POST",
        "/v1/workspaces/*/projects/*/apps/*/releases",
        "apps:write",
    ),
    (
        "GET",
        "/v1/workspaces/*/projects/*/apps/*/releases/*",
        "read",
    ),
    ("GET", "/v1/workspaces/*/projects/*/apps/*/runs", "read"),
    (
        "POST",
        "/v1/workspaces/*/projects/*/apps/*/runs",
        "runs:write",
    ),
    ("GET", "/v1/workspaces/*/projects/*/apps/*/runs/*", "read"),
    (
        "POST",
        "/v1/workspaces/*/projects/*/apps/*/runs/*/cancel",
        "runs:write",
    ),
    ("GET", "/v1/workspaces/*/projects/*/apps/*/triggers", "read"),
    (
        "PUT",
        "/v1/workspaces/*/projects/*/apps/*/triggers",
        "apps:write",
    ),
    (
        "GET",
        "/v1/workspaces/*/projects/*/apps/*/connections",
        "read",
    ),
    (
        "PUT",
        "/v1/workspaces/*/projects/*/apps/*/connections",
        "apps:write",
    ),
    ("GET", "/v1/workspaces/*/projects/*/apps/*/http", "read"),
    (
        "GET",
        "/v1/workspaces/*/projects/*/apps/*/websocket",
        "read",
    ),
    ("GET", "/v1/workspaces/*/projects/*/apps/*/logs", "read"),
    ("GET", "/v1/workspaces/*/projects/*/apps/*/events", "read"),
    (
        "POST",
        "/v1/workspaces/*/projects/*/apps/*/http-sample",
        "runs:write",
    ),
    ("GET", "/v1/workspaces/*/projects/*/artifacts", "read"),
    (
        "POST",
        "/v1/workspaces/*/projects/*/artifacts",
        "apps:write",
    ),
    ("GET", "/v1/workspaces/*/projects/*/artifacts/*", "read"),
    (
        "DELETE",
        "/v1/workspaces/*/projects/*/artifacts/*",
        "apps:write",
    ),
    (
        "GET",
        "/v1/workspaces/*/projects/*/artifacts/*/inspection",
        "read",
    ),
    ("GET", "/v1/workspaces/*/projects/*/connections", "read"),
    (
        "POST",
        "/v1/workspaces/*/projects/*/connections",
        "connections:write",
    ),
    ("GET", "/v1/workspaces/*/projects/*/connections/*", "read"),
    (
        "DELETE",
        "/v1/workspaces/*/projects/*/connections/*",
        "connections:write",
    ),
    (
        "GET",
        "/v1/workspaces/*/projects/*/endpoint-submissions/*",
        "read",
    ),
    ("GET", "/v1/workspaces/*/projects/*/secrets", "read"),
    (
        "POST",
        "/v1/workspaces/*/projects/*/secrets",
        "secrets:write",
    ),
    ("GET", "/v1/workspaces/*/projects/*/secrets/*", "read"),
    (
        "PUT",
        "/v1/workspaces/*/projects/*/secrets/*",
        "secrets:write",
    ),
    (
        "DELETE",
        "/v1/workspaces/*/projects/*/secrets/*",
        "secrets:write",
    ),
    ("GET", "/v1/workspaces/*/projects/*/operations", "read"),
    ("GET", "/v1/workspaces/*/projects/*/operations/*", "read"),
];

/// The operator's own routes: what no tenant's key is ever given. Tenants
/// and their keys, what a tenant is allowed, suspending one, the nodes, the
/// public egress policy, and how this control plane's own loops are doing.
pub const OPERATOR_ROUTES: &[(&str, &str)] = &[
    ("POST", "/v1/workspaces"),
    ("PATCH", "/v1/workspaces/*"),
    ("DELETE", "/v1/workspaces/*"),
    ("PATCH", "/v1/workspaces/*/http-limits"),
    ("POST", "/v1/workspaces/*/lifecycle"),
    ("GET", "/v1/workspaces/*/api-keys"),
    ("POST", "/v1/workspaces/*/api-keys"),
    ("DELETE", "/v1/workspaces/*/api-keys/*"),
    ("GET", "/v1/nodes"),
    ("POST", "/v1/nodes"),
    ("PATCH", "/v1/nodes/*"),
    ("DELETE", "/v1/nodes/*"),
    ("GET", "/v1/edges"),
    ("POST", "/v1/edges"),
    ("PATCH", "/v1/edges/*"),
    ("DELETE", "/v1/edges/*"),
    ("GET", "/v1/edge-routes"),
    ("GET", "/v1/public-egress-policy"),
    ("PUT", "/v1/public-egress-policy"),
    ("GET", "/v1/control-plane/status"),
];

/// What is answered without a credential: whether this process is up, and
/// whether it can serve. They say nothing but that, so that whatever probes
/// a control plane need hold nothing that opens it.
pub const OPEN_ROUTES: &[(&str, &str)] = &[("GET", "/healthz"), ("GET", "/readyz")];

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
    /// Every key of a workspace, for the control plane's own reads.
    pub async fn api_keys(&self, p: &Principal, tenant: &str) -> Result<Value> {
        self.api_key_page(p, tenant, crate::store::ListPage::whole())
            .await
    }
    pub async fn api_key_page(
        &self,
        p: &Principal,
        tenant: &str,
        page: crate::store::ListPage,
    ) -> Result<Value> {
        p.scope(tenant, None, false, true)?;
        let (before, limit) = page.bounds(1000)?;
        let mut tx = self.transaction(false, false).await?;
        Self::live_principal(&mut tx, p).await?;
        let rows: Vec<Value> = sqlx::query_scalar("SELECT jsonb_build_object('id',r.id,'name',r.name,'project_id',r.project_id,'permissions',r.api_permissions,'label',r.label,'prefix',r.prefix,'created_by',r.created_by,'expires',r.expires,'revoked',r.revoked,'created',r.created,'last_used',r.last_used) FROM credentials r WHERE r.tenant_id=$1 AND r.api_permissions IS NOT NULL AND ($2::text IS NULL OR (r.created,r.id)<(SELECT c.created,c.id FROM credentials c WHERE c.id=$2)) ORDER BY r.created DESC,r.id DESC LIMIT $3")
            .bind(tenant).bind(before).bind(limit + 1).fetch_all(&mut *tx).await?;
        Ok(crate::store::ListPage::page(rows, limit))
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

    /// A route as the contract writes it: a method, and a path under
    /// `/v1`, with `*` for each parameter.
    fn public(method: &str, pattern: &str) -> (String, String) {
        (
            method.to_owned(),
            pattern.trim_start_matches("/v1").to_owned(),
        )
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
            for method in methods
                .as_object()
                .unwrap()
                .keys()
                .filter(|key| *key != "servers")
            {
                routes.insert((method.to_uppercase(), pattern.join("/")));
            }
        }
        routes
    }

    #[test]
    fn the_contract_and_the_router_describe_the_same_routes() {
        let routed: BTreeSet<_> = KEY_ROUTES
            .iter()
            .map(|(method, pattern, _)| public(method, pattern))
            .chain(
                OPEN_ROUTES
                    .iter()
                    .map(|(method, path)| public(method, path)),
            )
            .chain(
                OPERATOR_ROUTES
                    .iter()
                    .map(|(method, pattern)| public(method, pattern)),
            )
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
            for (method, operation) in methods
                .as_object()
                .unwrap()
                .iter()
                .filter(|(key, _)| *key != "servers")
            {
                let route = (method.to_uppercase(), pattern.join("/"));
                // What needs no credential says so, and is of neither kind.
                if OPEN_ROUTES.contains(&(route.0.as_str(), route.1.as_str())) {
                    assert_eq!(operation["security"], json!([]), "{route:?}");
                    assert_eq!(operation["tags"], json!(["health"]), "{route:?}");
                    continue;
                }
                let marked = operation["security"] == json!([{"operator":[]}]);
                assert_eq!(marked, operators.contains(&route), "{route:?}");
                let tag = if marked { "operator" } else { "workspace" };
                assert_eq!(operation["tags"], json!([tag]), "{route:?}");
            }
        }
    }

    #[test]
    fn the_contract_is_this_versions() {
        // It is served by the binary it describes, and says which that is:
        // not 1.0.0 of an API that has made no such promise.
        let spec: Value = serde_json::from_str(include_str!("../static/api/openapi.json")).unwrap();
        assert_eq!(spec["info"]["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(spec["openapi"], "3.1.0");
    }

    #[test]
    fn every_operation_says_how_it_is_refused_and_names_its_parameters_once() {
        let spec: Value = serde_json::from_str(include_str!("../static/api/openapi.json")).unwrap();
        let reference = |name: &str| json!({"$ref": format!("#/components/responses/{name}")});
        for (path, methods) in spec["paths"].as_object().unwrap() {
            for (method, operation) in methods
                .as_object()
                .unwrap()
                .iter()
                .filter(|(key, _)| *key != "servers")
            {
                let at = format!("{method} {path}");
                let responses = &operation["responses"];
                if operation["security"] == json!([]) {
                    assert!(responses.get("401").is_none(), "{at}");
                    continue;
                }
                assert_eq!(responses["401"], reference("Unauthorized"), "{at}");
                assert_eq!(responses["default"], reference("Refused"), "{at}");
                // Changes are what a workspace's rate counts.
                assert_eq!(responses.get("429").is_some(), method != "get", "{at}");
                if method != "get" {
                    assert_eq!(responses["429"], reference("RateLimited"), "{at}");
                }
                // A path's parameters are the shared ones, each the name
                // the path gives it; and every one the path has is there.
                let mut named = BTreeSet::new();
                for parameter in operation["parameters"].as_array().unwrap() {
                    let parameter = match parameter["$ref"].as_str() {
                        Some(pointer) => {
                            let found = spec.pointer(pointer.trim_start_matches('#'));
                            found.unwrap_or_else(|| panic!("{at}: {pointer} is nothing"))
                        }
                        None => {
                            assert_ne!(parameter["in"], "path", "{at}: {parameter}");
                            parameter
                        }
                    };
                    if parameter["in"] == "path" {
                        named.insert(format!("{{{}}}", parameter["name"].as_str().unwrap()));
                    }
                }
                let in_path: BTreeSet<_> = path
                    .split('/')
                    .filter(|segment| segment.starts_with('{'))
                    .map(str::to_owned)
                    .collect();
                assert_eq!(named, in_path, "{at}");
            }
        }
        // Nothing is referred to that is not there.
        fn references(value: &Value, found: &mut Vec<String>) {
            match value {
                Value::Object(map) => {
                    if let Some(Value::String(pointer)) = map.get("$ref") {
                        found.push(pointer.clone());
                    }
                    map.values().for_each(|value| references(value, found));
                }
                Value::Array(items) => items.iter().for_each(|value| references(value, found)),
                _ => {}
            }
        }
        let mut found = Vec::new();
        references(&spec, &mut found);
        assert!(found.len() > 100);
        for pointer in found {
            assert!(
                spec.pointer(pointer.trim_start_matches('#')).is_some(),
                "{pointer} is nothing"
            );
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
        let path = ["v1", "workspaces", "w", "projects", "p", "apps", "a"];
        assert_eq!(permission("GET", &path), Some("read"));
        assert_eq!(permission("PATCH", &path), Some("apps:write"));
        assert_eq!(permission("PUT", &path), None);
        assert_eq!(permission("GET", &path[..6]), Some("read"));
        assert_eq!(permission("GET", &path[..5]), None);
        assert_eq!(permission("GET", &[&path[..], &["nothing"]].concat()), None);
        assert!(operators("POST", &["v1", "workspaces"]));
        assert!(!operators("POST", &["v1", "workspaces", "w"]));
        assert!(!operators("GET", &["v1", "workspaces"]));
        // The names the control plane once answered to are no routes.
        assert_eq!(permission("GET", &["v1", "tenants"]), None);
        assert!(!operators("POST", &["v1", "tenants"]));
        assert_eq!(
            permission(
                "GET",
                &[
                    "v1",
                    "workspaces",
                    "w",
                    "projects",
                    "p",
                    "external-endpoints"
                ]
            ),
            None
        );
    }
}
