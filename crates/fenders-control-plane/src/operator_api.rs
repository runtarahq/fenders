//! Private platform bridge for the independently deployed operator service.
//! Mounted only on a dedicated mTLS listener, never on customer or worker routers.
use crate::{
    error::{Error, Result},
    model::{Allowance, fingerprint, identity},
    store::Store,
    transport::PeerIdentity,
};
use axum::{
    Json, Router,
    body::to_bytes,
    extract::{Request, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{net::SocketAddr, path::PathBuf};

// Applied explicitly by the bridge installer; also part of fresh platform setup.
// The trigger covers older customer/CLI writers as well as the private bridge.
pub(crate) const MIGRATION: &str = "
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS allowance_revision bigint NOT NULL DEFAULT 1;
CREATE OR REPLACE FUNCTION advance_allowance_revision() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN NEW.allowance_revision := OLD.allowance_revision + 1; RETURN NEW; END $$;
CREATE OR REPLACE TRIGGER tenant_allowance_revision BEFORE UPDATE OF
 cpu_percent,memory_mib,instances,storage_bytes,transfer_bytes ON tenants
 FOR EACH ROW EXECUTE FUNCTION advance_allowance_revision();
CREATE TABLE IF NOT EXISTS operator_request_receipts (
 actor text NOT NULL, request_key text NOT NULL, tenant_id text NOT NULL REFERENCES tenants(id),
 request_hash text NOT NULL, response jsonb NOT NULL, created timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(actor,request_key));
";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EditAllowance {
    id: String,
    request_key: String,
    expected_revision: i64,
    reason: String,
    allowance: Allowance,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub listen: SocketAddr,
    pub ca_file: PathBuf,
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
    pub service_pin: String,
    /// Enable only after the customer gateway and scheduler enforce workspace fences.
    #[serde(default)]
    pub workspace_controls: bool,
}
#[derive(Clone)]
struct Bridge {
    store: Store,
    service_pin: String,
    workspace_controls: bool,
}

pub fn router(store: Store, service_pin: String) -> Result<Router> {
    router_with_controls(store, service_pin, false)
}
pub fn router_with_controls(
    store: Store,
    service_pin: String,
    workspace_controls: bool,
) -> Result<Router> {
    if service_pin.len() != 64
        || !service_pin
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::invalid(
            "operator service requires a SHA-256 certificate pin",
        ));
    }
    Ok(Router::new().fallback(dispatch).with_state(Bridge {
        store,
        service_pin,
        workspace_controls,
    }))
}
async fn dispatch(State(bridge): State<Bridge>, req: Request) -> Response {
    let mut response = match read(bridge, req).await {
        Ok(value) => Json(value).into_response(),
        Err(error) => error.into_response(),
    };
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    response
}
async fn read(bridge: Bridge, req: Request) -> Result<Value> {
    let pin = req
        .extensions()
        .get::<PeerIdentity>()
        .and_then(|p| p.0.as_deref());
    if pin != Some(bridge.service_pin.as_str()) {
        return Err(Error::unauthorized());
    }
    // Neither browser cookies nor customer API keys are accepted by this service.
    if req.headers().contains_key(header::COOKIE)
        || req.headers().contains_key(header::AUTHORIZATION)
    {
        return Err(Error::unauthorized());
    }
    let actors = req.headers().get_all("X-Fenders-Operator");
    let actor = actors
        .iter()
        .next()
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    if actors.iter().count() != 1
        || actor.len() != 32
        || !actor.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(Error::unauthorized());
    }
    let actor = actor.to_owned();
    let action = match (req.method().as_str(), req.uri().path()) {
        ("POST", "/operator/v1/workspaces.list") => "list",
        ("POST", "/operator/v1/activity.list") => "activity",
        ("POST", "/operator/v1/workspaces.get") => "get",
        ("POST", "/operator/v1/workspaces.allowance") => "allowance",
        ("POST", "/operator/v1/workspaces.action") => "action",
        ("POST", "/operator/v1/workspaces.revoke_access") => "revoke-access",
        ("POST", "/operator/v1/admission.policy") => "admission-policy",
        ("POST", "/operator/v1/admission.edit_policy") => "admission-edit",
        ("POST", "/operator/v1/admission.list") => "admission-list",
        ("POST", "/operator/v1/admission.get") => "admission-get",
        ("POST", "/operator/v1/admission.decide") => "admission-decide",
        _ => return Err(Error::missing()),
    };
    if req.uri().query().is_some() {
        return Err(Error::invalid("query parameters are not supported"));
    }
    let bytes = to_bytes(req.into_body(), 8192)
        .await
        .map_err(|_| Error::new(StatusCode::PAYLOAD_TOO_LARGE, "operator request too large"))?;
    if action == "activity" {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Activity {
            before: Option<i64>,
        }
        let input: Activity = serde_json::from_slice(&bytes)
            .map_err(|_| Error::invalid("invalid activity cursor"))?;
        if input.before.is_some_and(|v| v <= 0) {
            return Err(Error::invalid("invalid activity cursor"));
        }
        return bridge.store.operator_activity(input.before).await;
    }
    if action.starts_with("admission-") {
        return match action {
            "admission-policy" => {
                let _: std::collections::BTreeMap<String, Value> =
                    serde_json::from_slice(&bytes)
                        .map_err(|_| Error::invalid("invalid policy request"))?;
                bridge.store.operator_policy().await
            }
            "admission-edit" => {
                bridge
                    .store
                    .operator_edit_policy(
                        &actor,
                        serde_json::from_slice(&bytes)
                            .map_err(|_| Error::invalid("invalid policy edit"))?,
                    )
                    .await
            }
            "admission-decide" => {
                bridge
                    .store
                    .operator_decide(
                        &actor,
                        serde_json::from_slice(&bytes)
                            .map_err(|_| Error::invalid("invalid admission decision"))?,
                    )
                    .await
            }
            "admission-list" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Search {
                    status: String,
                    offset: i64,
                }
                let input: Search = serde_json::from_slice(&bytes)
                    .map_err(|_| Error::invalid("invalid request search"))?;
                bridge
                    .store
                    .operator_requests(&input.status, input.offset)
                    .await
            }
            _ => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Get {
                    id: String,
                }
                let input: Get = serde_json::from_slice(&bytes)
                    .map_err(|_| Error::invalid("invalid access request"))?;
                bridge.store.operator_request(&input.id).await
            }
        };
    }
    if action == "revoke-access" {
        bridge
            .store
            .operator_revoke_access(
                &actor,
                serde_json::from_slice(&bytes)
                    .map_err(|_| Error::invalid("invalid scoped revocation"))?,
            )
            .await
    } else if action == "action" {
        if !bridge.workspace_controls {
            return Err(Error::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "workspace controls are not enabled on this platform",
            ));
        }
        let input = serde_json::from_slice(&bytes)
            .map_err(|_| Error::invalid("invalid workspace action"))?;
        bridge.store.operator_workspace_action(&actor, input).await
    } else if action == "allowance" {
        let input: EditAllowance =
            serde_json::from_slice(&bytes).map_err(|_| Error::invalid("invalid allowance edit"))?;
        bridge.store.operator_allowance(&actor, input).await
    } else if action == "list" {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Search {
            q: String,
            offset: i64,
            limit: i64,
        }
        let input: Search = serde_json::from_slice(&bytes)
            .map_err(|_| Error::invalid("invalid workspace search"))?;
        if input.q.len() > 200
            || !(0..=100000).contains(&input.offset)
            || !(1..=100).contains(&input.limit)
        {
            return Err(Error::invalid("invalid workspace search"));
        }
        bridge
            .store
            .operator_workspaces(&input.q, input.offset, input.limit)
            .await
    } else {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Workspace {
            id: String,
        }
        let input: Workspace =
            serde_json::from_slice(&bytes).map_err(|_| Error::invalid("invalid workspace"))?;
        if input.id.len() != 32 || !input.id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::missing());
        }
        let mut result = bridge.store.operator_workspace(&input.id).await?;
        result["workspace_controls"] = json!(bridge.workspace_controls);
        Ok(result)
    }
}

// Explicit read projections: no configuration, secret values, token hashes,
// execution inputs or identity-provider subjects cross the operator boundary.
const WORKSPACE: &str = "SELECT t.id,t.name,t.display_name,t.created,
    t.cpu_percent,t.memory_mib,t.instances,t.storage_bytes,t.transfer_bytes,t.allowance_revision,
    t.lifecycle_state AS status,t.lifecycle_revision,t.lifecycle_reason,
    (SELECT min(u.email) FROM workspace_memberships m JOIN customer_users u ON u.id=m.user_id
      WHERE m.tenant_id=t.id AND m.role='owner' AND NOT m.revoked AND NOT u.disabled) AS owner_email,
    (SELECT count(*) FROM projects p WHERE p.tenant_id=t.id) AS projects,
    (SELECT count(*) FROM apps a WHERE a.tenant_id=t.id) AS apps,
    (SELECT count(*) FROM compute_reservations r WHERE r.tenant_id=t.id) AS reserved_instances,
    COALESCE((SELECT sum(r.memory_mib) FROM compute_reservations r WHERE r.tenant_id=t.id),0)::bigint AS reserved_memory_mib,
    COALESCE((SELECT sum(r.cpu_percent) FROM compute_reservations r WHERE r.tenant_id=t.id),0)::bigint AS reserved_cpu_percent,
    COALESCE((SELECT sum(r.bytes) FROM storage_reservations r WHERE r.tenant_id=t.id),0)::bigint AS reserved_storage_bytes,
    COALESCE((SELECT sum(used_bytes+held_bytes) FROM transfer_allowance_accounting WHERE tenant_id=t.id
      AND period=date_trunc('month',now() AT TIME ZONE 'UTC')::date),0)::bigint AS committed_transfer_bytes
    FROM tenants t";
const MATCH: &str = "($1='' OR position(lower($1) in lower(t.name))>0 OR position(lower($1) in lower(t.display_name))>0 OR position(lower($1) in lower(t.id))>0 OR EXISTS (
    SELECT 1 FROM workspace_memberships m JOIN customer_users u ON u.id=m.user_id
    WHERE m.tenant_id=t.id AND m.role='owner' AND NOT m.revoked AND NOT u.disabled
    AND position(lower($1) in lower(u.email))>0))";
impl Store {
    pub async fn migrate_operator(&self) -> Result<()> {
        let mut tx = self.transaction(true, false).await?;
        sqlx::raw_sql(MIGRATION).execute(&mut *tx).await?;
        sqlx::raw_sql(crate::customer_onboarding::MIGRATION)
            .execute(&mut *tx)
            .await?;
        sqlx::raw_sql(crate::operator_admission::MIGRATION)
            .execute(&mut *tx)
            .await?;
        sqlx::raw_sql(crate::workspace_lifecycle::MIGRATION)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }
    async fn operator_allowance(&self, actor: &str, input: EditAllowance) -> Result<Value> {
        identity(&input.id)?;
        identity(&input.request_key)?;
        if input.reason.trim().is_empty() || input.reason.len() > 500 || input.expected_revision < 1
        {
            return Err(Error::invalid(
                "a reason and current allowance revision are required",
            ));
        }
        input.allowance.validate()?;
        let hash = fingerprint(&json!(input));
        let mut tx = self.transaction(true, false).await?;
        let previous: Option<Value> = sqlx::query_scalar("SELECT jsonb_build_object('hash',request_hash,'response',response) FROM operator_request_receipts WHERE actor=$1 AND request_key=$2")
            .bind(actor).bind(&input.request_key).fetch_optional(&mut *tx).await?;
        if let Some(previous) = previous {
            if previous["hash"] != hash {
                return Err(Error::new(
                    StatusCode::CONFLICT,
                    "idempotency key has different arguments",
                ));
            }
            return Ok(previous["response"].clone());
        }
        let before: Value =
            sqlx::query_scalar("SELECT to_jsonb(t) FROM tenants t WHERE id=$1 FOR UPDATE")
                .bind(&input.id)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or_else(Error::missing)?;
        if before["allowance_revision"] != input.expected_revision {
            return Err(Error::new(
                StatusCode::CONFLICT,
                "allowance changed; refresh before editing",
            ));
        }
        let after = Self::set_allowance(&mut tx, &input.id, &input.allowance).await?;
        let limits = |row: &Value| json!({"cpu_percent":row["cpu_percent"],"memory_mib":row["memory_mib"],"instances":row["instances"],"storage_bytes":row["storage_bytes"],"transfer_bytes":row["transfer_bytes"]});
        let audit: Value = sqlx::query_scalar("INSERT INTO audit(tenant_id,actor,action,resource_id,detail) VALUES($1,$2,'operator.allowance',$1,$3) RETURNING jsonb_build_object('sequence',sequence,'created',created)")
            .bind(&input.id).bind(format!("operator:{actor}"))
            .bind(json!({"reason":input.reason.trim(),"before":limits(&before),"after":limits(&after),"revision":after["allowance_revision"],"request_key":input.request_key}))
            .fetch_one(&mut *tx).await?;
        let result = json!({"id":input.id,"allowance":limits(&after),"revision":after["allowance_revision"],"audit":audit});
        sqlx::query("INSERT INTO operator_request_receipts(actor,request_key,tenant_id,request_hash,response) VALUES($1,$2,$3,$4,$5)")
            .bind(actor).bind(&input.request_key).bind(&input.id).bind(hash).bind(&result).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(result)
    }
    async fn operator_workspaces(&self, q: &str, offset: i64, limit: i64) -> Result<Value> {
        let mut tx = self.snapshot().await?;
        let total: i64 =
            sqlx::query_scalar(&format!("SELECT count(*) FROM tenants t WHERE {MATCH}"))
                .bind(q)
                .fetch_one(&mut *tx)
                .await?;
        let items:Vec<Value>=sqlx::query_scalar(&format!("SELECT to_jsonb(w) FROM ({WORKSPACE} WHERE {MATCH} ORDER BY t.created DESC,t.id LIMIT $2 OFFSET $3) w"))
            .bind(q).bind(limit).bind(offset).fetch_all(&mut *tx).await?;
        Ok(json!({"items":items,"total":total}))
    }
    async fn operator_workspace(&self, id: &str) -> Result<Value> {
        let mut tx = self.snapshot().await?;
        let workspace: Value = sqlx::query_scalar(&format!(
            "SELECT to_jsonb(w) FROM ({WORKSPACE} WHERE t.id=$1) w"
        ))
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(Error::missing)?;
        // Cap each section and return totals. Large workspaces are not silently
        // represented as complete; follow-up pagination uses the same boundary.
        let apps:Vec<Value>=sqlx::query_scalar("SELECT jsonb_build_object('id',a.id,'name',a.name,'project_name',p.display_name,'phase',a.state,'desired_state',a.desired) FROM app_summaries a JOIN projects p ON p.id=a.project_id WHERE a.tenant_id=$1 ORDER BY a.name,a.id LIMIT 100")
            .bind(id).fetch_all(&mut *tx).await?;
        let members:Vec<Value>=sqlx::query_scalar("SELECT jsonb_build_object('id',m.id,'user_id',m.user_id,'email',u.email,'display_name',u.display_name,'role',m.role,'revision',m.revision,'project_id',m.project_id,'project_name',p.display_name,'disabled',u.disabled) FROM workspace_memberships m JOIN customer_users u ON u.id=m.user_id LEFT JOIN projects p ON p.id=m.project_id WHERE m.tenant_id=$1 AND NOT m.revoked ORDER BY m.created,m.id LIMIT 100")
            .bind(id).fetch_all(&mut *tx).await?;
        let credentials:Vec<Value>=sqlx::query_scalar("SELECT jsonb_build_object('id',c.id,'name',c.name,'role',c.role,'project_id',c.project_id,'expires',c.expires,'revoked',c.revoked) FROM credentials c WHERE c.tenant_id=$1 ORDER BY c.created DESC,c.id LIMIT 100")
            .bind(id).fetch_all(&mut *tx).await?;
        let member_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM workspace_memberships WHERE tenant_id=$1 AND NOT revoked",
        )
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
        let credential_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM credentials WHERE tenant_id=$1")
                .bind(id)
                .fetch_one(&mut *tx)
                .await?;
        let activity: Vec<Value> = sqlx::query_scalar("SELECT jsonb_build_object('sequence',sequence,'actor',actor,'created',created,'action',action,'kind',detail->'kind','reason',detail->'reason','before',detail->'before','after',detail->'after') FROM audit WHERE tenant_id=$1 AND action IN ('operator.access_revoke','operator.admission_decision','operator.allowance','operator.suspend','operator.suspended','operator.resume') ORDER BY sequence DESC LIMIT 25")
            .bind(id).fetch_all(&mut *tx).await?;
        Ok(
            json!({"workspace":workspace,"apps":apps,"members":members,"credentials":credentials,"member_count":member_count,"credential_count":credential_count,"activity":activity}),
        )
    }
}

impl Store {
    async fn operator_activity(&self, before: Option<i64>) -> Result<Value> {
        let mut tx = self.transaction(false, false).await?;
        // Only fields written by the known operator actions cross this boundary.
        // In particular, no generic customer audit details or request receipts.
        let mut items: Vec<Value> = sqlx::query_scalar("SELECT jsonb_build_object('sequence',a.sequence,'actor',a.actor,'created',a.created,'action',a.action,'workspace_id',a.tenant_id,'workspace_name',COALESCE(t.display_name,t.name),'resource_id',a.resource_id,'kind',a.detail->'kind','reason',a.detail->'reason','before',a.detail->'before','after',a.detail->'after','allowance',a.detail->'allowance') FROM audit a LEFT JOIN tenants t ON t.id=a.tenant_id WHERE a.action IN ('operator.admission_policy','operator.admission_decision','operator.access_revoke','operator.allowance','operator.suspend','operator.suspended','operator.resume') AND ($1::bigint IS NULL OR a.sequence<$1) ORDER BY a.sequence DESC LIMIT 26")
            .bind(before).fetch_all(&mut *tx).await?;
        let more = items.len() > 25;
        items.truncate(25);
        let next = if more {
            items.last().map(|v| v["sequence"].clone())
        } else {
            None
        };
        Ok(json!({"items":items,"next_before":next}))
    }
}
