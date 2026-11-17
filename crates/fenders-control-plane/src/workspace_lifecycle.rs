//! Workspace admission fence and stop lifecycle. This is authoritative platform
//! domain state; private operator identity/session handling remains independent.
use crate::{
    args,
    db::*,
    error::{Error, Result},
    model::{fingerprint, identity},
    store::{Store, Tx},
};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub(crate) const MIGRATION: &str = "
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS lifecycle_state text NOT NULL DEFAULT 'active'
 CHECK (lifecycle_state IN ('active','suspending','suspended'));
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS lifecycle_revision bigint NOT NULL DEFAULT 1;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS lifecycle_reason text;
";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WorkspaceAction {
    id: String,
    request_key: String,
    expected_revision: i64,
    action: String,
    reason: String,
}
impl Store {
    pub(crate) async fn workspace_active(tx: &mut Tx, tenant: &str) -> Result<bool> {
        let state: Option<String> =
            sqlx::query_scalar("SELECT lifecycle_state FROM tenants WHERE id=$1")
                .bind(tenant)
                .fetch_optional(&mut **tx)
                .await?;
        Ok(state.ok_or_else(Error::missing)? == "active")
    }
    pub(crate) async fn require_workspace_active(tx: &mut Tx, tenant: &str) -> Result<()> {
        if !Self::workspace_active(tx, tenant).await? {
            return Err(Error::new(
                StatusCode::FORBIDDEN,
                "workspace is suspended; read-only access remains available",
            ));
        }
        Ok(())
    }
    pub(crate) async fn reconcile_workspace_suspensions(tx: &mut Tx) -> Result<()> {
        let completed=rows(tx,"UPDATE tenants t SET lifecycle_state='suspended',lifecycle_revision=lifecycle_revision+1 WHERE lifecycle_state='suspending' AND NOT EXISTS(SELECT 1 FROM executions e WHERE e.tenant_id=t.id AND e.reserved) RETURNING id,lifecycle_revision",args![]).await?;
        for row in completed {
            Self::audit_system(tx,"workspace-controller","operator.suspended",&row["id"],&row["id"],json!({"revision":row["lifecycle_revision"],"reason":"all workload reservations released by existing observation/fencing rules"})).await?;
        }
        Ok(())
    }
    pub(crate) async fn operator_workspace_action(
        &self,
        actor: &str,
        input: WorkspaceAction,
    ) -> Result<Value> {
        identity(&input.id)?;
        identity(&input.request_key)?;
        if !matches!(input.action.as_str(), "suspend" | "resume")
            || input.expected_revision < 1
            || input.reason.trim().is_empty()
            || input.reason.len() > 500
        {
            return Err(Error::invalid("invalid workspace action or reason"));
        }
        let hash = fingerprint(&json!({"kind":"workspace-lifecycle","input":input}));
        let mut tx = self.transaction(true, false).await?;
        let previous:Option<Value>=sqlx::query_scalar("SELECT jsonb_build_object('hash',request_hash,'response',response) FROM operator_request_receipts WHERE actor=$1 AND request_key=$2")
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
        let before = one(
            &mut tx,
            "SELECT lifecycle_state,lifecycle_revision FROM tenants WHERE id=$1 FOR UPDATE",
            args![input.id],
        )
        .await?;
        if before["lifecycle_revision"] != input.expected_revision {
            return Err(conflict("workspace changed; refresh before editing"));
        }
        if input.action == "suspend" {
            if before["lifecycle_state"] != "active" {
                return Err(conflict("workspace is already suspending or suspended"));
            }
            exec(&mut tx,"UPDATE tenants SET lifecycle_state='suspending',lifecycle_revision=lifecycle_revision+1,lifecycle_reason=$2 WHERE id=$1",args![input.id,input.reason.trim()]).await?;
            // Cancel only never-dispatched schedule work. Assigned commands retain
            // their reservation until a current-generation stop is observed.
            for app in rows(
                &mut tx,
                "SELECT id FROM apps WHERE tenant_id=$1",
                args![input.id],
            )
            .await?
            {
                Self::cancel_schedule_dispatch(&mut tx, s(&app["id"]), "workspace-suspended")
                    .await?;
                Self::reset_schedule_clock(&mut tx, s(&app["id"]), false).await?;
            }
            exec(&mut tx,"UPDATE executions SET desired='stopped',generation=generation+1,updated=now() WHERE tenant_id=$1 AND reserved AND desired<>'stopped'",args![input.id]).await?;
            exec(&mut tx,"UPDATE executions SET state='stopped',reserved=false,finished_at=now(),updated=now() WHERE tenant_id=$1 AND reserved AND node_id IS NULL",args![input.id]).await?;
            // A legacy command deployment must never be replayed on resume.
            exec(&mut tx,"UPDATE deployments SET desired='stopped' WHERE tenant_id=$1 AND spec->>'mode'='command'",args![input.id]).await?;
            exec(
                &mut tx,
                "UPDATE apps SET revision=revision+1,updated=now() WHERE tenant_id=$1",
                args![input.id],
            )
            .await?;
            exec(&mut tx,"UPDATE app_releases SET state='failed',reason='workspace-suspended',updated=now() WHERE tenant_id=$1 AND state='preparing'",args![input.id]).await?;
            exec(&mut tx,"UPDATE operations SET state='failed',error='workspace-suspended',updated=now() WHERE tenant_id=$1 AND state='pending'",args![input.id]).await?;
            exec(&mut tx,"UPDATE app_http SET state='stopping',reason='workspace-suspended',generation=generation+1,execution_id=NULL,idle_draining=false,drain_until=now(),ready_until=NULL,updated=now() WHERE tenant_id=$1",args![input.id]).await?;
        } else {
            if before["lifecycle_state"] != "suspended" {
                return Err(conflict("workspace must finish suspending before resume"));
            }
            if optional(
                &mut tx,
                "SELECT id FROM executions WHERE tenant_id=$1 AND reserved LIMIT 1",
                args![input.id],
            )
            .await?
            .is_some()
            {
                return Err(conflict("workspace still has reserved workloads"));
            }
            exec(&mut tx,"UPDATE tenants SET lifecycle_state='active',lifecycle_revision=lifecycle_revision+1,lifecycle_reason=$2 WHERE id=$1",args![input.id,input.reason.trim()]).await?;
            for app in rows(
                &mut tx,
                "SELECT id,desired FROM apps WHERE tenant_id=$1",
                args![input.id],
            )
            .await?
            {
                // Next occurrence is strictly in the future; never catch up missed ticks.
                Self::reset_schedule_clock(&mut tx, s(&app["id"]), app["desired"] == "enabled")
                    .await?;
            }
            exec(&mut tx,"UPDATE app_http h SET state=CASE WHEN a.configuration->>'keep_warm'='false' THEN 'idle' ELSE 'starting' END,reason=NULL,execution_id=NULL,ready_until=now()+interval '5 minutes',drain_until=NULL,restart_after=NULL,updated=now() FROM apps a JOIN app_triggers t ON t.app_id=a.id JOIN app_releases r ON r.id=a.target_release_id WHERE h.app_id=a.id AND h.tenant_id=$1 AND a.desired='enabled' AND t.http AND NOT h.blocked AND r.state='ready'",args![input.id]).await?;
        }
        Self::reconcile_app_runs(&mut tx).await?;
        let row=one(&mut tx,"SELECT lifecycle_state AS status,lifecycle_revision AS revision FROM tenants WHERE id=$1",args![input.id]).await?;
        let audit=one(&mut tx,"INSERT INTO audit(tenant_id,actor,action,resource_id,detail) VALUES($1,$2,$3,$1,$4) RETURNING sequence,created",args![input.id,format!("operator:{actor}"),format!("operator.{}",input.action),json!({"reason":input.reason.trim(),"before":before["lifecycle_state"],"after":row["status"],"revision":row["revision"],"request_key":input.request_key})]).await?;
        Self::reconcile_workspace_suspensions(&mut tx).await?;
        let row=one(&mut tx,"SELECT lifecycle_state AS status,lifecycle_revision AS revision FROM tenants WHERE id=$1",args![input.id]).await?;
        let result =
            json!({"id":input.id,"status":row["status"],"revision":row["revision"],"audit":audit});
        sqlx::query("INSERT INTO operator_request_receipts(actor,request_key,tenant_id,request_hash,response) VALUES($1,$2,$3,$4,$5)")
            .bind(actor).bind(&input.request_key).bind(&input.id).bind(hash).bind(&result).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(result)
    }
}
