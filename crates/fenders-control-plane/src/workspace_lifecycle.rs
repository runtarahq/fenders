//! Workspace admission fence and stop lifecycle. This is authoritative platform
//! domain state; private operator identity/session handling remains independent.
use crate::{
    args,
    db::*,
    error::{Error, Result},
    model::identity,
    store::{Store, Tx},
};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

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
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS lifecycle_state text NOT NULL DEFAULT 'active'
 CHECK (lifecycle_state IN ('active','suspending','suspended'));
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS lifecycle_revision bigint NOT NULL DEFAULT 1;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS lifecycle_reason text;
";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WorkspaceAction {
    /// The workspace: from the request's path, never its body.
    #[serde(skip_deserializing)]
    pub(crate) id: String,
    /// The Idempotency-Key header's: never the body's, which once carried
    /// it. It is kept here because the request is known by it.
    #[serde(skip_deserializing)]
    request_key: Option<String>,
    expected_revision: i64,
    action: String,
    reason: String,
}
impl WorkspaceAction {
    /// The action under the key its request was made with.
    pub(crate) fn keyed(mut self, header: &str) -> Self {
        self.request_key = Some(header.to_owned());
        self
    }
}
/// A workspace that is gone is kept as a row, for what was used and done in
/// it; when it went is how it is told from one that is there.
pub(crate) const DELETION_MIGRATION: &str =
    "ALTER TABLE tenants ADD COLUMN IF NOT EXISTS deleted_at timestamptz";

impl Store {
    /// Whether a workspace was deleted. One that never was is not gone:
    /// whatever looks for it says so itself.
    pub async fn workspace_gone(&self, tenant: &str) -> Result<bool> {
        if identity(tenant).is_err() {
            return Ok(false);
        }
        let mut tx = self.transaction(false, false).await?;
        Ok(
            sqlx::query_scalar::<_, bool>("SELECT deleted_at IS NOT NULL FROM tenants WHERE id=$1")
                .bind(tenant)
                .fetch_optional(&mut *tx)
                .await?
                .unwrap_or(false),
        )
    }
    /// Removes a workspace that has been suspended and runs nothing.
    ///
    /// What made it usable goes: its keys open nothing, its secrets are
    /// destroyed, its components' storage is released and their bytes
    /// removed, its apps and connections are deleted. What records what it
    /// was and did stays in the database: the row itself, its projects, its
    /// usage, its operations and its audit trail. None of that is read
    /// through the API again: to the API the workspace does not exist.
    pub async fn delete_workspace(
        &self,
        p: &crate::model::Principal,
        tenant: &str,
        key: &str,
    ) -> Result<Value> {
        p.operator()?;
        identity(tenant)?;
        let request = json!({"kind":"workspace.delete","workspace":tenant});
        let mut tx = self.transaction(true, false).await?;
        if let Some(row) =
            crate::customer_api::operator_receipt(&mut tx, &p.id, key, &request).await?
        {
            return Ok(row);
        }
        let found = one(
            &mut tx,
            "SELECT lifecycle_state,EXISTS(SELECT 1 FROM executions e WHERE e.tenant_id=t.id AND e.reserved) AS running FROM tenants t WHERE t.id=$1 AND t.deleted_at IS NULL FOR UPDATE OF t",
            args![tenant],
        )
        .await?;
        if found["lifecycle_state"] != "suspended" || b(&found["running"]) {
            return Err(conflict(
                "suspend the workspace, and wait until it is suspended, before deleting it",
            )
            .coded("in_use"));
        }
        // Nothing of it starts again: its apps are deleted as an app is,
        // and with them their triggers and schedules.
        for app in rows(
            &mut tx,
            "SELECT id FROM apps WHERE tenant_id=$1 AND NOT deleted",
            args![tenant],
        )
        .await?
        {
            Self::cancel_schedule_dispatch(&mut tx, s(&app["id"]), "workspace-deleted").await?;
            Self::reset_schedule_clock(&mut tx, s(&app["id"]), false).await?;
        }
        exec(&mut tx,"UPDATE apps SET deleted=true,desired='stopped',revision=revision+1,updated=now() WHERE tenant_id=$1 AND NOT deleted",args![tenant]).await?;
        exec(&mut tx,"UPDATE app_triggers SET manual=false,http=false,revision=revision+1 WHERE tenant_id=$1",args![tenant]).await?;
        exec(&mut tx,"UPDATE operations SET state='failed',error='workspace-deleted',updated=now() WHERE tenant_id=$1 AND state='pending'",args![tenant]).await?;
        // Its keys open nothing.
        exec(
            &mut tx,
            "UPDATE credentials SET revoked=true WHERE tenant_id=$1 AND NOT revoked",
            args![tenant],
        )
        .await?;
        // Its secrets are destroyed, and what named them names nothing.
        exec(&mut tx,"UPDATE external_endpoints SET deleted=true,username_secret_id=NULL,password_secret_id=NULL WHERE tenant_id=$1",args![tenant]).await?;
        exec(
            &mut tx,
            "UPDATE external_https_endpoints SET deleted=true WHERE tenant_id=$1",
            args![tenant],
        )
        .await?;
        exec(
            &mut tx,
            "DELETE FROM secrets WHERE tenant_id=$1",
            args![tenant],
        )
        .await?;
        // Its components are retired as retention retires one: the storage
        // is released, and the bytes go when no other workspace has them.
        exec(&mut tx,"INSERT INTO artifact_blob_garbage(digest) SELECT DISTINCT digest FROM artifacts WHERE tenant_id=$1 AND retired_at IS NULL ON CONFLICT(digest) DO NOTHING",args![tenant]).await?;
        exec(&mut tx,"UPDATE artifact_validations v SET state='pending',inspection=NULL,error=NULL,node_id=NULL,node_boot=NULL,lease_until=NULL,generation=generation+1,updated=now() FROM artifacts a WHERE v.artifact_id=a.id AND a.tenant_id=$1 AND a.retired_at IS NULL",args![tenant]).await?;
        exec(
            &mut tx,
            "UPDATE artifacts SET retired_at=now() WHERE tenant_id=$1 AND retired_at IS NULL",
            args![tenant],
        )
        .await?;
        exec(
            &mut tx,
            "UPDATE tenants SET deleted_at=now() WHERE id=$1",
            args![tenant],
        )
        .await?;
        let row = json!({"id":tenant});
        exec(&mut tx,"INSERT INTO audit(tenant_id,actor,action,resource_id,detail) VALUES($1,$2,'tenant.delete',$1,'{}'::jsonb)",args![tenant,p.id]).await?;
        crate::customer_api::save_operator_receipt(
            &mut tx,
            &p.id,
            key,
            Some(tenant),
            &request,
            &row,
        )
        .await?;
        tx.commit().await?;
        Ok(row)
    }
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
            )
            .coded("workspace_suspended"));
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
        let key = input.request_key.clone().unwrap_or_default();
        crate::customer_api::request_key(&key)?;
        if !matches!(input.action.as_str(), "suspend" | "resume")
            || input.expected_revision < 1
            || input.reason.trim().is_empty()
            || input.reason.len() > 500
        {
            return Err(Error::invalid("invalid workspace action or reason"));
        }
        let request = json!({"kind":"workspace-lifecycle","input":input});
        let mut tx = self.transaction(true, false).await?;
        if let Some(previous) =
            crate::customer_api::operator_receipt(&mut tx, actor, &key, &request).await?
        {
            return Ok(previous);
        }
        let before = one(
            &mut tx,
            "SELECT lifecycle_state,lifecycle_revision FROM tenants WHERE id=$1 FOR UPDATE",
            args![input.id],
        )
        .await?;
        if before["lifecycle_revision"] != input.expected_revision {
            return Err(
                conflict("workspace changed; refresh before editing").coded("revision_conflict")
            );
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
        let audit=one(&mut tx,"INSERT INTO audit(tenant_id,actor,action,resource_id,detail,actor_label) VALUES($1,$2,$3,$1,$4,(SELECT label FROM credentials WHERE id=$2)) RETURNING sequence,created",args![input.id,format!("operator:{actor}"),format!("operator.{}",input.action),json!({"reason":input.reason.trim(),"before":before["lifecycle_state"],"after":row["status"],"revision":row["revision"],"request_key":key})]).await?;
        Self::reconcile_workspace_suspensions(&mut tx).await?;
        let row=one(&mut tx,"SELECT lifecycle_state AS status,lifecycle_revision AS revision FROM tenants WHERE id=$1",args![input.id]).await?;
        let result =
            json!({"id":input.id,"status":row["status"],"revision":row["revision"],"audit":audit});
        crate::customer_api::save_operator_receipt(
            &mut tx,
            actor,
            &key,
            Some(&input.id),
            &request,
            &result,
        )
        .await?;
        tx.commit().await?;
        // What the gateway knew of the workspace's apps is of before this.
        self.gateway.gates.forget_all();
        Ok(result)
    }
}
