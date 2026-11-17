//! Deletion fences new work immediately. Tombstones and execution history remain;
//! only current terminal observations release assigned reservations.
use crate::{
    args,
    db::*,
    error::Result,
    model::{Principal, identity},
    store::{Store, Tx},
};
use serde_json::{Value, json};

pub(crate) const MIGRATION: &str = "
ALTER TABLE apps ADD COLUMN IF NOT EXISTS deleted boolean NOT NULL DEFAULT false;
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='apps'::regclass AND conname='app_deleted_stopped') THEN
  ALTER TABLE apps ADD CONSTRAINT app_deleted_stopped CHECK (NOT deleted OR desired='stopped');
 END IF;
END $$;
CREATE OR REPLACE VIEW customer_app_summaries AS
 SELECT s.* FROM app_summaries s JOIN apps a ON a.id=s.id WHERE NOT a.deleted;
";

impl Store {
    pub async fn delete_app(
        &self,
        p: &Principal,
        tenant: &str,
        project: &str,
        app: &str,
        value: Value,
        key: &str,
    ) -> Result<Value> {
        identity(app)?;
        fields(&value, &["expected_revision"], &["expected_revision"])?;
        integer(&value["expected_revision"], 1, i64::MAX - 1)?;
        let request = json!({"kind":"delete-app","app_id":app,"value":value});
        let mut tx = self.transaction(true, false).await?;
        Self::project(&mut tx, p, tenant, project, true).await?;
        // Recover the original receipt even after the app is hidden. Project
        // authorization and the request fingerprint still precede that recovery.
        if let Some(previous) = Self::idem(&mut tx, tenant, project, key, &request).await? {
            return Ok(previous);
        }
        let row = Self::app_row(&mut tx, tenant, project, app).await?;
        if row["revision"] != value["expected_revision"] {
            return Err(conflict("app revision changed; reload before deleting"));
        }
        let op =
            Self::operation(&mut tx, tenant, project, key, &request, app, "delete-app").await?;
        Self::cancel_schedule_dispatch(&mut tx, app, "app-deleted").await?;
        Self::reset_schedule_clock(&mut tx, app, false).await?;
        exec(&mut tx,"UPDATE apps SET deleted=true,desired='stopped',revision=revision+1,updated=now() WHERE id=$1",args![app]).await?;
        exec(
            &mut tx,
            "UPDATE app_triggers SET manual=false,http=false,revision=revision+1 WHERE app_id=$1",
            args![app],
        )
        .await?;
        exec(&mut tx,"UPDATE app_releases SET state='failed',reason='app-deleted',updated=now() WHERE app_id=$1 AND state='preparing'",args![app]).await?;
        for connection in rows(
            &mut tx,
            "SELECT * FROM app_endpoint_connections WHERE app_id=$1 AND state='active'",
            args![app],
        )
        .await?
        {
            Self::withdraw_app_connection(&mut tx, &connection, s(&op["id"])).await?;
        }
        self.update_app_https(&mut tx, &row, &[], s(&op["id"]))
            .await?;
        exec(&mut tx,"UPDATE executions e SET desired='stopped',generation=generation+1,updated=now() WHERE reserved AND desired<>'stopped' AND EXISTS(SELECT 1 FROM app_execution_contexts c WHERE c.app_id=$1 AND c.execution_id=e.id)",args![app]).await?;
        exec(&mut tx,"UPDATE executions e SET state='stopped',reserved=false,finished_at=now(),updated=now() WHERE reserved AND node_id IS NULL AND EXISTS(SELECT 1 FROM app_execution_contexts c WHERE c.app_id=$1 AND c.execution_id=e.id)",args![app]).await?;
        exec(&mut tx,"UPDATE deployments SET desired='stopped' WHERE id IN(SELECT deployment_id FROM app_http WHERE app_id=$1)",args![app]).await?;
        exec(&mut tx,"UPDATE operations SET state='failed',error='app-deleted',updated=now() WHERE state='pending' AND id<>$2 AND (resource_id=$1 OR id IN(SELECT operation_id FROM app_http_operations WHERE app_id=$1))",args![app,op["id"]]).await?;
        exec(&mut tx,"UPDATE app_http SET generation=generation+1,state='stopping',reason='app-deleted',execution_id=NULL,idle_draining=false,drain_until=now(),ready_until=NULL,updated=now() WHERE app_id=$1",args![app]).await?;
        Self::network_reconcile(&mut tx).await?;
        Self::reconcile_app_runs(&mut tx).await?;
        Self::audit(
            &mut tx,
            p,
            "app.delete",
            app,
            tenant,
            json!({"revision":n(&row["revision"])+1}),
        )
        .await?;
        let result = one(
            &mut tx,
            "SELECT * FROM operations WHERE id=$1",
            args![op["id"]],
        )
        .await?;
        tx.commit().await?;
        Ok(result)
    }
    pub(crate) async fn reconcile_app_deletions(tx: &mut Tx) -> Result<()> {
        exec(tx,"UPDATE operations o SET state='succeeded',error=NULL,updated=now() FROM apps a WHERE o.kind='delete-app' AND o.state='pending' AND o.resource_id=a.id AND a.deleted AND NOT EXISTS(SELECT 1 FROM app_execution_contexts c JOIN executions e ON e.id=c.execution_id WHERE c.app_id=a.id AND e.reserved) AND NOT EXISTS(SELECT 1 FROM app_endpoint_connections c WHERE c.app_id=a.id AND c.state IN('active','revoking')) AND NOT EXISTS(SELECT 1 FROM app_https_connections c WHERE c.app_id=a.id AND c.state IN('active','revoking'))",args![]).await?;
        Ok(())
    }
}
