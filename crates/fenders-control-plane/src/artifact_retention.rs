//! Metadata retirement commits before physical deletion. Shared digests and
//! backup/upload operations are protected by the existing admission lock.
use crate::{
    args,
    db::*,
    error::{Error, Result},
    store::{Store, Tx, guarded_blocking},
};
impl Store {
    pub(crate) async fn expire_artifacts(tx: &mut Tx) -> Result<()> {
        exec(tx, include_str!("artifact_retention.sql"), args![]).await?;
        Ok(())
    }
    /// Retires an artifact on request, as retention retires one that was
    /// left: its storage is the workspace's again at once, and its bytes
    /// are removed when no artifact of any project has the same.
    ///
    /// Refused while anything names it: a version of an app (a version is
    /// kept for good, so an artifact that was ever an app's code stays), an
    /// execution, or an inspection a node has in hand.
    pub async fn delete_artifact(
        &self,
        p: &crate::model::Principal,
        tenant: &str,
        project: &str,
        artifact: &str,
        key: &str,
    ) -> Result<serde_json::Value> {
        crate::model::identity(artifact)?;
        let mut tx = self.transaction(true, false).await?;
        Self::project(&mut tx, p, tenant, project, true).await?;
        let request =
            serde_json::json!({"kind":"artifact.delete","project_id":project,"artifact":artifact});
        if let Some(row) = crate::customer_api::receipt(&mut tx, tenant, key, &request).await? {
            return Ok(row);
        }
        let found = one(&mut tx,"SELECT a.digest,a.size,
            EXISTS(SELECT 1 FROM app_versions v WHERE v.artifact_id=a.id)
            OR EXISTS(SELECT 1 FROM deployments d WHERE d.spec->>'artifact_id'=a.id)
            OR EXISTS(SELECT 1 FROM executions e WHERE e.spec->>'artifact_id'=a.id)
            OR EXISTS(SELECT 1 FROM artifact_validations v WHERE v.artifact_id=a.id AND v.state='validating' AND v.lease_until>now()) AS used
            FROM artifacts a WHERE a.tenant_id=$1 AND a.project_id=$2 AND a.id=$3 AND a.retired_at IS NULL FOR UPDATE OF a",args![tenant,project,artifact]).await?;
        if b(&found["used"]) {
            return Err(
                conflict("artifact is an app's code, or is being inspected").coded("in_use")
            );
        }
        exec(
            &mut tx,
            "UPDATE artifacts SET retired_at=now() WHERE id=$1",
            args![artifact],
        )
        .await?;
        exec(&mut tx,"UPDATE artifact_validations SET state='pending',inspection=NULL,error=NULL,node_id=NULL,node_boot=NULL,lease_until=NULL,generation=generation+1,updated=now() WHERE artifact_id=$1",args![artifact]).await?;
        exec(
            &mut tx,
            "INSERT INTO artifact_blob_garbage(digest) VALUES($1) ON CONFLICT(digest) DO NOTHING",
            args![found["digest"]],
        )
        .await?;
        let row = serde_json::json!({"id":artifact});
        Self::audit(
            &mut tx,
            p,
            "artifact.delete",
            artifact,
            tenant,
            serde_json::json!({"digest":found["digest"],"bytes":found["size"]}),
        )
        .await?;
        crate::customer_api::save_receipt(&mut tx, tenant, key, &request, &row).await?;
        tx.commit().await?;
        Ok(row)
    }
    pub(crate) async fn reclaim_artifact_blobs(&self) -> Result<()> {
        let mut tx = self.transaction(true, false).await?;
        let candidates=rows(&mut tx,"SELECT digest FROM artifact_blob_garbage WHERE next_attempt<=now() ORDER BY next_attempt,digest LIMIT 16 FOR UPDATE",args![]).await?;
        for entry in candidates {
            let digest = s(&entry["digest"]);
            let active=one(&mut tx,"SELECT EXISTS(SELECT 1 FROM artifacts WHERE digest=$1 AND retired_at IS NULL) present",args![digest]).await?;
            if !b(&active["present"]) {
                let file = self.state.join("blobs").join(digest);
                let (held, removed) = guarded_blocking(tx, move || -> Result<()> {
                    match std::fs::symlink_metadata(&file) {
                        Ok(meta) if meta.file_type().is_file() => std::fs::remove_file(&file)?,
                        Ok(_) => return Err(Error::invalid("unexpected artifact blob type")),
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(e) => return Err(e.into()),
                    }
                    std::fs::File::open(file.parent().ok_or_else(Error::internal)?)?.sync_all()?;
                    Ok(())
                })
                .await?;
                tx = held;
                if removed.is_err() {
                    exec(&mut tx,"UPDATE artifact_blob_garbage SET next_attempt=now()+interval '1 minute',error='blob-cleanup-unavailable' WHERE digest=$1",args![digest]).await?;
                    continue;
                }
            }
            exec(
                &mut tx,
                "DELETE FROM artifact_blob_garbage WHERE digest=$1",
                args![digest],
            )
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }
}
