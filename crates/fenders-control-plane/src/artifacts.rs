//! Metadata accepted only from an operator-owned compiler through an authenticated
//! node. Customers submit component bytes, never an inspection result.
use crate::{
    args,
    db::*,
    error::{Error, Result},
    model::{HOST_CONFINEMENT, MAX_UPLOAD, Principal, digest, identity},
    store::{Store, Tx},
};
pub use fenders_node_protocol::artifacts::*;
use serde_json::{Value, json};

fn boot(value: &Value) -> Result<&str> {
    let boot = text(&value["boot_id"])?;
    if boot.is_empty() || boot.len() > 128 || boot.chars().any(char::is_control) {
        return Err(Error::invalid("invalid node boot identity"));
    }
    Ok(boot)
}

async fn worker(tx: &mut Tx, node: &str, boot: &str) -> Result<Value> {
    optional(tx, "SELECT draining FROM nodes WHERE id=$1 AND NOT disabled AND backend='wasm' AND architecture='x86_64' AND runtime=$2 AND boot_id=$3 AND observed_confinement=$4", args![node,RUNTIME,boot,HOST_CONFINEMENT])
        .await?.ok_or_else(|| conflict("component worker identity or runtime changed"))
}

async fn assigned(
    tx: &mut Tx,
    node: &str,
    boot: &str,
    artifact: &str,
    generation: i64,
) -> Result<Value> {
    identity(artifact)?;
    if generation < 1 {
        return Err(Error::invalid("invalid validation generation"));
    }
    worker(tx, node, boot).await?;
    optional(tx, "SELECT v.*,a.digest,a.size,a.tenant_id,(v.lease_until>now()) AS lease_active FROM artifact_validations v JOIN artifacts a ON a.id=v.artifact_id WHERE v.artifact_id=$1 AND v.generation=$2 AND v.node_id=$3 AND v.node_boot=$4 AND v.runtime=$5 AND a.retired_at IS NULL", args![artifact,generation,node,boot,RUNTIME])
        .await?.ok_or_else(|| conflict("component validation assignment changed"))
}

fn job(row: &Value) -> Value {
    // The tenant is the node's compile cache scope: a compile reuses only
    // functions compiled for the same tenant.
    json!({"artifact_id":row["artifact_id"],"generation":row["generation"],"runtime":row["runtime"],"digest":row["digest"],"size":row["size"],"lease_until":row["lease_until"],"compile_scope":row["tenant_id"]})
}

impl Store {
    pub async fn artifact_inspection(
        &self,
        p: &Principal,
        tenant: &str,
        project: &str,
        artifact: &str,
    ) -> Result<Value> {
        let mut tx = self.transaction(false, false).await?;
        Self::project(&mut tx, p, tenant, project, false).await?;
        identity(artifact)?;
        let artifact_row = one(
            &mut tx,
            "SELECT retired_at FROM artifacts WHERE tenant_id=$1 AND project_id=$2 AND id=$3",
            args![tenant, project, artifact],
        )
        .await?;
        if !artifact_row["retired_at"].is_null() {
            return Err(Error::new(
                axum::http::StatusCode::GONE,
                "Unused upload expired. Upload the component again.",
            ));
        }
        one(&mut tx, "SELECT artifact_id,runtime,CASE WHEN state='validating' AND lease_until<=now() THEN 'pending' ELSE state END AS state,inspection,CASE WHEN state='validating' AND lease_until<=now() THEN 'compiler-unavailable' ELSE error END AS error,created,updated FROM artifact_validations WHERE tenant_id=$1 AND project_id=$2 AND artifact_id=$3", args![tenant,project,artifact]).await
    }

    /// Compilation claims are independent of execution assignments. The global
    /// mutation lock serializes claims with node disable/reboot and recovery.
    pub async fn claim_component(&self, node: &str, value: Value) -> Result<Value> {
        fields(&value, &["boot_id"], &["boot_id"])?;
        let boot = boot(&value)?;
        let mut tx = self.transaction(true, false).await?;
        let worker = worker(&mut tx, node, boot).await?;
        let recent = optional(
            &mut tx,
            "SELECT id FROM nodes WHERE id=$1 AND last_seen>now()-interval '30 seconds'",
            args![node],
        )
        .await?
        .is_some();
        if !recent {
            return Err(conflict("component worker heartbeat expired"));
        }
        // Advance the generation on the next claim. All expired owners immediately
        // lose content/result access, even if no replacement worker is available.
        exec(&mut tx, "UPDATE artifact_validations v SET state='pending',node_id=NULL,node_boot=NULL,lease_until=NULL,available_at=now(),error='compiler-unavailable',updated=now() WHERE state='validating' AND (lease_until<=now() OR EXISTS(SELECT 1 FROM nodes n WHERE n.id=v.node_id AND (n.disabled OR n.boot_id IS DISTINCT FROM v.node_boot OR n.runtime<>v.runtime OR n.observed_confinement IS DISTINCT FROM $1)))", args![HOST_CONFINEMENT]).await?;
        let existing = optional(&mut tx, "SELECT v.*,a.digest,a.size,a.tenant_id FROM artifact_validations v JOIN artifacts a ON a.id=v.artifact_id WHERE v.node_id=$1 AND v.node_boot=$2 AND v.state='validating' AND a.retired_at IS NULL", args![node,boot]).await?;
        let claim = if let Some(row) = existing {
            job(&row)
        } else if worker["draining"] == true {
            Value::Null
        // In turn among workspaces: the next component is that of the one
        // whose last was taken up longest ago, not the oldest of all. Nodes
        // compile one at a time, and a workspace that uploads a hundred
        // would otherwise hold every other's behind them.
        } else if let Some(row) = optional(&mut tx, "SELECT v.artifact_id FROM artifact_validations v WHERE v.state='pending' AND v.runtime=$1 AND v.available_at<=now() AND EXISTS(SELECT 1 FROM artifacts a WHERE a.id=v.artifact_id AND a.retired_at IS NULL) ORDER BY (SELECT max(o.updated) FROM artifact_validations o WHERE o.tenant_id=v.tenant_id AND o.generation>0 AND o.state<>'pending') NULLS FIRST,v.available_at,v.created,v.artifact_id LIMIT 1 FOR UPDATE OF v", args![RUNTIME]).await? {
            let next = one(&mut tx, "UPDATE artifact_validations SET state='validating',generation=generation+1,attempts=attempts+1,node_id=$1,node_boot=$2,lease_until=now()+interval '5 minutes',error=NULL,updated=now() WHERE artifact_id=$3 RETURNING generation", args![node,boot,row["artifact_id"]]).await?;
            let row = assigned(&mut tx, node, boot, s(&row["artifact_id"]), n(&next["generation"])).await?;
            job(&row)
        } else {
            Value::Null
        };
        tx.commit().await?;
        Ok(json!({"job":claim}))
    }

    pub async fn component_content(
        &self,
        node: &str,
        artifact: &str,
        generation: i64,
        value: Value,
    ) -> Result<Vec<u8>> {
        fields(&value, &["boot_id"], &["boot_id"])?;
        // Reading customer code is also barred while a restored control plane is
        // fenced; an old node must not acquire work from a restored assignment.
        let mut tx = self.transaction(true, false).await?;
        let row = assigned(&mut tx, node, boot(&value)?, artifact, generation).await?;
        if row["state"] != "validating" || row["lease_active"] != true {
            return Err(conflict("component validation lease expired"));
        }
        let path = self.state.join("blobs").join(s(&row["digest"]));
        use tokio::io::AsyncReadExt;
        let mut data = Vec::new();
        tokio::fs::File::open(path)
            .await?
            .take((MAX_UPLOAD + 1) as u64)
            .read_to_end(&mut data)
            .await?;
        if data.len() as i64 != n(&row["size"]) || digest(&data) != s(&row["digest"]) {
            return Err(Error::internal());
        }
        tx.commit().await?;
        Ok(data)
    }

    pub async fn component_result(
        &self,
        node: &str,
        artifact: &str,
        generation: i64,
        value: Value,
    ) -> Result<Value> {
        fields(&value, &["boot_id", "inspection", "error"], &["boot_id"])?;
        if value.get("inspection").is_some() == value.get("error").is_some() {
            return Err(Error::invalid("one inspection or error is required"));
        }
        let boot = boot(&value)?;
        let mut tx = self.transaction(true, false).await?;
        let row = assigned(&mut tx, node, boot, artifact, generation).await?;
        let state = if let Some(inspection) = value.get("inspection") {
            validate_inspection(inspection, s(&row["digest"]), n(&row["size"]) as usize)?;
            "valid"
        } else {
            match s(&value["error"]) {
                code if component_rejection(code).is_some() => "rejected",
                "compiler-unavailable" => "pending",
                _ => return Err(Error::invalid("unknown component validation error")),
            }
        };
        if row["state"] != "validating" {
            if row["state"] == state
                && row["inspection"] == value["inspection"]
                && row["error"] == value["error"]
            {
                return Ok(json!({"accepted":true}));
            }
            return Err(conflict("component validation result already recorded"));
        }
        if row["lease_active"] != true {
            return Err(conflict("component validation lease expired"));
        }
        exec(&mut tx, "UPDATE artifact_validations SET state=$1,inspection=$2::jsonb,error=$3,lease_until=NULL,available_at=now()+interval '30 seconds',updated=now() WHERE artifact_id=$4", args![state,value["inspection"],value["error"],artifact]).await?;
        Self::audit_system(
            &mut tx,
            node,
            "artifact.inspect",
            &json!(artifact),
            &row["tenant_id"],
            json!({"state":state,"generation":generation,"runtime":RUNTIME}),
        )
        .await?;
        tx.commit().await?;
        Ok(json!({"accepted":true}))
    }
}
