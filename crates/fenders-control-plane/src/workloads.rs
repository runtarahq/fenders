use crate::{
    args,
    db::*,
    error::{Error, Result},
    model::*,
    store::{Store, Tx},
};
use axum::http::StatusCode;
pub use fenders_node_protocol::workloads::*;
use serde_json::{Value, json};

/// The shortest value a secret may have.
const MIN_SECRET_BYTES: usize = 4;
/// Whether `plain` may be a secret's value: long enough that masking it in
/// a run's output does not mask the output, no longer than a value is, and
/// without NUL.
fn secret_value_fits(plain: &str) -> bool {
    (MIN_SECRET_BYTES..=1024).contains(&plain.len()) && !plain.contains('\0')
}

impl Store {
    pub(crate) async fn idem(
        tx: &mut Tx,
        tenant: &str,
        project: &str,
        key: &str,
        request: &Value,
    ) -> Result<Option<Value>> {
        if key.is_empty() || key.len() > 128 {
            return Err(Error::invalid(
                "Idempotency-Key is required (1–128 characters)",
            ));
        }
        let previous = optional(
            tx,
            "SELECT * FROM operations WHERE tenant_id=$1 AND project_id=$2 AND request_key=$3",
            args![tenant, project, key],
        )
        .await?;
        if previous
            .as_ref()
            .is_some_and(|p| p["request_hash"] != fingerprint(request))
        {
            return Err(conflict("idempotency key has different arguments"));
        }
        Ok(previous)
    }
    pub(crate) async fn operation(
        tx: &mut Tx,
        tenant: &str,
        project: &str,
        key: &str,
        request: &Value,
        resource: &str,
        kind: &str,
    ) -> Result<Value> {
        one(tx,"INSERT INTO operations(id,tenant_id,project_id,request_key,request_hash,resource_id,kind) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *",args![uid(),tenant,project,key,fingerprint(request),resource,kind]).await
    }
    pub(crate) async fn audit_system(
        tx: &mut Tx,
        actor: &str,
        action: &str,
        resource: &Value,
        tenant: &Value,
        detail: Value,
    ) -> Result<()> {
        exec(
            tx,
            "INSERT INTO audit(actor,action,resource_id,tenant_id,detail) VALUES($1,$2,$3,$4,$5)",
            args![actor, action, resource, tenant, detail],
        )
        .await?;
        Ok(())
    }
    pub async fn create_secret(
        &self,
        p: &Principal,
        tenant: &str,
        project: &str,
        value: Value,
    ) -> Result<Value> {
        self.create_secret_keyed(p, tenant, project, value, None)
            .await
    }
    pub async fn create_secret_keyed(
        &self,
        p: &Principal,
        tenant: &str,
        project: &str,
        value: Value,
        key: Option<&str>,
    ) -> Result<Value> {
        fields(&value, &["name", "value"], &["name", "value"])?;
        named(&value["name"])?;
        let plain = text(&value["value"])?;
        // A secret's value is masked wherever it appears in its runs' output.
        // One of a few bytes would mask those bytes everywhere in it, which
        // hides the output and shows where the value is: such a value is not
        // a secret worth storing, and is refused.
        if !secret_value_fits(plain) {
            return Err(Error::invalid(
                "invalid secret value: 4 to 1024 bytes, without NUL",
            ));
        }
        let mut tx = self.transaction(true, false).await?;
        Self::project(&mut tx, p, tenant, project, true).await?;
        // Receipt fingerprints exclude plaintext, and a replay is answered
        // with the first request's receipt whatever value it carries. Were
        // the value compared with the one stored, the answer would say
        // whether a guess was right: a secret is otherwise never read back,
        // and a key with `secrets:write` could try values without limit.
        let request = json!({"kind":"secret.create","project_id":project,"name":value["name"]});
        if let Some(key) = key
            && let Some(row) = crate::customer_api::receipt(&mut tx, tenant, key, &request).await?
        {
            return Ok(row);
        }
        Self::metadata_limit(&mut tx, tenant, "secrets", crate::store::MAX_SECRETS).await?;
        let resource = uid();
        let row=one(&mut tx,"INSERT INTO secrets(id,tenant_id,project_id,name,ciphertext) VALUES($1,$2,$3,$4,convert_to($5,'UTF8')) RETURNING id,name,created",args![resource,tenant,project,value["name"],self.cipher.encrypt(plain.as_bytes())]).await?;
        Self::audit(&mut tx, p, "secret.create", &resource, tenant, json!({})).await?;
        if let Some(key) = key {
            crate::customer_api::save_receipt(&mut tx, tenant, key, &request, &row).await?;
        }

        tx.commit().await?;
        Ok(row)
    }
    pub(crate) async fn check_refs(
        &self,
        tx: &mut Tx,
        tenant: &str,
        project: &str,
        spec: &Value,
    ) -> Result<()> {
        Self::check_network_refs(tx, tenant, project, spec).await?;
        one(
            tx,
            "SELECT id FROM artifacts WHERE tenant_id=$1 AND project_id=$2 AND id=$3 AND retired_at IS NULL",
            args![tenant, project, spec["artifact_id"]],
        )
        .await?;
        let mut size = serde_json::to_vec(&spec["env"]).unwrap().len();
        for (key, secret) in spec["secret_env"].as_object().unwrap() {
            let row=one(tx,"SELECT convert_from(ciphertext,'UTF8') token FROM secrets WHERE tenant_id=$1 AND project_id=$2 AND id=$3",args![tenant,project,secret]).await?;
            size += self
                .cipher
                .decrypt(s(&row["token"]))
                .map_err(|_| Error::internal())?
                .len()
                + key.len()
                + 8;
        }
        let bindings = spec["endpoint_env"].as_object();
        for (key, binding) in bindings.into_iter().flatten() {
            size += key.len()
                + if binding["field"] == "ca_certificate" {
                    let certificate = optional(
                        tx,
                        "SELECT ca_certificate FROM external_endpoints WHERE id=$1",
                        args![binding["endpoint_id"]],
                    )
                    .await?;
                    // Issuance uses fixed subjects/algorithms. Reserve 1024 bytes
                    // before issuance; validate actual JSON-escaped PEM afterwards.
                    certificate
                        .map(|v| v["ca_certificate"].to_string().len() + 8)
                        .unwrap_or(1024)
                } else {
                    64
                };
        }
        if size > 2048
            || spec["env"].as_object().unwrap().len()
                + spec["secret_env"].as_object().unwrap().len()
                + bindings.map(|b| b.len()).unwrap_or(0)
                > 32
        {
            return Err(Error::invalid("expanded environment exceeds node limit"));
        }
        Ok(())
    }
    pub(crate) async fn execution(
        tx: &mut Tx,
        tenant: &str,
        project: &str,
        spec: &Value,
        deployment: Option<&str>,
        revision: i64,
    ) -> Result<Value> {
        Self::require_workspace_active(tx, tenant).await?;
        let limits = one(
            tx,
            "SELECT * FROM tenants WHERE id=$1 FOR UPDATE",
            args![tenant],
        )
        .await?;
        let used=one(tx,"SELECT COALESCE(sum(cpu_percent),0) cpu,COALESCE(sum(memory_mib),0) memory,count(*) instances FROM compute_reservations WHERE tenant_id=$1",args![tenant]).await?;
        let memory = n(&spec["host_memory_mib"]) + WORKER_OVERHEAD_MIB;
        if n(&used["cpu"]) + n(&spec["cpu_percent"]) > n(&limits["cpu_percent"])
            || n(&used["memory"]) + memory > n(&limits["memory_mib"])
            || n(&used["instances"]) + 1 > n(&limits["instances"])
        {
            return Err(quota("tenant compute allowance exhausted"));
        }
        let row=one(tx,"INSERT INTO executions(id,tenant_id,project_id,deployment_id,revision,spec,cpu_percent,memory_mib) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *",args![uid(),tenant,project,deployment,revision,spec,spec["cpu_percent"],memory]).await?;
        if deployment.is_none() {
            Self::initial_grants(tx, tenant, project, "execution", s(&row["id"]), spec).await?;
        }
        Ok(row)
    }
    pub async fn create_workload(
        &self,
        p: &Principal,
        tenant: &str,
        project: &str,
        value: Value,
        key: &str,
        service: bool,
    ) -> Result<Value> {
        let allowed = if service {
            &["name", "spec"][..]
        } else {
            &["spec"][..]
        };
        fields(&value, allowed, allowed)?;
        let spec = wasm_spec(&value["spec"], service)?;
        let mut request = json!({"kind":if service {"deployment"} else {"execution"},"spec":spec});
        if service {
            request["name"] = json!(named(&value["name"])?);
        }
        let mut tx = self.transaction(true, false).await?;
        Self::project(&mut tx, p, tenant, project, true).await?;
        if let Some(previous) = Self::idem(&mut tx, tenant, project, key, &request).await? {
            return Ok(previous);
        }
        self.check_refs(&mut tx, tenant, project, &spec).await?;
        let deployment = if service { Some(uid()) } else { None };
        if let Some(d) = &deployment {
            exec(
                &mut tx,
                "INSERT INTO deployments(id,tenant_id,project_id,name,spec) VALUES($1,$2,$3,$4,$5)",
                args![d, tenant, project, request["name"], spec],
            )
            .await?;
            Self::initial_grants(&mut tx, tenant, project, "deployment", d, &spec).await?;
        }
        let run =
            Self::execution(&mut tx, tenant, project, &spec, deployment.as_deref(), 1).await?;
        let resource = deployment.as_deref().unwrap_or(s(&run["id"]));
        let kind = if service {
            "create-deployment"
        } else {
            "create-execution"
        };
        let op = Self::operation(&mut tx, tenant, project, key, &request, resource, kind).await?;
        Self::audit(&mut tx, p, kind, resource, tenant, json!({})).await?;
        tx.commit().await?;
        Ok(op)
    }
    pub async fn action(
        &self,
        p: &Principal,
        tenant: &str,
        project: &str,
        run: &str,
        action: &str,
        key: &str,
    ) -> Result<Value> {
        identity(run)?;
        let desired = match action {
            "pause" => "paused",
            "resume" => "running",
            "stop" => "stopped",
            _ => return Err(Error::invalid("unknown action")),
        };
        let request = json!({"kind":action,"execution":run});
        let mut tx = self.transaction(true, false).await?;
        Self::project(&mut tx, p, tenant, project, true).await?;
        if let Some(previous) = Self::idem(&mut tx, tenant, project, key, &request).await? {
            return Ok(previous);
        }
        let row = one(
            &mut tx,
            "SELECT * FROM executions WHERE tenant_id=$1 AND project_id=$2 AND id=$3 FOR UPDATE",
            args![tenant, project, run],
        )
        .await?;
        Self::independent_deployment(&mut tx, &row["deployment_id"]).await?;
        if action != "stop" && one(&mut tx,
            "SELECT EXISTS(SELECT 1 FROM app_execution_contexts c JOIN apps a ON a.id=c.app_id WHERE c.execution_id=$1 AND a.deleted) deleted",
            args![run]).await?["deleted"] == true {
            return Err(conflict("app was deleted; only stopping its execution is allowed"));
        }
        if terminal(s(&row["state"]))
            || action != "stop" && !matches!(s(&row["state"]), "running" | "paused")
        {
            return Err(conflict("execution is not available for this action"));
        }
        exec(&mut tx,"UPDATE operations SET state='failed',error='superseded',updated=now() WHERE resource_id=$1 AND state='pending'",args![run]).await?;
        exec(
            &mut tx,
            "UPDATE executions SET desired=$1,generation=generation+1,updated=now() WHERE id=$2",
            args![desired, run],
        )
        .await?;
        if action == "stop" && !row["deployment_id"].is_null() {
            exec(
                &mut tx,
                "UPDATE deployments SET desired='stopped' WHERE id=$1",
                args![row["deployment_id"]],
            )
            .await?;
        }
        let stopped = action == "stop" && row["node_id"].is_null();
        if stopped {
            exec(
                &mut tx,
                "UPDATE executions SET state='stopped',reserved=false WHERE id=$1",
                args![run],
            )
            .await?;
        }
        let mut op = Self::operation(&mut tx, tenant, project, key, &request, run, action).await?;
        if stopped {
            exec(
                &mut tx,
                "UPDATE operations SET state='succeeded' WHERE id=$1",
                args![op["id"]],
            )
            .await?;
            op["state"] = json!("succeeded");
        }
        Self::audit(
            &mut tx,
            p,
            &format!("execution.{action}"),
            run,
            tenant,
            json!({}),
        )
        .await?;
        Self::reconcile_app_runs(&mut tx).await?;
        tx.commit().await?;
        Ok(op)
    }
    pub async fn update_deployment(
        &self,
        p: &Principal,
        tenant: &str,
        project: &str,
        deployment: &str,
        value: Value,
        key: &str,
    ) -> Result<Value> {
        identity(deployment)?;
        fields(
            &value,
            &["expected_revision", "spec", "desired"],
            &["expected_revision"],
        )?;
        let revision = integer(&value["expected_revision"], 1, i32::MAX as i64 - 1)?;
        let desired = get(&value, "desired", json!("running"));
        if !matches!(s(&desired), "running" | "stopped") {
            return Err(Error::invalid("invalid deployment desired state"));
        }
        let new_spec = value.get("spec").map(|v| wasm_spec(v, true)).transpose()?;
        let mut request = value.clone();
        request["kind"] = json!("update-deployment");
        request["deployment"] = json!(deployment);
        let mut tx = self.transaction(true, false).await?;
        Self::project(&mut tx, p, tenant, project, true).await?;
        if let Some(previous) = Self::idem(&mut tx, tenant, project, key, &request).await? {
            return Ok(previous);
        }
        let old = one(
            &mut tx,
            "SELECT * FROM deployments WHERE tenant_id=$1 AND project_id=$2 AND id=$3 FOR UPDATE",
            args![tenant, project, deployment],
        )
        .await?;
        Self::independent_deployment(&mut tx, &old["id"]).await?;
        if n(&old["revision"]) != revision {
            return Err(conflict("deployment revision changed"));
        }
        let spec = new_spec.as_ref().unwrap_or(&old["spec"]);
        self.check_refs(&mut tx, tenant, project, spec).await?;
        if new_spec.is_some() {
            Self::initial_grants(&mut tx, tenant, project, "deployment", deployment, spec).await?;
        }
        exec(
            &mut tx,
            "UPDATE deployments SET spec=$1,revision=revision+1,desired=$2 WHERE id=$3",
            args![spec, desired, deployment],
        )
        .await?;
        exec(&mut tx,"UPDATE executions SET desired='stopped',generation=generation+1,updated=now() WHERE deployment_id=$1 AND reserved",args![deployment]).await?;
        exec(&mut tx,"UPDATE executions SET state='stopped',reserved=false WHERE deployment_id=$1 AND node_id IS NULL AND reserved",args![deployment]).await?;
        exec(&mut tx,"UPDATE operations SET state='failed',error='superseded',updated=now() WHERE resource_id=$1 AND state='pending'",args![deployment]).await?;
        let kind = if desired == "stopped" {
            "stop-deployment"
        } else {
            "update-deployment"
        };
        let mut op =
            Self::operation(&mut tx, tenant, project, key, &request, deployment, kind).await?;
        exec(
            &mut tx,
            "UPDATE operations SET target_revision=$1 WHERE id=$2",
            args![revision + 1, op["id"]],
        )
        .await?;
        op["target_revision"] = json!(revision + 1);
        Self::audit(
            &mut tx,
            p,
            kind,
            deployment,
            tenant,
            json!({"revision":revision+1}),
        )
        .await?;
        tx.commit().await?;
        Ok(op)
    }
    pub async fn schedule(&self) -> Result<()> {
        self.claim_schedule_occurrences().await?;
        self.dispatch_schedule_runs().await?;
        let mut tx = self.transaction(true, false).await?;
        Self::expire_schedule_queue(&mut tx).await?;
        Self::retire_schedule_dispatch(&mut tx).await?;
        crate::placement::expire(&mut tx).await?;
        Self::expire_ingress(&mut tx).await?;
        Self::expire_execution_logs(&mut tx).await?;
        Self::expire_app_events(&mut tx).await?;
        Self::compact_usage_backlog(&mut tx).await?;
        Self::compact_accounting(&mut tx).await?;
        Self::retire_execution_inputs(&mut tx).await?;
        Self::expire_artifacts(&mut tx).await?;
        Self::network_reconcile(&mut tx).await?;
        exec(&mut tx,"UPDATE executions SET state='unreachable',updated=now() WHERE reserved AND node_id IN (SELECT id FROM nodes WHERE last_seen<now()-interval '15 seconds') AND state IN ('starting','running','paused')",args![]).await?;
        self.reconcile_app_http(&mut tx).await?;
        for e in rows(&mut tx,"SELECT * FROM executions WHERE node_id IS NULL AND desired='running' AND reserved AND EXISTS(SELECT 1 FROM tenants t WHERE t.id=executions.tenant_id AND t.lifecycle_state='active') ORDER BY created,id",args![]).await? {
            let public = !Self::https_connections(&mut tx,s(&e["id"])).await?.is_empty();
            if public && self.current_https_policy(&mut tx).await.is_err() {
                crate::placement::record(&mut tx,&e,crate::placement::Rejection::PublicPolicy).await?;
                continue;
            }
            let candidates=rows(&mut tx,"SELECT n.*,COALESCE(sum(e.cpu_percent),0) used_cpu,COALESCE(sum(e.memory_mib),0) used_memory,count(e.id) used_instances FROM nodes n LEFT JOIN executions e ON e.node_id=n.id AND e.reserved WHERE NOT n.draining AND NOT n.disabled AND n.backend='wasm' AND n.architecture=$1 AND n.runtime=$2 AND n.last_seen>now()-interval '10 seconds' GROUP BY n.id ORDER BY count(e.id),n.id",args![e["spec"]["architecture"],e["spec"]["runtime"]]).await?;
            let mut rejection=Some(crate::placement::Rejection::NoWorker);
            for node in candidates {
                match crate::placement::candidate(&node,&e,public) {
                    Err(reason) => rejection=Some(rejection.unwrap().max(reason)),
                    Ok(budget) => {
                    exec(&mut tx,"UPDATE executions SET node_id=$1,egress_budget_launcher=$3,state='starting',updated=now() WHERE id=$2",args![node["id"],e["id"],if budget {node["egress_budget_launcher"].clone()} else {Value::Null}]).await?;
                    Self::audit_system(&mut tx,"scheduler","execution.assign",&e["id"],&e["tenant_id"],json!({"node_id":node["id"],"generation":e["generation"]})).await?;
                    rejection=None; break;
                    }
                }
            }
            if let Some(reason)=rejection { crate::placement::record(&mut tx,&e,reason).await?; }
        }
        for d in rows(&mut tx,"SELECT d.* FROM deployments d WHERE desired='running' AND EXISTS(SELECT 1 FROM tenants t WHERE t.id=d.tenant_id AND t.lifecycle_state='active') AND NOT EXISTS(SELECT 1 FROM app_http h WHERE h.deployment_id=d.id) AND (spec->>'restart_policy'='always' OR NOT EXISTS(SELECT 1 FROM executions e WHERE e.deployment_id=d.id AND e.revision=d.revision)) AND NOT EXISTS(SELECT 1 FROM executions e WHERE e.deployment_id=d.id AND e.reserved)",args![]).await? {
            if let Err(e)=Self::execution(&mut tx,s(&d["tenant_id"]),s(&d["project_id"]),&d["spec"],Some(s(&d["id"])),n(&d["revision"])).await&& e.status!=StatusCode::TOO_MANY_REQUESTS {return Err(e)}
        }
        exec(&mut tx,"UPDATE operations o SET state='succeeded',updated=now() WHERE kind='stop-deployment' AND state='pending' AND NOT EXISTS(SELECT 1 FROM executions e WHERE e.deployment_id=o.resource_id AND e.reserved)",args![]).await?;
        Self::reconcile_app_runs(&mut tx).await?;
        Self::reconcile_workspace_suspensions(&mut tx).await?;
        tx.commit().await?;
        self.reclaim_artifact_blobs().await?;
        self.reclaim_orphan_uploads().await?;
        self.websocket_sweep().await?;
        Ok(())
    }
}
#[cfg(test)]
mod secret_value_tests {
    use super::secret_value_fits;

    #[test]
    fn a_secrets_value_is_at_least_four_bytes() {
        for short in ["", "a", "ab", "abc"] {
            assert!(!secret_value_fits(short), "{short:?}");
        }
        assert!(secret_value_fits("abcd"));
        assert!(secret_value_fits(&"x".repeat(1024)));
        assert!(!secret_value_fits(&"x".repeat(1025)));
        assert!(!secret_value_fits("ab\0cd"));
        // Bytes, not characters: two letters of two bytes each are four.
        assert!(secret_value_fits("éé"));
    }
}
