use crate::{
    args,
    db::*,
    error::{Error, Result},
    model::*,
    store::Store,
    workloads::terminal,
};
use axum::http::StatusCode;
use serde_json::{Value, json};
impl Store {
    pub async fn register_node(&self, p: &Principal, value: Value) -> Result<Value> {
        self.register_node_keyed(p, value, None).await
    }
    /// With a key, a retry is answered with the node the first call
    /// registered, not refused as a second node of its name.
    pub async fn register_node_keyed(
        &self,
        p: &Principal,
        value: Value,
        key: Option<&str>,
    ) -> Result<Value> {
        p.operator()?;
        fields(
            &value,
            &[
                "name",
                "cert_sha256",
                "endpoint",
                "backend",
                "architecture",
                "runtime",
                "cpu_percent",
                "memory_mib",
                "instances",
                "egress_budget_launcher",
                "egress_budget_required",
            ],
            &[
                "name",
                "cert_sha256",
                "endpoint",
                "backend",
                "architecture",
                "runtime",
                "cpu_percent",
                "memory_mib",
                "instances",
            ],
        )?;
        named(&value["name"])?;
        let pin = text(&value["cert_sha256"])?;
        if pin.len() != 64
            || !pin
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::invalid("invalid certificate fingerprint"));
        }
        let endpoint = url::Url::parse(text(&value["endpoint"])?)
            .map_err(|_| Error::invalid("invalid node endpoint"))?;
        if endpoint.scheme() != "https"
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.path() != "/"
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            return Err(Error::invalid("node endpoint must be an HTTPS origin"));
        }
        if value["backend"] != "wasm"
            || value["architecture"] != "x86_64"
            || text(&value["runtime"])?.len() > 128
        {
            return Err(Error::invalid(
                "unsupported backend, architecture or runtime",
            ));
        }
        integer(&value["cpu_percent"], 1, 1000000)?;
        integer(&value["memory_mib"], 88, 100000000)?;
        integer(&value["instances"], 1, 100000)?;
        validate_runtime_digest(&value["egress_budget_launcher"])?;
        let budget = get(&value, "egress_budget_required", json!(false));
        if !budget.is_boolean() || budget == true && value["egress_budget_launcher"].is_null() {
            return Err(Error::invalid(
                "budgeted placement requires an approved launcher",
            ));
        }
        let request = json!({"kind":"node.register","value":value});
        let mut tx = self.transaction(true, false).await?;
        if let Some(key) = key
            && let Some(row) =
                crate::customer_api::operator_receipt(&mut tx, &p.id, key, &request).await?
        {
            return Ok(row);
        }
        let row=one(&mut tx,"INSERT INTO nodes(id,name,cert_sha256,endpoint,backend,architecture,runtime,cpu_percent,memory_mib,instances,egress_budget_launcher,egress_budget_required) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING *",args![uid(),value["name"],pin,endpoint.as_str().trim_end_matches('/'),value["backend"],value["architecture"],value["runtime"],value["cpu_percent"],value["memory_mib"],value["instances"],value["egress_budget_launcher"],budget]).await?;
        Self::audit_system(
            &mut tx,
            &p.id,
            "node.register",
            &row["id"],
            &Value::Null,
            json!({}),
        )
        .await?;
        if let Some(key) = key {
            crate::customer_api::save_operator_receipt(&mut tx, &p.id, key, None, &request, &row)
                .await?;
        }
        tx.commit().await?;
        Ok(row)
    }
    pub async fn nodes(&self, p: &Principal) -> Result<Value> {
        p.operator()?;
        let mut tx = self.transaction(false, false).await?;
        Ok(json!(
            rows(&mut tx, "SELECT * FROM nodes ORDER BY created", args![]).await?
        ))
    }
    pub async fn node_mode(&self, p: &Principal, node: &str, value: Value) -> Result<Value> {
        self.node_mode_keyed(p, node, value, None).await
    }
    /// A key is not required: the change says what the node is to be, and
    /// saying it twice changes nothing more. With one, a retry is answered
    /// as the first call was and leaves no second audit record.
    pub async fn node_mode_keyed(
        &self,
        p: &Principal,
        node: &str,
        value: Value,
        key: Option<&str>,
    ) -> Result<Value> {
        p.operator()?;
        identity(node)?;
        fields(
            &value,
            &[
                "draining",
                "disabled",
                "egress_budget_required",
                "egress_budget_launcher",
                "retained_egress_launchers",
            ],
            &[],
        )?;
        validate_runtime_digest(&value["egress_budget_launcher"])?;
        if let Some(retained) = value.get("retained_egress_launchers") {
            crate::egress_budget::validate_retained_launchers(retained)?;
        }
        if value.as_object().unwrap().is_empty()
            || value.as_object().unwrap().iter().any(|(k, v)| {
                !matches!(
                    k.as_str(),
                    "egress_budget_launcher" | "retained_egress_launchers"
                ) && !v.is_boolean()
            })
        {
            return Err(Error::invalid(
                "expected node flags and approved launcher digests",
            ));
        }
        let request = json!({"kind":"node.mode","node":node,"value":value});
        let mut tx = self.transaction(true, false).await?;
        if let Some(key) = key
            && let Some(row) =
                crate::customer_api::operator_receipt(&mut tx, &p.id, key, &request).await?
        {
            return Ok(row);
        }
        let old = one(
            &mut tx,
            "SELECT * FROM nodes WHERE id=$1 FOR UPDATE",
            args![node],
        )
        .await?;
        if get(
            &value,
            "egress_budget_required",
            old["egress_budget_required"].clone(),
        ) == true
            && get(
                &value,
                "egress_budget_launcher",
                old["egress_budget_launcher"].clone(),
            )
            .is_null()
        {
            return Err(Error::invalid(
                "budgeted placement requires an approved launcher",
            ));
        }
        exec(
            &mut tx,
            "UPDATE nodes SET draining=$1,disabled=$2,egress_budget_launcher=$4,egress_budget_required=$5,retained_egress_launchers=$6 WHERE id=$3",
            args![
                get(&value, "draining", old["draining"].clone()),
                get(&value, "disabled", old["disabled"].clone()),
                node,
                get(&value, "egress_budget_launcher", old["egress_budget_launcher"].clone()),
                get(&value, "egress_budget_required", old["egress_budget_required"].clone()),
                get(&value, "retained_egress_launchers", old["retained_egress_launchers"].clone())
            ],
        )
        .await?;
        // A disabled node is told nothing more: what it runs with public
        // HTTPS access is fenced, to be stopped when the node is seen again.
        if get(&value, "disabled", json!(false)) == true && old["disabled"] != true {
            for e in rows(&mut tx,"SELECT DISTINCT e.id FROM executions e JOIN app_execution_https x ON x.execution_id=e.id WHERE e.node_id=$1 AND e.reserved",args![node]).await? {
                Self::fence_https_execution(&mut tx, s(&e["id"])).await?;
            }
        }
        Self::audit_system(
            &mut tx,
            &p.id,
            "node.mode",
            &json!(node),
            &Value::Null,
            value.clone(),
        )
        .await?;
        let mut result = value;
        result["id"] = json!(node);
        if let Some(key) = key {
            crate::customer_api::save_operator_receipt(
                &mut tx, &p.id, key, None, &request, &result,
            )
            .await?;
        }
        tx.commit().await?;
        Ok(result)
    }
    pub async fn node_identity(&self, pin: &str) -> Result<Value> {
        let mut tx = self.transaction(false, false).await?;
        optional(
            &mut tx,
            "SELECT * FROM nodes WHERE cert_sha256=$1 AND NOT disabled",
            args![pin],
        )
        .await?
        .ok_or_else(|| Error::new(StatusCode::FORBIDDEN, "node not enrolled"))
    }
    pub async fn heartbeat(&self, node: &str, value: Value) -> Result<Value> {
        fields(
            &value,
            &[
                "boot_id",
                "reports",
                "network_leases",
                "confinement",
                "runtime_digest",
                "egress_budget_contract",
                "launcher_digest",
            ],
            &["boot_id", "reports"],
        )?;
        validate_runtime_digest(&value["runtime_digest"])?;
        validate_runtime_digest(&value["launcher_digest"])?;
        if !value["egress_budget_contract"].is_null() {
            let contract = text(&value["egress_budget_contract"])?;
            if contract.is_empty() || contract.len() > 128 {
                return Err(Error::invalid("invalid egress budget contract"));
            }
        }
        // Nodes still say whether they take network leases. None does, and
        // nothing here depends on it.
        if !get(&value, "network_leases", json!(false)).is_boolean()
            || text(&value["boot_id"])?.is_empty()
            || text(&value["boot_id"])?.len() > 128
        {
            return Err(Error::invalid("invalid heartbeat"));
        }
        if !value["confinement"].is_null()
            && (text(&value["confinement"])?.is_empty() || text(&value["confinement"])?.len() > 64)
        {
            return Err(Error::invalid("invalid host confinement capability"));
        }
        let reports = value["reports"]
            .as_array()
            .filter(|v| v.len() <= 1024)
            .ok_or_else(|| Error::invalid("invalid heartbeat reports"))?;
        let mut tx = self.transaction(true, false).await?;
        optional(
            &mut tx,
            "SELECT id FROM nodes WHERE id=$1 AND NOT disabled FOR UPDATE",
            args![node],
        )
        .await?
        .ok_or_else(|| Error::new(StatusCode::FORBIDDEN, "node disabled"))?;
        exec(&mut tx,"UPDATE nodes SET boot_id=$1,last_seen=now(),observed_confinement=$2,observed_runtime_digest=$4,observed_egress_budget=$5,observed_launcher_digest=$6 WHERE id=$3",args![value["boot_id"],value["confinement"],node,value["runtime_digest"],value["egress_budget_contract"],value["launcher_digest"]]).await?;
        for report in reports {
            fields(
                report,
                &[
                    "id",
                    "generation",
                    "state",
                    "sequence",
                    "cpu_usec",
                    "memory_bytes",
                    "exit_code",
                    "reason",
                    "action_error",
                    "cpu_measured",
                    "memory_measured",
                    "egress",
                    "egress_periods",
                    "egress_authority",
                    "runtime_authority",
                ],
                &[
                    "id",
                    "generation",
                    "state",
                    "sequence",
                    "cpu_usec",
                    "memory_bytes",
                ],
            )?;
            // A node's report, not a request's body: answered as it was.
            fenders_node_protocol::value::id(&report["id"])?;
            integer(&report["generation"], 1, i64::MAX)?;
            let Some(e) = optional(
                &mut tx,
                "SELECT * FROM executions WHERE id=$1 AND node_id=$2 FOR UPDATE",
                args![report["id"], node],
            )
            .await?
            else {
                continue;
            };
            if report["generation"] != e["generation"] || !b(&e["reserved"]) {
                continue;
            }
            let state = text(&report["state"])?;
            if !matches!(state, "starting" | "running" | "paused") && !terminal(state) {
                return Err(Error::invalid("invalid execution state"));
            }
            let sequence = integer(&report["sequence"], 0, i64::MAX)?;
            if sequence <= e["observation"]["sequence"].as_i64().unwrap_or(-1) {
                continue;
            }
            for key in ["cpu_measured", "memory_measured"] {
                if report.get(key).is_some_and(|v| !v.is_boolean()) {
                    return Err(Error::invalid("invalid measurement availability"));
                }
            }
            if let Some(authority) = report.get("egress_authority") {
                crate::egress_budget::validate_authority(authority, s(&value["boot_id"]))?;
                if value["confinement"] != HOST_CONFINEMENT {
                    return Err(Error::invalid("egress authority requires host confinement"));
                }
            }
            if let Some(authority) = report.get("runtime_authority") {
                crate::app_https::validate_runtime_authority(authority, s(&value["boot_id"]))?;
                if value["confinement"] != HOST_CONFINEMENT {
                    return Err(Error::invalid(
                        "runtime authority requires host confinement",
                    ));
                }
            }
            integer(&report["cpu_usec"], 0, i64::MAX)?;
            integer(&report["memory_bytes"], 0, i64::MAX)?;
            if let Some(egress) = report.get("egress").filter(|v| !v.is_null()) {
                crate::egress_usage::validate(egress, state, s(&value["boot_id"]))?;
                if value["confinement"] != crate::model::HOST_CONFINEMENT {
                    return Err(Error::invalid(
                        "egress measurement requires host confinement",
                    ));
                }
                crate::egress_usage::record(&mut tx, &e, egress).await?;
            }
            if let Some(periods) = report.get("egress_periods").filter(|v| !v.is_null()) {
                crate::egress_periods::validate(periods, state, s(&value["boot_id"]))?;
                if value["confinement"] != crate::model::HOST_CONFINEMENT {
                    return Err(Error::invalid("monthly egress requires host confinement"));
                }
                crate::egress_periods::record(&mut tx, &e, periods).await?;
            }
            if !report["reason"].is_null() && text(&report["reason"])?.len() > 256 {
                return Err(Error::invalid("invalid reason"));
            }
            if !report["action_error"].is_null()
                && !matches!(
                    s(&report["action_error"]),
                    "application-busy" | "control-unavailable"
                )
            {
                return Err(Error::invalid("invalid action error"));
            }
            if !report["exit_code"].is_null() {
                integer(&report["exit_code"], -255, 255)?;
            }
            Self::settle_terminal_egress(
                &mut tx,
                &e,
                report,
                s(&value["boot_id"]),
                value["confinement"] == HOST_CONFINEMENT,
            )
            .await?;
            exec(&mut tx,"UPDATE executions SET state=$1,reserved=$2,observation=$3,started_at=CASE WHEN $1 IN ('running','paused','exited') THEN COALESCE(started_at,now()) ELSE started_at END,finished_at=CASE WHEN NOT $2 THEN COALESCE(finished_at,now()) ELSE finished_at END,updated=now() WHERE id=$4",args![state,!terminal(state),report,e["id"]]).await?;
            exec(&mut tx,"INSERT INTO usage_samples(execution_id,generation,sequence,tenant_id,cpu_usec,memory_bytes,cpu_measured,memory_measured) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING",args![e["id"],e["generation"],sequence,e["tenant_id"],report["cpu_usec"],report["memory_bytes"],b(&report["cpu_measured"]),b(&report["memory_measured"])]).await?;
            Self::compact_usage(&mut tx, &e).await?;
            for op in rows(&mut tx,"SELECT * FROM operations WHERE tenant_id=$1 AND state='pending' AND (resource_id=$2 OR (resource_id=$3 AND kind IN ('create-deployment','update-deployment') AND target_revision=$4))",args![e["tenant_id"],e["id"],e["deployment_id"],e["revision"]]).await? {
                let kind=s(&op["kind"]);
                let success=(kind.starts_with("create-")||kind=="update-deployment") && matches!(state,"running"|"paused"|"exited") || kind=="pause" && state=="paused" || kind=="resume" && state=="running" || kind=="stop" && terminal(state);
                let failure=terminal(state)&&!success || !report["action_error"].is_null()&&matches!(kind,"pause"|"resume");
                if success || failure {
                    let error=if success {Value::Null} else if report["action_error"].is_null() {json!("execution terminated")} else {report["action_error"].clone()};
                    exec(&mut tx,"UPDATE operations SET state=$1,error=$2,updated=now() WHERE id=$3",args![if success {"succeeded"} else {"failed"},error,op["id"]]).await?;
                }
            }
            if !report["action_error"].is_null() && e["desired"] == "stopped" && !terminal(state) {
                // Retain the stop intent and reservation. A fresh generation
                // makes the worker retry a transient control failure without
                // temporarily restoring running intent or replaying a command.
                exec(
                    &mut tx,
                    "UPDATE executions SET generation=generation+1,updated=now() WHERE id=$1",
                    args![e["id"]],
                )
                .await?;
            } else if !report["action_error"].is_null() && e["desired"] != "stopped" {
                exec(
                    &mut tx,
                    "UPDATE executions SET desired=$1 WHERE id=$2",
                    args![
                        if state == "paused" {
                            "paused"
                        } else {
                            "running"
                        },
                        e["id"]
                    ],
                )
                .await?;
            }
        }
        Self::network_reconcile(&mut tx).await?;
        Self::reconcile_app_runs(&mut tx).await?;
        self.reconcile_app_http(&mut tx).await?;
        Self::reconcile_workspace_suspensions(&mut tx).await?;
        let assignments=rows(&mut tx,"SELECT id,generation,desired,spec,tenant_id,project_id FROM executions WHERE node_id=$1 AND reserved ORDER BY created",args![node]).await?;
        tx.commit().await?;
        Ok(json!(assignments))
    }
    pub async fn assignment(&self, node: &str, execution: &str, generation: i64) -> Result<Value> {
        identity(execution)?;
        let prepared = self.prepare_https(node, execution, generation).await?;
        let mut tx = self.transaction(true, false).await?;
        let e = optional(
            &mut tx,
            "SELECT * FROM executions WHERE id=$1 AND node_id=$2 AND generation=$3 AND reserved",
            args![execution, node, generation],
        )
        .await?
        .ok_or_else(|| conflict("assignment is stale or not owned by this node"))?;
        if e["desired"] == "stopped" {
            return Ok(
                json!({"id":e["id"],"generation":e["generation"],"desired":"stopped","spec":null,"artifact":null}),
            );
        }
        Self::require_workspace_active(&mut tx, s(&e["tenant_id"])).await?;
        let node = one(&mut tx, "SELECT * FROM nodes WHERE id=$1", args![node]).await?;
        if b(&node["disabled"]) || node["observed_confinement"] != HOST_CONFINEMENT {
            return Err(Error::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "node lacks required host confinement",
            ));
        }
        Self::check_app_connection_assignment(&mut tx, execution).await?;
        self.apply_https(&mut tx, &e, prepared).await?;
        let mut spec = e["spec"].clone();
        let artifact = one(
            &mut tx,
            "SELECT * FROM artifacts WHERE tenant_id=$1 AND project_id=$2 AND id=$3 AND retired_at IS NULL",
            args![e["tenant_id"], e["project_id"], spec["artifact_id"]],
        )
        .await?;
        let secrets = spec["secret_env"]
            .as_object()
            .ok_or_else(Error::internal)?
            .clone();
        // A shim keeps its guest's output only when asked, and is told with
        // the same field which variables to mask in it. Every run asks: a
        // node that cannot capture refuses the field, and the run with it,
        // rather than run with its output lost.
        let run_channel = self.run_channel_fields(execution, generation);
        if run_channel.is_some() {
            spec["output"] = json!({"redact_env": secrets.keys().collect::<Vec<_>>()});
        } else if !secrets.is_empty() {
            spec["log_redact_env"] = json!(secrets.keys().collect::<Vec<_>>());
        }
        for (variable, secret) in secrets {
            let row=one(&mut tx,"SELECT convert_from(ciphertext,'UTF8') token FROM secrets WHERE tenant_id=$1 AND project_id=$2 AND id=$3 AND bound",args![e["tenant_id"],e["project_id"],secret]).await?;
            // Opened only as the secret of this execution's own workspace
            // and project that it names: a ciphertext moved here from
            // another row does not open.
            let plain = crate::secret_binding::open(
                &self.cipher,
                s(&e["tenant_id"]),
                s(&e["project_id"]),
                s(&secret),
                s(&row["token"]),
            )?;
            spec["env"][variable] = json!(String::from_utf8(plain).map_err(|_| Error::internal())?);
        }
        for field in [
            "artifact_id",
            "secret_env",
            "architecture",
            "runtime",
            "restart_policy",
        ] {
            spec.as_object_mut().unwrap().remove(field);
        }
        spec["artifact"] = artifact["digest"].clone();
        // An execution of an app that accepts WebSocket connections sends
        // to them by calling the run channel over its host-bound origin.
        // No other launch of Fenders' own names one.
        if run_channel.is_some() && self.websocket_sender(execution).await?.is_some() {
            spec["host_origin"] = json!(crate::websocket::ORIGIN);
        }
        let egress = if !e["egress_budget_launcher"].is_null() {
            if !crate::egress_budget::assignment_launcher_eligible(
                &node,
                &e,
                &e["egress_budget_launcher"],
            ) {
                return Err(Error::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "assigned byte-grant launcher is unavailable",
                ));
            }
            spec["egress_budget"] = json!(true);
            json!({"contract":crate::egress_budget::CONTRACT,"launcher_digest":e["egress_budget_launcher"]})
        } else {
            Value::Null
        };
        // Outbound access is static launch policy: there is no lease.
        self.launch_policy(&mut tx, &e, &node, &mut spec).await?;
        for field in ["network_id", "endpoint_ids", "endpoint_env"] {
            spec.as_object_mut().unwrap().remove(field);
        }
        // What a shim node needs to start the run at all.
        for (field, value) in run_channel.iter().flat_map(|v| v.as_object()).flatten() {
            spec[field] = value.clone();
        }
        tx.commit().await?;
        Ok(
            json!({"id":e["id"],"generation":e["generation"],"desired":e["desired"],"spec":spec,"artifact":artifact,"egress":egress,"compile_scope":e["tenant_id"]}),
        )
    }
    /// Digests of the components this node could be assigned, newest first, so
    /// it can compile them before any execution is: running deployments' and
    /// enabled apps' active releases, whose manual, scheduled and HTTP runs
    /// launch them. The node must pass
    /// the gates an assignment does; draining nodes may still pre-warm.
    pub async fn prewarm_digests(&self, node: &str) -> Result<Vec<Value>> {
        let (digests, _) = self.prewarm_offer(node).await?;
        Ok(digests)
    }
    /// [`prewarm_digests`](Self::prewarm_digests), and the compile cache
    /// scope (a tenant whose component it is) of each.
    pub async fn prewarm_offer(&self, node: &str) -> Result<(Vec<Value>, Value)> {
        let mut tx = self.transaction(false, false).await?;
        let rows = rows(&mut tx, PREWARM, args![node, HOST_CONFINEMENT]).await?;
        tx.commit().await?;
        let scopes = rows
            .iter()
            .map(|row| (s(&row["digest"]).to_owned(), row["tenant_id"].clone()))
            .collect::<serde_json::Map<_, _>>();
        Ok((
            rows.into_iter().map(|row| row["digest"].clone()).collect(),
            Value::Object(scopes),
        ))
    }
    /// Only components this node is offered for pre-warming are served.
    pub async fn prewarm_artifact(&self, node: &str, digest: &str) -> Result<Vec<u8>> {
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::missing());
        }
        if !self
            .prewarm_digests(node)
            .await?
            .iter()
            .any(|listed| listed == digest)
        {
            return Err(Error::missing());
        }
        let bytes = std::fs::read(self.state.join("blobs").join(digest))?;
        if crate::model::digest(&bytes) != digest {
            return Err(Error::internal());
        }
        Ok(bytes)
    }
    pub async fn assigned_artifact(
        &self,
        node: &str,
        execution: &str,
        generation: i64,
    ) -> Result<Vec<u8>> {
        let assignment = self.assignment(node, execution, generation).await?;
        if assignment["artifact"].is_null() {
            return Err(conflict("stopped execution has no artifact assignment"));
        }
        let expected = text(&assignment["artifact"]["digest"])?;
        if expected.len() != 64 || !expected.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::internal());
        }
        let bytes = std::fs::read(self.state.join("blobs").join(expected))?;
        if digest(&bytes) != expected {
            return Err(Error::internal());
        }
        Ok(bytes)
    }
}

// Mirrors placement: an enabled, confined WASM node of the deployment's
// architecture and runtime, for workspaces that are active.
const PREWARM: &str = "WITH wanted AS (SELECT d.tenant_id, d.spec, d.created FROM deployments d WHERE d.desired='running' UNION ALL SELECT r.tenant_id, r.spec, r.created FROM apps p JOIN app_releases r ON r.id=p.active_release_id AND r.state='ready' WHERE p.desired='enabled') SELECT a.digest, min(a.tenant_id) AS tenant_id FROM nodes n JOIN wanted w ON w.spec->>'architecture'=n.architecture AND w.spec->>'runtime'=n.runtime JOIN tenants t ON t.id=w.tenant_id AND t.lifecycle_state='active' JOIN artifacts a ON a.tenant_id=w.tenant_id AND a.id=w.spec->>'artifact_id' AND a.retired_at IS NULL WHERE n.id=$1 AND NOT n.disabled AND n.backend='wasm' AND n.observed_confinement=$2 GROUP BY a.digest ORDER BY max(w.created) DESC LIMIT 8";
fn validate_runtime_digest(value: &Value) -> Result<()> {
    if !value.is_null()
        && !value.as_str().is_some_and(|v| {
            v.len() == 64
                && v.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
    {
        return Err(Error::invalid(
            "runtime digest must be lowercase SHA-256 or null",
        ));
    }
    Ok(())
}

/// Whose turn it is to send a heartbeat: one of each node at a time.
#[derive(Default)]
pub struct NodeTurns {
    nodes: std::sync::Mutex<std::collections::HashMap<String, std::sync::Arc<Turn>>>,
}

struct Turn {
    /// Held by the heartbeat being handled.
    handling: tokio::sync::Semaphore,
    /// Heartbeats being handled or waiting to be.
    present: std::sync::atomic::AtomicUsize,
}

/// A node's turn, given back when dropped.
pub struct NodeTurn {
    turn: std::sync::Arc<Turn>,
    handling: bool,
}

impl NodeTurns {
    /// `node`'s turn, once the heartbeat before this one is done. `None`
    /// when one is already waiting behind it: a third is refused.
    pub async fn take(&self, node: &str) -> Option<NodeTurn> {
        use std::sync::atomic::Ordering::SeqCst;
        let turn = self
            .nodes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(node.to_owned())
            .or_insert_with(|| {
                std::sync::Arc::new(Turn {
                    handling: tokio::sync::Semaphore::new(1),
                    present: Default::default(),
                })
            })
            .clone();
        if turn.present.fetch_add(1, SeqCst) >= 2 {
            turn.present.fetch_sub(1, SeqCst);
            return None;
        }
        // Counted from here: given back if this call is dropped while it waits.
        let mut taken = NodeTurn {
            turn: turn.clone(),
            handling: false,
        };
        turn.handling.acquire().await.ok()?.forget();
        taken.handling = true;
        Some(taken)
    }
}

impl Drop for NodeTurn {
    fn drop(&mut self) {
        if self.handling {
            self.turn.handling.add_permits(1);
        }
        self.turn
            .present
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(test)]
mod turn_tests {
    use super::NodeTurns;
    use std::sync::Arc;

    #[tokio::test]
    async fn a_node_has_one_heartbeat_handled_and_one_waiting() {
        let turns = Arc::new(NodeTurns::default());
        let first = turns.take("a").await.unwrap();
        // Another node is not held up by it.
        let other = turns.take("b").await.unwrap();
        // A second of the same node waits; a third is refused.
        let waiting = tokio::spawn({
            let turns = turns.clone();
            async move { turns.take("a").await.is_some() }
        });
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished());
        assert!(turns.take("a").await.is_none());
        // The first done, the second has its turn; then there is room again.
        drop(first);
        assert!(waiting.await.unwrap());
        let next = turns.take("a").await.unwrap();
        drop((next, other));
        // One that stops waiting gives its place back.
        let held = turns.take("a").await.unwrap();
        let abandoned = tokio::spawn({
            let turns = turns.clone();
            async move { turns.take("a").await.is_some() }
        });
        tokio::task::yield_now().await;
        abandoned.abort();
        let _ = abandoned.await;
        drop(held);
        assert!(turns.take("a").await.is_some());
    }
}
