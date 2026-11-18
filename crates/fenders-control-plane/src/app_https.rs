//! Public HTTPS origins an app may call. An execution is bound, once, to the
//! addresses its origins resolved to when it was assigned; that is part of its
//! launch policy and holds for its life. Code rollback never restores access;
//! removing an origin stops the executions launched with it.
use crate::{
    args,
    db::*,
    error::{Error, Result},
    model::*,
    public_egress::ResolvedTargets,
    store::{Store, Tx},
};
use axum::http::StatusCode;
use fenders_egress::{Origin, PublicTargets};
pub use fenders_node_protocol::app_https::*;
use serde_json::{Value, json};
use std::collections::BTreeSet;

/// Part of the first schema baseline, whose checksum covers this text; the
/// columns are dropped again by `sql/static_connections.sql`.
pub(crate) const RUNTIME_MIGRATION: &str = "
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS retained_https_runtimes jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(retained_https_runtimes)='array' AND jsonb_array_length(retained_https_runtimes)<=32);
ALTER TABLE executions ADD COLUMN IF NOT EXISTS public_https_runtime text CHECK (public_https_runtime ~ '^[a-f0-9]{64}$');";

pub(crate) fn origins(value: &Value) -> Result<Vec<String>> {
    let input = value
        .as_array()
        .filter(|v| v.len() <= fenders_egress::MAX_ORIGINS)
        .ok_or_else(|| Error::invalid("expected at most 16 HTTPS origins"))?;
    let mut result = BTreeSet::new();
    for value in input {
        let origin = Origin::public_https(text(value)?)
            .map_err(|_| Error::invalid("invalid public HTTPS origin"))?
            .to_string();
        if !result.insert(origin) {
            return Err(Error::invalid("duplicate HTTPS origin"));
        }
    }
    Ok(result.into_iter().collect())
}
/// Origins resolved outside a transaction, for [`Store::apply_https`].
pub(crate) struct PreparedHttps {
    ids: Value,
    resolved: Option<ResolvedTargets>,
}

impl Store {
    pub async fn public_egress_policy(&self, p: &Principal) -> Result<Value> {
        p.operator()?;
        let mut tx = self.transaction(false, false).await?;
        let mut row = one(&mut tx,"SELECT p.*,(SELECT count(DISTINCT e.id) FROM executions e JOIN app_execution_https x ON x.execution_id=e.id WHERE e.reserved AND e.desired='stopped') pending_executions FROM public_egress_policy p WHERE singleton",args![]).await?;
        row["configured_digest"] = self
            .public_egress
            .as_ref()
            .map(|r| json!(r.policy_digest()))
            .unwrap_or(Value::Null);
        Ok(row)
    }
    pub async fn activate_public_egress(&self, p: &Principal, value: Value) -> Result<Value> {
        self.activate_public_egress_keyed(p, value, None).await
    }
    /// A key is not required. With one, a retry of a change that was made
    /// is answered with the policy as it now stands, where without it the
    /// revision the retry expects would have passed and it would be refused.
    pub async fn activate_public_egress_keyed(
        &self,
        p: &Principal,
        value: Value,
        key: Option<&str>,
    ) -> Result<Value> {
        p.operator()?;
        fields(
            &value,
            &["expected_revision", "enabled", "digest"],
            &["expected_revision", "enabled"],
        )?;
        integer(&value["expected_revision"], 1, i64::MAX - 1)?;
        if !value["enabled"].is_boolean() {
            return Err(Error::invalid("enabled must be boolean"));
        }
        if value["enabled"] == true
            && self
                .public_egress
                .as_ref()
                .is_none_or(|r| value["digest"] != r.policy_digest())
        {
            return Err(conflict(
                "activate the configured public egress policy digest",
            ));
        }
        let request = json!({"kind":"public-egress.activate","value":value});
        let mut tx = self.transaction(true, false).await?;
        if let Some(key) = key
            && crate::customer_api::operator_receipt(&mut tx, &p.id, key, &request)
                .await?
                .is_some()
        {
            drop(tx);
            return self.public_egress_policy(p).await;
        }
        let old = one(
            &mut tx,
            "SELECT * FROM public_egress_policy WHERE singleton",
            args![],
        )
        .await?;
        if old["revision"] != value["expected_revision"] {
            return Err(conflict("public egress policy revision changed"));
        }
        let digest = if value["enabled"] == true {
            value["digest"].clone()
        } else {
            old["digest"].clone()
        };
        if old["enabled"] != value["enabled"] || old["digest"] != digest {
            exec(&mut tx,"UPDATE public_egress_policy SET enabled=$1,digest=$2,revision=revision+1,updated=now() WHERE singleton",args![value["enabled"],digest]).await?;
            for row in rows(&mut tx,"SELECT DISTINCT e.id FROM executions e JOIN app_execution_https x ON x.execution_id=e.id WHERE e.reserved",args![]).await? {
                Self::fence_https_execution(&mut tx,s(&row["id"])).await?;
            }
            Self::audit_system(
                &mut tx,
                &p.id,
                "public-egress.activate",
                &json!("public-egress"),
                &Value::Null,
                json!({"enabled":value["enabled"],"digest":digest}),
            )
            .await?;
        }
        if let Some(key) = key {
            // That it was made, not what it answered: the answer is read anew.
            crate::customer_api::save_operator_receipt(
                &mut tx,
                &p.id,
                key,
                None,
                &request,
                &Value::Null,
            )
            .await?;
        }
        tx.commit().await?;
        self.public_egress_policy(p).await
    }
    pub(crate) async fn current_https_policy(&self, tx: &mut Tx) -> Result<String> {
        let configured = self
            .public_egress
            .as_ref()
            .ok_or_else(|| {
                Error::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "public HTTPS egress is not configured",
                )
            })?
            .policy_digest();
        let policy = one(
            tx,
            "SELECT * FROM public_egress_policy WHERE singleton",
            args![],
        )
        .await?;
        if policy["enabled"] != true || policy["digest"] != configured {
            return Err(Error::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "public HTTPS policy is not active on this control plane",
            ));
        }
        Ok(configured.to_owned())
    }
    pub(crate) async fn initial_app_https(
        &self,
        tx: &mut Tx,
        app: &Value,
        value: &Value,
    ) -> Result<()> {
        let selected = origins(value)?;
        if !selected.is_empty() {
            self.current_https_policy(tx).await?;
        }
        for origin in selected {
            Self::insert_app_https(tx, app, &origin).await?;
        }
        Ok(())
    }
    async fn insert_app_https(tx: &mut Tx, app: &Value, origin: &str) -> Result<()> {
        if n(&one(
            tx,
            "SELECT count(*) n FROM app_https_connections WHERE app_id=$1",
            args![app["id"]],
        )
        .await?["n"])
            >= 1024
        {
            return Err(quota("app HTTPS history limit reached"));
        }
        exec(tx,"INSERT INTO app_https_connections(id,tenant_id,project_id,app_id,origin) VALUES($1,$2,$3,$4,$5)",args![uid(),app["tenant_id"],app["project_id"],app["id"],origin]).await?;
        Ok(())
    }
    pub(crate) async fn update_app_https(
        &self,
        tx: &mut Tx,
        app: &Value,
        selected: &[String],
        operation: &str,
    ) -> Result<bool> {
        let old = rows(tx,"SELECT * FROM app_https_connections WHERE app_id=$1 AND state='active' ORDER BY origin",args![app["id"]]).await?;
        let added = selected
            .iter()
            .filter(|origin| !old.iter().any(|c| c["origin"] == **origin))
            .collect::<Vec<_>>();
        if !added.is_empty() {
            self.current_https_policy(tx).await?;
        }
        let changed = old.iter().map(|c| s(&c["origin"])).collect::<Vec<_>>()
            != selected.iter().map(String::as_str).collect::<Vec<_>>();
        for connection in old
            .iter()
            .filter(|c| !selected.iter().any(|o| c["origin"] == *o))
        {
            exec(tx,"UPDATE app_https_connections SET state='revoking',revocation_operation_id=$1,updated=now() WHERE id=$2",args![operation,connection["id"]]).await?;
            let executions = rows(tx,"SELECT e.id FROM app_execution_https x JOIN executions e ON e.id=x.execution_id WHERE x.connection_id=$1 AND e.reserved",args![connection["id"]]).await?;
            for e in executions {
                Self::revoke_execution(tx, operation, s(&e["id"])).await?;
            }
        }
        for origin in added {
            Self::insert_app_https(tx, app, origin).await?;
        }
        Ok(changed)
    }
    /// Ends an execution's use of its binding: when the operator's policy
    /// changes under it, or its node is disabled.
    pub(crate) async fn fence_https_execution(tx: &mut Tx, execution: &str) -> Result<()> {
        exec(
            tx,
            "UPDATE execution_https_bindings SET fenced=true,updated=now() WHERE execution_id=$1",
            args![execution],
        )
        .await?;
        Self::stop_reserved(tx, execution).await
    }
    pub(crate) async fn record_app_https(tx: &mut Tx, app: &str, execution: &str) -> Result<()> {
        exec(tx,"INSERT INTO app_execution_https(tenant_id,project_id,app_id,execution_id,connection_id) SELECT tenant_id,project_id,app_id,$1,id FROM app_https_connections WHERE app_id=$2 AND state='active'",args![execution,app]).await?;
        Ok(())
    }
    pub(crate) async fn https_items(tx: &mut Tx, app: &str) -> Result<Vec<Value>> {
        rows(tx,"SELECT id,origin,desired,revocation_operation_id,updated,state,reason FROM app_https_observations WHERE app_id=$1 ORDER BY origin,created,id",args![app]).await
    }
    /// Customer-safe capability metadata. This is not a grant or a capacity
    /// promise; current authority is rechecked during mutation and assignment.
    pub async fn https_access(&self, p: &Principal, tenant: &str, project: &str) -> Result<Value> {
        let mut tx = self.transaction(false, false).await?;
        Self::project(&mut tx, p, tenant, project, false).await?;
        let policy = one(
            &mut tx,
            "SELECT p.*,r.active recovering FROM public_egress_policy p CROSS JOIN recovery_barrier r WHERE p.singleton AND r.singleton",
            args![],
        )
        .await?;
        let available = policy["enabled"] == true
            && policy["recovering"] == false
            && self
                .public_egress
                .as_ref()
                .is_some_and(|r| policy["digest"] == r.policy_digest());
        Ok(
            json!({"available":available,"max_origins":fenders_egress::MAX_ORIGINS,"reason":if available {Value::Null} else {json!("public-https-unavailable")}}),
        )
    }
    /// Syntax validation only: no DNS lookup, writes, execution or permission.
    pub async fn validate_https_access(
        &self,
        p: &Principal,
        tenant: &str,
        project: &str,
        value: Value,
    ) -> Result<Value> {
        let mut tx = self.transaction(false, false).await?;
        Self::project(&mut tx, p, tenant, project, false).await?;
        fields(&value, &["origins"], &["origins"])?;
        Ok(json!({"origins":origins(&value["origins"])?}))
    }
    pub(crate) async fn https_connections(tx: &mut Tx, execution: &str) -> Result<Vec<Value>> {
        rows(tx,"SELECT c.id,c.origin,c.state FROM app_execution_https x JOIN app_https_connections c ON c.id=x.connection_id WHERE x.execution_id=$1 ORDER BY c.origin,c.id",args![execution]).await
    }
    /// Resolves the execution's origins if it has no binding yet. Done before
    /// the assigning transaction, as DNS must not be awaited inside one.
    pub(crate) async fn prepare_https(
        &self,
        node: &str,
        execution: &str,
        generation: i64,
    ) -> Result<Option<PreparedHttps>> {
        let mut tx = self.transaction(false, false).await?;
        let e = optional(
            &mut tx,
            "SELECT * FROM executions WHERE id=$1 AND node_id=$2 AND generation=$3 AND reserved",
            args![execution, node, generation],
        )
        .await?
        .ok_or_else(|| conflict("assignment is stale or not owned by this node"))?;
        if e["desired"] == "stopped" {
            return Ok(None);
        }
        let connections = Self::https_connections(&mut tx, execution).await?;
        if connections.is_empty() {
            return Ok(None);
        }
        if connections.iter().any(|c| c["state"] != "active") {
            return Err(conflict("execution HTTPS access was withdrawn"));
        }
        if one(
            &mut tx,
            "SELECT active FROM recovery_barrier WHERE singleton",
            args![],
        )
        .await?["active"]
            == true
        {
            return Err(Error::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "public HTTPS is blocked during recovery",
            ));
        }
        self.current_https_policy(&mut tx).await?;
        if optional(
            &mut tx,
            "SELECT execution_id FROM execution_https_bindings WHERE execution_id=$1",
            args![execution],
        )
        .await?
        .is_some()
        {
            return Ok(None);
        }
        tx.commit().await?;
        let resolved = self
            .resolve_public_origins(
                &connections
                    .iter()
                    .map(|c| s(&c["origin"]).to_owned())
                    .collect::<Vec<_>>(),
            )
            .await
            .ok();
        Ok(Some(PreparedHttps {
            ids: json!(connections.iter().map(|c| &c["id"]).collect::<Vec<_>>()),
            resolved,
        }))
    }
    /// Binds the execution to a prepared answer, after rechecking its origins
    /// and the operator's policy inside the assigning transaction. The first
    /// binding stands: an assignment asked for again gets the same addresses.
    pub(crate) async fn apply_https(
        &self,
        tx: &mut Tx,
        e: &Value,
        prepared: Option<PreparedHttps>,
    ) -> Result<()> {
        if e["desired"] == "stopped" {
            return Ok(());
        }
        let connections = Self::https_connections(tx, s(&e["id"])).await?;
        if connections.is_empty() {
            return Ok(());
        }
        if connections.iter().any(|c| c["state"] != "active") {
            return Err(conflict("execution HTTPS access was withdrawn"));
        }
        let digest = self.current_https_policy(tx).await?;
        let Some(prepared) = prepared else {
            return Ok(());
        };
        if prepared.ids != json!(connections.iter().map(|c| &c["id"]).collect::<Vec<_>>()) {
            return Err(conflict("execution HTTPS policy changed during resolution"));
        }
        let unresolved = || {
            Error::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "public HTTPS resolution is unavailable",
            )
        };
        let resolved = prepared.resolved.ok_or_else(unresolved)?;
        if resolved.policy_digest() != digest {
            return Err(conflict("public HTTPS policy changed during resolution"));
        }
        let targets = resolved.launch_policy().map_err(|_| unresolved())?;
        exec(tx,"INSERT INTO execution_https_bindings(execution_id,targets,policy_digest) VALUES($1,$2,$3) ON CONFLICT(execution_id) DO NOTHING",args![e["id"],targets,digest]).await?;
        Ok(())
    }
    /// The execution's binding, while the policy it was made under is active.
    pub(crate) async fn https_transport(tx: &mut Tx, execution: &str) -> Result<Option<Value>> {
        optional(tx,"SELECT b.* FROM execution_https_bindings b JOIN public_egress_policy p ON p.singleton AND p.enabled AND p.digest=b.policy_digest WHERE execution_id=$1 AND NOT fenced",args![execution]).await
    }
    pub(crate) fn public_targets(binding: &Value) -> Result<PublicTargets> {
        PublicTargets::parse(s(&binding["targets"])).map_err(|_| Error::internal())
    }
}
