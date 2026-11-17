//! Scheduler decisions, with a scoped customer projection. No fleet identities
//! or counts enter the projection, and reading it never attempts placement.
use crate::{args, db::*, error::Result, model::HOST_CONFINEMENT, store::Tx};
use serde_json::{Value, json};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Rejection {
    NoWorker,
    Confinement,
    PublicHttps,
    EgressBudget,
    Size,
    Capacity,
    PublicPolicy,
}

impl Rejection {
    fn code(self) -> &'static str {
        match self {
            Self::NoWorker => "placement-no-worker",
            Self::Confinement => "placement-confinement",
            Self::PublicHttps => "placement-public-https",
            Self::EgressBudget => "placement-egress-budget",
            Self::Size => "placement-size",
            Self::Capacity => "placement-capacity",
            Self::PublicPolicy => "placement-public-policy",
        }
    }
}
/// Candidate ordering remains the scheduler's least-loaded order. Among rejected
/// candidates, the furthest satisfied gate describes the limiting requirement.
pub(crate) fn candidate(
    node: &Value,
    execution: &Value,
    public: bool,
) -> std::result::Result<bool, Rejection> {
    if node["observed_confinement"] != HOST_CONFINEMENT {
        return Err(Rejection::Confinement);
    }
    let private = !execution["spec"]["network_id"].is_null();
    // A public origin is pinned to its addresses by the guest runtime, which
    // the node must have reported.
    if public && node["observed_runtime_digest"].is_null() {
        return Err(Rejection::PublicHttps);
    }
    let budget = node["egress_budget_required"] == true && (public || private);
    if budget && !crate::egress_budget::eligible(node) {
        return Err(Rejection::EgressBudget);
    }
    if n(&execution["cpu_percent"]) > n(&node["cpu_percent"])
        || n(&execution["memory_mib"]) > n(&node["memory_mib"])
        || n(&node["instances"]) < 1
    {
        return Err(Rejection::Size);
    }
    if n(&node["used_cpu"]) + n(&execution["cpu_percent"]) > n(&node["cpu_percent"])
        || n(&node["used_memory"]) + n(&execution["memory_mib"]) > n(&node["memory_mib"])
        || n(&node["used_instances"]) >= n(&node["instances"])
    {
        return Err(Rejection::Capacity);
    }
    Ok(budget)
}
pub(crate) async fn record(tx: &mut Tx, e: &Value, reason: Rejection) -> Result<()> {
    // Refresh a stable decision at most every 30 seconds; changed decisions are
    // immediate. Keep one row per execution, rather than a heartbeat history.
    exec(tx,"INSERT INTO execution_placement(execution_id,generation,reason,observed_at) VALUES($1,$2,$3,now()) ON CONFLICT(execution_id) DO UPDATE SET generation=EXCLUDED.generation,reason=EXCLUDED.reason,observed_at=EXCLUDED.observed_at WHERE execution_placement.generation<>EXCLUDED.generation OR execution_placement.reason<>EXCLUDED.reason OR execution_placement.observed_at<now()-interval '30 seconds'",args![e["id"],e["generation"],reason.code()]).await?;
    Ok(())
}
/// Retire only obsolete placement detail, under the scheduler admission lock
/// and recovery barrier. Execution identities, outcomes and usage are untouched.
pub(crate) async fn expire(tx: &mut Tx) -> Result<()> {
    exec(tx, include_str!("placement_retention.sql"), args![]).await?;
    Ok(())
}
fn visit(value: &mut Value, action: &mut impl FnMut(&mut Value)) {
    if value.get("execution_id").is_some() {
        action(value);
    }
    for key in ["http", "latest_run"] {
        if let Some(value) = value.get_mut(key) {
            action(value);
        }
    }
}
/// Call only after normal app/run authorization. Tenant/project constraints also
/// fence the join itself. Assigned, stopped and superseded generations disappear.
pub(crate) async fn project(
    tx: &mut Tx,
    tenant: &str,
    project: &str,
    values: &mut [Value],
) -> Result<()> {
    let mut ids = Vec::new();
    for value in values.iter_mut() {
        visit(value, &mut |slot| {
            if matches!(s(&slot["state"]), "queued" | "starting")
                && let Some(id) = slot["execution_id"].as_str()
            {
                ids.push(id.to_owned());
            }
        });
    }
    if ids.is_empty() {
        return Ok(());
    }
    ids.sort();
    ids.dedup();
    let rows: Vec<Value> = sqlx::query_scalar("SELECT jsonb_build_object('execution_id',e.id,'reason',p.reason,'observed_at',p.observed_at) FROM execution_placement p JOIN executions e ON e.id=p.execution_id AND e.generation=p.generation WHERE e.tenant_id=$1 AND e.project_id=$2 AND e.id=ANY($3) AND e.node_id IS NULL AND e.reserved AND e.desired='running'")
        .bind(tenant).bind(project).bind(ids).fetch_all(&mut **tx).await?;
    let found = rows
        .into_iter()
        .map(|mut row| {
            let id = s(&row["execution_id"]).to_owned();
            row.as_object_mut().unwrap().remove("execution_id");
            (id, row)
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    for value in values {
        visit(value, &mut |slot| {
            if matches!(s(&slot["state"]), "queued" | "starting")
                && let Some(row) = found.get(s(&slot["execution_id"]))
            {
                slot["placement"] = json!(row);
            }
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn placement_gates_never_trade_security_for_capacity() {
        let mut node = json!({"observed_confinement":HOST_CONFINEMENT,"observed_runtime_digest":"reported","egress_budget_required":true,"observed_egress_budget":crate::egress_budget::CONTRACT,"egress_budget_launcher":"launcher","observed_launcher_digest":"launcher","cpu_percent":100,"memory_mib":128,"instances":1,"used_cpu":0,"used_memory":0,"used_instances":0});
        let e = json!({"spec":{"network_id":"private"},"cpu_percent":100,"memory_mib":88});
        assert_eq!(candidate(&node, &e, true), Ok(true));
        for (field, value, reason) in [
            (
                "observed_confinement",
                json!("unverified"),
                Rejection::Confinement,
            ),
            (
                "observed_runtime_digest",
                Value::Null,
                Rejection::PublicHttps,
            ),
            (
                "observed_egress_budget",
                json!("old-contract"),
                Rejection::EgressBudget,
            ),
            (
                "observed_launcher_digest",
                json!("other"),
                Rejection::EgressBudget,
            ),
            ("memory_mib", json!(64), Rejection::Size),
            ("cpu_percent", json!(50), Rejection::Size),
            ("used_memory", json!(64), Rejection::Capacity),
            ("used_cpu", json!(1), Rejection::Capacity),
            ("used_instances", json!(1), Rejection::Capacity),
        ] {
            let mut rejected = node.clone();
            rejected[field] = value;
            assert_eq!(candidate(&rejected, &e, true), Err(reason), "{field}");
        }
        node["observed_runtime_digest"] = Value::Null;
        let offline = json!({"spec":{},"cpu_percent":100,"memory_mib":88});
        assert_eq!(candidate(&node, &offline, false), Ok(false));
        assert_eq!(
            candidate(&node, &offline, true),
            Err(Rejection::PublicHttps)
        );
    }
}
