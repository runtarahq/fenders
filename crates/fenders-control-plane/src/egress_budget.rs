//! Transactional native byte-grant authority. Frozen native receipts settle
//! admission-period allowance; source-month measurements never release holds.
use crate::{
    args,
    db::*,
    error::{Error, Result},
    model::*,
    store::{Store, Tx},
};
use axum::http::StatusCode;
pub use fenders_node_protocol::egress_budget::*;
use serde_json::Value;
const MAX_GRANT: i64 = 16 * 1024 * 1024;
/// The most a run holds beyond what it has sent, where its shim says what it
/// has sent: one grant, and the least a running run keeps.
const MAX_UNSENT: u64 = MAX_GRANT as u64 + 256 * 1024;
/// How much of the `additional` bytes asked for is granted to a run whose
/// ceiling is `ceiling` and whose shim says it has `sent` so many: no more
/// than brings what it holds unsent to [`MAX_UNSENT`]. A shim that does not
/// say is granted what it asks, as before it could say.
fn grantable(additional: i64, ceiling: u64, sent: Option<u64>) -> i64 {
    match sent {
        Some(sent) => {
            let unsent = ceiling.saturating_sub(sent.min(ceiling));
            (additional as u64).min(MAX_UNSENT.saturating_sub(unsent)) as i64
        }
        None => additional,
    }
}
pub(crate) const RETAINED_LAUNCHERS_MIGRATION: &str = "ALTER TABLE nodes ADD COLUMN IF NOT EXISTS retained_egress_launchers jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(retained_egress_launchers)='array' AND jsonb_array_length(retained_egress_launchers)<=32)";

pub(crate) fn validate_retained_launchers(value: &Value) -> Result<()> {
    let launchers = value
        .as_array()
        .filter(|v| v.len() <= 32)
        .ok_or_else(|| Error::invalid("expected at most 32 retained launcher digests"))?;
    for (index, launcher) in launchers.iter().enumerate() {
        if !launcher.as_str().is_some_and(valid_digest) || launchers[..index].contains(launcher) {
            return Err(Error::invalid(
                "invalid or duplicate retained launcher digest",
            ));
        }
    }
    Ok(())
}

/// Current capability admits new placements. An existing execution may instead
/// use explicitly approved retained bytes, observed under this boot/generation.
pub(crate) fn execution_launcher_eligible(host: &Value, e: &Value, launcher: &Value) -> bool {
    launcher_eligible(host, e, launcher, n(&e["generation"]))
}

/// Lifecycle intent advances generation before the worker can report it. Permit
/// delivery to the same observed runtime; renewal still requires the new report.
pub(crate) fn assignment_launcher_eligible(host: &Value, e: &Value, launcher: &Value) -> bool {
    launcher_eligible(host, e, launcher, 1)
}

fn launcher_eligible(host: &Value, e: &Value, launcher: &Value, minimum_generation: i64) -> bool {
    if !launcher.as_str().is_some_and(valid_digest) {
        return false;
    }
    if eligible(host) && *launcher == host["observed_launcher_digest"] {
        return true;
    }
    let observed = &e["observation"];
    let authority = &observed["egress_authority"];
    let approved = *launcher == host["egress_budget_launcher"]
        || host["retained_egress_launchers"]
            .as_array()
            .is_some_and(|v| v.contains(launcher));
    approved
        && host["observed_confinement"] == HOST_CONFINEMENT
        && host["observed_egress_budget"] == CONTRACT
        && observed["generation"].as_i64().is_some_and(|generation| {
            generation >= 1 && generation >= minimum_generation && generation <= n(&e["generation"])
        })
        && matches!(s(&observed["state"]), "starting" | "running" | "paused")
        && host["boot_id"]
            .as_str()
            .is_some_and(|boot| validate_authority(authority, boot).is_ok())
        && authority["launcher_digest"] == *launcher
}
pub(crate) fn eligible(host: &Value) -> bool {
    host["observed_confinement"] == HOST_CONFINEMENT
        && host["observed_egress_budget"] == CONTRACT
        && !host["egress_budget_launcher"].is_null()
        && host["egress_budget_launcher"] == host["observed_launcher_digest"]
}
fn bytes(value: &Value) -> Result<u64> {
    value
        .as_u64()
        .ok_or_else(|| Error::invalid("invalid unsigned byte counter"))
}
impl Store {
    /// Read-only recovery view for the authenticated execution owner. It does
    /// not create authority or release held bytes, including after expiry.
    pub async fn egress_budget_status(
        &self,
        node: &str,
        execution: &str,
        generation: i64,
    ) -> Result<Value> {
        identity(node)?;
        identity(execution)?;
        let mut tx = self.transaction(false, false).await?;
        let owned: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM executions e JOIN nodes n ON n.id=e.node_id WHERE e.id=$1 AND e.node_id=$2 AND e.generation=$3 AND NOT n.disabled)")
            .bind(execution).bind(node).bind(generation).fetch_one(&mut *tx).await?;
        if !owned {
            return Err(conflict("stale or foreign execution grant"));
        }
        let grant = optional(&mut tx, "SELECT revision,state,period,period=date_trunc('month',now() AT TIME ZONE 'UTC')::date current_period,base_bytes,ceiling_bytes,held_bytes,boot_id,generation,launcher_digest,request_id,closure,CASE WHEN state='active' THEN GREATEST(0,LEAST(10000,floor(extract(epoch FROM (expires-clock_timestamp()))*1000)))::bigint ELSE 0 END ttl_ms FROM execution_egress_budgets WHERE execution_id=$1", args![execution]).await?;
        let capacity=one(&mut tx,"SELECT e.desired,GREATEST(0,t.transfer_bytes-COALESCE((SELECT sum(used_bytes+held_bytes) FROM transfer_allowance_accounting a WHERE a.tenant_id=t.id AND a.period=date_trunc('month',now() AT TIME ZONE 'UTC')::date),0))::bigint available_bytes FROM executions e JOIN tenants t ON t.id=e.tenant_id WHERE e.id=$1",args![execution]).await?;
        Ok(
            serde_json::json!({"grant":grant,"desired":capacity["desired"],"available_bytes":capacity["available_bytes"]}),
        )
    }
    /// Called in the heartbeat transaction after owner/generation/sequence and
    /// measurement validation. Terminal accounting never reopens native credit.
    pub(crate) async fn settle_terminal_egress(
        tx: &mut Tx,
        e: &Value,
        report: &Value,
        boot: &str,
        confined: bool,
    ) -> Result<()> {
        if !crate::workloads::terminal(s(&report["state"])) {
            return Ok(());
        }
        let Some(g)=optional(tx,"SELECT * FROM execution_egress_budgets WHERE execution_id=$1 AND state<>'closed' FOR UPDATE",args![e["id"]]).await? else {return Ok(())};
        let source = optional(
            tx,
            "SELECT * FROM execution_egress_usage WHERE execution_id=$1",
            args![e["id"]],
        )
        .await?;
        let meter = &report["egress"];
        let authority = &report["egress_authority"];
        let accepted = meter["bytes"].as_u64();
        let base = bytes(&g["base_bytes"])?;
        let ceiling = bytes(&g["ceiling_bytes"])?;
        let exact = confined
            && matches!(s(&report["state"]), "exited" | "stopped" | "failed")
            && g["node_id"] == e["node_id"]
            && g["boot_id"] == boot
            && meter["boot_id"] == boot
            && authority["contract"] == CONTRACT
            && authority["boot_id"] == boot
            && authority["launcher_digest"] == g["launcher_digest"]
            && meter["complete"] == true
            && meter["in_flight"] == 0
            && accepted.is_some_and(|n| {
                n >= base && n <= ceiling && (g["state"] != "frozen" || n == base)
            })
            && source.as_ref().is_some_and(|u| {
                u["consistent"] == true
                    && u["complete"] == true
                    && u["generation"] == e["generation"]
                    && u["boot_id"] == boot
                    && u["bytes"] == meter["bytes"]
            });
        let consumed = if exact {
            accepted.unwrap() - base
        } else {
            bytes(&g["held_bytes"])?
        };
        exec(tx,"INSERT INTO egress_allowance_usage(execution_id,tenant_id,project_id,period,bytes,conservative_bytes) VALUES($1,$2,$3,$4::date,$5::bigint,$6::bigint) ON CONFLICT(execution_id,period) DO UPDATE SET bytes=egress_allowance_usage.bytes+excluded.bytes,conservative_bytes=egress_allowance_usage.conservative_bytes+excluded.conservative_bytes",args![e["id"],e["tenant_id"],e["project_id"],g["period"],consumed.to_string(),if exact {"0".to_owned()} else {consumed.to_string()}]).await?;
        exec(tx,"UPDATE execution_egress_budgets SET state='closed',closure=$2,closed_at=now(),base_bytes=$3::numeric,held_bytes=0,expires=NULL,updated=now() WHERE execution_id=$1",args![e["id"],if exact {"terminal-exact"} else {"terminal-conservative"},if exact {accepted.unwrap().to_string()} else {base.to_string()}]).await?;
        Ok(())
    }
    pub(crate) async fn transfer_capacity(
        tx: &mut Tx,
        tenant: &str,
        additional: i64,
    ) -> Result<()> {
        let allowed: bool=sqlx::query_scalar("SELECT COALESCE((SELECT sum(used_bytes+held_bytes) FROM transfer_allowance_accounting WHERE tenant_id=t.id AND period=date_trunc('month',now() AT TIME ZONE 'UTC')::date),0)+$2::numeric<=t.transfer_bytes FROM tenants t WHERE id=$1")
            .bind(tenant).bind(additional).fetch_one(&mut **tx).await?;
        if !allowed {
            return Err(quota("transfer allowance exhausted"));
        }
        Ok(())
    }
    /// Internal node authority. The caller must authenticate the enrolled node;
    /// ownership, generation, boot and approved capability are rechecked here.
    /// Fleet activation/dispatch is deliberately separate from this allocator.
    pub async fn egress_budget(
        &self,
        node: &str,
        execution: &str,
        generation: i64,
        value: Value,
    ) -> Result<Value> {
        identity(node)?;
        identity(execution)?;
        fields(
            &value,
            &[
                "boot_id",
                "expected_revision",
                "request_id",
                "action",
                "bytes",
                "sent",
                "observation",
            ],
            &["boot_id", "expected_revision", "request_id", "action"],
        )?;
        // What the run has sent of what it was granted, as its shim reads it
        // from the launcher's meter: with it, a grant is held to what the
        // run has yet to send.
        let sent = match value.get("sent") {
            None | Some(Value::Null) => None,
            Some(sent) => Some(integer(sent, 0, i64::MAX)? as u64),
        };
        let expected = integer(&value["expected_revision"], 0, i64::MAX)?;
        let request = text(&value["request_id"])?;
        if request.is_empty() || request.len() > 128 {
            return Err(Error::invalid("invalid grant request ID"));
        }
        let action = text(&value["action"])?;
        if !matches!(action, "grant" | "freeze" | "settle") {
            return Err(Error::invalid("invalid grant action"));
        }
        let additional = if action == "grant" {
            integer(&value["bytes"], 0, MAX_GRANT)?
        } else {
            if value.get("bytes").is_some() {
                return Err(Error::invalid("bytes only applies to grants"));
            }
            0
        };
        if action != "settle" && value.get("observation").is_some() {
            return Err(Error::invalid("observation only applies to settlement"));
        }
        let hash = digest(serde_json::to_vec(&value).map_err(|_| Error::internal())?);
        let mut tx = self.watched_transaction().await?;
        let e=optional(&mut tx,"SELECT e.* FROM executions e WHERE e.id=$1 AND e.node_id=$2 AND e.generation=$3 FOR UPDATE",args![execution,node,generation]).await?
            .ok_or_else(||conflict("stale or foreign execution grant"))?;
        let host = one(
            &mut tx,
            "SELECT *,last_seen>now()-interval '15 seconds' fresh FROM nodes WHERE id=$1",
            args![node],
        )
        .await?;
        if host["disabled"] == true
            || host["boot_id"] != value["boot_id"]
            || host["boot_id"].is_null()
            || host["fresh"] != true
            || host["observed_confinement"] != HOST_CONFINEMENT
            || host["observed_egress_budget"] != CONTRACT
        {
            return Err(Error::new(
                StatusCode::FORBIDDEN,
                "node lacks approved byte-grant authority",
            ));
        }
        if action == "grant" && (!b(&e["reserved"]) || e["desired"] != "running") {
            return Err(conflict("execution cannot receive new byte authority"));
        }
        let existing = optional(
            &mut tx,
            "SELECT launcher_digest FROM execution_egress_budgets WHERE execution_id=$1",
            args![execution],
        )
        .await?;
        let launcher = if !e["egress_budget_launcher"].is_null() {
            &e["egress_budget_launcher"]
        } else if let Some(g) = &existing {
            &g["launcher_digest"]
        } else {
            &host["observed_launcher_digest"]
        };
        if !execution_launcher_eligible(&host, &e, launcher) {
            return Err(conflict(
                "execution is pinned to another byte-grant launcher",
            ));
        }
        exec(&mut tx,"INSERT INTO execution_egress_budgets(execution_id,tenant_id,project_id,node_id,boot_id,generation,launcher_digest) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING",args![execution,e["tenant_id"],e["project_id"],node,value["boot_id"],generation,launcher]).await?;
        let g=one(&mut tx,"SELECT *,period=date_trunc('month',now() AT TIME ZONE 'UTC')::date current_period FROM execution_egress_budgets WHERE execution_id=$1 FOR UPDATE",args![execution]).await?;
        if g["state"] == "closed" {
            return Err(conflict("execution byte authority is closed"));
        }
        if g["node_id"] != node
            || g["boot_id"] != value["boot_id"]
            || g["launcher_digest"] != *launcher
        {
            return Err(conflict("grant belongs to another runtime incarnation"));
        }
        if g["request_id"] == request {
            if g["request_hash"] != hash {
                return Err(conflict("grant request ID reused with different content"));
            }
        } else {
            if n(&g["revision"]) != expected {
                return Err(conflict("stale grant revision"));
            }
            let revision = if action == "settle" || action == "freeze" && g["state"] == "frozen" {
                expected
            } else {
                expected
                    .checked_add(1)
                    .ok_or_else(|| conflict("grant revision exhausted"))?
            };
            match action {
                "grant" => {
                    if g["state"] == "freezing"
                        || (g["state"] == "active"
                            && (g["generation"] != generation || g["current_period"] != true))
                    {
                        return Err(conflict(
                            "freeze and settle the previous grant before renewing",
                        ));
                    }
                    let base = bytes(&g["base_bytes"])?;
                    let ceiling = if g["state"] == "frozen" {
                        base
                    } else {
                        bytes(&g["ceiling_bytes"])?
                    };
                    // A run holds, of its workspace's allowance, no more
                    // than it has yet to send plus one grant: asked for more
                    // while that much is unsent, it is given what brings it
                    // there, and its grant is renewed all the same. Without
                    // this a run could be granted the whole allowance and
                    // hold it from its workspace's other runs and requests.
                    let additional = grantable(additional, ceiling, sent);
                    Self::transfer_capacity(&mut tx, s(&e["tenant_id"]), additional).await?;
                    let ceiling = ceiling
                        .checked_add(additional as u64)
                        .ok_or_else(|| quota("cumulative byte ceiling exhausted"))?;
                    let held = ceiling - base;
                    exec(&mut tx,"UPDATE execution_egress_budgets SET state='active',revision=$2,generation=$3,period=date_trunc('month',now() AT TIME ZONE 'UTC')::date,ceiling_bytes=$4::numeric,held_bytes=$5::bigint,expires=LEAST(clock_timestamp()+interval '10 seconds',(date_trunc('month',now() AT TIME ZONE 'UTC')+interval '1 month') AT TIME ZONE 'UTC') WHERE execution_id=$1",args![execution,revision,generation,ceiling.to_string(),held.to_string()]).await?;
                }
                "freeze" => {
                    if g["state"] != "frozen" {
                        exec(&mut tx,"UPDATE execution_egress_budgets SET state='freezing',revision=$2,generation=$3,expires=NULL,held_bytes=ceiling_bytes-base_bytes WHERE execution_id=$1",args![execution,revision,generation]).await?;
                    }
                }
                "settle" => {
                    if g["state"] != "freezing" {
                        return Err(conflict("settlement requires a frozen native grant"));
                    }
                    let observation = &value["observation"];
                    let accepted = bytes(&observation["egress_budget_bytes"])?;
                    if observation["egress_budget_enabled"] != true
                        || observation["egress_budget_measured"] != true
                        || observation["egress_budget_revision"] != g["revision"]
                        || observation["egress_budget_ceiling"] != g["ceiling_bytes"]
                        || observation["egress_budget_deadline_ns"] != 0
                        || observation["egress_budget_reserved"] != 0
                        || observation["egress_budget_in_flight"] != 0
                        || accepted < bytes(&g["base_bytes"])?
                        || accepted > bytes(&g["ceiling_bytes"])?
                    {
                        return Err(conflict("grant remains uncertain or has in-flight writes"));
                    }
                    let consumed = accepted - bytes(&g["base_bytes"])?;
                    exec(&mut tx,"INSERT INTO egress_allowance_usage(execution_id,tenant_id,project_id,period,bytes) VALUES($1,$2,$3,$4::date,$5::bigint) ON CONFLICT(execution_id,period) DO UPDATE SET bytes=egress_allowance_usage.bytes+excluded.bytes",args![execution,e["tenant_id"],e["project_id"],g["period"],consumed.to_string()]).await?;
                    // Keep the freeze revision: the native runtime has already
                    // applied it. The next grant advances it exactly once.
                    exec(&mut tx,"UPDATE execution_egress_budgets SET state='frozen',base_bytes=$2::numeric,held_bytes=0,expires=NULL WHERE execution_id=$1",args![execution,accepted.to_string()]).await?;
                }
                _ => unreachable!(),
            }
            exec(&mut tx,"UPDATE execution_egress_budgets SET request_id=$2,request_hash=$3,updated=now() WHERE execution_id=$1",args![execution,request,hash]).await?;
        }
        let result=one(&mut tx,"SELECT revision,state,period,base_bytes,ceiling_bytes,held_bytes,boot_id,CASE WHEN state='active' THEN GREATEST(0,LEAST(10000,floor(extract(epoch FROM (expires-clock_timestamp()))*1000)))::bigint ELSE 0 END ttl_ms FROM execution_egress_budgets WHERE execution_id=$1",args![execution]).await?;
        self.commit_watched(tx).await?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn retained_authority_requires_boot_generation_contract_and_observed_incarnation() {
        let old = json!("a".repeat(64));
        let host = json!({
            "observed_confinement":HOST_CONFINEMENT,"observed_egress_budget":CONTRACT,
            "boot_id":"one","egress_budget_launcher":"b".repeat(64),
            "observed_launcher_digest":"b".repeat(64),"retained_egress_launchers":[old]});
        let e = json!({"generation":7,"observation":{"generation":7,"state":"running",
            "egress_authority":{"contract":CONTRACT,"boot_id":"one","launcher_digest":old}}});
        assert!(execution_launcher_eligible(&host, &e, &old));
        let mut intent = e.clone();
        intent["generation"] = json!(8);
        assert!(assignment_launcher_eligible(&host, &intent, &old));
        assert!(!execution_launcher_eligible(&host, &intent, &old));
        intent["generation"] = json!(6);
        assert!(!assignment_launcher_eligible(&host, &intent, &old));
        for (key, value) in [
            ("generation", json!(8)),
            ("state", json!("stopped")),
            ("egress_authority", Value::Null),
            (
                "egress_authority",
                json!({"contract":CONTRACT,"boot_id":"two","launcher_digest":old}),
            ),
            (
                "egress_authority",
                json!({"contract":"legacy","boot_id":"one","launcher_digest":old}),
            ),
            (
                "egress_authority",
                json!({"contract":CONTRACT,"boot_id":"one","launcher_digest":"b".repeat(64)}),
            ),
        ] {
            let mut invalid = e.clone();
            invalid["observation"][key] = value;
            assert!(!execution_launcher_eligible(&host, &invalid, &old), "{key}");
        }
        for (key, value) in [
            ("retained_egress_launchers", json!([])),
            ("boot_id", json!("two")),
            ("observed_confinement", Value::Null),
            ("observed_egress_budget", Value::Null),
        ] {
            let mut invalid = host.clone();
            invalid[key] = value;
            assert!(!execution_launcher_eligible(&invalid, &e, &old), "{key}");
        }
    }
}
#[cfg(test)]
mod grant_tests {
    use super::{MAX_GRANT, MAX_UNSENT, grantable};

    #[test]
    fn a_run_holds_no_more_than_it_has_yet_to_send_and_one_grant() {
        let grant = MAX_GRANT;
        // Everything granted so far was sent: a whole grant more.
        assert_eq!(grantable(grant, 1 << 30, Some(1 << 30)), grant);
        // Nothing of the last grant was sent: only the least a run keeps.
        let ceiling = 1 << 30;
        let sent = ceiling - grant as u64;
        assert_eq!(
            grantable(grant, ceiling, Some(sent)),
            (MAX_UNSENT - grant as u64) as i64
        );
        // Asking again and again while sending nothing gains nothing more.
        let held = ceiling + MAX_UNSENT - grant as u64;
        assert_eq!(grantable(grant, held, Some(sent)), 0);
        assert_eq!(grantable(grant, held + (1 << 40), Some(sent)), 0);
        // A shim that claims more sent than it was granted gains no more
        // than one that sent it all.
        assert_eq!(grantable(grant, ceiling, Some(u64::MAX)), grant);
        // One that does not say is granted what it asks.
        assert_eq!(grantable(4096, ceiling, None), 4096);
    }
}
