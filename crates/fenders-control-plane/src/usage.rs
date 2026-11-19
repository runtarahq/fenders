//! Customer accounting: reservations are not measurements. Reads use one MVCC
//! snapshot so project rows reconcile to totals while admission continues.
use crate::{
    args,
    db::*,
    error::{Error, Result},
    model::Principal,
    store::Store,
};
use serde_json::{Value, json};

impl Store {
    pub async fn usage(&self, p: &Principal, tenant: &str, project: Option<&str>) -> Result<Value> {
        p.scope(tenant, project, false, false)?;
        let mut tx = self.snapshot().await?;
        Self::live_principal(&mut tx, p).await?;
        if let Some(project) = project {
            Self::project(&mut tx, p, tenant, project, false).await?;
        }
        let allowance = one(&mut tx, "SELECT id,name,cpu_percent,memory_mib,instances,storage_bytes,transfer_bytes FROM tenants WHERE id=$1", args![tenant]).await?;
        let http_limits = one(&mut tx, "SELECT http_concurrent_requests AS concurrent_requests,http_requests_per_minute AS requests_per_minute FROM tenants WHERE id=$1", args![tenant]).await?;
        let clock = one(&mut tx, "SELECT now() as_of,date_trunc('month',now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC' period_start,(date_trunc('month',now() AT TIME ZONE 'UTC')+interval '1 month') AT TIME ZONE 'UTC' period_end", args![]).await?;
        let projects = rows(&mut tx, include_str!("usage.sql"), args![tenant, project]).await?;
        let totals = aggregate(&projects)?;
        Ok(json!({
            "scope":if project.is_some(){"project"}else{"workspace"},
            "as_of":clock["as_of"],"project_id":project,"allowance":allowance,"http_limits":http_limits,
            "period":{"start":clock["period_start"],"end":clock["period_end"],"timezone":"UTC"},
            "projects":projects,"totals":totals,"accounting_retention":crate::accounting_retention::policy(),
            "measurement":{"cpu_window":"recorded execution lifetime","memory_freshness_seconds":30,
                "egress_bytes":totals["egress_bytes"],"egress_window":"recorded execution lifetime","egress_contract":"socket-payload-v1",
                "egress_period_contract":"socket-payload-utc-month-v1","egress_period_allowance_enforced":false},
            "diagnostics":{"retention_days":7,"workspace_payload_limit_bytes":crate::execution_logs::WORKSPACE_BYTES,"workspace_record_limit":crate::execution_logs::WORKSPACE_RECORDS,
                "charged_to_storage_allowance":false},
            // Existing consumers retain their accounting keys. CPU now returns
            // null when there are executions but no confirmed measurements.
            "reserved":{"cpu_percent":totals["reserved_cpu_percent"],"memory_mib":totals["reserved_memory_mib"],"instances":totals["reserved_instances"]},
            "storage_bytes":totals["storage_bytes"],"artifact_bytes":totals["artifact_bytes"],"cpu_usec":totals["cpu_usec"],
            "paused_memory_is_reserved":true,
            "ingress_month":{"bytes":totals["ingress_bytes"],"requests":totals["ingress_requests"]},
            "transfer_allowance":{"period_basis":"UTC admission month","bytes":totals["transfer_accounted_bytes"],"reserved_bytes":totals["transfer_reserved_bytes"],"outbound_conservative_bytes":totals["outbound_conservative_bytes"],"gateway_conservative_bytes":totals["gateway_conservative_bytes"],"gateway_leased_bytes":totals["gateway_leased_bytes"],"outbound_fleet_enforcement":false}
        }))
    }
}

// Reject unrepresentable totals rather than saturating or inventing zeros.
fn aggregate(projects: &[Value]) -> Result<Value> {
    let mut total = json!({});
    for key in [
        "outbound_grant_executions",
        "egress_month_bytes",
        "egress_month_measured",
        "egress_month_complete",
        "egress_period_sources",
        "egress_period_discontinuities",
        "egress_unassigned_bytes",
        "egress_bytes",
        "egress_measured",
        "egress_complete",
        "egress_discontinuities",
        "reserved_cpu_percent",
        "reserved_memory_mib",
        "reserved_instances",
        "wasm_instances",
        "uncertain_instances",
        "artifact_bytes",
        "storage_bytes",
        "ingress_bytes",
        "ingress_requests",
        "ingress_reserved_bytes",
        "transfer_accounted_bytes",
        "transfer_reserved_bytes",
        "outbound_conservative_bytes",
        "gateway_conservative_bytes",
        "gateway_leased_bytes",
        "executions",
        "measured_executions",
        "memory_expected",
        "memory_measured",
        "diagnostic_bytes",
        "diagnostic_records",
        "diagnostic_expired_bytes",
        "cpu_usec",
        "memory_bytes",
    ] {
        let mut sum = 0_u64;
        for project in projects {
            if !project[key].is_null() {
                let value = project[key].as_u64().ok_or_else(Error::internal)?;
                sum = sum.checked_add(value).ok_or_else(Error::internal)?;
            }
        }
        total[key] = json!(sum);
    }
    for (metric, expected, measured) in [
        ("egress_month_bytes", "executions", "egress_month_measured"),
        (
            "egress_unassigned_bytes",
            "executions",
            "egress_period_sources",
        ),
        ("egress_bytes", "executions", "egress_measured"),
        ("cpu_usec", "executions", "measured_executions"),
        ("memory_bytes", "memory_expected", "memory_measured"),
    ] {
        if total[measured] == 0 && total[expected] != 0 {
            total[metric] = Value::Null;
        }
    }
    total["oldest_memory_observed"] = projects
        .iter()
        .filter_map(|p| p["oldest_memory_observed"].as_str())
        .min()
        .map_or(Value::Null, |v| json!(v));
    for key in [
        "egress_last_sampled",
        "egress_received",
        "egress_month_sampled",
    ] {
        total[key] = projects
            .iter()
            .filter_map(|p| p[key].as_str())
            .max()
            .map_or(Value::Null, |v| json!(v));
    }
    total["egress_first_sampled"] = projects
        .iter()
        .filter_map(|p| p["egress_first_sampled"].as_str())
        .min()
        .map_or(Value::Null, |v| json!(v));
    total["last_cpu_observed"] = projects
        .iter()
        .filter_map(|p| p["last_cpu_observed"].as_str())
        .max()
        .map_or(Value::Null, |v| json!(v));
    Ok(total)
}

#[derive(serde::Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct HistoryPage {
    pub before: Option<String>,
    pub limit: Option<i64>,
}
impl Store {
    /// Monthly project/workspace totals have identical meaning before and
    /// after finalized detail compaction. A cursor grants no authorization.
    pub async fn usage_history(
        &self,
        p: &Principal,
        tenant: &str,
        project: Option<&str>,
        page: HistoryPage,
    ) -> Result<Value> {
        use chrono::Datelike;
        p.scope(tenant, project, false, false)?;
        let limit = integer(&json!(page.limit.unwrap_or(13)), 1, 60)?;
        if let Some(before) = &page.before {
            let date = chrono::NaiveDate::parse_from_str(before, "%Y-%m-%d")
                .map_err(|_| Error::invalid("invalid history month"))?;
            if date.day() != 1
                || !(1970..=9999).contains(&date.year())
                || date.format("%Y-%m-%d").to_string() != *before
            {
                return Err(Error::invalid("invalid history month"));
            }
        }
        let mut tx = self.snapshot().await?;
        Self::live_principal(&mut tx, p).await?;
        if let Some(project) = project {
            Self::project(&mut tx, p, tenant, project, false).await?;
        }
        one(&mut tx, "SELECT id FROM tenants WHERE id=$1", args![tenant]).await?;
        let clock = one(&mut tx, "SELECT now() as_of", args![]).await?;
        let mut items = rows(
            &mut tx,
            include_str!("usage_history.sql"),
            args![tenant, project, page.before, limit + 1],
        )
        .await?;
        for item in &items {
            for key in [
                "gateway_bytes",
                "gateway_requests",
                "outbound_accounted_bytes",
                "outbound_conservative_bytes",
                "accounted_bytes",
                "held_bytes",
                "observed_outbound_bytes",
                "observed_period_records",
            ] {
                if !(item[key].is_null() && matches!(key, "observed_outbound_bytes"))
                    && item[key].as_u64().is_none()
                {
                    return Err(Error::internal());
                }
            }
        }
        let more = items.len() > limit as usize;
        items.truncate(limit as usize);
        let next = if more {
            items.last().map(|v| v["period"].clone())
        } else {
            None
        };
        Ok(
            json!({"scope":if project.is_some(){"project"}else{"workspace"},"project_id":project,"as_of":clock["as_of"],
            "items":items,"next":next,"retention":crate::accounting_retention::policy(),
            "measurement":{"period":"UTC calendar month","allowance_basis":"admission month","outbound_observation_basis":"socket completion month","observations_are_allowance_charges":false}}),
        )
    }
}
