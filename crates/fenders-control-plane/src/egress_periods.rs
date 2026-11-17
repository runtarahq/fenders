//! Source-month socket observations. Never infer a month from receipt time or
//! split a cumulative counter by elapsed time. Gateway admission is separate.
use crate::{
    args,
    db::*,
    error::{Error, Result},
    store::Tx,
};
use chrono::{Datelike, NaiveDate};
pub use fenders_node_protocol::egress_periods::validate;
use fenders_node_protocol::egress_periods::{month, observed, periods};
use serde_json::Value;

fn invalid() -> Error {
    fenders_node_protocol::egress_periods::invalid().into()
}

fn comparable(old: &Value, new: &Value) -> Result<bool> {
    if old["boot_id"] != new["boot_id"]
        || new["bytes"].as_u64() < old["bytes"].as_u64()
        || new["expired_bytes"].as_u64() < old["expired_bytes"].as_u64()
    {
        return Ok(false);
    }
    let before = periods(old)?;
    let after = periods(new)?;
    let last = after.keys().next_back().map(|d| month(*d));
    let previous_last = before.keys().next_back().map(|d| month(*d));
    if previous_last > last
        || (previous_last == last && new["expired_bytes"] != old["expired_bytes"])
        || (old["complete"] == true
            && (new["complete"] != true
                || before != after
                || new["bytes"] != old["bytes"]
                || new["expired_bytes"] != old["expired_bytes"]))
    {
        return Ok(false);
    }
    let mut evicted = 0_u64;
    for (date, bytes) in before {
        match after.get(&date) {
            Some(next) if *next >= bytes => {}
            None if last.is_some_and(|last| month(date) + 24 <= last) => {
                evicted = evicted.checked_add(bytes).ok_or_else(invalid)?;
            }
            _ => return Ok(false),
        }
    }
    Ok(new["expired_bytes"].as_u64().unwrap() - old["expired_bytes"].as_u64().unwrap() >= evicted)
}

pub(crate) async fn record(tx: &mut Tx, execution: &Value, value: &Value) -> Result<()> {
    let bounds=one(tx,"SELECT to_timestamp(($1->>'observed')::double precision)<=now()+interval '5 minutes' AND to_timestamp(($1->>'observed')::double precision)>=created-interval '5 minutes' valid,to_char((created-interval '5 minutes') AT TIME ZONE 'UTC','YYYY-MM-01') first_period FROM executions WHERE id=$2",args![value,execution["id"]]).await?;
    if !b(&bounds["valid"]) {
        return Err(invalid());
    }
    let first =
        NaiveDate::parse_from_str(s(&bounds["first_period"]), "%Y-%m-%d").map_err(|_| invalid())?;
    let entries = periods(value)?;
    if entries.keys().any(|date| *date < first)
        || (value["expired_bytes"].as_u64().unwrap() > 0
            && entries
                .keys()
                .next_back()
                .is_none_or(|last| month(*last) - month(first) < 24))
    {
        return Err(invalid());
    }
    let old = optional(
        tx,
        "SELECT * FROM execution_egress_period_sources WHERE execution_id=$1 FOR UPDATE",
        args![execution["id"]],
    )
    .await?;
    if let Some(old) = &old {
        if n(&old["archived_periods"]) > 0 {
            return Err(conflict("monthly execution history is finalized"));
        }
        if value["observed"].as_f64() < old["payload"]["observed"].as_f64() {
            return Ok(());
        }
        if !b(&old["consistent"]) || !comparable(&old["payload"], value)? {
            exec(tx,"UPDATE execution_egress_period_sources SET consistent=false,complete=false WHERE execution_id=$1",args![execution["id"]]).await?;
            return Ok(());
        }
    }
    exec(tx,"INSERT INTO execution_egress_period_sources(execution_id,tenant_id,project_id,generation,boot_id,bytes,complete,payload,sampled_at) VALUES($1,$2,$3,$4,$5,($6->>'bytes')::numeric,($6->>'complete')::boolean,$6,to_timestamp(($6->>'observed')::double precision)) ON CONFLICT(execution_id) DO UPDATE SET generation=excluded.generation,bytes=excluded.bytes,complete=excluded.complete,payload=excluded.payload,sampled_at=excluded.sampled_at,received=now()",args![execution["id"],execution["tenant_id"],execution["project_id"],execution["generation"],value["boot_id"],value]).await?;
    // A consistent snapshot proves zero in its sampling month even if no write
    // has created a native bucket for it. Never backfill unobserved months.
    let mut entries = entries;
    let date = observed(value)?
        .date_naive()
        .with_day(1)
        .ok_or_else(invalid)?;
    entries.entry(date).or_insert(0);
    for (date, bytes) in entries {
        exec(tx,"INSERT INTO execution_egress_periods(execution_id,tenant_id,project_id,period,bytes,sampled_at) VALUES($1,$2,$3,$4::date,$5::numeric,to_timestamp(($6->>'observed')::double precision)) ON CONFLICT(execution_id,period) DO UPDATE SET bytes=GREATEST(execution_egress_periods.bytes,excluded.bytes),sampled_at=excluded.sampled_at",args![execution["id"],execution["tenant_id"],execution["project_id"],date.to_string(),bytes.to_string(),value]).await?;
    }
    let sum = one(
        tx,
        "SELECT COALESCE((SELECT sum(bytes) FROM execution_egress_periods WHERE execution_id=$1),0)+archived_bytes<=$2::numeric valid FROM execution_egress_period_sources WHERE execution_id=$1",
        args![
            execution["id"],
            value["bytes"].as_u64().unwrap().to_string()
        ],
    )
    .await?;
    if !b(&sum["valid"]) {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn sample() -> Value {
        json!({"contract":"socket-payload-utc-month-v1","bytes":10,"expired_bytes":0,"periods":[{"period":"2026-10-01","bytes":10}],"complete":false,"in_flight":0,"observed":1791300000.0,"boot_id":"boot"})
    }
    #[test]
    fn monthly_contract_rejects_malformed_nonconserving_and_impossible_periods() {
        let good = sample();
        validate(&good, "running", "boot").unwrap();
        for (field, value) in [
            ("bytes", json!(11)),
            ("expired_bytes", json!(-1)),
            ("in_flight", json!(129)),
            ("complete", json!(true)),
            ("boot_id", json!("other")),
            ("contract", json!("unknown")),
            ("observed", json!(0)),
        ] {
            let mut bad = good.clone();
            bad[field] = value;
            assert!(validate(&bad, "running", "boot").is_err(), "{field}");
        }
        for date in ["2026-10-02", "2026-1-01", "2026-11-01", "1969-12-01", "bad"] {
            let mut bad = good.clone();
            bad["periods"][0]["period"] = json!(date);
            assert!(validate(&bad, "running", "boot").is_err(), "{date}");
        }
        let mut bad = good.clone();
        bad["periods"] = json!([good["periods"][0], good["periods"][0]]);
        bad["bytes"] = json!(20);
        assert!(validate(&bad, "running", "boot").is_err());
        bad["periods"] =
            json!([{"period":"2024-10-01","bytes":10},{"period":"2026-10-01","bytes":10}]);
        assert!(validate(&bad, "running", "boot").is_err());
        bad["periods"] =
            json!([{"period":"2026-09-01","bytes":u64::MAX},{"period":"2026-10-01","bytes":1}]);
        assert!(validate(&bad, "running", "boot").is_err());
        bad = good.clone();
        bad["periods"] = json!([]);
        bad["expired_bytes"] = json!(10);
        assert!(validate(&bad, "running", "boot").is_err());
        bad = good.clone();
        bad["extra"] = json!(true);
        assert!(validate(&bad, "running", "boot").is_err());
    }
    #[test]
    fn monthly_transitions_reject_unexpired_disappearance_and_terminal_changes() {
        let good = sample();
        assert!(comparable(&good, &good).unwrap());
        let mut bad = good.clone();
        bad["periods"] = json!([]);
        bad["expired_bytes"] = json!(10);
        assert!(!comparable(&good, &bad).unwrap());
        bad = good.clone();
        bad["expired_bytes"] = json!(1);
        bad["bytes"] = json!(11);
        assert!(!comparable(&good, &bad).unwrap());
        let mut terminal = good.clone();
        terminal["complete"] = json!(true);
        assert!(!comparable(&terminal, &good).unwrap());
        assert!(comparable(&terminal, &terminal).unwrap());
        bad = terminal.clone();
        bad["periods"][0]["bytes"] = json!(20);
        bad["bytes"] = json!(20);
        assert!(!comparable(&terminal, &bad).unwrap());
    }
}
