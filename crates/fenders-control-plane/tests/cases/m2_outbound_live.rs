//! Scoped operator allowance setup/recovery and read-only real-worker evidence.
//! Never manufacture traffic, grant receipts, counters or execution outcomes.
use super::*;
use crate::durable::atomic_json;
use fenders_control_plane::store::Store;
use std::{fs, path::PathBuf, time::Duration};

async fn allowance(store: &Store, operator: &Principal, tenant: &str, bytes: i64) -> Value {
    let report = store.usage(operator, tenant, None).await.unwrap();
    let a = &report["allowance"];
    store.update_allowance(operator, tenant, serde_json::from_value(json!({"allowance":{
        "cpu_percent":a["cpu_percent"],"memory_mib":a["memory_mib"],"instances":a["instances"],
        "storage_bytes":a["storage_bytes"],"transfer_bytes":bytes
    }})).unwrap()).await.unwrap()
}

pub(super) async fn start(
    l: &IdentityLab,
    node: &str,
    build: &std::path::Path,
    output: PathBuf,
) -> tokio::task::JoinHandle<()> {
    let launcher = digest(fs::read(build.join("launch")).unwrap());
    l.lab
        .store
        .node_mode(
            &l.lab.operator,
            node,
            json!({
                "egress_budget_launcher":launcher,"egress_budget_required":true
            }),
        )
        .await
        .unwrap();
    let initial = allowance(&l.lab.store, &l.lab.operator, &l.lab.tenant, 1024).await;
    atomic_json(&output.join("outbound-setup.json"), &json!({"allowance":initial,"approved_launcher":launcher,"candidate_scope":"isolated acceptance worker only"})).unwrap();
    let store = l.lab.store.clone();
    let operator = l.lab.operator.clone();
    let tenant = l.lab.tenant.clone();
    tokio::spawn(async move {
        let mut sequence = 0;
        while !output.join("finish-outbound-control").exists() {
            if let Ok(bytes) = fs::read(output.join("outbound-request.json")) {
                let request: Value = serde_json::from_slice(&bytes).unwrap();
                let next = request["sequence"].as_u64().unwrap();
                if next > sequence {
                    let changed = match s(&request["action"]) {
                        "snapshot" => Value::Null,
                        "raise" => allowance(&store, &operator, &tenant, 65536).await,
                        "exhaust" => {
                            let usage = store.usage(&operator, &tenant, None).await.unwrap();
                            assert_eq!(usage["totals"]["transfer_reserved_bytes"], 0);
                            let used = n(&usage["totals"]["transfer_accounted_bytes"]);
                            assert!(used >= 1024);
                            allowance(&store, &operator, &tenant, used).await
                        }
                        _ => panic!("unsupported allowance acceptance action"),
                    };
                    let grants: Value = sqlx::query_scalar("SELECT COALESCE(jsonb_agg(to_jsonb(g) ORDER BY execution_id),'[]'::jsonb) FROM execution_egress_budgets g WHERE tenant_id=$1")
                        .bind(&tenant).fetch_one(&store.pool).await.unwrap();
                    let executions: Value = sqlx::query_scalar("SELECT COALESCE(jsonb_agg(jsonb_build_object('id',id,'state',state,'reserved',reserved,'budget_required',egress_budget_launcher IS NOT NULL,'observation',observation) ORDER BY created),'[]'::jsonb) FROM executions WHERE tenant_id=$1")
                        .bind(&tenant).fetch_one(&store.pool).await.unwrap();
                    atomic_json(&output.join("outbound-observed.json"), &json!({
                        "sequence":next,"action":request["action"],"changed_allowance":changed,
                        "grants":grants,"executions":executions,"observed_at":chrono::Utc::now().to_rfc3339()
                    })).unwrap();
                    sequence = next;
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
}
