//! Controlled calendar aging of real, completed output. Production scheduler
//! performs deletion; this fixture never alters payloads, outcomes or cursors.
use super::*;
use crate::durable::atomic_json;
use std::{fs, path::PathBuf, time::Duration};

async fn snapshot(pool: &sqlx::PgPool, execution: &str) -> Value {
    sqlx::query_scalar("SELECT jsonb_build_object('records',count(*),'bytes',COALESCE(sum(octet_length(payload)),0),'first_received',min(received),'last_received',max(received)) FROM execution_log_records WHERE execution_id=$1")
        .bind(execution).fetch_one(pool).await.unwrap()
}

pub(super) fn control(l: &IdentityLab, output: PathBuf) -> tokio::task::JoinHandle<()> {
    let pool = l.lab.store.pool.clone();
    let tenant = l.lab.tenant.clone();
    let project = l.lab.project.clone();
    tokio::spawn(async move {
        let mut done = false;
        while !output.join("finish-log-expiry").exists() {
            if !done && let Ok(bytes) = fs::read(output.join("age-log-request.json")) {
                let request: Value = serde_json::from_slice(&bytes).unwrap();
                let execution = s(&request["execution_id"]);
                let source: Value = sqlx::query_scalar("SELECT to_jsonb(s) FROM execution_log_sources s JOIN executions e ON e.id=s.execution_id JOIN app_execution_contexts c ON c.execution_id=e.id WHERE e.id=$1 AND e.tenant_id=$2 AND e.project_id=$3 AND NOT e.reserved AND e.state='exited' AND s.end_sequence=s.acknowledged AND NOT s.interrupted")
                    .bind(execution).bind(&tenant).bind(&project).fetch_one(&pool).await.unwrap();
                let before = snapshot(&pool, execution).await;
                assert!(n(&before["records"]) > 0);
                assert!(n(&before["bytes"]) > 0);
                let changed = sqlx::query("UPDATE execution_log_records SET received=now()-interval '8 days' WHERE execution_id=$1 AND tenant_id=$2")
                    .bind(execution).bind(&tenant).execute(&pool).await.unwrap().rows_affected();
                assert_eq!(changed, n(&before["records"]) as u64);
                let deadline = std::time::Instant::now() + Duration::from_secs(30);
                let after = loop {
                    let after = snapshot(&pool, execution).await;
                    if after["records"] == 0 {
                        break after;
                    }
                    assert!(
                        std::time::Instant::now() < deadline,
                        "production scheduler did not expire aged output"
                    );
                    tokio::time::sleep(Duration::from_millis(100)).await;
                };
                let retained: Value = sqlx::query_scalar(
                    "SELECT to_jsonb(s) FROM execution_log_sources s WHERE execution_id=$1",
                )
                .bind(execution)
                .fetch_one(&pool)
                .await
                .unwrap();
                assert_eq!(retained["pruned_through"], source["end_sequence"]);
                assert_eq!(retained["acknowledged"], source["acknowledged"]);
                atomic_json(
                    &output.join("age-log-observed.json"),
                    &json!({
                        "execution_id":execution,"controlled_age_days":8,
                        "before":before,"deleted_records":changed,"after":after,
                        "source_before":source,"source_after":retained,
                        "observed_at":chrono::Utc::now().to_rfc3339()
                    }),
                )
                .unwrap();
                done = true;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
}
