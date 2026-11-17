//! Age only an already observed retention timestamp for a real completed capture.
//! The production agent owns cleanup, log delivery, cursors and execution reports.
use super::*;
use crate::durable::atomic_json;
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use std::{
    fs,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

fn journal(output: &Path, writable: bool) -> Connection {
    let db = Connection::open_with_flags(
        output.join("node-state/agent/agent.sqlite3"),
        (if writable {
            OpenFlags::SQLITE_OPEN_READ_WRITE
        } else {
            OpenFlags::SQLITE_OPEN_READ_ONLY
        }) | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .unwrap();
    db.busy_timeout(Duration::from_secs(2)).unwrap();
    db
}

fn snapshot(output: &Path, execution: &str) -> Option<Value> {
    let db = journal(output, false);
    let mut value: Value = db.query_row("SELECT a.backend_id,a.archived,d.capture_id,d.acknowledged,d.complete,d.source_last,d.sealed_at,d.expired_at,d.pruned_at,d.last_error,d.prune_error,d.last_success FROM assignments a JOIN log_deliveries d ON d.execution_id=a.id WHERE a.id=? AND a.backend_id IS NOT NULL",
        [execution], |r| Ok(json!({"backend_id":r.get::<_,String>(0)?,"archived":r.get::<_,bool>(1)?,"capture_id":r.get::<_,Option<String>>(2)?,"acknowledged":r.get::<_,i64>(3)?,"complete":r.get::<_,bool>(4)?,"source_last":r.get::<_,i64>(5)?,"sealed_at":r.get::<_,Option<i64>>(6)?,"expired_at":r.get::<_,Option<i64>>(7)?,"pruned_at":r.get::<_,Option<i64>>(8)?,"delivery_error":r.get::<_,Option<String>>(9)?,"prune_error":r.get::<_,Option<String>>(10)?,"last_success":r.get::<_,Option<i64>>(11)?})))
        .optional().unwrap()?;
    let dir = output
        .join("node-state/node/runs")
        .join(s(&value["backend_id"]));
    let status: Value =
        serde_json::from_slice(&fs::read(dir.join("status.json")).unwrap()).unwrap();
    value["worker_status"] = json!({"id":status["id"],"state":status["state"],"exit_code":status["exit_code"],"reason":status["reason"]});
    let capture = Connection::open_with_flags(
        dir.join("output.sqlite3"),
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .unwrap();
    capture.busy_timeout(Duration::from_secs(2)).unwrap();
    value["capture"]=capture.query_row("SELECT id,next_sequence-1,total_bytes,closed,interrupted FROM capture WHERE singleton=1",[],|r|Ok(json!({"id":r.get::<_,String>(0)?,"last_sequence":r.get::<_,i64>(1)?,"total_bytes":r.get::<_,i64>(2)?,"closed":r.get::<_,bool>(3)?,"interrupted":r.get::<_,bool>(4)?}))).unwrap();
    let (records, bytes): (i64, i64) = capture
        .query_row(
            "SELECT count(*),COALESCE(sum(length(data)),0) FROM records",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    let tail = fs::read(dir.join("output.log")).unwrap();
    value["retained"] = json!({"records":records,"bytes":bytes,"tail_bytes":tail.len(),"tail_sha256":digest(&tail)});
    Some(value)
}

async fn wait(output: &Path, execution: &str, done: impl Fn(&Value) -> bool) -> Value {
    let deadline = Instant::now() + Duration::from_secs(80);
    loop {
        let value = snapshot(output, execution);
        if let Some(value) = value.as_ref()
            && done(value)
        {
            return value.clone();
        }
        assert!(
            Instant::now() < deadline,
            "native retention step timed out: {value:?}"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

pub(super) fn control(l: &IdentityLab, output: PathBuf) -> tokio::task::JoinHandle<()> {
    let pool = l.lab.store.pool.clone();
    let tenant = l.lab.tenant.clone();
    let project = l.lab.project.clone();
    tokio::spawn(async move {
        let mut sequence = 0;
        while !output.join("finish-local-retention").exists() {
            if let Ok(bytes) = fs::read(output.join("local-retention-request.json")) {
                let request: Value = serde_json::from_slice(&bytes).unwrap();
                let next = request["sequence"].as_u64().unwrap();
                if next > sequence {
                    let execution = s(&request["execution_id"]);
                    let owned:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM executions e JOIN app_execution_contexts c ON c.execution_id=e.id WHERE e.id=$1 AND e.tenant_id=$2 AND e.project_id=$3 AND e.state='exited' AND NOT e.reserved AND e.observation->>'exit_code'='0')")
                        .bind(execution).bind(&tenant).bind(&project).fetch_one(&pool).await.unwrap();
                    assert!(owned);
                    let value = match s(&request["action"]) {
                        "observe" => {
                            wait(&output, execution, |v| {
                                v["capture"]["closed"] == true
                                    && v["delivery_error"] == "delivery-rejected"
                            })
                            .await
                        }
                        "age" => {
                            assert!(output.join("hold-log-delivery").exists());
                            let before =
                                wait(&output, execution, |v| v["sealed_at"].as_i64().is_some())
                                    .await;
                            assert_eq!(before["acknowledged"], 0);
                            assert_eq!(before["complete"], false);
                            assert!(n(&before["retained"]["bytes"]) > 0);
                            assert!(before["expired_at"].is_null());
                            let db = journal(&output, true);
                            assert_eq!(db.execute("UPDATE log_deliveries SET sealed_at=unixepoch()-31*86400,prune_attempt=unixepoch()-31*86400 WHERE execution_id=? AND sealed_at=? AND NOT complete AND acknowledged=0 AND expired_at IS NULL",params![execution,n(&before["sealed_at"])]).unwrap(),1);
                            json!({"controlled_age_days":31,"before":before,"after_aging":snapshot(&output,execution).unwrap()})
                        }
                        "age-delivered" => {
                            assert!(!output.join("hold-log-delivery").exists());
                            let before = wait(&output, execution, |v| {
                                v["complete"] == true && v["archived"] == true
                            })
                            .await;
                            assert_eq!(before["acknowledged"], before["source_last"]);
                            assert!(n(&before["retained"]["bytes"]) > 0);
                            assert!(before["pruned_at"].is_null());
                            let db = journal(&output, true);
                            assert_eq!(db.execute("UPDATE log_deliveries SET last_success=unixepoch()-8*86400,prune_attempt=unixepoch()-8*86400 WHERE execution_id=? AND last_success=? AND complete AND acknowledged=source_last AND pruned_at IS NULL",params![execution,n(&before["last_success"])]).unwrap(),1);
                            json!({"controlled_age_days":8,"before":before,"after_aging":snapshot(&output,execution).unwrap()})
                        }
                        "pruned" => {
                            let value =
                                wait(&output, execution, |v| v["pruned_at"].as_i64().is_some())
                                    .await;
                            assert!(value["expired_at"].is_null());
                            assert_eq!(value["complete"], true);
                            assert_eq!(value["retained"]["bytes"], 0);
                            assert_eq!(value["retained"]["tail_bytes"], 0);
                            value
                        }
                        "expired" => {
                            let value =
                                wait(&output, execution, |v| v["expired_at"].as_i64().is_some())
                                    .await;
                            assert_eq!(value["acknowledged"], 0);
                            assert_eq!(value["complete"], false);
                            assert_eq!(value["retained"]["bytes"], 0);
                            assert_eq!(value["retained"]["tail_bytes"], 0);
                            value
                        }
                        "recover" => {
                            let before = snapshot(&output, execution).unwrap();
                            assert!(before["expired_at"].as_i64().is_some());
                            fs::remove_file(output.join("hold-log-delivery")).unwrap();
                            before
                        }
                        "delivered" => wait(&output, execution, |v| v["complete"] == true).await,
                        _ => panic!("unsupported local retention action"),
                    };
                    atomic_json(&output.join("local-retention-observed.json"),&json!({"sequence":next,"action":request["action"],"execution_id":execution,"observation":value,"observed_at":chrono::Utc::now().to_rfc3339()})).unwrap();
                    sequence = next;
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
}
