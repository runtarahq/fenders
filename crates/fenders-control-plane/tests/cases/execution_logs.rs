//! Real PostgreSQL receipt/retention tests; node output here is a protocol fixture.
use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use fenders_control_plane::execution_logs::*;

pub(super) fn batch(capture: &str, first: i64, last: i64, closed: bool, records: Value) -> Value {
    json!({"boot_id":"test-boot","format_version":1,"capture_id":capture,
        "first_sequence":first,"last_sequence":last,"closed":closed,
        "redaction":LOG_REDACTION,"redacted_env":[],"records":records})
}
pub(super) fn record(sequence: i64, data: &[u8]) -> Value {
    json!({"sequence":sequence,"at_ms":1791300000000_i64+sequence,"stream":"stdout","bytes":STANDARD.encode(data)})
}
async fn assigned(l: &Lab, key: &str) -> Value {
    let op = l.create(key, json!({"artifact_id":l.artifact})).await;
    l.store.schedule().await.unwrap();
    l.run(&op).await
}
async fn ingest(
    l: &Lab,
    node: &Value,
    e: &Value,
    body: Value,
) -> fenders_control_plane::error::Result<Value> {
    l.store
        .ingest_execution_logs(s(&node["id"]), s(&e["id"]), n(&e["generation"]), body)
        .await
}
async fn count(l: &Lab) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM execution_log_records")
        .fetch_one(&l.store.pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_fully_expired_sealed_source_records_a_gap_without_resurrecting_payload() {
    let l = Lab::new().await;
    let node = l.node("expiry-worker").await;
    let e = assigned(&l, "expired-output").await;
    let capture = uid();
    for invalid in [
        batch(&capture, 3, 2, false, json!([])),
        batch(&capture, 4, 2, true, json!([])),
        batch(
            &capture,
            3,
            2,
            true,
            json!([record(2, b"outside retained range")]),
        ),
    ] {
        assert_eq!(
            ingest(&l, &node, &e, invalid).await.unwrap_err().status,
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(count(&l).await, 0);
    let expired = batch(&capture, 3, 2, true, json!([]));
    let accepted = ingest(&l, &node, &e, expired.clone()).await.unwrap();
    assert_eq!(accepted["cursor"]["acknowledged"], 2);
    assert_eq!(accepted["cursor"]["source_gap"], true);
    assert_eq!(accepted["cursor"]["complete"], true);
    assert_eq!(ingest(&l, &node, &e, expired).await.unwrap(), accepted);
    // A delayed earlier page cannot resurrect records already recorded as lost.
    assert_eq!(
        ingest(
            &l,
            &node,
            &e,
            batch(
                &capture,
                1,
                2,
                true,
                json!([record(1, b"old"), record(2, b"old")])
            )
        )
        .await
        .unwrap(),
        accepted
    );
    let gap:Value=sqlx::query_scalar("SELECT jsonb_build_object('sequence',sequence,'from',gap_from,'stream',stream,'bytes',octet_length(payload)) FROM execution_log_records WHERE execution_id=$1").bind(s(&e["id"])).fetch_one(&l.store.pool).await.unwrap();
    assert_eq!(gap, json!({"sequence":2,"from":1,"stream":"gap","bytes":0}));
    assert_eq!(count(&l).await, 1);
    l.finish().await;
}

#[tokio::test]
async fn log_ingestion_is_atomic_idempotent_and_preserves_binary_and_closure() {
    let l = Lab::new().await;
    let node = l.node("worker").await;
    let e = assigned(&l, "logs").await;
    let capture = uid();
    let first = batch(&capture, 1, 2, true, json!([record(1, b"hello\0\xff")]));
    let (a, b) = tokio::join!(
        ingest(&l, &node, &e, first.clone()),
        ingest(&l, &node, &e, first.clone())
    );
    assert_eq!(a.unwrap(), b.unwrap());
    assert_eq!(count(&l).await, 1);
    let bytes: Vec<u8> = sqlx::query_scalar("SELECT payload FROM execution_log_records")
        .fetch_one(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(bytes, b"hello\0\xff");
    let reopened = Store::from_pool(l.store.pool.clone(), l.root.path()).unwrap();
    let retry = reopened
        .ingest_execution_logs(s(&node["id"]), s(&e["id"]), 1, first.clone())
        .await
        .unwrap();
    assert_eq!(retry["cursor"]["acknowledged"], 1);
    assert_eq!(retry["cursor"]["complete"], false);
    assert!(
        ingest(
            &l,
            &node,
            &e,
            batch(&capture, 1, 2, true, json!([record(1, b"changed")]))
        )
        .await
        .is_err()
    );
    assert!(
        ingest(
            &l,
            &node,
            &e,
            batch(&uid(), 1, 2, true, json!([record(1, b"hello")]))
        )
        .await
        .is_err()
    );
    let mut tail = record(2, b"error");
    tail["stream"] = json!("stderr");
    let receipt = ingest(&l, &node, &e, batch(&capture, 1, 2, true, json!([tail])))
        .await
        .unwrap();
    assert_eq!(receipt["cursor"]["acknowledged"], 2);
    assert_eq!(receipt["cursor"]["complete"], true);
    assert!(
        ingest(
            &l,
            &node,
            &e,
            batch(&capture, 1, 3, false, json!([record(3, b"after close")]))
        )
        .await
        .is_err()
    );
    assert_eq!(count(&l).await, 2);
    assert_eq!(
        ingest(&l, &node, &e, first).await.unwrap()["cursor"]["acknowledged"],
        2
    );
    assert_eq!(count(&l).await, 2);
    l.finish().await;
}

#[tokio::test]
async fn log_gaps_and_retention_never_resurrect_pruned_output() {
    let l = Lab::new().await;
    let node = l.node("worker").await;
    let e = assigned(&l, "logs").await;
    let capture = uid();
    let invalid = batch(
        &capture,
        4,
        6,
        false,
        json!([record(5, b"skipped available record")]),
    );
    assert!(ingest(&l, &node, &e, invalid).await.is_err());
    assert_eq!(count(&l).await, 0);
    let sources: i64 = sqlx::query_scalar("SELECT count(*) FROM execution_log_sources")
        .fetch_one(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(sources, 0);
    let page = batch(
        &capture,
        4,
        6,
        false,
        json!([record(4, b"four"), record(5, b"five")]),
    );
    let accepted = ingest(&l, &node, &e, page.clone()).await.unwrap();
    assert_eq!(accepted["cursor"]["acknowledged"], 5);
    assert_eq!(accepted["cursor"]["source_gap"], true);
    let gap: Value =
        sqlx::query_scalar("SELECT to_jsonb(r) FROM execution_log_records r WHERE stream='gap'")
            .fetch_one(&l.store.pool)
            .await
            .unwrap();
    assert_eq!(gap["gap_from"], 1);
    assert_eq!(gap["sequence"], 3);
    assert_eq!(count(&l).await, 3);
    ingest(&l, &node, &e, page.clone()).await.unwrap();
    assert_eq!(count(&l).await, 3);
    // Late duplicates from the lost range cannot silently fill it back in.
    ingest(
        &l,
        &node,
        &e,
        batch(&capture, 1, 6, false, json!([record(1, b"lost")])),
    )
    .await
    .unwrap();
    assert_eq!(count(&l).await, 3);
    sqlx::query("UPDATE execution_log_records SET received=now()-interval '8 days'")
        .execute(&l.store.pool)
        .await
        .unwrap();
    l.store.schedule().await.unwrap();
    assert_eq!(count(&l).await, 0);
    let retried = ingest(&l, &node, &e, page).await.unwrap();
    assert_eq!(retried["cursor"]["pruned_through"], 5);
    assert_eq!(count(&l).await, 0);
    // More than one MiB of real ingested payload evicts whole oldest records.
    let payload = vec![b'x'; 8192];
    for start in (6..142).step_by(8) {
        let records: Vec<_> = (start..start + 8)
            .map(|seq| record(seq, &payload))
            .collect();
        ingest(
            &l,
            &node,
            &e,
            batch(&capture, 1, 141, false, json!(records)),
        )
        .await
        .unwrap();
    }
    let (bytes, minimum): (i64, i64) = sqlx::query_as(
        "SELECT sum(octet_length(payload))::bigint,min(sequence) FROM execution_log_records",
    )
    .fetch_one(&l.store.pool)
    .await
    .unwrap();
    assert_eq!(bytes, EXECUTION_BYTES);
    assert_eq!(minimum, 14);
    let receipt = ingest(&l, &node, &e, batch(&capture, 1, 141, true, json!([])))
        .await
        .unwrap();
    assert_eq!(receipt["cursor"]["pruned_through"], 13);
    assert_eq!(receipt["cursor"]["complete"], true);
    l.finish().await;
}

#[tokio::test]
async fn log_worker_scope_secret_coverage_and_recovery_are_enforced() {
    let l = Lab::new().await;
    let node = l.node("worker").await;
    let wrong_node = l.node("other").await;
    let secret = l
        .store
        .create_secret(
            &l.operator,
            &l.tenant,
            &l.project,
            json!({"name":"password","value":"not-in-log"}),
        )
        .await
        .unwrap();
    let op = l
        .create(
            "secret",
            json!({"artifact_id":l.artifact,"secret_env":{"TOKEN":secret["id"]}}),
        )
        .await;
    l.store.schedule().await.unwrap();
    let e = l.run(&op).await;
    // Scheduler chooses either equally empty node; use the actual assignment.
    let (node, wrong_node) = if e["node_id"] == node["id"] {
        (node, wrong_node)
    } else {
        (wrong_node, node)
    };
    let mut body = batch(&uid(), 1, 1, true, json!([record(1, b"[REDACTED]")]));
    assert!(ingest(&l, &node, &e, body.clone()).await.is_err());
    body["redacted_env"] = json!(["TOKEN"]);
    assert!(ingest(&l, &wrong_node, &e, body.clone()).await.is_err());
    let mut stale = e.clone();
    stale["generation"] = json!(2);
    assert!(ingest(&l, &node, &stale, body.clone()).await.is_err());
    for (key, value) in [
        ("boot_id", json!("old-boot")),
        ("redaction", json!("none")),
        ("redacted_env", json!(["OTHER"])),
    ] {
        let mut bad = body.clone();
        bad[key] = value;
        assert!(ingest(&l, &node, &e, bad).await.is_err());
    }
    assert_eq!(count(&l).await, 0);
    sqlx::query("UPDATE nodes SET disabled=true WHERE id=$1")
        .bind(s(&node["id"]))
        .execute(&l.store.pool)
        .await
        .unwrap();
    assert!(ingest(&l, &node, &e, body.clone()).await.is_err());
    sqlx::query("UPDATE nodes SET disabled=false WHERE id=$1")
        .bind(s(&node["id"]))
        .execute(&l.store.pool)
        .await
        .unwrap();
    // Completed executions retain ownership so their final output can arrive.
    l.report(&node, &e, "exited", 1).await;
    ingest(&l, &node, &e, body.clone()).await.unwrap();
    sqlx::query("UPDATE recovery_barrier SET active=true")
        .execute(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(
        ingest(&l, &node, &e, body.clone())
            .await
            .unwrap_err()
            .status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    sqlx::query("UPDATE recovery_barrier SET active=false")
        .execute(&l.store.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE executions SET log_ingestion_fenced=true")
        .execute(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(
        ingest(&l, &node, &e, body).await.unwrap_err().status,
        StatusCode::CONFLICT
    );
    assert_eq!(count(&l).await, 1);
    l.finish().await;
}

#[tokio::test]
async fn log_database_failure_rolls_back_records_acknowledgment_and_retention() {
    let l = Lab::new().await;
    let node = l.node("worker").await;
    let e = assigned(&l, "logs").await;
    let capture = uid();
    ingest(
        &l,
        &node,
        &e,
        batch(&capture, 1, 1, false, json!([record(1, b"first")])),
    )
    .await
    .unwrap();
    sqlx::raw_sql("CREATE FUNCTION reject_log() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.sequence=3 THEN RAISE EXCEPTION 'injected log write failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_log BEFORE INSERT ON execution_log_records FOR EACH ROW EXECUTE FUNCTION reject_log();").execute(&l.store.pool).await.unwrap();
    let next = batch(
        &capture,
        1,
        3,
        true,
        json!([record(2, b"second"), record(3, b"third")]),
    );
    assert!(ingest(&l, &node, &e, next.clone()).await.is_err());
    assert_eq!(count(&l).await, 1);
    let state: Value = sqlx::query_scalar("SELECT to_jsonb(s) FROM execution_log_sources s")
        .fetch_one(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(state["acknowledged"], 1);
    assert_eq!(state["reported_last"], 1);
    assert!(state["end_sequence"].is_null());
    sqlx::query("DROP TRIGGER reject_log ON execution_log_records")
        .execute(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(
        ingest(&l, &node, &e, next.clone()).await.unwrap()["cursor"]["complete"],
        true
    );
    assert_eq!(count(&l).await, 3);
    ingest(&l, &node, &e, next).await.unwrap();
    assert_eq!(count(&l).await, 3);
    l.finish().await;
}

#[tokio::test]
async fn workspace_log_payload_and_record_budgets_preserve_other_tenants() {
    let l = Lab::new().await;
    let node = l.node("worker").await;
    let e = assigned(&l, "logs").await;
    let capture = uid();
    let other=l.store.create_tenant(&l.operator,serde_json::from_value(json!({"name":"other","allowance":{"cpu_percent":100,"memory_mib":128,"instances":1,"storage_bytes":1000000,"transfer_bytes":1000000}})).unwrap()).await.unwrap();
    let other_tenant = s(&other["id"]);
    let other_project: String =
        sqlx::query_scalar("SELECT id FROM projects WHERE tenant_id=$1 LIMIT 1")
            .bind(other_tenant)
            .fetch_one(&l.store.pool)
            .await
            .unwrap();
    // Bulk protocol-history fixtures exercise the actual production bounds
    // without allocating VMs or bypassing quotas through the public API.
    sqlx::query("INSERT INTO executions(id,tenant_id,project_id,spec,cpu_percent,memory_mib,reserved,state) SELECT 'history-'||i::text,$1,$2,'{}',1,1,false,'exited' FROM generate_series(1,66) i")
        .bind(&l.tenant).bind(&l.project).execute(&l.store.pool).await.unwrap();
    sqlx::query("INSERT INTO executions(id,tenant_id,project_id,spec,cpu_percent,memory_mib,reserved,state) VALUES('other-history',$1,$2,'{}',1,1,false,'exited')")
        .bind(other_tenant).bind(&other_project).execute(&l.store.pool).await.unwrap();
    sqlx::query("INSERT INTO execution_log_sources(execution_id,tenant_id,project_id,capture_id,acknowledged,reported_last,end_sequence) SELECT id,tenant_id,project_id,id,4096,4096,4096 FROM executions WHERE NOT reserved")
        .execute(&l.store.pool).await.unwrap();
    sqlx::query("INSERT INTO execution_log_records(tenant_id,project_id,execution_id,sequence,stream,at_ms,payload) SELECT tenant_id,project_id,execution_id,i,'stdout',1,'x'::bytea FROM execution_log_sources CROSS JOIN generate_series(1,4096) i WHERE execution_id IN (SELECT execution_id FROM execution_log_sources WHERE tenant_id=$1 ORDER BY execution_id LIMIT 17) ORDER BY execution_id,i")
        .bind(&l.tenant).execute(&l.store.pool).await.unwrap();
    sqlx::query("INSERT INTO execution_log_records(tenant_id,project_id,execution_id,sequence,stream,at_ms,payload) SELECT tenant_id,project_id,execution_id,1,'stderr',1,'foreign-data'::bytea FROM execution_log_sources WHERE tenant_id=$1")
        .bind(other_tenant).execute(&l.store.pool).await.unwrap();
    ingest(
        &l,
        &node,
        &e,
        batch(&capture, 1, 1, false, json!([record(1, b"current")])),
    )
    .await
    .unwrap();
    let rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM execution_log_records WHERE tenant_id=$1")
            .bind(&l.tenant)
            .fetch_one(&l.store.pool)
            .await
            .unwrap();
    assert_eq!(rows, WORKSPACE_RECORDS);
    let pruned: i64 = sqlx::query_scalar(
        "SELECT max(pruned_through) FROM execution_log_sources WHERE tenant_id=$1",
    )
    .bind(&l.tenant)
    .fetch_one(&l.store.pool)
    .await
    .unwrap();
    assert_eq!(pruned, 4096);
    // Replace only the synthetic history with 66 MiB, one MiB per execution.
    sqlx::query("DELETE FROM execution_log_records WHERE execution_id LIKE 'history-%'")
        .execute(&l.store.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO execution_log_records(tenant_id,project_id,execution_id,sequence,stream,at_ms,payload) SELECT tenant_id,project_id,execution_id,i,'stdout',1,decode(repeat('ab',8192),'hex') FROM execution_log_sources CROSS JOIN generate_series(1,128) i WHERE execution_id LIKE 'history-%' ORDER BY execution_id,i")
        .execute(&l.store.pool).await.unwrap();
    let receipt = ingest(
        &l,
        &node,
        &e,
        batch(&capture, 1, 2, false, json!([record(2, b"next")])),
    )
    .await
    .unwrap();
    let bytes: i64 = sqlx::query_scalar(
        "SELECT sum(octet_length(payload))::bigint FROM execution_log_records WHERE tenant_id=$1",
    )
    .bind(&l.tenant)
    .fetch_one(&l.store.pool)
    .await
    .unwrap();
    assert!(bytes <= WORKSPACE_BYTES && bytes > WORKSPACE_BYTES - 8192);
    assert_eq!(receipt["cursor"]["pruned_through"], 1);
    let other_bytes: Vec<u8> =
        sqlx::query_scalar("SELECT payload FROM execution_log_records WHERE tenant_id=$1")
            .bind(other_tenant)
            .fetch_one(&l.store.pool)
            .await
            .unwrap();
    assert_eq!(other_bytes, b"foreign-data");
    // Execution record count is independently bounded for tiny writes.
    sqlx::query("INSERT INTO execution_log_records(tenant_id,project_id,execution_id,sequence,stream,at_ms,payload) SELECT tenant_id,project_id,execution_id,i,'stdout',1,'x'::bytea FROM execution_log_sources CROSS JOIN generate_series(3,4098) i WHERE execution_id=$1")
        .bind(s(&e["id"])).execute(&l.store.pool).await.unwrap();
    sqlx::query("UPDATE execution_log_sources SET acknowledged=4098,reported_last=4098 WHERE execution_id=$1").bind(s(&e["id"])).execute(&l.store.pool).await.unwrap();
    let receipt = ingest(
        &l,
        &node,
        &e,
        batch(&capture, 1, 4099, true, json!([record(4099, b"last")])),
    )
    .await
    .unwrap();
    assert_eq!(receipt["cursor"]["pruned_through"], 3);
    let rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM execution_log_records WHERE execution_id=$1")
            .bind(s(&e["id"]))
            .fetch_one(&l.store.pool)
            .await
            .unwrap();
    assert_eq!(rows, EXECUTION_RECORDS);
    l.finish().await;
}
