use super::*;

async fn seed(l: &Lab, count: i32) -> Vec<String> {
    let ids: Vec<String> = sqlx::query_scalar("INSERT INTO executions(id,tenant_id,project_id,spec,cpu_percent,memory_mib,reserved,state,desired,observation,created,updated,finished_at) SELECT md5($1||n::text),$1,$2,'{}',1,1,false,'exited','stopped','{\"exit_code\":0}',now()-interval '40 days',now()-interval '40 days',now()-interval '40 days' FROM generate_series(1,$3) n RETURNING id")
        .bind(&l.tenant).bind(&l.project).bind(count).fetch_all(&l.store.pool).await.unwrap();
    sqlx::query("INSERT INTO execution_placement(execution_id,generation,reason,observed_at) SELECT id,generation,'placement-capacity',now()-interval '40 days' FROM executions")
        .execute(&l.store.pool).await.unwrap();
    ids
}
async fn count(l: &Lab) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM execution_placement")
        .fetch_one(&l.store.pool)
        .await
        .unwrap()
}
async fn executions(l: &Lab) -> Value {
    sqlx::query_scalar("SELECT jsonb_agg(to_jsonb(e) ORDER BY id) FROM executions e")
        .fetch_one(&l.store.pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn placement_retention_is_bounded_and_preserves_resource_retry_and_usage_records() {
    let l = Lab::new().await;
    let ids = seed(&l, 800).await;
    let id = &ids[0];
    sqlx::query("INSERT INTO operations(id,tenant_id,project_id,request_key,request_hash,resource_id,kind,state) VALUES($1,$2,$3,'retained-retry','retained-hash',$1,'create-execution','succeeded')")
        .bind(id).bind(&l.tenant).bind(&l.project).execute(&l.store.pool).await.unwrap();
    sqlx::query("INSERT INTO usage_samples(execution_id,generation,sequence,tenant_id,cpu_usec,memory_bytes) VALUES($1,1,1,$2,42,1024)")
        .bind(id).bind(&l.tenant).execute(&l.store.pool).await.unwrap();
    let before = executions(&l).await;
    let operation: Value = sqlx::query_scalar("SELECT to_jsonb(o) FROM operations o WHERE id=$1")
        .bind(id)
        .fetch_one(&l.store.pool)
        .await
        .unwrap();
    let usage: Value =
        sqlx::query_scalar("SELECT to_jsonb(u) FROM usage_samples u WHERE execution_id=$1")
            .bind(id)
            .fetch_one(&l.store.pool)
            .await
            .unwrap();
    l.store.schedule().await.unwrap();
    assert_eq!(count(&l).await, 544);
    let reopened = Store::from_pool(l.store.pool.clone(), l.root.path()).unwrap();
    let (a, b) = tokio::join!(l.store.schedule(), reopened.schedule());
    a.unwrap();
    b.unwrap();
    assert_eq!(count(&l).await, 32);
    reopened.schedule().await.unwrap();
    reopened.schedule().await.unwrap();
    assert_eq!(count(&l).await, 0);
    assert_eq!(executions(&l).await, before);
    let after: Value = sqlx::query_scalar("SELECT to_jsonb(o) FROM operations o WHERE id=$1")
        .bind(id)
        .fetch_one(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(after, operation);
    let after: Value =
        sqlx::query_scalar("SELECT to_jsonb(u) FROM usage_samples u WHERE execution_id=$1")
            .bind(id)
            .fetch_one(&l.store.pool)
            .await
            .unwrap();
    assert_eq!(after, usage);
    l.finish().await;
}

#[tokio::test]
async fn placement_retention_keeps_recent_active_unknown_and_unverifiable_diagnostics() {
    let l = Lab::new().await;
    let ids = seed(&l, 15).await;
    for (i, change) in [
        (0, "reserved=true"),
        (1, "state='running'"),
        (2, "state='lost'"),
        (3, "state='unreachable'"),
        (4, "observation='{}'"),
        (5, "observation='{\"exit_code\":-1}'"),
        (6, "observation='{\"exit_code\":256}'"),
        (7, "observation='{\"exit_code\":\"999999999999999999999\"}'"),
        (8, "finished_at=NULL"),
        (9, "updated=now()"),
        (10, "finished_at=now()"),
    ] {
        sqlx::query(&format!("UPDATE executions SET {change} WHERE id=$1"))
            .bind(&ids[i])
            .execute(&l.store.pool)
            .await
            .unwrap();
    }
    sqlx::query("UPDATE execution_placement SET observed_at=now() WHERE execution_id=$1")
        .bind(&ids[11])
        .execute(&l.store.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE execution_placement SET generation=2 WHERE execution_id=$1")
        .bind(&ids[12])
        .execute(&l.store.pool)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE executions SET state='stopped',observation='{}',finished_at=NULL WHERE id=$1",
    )
    .bind(&ids[13])
    .execute(&l.store.pool)
    .await
    .unwrap();
    sqlx::query("UPDATE executions SET state='failed',observation='{\"exit_code\":1}' WHERE id=$1")
        .bind(&ids[14])
        .execute(&l.store.pool)
        .await
        .unwrap();
    let before = executions(&l).await;
    l.store.schedule().await.unwrap();
    let mut expected = ids[..13].to_vec();
    expected.sort();
    let retained: Vec<String> =
        sqlx::query_scalar("SELECT execution_id FROM execution_placement ORDER BY execution_id")
            .fetch_all(&l.store.pool)
            .await
            .unwrap();
    assert_eq!(retained, expected);
    assert_eq!(executions(&l).await, before);
    l.finish().await;
}

#[tokio::test]
async fn placement_retention_is_atomic_and_recovery_barred() {
    let l = Lab::new().await;
    seed(&l, 3).await;
    let before = executions(&l).await;
    l.store.migrate().await.unwrap();
    assert_eq!(count(&l).await, 3, "bootstrap never infers retirement");
    assert_eq!(executions(&l).await, before);
    sqlx::query("UPDATE recovery_barrier SET active=true")
        .execute(&l.store.pool)
        .await
        .unwrap();
    assert!(l.store.schedule().await.is_err());
    assert_eq!(count(&l).await, 3);
    sqlx::query("UPDATE recovery_barrier SET active=false")
        .execute(&l.store.pool)
        .await
        .unwrap();
    sqlx::raw_sql("CREATE FUNCTION reject_placement_cleanup() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture cleanup failure'; END $$; CREATE TRIGGER reject_placement_cleanup AFTER DELETE ON execution_placement FOR EACH STATEMENT EXECUTE FUNCTION reject_placement_cleanup();")
        .execute(&l.store.pool).await.unwrap();
    assert!(l.store.schedule().await.is_err());
    assert_eq!(count(&l).await, 3);
    assert_eq!(executions(&l).await, before);
    sqlx::raw_sql("DROP TRIGGER reject_placement_cleanup ON execution_placement; DROP FUNCTION reject_placement_cleanup();")
        .execute(&l.store.pool).await.unwrap();
    l.store.schedule().await.unwrap();
    assert_eq!(count(&l).await, 0);
    assert_eq!(executions(&l).await, before);
    l.finish().await;
}
