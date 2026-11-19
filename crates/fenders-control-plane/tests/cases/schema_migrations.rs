use super::*;

async fn revision(pool: &sqlx::PgPool) -> String {
    sqlx::query_scalar(
        "SELECT xmin::text FROM pg_proc WHERE oid='advance_allowance_revision()'::regprocedure",
    )
    .fetch_one(pool)
    .await
    .unwrap()
}
async fn trigger_revision(l: &Lab) -> String {
    revision(&l.store.pool).await
}

#[tokio::test]
async fn concurrent_startup_records_existing_schema_once_without_replaying_ddl() {
    // Previous production releases have the complete baseline schema without
    // a ledger: every migration is then applied, once.
    let options: PgConnectOptions = std::env::var("FENDERS_TEST_DATABASE_URL")
        .expect("set FENDERS_TEST_DATABASE_URL to a dedicated PostgreSQL database")
        .parse()
        .unwrap();
    let admin = PgPoolOptions::new()
        .connect_with(options.clone())
        .await
        .unwrap();
    let schema = format!("rust_test_{}", uid());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&admin)
        .await
        .unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(16)
        .connect_with(options.options([("search_path", schema.as_str())]))
        .await
        .unwrap();
    sqlx::raw_sql(fenders_control_plane::store::SCHEMA)
        .execute(&pool)
        .await
        .unwrap();
    let root = tempfile::tempdir().unwrap();
    let store = Store::from_pool(pool.clone(), root.path()).unwrap();
    let (a, b) = tokio::join!(store.migrate(), store.migrate());
    a.unwrap();
    b.unwrap();
    // The function is the baseline's own: reading it shows its DDL ran.
    let applied = revision(&pool).await;
    let receipt: Value = sqlx::query_scalar(
        "SELECT jsonb_agg(to_jsonb(m) ORDER BY version) FROM control_schema_migrations m",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(receipt.as_array().unwrap().len(), 13);
    for (index, entry) in receipt.as_array().unwrap().iter().enumerate() {
        assert_eq!(entry["version"], index + 1);
        assert_eq!(s(&entry["checksum"]).len(), 64);
    }
    // The last of them took network leases out of the baseline.
    let leased: i64 = sqlx::query_scalar("SELECT count(*) FROM information_schema.columns WHERE table_schema=current_schema() AND column_name IN ('network_leases','network_ceiling','network_revision','public_https_runtime','retained_https_runtimes')")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(leased, 0);
    let (a, b) = tokio::join!(store.migrate(), store.migrate());
    a.unwrap();
    b.unwrap();
    assert_eq!(revision(&pool).await, applied, "startup replayed DDL");
    let retained: Value = sqlx::query_scalar(
        "SELECT jsonb_agg(to_jsonb(m) ORDER BY version) FROM control_schema_migrations m",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(retained, receipt);
    let token = std::fs::read_to_string(store.bootstrap().await.unwrap()).unwrap();
    store
        .authenticate(&token)
        .await
        .unwrap()
        .operator()
        .unwrap();
    pool.close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .unwrap();
}

#[tokio::test]
async fn unknown_or_modified_schema_history_refuses_startup_without_rewrite() {
    let l = Lab::new().await;
    let before = trigger_revision(&l).await;
    sqlx::query(
        "INSERT INTO control_schema_migrations(version,checksum) VALUES(40,repeat('a',64))",
    )
    .execute(&l.store.pool)
    .await
    .unwrap();
    let error = l.store.migrate().await.unwrap_err();
    assert_eq!(
        error.message,
        "unsupported control-plane schema migration history"
    );
    assert_eq!(trigger_revision(&l).await, before);
    sqlx::query("DELETE FROM control_schema_migrations WHERE version=40")
        .execute(&l.store.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE control_schema_migrations SET checksum=repeat('f',64)")
        .execute(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(l.store.migrate().await.unwrap_err().message, error.message);
    let retained: String =
        sqlx::query_scalar("SELECT checksum FROM control_schema_migrations WHERE version=1")
            .fetch_one(&l.store.pool)
            .await
            .unwrap();
    assert_eq!(retained, "f".repeat(64));
    assert_eq!(trigger_revision(&l).await, before);
    l.finish().await;
}

#[tokio::test]
async fn version_one_upgrade_adds_http_runs_without_rewriting_baseline() {
    let l = Lab::new().await;
    // Reconstruct the qualified version-1 database: its baseline is applied,
    // but HTTP request history has not been introduced yet.
    sqlx::raw_sql("DROP VIEW customer_app_runs; DROP TABLE app_http_runs; DELETE FROM control_schema_migrations WHERE version>=2")
        .execute(&l.store.pool).await.unwrap();
    let baseline: Value =
        sqlx::query_scalar("SELECT to_jsonb(m) FROM control_schema_migrations m WHERE version=1")
            .fetch_one(&l.store.pool)
            .await
            .unwrap();
    let before = trigger_revision(&l).await;
    let (a, b) = tokio::join!(l.store.migrate(), l.store.migrate());
    a.unwrap();
    b.unwrap();
    assert_eq!(
        trigger_revision(&l).await,
        before,
        "upgrade replayed baseline DDL"
    );
    let retained: Value =
        sqlx::query_scalar("SELECT to_jsonb(m) FROM control_schema_migrations m WHERE version=1")
            .fetch_one(&l.store.pool)
            .await
            .unwrap();
    assert_eq!(retained, baseline, "upgrade rewrote the original receipt");
    let versions: Vec<i64> =
        sqlx::query_scalar("SELECT version FROM control_schema_migrations ORDER BY version")
            .fetch_all(&l.store.pool)
            .await
            .unwrap();
    assert_eq!(versions, vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM customer_app_runs")
        .fetch_one(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(count, 0, "migration created an invocation");
    // Neither a changed additive migration nor a missing prefix can be repaired
    // by startup. Preserve the stored history on refusal.
    let checksum: String =
        sqlx::query_scalar("SELECT checksum FROM control_schema_migrations WHERE version=2")
            .fetch_one(&l.store.pool)
            .await
            .unwrap();
    sqlx::query("UPDATE control_schema_migrations SET checksum=repeat('a',64) WHERE version=2")
        .execute(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(
        l.store.migrate().await.unwrap_err().message,
        "unsupported control-plane schema migration history"
    );
    sqlx::query("UPDATE control_schema_migrations SET checksum=$1 WHERE version=2")
        .bind(checksum)
        .execute(&l.store.pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM control_schema_migrations WHERE version=1")
        .execute(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(
        l.store.migrate().await.unwrap_err().message,
        "unsupported control-plane schema migration history"
    );
    assert_eq!(trigger_revision(&l).await, before);
    l.finish().await;
}
