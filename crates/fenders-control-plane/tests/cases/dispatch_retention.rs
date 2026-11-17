use super::*;

async fn seed(l: &Lab, count: i32) -> (String, Vec<String>) {
    let node = l.node("retention-worker").await;
    approve_component(l, &node, false, true).await;
    let app = l.scheduled_app("retained", true).await.unwrap();
    sqlx::query("UPDATE app_schedules SET next_at=NULL WHERE app_id=$1")
        .bind(&app)
        .execute(&l.store.pool)
        .await
        .unwrap();
    let ids: Vec<String> = sqlx::query_scalar("INSERT INTO app_runs(id,tenant_id,project_id,app_id,release_id,source,admission,admission_reason,created,admission_updated,scheduled_at,trigger_revision) SELECT md5(a.id||n::text),a.tenant_id,a.project_id,a.id,a.target_release_id,'schedule','skipped','missed-deadline',now()-interval '40 days',now()-interval '40 days',date_trunc('minute',now())-interval '40 days'+n*interval '1 minute',1 FROM apps a CROSS JOIN generate_series(1,$2) n WHERE a.id=$1 RETURNING id").bind(&app).bind(count).fetch_all(&l.store.pool).await.unwrap();
    sqlx::query("INSERT INTO app_run_dispatch(run_id,tenant_id,project_id,app_id,state,deadline,created,updated,last_error) SELECT id,tenant_id,project_id,app_id,'cancelled',scheduled_at+interval '1 minute',created,created,'missed-deadline' FROM app_runs WHERE app_id=$1").bind(&app).execute(&l.store.pool).await.unwrap();
    (app, ids)
}
async fn counts(l: &Lab) -> (i64, i64) {
    sqlx::query_as("SELECT (SELECT count(*) FROM app_run_dispatch),(SELECT count(*) FROM app_runs WHERE dispatch_retired_at IS NOT NULL)").fetch_one(&l.store.pool).await.unwrap()
}

#[tokio::test]
async fn dispatch_retention_is_bounded_preserves_history_and_prevents_occurrence_replay() {
    let l = Lab::new().await;
    let (app, _) = seed(&l, 320).await;
    let before = l.runs(&app).await;
    let usage = l.store.usage(&l.operator, &l.tenant, None).await.unwrap();
    l.store.schedule().await.unwrap();
    assert_eq!(counts(&l).await, (64, 256));
    let reopened = Store::from_pool(l.store.pool.clone(), l.root.path()).unwrap();
    let (a, b) = tokio::join!(l.store.schedule(), reopened.schedule());
    a.unwrap();
    b.unwrap();
    assert_eq!(counts(&l).await, (0, 320));
    assert_eq!(l.runs(&app).await, before);
    assert_eq!(
        l.store.usage(&l.operator, &l.tenant, None).await.unwrap()["reserved"],
        usage["reserved"]
    );
    // A rewound cursor materializes the same old occurrences, never new work.
    sqlx::query("UPDATE app_schedules SET next_at=(SELECT min(scheduled_at) FROM app_runs WHERE app_id=$1) WHERE app_id=$1").bind(&app).execute(&l.store.pool).await.unwrap();
    l.store.claim_schedule_occurrences().await.unwrap();
    let duplicate_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM app_runs WHERE dispatch_retired_at IS NOT NULL")
            .fetch_one(&l.store.pool)
            .await
            .unwrap();
    assert_eq!(duplicate_count, 320);
    let replay_count: i64 = sqlx::query_scalar("SELECT count(*) FROM app_run_dispatch d JOIN app_runs r ON r.id=d.run_id WHERE r.dispatch_retired_at IS NOT NULL").fetch_one(&l.store.pool).await.unwrap();
    assert_eq!(replay_count, 0);
    l.finish().await;
}

#[tokio::test]
async fn dispatch_retention_preserves_recent_active_unknown_and_reason_bearing_detail() {
    let l = Lab::new().await;
    let (_, ids) = seed(&l, 10).await;
    // Distinct retention holds; the last two executions have known outcomes.
    sqlx::query("UPDATE app_run_dispatch SET updated=now() WHERE run_id=$1")
        .bind(&ids[0])
        .execute(&l.store.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE app_runs SET admission='pending',admission_reason=NULL WHERE id=$1")
        .bind(&ids[1])
        .execute(&l.store.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE app_run_dispatch SET state='pending' WHERE run_id=$1")
        .bind(&ids[1])
        .execute(&l.store.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE app_runs SET admission_reason=NULL WHERE id=$1")
        .bind(&ids[2])
        .execute(&l.store.pool)
        .await
        .unwrap();
    for (index, state, reserved, exit) in [
        (3, "exited", true, json!(0)),
        (4, "exited", false, Value::Null),
        (5, "failed", false, json!(-1)),
        (6, "exited", false, json!(256)),
        (7, "running", false, json!(0)),
        (8, "exited", false, json!(0)),
        (9, "failed", false, json!(1)),
    ] {
        let e = uid();
        sqlx::query("INSERT INTO executions(id,tenant_id,project_id,spec,cpu_percent,memory_mib,reserved,state,desired,observation,created,updated,finished_at) VALUES($1,$2,$3,'{}',1,1,$4,$5,'stopped',jsonb_build_object('exit_code',$6::jsonb),now()-interval '40 days',now()-interval '40 days',now()-interval '40 days')").bind(&e).bind(&l.tenant).bind(&l.project).bind(reserved).bind(state).bind(exit).execute(&l.store.pool).await.unwrap();
        sqlx::query("UPDATE app_runs SET execution_id=$2,admission='admitted',admission_reason=NULL WHERE id=$1").bind(&ids[index]).bind(&e).execute(&l.store.pool).await.unwrap();
        sqlx::query(
            "UPDATE app_run_dispatch SET state='dispatched',last_error=NULL WHERE run_id=$1",
        )
        .bind(&ids[index])
        .execute(&l.store.pool)
        .await
        .unwrap();
    }
    // Exercise retention in isolation, without dispatching/expiring pending work.
    let candidates: Vec<String> =
        sqlx::query_scalar("SELECT run_id FROM app_dispatch_retirable ORDER BY run_id")
            .fetch_all(&l.store.pool)
            .await
            .unwrap();
    let mut expected = vec![ids[8].clone(), ids[9].clone()];
    expected.sort();
    assert_eq!(candidates, expected);
    for id in &ids[..8] {
        assert!(
            sqlx::query("UPDATE app_runs SET dispatch_retired_at=now() WHERE id=$1")
                .bind(id)
                .execute(&l.store.pool)
                .await
                .is_err()
        );
    }
    for id in &expected {
        let before: Value =
            sqlx::query_scalar("SELECT to_jsonb(r) FROM app_run_observations r WHERE id=$1")
                .bind(id)
                .fetch_one(&l.store.pool)
                .await
                .unwrap();
        let mut tx = l.store.pool.begin().await.unwrap();
        sqlx::query("UPDATE app_runs SET dispatch_retired_at=now() WHERE id=$1")
            .bind(id)
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query("DELETE FROM app_run_dispatch WHERE run_id=$1")
            .bind(id)
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        let after: Value =
            sqlx::query_scalar("SELECT to_jsonb(r) FROM app_run_observations r WHERE id=$1")
                .bind(id)
                .fetch_one(&l.store.pool)
                .await
                .unwrap();
        assert_eq!(after, before);
    }
    assert_eq!(counts(&l).await, (8, 2));
    l.finish().await;
}

#[tokio::test]
async fn dispatch_retention_guards_are_atomic_and_recovery_barred() {
    let l = Lab::new().await;
    let (_, ids) = seed(&l, 1).await;
    let id = &ids[0];
    assert!(
        sqlx::query("DELETE FROM app_run_dispatch WHERE run_id=$1")
            .bind(id)
            .execute(&l.store.pool)
            .await
            .is_err()
    );
    assert!(
        sqlx::query("UPDATE app_runs SET dispatch_retired_at=now() WHERE id=$1")
            .bind(id)
            .execute(&l.store.pool)
            .await
            .is_err(),
        "marker alone cannot commit"
    );
    sqlx::raw_sql("CREATE FUNCTION reject_retention() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected delete failure'; END $$; CREATE TRIGGER reject_retention BEFORE DELETE ON app_run_dispatch FOR EACH ROW EXECUTE FUNCTION reject_retention();").execute(&l.store.pool).await.unwrap();
    assert!(l.store.schedule().await.is_err());
    assert_eq!(counts(&l).await, (1, 0));
    sqlx::query("DROP TRIGGER reject_retention ON app_run_dispatch")
        .execute(&l.store.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE recovery_barrier SET active=true")
        .execute(&l.store.pool)
        .await
        .unwrap();
    assert!(l.store.schedule().await.is_err());
    assert_eq!(counts(&l).await, (1, 0));
    sqlx::query("UPDATE recovery_barrier SET active=false")
        .execute(&l.store.pool)
        .await
        .unwrap();
    l.store.schedule().await.unwrap();
    assert_eq!(counts(&l).await, (0, 1));
    for sql in [
        "UPDATE app_runs SET dispatch_retired_at=NULL WHERE id=$1",
        "UPDATE app_runs SET admission='pending' WHERE id=$1",
        "DELETE FROM app_runs WHERE id=$1",
        "INSERT INTO app_run_dispatch(run_id,tenant_id,project_id,app_id,deadline) SELECT id,tenant_id,project_id,app_id,now() FROM app_runs WHERE id=$1",
        "INSERT INTO app_runs(id,tenant_id,project_id,app_id,release_id,source,admission,scheduled_at,trigger_revision) SELECT md5(id),tenant_id,project_id,app_id,release_id,source,'pending',scheduled_at,trigger_revision FROM app_runs WHERE id=$1",
    ] {
        assert!(
            sqlx::query(sql)
                .bind(id)
                .execute(&l.store.pool)
                .await
                .is_err(),
            "{sql}"
        );
    }
    l.finish().await;
}

#[tokio::test]
async fn dispatch_retention_bootstrap_does_not_invent_retirement() {
    let l = Lab::new().await;
    let (app, _) = seed(&l, 1).await;
    let before = l.runs(&app).await;
    l.store.migrate().await.unwrap();
    assert_eq!(counts(&l).await, (1, 0));
    assert_eq!(l.runs(&app).await, before);
    l.store.schedule().await.unwrap();
    assert_eq!(counts(&l).await, (0, 1));
    assert_eq!(l.runs(&app).await, before);
    l.finish().await;
}
