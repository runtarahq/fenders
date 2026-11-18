use super::*;

const RETIRE: &str = include_str!("../../src/execution_input_retention.sql");
async fn seed(l: &Lab, count: i32) -> Vec<String> {
    let spec = json!({"artifact_id":l.artifact,"env":{"INPUT":"x".repeat(1800)},"endpoint_env":{"DATABASE_URL":{"endpoint_id":uid(),"field":"url"}},"secret_env":{"TOKEN":uid()},"cpu_percent":1,"host_memory_mib":64});
    sqlx::query_scalar("INSERT INTO executions(id,tenant_id,project_id,spec,cpu_percent,memory_mib,reserved,state,desired,observation,created,updated,finished_at) SELECT md5($1||n::text),$1,$2,$4,1,64,false,'exited','stopped','{\"exit_code\":0}',now()-interval '40 days',now()-interval '40 days',now()-interval '40 days' FROM generate_series(1,$3) n RETURNING id")
        .bind(&l.tenant).bind(&l.project).bind(count).bind(spec).fetch_all(&l.store.pool).await.unwrap()
}
async fn row(l: &Lab, id: &str) -> Value {
    sqlx::query_scalar("SELECT to_jsonb(e) FROM executions e WHERE id=$1")
        .bind(id)
        .fetch_one(&l.store.pool)
        .await
        .unwrap()
}
async fn count(l: &Lab) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM executions WHERE inputs_retired_at IS NOT NULL")
        .fetch_one(&l.store.pool)
        .await
        .unwrap()
}
async fn retire(l: &Lab) {
    sqlx::raw_sql(RETIRE).execute(&l.store.pool).await.unwrap();
}

#[tokio::test]
async fn execution_input_retention_is_bounded_and_preserves_identity_usage_and_authority() {
    let l = Lab::new().await;
    let ids = seed(&l, 600).await;
    let before = row(&l, &ids[0]).await;
    let original: String = sqlx::query_scalar("SELECT spec::text FROM executions WHERE id=$1")
        .bind(&ids[0])
        .fetch_one(&l.store.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO usage_samples(execution_id,generation,sequence,tenant_id,cpu_usec,memory_bytes) VALUES($1,1,1,$2,42,1024)")
        .bind(&ids[0]).bind(&l.tenant).execute(&l.store.pool).await.unwrap();
    let usage = l.store.usage(&l.operator, &l.tenant, None).await.unwrap();
    l.store.schedule().await.unwrap();
    assert_eq!(count(&l).await, 256);
    let reopened = Store::from_pool(l.store.pool.clone(), l.root.path()).unwrap();
    let (a, b) = tokio::join!(reopened.schedule(), l.store.schedule());
    a.unwrap();
    b.unwrap();
    assert_eq!(count(&l).await, 600);
    let after = row(&l, &ids[0]).await;
    assert_eq!(after["original_spec_sha256"], digest(original));
    assert!(after["inputs_retired_at"].is_string());
    let mut expected = before;
    expected["spec"].as_object_mut().unwrap().remove("env");
    expected["spec"]
        .as_object_mut()
        .unwrap()
        .remove("endpoint_env");
    expected["inputs_retired_at"] = after["inputs_retired_at"].clone();
    expected["original_spec_sha256"] = after["original_spec_sha256"].clone();
    assert_eq!(
        after, expected,
        "every other field, including secret requirements, survives"
    );
    assert_eq!(
        l.store.usage(&l.operator, &l.tenant, None).await.unwrap()["totals"],
        usage["totals"]
    );
    reopened.schedule().await.unwrap();
    assert_eq!(row(&l, &ids[0]).await, after);
    l.finish().await;
}

#[tokio::test]
async fn execution_input_retention_preserves_unsettled_unknown_recent_and_pending_work() {
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
        (7, "finished_at=NULL"),
        (8, "updated=now()"),
        (9, "finished_at=now()"),
        (10, "spec='{}'"),
        (11, "spec='{\"env\":{},\"endpoint_env\":{}}'"),
    ] {
        sqlx::query(&format!("UPDATE executions SET {change} WHERE id=$1"))
            .bind(&ids[i])
            .execute(&l.store.pool)
            .await
            .unwrap();
    }
    sqlx::query("INSERT INTO operations(id,tenant_id,project_id,request_key,request_hash,resource_id,kind) VALUES($1,$2,$3,'pending','hash',$4,'create-execution')")
        .bind(uid()).bind(&l.tenant).bind(&l.project).bind(&ids[12]).execute(&l.store.pool).await.unwrap();
    let node = l.node("held-transfer").await;
    sqlx::query("INSERT INTO execution_egress_budgets(execution_id,tenant_id,project_id,node_id,boot_id,launcher_digest,generation,state,ceiling_bytes,held_bytes) VALUES($1,$2,$3,$4,'test-boot',repeat('a',64),1,'freezing',5,5)")
        .bind(&ids[13]).bind(&l.tenant).bind(&l.project).bind(s(&node["id"])).execute(&l.store.pool).await.unwrap();
    let mut before = Vec::new();
    for id in &ids[..14] {
        before.push(row(&l, id).await);
    }
    retire(&l).await;
    assert_eq!(count(&l).await, 1);
    for (id, old) in ids[..14].iter().zip(before) {
        assert_eq!(row(&l, id).await, old);
    }
    l.finish().await;
}

#[tokio::test]
async fn retirement_guards_original_inputs_and_prevents_reactivation_or_history_rewriting() {
    let l = Lab::new().await;
    let id = seed(&l, 1).await.remove(0);
    let before = row(&l, &id).await;
    for change in [
        "inputs_retired_at=now(),original_spec_sha256=repeat('0',64),spec=spec-ARRAY['env','endpoint_env']",
        "inputs_retired_at=now(),original_spec_sha256=encode(sha256(convert_to(spec::text,'UTF8')),'hex')",
        "inputs_retired_at=now(),original_spec_sha256=encode(sha256(convert_to(spec::text,'UTF8')),'hex'),spec=spec-ARRAY['env','endpoint_env','secret_env']",
        "inputs_retired_at=now(),original_spec_sha256=encode(sha256(convert_to(spec::text,'UTF8')),'hex'),spec=spec-ARRAY['env','endpoint_env'],generation=generation+1",
    ] {
        assert!(
            sqlx::query(&format!("UPDATE executions SET {change} WHERE id=$1"))
                .bind(&id)
                .execute(&l.store.pool)
                .await
                .is_err()
        );
        assert_eq!(row(&l, &id).await, before);
    }
    retire(&l).await;
    let after = row(&l, &id).await;
    for change in [
        "inputs_retired_at=NULL,original_spec_sha256=NULL",
        "reserved=true",
        "state='queued'",
        "spec=spec||'{\"env\":{\"INPUT\":\"reintroduced\"}}'",
        "original_spec_sha256=repeat('0',64)",
    ] {
        assert!(
            sqlx::query(&format!("UPDATE executions SET {change} WHERE id=$1"))
                .bind(&id)
                .execute(&l.store.pool)
                .await
                .is_err()
        );
        assert_eq!(row(&l, &id).await, after);
    }
    assert!(
        sqlx::query("DELETE FROM executions WHERE id=$1")
            .bind(&id)
            .execute(&l.store.pool)
            .await
            .is_err()
    );
    l.finish().await;
}

#[tokio::test]
async fn execution_input_retention_is_atomic_and_recovery_barred() {
    let l = Lab::new().await;
    let ids = seed(&l, 3).await;
    let before = row(&l, &ids[0]).await;
    l.store.migrate().await.unwrap();
    l.store.migrate().await.unwrap();
    assert_eq!(
        row(&l, &ids[0]).await,
        before,
        "bootstrap never expires data by itself"
    );
    sqlx::query("UPDATE recovery_barrier SET active=true")
        .execute(&l.store.pool)
        .await
        .unwrap();
    assert!(l.store.schedule().await.is_err());
    assert!(sqlx::raw_sql(RETIRE).execute(&l.store.pool).await.is_err());
    assert_eq!(count(&l).await, 0);
    sqlx::query("UPDATE recovery_barrier SET active=false")
        .execute(&l.store.pool)
        .await
        .unwrap();
    sqlx::raw_sql("CREATE FUNCTION reject_input_retirement() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture retention failure'; END $$; CREATE TRIGGER reject_input_retirement AFTER UPDATE ON executions FOR EACH STATEMENT EXECUTE FUNCTION reject_input_retirement();").execute(&l.store.pool).await.unwrap();
    assert!(l.store.schedule().await.is_err());
    assert_eq!(count(&l).await, 0);
    assert_eq!(row(&l, &ids[0]).await, before);
    sqlx::raw_sql("DROP TRIGGER reject_input_retirement ON executions; DROP FUNCTION reject_input_retirement();").execute(&l.store.pool).await.unwrap();
    l.store.schedule().await.unwrap();
    assert_eq!(count(&l).await, 3);
    l.finish().await;
}

#[tokio::test]
async fn retired_inputs_do_not_weaken_late_log_redaction_or_accept_worker_replay() {
    let l = Lab::new().await;
    let node = l.node("late-logs").await;
    let id = seed(&l, 1).await.remove(0);
    sqlx::query("UPDATE executions SET node_id=$2 WHERE id=$1")
        .bind(&id)
        .bind(s(&node["id"]))
        .execute(&l.store.pool)
        .await
        .unwrap();
    retire(&l).await;
    let before = row(&l, &id).await;
    let mut body = execution_logs::batch(&uid(), 1, 0, true, json!([]));
    assert_eq!(
        l.store
            .ingest_execution_logs(s(&node["id"]), &id, 1, body.clone())
            .await
            .unwrap_err()
            .status,
        StatusCode::CONFLICT
    );
    body["redacted_env"] = json!(["TOKEN"]);
    assert!(
        l.store
            .ingest_execution_logs(s(&node["id"]), &id, 1, body)
            .await
            .is_ok()
    );
    l.store.heartbeat(s(&node["id"]),json!({"boot_id":"test-boot","confinement":HOST_CONFINEMENT,"reports":[{"id":id,"generation":1,"state":"running","sequence":999,"cpu_usec":500,"memory_bytes":900}]})).await.unwrap();
    assert_eq!(row(&l, &id).await, before);
    l.finish().await;
}

#[tokio::test]
async fn retirement_preserves_customer_run_history_and_inputs_for_new_explicit_events() {
    let l = Lab::new().await;
    let node = l.node("command-worker").await;
    approve_component(&l, &node, false, true).await;
    let app = l.store.deploy_app(&l.operator,&l.tenant,&l.project,
        fenders_control_plane::apps::AppSubmission {
            value: json!({"name":"retained-config","artifact_id":l.artifact,"triggers":{"manual":true,"http":false},"configuration":{"env":{"INPUT":"keep-for-future-runs"}}}),
            key:"app", domain:"apps.test",
        }).await.unwrap();
    let app = s(&app["resource_id"]);
    let first = l
        .store
        .run_app(&l.operator, &l.tenant, &l.project, app, "first-event")
        .await
        .unwrap();
    l.store.schedule().await.unwrap();
    let run = l
        .store
        .app_run(
            &l.operator,
            &l.tenant,
            &l.project,
            app,
            s(&first["resource_id"]),
        )
        .await
        .unwrap();
    let execution = s(&run["execution_id"]);
    l.store.heartbeat(s(&node["id"]),json!({"boot_id":"test-boot","confinement":HOST_CONFINEMENT,"reports":[{"id":execution,"generation":1,"state":"exited","sequence":1,"exit_code":0,"cpu_usec":12,"memory_bytes":512}]})).await.unwrap();
    sqlx::query("UPDATE executions SET created=now()-interval '40 days',updated=now()-interval '40 days',finished_at=now()-interval '40 days' WHERE id=$1")
        .bind(execution).execute(&l.store.pool).await.unwrap();
    sqlx::query("UPDATE app_runs SET created=now()-interval '40 days',admission_updated=now()-interval '40 days' WHERE id=$1")
        .bind(s(&first["resource_id"])).execute(&l.store.pool).await.unwrap();
    sqlx::query("UPDATE operations SET created=now()-interval '40 days',updated=now()-interval '40 days' WHERE id=$1")
        .bind(s(&first["id"])).execute(&l.store.pool).await.unwrap();
    let history = l
        .store
        .app_run(
            &l.operator,
            &l.tenant,
            &l.project,
            app,
            s(&first["resource_id"]),
        )
        .await
        .unwrap();
    let app_before = l
        .store
        .app(&l.operator, &l.tenant, &l.project, app)
        .await
        .unwrap();
    l.store.schedule().await.unwrap();
    assert_eq!(count(&l).await, 1);
    assert_eq!(
        l.store
            .app_run(
                &l.operator,
                &l.tenant,
                &l.project,
                app,
                s(&first["resource_id"])
            )
            .await
            .unwrap(),
        history
    );
    assert_eq!(
        l.store
            .app(&l.operator, &l.tenant, &l.project, app)
            .await
            .unwrap(),
        app_before
    );
    assert_eq!(
        l.store
            .run_app(&l.operator, &l.tenant, &l.project, app, "first-event")
            .await
            .unwrap()["id"],
        first["id"]
    );
    let next = l
        .store
        .run_app(&l.operator, &l.tenant, &l.project, app, "next-event")
        .await
        .unwrap();
    let next_run = l
        .store
        .app_run(
            &l.operator,
            &l.tenant,
            &l.project,
            app,
            s(&next["resource_id"]),
        )
        .await
        .unwrap();
    assert_ne!(next_run["execution_id"], run["execution_id"]);
    let next_execution = row(&l, s(&next_run["execution_id"])).await;
    assert_eq!(
        next_execution["spec"]["env"]["INPUT"],
        "keep-for-future-runs"
    );
    assert!(next_execution["inputs_retired_at"].is_null());
    l.finish().await;
}

#[tokio::test]
async fn later_deployment_operations_do_not_retain_inputs_from_every_old_revision() {
    let l = Lab::new().await;
    let ids = seed(&l, 2).await;
    let deployment = uid();
    sqlx::query("INSERT INTO deployments(id,tenant_id,project_id,name,spec,desired,revision) VALUES($1,$2,$3,'retained-deployment','{}','stopped',2)")
        .bind(&deployment).bind(&l.tenant).bind(&l.project).execute(&l.store.pool).await.unwrap();
    for (id, revision) in ids.iter().zip([1, 2]) {
        sqlx::query("UPDATE executions SET deployment_id=$2,revision=$3 WHERE id=$1")
            .bind(id)
            .bind(&deployment)
            .bind(revision)
            .execute(&l.store.pool)
            .await
            .unwrap();
    }
    sqlx::query("INSERT INTO operations(id,tenant_id,project_id,request_key,request_hash,resource_id,kind,target_revision) VALUES($1,$2,$3,'new-release','hash',$4,'update-deployment',2)")
        .bind(uid()).bind(&l.tenant).bind(&l.project).bind(&deployment).execute(&l.store.pool).await.unwrap();
    retire(&l).await;
    assert!(row(&l, &ids[0]).await["inputs_retired_at"].is_string());
    assert!(row(&l, &ids[1]).await["inputs_retired_at"].is_null());
    l.finish().await;
}
