use super::*;
use fenders_control_plane::usage::HistoryPage;
async fn seed(l: &Lab, project: &str, count: i32) -> (Value, Vec<String>) {
    let key = uid();
    let node = l.node(&format!("meter-{}", &key[..8])).await;
    let ids:Vec<String>=sqlx::query_scalar("INSERT INTO executions(id,tenant_id,project_id,spec,node_id,cpu_percent,memory_mib,reserved,state,desired,created) SELECT md5($1||n::text),$2,$3,'{}',$4,1,1,false,'exited','stopped',now()-interval '3 years' FROM generate_series(1,$5) n RETURNING id").bind(&key).bind(&l.tenant).bind(project).bind(s(&node["id"])).bind(count).fetch_all(&l.store.pool).await.unwrap();
    sqlx::query("INSERT INTO execution_egress_period_sources(execution_id,tenant_id,project_id,generation,boot_id,bytes,complete,payload,sampled_at) SELECT id,tenant_id,project_id,generation,'test-boot',115,true,jsonb_build_object('contract','socket-payload-utc-month-v1','bytes',115,'expired_bytes',5,'periods',jsonb_build_array(jsonb_build_object('period',to_char(now()-interval '14 months','YYYY-MM-01'),'bytes',20),jsonb_build_object('period',to_char(now()-interval '12 months','YYYY-MM-01'),'bytes',40),jsonb_build_object('period',to_char(now(),'YYYY-MM-01'),'bytes',50)),'complete',true,'in_flight',0,'observed',extract(epoch FROM now()),'boot_id','test-boot'),now() FROM executions WHERE node_id=$1").bind(s(&node["id"])).execute(&l.store.pool).await.unwrap();
    sqlx::query("INSERT INTO execution_egress_periods(execution_id,tenant_id,project_id,period,bytes,sampled_at) SELECT id,tenant_id,project_id,(date_trunc('month',now() AT TIME ZONE 'UTC')-make_interval(months=>v.age))::date,v.bytes,now() FROM executions CROSS JOIN (VALUES(14,20),(12,40),(0,50)) v(age,bytes) WHERE node_id=$1").bind(s(&node["id"])).execute(&l.store.pool).await.unwrap();
    sqlx::query("INSERT INTO execution_egress_budgets(execution_id,tenant_id,project_id,node_id,boot_id,launcher_digest,generation,state,base_bytes,ceiling_bytes,closure,closed_at) SELECT id,tenant_id,project_id,node_id,'test-boot',repeat('a',64),generation,'closed',600,600,'terminal-conservative',now() FROM executions WHERE node_id=$1").bind(s(&node["id"])).execute(&l.store.pool).await.unwrap();
    sqlx::query("INSERT INTO egress_allowance_usage(execution_id,tenant_id,project_id,period,bytes,conservative_bytes) SELECT id,tenant_id,project_id,(date_trunc('month',now() AT TIME ZONE 'UTC')-make_interval(months=>v.age))::date,v.bytes,v.conservative FROM executions CROSS JOIN (VALUES(14,100,7),(12,200,9),(0,300,11)) v(age,bytes,conservative) WHERE node_id=$1").bind(s(&node["id"])).execute(&l.store.pool).await.unwrap();
    (node, ids)
}
async fn history(l: &Lab, project: Option<&str>) -> Value {
    l.store
        .usage_history(&l.operator, &l.tenant, project, HistoryPage::default())
        .await
        .unwrap()
}
async fn old_counts(l: &Lab) -> (i64, i64) {
    sqlx::query_as("SELECT (SELECT count(*) FROM execution_egress_periods WHERE period<(date_trunc('month',now() AT TIME ZONE 'UTC')-interval '12 months')::date),(SELECT count(*) FROM egress_allowance_usage WHERE period<(date_trunc('month',now() AT TIME ZONE 'UTC')-interval '12 months')::date)").fetch_one(&l.store.pool).await.unwrap()
}
#[tokio::test]
async fn finalized_months_compact_in_bounded_passes_preserving_history_and_conservation() {
    let l = Lab::new().await;
    let (node, ids) = seed(&l, &l.project, 320).await;
    let before = history(&l, None).await;
    let usage = l.store.usage(&l.operator, &l.tenant, None).await.unwrap();
    assert_eq!(before["items"].as_array().unwrap().len(), 3);
    assert_eq!(before["items"][2]["accounted_bytes"], 32000);
    assert_eq!(before["items"][2]["observed_outbound_bytes"], 6400);
    assert_eq!(usage["totals"]["egress_unassigned_bytes"], 1600);
    l.store.schedule().await.unwrap();
    assert_eq!(old_counts(&l).await, (64, 64));
    assert_eq!(history(&l, None).await["items"], before["items"]);
    let reopened = Store::from_pool(l.store.pool.clone(), l.root.path()).unwrap();
    let (a, b) = tokio::join!(l.store.schedule(), reopened.schedule());
    a.unwrap();
    b.unwrap();
    assert_eq!(old_counts(&l).await, (0, 0));
    assert_eq!(history(&l, None).await["items"], before["items"]);
    assert_eq!(
        l.store.usage(&l.operator, &l.tenant, None).await.unwrap()["totals"],
        usage["totals"]
    );
    let counts:(i64,i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM accounting_month_rollups),(SELECT sum(archived_bytes)::bigint FROM execution_egress_period_sources),(SELECT sum(archived_periods)::bigint FROM execution_egress_period_sources)").fetch_one(&l.store.pool).await.unwrap();
    assert_eq!(counts, (1, 6400, 320));
    let financial: (i64, i64) = sqlx::query_as(
        "SELECT sum(used_bytes)::bigint,sum(held_bytes)::bigint FROM transfer_allowance_accounting",
    )
    .fetch_one(&l.store.pool)
    .await
    .unwrap();
    assert_eq!(financial, (192000, 0));
    // New-sequence terminal replays cannot resurrect finalized history.
    let reports:Vec<Value>=ids.iter().map(|id|json!({"id":id,"generation":1,"sequence":999,"state":"exited","cpu_usec":0,"memory_bytes":0,"egress_periods":{"bogus":true}})).collect();
    l.store
        .heartbeat(
            s(&node["id"]),
            json!({"boot_id":"test-boot","confinement":HOST_CONFINEMENT,"reports":reports}),
        )
        .await
        .unwrap();
    l.store.schedule().await.unwrap();
    assert_eq!(old_counts(&l).await, (0, 0));
    assert_eq!(history(&l, None).await["items"], before["items"]);
    l.finish().await;
}
#[tokio::test]
async fn accounting_retention_preserves_uncertain_sources_open_grants_and_current_boundary() {
    let l = Lab::new().await;
    let (_, ids) = seed(&l, &l.project, 4).await;
    sqlx::query(
        "UPDATE executions SET reserved=true,state='unreachable',desired='paused' WHERE id=$1",
    )
    .bind(&ids[0])
    .execute(&l.store.pool)
    .await
    .unwrap();
    sqlx::query("UPDATE execution_egress_budgets SET state='active',ceiling_bytes=630,held_bytes=30,expires=now()-interval '1 day',closure=NULL,closed_at=NULL WHERE execution_id=$1").bind(&ids[1]).execute(&l.store.pool).await.unwrap();
    sqlx::query("UPDATE execution_egress_period_sources SET complete=false WHERE execution_id=$1")
        .bind(&ids[2])
        .execute(&l.store.pool)
        .await
        .unwrap();
    let before = history(&l, None).await;
    let usage = l.store.usage(&l.operator, &l.tenant, None).await.unwrap();
    l.store.schedule().await.unwrap();
    assert_eq!(old_counts(&l).await, (3, 2));
    assert_eq!(history(&l, None).await["items"], before["items"]);
    assert_eq!(
        l.store.usage(&l.operator, &l.tenant, None).await.unwrap()["totals"],
        usage["totals"]
    );
    let remaining:i64=sqlx::query_scalar("SELECT count(*) FROM execution_egress_periods WHERE period=(date_trunc('month',now() AT TIME ZONE 'UTC')-interval '12 months')::date").fetch_one(&l.store.pool).await.unwrap();
    assert_eq!(
        remaining, 4,
        "the oldest retained boundary month is inclusive"
    );
    assert_eq!(
        before["items"][0]["held_bytes"], 30,
        "expiry does not release uncertain grants"
    );
    l.finish().await;
}
#[tokio::test]
async fn accounting_rollup_failure_and_recovery_barrier_preserve_raw_records_atomically() {
    let l = Lab::new().await;
    seed(&l, &l.project, 3).await;
    let before = history(&l, None).await;
    sqlx::raw_sql("CREATE FUNCTION fail_accounting_rollup() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.outbound_accounted_bytes>0 THEN RAISE EXCEPTION 'injected settlement rollup failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_rollup BEFORE INSERT OR UPDATE ON accounting_month_rollups FOR EACH ROW EXECUTE FUNCTION fail_accounting_rollup();").execute(&l.store.pool).await.unwrap();
    assert!(l.store.schedule().await.is_err());
    assert_eq!(old_counts(&l).await, (3, 3));
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM accounting_month_rollups")
        .fetch_one(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
    let archived: i64 = sqlx::query_scalar(
        "SELECT sum(archived_bytes)::bigint FROM execution_egress_period_sources",
    )
    .fetch_one(&l.store.pool)
    .await
    .unwrap();
    assert_eq!(archived, 0);
    sqlx::query("DROP TRIGGER reject_rollup ON accounting_month_rollups")
        .execute(&l.store.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE recovery_barrier SET active=true")
        .execute(&l.store.pool)
        .await
        .unwrap();
    assert!(l.store.schedule().await.is_err());
    assert_eq!(history(&l, None).await["items"], before["items"]);
    assert_eq!(old_counts(&l).await, (3, 3));
    sqlx::query("UPDATE recovery_barrier SET active=false")
        .execute(&l.store.pool)
        .await
        .unwrap();
    l.store.schedule().await.unwrap();
    assert_eq!(old_counts(&l).await, (0, 0));
    assert_eq!(history(&l, None).await["items"], before["items"]);
    l.finish().await;
}
#[tokio::test]
async fn monthly_history_is_scoped_paginated_and_keeps_observations_separate_from_charges() {
    let l = Lab::new().await;
    seed(&l, &l.project, 2).await;
    let other = l
        .store
        .create_project(
            &l.operator,
            &l.tenant,
            serde_json::from_value(json!({"name":"other"})).unwrap(),
        )
        .await
        .unwrap();
    seed(&l, s(&other["id"]), 1).await;
    let (viewer, credential) = l.credential("viewer", Some(&l.project)).await;
    let first = l
        .store
        .usage_history(
            &viewer,
            &l.tenant,
            Some(&l.project),
            HistoryPage {
                limit: Some(1),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(first["items"][0]["accounted_bytes"], 600);
    assert_eq!(first["items"][0]["observed_outbound_bytes"], 100);
    // The cursor is `next`, as in every list, and has no other name.
    assert!(first["next"].is_string());
    assert!(first.get("next_before").is_none());
    assert!(
        l.store
            .usage_history(&viewer, &l.tenant, None, Default::default())
            .await
            .is_err()
    );
    assert!(
        l.store
            .usage_history(
                &viewer,
                &l.tenant,
                Some(s(&other["id"])),
                Default::default()
            )
            .await
            .is_err()
    );
    assert!(
        l.store
            .usage_history(&viewer, &uid(), Some(&l.project), Default::default())
            .await
            .is_err()
    );
    for before in ["2026-1-01", "2026-10-02", "bad", "1969-01-01"] {
        assert!(
            l.store
                .usage_history(
                    &viewer,
                    &l.tenant,
                    Some(&l.project),
                    HistoryPage {
                        before: Some(before.into()),
                        limit: Some(1)
                    }
                )
                .await
                .is_err()
        );
    }
    let page = l
        .store
        .usage_history(
            &viewer,
            &l.tenant,
            Some(&l.project),
            HistoryPage {
                before: first["next"].as_str().map(str::to_owned),
                limit: Some(60),
            },
        )
        .await
        .unwrap();
    assert_eq!(page["items"].as_array().unwrap().len(), 2);
    assert!(page["next"].is_null());
    let workspace = history(&l, None).await;
    let project = history(&l, Some(&l.project)).await;
    let other = history(&l, Some(s(&other["id"]))).await;
    for index in 0..3 {
        assert_eq!(
            n(&workspace["items"][index]["accounted_bytes"]),
            n(&project["items"][index]["accounted_bytes"])
                + n(&other["items"][index]["accounted_bytes"])
        );
    }
    let response = api::router(l.store.clone())
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/workspaces/{}/projects/{}/usage/history?limit=1",
                    l.tenant, l.project
                ))
                .header(
                    "Authorization",
                    format!("Bearer {}", s(&credential["token"])),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap();
    assert_eq!(body["items"], first["items"]);
    let response = api::router(l.store.clone())
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/workspaces/{}/projects/{}/usage/history?extra=1",
                    l.tenant, l.project
                ))
                .header(
                    "Authorization",
                    format!("Bearer {}", s(&credential["token"])),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    l.finish().await;
}
