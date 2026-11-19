use super::*;

async fn report(
    l: &Lab,
    node: &Value,
    e: &Value,
    sequence: i64,
    cpu: i64,
    memory: i64,
    measured: Option<bool>,
) {
    let mut report = json!({"id":e["id"],"generation":e["generation"],"state":"running","sequence":sequence,"cpu_usec":cpu,"memory_bytes":memory});
    if let Some(measured) = measured {
        report["cpu_measured"] = json!(measured);
        report["memory_measured"] = json!(measured);
    }
    l.store
        .heartbeat(
            s(&node["id"]),
            json!({"boot_id":"test-boot","reports":[report],"confinement":HOST_CONFINEMENT}),
        )
        .await
        .unwrap();
}
async fn usage(l: &Lab) -> Value {
    l.store.usage(&l.operator, &l.tenant, None).await.unwrap()
}

#[tokio::test]
async fn measurements_distinguish_unknown_zero_partial_stale_and_fenced_generations() {
    let l = Lab::new().await;
    let empty = usage(&l).await;
    assert_eq!(empty["totals"]["cpu_usec"], 0);
    let node = l.node("usage-worker").await;
    let op = l.create("usage", json!({"artifact_id":l.artifact})).await;
    l.store.schedule().await.unwrap();
    let e = l.run(&op).await;
    let no_sample = usage(&l).await;
    assert!(no_sample["cpu_usec"].is_null());
    assert!(no_sample["totals"]["memory_bytes"].is_null());
    report(&l, &node, &e, 1, 123, 512, None).await;
    assert!(
        usage(&l).await["cpu_usec"].is_null(),
        "legacy placeholders are not qualified measurements"
    );
    report(&l, &node, &e, 2, 0, 0, Some(true)).await;
    let zero = usage(&l).await;
    assert_eq!(zero["cpu_usec"], 0);
    assert_eq!(zero["totals"]["memory_measured"], 1);
    report(&l, &node, &e, 3, 200, 4096, Some(true)).await;
    report(&l, &node, &e, 3, 999, 999, Some(true)).await; // replay cannot change counters
    assert_eq!(usage(&l).await["cpu_usec"], 200);
    // A newer unavailable reading does not erase CPU history, but cannot claim
    // that the old memory reading is still current.
    report(&l, &node, &e, 4, 0, 0, Some(false)).await;
    let lost = usage(&l).await;
    assert_eq!(lost["cpu_usec"], 200);
    assert!(lost["totals"]["memory_bytes"].is_null());
    report(&l, &node, &e, 5, 210, 8192, Some(true)).await;
    sqlx::query(
        "UPDATE usage_samples SET observed=now()-interval '31 seconds' WHERE execution_id=$1",
    )
    .bind(s(&e["id"]))
    .execute(&l.store.pool)
    .await
    .unwrap();
    let stale = usage(&l).await;
    assert!(stale["totals"]["memory_bytes"].is_null());
    assert_eq!(stale["totals"]["memory_expected"], 1);
    sqlx::query("UPDATE executions SET generation=generation+1 WHERE id=$1")
        .bind(s(&e["id"]))
        .execute(&l.store.pool)
        .await
        .unwrap();
    report(&l, &node, &e, 6, 999, 999, Some(true)).await; // fenced report ignored
    assert_eq!(usage(&l).await["cpu_usec"], 210);
    let mut current = e.clone();
    current["generation"] = json!(2);
    report(&l, &node, &current, 7, 220, 16384, Some(true)).await;
    l.create("queued-unknown", json!({"artifact_id":l.artifact}))
        .await;
    let partial = usage(&l).await;
    assert_eq!(
        partial["cpu_usec"], 220,
        "generation changes do not double count cumulative execution CPU"
    );
    assert_eq!(partial["totals"]["executions"], 2);
    assert_eq!(partial["totals"]["measured_executions"], 1);
    assert_eq!(partial["totals"]["memory_bytes"], 16384);
    assert_eq!(partial["totals"]["memory_measured"], 1);
    assert_eq!(partial["totals"]["memory_expected"], 2);
    assert!(partial["measurement"]["egress_bytes"].is_null());
    let invalid=l.store.heartbeat(s(&node["id"]),json!({"boot_id":"test-boot","reports":[{"id":e["id"],"generation":2,"state":"running","sequence":8,"cpu_usec":1,"memory_bytes":2,"cpu_measured":"yes"}],"confinement":HOST_CONFINEMENT})).await;
    assert!(invalid.is_err());
    l.finish().await;
}

#[tokio::test]
async fn project_accounting_reconciles_compute_artifacts_transfer_and_diagnostics() {
    let l = Lab::new().await;
    let second = l
        .store
        .create_project(
            &l.operator,
            &l.tenant,
            serde_json::from_value(json!({"name":"second"})).unwrap(),
        )
        .await
        .unwrap();
    let node = l.node("usage-worker").await;
    let op = l.create("active", json!({"artifact_id":l.artifact})).await;
    l.store.schedule().await.unwrap();
    let e = l.run(&op).await;
    report(&l, &node, &e, 1, 500, 2048, Some(true)).await;
    // An uncertain WASM execution still reserves resources; accounting cannot release it.
    sqlx::query("UPDATE executions SET state='unreachable' WHERE id=$1")
        .bind(s(&e["id"]))
        .execute(&l.store.pool)
        .await
        .unwrap();
    let capture = uid();
    l.store
        .ingest_execution_logs(
            s(&node["id"]),
            s(&e["id"]),
            1,
            super::execution_logs::batch(
                &capture,
                1,
                2,
                true,
                json!([
                    super::execution_logs::record(1, b"hello"),
                    super::execution_logs::record(2, b"old")
                ]),
            ),
        )
        .await
        .unwrap();
    sqlx::query(
        "UPDATE execution_log_records SET received=now()-interval '8 days' WHERE sequence=2",
    )
    .execute(&l.store.pool)
    .await
    .unwrap();
    for (project, bytes) in [(l.project.as_str(), 100_i64), (s(&second["id"]), 200)] {
        sqlx::query("INSERT INTO traffic_usage(tenant_id,project_id,period,bytes,requests) VALUES($1,$2,date_trunc('month',now() AT TIME ZONE 'UTC')::date,$3,1)").bind(&l.tenant).bind(project).bind(bytes).execute(&l.store.pool).await.unwrap();
    }
    sqlx::query("INSERT INTO ingress_reservations(id,tenant_id,project_id,period,bytes,expires) VALUES($1,$2,$3,date_trunc('month',now() AT TIME ZONE 'UTC')::date,50,now()-interval '1 minute')").bind(uid()).bind(&l.tenant).bind(&l.project).execute(&l.store.pool).await.unwrap();
    let value = usage(&l).await;
    let t = &value["totals"];
    assert_eq!(t["reserved_instances"], 1);
    assert_eq!(t["uncertain_instances"], 1);
    assert_eq!(t["storage_bytes"], 8);
    assert_eq!(t["ingress_bytes"], 300);
    assert_eq!(
        t["ingress_reserved_bytes"], 50,
        "expired unsettled reservations still hold allowance"
    );
    assert_eq!(t["diagnostic_bytes"], 5);
    assert_eq!(t["diagnostic_records"], 1);
    assert_eq!(t["diagnostic_expired_bytes"], 3);
    assert_eq!(value["diagnostics"]["charged_to_storage_allowance"], false);
    for key in [
        "reserved_cpu_percent",
        "reserved_memory_mib",
        "reserved_instances",
        "storage_bytes",
        "ingress_bytes",
        "diagnostic_bytes",
    ] {
        let sum: i64 = value["projects"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| n(&p[key]))
            .sum();
        assert_eq!(n(&t[key]), sum, "{key}");
    }
    let scoped = l
        .store
        .usage(&l.operator, &l.tenant, Some(s(&second["id"])))
        .await
        .unwrap();
    assert_eq!(scoped["projects"].as_array().unwrap().len(), 1);
    assert_eq!(scoped["totals"]["reserved_instances"], 0);
    assert_eq!(scoped["totals"]["storage_bytes"], 0);
    l.finish().await;
}

#[tokio::test]
async fn usage_enforces_workspace_project_and_credential_scope() {
    let l = Lab::new().await;
    let (viewer, credential) = l.credential("viewer", Some(&l.project)).await;
    let foreign=l.store.create_tenant(&l.operator,serde_json::from_value(json!({"name":"foreign","allowance":{"cpu_percent":100,"memory_mib":1024,"instances":2,"storage_bytes":100000000,"transfer_bytes":10000000}})).unwrap()).await.unwrap();
    let foreign_project = l
        .store
        .projects(&l.operator, s(&foreign["id"]))
        .await
        .unwrap()[0]["id"]
        .clone();
    l.store
        .upload(
            &l.operator,
            s(&foreign["id"]),
            s(&foreign_project),
            b"\0asm\x0d\0\x01\0",
        )
        .await
        .unwrap();
    assert!(
        l.store
            .usage(&viewer, s(&foreign["id"]), Some(s(&foreign_project)))
            .await
            .is_err()
    );
    assert!(
        l.store
            .usage(&l.operator, &l.tenant, Some(s(&foreign_project)))
            .await
            .is_err()
    );
    let own = usage(&l).await;
    assert_eq!(own["totals"]["artifact_bytes"], 8);
    assert!(!own.to_string().contains(s(&foreign_project)));
    assert!(l.store.usage(&viewer, &l.tenant, None).await.is_err());
    assert!(
        l.store
            .usage(&viewer, &l.tenant, Some(&uid()))
            .await
            .is_err()
    );
    assert!(
        l.store
            .usage(&l.operator, &l.tenant, Some(&uid()))
            .await
            .is_err()
    );
    assert!(
        l.store
            .usage(&viewer, &uid(), Some(&l.project))
            .await
            .is_err()
    );
    let uri = format!("/v1/workspaces/{}/projects/{}/usage", l.tenant, l.project);
    let response = api::router(l.store.clone())
        .oneshot(
            Request::builder()
                .uri(&uri)
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
    let data: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap();
    assert_eq!(data["scope"], "project");
    assert_eq!(data["projects"].as_array().unwrap().len(), 1);
    l.store
        .revoke_credential(&l.operator, &l.tenant, s(&credential["id"]))
        .await
        .unwrap();
    let response = api::router(l.store.clone())
        .oneshot(
            Request::builder()
                .uri(&uri)
                .header(
                    "Authorization",
                    format!("Bearer {}", s(&credential["token"])),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    l.finish().await;
}

fn outbound(bytes: u64, complete: bool, observed: f64) -> Value {
    json!({"contract":"socket-payload-v1","bytes":bytes,"in_flight":0,"complete":complete,"observed":observed,"boot_id":"test-boot"})
}
fn sample_time() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64()
}
async fn send_outbound(
    l: &Lab,
    node: &Value,
    e: &Value,
    sequence: i64,
    state: &str,
    egress: Value,
) -> fenders_control_plane::error::Result<Value> {
    l.store.heartbeat(s(&node["id"]),json!({"boot_id":"test-boot","confinement":HOST_CONFINEMENT,"reports":[{"id":e["id"],"generation":e["generation"],"sequence":sequence,"state":state,"cpu_usec":0,"memory_bytes":0,"egress":egress}]})).await
}

#[tokio::test]
async fn outbound_rollup_survives_replay_generation_changes_and_terminal_reports() {
    let l = Lab::new().await;
    let node = l.node("egress-worker").await;
    let op = l.create("metered", json!({"artifact_id":l.artifact})).await;
    l.store.schedule().await.unwrap();
    let e = l.run(&op).await;
    let at = sample_time();
    assert!(usage(&l).await["totals"]["egress_bytes"].is_null());
    send_outbound(&l, &node, &e, 1, "running", outbound(0, false, at))
        .await
        .unwrap();
    assert_eq!(usage(&l).await["totals"]["egress_bytes"], 0);
    send_outbound(&l, &node, &e, 2, "running", outbound(100, false, at + 0.1))
        .await
        .unwrap();
    send_outbound(&l, &node, &e, 2, "running", outbound(999, false, at + 0.2))
        .await
        .unwrap();
    send_outbound(&l, &node, &e, 3, "running", outbound(999, false, at - 1.0))
        .await
        .unwrap();
    send_outbound(&l, &node, &e, 4, "running", Value::Null)
        .await
        .unwrap();
    assert_eq!(usage(&l).await["totals"]["egress_bytes"], 100);
    sqlx::query("UPDATE executions SET generation=generation+1 WHERE id=$1")
        .bind(s(&e["id"]))
        .execute(&l.store.pool)
        .await
        .unwrap();
    send_outbound(&l, &node, &e, 5, "running", outbound(999, false, at + 0.3))
        .await
        .unwrap();
    let mut current = e.clone();
    current["generation"] = json!(2);
    send_outbound(
        &l,
        &node,
        &current,
        6,
        "running",
        outbound(110, false, at + 0.4),
    )
    .await
    .unwrap();
    send_outbound(
        &l,
        &node,
        &current,
        7,
        "exited",
        outbound(120, true, at + 0.5),
    )
    .await
    .unwrap();
    send_outbound(
        &l,
        &node,
        &current,
        8,
        "exited",
        outbound(999, true, at + 0.6),
    )
    .await
    .unwrap();
    let totals = usage(&l).await;
    assert_eq!(totals["totals"]["egress_bytes"], 120);
    assert_eq!(totals["totals"]["egress_complete"], 1);
    assert_eq!(totals["totals"]["egress_measured"], 1);
    assert_eq!(
        totals["measurement"]["egress_window"],
        "recorded execution lifetime"
    );
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM execution_egress_usage")
        .fetch_one(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(rows, 1);
    let reopened = Store::from_pool(l.store.pool.clone(), l.root.path()).unwrap();
    assert_eq!(
        reopened.usage(&l.operator, &l.tenant, None).await.unwrap()["totals"]["egress_bytes"],
        120
    );
    drop(reopened);
    l.finish().await;
}

#[tokio::test]
async fn outbound_rejects_invalid_contracts_and_preserves_unsigned_counters() {
    let l = Lab::new().await;
    let node = l.node("egress-worker").await;
    let op = l.create("metered", json!({"artifact_id":l.artifact})).await;
    l.store.schedule().await.unwrap();
    let e = l.run(&op).await;
    let at = sample_time();
    for (key, bad) in [
        ("bytes", json!(-1)),
        ("bytes", json!(1.5)),
        ("bytes", json!("1")),
        ("contract", json!("unknown")),
        ("boot_id", json!("old-boot")),
        ("observed", json!(0)),
        ("observed", json!(at + 3600.0)),
        ("observed", json!(at - 3600.0)),
        ("complete", json!(true)),
        ("complete", json!("false")),
        ("in_flight", json!(129)),
        ("tenant_id", json!(l.tenant)),
    ] {
        let mut value = outbound(1, false, at);
        value[key] = bad;
        assert!(
            send_outbound(&l, &node, &e, 1, "running", value)
                .await
                .is_err(),
            "{key}"
        );
    }
    let mut pending = outbound(7, true, at);
    pending["in_flight"] = json!(1);
    assert!(
        send_outbound(&l, &node, &e, 1, "exited", pending)
            .await
            .is_err()
    );
    assert!(
        send_outbound(&l, &node, &e, 1, "lost", outbound(7, true, at))
            .await
            .is_err()
    );
    assert!(usage(&l).await["totals"]["egress_bytes"].is_null());
    // Meter insertion and terminal lifecycle changes are one transaction: a
    // later invalid report field must roll both back.
    assert!(l.store.heartbeat(s(&node["id"]),json!({"boot_id":"test-boot","confinement":HOST_CONFINEMENT,"reports":[{"id":e["id"],"generation":e["generation"],"sequence":1,"state":"exited","cpu_usec":0,"memory_bytes":0,"exit_code":256,"egress":outbound(9,true,at)}]})).await.is_err());
    assert!(usage(&l).await["totals"]["egress_bytes"].is_null());
    assert_eq!(usage(&l).await["totals"]["reserved_instances"], 1);
    send_outbound(&l, &node, &e, 1, "exited", outbound(u64::MAX, true, at))
        .await
        .unwrap();
    assert_eq!(
        usage(&l).await["totals"]["egress_bytes"].as_u64(),
        Some(u64::MAX)
    );
    l.finish().await;
}

#[tokio::test]
async fn outbound_discontinuities_are_lower_bounds_and_foreign_nodes_cannot_report() {
    let l = Lab::new().await;
    let node = l.node("egress-worker").await;
    let op = l.create("metered", json!({"artifact_id":l.artifact})).await;
    l.store.schedule().await.unwrap();
    let e = l.run(&op).await;
    let foreign = l.node("foreign-worker").await;
    let at = sample_time();
    send_outbound(&l, &foreign, &e, 1, "exited", outbound(999, true, at))
        .await
        .unwrap();
    assert!(usage(&l).await["totals"]["egress_bytes"].is_null());
    send_outbound(&l, &node, &e, 1, "running", outbound(100, false, at))
        .await
        .unwrap();
    send_outbound(&l, &node, &e, 2, "exited", outbound(50, true, at + 1.0))
        .await
        .unwrap();
    let total = usage(&l).await;
    assert_eq!(total["totals"]["egress_bytes"], 100);
    assert_eq!(total["totals"]["egress_complete"], 0);
    assert_eq!(total["totals"]["egress_discontinuities"], 1);
    let other = l
        .store
        .create_project(
            &l.operator,
            &l.tenant,
            serde_json::from_value(json!({"name":"empty"})).unwrap(),
        )
        .await
        .unwrap();
    let empty = l
        .store
        .usage(&l.operator, &l.tenant, Some(s(&other["id"])))
        .await
        .unwrap();
    assert_eq!(empty["totals"]["egress_bytes"], 0);
    let scoped = l
        .store
        .usage(&l.operator, &l.tenant, Some(&l.project))
        .await
        .unwrap();
    assert_eq!(scoped["totals"]["egress_bytes"], 100);
    l.finish().await;
}

#[tokio::test]
async fn heartbeat_downsampling_preserves_cpu_high_water_latest_time_and_memory() {
    let l = Lab::new().await;
    let node = l.node("compact-worker").await;
    let op = l.create("compact", json!({"artifact_id":l.artifact})).await;
    l.store.schedule().await.unwrap();
    let e = l.run(&op).await;
    // Deliberately nonmonotonic counters, unknown measurements and lifecycle
    // generations: compare retained witnesses to an independent in-memory oracle.
    let mut maximum = None;
    let mut measured_time = Value::Null;
    let mut current = e.clone();
    for sequence in 1..=48 {
        if sequence == 25 {
            sqlx::query("UPDATE executions SET generation=generation+1 WHERE id=$1")
                .bind(s(&e["id"]))
                .execute(&l.store.pool)
                .await
                .unwrap();
            current["generation"] = json!(2);
        }
        let cpu = (sequence * 71) % 503;
        let measured = sequence % 3 != 0;
        report(
            &l,
            &node,
            &current,
            sequence,
            cpu,
            sequence * 1024,
            Some(measured),
        )
        .await;
        let observed:Value=sqlx::query_scalar("SELECT to_jsonb(observed) FROM usage_samples WHERE execution_id=$1 AND generation=$2 AND sequence=$3").bind(s(&e["id"])).bind(n(&current["generation"])).bind(sequence).fetch_one(&l.store.pool).await.unwrap();
        if measured {
            maximum = Some(maximum.unwrap_or(0).max(cpu));
            measured_time = observed;
        }
        let result = usage(&l).await;
        assert_eq!(result["cpu_usec"], json!(maximum));
        assert_eq!(result["totals"]["last_cpu_observed"], measured_time);
        assert_eq!(
            result["totals"]["memory_bytes"],
            if measured {
                json!(sequence * 1024)
            } else {
                Value::Null
            }
        );
        let count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM usage_samples WHERE execution_id=$1")
                .bind(s(&e["id"]))
                .fetch_one(&l.store.pool)
                .await
                .unwrap();
        assert!(count <= 3, "retained {count} samples at {sequence}");
    }
    let before = usage(&l).await;
    report(&l, &node, &e, 999, 99999, 99999, Some(true)).await; // old generation
    report(&l, &node, &current, 48, 99999, 99999, Some(true)).await; // replay
    let after = usage(&l).await;
    assert_eq!(before["totals"], after["totals"]);
    l.finish().await;
}

#[tokio::test]
async fn queued_histories_compact_in_bounded_restart_safe_batches() {
    let l = Lab::new().await;
    let node = l.node("compact-worker").await;
    let op = l.create("old", json!({"artifact_id":l.artifact})).await;
    l.store.schedule().await.unwrap();
    let e = l.run(&op).await;
    report(&l, &node, &e, 1, 7, 4096, Some(true)).await;
    // Seed queued historical heartbeats. The selected
    // CPU maximum, newest qualified CPU time and newest memory report differ.
    sqlx::query("INSERT INTO usage_samples(execution_id,generation,sequence,tenant_id,cpu_usec,memory_bytes,cpu_measured,memory_measured,observed) SELECT $1,1,n,$2,CASE WHEN n=100 THEN 99999 ELSE n END,n*2,n<1100,n<1100,now()-interval '1 day'+n*interval '1 second' FROM generate_series(2,1200) n").bind(s(&e["id"])).bind(&l.tenant).execute(&l.store.pool).await.unwrap();
    sqlx::query(
        "UPDATE executions SET observation=jsonb_build_object('sequence',1200) WHERE id=$1",
    )
    .bind(s(&e["id"]))
    .execute(&l.store.pool)
    .await
    .unwrap();
    let original = usage(&l).await;
    assert_eq!(original["cpu_usec"], 99999);
    assert!(original["totals"]["memory_bytes"].is_null());
    sqlx::query("INSERT INTO usage_compaction_queue(execution_id) VALUES($1)")
        .bind(s(&e["id"]))
        .execute(&l.store.pool)
        .await
        .unwrap();
    l.store.migrate().await.unwrap();
    let queued: i64 = sqlx::query_scalar("SELECT count(*) FROM usage_compaction_queue")
        .fetch_one(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(queued, 1);
    l.store.schedule().await.unwrap();
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM usage_samples")
        .fetch_one(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(
        count,
        1200 - 256,
        "one scheduler pass deletes at most 256 rows per execution"
    );
    let reopened = Store::from_pool(l.store.pool.clone(), l.root.path()).unwrap();
    for _ in 0..6 {
        reopened.schedule().await.unwrap();
    }
    let final_usage = usage(&l).await;
    assert_eq!(original["totals"], final_usage["totals"]);
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM usage_samples")
        .fetch_one(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(rows, 3);
    let queued: i64 = sqlx::query_scalar("SELECT count(*) FROM usage_compaction_queue")
        .fetch_one(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(queued, 0);
    // A later missing memory reading stays missing; compaction cannot select an
    // older measured row and make it look fresh again.
    report(&l, &node, &e, 1201, 0, 0, Some(false)).await;
    assert!(usage(&l).await["totals"]["memory_bytes"].is_null());
    assert_eq!(usage(&l).await["cpu_usec"], 99999);
    drop(reopened);
    l.finish().await;
}

#[tokio::test]
async fn compaction_is_atomic_with_reports_and_serializes_against_cleanup() {
    let l = Lab::new().await;
    let node = l.node("compact-worker").await;
    let op = l.create("racing", json!({"artifact_id":l.artifact})).await;
    l.store.schedule().await.unwrap();
    let e = l.run(&op).await;
    sqlx::query("INSERT INTO usage_samples(execution_id,generation,sequence,tenant_id,cpu_usec,memory_bytes,cpu_measured,memory_measured) SELECT $1,1,n,$2,n,n,true,true FROM generate_series(1,700) n").bind(s(&e["id"])).bind(&l.tenant).execute(&l.store.pool).await.unwrap();
    sqlx::query("INSERT INTO usage_compaction_queue(execution_id) VALUES($1)")
        .bind(s(&e["id"]))
        .execute(&l.store.pool)
        .await
        .unwrap();
    let count = || {
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM usage_samples").fetch_one(&l.store.pool)
    };
    let valid = json!({"id":e["id"],"generation":1,"sequence":701,"state":"running","cpu_usec":8000,"memory_bytes":4096,"cpu_measured":true,"memory_measured":true});
    let mut invalid = valid.clone();
    invalid["state"] = json!("bogus");
    invalid["sequence"] = json!(702);
    assert!(l.store.heartbeat(s(&node["id"]),json!({"boot_id":"test-boot","reports":[valid.clone(),invalid],"confinement":HOST_CONFINEMENT})).await.is_err());
    assert_eq!(
        count().await.unwrap(),
        700,
        "later failure rolls back earlier insertion and pruning"
    );
    sqlx::query("UPDATE recovery_barrier SET active=true")
        .execute(&l.store.pool)
        .await
        .unwrap();
    assert!(l.store.schedule().await.is_err());
    assert_eq!(count().await.unwrap(), 700);
    sqlx::query("UPDATE recovery_barrier SET active=false")
        .execute(&l.store.pool)
        .await
        .unwrap();
    let (heartbeat, cleanup) = tokio::join!(
        l.store.heartbeat(
            s(&node["id"]),
            json!({"boot_id":"test-boot","reports":[valid],"confinement":HOST_CONFINEMENT})
        ),
        l.store.schedule()
    );
    heartbeat.unwrap();
    cleanup.unwrap();
    assert_eq!(count().await.unwrap(), 189);
    l.store.schedule().await.unwrap();
    assert!(count().await.unwrap() <= 3);
    let totals = usage(&l).await;
    assert_eq!(totals["cpu_usec"], 8000);
    assert_eq!(totals["totals"]["memory_bytes"], 4096);
    l.finish().await;
}

fn period_month(ago: u32) -> chrono::NaiveDate {
    use chrono::Datelike;
    chrono::Utc::now()
        .date_naive()
        .with_day(1)
        .unwrap()
        .checked_sub_months(chrono::Months::new(ago))
        .unwrap()
}
fn period_counter(
    at: f64,
    expired: u64,
    complete: bool,
    entries: &[(chrono::NaiveDate, u64)],
) -> Value {
    let bytes = entries
        .iter()
        .fold(expired, |sum, (_, n)| sum.checked_add(*n).unwrap());
    json!({"contract":"socket-payload-utc-month-v1","bytes":bytes,"expired_bytes":expired,"periods":entries.iter().map(|(p,n)|json!({"period":p.to_string(),"bytes":n})).collect::<Vec<_>>(),"complete":complete,"in_flight":0,"observed":at,"boot_id":"test-boot"})
}
async fn send_periods(
    l: &Lab,
    node: &Value,
    e: &Value,
    sequence: i64,
    state: &str,
    value: Value,
) -> fenders_control_plane::error::Result<Value> {
    l.store.heartbeat(s(&node["id"]),json!({"boot_id":"test-boot","confinement":HOST_CONFINEMENT,"reports":[{"id":e["id"],"generation":e["generation"],"sequence":sequence,"state":state,"cpu_usec":0,"memory_bytes":0,"egress_periods":value}]})).await
}
async fn old_execution(l: &Lab, e: &Value) {
    sqlx::query("UPDATE executions SET created=now()-interval '3 years' WHERE id=$1")
        .bind(s(&e["id"]))
        .execute(&l.store.pool)
        .await
        .unwrap();
}

#[tokio::test]
async fn monthly_payload_attribution_is_idempotent_scoped_and_retained_after_terminal_report() {
    let l = Lab::new().await;
    let node = l.node("monthly").await;
    let op = l.create("monthly", json!({"artifact_id":l.artifact})).await;
    l.store.schedule().await.unwrap();
    let mut e = l.run(&op).await;
    old_execution(&l, &e).await;
    assert!(usage(&l).await["totals"]["egress_month_bytes"].is_null());
    let prior = period_month(1);
    let current = period_month(0);
    let at = sample_time();
    let old = prior.and_hms_opt(12, 0, 0).unwrap().and_utc().timestamp() as f64;
    send_periods(
        &l,
        &node,
        &e,
        1,
        "running",
        period_counter(old, 0, false, &[(prior, 40)]),
    )
    .await
    .unwrap();
    assert!(
        usage(&l).await["totals"]["egress_month_bytes"].is_null(),
        "a stale sample cannot prove current-month zero"
    );
    send_periods(
        &l,
        &node,
        &e,
        2,
        "running",
        period_counter(at, 0, false, &[(prior, 40), (current, 60)]),
    )
    .await
    .unwrap();
    let totals = usage(&l).await;
    assert_eq!(totals["totals"]["egress_month_bytes"], 60);
    assert_eq!(totals["totals"]["egress_unassigned_bytes"], 0);
    send_periods(
        &l,
        &node,
        &e,
        2,
        "running",
        period_counter(at, 0, false, &[(prior, 40), (current, 600)]),
    )
    .await
    .unwrap();
    send_periods(
        &l,
        &node,
        &e,
        3,
        "running",
        period_counter(old, 0, false, &[(prior, 900)]),
    )
    .await
    .unwrap();
    assert_eq!(usage(&l).await["totals"]["egress_month_bytes"], 60);
    let foreign = l.node("foreign-meter").await;
    send_periods(
        &l,
        &foreign,
        &e,
        4,
        "running",
        period_counter(at + 0.01, 0, false, &[(prior, 40), (current, 900)]),
    )
    .await
    .unwrap();
    assert_eq!(usage(&l).await["totals"]["egress_month_bytes"], 60);
    sqlx::query("UPDATE executions SET generation=generation+1 WHERE id=$1")
        .bind(s(&e["id"]))
        .execute(&l.store.pool)
        .await
        .unwrap();
    send_periods(
        &l,
        &node,
        &e,
        4,
        "running",
        period_counter(at + 0.01, 0, false, &[(prior, 40), (current, 900)]),
    )
    .await
    .unwrap();
    assert_eq!(usage(&l).await["totals"]["egress_month_bytes"], 60);
    e["generation"] = json!(e["generation"].as_i64().unwrap() + 1);
    send_periods(
        &l,
        &node,
        &e,
        4,
        "exited",
        period_counter(at + 0.02, 0, true, &[(prior, 40), (current, 110)]),
    )
    .await
    .unwrap();
    let result = usage(&l).await;
    assert_eq!(result["totals"]["egress_month_bytes"], 110);
    assert_eq!(result["totals"]["egress_month_complete"], 1);
    assert_eq!(result["totals"]["reserved_instances"], 0);
    let project = l
        .store
        .usage(&l.operator, &l.tenant, Some(&l.project))
        .await
        .unwrap();
    assert_eq!(project["totals"]["egress_month_bytes"], 110);
    let reopened = Store::from_pool(l.store.pool.clone(), l.root.path()).unwrap();
    assert_eq!(
        reopened.usage(&l.operator, &l.tenant, None).await.unwrap()["totals"]["egress_month_bytes"],
        110
    );
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM execution_egress_periods")
        .fetch_one(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(rows, 2);
    l.finish().await;
}

#[tokio::test]
async fn monthly_expiration_preserves_known_history_and_never_charges_missing_detail_to_now() {
    let l = Lab::new().await;
    let node = l.node("monthly-expiry").await;
    let op = l.create("monthly", json!({"artifact_id":l.artifact})).await;
    l.store.schedule().await.unwrap();
    let e = l.run(&op).await;
    old_execution(&l, &e).await;
    let ancient = period_month(24);
    let current = period_month(0);
    let at = sample_time();
    let old = ancient.and_hms_opt(12, 0, 0).unwrap().and_utc().timestamp() as f64;
    send_periods(
        &l,
        &node,
        &e,
        1,
        "running",
        period_counter(old, 0, false, &[(ancient, 5)]),
    )
    .await
    .unwrap();
    send_periods(
        &l,
        &node,
        &e,
        2,
        "running",
        period_counter(at, 15, false, &[(current, 95)]),
    )
    .await
    .unwrap();
    let result = usage(&l).await;
    assert_eq!(result["totals"]["egress_month_bytes"], 95);
    assert_eq!(
        result["totals"]["egress_unassigned_bytes"], 10,
        "five expired bytes already retain their known month"
    );
    // Attempts to relocate bytes between months freeze evidence rather than
    // independently maximizing each bucket into an inflated total.
    let previous = period_month(1);
    send_periods(
        &l,
        &node,
        &e,
        3,
        "running",
        period_counter(at + 0.01, 15, false, &[(previous, 45), (current, 50)]),
    )
    .await
    .unwrap();
    assert_eq!(usage(&l).await["totals"]["egress_month_bytes"], 95);
    assert_eq!(
        usage(&l).await["totals"]["egress_period_discontinuities"],
        1
    );
    send_periods(
        &l,
        &node,
        &e,
        4,
        "exited",
        period_counter(at + 0.02, 15, true, &[(current, 1000)]),
    )
    .await
    .unwrap();
    assert_eq!(usage(&l).await["totals"]["egress_month_bytes"], 95);
    assert_eq!(usage(&l).await["totals"]["egress_month_complete"], 0);
    l.finish().await;
}

#[tokio::test]
async fn monthly_reports_support_unsigned_totals_and_roll_back_with_late_report_failure() {
    let l = Lab::new().await;
    let node = l.node("monthly-rollback").await;
    let op = l.create("monthly", json!({"artifact_id":l.artifact})).await;
    l.store.schedule().await.unwrap();
    let e = l.run(&op).await;
    let current = period_month(0);
    let at = sample_time();
    let value = period_counter(at, 0, false, &[]);
    send_periods(&l, &node, &e, 1, "running", value.clone())
        .await
        .unwrap();
    assert_eq!(usage(&l).await["totals"]["egress_month_bytes"], 0);
    let value = period_counter(at + 0.01, 0, false, &[(current, u64::MAX)]);
    let invalid=l.store.heartbeat(s(&node["id"]),json!({"boot_id":"test-boot","confinement":HOST_CONFINEMENT,"reports":[{"id":e["id"],"generation":e["generation"],"sequence":2,"state":"exited","cpu_usec":0,"memory_bytes":0,"reason":"x".repeat(257),"egress_periods":value}]})).await;
    assert!(invalid.is_err());
    assert_eq!(usage(&l).await["totals"]["egress_month_bytes"], 0);
    assert_eq!(usage(&l).await["totals"]["reserved_instances"], 1);
    send_periods(&l, &node, &e, 2, "running", value)
        .await
        .unwrap();
    assert_eq!(
        usage(&l).await["totals"]["egress_month_bytes"].as_u64(),
        Some(u64::MAX)
    );
    let mut bad = period_counter(at + 0.02, 0, false, &[(current, 1)]);
    bad["observed"] = json!(at + 1000.0);
    assert!(
        send_periods(&l, &node, &e, 3, "running", bad)
            .await
            .is_err()
    );
    assert_eq!(
        usage(&l).await["totals"]["egress_period_discontinuities"],
        0
    );
    l.finish().await;
}

#[tokio::test]
async fn monthly_concurrent_reports_converge_and_previous_terminal_sources_prove_current_zero() {
    let l = Lab::new().await;
    let node = l.node("monthly-race").await;
    let op = l
        .create("monthly-race", json!({"artifact_id":l.artifact}))
        .await;
    l.store.schedule().await.unwrap();
    let e = l.run(&op).await;
    let current = period_month(0);
    let at = sample_time();
    send_periods(
        &l,
        &node,
        &e,
        1,
        "running",
        period_counter(at, 0, false, &[]),
    )
    .await
    .unwrap();
    let (a, b) = tokio::join!(
        send_periods(
            &l,
            &node,
            &e,
            2,
            "running",
            period_counter(at + 0.01, 0, false, &[(current, 10)])
        ),
        send_periods(
            &l,
            &node,
            &e,
            3,
            "running",
            period_counter(at + 0.02, 0, false, &[(current, 20)])
        )
    );
    a.unwrap();
    b.unwrap();
    assert_eq!(usage(&l).await["totals"]["egress_month_bytes"], 20);
    send_periods(
        &l,
        &node,
        &e,
        4,
        "exited",
        period_counter(at + 0.03, 0, true, &[(current, 20)]),
    )
    .await
    .unwrap();
    let op = l
        .create("previous-month", json!({"artifact_id":l.artifact}))
        .await;
    l.store.schedule().await.unwrap();
    let e = l.run(&op).await;
    old_execution(&l, &e).await;
    let previous = period_month(1);
    let then = previous
        .and_hms_opt(12, 0, 0)
        .unwrap()
        .and_utc()
        .timestamp() as f64;
    send_periods(
        &l,
        &node,
        &e,
        1,
        "exited",
        period_counter(then, 0, true, &[(previous, 7)]),
    )
    .await
    .unwrap();
    let total = usage(&l).await;
    assert_eq!(total["totals"]["egress_month_bytes"], 20);
    assert_eq!(total["totals"]["egress_month_measured"], 2);
    assert_eq!(total["totals"]["egress_month_complete"], 2);
    let rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM execution_egress_periods WHERE execution_id=$1 AND period=$2::date",
    )
    .bind(s(&e["id"]))
    .bind(current.to_string())
    .fetch_one(&l.store.pool)
    .await
    .unwrap();
    assert_eq!(
        rows, 0,
        "zero is inferred from confirmed termination, not a fabricated monthly report"
    );
    l.finish().await;
}

/// What a gateway session holds of a transfer allowance is held: it is in
/// the usage report as reserved, and nothing else may be given it. The
/// lease of a session that is gone is counted as used, conservatively.
#[tokio::test]
async fn a_gateways_lease_is_held_and_a_dead_gateways_is_charged_conservatively() {
    let l = Lab::new().await;
    let lease = |session: String, bytes: i64| {
        sqlx::query("INSERT INTO gateway_transfer_leases(session_id,tenant_id,project_id,period,held_bytes) VALUES($1,$2,$3,date_trunc('month',now() AT TIME ZONE 'UTC')::date,$4)")
            .bind(session)
            .bind(&l.tenant)
            .bind(&l.project)
            .bind(bytes)
            .execute(&l.store.pool)
    };
    // This process's session, alive, and one of a process that is gone.
    l.store.flush_gateway().await.unwrap();
    let (alive, dead) = (l.store.gateway.session().to_owned(), uid());
    sqlx::query(
        "INSERT INTO gateway_sessions(id,seen) VALUES($1,clock_timestamp()-interval '1 minute')",
    )
    .bind(&dead)
    .execute(&l.store.pool)
    .await
    .unwrap();
    lease(alive.clone(), 3000).await.unwrap();
    lease(dead.clone(), 700).await.unwrap();
    // And one whose session has no row at all.
    lease(uid(), 50).await.unwrap();

    let before = usage(&l).await;
    let allowance = &before["transfer_allowance"];
    assert_eq!(allowance["reserved_bytes"], 3750);
    assert_eq!(allowance["bytes"], 0);
    assert_eq!(before["totals"]["ingress_reserved_bytes"], 3750);

    l.store.schedule().await.unwrap();
    let after = usage(&l).await;
    let allowance = &after["transfer_allowance"];
    assert_eq!(allowance["reserved_bytes"], 3000, "the live lease is kept");
    assert_eq!(allowance["bytes"], 750, "what the dead held is used");
    assert_eq!(allowance["gateway_conservative_bytes"], 750);
    assert_eq!(after["ingress_month"]["bytes"], 750);
    assert_eq!(after["ingress_month"]["requests"], 0);
    let sessions: Vec<String> = sqlx::query_scalar("SELECT id FROM gateway_sessions")
        .fetch_all(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(sessions, vec![alive]);
    // Settled once: another pass charges nothing more.
    l.store.schedule().await.unwrap();
    assert_eq!(usage(&l).await["transfer_allowance"]["bytes"], 750);
    l.finish().await;
}
