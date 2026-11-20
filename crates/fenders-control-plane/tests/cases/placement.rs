use super::*;

#[tokio::test]
async fn placement_observations_are_scoped_fresh_and_hidden_after_assignment_or_fencing() {
    let l = Lab::new().await;
    let node = l.node("worker").await;
    approve_component(&l, &node, true, true).await;
    l.store
        .node_mode(&l.operator, s(&node["id"]), json!({"draining":true}))
        .await
        .unwrap();
    let op = l
        .deploy("placement", true, false, "placement")
        .await
        .unwrap();
    let app = s(&op["resource_id"]);
    l.store.schedule().await.unwrap();
    let (viewer, _) = l.credential("viewer", Some(&l.project)).await;
    let value = l
        .store
        .app(&viewer, &l.tenant, &l.project, app)
        .await
        .unwrap();
    let placement = &value["http"]["placement"];
    assert_eq!(placement["reason"], "placement-no-worker");
    assert!(placement["observed_at"].is_string());
    assert_eq!(placement.as_object().unwrap().len(), 2);
    assert!(!placement.to_string().contains(s(&node["id"])));
    assert_eq!(l.http(app).await["placement"], *placement);
    assert_eq!(
        l.store
            .apps(&viewer, &l.tenant, &l.project, Default::default())
            .await
            .unwrap()["items"][0]["http"]["placement"],
        *placement
    );
    assert!(l.store.app(&viewer, &uid(), &l.project, app).await.is_err());
    let execution = s(&value["http"]["execution_id"]);
    let before = l.execution(execution).await;
    l.store.schedule().await.unwrap();
    assert_eq!(
        l.http(app).await["placement"],
        *placement,
        "stable decisions are sampled rather than written per heartbeat"
    );
    assert_eq!(l.execution(execution).await, before);
    sqlx::query("UPDATE execution_placement SET observed_at=now()-interval '1 minute' WHERE execution_id=$1").bind(execution).execute(&l.store.pool).await.unwrap();
    l.store.schedule().await.unwrap();
    assert_ne!(
        l.http(app).await["placement"]["observed_at"],
        placement["observed_at"]
    );
    sqlx::query(
        "UPDATE nodes SET draining=false,observed_confinement=NULL,last_seen=now() WHERE id=$1",
    )
    .bind(s(&node["id"]))
    .execute(&l.store.pool)
    .await
    .unwrap();
    l.store.schedule().await.unwrap();
    assert_eq!(
        l.http(app).await["placement"]["reason"],
        "placement-confinement"
    );
    sqlx::query(
        "UPDATE nodes SET observed_confinement=$2,memory_mib=64,last_seen=now() WHERE id=$1",
    )
    .bind(s(&node["id"]))
    .bind(HOST_CONFINEMENT)
    .execute(&l.store.pool)
    .await
    .unwrap();
    l.store.schedule().await.unwrap();
    assert_eq!(l.http(app).await["placement"]["reason"], "placement-size");
    let reopened = Store::from_pool(l.store.pool.clone(), l.root.path()).unwrap();
    reopened.migrate().await.unwrap();
    assert_eq!(
        reopened
            .app(&viewer, &l.tenant, &l.project, app)
            .await
            .unwrap()["http"]["placement"]["reason"],
        "placement-size"
    );
    sqlx::query("UPDATE executions SET generation=generation+1 WHERE id=$1")
        .bind(execution)
        .execute(&l.store.pool)
        .await
        .unwrap();
    assert!(
        l.http(app).await["placement"].is_null(),
        "old generation decisions are hidden"
    );
    l.store.schedule().await.unwrap();
    assert_eq!(l.http(app).await["placement"]["reason"], "placement-size");
    sqlx::query("UPDATE nodes SET memory_mib=128,last_seen=now() WHERE id=$1")
        .bind(s(&node["id"]))
        .execute(&l.store.pool)
        .await
        .unwrap();
    l.store.schedule().await.unwrap();
    assert_eq!(l.execution(execution).await["node_id"], node["id"]);
    assert!(
        l.http(app).await["placement"].is_null(),
        "assignment immediately hides old decisions, even before HTTP reconciliation"
    );
    l.finish().await;
}

#[tokio::test]
async fn occupied_capacity_explains_queued_commands_without_changing_admission() {
    let l = Lab::new().await;
    let node = l.node("worker").await;
    approve_component(&l, &node, true, true).await;
    let occupied = l
        .create("occupant", json!({"artifact_id":l.artifact}))
        .await;
    l.store.schedule().await.unwrap();
    let occupied = l.run(&occupied).await;
    let deployed = l.deploy("queued", false, true, "queued").await.unwrap();
    let app = s(&deployed["resource_id"]);
    let op = l
        .store
        .run_app(&l.operator, &l.tenant, &l.project, app, "queued-run")
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
            s(&op["resource_id"]),
        )
        .await
        .unwrap();
    assert_eq!(run["placement"]["reason"], "placement-capacity");
    assert_eq!(run["state"], "queued");
    assert_eq!(run["reserved"], true);
    assert!(
        run["diagnostic"]["summary"]
            .as_str()
            .unwrap()
            .contains("occupied")
    );
    assert_eq!(
        l.store
            .app(&l.operator, &l.tenant, &l.project, app)
            .await
            .unwrap()["latest_run"]["placement"],
        run["placement"]
    );
    assert_eq!(
        l.store
            .app_history(
                &l.operator,
                &l.tenant,
                &l.project,
                app,
                "runs",
                Default::default()
            )
            .await
            .unwrap()["items"][0]["placement"],
        run["placement"]
    );
    // A more weakly qualified spare cannot make the explanation blame security
    // when an otherwise qualified worker is simply occupied.
    let spare = l.node("unqualified").await;
    sqlx::query("UPDATE nodes SET observed_confinement=NULL WHERE id=$1")
        .bind(s(&spare["id"]))
        .execute(&l.store.pool)
        .await
        .unwrap();
    l.store.schedule().await.unwrap();
    assert_eq!(
        l.store
            .app_run(
                &l.operator,
                &l.tenant,
                &l.project,
                app,
                s(&op["resource_id"])
            )
            .await
            .unwrap()["placement"]["reason"],
        "placement-capacity"
    );
    l.report(&node, &occupied, "exited", 1).await;
    l.store.schedule().await.unwrap();
    let assigned = l
        .store
        .app_run(
            &l.operator,
            &l.tenant,
            &l.project,
            app,
            s(&op["resource_id"]),
        )
        .await
        .unwrap();
    assert_eq!(assigned["state"], "starting");
    assert!(assigned["placement"].is_null());
    assert_eq!(
        l.execution(s(&run["execution_id"])).await["node_id"],
        node["id"]
    );
    l.finish().await;
}

#[tokio::test]
async fn a_nodes_declared_capacity_is_changed_and_placement_counts_it() {
    let l = Lab::new().await;
    // The lab's node holds one execution: 100% CPU, 128 MiB, one instance.
    let node = l.node("overcommitted").await;
    approve_component(&l, &node, true, true).await;
    let first =
        s(&l.deploy("first", true, false, "first").await.unwrap()["resource_id"]).to_owned();
    let second =
        s(&l.deploy("second", true, false, "second").await.unwrap()["resource_id"]).to_owned();
    l.store.schedule().await.unwrap();
    let placed = || async {
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM executions WHERE reserved AND node_id IS NOT NULL",
        )
        .fetch_one(&l.store.pool)
        .await
        .unwrap()
    };
    assert_eq!(placed().await, 1);
    for bad in [
        json!({"cpu_percent":0}),
        json!({"memory_mib":"lots"}),
        json!({"instances":100001}),
    ] {
        assert_eq!(
            l.store
                .node_mode(&l.operator, s(&node["id"]), bad)
                .await
                .unwrap_err()
                .status,
            StatusCode::BAD_REQUEST
        );
    }
    // Declared with twice the CPU, memory and instances: the second fits.
    l.store
        .node_mode(
            &l.operator,
            s(&node["id"]),
            json!({"cpu_percent":200,"memory_mib":256,"instances":2}),
        )
        .await
        .unwrap();
    l.store.schedule().await.unwrap();
    assert_eq!(placed().await, 2);
    for app in [&first, &second] {
        assert!(!l.http(app).await["execution_id"].is_null());
    }
    // Lowered below what is placed: nothing is stopped.
    l.store
        .node_mode(&l.operator, s(&node["id"]), json!({"cpu_percent":50}))
        .await
        .unwrap();
    l.store.schedule().await.unwrap();
    assert_eq!(placed().await, 2);
    l.finish().await;
}
