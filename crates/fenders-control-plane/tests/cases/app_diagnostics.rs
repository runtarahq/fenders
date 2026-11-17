use super::*;
#[tokio::test]
async fn real_rollout_failure_and_uncertain_command_have_consistent_read_only_guidance() {
    let l = Lab::new().await;
    let node = l.node("worker").await;
    approve_component(&l, &node, true, true).await;
    let op = l.deploy("timeout", true, false, "timeout").await.unwrap();
    let app = s(&op["resource_id"]);
    sqlx::query("UPDATE app_http SET ready_until=now()-interval '1 second' WHERE app_id=$1")
        .bind(app)
        .execute(&l.store.pool)
        .await
        .unwrap();
    l.store.schedule().await.unwrap();
    let value = l
        .store
        .app(&l.operator, &l.tenant, &l.project, app)
        .await
        .unwrap();
    assert_eq!(value["state"], "failed");
    assert_eq!(value["target_release"]["reason"], "http-readiness-timeout");
    let diagnostic = &value["target_release"]["diagnostic"];
    assert!(diagnostic["summary"].as_str().unwrap().contains("deadline"));
    assert_eq!(diagnostic, &value["http"]["diagnostic"]);
    assert_eq!(l.http(app).await["diagnostic"], *diagnostic);
    let release = s(&value["target_release"]["id"]);
    assert_eq!(
        l.store
            .app_release(&l.operator, &l.tenant, &l.project, app, release)
            .await
            .unwrap()["diagnostic"],
        *diagnostic
    );
    assert_eq!(
        l.store
            .app_history(
                &l.operator,
                &l.tenant,
                &l.project,
                app,
                "releases",
                Default::default()
            )
            .await
            .unwrap()["items"][0]["diagnostic"],
        *diagnostic
    );
    // The Versions view carries the failed rollout as that code's latest deployment.
    let version = s(&value["target_release"]["version_id"]);
    let code = l
        .store
        .app_version(&l.operator, &l.tenant, &l.project, app, version)
        .await
        .unwrap();
    assert_eq!(code["last_release"]["id"], release);
    assert_eq!(code["last_release"]["state"], "failed");
    assert_eq!(code["last_release"]["diagnostic"], *diagnostic);
    let versions = l
        .store
        .app_versions(&l.operator, &l.tenant, &l.project, app, None)
        .await
        .unwrap();
    assert_eq!(versions["items"][0], code);
    let (viewer, _) = l.credential("viewer", Some(&l.project)).await;
    assert_eq!(
        l.store
            .app(&viewer, &l.tenant, &l.project, app)
            .await
            .unwrap()["http"]["diagnostic"],
        *diagnostic
    );
    let listed = l
        .store
        .apps(&viewer, &l.tenant, &l.project, Default::default())
        .await
        .unwrap();
    assert_eq!(listed["items"][0]["http"]["diagnostic"], *diagnostic);
    assert_eq!(
        l.store
            .app(&viewer, &uid(), &l.project, app)
            .await
            .unwrap_err()
            .status,
        StatusCode::NOT_FOUND
    );
    let command = l
        .deploy("uncertain", false, true, "uncertain")
        .await
        .unwrap();
    let command = s(&command["resource_id"]);
    let run = l
        .store
        .run_app(&l.operator, &l.tenant, &l.project, command, "one-run")
        .await
        .unwrap();
    let run = s(&run["resource_id"]);
    let value = l
        .store
        .app_run(&l.operator, &l.tenant, &l.project, command, run)
        .await
        .unwrap();
    sqlx::query("UPDATE executions SET state='failed',observation='{\"reason\":\"worker-lost\"}' WHERE id=$1").bind(s(&value["execution_id"])).execute(&l.store.pool).await.unwrap();
    let value = l
        .store
        .app_run(&l.operator, &l.tenant, &l.project, command, run)
        .await
        .unwrap();
    assert_eq!(value["state"], "unknown");
    assert_eq!(value["reserved"], true);
    assert!(value["exit_code"].is_null());
    assert!(
        value["diagnostic"]["detail"]
            .as_str()
            .unwrap()
            .contains("not replay")
    );
    assert_eq!(
        l.store
            .app(&viewer, &l.tenant, &l.project, command)
            .await
            .unwrap()["latest_run"]["diagnostic"],
        value["diagnostic"]
    );
    assert_eq!(
        l.store
            .app_history(
                &viewer,
                &l.tenant,
                &l.project,
                command,
                "runs",
                Default::default()
            )
            .await
            .unwrap()["items"][0]["diagnostic"],
        value["diagnostic"]
    );
    assert_eq!(
        l.store
            .app_history(
                &viewer,
                &l.tenant,
                &l.project,
                command,
                "runs",
                Default::default()
            )
            .await
            .unwrap()["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        l.execution(s(&value["execution_id"])).await["reserved"],
        true
    );
    sqlx::query("UPDATE executions SET observation='{\"reason\":\"worker-lost\",\"exit_code\":7}' WHERE id=$1")
        .bind(s(&value["execution_id"])).execute(&l.store.pool).await.unwrap();
    let known = l
        .store
        .app_run(&viewer, &l.tenant, &l.project, command, run)
        .await
        .unwrap();
    assert_eq!(known["state"], "failed");
    assert!(
        known["diagnostic"]["summary"]
            .as_str()
            .unwrap()
            .contains("result was recorded")
    );
    sqlx::query("UPDATE executions SET observation='{\"exit_code\":7}' WHERE id=$1")
        .bind(s(&value["execution_id"]))
        .execute(&l.store.pool)
        .await
        .unwrap();
    let known = l
        .store
        .app_run(&viewer, &l.tenant, &l.project, command, run)
        .await
        .unwrap();
    assert!(
        known["diagnostic"]["summary"]
            .as_str()
            .unwrap()
            .contains("non-zero exit status")
    );
}
