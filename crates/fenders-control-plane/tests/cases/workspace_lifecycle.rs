//! A workspace suspended and resumed by the operator, and the operator's
//! own credential.
use super::*;

/// The operator's action on a workspace; the workspace is the path's.
async fn workspace_action(l: &Lab, input: &Value) -> (StatusCode, Value) {
    let mut body = input.clone();
    let tenant = body.as_object_mut().unwrap().remove("id").unwrap();
    // The request's key is its Idempotency-Key header.
    let key = body.as_object_mut().unwrap().remove("request_key").unwrap();
    let response = api::router(l.store.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/workspaces/{}/lifecycle", s(&tenant)))
                .header("Authorization", format!("Bearer {}", l.token))
                .header("Idempotency-Key", s(&key))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let mut value: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 8192).await.unwrap()).unwrap();
    // Each refusal names its own request.
    if let Some(v) = value.as_object_mut() {
        v.remove("request_id");
    }
    (status, value)
}
#[tokio::test]
async fn suspension_is_atomic_and_concurrent_retries_share_the_audit_receipt() {
    let l = Lab::new().await;
    let input = json!({"id":l.tenant,"request_key":uid(),"action":"suspend","reason":"Private trial suspension","expected_revision":1});
    // A tenant's key does not suspend its workspace, or resume it.
    let (_, key) = l.credential("owner", None).await;
    let refused = api::router(l.store.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/workspaces/{}/lifecycle", l.tenant))
                .header("Authorization", format!("Bearer {}", s(&key["token"])))
                .header("content-type", "application/json")
                .header("Idempotency-Key", uid())
                .body(Body::from(
                    json!({"action":"suspend","reason":"mine","expected_revision":1}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    sqlx::raw_sql("CREATE FUNCTION deny_suspend_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='operator.suspend' THEN RAISE EXCEPTION 'fixture audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER deny_suspend_audit BEFORE INSERT ON audit FOR EACH ROW EXECUTE FUNCTION deny_suspend_audit();").execute(&l.store.pool).await.unwrap();
    assert_eq!(
        workspace_action(&l, &input).await.0,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    let state: String = sqlx::query_scalar("SELECT lifecycle_state FROM tenants WHERE id=$1")
        .bind(&l.tenant)
        .fetch_one(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(state, "active");
    let receipts: i64 = sqlx::query_scalar("SELECT count(*) FROM operator_request_receipts")
        .fetch_one(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(receipts, 0);
    sqlx::query("DROP TRIGGER deny_suspend_audit ON audit")
        .execute(&l.store.pool)
        .await
        .unwrap();
    let (first, second) = tokio::join!(workspace_action(&l, &input), workspace_action(&l, &input));
    assert_eq!(first.0, StatusCode::OK);
    assert_eq!(first, second);
    assert_eq!(first.1["status"], "suspended");
    assert_eq!(first.1["revision"], 3);
    let audits: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit WHERE action='operator.suspend'")
            .fetch_one(&l.store.pool)
            .await
            .unwrap();
    assert_eq!(audits, 1);
    let mut stale = input.clone();
    stale["action"] = json!("resume");
    assert_eq!(workspace_action(&l, &stale).await.0, StatusCode::CONFLICT);
    stale["request_key"] = json!(uid());
    assert_eq!(workspace_action(&l, &stale).await.0, StatusCode::CONFLICT);
    stale["expected_revision"] = json!(3);
    assert_eq!(workspace_action(&l, &stale).await.0, StatusCode::OK);
    assert_eq!(
        workspace_action(&l, &input).await,
        first,
        "old receipt never reapplies suspension after resume"
    );
    l.finish().await;
}
#[tokio::test]
async fn suspension_fences_admission_retains_unknown_work_and_resumes_without_replay() {
    use fenders_control_plane::apps::AppSubmission;
    let l = Lab::new().await;
    let first = l.node("http-worker").await;
    let second = l.node("command-worker").await;
    approve_component(&l, &first, true, true).await;
    let mut ids = Vec::new();
    for (name, http, schedule) in [
        ("web", true, false),
        ("command", false, false),
        ("clock", false, true),
    ] {
        let op=l.store.deploy_app(&l.operator,&l.tenant,&l.project,AppSubmission{value:json!({"name":name,"artifact_id":l.artifact,"triggers":{"manual":true,"http":http,"schedule":{"enabled":schedule,"expression":"* * * * *","timezone":"UTC"}}}),key:name,domain:"apps.test"}).await.unwrap();
        ids.push(s(&op["resource_id"]).to_owned());
    }
    l.store.schedule().await.unwrap();
    let web = l.execution(s(&l.http(&ids[0]).await["execution_id"])).await;
    let web_node = if web["node_id"] == first["id"] {
        &first
    } else {
        &second
    };
    let command_node = if web_node["id"] == first["id"] {
        &second
    } else {
        &first
    };
    l.report(web_node, &web, "running", 1).await;
    let host = format!("app-{}.apps.test", ids[0]);
    let (_, lease) = l.store.ingress_start(&host, 0).await.unwrap();
    l.store.ingress_finish(&lease, Some(0)).await.unwrap();
    let run = l
        .store
        .run_app(
            &l.operator,
            &l.tenant,
            &l.project,
            &ids[1],
            "explicit-before-suspend",
        )
        .await
        .unwrap();
    l.store.schedule().await.unwrap();
    let command_id: String = sqlx::query_scalar("SELECT execution_id FROM app_runs WHERE id=$1")
        .bind(s(&run["resource_id"]))
        .fetch_one(&l.store.pool)
        .await
        .unwrap();
    let command = l.execution(&command_id).await;
    assert_eq!(command["node_id"], command_node["id"]);
    l.report(command_node, &command, "running", 1).await;
    // Claim a due occurrence but do not dispatch it; suspend must cancel it.
    sqlx::query("UPDATE app_schedules SET next_at=date_trunc('minute',now()) WHERE app_id=$1")
        .bind(&ids[2])
        .execute(&l.store.pool)
        .await
        .unwrap();
    l.store.claim_schedule_occurrences().await.unwrap();
    let input = json!({"id":l.tenant,"request_key":uid(),"action":"suspend","reason":"Acceptance suspension","expected_revision":1});
    let response = workspace_action(&l, &input).await;
    assert_eq!(response.0, StatusCode::OK, "{response:?}");
    assert_eq!(response.1["status"], "suspending");
    assert_eq!(workspace_action(&l, &input).await, response);
    let stopped_command = l.execution(s(&command["id"])).await;
    assert_eq!(stopped_command["desired"], "stopped");
    assert_eq!(stopped_command["reserved"], true);
    assert_eq!(stopped_command["generation"], n(&command["generation"]) + 1);
    assert!(
        l.store
            .assignment(
                s(&command_node["id"]),
                s(&command["id"]),
                n(&command["generation"])
            )
            .await
            .is_err(),
        "old dispatch cannot fetch launch configuration"
    );
    let stop = l
        .store
        .assignment(
            s(&command_node["id"]),
            s(&command["id"]),
            n(&stopped_command["generation"]),
        )
        .await
        .unwrap();
    assert_eq!(stop["desired"], "stopped");
    assert!(stop["spec"].is_null());
    let (owner, _) = l.credential("owner", None).await;
    assert!(
        l.store
            .app(&owner, &l.tenant, &l.project, &ids[0])
            .await
            .is_ok(),
        "customer can read retained data"
    );
    assert_eq!(
        l.store
            .create_project(
                &owner,
                &l.tenant,
                Named {
                    name: "blocked".into()
                }
            )
            .await
            .unwrap_err()
            .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        l.store
            .run_app(
                &owner,
                &l.tenant,
                &l.project,
                &ids[1],
                "denied-while-suspended"
            )
            .await
            .unwrap_err()
            .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        l.store
            .upload(&owner, &l.tenant, &l.project, b"\0asm\x0d\0\x01\0")
            .await
            .unwrap_err()
            .status,
        StatusCode::FORBIDDEN
    );
    assert!(l.store.ingress_start(&host, 0).await.is_err());
    assert!(l.store.ingress_begin(&host, 0, true).await.is_err());
    l.store.dispatch_schedule_runs().await.unwrap();
    let pending: i64 =
        sqlx::query_scalar("SELECT count(*) FROM app_run_dispatch WHERE state='pending'")
            .fetch_one(&l.store.pool)
            .await
            .unwrap();
    assert_eq!(pending, 0);
    // Timeout, stale stop report and current-generation action failure must not
    // release a reservation or reopen admission.
    sqlx::query("UPDATE nodes SET last_seen=now()-interval '1 minute' WHERE id=$1")
        .bind(s(&command_node["id"]))
        .execute(&l.store.pool)
        .await
        .unwrap();
    l.report(web_node, &l.execution(s(&web["id"])).await, "stopped", 2)
        .await;
    l.store.schedule().await.unwrap();
    l.report(command_node, &command, "stopped", 2).await;
    assert_eq!(l.execution(s(&command["id"])).await["reserved"], true);
    let resume = json!({"id":l.tenant,"request_key":uid(),"action":"resume","reason":"Resume accepted workspace","expected_revision":2});
    assert_eq!(workspace_action(&l, &resume).await.0, StatusCode::CONFLICT);
    let state: String = sqlx::query_scalar("SELECT lifecycle_state FROM tenants WHERE id=$1")
        .bind(&l.tenant)
        .fetch_one(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(state, "suspending");
    l.store.heartbeat(s(&command_node["id"]),json!({"boot_id":"test-boot","confinement":HOST_CONFINEMENT,"reports":[{"id":command["id"],"generation":stopped_command["generation"],"state":"running","sequence":2,"cpu_usec":12,"memory_bytes":512,"action_error":"control-unavailable"}]})).await.unwrap();
    let retry_stop = l.execution(s(&command["id"])).await;
    assert_eq!(retry_stop["desired"], "stopped");
    assert_eq!(retry_stop["reserved"], true);
    assert_eq!(
        n(&retry_stop["generation"]),
        n(&stopped_command["generation"]) + 1
    );
    l.report(command_node, &retry_stop, "stopped", 3).await;
    let state: String = sqlx::query_scalar("SELECT lifecycle_state FROM tenants WHERE id=$1")
        .bind(&l.tenant)
        .fetch_one(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(state, "suspended");
    let mut resume = resume;
    resume["expected_revision"] = json!(3);
    assert_eq!(workspace_action(&l, &resume).await.0, StatusCode::OK);
    l.store.schedule().await.unwrap();
    let commands: i64 =
        sqlx::query_scalar("SELECT count(*) FROM executions WHERE spec->>'mode'='command'")
            .fetch_one(&l.store.pool)
            .await
            .unwrap();
    assert_eq!(commands, 1, "resume cannot invoke or replay a command");
    let future: bool =
        sqlx::query_scalar("SELECT next_at>now() FROM app_schedules WHERE app_id=$1")
            .bind(&ids[2])
            .fetch_one(&l.store.pool)
            .await
            .unwrap();
    assert!(future, "resume advances the clock beyond missed ticks");
    assert_ne!(
        l.http(&ids[0]).await["execution_id"],
        web["id"],
        "enabled HTTP gets a new fenced execution"
    );
    assert!(
        l.store
            .create_project(
                &owner,
                &l.tenant,
                Named {
                    name: "after-resume".into()
                }
            )
            .await
            .is_ok()
    );
    l.finish().await;
}

/// The operator credential is the one in the state directory's file: it does
/// not lapse while it is, and replacing the file ends the one before it.
#[tokio::test]
async fn the_operator_credential_is_the_files_and_replacing_the_file_ends_the_old_one() {
    let l = Lab::new().await;
    let path = l.store.bootstrap().await.unwrap();
    let first = std::fs::read_to_string(&path).unwrap();
    assert_eq!(first, l.token);
    // As a control plane first started more than thirty days ago had it.
    sqlx::query("UPDATE credentials SET expires=now()-interval '1 day' WHERE role='operator'")
        .execute(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(
        l.store.authenticate(&first).await.unwrap_err().status,
        StatusCode::UNAUTHORIZED
    );
    // The next start makes it valid again, and it stays valid.
    l.store.bootstrap().await.unwrap();
    assert!(l.store.authenticate(&first).await.is_ok());
    let lapses: bool = sqlx::query_scalar(
        "SELECT bool_or(expires<'infinity') FROM credentials WHERE role='operator' AND NOT revoked",
    )
    .fetch_one(&l.store.pool)
    .await
    .unwrap();
    assert!(!lapses);

    // Replaced: a new credential, and the old one is refused.
    std::fs::remove_file(&path).unwrap();
    let second = std::fs::read_to_string(l.store.bootstrap().await.unwrap()).unwrap();
    assert_ne!(second, first);
    assert!(l.store.authenticate(&second).await.is_ok());
    assert_eq!(
        l.store.authenticate(&first).await.unwrap_err().status,
        StatusCode::UNAUTHORIZED
    );
    // One that was revoked is not revived by a start, whatever the file says.
    sqlx::query("UPDATE credentials SET revoked=true WHERE role='operator'")
        .execute(&l.store.pool)
        .await
        .unwrap();
    l.store.bootstrap().await.unwrap();
    assert_eq!(
        l.store.authenticate(&second).await.unwrap_err().status,
        StatusCode::UNAUTHORIZED
    );
    l.finish().await;
}

async fn lifecycle(l: &Lab, key: Option<&str>, body: Value) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method("POST")
        .uri(format!("/v1/workspaces/{}/lifecycle", l.tenant))
        .header("Authorization", format!("Bearer {}", l.token))
        .header("content-type", "application/json");
    if let Some(key) = key {
        request = request.header("Idempotency-Key", key);
    }
    let response = api::router(l.store.clone())
        .oneshot(request.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let mut value: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 8192).await.unwrap()).unwrap();
    if let Some(v) = value.as_object_mut() {
        v.remove("request_id");
    }
    (status, value)
}

#[tokio::test]
async fn a_suspension_takes_its_key_from_the_header_as_every_change_does() {
    let l = Lab::new().await;
    let suspend = json!({"action":"suspend","reason":"Unpaid","expected_revision":1});
    // Any key a caller might choose, not only 32 hex digits.
    let first = lifecycle(&l, Some("suspend acme/2026-11"), suspend.clone()).await;
    assert_eq!(first.0, StatusCode::OK, "{}", first.1);
    assert_eq!(first.1["status"], "suspended");
    // The retry is the first answer, though the revision it expects has passed.
    assert_eq!(
        lifecycle(&l, Some("suspend acme/2026-11"), suspend.clone()).await,
        first
    );
    let mut other = suspend.clone();
    other["reason"] = json!("Another reason");
    assert_eq!(
        lifecycle(&l, Some("suspend acme/2026-11"), other).await.0,
        StatusCode::CONFLICT
    );
    // No key at all is a request to make again, and says so: not a 404.
    let keyless = lifecycle(&l, None, suspend.clone()).await;
    assert_eq!(keyless.0, StatusCode::BAD_REQUEST, "{}", keyless.1);
    assert!(s(&keyless.1["error"]).contains("Idempotency-Key"));

    let resume = json!({"action":"resume","reason":"Paid","expected_revision":first.1["revision"]});
    // The key was once sent in the body. It is the header's alone now: a
    // body that names one is malformed, and changes nothing.
    let mut in_body = resume.clone();
    in_body["request_key"] = json!("resume-1");
    for header in [None, Some("resume-1")] {
        let refused = lifecycle(&l, header, in_body.clone()).await;
        assert_eq!(refused.0, StatusCode::BAD_REQUEST, "{}", refused.1);
    }
    let resumed = lifecycle(&l, Some("resume-1"), resume.clone()).await;
    assert_eq!(resumed.0, StatusCode::OK, "{}", resumed.1);
    assert_eq!(resumed.1["status"], "active");
    assert_eq!(lifecycle(&l, Some("resume-1"), resume).await, resumed);
    let receipts: i64 = sqlx::query_scalar("SELECT count(*) FROM operator_request_receipts")
        .fetch_one(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(receipts, 2);
    l.finish().await;
}
