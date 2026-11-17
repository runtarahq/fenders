use super::*;
use fenders_control_plane::{operator_api, transport::PeerIdentity};

#[tokio::test]
async fn private_operator_reads_are_bounded_and_absent_from_customer_and_worker_routers() {
    let lab = Lab::new().await;
    let pin = digest("independent-operator-service");
    let bridge = operator_api::router(lab.store.clone(), pin.clone()).unwrap();
    let request = |path: &str, body: Value, peer: Option<&str>| {
        let mut req = Request::builder()
            .method("POST")
            .uri(path)
            .header("X-Fenders-Operator", "a".repeat(32))
            .body(Body::from(body.to_string()))
            .unwrap();
        if let Some(peer) = peer {
            req.extensions_mut().insert(PeerIdentity(Some(peer.into())));
        }
        req
    };
    let list = "/operator/v1/workspaces.list";
    let input = json!({"q":"alpha","offset":0,"limit":25});
    for peer in [None, Some("worker-pin"), Some("arbitrary-certificate")] {
        let response = bridge
            .clone()
            .oneshot(request(list, input.clone(), peer))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    for forbidden in ["authorization", "cookie"] {
        let mut req = request(list, input.clone(), Some(&pin));
        req.headers_mut()
            .insert(forbidden, "customer-credential".parse().unwrap());
        assert_eq!(
            bridge.clone().oneshot(req).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
    }
    let response = bridge
        .clone()
        .oneshot(request(list, input.clone(), Some(&pin)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let value: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap())
            .unwrap();
    assert_eq!(value["total"], 1);
    assert_eq!(value["items"][0]["id"], lab.tenant);
    assert_eq!(value["items"][0]["reserved_memory_mib"], 0);
    assert_eq!(value["items"][0]["memory_mib"], 4096);
    for q in ["%", "_", "no-such-workspace"] {
        let response = bridge
            .clone()
            .oneshot(request(
                list,
                json!({"q":q,"offset":0,"limit":25}),
                Some(&pin),
            ))
            .await
            .unwrap();
        let value: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap())
                .unwrap();
        assert_eq!(value["total"], 0, "search treats SQL wildcards literally");
    }
    let (_, credential) = lab.credential("owner", None).await;
    let response = bridge
        .clone()
        .oneshot(request(
            "/operator/v1/workspaces.get",
            json!({"id":lab.tenant}),
            Some(&pin),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let body = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(!body.contains("token_hash") && !body.contains(s(&credential["token"])));
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["credential_count"], 1);
    assert_eq!(value["credentials"][0]["id"], credential["id"]);
    for input in [
        json!({"q":"","offset":0,"limit":101}),
        json!({"q":"","offset":-1,"limit":1}),
        json!({"q":"","offset":0,"limit":1,"sql":"anything"}),
    ] {
        assert_eq!(
            bridge
                .clone()
                .oneshot(request(list, input, Some(&pin)))
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
    let response = bridge
        .oneshot(request(
            "/operator/v1/workspaces.get",
            json!({"id":"f".repeat(32)}),
            Some(&pin),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    // Adding the bridge never adds management routes to the public/customer
    // router or lets its certificate impersonate a worker.
    let response = api::router(lab.store.clone())
        .oneshot(request(list, input.clone(), Some(&pin)))
        .await
        .unwrap();
    assert!(!response.status().is_success());
    let response = api::internal(lab.store.clone())
        .oneshot(request(list, input, Some(&pin)))
        .await
        .unwrap();
    assert!(!response.status().is_success());
    // Exercise the actual dedicated TLS listener: sharing a CA with another
    // client does not give that client operator access.
    let certificates = tempfile::tempdir().unwrap();
    let pins = fenders_control_plane::pki::create(
        certificates.path(),
        &std::collections::BTreeMap::from([
            ("bridge".into(), vec!["127.0.0.1".into()]),
            ("operator".into(), vec!["operator.test".into()]),
            ("worker".into(), vec!["worker.test".into()]),
        ]),
    )
    .unwrap();
    let tls = fenders_control_plane::transport::server_config(
        &certificates.path().join("bridge.pem"),
        &certificates.path().join("bridge.key"),
        Some(&certificates.path().join("ca.pem")),
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("https://{}{list}", listener.local_addr().unwrap());
    let router = operator_api::router(lab.store.clone(), s(&pins["operator"]).into()).unwrap();
    let server = tokio::spawn(fenders_control_plane::transport::serve_tls(
        listener, tls, router,
    ));
    for identity in [None, Some("worker"), Some("operator")] {
        let mut builder = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .tls_built_in_root_certs(false)
            .add_root_certificate(
                reqwest::Certificate::from_pem(
                    &std::fs::read(certificates.path().join("ca.pem")).unwrap(),
                )
                .unwrap(),
            );
        if let Some(identity) = identity {
            let pem = format!(
                "{}\n{}",
                std::fs::read_to_string(certificates.path().join(format!("{identity}.pem")))
                    .unwrap(),
                std::fs::read_to_string(certificates.path().join(format!("{identity}.key")))
                    .unwrap()
            );
            builder = builder.identity(reqwest::Identity::from_pem(pem.as_bytes()).unwrap());
        }
        let response = builder
            .build()
            .unwrap()
            .post(&url)
            .header("X-Fenders-Operator", "a".repeat(32))
            .header("Content-Type", "application/json")
            .body(json!({"q":"alpha","offset":0,"limit":25}).to_string())
            .send()
            .await;
        match identity {
            None => assert!(response.is_err(), "a public client cannot complete mTLS"),
            Some("worker") => assert_eq!(response.unwrap().status(), StatusCode::UNAUTHORIZED),
            _ => assert_eq!(response.unwrap().status(), StatusCode::OK),
        }
    }
    server.abort();
    lab.finish().await;
}

async fn edit(bridge: &axum::Router, pin: &str, body: &Value) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method("POST")
        .uri("/operator/v1/workspaces.allowance")
        .header("X-Fenders-Operator", "a".repeat(32))
        .body(Body::from(body.to_string()))
        .unwrap();
    req.extensions_mut().insert(PeerIdentity(Some(pin.into())));
    let response = bridge.clone().oneshot(req).await.unwrap();
    let status = response.status();
    (
        status,
        serde_json::from_slice(&to_bytes(response.into_body(), 8192).await.unwrap()).unwrap(),
    )
}

#[tokio::test]
async fn allowance_edit_is_atomic_stale_safe_and_recoverable() {
    let lab = Lab::new().await;
    let pin = digest("operator");
    let bridge = operator_api::router(lab.store.clone(), pin.clone()).unwrap();
    let limits = json!({"cpu_percent":400,"memory_mib":8192,"instances":4,"storage_bytes":20000000000i64,"transfer_bytes":10000000});
    let input = json!({"id":lab.tenant,"request_key":uid(),"expected_revision":1,"reason":"Agreed private trial increase","allowance":limits});
    let (first, second) = tokio::join!(edit(&bridge, &pin, &input), edit(&bridge, &pin, &input));
    assert_eq!(first.0, StatusCode::OK, "{first:?}");
    assert_eq!(
        first, second,
        "concurrent/lost-response retries return exactly the committed result"
    );
    assert_eq!(first.1["revision"], 2);
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit WHERE action='operator.allowance'")
            .fetch_one(&lab.store.pool)
            .await
            .unwrap();
    assert_eq!(count, 1);
    let detail: Value =
        sqlx::query_scalar("SELECT detail FROM audit WHERE action='operator.allowance'")
            .fetch_one(&lab.store.pool)
            .await
            .unwrap();
    assert_eq!(detail["before"]["memory_mib"], 4096);
    assert_eq!(detail["after"]["memory_mib"], 8192);
    assert_eq!(detail["reason"], input["reason"]);
    let mut changed = input.clone();
    changed["reason"] = json!("Different intent");
    assert_eq!(edit(&bridge, &pin, &changed).await.0, StatusCode::CONFLICT);
    changed["request_key"] = json!(uid());
    assert_eq!(
        edit(&bridge, &pin, &changed).await.1["error"],
        "allowance changed; refresh before editing"
    );
    // Older CLI/customer binaries still invalidate the edit token, including ABA.
    sqlx::query("UPDATE tenants SET memory_mib=4096 WHERE id=$1")
        .bind(&lab.tenant)
        .execute(&lab.store.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE tenants SET memory_mib=8192 WHERE id=$1")
        .bind(&lab.tenant)
        .execute(&lab.store.pool)
        .await
        .unwrap();
    changed["expected_revision"] = json!(2);
    assert_eq!(edit(&bridge, &pin, &changed).await.0, StatusCode::CONFLICT);
    changed["expected_revision"] = json!(4);
    sqlx::query("UPDATE artifacts SET size=2048 WHERE id=$1")
        .bind(&lab.artifact)
        .execute(&lab.store.pool)
        .await
        .unwrap();
    changed["allowance"]["storage_bytes"] = json!(1024);
    assert_eq!(
        edit(&bridge, &pin, &changed).await.1["error"],
        "allowance is below current usage or reservations"
    );
    changed["allowance"]["storage_bytes"] = limits["storage_bytes"].clone();
    sqlx::query("INSERT INTO traffic_usage(tenant_id,project_id,period,bytes,requests) VALUES($1,$2,date_trunc('month',now() AT TIME ZONE 'UTC')::date,4096,1)")
        .bind(&lab.tenant).bind(&lab.project).execute(&lab.store.pool).await.unwrap();
    changed["allowance"]["transfer_bytes"] = json!(1024);
    assert_eq!(edit(&bridge, &pin, &changed).await.0, StatusCode::CONFLICT);
    changed["allowance"]["transfer_bytes"] = limits["transfer_bytes"].clone();
    // If durable audit fails neither limits, revision nor receipt may commit.
    sqlx::raw_sql("CREATE FUNCTION deny_operator_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='operator.allowance' THEN RAISE EXCEPTION 'fixture audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER deny_operator_audit BEFORE INSERT ON audit FOR EACH ROW EXECUTE FUNCTION deny_operator_audit();").execute(&lab.store.pool).await.unwrap();
    assert_eq!(
        edit(&bridge, &pin, &changed).await.0,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    let revision: i64 = sqlx::query_scalar("SELECT allowance_revision FROM tenants WHERE id=$1")
        .bind(&lab.tenant)
        .fetch_one(&lab.store.pool)
        .await
        .unwrap();
    assert_eq!(revision, 4);
    let receipts: i64 = sqlx::query_scalar("SELECT count(*) FROM operator_request_receipts")
        .fetch_one(&lab.store.pool)
        .await
        .unwrap();
    assert_eq!(receipts, 1);
    sqlx::raw_sql("DROP TRIGGER deny_operator_audit ON audit")
        .execute(&lab.store.pool)
        .await
        .unwrap();
    assert_eq!(edit(&bridge, &pin, &changed).await.0, StatusCode::OK);
    // A retry of the first intent must not revert a subsequent edit.
    assert_eq!(edit(&bridge, &pin, &input).await, first);
    let revision: i64 = sqlx::query_scalar("SELECT allowance_revision FROM tenants WHERE id=$1")
        .bind(&lab.tenant)
        .fetch_one(&lab.store.pool)
        .await
        .unwrap();
    assert_eq!(revision, 5);
    lab.finish().await;
}

async fn workspace_action(bridge: &axum::Router, pin: &str, input: &Value) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method("POST")
        .uri("/operator/v1/workspaces.action")
        .header("X-Fenders-Operator", "a".repeat(32))
        .body(Body::from(input.to_string()))
        .unwrap();
    request
        .extensions_mut()
        .insert(PeerIdentity(Some(pin.into())));
    let response = bridge.clone().oneshot(request).await.unwrap();
    (
        response.status(),
        serde_json::from_slice(&to_bytes(response.into_body(), 8192).await.unwrap()).unwrap(),
    )
}
#[tokio::test]
async fn suspension_is_atomic_and_concurrent_retries_share_the_audit_receipt() {
    let l = Lab::new().await;
    let pin = digest("operator");
    let bridge = operator_api::router_with_controls(l.store.clone(), pin.clone(), true).unwrap();
    let input = json!({"id":l.tenant,"request_key":uid(),"action":"suspend","reason":"Private trial suspension","expected_revision":1});
    sqlx::raw_sql("CREATE FUNCTION deny_suspend_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='operator.suspend' THEN RAISE EXCEPTION 'fixture audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER deny_suspend_audit BEFORE INSERT ON audit FOR EACH ROW EXECUTE FUNCTION deny_suspend_audit();").execute(&l.store.pool).await.unwrap();
    assert_eq!(
        workspace_action(&bridge, &pin, &input).await.0,
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
    let (first, second) = tokio::join!(
        workspace_action(&bridge, &pin, &input),
        workspace_action(&bridge, &pin, &input)
    );
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
    assert_eq!(
        workspace_action(&bridge, &pin, &stale).await.0,
        StatusCode::CONFLICT
    );
    stale["request_key"] = json!(uid());
    assert_eq!(
        workspace_action(&bridge, &pin, &stale).await.0,
        StatusCode::CONFLICT
    );
    stale["expected_revision"] = json!(3);
    assert_eq!(
        workspace_action(&bridge, &pin, &stale).await.0,
        StatusCode::OK
    );
    assert_eq!(
        workspace_action(&bridge, &pin, &input).await,
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
    let pin = digest("operator");
    let bridge = operator_api::router_with_controls(l.store.clone(), pin.clone(), true).unwrap();
    let input = json!({"id":l.tenant,"request_key":uid(),"action":"suspend","reason":"Acceptance suspension","expected_revision":1});
    let disabled = operator_api::router(l.store.clone(), pin.clone()).unwrap();
    assert_eq!(
        workspace_action(&disabled, &pin, &input).await.0,
        StatusCode::SERVICE_UNAVAILABLE,
        "rollout guard defaults closed"
    );
    let response = workspace_action(&bridge, &pin, &input).await;
    assert_eq!(response.0, StatusCode::OK, "{response:?}");
    assert_eq!(response.1["status"], "suspending");
    assert_eq!(workspace_action(&bridge, &pin, &input).await, response);
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
    assert_eq!(
        workspace_action(&bridge, &pin, &resume).await.0,
        StatusCode::CONFLICT
    );
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
    assert_eq!(
        workspace_action(&bridge, &pin, &resume).await.0,
        StatusCode::OK
    );
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

#[tokio::test]
async fn global_operator_activity_is_bounded_private_and_cursor_stable() {
    let lab = Lab::new().await;
    let pin = digest("activity-private-operator");
    let bridge = operator_api::router(lab.store.clone(), pin.clone()).unwrap();
    let req = |body: Value, authenticated: bool| {
        let mut request = Request::builder()
            .method("POST")
            .uri("/operator/v1/activity.list")
            .header("X-Fenders-Operator", "a".repeat(32))
            .body(Body::from(body.to_string()))
            .unwrap();
        if authenticated {
            request
                .extensions_mut()
                .insert(PeerIdentity(Some(pin.clone())));
        }
        request
    };
    for i in 0..28 {
        sqlx::query("INSERT INTO audit(actor,action,resource_id,detail) VALUES('operator:test','operator.admission_policy','admission',$1)")
            .bind(json!({"reason":format!("Policy change {i}"),"before":{"mode":"closed"},"after":{"mode":"approval"},"request_key":"not-for-browser","extra_secret":"must-not-cross"})).execute(&lab.store.pool).await.unwrap();
    }
    sqlx::query("INSERT INTO audit(actor,action,resource_id,detail) VALUES('customer','secret.update','secret',$1)").bind(json!({"reason":"private-customer-detail"})).execute(&lab.store.pool).await.unwrap();
    assert_eq!(
        bridge
            .clone()
            .oneshot(req(json!({}), false))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let response = bridge.clone().oneshot(req(json!({}), true)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    for excluded in [
        "must-not-cross",
        "not-for-browser",
        "private-customer-detail",
    ] {
        assert!(!text.contains(excluded));
    }
    let page: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(page["items"].as_array().unwrap().len(), 25);
    assert_eq!(page["items"][0]["reason"], "Policy change 27");
    assert_eq!(page["items"][0]["before"]["mode"], "closed");
    assert!(
        page["items"][0]["workspace_id"].is_null(),
        "global policy must appear without a workspace"
    );
    let first = page["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["sequence"].clone())
        .collect::<Vec<_>>();
    sqlx::query("INSERT INTO audit(tenant_id,actor,action,resource_id,detail) VALUES($1,'operator:test','operator.allowance',$1,$2)").bind(&lab.tenant).bind(json!({"reason":"Concurrent new change","before":{"memory_mib":4096},"after":{"memory_mib":8192}})).execute(&lab.store.pool).await.unwrap();
    let response = bridge
        .clone()
        .oneshot(req(json!({"before":page["next_before"]}), true))
        .await
        .unwrap();
    let older: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap())
            .unwrap();
    assert_eq!(older["items"].as_array().unwrap().len(), 3);
    assert!(older["next_before"].is_null());
    assert!(
        older["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|v| !first.contains(&v["sequence"]))
    );
    let response = bridge.clone().oneshot(req(json!({}), true)).await.unwrap();
    let latest: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap())
            .unwrap();
    assert_eq!(latest["items"][0]["workspace_id"], lab.tenant);
    assert_eq!(latest["items"][0]["workspace_name"], "alpha");
    for invalid in [
        json!({"before":0}),
        json!({"before":-1}),
        json!({"before":"bad"}),
        json!({"limit":10000}),
    ] {
        assert_eq!(
            bridge
                .clone()
                .oneshot(req(invalid, true))
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
    let mut public = req(json!({}), true);
    public.headers_mut().insert(
        "Authorization",
        format!("Bearer {}", lab.token).parse().unwrap(),
    );
    assert!(
        !api::router(lab.store.clone())
            .oneshot(public)
            .await
            .unwrap()
            .status()
            .is_success()
    );
    lab.finish().await;
}
