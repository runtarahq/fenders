use super::*;
use fenders_control_plane::customer_onboarding::OnboardingConfig;

pub(super) fn policy(max_workspaces: i64) -> OnboardingConfig {
    OnboardingConfig {
        allowance: Allowance {
            cpu_percent: 100,
            memory_mib: 128,
            storage_bytes: 1_073_741_824,
            instances: 1,
            transfer_bytes: 1_073_741_824,
        },
        max_workspaces,
        verification_email: None,
    }
}

#[tokio::test]
async fn verified_onboarding_is_atomic_isolated_and_not_repeated() {
    let mut l = IdentityLab::new().await;
    let legacy = l.login("legacy").await;
    l.member(&legacy, "owner", None).await;
    l.lab.store = l.lab.store.clone().with_onboarding(policy(10)).unwrap();
    sqlx::query("UPDATE admission_policy SET mode='automatic' WHERE singleton")
        .execute(&l.lab.store.pool)
        .await
        .unwrap();
    l.lab.store.migrate().await.unwrap(); // upgrade/rerun preserves existing users
    let legacy = l.login("legacy").await;
    let (_, info) = l.request(&legacy, "GET", "/auth/session", None, true).await;
    assert_eq!(info["workspaces"].as_array().unwrap().len(), 1);
    assert_eq!(info["onboarding"]["workspace_pending"], false);
    assert!(info["onboarding"]["workspace_id"].is_null());

    let (first, second) = tokio::join!(l.login("new-owner"), l.login("new-owner"));
    assert_eq!(first.user, second.user);
    let (_, info) = l.request(&first, "GET", "/auth/session", None, true).await;
    let home = s(&info["onboarding"]["workspace_id"]).to_owned();
    assert_eq!(info["email"], "new-owner@example.test");
    assert_eq!(info["workspaces"].as_array().unwrap().len(), 1);
    assert_eq!(info["workspaces"][0]["id"], home);
    assert_eq!(info["workspaces"][0]["memberships"][0]["role"], "owner");
    let project = s(&info["workspaces"][0]["default_project_id"]);
    let (status, projects) = l
        .request(
            &first,
            "GET",
            &format!("/v1/tenants/{home}/projects"),
            None,
            true,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(projects[0]["display_name"], "Production");
    assert_eq!(projects[0]["id"], project);
    assert_eq!(
        l.request(
            &first,
            "GET",
            &format!("/v1/tenants/{}/projects", l.lab.tenant),
            None,
            true
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        l.request(&first, "POST", "/auth/onboarding", None, false)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    let (a, b) = tokio::join!(
        l.request(&first, "POST", "/auth/onboarding", None, true),
        l.request(&second, "POST", "/auth/onboarding", None, true)
    );
    assert_eq!(a.0, StatusCode::OK);
    assert_eq!(b.1["onboarding"]["workspace_id"], home);
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit WHERE action='customer.onboard'")
            .fetch_one(&l.lab.store.pool)
            .await
            .unwrap();
    assert_eq!(count, 1);
    let executions: i64 = sqlx::query_scalar("SELECT count(*) FROM executions")
        .fetch_one(&l.lab.store.pool)
        .await
        .unwrap();
    assert_eq!(executions, 0, "onboarding must never invoke an app");
    let allowance: (i64, i64, i32) =
        sqlx::query_as("SELECT cpu_percent,memory_mib,instances FROM tenants WHERE id=$1")
            .bind(&home)
            .fetch_one(&l.lab.store.pool)
            .await
            .unwrap();
    assert_eq!(allowance, (100, 128, 1));

    // Revoke this owner after assigning another owner through existing barriers.
    l.lab
        .store
        .add_member(
            &l.lab.operator,
            &home,
            json!({"user_id":legacy.user,"role":"owner"}),
        )
        .await
        .unwrap();
    let member = &info["workspaces"][0]["memberships"][0];
    l.lab
        .store
        .update_member(
            &l.lab.operator,
            &home,
            s(&member["id"]),
            json!({"expected_revision":member["revision"],"role":"owner","revoked":true}),
        )
        .await
        .unwrap();
    let again = l.login("new-owner").await;
    let (_, info) = l
        .request(&again, "POST", "/auth/onboarding", None, true)
        .await;
    assert_eq!(info["workspaces"], json!([]));
    assert_eq!(info["onboarding"]["workspace_id"], home);
    assert_eq!(info["onboarding"]["workspace_pending"], false);
    l.finish().await;
}

#[tokio::test]
async fn onboarding_requires_fresh_verified_email_and_bounded_admission() {
    let mut l = IdentityLab::new().await;
    l.lab.store = l.lab.store.clone().with_onboarding(policy(1)).unwrap();
    sqlx::query("UPDATE admission_policy SET mode='automatic' WHERE singleton")
        .execute(&l.lab.store.pool)
        .await
        .unwrap();
    let unverified = l.login_mode("unverified", "unverified").await;
    l.member(&unverified, "viewer", None).await; // even existing grants cannot bypass verification
    let (_, info) = l
        .request(&unverified, "GET", "/auth/session", None, true)
        .await;
    assert_eq!(info["onboarding"]["verification_required"], true);
    assert_eq!(info["workspaces"], json!([]));
    assert_eq!(
        l.request(
            &unverified,
            "POST",
            "/auth/onboarding",
            Some(json!({"email_verified":true})),
            true
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        l.request(
            &unverified,
            "GET",
            &format!("/v1/tenants/{}/projects", l.lab.tenant),
            None,
            true
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let missing = l.login_mode("missing", "missing-email").await;
    assert_eq!(
        l.request(&missing, "POST", "/auth/onboarding", None, true)
            .await
            .0,
        StatusCode::FORBIDDEN
    );

    let verified = l.login("unverified").await;
    assert_eq!(verified.user, unverified.user);
    let (_, info) = l
        .request(&verified, "GET", "/auth/session", None, true)
        .await;
    assert_eq!(info["onboarding"]["verification_required"], false);
    assert!(!info["onboarding"]["workspace_id"].is_null());
    let waiting = l.login("waiting").await;
    let (_, info) = l
        .request(&waiting, "POST", "/auth/onboarding", None, true)
        .await;
    assert_eq!(info["onboarding"]["workspace_pending"], true);
    assert_eq!(info["workspaces"], json!([]));
    l.lab.store = l.lab.store.clone().with_onboarding(policy(2)).unwrap();
    sqlx::query("UPDATE admission_policy SET mode='automatic' WHERE singleton")
        .execute(&l.lab.store.pool)
        .await
        .unwrap();
    let (a, b) = tokio::join!(
        l.request(&waiting, "POST", "/auth/onboarding", None, true),
        l.request(&waiting, "POST", "/auth/onboarding", None, true)
    );
    assert_eq!(a.1["onboarding"]["workspace_pending"], false);
    assert_eq!(
        a.1["onboarding"]["workspace_id"],
        b.1["onboarding"]["workspace_id"]
    );
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM customer_users WHERE onboarded_workspace_id IS NOT NULL",
    )
    .fetch_one(&l.lab.store.pool)
    .await
    .unwrap();
    assert_eq!(count, 2);
    l.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires local Playwright and Chromium"]
async fn onboarding_console_against_rust_api() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let mut l = IdentityLab::at_origin(&origin).await;
    l.lab.store = l.lab.store.clone().with_onboarding(policy(5)).unwrap();
    sqlx::query("UPDATE admission_policy SET mode='automatic' WHERE singleton")
        .execute(&l.lab.store.pool)
        .await
        .unwrap();
    l.provider
        .browser_email_verified
        .store(false, Ordering::SeqCst);
    let provider = l.provider.clone();
    // This approval endpoint is only on the local signed OIDC test provider.
    let approval = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let approval_url = format!("http://{}/verify", approval.local_addr().unwrap());
    let approval_server = tokio::spawn(async move {
        axum::serve(
            approval,
            Router::new().route(
                "/verify",
                axum::routing::post(move || {
                    let provider = provider.clone();
                    async move {
                        provider
                            .browser_email_verified
                            .store(true, Ordering::SeqCst);
                        StatusCode::NO_CONTENT
                    }
                }),
            ),
        )
        .await
        .unwrap();
    });
    let server =
        tokio::spawn(axum::serve(listener, api::router(l.lab.store.clone())).into_future());
    let passed = run_console_browser(
        "tests/verify_onboarding.cjs",
        json!({"origin":origin,"verification":approval_url}),
    )
    .await;
    server.abort();
    approval_server.abort();
    let home_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM customer_users WHERE onboarded_workspace_id IS NOT NULL",
    )
    .fetch_one(&l.lab.store.pool)
    .await
    .unwrap();
    assert_eq!(home_count, 1);
    let executions: i64 = sqlx::query_scalar("SELECT count(*) FROM executions")
        .fetch_one(&l.lab.store.pool)
        .await
        .unwrap();
    assert_eq!(executions, 0);
    l.finish().await;
    assert!(passed, "onboarding console acceptance failed");
}

#[tokio::test]
async fn onboarding_audit_failure_rolls_back_identity_workspace_and_membership() {
    let mut l = IdentityLab::new().await;
    l.lab.store = l.lab.store.clone().with_onboarding(policy(2)).unwrap();
    sqlx::query("UPDATE admission_policy SET mode='automatic' WHERE singleton")
        .execute(&l.lab.store.pool)
        .await
        .unwrap();
    sqlx::raw_sql("CREATE FUNCTION reject_onboarding_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='customer.onboard' THEN RAISE EXCEPTION 'injected audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_onboarding_audit BEFORE INSERT ON audit FOR EACH ROW EXECUTE FUNCTION reject_onboarding_audit();").execute(&l.lab.store.pool).await.unwrap();
    let login = l.begin("audit-failure", "valid").await;
    assert_eq!(
        l.callback(&login).await.status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    let count:(i64,i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM tenants),(SELECT count(*) FROM customer_users),(SELECT count(*) FROM workspace_memberships)").fetch_one(&l.lab.store.pool).await.unwrap();
    assert_eq!(count, (1, 0, 0));
    sqlx::raw_sql("DROP TRIGGER reject_onboarding_audit ON audit")
        .execute(&l.lab.store.pool)
        .await
        .unwrap();
    let browser = l.login("audit-failure").await;
    assert_eq!(
        l.request(&browser, "GET", "/auth/session", None, true)
            .await
            .1["workspaces"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    l.finish().await;
}

async fn admission_call(l: &IdentityLab, action: &str, input: Value) -> (StatusCode, Value) {
    operator_call(l, &format!("admission.{action}"), input).await
}
pub(super) async fn operator_call(
    l: &IdentityLab,
    action: &str,
    input: Value,
) -> (StatusCode, Value) {
    let pin = digest("admission-private-bridge");
    let router =
        fenders_control_plane::operator_api::router(l.lab.store.clone(), pin.clone()).unwrap();
    let mut req = Request::builder()
        .method("POST")
        .uri(format!("/operator/v1/{action}"))
        .header("X-Fenders-Operator", "a".repeat(32))
        .body(Body::from(input.to_string()))
        .unwrap();
    req.extensions_mut()
        .insert(fenders_control_plane::transport::PeerIdentity(Some(pin)));
    let response = router.oneshot(req).await.unwrap();
    let status = response.status();
    (
        status,
        serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap())
            .unwrap(),
    )
}
async fn approval_policy(l: &IdentityLab, cap: i64) -> Value {
    let (status,result)=admission_call(l,"edit_policy",json!({"request_key":uid(),"expected_revision":1,"reason":"Open isolated acceptance queue","mode":"approval","max_workspaces":cap,"allowance":policy(cap).allowance})).await;
    assert_eq!(status, StatusCode::OK, "{result}");
    result
}
#[tokio::test]
async fn operator_admission_defaults_closed_requires_verification_and_decides_once() {
    let mut l = IdentityLab::new().await;
    l.lab.store = l.lab.store.clone().with_onboarding(policy(2)).unwrap();
    let owner = l.login("requester").await;
    let (_, info) = l.request(&owner, "GET", "/auth/session", None, false).await;
    assert_eq!(info["onboarding"]["admission"]["status"], "closed");
    assert_eq!(info["workspaces"], json!([]));
    let (_, queue) = admission_call(&l, "list", json!({"status":"pending","offset":0})).await;
    assert_eq!(queue["total"], 0);
    approval_policy(&l, 2).await;
    let unverified = l.login_mode("unverified-requester", "unverified").await;
    assert_eq!(
        l.request(&unverified, "POST", "/auth/onboarding", None, true)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    let _ = tokio::join!(
        l.request(&owner, "POST", "/auth/onboarding", None, true),
        l.request(&owner, "POST", "/auth/onboarding", None, true)
    );
    let (_, queue) = admission_call(&l, "list", json!({"status":"pending","offset":0})).await;
    assert_eq!(queue["total"], 1);
    let id = queue["items"][0]["id"].clone();
    let (_, info) = l.request(&owner, "GET", "/auth/session", None, false).await;
    assert_eq!(info["onboarding"]["admission"]["status"], "pending");
    let decision = json!({"id":id,"request_key":uid(),"expected_revision":1,"expected_policy_revision":2,"action":"approve","reason":"Private admission acceptance","allowance":policy(2).allowance});
    // Failure to record the operator decision must roll back workspace, member,
    // default project, customer-onboard audit, receipt and request state together.
    sqlx::raw_sql("CREATE FUNCTION reject_admission_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='operator.admission_decision' THEN RAISE EXCEPTION 'fixture failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_admission_audit BEFORE INSERT ON audit FOR EACH ROW EXECUTE FUNCTION reject_admission_audit();").execute(&l.lab.store.pool).await.unwrap();
    assert_eq!(
        admission_call(&l, "decide", decision.clone()).await.0,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    let homes: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM customer_users WHERE onboarded_workspace_id IS NOT NULL",
    )
    .fetch_one(&l.lab.store.pool)
    .await
    .unwrap();
    assert_eq!(homes, 0);
    sqlx::query("DROP TRIGGER reject_admission_audit ON audit")
        .execute(&l.lab.store.pool)
        .await
        .unwrap();
    let (a, b) = tokio::join!(
        admission_call(&l, "decide", decision.clone()),
        admission_call(&l, "decide", decision.clone())
    );
    assert_eq!(a.0, StatusCode::OK, "{}", a.1);
    assert_eq!(a, b);
    let home = a.1["workspace_id"].as_str().unwrap();
    let counts:(i64,i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM workspace_memberships WHERE tenant_id=$1 AND role='owner'),(SELECT count(*) FROM projects WHERE tenant_id=$1 AND is_default),(SELECT count(*) FROM executions WHERE tenant_id=$1)").bind(home).fetch_one(&l.lab.store.pool).await.unwrap();
    assert_eq!(counts, (1, 1, 0));
    let (status, detail) = operator_call(&l, "workspaces.get", json!({"id":home})).await;
    assert_eq!(status, StatusCode::OK, "{detail}");
    let activity = detail["activity"].as_array().unwrap();
    assert_eq!(activity.len(), 1);
    assert_eq!(activity[0]["sequence"], a.1["audit"]["sequence"]);
    assert_eq!(activity[0]["action"], "operator.admission_decision");
    assert_eq!(activity[0]["reason"], decision["reason"]);
    assert_eq!(activity[0]["before"], "pending");
    assert_eq!(activity[0]["after"], "approved");
    let (_, info) = l.request(&owner, "GET", "/auth/session", None, false).await;
    assert_eq!(info["workspaces"][0]["id"], home);
    assert_eq!(info["onboarding"]["workspace_pending"], false);
    let mut other = decision.clone();
    other["request_key"] = json!(uid());
    assert_eq!(
        admission_call(&l, "decide", other).await.0,
        StatusCode::CONFLICT
    );
    let mut changed = decision;
    changed["reason"] = json!("different intent");
    assert_eq!(
        admission_call(&l, "decide", changed).await.0,
        StatusCode::CONFLICT
    );
    l.finish().await;
}
#[tokio::test]
async fn operator_admission_decline_cap_and_changed_identity_are_enforced() {
    let mut l = IdentityLab::new().await;
    l.lab.store = l.lab.store.clone().with_onboarding(policy(1)).unwrap();
    approval_policy(&l, 1).await;
    let declined = l.login("declined").await;
    let (_, q) = admission_call(&l, "list", json!({"status":"pending","offset":0})).await;
    let decision = json!({"id":q["items"][0]["id"],"request_key":uid(),"expected_revision":1,"expected_policy_revision":2,"action":"decline","reason":"Private trial is full"});
    assert_eq!(
        admission_call(&l, "decide", decision.clone()).await.0,
        StatusCode::OK
    );
    let (_, info) = l
        .request(&declined, "POST", "/auth/onboarding", None, true)
        .await;
    assert_eq!(info["onboarding"]["admission"]["status"], "declined");
    assert_eq!(
        info["onboarding"]["admission"]["reason"],
        "Private trial is full"
    );
    l.login("declined").await;
    let (_, q) = admission_call(&l, "list", json!({"status":"pending","offset":0})).await;
    assert_eq!(q["total"], 0);
    let first = l.login("first").await;
    let second = l.login("second").await;
    let (_, q) = admission_call(&l, "list", json!({"status":"pending","offset":0})).await;
    assert_eq!(q["total"], 2);
    let decision = |id: &Value| json!({"id":id,"request_key":uid(),"expected_revision":1,"expected_policy_revision":2,"action":"approve","reason":"Approve isolated user","allowance":policy(1).allowance});
    let d = decision(&q["items"][0]["id"]);
    sqlx::query("UPDATE customer_users SET email_verified=false WHERE id=$1")
        .bind(&first.user)
        .execute(&l.lab.store.pool)
        .await
        .unwrap();
    assert_eq!(
        admission_call(&l, "decide", d.clone()).await.0,
        StatusCode::CONFLICT
    );
    l.login("first").await;
    let (a, b) = tokio::join!(
        admission_call(&l, "decide", d),
        admission_call(&l, "decide", decision(&q["items"][1]["id"]))
    );
    assert!(
        (a.0 == StatusCode::OK && b.0 == StatusCode::CONFLICT)
            || (b.0 == StatusCode::OK && a.0 == StatusCode::CONFLICT)
    );
    let homes: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM customer_users WHERE onboarded_workspace_id IS NOT NULL",
    )
    .fetch_one(&l.lab.store.pool)
    .await
    .unwrap();
    assert_eq!(homes, 1);
    assert_eq!(
        l.request(
            &second,
            "POST",
            "/api/admission/decision",
            Some(json!({})),
            true
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(admission_call(&l,"edit_policy",json!({"request_key":uid(),"expected_revision":1,"reason":"stale","mode":"closed","max_workspaces":1,"allowance":policy(1).allowance})).await.0,StatusCode::CONFLICT);
    l.finish().await;
}
