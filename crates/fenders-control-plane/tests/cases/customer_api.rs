use super::*;

async fn call(
    l: &Lab,
    token: &str,
    method: &str,
    path: &str,
    body: Value,
    key: &str,
) -> (StatusCode, Value) {
    let response = api::router(l.store.clone())
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header("Authorization", format!("Bearer {token}"))
                .header("Idempotency-Key", key)
                .header("Content-Type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let body: Value = serde_json::from_slice(&body).unwrap();
    // Whatever a test asks, the answer is one the contract describes.
    super::contract::conforms(method, path, status, &body);
    (status, body)
}
async fn key(l: &Lab, scope: Option<&str>, permissions: &[&str]) -> Value {
    let (status, value) = call(l, &l.token, "POST", &format!("/v1/workspaces/{}/api-keys", l.tenant),
        json!({"name":"automation","project_id":scope,"permissions":permissions,"ttl_seconds":3600}), &uid()).await;
    assert_eq!(status, StatusCode::CREATED, "{value}");
    value
}

#[tokio::test]
async fn customer_api_keys_are_held_to_their_routes_and_revalidate_revocation() {
    let l = Lab::new().await;
    let k = key(&l, Some(&l.project), &["read", "runs:write"]).await;
    let token = s(&k["token"]);
    let p = l.store.authenticate(token).await.unwrap();
    let base = format!("/v1/workspaces/{}/projects/{}", l.tenant, l.project);
    assert_eq!(
        call(&l, token, "GET", &(base.clone() + "/apps"), json!({}), "")
            .await
            .0,
        StatusCode::OK
    );
    for (method, path) in [
        ("POST", base.clone() + "/apps/deploy"),
        ("GET", base.clone() + "/executions"),
        (
            "POST",
            format!(
                "/v1/workspaces/{}/projects/{}/executions",
                l.tenant, l.project
            ),
        ),
        ("GET", "/v1/nodes".into()),
        ("POST", format!("/v1/workspaces/{}/credentials", l.tenant)),
        ("POST", format!("/v1/workspaces/{}/api-keys", l.tenant)),
    ] {
        let status = call(&l, token, method, &path, json!({}), "deny").await.0;
        assert!(
            matches!(status, StatusCode::FORBIDDEN | StatusCode::NOT_FOUND),
            "{method} {path}: {status}"
        );
    }
    let other = uid();
    assert_eq!(
        call(
            &l,
            token,
            "GET",
            &format!("/v1/workspaces/{}/projects/{other}/apps", l.tenant),
            json!({}),
            ""
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        call(
            &l,
            token,
            "GET",
            &format!("/v1/workspaces/{other}/projects/{}/apps", l.project),
            json!({}),
            ""
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    let listed = l.store.api_keys(&l.operator, &l.tenant).await.unwrap();
    assert!(listed["items"][0]["last_used"].is_string());
    assert!(!listed.to_string().contains(token));
    assert!(listed["items"][0].get("token_hash").is_none());
    l.store
        .revoke_credential(&l.operator, &l.tenant, s(&k["id"]))
        .await
        .unwrap();
    assert_eq!(
        call(&l, token, "GET", &(base + "/apps"), json!({}), "")
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    // Authentication completed before revocation: the write transaction still rejects it.
    assert_eq!(
        l.store
            .create_project(
                &p,
                &l.tenant,
                serde_json::from_value(json!({"name":"denied"})).unwrap()
            )
            .await
            .unwrap_err()
            .status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        l.store.projects(&p, &l.tenant).await.unwrap_err().status,
        StatusCode::UNAUTHORIZED
    );
    l.finish().await;
}

#[tokio::test]
async fn customer_api_key_and_project_retries_do_not_duplicate_or_reveal_keys() {
    let l = Lab::new().await;
    let route = format!("/v1/workspaces/{}/api-keys", l.tenant);
    let request = json!({"name":"pipeline","project_id":null,"permissions":["read","projects:write"],"ttl_seconds":3600});
    let (a, b) = tokio::join!(
        call(&l, &l.token, "POST", &route, request.clone(), "issue"),
        call(&l, &l.token, "POST", &route, request.clone(), "issue")
    );
    assert_eq!(a.1["id"], b.1["id"]);
    // One of them issued the key and is shown its token, once. The other
    // made nothing, and is told that it holds no token for the key.
    let (issued, replayed) = if a.0 == StatusCode::CREATED {
        (&a, &b)
    } else {
        (&b, &a)
    };
    assert_eq!(issued.0, StatusCode::CREATED, "{}", issued.1);
    assert_eq!(issued.1["replayed"], false);
    assert_eq!(replayed.0, StatusCode::OK, "{}", replayed.1);
    assert_eq!(replayed.1["replayed"], true);
    assert!(replayed.1["token"].is_null());
    let secret = issued.1["token"].as_str().unwrap();
    // A later retry is told the same, and the key it cannot use is the
    // operator's to revoke by the id it was given.
    let later = call(&l, &l.token, "POST", &route, request.clone(), "issue").await;
    assert_eq!(later, *replayed);
    assert!(!later.1.to_string().contains(secret));
    let mut different = request.clone();
    different["ttl_seconds"] = json!(7200);
    assert_eq!(
        call(&l, &l.token, "POST", &route, different, "issue")
            .await
            .0,
        StatusCode::CONFLICT
    );
    let project_route = format!("/v1/workspaces/{}/projects", l.tenant);
    let (a, b) = tokio::join!(
        call(
            &l,
            secret,
            "POST",
            &project_route,
            json!({"name":"API project"}),
            "project"
        ),
        call(
            &l,
            secret,
            "POST",
            &project_route,
            json!({"name":"API project"}),
            "project"
        )
    );
    assert_eq!(a.0, StatusCode::CREATED, "{}", a.1);
    assert_eq!(a, b);
    assert_eq!(
        call(
            &l,
            secret,
            "POST",
            &project_route,
            json!({"name":"Other project"}),
            "project"
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        call(
            &l,
            secret,
            "POST",
            &project_route,
            json!({"name":"Missing key"}),
            ""
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let p = l.store.authenticate(secret).await.unwrap();
    l.store
        .revoke_credential(&l.operator, &l.tenant, s(&k_id(&l).await))
        .await
        .unwrap();
    assert_eq!(
        l.store
            .create_project(
                &p,
                &l.tenant,
                serde_json::from_value(json!({"name":"No admission"})).unwrap()
            )
            .await
            .unwrap_err()
            .status,
        StatusCode::UNAUTHORIZED
    );
    l.finish().await;
}
async fn k_id(l: &Lab) -> Value {
    l.store.api_keys(&l.operator, &l.tenant).await.unwrap()["items"][0]["id"].clone()
}

#[tokio::test]
async fn customer_api_deploy_requires_explicit_run_and_reuses_original_operation() {
    let l = Lab::new().await;
    let node = l.node("compiler").await;
    approve_component(&l, &node, false, true).await;
    let deployer = key(&l, Some(&l.project), &["read", "apps:write"]).await;
    let runner = key(&l, Some(&l.project), &["read", "runs:write"]).await;
    let observer = key(&l, Some(&l.project), &["read"]).await;
    let base = format!("/v1/workspaces/{}/projects/{}", l.tenant, l.project);
    let payload = json!({"name":"api-command","artifact_id":l.artifact,"triggers":{"manual":true,"http":false}});
    let (status, op) = call(
        &l,
        s(&deployer["token"]),
        "POST",
        &(base.clone() + "/apps/deploy"),
        payload.clone(),
        "deploy",
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{op}");
    assert_eq!(
        call(
            &l,
            s(&deployer["token"]),
            "POST",
            &(base.clone() + "/apps/deploy"),
            payload,
            "deploy"
        )
        .await
        .1,
        op
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM app_runs")
        .fetch_one(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
    let runs = format!("{base}/apps/{}/runs", s(&op["resource_id"]));
    for k in [&deployer, &observer] {
        assert_eq!(
            call(&l, s(&k["token"]), "POST", &runs, json!({}), "run")
                .await
                .0,
            StatusCode::FORBIDDEN
        );
    }
    let (status, run) = call(&l, s(&runner["token"]), "POST", &runs, json!({}), "run").await;
    assert_eq!(status, StatusCode::ACCEPTED, "{run}");
    assert_eq!(
        call(&l, s(&runner["token"]), "POST", &runs, json!({}), "run")
            .await
            .1,
        run
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM app_runs")
        .fetch_one(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
    l.finish().await;
}

#[tokio::test]
async fn customer_api_secret_retries_do_not_tell_a_guess_and_expired_keys_fail() {
    let l = Lab::new().await;
    let k = key(&l, Some(&l.project), &["read", "secrets:write"]).await;
    let token = s(&k["token"]);
    let route = format!("/v1/workspaces/{}/projects/{}/secrets", l.tenant, l.project);
    let body = json!({"name":"password","value":"private-low-entropy-example"});
    let (status, created) = call(&l, token, "POST", &route, body.clone(), "secret").await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(
        call(&l, token, "POST", &route, body, "secret").await.1,
        created
    );
    // A value of a few bytes would mask those bytes wherever they appear in
    // a run's output: refused.
    for short in ["", "1", "yes"] {
        assert_eq!(
            call(
                &l,
                token,
                "POST",
                &route,
                json!({"name":"short","value":short}),
                &uid()
            )
            .await
            .0,
            StatusCode::BAD_REQUEST,
            "{short:?}"
        );
    }
    // A retry with another value is answered as the first was: whether it
    // matched the stored value is not something a caller is told. The
    // secret keeps the value it was created with.
    let guessed = call(
        &l,
        token,
        "POST",
        &route,
        json!({"name":"password","value":"different"}),
        "secret",
    )
    .await;
    assert_eq!(guessed, (StatusCode::CREATED, created.clone()));
    let stored: i64 = sqlx::query_scalar("SELECT count(*) FROM secrets WHERE name='password'")
        .fetch_one(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(stored, 1);
    // The key with another name is still a different request.
    assert_eq!(
        call(
            &l,
            token,
            "POST",
            &route,
            json!({"name":"other","value":"private-low-entropy-example"}),
            "secret"
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let receipt: String = sqlx::query_scalar(
        "SELECT response::text FROM customer_request_receipts WHERE request_key='secret'",
    )
    .fetch_one(&l.store.pool)
    .await
    .unwrap();
    assert!(!receipt.contains("private-low-entropy-example"));
    let read = call(&l, token, "GET", &route, json!({}), "").await;
    assert_eq!(read.0, StatusCode::OK);
    assert!(!read.1.to_string().contains("private-low-entropy-example"));
    sqlx::query("UPDATE credentials SET expires=now()-interval '1 second' WHERE id=$1")
        .bind(s(&k["id"]))
        .execute(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(
        call(&l, token, "GET", &route, json!({}), "").await.0,
        StatusCode::UNAUTHORIZED
    );
    l.finish().await;
}

#[tokio::test]
async fn customer_api_connections_resolve_both_protocols_atomically_without_granting_on_registration()
 {
    let (mut l, _, _) = app_connections::setup().await;
    let dns = dns::DnsLab::new().await;
    l.store = l.store.with_public_egress(dns.config.clone()).unwrap();
    let policy = l.store.public_egress_policy(&l.operator).await.unwrap();
    l.store.activate_public_egress(&l.operator,json!({"expected_revision":policy["revision"],"enabled":true,"digest":policy["configured_digest"]})).await.unwrap();
    let k = key(
        &l,
        Some(&l.project),
        &["read", "apps:write", "connections:write"],
    )
    .await;
    let token = s(&k["token"]);
    let base = format!("/v1/workspaces/{}/projects/{}", l.tenant, l.project);
    let tcp = call(
        &l,
        token,
        "POST",
        &(base.clone() + "/connections"),
        json!({"name":"tcp","type":"tcp","host":"10.50.0.2","port":1234}),
        "tcp",
    )
    .await;
    let https = call(
        &l,
        token,
        "POST",
        &(base.clone() + "/connections"),
        json!({"name":"https","type":"https","origin":"https://example.com"}),
        "https",
    )
    .await;
    assert!(tcp.0.is_success(), "{}", tcp.1);
    assert!(https.0.is_success(), "{}", https.1);
    let count:i64=sqlx::query_scalar("SELECT (SELECT count(*) FROM app_endpoint_connections)+(SELECT count(*) FROM app_https_connections)").fetch_one(&l.store.pool).await.unwrap();
    assert_eq!(count, 0);
    for route in [
        format!("{base}/apps/deploy"),
        format!(
            "/v1/workspaces/{}/projects/{}/apps/deploy",
            l.tenant, l.project
        ),
    ] {
        assert_eq!(
            call(
                &l,
                token,
                "POST",
                &route,
                json!({"https_origins":["https://unregistered.example"]}),
                "bypass-catalog"
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
    }
    let payload = json!({"name":"connected","artifact_id":l.artifact,"triggers":{"manual":true,"http":false},"connections":[{"connection_id":tcp.1["resource_id"],"prefix":"REMOTE_"},{"connection_id":https.1["resource_id"]}]});
    let deployed = call(
        &l,
        token,
        "POST",
        &(base.clone() + "/apps/deploy"),
        payload.clone(),
        "deploy-unified",
    )
    .await;
    assert_eq!(deployed.0, StatusCode::CREATED, "{}", deployed.1);
    let app = format!("{base}/apps/{}", s(&deployed.1["resource_id"]));
    let connections = call(
        &l,
        token,
        "GET",
        &(app.clone() + "/connections"),
        json!({}),
        "",
    )
    .await
    .1;
    assert_eq!(connections["items"].as_array().unwrap().len(), 1);
    assert_eq!(connections["https_origins"].as_array().unwrap().len(), 1);
    let removed = call(
        &l,
        token,
        "PUT",
        &(app.clone() + "/connections"),
        json!({"connections":[],"expected_revision":connections["revision"]}),
        "disconnect-all",
    )
    .await;
    assert!(removed.0.is_success(), "{}", removed.1);
    let denied=call(&l,token,"PUT",&(app+"/connections"),json!({"connections":[{"connection_id":uid()}],"expected_revision":connections["revision"]}),"unavailable").await;
    assert_eq!(denied.0, StatusCode::NOT_FOUND);
    assert_eq!(
        call(
            &l,
            token,
            "POST",
            &(base + "/apps/deploy"),
            payload,
            "deploy-unified"
        )
        .await
        .1,
        deployed.1
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM app_runs")
        .fetch_one(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
    l.finish().await;
}

/// A run that has not ended is stopped by a key that may run, through the
/// app it is a run of.
#[tokio::test]
async fn a_run_is_cancelled_through_its_app_by_a_key_that_may_run() {
    let l = Lab::new().await;
    let node = l.node("compiler").await;
    approve_component(&l, &node, false, true).await;
    let deployer = key(&l, Some(&l.project), &["read", "apps:write"]).await;
    let runner = key(&l, Some(&l.project), &["read", "runs:write"]).await;
    let observer = key(&l, Some(&l.project), &["read"]).await;
    let base = format!("/v1/workspaces/{}/projects/{}", l.tenant, l.project);
    let mut apps = Vec::new();
    for name in ["cancel-one", "cancel-two"] {
        let (status, op) = call(
            &l,
            s(&deployer["token"]),
            "POST",
            &(base.clone() + "/apps/deploy"),
            json!({"name":name,"artifact_id":l.artifact,"triggers":{"manual":true,"http":false}}),
            &uid(),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{op}");
        apps.push(s(&op["resource_id"]).to_owned());
    }
    let runs = format!("{base}/apps/{}/runs", apps[0]);
    let (status, started) = call(&l, s(&runner["token"]), "POST", &runs, json!({}), &uid()).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{started}");
    let run: String = sqlx::query_scalar("SELECT id FROM customer_app_runs WHERE app_id=$1")
        .bind(&apps[0])
        .fetch_one(&l.store.pool)
        .await
        .unwrap();
    let cancel = format!("{runs}/{run}/cancel");
    // Not by a key that only reads or only deploys, and not through another app.
    for k in [&observer, &deployer] {
        assert_eq!(
            call(&l, s(&k["token"]), "POST", &cancel, json!({}), &uid())
                .await
                .0,
            StatusCode::FORBIDDEN
        );
    }
    let other = format!("{base}/apps/{}/runs/{run}/cancel", apps[1]);
    assert_eq!(
        call(&l, s(&runner["token"]), "POST", &other, json!({}), &uid())
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    let request = uid();
    let (status, stopped) = call(
        &l,
        s(&runner["token"]),
        "POST",
        &cancel,
        json!({}),
        &request,
    )
    .await;
    // The run had not been given to a node, so it is stopped already.
    assert_eq!(status, StatusCode::OK, "{stopped}");
    assert_eq!(stopped["state"], "succeeded");
    // The operation is of the run that was named, not of the execution
    // the control plane stopped for it, which no route reads.
    assert_eq!(stopped["kind"], "cancel-run");
    assert_eq!(stopped["resource_id"], started["resource_id"]);
    // The same request again is the same answer, not a second stop.
    assert_eq!(
        call(
            &l,
            s(&runner["token"]),
            "POST",
            &cancel,
            json!({}),
            &request
        )
        .await
        .1,
        stopped
    );
    let (status, after) = call(
        &l,
        s(&observer["token"]),
        "GET",
        &format!("{runs}/{run}"),
        json!({}),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        matches!(s(&after["state"]), "cancelled" | "stopped"),
        "{after}"
    );
    // A run that ended has nothing left to stop.
    assert_eq!(
        call(&l, s(&runner["token"]), "POST", &cancel, json!({}), &uid())
            .await
            .0,
        StatusCode::CONFLICT
    );
    l.finish().await;
}

/// Every route is one a tenant's key may be given, or one of the operator's
/// own: tenants and their keys, what a tenant is allowed, suspending one,
/// the nodes, the public egress policy and this control plane's own status.
/// What lay beneath the app API answers nobody, the operator included.
#[tokio::test]
async fn the_operator_has_its_own_routes_and_no_others() {
    let l = Lab::new().await;
    let t = format!("/v1/workspaces/{}", l.tenant);
    let p = format!("{t}/projects/{}", l.project);
    let id = uid();
    for (method, path) in [
        ("POST", format!("{p}/executions")),
        ("POST", format!("{p}/deployments")),
        ("PATCH", format!("{p}/deployments/{id}")),
        ("POST", format!("{p}/executions/{id}/stop")),
        ("POST", format!("{p}/executions/{id}/pause")),
        ("POST", format!("{p}/grants")),
        ("POST", format!("{p}/grants/{id}/revoke")),
        ("POST", format!("{p}/routes")),
        ("GET", format!("{p}/executions")),
        ("GET", format!("{p}/executions/{id}")),
        ("GET", format!("{p}/deployments")),
        ("GET", format!("{p}/grants")),
        ("GET", format!("{p}/routes")),
        ("GET", format!("{p}/networks")),
        ("GET", format!("{t}/settings")),
        ("PATCH", format!("{t}/settings")),
        ("GET", format!("{t}/credentials")),
        ("POST", format!("{t}/credentials")),
        ("GET", "/v1/anything-else".to_owned()),
    ] {
        let (status, body) = call(&l, &l.token, method, &path, json!({}), &uid()).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{method} {path}: {body}");
    }
    // Its own answer to the operator, and to no key whatever the key holds.
    let every = [
        "read",
        "apps:write",
        "runs:write",
        "projects:write",
        "connections:write",
        "secrets:write",
    ];
    let holder = key(&l, None, &every).await;
    for (method, path) in [
        ("POST", "/v1/workspaces".to_owned()),
        ("PATCH", t.clone()),
        ("PATCH", format!("{t}/http-limits")),
        ("POST", format!("{t}/lifecycle")),
        ("GET", format!("{t}/api-keys")),
        ("POST", format!("{t}/api-keys")),
        ("DELETE", format!("{t}/api-keys/{id}")),
        ("GET", "/v1/nodes".to_owned()),
        ("POST", "/v1/nodes".to_owned()),
        ("PATCH", format!("/v1/nodes/{id}")),
        ("GET", "/v1/public-egress-policy".to_owned()),
        ("PUT", "/v1/public-egress-policy".to_owned()),
        ("GET", "/v1/control-plane/status".to_owned()),
    ] {
        let segments: Vec<_> = path.trim_matches('/').split('/').collect();
        assert!(
            fenders_control_plane::customer_api::operators(method, &segments),
            "{method} {path}"
        );
        assert!(
            fenders_control_plane::customer_api::permission(method, &segments).is_none(),
            "{method} {path}"
        );
        let (status, _) = call(&l, s(&holder["token"]), method, &path, json!({}), &uid()).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "a key: {method} {path}");
        let (status, _) = call(&l, &l.token, method, &path, json!({}), &uid()).await;
        assert!(
            !matches!(status, StatusCode::NOT_FOUND if !path.contains(&id))
                && status != StatusCode::FORBIDDEN
                && status != StatusCode::UNAUTHORIZED,
            "the operator: {method} {path}: {status}"
        );
    }
    l.finish().await;
}

/// A tenant's keys are the operator's to issue, list and revoke. A key does
/// what its permissions say and cannot make another, whatever it holds.
#[tokio::test]
async fn a_tenants_keys_are_the_operators_to_issue() {
    let l = Lab::new().await;
    let every = [
        "read",
        "apps:write",
        "runs:write",
        "projects:write",
        "connections:write",
        "secrets:write",
    ];
    let ask = json!({"name":"line","project_id":null,"permissions":every,"ttl_seconds":3600});
    let key = l
        .store
        .create_api_key(
            &l.operator,
            &l.tenant,
            serde_json::from_value(ask.clone()).unwrap(),
            &uid(),
        )
        .await
        .unwrap();
    let holder = l.store.authenticate(s(&key["token"])).await.unwrap();
    assert_eq!(holder.role, Role::Key);
    assert_eq!(key["created_by"], l.operator.id);
    // With every permission there is, it makes, lists and revokes none.
    for refused in [
        l.store
            .create_api_key(
                &holder,
                &l.tenant,
                serde_json::from_value(ask.clone()).unwrap(),
                &uid(),
            )
            .await,
        l.store.api_keys(&holder, &l.tenant).await,
        l.store
            .revoke_credential(&holder, &l.tenant, s(&key["id"]))
            .await,
    ] {
        assert_eq!(refused.unwrap_err().status, StatusCode::FORBIDDEN);
    }
    // Nor over the API, on the operator's route or the workspace's name for it.
    for path in [
        format!("/v1/workspaces/{}/api-keys", l.tenant),
        format!("/v1/workspaces/{}/api-keys", l.tenant),
    ] {
        let (status, _) = call(&l, s(&key["token"]), "POST", &path, ask.clone(), &uid()).await;
        assert!(
            matches!(status, StatusCode::FORBIDDEN | StatusCode::NOT_FOUND),
            "{path}: {status}"
        );
    }
    // The operator does all three, and a revoked key stops at once.
    let (status, second) = call(
        &l,
        &l.token,
        "POST",
        &format!("/v1/workspaces/{}/api-keys", l.tenant),
        ask.clone(),
        &uid(),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{second}");
    assert_eq!(
        l.store.api_keys(&l.operator, &l.tenant).await.unwrap()["items"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    l.store
        .revoke_credential(&l.operator, &l.tenant, s(&key["id"]))
        .await
        .unwrap();
    assert_eq!(
        l.store
            .authenticate(s(&key["token"]))
            .await
            .unwrap_err()
            .status,
        StatusCode::UNAUTHORIZED
    );
    assert!(l.store.authenticate(s(&second["token"])).await.is_ok());
    // No role of a person is a credential's kind.
    for role in ["owner", "editor", "viewer"] {
        let refused = sqlx::query("INSERT INTO credentials(id,token_hash,tenant_id,name,role,expires) VALUES($1,$2,$3,'role',$4,now()+interval '1 hour')")
            .bind(uid()).bind(uid()).bind(&l.tenant).bind(role).execute(&l.store.pool).await;
        assert!(refused.is_err(), "{role}");
    }
    l.finish().await;
}

/// A key carries a label its issuer chose, and every change the key makes
/// is recorded with it: a product built on the API reads its own users back
/// out of the audit trail, of which the API knows nothing.
#[tokio::test]
async fn a_keys_label_is_recorded_with_what_it_does() {
    let l = Lab::new().await;
    let issue = |label: Value| {
        let (store, operator, tenant) = (l.store.clone(), l.operator.clone(), l.tenant.clone());
        async move {
            store
                .create_api_key(
                    &operator,
                    &tenant,
                    serde_json::from_value(json!({"name":"console","project_id":null,"permissions":["read","secrets:write"],"ttl_seconds":3600,"label":label})).unwrap(),
                    &uid(),
                )
                .await
        }
    };
    let labelled = issue(json!("user:4f2a alice@example.test")).await.unwrap();
    let plain = issue(Value::Null).await.unwrap();
    assert_eq!(labelled["label"], "user:4f2a alice@example.test");
    assert!(plain["label"].is_null());
    // It is what the key says of itself, and what a listing says of it.
    let (status, me) = call(&l, s(&labelled["token"]), "GET", "/v1/me", json!({}), "").await;
    assert_eq!(
        (status, &me["label"]),
        (StatusCode::OK, &json!("user:4f2a alice@example.test"))
    );
    let listed = l.store.api_keys(&l.operator, &l.tenant).await.unwrap();
    assert!(
        listed["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|k| k["label"] == "user:4f2a alice@example.test")
    );
    // A change each key makes, and one the operator makes.
    let path = format!("/v1/workspaces/{}/projects/{}/secrets", l.tenant, l.project);
    for (token, name) in [
        (s(&labelled["token"]), "by-labelled"),
        (s(&plain["token"]), "by-plain"),
        (l.token.as_str(), "by-operator"),
    ] {
        let (status, body) = call(
            &l,
            token,
            "POST",
            &path,
            json!({"name":name,"value":"a value"}),
            &uid(),
        )
        .await;
        assert!(status.is_success(), "{name}: {body}");
    }
    let recorded: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT actor,actor_label FROM audit WHERE tenant_id=$1 AND action LIKE 'secret.%' ORDER BY sequence",
    )
    .bind(&l.tenant)
    .fetch_all(&l.store.pool)
    .await
    .unwrap();
    assert_eq!(
        recorded,
        [
            (
                s(&labelled["id"]).to_owned(),
                Some("user:4f2a alice@example.test".to_owned())
            ),
            (s(&plain["id"]).to_owned(), None),
            (l.operator.id.clone(), None),
        ]
    );
    // One line of at most 128 bytes.
    for refused in [json!(""), json!("x".repeat(129)), json!("two\nlines")] {
        assert!(issue(refused.clone()).await.is_err(), "{refused}");
    }
    assert!(issue(json!("x".repeat(128))).await.is_ok());
    l.finish().await;
}

/// An upload's body may be 16 MiB and is held whole. None of it is read for
/// a credential that may not upload there, or when it says it is too large.
#[tokio::test]
async fn an_uploads_body_is_not_read_for_a_credential_that_may_not_upload_there() {
    let l = Lab::new().await;
    let (_, viewer) = l.credential("viewer", None).await;
    let (_, editor) = l.credential("editor", None).await;
    let upload = |token: String, tenant: String, declared: Option<usize>| {
        let router = api::router(l.store.clone());
        let project = l.project.clone();
        async move {
            // A body that records being asked for its first piece.
            let read = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let asked = read.clone();
            let body = Body::new(Asked(Some(move || {
                asked.store(true, std::sync::atomic::Ordering::SeqCst);
            })));
            let mut request = Request::builder()
                .method("POST")
                .uri(format!(
                    "/v1/workspaces/{tenant}/projects/{project}/artifacts"
                ))
                .header("Authorization", format!("Bearer {token}"))
                .header("Content-Type", "application/wasm");
            if let Some(declared) = declared {
                request = request.header("Content-Length", declared);
            }
            let status = router
                .oneshot(request.body(body).unwrap())
                .await
                .unwrap()
                .status();
            (status, read.load(std::sync::atomic::Ordering::SeqCst))
        }
    };
    // Another workspace, a read-only credential, a body that says it is too
    // large: refused with nothing read.
    assert_eq!(
        upload(s(&editor["token"]).to_owned(), uid(), None).await,
        (StatusCode::NOT_FOUND, false)
    );
    assert_eq!(
        upload(s(&viewer["token"]).to_owned(), l.tenant.clone(), None).await,
        (StatusCode::FORBIDDEN, false)
    );
    assert_eq!(
        upload(
            s(&editor["token"]).to_owned(),
            l.tenant.clone(),
            Some(17 << 20)
        )
        .await,
        (StatusCode::PAYLOAD_TOO_LARGE, false)
    );
    // One that may upload there is read (and refused for what it holds).
    assert_eq!(
        upload(s(&editor["token"]).to_owned(), l.tenant.clone(), None).await,
        (StatusCode::BAD_REQUEST, true)
    );
    l.finish().await;
}

/// A body of one small piece, calling `asked` when it is first polled.
struct Asked<F>(Option<F>);
impl<F: FnOnce() + Unpin> http_body::Body for Asked<F> {
    type Data = axum::body::Bytes;
    type Error = std::convert::Infallible;
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        std::task::Poll::Ready(self.0.take().map(|asked| {
            asked();
            Ok(http_body::Frame::data(axum::body::Bytes::from_static(
                b"not wasm",
            )))
        }))
    }
}

/// What a workspace can make without being charged for it is bounded: rows
/// of each kind, and changes in a minute.
#[tokio::test]
async fn a_workspaces_rows_and_changes_are_bounded() {
    let l = Lab::new().await;
    // Up to the limits, as a busy workspace would have got there.
    sqlx::query("INSERT INTO projects(id,tenant_id,name,display_name,slug) SELECT md5('p'||n),$1,'p'||n,'P'||n,'p'||n FROM generate_series(1,255) n")
        .bind(&l.tenant).execute(&l.store.pool).await.unwrap();
    sqlx::query("INSERT INTO secrets(id,tenant_id,project_id,name,ciphertext) SELECT md5('s'||n),$1,$2,'s'||n,'\\x00' FROM generate_series(1,4096) n")
        .bind(&l.tenant).bind(&l.project).execute(&l.store.pool).await.unwrap();
    sqlx::query("INSERT INTO credentials(id,token_hash,tenant_id,name,role,expires) SELECT md5('c'||n),md5('h'||n),$1,'c','key',now()+interval '1 hour' FROM generate_series(1,1024) n")
        .bind(&l.tenant).execute(&l.store.pool).await.unwrap();
    let quota = StatusCode::TOO_MANY_REQUESTS;
    let project = |name: &'static str| {
        l.store.create_project(
            &l.operator,
            &l.tenant,
            serde_json::from_value(json!({"name":name})).unwrap(),
        )
    };
    assert_eq!(project("one-more").await.unwrap_err().status, quota);
    assert_eq!(
        l.store
            .create_secret(
                &l.operator,
                &l.tenant,
                &l.project,
                json!({"name":"more","value":"value"})
            )
            .await
            .unwrap_err()
            .status,
        quota
    );
    let issue = || async {
        l.store
            .create_api_key(
                &l.operator,
                &l.tenant,
                serde_json::from_value(
                    json!({"name":"more","project_id":null,"permissions":["read"],"ttl_seconds":86400}),
                )
                .unwrap(),
                &uid(),
            )
            .await
    };
    assert_eq!(issue().await.unwrap_err().status, quota);
    // Credentials that open nothing any more do not count.
    sqlx::query("UPDATE credentials SET revoked=true WHERE id=md5('c1')")
        .execute(&l.store.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE credentials SET expires=now()-interval '1 second' WHERE id=md5('c2')")
        .execute(&l.store.pool)
        .await
        .unwrap();
    let (_, editor) = l.credential("editor", None).await;
    issue().await.unwrap();
    assert_eq!(issue().await.unwrap_err().status, quota);

    // Changes in a minute: refused or not, each one counts, and reads do not.
    let path = format!("/v1/workspaces/{}/projects/{}/secrets", l.tenant, l.project);
    let token = s(&editor["token"]);
    let mut last = (StatusCode::OK, json!({}));
    for _ in 0..600 {
        last = call(
            &l,
            token,
            "POST",
            &path,
            json!({"name":"x","value":"value"}),
            // A key names each change it asks for.
            &uid(),
        )
        .await;
    }
    // The row limit, not yet the rate: over the API a limit reached is a
    // conflict with what the workspace has, which waiting does not cure.
    assert_eq!(last.0, StatusCode::CONFLICT, "{}", last.1);
    assert_eq!(last.1["code"], "quota_exhausted");
    assert_eq!(last.1["error"], "workspace metadata limit exhausted");
    let (status, body) = call(
        &l,
        token,
        "POST",
        &path,
        json!({"name":"x","value":"value"}),
        &uid(),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["code"], "rate_limited");
    assert_eq!(body["error"], "too many changes in a minute", "{body}");
    // It says when to ask again: within the minute the count is kept for.
    let refused = api::router(l.store.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(&path)
                .header("Authorization", format!("Bearer {token}"))
                .header("Idempotency-Key", uid())
                .header("Content-Type", "application/json")
                .body(Body::from(json!({"name":"x","value":"value"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(refused.status(), StatusCode::TOO_MANY_REQUESTS);
    let wait: u64 = refused.headers()["retry-after"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!((1..=60).contains(&wait), "{wait}");
    assert_eq!(
        call(&l, token, "GET", &path, json!({}), "").await.0,
        StatusCode::OK
    );
    // The operator's own changes are not counted against the workspace.
    assert_eq!(
        call(
            &l,
            &l.token,
            "POST",
            &path,
            json!({"name":"x","value":"value"}),
            &uid()
        )
        .await
        .1["error"],
        "workspace metadata limit exhausted"
    );
    l.finish().await;
}

/// A workspace's credentials see its plan and state, not the operator's own
/// notes on it.
#[tokio::test]
async fn a_workspaces_credentials_do_not_see_the_operators_notes_on_it() {
    let l = Lab::new().await;
    sqlx::query("UPDATE tenants SET lifecycle_reason='chargeback under review' WHERE id=$1")
        .bind(&l.tenant)
        .execute(&l.store.pool)
        .await
        .unwrap();
    let (viewer, _) = l.credential("viewer", None).await;
    let seen = l.store.tenants(&viewer).await.unwrap();
    assert_eq!(seen.as_array().unwrap().len(), 1);
    let seen = &seen[0];
    assert_eq!(seen["id"], l.tenant.as_str());
    assert!(seen["cpu_percent"].is_number() && seen["lifecycle_state"].is_string());
    for hidden in [
        "lifecycle_reason",
        "lifecycle_revision",
        "allowance_revision",
    ] {
        assert!(seen.get(hidden).is_none(), "{hidden}");
    }
    assert!(!seen.to_string().contains("chargeback"));
    // The operator sees all of it.
    let all = l.store.tenants(&l.operator).await.unwrap();
    assert_eq!(all[0]["lifecycle_reason"], "chargeback under review");
    assert!(all[0]["allowance_revision"].is_number());
    l.finish().await;
}

/// Every answer of the management listener, refusals included, carries the
/// headers a browser needs to keep a console's session on TLS and unframed.
#[tokio::test]
async fn management_answers_carry_browser_security_headers() {
    let l = Lab::new().await;
    for (path, token) in [
        ("/v1/workspaces", Some(l.token.as_str())),
        ("/v1/workspaces", None),
        ("/api/openapi.json", None),
        ("/no/such/path", Some(l.token.as_str())),
    ] {
        let mut request = Request::builder().uri(path);
        if let Some(token) = token {
            request = request.header("Authorization", format!("Bearer {token}"));
        }
        let response = api::router(l.store.clone())
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let headers = response.headers();
        assert_eq!(
            headers["strict-transport-security"], "max-age=31536000",
            "{path}"
        );
        assert_eq!(headers["x-content-type-options"], "nosniff", "{path}");
        assert_eq!(headers["x-frame-options"], "DENY", "{path}");
        assert_eq!(headers["referrer-policy"], "no-referrer", "{path}");
    }
    l.finish().await;
}

/// A stored secret is its row's alone: its ciphertext moved to another row
/// opens for no run, and secrets stored before that was so are bound once.
#[tokio::test]
async fn a_secrets_ciphertext_opens_only_for_its_own_row() {
    let l = Lab::new().await;
    let node = l.node("worker").await;
    let secret = |name: &'static str, value: &'static str| {
        let l = &l;
        async move {
            let row = l
                .store
                .create_secret(
                    &l.operator,
                    &l.tenant,
                    &l.project,
                    json!({"name":name,"value":value}),
                )
                .await
                .unwrap();
            s(&row["id"]).to_owned()
        }
    };
    let launch = |key: &'static str, id: String| {
        let l = &l;
        async move {
            let app = l
                .try_configured_app(json!({"secret_env":{"TOKEN":id}}))
                .await?;
            l.start_app(&app, key).await
        }
    };
    let (own, other) = (
        secret("own", "own-value").await,
        secret("other", "other-value").await,
    );
    // One secret's ciphertext written over another's, as someone who could
    // write the database might: the row it now sits in opens for no run.
    sqlx::query(
        "UPDATE secrets SET ciphertext=(SELECT ciphertext FROM secrets WHERE id=$1) WHERE id=$2",
    )
    .bind(&other)
    .bind(&own)
    .execute(&l.store.pool)
    .await
    .unwrap();
    let refused = launch("moved", own.clone()).await.unwrap_err();
    assert_eq!(refused.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(!refused.message.contains("value"));
    // The one it was taken from is as it was.
    let op = launch("untouched", other.clone()).await.unwrap();
    l.store.schedule().await.unwrap();
    let e = l.run(&op).await;
    let spec = l
        .store
        .assignment(s(&node["id"]), s(&e["id"]), n(&e["generation"]))
        .await
        .unwrap()["spec"]
        .clone();
    assert_eq!(spec["env"]["TOKEN"], "other-value");

    // A secret stored before ciphertexts named their rows: the value alone,
    // encrypted. The next start binds it, once.
    let cipher = fernet::Fernet::new(
        std::fs::read_to_string(l.root.path().join("encryption.key"))
            .unwrap()
            .trim(),
    )
    .unwrap();
    let stored = |id: &'static str, value: &'static str| {
        let (l, token) = (&l, cipher.encrypt(value.as_bytes()));
        async move {
            sqlx::query("INSERT INTO secrets(id,tenant_id,project_id,name,ciphertext) VALUES($1,$2,$3,$1,convert_to($4,'UTF8'))")
                .bind(id).bind(&l.tenant).bind(&l.project).bind(token)
                .execute(&l.store.pool).await.unwrap();
        }
    };
    let before = "0123456789abcdef0123456789abcde1";
    stored(before, "stored-before").await;
    sqlx::query("UPDATE secret_binding SET completed=NULL")
        .execute(&l.store.pool)
        .await
        .unwrap();
    l.store.migrate().await.unwrap();
    assert!(launch("bound-at-start", before.to_owned()).await.is_ok());
    // A row that turns up unbound after that was not written by the control
    // plane: later starts do not bind it, and it opens for no run.
    let after = "0123456789abcdef0123456789abcde2";
    stored(after, "stored-after").await;
    l.store.migrate().await.unwrap();
    let bound: bool = sqlx::query_scalar("SELECT bound FROM secrets WHERE id=$1")
        .bind(after)
        .fetch_one(&l.store.pool)
        .await
        .unwrap();
    assert!(!bound);
    assert!(launch("never-bound", after.to_owned()).await.is_err());
    l.finish().await;
}

async fn tenants_named(l: &Lab, name: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM tenants WHERE name=$1")
        .bind(name)
        .fetch_one(&l.store.pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_retried_tenant_creation_makes_one_tenant() {
    let l = Lab::new().await;
    let tenant = json!({"name":"acme","allowance":{"cpu_percent":200,"memory_mib":1024,"storage_bytes":1073741824,"instances":2,"transfer_bytes":1073741824}});
    // Two at once, as a client that timed out and tried again would send.
    let (a, b) = tokio::join!(
        call(
            &l,
            &l.token,
            "POST",
            "/v1/workspaces",
            tenant.clone(),
            "acme"
        ),
        call(
            &l,
            &l.token,
            "POST",
            "/v1/workspaces",
            tenant.clone(),
            "acme"
        )
    );
    assert_eq!(a.0, StatusCode::CREATED, "{}", a.1);
    assert_eq!(a, b);
    assert_eq!(tenants_named(&l, "acme").await, 1);
    // One audit record of it, and one default project.
    let (audits, projects): (i64, i64) = sqlx::query_as("SELECT (SELECT count(*) FROM audit WHERE action='tenant.create' AND resource_id=$1),(SELECT count(*) FROM projects WHERE tenant_id=$1)")
        .bind(s(&a.1["id"]))
        .fetch_one(&l.store.pool)
        .await
        .unwrap();
    assert_eq!((audits, projects), (1, 1));
    // The key with other arguments is refused, and makes nothing.
    let mut other = tenant.clone();
    other["allowance"]["instances"] = json!(3);
    let refused = call(&l, &l.token, "POST", "/v1/workspaces", other, "acme").await;
    assert_eq!(refused.0, StatusCode::CONFLICT, "{}", refused.1);
    // A name is a label, not an identity: another key makes another tenant of it.
    let second = call(
        &l,
        &l.token,
        "POST",
        "/v1/workspaces",
        tenant.clone(),
        "acme-2",
    )
    .await;
    assert_eq!(second.0, StatusCode::CREATED, "{}", second.1);
    assert_ne!(second.1["id"], a.1["id"]);
    assert_eq!(tenants_named(&l, "acme").await, 2);
    // Without a key nothing is made: a retry could not be told from a new request.
    let keyless = call(&l, &l.token, "POST", "/v1/workspaces", tenant, "").await;
    assert_eq!(keyless.0, StatusCode::BAD_REQUEST, "{}", keyless.1);
    assert_eq!(tenants_named(&l, "acme").await, 2);
    l.finish().await;
}

#[tokio::test]
async fn a_retried_node_registration_is_answered_with_the_node() {
    let l = Lab::new().await;
    let node = json!({"name":"node-1","cert_sha256":"a".repeat(64),"endpoint":"https://node-1.internal:9443","backend":"wasm","architecture":"x86_64","runtime":"wasmtime-50.0.0-fenders-v1","cpu_percent":200,"memory_mib":1024,"instances":4});
    let first = call(&l, &l.token, "POST", "/v1/nodes", node.clone(), "node-1").await;
    assert_eq!(first.0, StatusCode::CREATED, "{}", first.1);
    // The guide's own example: the same request with the same key.
    let again = call(&l, &l.token, "POST", "/v1/nodes", node.clone(), "node-1").await;
    assert_eq!(again, first);
    // A second node of the name is still refused, and so is the key reused.
    let duplicate = call(&l, &l.token, "POST", "/v1/nodes", node.clone(), "node-1b").await;
    assert_eq!(duplicate.0, StatusCode::CONFLICT, "{}", duplicate.1);
    let mut other = node.clone();
    other["instances"] = json!(8);
    let reused = call(&l, &l.token, "POST", "/v1/nodes", other, "node-1").await;
    assert_eq!(reused.0, StatusCode::CONFLICT, "{}", reused.1);
    assert_eq!(
        call(&l, &l.token, "POST", "/v1/nodes", node, "").await.0,
        StatusCode::BAD_REQUEST
    );
    let nodes: i64 = sqlx::query_scalar("SELECT count(*) FROM nodes")
        .fetch_one(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(nodes, 1);

    // A node's mode needs no key; with one, a retry leaves one record.
    let route = format!("/v1/nodes/{}", s(&first.1["id"]));
    let drain = json!({"draining":true});
    let a = call(&l, &l.token, "PATCH", &route, drain.clone(), "drain").await;
    let b = call(&l, &l.token, "PATCH", &route, drain.clone(), "drain").await;
    assert_eq!(a.0, StatusCode::OK, "{}", a.1);
    assert_eq!(a, b);
    let audits = "SELECT count(*) FROM audit WHERE action='node.mode'";
    let recorded: i64 = sqlx::query_scalar(audits)
        .fetch_one(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(recorded, 1);
    assert_eq!(
        call(
            &l,
            &l.token,
            "PATCH",
            &route,
            json!({"draining":false}),
            "drain"
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        call(&l, &l.token, "PATCH", &route, drain, "").await.0,
        StatusCode::OK
    );
    let recorded: i64 = sqlx::query_scalar(audits)
        .fetch_one(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(recorded, 2);
    l.finish().await;
}

#[tokio::test]
async fn the_operators_other_changes_honour_a_key_and_do_not_require_one() {
    let l = Lab::new().await;
    let audits = |action: &'static str| {
        let pool = l.store.pool.clone();
        async move {
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM audit WHERE action=$1")
                .bind(action)
                .fetch_one(&pool)
                .await
                .unwrap()
        }
    };
    // An allowance: the retry is answered as the first call was, though the
    // tenant has changed since.
    let tenant = format!("/v1/workspaces/{}", l.tenant);
    let allowance = json!({"allowance":{"cpu_percent":300,"memory_mib":2048,"instances":3,"storage_bytes":20000000000i64,"transfer_bytes":10000000}});
    let first = call(&l, &l.token, "PATCH", &tenant, allowance.clone(), "allow").await;
    assert_eq!(first.0, StatusCode::OK, "{}", first.1);
    assert_eq!(first.1["cpu_percent"], 300);
    let size = call(
        &l,
        &l.token,
        "PATCH",
        &tenant,
        json!({"default_app_size":"medium"}),
        "",
    )
    .await;
    assert_eq!(size.0, StatusCode::OK, "{}", size.1);
    let again = call(&l, &l.token, "PATCH", &tenant, allowance, "allow").await;
    assert_eq!(again, first);
    assert_eq!(audits("tenant.allowance").await, 1);
    assert_eq!(
        call(
            &l,
            &l.token,
            "PATCH",
            &tenant,
            json!({"default_app_size":"large"}),
            "allow"
        )
        .await
        .0,
        StatusCode::CONFLICT
    );

    // HTTP limits.
    let route = format!("/v1/workspaces/{}/http-limits", l.tenant);
    let limits = json!({"concurrent_requests":8,"requests_per_minute":120});
    let a = call(&l, &l.token, "PATCH", &route, limits.clone(), "limits").await;
    let b = call(&l, &l.token, "PATCH", &route, limits.clone(), "limits").await;
    assert_eq!(a.0, StatusCode::OK, "{}", a.1);
    assert_eq!(a, b);
    assert_eq!(audits("tenant.http-limits").await, 1);
    assert_eq!(
        call(&l, &l.token, "PATCH", &route, limits, "").await.0,
        StatusCode::OK
    );
    assert_eq!(audits("tenant.http-limits").await, 2);

    // The egress policy is guarded by a revision, which a change advances:
    // a retry without a key is refused, and with one is given the policy.
    let policy = "/v1/public-egress-policy";
    let before = call(&l, &l.token, "GET", policy, json!({}), "").await.1;
    sqlx::query("UPDATE public_egress_policy SET enabled=true,digest=repeat('a',64)")
        .execute(&l.store.pool)
        .await
        .unwrap();
    let disable = json!({"expected_revision":before["revision"],"enabled":false});
    let a = call(&l, &l.token, "PUT", policy, disable.clone(), "egress").await;
    assert_eq!(a.0, StatusCode::OK, "{}", a.1);
    assert_eq!(a.1["enabled"], false);
    assert_ne!(a.1["revision"], before["revision"]);
    let b = call(&l, &l.token, "PUT", policy, disable.clone(), "egress").await;
    assert_eq!((b.0, &b.1["revision"]), (StatusCode::OK, &a.1["revision"]));
    assert_eq!(
        call(&l, &l.token, "PUT", policy, disable, "").await.0,
        StatusCode::CONFLICT
    );
    assert_eq!(audits("public-egress.activate").await, 1);
    l.finish().await;
}

#[tokio::test]
async fn what_became_of_a_request_is_found_by_whatever_key_it_was_made_with() {
    let l = Lab::new().await;
    l.validated().await;
    let k = key(
        &l,
        Some(&l.project),
        &["read", "apps:write", "runs:write", "connections:write"],
    )
    .await;
    let token = s(&k["token"]);
    let base = format!("/v1/workspaces/{}/projects/{}", l.tenant, l.project);
    let found = |path: String| {
        let (l, base) = (&l, base.clone());
        async move { call(l, token, "GET", &(base + &path), json!({}), "").await }
    };

    // A key is its caller's to choose: here with a space, a slash and a hash.
    let chosen = "deploy 2026/11 #1";
    let encoded = "deploy%202026%2F11%20%231";
    let (status, deployed) = call(
        &l,
        token,
        "POST",
        &(base.clone() + "/apps/deploy"),
        json!({"name":"found","artifact_id":l.artifact,"triggers":{"manual":true,"http":false}}),
        chosen,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{deployed}");
    let (status, submission) = found(format!("/app-submissions/{encoded}")).await;
    assert_eq!(status, StatusCode::OK, "{submission}");
    assert_eq!(submission["id"], deployed["id"]);
    assert_eq!(submission["resource_id"], deployed["resource_id"]);

    // A short one, which is no identifier.
    let app = s(&deployed["resource_id"]);
    let (status, run) = call(
        &l,
        token,
        "POST",
        &format!("{base}/apps/{app}/runs"),
        json!({}),
        "r1",
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{run}");
    let (status, submission) = found(format!("/apps/{app}/submissions/r1")).await;
    assert_eq!(status, StatusCode::OK, "{submission}");
    assert_eq!(submission["id"], run["id"]);
    // An app's actions are found through that app, a deployment is not one.
    assert_eq!(
        found(format!("/apps/{app}/submissions/{encoded}")).await.0,
        StatusCode::NOT_FOUND
    );

    let (status, connection) = call(
        &l,
        token,
        "POST",
        &(base.clone() + "/connections"),
        json!({"type":"https","name":"example","origin":"https://example.com"}),
        "connect 1",
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{connection}");
    let (status, submission) = found("/endpoint-submissions/connect%201".into()).await;
    assert_eq!(status, StatusCode::OK, "{submission}");
    assert_eq!(submission["id"], connection["id"]);

    // A key nothing was made with, one no request could carry, and bytes
    // that are no text all name nothing.
    for missing in ["never-sent".to_owned(), "k".repeat(129), "%ff".to_owned()] {
        for path in [
            format!("/app-submissions/{missing}"),
            format!("/apps/{app}/submissions/{missing}"),
            format!("/endpoint-submissions/{missing}"),
        ] {
            assert_eq!(found(path.clone()).await.0, StatusCode::NOT_FOUND, "{path}");
        }
    }
    l.finish().await;
}

#[tokio::test]
async fn a_refusals_code_says_why_where_the_status_does_not() {
    let l = Lab::new().await;
    let writer = key(&l, None, &["read", "apps:write", "projects:write"]).await;
    let reader = key(&l, None, &["read"]).await;
    let (writer, reader) = (s(&writer["token"]), s(&reader["token"]));
    let projects = format!("/v1/workspaces/{}/projects", l.tenant);
    let base = format!("{projects}/{}", l.project);
    let refused = |token: &'static str,
                   method: &'static str,
                   path: String,
                   body: Value,
                   key: &'static str| {
        let l = &l;
        let token = match token {
            "operator" => l.token.clone(),
            "writer" => writer.to_owned(),
            _ => reader.to_owned(),
        };
        async move {
            let (status, value) = call(l, &token, method, &path, body, key).await;
            (status, s(&value["code"]).to_owned())
        }
    };
    let named = json!({"name":"Coded"});

    // 400: the key is missing, not the body malformed.
    assert_eq!(
        refused("writer", "POST", projects.clone(), named.clone(), "").await,
        (StatusCode::BAD_REQUEST, "idempotency_key_required".into())
    );
    assert_eq!(
        refused("writer", "POST", projects.clone(), json!({"nom":"x"}), "k0").await,
        (StatusCode::BAD_REQUEST, "invalid_request".into())
    );
    // 409, three ways: the key was used for something else, the thing
    // exists, the caller's copy is old.
    assert_eq!(
        call(&l, writer, "POST", &projects, named.clone(), "k1")
            .await
            .0,
        StatusCode::CREATED
    );
    assert_eq!(
        refused(
            "writer",
            "POST",
            projects.clone(),
            json!({"name":"Another"}),
            "k1"
        )
        .await,
        (StatusCode::CONFLICT, "idempotency_key_reused".into())
    );
    assert_eq!(
        refused("writer", "POST", projects.clone(), named.clone(), "k2").await,
        (StatusCode::CONFLICT, "already_exists".into())
    );
    // The lab's component has not been inspected.
    let deploy =
        json!({"name":"coded","artifact_id":l.artifact,"triggers":{"manual":true,"http":false}});
    assert_eq!(
        refused(
            "writer",
            "POST",
            base.clone() + "/apps/deploy",
            deploy,
            "k3"
        )
        .await,
        (StatusCode::CONFLICT, "not_validated".into())
    );
    let app = l.command_app().await;
    assert_eq!(
        refused(
            "writer",
            "PATCH",
            format!("{base}/apps/{app}"),
            json!({"desired":"stopped","expected_revision":999}),
            "k4"
        )
        .await,
        (StatusCode::CONFLICT, "revision_conflict".into())
    );
    // 403: the key may not, as against the workspace may not.
    assert_eq!(
        refused("reader", "POST", projects.clone(), named.clone(), "k5").await,
        (StatusCode::FORBIDDEN, "permission_denied".into())
    );
    assert_eq!(
        refused("reader", "GET", "/v1/nodes".into(), json!({}), "").await,
        (StatusCode::FORBIDDEN, "permission_denied".into())
    );
    let suspend = json!({"action":"suspend","reason":"Coded","expected_revision":1});
    let lifecycle = format!("/v1/workspaces/{}/lifecycle", l.tenant);
    assert_eq!(
        call(&l, &l.token, "POST", &lifecycle, suspend, "k6")
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        refused(
            "writer",
            "POST",
            projects.clone(),
            json!({"name":"Suspended"}),
            "k7"
        )
        .await,
        (StatusCode::FORBIDDEN, "workspace_suspended".into())
    );
    // A status with one meaning keeps its own name.
    assert_eq!(
        refused(
            "writer",
            "GET",
            format!("{projects}/{}/apps", uid()),
            json!({}),
            ""
        )
        .await,
        (StatusCode::NOT_FOUND, "not_found".into())
    );
    l.finish().await;
}

#[tokio::test]
async fn an_exhausted_allowance_is_a_conflict_and_not_a_rate() {
    let l = Lab::new().await;
    let k = key(&l, Some(&l.project), &["read", "apps:write"]).await;
    // Room for what the lab uploaded and nothing more.
    sqlx::query("UPDATE tenants SET storage_bytes=1024 WHERE id=$1")
        .bind(&l.tenant)
        .execute(&l.store.pool)
        .await
        .unwrap();
    let mut component = b"\0asm\x0d\0\x01\0".to_vec();
    component.resize(2048, 0);
    let response = api::router(l.store.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/v1/workspaces/{}/projects/{}/artifacts",
                    l.tenant, l.project
                ))
                .header("Authorization", format!("Bearer {}", s(&k["token"])))
                .header("Content-Type", "application/wasm")
                .body(Body::from(component.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert!(response.headers().get("retry-after").is_none());
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 8192).await.unwrap()).unwrap();
    assert_eq!(body["code"], "quota_exhausted", "{body}");
    assert_eq!(body["error"], "tenant storage allowance exhausted");
    // Inside the control plane it is still told by the status it had,
    // which the scheduler and the gateway go by.
    let refused = l
        .store
        .upload(&l.operator, &l.tenant, &l.project, &component)
        .await
        .unwrap_err();
    assert_eq!(refused.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(refused.code(), "quota_exhausted");
    l.finish().await;
}

/// One request, with the headers of its answer.
async fn answer(
    l: &Lab,
    token: Option<&str>,
    method: &str,
    path: &str,
) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let mut request = Request::builder().method(method).uri(path);
    if let Some(token) = token {
        request = request.header("Authorization", format!("Bearer {token}"));
    }
    let response = api::router(l.store.clone())
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let (status, headers) = (response.status(), response.headers().clone());
    let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    (status, headers, body.to_vec())
}

#[tokio::test]
async fn a_refusal_names_the_credential_wanted_and_the_methods_taken() {
    let l = Lab::new().await;
    let k = key(&l, None, &["read"]).await;
    let token = s(&k["token"]);
    let projects = format!("/v1/workspaces/{}/projects", l.tenant);
    let app = format!("{projects}/{}/apps/{}", l.project, uid());

    // No credential, and one that opens nothing: a bearer token is wanted.
    for token in [None, Some("fnd_tok_nothing")] {
        let (status, headers, _) = answer(&l, token, "GET", "/v1/me").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(headers["www-authenticate"], "Bearer");
    }

    // A path that is one, asked with a method it does not take.
    let allowed = |path: String, token: String, method: &'static str| {
        let l = &l;
        async move {
            let (status, headers, body) = answer(l, Some(&token), method, &path).await;
            let body: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED, "{method} {path}");
            assert_eq!(body["code"], "method_not_allowed");
            headers["allow"].to_str().unwrap().to_owned()
        }
    };
    assert_eq!(
        allowed(projects.clone(), token.into(), "DELETE").await,
        "GET, HEAD, POST"
    );
    assert_eq!(
        allowed(app.clone(), token.into(), "PUT").await,
        "GET, HEAD, PATCH, DELETE"
    );
    assert_eq!(
        allowed(format!("{app}/triggers"), token.into(), "POST").await,
        "GET, HEAD, PUT"
    );
    assert_eq!(
        allowed("/v1/me".into(), token.into(), "POST").await,
        "GET, HEAD"
    );
    // The operator is told of its own routes too, where a path has them.
    assert_eq!(
        allowed("/v1/workspaces".into(), l.token.clone(), "DELETE").await,
        "GET, HEAD, POST"
    );
    assert_eq!(
        allowed("/v1/nodes".into(), l.token.clone(), "PUT").await,
        "GET, HEAD, POST"
    );
    // A key is not told of them: of /v1/workspaces it may only list, a route
    // of the operator's is refused it as ever, and /v1/nodes is nothing it
    // could use by any method.
    let (status, headers, _) = answer(&l, Some(token), "POST", "/v1/workspaces").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(headers.get("allow").is_none());
    assert_eq!(
        allowed("/v1/workspaces".into(), token.into(), "DELETE").await,
        "GET, HEAD"
    );
    for method in ["GET", "PUT"] {
        let (status, headers, _) = answer(&l, Some(token), method, "/v1/nodes").await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{method}");
        assert!(headers.get("allow").is_none());
    }
    // A path that is none stays unknown to everyone, by any method.
    for token in [token, l.token.as_str()] {
        let (status, headers, _) = answer(&l, Some(token), "DELETE", "/v1/nothing").await;
        assert!(
            matches!(status, StatusCode::NOT_FOUND | StatusCode::FORBIDDEN),
            "{status}"
        );
        assert!(headers.get("allow").is_none());
    }

    // HEAD is GET without the body, to a key as to the operator.
    for (token, path) in [
        (token, projects.as_str()),
        (token, "/v1/me"),
        (l.token.as_str(), "/v1/nodes"),
    ] {
        let (status, headers, body) = answer(&l, Some(token), "HEAD", path).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert!(body.is_empty());
        assert_eq!(headers["cache-control"], "no-store");
    }
    // And is refused as GET would be.
    let (status, _, body) = answer(&l, Some(token), "HEAD", "/v1/nodes").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body.is_empty());
    // A change by HEAD is not one.
    let (status, _, _) = answer(
        &l,
        Some(token),
        "HEAD",
        &format!("{app}/runs/{}/cancel", uid()),
    )
    .await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    l.finish().await;
}

#[tokio::test]
async fn a_body_is_what_it_says_it_is_or_is_not_read() {
    let l = Lab::new().await;
    let k = key(&l, None, &["read", "apps:write", "projects:write"]).await;
    let token = s(&k["token"]);
    let send = |path: String, media: Option<&'static str>, body: Vec<u8>| {
        let l = &l;
        async move {
            let mut request = Request::builder()
                .method("POST")
                .uri(path)
                .header("Authorization", format!("Bearer {token}"))
                .header("Idempotency-Key", uid());
            if let Some(media) = media {
                request = request.header("Content-Type", media);
            }
            let response = api::router(l.store.clone())
                .oneshot(request.body(Body::from(body)).unwrap())
                .await
                .unwrap();
            let status = response.status();
            let body: Value =
                serde_json::from_slice(&to_bytes(response.into_body(), 8192).await.unwrap())
                    .unwrap();
            (status, body)
        }
    };
    let projects = format!("/v1/workspaces/{}/projects", l.tenant);
    let project = |name: &str| json!({"name":name}).to_string().into_bytes();
    // JSON sent as a form, as curl -d does unasked, or as nothing at all.
    for media in [
        Some("application/x-www-form-urlencoded"),
        Some("text/plain"),
        None,
    ] {
        let (status, body) = send(projects.clone(), media, project("Unsaid")).await;
        assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE, "{media:?}");
        assert_eq!(body["code"], "unsupported_media_type");
    }
    let made: i64 = sqlx::query_scalar("SELECT count(*) FROM projects WHERE display_name='Unsaid'")
        .fetch_one(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(made, 0);
    // Its parameters and its case are not what is asked about.
    for (media, name) in [
        ("application/json", "Plain"),
        ("application/json; charset=utf-8", "Charset"),
        ("Application/JSON", "Shouted"),
    ] {
        let (status, body) = send(projects.clone(), Some(media), project(name)).await;
        assert_eq!(status, StatusCode::CREATED, "{media}: {body}");
    }
    // A request with no body says nothing about one.
    let app = l.command_app().await;
    let runs = format!("{projects}/{}/apps/{app}/runs", l.project);
    let runner = key(&l, None, &["read", "runs:write"]).await;
    let response = api::router(l.store.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(&runs)
                .header("Authorization", format!("Bearer {}", s(&runner["token"])))
                .header("Idempotency-Key", uid())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);

    // A component is application/wasm, and JSON is not one.
    let artifacts = format!("{projects}/{}/artifacts", l.project);
    let component = b"\0asm\x0d\0\x01\0 another".to_vec();
    for media in [
        Some("application/json"),
        Some("application/octet-stream"),
        None,
    ] {
        let (status, body) = send(artifacts.clone(), media, component.clone()).await;
        assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE, "{media:?}");
        assert_eq!(body["code"], "unsupported_media_type");
    }
    let (status, body) = send(artifacts, Some("application/wasm"), component).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    l.finish().await;
}

#[tokio::test]
async fn an_id_that_could_be_none_is_malformed_in_a_body_and_missing_in_a_path() {
    let l = Lab::new().await;
    let app = l.command_app().await;
    let k = key(&l, None, &["read", "apps:write"]).await;
    let token = s(&k["token"]);
    let base = format!("/v1/workspaces/{}/projects/{}", l.tenant, l.project);
    let triggers = json!({"manual":true,"http":false});
    let revision = l
        .store
        .app(&l.operator, &l.tenant, &l.project, &app)
        .await
        .unwrap()["revision"]
        .clone();
    let cases = [
        (
            "POST",
            format!("{base}/apps/deploy"),
            json!({"name":"malformed","artifact_id":"@","triggers":triggers}),
        ),
        (
            "POST",
            format!("{base}/apps"),
            json!({"name":"malformed","artifact_id":"@"}),
        ),
        (
            "POST",
            format!("{base}/apps/{app}/versions"),
            json!({"artifact_id":"@","expected_revision":revision}),
        ),
        (
            "POST",
            format!("{base}/apps/{app}/releases"),
            json!({"version_id":"@","expected_revision":revision}),
        ),
        (
            "PUT",
            format!("{base}/apps/{app}/connections"),
            json!({"connections":[{"connection_id":"@"}],"expected_revision":revision}),
        ),
    ];
    for (method, path, body) in &cases {
        // No id at all: too short, not hexadecimal, upper case, not a string.
        for malformed in [
            json!("abc"),
            json!("z".repeat(32)),
            json!("A".repeat(32)),
            json!(7),
        ] {
            let body = serde_json::from_str::<Value>(
                &body.to_string().replace("\"@\"", &malformed.to_string()),
            )
            .unwrap();
            let (status, answer) = call(&l, token, method, path, body, &uid()).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{method} {path}: {answer}");
            assert_eq!(answer["code"], "invalid_request");
        }
        // One that could be an id, and names nothing.
        let body = serde_json::from_str::<Value>(&body.to_string().replace('@', &uid())).unwrap();
        let (status, answer) = call(&l, token, method, path, body, &uid()).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{method} {path}: {answer}");
    }
    // What a path names is missing either way: a path names a thing.
    for path in [
        format!("{base}/apps/abc"),
        format!("{base}/artifacts/{}", "Z".repeat(32)),
        format!("/v1/workspaces/{}/projects/abc/apps", l.tenant),
    ] {
        assert_eq!(
            call(&l, token, "GET", &path, json!({}), "").await.0,
            StatusCode::NOT_FOUND,
            "{path}"
        );
    }
    let limits = json!({"concurrent_requests":8,"requests_per_minute":120});
    assert_eq!(
        call(
            &l,
            &l.token,
            "PATCH",
            "/v1/workspaces/abc/http-limits",
            limits,
            ""
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    l.finish().await;
}

#[tokio::test]
async fn accepted_means_still_pending_and_nothing_else() {
    let l = Lab::new().await;
    l.validated().await;
    let k = key(
        &l,
        Some(&l.project),
        &["read", "apps:write", "runs:write", "connections:write"],
    )
    .await;
    let token = s(&k["token"]);
    let base = format!("/v1/workspaces/{}/projects/{}", l.tenant, l.project);
    // Every change that answers with an operation, as it is first made and
    // as it is retried: 202 exactly when the operation is pending.
    let mut seen = std::collections::BTreeSet::new();
    let mut change = async |method: &str, path: String, body: Value, made: StatusCode| {
        let key = uid();
        for attempt in ["first", "retry"] {
            let (status, op) = call(&l, token, method, &path, body.clone(), &key).await;
            let expected = if op["state"] == "pending" {
                StatusCode::ACCEPTED
            } else {
                made
            };
            assert_eq!(status, expected, "{attempt} {method} {path}: {op}");
            seen.insert((s(&op["kind"]).to_owned(), s(&op["state"]).to_owned()));
        }
        call(&l, token, method, &path, body, &key).await.1
    };
    let deploy = |name: &str, http: bool| json!({"name":name,"artifact_id":l.artifact,"triggers":{"manual":true,"http":http}});
    // With no node, an HTTP app waits for one; a command app needs none.
    let web = change(
        "POST",
        format!("{base}/apps/deploy"),
        deploy("web", true),
        StatusCode::CREATED,
    )
    .await;
    assert_eq!(web["state"], "pending");
    let app = change(
        "POST",
        format!("{base}/apps/deploy"),
        deploy("job", false),
        StatusCode::CREATED,
    )
    .await;
    assert_eq!(app["state"], "succeeded");
    let app = s(&app["resource_id"]).to_owned();
    let revision = async || {
        l.store
            .app(&l.operator, &l.tenant, &l.project, &app)
            .await
            .unwrap()["revision"]
            .clone()
    };
    let connection = change(
        "POST",
        format!("{base}/connections"),
        json!({"type":"https","name":"example","origin":"https://example.com"}),
        StatusCode::CREATED,
    )
    .await;
    let run = change(
        "POST",
        format!("{base}/apps/{app}/runs"),
        json!({}),
        StatusCode::OK,
    )
    .await;
    assert_eq!(run["state"], "pending");
    change(
        "POST",
        format!("{base}/apps/{app}/runs/{}/cancel", s(&run["resource_id"])),
        json!({}),
        StatusCode::OK,
    )
    .await;
    change(
        "PUT",
        format!("{base}/apps/{app}/triggers"),
        json!({"manual":false,"expected_revision":1}),
        StatusCode::OK,
    )
    .await;
    change(
        "PATCH",
        format!("{base}/apps/{app}"),
        json!({"desired":"stopped","expected_revision":revision().await}),
        StatusCode::OK,
    )
    .await;
    // A deletion says its revision in its query, and has no body.
    let delete = format!("{base}/apps/{app}?expected_revision={}", revision().await);
    let deleted = uid();
    for attempt in ["first", "retry"] {
        let response = api::router(l.store.clone())
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(&delete)
                    .header("Authorization", format!("Bearer {token}"))
                    .header("Idempotency-Key", &deleted)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let op: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 8192).await.unwrap()).unwrap();
        let expected = if op["state"] == "pending" {
            StatusCode::ACCEPTED
        } else {
            StatusCode::OK
        };
        assert_eq!(status, expected, "{attempt} DELETE {delete}: {op}");
        seen.insert((s(&op["kind"]).to_owned(), s(&op["state"]).to_owned()));
    }
    // Revoking a connection takes no body.
    let revoke = format!("{base}/connections/{}", s(&connection["resource_id"]));
    let revoked = uid();
    for attempt in ["first", "retry"] {
        let response = api::router(l.store.clone())
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(&revoke)
                    .header("Authorization", format!("Bearer {token}"))
                    .header("Idempotency-Key", &revoked)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let op: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 8192).await.unwrap()).unwrap();
        let expected = if op["state"] == "pending" {
            StatusCode::ACCEPTED
        } else {
            StatusCode::OK
        };
        assert_eq!(status, expected, "{attempt} DELETE {revoke}: {op}");
        seen.insert((s(&op["kind"]).to_owned(), s(&op["state"]).to_owned()));
    }
    // Both were met: an operation pending, and operations made.
    assert!(seen.iter().any(|(_, state)| state == "pending"), "{seen:?}");
    assert!(
        seen.iter().any(|(_, state)| state == "succeeded"),
        "{seen:?}"
    );
    assert!(seen.len() >= 8, "{seen:?}");
    l.finish().await;
}

#[tokio::test]
async fn the_api_has_one_name_for_a_thing() {
    let l = Lab::new().await;
    let k = key(&l, None, &["read", "connections:write"]).await;
    let token = s(&k["token"]);
    let tenants = format!("/v1/tenants/{}", l.tenant);
    let workspace = format!("/v1/workspaces/{}", l.tenant);
    // A workspace was once also a tenant, and a connection an external
    // endpoint. Those names are no routes now, to a key or the operator.
    for (method, path) in [
        ("GET", "/v1/tenants".to_owned()),
        ("POST", "/v1/tenants".to_owned()),
        ("GET", format!("{tenants}/projects")),
        ("GET", format!("{tenants}/projects/{}/apps", l.project)),
        ("GET", format!("{tenants}/api-keys")),
        ("POST", format!("{tenants}/lifecycle")),
        (
            "GET",
            format!("{workspace}/projects/{}/external-endpoints", l.project),
        ),
        (
            "POST",
            format!("{workspace}/projects/{}/external-endpoints", l.project),
        ),
    ] {
        let as_operator = call(&l, &l.token, method, &path, json!({}), "k").await;
        assert_eq!(as_operator.0, StatusCode::NOT_FOUND, "{method} {path}");
        let as_key = call(&l, token, method, &path, json!({}), "k").await;
        assert!(
            matches!(as_key.0, StatusCode::NOT_FOUND | StatusCode::FORBIDDEN),
            "{method} {path}: {}",
            as_key.0
        );
    }
    // The operator's routes are where the workspace's are.
    let workspaces = call(&l, &l.token, "GET", "/v1/workspaces", json!({}), "").await;
    assert_eq!(workspaces.0, StatusCode::OK);
    let keys = call(
        &l,
        &l.token,
        "GET",
        &format!("{workspace}/api-keys"),
        json!({}),
        "",
    )
    .await;
    assert_eq!(keys.0, StatusCode::OK, "{}", keys.1);
    let limits = json!({"concurrent_requests":8,"requests_per_minute":120});
    let limited = call(
        &l,
        &l.token,
        "PATCH",
        &format!("{workspace}/http-limits"),
        limits.clone(),
        "",
    )
    .await;
    assert_eq!(limited.0, StatusCode::OK, "{}", limited.1);
    // And a key is refused them there, as it was.
    for (method, path, body) in [
        ("GET", format!("{workspace}/api-keys"), json!({})),
        ("PATCH", format!("{workspace}/http-limits"), limits),
        ("POST", "/v1/workspaces".to_owned(), json!({})),
        (
            "PATCH",
            workspace.clone(),
            json!({"default_app_size":"large"}),
        ),
    ] {
        let refused = call(&l, token, method, &path, body, "k").await;
        assert_eq!(refused.0, StatusCode::FORBIDDEN, "{method} {path}");
        assert_eq!(refused.1["code"], "permission_denied");
    }
    // A connection is a connection, to make and to read.
    let connections = format!("{workspace}/projects/{}/connections", l.project);
    let made = call(
        &l,
        token,
        "POST",
        &connections,
        json!({"type":"https","name":"example","origin":"https://example.com"}),
        "connect",
    )
    .await;
    assert_eq!(made.0, StatusCode::CREATED, "{}", made.1);
    let read = call(
        &l,
        token,
        "GET",
        &format!("{connections}/{}", s(&made.1["resource_id"])),
        json!({}),
        "",
    )
    .await;
    assert_eq!(read.0, StatusCode::OK, "{}", read.1);
    assert_eq!(read.1["name"], "example");
    l.finish().await;
}

#[tokio::test]
async fn an_operation_says_what_was_asked_and_nothing_of_who_asked() {
    let l = Lab::new().await;
    let app = l.command_app().await;
    let writer = key(&l, Some(&l.project), &["read", "runs:write"]).await;
    let reader = key(&l, Some(&l.project), &["read"]).await;
    let (writer, reader) = (s(&writer["token"]), s(&reader["token"]));
    let base = format!("/v1/workspaces/{}/projects/{}", l.tenant, l.project);
    let (status, run) = call(
        &l,
        writer,
        "POST",
        &format!("{base}/apps/{app}/runs"),
        json!({}),
        "the writer's own key",
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{run}");
    let names = |operation: &Value| {
        operation
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>()
            .join(",")
    };
    let shown = "created,error,id,kind,resource_id,state,updated";
    assert_eq!(names(&run), shown);
    let cancel = format!("{base}/apps/{app}/runs/{}/cancel", s(&run["resource_id"]));
    let (_, cancelled) = call(&l, writer, "POST", &cancel, json!({}), "cancel it").await;
    assert_eq!(names(&cancelled), shown);

    // Another key of the project reads the operations: what was done, and
    // not the keys the writer made its requests with.
    let (status, listed) = call(
        &l,
        reader,
        "GET",
        &format!("{base}/operations"),
        json!({}),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let listed = listed["items"].as_array().unwrap();
    assert!(listed.len() >= 2);
    for operation in listed {
        assert_eq!(names(operation), shown);
    }
    let text = Value::Array(listed.clone()).to_string();
    assert!(!text.contains("the writer's own key") && !text.contains("cancel it"));
    // The cancellation is read as it was answered, wherever it is read.
    let read = listed
        .iter()
        .find(|operation| operation["id"] == cancelled["id"])
        .unwrap();
    assert_eq!(read["kind"], "cancel-run");
    assert_eq!(read["resource_id"], run["resource_id"]);
    let (_, one) = call(
        &l,
        reader,
        "GET",
        &format!("{base}/operations/{}", s(&cancelled["id"])),
        json!({}),
        "",
    )
    .await;
    assert_eq!(&one, read);
    // By the key it was made with, through the app it was made of.
    let (status, found) = call(
        &l,
        reader,
        "GET",
        &format!("{base}/apps/{app}/submissions/cancel%20it"),
        json!({}),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{found}");
    assert_eq!(&found, read);

    // A workspace is a workspace in what is answered, as in what is asked.
    let (_, me) = call(&l, reader, "GET", "/v1/me", json!({}), "").await;
    assert_eq!(me["workspace_id"], l.tenant);
    assert!(me.get("tenant_id").is_none());
    let (_, read) = call(
        &l,
        reader,
        "GET",
        &format!("{base}/apps/{app}"),
        json!({}),
        "",
    )
    .await;
    assert_eq!(read["workspace_id"], l.tenant);
    l.finish().await;
}

#[tokio::test]
async fn every_list_is_pages_of_items_newest_first() {
    let l = Lab::new().await;
    let operator = l.token.clone();
    let workspace = format!("/v1/workspaces/{}", l.tenant);
    let project = format!("{workspace}/projects/{}", l.project);
    // Three of each kind of thing, beside what the lab has.
    for n in 0..3 {
        let allowance = json!({"cpu_percent":100,"memory_mib":512,"storage_bytes":1048576,"instances":1,"transfer_bytes":1048576});
        for (path, body) in [
            (
                "/v1/workspaces".to_owned(),
                json!({"name":format!("w{n}"),"allowance":allowance}),
            ),
            (
                format!("{workspace}/projects"),
                json!({"name":format!("Project {n}")}),
            ),
            (
                format!("{project}/secrets"),
                json!({"name":format!("secret-{n}"),"value":"value"}),
            ),
            (
                format!("{project}/connections"),
                json!({"type":"https","name":format!("origin-{n}"),"origin":format!("https://o{n}.example.com")}),
            ),
            (
                format!("{workspace}/api-keys"),
                json!({"name":format!("key-{n}"),"permissions":["read"],"ttl_seconds":60}),
            ),
            (
                "/v1/nodes".to_owned(),
                json!({"name":format!("node-{n}"),"cert_sha256":format!("{n}").repeat(64),"endpoint":format!("https://node-{n}.internal:9443"),"backend":"wasm","architecture":"x86_64","runtime":"wasmtime-50.0.0-fenders-v1","cpu_percent":200,"memory_mib":1024,"instances":4}),
            ),
        ] {
            let made = call(&l, &operator, "POST", &path, body, &uid()).await;
            assert!(made.0.is_success(), "POST {path}: {}", made.1);
        }
        l.store
            .upload(
                &l.operator,
                &l.tenant,
                &l.project,
                format!("\0asm\x0d\0\x01\0 {n}").as_bytes(),
            )
            .await
            .unwrap();
    }
    for list in [
        "/v1/workspaces".to_owned(),
        format!("{workspace}/projects"),
        format!("{workspace}/api-keys"),
        "/v1/nodes".to_owned(),
        format!("{project}/artifacts"),
        format!("{project}/secrets"),
        format!("{project}/connections"),
        format!("{project}/operations"),
    ] {
        // All at once: items, and no page after them.
        let (status, whole) = call(&l, &operator, "GET", &list, json!({}), "").await;
        assert_eq!(status, StatusCode::OK, "{list}: {whole}");
        assert!(whole["next"].is_null(), "{list}");
        let whole: Vec<Value> = whole["items"].as_array().unwrap().clone();
        assert!(whole.len() >= 3, "{list}: {}", whole.len());
        // Newest first.
        let created: Vec<&str> = whole.iter().map(|item| s(&item["created"])).collect();
        assert!(
            created.windows(2).all(|pair| pair[0] >= pair[1]),
            "{list}: {created:?}"
        );
        // The same by twos: each page's next continues it, and the last has none.
        let mut walked = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let path = match &cursor {
                Some(cursor) => format!("{list}?limit=2&before={cursor}"),
                None => format!("{list}?limit=2"),
            };
            let (status, page) = call(&l, &operator, "GET", &path, json!({}), "").await;
            assert_eq!(status, StatusCode::OK, "{path}: {page}");
            let items = page["items"].as_array().unwrap();
            assert!(items.len() <= 2 && !items.is_empty(), "{path}");
            walked.extend(items.iter().cloned());
            match page["next"].as_str() {
                Some(next) => cursor = Some(next.to_owned()),
                None => break,
            }
            assert_eq!(items.len(), 2, "{path}: a page with a next is a full one");
            assert!(walked.len() <= whole.len(), "{list} does not end");
        }
        assert_eq!(walked, whole, "{list}");
        // What a list takes, and nothing else.
        for (query, status) in [
            ("limit=0", StatusCode::BAD_REQUEST),
            ("limit=101", StatusCode::BAD_REQUEST),
            ("limit=many", StatusCode::BAD_REQUEST),
            ("before=not-a-cursor", StatusCode::BAD_REQUEST),
            ("offset=2", StatusCode::BAD_REQUEST),
            ("limit=100", StatusCode::OK),
        ] {
            let path = format!("{list}?{query}");
            assert_eq!(
                call(&l, &operator, "GET", &path, json!({}), "").await.0,
                status,
                "{path}"
            );
        }
        // A cursor that names nothing has nothing after it.
        let (status, page) = call(
            &l,
            &operator,
            "GET",
            &format!("{list}?before={}", uid()),
            json!({}),
            "",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(page, json!({"items":[],"next":null}), "{list}");
    }
    // A key's lists are its own, paged the same.
    let k = key(&l, None, &["read"]).await;
    let (_, mine) = call(&l, s(&k["token"]), "GET", "/v1/workspaces", json!({}), "").await;
    assert_eq!(mine["items"].as_array().unwrap().len(), 1);
    assert_eq!(mine["items"][0]["id"], l.tenant);
    assert!(mine["next"].is_null());
    l.finish().await;
}

#[tokio::test]
async fn a_change_names_the_revision_it_was_decided_on() {
    let l = Lab::new().await;
    let app = l.command_app().await;
    let k = key(&l, None, &["read", "apps:write"]).await;
    let token = s(&k["token"]);
    let route = format!(
        "/v1/workspaces/{}/projects/{}/apps/{app}",
        l.tenant, l.project
    );
    let (_, read) = call(&l, token, "GET", &route, json!({}), "").await;
    let revision = read["revision"].as_i64().unwrap();
    let delete = |query: String, body: Option<Value>| {
        let (l, route) = (&l, route.clone());
        async move {
            let mut request = Request::builder()
                .method("DELETE")
                .uri(format!("{route}{query}"))
                .header("Authorization", format!("Bearer {token}"))
                .header("Idempotency-Key", uid());
            let body = match body {
                Some(body) => {
                    request = request.header("Content-Type", "application/json");
                    Body::from(body.to_string())
                }
                None => Body::empty(),
            };
            let response = api::router(l.store.clone())
                .oneshot(request.body(body).unwrap())
                .await
                .unwrap();
            let status = response.status();
            let body: Value =
                serde_json::from_slice(&to_bytes(response.into_body(), 8192).await.unwrap())
                    .unwrap();
            (status, body)
        }
    };
    // A deletion has no body: the revision it is of is in its query. One
    // in a body, as it once was sent, is not read.
    let in_body = delete(String::new(), Some(json!({"expected_revision":revision}))).await;
    assert_eq!(in_body.0, StatusCode::BAD_REQUEST, "{}", in_body.1);
    for query in [
        "",
        "?expected_revision=",
        "?expected_revision=soon",
        "?revision=1",
    ] {
        assert_eq!(
            delete(query.to_owned(), None).await.0,
            StatusCode::BAD_REQUEST,
            "{query}"
        );
    }
    let stale = delete(format!("?expected_revision={}", revision + 1), None).await;
    assert_eq!(stale.0, StatusCode::CONFLICT);
    assert_eq!(stale.1["code"], "revision_conflict");
    let (_, still) = call(&l, token, "GET", &route, json!({}), "").await;
    assert_eq!(still["revision"], revision);
    let deleted = delete(format!("?expected_revision={revision}"), None).await;
    assert!(deleted.0.is_success(), "{}", deleted.1);
    assert_eq!(deleted.1["kind"], "delete-app");
    assert_eq!(
        call(&l, token, "GET", &route, json!({}), "").await.0,
        StatusCode::NOT_FOUND
    );

    // A workspace's allowance has a revision too, which the operator's
    // change may name: then one decided on an allowance since changed is
    // refused, where without it the later change silently wins.
    let workspace = format!("/v1/workspaces/{}", l.tenant);
    let (_, listed) = call(&l, &l.token, "GET", "/v1/workspaces", json!({}), "").await;
    let current = listed["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|workspace| workspace["id"] == l.tenant)
        .unwrap()["allowance_revision"]
        .as_i64()
        .unwrap();
    let allowance = |instances: i64| json!({"cpu_percent":400,"memory_mib":4096,"instances":instances,"storage_bytes":20000000000i64,"transfer_bytes":10000000});
    let first = call(
        &l,
        &l.token,
        "PATCH",
        &workspace,
        json!({"allowance":allowance(5),"expected_revision":current}),
        "",
    )
    .await;
    assert_eq!(first.0, StatusCode::OK, "{}", first.1);
    assert_eq!(first.1["allowance_revision"], current + 1);
    let stale = call(
        &l,
        &l.token,
        "PATCH",
        &workspace,
        json!({"allowance":allowance(6),"expected_revision":current}),
        "",
    )
    .await;
    assert_eq!(stale.0, StatusCode::CONFLICT, "{}", stale.1);
    assert_eq!(stale.1["code"], "revision_conflict");
    // Without one the change is made, as it was.
    let unguarded = call(
        &l,
        &l.token,
        "PATCH",
        &workspace,
        json!({"allowance":allowance(6)}),
        "",
    )
    .await;
    assert_eq!(unguarded.0, StatusCode::OK, "{}", unguarded.1);
    assert_eq!(unguarded.1["instances"], 6);
    l.finish().await;
}

#[tokio::test]
async fn whether_it_is_up_and_can_serve_is_asked_without_a_credential() {
    let l = Lab::new().await;
    let probe = |path: &'static str, token: Option<&'static str>| {
        let l = &l;
        async move {
            let mut request = Request::builder().uri(path);
            if let Some(token) = token {
                request = request.header("Authorization", format!("Bearer {token}"));
            }
            let response = api::router(l.store.clone())
                .oneshot(request.body(Body::empty()).unwrap())
                .await
                .unwrap();
            let status = response.status();
            let headers = response.headers().clone();
            let body: Value =
                serde_json::from_slice(&to_bytes(response.into_body(), 8192).await.unwrap())
                    .unwrap();
            super::contract::conforms("GET", path, status, &body);
            (status, headers, body)
        }
    };
    // No credential, and one that opens nothing, are answered the same.
    for token in [None, Some("fnd_tok_nothing")] {
        let (status, headers, body) = probe("/healthz", token).await;
        assert_eq!((status, &body), (StatusCode::OK, &json!({"status":"ok"})));
        assert_eq!(headers["cache-control"], "no-store");
        let (status, _, body) = probe("/readyz", token).await;
        assert_eq!(
            (status, &body),
            (StatusCode::OK, &json!({"status":"ready"}))
        );
    }
    // Nothing else is, and these are only at the root, only by GET.
    for (method, path) in [
        ("GET", "/v1/healthz"),
        ("GET", "/health"),
        ("POST", "/healthz"),
        ("GET", "/v1/control-plane/status"),
    ] {
        let response = api::router(l.store.clone())
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{method} {path}"
        );
    }
    // After a restore, until the operator activates it, no change is
    // admitted: it is up, and not ready. It says only that.
    sqlx::query("UPDATE recovery_barrier SET active=true")
        .execute(&l.store.pool)
        .await
        .unwrap();
    let (status, _, body) = probe("/readyz", None).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body, json!({"status":"unavailable"}));
    assert_eq!(probe("/healthz", None).await.0, StatusCode::OK);
    sqlx::query("UPDATE recovery_barrier SET active=false")
        .execute(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(probe("/readyz", None).await.0, StatusCode::OK);
    // A database that is not there: up, and not ready.
    l.store.pool.close().await;
    assert_eq!(probe("/healthz", None).await.0, StatusCode::OK);
    assert_eq!(
        probe("/readyz", None).await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    sqlx::query(&format!("DROP SCHEMA {} CASCADE", l.schema))
        .execute(&l.admin)
        .await
        .unwrap();
}

#[tokio::test]
async fn a_workspace_is_read_by_itself() {
    let l = Lab::new().await;
    let route = format!("/v1/workspaces/{}", l.tenant);
    let (status, mine) = call(&l, &l.token, "GET", &route, json!({}), "").await;
    assert_eq!(status, StatusCode::OK, "{mine}");
    assert_eq!(mine["id"], l.tenant);
    assert_eq!(mine["name"], "alpha");
    assert_eq!(mine["lifecycle_revision"], 1);
    // It is the workspace the list has.
    let (_, listed) = call(&l, &l.token, "GET", "/v1/workspaces", json!({}), "").await;
    assert_eq!(listed["items"][0], mine);
    // A key reads its own, without what is the operator's; one of a
    // project reads the workspace its project is of.
    for scope in [None, Some(l.project.as_str())] {
        let k = key(&l, scope, &["read"]).await;
        let (status, read) = call(&l, s(&k["token"]), "GET", &route, json!({}), "").await;
        assert_eq!(status, StatusCode::OK, "{read}");
        assert_eq!(read["id"], l.tenant);
        assert_eq!(read["instances"], mine["instances"]);
        for operators in [
            "lifecycle_revision",
            "lifecycle_reason",
            "allowance_revision",
        ] {
            assert!(read.get(operators).is_none(), "{operators}");
        }
    }
    // Another's, and one that is none, do not exist to it or to anyone.
    let other = call(
        &l,
        &l.token,
        "POST",
        "/v1/workspaces",
        json!({"name":"other","allowance":{"cpu_percent":100,"memory_mib":512,"storage_bytes":1048576,"instances":1,"transfer_bytes":1048576}}),
        "other",
    )
    .await;
    let k = key(&l, None, &["read"]).await;
    for (token, id, expected) in [
        (
            s(&k["token"]),
            s(&other.1["id"]).to_owned(),
            StatusCode::NOT_FOUND,
        ),
        (s(&k["token"]), uid(), StatusCode::NOT_FOUND),
        (l.token.as_str(), uid(), StatusCode::NOT_FOUND),
        (l.token.as_str(), "abc".to_owned(), StatusCode::NOT_FOUND),
        (
            l.token.as_str(),
            s(&other.1["id"]).to_owned(),
            StatusCode::OK,
        ),
    ] {
        let status = call(
            &l,
            token,
            "GET",
            &format!("/v1/workspaces/{id}"),
            json!({}),
            "",
        )
        .await
        .0;
        assert_eq!(status, expected, "{id}");
    }
    l.finish().await;
}
