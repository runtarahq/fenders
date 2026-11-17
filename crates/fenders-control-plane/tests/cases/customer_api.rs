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
    (status, serde_json::from_slice(&body).unwrap())
}
async fn key(l: &Lab, scope: Option<&str>, permissions: &[&str]) -> Value {
    let (status, value) = call(l, &l.token, "POST", &format!("/v1/workspaces/{}/api-keys", l.tenant),
        json!({"name":"automation","project_id":scope,"permissions":permissions,"ttl_seconds":3600}), &uid()).await;
    assert_eq!(status, StatusCode::CREATED, "{value}");
    value
}

#[tokio::test]
async fn customer_api_keys_limit_aliases_and_revalidate_revocation() {
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
            format!("/v1/tenants/{}/projects/{}/executions", l.tenant, l.project),
        ),
        ("GET", "/v1/nodes".into()),
        ("POST", format!("/v1/tenants/{}/credentials", l.tenant)),
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
    assert_eq!(a.0, StatusCode::CREATED);
    assert_eq!(b.0, StatusCode::CREATED);
    assert_eq!(a.1["id"], b.1["id"]);
    assert_ne!(a.1.get("token").is_some(), b.1.get("token").is_some());
    let secret =
        a.1.get("token")
            .or(b.1.get("token"))
            .unwrap()
            .as_str()
            .unwrap();
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
async fn customer_api_secret_retries_compare_encrypted_value_and_expired_keys_fail() {
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
    assert_eq!(
        call(
            &l,
            token,
            "POST",
            &route,
            json!({"name":"password","value":"different"}),
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
            "/v1/tenants/{}/projects/{}/apps/deploy",
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

/// A credential lives no longer than the one that issued it, and ends when
/// that one is revoked, or when the member who issued it is removed or their
/// account disabled.
#[tokio::test]
async fn credentials_end_with_whoever_issued_them() {
    let l = Lab::new().await;
    let issue = |by: Principal, ttl: i64| {
        let store = l.store.clone();
        let tenant = l.tenant.clone();
        async move {
            let v = store
                .issue_credential(
                    &by,
                    &tenant,
                    serde_json::from_value(
                        json!({"name":"line","role":"owner","project_id":null,"ttl_seconds":ttl}),
                    )
                    .unwrap(),
                )
                .await
                .unwrap();
            (store.authenticate(s(&v["token"])).await.unwrap(), v)
        }
    };
    let expires = |id: &str| {
        let (pool, id) = (l.store.pool.clone(), id.to_owned());
        async move {
            sqlx::query_scalar::<_, f64>(
                "SELECT extract(epoch FROM expires)::float8 FROM credentials WHERE id=$1",
            )
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap()
        }
    };
    // Two minutes from the operator; thirty days asked of it, and of that.
    let (parent, parent_row) = issue(l.operator.clone(), 120).await;
    let (child, child_row) = issue(parent.clone(), 2_592_000).await;
    let (_, grandchild_row) = issue(child.clone(), 2_592_000).await;
    let limit = expires(s(&parent_row["id"])).await;
    assert_eq!(expires(s(&child_row["id"])).await, limit);
    assert_eq!(expires(s(&grandchild_row["id"])).await, limit);
    // An API key issued with a credential ends with it too.
    let (status, key) = call(
        &l,
        s(&child_row["token"]),
        "POST",
        &format!("/v1/workspaces/{}/api-keys", l.tenant),
        json!({"name":"automation","project_id":null,"permissions":["read"],"ttl_seconds":2592000}),
        &uid(),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{key}");
    assert_eq!(expires(s(&key["id"])).await, limit);
    // The operator's own are as long as asked.
    let (_, long) = issue(l.operator.clone(), 2_592_000).await;
    assert!(expires(s(&long["id"])).await > limit + 29.0 * 86400.0);

    // Revoking the parent ends the whole line, and nothing beside it.
    l.store
        .revoke_credential(&l.operator, &l.tenant, s(&parent_row["id"]))
        .await
        .unwrap();
    for token in [&parent_row, &child_row, &grandchild_row, &key] {
        assert_eq!(
            l.store
                .authenticate(s(&token["token"]))
                .await
                .unwrap_err()
                .status,
            StatusCode::UNAUTHORIZED
        );
    }
    assert!(l.store.authenticate(s(&long["token"])).await.is_ok());

    // A member who issued credentials while an owner: removed, or disabled.
    let member_with_key = |name: &'static str| {
        let l = &l;
        let issue = &issue;
        async move {
            let (user, membership) = (uid(), uid());
            sqlx::query("INSERT INTO customer_users(id,issuer,subject) VALUES($1,'https://identity.test',$2)")
                .bind(&user).bind(name).execute(&l.store.pool).await.unwrap();
            sqlx::query("INSERT INTO workspace_memberships(id,tenant_id,user_id,role) VALUES($1,$2,$3,'owner')")
                .bind(&membership).bind(&l.tenant).bind(&user).execute(&l.store.pool).await.unwrap();
            // As `create_api_key` and `issue_credential` record it for a
            // browser session of theirs.
            let (issued, row) = issue(l.operator.clone(), 3600).await;
            sqlx::query("UPDATE credentials SET created_by=$1 WHERE id=$2")
                .bind(&user)
                .bind(s(&row["id"]))
                .execute(&l.store.pool)
                .await
                .unwrap();
            // And one issued with that in turn.
            let (_, second) = issue(issued, 3600).await;
            (user, membership, row, second)
        }
    };
    // Another owner stays, so the last-owner rule allows the changes.
    let _staying = member_with_key("staying").await;
    let (_, membership, first, second) = member_with_key("removed").await;
    l.store
        .update_member(
            &l.operator,
            &l.tenant,
            &membership,
            json!({"revoked":true,"expected_revision":1}),
        )
        .await
        .unwrap();
    let (user, _, third, fourth) = member_with_key("disabled").await;
    l.store
        .update_customer_user(
            &l.operator,
            &user,
            json!({"disabled":true,"expected_revision":1}),
        )
        .await
        .unwrap();
    for token in [&first, &second, &third, &fourth] {
        assert_eq!(
            l.store
                .authenticate(s(&token["token"]))
                .await
                .unwrap_err()
                .status,
            StatusCode::UNAUTHORIZED
        );
    }
    // The owner who stayed keeps theirs.
    assert!(l.store.authenticate(s(&_staying.2["token"])).await.is_ok());
    assert!(l.store.authenticate(s(&long["token"])).await.is_ok());
    l.finish().await;
}
