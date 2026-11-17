use super::*;

#[tokio::test]
async fn identity_migration_preserves_membership_and_keys_but_invalidates_sessions() {
    let l = IdentityLab::new().await;
    let browser = l.login("migrate-owner").await;
    let membership = l.member(&browser, "owner", None).await;
    let (_, key) = l.lab.credential("editor", None).await;
    let original = l
        .lab
        .store
        .customer_user(&l.lab.operator, &browser.user)
        .await
        .unwrap();
    let mapping = json!({"expected_revision":original["revision"],"expected_issuer":original["issuer"],"expected_subject":original["subject"],"issuer":"https://auth.example.test/","subject":"auth0|migrated-owner"});
    let path = format!("/v1/customer-users/{}/identity", browser.user);
    assert_eq!(
        l.request(&browser, "PATCH", &path, Some(mapping.clone()), true)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    let response = api::router(l.lab.store.clone())
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(&path)
                .header("Authorization", format!("Bearer {}", l.lab.token))
                .body(Body::from(mapping.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let result: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap();
    assert_eq!(result["id"], browser.user);
    assert_eq!(result["revision"], 2);
    assert_eq!(result["subject"], mapping["subject"]);
    assert_eq!(result["disabled"], false);
    assert_eq!(
        l.request(&browser, "GET", "/auth/session", None, false)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    let retained: Value =
        sqlx::query_scalar("SELECT to_jsonb(m) FROM workspace_memberships m WHERE id=$1")
            .bind(s(&membership["id"]))
            .fetch_one(&l.lab.store.pool)
            .await
            .unwrap();
    assert_eq!(retained, membership);
    assert!(l.lab.store.authenticate(s(&key["token"])).await.is_ok());
    // A lost migration response cannot move the identity a second time.
    assert_eq!(
        l.lab
            .store
            .migrate_customer_identity(&l.lab.operator, &browser.user, mapping)
            .await
            .unwrap_err()
            .status,
        StatusCode::CONFLICT
    );
    // The old provider identity gets no inherited workspace access on login.
    let old = l.login("migrate-owner").await;
    assert_ne!(old.user, browser.user);
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM workspace_memberships WHERE user_id=$1")
            .bind(&old.user)
            .fetch_one(&l.lab.store.pool)
            .await
            .unwrap();
    assert_eq!(count, 0);
    let audit: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit WHERE action='customer_user.migrate_identity'",
    )
    .fetch_one(&l.lab.store.pool)
    .await
    .unwrap();
    assert_eq!(audit, 1);
    l.finish().await;
}

#[tokio::test]
async fn identity_migration_rejects_collision_and_rolls_back_on_audit_failure() {
    let l = IdentityLab::new().await;
    let browser = l.login("migration-errors").await;
    let original = l
        .lab
        .store
        .customer_user(&l.lab.operator, &browser.user)
        .await
        .unwrap();
    let mut mapping = json!({"expected_revision":original["revision"],"expected_issuer":original["issuer"],"expected_subject":original["subject"],"issuer":"https://auth.example.test/","subject":"auth0|collision"});
    sqlx::query("INSERT INTO customer_users(id,issuer,subject) VALUES($1,$2,$3)")
        .bind(uid())
        .bind(s(&mapping["issuer"]))
        .bind(s(&mapping["subject"]))
        .execute(&l.lab.store.pool)
        .await
        .unwrap();
    assert_eq!(
        l.lab
            .store
            .migrate_customer_identity(&l.lab.operator, &browser.user, mapping.clone())
            .await
            .unwrap_err()
            .status,
        StatusCode::CONFLICT
    );
    mapping["subject"] = json!("auth0|unique");
    mapping["issuer"] = json!("https://user:password@auth.example.test/");
    assert_eq!(
        l.lab
            .store
            .migrate_customer_identity(&l.lab.operator, &browser.user, mapping.clone())
            .await
            .unwrap_err()
            .status,
        StatusCode::BAD_REQUEST
    );
    mapping["issuer"] = json!("https://auth.example.test/");
    sqlx::query("ALTER TABLE audit ADD CONSTRAINT reject_identity_migration CHECK (action <> 'customer_user.migrate_identity')")
        .execute(&l.lab.store.pool).await.unwrap();
    assert!(
        l.lab
            .store
            .migrate_customer_identity(&l.lab.operator, &browser.user, mapping)
            .await
            .is_err()
    );
    assert_eq!(
        l.lab
            .store
            .customer_user(&l.lab.operator, &browser.user)
            .await
            .unwrap(),
        original
    );
    assert_eq!(
        l.request(&browser, "GET", "/auth/session", None, false)
            .await
            .0,
        StatusCode::OK
    );
    l.finish().await;
}

async fn operator_request(
    l: &IdentityLab,
    method: &str,
    user: &str,
    value: Value,
) -> (StatusCode, Value) {
    let response = api::router(l.lab.store.clone())
        .oneshot(
            Request::builder()
                .method(method)
                .uri(format!("/v1/customer-users/{user}"))
                .header("Authorization", format!("Bearer {}", l.lab.token))
                .body(if value.is_null() {
                    Body::empty()
                } else {
                    Body::from(value.to_string())
                })
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    assert_eq!(response.headers()["cache-control"], "no-store");
    (
        status,
        serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap(),
    )
}

#[tokio::test]
async fn account_suspension_invalidates_sessions_preserves_work_and_requires_fresh_login() {
    let l = IdentityLab::new().await;
    let browser = l.login("account").await;
    let second = l.login("account").await;
    let unrelated = l.login("unrelated").await;
    let membership = l.member(&browser, "editor", None).await;
    let session: Value = sqlx::query_scalar(
        "SELECT to_jsonb(s) FROM browser_sessions s WHERE user_id=$1 ORDER BY id LIMIT 1",
    )
    .bind(&browser.user)
    .fetch_one(&l.lab.store.pool)
    .await
    .unwrap();
    let stale: Principal = serde_json::from_value(json!({"id":browser.user,"role":"editor","tenant_id":l.lab.tenant,"project_id":null,"membership_id":membership["id"],"session_id":session["id"]})).unwrap();
    let operation = l
        .lab
        .create("account-suspension", json!({"artifact_id":l.lab.artifact}))
        .await;
    let execution = l.lab.run(&operation).await;
    let before = l
        .lab
        .store
        .usage(&l.lab.operator, &l.lab.tenant, None)
        .await
        .unwrap();
    let path = format!("/v1/customer-users/{}", browser.user);
    assert_eq!(
        l.request(&browser, "GET", &path, None, false).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        l.request(
            &browser,
            "PATCH",
            &path,
            Some(json!({"disabled":true,"expected_revision":1})),
            true
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let (credential, _) = l.lab.credential("owner", None).await;
    assert_eq!(
        l.lab
            .store
            .customer_user(&credential, &browser.user)
            .await
            .unwrap_err()
            .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        l.lab
            .store
            .update_customer_user(
                &credential,
                &browser.user,
                json!({"disabled":true,"expected_revision":1})
            )
            .await
            .unwrap_err()
            .status,
        StatusCode::FORBIDDEN
    );
    let (status, original) = operator_request(&l, "GET", &browser.user, Value::Null).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(original["revision"], 1);
    for payload in [
        json!({}),
        json!({"disabled":"true","expected_revision":1}),
        json!({"disabled":true,"expected_revision":0}),
        json!({"disabled":true,"expected_revision":1,"subject":"substitute"}),
    ] {
        assert_eq!(
            operator_request(&l, "PATCH", &browser.user, payload)
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
    }
    let (status, disabled) = operator_request(
        &l,
        "PATCH",
        &browser.user,
        json!({"disabled":true,"expected_revision":1}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(disabled["disabled"], true);
    assert_eq!(disabled["revision"], 2);
    assert_eq!(disabled["subject"], original["subject"]);
    for old in [&browser, &second] {
        assert_eq!(
            l.request(old, "GET", "/auth/session", None, false).await.0,
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        l.request(&unrelated, "GET", "/auth/session", None, false)
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        l.lab
            .store
            .create_project(
                &stale,
                &l.lab.tenant,
                serde_json::from_value(json!({"name":"stale-session"})).unwrap()
            )
            .await
            .unwrap_err()
            .status,
        StatusCode::UNAUTHORIZED
    );
    let pending = l.begin("account", "valid").await;
    assert_eq!(
        l.callback(&pending).await.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(l.lab.run(&operation).await, execution);
    assert_eq!(
        l.lab
            .store
            .usage(&l.lab.operator, &l.lab.tenant, None)
            .await
            .unwrap()["reserved"],
        before["reserved"]
    );
    let members = l
        .lab
        .store
        .members(&l.lab.operator, &l.lab.tenant)
        .await
        .unwrap();
    // The customer read model also contains profile metadata. Every persisted
    // membership field must remain unchanged by account suspension.
    for field in [
        "id",
        "user_id",
        "project_id",
        "role",
        "revoked",
        "revision",
        "created",
        "updated",
    ] {
        assert_eq!(members["items"][0][field], membership[field], "{field}");
    }
    assert_eq!(
        operator_request(
            &l,
            "PATCH",
            &browser.user,
            json!({"disabled":false,"expected_revision":1})
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        operator_request(
            &l,
            "PATCH",
            &browser.user,
            json!({"disabled":false,"expected_revision":2})
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        l.request(&browser, "GET", "/auth/session", None, false)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    let fresh = l.login("account").await;
    assert_eq!(fresh.user, browser.user);
    assert_eq!(
        l.request(&fresh, "GET", "/auth/session", None, false)
            .await
            .1["workspaces"][0]["memberships"][0]["role"],
        "editor"
    );
    let audit: Value = sqlx::query_scalar(
        "SELECT jsonb_agg(detail ORDER BY sequence) FROM audit WHERE action='customer_user.update'",
    )
    .fetch_one(&l.lab.store.pool)
    .await
    .unwrap();
    assert_eq!(audit.as_array().unwrap().len(), 2);
    assert_eq!(audit[0]["sessions_removed"], 2);
    assert!(!audit.to_string().contains(&browser.csrf));
    assert_eq!(
        operator_request(&l, "GET", &uid(), Value::Null).await.0,
        StatusCode::NOT_FOUND
    );
    l.finish().await;
}

#[tokio::test]
async fn account_state_is_revisioned_atomic_and_blocked_during_recovery() {
    let l = IdentityLab::new().await;
    let browser = l.login("concurrent").await;
    let change = json!({"disabled":true,"expected_revision":1});
    sqlx::query("UPDATE recovery_barrier SET active=true")
        .execute(&l.lab.store.pool)
        .await
        .unwrap();
    assert_eq!(
        operator_request(&l, "PATCH", &browser.user, change.clone())
            .await
            .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        operator_request(&l, "GET", &browser.user, Value::Null)
            .await
            .1["revision"],
        1
    );
    sqlx::query("UPDATE recovery_barrier SET active=false")
        .execute(&l.lab.store.pool)
        .await
        .unwrap();
    // A failed audit must roll back both account state and session deletion.
    sqlx::query("ALTER TABLE audit ADD CONSTRAINT reject_account_audit CHECK (action <> 'customer_user.update')").execute(&l.lab.store.pool).await.unwrap();
    assert_eq!(
        operator_request(&l, "PATCH", &browser.user, change.clone())
            .await
            .0,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        operator_request(&l, "GET", &browser.user, Value::Null)
            .await
            .1["revision"],
        1
    );
    assert_eq!(
        l.request(&browser, "GET", "/auth/session", None, false)
            .await
            .0,
        StatusCode::OK
    );
    sqlx::query("ALTER TABLE audit DROP CONSTRAINT reject_account_audit")
        .execute(&l.lab.store.pool)
        .await
        .unwrap();
    let (a, b) = tokio::join!(
        operator_request(&l, "PATCH", &browser.user, change.clone()),
        operator_request(&l, "PATCH", &browser.user, change)
    );
    assert!(
        (a.0 == StatusCode::OK && b.0 == StatusCode::CONFLICT)
            || (b.0 == StatusCode::OK && a.0 == StatusCode::CONFLICT)
    );
    let reopened = Store::from_pool(l.lab.store.pool.clone(), l.lab.root.path()).unwrap();
    assert_eq!(
        reopened
            .customer_user(&l.lab.operator, &browser.user)
            .await
            .unwrap()["revision"],
        2
    );
    // Simulate a existing-user disabled account with a retained session. An enable
    // also clears it, so historical credentials can never become usable again.
    sqlx::query("INSERT INTO browser_sessions(id,user_id,token_hash,csrf_hash,csrf_encrypted,expires,client_id,provider_iat) VALUES($1,$2,$3,$4,'old',now()+interval '1 hour','fenders-test',0)")
        .bind(uid()).bind(&browser.user).bind(digest(browser.cookie.split_once('=').unwrap().1)).bind(digest(&browser.csrf)).execute(&l.lab.store.pool).await.unwrap();
    assert_eq!(
        operator_request(
            &l,
            "PATCH",
            &browser.user,
            json!({"disabled":false,"expected_revision":2})
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        l.request(&browser, "GET", "/auth/session", None, false)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    let fresh = l.login("concurrent").await;
    // Explicit same-state updates can revoke sessions without changing access.
    assert_eq!(
        operator_request(
            &l,
            "PATCH",
            &browser.user,
            json!({"disabled":false,"expected_revision":3})
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        l.request(&fresh, "GET", "/auth/session", None, false)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    l.finish().await;
}

#[tokio::test]
async fn account_suspension_preserves_last_owner_across_workspaces_and_member_races() {
    let l = IdentityLab::new().await;
    let owner = l.login("owner").await;
    let backup = l.login("backup").await;
    l.member(&owner, "owner", None).await;
    let change = json!({"disabled":true,"expected_revision":1});
    assert_eq!(
        operator_request(&l, "PATCH", &owner.user, change.clone())
            .await
            .0,
        StatusCode::CONFLICT
    );
    let alternative = l.member(&backup, "owner", None).await;
    let other = l.lab.store.create_tenant(&l.lab.operator,serde_json::from_value(json!({"name":"other","allowance":{"cpu_percent":100,"memory_mib":256,"instances":1,"storage_bytes":1000000,"transfer_bytes":1000000}})).unwrap()).await.unwrap();
    l.lab
        .store
        .add_member(
            &l.lab.operator,
            s(&other["id"]),
            json!({"user_id":owner.user,"role":"owner"}),
        )
        .await
        .unwrap();
    assert_eq!(
        operator_request(&l, "PATCH", &owner.user, change.clone())
            .await
            .0,
        StatusCode::CONFLICT
    );
    l.lab
        .store
        .add_member(
            &l.lab.operator,
            s(&other["id"]),
            json!({"user_id":backup.user,"role":"owner"}),
        )
        .await
        .unwrap();
    let (disable, demote) = tokio::join!(
        operator_request(&l, "PATCH", &owner.user, change),
        l.lab.store.update_member(
            &l.lab.operator,
            &l.lab.tenant,
            s(&alternative["id"]),
            json!({"role":"viewer","expected_revision":1})
        )
    );
    assert!(
        (disable.0 == StatusCode::OK
            && demote.as_ref().unwrap_err().status == StatusCode::CONFLICT)
            || (disable.0 == StatusCode::CONFLICT && demote.is_ok())
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM workspace_memberships m JOIN customer_users u ON u.id=m.user_id WHERE m.tenant_id=$1 AND m.role='owner' AND NOT m.revoked AND NOT u.disabled")
        .bind(&l.lab.tenant).fetch_one(&l.lab.store.pool).await.unwrap();
    assert_eq!(count, 1);
    l.finish().await;
}

#[tokio::test]
async fn repeated_bootstrap_preserves_existing_identity_and_sessions() {
    let l = IdentityLab::new().await;
    let browser = l.login("existing-user").await;
    l.lab.store.migrate().await.unwrap();
    l.lab.store.migrate().await.unwrap();
    let (_, account) = operator_request(&l, "GET", &browser.user, Value::Null).await;
    assert_eq!(account["revision"], 1);
    assert_eq!(account["disabled"], false);
    assert_eq!(account["subject"], "existing-user");
    assert_eq!(
        l.request(&browser, "GET", "/auth/session", None, false)
            .await
            .0,
        StatusCode::OK
    );
    l.finish().await;
}
