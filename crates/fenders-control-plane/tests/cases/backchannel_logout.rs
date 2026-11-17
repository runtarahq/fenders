use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

fn claims(p: &Provider, subject: Option<&str>, sid: Option<&str>) -> Value {
    let now: chrono::DateTime<chrono::Utc> = std::time::SystemTime::now().into();
    let mut value = json!({"iss":p.issuer,"aud":"fenders-test","iat":now.timestamp(),"exp":now.timestamp()+300,"jti":uid(),"events":{"http://schemas.openid.net/event/backchannel-logout":{}}});
    if let Some(sub) = subject {
        value["sub"] = json!(sub);
    }
    if let Some(sid) = sid {
        value["sid"] = json!(sid);
    }
    value
}
fn signed(p: &Provider, header: Value, claims: &Value, wrong: bool) -> String {
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap())
    );
    let key = if wrong { &p.wrong_key } else { &p.key };
    format!(
        "{input}.{}",
        URL_SAFE_NO_PAD.encode(
            key.sign(&CoreJwsSigningAlgorithm::EdDsa, input.as_bytes())
                .unwrap()
        )
    )
}
fn token(p: &Provider, claims: &Value) -> String {
    signed(
        p,
        json!({"alg":"EdDSA","kid":"signing","typ":"logout+jwt"}),
        claims,
        false,
    )
}
async fn deliver(l: &IdentityLab, body: &str, content_type: &str) -> StatusCode {
    let response = api::router(l.lab.store.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/backchannel-logout")
                .header("content-type", content_type)
                .body(Body::from(body.to_owned()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(!response.headers().contains_key("set-cookie"));
    assert_eq!(response.headers()["cache-control"], "no-store");
    response.status()
}
async fn send(l: &IdentityLab, token: &str) -> StatusCode {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("logout_token", token)
        .append_pair("extension", "ignored")
        .finish();
    deliver(l, &body, "application/x-www-form-urlencoded").await
}
async fn sid(l: &IdentityLab, b: &Browser) -> String {
    sqlx::query_scalar("SELECT provider_sid FROM browser_sessions WHERE token_hash=$1")
        .bind(fenders_control_plane::model::digest(
            b.cookie.split_once('=').unwrap().1,
        ))
        .fetch_one(&l.lab.store.pool)
        .await
        .unwrap()
}
async fn alive(l: &IdentityLab, b: &Browser, yes: bool) {
    assert_eq!(
        l.request(b, "GET", "/auth/session", None, false).await.0,
        if yes {
            StatusCode::OK
        } else {
            StatusCode::UNAUTHORIZED
        }
    );
}

#[tokio::test]
async fn provider_logout_is_session_scoped_replay_safe_and_fences_pending_login() {
    let l = IdentityLab::new().await;
    let first = l.login("owner").await;
    let membership = l.member(&first, "owner", None).await;
    let session: String = sqlx::query_scalar("SELECT id FROM browser_sessions WHERE user_id=$1")
        .bind(&first.user)
        .fetch_one(&l.lab.store.pool)
        .await
        .unwrap();
    let stale: Principal=serde_json::from_value(json!({"id":first.user,"role":"owner","tenant_id":l.lab.tenant,"project_id":null,"membership_id":membership["id"],"session_id":session})).unwrap();
    let second = l.login("owner").await;
    let other = l.login("other").await;
    let foreign_client = l.login("owner").await;
    sqlx::query("UPDATE browser_sessions SET client_id='another-client' WHERE token_hash=$1")
        .bind(fenders_control_plane::model::digest(
            foreign_client.cookie.split_once('=').unwrap().1,
        ))
        .execute(&l.lab.store.pool)
        .await
        .unwrap();
    let foreign_issuer = l.login("foreign-issuer").await;
    sqlx::query("UPDATE customer_users SET issuer='https://another-issuer.invalid',subject='owner' WHERE id=$1").bind(&foreign_issuer.user).execute(&l.lab.store.pool).await.unwrap();
    let first_sid = sid(&l, &first).await;
    assert_ne!(first_sid, sid(&l, &second).await);
    // Both selectors must match; a foreign subject cannot target this sid.
    assert_eq!(
        send(
            &l,
            &token(
                &l.provider,
                &claims(&l.provider, Some("other"), Some(&first_sid))
            )
        )
        .await,
        StatusCode::OK
    );
    alive(&l, &first, true).await;
    let logout = token(&l.provider, &claims(&l.provider, None, Some(&first_sid)));
    let (a, b) = tokio::join!(send(&l, &logout), send(&l, &logout));
    assert_eq!((a, b), (StatusCode::OK, StatusCode::OK));
    alive(&l, &first, false).await;
    assert_eq!(
        l.lab
            .store
            .create_project(
                &stale,
                &l.lab.tenant,
                serde_json::from_value(json!({"name":"revoked-session"})).unwrap()
            )
            .await
            .unwrap_err()
            .status,
        StatusCode::UNAUTHORIZED
    );
    alive(&l, &second, true).await;
    alive(&l, &other, true).await;
    let removed: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit WHERE action='browser_session.provider_logout'",
    )
    .fetch_one(&l.lab.store.pool)
    .await
    .unwrap();
    assert_eq!(removed, 2);

    let pending = l.begin("owner", "valid").await;
    let challenge = l
        .provider
        .codes
        .lock()
        .unwrap()
        .values()
        .next()
        .unwrap()
        .challenge
        .clone();
    assert_eq!(
        send(
            &l,
            &token(
                &l.provider,
                &claims(&l.provider, Some("owner"), Some(&challenge))
            )
        )
        .await,
        StatusCode::OK
    );
    assert_eq!(
        l.callback(&pending).await.status(),
        StatusCode::UNAUTHORIZED
    );
    alive(&l, &second, true).await;

    let mut all = claims(&l.provider, Some("owner"), None);
    all["iat"] = json!(all["iat"].as_i64().unwrap() - 1);
    let all_token = token(&l.provider, &all);
    assert_eq!(send(&l, &all_token).await, StatusCode::OK);
    alive(&l, &second, false).await;
    alive(&l, &foreign_client, true).await;
    alive(&l, &foreign_issuer, true).await;
    alive(&l, &other, true).await;
    let fresh = l.login("owner").await;
    assert_eq!(fresh.user, first.user);
    // Rebuild the router to establish DB-backed, not process-local replay state.
    assert_eq!(send(&l, &all_token).await, StatusCode::OK);
    alive(&l, &fresh, true).await;
    let memberships: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM workspace_memberships WHERE user_id=$1 AND NOT revoked",
    )
    .bind(&first.user)
    .fetch_one(&l.lab.store.pool)
    .await
    .unwrap();
    assert_eq!(memberships, 1);
    let mut substituted = all.clone();
    substituted["sub"] = json!("other");
    assert_eq!(
        send(&l, &token(&l.provider, &substituted)).await,
        StatusCode::BAD_REQUEST
    );
    alive(&l, &other, true).await;
    l.finish().await;
}

#[tokio::test]
async fn provider_logout_refuses_invalid_claims_signatures_and_framing() {
    let l = IdentityLab::new().await;
    let owner = l.login("owner").await;
    let confused = l.begin("owner", "logout-confusion").await;
    assert_eq!(
        l.callback(&confused).await.status(),
        StatusCode::UNAUTHORIZED
    );
    let valid = claims(&l.provider, Some("owner"), None);
    let now = valid["iat"].as_i64().unwrap();
    for (name, value) in [
        ("iss", json!("https://foreign.invalid")),
        ("aud", json!("other")),
        ("aud", json!(["fenders-test", "other"])),
        ("iat", json!(now + 120)),
        ("iat", json!(now - 301)),
        ("exp", json!(now - 1)),
        ("exp", json!(now + 601)),
        ("jti", json!("")),
        ("sub", Value::Null),
        ("sid", json!("")),
        ("nonce", Value::Null),
        ("events", json!({})),
        (
            "events",
            json!({"http://schemas.openid.net/event/backchannel-logout":true}),
        ),
    ] {
        let mut bad = valid.clone();
        bad[name] = value;
        assert_eq!(
            send(&l, &token(&l.provider, &bad)).await,
            StatusCode::BAD_REQUEST,
            "{name}"
        );
    }
    for name in ["iss", "aud", "iat", "exp", "jti", "events"] {
        let mut bad = valid.clone();
        bad.as_object_mut().unwrap().remove(name);
        assert_eq!(
            send(&l, &token(&l.provider, &bad)).await,
            StatusCode::BAD_REQUEST,
            "missing {name}"
        );
    }
    for header in [
        json!({"alg":"none"}),
        json!({"alg":"HS256"}),
        json!({"alg":"EdDSA","kid":"unknown"}),
        json!({"alg":"EdDSA","typ":"at+jwt"}),
        json!({"alg":"EdDSA","crit":[]}),
        json!({"alg":"EdDSA","jku":"http://127.0.0.1/keys"}),
    ] {
        assert_eq!(
            send(&l, &signed(&l.provider, header, &valid, false)).await,
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(
        send(
            &l,
            &signed(
                &l.provider,
                json!({"alg":"EdDSA","kid":"signing"}),
                &valid,
                true
            )
        )
        .await,
        StatusCode::BAD_REQUEST
    );
    let good = token(&l.provider, &valid);
    assert_eq!(
        deliver(
            &l,
            &format!("logout_token={good}&logout_token={good}"),
            "application/x-www-form-urlencoded"
        )
        .await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        deliver(&l, &format!("logout_token={good}"), "application/json").await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(send(&l, "malformed").await, StatusCode::BAD_REQUEST);
    assert_eq!(
        deliver(&l, &"x".repeat(16_385), "application/x-www-form-urlencoded").await,
        StatusCode::BAD_REQUEST
    );
    // With no keys held and the provider unavailable, a notice is not
    // taken on trust.
    l.provider.key_phase.store(2, Ordering::SeqCst);
    l.lab.store.forget_provider_metadata().await;
    assert_eq!(send(&l, &good).await, StatusCode::SERVICE_UNAVAILABLE);
    alive(&l, &owner, true).await;
    let receipts: i64 = sqlx::query_scalar("SELECT count(*) FROM browser_logout_events")
        .fetch_one(&l.lab.store.pool)
        .await
        .unwrap();
    assert_eq!(receipts, 0);
    l.provider.key_phase.store(0, Ordering::SeqCst);
    l.provider.key_delay_ms.store(2100, Ordering::SeqCst);
    let mut expiring = claims(&l.provider, Some("owner"), None);
    expiring["exp"] = json!(expiring["iat"].as_i64().unwrap() + 2);
    l.lab.store.forget_provider_metadata().await;
    let reads = l.provider.key_reads.load(Ordering::SeqCst);
    assert_eq!(
        send(&l, &token(&l.provider, &expiring)).await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        l.provider.key_reads.load(Ordering::SeqCst),
        reads + 1,
        "the token must expire during the delayed key read, not before it"
    );
    alive(&l, &owner, true).await;
    l.finish().await;
}

#[tokio::test]
async fn provider_logout_receipt_capacity_expiry_and_failed_commit_are_safe() {
    let l = IdentityLab::new().await;
    let owner = l.login("owner").await;
    let value = claims(&l.provider, Some("owner"), None);
    let encoded = token(&l.provider, &value);
    sqlx::raw_sql("CREATE FUNCTION fail_logout_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected logout audit failure'; END $$; CREATE TRIGGER fail_logout_commit BEFORE INSERT ON audit FOR EACH ROW WHEN (NEW.action='browser_session.provider_logout') EXECUTE FUNCTION fail_logout_commit();").execute(&l.lab.store.pool).await.unwrap();
    assert_eq!(send(&l, &encoded).await, StatusCode::INTERNAL_SERVER_ERROR);
    alive(&l, &owner, true).await;
    let receipts: i64 = sqlx::query_scalar("SELECT count(*) FROM browser_logout_events")
        .fetch_one(&l.lab.store.pool)
        .await
        .unwrap();
    assert_eq!(receipts, 0);
    sqlx::raw_sql("DROP TRIGGER fail_logout_commit ON audit; DROP FUNCTION fail_logout_commit(); INSERT INTO browser_logout_events SELECT 'receipt-'||n,'hash','https://other.invalid','other','other',NULL,0,now()+interval '1 hour' FROM generate_series(1,10000) n;").execute(&l.lab.store.pool).await.unwrap();
    assert_eq!(send(&l, &encoded).await, StatusCode::SERVICE_UNAVAILABLE);
    alive(&l, &owner, true).await;
    sqlx::query(
        "UPDATE browser_logout_events SET expires=now()-interval '1 second' WHERE id='receipt-1'",
    )
    .execute(&l.lab.store.pool)
    .await
    .unwrap();
    assert_eq!(send(&l, &encoded).await, StatusCode::OK);
    alive(&l, &owner, false).await;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM browser_logout_events")
        .fetch_one(&l.lab.store.pool)
        .await
        .unwrap();
    assert_eq!(count, 10000);
    l.finish().await;
}
