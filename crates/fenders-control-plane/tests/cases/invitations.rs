use super::*;
use fenders_control_plane::invitation_email::InvitationEmailConfig;
async fn setup() -> (IdentityLab, Browser) {
    let mut l = IdentityLab::new().await;
    let password = l.lab.root.path().join("smtp");
    std::fs::write(&password, "test-only").unwrap();
    l.lab.store = l
        .lab
        .store
        .clone()
        .with_invitation_email(InvitationEmailConfig {
            host: "localhost".into(),
            port: 1,
            username: "test".into(),
            password_file: password,
            from: "Fenders <hello@example.test>".into(),
            console_origin: "https://console.example.test".into(),
        })
        .unwrap();
    let owner = l.login("inviter").await;
    l.member(&owner, "owner", None).await;
    (l, owner)
}
fn path(l: &IdentityLab) -> String {
    format!("/v1/tenants/{}/invitations", l.lab.tenant)
}
fn intent(subject: &str, project: Option<&str>) -> Value {
    json!({"email":format!("{subject}@example.test"),"project_id":project,"role":"viewer","request_key":uid()})
}
async fn create(l: &IdentityLab, owner: &Browser, subject: &str, project: Option<&str>) -> Value {
    let (status, row) = l
        .request(
            owner,
            "POST",
            &path(l),
            Some(intent(subject, project)),
            true,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{row}");
    row
}
#[tokio::test]
async fn invitation_requires_verified_consent_and_never_replays_membership() {
    let (l, owner) = setup().await;
    let payload = intent("recipient", Some(&l.lab.project));
    let collection = path(&l);
    let (a, b) = tokio::join!(
        l.request(&owner, "POST", &collection, Some(payload.clone()), true),
        l.request(&owner, "POST", &collection, Some(payload.clone()), true)
    );
    assert_eq!(a.0, StatusCode::OK, "{}", a.1);
    assert_eq!(a.1["id"], b.1["id"]);
    let row = a.1;
    let endpoint = format!("/v1/invitations/{}", s(&row["id"]));
    let recipient = l.login("recipient").await;
    let outsider = l.login("outsider").await;
    assert_eq!(
        l.request(&outsider, "GET", &endpoint, None, true).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        l.request(
            &outsider,
            "POST",
            &endpoint,
            Some(json!({"action":"accept","expected_revision":1})),
            true
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    let before = l
        .request(&recipient, "GET", "/auth/session", None, true)
        .await
        .1;
    assert_eq!(before["workspaces"].as_array().unwrap().len(), 0);
    assert_eq!(
        l.request(
            &recipient,
            "POST",
            &endpoint,
            Some(json!({"action":"accept","expected_revision":1})),
            false
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    sqlx::query("UPDATE customer_users SET email_verified=false WHERE id=$1")
        .bind(&recipient.user)
        .execute(&l.lab.store.pool)
        .await
        .unwrap();
    assert_eq!(
        l.request(
            &recipient,
            "POST",
            &endpoint,
            Some(json!({"action":"accept","expected_revision":1})),
            true
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let recipient = l.login("recipient").await;
    let decision = json!({"action":"accept","expected_revision":1});
    let (a, b) = tokio::join!(
        l.request(&recipient, "POST", &endpoint, Some(decision.clone()), true),
        l.request(&recipient, "POST", &endpoint, Some(decision.clone()), true)
    );
    assert_eq!(a.0, StatusCode::OK, "{}", a.1);
    assert_eq!(b.0, StatusCode::OK, "{}", b.1);
    assert_eq!(a.1["membership_id"], b.1["membership_id"]);
    let member = s(&a.1["membership_id"]);
    let info = l
        .request(&recipient, "GET", "/auth/session", None, true)
        .await
        .1;
    assert_eq!(info["workspaces"][0]["id"], l.lab.tenant);
    assert_eq!(
        info["workspaces"][0]["memberships"][0]["project_id"],
        l.lab.project
    );
    l.lab
        .store
        .update_member(
            &l.lab.operator,
            &l.lab.tenant,
            member,
            json!({"revoked":true,"expected_revision":1}),
        )
        .await
        .unwrap();
    assert_eq!(
        l.request(&recipient, "POST", &endpoint, Some(decision), true)
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        l.request(&recipient, "GET", "/auth/session", None, true)
            .await
            .1["workspaces"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM workspace_memberships WHERE user_id=$1")
            .bind(&recipient.user)
            .fetch_one(&l.lab.store.pool)
            .await
            .unwrap();
    assert_eq!(count, 1);
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit WHERE action='invitation.accepted'")
            .fetch_one(&l.lab.store.pool)
            .await
            .unwrap();
    assert_eq!(count, 1);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM executions")
        .fetch_one(&l.lab.store.pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
    l.finish().await;
}
#[tokio::test]
async fn invitation_denial_expiry_revocation_and_smtp_failure_remain_recoverable() {
    let (l, owner) = setup().await;
    let viewer = l.login("viewer").await;
    l.member(&viewer, "viewer", None).await;
    assert_eq!(
        l.request(
            &viewer,
            "POST",
            &path(&l),
            Some(intent("denied", None)),
            true
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let recipient = l.login("decliner").await;
    let row = create(&l, &owner, "decliner", None).await;
    let endpoint = format!("/v1/invitations/{}", s(&row["id"]));
    let decision = json!({"action":"decline","expected_revision":1});
    assert_eq!(
        l.request(&recipient, "POST", &endpoint, Some(decision.clone()), true)
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        l.request(&recipient, "POST", &endpoint, Some(decision), true)
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        l.request(
            &recipient,
            "POST",
            &endpoint,
            Some(json!({"action":"accept","expected_revision":2})),
            true
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    for expired in [false, true] {
        let subject = if expired { "expired" } else { "revoked" };
        let row = create(&l, &owner, subject, None).await;
        if expired {
            sqlx::query(
                "UPDATE workspace_invitations SET expires=now()-interval '1 second' WHERE id=$1",
            )
            .bind(s(&row["id"]))
            .execute(&l.lab.store.pool)
            .await
            .unwrap();
        } else {
            assert_eq!(
                l.request(
                    &owner,
                    "POST",
                    &format!("{}/{}", path(&l), s(&row["id"])),
                    Some(json!({"action":"revoke","expected_revision":1})),
                    true
                )
                .await
                .0,
                StatusCode::OK
            );
        }
        let recipient = l.login(subject).await;
        let (status, result) = l
            .request(
                &recipient,
                "POST",
                &format!("/v1/invitations/{}", s(&row["id"])),
                Some(json!({"action":"accept","expected_revision":1})),
                true,
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{result}");
    }
    l.lab.store.deliver_invitation_email().await.unwrap(); // consume the expired queued request
    let row = create(&l, &owner, "delivery", None).await;
    let endpoint = format!("{}/{}", path(&l), s(&row["id"]));
    let resend = json!({"action":"resend","expected_revision":1});
    assert_eq!(
        l.request(&owner, "POST", &endpoint, Some(resend.clone()), true)
            .await
            .0,
        StatusCode::TOO_MANY_REQUESTS
    );
    for _ in 0..5 {
        sqlx::query("UPDATE invitation_outbox SET available_at=now() WHERE invitation_id=$1")
            .bind(s(&row["id"]))
            .execute(&l.lab.store.pool)
            .await
            .unwrap();
        l.lab.store.deliver_invitation_email().await.unwrap();
    }
    let state: String =
        sqlx::query_scalar("SELECT state FROM invitation_outbox WHERE invitation_id=$1")
            .bind(s(&row["id"]))
            .fetch_one(&l.lab.store.pool)
            .await
            .unwrap();
    assert_eq!(state, "failed");
    sqlx::query("UPDATE invitation_outbox SET requested_at=now()-interval '2 minutes' WHERE invitation_id=$1").bind(s(&row["id"])).execute(&l.lab.store.pool).await.unwrap();
    let (status, result) = l
        .request(&owner, "POST", &endpoint, Some(resend.clone()), true)
        .await;
    assert_eq!(status, StatusCode::OK, "{result}");
    assert_eq!(result["delivery"], "queued");
    assert_eq!(
        l.request(&owner, "POST", &endpoint, Some(resend), true)
            .await
            .0,
        StatusCode::CONFLICT
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM workspace_memberships")
        .fetch_one(&l.lab.store.pool)
        .await
        .unwrap();
    assert_eq!(count, 2);
    l.finish().await;
}
#[tokio::test]
async fn invited_new_user_does_not_provision_workspace_and_inviter_must_keep_authority() {
    let (mut l, owner) = setup().await;
    let row = create(&l, &owner, "new-invitee", None).await;
    l.lab.store = l
        .lab
        .store
        .clone()
        .with_onboarding(super::customer_onboarding::policy(10))
        .unwrap();
    sqlx::query("UPDATE admission_policy SET mode='automatic'")
        .execute(&l.lab.store.pool)
        .await
        .unwrap();
    let recipient = l.login("new-invitee").await;
    let info = l
        .request(&recipient, "GET", "/auth/session", None, true)
        .await
        .1;
    assert!(info["onboarding"]["workspace_id"].is_null());
    let other = l.login("replacement-owner").await;
    l.member(&other, "owner", None).await;
    let members = l
        .lab
        .store
        .members(&l.lab.operator, &l.lab.tenant)
        .await
        .unwrap();
    let member = members["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["user_id"] == owner.user)
        .unwrap();
    l.lab
        .store
        .update_member(
            &l.lab.operator,
            &l.lab.tenant,
            s(&member["id"]),
            json!({"revoked":true,"expected_revision":1}),
        )
        .await
        .unwrap();
    assert_eq!(
        l.request(
            &recipient,
            "POST",
            &format!("/v1/invitations/{}", s(&row["id"])),
            Some(json!({"action":"accept","expected_revision":1})),
            true
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    l.finish().await;
}
