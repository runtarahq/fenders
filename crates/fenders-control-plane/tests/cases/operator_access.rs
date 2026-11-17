//! Private operator revocations exercise real OIDC sessions and PostgreSQL transactions.
use super::customer_onboarding::operator_call;
use super::*;

#[tokio::test]
async fn operator_revocation_is_scoped_atomic_and_recoverable() {
    let l = IdentityLab::new().await;
    let owner = l.login("owner").await;
    let member = l.login("member").await;
    let owner_grant = l.member(&owner, "owner", None).await;
    let grant = l.member(&member, "editor", None).await;
    let other = l.lab.store.create_tenant(&l.lab.operator, serde_json::from_value(json!({"name":"other","allowance":{"cpu_percent":100,"memory_mib":128,"instances":1,"storage_bytes":1000000,"transfer_bytes":1000000}})).unwrap()).await.unwrap();
    let other_id = s(&other["id"]);
    l.lab
        .store
        .add_member(
            &l.lab.operator,
            other_id,
            json!({"user_id":member.user,"role":"viewer"}),
        )
        .await
        .unwrap();
    let action = "workspaces.revoke_access";
    let input = json!({"id":l.lab.tenant,"target_id":grant["id"],"kind":"member","expected_revision":1,"request_key":uid(),"reason":"Revoke only the reviewed grant"});
    let mut denied = input.clone();
    denied["target_id"] = owner_grant["id"].clone();
    let result = operator_call(&l, action, denied).await;
    assert_eq!(result.0, StatusCode::CONFLICT);
    assert_eq!(
        result.1["error"],
        "add another owner before removing the last owner"
    );
    let mut stale = input.clone();
    stale["expected_revision"] = json!(2);
    assert_eq!(
        operator_call(&l, action, stale).await.0,
        StatusCode::CONFLICT
    );
    let mut wrong = input.clone();
    wrong["id"] = json!(other_id);
    assert_eq!(
        operator_call(&l, action, wrong).await.0,
        StatusCode::NOT_FOUND
    );
    let session: Value =
        sqlx::query_scalar("SELECT to_jsonb(s) FROM browser_sessions s WHERE user_id=$1")
            .bind(&member.user)
            .fetch_one(&l.lab.store.pool)
            .await
            .unwrap();
    let old_principal:Principal=serde_json::from_value(json!({"id":member.user,"role":"editor","tenant_id":l.lab.tenant,"membership_id":grant["id"],"session_id":session["id"]})).unwrap();
    let path = format!("/v1/tenants/{}/projects", l.lab.tenant);
    assert_eq!(
        l.request(&member, "GET", &path, None, true).await.0,
        StatusCode::OK
    );
    sqlx::raw_sql("CREATE FUNCTION reject_access_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='operator.access_revoke' THEN RAISE EXCEPTION 'fixture audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_access_audit BEFORE INSERT ON audit FOR EACH ROW EXECUTE FUNCTION reject_access_audit();").execute(&l.lab.store.pool).await.unwrap();
    assert_eq!(
        operator_call(&l, action, input.clone()).await.0,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        l.request(&member, "GET", &path, None, true).await.0,
        StatusCode::OK
    );
    let (revoked, revision): (bool, i64) =
        sqlx::query_as("SELECT revoked,revision FROM workspace_memberships WHERE id=$1")
            .bind(s(&grant["id"]))
            .fetch_one(&l.lab.store.pool)
            .await
            .unwrap();
    assert_eq!((revoked, revision), (false, 1));
    sqlx::query("DROP TRIGGER reject_access_audit ON audit")
        .execute(&l.lab.store.pool)
        .await
        .unwrap();
    let (a, b) = tokio::join!(
        operator_call(&l, action, input.clone()),
        operator_call(&l, action, input.clone())
    );
    assert_eq!(a.0, StatusCode::OK, "{:?}", a);
    assert_eq!(a, b);
    assert_eq!(
        operator_call(&l, action, input.clone()).await,
        a,
        "a lost result returns the exact original audit"
    );
    let mut changed = input.clone();
    changed["reason"] = json!("Changed intent");
    assert_eq!(
        operator_call(&l, action, changed).await.0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        l.request(&member, "GET", &path, None, true).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        l.request(
            &member,
            "GET",
            &format!("/v1/tenants/{other_id}/projects"),
            None,
            true
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        l.request(&owner, "GET", &path, None, true).await.0,
        StatusCode::OK
    );
    assert_eq!(
        l.lab
            .store
            .create_project(
                &old_principal,
                &l.lab.tenant,
                serde_json::from_value(json!({"name":"stale-member"})).unwrap()
            )
            .await
            .unwrap_err()
            .status,
        StatusCode::UNAUTHORIZED
    );

    let (key_principal, key) = l.lab.credential("editor", None).await;
    let (_, unrelated_key) = l.lab.credential("viewer", None).await;
    let revoke = json!({"id":l.lab.tenant,"target_id":key["id"],"kind":"credential","request_key":uid(),"reason":"Retire this API key"});
    sqlx::query("CREATE TRIGGER reject_access_audit BEFORE INSERT ON audit FOR EACH ROW EXECUTE FUNCTION reject_access_audit()").execute(&l.lab.store.pool).await.unwrap();
    assert_eq!(
        operator_call(&l, action, revoke.clone()).await.0,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert!(l.lab.store.authenticate(s(&key["token"])).await.is_ok());
    sqlx::query("DROP TRIGGER reject_access_audit ON audit")
        .execute(&l.lab.store.pool)
        .await
        .unwrap();
    let (a, b) = tokio::join!(
        operator_call(&l, action, revoke.clone()),
        operator_call(&l, action, revoke.clone())
    );
    assert_eq!(a.0, StatusCode::OK);
    assert_eq!(a, b);
    assert_eq!(
        l.lab
            .store
            .authenticate(s(&key["token"]))
            .await
            .unwrap_err()
            .status,
        StatusCode::UNAUTHORIZED
    );
    assert!(
        l.lab
            .store
            .authenticate(s(&unrelated_key["token"]))
            .await
            .is_ok()
    );
    assert_eq!(
        l.lab
            .store
            .create_project(
                &key_principal,
                &l.lab.tenant,
                serde_json::from_value(json!({"name":"stale-key"})).unwrap()
            )
            .await
            .unwrap_err()
            .status,
        StatusCode::UNAUTHORIZED
    );
    let (_, detail) = operator_call(&l, "workspaces.get", json!({"id":l.lab.tenant})).await;
    assert_eq!(detail["members"].as_array().unwrap().len(), 1);
    assert_eq!(detail["members"][0]["revision"], 1);
    assert_eq!(detail["activity"].as_array().unwrap().len(), 2);
    assert_eq!(detail["activity"][0]["sequence"], a.1["audit"]["sequence"]);
    assert_eq!(detail["activity"][0]["kind"], "credential");
    assert_eq!(detail["activity"][0]["before"]["revoked"], false);
    assert_eq!(detail["activity"][0]["after"]["revoked"], true);
    assert!(!detail.to_string().contains(s(&key["token"])));
    l.finish().await;
}
