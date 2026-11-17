//! Real OIDC verification against a local signing provider, never a production
//! identity service. Browser flows use the actual management router and database.
use super::*;
#[path = "backchannel_logout.rs"]
mod backchannel_logout;
#[path = "customer_account_state.rs"]
mod customer_account_state;
#[path = "customer_onboarding.rs"]
mod customer_onboarding;
#[path = "invitations.rs"]
mod invitations;
#[path = "m1_live.rs"]
mod m1_live;
#[path = "m2_https_live.rs"]
mod m2_https_live;
#[path = "m2_pickup_live.rs"]
mod m2_pickup_live;
#[path = "m2_triggers_live.rs"]
mod m2_triggers_live;
#[path = "operator_access.rs"]
mod operator_access;
#[path = "m2_worker.rs"]
mod worker;
use axum::{Json, Router, extract::State, response::IntoResponse};
use fenders_control_plane::browser_auth::BrowserAuthConfig;
use openidconnect::{
    AccessToken, Audience, ClientId, EmptyAdditionalClaims, IssuerUrl, JsonWebKeyId, Nonce,
    PkceCodeChallenge, PkceCodeVerifier, PrivateSigningKey, StandardClaims, SubjectIdentifier,
    core::{
        CoreEdDsaPrivateSigningKey, CoreIdToken, CoreIdTokenClaims, CoreJsonWebKeySet,
        CoreJwsSigningAlgorithm,
    },
};
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

struct Code {
    subject: String,
    nonce: String,
    challenge: String,
    mode: &'static str,
}
struct Provider {
    issuer: String,
    console_origin: String,
    key: CoreEdDsaPrivateSigningKey,
    wrong_key: CoreEdDsaPrivateSigningKey,
    rotated_key: CoreEdDsaPrivateSigningKey,
    rotated_wrong_key: CoreEdDsaPrivateSigningKey,
    key_phase: AtomicUsize,
    key_reads: AtomicUsize,
    key_delay_ms: AtomicUsize,
    browser_email_verified: std::sync::atomic::AtomicBool,
    codes: Mutex<HashMap<String, Code>>,
    exchanges: AtomicUsize,
}
struct IdentityLab {
    lab: Lab,
    provider: Arc<Provider>,
    server: tokio::task::JoinHandle<()>,
}
struct Login {
    cookie: String,
    callback: String,
}
struct Browser {
    cookie: String,
    user: String,
    csrf: String,
}
impl IdentityLab {
    async fn new() -> Self {
        Self::at_origin("http://localhost:19091").await
    }
    async fn at_origin(console_origin: &str) -> Self {
        Self::with_lab(Lab::new().await, console_origin).await
    }
    async fn with_lab(mut lab: Lab, console_origin: &str) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://{}", listener.local_addr().unwrap());
        let key = |id: &str| {
            CoreEdDsaPrivateSigningKey::from_ed25519_pem(
                &rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
                    .unwrap()
                    .serialize_pem(),
                Some(JsonWebKeyId::new(id.into())),
            )
            .unwrap()
        };
        let provider = Arc::new(Provider {
            issuer: issuer.clone(),
            console_origin: console_origin.into(),
            key: key("signing"),
            wrong_key: key("signing"),
            rotated_key: key("rotated"),
            rotated_wrong_key: key("rotated"),
            key_phase: AtomicUsize::new(0),
            key_reads: AtomicUsize::new(0),
            key_delay_ms: AtomicUsize::new(0),
            browser_email_verified: std::sync::atomic::AtomicBool::new(true),
            codes: Mutex::new(HashMap::new()),
            exchanges: AtomicUsize::new(0),
        });
        let router=Router::new()
            .route("/.well-known/openid-configuration",axum::routing::get(|State(p):State<Arc<Provider>>|async move{Json(json!({"issuer":p.issuer,"authorization_endpoint":format!("{}/authorize",p.issuer),"token_endpoint":format!("{}/token",p.issuer),"jwks_uri":format!("{}/jwks",p.issuer),"response_types_supported":["code"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["EdDSA"]}))}))
            .route("/jwks",axum::routing::get(signing_keys))
            .route("/authorize",axum::routing::get(authorize_browser))
            .route("/logout", axum::routing::get(|State(p): State<Arc<Provider>>| async move {
                axum::response::Redirect::to(&format!("{}/console/?signin=signed-out", p.console_origin))
            }))
            .route("/token",axum::routing::post(exchange)).with_state(provider.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        lab.store = lab
            .store
            .with_browser_auth(
                BrowserAuthConfig {
                    issuer,
                    client_id: "fenders-test".into(),
                    client_secret: None,
                    console_origin: console_origin.into(),
                    endpoint_origins: vec![],
                    provider_ca_pem: None,
                    provider_logout_url: None,
                },
                true,
            )
            .unwrap();
        Self {
            lab,
            provider,
            server,
        }
    }
    async fn begin(&self, subject: &str, mode: &'static str) -> Login {
        let response = api::router(self.lab.store.clone())
            .oneshot(
                Request::builder()
                    .uri("/auth/login")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let cookie = response.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        assert!(
            response.headers()["set-cookie"]
                .to_str()
                .unwrap()
                .contains("HttpOnly; SameSite=Lax")
        );
        let url = url::Url::parse(response.headers()["location"].to_str().unwrap()).unwrap();
        let query: HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(query["scope"], "openid email profile");
        assert_eq!(query["response_type"], "code");
        assert_eq!(query["code_challenge_method"], "S256");
        assert_eq!(
            query["redirect_uri"],
            format!("{}/auth/callback", self.provider.console_origin)
        );
        let code = uid();
        self.provider.codes.lock().unwrap().insert(
            code.clone(),
            Code {
                subject: subject.into(),
                nonce: query["nonce"].clone(),
                challenge: query["code_challenge"].clone(),
                mode,
            },
        );
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("state", &query["state"])
            .append_pair("code", &code)
            .finish();
        Login {
            cookie,
            callback: format!("/auth/callback?{query}"),
        }
    }
    async fn callback(&self, login: &Login) -> axum::response::Response {
        api::router(self.lab.store.clone())
            .oneshot(
                Request::builder()
                    .uri(&login.callback)
                    .header("Cookie", &login.cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
    }
    async fn login(&self, subject: &str) -> Browser {
        self.login_mode(subject, "valid").await
    }
    async fn login_mode(&self, subject: &str, mode: &'static str) -> Browser {
        let login = self.begin(subject, mode).await;
        let response = self.callback(&login).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(response.headers()["location"], "/console/");
        assert_eq!(response.headers()["cache-control"], "no-store");
        let cookie = response
            .headers()
            .get_all("set-cookie")
            .iter()
            .map(|v| v.to_str().unwrap())
            .find(|v| v.starts_with("fenders_dev_session="))
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let mut browser = Browser {
            cookie,
            user: String::new(),
            csrf: String::new(),
        };
        let (status, info) = self
            .request(&browser, "GET", "/auth/session", None, true)
            .await;
        assert_eq!(status, StatusCode::OK);
        browser.user = s(&info["user_id"]).into();
        browser.csrf = s(&info["csrf"]).into();
        browser
    }
    async fn request(
        &self,
        browser: &Browser,
        method: &str,
        path: &str,
        value: Option<Value>,
        csrf: bool,
    ) -> (StatusCode, Value) {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header("Cookie", &browser.cookie);
        if csrf {
            request = request
                .header("Origin", &self.provider.console_origin)
                .header("X-CSRF-Token", &browser.csrf);
        }
        let response = api::router(self.lab.store.clone())
            .oneshot(
                request
                    .body(
                        value
                            .map(|v| Body::from(v.to_string()))
                            .unwrap_or_else(Body::empty),
                    )
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        assert_eq!(response.headers()["cache-control"], "no-store");
        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        (
            status,
            if bytes.is_empty() {
                Value::Null
            } else {
                serde_json::from_slice(&bytes).unwrap()
            },
        )
    }
    async fn member(&self, browser: &Browser, role: &str, project: Option<&str>) -> Value {
        self.lab
            .store
            .add_member(
                &self.lab.operator,
                &self.lab.tenant,
                json!({"user_id":browser.user,"role":role,"project_id":project}),
            )
            .await
            .unwrap()
    }
    async fn finish(self) {
        self.server.abort();
        self.lab.finish().await;
    }
}
// Test-only provider approval. Production uses the configured external IdP;
// there is no identity or session injection endpoint in the application.
async fn authorize_browser(
    State(p): State<Arc<Provider>>,
    axum::extract::Query(query): axum::extract::Query<HashMap<String, String>>,
) -> axum::response::Response {
    assert_eq!(query["client_id"], "fenders-test");
    assert_eq!(query["scope"], "openid email profile");
    assert_eq!(query["code_challenge_method"], "S256");
    assert_eq!(query["response_type"], "code");
    assert_eq!(
        query["redirect_uri"],
        format!("{}/auth/callback", p.console_origin)
    );
    let code = uid();
    p.codes.lock().unwrap().insert(
        code.clone(),
        Code {
            subject: "console-owner".into(),
            nonce: query["nonce"].clone(),
            challenge: query["code_challenge"].clone(),
            mode: if p.browser_email_verified.load(Ordering::SeqCst) {
                "valid"
            } else {
                "unverified"
            },
        },
    );
    let mut callback = url::Url::parse(&query["redirect_uri"]).unwrap();
    callback
        .query_pairs_mut()
        .append_pair("code", &code)
        .append_pair("state", &query["state"]);
    axum::response::Redirect::to(callback.as_str()).into_response()
}
async fn signing_keys(State(p): State<Arc<Provider>>) -> axum::response::Response {
    p.key_reads.fetch_add(1, Ordering::SeqCst);
    tokio::time::sleep(std::time::Duration::from_millis(
        p.key_delay_ms.load(Ordering::SeqCst) as u64,
    ))
    .await;
    let keys = match p.key_phase.load(Ordering::SeqCst) {
        0 => vec![p.key.as_verification_key()],
        1 => vec![p.rotated_key.as_verification_key()],
        2 => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
        3 => vec![
            p.rotated_key.as_verification_key(),
            p.rotated_wrong_key.as_verification_key(),
        ],
        _ => unreachable!(),
    };
    Json(CoreJsonWebKeySet::new(keys)).into_response()
}
async fn exchange(
    State(p): State<Arc<Provider>>,
    axum::Form(form): axum::Form<HashMap<String, String>>,
) -> axum::response::Response {
    p.exchanges.fetch_add(1, Ordering::SeqCst);
    let Some(code) = p
        .codes
        .lock()
        .unwrap()
        .remove(form.get("code").map(String::as_str).unwrap_or(""))
    else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    assert_eq!(form["grant_type"], "authorization_code");
    assert_eq!(form["client_id"], "fenders-test");
    assert_eq!(
        form["redirect_uri"],
        format!("{}/auth/callback", p.console_origin)
    );
    assert_eq!(
        PkceCodeChallenge::from_code_verifier_sha256(&PkceCodeVerifier::new(
            form["code_verifier"].clone()
        ))
        .as_str(),
        code.challenge
    );
    let now: chrono::DateTime<chrono::Utc> = std::time::SystemTime::now().into();
    let provider_sid = code.challenge.clone();
    let rotate = code.mode.starts_with("rotate-");
    let mode = code.mode.strip_prefix("rotate-").unwrap_or(code.mode);
    if rotate {
        p.key_phase.store(
            match mode {
                "unpublished" => 0,
                "unavailable" => 2,
                "ambiguous" => 3,
                _ => 1,
            },
            Ordering::SeqCst,
        );
    }
    let issuer = if mode == "issuer" {
        "https://wrong.example"
    } else {
        &p.issuer
    };
    let aud = if mode == "audience" {
        "someone-else"
    } else {
        "fenders-test"
    };
    let mut claims = CoreIdTokenClaims::new(
        IssuerUrl::new(issuer.into()).unwrap(),
        vec![Audience::new(aud.into())],
        now + chrono::Duration::seconds(if mode == "expired" { -10 } else { 300 }),
        if mode == "future" {
            now + chrono::Duration::minutes(10)
        } else {
            now
        },
        StandardClaims::new(SubjectIdentifier::new(code.subject.clone()))
            .set_email(if mode == "missing-email" {
                None
            } else {
                Some(openidconnect::EndUserEmail::new(format!(
                    "{}@example.test",
                    code.subject
                )))
            })
            .set_email_verified(Some(mode != "unverified")),
        EmptyAdditionalClaims {},
    )
    .set_nonce(Some(Nonce::new(if mode == "nonce" {
        "wrong".into()
    } else {
        code.nonce
    })));
    if mode == "azp" {
        claims = claims.set_authorized_party(Some(ClientId::new("wrong-client".into())));
    }
    let access = AccessToken::new("signed-access-token".into());
    let id = CoreIdToken::new(
        claims,
        if rotate && mode == "signature" {
            &p.rotated_wrong_key
        } else if rotate {
            &p.rotated_key
        } else if mode == "signature" {
            &p.wrong_key
        } else {
            &p.key
        },
        CoreJwsSigningAlgorithm::EdDsa,
        Some(&access),
        None,
    )
    .unwrap();
    // Add a signed provider session ID using the provider's original key. This
    // exercises preservation of additional claims through the real verifier.
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let encoded = id.to_string();
    let parts: Vec<_> = encoded.split('.').collect();
    let mut extra: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
    extra["sid"] = json!(provider_sid);
    if mode == "profile-time" {
        extra["updated_at"] = json!(now.to_rfc3339());
    } else if mode == "invalid-profile-time" {
        extra["updated_at"] = json!("not a timestamp");
    }
    if mode == "logout-confusion" {
        extra["events"] = json!({"http://schemas.openid.net/event/backchannel-logout":{}});
    }
    let key = if rotate && mode == "signature" {
        &p.rotated_wrong_key
    } else if rotate {
        &p.rotated_key
    } else if mode == "signature" {
        &p.wrong_key
    } else {
        &p.key
    };
    let signed = format!(
        "{}.{}",
        parts[0],
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&extra).unwrap())
    );
    let encoded = format!(
        "{signed}.{}",
        URL_SAFE_NO_PAD.encode(
            key.sign(&CoreJwsSigningAlgorithm::EdDsa, signed.as_bytes())
                .unwrap()
        )
    );
    Json(json!({"access_token":if mode=="access-hash" {"substituted"}else{access.secret()},"token_type":"Bearer","id_token":encoded})).into_response()
}

#[tokio::test]
async fn oidc_signing_key_rotation_refreshes_once_without_replaying_exchange() {
    let l = IdentityLab::new().await;
    let owner = l.login("owner").await;
    l.member(&owner, "owner", None).await;
    // The provider's keys are fetched when a sign-in begins and held: the
    // callback reads them again only for a key that is not among them, once.
    for (mode, status, reads) in [
        ("signature", StatusCode::UNAUTHORIZED, 0),
        ("rotate-unpublished", StatusCode::UNAUTHORIZED, 1),
        ("rotate-unavailable", StatusCode::SERVICE_UNAVAILABLE, 1),
        ("rotate-ambiguous", StatusCode::UNAUTHORIZED, 1),
        ("rotate-signature", StatusCode::UNAUTHORIZED, 1),
        ("rotate-nonce", StatusCode::UNAUTHORIZED, 1),
        ("rotate-access-hash", StatusCode::UNAUTHORIZED, 1),
    ] {
        l.provider.key_phase.store(0, Ordering::SeqCst);
        l.lab.store.forget_provider_metadata().await;
        let login = l.begin("owner", mode).await;
        let before = l.provider.exchanges.load(Ordering::SeqCst);
        let keys = l.provider.key_reads.load(Ordering::SeqCst);
        let response = l.callback(&login).await;
        assert_eq!(response.status(), status, "{mode}");
        assert!(!response.headers().contains_key("set-cookie"));
        assert_eq!(
            l.provider.exchanges.load(Ordering::SeqCst),
            before + 1,
            "{mode}"
        );
        assert_eq!(
            l.provider.key_reads.load(Ordering::SeqCst),
            keys + reads,
            "{mode}"
        );
        assert_eq!(l.callback(&login).await.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(l.provider.exchanges.load(Ordering::SeqCst), before + 1);
        assert_eq!(l.provider.key_reads.load(Ordering::SeqCst), keys + reads);
        let counts: (i64, i64, i64) = sqlx::query_as("SELECT (SELECT count(*) FROM browser_logins),(SELECT count(*) FROM browser_sessions),(SELECT count(*) FROM customer_users)")
            .fetch_one(&l.lab.store.pool).await.unwrap();
        assert_eq!(counts, (0, 1, 1));
        assert_eq!(
            l.request(&owner, "GET", "/auth/session", None, false)
                .await
                .0,
            StatusCode::OK
        );
    }
    l.provider.key_phase.store(0, Ordering::SeqCst);
    l.lab.store.forget_provider_metadata().await;
    let login = l.begin("owner", "rotate-valid").await;
    let before = l.provider.exchanges.load(Ordering::SeqCst);
    let keys = l.provider.key_reads.load(Ordering::SeqCst);
    let response = l.callback(&login).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(l.provider.exchanges.load(Ordering::SeqCst), before + 1);
    assert_eq!(l.provider.key_reads.load(Ordering::SeqCst), keys + 1);
    let cookie = response
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap())
        .find(|v| v.starts_with("fenders_dev_session="))
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let browser = Browser {
        cookie,
        user: String::new(),
        csrf: String::new(),
    };
    let (status, info) = l
        .request(&browser, "GET", "/auth/session", None, false)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(info["user_id"], owner.user);
    assert_eq!(info["workspaces"][0]["memberships"][0]["role"], "owner");
    assert_eq!(l.callback(&login).await.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(l.provider.exchanges.load(Ordering::SeqCst), before + 1);
    assert_eq!(l.provider.key_reads.load(Ordering::SeqCst), keys + 1);
    // Sign-ins that anyone may start cost the provider nothing more: its
    // keys are held, however many begin.
    for _ in 0..5 {
        l.begin("owner", "signature").await;
    }
    assert_eq!(l.provider.key_reads.load(Ordering::SeqCst), keys + 1);
    assert_eq!(
        l.request(&owner, "GET", "/auth/session", None, false)
            .await
            .0,
        StatusCode::OK
    );
    l.finish().await;
}

#[tokio::test]
async fn oidc_code_flow_verifies_tokens_and_never_accepts_claims_as_permissions() {
    let l = IdentityLab::new().await;
    for mode in [
        "signature",
        "issuer",
        "audience",
        "nonce",
        "expired",
        "future",
        "azp",
        "access-hash",
    ] {
        let login = l.begin("attacker", mode).await;
        assert_eq!(
            l.callback(&login).await.status(),
            StatusCode::UNAUTHORIZED,
            "{mode}"
        );
        assert_eq!(
            l.callback(&login).await.status(),
            StatusCode::UNAUTHORIZED,
            "replay {mode}"
        );
    }
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM browser_sessions")
            .fetch_one(&l.lab.store.pool)
            .await
            .unwrap(),
        0
    );
    let browser = l.login("verified-user").await;
    assert_eq!(
        l.request(&browser, "GET", "/v1/control-plane/status", None, false)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    let (_, info) = l
        .request(&browser, "GET", "/auth/session", None, false)
        .await;
    assert_eq!(info["workspaces"], json!([]));
    assert_eq!(
        l.request(&browser, "GET", "/v1/nodes", None, false).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        l.request(&browser, "GET", "/v1/nodes", None, false).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        l.request(&browser, "POST", "/v1/tenants", Some(json!({})), true)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    let stored: Value = sqlx::query_scalar("SELECT to_jsonb(s) FROM browser_sessions s")
        .fetch_one(&l.lab.store.pool)
        .await
        .unwrap();
    assert!(
        !stored
            .to_string()
            .contains(browser.cookie.split_once('=').unwrap().1)
    );
    assert!(!stored.to_string().contains(&browser.csrf));
    assert_eq!(l.provider.exchanges.load(Ordering::SeqCst), 9);
    l.finish().await;
}

#[tokio::test]
async fn oidc_profile_timestamp_accepts_rfc3339_but_rejects_malformed_claims() {
    let l = IdentityLab::new().await;
    let login = l.begin("profile-owner", "invalid-profile-time").await;
    assert_eq!(l.callback(&login).await.status(), StatusCode::UNAUTHORIZED);
    let browser = l.login_mode("profile-owner", "profile-time").await;
    let (status, info) = l
        .request(&browser, "GET", "/auth/session", None, false)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(info["email"], "profile-owner@example.test");
    assert_eq!(info["workspaces"], json!([]));
    l.finish().await;
}

#[tokio::test]
async fn oidc_browser_binding_expiry_and_single_use_are_enforced() {
    let l = IdentityLab::new().await;
    let mut login = l.begin("user", "valid").await;
    let correct = login.cookie.clone();
    login.cookie = "fenders_dev_login=wrong".into();
    assert_eq!(l.callback(&login).await.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(l.provider.exchanges.load(Ordering::SeqCst), 0);
    login.cookie = correct;
    assert_eq!(l.callback(&login).await.status(), StatusCode::SEE_OTHER);
    assert_eq!(l.callback(&login).await.status(), StatusCode::UNAUTHORIZED);
    let login = l.begin("user", "valid").await;
    sqlx::query("UPDATE browser_logins SET expires=now()-interval '1 second'")
        .execute(&l.lab.store.pool)
        .await
        .unwrap();
    assert_eq!(l.callback(&login).await.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(l.provider.exchanges.load(Ordering::SeqCst), 1);
    let login = l.begin("other", "valid").await;
    let (a, b) = tokio::join!(l.callback(&login), l.callback(&login));
    assert!(
        a.status() == StatusCode::SEE_OTHER && b.status() == StatusCode::UNAUTHORIZED
            || b.status() == StatusCode::SEE_OTHER && a.status() == StatusCode::UNAUTHORIZED
    );
    assert_eq!(l.provider.exchanges.load(Ordering::SeqCst), 2);
    l.finish().await;
}

#[tokio::test]
async fn browser_membership_scope_and_csrf_protect_the_customer_api() {
    let l = IdentityLab::new().await;
    let owner = l.login("owner").await;
    let viewer = l.login("viewer").await;
    let editor = l.login("editor").await;
    l.member(&owner, "owner", None).await;
    l.member(&viewer, "viewer", Some(&l.lab.project)).await;
    l.member(&editor, "editor", Some(&l.lab.project)).await;
    let base = format!("/v1/tenants/{}", l.lab.tenant);
    let (_, projects) = l
        .request(&viewer, "GET", &format!("{base}/projects"), None, false)
        .await;
    assert_eq!(projects.as_array().unwrap().len(), 1);
    assert_eq!(projects[0]["id"], l.lab.project);
    let (_, info) = l
        .request(&viewer, "GET", "/auth/session", None, false)
        .await;
    assert_eq!(info["workspaces"][0]["default_project_id"], l.lab.project);
    assert_eq!(
        l.request(&viewer, "GET", &format!("{base}/usage"), None, false)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        l.request(
            &editor,
            "POST",
            &format!("{base}/projects"),
            Some(json!({"name":"denied"})),
            true
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    let scopes = format!("{base}/projects/{}/apps", l.lab.project);
    assert_eq!(
        l.request(&viewer, "GET", &scopes, None, false).await.0,
        StatusCode::OK
    );
    assert_eq!(
        l.request(
            &viewer,
            "POST",
            &scopes,
            Some(json!({"name":"denied","artifact_id":l.lab.artifact})),
            true
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        l.request(
            &editor,
            "GET",
            &format!("{base}/projects/{}/apps", uid()),
            None,
            false
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        l.request(
            &owner,
            "POST",
            &format!("{base}/projects"),
            Some(json!({"name":"no-csrf"})),
            false
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let mut wrong = Browser {
        cookie: owner.cookie.clone(),
        user: owner.user.clone(),
        csrf: "wrong".into(),
    };
    assert_eq!(
        l.request(
            &wrong,
            "POST",
            &format!("{base}/projects"),
            Some(json!({"name":"bad-csrf"})),
            true
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let request = Request::builder()
        .method("POST")
        .uri(format!("{base}/projects"))
        .header("Cookie", &owner.cookie)
        .header("Origin", "https://evil.example")
        .header("X-CSRF-Token", &owner.csrf)
        .body(Body::from("{\"name\":\"evil\"}"))
        .unwrap();
    assert_eq!(
        api::router(l.lab.store.clone())
            .oneshot(request)
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        l.request(
            &owner,
            "POST",
            &format!("{base}/projects"),
            Some(json!({"name":"Allowed"})),
            true
        )
        .await
        .0,
        StatusCode::CREATED
    );
    wrong.cookie = format!("{}; {}", owner.cookie, owner.cookie);
    assert_eq!(
        l.request(&wrong, "GET", "/auth/session", None, false)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        l.request(&owner, "POST", "/auth/logout", None, true)
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        l.request(&owner, "GET", "/auth/session", None, false)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    l.finish().await;
}

#[tokio::test]
async fn provider_logout_requires_csrf_and_invalidates_local_session_before_redirect() {
    let mut l = IdentityLab::new().await;
    let logout_url = format!("{}/logout?client_id=fenders-test", l.provider.issuer);
    l.lab.store = l
        .lab
        .store
        .clone()
        .with_browser_auth(
            BrowserAuthConfig {
                issuer: l.provider.issuer.clone(),
                client_id: "fenders-test".into(),
                client_secret: None,
                console_origin: l.provider.console_origin.clone(),
                endpoint_origins: vec![],
                provider_ca_pem: None,
                provider_logout_url: Some(logout_url.clone()),
            },
            true,
        )
        .unwrap();
    let browser = l.login("owner").await;
    assert_eq!(
        l.request(&browser, "POST", "/auth/logout", None, false)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        l.request(&browser, "GET", "/auth/session", None, false)
            .await
            .0,
        StatusCode::OK
    );
    let invalid_csrf = api::router(l.lab.store.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/logout")
                .header("Cookie", &browser.cookie)
                .header("Origin", &l.provider.console_origin)
                .header("X-CSRF-Token", "invalid")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(invalid_csrf.status(), StatusCode::FORBIDDEN);
    let response = api::router(l.lab.store.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/logout")
                .header("Cookie", &browser.cookie)
                .header("Origin", &l.provider.console_origin)
                .header("X-CSRF-Token", &browser.csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let cookies: Vec<_> = response
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|h| h.to_str().unwrap())
        .collect();
    assert_eq!(cookies.len(), 2);
    assert!(cookies.iter().all(|c| c.contains("Max-Age=0")));
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 8192).await.unwrap()).unwrap();
    assert_eq!(body, json!({"logout_url":logout_url}));
    // Recover the same fixed provider destination if the committed response was
    // lost, whether the browser retained its old cookie or applied its clearing.
    for cookie in [Some(browser.cookie.as_str()), None] {
        let mut request = Request::builder()
            .method("POST")
            .uri("/auth/logout")
            .header("Origin", &l.provider.console_origin)
            .header("X-CSRF-Token", &browser.csrf);
        if let Some(cookie) = cookie {
            request = request.header("Cookie", cookie);
        }
        let retry = api::router(l.lab.store.clone())
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(retry.status(), StatusCode::OK);
        let value: Value =
            serde_json::from_slice(&to_bytes(retry.into_body(), 8192).await.unwrap()).unwrap();
        assert_eq!(value, json!({"logout_url":logout_url}));
    }
    for origin in [None, Some("https://outsider.example")] {
        let mut request = Request::builder()
            .method("POST")
            .uri("/auth/logout")
            .header("X-CSRF-Token", &browser.csrf);
        if let Some(origin) = origin {
            request = request.header("Origin", origin);
        }
        let response = api::router(l.lab.store.clone())
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    assert_eq!(
        l.request(&browser, "GET", "/auth/session", None, false)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    l.finish().await;
}

#[tokio::test]
async fn memberships_are_revisioned_and_revocation_rechecks_in_mutation_transaction() {
    let l = IdentityLab::new().await;
    let owner = l.login("owner").await;
    let editor = l.login("editor").await;
    let owner_member = l.member(&owner, "owner", None).await;
    let member = l.member(&editor, "editor", None).await;
    assert_eq!(l.member(&editor, "editor", None).await["id"], member["id"]);
    let base = format!("/v1/tenants/{}/members", l.lab.tenant);
    assert_eq!(
        l.request(
            &owner,
            "PATCH",
            &format!("{base}/{}", s(&owner_member["id"])),
            Some(json!({"revoked":true,"expected_revision":1})),
            true
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        l.request(
            &owner,
            "POST",
            &base,
            Some(json!({"user_id":editor.user,"role":"operator"})),
            true
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let session: Value =
        sqlx::query_scalar("SELECT to_jsonb(s) FROM browser_sessions s WHERE user_id=$1")
            .bind(&editor.user)
            .fetch_one(&l.lab.store.pool)
            .await
            .unwrap();
    let stale:Principal=serde_json::from_value(json!({"id":editor.user,"role":"editor","tenant_id":l.lab.tenant,"project_id":null,"membership_id":member["id"],"session_id":session["id"]})).unwrap();
    let change = json!({"role":"viewer","expected_revision":1});
    let path = format!("{base}/{}", s(&member["id"]));
    let (a, b) = tokio::join!(
        l.request(&owner, "PATCH", &path, Some(change.clone()), true),
        l.request(&owner, "PATCH", &path, Some(change), true)
    );
    assert!(
        a.0 == StatusCode::OK && b.0 == StatusCode::CONFLICT
            || b.0 == StatusCode::OK && a.0 == StatusCode::CONFLICT
    );
    assert_eq!(
        l.lab
            .store
            .create_project(
                &stale,
                &l.lab.tenant,
                serde_json::from_value(json!({"name":"stale"})).unwrap()
            )
            .await
            .unwrap_err()
            .status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        l.request(
            &editor,
            "POST",
            &format!("/v1/tenants/{}/projects", l.lab.tenant),
            Some(json!({"name":"viewer-write"})),
            true
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        l.request(
            &owner,
            "PATCH",
            &path,
            Some(json!({"revoked":true,"expected_revision":2})),
            true
        )
        .await
        .0,
        StatusCode::OK
    );
    let (_, info) = l
        .request(&editor, "GET", "/auth/session", None, false)
        .await;
    assert_eq!(info["workspaces"], json!([]));
    sqlx::query("UPDATE recovery_barrier SET active=true")
        .execute(&l.lab.store.pool)
        .await
        .unwrap();
    assert_eq!(
        l.request(
            &owner,
            "PATCH",
            &path,
            Some(json!({"revoked":false,"expected_revision":3})),
            true
        )
        .await
        .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    l.finish().await;
}

#[tokio::test]
async fn browser_sessions_rotate_expire_and_observe_multiple_project_grants() {
    let l = IdentityLab::new().await;
    let browser = l.login("user").await;
    l.member(&browser, "editor", Some(&l.lab.project)).await;
    let other = l
        .lab
        .store
        .create_project(
            &l.lab.operator,
            &l.lab.tenant,
            serde_json::from_value(json!({"name":"Second"})).unwrap(),
        )
        .await
        .unwrap();
    l.member(&browser, "viewer", Some(s(&other["id"]))).await;
    let base = format!("/v1/tenants/{}", l.lab.tenant);
    let (_, projects) = l
        .request(&browser, "GET", &format!("{base}/projects"), None, false)
        .await;
    assert_eq!(projects.as_array().unwrap().len(), 2);
    assert_eq!(
        l.request(
            &browser,
            "POST",
            &format!("{base}/projects/{}/apps", s(&other["id"])),
            Some(json!({"name":"denied","artifact_id":l.lab.artifact})),
            true
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let another=l.lab.store.create_tenant(&l.lab.operator,serde_json::from_value(json!({"name":"second-workspace","allowance":{"cpu_percent":100,"memory_mib":1024,"instances":1,"storage_bytes":1000000,"transfer_bytes":10000000}})).unwrap()).await.unwrap();
    assert_eq!(
        l.request(
            &browser,
            "GET",
            &format!("/v1/tenants/{}/projects", s(&another["id"])),
            None,
            false
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    l.lab
        .store
        .add_member(
            &l.lab.operator,
            s(&another["id"]),
            json!({"user_id":browser.user,"role":"viewer"}),
        )
        .await
        .unwrap();
    let (_, info) = l
        .request(&browser, "GET", "/auth/session", None, false)
        .await;
    assert_eq!(info["workspaces"].as_array().unwrap().len(), 2);
    let mut login = l.begin("user", "valid").await;
    login.cookie = format!("{}; {}", login.cookie, browser.cookie);
    let response = l.callback(&login).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        l.request(&browser, "GET", "/auth/session", None, false)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    let fresh = l.login("user").await;
    assert_eq!(fresh.user, browser.user);
    // A session left unused for half an hour is over, though its eight
    // hours are not; one in use is kept, its use written down once a minute.
    let used = |ago: &'static str| {
        let pool = l.lab.store.pool.clone();
        async move {
            sqlx::query(&format!(
                "UPDATE browser_sessions SET last_used=now()-interval '{ago}'"
            ))
            .execute(&pool)
            .await
            .unwrap();
        }
    };
    let session = || async {
        l.request(&fresh, "GET", "/auth/session", None, false)
            .await
            .0
    };
    used("29 minutes").await;
    assert_eq!(session().await, StatusCode::OK);
    let recent: bool = sqlx::query_scalar(
        "SELECT bool_or(last_used>now()-interval '1 minute') FROM browser_sessions",
    )
    .fetch_one(&l.lab.store.pool)
    .await
    .unwrap();
    assert!(recent, "its use was written down");
    used("31 minutes").await;
    assert_eq!(session().await, StatusCode::UNAUTHORIZED);
    let (status, _) = l
        .request(
            &fresh,
            "GET",
            &format!("/v1/tenants/{}/projects", l.lab.tenant),
            None,
            false,
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    used("1 second").await;
    assert_eq!(session().await, StatusCode::OK);
    sqlx::query("UPDATE browser_sessions SET expires=now()-interval '1 second'")
        .execute(&l.lab.store.pool)
        .await
        .unwrap();
    assert_eq!(
        l.request(&fresh, "GET", "/auth/session", None, false)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    sqlx::query("UPDATE customer_users SET disabled=true WHERE id=$1")
        .bind(&browser.user)
        .execute(&l.lab.store.pool)
        .await
        .unwrap();
    let disabled = l.begin("user", "valid").await;
    assert_eq!(
        l.callback(&disabled).await.status(),
        StatusCode::UNAUTHORIZED
    );
    l.finish().await;
}

#[tokio::test]
async fn customer_assets_and_signin_failure_respect_browser_and_api_boundaries() {
    let l = Lab::new().await;
    // The control plane ships no console: a wrapping binary supplies one.
    let missing = api::router(l.store.clone())
        .oneshot(
            Request::builder()
                .uri("/console/")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_ne!(missing.status(), StatusCode::OK);
    static CONSOLE: [api::Asset; 2] = [
        api::Asset {
            path: "/console/",
            content_type: "text/html; charset=utf-8",
            body: b"<!doctype html>",
        },
        api::Asset {
            path: "/console/app.js",
            content_type: "text/javascript",
            body: b"'use strict'",
        },
    ];
    let with_console = l.store.clone().with_assets(&CONSOLE);
    for (path, mime) in [
        ("/console/", "text/html; charset=utf-8"),
        ("/console/app.js", "text/javascript"),
        ("/api", "text/html; charset=utf-8"),
        ("/api/openapi.json", "application/json"),
    ] {
        let response = api::router(with_console.clone())
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["content-type"], mime);
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert!(
            response.headers()["content-security-policy"]
                .to_str()
                .unwrap()
                .contains("script-src 'self'")
        );
        let body = to_bytes(response.into_body(), 128 * 1024).await.unwrap();
        assert!(!body.is_empty());
    }
    for path in [
        "/auth/login",
        "/auth/callback?code=private-code&state=private-state",
    ] {
        for (accept, expected) in [
            ("application/json", StatusCode::SERVICE_UNAVAILABLE),
            ("text/html", StatusCode::SEE_OTHER),
        ] {
            let response = api::router(l.store.clone())
                .oneshot(
                    Request::builder()
                        .uri(path)
                        .header("Accept", accept)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), expected);
            assert_eq!(response.headers()["referrer-policy"], "no-referrer");
            if accept == "text/html" {
                assert_eq!(response.headers()["location"], "/console/?signin=failed");
            }
        }
    }
    l.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires local Playwright and Chromium; run explicitly with --ignored --nocapture"]
async fn customer_console_browser_against_rust_api() {
    use std::time::Duration;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let mut l = IdentityLab::at_origin(&origin).await;
    l.lab.store = l
        .lab
        .store
        .clone()
        .with_browser_auth(
            BrowserAuthConfig {
                issuer: l.provider.issuer.clone(),
                client_id: "fenders-test".into(),
                client_secret: None,
                console_origin: origin.clone(),
                endpoint_origins: vec![],
                provider_ca_pem: None,
                provider_logout_url: Some(format!("{}/logout", l.provider.issuer)),
            },
            true,
        )
        .unwrap();
    let password = l.lab.root.path().join("smtp");
    std::fs::write(&password, "fixture-only").unwrap();
    l.lab.store = l
        .lab
        .store
        .clone()
        .with_invitation_email(
            fenders_control_plane::invitation_email::InvitationEmailConfig {
                host: "localhost".into(),
                port: 1,
                username: "fixture".into(),
                password_file: password,
                from: "Fenders <hello@example.test>".into(),
                console_origin: "https://console.example.test".into(),
            },
        )
        .unwrap();
    let dns = super::dns::DnsLab::new().await;
    l.lab.store = l.lab.store.with_public_egress(dns.config.clone()).unwrap();
    let public_runtime = digest("browser-runtime-protocol-fixture");
    let owner = l.login("console-owner").await;
    l.member(&owner, "owner", None).await;
    let viewer = l.login("console-viewer").await;
    let viewer_membership = l.member(&viewer, "viewer", Some(&l.lab.project)).await;
    let editor = l.login("console-editor").await;
    l.member(&editor, "editor", None).await;
    let scoped_editor = l.login("console-project-editor").await;
    l.member(&scoped_editor, "editor", Some(&l.lab.project))
        .await;
    let no_access = l.login("console-no-access").await;
    let onboard = l.login("console-onboard").await;
    let expired = l.login("console-expired").await;
    sqlx::query("UPDATE browser_sessions SET expires=now()-interval '1 second' WHERE user_id=$1")
        .bind(&expired.user)
        .execute(&l.lab.store.pool)
        .await
        .unwrap();
    let second = l.lab.store.create_tenant(&l.lab.operator, serde_json::from_value(json!({"name":"other-workspace","allowance":{"cpu_percent":100,"memory_mib":512,"instances":2,"storage_bytes":10_000_000_000_i64,"transfer_bytes":1000000}})).unwrap()).await.unwrap();
    // HTTPS draft isolation needs two projects independently of endpoint setup.
    l.lab
        .store
        .create_project(
            &l.lab.operator,
            s(&second["id"]),
            serde_json::from_value(json!({"name":"Other HTTPS project"})).unwrap(),
        )
        .await
        .unwrap();
    l.lab
        .store
        .add_member(
            &l.lab.operator,
            s(&second["id"]),
            json!({"user_id":owner.user,"role":"owner"}),
        )
        .await
        .unwrap();
    let (node, sample_tls, sample_peer) = console_http_peer(&l.lab).await;
    sqlx::query("UPDATE nodes SET cpu_percent=400,memory_mib=4096,instances=16 WHERE id=$1")
        .bind(s(&node["id"]))
        .execute(&l.lab.store.pool)
        .await
        .unwrap();
    approve_component(&l.lab, &node, true, true).await;
    let mut diagnostics_fixture = console_diagnostics_fixture(&l.lab, &node).await;
    let mut activity_fixture = Value::Null;
    let mut bulk_fixture = Value::Null;
    for index in 0..26 {
        let deployed = l
            .lab
            .deploy(
                &format!("command-{index:02}"),
                false,
                true,
                &format!("console-{index}"),
            )
            .await
            .unwrap();
        if index == 0 {
            activity_fixture =
                console_activity_fixture(&l.lab, &node, s(&deployed["resource_id"]), false).await;
        } else if index == 1 {
            bulk_fixture =
                console_activity_fixture(&l.lab, &node, s(&deployed["resource_id"]), true).await;
        }
    }
    let http = l
        .lab
        .deploy("http-preparing", true, false, "console-http")
        .await
        .unwrap();
    let mut runs_fixture = Value::Null;
    if std::env::var("FENDERS_CONSOLE_FOCUS").as_deref() == Ok("runs") {
        let deployed=l.lab.store.deploy_app(&l.lab.operator,&l.lab.tenant,&l.lab.project,fenders_control_plane::apps::AppSubmission {
            value:json!({"name":"invocation-history","artifact_id":l.lab.artifact,"triggers":{"http":true,"manual":true}}),key:"invocation-history",domain:"apps.localhost"
        }).await.unwrap();
        let app = s(&deployed["resource_id"]);
        l.lab.http_running(app, &node).await;
        let manual = l
            .lab
            .store
            .run_app(
                &l.lab.operator,
                &l.lab.tenant,
                &l.lab.project,
                app,
                "manual-run",
            )
            .await
            .unwrap();
        l.lab.store.schedule().await.unwrap();
        let run = l
            .lab
            .store
            .app_run(
                &l.lab.operator,
                &l.lab.tenant,
                &l.lab.project,
                app,
                s(&manual["resource_id"]),
            )
            .await
            .unwrap();
        let execution = l.lab.execution(s(&run["execution_id"])).await;
        l.lab.report(&node, &execution, "exited", 1).await;
        let revision = l
            .lab
            .store
            .app_triggers(&l.lab.operator, &l.lab.tenant, &l.lab.project, app)
            .await
            .unwrap()["revision"]
            .clone();
        l.lab.store.update_app_triggers(&l.lab.operator,&l.lab.tenant,&l.lab.project,app,json!({"expected_revision":revision,"schedule":{"enabled":true,"expression":"0 0 1 1 *","timezone":"UTC"}}),"enable-schedule-test").await.unwrap();
        let scheduled = l
            .lab
            .store
            .run_app_event(
                &l.lab.operator,
                &l.lab.tenant,
                &l.lab.project,
                app,
                fenders_control_plane::app_runtime::RunEvent {
                    key: "schedule-test",
                    source: fenders_control_plane::app_runtime::RunSource::TestSchedule,
                    trigger_time: None,
                },
            )
            .await
            .unwrap();
        l.lab.store.schedule().await.unwrap();
        let run = l
            .lab
            .store
            .app_run(
                &l.lab.operator,
                &l.lab.tenant,
                &l.lab.project,
                app,
                s(&scheduled["resource_id"]),
            )
            .await
            .unwrap();
        let execution = l.lab.execution(s(&run["execution_id"])).await;
        l.lab.report(&node, &execution, "exited", 1).await;
        for i in 0..23 {
            let (_, id) = l
                .lab
                .store
                .ingress_wait_request(
                    &format!("app-{app}.apps.localhost"),
                    0,
                    Some((
                        "GET",
                        if i == 22 {
                            "/untrusted/<img>?token=hidden"
                        } else {
                            "/hello"
                        },
                    )),
                )
                .await
                .unwrap();
            l.lab.store.ingress_dispatched(&id).await.unwrap();
            l.lab
                .store
                .ingress_complete(&id, Some(2), Some(if i == 22 { 503 } else { 200 }))
                .await
                .unwrap();
        }
        runs_fixture = json!({"app":app});
    }
    // Retire a real historical release through the production SQL path. Its
    // app/version/outcome remain readable; the browser never fabricates expiry.
    let retired_release = uid();
    sqlx::query("INSERT INTO app_releases(id,tenant_id,project_id,app_id,version_id,configuration,spec,state,reason) SELECT $1,tenant_id,project_id,app_id,version_id,configuration||'{\"env\":{\"OLD_INPUT\":\"historical\"}}'::jsonb,spec||'{\"env\":{\"OLD_INPUT\":\"historical\"}}'::jsonb,'failed','superseded' FROM app_releases WHERE id=$2")
        .bind(&retired_release).bind(s(&activity_fixture["release"])).execute(&l.lab.store.pool).await.unwrap();
    super::release_input_retention::age(&l.lab, &retired_release).await;
    sqlx::raw_sql(include_str!("../../src/release_input_retention.sql"))
        .execute(&l.lab.store.pool)
        .await
        .unwrap();
    activity_fixture["retiredRelease"] = json!(retired_release);
    let (draft, _) = define_app(&l.lab, "draft-only").await;
    let projects = l
        .lab
        .store
        .projects(&l.lab.operator, &l.lab.tenant)
        .await
        .unwrap();
    let production = projects
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["is_default"] == true)
        .unwrap();
    let unconfigured_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let unconfigured_origin = format!("http://{}", unconfigured_listener.local_addr().unwrap());
    let unconfigured_store = Store::from_pool(l.lab.store.pool.clone(), l.lab.root.path()).unwrap();
    let unconfigured_server = tokio::spawn(async move {
        axum::serve(unconfigured_listener, api::router(unconfigured_store))
            .await
            .unwrap();
    });
    let command = r#"(component
      (core module $m (func (export "run") (result i32) i32.const 0))
      (core instance $i (instantiate $m))
      (func $run (result (result)) (canon lift (core func $i "run")))
      (instance $cli (export "run" (func $run)))
      (export "wasi:cli/run@0.2.0" (instance $cli)))"#;
    let http_wit = r#"
      (import "wasi:http/types@0.2.6" (instance $types
        (export "incoming-request" (type (sub resource)))
        (export "response-outparam" (type (sub resource)))))
      (alias export $types "incoming-request" (type $request))
      (alias export $types "response-outparam" (type $response))
      (core module $h (func (export "handle") (param i32 i32)))
      (core instance $hi (instantiate $h))
      (func $handle (param "request" (own $request)) (param "response" (own $response))
        (canon lift (core func $hi "handle")))
      (instance $http (export "handle" (func $handle)))
      (export "wasi:http/incoming-handler@0.2.6" (instance $http))"#;
    let command_bytes = wat::parse_str(command).unwrap();
    let dual_bytes =
        wat::parse_str(command.replacen("(component", &format!("(component {http_wit}"), 1))
            .unwrap();
    use base64::Engine;
    let unsupported = wat::parse_str(command.replacen(
        "(component",
        "(component (import \"private:host/magic\" (instance (export \"call\" (func))))",
        1,
    ))
    .unwrap();
    let excessive = wat::parse_str(command.replacen(
        "(export \"wasi:cli/run",
        &format!(
            "(export \"{}\" (instance $cli)) (export \"wasi:cli/run",
            "x".repeat(257)
        ),
        1,
    ))
    .unwrap();
    let component_bytes = json!({"command":base64::engine::general_purpose::STANDARD.encode(command_bytes),"dual":base64::engine::general_purpose::STANDARD.encode(dual_bytes),"unsupported":base64::engine::general_purpose::STANDARD.encode(unsupported),"excessive":base64::engine::general_purpose::STANDARD.encode(excessive)});
    // Actual pinned inspection, through the durable job protocol. This local
    // test worker is not a confinement or guest-execution acceptance substitute.
    // Record a real placement rejection after the historical fixture setup.
    // No scheduler loop runs before the diagnostics case explicitly stops it.
    l.lab
        .store
        .node_mode(&l.lab.operator, s(&node["id"]), json!({"draining":true}))
        .await
        .unwrap();
    let placement=l.lab.store.deploy_app(&l.lab.operator,&l.lab.tenant,s(&diagnostics_fixture["project"]),fenders_control_plane::apps::AppSubmission{value:json!({"name":"awaiting-worker","artifact_id":diagnostics_fixture["artifact"],"triggers":{"http":true,"manual":false}}),key:"awaiting-worker",domain:"apps.test"}).await.unwrap();
    l.lab.store.schedule().await.unwrap();
    diagnostics_fixture["placementApp"] = placement["resource_id"].clone();
    l.lab
        .store
        .node_mode(&l.lab.operator, s(&node["id"]), json!({"draining":false}))
        .await
        .unwrap();
    let compiler_store = l.lab.store.clone();
    let compiler_node = s(&node["id"]).to_owned();
    let runtime_heartbeat = public_runtime.clone();
    let compiler = tokio::spawn(async move {
        let mut report_sequence = 0;
        let mut idle_primed = false;
        loop {
            compiler_store.heartbeat(&compiler_node,json!({"boot_id":"test-boot","reports":[],"confinement":HOST_CONFINEMENT,"runtime_digest":runtime_heartbeat})).await.unwrap();
            let job = compiler_store
                .claim_component(&compiler_node, json!({"boot_id":"test-boot"}))
                .await
                .unwrap()["job"]
                .clone();
            if !job.is_null() {
                let bytes = compiler_store
                    .component_content(
                        &compiler_node,
                        s(&job["artifact_id"]),
                        n(&job["generation"]),
                        json!({"boot_id":"test-boot"}),
                    )
                    .await
                    .unwrap();
                let inspected =
                    tokio::task::spawn_blocking(move || fenders_component::inspect(&bytes))
                        .await
                        .unwrap();
                let result = match inspected {
                    Ok(inspection) => json!({"boot_id":"test-boot","inspection":inspection}),
                    Err(error) => {
                        json!({"boot_id":"test-boot","error":fenders_component::rejection_code(&error).unwrap_or("compiler-unavailable")})
                    }
                };
                compiler_store
                    .component_result(
                        &compiler_node,
                        s(&job["artifact_id"]),
                        n(&job["generation"]),
                        result,
                    )
                    .await
                    .unwrap();
            }
            // Only the final HTTP sample scenario opts into simulated worker
            // lifecycle reports. Other console cases retain their queued state.
            let sample: Option<String> =
                sqlx::query_scalar("SELECT id FROM apps WHERE name='console-http-sample'")
                    .fetch_optional(&compiler_store.pool)
                    .await
                    .unwrap();
            if let Some(app) = sample {
                compiler_store.schedule().await.unwrap();
                let execution:Option<Value> = sqlx::query_scalar("SELECT to_jsonb(e) FROM executions e JOIN app_http h ON h.execution_id=e.id WHERE h.app_id=$1 AND e.node_id=$2")
                    .bind(&app).bind(&compiler_node).fetch_optional(&compiler_store.pool).await.unwrap();
                if let Some(e) = execution {
                    report_sequence += 1;
                    compiler_store.heartbeat(&compiler_node,json!({"boot_id":"test-boot","confinement":HOST_CONFINEMENT,"runtime_digest":runtime_heartbeat,"reports":[{"id":e["id"],"generation":e["generation"],"sequence":report_sequence,"state":e["desired"],"cpu_usec":0,"memory_bytes":1024,"cpu_measured":true,"memory_measured":true,"egress":{"contract":"socket-payload-v1","boot_id":"test-boot","bytes":4096,"in_flight":0,"complete":false,"observed":std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs_f64()},"egress_periods":{"contract":"socket-payload-utc-month-v1","boot_id":"test-boot","bytes":4096,"expired_bytes":0,"periods":[{"period":chrono::Utc::now().format("%Y-%m-01").to_string(),"bytes":4096}],"in_flight":0,"complete":false,"observed":std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs_f64()}}]})).await.unwrap();
                }
                if !idle_primed {
                    idle_primed = sqlx::query("UPDATE app_http SET last_activity=now()-interval '61 seconds' WHERE app_id=$1 AND state='serving'")
                        .bind(&app).execute(&compiler_store.pool).await.unwrap().rows_affected()>0;
                }
            }
            // Explicit HTTPS browser scenario: real admission, DNS assignment
            // and policy; synthetic running/terminal reports, never a real VM.
            // Withhold terminal acknowledgment while public policy is enabled
            // so the browser can observe an uncertain worker and Revoking.
            if let Some(app) = sqlx::query_scalar::<_, String>(
                "SELECT id FROM apps WHERE name='console-https-running'",
            )
            .fetch_optional(&compiler_store.pool)
            .await
            .unwrap()
            {
                compiler_store.schedule().await.unwrap();
                let executions:Vec<Value>=sqlx::query_scalar("SELECT to_jsonb(e) FROM executions e JOIN app_runs r ON r.execution_id=e.id WHERE r.app_id=$1 AND e.node_id=$2 AND e.reserved").bind(&app).bind(&compiler_node).fetch_all(&compiler_store.pool).await.unwrap();
                for e in executions {
                    let enabled: bool =
                        sqlx::query_scalar("SELECT enabled FROM public_egress_policy")
                            .fetch_one(&compiler_store.pool)
                            .await
                            .unwrap();
                    if e["desired"] == "stopped" && enabled {
                        continue;
                    }
                    if e["desired"] != "stopped"
                        && compiler_store
                            .assignment(&compiler_node, s(&e["id"]), n(&e["generation"]))
                            .await
                            .is_err()
                    {
                        continue;
                    }
                    report_sequence += 1;
                    compiler_store.heartbeat(&compiler_node,json!({"boot_id":"test-boot","confinement":HOST_CONFINEMENT,"runtime_digest":runtime_heartbeat,"reports":[{"id":e["id"],"generation":e["generation"],"sequence":report_sequence,"state":e["desired"],"cpu_usec":0,"memory_bytes":1024,"cpu_measured":true,"memory_measured":true,"egress":{"contract":"socket-payload-v1","boot_id":"test-boot","bytes":4096,"in_flight":0,"complete":false,"observed":std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs_f64()},"egress_periods":{"contract":"socket-payload-utc-month-v1","boot_id":"test-boot","bytes":4096,"expired_bytes":0,"periods":[{"period":chrono::Utc::now().format("%Y-%m-01").to_string(),"bytes":4096}],"in_flight":0,"complete":false,"observed":std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs_f64()}}]})).await.unwrap();
                }
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    });
    // Seed historical database accounting, including an absent month and an
    // archived partial observation. Browser responses still use the real API.
    sqlx::query("INSERT INTO traffic_usage(tenant_id,project_id,period,bytes,requests) SELECT $1,$2,(date_trunc('month',now() AT TIME ZONE 'UTC')-make_interval(months=>age))::date,age*1024,age FROM generate_series(1,14) age WHERE age<>9")
        .bind(&l.lab.tenant).bind(&l.lab.project).execute(&l.lab.store.pool).await.unwrap();
    sqlx::query("INSERT INTO accounting_month_rollups(tenant_id,project_id,period,outbound_accounted_bytes,outbound_conservative_bytes,settlement_records,observed_outbound_bytes,observed_period_records,observed_at) VALUES($1,$2,(date_trunc('month',now() AT TIME ZONE 'UTC')-interval '14 months')::date,4096,1024,1,2048,1,now()-interval '14 months')")
        .bind(&l.lab.tenant).bind(&l.lab.project).execute(&l.lab.store.pool).await.unwrap();
    let fixture = json!({"origin":origin,"unconfiguredOrigin":unconfigured_origin,"tenant":l.lab.tenant,"project":l.lab.project,"production":production["id"],"secondTenant":second["id"],"httpApp":http["resource_id"],"draftApp":draft,"viewerMembership":viewer_membership,
        "onboardCookie":onboard.cookie,"viewerCookie":viewer.cookie,"editorCookie":editor.cookie,"scopedEditorCookie":scoped_editor.cookie,"noAccessCookie":no_access.cookie,"expiredCookie":expired.cookie,"components":component_bytes,"activity":activity_fixture,"runs":runs_fixture,"diagnostics":diagnostics_fixture,"bulkActivity":bulk_fixture,"operatorToken":l.lab.token,"httpsNode":node["id"],"httpsRuntime":public_runtime});
    let store = l.lab.store.clone();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            api::management(api::ApiState {
                store,
                domain: "apps.localhost".to_owned(),
                tls: Some(sample_tls),
            }),
        )
        .await
        .unwrap();
    });
    let passed = run_console_browser("tests/verify_customer.cjs", fixture).await;
    if !passed {
        let activity = tokio::time::timeout(Duration::from_secs(2),sqlx::query_scalar::<_,Value>("SELECT COALESCE(jsonb_agg(to_jsonb(s)),'[]'::jsonb) FROM (SELECT state,wait_event_type,wait_event,count(*) FROM pg_stat_activity WHERE datname=current_database() GROUP BY state,wait_event_type,wait_event) s").fetch_one(&l.lab.store.pool)).await;
        eprintln!(
            "Browser database activity: {activity:?}; pool size={}, idle={}",
            l.lab.store.pool.size(),
            l.lab.store.pool.num_idle()
        );
    }
    server.abort();
    unconfigured_server.abort();
    compiler.abort();
    sample_peer.abort();
    let browser_exchanged = l.provider.exchanges.load(Ordering::SeqCst) > 6;
    l.finish().await;
    assert!(
        browser_exchanged,
        "browser did not complete the OIDC exchange"
    );
    assert!(passed, "customer browser acceptance failed");
}

// A real pinned-mTLS RPC fixture with scripted application responses. It is not
// a guest, and lifecycle reports below do not establish KVM execution evidence.
async fn console_http_peer(l: &Lab) -> (Value, api::PeerCredentials, tokio::task::JoinHandle<()>) {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use fenders_control_plane::{pki, transport};
    let dir = l.root.path().join("console-http-pki");
    let pins = pki::create(
        &dir,
        &std::collections::BTreeMap::from([
            ("control".to_owned(), vec!["127.0.0.1".to_owned()]),
            ("node".to_owned(), vec!["127.0.0.1".to_owned()]),
        ]),
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("https://{}", listener.local_addr().unwrap());
    let calls = Arc::new(AtomicUsize::new(0));
    let router = Router::new().route(
        "/rpc/ingress",
        axum::routing::post(move |Json(request): Json<Value>| {
            let call = calls.fetch_add(1, Ordering::SeqCst) + 1;
            async move {
                let (status, headers, body) = match call {
                    1 => (
                        200,
                        json!({"content-type":"text/html","set-cookie":"never-apply=1"}),
                        STANDARD.encode(format!(
                            "<script>throw new Error('untrusted')</script>\nHello 🦀\u{202e}\n{}",
                            "x".repeat(20000)
                        )),
                    ),
                    2 => (
                        302,
                        json!({"location":"https://untrusted.invalid/"}),
                        STANDARD.encode("Redirect was not followed"),
                    ),
                    3 => (
                        503,
                        json!({"content-type":"text/plain"}),
                        STANDARD.encode("Application unavailable"),
                    ),
                    4 => (200, json!({}), "not base64!".to_owned()),
                    _ => (
                        200,
                        json!({"content-type":"application/json"}),
                        STANDARD.encode(request["request"].to_string()),
                    ),
                };
                Json(json!({"status":status,"headers":headers,"body":body}))
            }
        }),
    );
    let config = transport::server_config(
        &dir.join("node.pem"),
        &dir.join("node.key"),
        Some(&dir.join("ca.pem")),
    )
    .unwrap();
    let server = tokio::spawn(async move {
        transport::serve_tls(listener, config, router)
            .await
            .unwrap();
    });
    let node=l.store.register_node(&l.operator,json!({"name":"console-compiler-fixture","cert_sha256":pins["node"],"endpoint":endpoint,"backend":"wasm","architecture":"x86_64","runtime":"wasmtime-50.0.0-fenders-v1","cpu_percent":100,"memory_mib":1024,"instances":4})).await.unwrap();
    l.store
        .heartbeat(
            s(&node["id"]),
            json!({"boot_id":"test-boot","reports":[],"confinement":HOST_CONFINEMENT}),
        )
        .await
        .unwrap();
    (
        node,
        api::PeerCredentials {
            ca: dir.join("ca.pem"),
            cert: dir.join("control.pem"),
            key: dir.join("control.key"),
        },
        server,
    )
}

// Durable API fixture with real ingestion. Worker outcomes are protocol data;
// this does not claim that a guest ran on the browser test host.
async fn console_activity_fixture(l: &Lab, node: &Value, app: &str, bulk: bool) -> Value {
    use super::execution_logs::{batch, record};
    let mut fixture = Value::Null;
    for index in 0..if bulk { 3 } else { 22 } {
        let op = l
            .store
            .run_app(&l.operator, &l.tenant, &l.project, app, &uid())
            .await
            .unwrap();
        l.store.schedule().await.unwrap();
        let run = l
            .store
            .app_run(
                &l.operator,
                &l.tenant,
                &l.project,
                app,
                s(&op["resource_id"]),
            )
            .await
            .unwrap();
        let e = l.execution(s(&run["execution_id"])).await;
        let records = if bulk {
            if index == 0 {
                fixture = json!({"app":app,"run":run["id"]});
                json!(
                    (1..=1100)
                        .map(|seq| record(seq, b"row\n"))
                        .collect::<Vec<_>>()
                )
            } else {
                json!(
                    (1..=80)
                        .map(|seq| record(seq, &vec![b'x'; 8192]))
                        .collect::<Vec<_>>()
                )
            }
        } else if index == 0 {
            let mut records = (3..=105)
                .map(|seq| record(seq, format!("line {seq}\n").as_bytes()))
                .collect::<Vec<_>>();
            records[98] = record(101, b"split: \xe2");
            records[99] = record(102, b"stderr is separate\n");
            records[99]["stream"] = json!("stderr");
            records[100] = record(103, b"\x82\xac <img src=x onerror=alert(1)>\0\xff\x1b\n");
            fixture =
                json!({"app":app,"run":run["id"],"execution":e["id"],"release":run["release_id"]});
            json!(records)
        } else {
            json!([])
        };
        let capture = uid();
        let chunks = if bulk || index == 0 {
            records
                .as_array()
                .unwrap()
                .chunks(8)
                .map(|rows| json!(rows))
                .collect::<Vec<_>>()
        } else {
            vec![json!([])]
        };
        for chunk in chunks {
            let mut payload = batch(
                &capture,
                if !bulk && index == 0 { 3 } else { 1 },
                if bulk {
                    records.as_array().unwrap().len() as i64
                } else if index == 0 {
                    105
                } else {
                    0
                },
                true,
                chunk,
            );
            if !bulk && index == 1 {
                payload["interrupted"] = json!(true);
                fixture["interruptedRun"] = run["id"].clone();
            }
            l.store
                .ingest_execution_logs(s(&node["id"]), s(&e["id"]), n(&e["generation"]), payload)
                .await
                .unwrap();
        }
        l.report(node, &e, "exited", 1).await;
    }
    fixture
}

#[tokio::test]
async fn external_endpoint_sessions_require_live_project_membership() {
    let l = IdentityLab::new().await;
    let viewer = l.login("catalog-viewer").await;
    let membership = l.member(&viewer, "viewer", Some(&l.lab.project)).await;
    let base = format!(
        "/v1/tenants/{}/projects/{}/external-endpoints",
        l.lab.tenant, l.lab.project
    );
    let (status, endpoints) = l.request(&viewer, "GET", &base, None, false).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(endpoints, json!([]));
    let session: Value =
        sqlx::query_scalar("SELECT to_jsonb(s) FROM browser_sessions s WHERE user_id=$1")
            .bind(&viewer.user)
            .fetch_one(&l.lab.store.pool)
            .await
            .unwrap();
    let stale: Principal = serde_json::from_value(json!({"id":viewer.user,"role":"viewer","tenant_id":l.lab.tenant,"project_id":l.lab.project,"membership_id":membership["id"],"session_id":session["id"]})).unwrap();
    sqlx::query("UPDATE workspace_memberships SET revoked=true WHERE id=$1")
        .bind(s(&membership["id"]))
        .execute(&l.lab.store.pool)
        .await
        .unwrap();
    assert_eq!(
        l.lab
            .store
            .resources(
                &stale,
                &l.lab.tenant,
                &l.lab.project,
                "external-endpoints",
                None
            )
            .await
            .unwrap_err()
            .status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        l.request(&viewer, "GET", &base, None, false).await.0,
        StatusCode::NOT_FOUND
    );
    l.finish().await;
}

// Real rollout reconciliation; this is still a worker-protocol fixture, not KVM.
async fn console_diagnostics_fixture(l: &Lab, node: &Value) -> Value {
    let project = l
        .store
        .create_project(
            &l.operator,
            &l.tenant,
            serde_json::from_value(json!({"name":"Diagnostic samples"})).unwrap(),
        )
        .await
        .unwrap();
    let project = s(&project["id"]);
    let artifact = l
        .store
        .upload(&l.operator, &l.tenant, project, b"\0asm\x0d\0\x01\0")
        .await
        .unwrap();
    approve_component(l, node, true, true).await;
    let op=l.store.deploy_app(&l.operator,&l.tenant,project,fenders_control_plane::apps::AppSubmission{value:json!({"name":"startup-timeout","artifact_id":artifact["id"],"triggers":{"http":true,"manual":false}}),key:"startup-timeout",domain:"apps.test"}).await.unwrap();
    let app = s(&op["resource_id"]);
    sqlx::query("UPDATE app_http SET ready_until=now()-interval '1 second' WHERE app_id=$1")
        .bind(app)
        .execute(&l.store.pool)
        .await
        .unwrap();
    l.store.schedule().await.unwrap();
    let value = l
        .store
        .app(&l.operator, &l.tenant, project, app)
        .await
        .unwrap();
    assert_eq!(value["target_release"]["reason"], "http-readiness-timeout");
    let wake=l.store.deploy_app(&l.operator,&l.tenant,project,fenders_control_plane::apps::AppSubmission{value:json!({"name":"wake-timeout","artifact_id":artifact["id"],"configuration":{"keep_warm":false},"triggers":{"http":true,"manual":false}}),key:"wake-timeout",domain:"apps.test"}).await.unwrap();
    let wake = s(&wake["resource_id"]);
    l.store.schedule().await.unwrap();
    let http = l
        .store
        .app_http_status(&l.operator, &l.tenant, project, wake)
        .await
        .unwrap();
    let execution = s(&http["execution_id"]);
    let read = || {
        sqlx::query_scalar::<_, Value>(
            "SELECT to_jsonb(e) FROM executions e WHERE id=$1 AND tenant_id=$2 AND project_id=$3",
        )
        .bind(execution)
        .bind(&l.tenant)
        .bind(project)
        .fetch_one(&l.store.pool)
    };
    let running = read().await.unwrap();
    l.report(node, &running, "running", 1).await;
    sqlx::query("UPDATE app_http SET last_activity=now()-interval '61 seconds' WHERE app_id=$1")
        .bind(wake)
        .execute(&l.store.pool)
        .await
        .unwrap();
    l.store.schedule().await.unwrap();
    let stopped = read().await.unwrap();
    assert_eq!(stopped["desired"], "stopped");
    l.report(node, &stopped, "stopped", 3).await;
    assert_eq!(
        l.store
            .app_http_status(&l.operator, &l.tenant, project, wake)
            .await
            .unwrap()["state"],
        "idle"
    );
    let (_, request) = l
        .store
        .ingress_begin(&format!("app-{wake}.apps.test"), 0, true)
        .await
        .unwrap();
    // Expire an admitted wake; the actual reconciler keeps the ready release.

    sqlx::query("UPDATE app_http SET ready_until=now()-interval '1 second' WHERE app_id=$1")
        .bind(wake)
        .execute(&l.store.pool)
        .await
        .unwrap();
    l.store.schedule().await.unwrap();
    l.store.ingress_finish(&request, Some(0)).await.unwrap();
    let wake_value = l
        .store
        .app(&l.operator, &l.tenant, project, wake)
        .await
        .unwrap();
    assert_eq!(wake_value["target_release"]["state"], "ready");
    assert_eq!(wake_value["http"]["reason"], "http-readiness-timeout");
    json!({"project":project,"artifact":artifact["id"],"app":app,"release":value["target_release"]["id"],"wake":wake,"wakeRelease":wake_value["target_release"]["id"]})
}

pub(super) async fn run_console_browser(script: &'static str, fixture: Value) -> bool {
    use std::{
        io::Write,
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    tokio::task::spawn_blocking(move || {
        let mut command = Command::new("node");
        command
            .arg(script)
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .stdin(Stdio::piped());
        if let Some(path) = fixture["trustedCaFile"].as_str() {
            command.env("NODE_EXTRA_CA_CERTS", path);
        }
        let mut child = command
            .spawn()
            .expect("install Node and local Playwright first");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(fixture.to_string().as_bytes())
            .unwrap();
        let start = Instant::now();
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status.success();
            }
            if start.elapsed()
                > Duration::from_secs(
                    if script == "tests/verify_m2_https_live.cjs"
                        && std::env::var("FENDERS_M2_LOCAL_RETENTION").as_deref() == Ok("1")
                    {
                        // Observe three ordinary 60-second worker retention passes.
                        360
                    } else if matches!(
                        script,
                        "tests/verify_m1_live.cjs" | "tests/verify_m2_triggers_live.cjs"
                    ) {
                        600
                    } else {
                        180
                    },
                )
            {
                child.kill().unwrap();
                child.wait().unwrap();
                break false;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    })
    .await
    .unwrap()
}
