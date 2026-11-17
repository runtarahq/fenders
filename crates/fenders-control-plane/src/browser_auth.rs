//! Authorization-code + PKCE login. Protocol verification comes from the pinned
//! OpenID Connect library; Fenders owns browser binding, sessions and scope.
pub(crate) mod logout;
pub mod tailscale;
use crate::{
    args,
    db::*,
    error::{Error, Result},
    model::digest,
    store::{Store, token},
};
use axum::{
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use openidconnect::{
    AccessTokenHash, AuthorizationCode, ClaimsVerificationError, ClientId, ClientSecret, CsrfToken,
    HttpRequest, HttpResponse, IssuerUrl, Nonce, OAuth2TokenResponse, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, RequestTokenError, Scope, SignatureVerificationError,
    TokenResponse,
    core::{
        CoreAuthenticationFlow, CoreClient, CoreErrorResponseType, CoreJwsSigningAlgorithm,
        CoreProviderMetadata,
    },
};
use serde::Deserialize;
use serde_json::json;
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};
use url::Url;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserAuthConfig {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub console_origin: String,
    #[serde(default)]
    pub endpoint_origins: Vec<String>,
    /// Optional operator-supplied PEM CA bundle for this provider's HTTPS client.
    /// Public Web PKI roots remain enabled. Never shared with workload clients.
    #[serde(default)]
    pub provider_ca_pem: Option<String>,
    /// Provider-owned browser logout URL, including its fixed return URL/client.
    /// Never derived from request parameters. Must use an allowed provider origin.
    #[serde(default)]
    pub provider_logout_url: Option<String>,
}
/// How long the provider's metadata and keys are used before they are
/// fetched again, and how soon they may be fetched again for a key that is
/// not among them.
const METADATA_FRESH: std::time::Duration = std::time::Duration::from_secs(300);
const METADATA_REFRESH: std::time::Duration = std::time::Duration::from_secs(10);

struct Discovered {
    /// When it was fetched, and when it was last fetched for a key not held.
    fetched: std::time::Instant,
    refreshed: Option<std::time::Instant>,
    metadata: CoreProviderMetadata,
}

pub struct BrowserAuth {
    /// Development sign-in from Tailscale Serve, in place of the provider.
    tailscale: Option<tailscale::TailscaleIdentityConfig>,
    config: BrowserAuthConfig,
    http: reqwest::Client,
    allowed: Vec<String>,
    origin: String,
    dev: bool,
    /// The provider's metadata and keys as last fetched.
    discovered: tokio::sync::Mutex<Option<Discovered>>,
}
impl<'a> openidconnect::AsyncHttpClient<'a> for BrowserAuth {
    type Error = Error;
    type Future =
        std::pin::Pin<Box<dyn std::future::Future<Output = Result<HttpResponse>> + Send + 'a>>;
    fn call(&'a self, request: HttpRequest) -> Self::Future {
        Box::pin(self.http(request))
    }
}
impl BrowserAuth {
    pub fn new(config: BrowserAuthConfig, dev: bool) -> Result<Self> {
        if config.client_id.is_empty()
            || config.client_id.len() > 512
            || config
                .client_secret
                .as_ref()
                .is_some_and(|v| v.is_empty() || v.len() > 4096)
            || config.endpoint_origins.len() > 8
        {
            return Err(Error::invalid(
                "invalid browser authentication configuration",
            ));
        }
        let issuer = secure_url(&config.issuer, dev)?;
        let console = secure_url(&config.console_origin, dev)?;
        if console.path() != "/" {
            return Err(Error::invalid("console URL must be an origin"));
        }
        let origin = console.origin().ascii_serialization();
        let mut allowed = vec![issuer.origin().ascii_serialization()];
        for value in &config.endpoint_origins {
            let url = secure_url(value, dev)?;
            if url.path() != "/" {
                return Err(Error::invalid(
                    "provider endpoint allowlist requires origins",
                ));
            }
            allowed.push(url.origin().ascii_serialization());
        }
        if let Some(value) = &config.provider_logout_url {
            let mut endpoint =
                Url::parse(value).map_err(|_| Error::invalid("invalid provider logout URL"))?;
            endpoint.set_query(None);
            secure_url(endpoint.as_str(), dev)?;
            if value.len() > 4096 || !allowed.contains(&endpoint.origin().ascii_serialization()) {
                return Err(Error::invalid(
                    "provider logout URL must use an allowed provider origin",
                ));
            }
        }
        let mut http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(10));
        if let Some(pem) = &config.provider_ca_pem {
            for certificate in provider_certificates(pem)? {
                http = http.add_root_certificate(certificate);
            }
        }
        let http = http.build().map_err(|_| Error::internal())?;
        Ok(Self {
            tailscale: None,
            config,
            http,
            allowed,
            origin,
            dev,
            discovered: Default::default(),
        })
    }
    fn context(&self) -> String {
        digest(serde_json::to_vec(&json!({"issuer":self.config.issuer,"client_id":self.config.client_id,"origin":self.origin})).unwrap())
    }
    pub(crate) fn session_cookie(&self) -> &'static str {
        if self.dev {
            "fenders_dev_session"
        } else {
            "__Host-fenders_session"
        }
    }
    fn login_cookie(&self) -> &'static str {
        if self.dev {
            "fenders_dev_login"
        } else {
            "__Host-fenders_login"
        }
    }
    fn cookie(&self, name: &str, value: &str, age: u32) -> String {
        format!(
            "{name}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={age}{}",
            if self.dev { "" } else { "; Secure" }
        )
    }
    pub(crate) fn same_origin(&self, headers: &HeaderMap) -> Result<()> {
        if headers.get_all(header::ORIGIN).iter().count() != 1
            || headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) != Some(&self.origin)
        {
            return Err(Error::new(
                StatusCode::FORBIDDEN,
                "same-origin request required",
            ));
        }
        Ok(())
    }
    fn allowed(&self, url: &Url) -> Result<()> {
        secure_url(url.as_str(), self.dev)?;
        if !self.allowed.contains(&url.origin().ascii_serialization()) {
            return Err(Error::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "identity provider endpoint is not allowed",
            ));
        }
        Ok(())
    }
    async fn http(&self, request: HttpRequest) -> Result<HttpResponse> {
        let url = Url::parse(&request.uri().to_string()).map_err(|_| Error::internal())?;
        self.allowed(&url)?;
        let (parts, body) = request.into_parts();
        let mut response = self
            .http
            .request(parts.method, url)
            .headers(parts.headers)
            .body(body)
            .send()
            .await
            .map_err(|_| provider_error())?;
        if response.content_length().is_some_and(|n| n > 262144) {
            return Err(provider_error());
        }
        let status = response.status();
        let headers = response.headers().clone();
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| provider_error())? {
            if body.len() + chunk.len() > 262144 {
                return Err(provider_error());
            }
            body.extend_from_slice(&chunk);
        }
        let mut result = HttpResponse::new(body);
        *result.status_mut() = status;
        *result.headers_mut() = headers;
        Ok(result)
    }
    /// The provider's metadata and signing keys, fetched at most every five
    /// minutes. Every sign-in, callback and logout notice needs them, and
    /// anyone may start a sign-in or post a notice: fetched each time, those
    /// became two requests to the provider apiece, from this host.
    async fn metadata(&self) -> Result<CoreProviderMetadata> {
        self.discover(false).await
    }
    /// [`metadata`](Self::metadata) for a token signed with a key that is
    /// not among those held: the provider may have changed its keys since.
    /// Fetched again, though not more than once in ten seconds, whoever
    /// asks: a made-up key id buys no more requests than that.
    async fn metadata_refreshed(&self) -> Result<CoreProviderMetadata> {
        self.discover(true).await
    }
    async fn discover(&self, refresh: bool) -> Result<CoreProviderMetadata> {
        // Held across the fetch: those who arrive meanwhile wait for its
        // answer rather than each asking the provider.
        let mut discovered = self.discovered.lock().await;
        if let Some(held) = &*discovered {
            let usable = if refresh {
                // Fetched again for a key not held, unless it just was.
                held.refreshed
                    .is_some_and(|at| at.elapsed() < METADATA_REFRESH)
            } else {
                held.fetched.elapsed() < METADATA_FRESH
            };
            if usable {
                return Ok(held.metadata.clone());
            }
        }
        let metadata = self.fetch_metadata().await?;
        let now = std::time::Instant::now();
        *discovered = Some(Discovered {
            fetched: now,
            refreshed: refresh.then_some(now),
            metadata: metadata.clone(),
        });
        Ok(metadata)
    }
    /// Forgets the provider's metadata, so that the next use fetches it.
    /// Public for tests, which change what their provider serves.
    #[doc(hidden)]
    pub async fn forget_provider_metadata(&self) {
        *self.discovered.lock().await = None;
    }
    async fn fetch_metadata(&self) -> Result<CoreProviderMetadata> {
        let metadata = CoreProviderMetadata::discover_async(
            IssuerUrl::new(self.config.issuer.clone())
                .map_err(|_| Error::invalid("invalid issuer"))?,
            self,
        )
        .await
        .map_err(|_| provider_error())?;
        self.allowed(metadata.authorization_endpoint().url())?;
        self.allowed(metadata.token_endpoint().ok_or_else(provider_error)?.url())?;
        Ok(metadata)
    }
    async fn login(
        &self,
        store: &Store,
        headers: &HeaderMap,
        force_login: bool,
    ) -> Result<Response> {
        let client = CoreClient::from_provider_metadata(
            self.metadata().await?,
            ClientId::new(self.config.client_id.clone()),
            self.config.client_secret.clone().map(ClientSecret::new),
        )
        .set_redirect_uri(
            RedirectUrl::new(format!("{}/auth/callback", self.origin))
                .map_err(|_| Error::internal())?,
        );
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let request = client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .add_scope(Scope::new("email".into()))
            .add_scope(Scope::new("profile".into()))
            .set_pkce_challenge(challenge);
        let request = if force_login {
            request.add_extra_param("prompt", "login")
        } else {
            request
        };
        let (url, state, nonce) = request.url();
        let browser = token("fnd_login_")?;
        let old = cookie_value(headers, self.login_cookie())?;
        let mut tx = store.transaction(true, false).await?;
        exec(
            &mut tx,
            "DELETE FROM browser_logins WHERE expires<=now() OR browser_hash=$1",
            args![old.as_ref().map(digest)],
        )
        .await?;
        if n(&one(&mut tx, "SELECT count(*) AS n FROM browser_logins", args![]).await?["n"])
            >= 10000
        {
            return Err(Error::new(
                StatusCode::TOO_MANY_REQUESTS,
                "login capacity exhausted",
            ));
        }
        exec(&mut tx,"INSERT INTO browser_logins(state_hash,browser_hash,context_hash,nonce_encrypted,pkce_encrypted) VALUES($1,$2,$3,$4,$5)",args![digest(state.secret()),digest(&browser),self.context(),store.cipher.encrypt(nonce.secret().as_bytes()),store.cipher.encrypt(verifier.secret().as_bytes())]).await?;
        tx.commit().await?;
        redirect(
            url.as_str(),
            &[self.cookie(self.login_cookie(), &browser, 300)],
        )
    }
    async fn callback(&self, store: &Store, headers: &HeaderMap, query: &str) -> Result<Response> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Callback {
            code: String,
            state: String,
            #[serde(default)]
            iss: Option<String>,
            #[serde(default)]
            session_state: Option<String>,
        }
        let callback: Callback = serde_url(query).inspect_err(|_| {
            eprintln!("browser_auth callback rejected: callback_parameters");
        })?;
        if callback.code.is_empty()
            || callback.code.len() > 4096
            || callback.state.len() > 256
            || callback
                .iss
                .as_ref()
                .is_some_and(|v| v != &self.config.issuer)
            || callback
                .session_state
                .as_ref()
                .is_some_and(|s| s.len() > 1024)
        {
            return Err(login_failure("callback_binding"));
        }
        let browser = cookie_value(headers, self.login_cookie())?
            .ok_or_else(|| login_failure("login_cookie_missing"))?;
        let mut tx = store.transaction(true, false).await?;
        let pending=optional(&mut tx,"DELETE FROM browser_logins WHERE state_hash=$1 AND browser_hash=$2 AND context_hash=$3 AND expires>now() RETURNING *",args![digest(&callback.state),digest(&browser),self.context()]).await?.ok_or_else(|| login_failure("login_state_missing_or_expired"))?;
        tx.commit().await?; // Single use before the external token exchange.
        let decrypt = |key: &str| -> Result<String> {
            String::from_utf8(
                store
                    .cipher
                    .decrypt(s(&pending[key]))
                    .map_err(|_| Error::internal())?,
            )
            .map_err(|_| Error::internal())
        };
        let client = CoreClient::from_provider_metadata(
            self.metadata().await?,
            ClientId::new(self.config.client_id.clone()),
            self.config.client_secret.clone().map(ClientSecret::new),
        )
        .set_redirect_uri(
            RedirectUrl::new(format!("{}/auth/callback", self.origin))
                .map_err(|_| Error::internal())?,
        );
        let response = client
            .exchange_code(AuthorizationCode::new(callback.code))
            .map_err(|_| provider_error())?
            .set_pkce_verifier(PkceCodeVerifier::new(decrypt("pkce_encrypted")?))
            .request_async(self)
            .await
            .map_err(|error| {
                // Never log the error itself: parse errors retain the entire token
                // response. Fixed categories distinguish provider rejection from
                // transport and response decoding failures without exposing tokens.
                login_failure(match &error {
                    RequestTokenError::ServerResponse(response) => match response.error() {
                        CoreErrorResponseType::InvalidClient => "token_exchange_invalid_client",
                        CoreErrorResponseType::InvalidGrant => "token_exchange_invalid_grant",
                        _ => "token_exchange_provider_rejection",
                    },
                    RequestTokenError::Request(_) => "token_exchange_transport",
                    RequestTokenError::Parse(error, _) => match error.path().to_string().as_str() {
                        "id_token" => "token_response_id_token_parse",
                        "expires_in" => "token_response_expiry_parse",
                        "token_type" => "token_response_type_parse",
                        _ => "token_response_parse",
                    },
                    RequestTokenError::Other(_) => "token_exchange_response",
                })
            })?;
        let id = response
            .id_token()
            .ok_or_else(|| login_failure("id_token_missing"))?;
        let algorithms = [
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
            CoreJwsSigningAlgorithm::EcdsaP256Sha256,
            CoreJwsSigningAlgorithm::EdDsa,
        ];
        let refreshed_client;
        let mut verifier = client
            .id_token_verifier()
            .set_allowed_algs(algorithms.clone());
        let nonce = Nonce::new(decrypt("nonce_encrypted")?);
        let mut claims = id.claims(&verifier, &nonce);
        if matches!(
            &claims,
            Err(ClaimsVerificationError::SignatureVerification(
                SignatureVerificationError::NoMatchingKey
            ))
        ) {
            // A key can rotate after discovery but before the single token
            // exchange above. Refresh trusted metadata/JWKS once, then verify
            // the same response fully. Never exchange the code a second time.
            refreshed_client = CoreClient::from_provider_metadata(
                self.metadata_refreshed().await?,
                ClientId::new(self.config.client_id.clone()),
                self.config.client_secret.clone().map(ClientSecret::new),
            );
            verifier = refreshed_client
                .id_token_verifier()
                .set_allowed_algs(algorithms);
            claims = id.claims(&verifier, &nonce);
        }
        let claims = claims.map_err(|error| {
            // Log fixed categories only: library error strings can contain
            // token claims or nonces and must never enter service logs.
            login_failure(match error {
                ClaimsVerificationError::Expired(_) => "id_token_expired",
                ClaimsVerificationError::InvalidAudience(_) => "id_token_audience",
                ClaimsVerificationError::InvalidIssuer(_) => "id_token_issuer",
                ClaimsVerificationError::InvalidNonce(_) => "id_token_nonce",
                ClaimsVerificationError::SignatureVerification(_) => "id_token_signature",
                _ => "id_token_verification",
            })
        })?;
        let now: chrono::DateTime<chrono::Utc> = SystemTime::now().into();
        if claims.audiences().len() != 1
            || claims
                .authorized_party()
                .is_some_and(|p| p.as_str() != self.config.client_id)
            || claims.issue_time() > now + chrono::Duration::seconds(60)
            || claims.issue_time() < now - chrono::Duration::minutes(5)
        {
            return Err(login_failure("id_token_binding_or_issue_time"));
        }
        if let Some(expected) = claims.access_token_hash() {
            let actual = AccessTokenHash::from_token(
                response.access_token(),
                id.signing_alg().map_err(|_| Error::unauthorized())?,
                id.signing_key(&verifier)
                    .map_err(|_| Error::unauthorized())?,
            )
            .map_err(|_| Error::unauthorized())?;
            if actual != *expected {
                return Err(login_failure("access_token_hash"));
            }
        }
        let old = cookie_value(headers, self.session_cookie())?;
        let binding = logout::login_binding(
            &id.to_string(),
            &self.config.client_id,
            claims.issue_time().timestamp(),
        )
        .inspect_err(|_| {
            eprintln!("browser_auth callback rejected: logout_binding");
        })?;
        let session = store
            .verified_session(
                &self.config.issuer,
                claims.subject().as_str(),
                &binding,
                old.as_deref(),
                crate::customer_onboarding::VerifiedProfile {
                    email: claims
                        .email()
                        .and_then(|v| crate::customer_onboarding::canonical_email(v.as_str())),
                    email_verified: claims.email_verified() == Some(true),
                    display_name: claims
                        .name()
                        .and_then(|v| v.get(None))
                        .map(|v| v.as_str().to_owned()),
                },
            )
            .await
            .inspect_err(|_| {
                eprintln!("browser_auth callback rejected: session_creation");
            })?;
        redirect(
            "/console/",
            &[
                self.cookie(self.session_cookie(), &session.token, 28800),
                self.cookie(self.login_cookie(), "", 0),
            ],
        )
    }
    pub(crate) async fn handle(
        &self,
        store: &Store,
        method: &str,
        path: &str,
        query: &str,
        headers: &HeaderMap,
    ) -> Result<Response> {
        // Apart: anyone can start sign-ins, and those must not take the
        // places of the callbacks that finish the ones already under way.
        static LOGINS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(32);
        static CALLBACKS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(32);
        let _permit = if matches!(path, "/auth/login" | "/auth/callback") {
            let places = if path == "/auth/login" {
                &LOGINS
            } else {
                &CALLBACKS
            };
            Some(places.try_acquire().map_err(|_| {
                Error::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "sign-in capacity exhausted",
                )
            })?)
        } else {
            None
        };
        match (method, path) {
            ("GET", "/auth/login") if self.tailscale.is_some() => {
                self.tailscale_login(store, self.tailscale.as_ref().unwrap(), headers)
                    .await
            }
            ("GET", "/auth/login") => {
                self.login(
                    store,
                    headers,
                    url::form_urlencoded::parse(query.as_bytes())
                        .any(|(k, v)| k == "prompt" && v == "login"),
                )
                .await
            }
            ("GET", "/auth/callback") if self.tailscale.is_some() => Err(Error::missing()),
            ("GET", "/auth/callback") => self.callback(store, headers, query).await,
            ("GET", "/auth/session") => {
                let secret = cookie_value(headers, self.session_cookie())?
                    .ok_or_else(Error::unauthorized)?;
                let session = store.browser_session(&secret, None).await?;
                Ok(private_response(
                    axum::Json(store.session_info(&session).await?).into_response(),
                ))
            }
            ("POST", "/auth/logout") => {
                self.same_origin(headers)?;
                let csrf = headers
                    .get("X-CSRF-Token")
                    .and_then(|v| v.to_str().ok())
                    .filter(|v| !v.is_empty() && v.len() <= 256)
                    .ok_or_else(|| Error::new(StatusCode::FORBIDDEN, "CSRF token required"))?;
                if let Some(secret) = cookie_value(headers, self.session_cookie())? {
                    match store.browser_session(&secret, Some(csrf)).await {
                        Ok(_) => store.end_browser_session(&secret).await?,
                        // The first reply may have been lost after deleting the
                        // session. Same-origin retries recover only the fixed
                        // provider destination and clear cookies again; they
                        // grant no access and do not mutate another session.
                        Err(error) if error.status == StatusCode::UNAUTHORIZED => {}
                        Err(error) => return Err(error),
                    }
                }
                let mut response = match &self.config.provider_logout_url {
                    Some(url) => axum::Json(json!({"logout_url":url})).into_response(),
                    None => StatusCode::NO_CONTENT.into_response(),
                };
                response.headers_mut().insert(
                    header::SET_COOKIE,
                    self.cookie(self.session_cookie(), "", 0)
                        .parse()
                        .map_err(|_| Error::internal())?,
                );
                response.headers_mut().append(
                    header::SET_COOKIE,
                    self.cookie(self.login_cookie(), "", 0)
                        .parse()
                        .map_err(|_| Error::internal())?,
                );
                Ok(private_response(response))
            }
            ("POST", "/auth/onboarding") => {
                self.same_origin(headers)?;
                let secret = cookie_value(headers, self.session_cookie())?
                    .ok_or_else(Error::unauthorized)?;
                let csrf = headers
                    .get("X-CSRF-Token")
                    .and_then(|v| v.to_str().ok())
                    .ok_or_else(|| Error::new(StatusCode::FORBIDDEN, "CSRF token required"))?;
                let session = store.browser_session(&secret, Some(csrf)).await?;
                store.complete_onboarding(&session).await?;
                Ok(private_response(
                    axum::Json(store.session_info(&session).await?).into_response(),
                ))
            }
            ("POST", "/auth/verification-email") => {
                self.same_origin(headers)?;
                let secret = cookie_value(headers, self.session_cookie())?
                    .ok_or_else(Error::unauthorized)?;
                let csrf = headers
                    .get("X-CSRF-Token")
                    .and_then(|v| v.to_str().ok())
                    .ok_or_else(|| Error::new(StatusCode::FORBIDDEN, "CSRF token required"))?;
                let session = store.browser_session(&secret, Some(csrf)).await?;
                if session["issuer"] != self.config.issuer {
                    return Err(Error::unauthorized());
                }
                store
                    .resend_verification_email(&session, &self.config.client_id)
                    .await?;
                Ok(private_response(StatusCode::NO_CONTENT.into_response()))
            }
            _ => Err(Error::missing()),
        }
    }
}

fn login_failure(stage: &'static str) -> Error {
    eprintln!("browser_auth callback rejected: {stage}");
    Error::unauthorized()
}

fn provider_certificates(pem: &str) -> Result<Vec<reqwest::Certificate>> {
    let invalid = || Error::invalid("invalid identity provider CA bundle");
    if pem.is_empty() || pem.len() > 65536 {
        return Err(invalid());
    }
    let mut roots = rustls::RootCertStore::empty();
    let mut certificates = Vec::new();
    let mut remaining = pem.trim();
    while !remaining.is_empty() {
        if certificates.len() == 8 || !remaining.starts_with("-----BEGIN CERTIFICATE-----") {
            return Err(invalid());
        }
        let end = remaining
            .find("-----END CERTIFICATE-----")
            .ok_or_else(invalid)?
            + "-----END CERTIFICATE-----".len();
        let block = &remaining[..end];
        let Some(rustls_pemfile::Item::X509Certificate(der)) =
            rustls_pemfile::read_one(&mut block.as_bytes()).map_err(|_| invalid())?
        else {
            return Err(invalid());
        };
        roots.add(der.clone()).map_err(|_| invalid())?;
        certificates.push(reqwest::Certificate::from_der(&der).map_err(|_| invalid())?);
        remaining = remaining[end..].trim();
    }
    if certificates.is_empty() {
        return Err(invalid());
    }
    Ok(certificates)
}
impl Store {
    pub fn with_browser_auth(mut self, config: BrowserAuthConfig, dev: bool) -> Result<Self> {
        self.browser_auth = Some(Arc::new(BrowserAuth::new(config, dev)?));
        Ok(self)
    }
}
fn secure_url(value: &str, dev: bool) -> Result<Url> {
    let url = Url::parse(value).map_err(|_| Error::invalid("invalid authentication URL"))?;
    let loopback = url.host().is_some_and(|h| match h {
        url::Host::Domain(name) => name == "localhost",
        url::Host::Ipv4(ip) => ip.is_loopback(),
        url::Host::Ipv6(ip) => ip.is_loopback(),
    });
    if value.len() > 2048
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !(url.scheme() == "https" || dev && url.scheme() == "http" && loopback)
    {
        return Err(Error::invalid(
            "authentication URLs require HTTPS; development HTTP requires loopback",
        ));
    }
    Ok(url)
}
pub(crate) fn cookie_value(headers: &HeaderMap, name: &str) -> Result<Option<String>> {
    let mut found = None;
    for header in headers.get_all(header::COOKIE) {
        let header = header.to_str().map_err(|_| Error::unauthorized())?;
        if header.len() > 8192 {
            return Err(Error::unauthorized());
        }
        for cookie in header.split(';') {
            if let Some((key, value)) = cookie.trim().split_once('=')
                && key == name
            {
                if found.is_some()
                    || value.len() > 256
                    || !value
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
                {
                    return Err(Error::unauthorized());
                }
                found = Some(value.to_owned());
            }
        }
    }
    Ok(found)
}
pub(crate) fn private_response(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    response
        .headers_mut()
        .insert(header::PRAGMA, "no-cache".parse().unwrap());
    response
        .headers_mut()
        .insert(header::REFERRER_POLICY, "no-referrer".parse().unwrap());
    response
}
fn redirect(location: &str, cookies: &[String]) -> Result<Response> {
    let mut response = StatusCode::SEE_OTHER.into_response();
    response.headers_mut().insert(
        header::LOCATION,
        location.parse().map_err(|_| Error::internal())?,
    );
    for cookie in cookies {
        response.headers_mut().append(
            header::SET_COOKIE,
            cookie.parse().map_err(|_| Error::internal())?,
        );
    }
    Ok(private_response(response))
}
fn provider_error() -> Error {
    Error::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "identity provider unavailable",
    )
}
fn serde_url<T: serde::de::DeserializeOwned>(query: &str) -> Result<T> {
    let uri = format!("/?{query}")
        .parse::<axum::http::Uri>()
        .map_err(|_| Error::unauthorized())?;
    axum::extract::Query::<T>::try_from_uri(&uri)
        .map(|q| q.0)
        .map_err(|_| Error::unauthorized())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    #[test]
    fn browser_configuration_cookie_and_origin_boundaries() {
        let config = BrowserAuthConfig {
            issuer: "https://identity.example".into(),
            client_id: "fenders".into(),
            client_secret: None,
            console_origin: "https://console.example".into(),
            endpoint_origins: vec![],
            provider_ca_pem: None,
            provider_logout_url: None,
        };
        let auth = BrowserAuth::new(config.clone(), false).unwrap();
        for value in [
            "https://other.example/logout",
            "http://identity.example/logout",
            "https://user:password@identity.example/logout",
            "https://identity.example/logout#fragment",
        ] {
            let mut invalid = config.clone();
            invalid.provider_logout_url = Some(value.into());
            assert!(BrowserAuth::new(invalid, false).is_err());
        }
        let mut configured = config;
        configured.provider_logout_url = Some("https://identity.example/v2/logout?client_id=fenders&returnTo=https%3A%2F%2Fconsole.example%2Fconsole%2F%3Fsignin%3Dsigned-out".into());
        assert!(BrowserAuth::new(configured, false).is_ok());
        let cookie = auth.cookie(auth.session_cookie(), "opaque", 28800);
        assert_eq!(
            cookie,
            "__Host-fenders_session=opaque; Path=/; HttpOnly; SameSite=Lax; Max-Age=28800; Secure"
        );
        for url in [
            "http://identity.example",
            "https://user:pass@identity.example",
            "https://identity.example/#fragment",
            "https://identity.example/?key=value",
        ] {
            assert!(secure_url(url, false).is_err());
        }
        assert!(secure_url("http://[::1]:19091", true).is_ok());
        assert!(secure_url("http://192.168.1.1", true).is_err());
        assert!(
            auth.allowed(&Url::parse("https://unconfigured.example/token").unwrap())
                .is_err()
        );
        let mut headers = HeaderMap::new();
        headers.insert(header::ORIGIN, "https://console.example".parse().unwrap());
        assert!(auth.same_origin(&headers).is_ok());
        headers.append(header::ORIGIN, "https://console.example".parse().unwrap());
        assert!(auth.same_origin(&headers).is_err());
    }

    #[test]
    fn provider_ca_bundle_is_bounded_certificate_only_and_optional() {
        let root = tempfile::tempdir().unwrap();
        crate::pki::create(root.path(), &Default::default()).unwrap();
        let pem = std::fs::read_to_string(root.path().join("ca.pem")).unwrap();
        let key = std::fs::read_to_string(root.path().join("ca.key")).unwrap();
        assert_eq!(provider_certificates(&pem).unwrap().len(), 1);
        assert_eq!(provider_certificates(&pem.repeat(8)).unwrap().len(), 8);
        for invalid in [
            String::new(),
            "garbage".into(),
            "x".repeat(65537),
            pem.repeat(9),
            key.clone(),
            format!("{pem}{key}"),
            format!("garbage\n{pem}"),
            format!("{pem}garbage"),
            format!(
                "{pem}-----BEGIN ENCRYPTED PRIVATE KEY-----\nAA==\n-----END ENCRYPTED PRIVATE KEY-----\n"
            ),
            "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n".into(),
        ] {
            let error = provider_certificates(&invalid).expect_err("invalid CA accepted");
            assert_eq!(error.status, StatusCode::BAD_REQUEST);
            assert_eq!(error.message, "invalid identity provider CA bundle");
        }
        let config: BrowserAuthConfig = serde_json::from_value(json!({
            "issuer":"https://identity.example", "client_id":"fenders",
            "console_origin":"https://console.example"
        }))
        .unwrap();
        assert!(config.provider_ca_pem.is_none());
        assert!(BrowserAuth::new(config, false).is_ok());
    }

    #[tokio::test]
    async fn provider_tls_requires_trust_name_and_validity_without_bypasses() {
        let root = tempfile::tempdir().unwrap();
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        let ca = ca.self_signed(&ca_key).unwrap();
        let other = tempfile::tempdir().unwrap();
        crate::pki::create(other.path(), &Default::default()).unwrap();
        let wrong_ca = std::fs::read_to_string(other.path().join("ca.pem")).unwrap();
        for (name, host, expired) in [
            ("valid", "127.0.0.1", false),
            ("wrong-name", "wrong.example", false),
            ("expired", "127.0.0.1", true),
        ] {
            let key = rcgen::KeyPair::generate().unwrap();
            let mut cert = rcgen::CertificateParams::new(vec![host.into()]).unwrap();
            cert.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
            if expired {
                cert.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(2);
                cert.not_after = time::OffsetDateTime::now_utc() - time::Duration::days(1);
            }
            let cert = cert.signed_by(&key, &ca, &ca_key).unwrap();
            let certificate = root.path().join(format!("{name}.pem"));
            let private_key = root.path().join(format!("{name}.key"));
            std::fs::write(&certificate, cert.pem()).unwrap();
            crate::pki::private_file(&private_key, key.serialize_pem().as_bytes()).unwrap();
            let config = crate::transport::server_config(&certificate, &private_key, None).unwrap();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let origin = format!("https://{}", listener.local_addr().unwrap());
            let hits = Arc::new(AtomicUsize::new(0));
            let count = hits.clone();
            let router = axum::Router::new().route(
                "/",
                axum::routing::get(move || {
                    count.fetch_add(1, Ordering::SeqCst);
                    async { "provider reached" }
                }),
            );
            let server = tokio::spawn(crate::transport::serve_tls(listener, config, router));
            for pem in [None, Some(wrong_ca.clone()), Some(ca.pem())] {
                let trusted = pem.as_deref() == Some(ca.pem().as_str());
                let auth = BrowserAuth::new(
                    BrowserAuthConfig {
                        issuer: origin.clone(),
                        client_id: "fenders".into(),
                        client_secret: None,
                        console_origin: "https://console.example".into(),
                        endpoint_origins: vec![],
                        provider_ca_pem: pem,
                        provider_logout_url: None,
                    },
                    false,
                )
                .unwrap();
                let request = axum::http::Request::builder()
                    .uri(&origin)
                    .body(Vec::new())
                    .unwrap();
                let response = auth.http(request).await;
                if name == "valid" && trusted {
                    assert_eq!(response.unwrap().status(), StatusCode::OK);
                } else {
                    let error = response.expect_err("untrusted TLS request succeeded");
                    assert_eq!(error.status, StatusCode::SERVICE_UNAVAILABLE);
                    assert_eq!(error.message, "identity provider unavailable");
                }
                let outside = axum::http::Request::builder()
                    .uri("https://not-allowed.example/")
                    .body(Vec::new())
                    .unwrap();
                assert_eq!(
                    auth.http(outside).await.unwrap_err().message,
                    "identity provider endpoint is not allowed"
                );
            }
            assert_eq!(hits.load(Ordering::SeqCst), usize::from(name == "valid"));
            server.abort();
        }
    }
}
