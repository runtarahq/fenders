//! Provider-authenticated logout, independent of browser cookies and CSRF.
//! JSON framing/claims are local; signature primitives and JWK compatibility
//! come from the same pinned OpenID Connect library as interactive sign-in.
use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use openidconnect::{JsonWebKey, JsonWebKeyAlgorithm, JsonWebKeyUse, JwsSigningAlgorithm};
use serde_json::Value;
use std::collections::BTreeMap;

const EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";
const TOKEN_LIMIT: usize = 12_288;

fn invalid() -> Error {
    Error::invalid("invalid logout request")
}
fn opaque(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}
fn optional_string<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<String>, D::Error> {
    String::deserialize(d).map(Some)
}
fn payload(token: &str) -> Result<Vec<u8>> {
    if token.len() > TOKEN_LIMIT || token.split('.').count() != 3 {
        return Err(invalid());
    }
    URL_SAFE_NO_PAD
        .decode(token.split('.').nth(1).ok_or_else(invalid)?)
        .map_err(|_| invalid())
}

pub(crate) struct LoginBinding {
    pub client_id: String,
    pub sid: Option<String>,
    pub issued: i64,
}
/// Only called after full ID-token verification. Reject logout-token confusion
/// even if a provider accidentally emits both a nonce and logout event claims.
pub(super) fn login_binding(token: &str, client: &str, issued: i64) -> Result<LoginBinding> {
    #[derive(Deserialize)]
    struct Extra {
        #[serde(default, deserialize_with = "optional_string")]
        sid: Option<String>,
        #[serde(flatten)]
        other: BTreeMap<String, Value>,
    }
    let claims: Extra =
        serde_json::from_slice(&payload(token)?).map_err(|_| Error::unauthorized())?;
    if claims.other.contains_key("events") || claims.sid.as_ref().is_some_and(|s| !opaque(s, 1024))
    {
        return Err(Error::unauthorized());
    }
    Ok(LoginBinding {
        client_id: client.into(),
        sid: claims.sid,
        issued,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    alg: CoreJwsSigningAlgorithm,
    kid: Option<String>,
    typ: Option<String>,
}
#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}
impl Audience {
    fn matches(&self, client: &str) -> bool {
        match self {
            Self::One(v) => v == client,
            Self::Many(v) => v.len() == 1 && v[0] == client,
        }
    }
}
#[derive(Deserialize)]
struct Claims {
    iss: String,
    aud: Audience,
    iat: i64,
    exp: i64,
    jti: String,
    #[serde(default, deserialize_with = "optional_string")]
    sub: Option<String>,
    #[serde(default, deserialize_with = "optional_string")]
    sid: Option<String>,
    events: BTreeMap<String, Value>,
    #[serde(flatten)]
    other: BTreeMap<String, Value>,
}
impl Claims {
    fn valid_time(&self) -> bool {
        let now: chrono::DateTime<chrono::Utc> = SystemTime::now().into();
        let now = now.timestamp();
        self.iat >= now - 300
            && self.iat <= now + 30
            && self.exp > now
            && self.exp > self.iat
            && self.exp <= self.iat.saturating_add(600)
    }
}
impl BrowserAuth {
    pub(crate) async fn backchannel_logout(
        &self,
        store: &Store,
        headers: &HeaderMap,
        bytes: &[u8],
    ) -> Result<Response> {
        static LOGOUTS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(8);
        let _permit = LOGOUTS.try_acquire().map_err(|_| {
            Error::new(StatusCode::SERVICE_UNAVAILABLE, "logout capacity exhausted")
        })?;
        if bytes.len() > 16_384
            || headers
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .is_none_or(|v| {
                    v.split(';').next().unwrap_or("").trim() != "application/x-www-form-urlencoded"
                })
        {
            return Err(invalid());
        }
        #[derive(Deserialize)]
        struct Form {
            logout_token: String,
        }
        // Unknown form fields are allowed by the protocol; duplicate tokens are not.
        let form: Form =
            serde_url(std::str::from_utf8(bytes).map_err(|_| invalid())?).map_err(|_| invalid())?;
        let token = form.logout_token;
        let decoded = payload(&token)?;
        let claims: Claims = serde_json::from_slice(&decoded).map_err(|_| invalid())?;
        if claims.iss != self.config.issuer
            || !claims.aud.matches(&self.config.client_id)
            || !claims.valid_time()
            || !opaque(&claims.jti, 256)
            || claims.sub.as_ref().is_some_and(|s| !opaque(s, 255))
            || claims.sid.as_ref().is_some_and(|s| !opaque(s, 1024))
            || claims.sub.is_none() && claims.sid.is_none()
            || claims.other.contains_key("nonce")
            || !claims.events.get(EVENT).is_some_and(Value::is_object)
        {
            return Err(invalid());
        }
        let mut segments = token.split('.');
        let head = URL_SAFE_NO_PAD
            .decode(segments.next().ok_or_else(invalid)?)
            .map_err(|_| invalid())?;
        let head: Header = serde_json::from_slice(&head).map_err(|_| invalid())?;
        if !matches!(
            head.alg,
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256
                | CoreJwsSigningAlgorithm::EcdsaP256Sha256
                | CoreJwsSigningAlgorithm::EdDsa
        ) || head
            .typ
            .as_ref()
            .is_some_and(|v| !matches!(v.as_str(), "JWT" | "logout+jwt"))
            || head.kid.as_ref().is_some_and(|v| !opaque(v, 512))
        {
            return Err(invalid());
        }
        let (signed, signature) = token.rsplit_once('.').ok_or_else(invalid)?;
        let signature = URL_SAFE_NO_PAD.decode(signature).map_err(|_| invalid())?;
        // Always use fresh metadata from the configured issuer. Header-provided
        // URLs/keys and critical extensions are refused, never followed.
        let metadata = self.metadata().await?;
        let keys: Vec<_> = metadata
            .jwks()
            .keys()
            .iter()
            .filter(|key| {
                head.kid
                    .as_ref()
                    .is_none_or(|id| key.key_id().is_some_and(|kid| kid.as_str() == id))
                    && key.key_use().is_none_or(JsonWebKeyUse::allows_signature)
                    && head.alg.key_type().as_ref() == Some(key.key_type())
                    && match key.signing_alg() {
                        JsonWebKeyAlgorithm::Unspecified => true,
                        JsonWebKeyAlgorithm::Algorithm(alg) => alg == &head.alg,
                        JsonWebKeyAlgorithm::Unsupported => false,
                    }
            })
            .collect();
        if keys.len() != 1 {
            return Err(invalid());
        }
        keys[0]
            .verify_signature(&head.alg, signed.as_bytes(), &signature)
            .map_err(|_| invalid())?;
        // Discovery/JWKS may consume the remainder of a short token lifetime.
        if !claims.valid_time() {
            return Err(invalid());
        }

        let id = digest(
            serde_json::to_vec(&json!([claims.iss, self.config.client_id, claims.jti]))
                .map_err(|_| Error::internal())?,
        );
        let hash = digest(&token);
        let mut tx = store.transaction(true, false).await?;
        exec(
            &mut tx,
            "DELETE FROM browser_logout_events WHERE expires<=now()",
            args![],
        )
        .await?;
        if let Some(old) = optional(
            &mut tx,
            "SELECT token_hash FROM browser_logout_events WHERE id=$1",
            args![id],
        )
        .await?
        {
            if old["token_hash"] != hash {
                return Err(invalid());
            }
            // A delivery retry must not revoke sessions created after its first commit.
            return Ok(private_response(StatusCode::OK.into_response()));
        }
        if one(
            &mut tx,
            "SELECT count(*) AS n FROM browser_logout_events",
            args![],
        )
        .await?["n"]
            .as_i64()
            .unwrap_or(i64::MAX)
            >= 10_000
        {
            return Err(Error::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "logout receipt capacity exhausted",
            ));
        }
        exec(&mut tx, "INSERT INTO browser_logout_events(id,token_hash,issuer,client_id,subject,sid,issued,expires) VALUES($1,$2,$3,$4,$5,$6,$7,now()+interval '11 minutes')", args![id,hash,claims.iss,self.config.client_id,claims.sub,claims.sid,claims.iat]).await?;
        let removed = exec(&mut tx, "DELETE FROM browser_sessions s USING customer_users u WHERE s.user_id=u.id AND u.issuer=$1 AND s.client_id=$2 AND ($3::text IS NULL OR u.subject=$3) AND ($4::text IS NULL OR s.provider_sid=$4)", args![claims.iss,self.config.client_id,claims.sub,claims.sid]).await?;
        Store::audit_system(
            &mut tx,
            "oidc",
            "browser_session.provider_logout",
            &json!(id),
            &Value::Null,
            json!({"sessions_removed":removed}),
        )
        .await?;
        tx.commit().await?;
        Ok(private_response(StatusCode::OK.into_response()))
    }
}
