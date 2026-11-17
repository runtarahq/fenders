//! Development sign-in from Tailscale Serve's identity headers.
//!
//! Tailscale Serve, proxying a tailnet user's request, sets
//! `Tailscale-User-Login` (and `-Name`) itself and drops any the client sent.
//! With `--tailscale-identity` the customer console signs that user in without
//! an OIDC provider, and gives the listed logins a membership in a workspace
//! made beforehand.
//!
//! **Not an authentication boundary on its own.** The headers prove a tailnet
//! identity only for requests that came through Serve; anything else that can
//! reach the listener can send them. The control plane therefore refuses this
//! mode unless it listens on loopback only, and it is for development hosts,
//! never a customer deployment.
use super::*;
use serde_json::Value;
use std::collections::BTreeMap;

/// The issuer recorded for users signed in this way.
pub const ISSUER: &str = "https://login.tailscale.com";
const CLIENT: &str = "tailscale-serve";

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TailscaleIdentityConfig {
    /// The console as tailnet users open it, such as `https://host.tailnet.ts.net`.
    pub console_origin: String,
    /// Tailscale logins allowed to sign in, each with the workspace it gets.
    pub users: BTreeMap<String, TailscaleUser>,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TailscaleUser {
    /// An existing workspace the login is made a member of at first sign-in.
    pub workspace: String,
    /// `owner`, `editor` or `viewer`, workspace-wide.
    pub role: String,
}

impl TailscaleIdentityConfig {
    /// The provider configuration this mode stands in for; no request is ever
    /// made to its issuer.
    pub(super) fn provider(&self) -> BrowserAuthConfig {
        BrowserAuthConfig {
            issuer: ISSUER.into(),
            client_id: CLIENT.into(),
            client_secret: None,
            console_origin: self.console_origin.clone(),
            endpoint_origins: vec![],
            provider_ca_pem: None,
            provider_logout_url: None,
        }
    }
    pub(super) fn validate(&self) -> Result<()> {
        if self.users.is_empty() || self.users.len() > 64 {
            return Err(Error::invalid("list 1 to 64 Tailscale logins"));
        }
        for (login, user) in &self.users {
            if !valid_login(login) {
                return Err(Error::invalid("invalid Tailscale login"));
            }
            crate::model::identity(&user.workspace)?;
            crate::customer_identity::member_role(&json!(user.role), &Value::Null)?;
        }
        Ok(())
    }
}

fn valid_login(login: &str) -> bool {
    !login.is_empty()
        && login.len() <= 255
        && login.contains('@')
        && login.bytes().all(|b| b.is_ascii_graphic())
}

fn header_text(headers: &HeaderMap, name: &str) -> Option<String> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?.trim().to_owned();
    // More than one is not what Serve sends.
    (values.next().is_none() && !value.is_empty()).then_some(value)
}

impl BrowserAuth {
    /// Signs in the Tailscale user Serve named, if listed.
    pub(super) async fn tailscale_login(
        &self,
        store: &Store,
        config: &TailscaleIdentityConfig,
        headers: &HeaderMap,
    ) -> Result<Response> {
        let login = header_text(headers, "tailscale-user-login")
            .filter(|login| valid_login(login))
            .ok_or_else(|| {
                Error::new(
                    StatusCode::FORBIDDEN,
                    "open the console through Tailscale Serve to sign in",
                )
            })?
            .to_ascii_lowercase();
        let user = config
            .users
            .iter()
            .find(|(listed, _)| listed.eq_ignore_ascii_case(&login))
            .map(|(_, user)| user)
            .ok_or_else(|| {
                Error::new(
                    StatusCode::FORBIDDEN,
                    "this Tailscale login is not allowed here",
                )
            })?;
        let old = cookie_value(headers, self.session_cookie())?;
        let binding = logout::LoginBinding {
            client_id: CLIENT.into(),
            sid: None,
            issued: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| Error::internal())?
                .as_secs() as i64,
        };
        let session = store
            .verified_session(
                ISSUER,
                &login,
                &binding,
                old.as_deref(),
                crate::customer_onboarding::VerifiedProfile {
                    email: crate::customer_onboarding::canonical_email(&login),
                    email_verified: true,
                    display_name: header_text(headers, "tailscale-user-name"),
                },
            )
            .await?;
        store
            .tailscale_membership(&login, &user.workspace, &user.role)
            .await?;
        redirect(
            "/console/",
            &[self.cookie(self.session_cookie(), &session.token, 28800)],
        )
    }
}

impl Store {
    pub fn with_tailscale_identity(mut self, config: TailscaleIdentityConfig) -> Result<Self> {
        config.validate()?;
        let mut auth = BrowserAuth::new(config.provider(), false)?;
        auth.tailscale = Some(config);
        self.browser_auth = Some(std::sync::Arc::new(auth));
        Ok(self)
    }
    /// Gives a listed login its workspace membership once. An existing
    /// membership, revoked or not, is left as it is.
    async fn tailscale_membership(&self, login: &str, workspace: &str, role: &str) -> Result<()> {
        use crate::{
            args,
            db::{one, optional},
        };
        let mut tx = self.transaction(true, false).await?;
        let user = one(
            &mut tx,
            "SELECT id FROM customer_users WHERE issuer=$1 AND subject=$2",
            args![ISSUER, login],
        )
        .await?;
        one(
            &mut tx,
            "SELECT id FROM tenants WHERE id=$1",
            args![workspace],
        )
        .await?;
        if optional(
            &mut tx,
            "SELECT id FROM workspace_memberships WHERE tenant_id=$1 AND user_id=$2 AND project_id IS NULL",
            args![workspace, user["id"]],
        )
        .await?
        .is_none()
        {
            let row = one(
                &mut tx,
                "INSERT INTO workspace_memberships(id,tenant_id,user_id,project_id,role) VALUES($1,$2,$3,NULL,$4) RETURNING id",
                args![crate::model::uid(), workspace, user["id"], role],
            )
            .await?;
            Self::audit_system(
                &mut tx,
                "tailscale-identity",
                "member.add",
                &row["id"],
                &json!(workspace),
                json!({"role":role,"user_id":user["id"],"login":login}),
            )
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_and_headers_are_strict() {
        let config = |users: Value| -> TailscaleIdentityConfig {
            serde_json::from_value(
                json!({"console_origin":"https://dev.tailnet.ts.net","users":users}),
            )
            .unwrap()
        };
        let workspace = "0".repeat(32);
        assert!(
            config(json!({"a@example.com":{"workspace":workspace,"role":"owner"}}))
                .validate()
                .is_ok()
        );
        assert!(config(json!({})).validate().is_err());
        for (login, role) in [("no-at-sign", "owner"), ("a@example.com", "admin")] {
            assert!(
                config(json!({login:{"workspace":workspace,"role":role}}))
                    .validate()
                    .is_err()
            );
        }
        assert!(
            config(json!({"a@example.com":{"workspace":"short","role":"owner"}}))
                .validate()
                .is_err()
        );
        let mut headers = HeaderMap::new();
        assert!(header_text(&headers, "tailscale-user-login").is_none());
        headers.append("tailscale-user-login", "a@example.com".parse().unwrap());
        assert_eq!(
            header_text(&headers, "tailscale-user-login").as_deref(),
            Some("a@example.com")
        );
        headers.append("tailscale-user-login", "b@example.com".parse().unwrap());
        assert!(header_text(&headers, "tailscale-user-login").is_none());
    }
}
