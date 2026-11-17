//! Verified customer onboarding. Identity authentication never grants operator
//! privileges; this narrow admission path uses an operator-configured allowance.
use crate::{
    args,
    db::*,
    error::{Error, Result},
    model::{Allowance, uid},
    store::{Store, Tx},
};
use axum::http::StatusCode;
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;

pub(crate) const MIGRATION: &str = "
ALTER TABLE customer_users ADD COLUMN IF NOT EXISTS email text;
ALTER TABLE customer_users ADD COLUMN IF NOT EXISTS email_verified boolean NOT NULL DEFAULT false;
ALTER TABLE customer_users ADD COLUMN IF NOT EXISTS display_name text;
ALTER TABLE customer_users ADD COLUMN IF NOT EXISTS email_required boolean NOT NULL DEFAULT false;
ALTER TABLE customer_users ADD COLUMN IF NOT EXISTS onboarding_required boolean NOT NULL DEFAULT false;
ALTER TABLE customer_users ADD COLUMN IF NOT EXISTS onboarded_workspace_id text REFERENCES tenants(id);
ALTER TABLE customer_users ADD COLUMN IF NOT EXISTS verification_requested_at timestamptz;
CREATE UNIQUE INDEX IF NOT EXISTS customer_home_workspace ON customer_users(onboarded_workspace_id);
";

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OnboardingConfig {
    pub allowance: Allowance,
    /// Explicit admission cap for this private release, not physical reservation.
    pub max_workspaces: i64,
    #[serde(default)]
    pub verification_email: Option<Auth0EmailConfig>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Auth0EmailConfig {
    pub tenant_domain: String,
    pub client_id: String,
    pub client_secret: String,
}

pub(crate) struct VerifiedProfile {
    pub email: Option<String>,
    pub email_verified: bool,
    pub display_name: Option<String>,
}

/// Keep mailbox aliases distinct. In particular, do not strip dots or '+' tags.
pub(crate) fn canonical_email(value: &str) -> Option<String> {
    let value = value.trim();
    if value.len() > 254 {
        return None;
    }
    let (local, domain) = value.rsplit_once('@')?;
    if local.is_empty()
        || local.len() > 64
        || !local.is_ascii()
        || local
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || "@<>(),;:\\\"[]".contains(c))
    {
        return None;
    }
    let url::Host::Domain(domain) = url::Host::parse(domain).ok()? else {
        return None;
    };
    if !domain.contains('.') || domain.ends_with('.') {
        return None;
    }
    Some(format!("{local}@{domain}"))
}

impl Store {
    pub fn with_onboarding(mut self, config: OnboardingConfig) -> Result<Self> {
        config.allowance.validate()?;
        if !(1..=100_000).contains(&config.max_workspaces) {
            return Err(Error::invalid(
                "invalid self-service workspace admission cap",
            ));
        }
        if let Some(email) = &config.verification_email
            && (!email.tenant_domain.ends_with(".auth0.com")
                || !email
                    .tenant_domain
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b".-".contains(&b))
                || email.tenant_domain.len() > 253
                || email.client_id.is_empty()
                || email.client_id.len() > 512
                || email.client_secret.is_empty()
                || email.client_secret.len() > 4096)
        {
            return Err(Error::invalid(
                "invalid Auth0 verification-email configuration",
            ));
        }
        self.onboarding = Some(Arc::new(config));
        Ok(self)
    }

    /// Uses the existing mutation/admission lock; login, retries and concurrent
    /// tabs cannot create multiple home workspaces or exceed the admission cap.
    pub(crate) async fn onboard_user(&self, tx: &mut Tx, user: &Value) -> Result<()> {
        if user["onboarding_required"] != true
            || !user["onboarded_workspace_id"].is_null()
            || user["email_verified"] != true
            || user["disabled"] == true
        {
            return Ok(());
        }
        // An invited user reviews consent before independent workspace admission.
        // Accepted invitations also prevent a later login creating a home workspace,
        // including after the invited membership has been revoked.
        if one(tx, "SELECT EXISTS(SELECT 1 FROM workspace_invitations WHERE recipient_id=$1 AND status='accepted' OR email=$2 AND status='pending' AND expires>now()) AS invited", args![user["id"],user["email"]]).await?["invited"] == true {
            return Ok(());
        }
        let policy = one(
            tx,
            "SELECT * FROM admission_policy WHERE singleton",
            args![],
        )
        .await?;
        if policy["mode"] == "closed" {
            return Ok(());
        }
        if policy["mode"] == "approval" {
            return Self::queue_admission(tx, user).await;
        }
        let Some(policy) = &self.onboarding else {
            return Ok(());
        };
        let used = one(
            tx,
            "SELECT count(*) AS n FROM customer_users WHERE onboarded_workspace_id IS NOT NULL",
            args![],
        )
        .await?;
        if n(&used["n"]) >= policy.max_workspaces {
            return Ok(());
        }
        Self::provision_home_workspace(tx, user, &policy.allowance).await?;
        Ok(())
    }
    pub(crate) async fn provision_home_workspace(
        tx: &mut Tx,
        user: &Value,
        allowance: &Allowance,
    ) -> Result<String> {
        let name = format!("workspace-{}", uid());
        let display = user["display_name"]
            .as_str()
            .filter(|v| !v.is_empty())
            .map(|v| format!("{}'s workspace", v.chars().take(40).collect::<String>()))
            .unwrap_or_else(|| "My workspace".into());
        let (workspace, project) =
            Self::create_workspace_records(tx, &name, &display, allowance).await?;
        let workspace_id = s(&workspace["id"]);
        exec(
            tx,
            "INSERT INTO workspace_memberships(id,tenant_id,user_id,role) VALUES($1,$2,$3,'owner')",
            args![uid(), workspace_id, user["id"]],
        )
        .await?;
        exec(tx, "UPDATE customer_users SET onboarded_workspace_id=$2,onboarding_required=false,updated=now() WHERE id=$1", args![user["id"],workspace_id]).await?;
        Self::audit_system(
            tx,
            s(&user["id"]),
            "customer.onboard",
            &workspace["id"],
            &workspace["id"],
            json!({"project_id":project}),
        )
        .await?;
        Ok(workspace_id.to_owned())
    }

    pub(crate) async fn complete_onboarding(&self, session: &Value) -> Result<()> {
        let mut tx = self.transaction(true, false).await?;
        let user = one(&mut tx, "SELECT u.* FROM customer_users u JOIN browser_sessions s ON s.user_id=u.id WHERE s.id=$1 AND s.expires>now() AND NOT u.disabled FOR UPDATE OF u", args![session["id"]]).await?;
        if user["email_verified"] != true {
            return Err(Error::new(
                StatusCode::FORBIDDEN,
                "verify your email before creating a workspace",
            ));
        }
        self.onboard_user(&mut tx, &user).await?;
        tx.commit().await?;
        Ok(())
    }

    pub(crate) async fn resend_verification_email(
        &self,
        session: &Value,
        login_client: &str,
    ) -> Result<()> {
        let config = self
            .onboarding
            .as_ref()
            .and_then(|v| v.verification_email.as_ref())
            .ok_or_else(|| {
                Error::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "verification email delivery is not configured",
                )
            })?;
        let mut tx = self.transaction(true, false).await?;
        let user = one(&mut tx, "SELECT u.*,verification_requested_at>now()-interval '60 seconds' AS cooling_down FROM customer_users u JOIN browser_sessions s ON s.user_id=u.id WHERE s.id=$1 AND s.expires>now() AND NOT u.disabled FOR UPDATE OF u", args![session["id"]]).await?;
        if user["email_verified"] == true || user["email"].is_null() {
            return Err(Error::invalid(
                "this account does not need an email verification request",
            ));
        }
        if user["cooling_down"] == true {
            return Err(Error::new(
                StatusCode::TOO_MANY_REQUESTS,
                "wait one minute before requesting another verification email",
            ));
        }
        exec(
            &mut tx,
            "UPDATE customer_users SET verification_requested_at=now() WHERE id=$1",
            args![user["id"]],
        )
        .await?;
        Self::audit_system(
            &mut tx,
            s(&user["id"]),
            "customer.verification_email_requested",
            &user["id"],
            &Value::Null,
            json!({}),
        )
        .await?;
        tx.commit().await?;

        // No caller-supplied recipient or URL; scope is server-side update:users.
        // Reserve the cooldown before I/O because a lost response may still send.
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(std::time::Duration::from_secs(3))
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|_| Error::internal())?;
        let origin = format!("https://{}", config.tenant_domain);
        let token = client.post(format!("{origin}/oauth/token"))
            .header("Content-Type", "application/json").body(json!({"grant_type":"client_credentials","client_id":config.client_id,"client_secret":config.client_secret,"audience":format!("{origin}/api/v2/"),"scope":"update:users"}).to_string())
            .send().await.map_err(|_| verification_delivery_error())?;
        let token = provider_json(token).await?;
        let access = token["access_token"]
            .as_str()
            .filter(|v| !v.is_empty() && v.len() <= 16384)
            .ok_or_else(verification_delivery_error)?;
        let response = client
            .post(format!("{origin}/api/v2/jobs/verification-email"))
            .bearer_auth(access)
            .header("Content-Type", "application/json")
            .body(json!({"user_id":user["subject"],"client_id":login_client}).to_string())
            .send()
            .await
            .map_err(|_| verification_delivery_error())?;
        if response.status() != reqwest::StatusCode::CREATED {
            return Err(verification_delivery_error());
        }
        Ok(())
    }
}

fn verification_delivery_error() -> Error {
    Error::new(
        StatusCode::BAD_GATEWAY,
        "verification email delivery could not be confirmed; check your inbox or retry in one minute",
    )
}

async fn provider_json(mut response: reqwest::Response) -> Result<Value> {
    if !response.status().is_success() {
        return Err(verification_delivery_error());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| verification_delivery_error())?
    {
        if bytes.len() + chunk.len() > 32768 {
            return Err(verification_delivery_error());
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| verification_delivery_error())
}
