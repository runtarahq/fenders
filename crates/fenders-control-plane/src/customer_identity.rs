//! Customer identities are exact OIDC issuer/subject pairs. Memberships grant
//! scoped customer roles; neither claims nor sessions can grant operator access.
use crate::{
    args,
    db::*,
    error::{Error, Result},
    model::{Principal, Role, digest, identity, uid},
    store::{Store, Tx, token},
};
use axum::http::StatusCode;
use serde_json::{Value, json};

pub struct SessionSecret {
    pub token: String,
    pub csrf: String,
}

/// When a session was last used, for ending one left idle.
pub(crate) const SESSION_IDLE_MIGRATION: &str = "ALTER TABLE browser_sessions ADD COLUMN IF NOT EXISTS last_used timestamptz NOT NULL DEFAULT now()";
/// A session that was used in the last thirty minutes.
const SESSION_IN_USE: &str = "s.last_used>now()-interval '30 minutes'";

impl Store {
    /// Explicit operator migration of a verified identity. Stable user IDs keep
    /// workspace grants intact; neither matching emails nor claims grant access.
    pub async fn migrate_customer_identity(
        &self,
        p: &Principal,
        user: &str,
        value: Value,
    ) -> Result<Value> {
        p.operator()?;
        identity(user)?;
        let keys = [
            "expected_revision",
            "expected_issuer",
            "expected_subject",
            "issuer",
            "subject",
        ];
        fields(&value, &keys, &keys)?;
        integer(&value["expected_revision"], 1, i64::MAX - 1)?;
        for (key, max) in [
            ("issuer", 2048),
            ("expected_issuer", 2048),
            ("subject", 255),
            ("expected_subject", 255),
        ] {
            let input = text(&value[key])?;
            if input.is_empty() || input.len() > max || input.chars().any(char::is_control) {
                return Err(Error::invalid("invalid identity mapping"));
            }
        }
        let issuer = url::Url::parse(s(&value["issuer"]))
            .map_err(|_| Error::invalid("invalid identity issuer"))?;
        if issuer.scheme() != "https"
            || issuer.host_str().is_none()
            || !issuer.username().is_empty()
            || issuer.password().is_some()
            || issuer.query().is_some()
            || issuer.fragment().is_some()
        {
            return Err(Error::invalid("identity issuer must be an HTTPS URL"));
        }
        let mut tx = self.transaction(true, false).await?;
        let current = one(
            &mut tx,
            "SELECT * FROM customer_users WHERE id=$1 FOR UPDATE",
            args![user],
        )
        .await?;
        if current["revision"] != value["expected_revision"]
            || current["issuer"] != value["expected_issuer"]
            || current["subject"] != value["expected_subject"]
        {
            return Err(conflict("identity changed; reload before migrating"));
        }
        if optional(
            &mut tx,
            "SELECT id FROM customer_users WHERE issuer=$1 AND subject=$2 AND id<>$3",
            args![value["issuer"], value["subject"], user],
        )
        .await?
        .is_some()
        {
            return Err(conflict(
                "target identity already belongs to another account",
            ));
        }
        let row = one(&mut tx, "UPDATE customer_users SET issuer=$2,subject=$3,revision=revision+1,updated=now() WHERE id=$1 RETURNING id,issuer,subject,disabled,revision,created,updated", args![user,value["issuer"],value["subject"]]).await?;
        let removed = exec(
            &mut tx,
            "DELETE FROM browser_sessions WHERE user_id=$1",
            args![user],
        )
        .await?;
        Self::audit_system(&mut tx, &p.id, "customer_user.migrate_identity", &json!(user), &Value::Null,
            json!({"previous_issuer":current["issuer"],"previous_subject":current["subject"],"issuer":row["issuer"],"subject":row["subject"],"revision":row["revision"],"sessions_removed":removed})).await?;
        tx.commit().await?;
        Ok(row)
    }

    pub async fn customer_user(&self, p: &Principal, user: &str) -> Result<Value> {
        p.operator()?;
        identity(user)?;
        let mut tx = self.transaction(false, false).await?;
        one(&mut tx, "SELECT id,issuer,subject,disabled,revision,created,updated FROM customer_users WHERE id=$1", args![user]).await
    }

    /// Disable browser access without changing grants or workload ownership.
    /// Re-enabling never revives a removed session; a fresh OIDC login is needed.
    pub async fn update_customer_user(
        &self,
        p: &Principal,
        user: &str,
        value: Value,
    ) -> Result<Value> {
        p.operator()?;
        identity(user)?;
        fields(
            &value,
            &["disabled", "expected_revision"],
            &["disabled", "expected_revision"],
        )?;
        integer(&value["expected_revision"], 1, i64::MAX - 1)?;
        if !value["disabled"].is_boolean() {
            return Err(Error::invalid("disabled must be a boolean"));
        }
        let mut tx = self.transaction(true, false).await?;
        let current = one(
            &mut tx,
            "SELECT disabled,revision FROM customer_users WHERE id=$1 FOR UPDATE",
            args![user],
        )
        .await?;
        if current["revision"] != value["expected_revision"] {
            return Err(conflict("account changed; reload before saving"));
        }
        // Serialize with member edits, verified login and scoped mutations.
        // Account suspension must not bypass the existing last-owner barrier.
        if value["disabled"] == true && current["disabled"] == false
            && one(&mut tx, "SELECT EXISTS(SELECT 1 FROM workspace_memberships m WHERE m.user_id=$1 AND m.role='owner' AND NOT m.revoked AND NOT EXISTS(SELECT 1 FROM workspace_memberships other JOIN customer_users u ON u.id=other.user_id WHERE other.tenant_id=m.tenant_id AND other.role='owner' AND NOT other.revoked AND NOT u.disabled AND (NOT u.email_required OR u.email_verified) AND other.user_id<>$1)) AS blocked", args![user]).await?["blocked"] == true
        {
            return Err(conflict("assign another enabled owner in every workspace before disabling this account"));
        }
        let row = one(&mut tx, "UPDATE customer_users SET disabled=$2,revision=revision+1,updated=now() WHERE id=$1 RETURNING id,issuer,subject,disabled,revision,created,updated", args![user,value["disabled"]]).await?;
        // Remove credentials on either transition, including an explicit same-
        // state edit. This also prevents pre-upgrade disabled sessions returning.
        let removed = exec(
            &mut tx,
            "DELETE FROM browser_sessions WHERE user_id=$1",
            args![user],
        )
        .await?;
        // A disabled user's API keys and credentials go with their sessions,
        // in every workspace; enabling the user again does not revive them.
        if value["disabled"] == true {
            Self::revoke_issued_by(&mut tx, None, user).await?;
        }
        Self::audit_system(&mut tx, &p.id, "customer_user.update", &json!(user), &Value::Null,
            json!({"disabled":row["disabled"],"revision":row["revision"],"sessions_removed":removed})).await?;
        tx.commit().await?;
        Ok(row)
    }

    pub(crate) async fn live_principal(tx: &mut Tx, p: &Principal) -> Result<()> {
        match (&p.session_id, &p.membership_id) {
            (None, None) if p.tenant_id.is_some() => {
                let valid: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM credentials WHERE id=$1 AND NOT revoked AND expires>now() AND role=$2 AND tenant_id=$3 AND project_id IS NOT DISTINCT FROM $4 AND api_permissions IS NOT DISTINCT FROM $5)")
                    .bind(&p.id).bind(p.role.as_str()).bind(&p.tenant_id).bind(&p.project_id).bind(p.api_permissions.as_ref().map(|permissions| serde_json::json!(permissions))).fetch_one(&mut **tx).await?;
                if valid {
                    Ok(())
                } else {
                    Err(Error::unauthorized())
                }
            }
            (None, None) => Ok(()),

            (Some(session), Some(member)) => {
                let valid=one(tx,"SELECT EXISTS(SELECT 1 FROM workspace_memberships m JOIN browser_sessions s ON s.user_id=m.user_id JOIN customer_users u ON u.id=s.user_id WHERE s.id=$1 AND m.id=$2 AND s.expires>now() AND s.last_used>now()-interval '30 minutes' AND NOT u.disabled AND (NOT u.email_required OR u.email_verified) AND NOT m.revoked AND m.role=$3 AND m.tenant_id=$4 AND m.project_id IS NOT DISTINCT FROM $5 AND u.id=$6) AS valid",args![session,member,p.role.as_str(),p.tenant_id,p.project_id,p.id]).await?;
                if valid["valid"] == true {
                    Ok(())
                } else {
                    Err(Error::unauthorized())
                }
            }
            _ => Err(Error::unauthorized()),
        }?;
        if let Some(tenant) = &p.tenant_id {
            let writing: bool = sqlx::query_scalar(
                "SELECT COALESCE(current_setting('fenders.mutation',true),'')='true'",
            )
            .fetch_one(&mut **tx)
            .await?;
            if writing {
                Self::require_workspace_active(tx, tenant).await?;
            }
        }
        Ok(())
    }
    pub async fn members(&self, p: &Principal, tenant: &str) -> Result<Value> {
        p.scope(tenant, None, false, true)?;
        let mut tx = self.transaction(false, false).await?;
        Self::live_principal(&mut tx, p).await?;
        Ok(
            json!({"items":rows(&mut tx,"SELECT m.id,m.user_id,m.project_id,m.role,m.revoked,m.revision,m.created,m.updated,u.email,u.display_name FROM workspace_memberships m JOIN customer_users u ON u.id=m.user_id WHERE m.tenant_id=$1 ORDER BY m.created,m.id",args![tenant]).await?}),
        )
    }
    pub async fn add_member(&self, p: &Principal, tenant: &str, value: Value) -> Result<Value> {
        p.scope(tenant, None, true, true)?;
        fields(
            &value,
            &["user_id", "role", "project_id"],
            &["user_id", "role"],
        )?;
        identity(text(&value["user_id"])?)?;
        let role = member_role(&value["role"], &value["project_id"])?;
        if !value["project_id"].is_null() {
            identity(text(&value["project_id"])?)?;
        }
        let mut tx = self.transaction(true, false).await?;
        Self::live_principal(&mut tx, p).await?;
        one(&mut tx, "SELECT id FROM tenants WHERE id=$1", args![tenant]).await?;
        one(
            &mut tx,
            "SELECT id FROM customer_users WHERE id=$1 AND NOT disabled",
            args![value["user_id"]],
        )
        .await?;
        if !value["project_id"].is_null() {
            one(
                &mut tx,
                "SELECT id FROM projects WHERE tenant_id=$1 AND id=$2",
                args![tenant, value["project_id"]],
            )
            .await?;
        }
        if let Some(existing)=optional(&mut tx,"SELECT * FROM workspace_memberships WHERE tenant_id=$1 AND user_id=$2 AND project_id IS NOT DISTINCT FROM $3",args![tenant,value["user_id"],value["project_id"]]).await? {
            if existing["role"]==role && existing["revoked"]==false {return Ok(existing);}
            return Err(conflict("membership exists; update its current revision"));
        }
        let row=one(&mut tx,"INSERT INTO workspace_memberships(id,tenant_id,user_id,project_id,role) VALUES($1,$2,$3,$4,$5) RETURNING *",args![uid(),tenant,value["user_id"],value["project_id"],role]).await?;
        Self::audit(
            &mut tx,
            p,
            "member.add",
            s(&row["id"]),
            tenant,
            json!({"role":role,"user_id":value["user_id"],"project_id":value["project_id"]}),
        )
        .await?;
        tx.commit().await?;
        Ok(row)
    }
    pub async fn update_member(
        &self,
        p: &Principal,
        tenant: &str,
        member: &str,
        value: Value,
    ) -> Result<Value> {
        p.scope(tenant, None, true, true)?;
        identity(member)?;
        fields(
            &value,
            &["role", "revoked", "expected_revision"],
            &["expected_revision"],
        )?;
        integer(&value["expected_revision"], 1, i64::MAX - 1)?;
        if value.get("role").is_none() && value.get("revoked").is_none() {
            return Err(Error::invalid("membership update is empty"));
        }
        if value.get("revoked").is_some_and(|v| !v.is_boolean()) {
            return Err(Error::invalid("revoked must be a boolean"));
        }
        let mut tx = self.transaction(true, false).await?;
        Self::live_principal(&mut tx, p).await?;
        let row = Self::update_membership_in_tx(&mut tx, tenant, member, &value).await?;
        Self::audit(
            &mut tx,
            p,
            "member.update",
            member,
            tenant,
            json!({"role":row["role"],"revoked":row["revoked"],"revision":row["revision"]}),
        )
        .await?;
        tx.commit().await?;
        Ok(row)
    }
    pub(crate) async fn update_membership_in_tx(
        tx: &mut Tx,
        tenant: &str,
        member: &str,
        value: &Value,
    ) -> Result<Value> {
        let row = one(
            tx,
            "SELECT * FROM workspace_memberships WHERE tenant_id=$1 AND id=$2",
            args![tenant, member],
        )
        .await?;
        if row["revision"] != value["expected_revision"] {
            return Err(conflict("membership changed; reload before saving"));
        }
        let role = get(value, "role", row["role"].clone());
        let role = member_role(&role, &row["project_id"])?;
        let revoked = get(value, "revoked", row["revoked"].clone());
        if row["role"]=="owner" && row["revoked"]==false && (role!="owner"||revoked==true)
            && one(tx,"SELECT count(*) AS n FROM workspace_memberships m JOIN customer_users u ON u.id=m.user_id WHERE m.tenant_id=$1 AND m.role='owner' AND NOT m.revoked AND NOT u.disabled AND (NOT u.email_required OR u.email_verified) AND m.id<>$2",args![tenant,member]).await?["n"]==0 {
                return Err(conflict("add another owner before removing the last owner"));
        }
        let updated=one(tx,"UPDATE workspace_memberships SET role=$1,revoked=$2,revision=revision+1,updated=now() WHERE id=$3 RETURNING *",args![role,revoked,member]).await?;
        // A member who is removed, or is no longer an owner, could issue API
        // keys and credentials while they were one. Those end here: a bearer
        // credential is checked against its own row, not its issuer's
        // standing, and would otherwise outlive the access it came from.
        if row["role"] == "owner" && (updated["role"] != "owner" || updated["revoked"] == true) {
            Self::revoke_issued_by(tx, Some(tenant), crate::db::s(&row["user_id"])).await?;
        }
        Ok(updated)
    }
    /// Called only after a cryptographically verified OIDC callback. Not an API
    /// for accepting caller-supplied claims or trading bearer credentials.
    pub(crate) async fn verified_session(
        &self,
        issuer: &str,
        subject: &str,
        binding: &crate::browser_auth::logout::LoginBinding,
        old_token: Option<&str>,
        profile: crate::customer_onboarding::VerifiedProfile,
    ) -> Result<SessionSecret> {
        if subject.is_empty() || subject.len() > 255 || issuer.len() > 2048 {
            return Err(Error::unauthorized());
        }
        let secret = token("fnd_session_")?;
        let csrf = token("fnd_csrf_")?;
        let mut tx = self.transaction(true, false).await?;
        exec(
            &mut tx,
            "DELETE FROM browser_logout_events WHERE expires<=now()",
            args![],
        )
        .await?;
        if one(&mut tx, "SELECT EXISTS(SELECT 1 FROM browser_logout_events WHERE issuer=$1 AND client_id=$2 AND (subject IS NULL OR subject=$3) AND (sid IS NULL OR sid=$4) AND (sid IS NOT NULL OR issued>=$5)) AS blocked", args![issuer,binding.client_id,subject,binding.sid,binding.issued]).await?["blocked"] == true {
            return Err(Error::unauthorized());
        }
        let email_verified = profile.email.is_some() && profile.email_verified;
        let display_name = profile.display_name.map(|name| {
            name.chars()
                .filter(|c| !c.is_control())
                .take(100)
                .collect::<String>()
        });
        let user=one(&mut tx,"INSERT INTO customer_users(id,issuer,subject,email,email_verified,display_name,email_required,onboarding_required) VALUES($1,$2,$3,$4,$5,$6,$7,$7) ON CONFLICT(issuer,subject) DO UPDATE SET email=excluded.email,email_verified=excluded.email_verified,display_name=excluded.display_name,email_required=customer_users.email_required OR excluded.email_required,updated=now() RETURNING *",args![uid(),issuer,subject,profile.email,email_verified,display_name,self.onboarding.is_some()]).await?;
        if user["disabled"] == true {
            return Err(Error::unauthorized());
        }
        self.onboard_user(&mut tx, &user).await?;
        if let Some(old) = old_token {
            exec(
                &mut tx,
                "DELETE FROM browser_sessions WHERE token_hash=$1",
                args![digest(old)],
            )
            .await?;
        }
        exec(&mut tx,"DELETE FROM browser_sessions WHERE expires<=now() OR id IN (SELECT id FROM browser_sessions WHERE user_id=$1 ORDER BY created DESC,id DESC OFFSET 9)",args![user["id"]]).await?;
        exec(&mut tx,"INSERT INTO browser_sessions(id,user_id,token_hash,csrf_hash,csrf_encrypted,expires,client_id,provider_sid,provider_iat) VALUES($1,$2,$3,$4,$5,now()+interval '8 hours',$6,$7,$8)",args![uid(),user["id"],digest(&secret),digest(&csrf),self.cipher.encrypt(csrf.as_bytes()),binding.client_id,binding.sid,binding.issued]).await?;
        tx.commit().await?;
        Ok(SessionSecret {
            token: secret,
            csrf,
        })
    }
    pub(crate) async fn browser_session(&self, secret: &str, csrf: Option<&str>) -> Result<Value> {
        if !secret.starts_with("fnd_session_") || secret.len() > 256 {
            return Err(Error::unauthorized());
        }
        let mut tx = self.transaction(false, false).await?;
        // A session ends eight hours after sign-in, and sooner when it is
        // left unused: one in a browser that was walked away from is not
        // good for the rest of the working day.
        let row=optional(&mut tx,&format!("SELECT s.*,u.issuer,u.subject,u.email,u.email_verified,u.email_required,s.last_used<now()-interval '1 minute' AS used_a_while_ago FROM browser_sessions s JOIN customer_users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires>now() AND {SESSION_IN_USE} AND NOT u.disabled"),args![digest(secret)]).await?.ok_or_else(Error::unauthorized)?;
        if csrf.is_some_and(|v| v.len() > 256 || digest(v) != row["csrf_hash"]) {
            return Err(Error::new(StatusCode::FORBIDDEN, "invalid CSRF token"));
        }
        drop(tx);
        // Used now. Written at most once a minute for a session, so that a
        // request is not a write.
        if row["used_a_while_ago"] == true {
            let mut tx = self.transaction(true, false).await?;
            exec(&mut tx,"UPDATE browser_sessions SET last_used=now() WHERE id=$1 AND last_used<now()-interval '1 minute'",args![row["id"]]).await?;
            tx.commit().await?;
        }
        Ok(row)
    }
    pub(crate) async fn session_principal(
        &self,
        session: &Value,
        tenant: &str,
        project: Option<&str>,
    ) -> Result<Principal> {
        identity(tenant)?;
        if let Some(project) = project {
            identity(project)?;
        }
        let mut tx = self.transaction(false, false).await?;
        let row=optional(&mut tx,"SELECT * FROM workspace_memberships WHERE user_id=$1 AND tenant_id=$2 AND NOT revoked AND (project_id IS NULL OR project_id=$3) ORDER BY CASE role WHEN 'owner' THEN 3 WHEN 'editor' THEN 2 ELSE 1 END DESC,project_id NULLS FIRST LIMIT 1",args![session["user_id"],tenant,project]).await?.ok_or_else(Error::missing)?;
        let p:Principal=serde_json::from_value(json!({"id":session["user_id"],"role":row["role"],"tenant_id":tenant,"project_id":row["project_id"],"membership_id":row["id"],"session_id":session["id"]})).map_err(|_|Error::internal())?;
        Self::live_principal(&mut tx, &p).await?;
        Ok(p)
    }
    pub(crate) async fn session_info(&self, session: &Value) -> Result<Value> {
        let mut tx = self.transaction(false, false).await?;
        let user = one(&mut tx, "SELECT id,email,email_verified,email_required,display_name,onboarding_required,onboarded_workspace_id FROM customer_users WHERE id=$1", args![session["user_id"]]).await?;
        let admission = Self::admission_status(&mut tx, &user).await?;
        let verification_required =
            user["email_required"] == true && user["email_verified"] != true;
        let workspaces = if verification_required {
            vec![]
        } else {
            rows(&mut tx,"SELECT t.id,t.display_name,t.lifecycle_state AS status,(SELECT p.id FROM projects p WHERE p.tenant_id=t.id AND EXISTS(SELECT 1 FROM workspace_memberships access WHERE access.user_id=$1 AND access.tenant_id=p.tenant_id AND NOT access.revoked AND (access.project_id IS NULL OR access.project_id=p.id)) ORDER BY p.is_default DESC,p.created,p.id LIMIT 1) AS default_project_id,jsonb_agg(jsonb_build_object('id',m.id,'role',m.role,'project_id',m.project_id,'revision',m.revision) ORDER BY m.created,m.id) AS memberships FROM tenants t JOIN workspace_memberships m ON m.tenant_id=t.id WHERE m.user_id=$1 AND NOT m.revoked GROUP BY t.id ORDER BY t.created,t.id",args![session["user_id"]]).await?
        };
        let csrf = String::from_utf8(
            self.cipher
                .decrypt(s(&session["csrf_encrypted"]))
                .map_err(|_| Error::internal())?,
        )
        .map_err(|_| Error::internal())?;
        Ok(
            json!({"unserved":if self.refuse_unserved { crate::unavailable::FEATURES } else { &[] },"user_id":session["user_id"],"expires":session["expires"],"csrf":csrf,"workspaces":workspaces,"email":user["email"],"display_name":user["display_name"],"email_verified":user["email_verified"],"onboarding":{"admission":admission,"verification_required":verification_required,"workspace_pending":user["onboarding_required"],"workspace_id":user["onboarded_workspace_id"],"verification_resend":self.onboarding.as_ref().is_some_and(|v|v.verification_email.is_some())}}),
        )
    }
    pub(crate) async fn session_projects(&self, session: &Value, tenant: &str) -> Result<Value> {
        identity(tenant)?;
        if session["email_required"] == true && session["email_verified"] != true {
            return Err(Error::new(
                StatusCode::FORBIDDEN,
                "verify your email to access a workspace",
            ));
        }
        let mut tx = self.transaction(false, false).await?;
        if optional(&mut tx,"SELECT id FROM workspace_memberships WHERE user_id=$1 AND tenant_id=$2 AND NOT revoked LIMIT 1",args![session["user_id"],tenant]).await?.is_none(){return Err(Error::missing());}
        Ok(json!(rows(&mut tx,"SELECT p.* FROM projects p WHERE p.tenant_id=$1 AND EXISTS(SELECT 1 FROM workspace_memberships m WHERE m.user_id=$2 AND m.tenant_id=p.tenant_id AND NOT m.revoked AND (m.project_id IS NULL OR m.project_id=p.id)) ORDER BY p.created,p.id",args![tenant,session["user_id"]]).await?))
    }
    pub(crate) async fn end_browser_session(&self, secret: &str) -> Result<()> {
        let mut tx = self.transaction(true, false).await?;
        exec(
            &mut tx,
            "DELETE FROM browser_sessions WHERE token_hash=$1",
            args![digest(secret)],
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }
}
pub(crate) fn member_role(value: &Value, project: &Value) -> Result<&'static str> {
    match text(value)? {
        "owner" if project.is_null() => Ok(Role::Owner.as_str()),
        "editor" => Ok(Role::Editor.as_str()),
        "viewer" => Ok(Role::Viewer.as_str()),
        _ => Err(Error::invalid("invalid customer role or project scope")),
    }
}
