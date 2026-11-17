//! Email-bound, explicit-consent workspace invitations and a durable mail outbox.
use crate::{
    args,
    db::*,
    error::{Error, Result},
    invitation_email::{InvitationEmailConfig, InvitationMailer},
    model::{Principal, identity, uid},
    store::{Store, Tx},
};
use axum::http::StatusCode;
use serde_json::{Value, json};
use std::sync::Arc;

pub(crate) const MIGRATION: &str = "
CREATE TABLE IF NOT EXISTS workspace_invitations (
 id text PRIMARY KEY, tenant_id text NOT NULL REFERENCES tenants(id), project_id text,
 email text NOT NULL, role text NOT NULL CHECK(role IN ('viewer','editor','owner')),
 inviter_id text NOT NULL REFERENCES customer_users(id), request_key text NOT NULL,
 status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','accepted','declined','revoked')),
 revision bigint NOT NULL DEFAULT 1, recipient_id text REFERENCES customer_users(id),
 membership_id text REFERENCES workspace_memberships(id), created timestamptz NOT NULL DEFAULT now(),
 expires timestamptz NOT NULL DEFAULT now()+interval '7 days', decided_at timestamptz,
 UNIQUE(tenant_id,request_key), FOREIGN KEY(tenant_id,project_id) REFERENCES projects(tenant_id,id),
 CHECK(role<>'owner' OR project_id IS NULL)
);
CREATE INDEX IF NOT EXISTS invitation_recipient ON workspace_invitations(email,created);
CREATE TABLE IF NOT EXISTS invitation_outbox (
 invitation_id text PRIMARY KEY REFERENCES workspace_invitations(id),
 state text NOT NULL DEFAULT 'queued' CHECK(state IN ('queued','sending','sent','failed','cancelled')),
 attempts bigint NOT NULL DEFAULT 0, available_at timestamptz NOT NULL DEFAULT now(),
 requested_at timestamptz NOT NULL DEFAULT now(), sent_at timestamptz, lease text
);
";
const VIEW: &str = "SELECT i.*,CASE WHEN i.status='pending' AND i.expires<=now() THEN 'expired' ELSE i.status END AS status,t.display_name AS workspace_name,p.display_name AS project_name,o.state AS delivery,o.sent_at FROM workspace_invitations i JOIN tenants t ON t.id=i.tenant_id LEFT JOIN projects p ON p.id=i.project_id JOIN invitation_outbox o ON o.invitation_id=i.id";

impl Store {
    pub fn with_invitation_email(mut self, config: InvitationEmailConfig) -> Result<Self> {
        self.invitation_mailer = Some(Arc::new(InvitationMailer::new(config)?));
        Ok(self)
    }
    async fn invitation_view(tx: &mut Tx, id: &str) -> Result<Value> {
        one(tx, &format!("{VIEW} WHERE i.id=$1"), args![id]).await
    }
    pub async fn invitations(&self, p: &Principal, tenant: &str) -> Result<Value> {
        p.scope(tenant, None, false, true)?;
        let mut tx = self.transaction(false, false).await?;
        Self::live_principal(&mut tx, p).await?;
        Ok(
            json!({"enabled":self.invitation_mailer.is_some(),"items":rows(&mut tx,&format!("{VIEW} WHERE i.tenant_id=$1 ORDER BY i.created DESC,i.id DESC LIMIT 100"),args![tenant]).await?}),
        )
    }
    pub async fn invite(&self, p: &Principal, tenant: &str, value: Value) -> Result<Value> {
        p.scope(tenant, None, true, true)?;
        if p.session_id.is_none() {
            return Err(Error::new(
                StatusCode::FORBIDDEN,
                "use a workspace owner session to invite members",
            ));
        }
        if self.invitation_mailer.is_none() {
            return Err(Error::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "invitation email is not configured",
            ));
        }
        fields(
            &value,
            &["email", "role", "project_id", "request_key"],
            &["email", "role", "request_key"],
        )?;
        let email = crate::customer_onboarding::canonical_email(text(&value["email"])?)
            .ok_or_else(|| Error::invalid("enter a valid email address"))?;
        let role = crate::customer_identity::member_role(&value["role"], &value["project_id"])?;
        identity(text(&value["request_key"])?)?;
        let mut tx = self.transaction(true, false).await?;
        Self::live_principal(&mut tx, p).await?;
        if let Some(existing) = optional(
            &mut tx,
            "SELECT * FROM workspace_invitations WHERE tenant_id=$1 AND request_key=$2",
            args![tenant, value["request_key"]],
        )
        .await?
        {
            if existing["inviter_id"] != p.id
                || existing["email"] != email
                || existing["role"] != role
                || existing["project_id"] != value["project_id"]
            {
                return Err(conflict(
                    "request key was already used for another invitation",
                ));
            }
            return Self::invitation_view(&mut tx, s(&existing["id"])).await;
        }
        if !value["project_id"].is_null() {
            identity(text(&value["project_id"])?)?;
            one(
                &mut tx,
                "SELECT id FROM projects WHERE tenant_id=$1 AND id=$2",
                args![tenant, value["project_id"]],
            )
            .await?;
        }
        if optional(&mut tx,"SELECT id FROM workspace_invitations WHERE tenant_id=$1 AND email=$2 AND project_id IS NOT DISTINCT FROM $3 AND status='pending' AND expires>now()",args![tenant,email,value["project_id"]]).await?.is_some() { return Err(conflict("an invitation for this email and scope is already pending; resend or revoke it")); }
        if n(&one(&mut tx,"SELECT count(*) AS n FROM workspace_invitations WHERE tenant_id=$1 AND created>now()-interval '1 day'",args![tenant]).await?["n"]) >= 100 { return Err(Error::new(StatusCode::TOO_MANY_REQUESTS,"workspace invitation limit reached; try again tomorrow")); }
        let id = uid();
        exec(&mut tx,"INSERT INTO workspace_invitations(id,tenant_id,project_id,email,role,inviter_id,request_key) VALUES($1,$2,$3,$4,$5,$6,$7)",args![id,tenant,value["project_id"],email,role,p.id,value["request_key"]]).await?;
        exec(
            &mut tx,
            "INSERT INTO invitation_outbox(invitation_id) VALUES($1)",
            args![id],
        )
        .await?;
        Self::audit(
            &mut tx,
            p,
            "invitation.create",
            &id,
            tenant,
            json!({"email":email,"role":role,"project_id":value["project_id"]}),
        )
        .await?;
        let result = Self::invitation_view(&mut tx, &id).await?;
        tx.commit().await?;
        Ok(result)
    }
    pub async fn update_invitation(
        &self,
        p: &Principal,
        tenant: &str,
        id: &str,
        value: Value,
    ) -> Result<Value> {
        p.scope(tenant, None, true, true)?;
        identity(id)?;
        fields(
            &value,
            &["action", "expected_revision"],
            &["action", "expected_revision"],
        )?;
        integer(&value["expected_revision"], 1, i64::MAX - 1)?;
        let action = text(&value["action"])?;
        if !["revoke", "resend"].contains(&action) {
            return Err(Error::invalid("invalid invitation action"));
        }
        let mut tx = self.transaction(true, false).await?;
        Self::live_principal(&mut tx, p).await?;
        let row=one(&mut tx,"SELECT *,expires<=now() AS expired FROM workspace_invitations WHERE id=$1 AND tenant_id=$2 FOR UPDATE",args![id,tenant]).await?;
        if action == "revoke" && row["status"] == "revoked" {
            return Self::invitation_view(&mut tx, id).await;
        }
        if row["revision"] != value["expected_revision"]
            || row["status"] != "pending"
            || row["expired"] == true
        {
            return Err(conflict(
                "invitation changed or expired; refresh before continuing",
            ));
        }
        if action == "revoke" {
            exec(&mut tx,"UPDATE workspace_invitations SET status='revoked',revision=revision+1,decided_at=now() WHERE id=$1",args![id]).await?;
            exec(
                &mut tx,
                "UPDATE invitation_outbox SET state='cancelled',lease=NULL WHERE invitation_id=$1",
                args![id],
            )
            .await?;
        } else {
            if self.invitation_mailer.is_none() {
                return Err(Error::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "invitation email is not configured",
                ));
            }
            if !Self::inviter_authorized(&mut tx, &row).await? {
                return Err(conflict(
                    "inviter no longer has owner access; revoke and create a new invitation",
                ));
            }
            let outbox=one(&mut tx,"SELECT *,requested_at>now()-interval '60 seconds' AS cooling FROM invitation_outbox WHERE invitation_id=$1",args![id]).await?;
            if outbox["cooling"] == true || outbox["state"] == "sending" {
                return Err(Error::new(
                    StatusCode::TOO_MANY_REQUESTS,
                    "wait one minute before resending this invitation",
                ));
            }
            exec(&mut tx,"UPDATE invitation_outbox SET state='queued',attempts=0,available_at=now(),requested_at=now(),lease=NULL WHERE invitation_id=$1",args![id]).await?;
            exec(
                &mut tx,
                "UPDATE workspace_invitations SET revision=revision+1 WHERE id=$1",
                args![id],
            )
            .await?;
        }
        Self::audit(
            &mut tx,
            p,
            &format!("invitation.{action}"),
            id,
            tenant,
            json!({"previous_revision":row["revision"]}),
        )
        .await?;
        let result = Self::invitation_view(&mut tx, id).await?;
        tx.commit().await?;
        Ok(result)
    }
    async fn invitation_user(tx: &mut Tx, session: &Value) -> Result<Value> {
        let user=one(tx,"SELECT u.* FROM customer_users u JOIN browser_sessions s ON s.user_id=u.id WHERE s.id=$1 AND s.expires>now() AND NOT u.disabled",args![session["id"]]).await?;
        if user["email_verified"] != true || user["email"].is_null() {
            return Err(Error::new(
                StatusCode::FORBIDDEN,
                "verify your email to review invitations",
            ));
        }
        Ok(user)
    }
    async fn inviter_authorized(tx: &mut Tx, row: &Value) -> Result<bool> {
        Ok(one(tx,"SELECT EXISTS(SELECT 1 FROM workspace_memberships m JOIN customer_users u ON u.id=m.user_id WHERE m.tenant_id=$1 AND m.user_id=$2 AND m.role='owner' AND NOT m.revoked AND NOT u.disabled AND (NOT u.email_required OR u.email_verified)) AS valid",args![row["tenant_id"],row["inviter_id"]]).await?["valid"]==true)
    }
    pub(crate) async fn received_invitations(
        &self,
        session: &Value,
        id: Option<&str>,
    ) -> Result<Value> {
        let mut tx = self.transaction(false, false).await?;
        let user = Self::invitation_user(&mut tx, session).await?;
        if let Some(id) = id {
            identity(id)?;
            // Unknown and wrong-email links are indistinguishable.
            one(
                &mut tx,
                "SELECT id FROM workspace_invitations WHERE id=$1 AND email=$2",
                args![id, user["email"]],
            )
            .await?;
            return Self::invitation_view(&mut tx, id).await;
        }
        Ok(
            json!({"items":rows(&mut tx,&format!("{VIEW} WHERE i.email=$1 AND i.status='pending' AND i.expires>now() ORDER BY i.created DESC LIMIT 100"),args![user["email"]]).await?}),
        )
    }
    pub(crate) async fn decide_invitation(
        &self,
        session: &Value,
        id: &str,
        value: Value,
    ) -> Result<Value> {
        identity(id)?;
        fields(
            &value,
            &["action", "expected_revision"],
            &["action", "expected_revision"],
        )?;
        integer(&value["expected_revision"], 1, i64::MAX - 1)?;
        let status = match text(&value["action"])? {
            "accept" => "accepted",
            "decline" => "declined",
            _ => return Err(Error::invalid("choose accept or decline")),
        };
        let mut tx = self.transaction(true, false).await?;
        let user = Self::invitation_user(&mut tx, session).await?;
        let row=one(&mut tx,"SELECT *,expires<=now() AS expired FROM workspace_invitations WHERE id=$1 AND email=$2 FOR UPDATE",args![id,user["email"]]).await?;
        if row["status"] == status && row["recipient_id"] == user["id"] {
            return Self::invitation_view(&mut tx, id).await;
        }
        if row["status"] != "pending"
            || row["expired"] == true
            || row["revision"] != value["expected_revision"]
        {
            return Err(conflict(
                "invitation changed or expired; refresh before deciding",
            ));
        }
        let mut member = Value::Null;
        if status == "accepted" {
            Self::require_workspace_active(&mut tx, s(&row["tenant_id"])).await?;
            if !Self::inviter_authorized(&mut tx, &row).await? {
                return Err(conflict(
                    "inviter no longer has owner access; ask for a new invitation",
                ));
            }
            if let Some(existing)=optional(&mut tx,"SELECT * FROM workspace_memberships WHERE tenant_id=$1 AND user_id=$2 AND project_id IS NOT DISTINCT FROM $3",args![row["tenant_id"],user["id"],row["project_id"]]).await? {
                // Old/replayed invitations never reactivate revoked access or replace roles.
                if existing["revoked"]==true || existing["role"]!=row["role"] { return Err(conflict("access already exists with different settings; ask an owner to review it")); }
                member=existing["id"].clone();
            } else {
                member=json!(uid());
                exec(&mut tx,"INSERT INTO workspace_memberships(id,tenant_id,user_id,project_id,role) VALUES($1,$2,$3,$4,$5)",args![member,row["tenant_id"],user["id"],row["project_id"],row["role"]]).await?;
            }
        }
        exec(&mut tx,"UPDATE workspace_invitations SET status=$2,recipient_id=$3,membership_id=$4,revision=revision+1,decided_at=now() WHERE id=$1",args![id,status,user["id"],member]).await?;
        exec(&mut tx,"UPDATE invitation_outbox SET state='cancelled',lease=NULL WHERE invitation_id=$1 AND state<>'sent'",args![id]).await?;
        Self::audit_system(
            &mut tx,
            s(&user["id"]),
            &format!("invitation.{status}"),
            &json!(id),
            &row["tenant_id"],
            json!({"membership_id":member,"role":row["role"],"project_id":row["project_id"]}),
        )
        .await?;
        let result = Self::invitation_view(&mut tx, id).await?;
        tx.commit().await?;
        Ok(result)
    }
    /// At-least-once mail delivery: an uncertain SMTP outcome can repeat the same
    /// message/link. It cannot repeat a membership decision or create a workspace.
    pub async fn deliver_invitation_email(&self) -> Result<()> {
        let Some(mailer) = &self.invitation_mailer else {
            return Ok(());
        };
        let mut tx = self.transaction(true, false).await?;
        let Some(row)=optional(&mut tx,"SELECT i.*,t.display_name AS workspace_name,p.display_name AS project_name FROM invitation_outbox o JOIN workspace_invitations i ON i.id=o.invitation_id JOIN tenants t ON t.id=i.tenant_id LEFT JOIN projects p ON p.id=i.project_id WHERE o.state IN ('queued','sending') AND o.available_at<=now() ORDER BY o.available_at,i.id LIMIT 1 FOR UPDATE OF o SKIP LOCKED",args![]).await? else {return Ok(())};
        let id = s(&row["id"]);
        if row["status"] != "pending"
            || !Self::inviter_authorized(&mut tx, &row).await?
            || one(
                &mut tx,
                "SELECT expires<=now() AS expired FROM workspace_invitations WHERE id=$1",
                args![id],
            )
            .await?["expired"]
                == true
        {
            exec(
                &mut tx,
                "UPDATE invitation_outbox SET state='cancelled',lease=NULL WHERE invitation_id=$1",
                args![id],
            )
            .await?;
            tx.commit().await?;
            return Ok(());
        }
        let lease = uid();
        exec(&mut tx,"UPDATE invitation_outbox SET state='sending',attempts=attempts+1,lease=$2,available_at=now()+interval '2 minutes' WHERE invitation_id=$1",args![id,lease]).await?;
        tx.commit().await?;
        let delivered = mailer
            .send(
                id,
                s(&row["email"]),
                s(&row["workspace_name"]),
                s(&row["role"]),
                row["project_name"].as_str().unwrap_or("Entire workspace"),
            )
            .await
            .is_ok();
        let mut tx = self.transaction(true, false).await?;
        exec(&mut tx,"UPDATE invitation_outbox SET state=CASE WHEN $3 THEN 'sent' WHEN attempts>=5 THEN 'failed' ELSE 'queued' END,sent_at=CASE WHEN $3 THEN now() ELSE sent_at END,available_at=now()+interval '1 minute',lease=NULL WHERE invitation_id=$1 AND lease=$2",args![id,lease,delivered]).await?;
        tx.commit().await?;
        Ok(())
    }
}
