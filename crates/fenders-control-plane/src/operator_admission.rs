//! Operator-reviewed admission uses the authoritative platform transaction.
//! Only the private mTLS bridge exposes decisions and policy edits.
use crate::{
    args,
    db::*,
    error::{Error, Result},
    model::{Allowance, fingerprint, identity, uid},
    store::{Store, Tx},
};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub(crate) const MIGRATION: &str = "
CREATE TABLE IF NOT EXISTS admission_policy (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 mode text NOT NULL CHECK(mode IN ('closed','approval','automatic')),
 revision bigint NOT NULL DEFAULT 1, max_workspaces bigint NOT NULL CHECK(max_workspaces>0),
 allowance jsonb NOT NULL);
INSERT INTO admission_policy(singleton,mode,max_workspaces,allowance)
 VALUES(true,'closed',10,'{\"cpu_percent\":100,\"memory_mib\":128,\"instances\":1,\"storage_bytes\":1073741824,\"transfer_bytes\":1073741824}')
 ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS admission_requests (
 id text PRIMARY KEY, user_id text NOT NULL UNIQUE REFERENCES customer_users(id),
 email text NOT NULL, status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','declined')),
 revision bigint NOT NULL DEFAULT 1, reason text, workspace_id text REFERENCES tenants(id),
 created timestamptz NOT NULL DEFAULT now(), updated timestamptz NOT NULL DEFAULT now(),
 CHECK ((status='approved')=(workspace_id IS NOT NULL)));
ALTER TABLE operator_request_receipts ALTER COLUMN tenant_id DROP NOT NULL;
";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EditPolicy {
    request_key: String,
    expected_revision: i64,
    reason: String,
    mode: String,
    max_workspaces: i64,
    allowance: Allowance,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Decision {
    id: String,
    request_key: String,
    expected_revision: i64,
    expected_policy_revision: i64,
    action: String,
    reason: String,
    #[serde(default)]
    allowance: Option<Allowance>,
}
fn conflict(message: &'static str) -> Error {
    Error::new(StatusCode::CONFLICT, message)
}
fn reason(value: &str) -> Result<()> {
    if value.trim().is_empty() || value.len() > 500 {
        return Err(Error::invalid("a reason is required"));
    }
    Ok(())
}
pub(crate) async fn receipt(
    tx: &mut Tx,
    actor: &str,
    key: &str,
    hash: &str,
) -> Result<Option<Value>> {
    if let Some(row)=optional(tx,"SELECT request_hash,response FROM operator_request_receipts WHERE actor=$1 AND request_key=$2",args![actor,key]).await? {
        if row["request_hash"] != hash { return Err(conflict("idempotency key has different arguments")); }
        return Ok(Some(row["response"].clone()));
    }
    Ok(None)
}
pub(crate) async fn remember(
    tx: &mut Tx,
    actor: &str,
    key: &str,
    tenant: Option<&str>,
    hash: &str,
    response: &Value,
) -> Result<()> {
    exec(tx,"INSERT INTO operator_request_receipts(actor,request_key,tenant_id,request_hash,response) VALUES($1,$2,$3,$4,$5)",args![actor,key,tenant,hash,response]).await?;
    Ok(())
}
const REQUEST: &str = "SELECT r.id,r.email,u.display_name,u.email_verified,u.disabled,r.status,r.revision,r.reason,r.workspace_id,r.created,r.updated FROM admission_requests r JOIN customer_users u ON u.id=r.user_id";
impl Store {
    pub(crate) async fn admission_status(tx: &mut Tx, user: &Value) -> Result<Value> {
        let policy = one(
            tx,
            "SELECT mode FROM admission_policy WHERE singleton",
            args![],
        )
        .await?;
        let request = optional(
            tx,
            "SELECT status,reason,workspace_id FROM admission_requests WHERE user_id=$1",
            args![user["id"]],
        )
        .await?;
        Ok(
            json!({"policy":policy["mode"],"status":request.as_ref().map(|r|r["status"].clone()).unwrap_or_else(||json!(if policy["mode"]=="closed" {"closed"} else {"eligible"})),"reason":request.as_ref().map(|r|r["reason"].clone())}),
        )
    }
    pub(crate) async fn queue_admission(tx: &mut Tx, user: &Value) -> Result<()> {
        // A refreshed verified email invalidates an operator's stale decision.
        let previous = optional(
            tx,
            "SELECT id FROM admission_requests WHERE user_id=$1",
            args![user["id"]],
        )
        .await?;
        exec(tx,"INSERT INTO admission_requests(id,user_id,email) VALUES($1,$2,$3) ON CONFLICT(user_id) DO UPDATE SET email=excluded.email,revision=admission_requests.revision+1,updated=now() WHERE admission_requests.status='pending' AND admission_requests.email<>excluded.email",args![uid(),user["id"],user["email"]]).await?;
        if previous.is_none() {
            Self::audit_system(
                tx,
                s(&user["id"]),
                "customer.access_requested",
                &user["id"],
                &Value::Null,
                json!({}),
            )
            .await?;
        }
        Ok(())
    }
    pub(crate) async fn operator_policy(&self) -> Result<Value> {
        let mut tx = self.snapshot().await?;
        let policy = one(
            &mut tx,
            "SELECT mode,revision,max_workspaces,allowance FROM admission_policy WHERE singleton",
            args![],
        )
        .await?;
        let used = one(
            &mut tx,
            "SELECT count(*) AS n FROM customer_users WHERE onboarded_workspace_id IS NOT NULL",
            args![],
        )
        .await?;
        Ok(json!({"policy":policy,"admitted_workspaces":used["n"]}))
    }
    pub(crate) async fn operator_edit_policy(
        &self,
        actor: &str,
        input: EditPolicy,
    ) -> Result<Value> {
        identity(&input.request_key)?;
        reason(&input.reason)?;
        input.allowance.validate()?;
        // Automatic admission remains a preserved future mode, unavailable here.
        if !matches!(input.mode.as_str(), "closed" | "approval")
            || !(1..=100000).contains(&input.max_workspaces)
        {
            return Err(Error::invalid("invalid admission policy"));
        }
        let hash = fingerprint(&json!({"action":"admission.policy","input":input}));
        let mut tx = self.transaction(true, false).await?;
        if let Some(saved) = receipt(&mut tx, actor, &input.request_key, &hash).await? {
            return Ok(saved);
        }
        let before=one(&mut tx,"SELECT mode,revision,max_workspaces,allowance FROM admission_policy WHERE singleton FOR UPDATE",args![]).await?;
        if before["revision"] != input.expected_revision {
            return Err(conflict("admission policy changed; refresh before editing"));
        }
        let used = one(
            &mut tx,
            "SELECT count(*) AS n FROM customer_users WHERE onboarded_workspace_id IS NOT NULL",
            args![],
        )
        .await?;
        if n(&used["n"]) > input.max_workspaces {
            return Err(conflict("admission cap is below admitted workspaces"));
        }
        let after=one(&mut tx,"UPDATE admission_policy SET mode=$1,max_workspaces=$2,allowance=$3,revision=revision+1 WHERE singleton RETURNING mode,revision,max_workspaces,allowance",args![input.mode,input.max_workspaces,json!(input.allowance)]).await?;
        let audit=one(&mut tx,"INSERT INTO audit(actor,action,resource_id,detail) VALUES($1,'operator.admission_policy','admission',$2) RETURNING sequence,created",args![format!("operator:{actor}"),json!({"reason":input.reason.trim(),"before":before,"after":after,"request_key":input.request_key})]).await?;
        let response = json!({"policy":after,"audit":audit});
        remember(&mut tx, actor, &input.request_key, None, &hash, &response).await?;
        tx.commit().await?;
        Ok(response)
    }
    pub(crate) async fn operator_requests(&self, status: &str, offset: i64) -> Result<Value> {
        if !matches!(status, "pending" | "approved" | "declined") || !(0..=100000).contains(&offset)
        {
            return Err(Error::invalid("invalid access request search"));
        }
        let mut tx = self.snapshot().await?;
        let items = rows(
            &mut tx,
            &format!("{REQUEST} WHERE r.status=$1 ORDER BY r.created,r.id LIMIT 25 OFFSET $2"),
            args![status, offset],
        )
        .await?;
        let total = one(
            &mut tx,
            "SELECT count(*) AS n FROM admission_requests WHERE status=$1",
            args![status],
        )
        .await?;
        Ok(json!({"items":items,"total":total["n"]}))
    }
    pub(crate) async fn operator_request(&self, id: &str) -> Result<Value> {
        identity(id)?;
        let mut tx = self.snapshot().await?;
        let request = optional(&mut tx, &format!("{REQUEST} WHERE r.id=$1"), args![id])
            .await?
            .ok_or_else(Error::missing)?;
        let policy = one(
            &mut tx,
            "SELECT mode,revision,max_workspaces,allowance FROM admission_policy WHERE singleton",
            args![],
        )
        .await?;
        Ok(json!({"request":request,"policy":policy}))
    }
    pub(crate) async fn operator_decide(&self, actor: &str, input: Decision) -> Result<Value> {
        identity(&input.id)?;
        identity(&input.request_key)?;
        reason(&input.reason)?;
        if !matches!(input.action.as_str(), "approve" | "decline")
            || (input.action == "approve") != input.allowance.is_some()
        {
            return Err(Error::invalid("choose approve with allowance or decline"));
        }
        if let Some(allowance) = &input.allowance {
            allowance.validate()?;
        }
        let hash = fingerprint(&json!({"action":"admission.decide","input":input}));
        let mut tx = self.transaction(true, false).await?;
        if let Some(saved) = receipt(&mut tx, actor, &input.request_key, &hash).await? {
            return Ok(saved);
        }
        let before = optional(
            &mut tx,
            "SELECT * FROM admission_requests WHERE id=$1 FOR UPDATE",
            args![input.id],
        )
        .await?
        .ok_or_else(Error::missing)?;
        if before["revision"] != input.expected_revision || before["status"] != "pending" {
            return Err(conflict("access request changed; refresh before deciding"));
        }
        let policy = one(
            &mut tx,
            "SELECT * FROM admission_policy WHERE singleton FOR UPDATE",
            args![],
        )
        .await?;
        if policy["revision"] != input.expected_policy_revision {
            return Err(conflict("admission policy changed; refresh before editing"));
        }
        let mut workspace_id = None;
        if let Some(allowance) = &input.allowance {
            if policy["mode"] != "approval" {
                return Err(conflict("workspace admission is closed"));
            }
            let user = one(
                &mut tx,
                "SELECT * FROM customer_users WHERE id=$1 FOR UPDATE",
                args![before["user_id"]],
            )
            .await?;
            if user["disabled"] == true
                || user["email_verified"] != true
                || user["email"] != before["email"]
                || user["onboarding_required"] != true
                || !user["onboarded_workspace_id"].is_null()
            {
                return Err(conflict("requester is not eligible for admission"));
            }
            let used = one(
                &mut tx,
                "SELECT count(*) AS n FROM customer_users WHERE onboarded_workspace_id IS NOT NULL",
                args![],
            )
            .await?;
            if n(&used["n"]) >= n(&policy["max_workspaces"]) {
                return Err(conflict("workspace admission cap reached"));
            }
            workspace_id = Some(Self::provision_home_workspace(&mut tx, &user, allowance).await?);
        }
        let state = if workspace_id.is_some() {
            "approved"
        } else {
            "declined"
        };
        exec(&mut tx,"UPDATE admission_requests SET status=$2,revision=revision+1,reason=$3,workspace_id=$4,updated=now() WHERE id=$1",args![input.id,state,input.reason.trim(),workspace_id]).await?;
        let audit=one(&mut tx,"INSERT INTO audit(tenant_id,actor,action,resource_id,detail) VALUES($1,$2,'operator.admission_decision',$3,$4) RETURNING sequence,created",args![workspace_id,format!("operator:{actor}"),input.id,json!({"reason":input.reason.trim(),"before":"pending","after":state,"allowance":input.allowance,"request_key":input.request_key})]).await?;
        let response = json!({"id":input.id,"status":state,"revision":input.expected_revision+1,"workspace_id":workspace_id,"audit":audit});
        remember(
            &mut tx,
            actor,
            &input.request_key,
            workspace_id.as_deref(),
            &hash,
            &response,
        )
        .await?;
        tx.commit().await?;
        Ok(response)
    }
}
