//! Narrow workspace-scoped revocation for the private operator bridge.
use crate::{
    args,
    db::*,
    error::{Error, Result},
    model::{fingerprint, identity},
    operator_admission::{receipt, remember},
    store::Store,
};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RevokeAccess {
    id: String,
    target_id: String,
    kind: String,
    request_key: String,
    reason: String,
    #[serde(default)]
    expected_revision: Option<i64>,
}

impl Store {
    pub(crate) async fn operator_revoke_access(
        &self,
        actor: &str,
        input: RevokeAccess,
    ) -> Result<Value> {
        identity(&input.id)?;
        identity(&input.target_id)?;
        identity(&input.request_key)?;
        if input.reason.trim().is_empty()
            || input.reason.len() > 500
            || !matches!(input.kind.as_str(), "member" | "credential")
            || (input.kind == "member"
                && !input
                    .expected_revision
                    .is_some_and(|r| r > 0 && r < i64::MAX))
            || (input.kind == "credential" && input.expected_revision.is_some())
        {
            return Err(Error::invalid("invalid scoped revocation"));
        }
        let hash = fingerprint(&json!({"action":"workspaces.revoke_access","input":input}));
        // Same admission lock as customer membership/key writers and live_principal.
        let mut tx = self.transaction(true, false).await?;
        if let Some(saved) = receipt(&mut tx, actor, &input.request_key, &hash).await? {
            return Ok(saved);
        }
        let before = if input.kind == "member" {
            one(&mut tx,"SELECT id,user_id,project_id,role,revision,revoked FROM workspace_memberships WHERE tenant_id=$1 AND id=$2",args![input.id,input.target_id]).await?
        } else {
            one(&mut tx,"SELECT id,name,project_id,role,revoked FROM credentials WHERE tenant_id=$1 AND id=$2",args![input.id,input.target_id]).await?
        };
        if before["revoked"] == true {
            return Err(Error::new(
                StatusCode::CONFLICT,
                "access is already revoked; refresh before editing",
            ));
        }
        let mut after = before.clone();
        if input.kind == "member" {
            let row = Self::update_membership_in_tx(
                &mut tx,
                &input.id,
                &input.target_id,
                &json!({"expected_revision":input.expected_revision,"revoked":true}),
            )
            .await?;
            after["revision"] = row["revision"].clone();
        } else {
            Self::revoke_credential_in_tx(&mut tx, &input.id, &input.target_id).await?;
        }
        after["revoked"] = json!(true);
        let audit=one(&mut tx,"INSERT INTO audit(tenant_id,actor,action,resource_id,detail) VALUES($1,$2,'operator.access_revoke',$3,$4) RETURNING sequence,created",args![input.id,format!("operator:{actor}"),input.target_id,json!({"kind":input.kind,"reason":input.reason.trim(),"before":before,"after":after,"request_key":input.request_key})]).await?;
        let response = json!({"id":input.id,"target_id":input.target_id,"kind":input.kind,"revoked":true,"audit":audit});
        remember(
            &mut tx,
            actor,
            &input.request_key,
            Some(&input.id),
            &hash,
            &response,
        )
        .await?;
        tx.commit().await?;
        Ok(response)
    }
}
