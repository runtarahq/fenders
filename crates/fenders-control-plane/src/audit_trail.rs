//! Reading the audit trail.
//!
//! Every change leaves a record: who made it, what it was, of what, and
//! when. The operator reads any workspace's. A workspace's key reads its
//! own workspace's, so that a product built on this can show its users what
//! was done in their name: the label a key was issued with is on each
//! record the key made.
use crate::{
    error::{Error, Result},
    model::{Principal, Role},
    store::Store,
};
use serde_json::{Value, json};

/// A record's project, and the index a workspace's trail is read by.
pub(crate) const MIGRATION: &str = "
ALTER TABLE audit ADD COLUMN IF NOT EXISTS project_id text;
CREATE INDEX IF NOT EXISTS audit_workspace_trail ON audit(tenant_id, sequence DESC);
";

/// Which records are asked for. A trail is read newest first, as every list
/// is; `before` is the `next` of the page before.
#[derive(Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditPage {
    pub before: Option<String>,
    pub limit: Option<i64>,
    /// Records of this action alone, as `app.create`.
    pub action: Option<String>,
    /// Records made by keys issued with this label.
    pub actor_label: Option<String>,
    /// Records made at or after this time.
    pub since: Option<String>,
    /// Records made before this time.
    pub until: Option<String>,
}

/// A time a caller gave, as text PostgreSQL reads the same way.
fn time(given: &Option<String>) -> Result<Option<String>> {
    given
        .as_deref()
        .map(|text| {
            chrono::DateTime::parse_from_rfc3339(text)
                .map(|time| time.to_rfc3339())
                .map_err(|_| Error::invalid("since and until are RFC 3339 times"))
        })
        .transpose()
}

impl Store {
    pub async fn audit_trail(&self, p: &Principal, tenant: &str, page: AuditPage) -> Result<Value> {
        // A key of one project reads what was done in that project.
        p.scope(tenant, p.project_id.as_deref(), false, false)?;
        let limit = page.limit.unwrap_or(100);
        if !(1..=100).contains(&limit) {
            return Err(Error::invalid("page limit must be between 1 and 100"));
        }
        let before = page
            .before
            .as_deref()
            .map(|cursor| {
                cursor
                    .parse::<i64>()
                    .ok()
                    .filter(|sequence| *sequence > 0)
                    .ok_or_else(|| Error::invalid("invalid page cursor"))
            })
            .transpose()?;
        for text in [&page.action, &page.actor_label].into_iter().flatten() {
            if text.is_empty() || text.len() > 128 || text.chars().any(char::is_control) {
                return Err(Error::invalid("invalid audit filter"));
            }
        }
        let (since, until) = (time(&page.since)?, time(&page.until)?);
        let mut tx = self.transaction(false, false).await?;
        Self::live_principal(&mut tx, p).await?;
        let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM tenants WHERE id=$1)")
            .bind(tenant)
            .fetch_one(&mut *tx)
            .await?;
        if !exists {
            return Err(Error::missing());
        }
        // What a record says to a key depends on whose it is. A record one
        // of the workspace's own keys made is shown whole. One the operator
        // or the control plane made is shown as having happened, and when,
        // and of what: who exactly, and the detail (the reason of a
        // suspension among it), are the operator's.
        let mut items: Vec<Value> = sqlx::query_scalar(
            "SELECT jsonb_build_object(
                'sequence',a.sequence,'created',a.created,'action',a.action,
                'resource_id',a.resource_id,'project_id',a.project_id,
                'actor',CASE WHEN $2 OR own.id IS NOT NULL THEN a.actor
                    WHEN operators.id IS NOT NULL OR a.actor LIKE 'operator:%' THEN 'operator'
                    ELSE 'control-plane' END,
                'actor_label',CASE WHEN $2 OR own.id IS NOT NULL THEN a.actor_label END,
                'detail',CASE WHEN $2 OR own.id IS NOT NULL THEN a.detail END)
             FROM audit a
             LEFT JOIN credentials own ON own.id=a.actor AND own.tenant_id=a.tenant_id AND own.role='key'
             LEFT JOIN credentials operators ON operators.id=a.actor AND operators.role='operator'
             WHERE a.tenant_id=$1
               AND ($3::text IS NULL OR a.project_id=$3)
               AND ($4::bigint IS NULL OR a.sequence<$4)
               AND ($5::text IS NULL OR a.action=$5)
               AND ($6::text IS NULL OR (a.actor_label=$6 AND ($2 OR own.id IS NOT NULL)))
               AND ($7::text IS NULL OR a.created>=$7::timestamptz)
               AND ($8::text IS NULL OR a.created<$8::timestamptz)
             ORDER BY a.sequence DESC LIMIT $9",
        )
        .bind(tenant)
        .bind(p.role == Role::Operator)
        .bind(&p.project_id)
        .bind(before)
        .bind(&page.action)
        .bind(&page.actor_label)
        .bind(since)
        .bind(until)
        .bind(limit + 1)
        .fetch_all(&mut *tx)
        .await?;
        let more = items.len() > limit as usize;
        items.truncate(limit as usize);
        let next = match (more, items.last()) {
            (true, Some(last)) => json!(last["sequence"].to_string()),
            _ => Value::Null,
        };
        Ok(json!({"items":items,"next":next}))
    }
}
