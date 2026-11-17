//! Customer workspace settings and project naming, using existing tenant scope.
use crate::{
    error::{Error, Result},
    model::Principal,
    store::Store,
};
use axum::http::StatusCode;
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceSettings {
    pub display_name: String,
    pub default_app_size: String,
    pub expected_revision: i64,
}

pub(crate) fn project_name(value: &str) -> Result<(String, String)> {
    let display = value.trim();
    if !(2..=40).contains(&display.chars().count()) || display.chars().any(char::is_control) {
        return Err(Error::invalid(
            "project name must contain 2–40 printable characters",
        ));
    }
    let mut slug = String::new();
    for c in display.chars() {
        if c.is_ascii_alphanumeric() {
            slug.push(c.to_ascii_lowercase());
        } else if !slug.is_empty() && !slug.ends_with('-') {
            slug.push('-');
        }
    }
    let slug = slug.trim_end_matches('-').to_owned();
    if slug.is_empty() {
        return Err(Error::invalid(
            "project name must contain an ASCII letter or number",
        ));
    }
    Ok((display.to_owned(), slug))
}

impl Store {
    pub async fn workspace_settings(&self, p: &Principal, tenant: &str) -> Result<Value> {
        p.scope(tenant, None, false, false)?;
        let mut tx = self.transaction(false, false).await?;
        Self::live_principal(&mut tx, p).await?;
        sqlx::query_scalar::<_,Value>("SELECT jsonb_build_object('display_name',display_name,'default_app_size',default_app_size,'revision',settings_revision) FROM tenants WHERE id=$1")
            .bind(tenant).fetch_optional(&mut *tx).await?.ok_or_else(Error::missing)
    }

    pub async fn update_workspace_settings(
        &self,
        p: &Principal,
        tenant: &str,
        value: WorkspaceSettings,
    ) -> Result<Value> {
        p.scope(tenant, None, true, true)?;
        let display = value.display_name.trim();
        if !(1..=60).contains(&display.chars().count()) || display.chars().any(char::is_control) {
            return Err(Error::invalid(
                "workspace display name must contain 1–60 printable characters",
            ));
        }
        if !matches!(
            value.default_app_size.as_str(),
            "small" | "medium" | "large"
        ) || value.expected_revision < 1
        {
            return Err(Error::invalid("invalid default size or settings revision"));
        }
        let mut tx = self.transaction(true, false).await?;
        Self::live_principal(&mut tx, p).await?;
        let current = sqlx::query_scalar::<_, i64>(
            "SELECT settings_revision FROM tenants WHERE id=$1 FOR UPDATE",
        )
        .bind(tenant)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(Error::missing)?;
        if current != value.expected_revision {
            return Err(Error::new(
                StatusCode::CONFLICT,
                "workspace settings changed; reload before saving",
            ));
        }
        let row = sqlx::query_scalar::<_,Value>("UPDATE tenants SET display_name=$2,default_app_size=$3,settings_revision=settings_revision+1 WHERE id=$1 RETURNING jsonb_build_object('display_name',display_name,'default_app_size',default_app_size,'revision',settings_revision)")
            .bind(tenant).bind(display).bind(&value.default_app_size).fetch_one(&mut *tx).await?;
        Self::audit(
            &mut tx,
            p,
            "workspace.settings",
            tenant,
            tenant,
            json!({"revision":current+1}),
        )
        .await?;
        tx.commit().await?;
        Ok(row)
    }
}
