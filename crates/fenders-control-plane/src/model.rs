use crate::error::{Error, Result};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
// Node-shared identities, digests and limits live in the protocol crate.
pub use fenders_node_protocol::model::*;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Operator,
    Owner,
    Editor,
    Viewer,
}
impl Role {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Operator => "operator",
            Self::Owner => "owner",
            Self::Editor => "editor",
            Self::Viewer => "viewer",
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Principal {
    pub id: String,
    pub role: Role,
    pub tenant_id: Option<String>,
    pub project_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub membership_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_permissions: Option<Vec<String>>,
}
impl Principal {
    pub fn operator(&self) -> Result<()> {
        if self.role != Role::Operator {
            return Err(Error::new(StatusCode::FORBIDDEN, "operator required"));
        }
        Ok(())
    }
    pub fn scope(
        &self,
        tenant: &str,
        project: Option<&str>,
        write: bool,
        owner: bool,
    ) -> Result<()> {
        identity(tenant)?;
        if let Some(project) = project {
            identity(project)?;
        }
        if self.role == Role::Operator {
            return Ok(());
        }
        if self.tenant_id.as_deref() != Some(tenant)
            || self.project_id.is_some() && self.project_id.as_deref() != project
        {
            return Err(Error::missing());
        }
        if owner && (self.role != Role::Owner || self.project_id.is_some()) {
            return Err(Error::new(StatusCode::FORBIDDEN, "tenant owner required"));
        }
        if write && self.role == Role::Viewer {
            return Err(Error::new(StatusCode::FORBIDDEN, "read-only credential"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Allowance {
    pub cpu_percent: i64,
    pub memory_mib: i64,
    pub storage_bytes: i64,
    pub instances: i32,
    pub transfer_bytes: i64,
}
impl Allowance {
    pub fn validate(&self) -> Result<()> {
        if !(1..=1_000_000).contains(&self.cpu_percent)
            || !(88..=100_000_000).contains(&self.memory_mib)
            || !(1024..=1_000_000_000_000_000).contains(&self.storage_bytes)
            || !(1..=100_000).contains(&self.instances)
            || !(1024..=1_000_000_000_000_000).contains(&self.transfer_bytes)
        {
            return Err(Error::invalid("allowance outside supported bounds"));
        }
        Ok(())
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateTenant {
    pub name: String,
    pub allowance: Allowance,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateAllowance {
    pub allowance: Allowance,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Named {
    pub name: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssueCredential {
    pub name: String,
    pub role: Role,
    pub project_id: Option<String>,
    #[serde(default = "default_ttl")]
    pub ttl_seconds: i64,
}
fn default_ttl() -> i64 {
    86400
}
