use crate::error::{Error, Result};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
// Node-shared identities, digests and limits live in the protocol crate.
pub use fenders_node_protocol::model::*;

/// Whose a credential is. The operator's creates tenants and their keys; a
/// tenant's key does what its permissions say, within its tenant and, when
/// it names one, its project. There are no other kinds: who a person is and
/// what role they hold is the business of whatever is built on this API,
/// which issues keys with the permissions it has decided on.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Operator,
    Key,
}
impl Role {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Operator => "operator",
            Self::Key => "key",
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
        operator: bool,
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
        // What is the operator's alone: a tenant's keys and its settings.
        if operator {
            return Err(Error::new(StatusCode::FORBIDDEN, "operator required"));
        }
        // Beside the table of what each route takes (customer_api): a key
        // that may change nothing changes nothing, however it is asked.
        if write
            && !self
                .api_permissions
                .as_ref()
                .is_some_and(|held| held.iter().any(|v| v.ends_with(":write")))
        {
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
