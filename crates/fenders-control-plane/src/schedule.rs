//! Schedule previews. Cron evaluation itself is shared with nodes.
use crate::error::{Error, Result};
use crate::{model::Principal, store::Store};
use chrono::{DateTime, Utc};
pub use fenders_node_protocol::schedule::*;
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchedulePreview {
    pub expression: String,
    pub timezone: String,
    pub after: Option<String>,
}

impl Store {
    pub async fn preview_schedule(
        &self,
        p: &Principal,
        tenant: &str,
        project: &str,
        value: SchedulePreview,
    ) -> Result<Value> {
        let mut tx = self.transaction(false, false).await?;
        Self::project(&mut tx, p, tenant, project, false).await?;
        let after = match value.after {
            Some(v) if v.len() <= 40 => DateTime::parse_from_rfc3339(&v)
                .map_err(|_| Error::invalid("after must be an RFC3339 timestamp"))?
                .with_timezone(&Utc),
            Some(_) => return Err(Error::invalid("after timestamp too long")),
            None => DateTime::<Utc>::from(std::time::SystemTime::now()),
        };
        let schedule = Schedule::parse(&value.expression, &value.timezone)?;
        let occurrences = schedule.next(after, 5)?;
        Ok(
            json!({"expression":schedule.expression,"timezone":schedule.timezone.name(),"timezone_database":chrono_tz::IANA_TZDB_VERSION,
            "occurrences":occurrences.iter().map(|t|json!({"utc":t.to_rfc3339(),"local":t.with_timezone(&schedule.timezone).to_rfc3339()})).collect::<Vec<_>>() }),
        )
    }
}
