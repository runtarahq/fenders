//! Scoped app history: lifecycle observations interleaved with invocations.
//! No specs, configuration, actor identities or free-form worker messages are
//! copied into this customer history.
use crate::{
    args,
    db::*,
    error::{Error, Result},
    model::{Principal, identity},
    store::{Store, Tx},
};
use serde_json::{Value, json};

#[derive(Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventPage {
    pub before: Option<String>,
    pub limit: Option<i64>,
    pub release_id: Option<String>,
    pub run_id: Option<String>,
    pub execution_id: Option<String>,
    /// `lifecycle` lists only recorded transitions; `http`, `manual` and
    /// `schedule` list only invocations of that trigger.
    #[serde(rename = "type")]
    pub entry_type: Option<String>,
}

/// One timeline over retained lifecycle events and invocation records. Each
/// invocation is one entry; its command admission and execution transitions
/// are shown only for the lifecycle type or an explicit release, run or
/// execution filter, which narrow the history to recorded transitions.
const ENTRIES: &str = "SELECT 'lifecycle'::text AS entry,e.id,e.recorded_at AS at FROM app_lifecycle_events e WHERE e.tenant_id=$1 AND e.project_id=$2 AND e.app_id=$3 AND e.recorded_at>=now()-interval '30 days' AND $4 IN ('','lifecycle') AND ($4='lifecycle' OR $8 OR e.run_id IS NULL) AND ($5::text IS NULL OR e.release_id=$5) AND ($6::text IS NULL OR e.run_id=$6) AND ($7::text IS NULL OR e.execution_id=$7)
 UNION ALL SELECT 'run',r.id,COALESCE(r.scheduled_at,r.created) FROM customer_app_runs r WHERE r.tenant_id=$1 AND r.project_id=$2 AND r.app_id=$3 AND NOT $8 AND ($4='' OR r.source=$4 OR $4='schedule' AND r.source='test-schedule') AND $4<>'lifecycle'";

impl Store {
    pub async fn app_events(
        &self,
        p: &Principal,
        tenant: &str,
        project: &str,
        app: &str,
        page: EventPage,
    ) -> Result<Value> {
        let limit = page.limit.unwrap_or(50);
        if !(1..=100).contains(&limit) {
            return Err(Error::invalid("event page limit must be between 1 and 100"));
        }
        for id in [
            &page.before,
            &page.release_id,
            &page.run_id,
            &page.execution_id,
        ]
        .into_iter()
        .flatten()
        {
            identity(id)?;
        }
        let mut tx = self.snapshot().await?;
        Self::project(&mut tx, p, tenant, project, false).await?;
        Self::app_row(&mut tx, tenant, project, app).await?;
        if let Some(id) = &page.release_id {
            one(&mut tx,"SELECT id FROM app_releases WHERE tenant_id=$1 AND project_id=$2 AND app_id=$3 AND id=$4",args![tenant,project,app,id]).await?;
        }
        if let Some(id) = &page.run_id {
            one(&mut tx,"SELECT id FROM app_runs WHERE tenant_id=$1 AND project_id=$2 AND app_id=$3 AND id=$4",args![tenant,project,app,id]).await?;
        }
        if let Some(id) = &page.execution_id {
            one(&mut tx,"SELECT execution_id FROM app_execution_contexts WHERE tenant_id=$1 AND project_id=$2 AND app_id=$3 AND execution_id=$4",args![tenant,project,app,id]).await?;
        }
        let entry_type = page.entry_type.as_deref().unwrap_or("");
        if !matches!(
            entry_type,
            "" | "lifecycle" | "http" | "manual" | "schedule"
        ) {
            return Err(Error::invalid("unsupported event type filter"));
        }
        let narrowed =
            page.release_id.is_some() || page.run_id.is_some() || page.execution_id.is_some();
        // Record filters already select recorded transitions only.
        let entry_type = if narrowed { "" } else { entry_type };
        let cursor = if let Some(id) = &page.before {
            one(
                &mut tx,
                &format!("SELECT at,id FROM ({ENTRIES}) t WHERE id=$9"),
                args![
                    tenant,
                    project,
                    app,
                    entry_type,
                    page.release_id,
                    page.run_id,
                    page.execution_id,
                    narrowed,
                    id
                ],
            )
            .await?
        } else {
            Value::Null
        };
        let mut entries=rows(&mut tx,&format!("SELECT entry,id FROM ({ENTRIES}) t WHERE $9::timestamptz IS NULL OR (at,id)<($9::timestamptz,$10) ORDER BY at DESC,id DESC LIMIT $11"),args![tenant,project,app,entry_type,page.release_id,page.run_id,page.execution_id,narrowed,cursor["at"],cursor["id"],limit+1]).await?;
        let more = entries.len() > limit as usize;
        entries.truncate(limit as usize);
        let ids = |kind: &str| -> Vec<Value> {
            entries
                .iter()
                .filter(|e| e["entry"] == kind)
                .map(|e| e["id"].clone())
                .collect()
        };
        let lifecycle=rows(&mut tx,"SELECT 'lifecycle' AS entry,id,recorded_at,kind,state,previous_state,release_id,version,run_id,execution_id,source,desired,previous_desired,generation,reserved,outcome,exit_code FROM app_lifecycle_events WHERE tenant_id=$1 AND project_id=$2 AND app_id=$3 AND id=ANY(ARRAY(SELECT jsonb_array_elements_text($4)))",args![tenant,project,app,ids("lifecycle")]).await?;
        let mut runs=rows(&mut tx,"SELECT 'run' AS entry,r.* FROM customer_app_runs r WHERE tenant_id=$1 AND project_id=$2 AND app_id=$3 AND id=ANY(ARRAY(SELECT jsonb_array_elements_text($4)))",args![tenant,project,app,ids("run")]).await?;
        crate::placement::project(&mut tx, tenant, project, &mut runs).await?;
        // Each invocation carries its first 32 retained command admission and
        // execution transitions (a run records far fewer); HTTP requests have none.
        let transitions=rows(&mut tx,"SELECT id,recorded_at,kind,state,previous_state,release_id,version,run_id,execution_id,source,desired,previous_desired,generation,reserved,outcome,exit_code FROM (SELECT e.*,row_number() OVER (PARTITION BY run_id ORDER BY recorded_at,id) AS n FROM app_lifecycle_events e WHERE tenant_id=$1 AND project_id=$2 AND app_id=$3 AND recorded_at>=now()-interval '30 days' AND run_id=ANY(ARRAY(SELECT jsonb_array_elements_text($4)))) t WHERE n<=32 ORDER BY recorded_at,id",args![tenant,project,app,ids("run")]).await?;
        for run in &mut runs {
            crate::app_diagnostics::decorate(run);
            run["transitions"] = Value::Array(
                transitions
                    .iter()
                    .filter(|e| e["run_id"] == run["id"])
                    .cloned()
                    .collect(),
            );
        }
        let items: Vec<Value> = entries
            .iter()
            .filter_map(|e| {
                lifecycle
                    .iter()
                    .chain(&runs)
                    .find(|item| item["entry"] == e["entry"] && item["id"] == e["id"])
                    .cloned()
            })
            .collect();
        let next = if more {
            entries.last().unwrap()["id"].clone()
        } else {
            Value::Null
        };
        let missed_history_pending = Self::missed_history_pending(&mut tx, app).await?;
        // Chip totals over the retained timeline, independent of type and cursor.
        let counts = if narrowed {
            Value::Null
        } else {
            one(&mut tx,"SELECT (SELECT count(*) FROM app_lifecycle_events WHERE tenant_id=$1 AND project_id=$2 AND app_id=$3 AND recorded_at>=now()-interval '30 days' AND run_id IS NULL)+count(r.id) AS all,count(*) FILTER (WHERE r.source='http') AS http,count(*) FILTER (WHERE r.source='manual') AS manual,count(*) FILTER (WHERE r.source IN ('schedule','test-schedule')) AS schedule,(SELECT count(*) FROM app_lifecycle_events WHERE tenant_id=$1 AND project_id=$2 AND app_id=$3 AND recorded_at>=now()-interval '30 days') AS lifecycle,count(r.id) AS invocations,count(*) FILTER (WHERE r.state='failed') AS failed,count(*) FILTER (WHERE r.state='unknown') AS unknown FROM customer_app_runs r WHERE r.tenant_id=$1 AND r.project_id=$2 AND r.app_id=$3",args![tenant,project,app]).await?
        };
        let coverage=one(&mut tx,"SELECT started_at AS recording_started_at,GREATEST(started_at,now()-interval '30 days') AS retained_since FROM app_lifecycle_coverage",args![]).await?;
        Ok(
            json!({"items":items,"next":next,"coverage":coverage,"retention_days":30,"missed_history_pending":missed_history_pending,"counts":counts}),
        )
    }
    pub(crate) async fn expire_app_events(tx: &mut Tx) -> Result<()> {
        exec(tx,"DELETE FROM app_lifecycle_events WHERE id IN (SELECT id FROM app_lifecycle_events WHERE recorded_at<now()-interval '30 days' ORDER BY recorded_at,id LIMIT 512)",args![]).await?;
        Ok(())
    }
}
