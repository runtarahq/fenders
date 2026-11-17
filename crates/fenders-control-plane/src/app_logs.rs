//! Scoped customer logs. Opaque cursors bind scope and filters and remain usable
//! after retention removes the anchor row. They are never an authorization token.
use crate::{
    args,
    db::*,
    error::{Error, Result},
    execution_logs::*,
    model::{Principal, identity},
    store::Store,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogPage {
    pub after: Option<String>,
    pub limit: Option<i64>,
    pub release_id: Option<String>,
    pub run_id: Option<String>,
    pub execution_id: Option<String>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    kind: String,
    scope: Value,
    after: i64,
}
impl Store {
    pub async fn app_logs(
        &self,
        p: &Principal,
        tenant: &str,
        project: &str,
        app: &str,
        mut page: LogPage,
    ) -> Result<Value> {
        let limit = page.limit.unwrap_or(50);
        if !(1..=100).contains(&limit) {
            return Err(Error::invalid("log page limit must be between 1 and 100"));
        }
        for value in [&page.release_id, &page.run_id, &page.execution_id]
            .into_iter()
            .flatten()
        {
            identity(value)?;
        }
        // Authorizations, records and collection observations describe one DB
        // snapshot even while ingestion and expiration continue concurrently.
        let mut tx = self.snapshot().await?;
        Self::project(&mut tx, p, tenant, project, false).await?;
        Self::app_row(&mut tx, tenant, project, app).await?;
        if let Some(release) = &page.release_id {
            one(&mut tx,"SELECT id FROM app_releases WHERE tenant_id=$1 AND project_id=$2 AND app_id=$3 AND id=$4",args![tenant,project,app,release]).await?;
        }
        if let Some(run) = &page.run_id {
            let run=one(&mut tx,"SELECT id,source,execution_id FROM customer_app_runs WHERE tenant_id=$1 AND project_id=$2 AND app_id=$3 AND id=$4",args![tenant,project,app,run]).await?;
            if run["source"] == "http" && !run["execution_id"].is_null() {
                if page
                    .execution_id
                    .as_deref()
                    .is_some_and(|id| id != s(&run["execution_id"]))
                {
                    return Err(Error::invalid("run execution filter does not match"));
                }
                page.run_id = None;
                page.execution_id = Some(s(&run["execution_id"]).to_owned());
            }
        }
        if let Some(execution) = &page.execution_id {
            one(&mut tx,"SELECT execution_id FROM app_execution_contexts WHERE tenant_id=$1 AND project_id=$2 AND app_id=$3 AND execution_id=$4",args![tenant,project,app,execution]).await?;
        }
        let recovery = one(
            &mut tx,
            "SELECT restored FROM recovery_barrier WHERE singleton",
            args![],
        )
        .await?;
        let scope = json!({"tenant":tenant,"project":project,"app":app,"release":page.release_id,"run":page.run_id,"execution":page.execution_id,"restored":recovery["restored"]});
        let after = if let Some(token) = &page.after {
            if token.len() > 2048 {
                return Err(Error::invalid("invalid app log cursor"));
            }
            let decoded = self
                .cipher
                .decrypt(token)
                .map_err(|_| Error::invalid("invalid app log cursor"))?;
            let cursor: Cursor = serde_json::from_slice(&decoded)
                .map_err(|_| Error::invalid("invalid app log cursor"))?;
            if cursor.kind != "app-logs-v1" || cursor.scope != scope || cursor.after < 0 {
                return Err(Error::invalid("log cursor scope or history changed"));
            }
            cursor.after
        } else {
            0
        };
        let found=rows(&mut tx,"SELECT r.id AS cursor,r.execution_id,r.sequence,r.stream,r.at_ms,r.received,r.gap_from,octet_length(r.payload) AS byte_count,replace(encode(r.payload,'base64'),E'\\n','') AS bytes,c.release_id,c.version_id,c.version,c.run_id,c.source FROM execution_log_records r JOIN app_execution_contexts c ON c.execution_id=r.execution_id WHERE c.tenant_id=$1 AND c.project_id=$2 AND c.app_id=$3 AND ($4::text IS NULL OR c.release_id=$4) AND ($5::text IS NULL OR c.run_id=$5) AND ($6::text IS NULL OR c.execution_id=$6) AND r.id>$7 AND r.received>=now()-interval '7 days' ORDER BY r.id LIMIT $8",args![tenant,project,app,page.release_id,page.run_id,page.execution_id,after,limit+1]).await?;
        let mut items = Vec::new();
        let mut payload = 0;
        let mut next = after;
        let mut more = false;
        for mut record in found {
            if items.len() == limit as usize || payload + n(&record["byte_count"]) > 65536 {
                more = true;
                break;
            }
            payload += n(&record["byte_count"]);
            next = n(&record["cursor"]);
            record.as_object_mut().unwrap().remove("cursor");
            record["id"] = json!(format!(
                "{}:{}",
                s(&record["execution_id"]),
                n(&record["sequence"])
            ));
            items.push(record);
        }
        let collection=one(&mut tx,"SELECT count(*) AS executions,count(*) FILTER(WHERE collection_state='complete') AS complete,count(*) FILTER(WHERE collection_state='fenced') AS fenced,count(*) FILTER(WHERE collection_state='not-started') AS not_started,count(*) FILTER(WHERE collection_state='awaiting') AS awaiting,count(*) FILTER(WHERE collection_state='unavailable') AS unavailable,count(*) FILTER(WHERE collection_state='collecting') AS collecting,count(*) FILTER(WHERE collection_state='stale') AS stale,count(*) FILTER(WHERE collection_state='incomplete') AS incomplete,count(*) FILTER(WHERE source_gap) AS source_gaps,count(*) FILTER(WHERE retention_truncated) AS truncated_captures,max(last_received) AS last_received FROM app_log_observations c WHERE c.tenant_id=$1 AND c.project_id=$2 AND c.app_id=$3 AND ($4::text IS NULL OR c.release_id=$4) AND ($5::text IS NULL OR c.run_id=$5) AND ($6::text IS NULL OR c.execution_id=$6)",args![tenant,project,app,page.release_id,page.run_id,page.execution_id]).await?;
        let cursor = Cursor {
            kind: "app-logs-v1".into(),
            scope,
            after: next,
        };
        let next = self
            .cipher
            .encrypt(&serde_json::to_vec(&cursor).map_err(|_| Error::internal())?);
        Ok(
            json!({"items":items,"next":next,"has_more":more,"encoding":"base64","collection":collection,"retention":{"days":7,"execution_bytes":EXECUTION_BYTES,"execution_records":EXECUTION_RECORDS,"workspace_bytes":WORKSPACE_BYTES,"workspace_records":WORKSPACE_RECORDS}}),
        )
    }
}
