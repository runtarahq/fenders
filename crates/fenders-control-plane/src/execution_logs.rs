//! Bounded, retry-safe ingestion from enrolled nodes. Customer code cannot write
//! this protocol; source identity and execution ownership are checked together.
use crate::{
    args,
    db::*,
    error::{Error, Result},
    model::{HOST_CONFINEMENT, LOG_REDACTION, identity},
    store::{Store, Tx},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;
use serde_json::{Value, json};

pub const MAX_REQUEST: usize = 128 * 1024;
pub const EXECUTION_BYTES: i64 = 1024 * 1024;
pub const EXECUTION_RECORDS: i64 = 4096;
pub const WORKSPACE_BYTES: i64 = 64 * 1024 * 1024;
pub const WORKSPACE_RECORDS: i64 = 65536;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Batch {
    boot_id: String,
    format_version: i64,
    capture_id: String,
    first_sequence: i64,
    last_sequence: i64,
    closed: bool,
    #[serde(default)]
    interrupted: bool,
    redaction: String,
    redacted_env: Vec<String>,
    records: Vec<Record>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    sequence: i64,
    at_ms: i64,
    stream: String,
    bytes: String,
}
impl Batch {
    fn parse(value: Value) -> Result<Self> {
        if serde_json::to_vec(&value)
            .map_err(|_| Error::internal())?
            .len()
            > MAX_REQUEST
        {
            return Err(Error::new(
                axum::http::StatusCode::PAYLOAD_TOO_LARGE,
                "log batch too large",
            ));
        }
        let batch: Self = serde_json::from_value(value)
            .map_err(|_| Error::invalid("invalid log batch fields"))?;
        identity(&batch.capture_id)?;
        if batch.boot_id.is_empty()
            || batch.boot_id.len() > 128
            || batch.boot_id.chars().any(char::is_control)
            || batch.format_version != 1
            || batch.interrupted && !batch.closed
            || batch.redaction != LOG_REDACTION
            || batch.first_sequence < 1
            || batch.last_sequence < 0
            || (batch.last_sequence == 0 && batch.first_sequence != 1)
            || (batch.last_sequence > 0
                && batch.first_sequence > batch.last_sequence
                && !(batch.closed
                    && batch.records.is_empty()
                    && batch.last_sequence.checked_add(1) == Some(batch.first_sequence)))
            || batch.records.len() > 64
            || batch.redacted_env.len() > 32
        {
            return Err(Error::invalid("invalid log capture metadata"));
        }
        let mut names = std::collections::HashSet::new();
        for name in &batch.redacted_env {
            if name.is_empty()
                || name.len() > 128
                || !names.insert(name)
                || !name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
            {
                return Err(Error::invalid("invalid log redaction coverage"));
            }
        }
        let mut previous: Option<i64> = None;
        let mut size = 0;
        for record in &batch.records {
            if record.sequence < batch.first_sequence
                || record.sequence > batch.last_sequence
                || previous.is_some_and(|seq| seq.checked_add(1) != Some(record.sequence))
                || !(0..=253402300799999).contains(&record.at_ms)
                || !matches!(record.stream.as_str(), "stdout" | "stderr")
                || record.bytes.len() > 10924
            {
                return Err(Error::invalid("invalid log record"));
            }
            let bytes = STANDARD
                .decode(&record.bytes)
                .map_err(|_| Error::invalid("invalid log bytes"))?;
            if bytes.is_empty() || bytes.len() > 8192 {
                return Err(Error::invalid("invalid log record size"));
            }
            size += bytes.len();
            previous = Some(record.sequence);
        }
        if size > 65536 {
            return Err(Error::invalid("log page exceeds payload bound"));
        }
        Ok(batch)
    }
}

impl Store {
    pub async fn ingest_execution_logs(
        &self,
        node: &str,
        execution: &str,
        generation: i64,
        value: Value,
    ) -> Result<Value> {
        identity(execution)?;
        if generation < 1 {
            return Err(Error::invalid("invalid log generation"));
        }
        let batch = Batch::parse(value)?;
        let mut tx = self.transaction(true, false).await?;
        let execution_row = optional(&mut tx,
            "SELECT e.* FROM executions e JOIN nodes n ON n.id=e.node_id WHERE e.id=$1 AND e.generation=$2 AND e.node_id=$3 AND NOT e.log_ingestion_fenced AND NOT n.disabled AND n.backend='wasm' AND n.boot_id=$4 AND n.observed_confinement=$5",
            args![execution,generation,node,batch.boot_id,HOST_CONFINEMENT]).await?
            .ok_or_else(|| conflict("log execution ownership or worker identity changed"))?;
        if execution_row["spec"]["secret_env"]
            .as_object()
            .is_some_and(|required| required.keys().any(|key| !batch.redacted_env.contains(key)))
        {
            return Err(conflict("log capture does not cover injected secrets"));
        }
        exec(&mut tx, "INSERT INTO execution_log_sources(execution_id,tenant_id,project_id,capture_id) VALUES($1,$2,$3,$4) ON CONFLICT(execution_id) DO NOTHING",
            args![execution,execution_row["tenant_id"],execution_row["project_id"],batch.capture_id]).await?;
        let source = one(
            &mut tx,
            "SELECT * FROM execution_log_sources WHERE execution_id=$1 FOR UPDATE",
            args![execution],
        )
        .await?;
        if source["capture_id"] != batch.capture_id {
            return Err(conflict("log capture identity changed"));
        }
        let mut ack = n(&source["acknowledged"]);
        let reported = n(&source["reported_last"]).max(batch.last_sequence);
        let mut end = source["end_sequence"].as_i64();
        if end.is_some_and(|end| {
            batch.last_sequence > end || batch.closed && batch.last_sequence != end
        }) || batch.closed && batch.last_sequence < reported
        {
            return Err(conflict("log capture closure contradicts received records"));
        }
        if batch.closed {
            end = Some(batch.last_sequence);
        }
        let mut gap = b(&source["source_gap"]);
        // The node retained a suffix. Record the lost range instead of silently
        // advancing the delivery cursor. Missing records inside that suffix fail.
        if batch.first_sequence - 1 > ack {
            exec(&mut tx,"INSERT INTO execution_log_records(tenant_id,project_id,execution_id,sequence,stream,payload,gap_from) VALUES($1,$2,$3,$4,'gap',''::bytea,$5)",
                args![execution_row["tenant_id"],execution_row["project_id"],execution,batch.first_sequence-1,ack+1]).await?;
            ack = batch.first_sequence - 1;
            gap = true;
        }
        for record in &batch.records {
            if record.sequence <= ack {
                // A response may be lost after commit. Retained duplicate bytes
                // must agree; pruned/known-lost data must never be resurrected.
                if let Some(old) = optional(&mut tx,"SELECT stream,(at_ms=$3 AND stream=$4 AND payload=decode($5,'base64')) AS identical FROM execution_log_records WHERE execution_id=$1 AND sequence=$2",
                    args![execution,record.sequence,record.at_ms,record.stream,record.bytes]).await?
                    && old["stream"] != "gap" && old["identical"] != true {
                    return Err(conflict("log record conflicts with a committed sequence"));
                }
                continue;
            }
            if ack.checked_add(1) != Some(record.sequence) {
                return Err(conflict("log batch skips an available sequence"));
            }
            exec(&mut tx,"INSERT INTO execution_log_records(tenant_id,project_id,execution_id,sequence,stream,at_ms,payload) VALUES($1,$2,$3,$4,$5,$6,decode($7,'base64'))",
                args![execution_row["tenant_id"],execution_row["project_id"],execution,record.sequence,record.stream,record.at_ms,record.bytes]).await?;
            ack = record.sequence;
        }
        if batch.records.is_empty() && ack < batch.last_sequence {
            return Err(conflict("log batch omits available records"));
        }
        // Nullable integer uses a typed bind; the JSON SQL helpers type null as
        // text and are intentionally not used for this value.
        sqlx::query("UPDATE execution_log_sources SET acknowledged=$1,reported_last=$2,end_sequence=$3,source_gap=$4,interrupted=interrupted OR $6,updated=now() WHERE execution_id=$5")
            .bind(ack).bind(reported).bind(end).bind(gap).bind(execution).bind(batch.interrupted).execute(&mut *tx).await?;
        Self::expire_execution_logs(&mut tx).await?;
        Self::bound_execution_logs(&mut tx, execution, s(&execution_row["tenant_id"])).await?;
        let result = one(&mut tx,"SELECT capture_id,acknowledged,source_gap,interrupted,pruned_through,COALESCE(end_sequence=acknowledged,false) AS complete FROM execution_log_sources WHERE execution_id=$1",args![execution]).await?;
        tx.commit().await?;
        Ok(json!({"accepted":true,"cursor":result}))
    }

    pub(crate) async fn expire_execution_logs(tx: &mut Tx) -> Result<()> {
        exec(tx,"WITH removed AS (DELETE FROM execution_log_records WHERE received<now()-interval '7 days' RETURNING execution_id,sequence), bounds AS (SELECT execution_id,max(sequence) AS sequence FROM removed GROUP BY execution_id) UPDATE execution_log_sources s SET pruned_through=GREATEST(s.pruned_through,b.sequence) FROM bounds b WHERE s.execution_id=b.execution_id",args![]).await?;
        Ok(())
    }
    async fn bound_execution_logs(tx: &mut Tx, execution: &str, tenant: &str) -> Result<()> {
        exec(tx,"WITH retained AS (SELECT id,row_number() OVER(ORDER BY id DESC) AS records,sum(octet_length(payload)) OVER(ORDER BY id DESC) AS bytes FROM execution_log_records WHERE execution_id=$1), removed AS (DELETE FROM execution_log_records WHERE id IN (SELECT id FROM retained WHERE records>$2 OR bytes>$3) RETURNING execution_id,sequence), bounds AS (SELECT execution_id,max(sequence) AS sequence FROM removed GROUP BY execution_id) UPDATE execution_log_sources s SET pruned_through=GREATEST(s.pruned_through,b.sequence) FROM bounds b WHERE s.execution_id=b.execution_id",
            args![execution,EXECUTION_RECORDS,EXECUTION_BYTES]).await?;
        exec(tx,"WITH retained AS (SELECT id,row_number() OVER(ORDER BY id DESC) AS records,sum(octet_length(payload)) OVER(ORDER BY id DESC) AS bytes FROM execution_log_records WHERE tenant_id=$1), removed AS (DELETE FROM execution_log_records WHERE id IN (SELECT id FROM retained WHERE records>$2 OR bytes>$3) RETURNING execution_id,sequence), bounds AS (SELECT execution_id,max(sequence) AS sequence FROM removed GROUP BY execution_id) UPDATE execution_log_sources s SET pruned_through=GREATEST(s.pruned_through,b.sequence) FROM bounds b WHERE s.execution_id=b.execution_id",
            args![tenant,WORKSPACE_RECORDS,WORKSPACE_BYTES]).await?;
        Ok(())
    }
}
