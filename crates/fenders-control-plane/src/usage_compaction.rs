//! Exact downsampling for existing customer projections. Preserve at most three
//! witnesses: latest report, CPU high water, latest qualified CPU observation.
use crate::{
    args,
    db::*,
    error::Result,
    store::{Store, Tx},
};
use serde_json::Value;
const BATCH: i64 = 256;

impl Store {
    pub(crate) async fn compact_usage(tx: &mut Tx, execution: &Value) -> Result<()> {
        let removed = exec(
            tx,
            include_str!("usage_compaction.sql"),
            args![execution["id"], execution["tenant_id"], BATCH],
        )
        .await?;
        if removed == BATCH as u64 {
            exec(tx,"INSERT INTO usage_compaction_queue(execution_id) VALUES($1) ON CONFLICT DO NOTHING",args![execution["id"]]).await?;
        } else {
            exec(
                tx,
                "DELETE FROM usage_compaction_queue WHERE execution_id=$1",
                args![execution["id"]],
            )
            .await?;
        }
        Ok(())
    }

    pub(crate) async fn compact_usage_backlog(tx: &mut Tx) -> Result<()> {
        // Same admission transaction/lock as ingestion. Rotate large histories
        // so one old execution cannot starve the rest of the bounded queue.
        let work=rows(tx,"SELECT e.id,e.tenant_id FROM usage_compaction_queue q JOIN executions e ON e.id=q.execution_id ORDER BY q.queued_at,q.execution_id LIMIT 8",args![]).await?;
        for execution in work {
            Self::compact_usage(tx, &execution).await?;
            exec(tx,"UPDATE usage_compaction_queue SET queued_at=clock_timestamp() WHERE execution_id=$1",args![execution["id"]]).await?;
        }
        Ok(())
    }
}
