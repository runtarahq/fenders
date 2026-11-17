//! Preserve run/occurrence tombstones while pruning settled dispatch detail.
use crate::{
    args,
    db::*,
    error::Result,
    store::{Store, Tx},
};

impl Store {
    pub(crate) async fn retire_schedule_dispatch(tx: &mut Tx) -> Result<()> {
        // The caller holds the admission lock, shared with dispatch and recovery.
        // Independent SQL guards reject retirement of active/uncertain work and
        // require the immutable marker and deletion to commit together.
        for row in rows(
            tx,
            "SELECT run_id FROM app_dispatch_retirable ORDER BY updated,run_id LIMIT 256",
            args![],
        )
        .await?
        {
            exec(
                tx,
                "UPDATE app_runs SET dispatch_retired_at=now() WHERE id=$1",
                args![row["run_id"]],
            )
            .await?;
            exec(
                tx,
                "DELETE FROM app_run_dispatch WHERE run_id=$1",
                args![row["run_id"]],
            )
            .await?;
        }
        Ok(())
    }
}
