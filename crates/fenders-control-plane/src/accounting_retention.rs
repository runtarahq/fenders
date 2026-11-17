//! Bounded, transactional compaction of sealed accounting records. Never prune
//! execution identity, grant tombstones, active sources or uncertain holds.
use crate::{
    args,
    db::*,
    error::Result,
    store::{Store, Tx},
};
use serde_json::{Value, json};
pub(crate) const MONTHS: i64 = 13;
pub(crate) fn policy() -> Value {
    json!({"finalized_detail_months":MONTHS,"calendar":"UTC","monthly_totals":"retained","active_and_uncertain_records":"retained","resource_identities":"retained","max_detail_rows_per_pass":512})
}
impl Store {
    pub(crate) async fn compact_accounting(tx: &mut Tx) -> Result<()> {
        // Ingestion, terminal settlement and cleanup share the admission lock.
        // Both independent classes make progress; a pass moves at most 256 each.
        exec(
            tx,
            include_str!("accounting_period_retention.sql"),
            args![MONTHS - 1, 256],
        )
        .await?;
        exec(
            tx,
            include_str!("accounting_allowance_retention.sql"),
            args![MONTHS - 1, 256],
        )
        .await?;
        Ok(())
    }
}
