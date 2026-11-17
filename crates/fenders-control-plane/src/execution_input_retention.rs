//! Expire duplicate invocation and unselected release inputs after settlement.
//! Secret-reference names stay in specs so late logs retain redaction checks.
use crate::{
    args,
    db::exec,
    error::Result,
    store::{Store, Tx},
};

impl Store {
    pub(crate) async fn retire_execution_inputs(tx: &mut Tx) -> Result<()> {
        // The scheduler holds the same admission lock as lifecycle/usage writes.
        // The SQL guard independently validates the original row and recovery.
        exec(tx, include_str!("execution_input_retention.sql"), args![]).await?;
        exec(tx, include_str!("release_input_retention.sql"), args![]).await?;
        Ok(())
    }
}
