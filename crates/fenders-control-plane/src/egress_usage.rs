//! Cumulative socket-payload observations, not monthly transfer billing.
use crate::{
    args,
    db::*,
    error::{Error, Result},
    store::Tx,
};
pub use fenders_node_protocol::egress_usage::*;
use serde_json::Value;

// Called only after the authenticated node, execution owner, generation and
// heartbeat sequence checks, while the execution row remains locked.
pub(crate) async fn record(tx: &mut Tx, execution: &Value, value: &Value) -> Result<()> {
    let clock=one(tx,"SELECT to_timestamp(($1->>'observed')::double precision)<=now()+interval '5 minutes' AND to_timestamp(($1->>'observed')::double precision)>=created-interval '5 minutes' valid FROM executions WHERE id=$2",args![value,execution["id"]]).await?;
    if !b(&clock["valid"]) {
        return Err(Error::invalid(
            "egress observation timestamp outside execution window",
        ));
    }
    exec(tx,"INSERT INTO execution_egress_usage(execution_id,tenant_id,project_id,generation,boot_id,bytes,complete,sampled_at,first_sampled_at) VALUES($1,$2,$3,$4,$5,($6->>'bytes')::numeric,($6->>'complete')::boolean,to_timestamp(($6->>'observed')::double precision),to_timestamp(($6->>'observed')::double precision)) ON CONFLICT(execution_id) DO UPDATE SET generation=EXCLUDED.generation,bytes=GREATEST(execution_egress_usage.bytes,EXCLUDED.bytes),consistent=execution_egress_usage.consistent AND EXCLUDED.bytes>=execution_egress_usage.bytes AND EXCLUDED.boot_id=execution_egress_usage.boot_id,complete=EXCLUDED.complete AND execution_egress_usage.consistent AND EXCLUDED.bytes>=execution_egress_usage.bytes AND EXCLUDED.boot_id=execution_egress_usage.boot_id,sampled_at=EXCLUDED.sampled_at,received=now() WHERE EXCLUDED.sampled_at>=execution_egress_usage.sampled_at",args![execution["id"],execution["tenant_id"],execution["project_id"],execution["generation"],value["boot_id"],value]).await?;
    Ok(())
}
