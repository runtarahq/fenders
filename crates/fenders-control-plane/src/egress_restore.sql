-- Called only inside restore activation after explicit external fencing.
-- Unknown post-backup grants cannot be reconstructed from a restored snapshot.
WITH grants AS MATERIALIZED (
    SELECT * FROM execution_egress_budgets WHERE state<>'closed' FOR UPDATE
), charged AS (
    INSERT INTO egress_allowance_usage(execution_id,tenant_id,project_id,period,bytes,conservative_bytes)
    SELECT execution_id,tenant_id,project_id,period,held_bytes,held_bytes FROM grants
    ON CONFLICT(execution_id,period) DO UPDATE SET
        bytes=egress_allowance_usage.bytes+excluded.bytes,
        conservative_bytes=egress_allowance_usage.conservative_bytes+excluded.conservative_bytes
    RETURNING execution_id
)
UPDATE execution_egress_budgets g
SET state='closed',closure='restore-conservative',closed_at=now(),held_bytes=0,expires=NULL,updated=now()
FROM charged c WHERE g.execution_id=c.execution_id;
