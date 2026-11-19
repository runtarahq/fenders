-- What each gateway session holds of a workspace's monthly transfer
-- allowance for one of its projects: bytes it may pass without asking,
-- counted as held by every check of the allowance. A gateway takes its
-- used bytes off its lease as it records them, and gives back what it has
-- no use for. The lease of a session that is gone is counted as used, and
-- said to be conservative: what it passed is not known.
CREATE TABLE IF NOT EXISTS gateway_transfer_leases (
    session_id text NOT NULL, tenant_id text NOT NULL, project_id text NOT NULL,
    period date NOT NULL, held_bytes bigint NOT NULL CHECK(held_bytes>=0),
    updated timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(session_id,tenant_id,project_id,period),
    FOREIGN KEY(tenant_id,project_id) REFERENCES projects(tenant_id,id));
CREATE INDEX IF NOT EXISTS gateway_transfer_lease_allowance ON gateway_transfer_leases(tenant_id,period);
ALTER TABLE traffic_usage ADD COLUMN IF NOT EXISTS conservative_bytes bigint NOT NULL DEFAULT 0 CHECK(conservative_bytes>=0 AND conservative_bytes<=bytes);
CREATE OR REPLACE VIEW transfer_allowance_accounting AS
    SELECT tenant_id,project_id,period,bytes::numeric used_bytes,0::numeric held_bytes FROM traffic_usage
    UNION ALL SELECT tenant_id,project_id,period,0::numeric,bytes::numeric FROM ingress_reservations
    UNION ALL SELECT tenant_id,project_id,period,bytes::numeric,0::numeric FROM egress_allowance_usage
    UNION ALL SELECT tenant_id,project_id,period,0::numeric,held_bytes::numeric FROM execution_egress_budgets
    UNION ALL SELECT tenant_id,project_id,period,outbound_accounted_bytes,0::numeric FROM accounting_month_rollups
    UNION ALL SELECT tenant_id,project_id,period,0::numeric,held_bytes::numeric FROM gateway_transfer_leases;
