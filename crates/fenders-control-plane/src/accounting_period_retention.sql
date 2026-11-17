WITH candidates AS MATERIALIZED (
    SELECT p.execution_id,p.period FROM execution_egress_periods p
    JOIN executions e ON e.id=p.execution_id
    JOIN execution_egress_period_sources s ON s.execution_id=e.id
    WHERE NOT e.reserved AND s.complete AND s.consistent
        AND NOT EXISTS(SELECT 1 FROM execution_egress_budgets g WHERE g.execution_id=e.id AND g.state<>'closed')
        AND p.period<(date_trunc('month',now() AT TIME ZONE 'UTC')-make_interval(months=>$1::int))::date
    ORDER BY p.period,p.execution_id LIMIT $2 FOR UPDATE OF p
), moved AS (
    DELETE FROM execution_egress_periods p USING candidates c
    WHERE p.execution_id=c.execution_id AND p.period=c.period RETURNING p.*
), rolled AS (
    INSERT INTO accounting_month_rollups(tenant_id,project_id,period,observed_outbound_bytes,observed_period_records,observed_at)
    SELECT tenant_id,project_id,period,sum(bytes),count(*),max(sampled_at) FROM moved GROUP BY tenant_id,project_id,period
    ON CONFLICT(tenant_id,project_id,period) DO UPDATE SET
        observed_outbound_bytes=accounting_month_rollups.observed_outbound_bytes+excluded.observed_outbound_bytes,
        observed_period_records=accounting_month_rollups.observed_period_records+excluded.observed_period_records,
        observed_at=GREATEST(accounting_month_rollups.observed_at,excluded.observed_at)
    RETURNING period
), totals AS (SELECT execution_id,sum(bytes) bytes,count(*) periods FROM moved GROUP BY execution_id)
UPDATE execution_egress_period_sources s
SET archived_bytes=s.archived_bytes+t.bytes,archived_periods=s.archived_periods+t.periods
FROM totals t WHERE s.execution_id=t.execution_id
