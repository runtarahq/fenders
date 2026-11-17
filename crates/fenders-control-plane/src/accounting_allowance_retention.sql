WITH candidates AS MATERIALIZED (
    SELECT u.execution_id,u.period FROM egress_allowance_usage u
    JOIN executions e ON e.id=u.execution_id
    JOIN execution_egress_budgets g ON g.execution_id=e.id
    WHERE NOT e.reserved AND g.state='closed'
        AND u.period<(date_trunc('month',now() AT TIME ZONE 'UTC')-make_interval(months=>$1::int))::date
    ORDER BY u.period,u.execution_id LIMIT $2 FOR UPDATE OF u
), moved AS (
    DELETE FROM egress_allowance_usage u USING candidates c
    WHERE u.execution_id=c.execution_id AND u.period=c.period RETURNING u.*
)
INSERT INTO accounting_month_rollups(tenant_id,project_id,period,outbound_accounted_bytes,outbound_conservative_bytes,settlement_records)
SELECT tenant_id,project_id,period,sum(bytes),sum(conservative_bytes),count(*) FROM moved GROUP BY tenant_id,project_id,period
ON CONFLICT(tenant_id,project_id,period) DO UPDATE SET
    outbound_accounted_bytes=accounting_month_rollups.outbound_accounted_bytes+excluded.outbound_accounted_bytes,
    outbound_conservative_bytes=accounting_month_rollups.outbound_conservative_bytes+excluded.outbound_conservative_bytes,
    settlement_records=accounting_month_rollups.settlement_records+excluded.settlement_records
