WITH source AS (
    SELECT tenant_id,project_id,period,bytes::numeric gateway_bytes,requests::numeric gateway_requests,
        0::numeric outbound_accounted_bytes,0::numeric outbound_conservative_bytes,0::numeric held_bytes,
        0::numeric observed_outbound_bytes,0::bigint observed_period_records,NULL::timestamptz observed_at FROM traffic_usage
    UNION ALL SELECT tenant_id,project_id,period,0,0,bytes,conservative_bytes,0,0,0,NULL FROM egress_allowance_usage
    UNION ALL SELECT tenant_id,project_id,period,0,0,outbound_accounted_bytes,outbound_conservative_bytes,0,
        observed_outbound_bytes,observed_period_records,observed_at FROM accounting_month_rollups
    UNION ALL SELECT tenant_id,project_id,period,0,0,0,0,0,bytes,1,sampled_at FROM execution_egress_periods
    UNION ALL SELECT tenant_id,project_id,period,0,0,0,0,bytes,0,0,NULL FROM ingress_reservations
    UNION ALL SELECT tenant_id,project_id,period,0,0,0,0,held_bytes,0,0,NULL FROM gateway_transfer_leases
    UNION ALL SELECT tenant_id,project_id,period,0,0,0,0,held_bytes,0,0,NULL FROM execution_egress_budgets WHERE held_bytes>0
), accounting AS (
SELECT period,sum(gateway_bytes) gateway_bytes,sum(gateway_requests) gateway_requests,
    sum(outbound_accounted_bytes) outbound_accounted_bytes,sum(outbound_conservative_bytes) outbound_conservative_bytes,
    sum(gateway_bytes+outbound_accounted_bytes) accounted_bytes,sum(held_bytes) held_bytes,
    CASE WHEN sum(observed_period_records)>0 THEN sum(observed_outbound_bytes) END observed_outbound_bytes,
    sum(observed_period_records) observed_period_records,max(observed_at) observed_at
FROM source WHERE tenant_id=$1 AND ($2 IS NULL OR project_id=$2) AND ($3 IS NULL OR period<$3::date)
GROUP BY period
) SELECT * FROM accounting ORDER BY period DESC LIMIT $4
