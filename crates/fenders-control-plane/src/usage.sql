WITH scope AS MATERIALIZED (
    SELECT id,display_name FROM projects WHERE tenant_id=$1 AND ($2 IS NULL OR id=$2)
), e AS MATERIALIZED (
    SELECT e.* FROM executions e JOIN scope p ON p.id=e.project_id WHERE e.tenant_id=$1
), outbound_grants AS (
    SELECT g.project_id,count(*) executions FROM execution_egress_budgets g
    JOIN scope p ON p.id=g.project_id WHERE g.tenant_id=$1
        AND g.period=date_trunc('month',now() AT TIME ZONE 'UTC')::date
    GROUP BY g.project_id
), samples AS (
    SELECT e.id,max(s.cpu_usec) FILTER(WHERE s.cpu_measured) cpu_usec,
        max(s.observed) FILTER(WHERE s.cpu_measured) last_cpu_observed
    FROM e LEFT JOIN usage_samples s ON s.execution_id=e.id AND s.tenant_id=$1 GROUP BY e.id
), execution_usage AS (
    SELECT e.project_id,count(*) executions,count(s.cpu_usec) measured_executions,
        CASE WHEN count(s.cpu_usec)>0 THEN sum(s.cpu_usec) ELSE NULL END cpu_usec,
        max(s.last_cpu_observed) last_cpu_observed,
        count(*) FILTER(WHERE e.reserved) memory_expected,
        count(*) FILTER(WHERE e.reserved AND latest.memory_measured AND latest.observed>=now()-interval '30 seconds') memory_measured,
        sum(latest.memory_bytes) FILTER(WHERE e.reserved AND latest.memory_measured AND latest.observed>=now()-interval '30 seconds') memory_bytes,
        min(latest.observed) FILTER(WHERE e.reserved AND latest.memory_measured AND latest.observed>=now()-interval '30 seconds') oldest_memory_observed
    FROM e JOIN samples s ON s.id=e.id
    LEFT JOIN LATERAL (SELECT memory_bytes,memory_measured,observed FROM usage_samples u
        WHERE u.execution_id=e.id AND u.tenant_id=$1 AND u.generation=e.generation ORDER BY sequence DESC LIMIT 1) latest ON true
    GROUP BY e.project_id
), egress AS (
    SELECT e.project_id,count(u.execution_id) egress_measured,
        count(*) FILTER(WHERE u.complete) egress_complete,
        count(*) FILTER(WHERE NOT u.consistent) egress_discontinuities,
        sum(u.bytes) egress_bytes,min(u.first_sampled_at) egress_first_sampled,
        max(u.sampled_at) egress_last_sampled,max(u.received) egress_received
    FROM e LEFT JOIN execution_egress_usage u ON u.execution_id=e.id AND u.tenant_id=$1
    GROUP BY e.project_id
), monthly_detail AS (
    SELECT e.id,e.project_id,s.execution_id source_id,s.consistent,s.complete,s.sampled_at,
        s.bytes-COALESCE(history.bytes,0)-s.archived_bytes unassigned,
        CASE WHEN p.execution_id IS NOT NULL THEN p.bytes
             WHEN s.consistent AND s.complete AND s.sampled_at<date_trunc('month',now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC' THEN 0 END bytes,
        p.sampled_at period_sampled
    FROM e LEFT JOIN execution_egress_period_sources s ON s.execution_id=e.id AND s.tenant_id=$1
    LEFT JOIN execution_egress_periods p ON p.execution_id=e.id AND p.tenant_id=$1 AND p.period=date_trunc('month',now() AT TIME ZONE 'UTC')::date
    LEFT JOIN LATERAL (SELECT sum(bytes) bytes FROM execution_egress_periods p WHERE p.execution_id=e.id AND p.tenant_id=$1) history ON true
), monthly AS (
    SELECT project_id,sum(bytes) egress_month_bytes,count(bytes) egress_month_measured,
        count(*) FILTER(WHERE bytes IS NOT NULL AND consistent AND complete) egress_month_complete,
        count(source_id) egress_period_sources,count(*) FILTER(WHERE NOT consistent) egress_period_discontinuities,
        sum(unassigned) egress_unassigned_bytes,max(period_sampled) egress_month_sampled
    FROM monthly_detail GROUP BY project_id
), reservations AS (
    SELECT project_id,sum(cpu_percent) cpu,sum(memory_mib) memory,count(*) instances,count(*) wasm,
        count(*) FILTER(WHERE state IN ('unreachable','lost','stopping') OR desired='stopped') uncertain
    FROM e WHERE reserved GROUP BY project_id
), storage AS (
    SELECT a.project_id,sum(a.size) bytes,sum(a.size) artifact FROM artifacts a JOIN scope p ON p.id=a.project_id
    WHERE a.tenant_id=$1 AND a.retired_at IS NULL GROUP BY a.project_id
), traffic AS (
    SELECT t.project_id,t.bytes,t.requests,t.conservative_bytes FROM traffic_usage t JOIN scope p ON p.id=t.project_id
    WHERE t.tenant_id=$1 AND t.period=date_trunc('month',now() AT TIME ZONE 'UTC')::date
), pending AS (
    SELECT i.project_id,sum(i.bytes) bytes FROM (
        SELECT tenant_id,project_id,period,bytes FROM ingress_reservations
        UNION ALL SELECT tenant_id,project_id,period,held_bytes FROM gateway_transfer_leases
    ) i JOIN scope p ON p.id=i.project_id
    WHERE i.tenant_id=$1 AND i.period=date_trunc('month',now() AT TIME ZONE 'UTC')::date GROUP BY i.project_id
), leased AS (
    SELECT g.project_id,sum(g.held_bytes) bytes FROM gateway_transfer_leases g JOIN scope p ON p.id=g.project_id
    WHERE g.tenant_id=$1 AND g.period=date_trunc('month',now() AT TIME ZONE 'UTC')::date GROUP BY g.project_id
), allowance AS (
    SELECT a.project_id,sum(a.used_bytes) used_bytes,sum(a.held_bytes) held_bytes
    FROM transfer_allowance_accounting a JOIN scope p ON p.id=a.project_id
    WHERE a.tenant_id=$1 AND a.period=date_trunc('month',now() AT TIME ZONE 'UTC')::date GROUP BY a.project_id
), conservative AS (
    SELECT a.project_id,sum(a.conservative_bytes) bytes FROM (SELECT tenant_id,project_id,period,conservative_bytes FROM egress_allowance_usage UNION ALL SELECT tenant_id,project_id,period,outbound_conservative_bytes FROM accounting_month_rollups) a JOIN scope p ON p.id=a.project_id
    WHERE a.tenant_id=$1 AND a.period=date_trunc('month',now() AT TIME ZONE 'UTC')::date GROUP BY a.project_id
), logs AS (
    SELECT l.project_id,sum(octet_length(payload)) FILTER(WHERE received>=now()-interval '7 days') bytes,
        count(*) FILTER(WHERE received>=now()-interval '7 days') records,
        sum(octet_length(payload)) FILTER(WHERE received<now()-interval '7 days') expired
    FROM execution_log_records l JOIN scope p ON p.id=l.project_id WHERE l.tenant_id=$1 GROUP BY l.project_id
)
SELECT p.id,p.display_name AS name,
    CASE WHEN u.executions IS NULL THEN 0 ELSE mo.egress_month_bytes END egress_month_bytes,
    COALESCE(mo.egress_month_measured,0) egress_month_measured,COALESCE(mo.egress_month_complete,0) egress_month_complete,
    COALESCE(mo.egress_period_sources,0) egress_period_sources,COALESCE(mo.egress_period_discontinuities,0) egress_period_discontinuities,
    CASE WHEN u.executions IS NULL THEN 0 ELSE mo.egress_unassigned_bytes END egress_unassigned_bytes,mo.egress_month_sampled,
    COALESCE(g.egress_measured,0) egress_measured,COALESCE(g.egress_complete,0) egress_complete,
    COALESCE(g.egress_discontinuities,0) egress_discontinuities,
    CASE WHEN u.executions IS NULL THEN 0 ELSE g.egress_bytes END egress_bytes,
    g.egress_first_sampled,g.egress_last_sampled,g.egress_received,
    COALESCE(r.cpu,0) reserved_cpu_percent,COALESCE(r.memory,0) reserved_memory_mib,
    COALESCE(r.instances,0) reserved_instances,COALESCE(r.wasm,0) wasm_instances,COALESCE(r.uncertain,0) uncertain_instances,
    COALESCE(s.bytes,0) storage_bytes,COALESCE(s.artifact,0) artifact_bytes,
    COALESCE(t.bytes,0) ingress_bytes,COALESCE(t.requests,0) ingress_requests,COALESCE(i.bytes,0) ingress_reserved_bytes,
    COALESCE(ta.used_bytes,0) transfer_accounted_bytes,COALESCE(ta.held_bytes,0) transfer_reserved_bytes,
    COALESCE(tc.bytes,0) outbound_conservative_bytes,COALESCE(t.conservative_bytes,0) gateway_conservative_bytes,COALESCE(gl.bytes,0) gateway_leased_bytes,
    COALESCE(og.executions,0) outbound_grant_executions,
    COALESCE(u.executions,0) executions,COALESCE(u.measured_executions,0) measured_executions,
    CASE WHEN u.executions IS NULL THEN 0 ELSE u.cpu_usec END cpu_usec,u.last_cpu_observed,
    COALESCE(u.memory_expected,0) memory_expected,COALESCE(u.memory_measured,0) memory_measured,
    CASE WHEN COALESCE(u.memory_expected,0)=0 THEN 0 ELSE u.memory_bytes END memory_bytes,u.oldest_memory_observed,
    COALESCE(l.bytes,0) diagnostic_bytes,COALESCE(l.records,0) diagnostic_records,COALESCE(l.expired,0) diagnostic_expired_bytes
FROM scope p LEFT JOIN reservations r ON r.project_id=p.id LEFT JOIN storage s ON s.project_id=p.id
LEFT JOIN traffic t ON t.project_id=p.id LEFT JOIN pending i ON i.project_id=p.id
LEFT JOIN execution_usage u ON u.project_id=p.id LEFT JOIN logs l ON l.project_id=p.id
LEFT JOIN egress g ON g.project_id=p.id LEFT JOIN monthly mo ON mo.project_id=p.id
LEFT JOIN allowance ta ON ta.project_id=p.id LEFT JOIN leased gl ON gl.project_id=p.id LEFT JOIN conservative tc ON tc.project_id=p.id
LEFT JOIN outbound_grants og ON og.project_id=p.id ORDER BY p.display_name,p.id
