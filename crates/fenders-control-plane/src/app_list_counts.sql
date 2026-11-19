-- Summary cards describe the whole authorized project, never just this page.
WITH scoped AS MATERIALIZED (
    SELECT id,created,name,state,triggers,http
    FROM customer_app_summaries WHERE tenant_id=$1 AND project_id=$2
), filtered AS (
    SELECT id,created FROM scoped
    WHERE position(lower($3) in lower(name))>0
      AND CASE WHEN $4='' THEN true
          WHEN $4='none' THEN NOT (triggers->>'http')::boolean
              AND NOT (triggers->>'manual')::boolean AND NOT (triggers->>'schedule')::boolean
          ELSE (triggers->>$4)::boolean END
      AND ($5='' OR state=$5)
)
SELECT jsonb_build_object(
    'total', count(*),
    'ready', count(*) FILTER (WHERE state='ready'),
    'stopped', count(*) FILTER (WHERE state='stopped'),
    'serving_http', count(*) FILTER (WHERE http->>'state'='serving'),
    'manual', count(*) FILTER (WHERE (triggers->>'manual')::boolean),
    'schedule', count(*) FILTER (WHERE (triggers->>'schedule')::boolean),
    'http', count(*) FILTER (WHERE (triggers->>'http')::boolean),
    'none', count(*) FILTER (WHERE NOT (triggers->>'manual')::boolean
        AND NOT (triggers->>'schedule')::boolean AND NOT (triggers->>'http')::boolean),
    'pending_connections',
        (SELECT count(*) FROM app_connection_observations WHERE tenant_id=$1 AND project_id=$2 AND state='pending')
        + (SELECT count(*) FROM app_https_observations WHERE tenant_id=$1 AND project_id=$2 AND state='pending')
) AS summary,
(SELECT count(*) FROM filtered) AS total
FROM scoped
