-- A WebSocket connection the gateway holds for an app is one row among the
-- app's requests: opened when the app accepted it, finished when it closed,
-- with what passed over it. Its messages are not rows. Every statement can
-- be run again on a database that already had it.
ALTER TABLE app_http_runs ADD COLUMN IF NOT EXISTS websocket jsonb;
CREATE INDEX IF NOT EXISTS http_run_open_websocket ON app_http_runs(created) WHERE websocket IS NOT NULL AND finished_at IS NULL;

-- customer_app_runs as before, with that column last.
CREATE OR REPLACE VIEW customer_app_runs AS
 SELECT r.*,NULL::text AS method,NULL::text AS path,NULL::integer AS http_status,
 CASE WHEN finished_at IS NOT NULL AND started_at IS NOT NULL THEN GREATEST(0,extract(epoch FROM (finished_at-started_at))*1000)::bigint END AS duration_ms,
 NULL::jsonb AS websocket
 FROM app_run_observations r
 UNION ALL
 SELECT h.id,h.tenant_id,h.project_id,h.app_id,h.release_id,h.execution_id,'http'::text AS source,h.created,v.number AS version,
 NULL::text AS execution_state,false AS reserved,h.state,NULL::integer AS exit_code,NULL::text AS reason,
 h.started_at,h.finished_at,COALESCE(h.finished_at,h.started_at,h.created) AS updated,
 'admitted'::text AS admission,NULL::timestamptz AS scheduled_at,NULL::bigint AS trigger_revision,
 h.method,h.path,h.http_status,
 CASE WHEN h.finished_at IS NOT NULL THEN GREATEST(0,extract(epoch FROM (h.finished_at-h.created))*1000)::bigint END AS duration_ms,
 h.websocket
 FROM app_http_runs h JOIN app_releases l ON l.id=h.release_id JOIN app_versions v ON v.id=l.version_id;
