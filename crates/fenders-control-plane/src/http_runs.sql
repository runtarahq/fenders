-- Request metadata only: never retain query strings, headers, bodies or credentials.
CREATE TABLE IF NOT EXISTS app_http_runs (
 id text PRIMARY KEY, tenant_id text NOT NULL, project_id text NOT NULL,
 app_id text NOT NULL, release_id text NOT NULL, execution_id text,
 method text NOT NULL CHECK(method IN ('GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS')),
 path text NOT NULL CHECK(length(path)<=2048 AND left(path,1)='/' AND position('?' in path)=0),
 state text NOT NULL DEFAULT 'queued' CHECK(state IN ('queued','running','succeeded','failed','unknown')),
 http_status integer CHECK(http_status BETWEEN 200 AND 599),
 created timestamptz NOT NULL DEFAULT clock_timestamp(), started_at timestamptz, finished_at timestamptz,
 FOREIGN KEY(tenant_id,project_id,app_id,release_id) REFERENCES app_releases(tenant_id,project_id,app_id,id),
 FOREIGN KEY(tenant_id,project_id,execution_id) REFERENCES executions(tenant_id,project_id,id)
);
CREATE INDEX IF NOT EXISTS http_run_history ON app_http_runs(app_id,created DESC,id DESC);
CREATE INDEX IF NOT EXISTS http_run_retention ON app_http_runs(created) WHERE finished_at IS NOT NULL;
CREATE OR REPLACE VIEW customer_app_runs AS
 SELECT r.*,NULL::text AS method,NULL::text AS path,NULL::integer AS http_status,
 CASE WHEN finished_at IS NOT NULL AND started_at IS NOT NULL THEN GREATEST(0,extract(epoch FROM (finished_at-started_at))*1000)::bigint END AS duration_ms
 FROM app_run_observations r
 UNION ALL
 SELECT h.id,h.tenant_id,h.project_id,h.app_id,h.release_id,h.execution_id,'http'::text AS source,h.created,v.number AS version,
 NULL::text AS execution_state,false AS reserved,h.state,NULL::integer AS exit_code,NULL::text AS reason,
 h.started_at,h.finished_at,COALESCE(h.finished_at,h.started_at,h.created) AS updated,
 'admitted'::text AS admission,NULL::timestamptz AS scheduled_at,NULL::bigint AS trigger_revision,
 h.method,h.path,h.http_status,
 CASE WHEN h.finished_at IS NOT NULL THEN GREATEST(0,extract(epoch FROM (h.finished_at-h.created))*1000)::bigint END AS duration_ms
 FROM app_http_runs h JOIN app_releases l ON l.id=h.release_id JOIN app_versions v ON v.id=l.version_id;
