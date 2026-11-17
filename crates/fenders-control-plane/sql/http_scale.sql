-- HTTP apps on more than one execution, and a release that takes over
-- without a gap. Every statement can be run again on a database that
-- already had it.

-- The executions of an app beyond its first, started under load and stopped
-- when idle. They belong to one generation of the app's HTTP binding: a
-- later generation's are other rows.
CREATE TABLE IF NOT EXISTS app_http_extras (
    execution_id text PRIMARY KEY,
    app_id text NOT NULL,
    tenant_id text NOT NULL,
    project_id text NOT NULL,
    generation integer NOT NULL,
    created timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS app_http_extras_app ON app_http_extras(app_id);

-- The execution of a release that is being brought up beside the one that
-- serves, and until when it has to become ready.
ALTER TABLE app_http ADD COLUMN IF NOT EXISTS candidate_execution_id text;
ALTER TABLE app_http ADD COLUMN IF NOT EXISTS candidate_until timestamptz;

-- A generation of an app's binding had one execution, and so one attempt.
-- It now has one for each execution; attempts are read by execution.
ALTER TABLE app_http_attempts DROP CONSTRAINT IF EXISTS app_http_attempts_app_id_generation_key;
