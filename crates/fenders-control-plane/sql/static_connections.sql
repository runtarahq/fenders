-- Connections are static launch policy: an execution is told what it may
-- reach when it is assigned, and removing a connection stops the executions
-- launched with it. Network leases, their revisions and acknowledgements, and
-- per-node approval of a guest runtime for public HTTPS are gone.
-- Every statement can be run again on a database that already had it.

-- Allowed means a run started now would be given the origin; its addresses are
-- resolved for each run when it is assigned.
CREATE OR REPLACE VIEW app_https_observations AS
SELECT id,tenant_id,project_id,app_id,origin,created,updated,desired,
       revocation_operation_id,enabled,state,
       CASE WHEN state='allowed' THEN NULL
            WHEN state='revoking' THEN 'waiting-for-execution-fence'
            ELSE 'public-policy-disabled' END AS reason
FROM (
  SELECT c.id,c.tenant_id,c.project_id,c.app_id,c.origin,c.created,c.updated,
         c.state='active' AS desired,c.revocation_operation_id,p.enabled,
         CASE WHEN c.state='revoking' THEN 'revoking'
              WHEN p.enabled THEN 'allowed' ELSE 'pending' END AS state
  FROM app_https_connections c CROSS JOIN public_egress_policy p
  WHERE c.state<>'revoked'
) o;

-- One record of the executions an operation stopped by removing a
-- connection, TCP or HTTPS; the operation is done when they have ended.
ALTER TABLE IF EXISTS https_revocations RENAME TO connection_revocations;
DROP TABLE IF EXISTS network_revocations;
DROP VIEW IF EXISTS endpoint_binding_observations;

-- app_run_observations as in the baseline, but for the reason a run stopped
-- by such an operation reads with: `connection-removed`, whichever kind of
-- connection it was.
CREATE OR REPLACE VIEW app_run_observations AS
 SELECT r.id,
    r.tenant_id,
    r.project_id,
    r.app_id,
    r.release_id,
    r.execution_id,
    r.source,
    r.created,
    v.number AS version,
    e.state AS execution_state,
    COALESCE(e.reserved, false) AS reserved,
        CASE
            WHEN (r.admission = 'pending'::text) THEN 'queued'::text
            WHEN (r.admission = 'skipped'::text) THEN 'skipped'::text
            WHEN (r.admission = 'cancelled'::text) THEN 'cancelled'::text
            ELSE
            CASE e.state
                WHEN 'queued'::text THEN 'queued'::text
                WHEN 'starting'::text THEN 'starting'::text
                WHEN 'running'::text THEN 'running'::text
                WHEN 'paused'::text THEN 'running'::text
                WHEN 'stopping'::text THEN 'running'::text
                WHEN 'stopped'::text THEN 'cancelled'::text
                WHEN 'failed'::text THEN
                CASE
                    WHEN (((e.observation ->> 'reason'::text) = 'worker-lost'::text) AND ((e.observation ->> 'exit_code'::text) IS NULL)) THEN 'unknown'::text
                    ELSE 'failed'::text
                END
                WHEN 'exited'::text THEN
                CASE
                    WHEN ((e.observation ->> 'exit_code'::text) = '0'::text) THEN 'succeeded'::text
                    WHEN ((e.observation ->> 'exit_code'::text) IS NULL) THEN 'unknown'::text
                    ELSE 'failed'::text
                END
                ELSE 'unknown'::text
            END
        END AS state,
    ((e.observation ->> 'exit_code'::text))::integer AS exit_code,
    COALESCE(r.admission_reason, d.last_error,
        CASE
            WHEN ((e.state = 'stopped'::text) AND (NOT e.reserved) AND ((e.observation ->> 'reason'::text) = 'requested-stop'::text) AND (EXISTS ( SELECT 1
               FROM (connection_revocations h
                 JOIN operations o ON ((o.id = h.operation_id)))
              WHERE ((h.execution_id = e.id) AND (o.kind = 'app-connections'::text) AND (o.tenant_id = r.tenant_id) AND (o.project_id = r.project_id) AND (o.resource_id = r.app_id))))) THEN 'connection-removed'::text
            ELSE (e.observation ->> 'reason'::text)
        END) AS reason,
    e.started_at,
        CASE
            WHEN (r.admission = ANY (ARRAY['skipped'::text, 'cancelled'::text])) THEN r.admission_updated
            WHEN (e.state = ANY (ARRAY['exited'::text, 'stopped'::text, 'failed'::text, 'lost'::text])) THEN COALESCE(e.finished_at, e.updated)
            ELSE NULL::timestamp with time zone
        END AS finished_at,
    COALESCE(e.updated, r.admission_updated) AS updated,
    r.admission,
    r.scheduled_at,
    r.trigger_revision
   FROM ((((app_runs r
     LEFT JOIN executions e ON ((e.id = r.execution_id)))
     LEFT JOIN app_run_dispatch d ON ((d.run_id = r.id)))
     JOIN app_releases l ON ((l.id = r.release_id)))
     JOIN app_versions v ON ((v.id = l.version_id)));

ALTER TABLE execution_https_bindings DROP COLUMN IF EXISTS validated_until;
ALTER TABLE executions
  DROP COLUMN IF EXISTS network_ceiling,
  DROP COLUMN IF EXISTS network_policy,
  DROP COLUMN IF EXISTS network_revision,
  DROP COLUMN IF EXISTS network_ack,
  DROP COLUMN IF EXISTS public_https_runtime;
ALTER TABLE nodes DROP CONSTRAINT IF EXISTS nodes_egress_budget_required_check;
ALTER TABLE nodes
  DROP COLUMN IF EXISTS network_leases,
  DROP COLUMN IF EXISTS observed_network_leases,
  DROP COLUMN IF EXISTS public_https_runtime,
  DROP COLUMN IF EXISTS retained_https_runtimes,
  ADD CONSTRAINT nodes_egress_budget_required_check
    CHECK ((NOT egress_budget_required) OR (egress_budget_launcher IS NOT NULL));
