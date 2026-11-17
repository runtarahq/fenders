-- Customer observations mirror execution-bound runtime approval. A valid DNS
-- binding alone cannot authorize a withdrawn runtime or a different host boot.
CREATE OR REPLACE VIEW app_https_observations AS
SELECT id,tenant_id,project_id,app_id,origin,created,updated,desired,
       revocation_operation_id,enabled,state,
       CASE WHEN state='allowed' THEN NULL
            WHEN state='revoking' THEN 'waiting-for-execution-fence'
            WHEN NOT enabled THEN 'public-policy-disabled'
            ELSE 'execution-binding-required' END AS reason
FROM (
  SELECT c.id,c.tenant_id,c.project_id,c.app_id,c.origin,c.created,c.updated,
         c.state='active' AS desired,c.revocation_operation_id,p.enabled,
         CASE WHEN c.state='revoking' THEN 'revoking'
              WHEN p.enabled AND EXISTS (
                SELECT 1 FROM app_execution_https x
                JOIN execution_https_bindings b ON b.execution_id=x.execution_id
                JOIN executions e ON e.id=x.execution_id
                JOIN nodes n ON n.id=e.node_id
                WHERE x.connection_id=c.id AND NOT b.fenced
                  AND b.policy_digest=p.digest AND b.validated_until>clock_timestamp()
                  AND e.reserved AND e.desired<>'stopped' AND NOT n.disabled
                  AND n.network_leases AND n.observed_network_leases
                  AND n.observed_confinement='landlock6-seccomp-v2'
                  AND (e.public_https_runtime=n.public_https_runtime
                       OR n.retained_https_runtimes @> to_jsonb(ARRAY[e.public_https_runtime]))
                  AND ((e.public_https_runtime=n.public_https_runtime
                        AND e.public_https_runtime=n.observed_runtime_digest)
                    OR (e.observation->'generation'=to_jsonb(e.generation)
                        AND e.observation->>'state' IN ('starting','running','paused')
                        AND e.observation->'runtime_authority'=jsonb_build_object(
                          'contract','execution-runtime-v1','boot_id',n.boot_id,
                          'runtime_digest',e.public_https_runtime)))
              ) THEN 'allowed' ELSE 'pending' END AS state
  FROM app_https_connections c CROSS JOIN public_egress_policy p
  WHERE c.state<>'revoked'
) o;
