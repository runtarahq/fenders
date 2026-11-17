WITH keep AS MATERIALIZED (
    (SELECT generation,sequence FROM usage_samples WHERE execution_id=$1 AND tenant_id=$2
        ORDER BY generation DESC,sequence DESC LIMIT 1)
    UNION
    (SELECT generation,sequence FROM usage_samples WHERE execution_id=$1 AND tenant_id=$2 AND cpu_measured
        ORDER BY cpu_usec DESC,observed DESC,generation DESC,sequence DESC LIMIT 1)
    UNION
    (SELECT generation,sequence FROM usage_samples WHERE execution_id=$1 AND tenant_id=$2 AND cpu_measured
        ORDER BY observed DESC,generation DESC,sequence DESC LIMIT 1)
), victims AS MATERIALIZED (
    SELECT u.generation,u.sequence FROM usage_samples u WHERE u.execution_id=$1 AND u.tenant_id=$2
        AND NOT EXISTS(SELECT 1 FROM keep k WHERE k.generation=u.generation AND k.sequence=u.sequence)
    ORDER BY u.generation,u.sequence LIMIT $3
)
DELETE FROM usage_samples u USING victims v WHERE u.execution_id=$1 AND u.tenant_id=$2
    AND u.generation=v.generation AND u.sequence=v.sequence
