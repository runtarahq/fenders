WITH victims AS MATERIALIZED (
    SELECT id FROM execution_inputs_retirable ORDER BY updated,id LIMIT 256
)
UPDATE executions e SET inputs_retired_at=now(),
    original_spec_sha256=encode(sha256(convert_to(e.spec::text,'UTF8')),'hex'),
    spec=e.spec-ARRAY['env','endpoint_env']
FROM victims v WHERE e.id=v.id
