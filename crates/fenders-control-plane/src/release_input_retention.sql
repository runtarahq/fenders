WITH victims AS MATERIALIZED (
    SELECT id FROM release_inputs_retirable ORDER BY unreferenced_since,id LIMIT 256
)
UPDATE app_releases r SET inputs_retired_at=now(),
    original_inputs_sha256=encode(sha256(convert_to(jsonb_build_object('configuration',r.configuration,'spec',r.spec)::text,'UTF8')),'hex'),
    configuration=r.configuration-'env',spec=r.spec-ARRAY['env','endpoint_env']
FROM victims v WHERE r.id=v.id
