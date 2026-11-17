WITH candidates AS MATERIALIZED (
    SELECT a.id,a.digest FROM artifacts a
    WHERE a.retired_at IS NULL AND a.last_uploaded_at<now()-interval '7 days'
        AND NOT EXISTS(SELECT 1 FROM app_versions v WHERE v.artifact_id=a.id)
        AND NOT EXISTS(SELECT 1 FROM deployments d WHERE d.spec->>'artifact_id'=a.id)
        AND NOT EXISTS(SELECT 1 FROM executions e WHERE e.spec->>'artifact_id'=a.id)
        AND NOT EXISTS(SELECT 1 FROM artifact_validations v WHERE v.artifact_id=a.id AND v.state='validating' AND v.lease_until>now())
    ORDER BY a.last_uploaded_at,a.id LIMIT 64 FOR UPDATE OF a
), retired AS (
    UPDATE artifacts a SET retired_at=now() FROM candidates c WHERE a.id=c.id RETURNING a.id,a.digest,a.tenant_id,a.size
), audited AS (
    INSERT INTO audit(tenant_id,actor,action,resource_id,detail) SELECT tenant_id,'retention','artifact.expire',id,jsonb_build_object('digest',digest,'bytes',size) FROM retired RETURNING sequence
), fenced AS (
    UPDATE artifact_validations v SET state='pending',inspection=NULL,error=NULL,node_id=NULL,node_boot=NULL,lease_until=NULL,
        generation=generation+1,updated=now() FROM retired a WHERE v.artifact_id=a.id RETURNING v.artifact_id
)
INSERT INTO artifact_blob_garbage(digest) SELECT DISTINCT digest FROM retired
ON CONFLICT(digest) DO NOTHING
