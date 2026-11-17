WITH victims AS MATERIALIZED (
    SELECT p.execution_id FROM execution_placement p
    JOIN executions e ON e.id=p.execution_id
    WHERE NOT e.reserved AND p.generation<=e.generation
      AND greatest(p.observed_at,e.created,e.updated,e.finished_at)<now()-interval '30 days'
      AND (
        (e.state='stopped' AND e.node_id IS NULL)
        OR (e.state IN ('exited','failed') AND e.finished_at IS NOT NULL AND CASE
          WHEN e.observation->>'exit_code' ~ '^[0-9]{1,3}$'
          THEN (e.observation->>'exit_code')::integer BETWEEN 0 AND 255
          ELSE false END)
      )
    ORDER BY p.observed_at,p.execution_id LIMIT 256
)
DELETE FROM execution_placement p USING victims v WHERE p.execution_id=v.execution_id
