-- When an edge was last heard from: by its gateway session's flush, and by
-- its last flush when it closes. An edge that restarts keeps its apps for
-- as long as a session that stopped flushing would be believed.
ALTER TABLE edges ADD COLUMN IF NOT EXISTS seen timestamptz
