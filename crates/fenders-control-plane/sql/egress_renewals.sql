-- Revisions of a run's outbound grant that renewals answered from memory may
-- take (src/renewal.rs): a grant written here reserves those above it, and a
-- revision a renewal may have issued is accepted as current.
ALTER TABLE execution_egress_budgets ADD COLUMN IF NOT EXISTS revision_reserved bigint NOT NULL DEFAULT 0;
