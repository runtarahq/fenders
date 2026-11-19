-- A lease of a workspace's transfer allowance the operator recalled to change
-- the allowance: the session that holds it gives back what it has not
-- reserved for requests in flight at its next flush, and clears this.
ALTER TABLE gateway_transfer_leases ADD COLUMN IF NOT EXISTS recalled boolean NOT NULL DEFAULT false;
