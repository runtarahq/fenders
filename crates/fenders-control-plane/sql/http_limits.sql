-- How many requests of a workspace's HTTP apps may be in flight at once and
-- how many may be admitted in a minute: limits of its plan, which an
-- operator sets. They were the constants 16 and 600, and still are until
-- set. Every statement can be run again on a database that already had it.
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS http_concurrent_requests integer NOT NULL DEFAULT 16 CHECK (http_concurrent_requests > 0);
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS http_requests_per_minute integer NOT NULL DEFAULT 600 CHECK (http_requests_per_minute > 0);
