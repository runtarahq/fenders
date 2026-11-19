-- What decides whether an app serves, what a host name routes to, and what
-- a run's launch names. A transaction that changes any of it says so: it
-- sets fenders.gates_changed for itself, and notifies fenders_gates at
-- commit. What the gateway and the run channel keep in memory of these is
-- believed until then. A heartbeat or a scheduler pass that changes none of
-- it leaves them be.
CREATE OR REPLACE FUNCTION fenders_gates_changed() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    PERFORM set_config('fenders.gates_changed', '1', true);
    PERFORM pg_notify('fenders_gates', '');
    RETURN NULL;
END
$$;
DROP TRIGGER IF EXISTS executions_gates ON executions;
CREATE TRIGGER executions_gates AFTER UPDATE OF desired, state, reserved, generation, node_id, revision ON executions
    FOR EACH ROW WHEN (OLD.desired IS DISTINCT FROM NEW.desired OR OLD.state IS DISTINCT FROM NEW.state
        OR OLD.reserved IS DISTINCT FROM NEW.reserved OR OLD.generation IS DISTINCT FROM NEW.generation
        OR OLD.node_id IS DISTINCT FROM NEW.node_id OR OLD.revision IS DISTINCT FROM NEW.revision)
    EXECUTE FUNCTION fenders_gates_changed();
DROP TRIGGER IF EXISTS nodes_gates ON nodes;
CREATE TRIGGER nodes_gates AFTER UPDATE OF disabled, observed_confinement, boot_id ON nodes
    FOR EACH ROW WHEN (OLD.disabled IS DISTINCT FROM NEW.disabled
        OR OLD.observed_confinement IS DISTINCT FROM NEW.observed_confinement
        OR OLD.boot_id IS DISTINCT FROM NEW.boot_id)
    EXECUTE FUNCTION fenders_gates_changed();
DROP TRIGGER IF EXISTS app_http_gates ON app_http;
CREATE TRIGGER app_http_gates AFTER INSERT OR DELETE OR UPDATE OF state, execution_id, generation, blocked, idle_draining, deployment_id, candidate_execution_id, candidate_until ON app_http
    FOR EACH ROW EXECUTE FUNCTION fenders_gates_changed();
DROP TRIGGER IF EXISTS app_http_extras_gates ON app_http_extras;
CREATE TRIGGER app_http_extras_gates AFTER INSERT OR DELETE OR UPDATE ON app_http_extras
    FOR EACH ROW EXECUTE FUNCTION fenders_gates_changed();
DROP TRIGGER IF EXISTS apps_gates ON apps;
CREATE TRIGGER apps_gates AFTER UPDATE OF desired, target_release_id, configuration ON apps
    FOR EACH ROW WHEN (OLD.desired IS DISTINCT FROM NEW.desired
        OR OLD.target_release_id IS DISTINCT FROM NEW.target_release_id
        OR OLD.configuration IS DISTINCT FROM NEW.configuration)
    EXECUTE FUNCTION fenders_gates_changed();
DROP TRIGGER IF EXISTS app_triggers_gates ON app_triggers;
CREATE TRIGGER app_triggers_gates AFTER INSERT OR DELETE OR UPDATE OF http ON app_triggers
    FOR EACH ROW EXECUTE FUNCTION fenders_gates_changed();
DROP TRIGGER IF EXISTS app_releases_gates ON app_releases;
CREATE TRIGGER app_releases_gates AFTER UPDATE OF state ON app_releases
    FOR EACH ROW WHEN (OLD.state IS DISTINCT FROM NEW.state)
    EXECUTE FUNCTION fenders_gates_changed();
DROP TRIGGER IF EXISTS deployments_gates ON deployments;
CREATE TRIGGER deployments_gates AFTER UPDATE OF desired, revision ON deployments
    FOR EACH ROW WHEN (OLD.desired IS DISTINCT FROM NEW.desired OR OLD.revision IS DISTINCT FROM NEW.revision)
    EXECUTE FUNCTION fenders_gates_changed();
DROP TRIGGER IF EXISTS routes_gates ON routes;
CREATE TRIGGER routes_gates AFTER INSERT OR DELETE OR UPDATE ON routes
    FOR EACH ROW EXECUTE FUNCTION fenders_gates_changed();
DROP TRIGGER IF EXISTS tenants_gates ON tenants;
CREATE TRIGGER tenants_gates AFTER UPDATE OF lifecycle_state, http_concurrent_requests, http_requests_per_minute, transfer_bytes ON tenants
    FOR EACH ROW WHEN (OLD.lifecycle_state IS DISTINCT FROM NEW.lifecycle_state
        OR OLD.http_concurrent_requests IS DISTINCT FROM NEW.http_concurrent_requests
        OR OLD.http_requests_per_minute IS DISTINCT FROM NEW.http_requests_per_minute
        OR OLD.transfer_bytes IS DISTINCT FROM NEW.transfer_bytes)
    EXECUTE FUNCTION fenders_gates_changed();
