-- Fast pickup: notifications are delivered at commit, so a woken scheduler or
-- node always sees the change that woke it.
CREATE OR REPLACE FUNCTION fenders_execution_notify() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.node_id IS NULL AND NEW.reserved AND NEW.desired = 'running' THEN
        PERFORM pg_notify('fenders_schedule', '');
    END IF;
    IF NEW.node_id IS NOT NULL THEN
        PERFORM pg_notify('fenders_assignment', NEW.node_id);
    END IF;
    IF TG_OP = 'UPDATE' AND OLD.node_id IS NOT NULL
        AND OLD.node_id IS DISTINCT FROM NEW.node_id THEN
        PERFORM pg_notify('fenders_assignment', OLD.node_id);
    END IF;
    RETURN NULL;
END
$$;
DROP TRIGGER IF EXISTS executions_pickup_notify ON executions;
CREATE TRIGGER executions_pickup_notify
    AFTER INSERT OR UPDATE OF node_id, desired, generation, reserved ON executions
    FOR EACH ROW EXECUTE FUNCTION fenders_execution_notify();
