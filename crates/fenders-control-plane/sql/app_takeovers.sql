-- An app's serving execution changed (a new release took over, or an app
-- started serving): the edge that holds its queue tells the shims waiting
-- on it, and on the candidate's, to ask again, so that the execution taken
-- over from takes nothing more. Payload: the app, and the candidate that
-- took over, if one did.
CREATE OR REPLACE FUNCTION fenders_app_takeover() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_notify('fenders_app', NEW.app_id || ':' || COALESCE(OLD.candidate_execution_id, ''));
    RETURN NULL;
END
$$;
DROP TRIGGER IF EXISTS app_http_takeover ON app_http;
CREATE TRIGGER app_http_takeover AFTER UPDATE OF execution_id ON app_http
    FOR EACH ROW WHEN (OLD.execution_id IS DISTINCT FROM NEW.execution_id AND NEW.execution_id IS NOT NULL)
    EXECUTE FUNCTION fenders_app_takeover();
