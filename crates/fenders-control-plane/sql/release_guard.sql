-- A request's reservation, recorded by an edge without the mutation lock,
-- waits only for releases' inputs being retired, which hold this lock
-- (184923782) alone, not the mutation lock: a burst of wakes recorded
-- reservations one at a time behind every scheduler pass. Retirement takes
-- it before it looks for references: a reservation recorded before is seen
-- by it, and one recorded after finds the release retired. An app's
-- choice of release is made under the mutation lock, as it was.
CREATE OR REPLACE FUNCTION release_input_reference_guard() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF TG_TABLE_NAME='apps' THEN
        PERFORM pg_advisory_xact_lock(184923781);
        IF EXISTS(SELECT 1 FROM app_releases WHERE id IN (NEW.active_release_id,NEW.target_release_id) AND inputs_retired_at IS NOT NULL) THEN
            RAISE EXCEPTION 'retired release cannot be selected; create a fresh release from its code' USING ERRCODE='23514';
        END IF;
    ELSE
        PERFORM pg_advisory_xact_lock_shared(184923782);
        IF EXISTS(SELECT 1 FROM app_releases WHERE id=NEW.release_id AND inputs_retired_at IS NOT NULL) THEN
            RAISE EXCEPTION 'retired release cannot admit new work' USING ERRCODE='23514';
        END IF;
    END IF;
    RETURN NEW;
END $$
