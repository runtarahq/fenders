-- WASM-only MVP baseline. Legacy managed-service databases require a fresh database.
SET LOCAL check_function_bodies = false;
CREATE FUNCTION app_dispatch_delivery_guard() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE retired timestamptz;
BEGIN
    IF TG_OP='DELETE' THEN
        SELECT dispatch_retired_at INTO retired FROM app_runs WHERE id=OLD.run_id FOR UPDATE;
        IF retired IS NULL THEN
            RAISE EXCEPTION 'dispatch deletion requires retirement' USING ERRCODE='23514';
        END IF;
        RETURN OLD;
    END IF;
    SELECT dispatch_retired_at INTO retired FROM app_runs WHERE id=NEW.run_id FOR UPDATE;
    IF retired IS NOT NULL THEN
        RAISE EXCEPTION 'retired dispatch cannot be replayed' USING ERRCODE='23514';
    END IF;
    IF TG_OP='UPDATE' AND NEW.run_id IS DISTINCT FROM OLD.run_id THEN
        RAISE EXCEPTION 'dispatch identity is immutable' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;

CREATE FUNCTION app_dispatch_retirement_atomic() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.dispatch_retired_at IS NOT NULL AND EXISTS(SELECT 1 FROM app_run_dispatch WHERE run_id=NEW.id) THEN
        RAISE EXCEPTION 'retirement must remove dispatch atomically' USING ERRCODE='23514';
    END IF;
    RETURN NULL;
END $$;

CREATE FUNCTION app_dispatch_retirement_guard() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF TG_OP='INSERT' THEN
        IF NEW.dispatch_retired_at IS NOT NULL THEN
            RAISE EXCEPTION 'new run cannot be retired' USING ERRCODE='23514';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.dispatch_retired_at IS NOT NULL THEN
        IF TG_OP='DELETE' OR NEW IS DISTINCT FROM OLD THEN
            RAISE EXCEPTION 'retired run identity is immutable' USING ERRCODE='23514';
        END IF;
    ELSIF TG_OP='UPDATE' AND NEW.dispatch_retired_at IS NOT NULL THEN
        IF NEW.dispatch_retired_at IS DISTINCT FROM transaction_timestamp()
           OR (to_jsonb(NEW)-'dispatch_retired_at') IS DISTINCT FROM (to_jsonb(OLD)-'dispatch_retired_at')
           OR NOT EXISTS(SELECT 1 FROM app_dispatch_retirable WHERE run_id=OLD.id) THEN
            RAISE EXCEPTION 'run is not eligible for dispatch retirement' USING ERRCODE='23514';
        END IF;
    END IF;
    IF TG_OP='DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END $$;

CREATE FUNCTION app_execution_lifecycle_changed() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    -- Heartbeats and arbitrary diagnostic text do not generate events. Only a
    -- fixed worker-lost classification influences the recorded outcome.
    IF (NEW.state,NEW.desired,NEW.generation,NEW.reserved,NEW.observation->>'exit_code',COALESCE(NEW.observation->>'reason'='worker-lost',false))
        IS DISTINCT FROM (OLD.state,OLD.desired,OLD.generation,OLD.reserved,OLD.observation->>'exit_code',COALESCE(OLD.observation->>'reason'='worker-lost',false)) THEN
        PERFORM record_app_execution_lifecycle(NEW.id,OLD.state,OLD.desired);
    END IF;
    RETURN NEW;
END $$;

CREATE FUNCTION app_lifecycle_changed() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    app text; release text; run text; execution text; origin text;
    current_state text; prior_state text; intent text; prior_intent text; gen bigint;
BEGIN
    IF TG_TABLE_NAME='apps' THEN
        IF TG_OP='UPDATE' AND NEW.desired=OLD.desired THEN RETURN NEW; END IF;
        app:=NEW.id; release:=NEW.target_release_id; current_state:=NEW.desired;
        IF TG_OP='UPDATE' THEN prior_state:=OLD.desired; END IF;
    ELSIF TG_TABLE_NAME='app_releases' THEN
        IF TG_OP='UPDATE' AND NEW.state=OLD.state THEN RETURN NEW; END IF;
        app:=NEW.app_id; release:=NEW.id; current_state:=NEW.state;
        IF TG_OP='UPDATE' THEN prior_state:=OLD.state; END IF;
    ELSIF TG_TABLE_NAME='app_http' THEN
        IF TG_OP='UPDATE' AND (NEW.state,NEW.blocked,NEW.generation,NEW.execution_id) IS NOT DISTINCT FROM (OLD.state,OLD.blocked,OLD.generation,OLD.execution_id) THEN RETURN NEW; END IF;
        app:=NEW.app_id; execution:=NEW.execution_id; origin:='http'; current_state:=NEW.state; gen:=NEW.generation;
        intent:=CASE WHEN NEW.blocked THEN 'blocked' ELSE 'unblocked' END;
        SELECT release_id INTO release FROM app_http_attempts WHERE execution_id=execution;
        IF TG_OP='UPDATE' THEN prior_state:=OLD.state; prior_intent:=CASE WHEN OLD.blocked THEN 'blocked' ELSE 'unblocked' END; END IF;
    ELSIF TG_TABLE_NAME='app_runs' THEN
        IF TG_OP='UPDATE' AND (NEW.admission,NEW.execution_id) IS NOT DISTINCT FROM (OLD.admission,OLD.execution_id) THEN RETURN NEW; END IF;
        app:=NEW.app_id; release:=NEW.release_id; run:=NEW.id; execution:=NEW.execution_id; origin:=NEW.source; current_state:=NEW.admission;
        IF TG_OP='UPDATE' THEN prior_state:=OLD.admission; END IF;
    ELSIF TG_TABLE_NAME='app_http_attempts' THEN
        PERFORM record_app_execution_lifecycle(NEW.execution_id,NULL,NULL);
        RETURN NEW;
    END IF;
    INSERT INTO app_lifecycle_events(tenant_id,project_id,app_id,kind,state,previous_state,release_id,version,run_id,execution_id,source,desired,previous_desired,generation)
    VALUES(NEW.tenant_id,NEW.project_id,app,CASE TG_TABLE_NAME WHEN 'apps' THEN 'app' WHEN 'app_releases' THEN 'release' WHEN 'app_http' THEN 'http' ELSE 'run' END,current_state,prior_state,release,
        (SELECT v.number FROM app_releases r JOIN app_versions v ON v.id=r.version_id WHERE r.id=release),run,execution,origin,intent,prior_intent,gen);
    IF TG_TABLE_NAME='app_runs' AND execution IS NOT NULL THEN
        IF TG_OP='INSERT' THEN PERFORM record_app_execution_lifecycle(execution,NULL,NULL);
        ELSIF NEW.execution_id IS DISTINCT FROM OLD.execution_id THEN PERFORM record_app_execution_lifecycle(execution,NULL,NULL); END IF;
    END IF;
    RETURN NEW;
END $$;

CREATE FUNCTION execution_input_retirement_guard() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF TG_OP='INSERT' THEN
        IF NEW.inputs_retired_at IS NOT NULL OR NEW.original_spec_sha256 IS NOT NULL THEN
            RAISE EXCEPTION 'new execution cannot have retired inputs' USING ERRCODE='23514';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.inputs_retired_at IS NOT NULL THEN
        IF TG_OP='DELETE' THEN
            RAISE EXCEPTION 'retired execution identity must remain' USING ERRCODE='23514';
        END IF;
        IF NEW.inputs_retired_at IS DISTINCT FROM OLD.inputs_retired_at
           OR NEW.original_spec_sha256 IS DISTINCT FROM OLD.original_spec_sha256
           OR NEW.spec IS DISTINCT FROM OLD.spec OR NEW.reserved
           OR NEW.state IS DISTINCT FROM OLD.state
           OR NEW.node_id IS DISTINCT FROM OLD.node_id THEN
            RAISE EXCEPTION 'retired execution inputs cannot be replaced or replayed' USING ERRCODE='23514';
        END IF;
    ELSIF TG_OP='UPDATE' AND (NEW.inputs_retired_at IS NOT NULL OR NEW.original_spec_sha256 IS NOT NULL) THEN
        IF NEW.inputs_retired_at IS DISTINCT FROM transaction_timestamp()
           OR NEW.original_spec_sha256 IS DISTINCT FROM encode(sha256(convert_to(OLD.spec::text,'UTF8')),'hex')
           OR NEW.spec IS DISTINCT FROM (OLD.spec-ARRAY['env','endpoint_env'])
           OR (to_jsonb(NEW)-ARRAY['spec','inputs_retired_at','original_spec_sha256'])
               IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['spec','inputs_retired_at','original_spec_sha256'])
           OR EXISTS(SELECT 1 FROM recovery_barrier WHERE active)
           OR NOT EXISTS(SELECT 1 FROM execution_inputs_retirable WHERE id=OLD.id) THEN
            RAISE EXCEPTION 'execution inputs are not eligible for retirement' USING ERRCODE='23514';
        END IF;
    END IF;
    IF TG_OP='DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END $$;

CREATE FUNCTION immutable_app_release() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(184923781);
    IF OLD.inputs_retired_at IS NOT NULL THEN
        IF NEW IS DISTINCT FROM OLD THEN
            RAISE EXCEPTION 'retired release evidence is immutable' USING ERRCODE='23514';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.inputs_retired_at IS NOT NULL OR NEW.original_inputs_sha256 IS NOT NULL THEN
        IF NEW.inputs_retired_at IS DISTINCT FROM transaction_timestamp()
            OR NEW.original_inputs_sha256 IS DISTINCT FROM encode(sha256(convert_to(jsonb_build_object('configuration',OLD.configuration,'spec',OLD.spec)::text,'UTF8')),'hex')
            OR NEW.configuration IS DISTINCT FROM (OLD.configuration-'env')
            OR NEW.spec IS DISTINCT FROM (OLD.spec-ARRAY['env','endpoint_env'])
            OR (to_jsonb(NEW)-ARRAY['configuration','spec','inputs_retired_at','original_inputs_sha256'])
                IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['configuration','spec','inputs_retired_at','original_inputs_sha256'])
            OR EXISTS(SELECT 1 FROM recovery_barrier WHERE active)
            OR NOT EXISTS(SELECT 1 FROM release_inputs_retirable WHERE id=OLD.id)
        THEN RAISE EXCEPTION 'release inputs are not eligible for retirement' USING ERRCODE='23514'; END IF;
        RETURN NEW;
    END IF;
    IF (NEW.id,NEW.tenant_id,NEW.project_id,NEW.app_id,NEW.version_id,NEW.configuration,NEW.spec,NEW.created)
        IS DISTINCT FROM (OLD.id,OLD.tenant_id,OLD.project_id,OLD.app_id,OLD.version_id,OLD.configuration,OLD.spec,OLD.created) THEN
        RAISE EXCEPTION 'release code and configuration are immutable' USING ERRCODE='23514';
    END IF;
    IF NEW.unreferenced_since IS DISTINCT FROM OLD.unreferenced_since THEN
        IF NOT ((NEW.unreferenced_since IS NULL AND EXISTS(SELECT 1 FROM apps a WHERE NEW.id IN (a.active_release_id,a.target_release_id)))
            OR (OLD.unreferenced_since IS NULL AND NEW.unreferenced_since=transaction_timestamp()
                AND NOT EXISTS(SELECT 1 FROM apps a WHERE NEW.id IN (a.active_release_id,a.target_release_id)))) THEN
            RAISE EXCEPTION 'release retention clock cannot be rewritten' USING ERRCODE='23514';
        END IF;
    END IF;
    RETURN NEW;
END $$;

CREATE FUNCTION immutable_app_version() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'app code versions are immutable' USING ERRCODE='23514';
END;
$$;

CREATE FUNCTION immutable_schedule_revision() RETURNS trigger
    LANGUAGE plpgsql
    AS $$ BEGIN
    RAISE EXCEPTION 'schedule revisions are immutable' USING ERRCODE='23514';
END $$;

CREATE FUNCTION record_app_execution_lifecycle(execution text, previous text, prior_desired text) RETURNS void
    LANGUAGE sql
    AS $$
    INSERT INTO app_lifecycle_events(tenant_id,project_id,app_id,kind,state,previous_state,release_id,version,run_id,execution_id,source,desired,previous_desired,generation,reserved,outcome,exit_code)
    SELECT c.tenant_id,c.project_id,c.app_id,'execution',e.state,previous,c.release_id,c.version,c.run_id,e.id,c.source,e.desired,prior_desired,e.generation,e.reserved,
        CASE WHEN c.source='http' THEN NULL
            WHEN e.state='stopped' THEN 'cancelled'
            WHEN e.state='exited' THEN CASE WHEN e.observation->>'exit_code'='0' THEN 'succeeded' WHEN e.observation->>'exit_code' IS NULL THEN 'unknown' ELSE 'failed' END
            WHEN e.state='failed' THEN CASE WHEN e.observation->>'reason'='worker-lost' AND e.observation->>'exit_code' IS NULL THEN 'unknown' ELSE 'failed' END
            WHEN e.state='lost' THEN 'unknown' END,
        (e.observation->>'exit_code')::integer
    FROM executions e JOIN app_execution_contexts c ON c.execution_id=e.id WHERE e.id=execution;
$$;

CREATE FUNCTION release_input_identity_guard() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF TG_OP='DELETE' AND OLD.inputs_retired_at IS NOT NULL THEN
        RAISE EXCEPTION 'retired release identity must remain' USING ERRCODE='23514';
    ELSIF TG_OP='INSERT' AND (NEW.inputs_retired_at IS NOT NULL OR NEW.original_inputs_sha256 IS NOT NULL
        OR NEW.unreferenced_since IS DISTINCT FROM transaction_timestamp()) THEN
        RAISE EXCEPTION 'new release requires intact inputs and a fresh retention clock' USING ERRCODE='23514';
    END IF;
    IF TG_OP='DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END $$;

CREATE FUNCTION release_input_reference_clock() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF TG_OP='UPDATE' THEN
        UPDATE app_releases SET unreferenced_since=now()
        WHERE id IN (OLD.active_release_id,OLD.target_release_id) AND unreferenced_since IS NULL
            AND NOT EXISTS(SELECT 1 FROM apps a WHERE app_releases.id IN (a.active_release_id,a.target_release_id));
    END IF;
    UPDATE app_releases SET unreferenced_since=NULL
        WHERE id IN (NEW.active_release_id,NEW.target_release_id) AND unreferenced_since IS NOT NULL;
    RETURN NEW;
END $$;

CREATE FUNCTION release_input_reference_guard() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(184923781);
    IF TG_TABLE_NAME='apps' THEN
        IF EXISTS(SELECT 1 FROM app_releases WHERE id IN (NEW.active_release_id,NEW.target_release_id) AND inputs_retired_at IS NOT NULL) THEN
            RAISE EXCEPTION 'retired release cannot be selected; create a fresh release from its code' USING ERRCODE='23514';
        END IF;
    ELSE
        IF EXISTS(SELECT 1 FROM app_releases WHERE id=NEW.release_id AND inputs_retired_at IS NOT NULL) THEN
            RAISE EXCEPTION 'retired release cannot admit new work' USING ERRCODE='23514';
        END IF;
    END IF;
    RETURN NEW;
END $$;

CREATE TABLE accounting_month_rollups (
    tenant_id text NOT NULL,
    project_id text NOT NULL,
    period date NOT NULL,
    outbound_accounted_bytes numeric(30,0) DEFAULT 0 NOT NULL,
    outbound_conservative_bytes numeric(30,0) DEFAULT 0 NOT NULL,
    settlement_records bigint DEFAULT 0 NOT NULL,
    observed_outbound_bytes numeric(30,0) DEFAULT 0 NOT NULL,
    observed_period_records bigint DEFAULT 0 NOT NULL,
    observed_at timestamp with time zone,
    CONSTRAINT accounting_month_rollups_check CHECK (((outbound_conservative_bytes >= (0)::numeric) AND (outbound_conservative_bytes <= outbound_accounted_bytes))),
    CONSTRAINT accounting_month_rollups_observed_outbound_bytes_check CHECK ((observed_outbound_bytes >= (0)::numeric)),
    CONSTRAINT accounting_month_rollups_observed_period_records_check CHECK ((observed_period_records >= 0)),
    CONSTRAINT accounting_month_rollups_outbound_accounted_bytes_check CHECK ((outbound_accounted_bytes >= (0)::numeric)),
    CONSTRAINT accounting_month_rollups_period_check CHECK ((period = (date_trunc('month'::text, (period)::timestamp with time zone))::date)),
    CONSTRAINT accounting_month_rollups_settlement_records_check CHECK ((settlement_records >= 0))
);

CREATE TABLE app_endpoint_connections (
    id text NOT NULL,
    tenant_id text NOT NULL,
    project_id text NOT NULL,
    app_id text NOT NULL,
    endpoint_id text NOT NULL,
    prefix text DEFAULT ''::text NOT NULL,
    state text DEFAULT 'active'::text NOT NULL,
    revocation_operation_id text,
    created timestamp with time zone DEFAULT now() NOT NULL,
    updated timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT app_endpoint_connections_check CHECK (((state = 'active'::text) = (revocation_operation_id IS NULL))),
    CONSTRAINT app_endpoint_connections_state_check CHECK ((state = ANY (ARRAY['active'::text, 'revoking'::text, 'revoked'::text])))
);

CREATE TABLE app_http (
    app_id text NOT NULL,
    tenant_id text NOT NULL,
    project_id text NOT NULL,
    hostname text NOT NULL,
    deployment_id text,
    execution_id text,
    generation integer DEFAULT 0 NOT NULL,
    state text DEFAULT 'disabled'::text NOT NULL,
    reason text,
    blocked boolean DEFAULT false NOT NULL,
    drain_until timestamp with time zone,
    ready_until timestamp with time zone,
    failures integer DEFAULT 0 NOT NULL,
    restart_after timestamp with time zone,
    failure_window timestamp with time zone DEFAULT now() NOT NULL,
    updated timestamp with time zone DEFAULT now() NOT NULL,
    last_activity timestamp with time zone DEFAULT now() NOT NULL,
    idle_draining boolean DEFAULT false NOT NULL,
    CONSTRAINT app_http_failures_check CHECK ((failures >= 0)),
    CONSTRAINT app_http_generation_check CHECK ((generation >= 0)),
    CONSTRAINT app_http_state_check CHECK ((state = ANY (ARRAY['disabled'::text, 'starting'::text, 'serving'::text, 'stopping'::text, 'unavailable'::text, 'idle'::text])))
);

CREATE TABLE executions (
    id text NOT NULL,
    tenant_id text NOT NULL,
    project_id text NOT NULL,
    deployment_id text,
    revision integer DEFAULT 1 NOT NULL,
    spec jsonb NOT NULL,
    node_id text,
    generation bigint DEFAULT 1 NOT NULL,
    desired text DEFAULT 'running'::text NOT NULL,
    state text DEFAULT 'queued'::text NOT NULL,
    cpu_percent bigint NOT NULL,
    memory_mib bigint NOT NULL,
    reserved boolean DEFAULT true NOT NULL,
    observation jsonb DEFAULT '{}'::jsonb NOT NULL,
    created timestamp with time zone DEFAULT now() NOT NULL,
    updated timestamp with time zone DEFAULT now() NOT NULL,
    network_ceiling jsonb,
    network_policy jsonb DEFAULT '[]'::jsonb NOT NULL,
    network_revision bigint DEFAULT 1 NOT NULL,
    network_ack bigint DEFAULT 0 NOT NULL,
    started_at timestamp with time zone,
    finished_at timestamp with time zone,
    log_ingestion_fenced boolean DEFAULT false NOT NULL,
    egress_budget_launcher text,
    public_https_runtime text CHECK (public_https_runtime ~ '^[a-f0-9]{64}$'),
    inputs_retired_at timestamp with time zone,
    original_spec_sha256 text,
    CONSTRAINT execution_input_retirement_metadata CHECK ((((inputs_retired_at IS NULL) AND (original_spec_sha256 IS NULL)) OR ((inputs_retired_at IS NOT NULL) AND (original_spec_sha256 IS NOT NULL) AND (original_spec_sha256 ~ '^[0-9a-f]{64}$'::text) AND (NOT (spec ?| ARRAY['env'::text, 'endpoint_env'::text]))))),
    CONSTRAINT executions_desired_check CHECK ((desired = ANY (ARRAY['running'::text, 'paused'::text, 'stopped'::text]))),
    CONSTRAINT executions_egress_budget_launcher_check CHECK (((egress_budget_launcher IS NULL) OR (egress_budget_launcher ~ '^[a-f0-9]{64}$'::text))),
    CONSTRAINT executions_state_check CHECK ((state = ANY (ARRAY['queued'::text, 'starting'::text, 'running'::text, 'paused'::text, 'stopping'::text, 'exited'::text, 'failed'::text, 'stopped'::text, 'lost'::text, 'unreachable'::text])))
);

CREATE TABLE nodes (
    id text NOT NULL,
    name text NOT NULL,
    cert_sha256 text NOT NULL,
    endpoint text NOT NULL,
    backend text NOT NULL,
    architecture text NOT NULL,
    runtime text NOT NULL,
    cpu_percent bigint NOT NULL,
    memory_mib bigint NOT NULL,
    instances integer NOT NULL,
    draining boolean DEFAULT false NOT NULL,
    disabled boolean DEFAULT false NOT NULL,
    boot_id text,
    last_seen timestamp with time zone,
    created timestamp with time zone DEFAULT now() NOT NULL,
    network_leases boolean DEFAULT false NOT NULL,
    observed_network_leases boolean DEFAULT false NOT NULL,
    observed_confinement text,
    public_https_runtime text,
    observed_runtime_digest text,
    egress_budget_launcher text,
    observed_egress_budget text,
    observed_launcher_digest text,
    retained_egress_launchers jsonb DEFAULT '[]'::jsonb NOT NULL CHECK (jsonb_typeof(retained_egress_launchers)='array' AND jsonb_array_length(retained_egress_launchers)<=32),
    retained_https_runtimes jsonb DEFAULT '[]'::jsonb NOT NULL CHECK (jsonb_typeof(retained_https_runtimes)='array' AND jsonb_array_length(retained_https_runtimes)<=32),
    egress_budget_required boolean DEFAULT false NOT NULL,
    CONSTRAINT nodes_backend_check CHECK ((backend = 'wasm'::text)),
    CONSTRAINT nodes_cpu_percent_check CHECK ((cpu_percent > 0)),
    CONSTRAINT nodes_egress_budget_required_check CHECK (((NOT egress_budget_required) OR (network_leases AND (egress_budget_launcher IS NOT NULL)))),
    CONSTRAINT nodes_instances_check CHECK ((instances > 0)),
    CONSTRAINT nodes_memory_mib_check CHECK ((memory_mib > 0)),
    CONSTRAINT nodes_observed_runtime_digest_check CHECK ((observed_runtime_digest ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT nodes_public_https_runtime_check CHECK ((public_https_runtime ~ '^[0-9a-f]{64}$'::text))
);

CREATE VIEW app_http_observations AS
 SELECT h.app_id,
    h.tenant_id,
    h.project_id,
    h.hostname,
    h.execution_id,
        CASE
            WHEN ((h.state = 'serving'::text) AND (NOT COALESCE(((n.id IS NOT NULL) AND (NOT n.disabled) AND (n.last_seen > (now() - '00:00:15'::interval)) AND (n.observed_confinement = 'landlock6-seccomp-v2'::text) AND (e.state = 'running'::text) AND (e.desired = 'running'::text) AND e.reserved), false))) THEN 'unavailable'::text
            ELSE h.state
        END AS state,
        CASE
            WHEN ((h.state = 'serving'::text) AND (NOT COALESCE(((n.id IS NOT NULL) AND (NOT n.disabled) AND (n.last_seen > (now() - '00:00:15'::interval)) AND (n.observed_confinement = 'landlock6-seccomp-v2'::text) AND (e.state = 'running'::text) AND (e.desired = 'running'::text) AND e.reserved), false))) THEN 'worker-unavailable'::text
            ELSE h.reason
        END AS reason
   FROM ((app_http h
     LEFT JOIN executions e ON ((e.id = h.execution_id)))
     LEFT JOIN nodes n ON ((n.id = e.node_id)));

CREATE TABLE app_triggers (
    app_id text NOT NULL,
    tenant_id text NOT NULL,
    project_id text NOT NULL,
    revision bigint DEFAULT 1 NOT NULL,
    manual boolean DEFAULT false NOT NULL,
    updated timestamp with time zone DEFAULT now() NOT NULL,
    http boolean DEFAULT false NOT NULL,
    CONSTRAINT app_triggers_revision_check CHECK ((revision > 0))
);

CREATE TABLE apps (
    id text NOT NULL,
    tenant_id text NOT NULL,
    project_id text NOT NULL,
    name text NOT NULL,
    revision bigint DEFAULT 1 NOT NULL,
    latest_version bigint DEFAULT 1 NOT NULL,
    created timestamp with time zone DEFAULT now() NOT NULL,
    updated timestamp with time zone DEFAULT now() NOT NULL,
    desired text DEFAULT 'stopped'::text NOT NULL,
    configuration jsonb DEFAULT '{"env": {}, "size": "small", "secret_env": {}}'::jsonb NOT NULL,
    active_release_id text,
    target_release_id text,
    CONSTRAINT apps_desired_check CHECK ((desired = ANY (ARRAY['enabled'::text, 'stopped'::text]))),
    CONSTRAINT apps_latest_version_check CHECK ((latest_version > 0)),
    CONSTRAINT apps_revision_check CHECK ((revision > 0))
);

CREATE TABLE external_endpoints (
    id text NOT NULL,
    tenant_id text NOT NULL,
    project_id text NOT NULL,
    network_id text NOT NULL,
    name text NOT NULL,
    host text NOT NULL,
    address inet NOT NULL,
    port integer NOT NULL,
    database text NOT NULL,
    username_secret_id text,
    password_secret_id text,
    ca_certificate text DEFAULT ''::text NOT NULL,
    deleted boolean DEFAULT false NOT NULL,
    created timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT external_endpoints_address_check CHECK (((family(address) = 4) AND (masklen(address) = 32))),
    CONSTRAINT external_endpoints_port_check CHECK (((port >= 1) AND (port <= 65535)))
);

CREATE VIEW app_connection_observations AS
 SELECT c.id,
    c.tenant_id,
    c.project_id,
    c.app_id,
    c.endpoint_id,
    c.prefix,
    c.revocation_operation_id,
    c.created,
    c.updated,
    (c.state = 'active'::text) AS desired,
    e.name,
        CASE
            WHEN (c.state = 'revoking'::text) THEN 'revoking'::text
            WHEN (r.reason IS NULL) THEN 'allowed'::text
            ELSE 'pending'::text
        END AS state,
    r.reason
   FROM (((((app_endpoint_connections c
     JOIN external_endpoints e ON ((e.id = c.endpoint_id)))
     JOIN apps a ON ((a.id = c.app_id)))
     JOIN app_triggers t ON ((t.app_id = a.id)))
     LEFT JOIN app_http_observations h ON ((h.app_id = a.id)))
     CROSS JOIN LATERAL ( SELECT
                CASE
                    WHEN (c.state = 'revoking'::text) THEN 'waiting-for-enforcement'::text
                    WHEN e.deleted THEN 'endpoint-deleted'::text
                    WHEN ((a.desired = 'enabled'::text) AND t.http AND ((a.target_release_id IS DISTINCT FROM a.active_release_id) OR (COALESCE(h.state, 'disabled'::text) <> ALL (ARRAY['serving'::text, 'idle'::text])))) THEN 'http-release-pending'::text
                    ELSE NULL::text
                END AS reason) r)
  WHERE (c.state <> 'revoked'::text);

CREATE TABLE app_run_dispatch (
    run_id text NOT NULL,
    tenant_id text NOT NULL,
    project_id text NOT NULL,
    app_id text NOT NULL,
    state text DEFAULT 'pending'::text NOT NULL,
    deadline timestamp with time zone NOT NULL,
    attempts bigint DEFAULT 0 NOT NULL,
    last_error text,
    created timestamp with time zone DEFAULT now() NOT NULL,
    updated timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT app_run_dispatch_state_check CHECK ((state = ANY (ARRAY['pending'::text, 'dispatched'::text, 'cancelled'::text])))
);

CREATE TABLE app_runs (
    id text NOT NULL,
    tenant_id text NOT NULL,
    project_id text NOT NULL,
    app_id text NOT NULL,
    release_id text NOT NULL,
    execution_id text,
    source text NOT NULL,
    created timestamp with time zone DEFAULT now() NOT NULL,
    admission text DEFAULT 'admitted'::text NOT NULL,
    admission_reason text,
    admission_updated timestamp with time zone DEFAULT now() NOT NULL,
    scheduled_at timestamp with time zone,
    trigger_revision bigint,
    dispatch_retired_at timestamp with time zone,
    CONSTRAINT app_runs_admission_check CHECK ((admission = ANY (ARRAY['pending'::text, 'admitted'::text, 'skipped'::text, 'cancelled'::text]))),
    CONSTRAINT app_runs_admission_execution CHECK ((((admission = 'pending'::text) AND (execution_id IS NULL)) OR ((admission = 'admitted'::text) AND (execution_id IS NOT NULL)) OR (admission = ANY (ARRAY['skipped'::text, 'cancelled'::text])))),
    CONSTRAINT app_runs_schedule_identity CHECK ((((source = 'schedule'::text) AND (trigger_revision IS NOT NULL) AND (scheduled_at IS NOT NULL)) OR ((source <> 'schedule'::text) AND (trigger_revision IS NULL) AND (scheduled_at IS NULL)))),
    CONSTRAINT app_runs_source_check CHECK ((source = ANY (ARRAY['manual'::text, 'schedule'::text, 'test-schedule'::text])))
);

CREATE VIEW app_dispatch_retirable AS
 SELECT d.run_id,
    d.updated
   FROM ((app_run_dispatch d
     JOIN app_runs r ON ((r.id = d.run_id)))
     LEFT JOIN executions e ON ((e.id = r.execution_id)))
  WHERE ((r.source = 'schedule'::text) AND (r.dispatch_retired_at IS NULL) AND (d.state = ANY (ARRAY['dispatched'::text, 'cancelled'::text])) AND (r.admission = ANY (ARRAY['admitted'::text, 'skipped'::text, 'cancelled'::text])) AND ((d.last_error IS NULL) OR (r.admission_reason IS NOT NULL)) AND (GREATEST(d.created, d.updated, d.deadline, r.created, r.admission_updated, e.created, e.updated, e.finished_at) < (now() - '30 days'::interval)) AND (((r.execution_id IS NULL) AND (r.admission = ANY (ARRAY['skipped'::text, 'cancelled'::text])) AND (r.admission_reason IS NOT NULL)) OR ((NOT e.reserved) AND (((e.state = 'stopped'::text) AND (e.node_id IS NULL)) OR ((e.state = ANY (ARRAY['exited'::text, 'failed'::text])) AND
        CASE
            WHEN ((e.observation ->> 'exit_code'::text) ~ '^[0-9]{1,3}$'::text) THEN ((((e.observation ->> 'exit_code'::text))::integer >= 0) AND (((e.observation ->> 'exit_code'::text))::integer <= 255))
            ELSE false
        END)))));

CREATE TABLE app_execution_connections (
    tenant_id text NOT NULL,
    project_id text NOT NULL,
    app_id text NOT NULL,
    execution_id text NOT NULL,
    connection_id text NOT NULL
);

CREATE TABLE app_http_attempts (
    execution_id text NOT NULL,
    tenant_id text NOT NULL,
    project_id text NOT NULL,
    app_id text NOT NULL,
    release_id text NOT NULL,
    generation integer NOT NULL
);

CREATE TABLE app_releases (
    id text NOT NULL,
    tenant_id text NOT NULL,
    project_id text NOT NULL,
    app_id text NOT NULL,
    version_id text NOT NULL,
    configuration jsonb NOT NULL,
    spec jsonb NOT NULL,
    state text NOT NULL,
    reason text,
    created timestamp with time zone DEFAULT now() NOT NULL,
    updated timestamp with time zone DEFAULT now() NOT NULL,
    unreferenced_since timestamp with time zone DEFAULT now(),
    inputs_retired_at timestamp with time zone,
    original_inputs_sha256 text,
    CONSTRAINT app_releases_state_check CHECK ((state = ANY (ARRAY['preparing'::text, 'ready'::text, 'failed'::text]))),
    CONSTRAINT release_input_retirement_metadata CHECK ((((inputs_retired_at IS NULL) AND (original_inputs_sha256 IS NULL)) OR ((inputs_retired_at IS NOT NULL) AND (original_inputs_sha256 IS NOT NULL) AND (original_inputs_sha256 ~ '^[0-9a-f]{64}$'::text) AND (NOT (configuration ? 'env'::text)) AND (NOT (spec ?| ARRAY['env'::text, 'endpoint_env'::text])))))
);

CREATE TABLE app_versions (
    id text NOT NULL,
    tenant_id text NOT NULL,
    project_id text NOT NULL,
    app_id text NOT NULL,
    number bigint NOT NULL,
    artifact_id text NOT NULL,
    inspection jsonb NOT NULL,
    created timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT app_versions_number_check CHECK ((number > 0))
);

CREATE VIEW app_execution_contexts AS
 SELECT r.tenant_id,
    r.project_id,
    r.app_id,
    r.release_id,
    l.version_id,
    v.number AS version,
    r.execution_id,
    r.id AS run_id,
    r.source
   FROM ((app_runs r
     JOIN app_releases l ON ((l.id = r.release_id)))
     JOIN app_versions v ON ((v.id = l.version_id)))
UNION ALL
 SELECT h.tenant_id,
    h.project_id,
    h.app_id,
    h.release_id,
    l.version_id,
    v.number AS version,
    h.execution_id,
    NULL::text AS run_id,
    'http'::text AS source
   FROM ((app_http_attempts h
     JOIN app_releases l ON ((l.id = h.release_id)))
     JOIN app_versions v ON ((v.id = l.version_id)));

CREATE TABLE app_execution_https (
    tenant_id text NOT NULL,
    project_id text NOT NULL,
    app_id text NOT NULL,
    execution_id text NOT NULL,
    connection_id text NOT NULL
);

CREATE TABLE app_http_operations (
    operation_id text NOT NULL,
    tenant_id text NOT NULL,
    project_id text NOT NULL,
    app_id text NOT NULL,
    generation integer NOT NULL,
    rollout_state text,
    rollout_error text,
    CONSTRAINT app_http_operations_generation_check CHECK ((generation > 0)),
    CONSTRAINT app_http_operations_rollout_state_check CHECK ((rollout_state = ANY (ARRAY['succeeded'::text, 'failed'::text])))
);

CREATE TABLE app_https_connections (
    id text NOT NULL,
    tenant_id text NOT NULL,
    project_id text NOT NULL,
    app_id text NOT NULL,
    origin text NOT NULL,
    state text DEFAULT 'active'::text NOT NULL,
    revocation_operation_id text,
    created timestamp with time zone DEFAULT now() NOT NULL,
    updated timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT app_https_connections_check CHECK (((state = 'active'::text) = (revocation_operation_id IS NULL))),
    CONSTRAINT app_https_connections_state_check CHECK ((state = ANY (ARRAY['active'::text, 'revoking'::text, 'revoked'::text])))
);

CREATE TABLE execution_https_bindings (
    execution_id text NOT NULL,
    targets text NOT NULL,
    policy_digest text NOT NULL,
    validated_until timestamp with time zone NOT NULL,
    fenced boolean DEFAULT false NOT NULL,
    created timestamp with time zone DEFAULT now() NOT NULL,
    updated timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public_egress_policy (
    singleton boolean DEFAULT true NOT NULL,
    revision bigint DEFAULT 1 NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    digest text,
    updated timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT public_egress_policy_check CHECK (((NOT enabled) OR ((digest IS NOT NULL) AND (digest ~ '^[0-9a-f]{64}$'::text)))),
    CONSTRAINT public_egress_policy_singleton_check CHECK (singleton)
);

-- app_https_observations is installed from sql/app_https_observations.sql.

CREATE TABLE app_lifecycle_coverage (
    singleton boolean DEFAULT true NOT NULL,
    started_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    CONSTRAINT app_lifecycle_coverage_singleton_check CHECK (singleton)
);

CREATE TABLE app_lifecycle_events (
    id text DEFAULT replace((gen_random_uuid())::text, '-'::text, ''::text) NOT NULL,
    tenant_id text NOT NULL,
    project_id text NOT NULL,
    app_id text NOT NULL,
    recorded_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    kind text NOT NULL,
    state text NOT NULL,
    previous_state text,
    release_id text,
    version bigint,
    run_id text,
    execution_id text,
    source text,
    desired text,
    previous_desired text,
    generation bigint,
    reserved boolean,
    outcome text,
    exit_code integer,
    CONSTRAINT app_lifecycle_events_kind_check CHECK ((kind = ANY (ARRAY['app'::text, 'release'::text, 'http'::text, 'run'::text, 'execution'::text])))
);

CREATE TABLE execution_log_records (
    id bigint NOT NULL,
    tenant_id text NOT NULL,
    project_id text NOT NULL,
    execution_id text NOT NULL,
    sequence bigint NOT NULL,
    stream text NOT NULL,
    at_ms bigint,
    payload bytea NOT NULL,
    gap_from bigint,
    received timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT execution_log_records_at_ms_check CHECK ((at_ms >= 0)),
    CONSTRAINT execution_log_records_check CHECK ((((stream = 'gap'::text) AND (at_ms IS NULL) AND (octet_length(payload) = 0) AND (gap_from IS NOT NULL) AND (gap_from > 0) AND (gap_from <= sequence)) OR ((stream = ANY (ARRAY['stdout'::text, 'stderr'::text])) AND (at_ms IS NOT NULL) AND (gap_from IS NULL) AND ((octet_length(payload) >= 1) AND (octet_length(payload) <= 8192))))),
    CONSTRAINT execution_log_records_sequence_check CHECK ((sequence > 0)),
    CONSTRAINT execution_log_records_stream_check CHECK ((stream = ANY (ARRAY['stdout'::text, 'stderr'::text, 'gap'::text])))
);

CREATE TABLE execution_log_sources (
    execution_id text NOT NULL,
    tenant_id text NOT NULL,
    project_id text NOT NULL,
    capture_id text NOT NULL,
    acknowledged bigint DEFAULT 0 NOT NULL,
    reported_last bigint DEFAULT 0 NOT NULL,
    end_sequence bigint,
    source_gap boolean DEFAULT false NOT NULL,
    pruned_through bigint DEFAULT 0 NOT NULL,
    created timestamp with time zone DEFAULT now() NOT NULL,
    updated timestamp with time zone DEFAULT now() NOT NULL,
    interrupted boolean DEFAULT false NOT NULL,
    CONSTRAINT execution_log_sources_acknowledged_check CHECK ((acknowledged >= 0)),
    CONSTRAINT execution_log_sources_check CHECK ((reported_last >= acknowledged)),
    CONSTRAINT execution_log_sources_check1 CHECK ((end_sequence >= acknowledged)),
    CONSTRAINT execution_log_sources_check2 CHECK (((pruned_through >= 0) AND (pruned_through <= acknowledged)))
);

CREATE VIEW app_log_observations AS
 SELECT c.tenant_id,
    c.project_id,
    c.app_id,
    c.release_id,
    c.version_id,
    c.version,
    c.execution_id,
    c.run_id,
    c.source,
    s.updated AS last_received,
        CASE
            WHEN ((s.end_sequence = s.acknowledged) AND (NOT s.interrupted)) THEN 'complete'::text
            WHEN e.log_ingestion_fenced THEN 'fenced'::text
            WHEN s.interrupted THEN 'incomplete'::text
            WHEN (e.node_id IS NULL) THEN 'not-started'::text
            WHEN (s.execution_id IS NULL) THEN
            CASE
                WHEN ((NOT e.reserved) AND (e.updated < (now() - '00:00:30'::interval))) THEN 'unavailable'::text
                ELSE 'awaiting'::text
            END
            WHEN (s.updated < (now() - '00:00:30'::interval)) THEN
            CASE
                WHEN (NOT e.reserved) THEN 'incomplete'::text
                ELSE 'stale'::text
            END
            ELSE 'collecting'::text
        END AS collection_state,
    COALESCE(s.source_gap, false) AS source_gap,
    (COALESCE((s.pruned_through > 0), false) OR (EXISTS ( SELECT 1
           FROM execution_log_records r
          WHERE ((r.execution_id = c.execution_id) AND (r.received < (now() - '7 days'::interval)))))) AS retention_truncated
   FROM ((app_execution_contexts c
     JOIN executions e ON ((e.id = c.execution_id)))
     LEFT JOIN execution_log_sources s ON ((s.execution_id = c.execution_id)));

CREATE TABLE https_revocations (
    operation_id text NOT NULL,
    execution_id text NOT NULL
);

CREATE TABLE operations (
    id text NOT NULL,
    tenant_id text NOT NULL,
    project_id text NOT NULL,
    request_key text NOT NULL,
    request_hash text NOT NULL,
    resource_id text NOT NULL,
    kind text NOT NULL,
    target_revision integer DEFAULT 1 NOT NULL,
    state text DEFAULT 'pending'::text NOT NULL,
    error text,
    created timestamp with time zone DEFAULT now() NOT NULL,
    updated timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT operations_state_check CHECK ((state = ANY (ARRAY['pending'::text, 'succeeded'::text, 'failed'::text])))
);

CREATE VIEW app_run_observations AS
 SELECT r.id,
    r.tenant_id,
    r.project_id,
    r.app_id,
    r.release_id,
    r.execution_id,
    r.source,
    r.created,
    v.number AS version,
    e.state AS execution_state,
    COALESCE(e.reserved, false) AS reserved,
        CASE
            WHEN (r.admission = 'pending'::text) THEN 'queued'::text
            WHEN (r.admission = 'skipped'::text) THEN 'skipped'::text
            WHEN (r.admission = 'cancelled'::text) THEN 'cancelled'::text
            ELSE
            CASE e.state
                WHEN 'queued'::text THEN 'queued'::text
                WHEN 'starting'::text THEN 'starting'::text
                WHEN 'running'::text THEN 'running'::text
                WHEN 'paused'::text THEN 'running'::text
                WHEN 'stopping'::text THEN 'running'::text
                WHEN 'stopped'::text THEN 'cancelled'::text
                WHEN 'failed'::text THEN
                CASE
                    WHEN (((e.observation ->> 'reason'::text) = 'worker-lost'::text) AND ((e.observation ->> 'exit_code'::text) IS NULL)) THEN 'unknown'::text
                    ELSE 'failed'::text
                END
                WHEN 'exited'::text THEN
                CASE
                    WHEN ((e.observation ->> 'exit_code'::text) = '0'::text) THEN 'succeeded'::text
                    WHEN ((e.observation ->> 'exit_code'::text) IS NULL) THEN 'unknown'::text
                    ELSE 'failed'::text
                END
                ELSE 'unknown'::text
            END
        END AS state,
    ((e.observation ->> 'exit_code'::text))::integer AS exit_code,
    COALESCE(r.admission_reason, d.last_error,
        CASE
            WHEN ((e.state = 'stopped'::text) AND (NOT e.reserved) AND ((e.observation ->> 'reason'::text) = 'requested-stop'::text) AND (EXISTS ( SELECT 1
               FROM (https_revocations h
                 JOIN operations o ON ((o.id = h.operation_id)))
              WHERE ((h.execution_id = e.id) AND (o.kind = 'app-connections'::text) AND (o.tenant_id = r.tenant_id) AND (o.project_id = r.project_id) AND (o.resource_id = r.app_id))))) THEN 'https-access-revoked'::text
            ELSE (e.observation ->> 'reason'::text)
        END) AS reason,
    e.started_at,
        CASE
            WHEN (r.admission = ANY (ARRAY['skipped'::text, 'cancelled'::text])) THEN r.admission_updated
            WHEN (e.state = ANY (ARRAY['exited'::text, 'stopped'::text, 'failed'::text, 'lost'::text])) THEN COALESCE(e.finished_at, e.updated)
            ELSE NULL::timestamp with time zone
        END AS finished_at,
    COALESCE(e.updated, r.admission_updated) AS updated,
    r.admission,
    r.scheduled_at,
    r.trigger_revision
   FROM ((((app_runs r
     LEFT JOIN executions e ON ((e.id = r.execution_id)))
     LEFT JOIN app_run_dispatch d ON ((d.run_id = r.id)))
     JOIN app_releases l ON ((l.id = r.release_id)))
     JOIN app_versions v ON ((v.id = l.version_id)));

CREATE TABLE app_schedule_misses (
    id text NOT NULL,
    tenant_id text NOT NULL,
    project_id text NOT NULL,
    app_id text NOT NULL,
    revision bigint NOT NULL,
    release_id text NOT NULL,
    first_at timestamp with time zone NOT NULL,
    next_at timestamp with time zone NOT NULL,
    until_at timestamp with time zone NOT NULL,
    complete boolean DEFAULT false NOT NULL,
    updated timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT app_schedule_misses_check CHECK (((first_at <= next_at) AND (next_at <= until_at)))
);

CREATE TABLE app_schedule_revisions (
    app_id text NOT NULL,
    tenant_id text NOT NULL,
    project_id text NOT NULL,
    revision bigint NOT NULL,
    enabled boolean NOT NULL,
    expression text NOT NULL,
    timezone text NOT NULL,
    timezone_database text NOT NULL,
    created timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT app_schedule_revisions_revision_check CHECK ((revision > 0))
);

CREATE TABLE app_schedules (
    app_id text NOT NULL,
    tenant_id text NOT NULL,
    project_id text NOT NULL,
    revision bigint NOT NULL,
    next_at timestamp with time zone,
    updated timestamp with time zone DEFAULT now() NOT NULL
);

CREATE VIEW app_summaries AS
 SELECT a.id,
    a.tenant_id,
    a.project_id,
    a.name,
    a.revision,
    a.latest_version,
    a.created,
    a.updated,
    a.desired,
    a.configuration,
    a.active_release_id,
    a.target_release_id,
        CASE
            WHEN (a.target_release_id IS NULL) THEN 'draft'::text
            WHEN (a.desired = 'stopped'::text) THEN 'stopped'::text
            ELSE target.state
        END AS state,
    jsonb_build_object('manual', t.manual, 'http', t.http, 'schedule', COALESCE(config.enabled, false), 'revision', t.revision) AS triggers,
        CASE
            WHEN (latest.id IS NOT NULL) THEN jsonb_build_object('id', latest.id, 'number', latest.number, 'artifact_id', latest.artifact_id, 'capabilities', jsonb_build_object('http', (latest.inspection -> 'http'::text), 'command', (latest.inspection -> 'command'::text)))
            ELSE NULL::jsonb
        END AS latest_code,
        CASE
            WHEN (active.id IS NOT NULL) THEN jsonb_build_object('id', active.id, 'version_id', active.version_id, 'version', active_code.number, 'state', active.state, 'reason', active.reason, 'created', active.created, 'updated', active.updated)
            ELSE NULL::jsonb
        END AS active_release,
        CASE
            WHEN (target.id IS NOT NULL) THEN jsonb_build_object('id', target.id, 'version_id', target.version_id, 'version', target_code.number, 'state', target.state, 'reason', target.reason, 'created', target.created, 'updated', target.updated)
            ELSE NULL::jsonb
        END AS target_release,
    jsonb_build_object('url',
        CASE
            WHEN (h.hostname IS NOT NULL) THEN ('https://'::text || h.hostname)
            ELSE NULL::text
        END, 'state', COALESCE(h.state, 'disabled'::text), 'reason', h.reason, 'execution_id', h.execution_id) AS http,
        CASE
            WHEN (run.id IS NOT NULL) THEN jsonb_build_object('id', run.id, 'source', run.source, 'release_id', run.release_id, 'execution_id', run.execution_id, 'state', run.state, 'exit_code', run.exit_code, 'reason', run.reason, 'scheduled_at', run.scheduled_at, 'created', run.created, 'started_at', run.started_at, 'finished_at', run.finished_at)
            ELSE NULL::jsonb
        END AS latest_run,
        CASE
            WHEN (config.app_id IS NOT NULL) THEN jsonb_build_object('enabled', config.enabled, 'expression', config.expression, 'timezone', config.timezone, 'timezone_database', config.timezone_database, 'next_at', schedule.next_at)
            ELSE NULL::jsonb
        END AS schedule
   FROM ((((((((((apps a
     JOIN app_triggers t ON ((t.app_id = a.id)))
     LEFT JOIN app_versions latest ON (((latest.app_id = a.id) AND (latest.number = a.latest_version))))
     LEFT JOIN app_releases active ON ((active.id = a.active_release_id)))
     LEFT JOIN app_versions active_code ON ((active_code.id = active.version_id)))
     LEFT JOIN app_releases target ON ((target.id = a.target_release_id)))
     LEFT JOIN app_versions target_code ON ((target_code.id = target.version_id)))
     LEFT JOIN app_http_observations h ON ((h.app_id = a.id)))
     LEFT JOIN app_schedules schedule ON ((schedule.app_id = a.id)))
     LEFT JOIN app_schedule_revisions config ON (((config.app_id = schedule.app_id) AND (config.revision = schedule.revision))))
     LEFT JOIN LATERAL ( SELECT r.id,
            r.tenant_id,
            r.project_id,
            r.app_id,
            r.release_id,
            r.execution_id,
            r.source,
            r.created,
            r.version,
            r.execution_state,
            r.reserved,
            r.state,
            r.exit_code,
            r.reason,
            r.started_at,
            r.finished_at,
            r.updated,
            r.admission,
            r.scheduled_at,
            r.trigger_revision
           FROM app_run_observations r
          WHERE (r.app_id = a.id)
          ORDER BY COALESCE(r.scheduled_at, r.created) DESC, r.created DESC, r.id DESC
         LIMIT 1) run ON (true));

CREATE TABLE artifact_blob_garbage (
    digest text NOT NULL,
    next_attempt timestamp with time zone DEFAULT now() NOT NULL,
    error text,
    CONSTRAINT artifact_blob_garbage_digest_check CHECK ((digest ~ '^[a-f0-9]{64}$'::text))
);

CREATE TABLE artifact_validations (
    artifact_id text NOT NULL,
    tenant_id text NOT NULL,
    project_id text NOT NULL,
    runtime text NOT NULL,
    state text DEFAULT 'pending'::text NOT NULL,
    generation bigint DEFAULT 0 NOT NULL,
    attempts bigint DEFAULT 0 NOT NULL,
    node_id text,
    node_boot text,
    lease_until timestamp with time zone,
    available_at timestamp with time zone DEFAULT now() NOT NULL,
    inspection jsonb,
    error text,
    created timestamp with time zone DEFAULT now() NOT NULL,
    updated timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT artifact_validations_attempts_check CHECK ((attempts >= 0)),
    CONSTRAINT artifact_validations_check CHECK (((state = 'valid'::text) = (inspection IS NOT NULL))),
    CONSTRAINT artifact_validations_check1 CHECK (((state = 'validating'::text) = (lease_until IS NOT NULL))),
    CONSTRAINT artifact_validations_check2 CHECK (((state = 'pending'::text) OR ((node_id IS NOT NULL) AND (node_boot IS NOT NULL) AND (generation > 0)))),
    CONSTRAINT artifact_validations_error_check CHECK ((error = ANY (ARRAY['component-not-accepted'::text, 'compiler-unavailable'::text, 'invalid-component'::text, 'unsupported-imports'::text, 'incompatible-entry-points'::text, 'interface-limits'::text]))),
    CONSTRAINT artifact_validations_generation_check CHECK ((generation >= 0)),
    CONSTRAINT artifact_validations_state_check CHECK ((state = ANY (ARRAY['pending'::text, 'validating'::text, 'valid'::text, 'rejected'::text])))
);

CREATE TABLE artifacts (
    id text NOT NULL,
    tenant_id text NOT NULL,
    project_id text NOT NULL,
    digest text NOT NULL,
    size bigint NOT NULL,
    created timestamp with time zone DEFAULT now() NOT NULL,
    last_uploaded_at timestamp with time zone DEFAULT now() NOT NULL,
    retired_at timestamp with time zone,
    CONSTRAINT artifacts_size_check CHECK ((size > 0))
);

CREATE TABLE audit (
    sequence bigint NOT NULL,
    tenant_id text,
    actor text NOT NULL,
    action text NOT NULL,
    resource_id text,
    detail jsonb DEFAULT '{}'::jsonb NOT NULL,
    created timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE audit_sequence_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE audit_sequence_seq OWNED BY audit.sequence;

CREATE VIEW compute_reservations AS
 SELECT tenant_id,
    project_id,
    cpu_percent,
    memory_mib
   FROM executions
  WHERE reserved;

CREATE TABLE credentials (
    id text NOT NULL,
    token_hash text NOT NULL,
    tenant_id text,
    project_id text,
    name text NOT NULL,
    role text NOT NULL,
    expires timestamp with time zone NOT NULL,
    revoked boolean DEFAULT false NOT NULL,
    created timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT credentials_check CHECK (((role = 'operator'::text) = (tenant_id IS NULL))),
    CONSTRAINT credentials_role_check CHECK ((role = ANY (ARRAY['operator'::text, 'owner'::text, 'editor'::text, 'viewer'::text])))
);

CREATE TABLE deployments (
    id text NOT NULL,
    tenant_id text NOT NULL,
    project_id text NOT NULL,
    name text NOT NULL,
    revision integer DEFAULT 1 NOT NULL,
    spec jsonb NOT NULL,
    desired text DEFAULT 'running'::text NOT NULL,
    created timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT deployments_desired_check CHECK ((desired = ANY (ARRAY['running'::text, 'stopped'::text])))
);

CREATE TABLE egress_allowance_usage (
    execution_id text NOT NULL,
    tenant_id text NOT NULL,
    project_id text NOT NULL,
    period date NOT NULL,
    bytes bigint NOT NULL,
    conservative_bytes bigint DEFAULT 0 NOT NULL,
    CONSTRAINT egress_allowance_usage_bytes_check CHECK ((bytes >= 0)),
    CONSTRAINT egress_allowance_usage_check CHECK (((conservative_bytes >= 0) AND (conservative_bytes <= bytes))),
    CONSTRAINT egress_allowance_usage_period_check CHECK ((period = (date_trunc('month'::text, (period)::timestamp with time zone))::date))
);

CREATE VIEW endpoint_binding_observations AS
 SELECT id AS endpoint_id,
    id AS binding_id,
    address,
    (NOT deleted) AS ready
   FROM external_endpoints;

CREATE TABLE execution_egress_budgets (
    execution_id text NOT NULL,
    tenant_id text NOT NULL,
    project_id text NOT NULL,
    node_id text NOT NULL,
    boot_id text NOT NULL,
    launcher_digest text NOT NULL,
    generation bigint NOT NULL,
    revision bigint DEFAULT 0 NOT NULL,
    state text DEFAULT 'frozen'::text NOT NULL,
    period date DEFAULT (date_trunc('month'::text, (now() AT TIME ZONE 'UTC'::text)))::date NOT NULL,
    base_bytes numeric(20,0) DEFAULT 0 NOT NULL,
    ceiling_bytes numeric(20,0) DEFAULT 0 NOT NULL,
    held_bytes bigint DEFAULT 0 NOT NULL,
    expires timestamp with time zone,
    request_id text,
    request_hash text,
    updated timestamp with time zone DEFAULT now() NOT NULL,
    closure text,
    closed_at timestamp with time zone,
    CONSTRAINT execution_egress_budgets_balance_check CHECK ((((state = ANY (ARRAY['frozen'::text, 'closed'::text])) AND (held_bytes = 0) AND (expires IS NULL)) OR ((state = 'active'::text) AND ((held_bytes)::numeric = (ceiling_bytes - base_bytes)) AND (expires IS NOT NULL)) OR ((state = 'freezing'::text) AND ((held_bytes)::numeric = (ceiling_bytes - base_bytes)) AND (expires IS NULL)))),
    CONSTRAINT execution_egress_budgets_base_bytes_check CHECK (((base_bytes >= (0)::numeric) AND (base_bytes <= '18446744073709551615'::numeric))),
    CONSTRAINT execution_egress_budgets_check CHECK (((ceiling_bytes >= base_bytes) AND (ceiling_bytes <= '18446744073709551615'::numeric))),
    CONSTRAINT execution_egress_budgets_closure_check CHECK ((((state = 'closed'::text) AND (closure IS NOT NULL) AND (closure = ANY (ARRAY['terminal-exact'::text, 'terminal-conservative'::text, 'restore-conservative'::text])) AND (closed_at IS NOT NULL)) OR ((state <> 'closed'::text) AND (closure IS NULL) AND (closed_at IS NULL)))),
    CONSTRAINT execution_egress_budgets_generation_check CHECK ((generation > 0)),
    CONSTRAINT execution_egress_budgets_held_bytes_check CHECK ((held_bytes >= 0)),
    CONSTRAINT execution_egress_budgets_launcher_digest_check CHECK ((launcher_digest ~ '^[a-f0-9]{64}$'::text)),
    CONSTRAINT execution_egress_budgets_period_check CHECK ((period = (date_trunc('month'::text, (period)::timestamp with time zone))::date)),
    CONSTRAINT execution_egress_budgets_revision_check CHECK ((revision >= 0)),
    CONSTRAINT execution_egress_budgets_state_check CHECK ((state = ANY (ARRAY['frozen'::text, 'active'::text, 'freezing'::text, 'closed'::text])))
);

CREATE TABLE execution_egress_period_sources (
    execution_id text NOT NULL,
    tenant_id text NOT NULL,
    project_id text NOT NULL,
    generation bigint NOT NULL,
    boot_id text NOT NULL,
    bytes numeric(20,0) NOT NULL,
    consistent boolean DEFAULT true NOT NULL,
    complete boolean NOT NULL,
    payload jsonb NOT NULL,
    sampled_at timestamp with time zone NOT NULL,
    received timestamp with time zone DEFAULT now() NOT NULL,
    archived_bytes numeric(20,0) DEFAULT 0 NOT NULL,
    archived_periods bigint DEFAULT 0 NOT NULL,
    CONSTRAINT execution_egress_period_sources_archived_periods_check CHECK ((archived_periods >= 0)),
    CONSTRAINT execution_egress_period_sources_bytes_check CHECK (((bytes >= (0)::numeric) AND (bytes <= '18446744073709551615'::numeric))),
    CONSTRAINT execution_egress_period_sources_check CHECK (((archived_bytes >= (0)::numeric) AND (archived_bytes <= bytes)))
);

CREATE TABLE execution_egress_periods (
    execution_id text NOT NULL,
    tenant_id text NOT NULL,
    project_id text NOT NULL,
    period date NOT NULL,
    bytes numeric(20,0) NOT NULL,
    sampled_at timestamp with time zone NOT NULL,
    CONSTRAINT execution_egress_periods_bytes_check CHECK (((bytes >= (0)::numeric) AND (bytes <= '18446744073709551615'::numeric))),
    CONSTRAINT execution_egress_periods_period_check CHECK ((EXTRACT(day FROM period) = (1)::numeric))
);

CREATE TABLE execution_egress_usage (
    execution_id text NOT NULL,
    tenant_id text NOT NULL,
    project_id text NOT NULL,
    generation bigint NOT NULL,
    boot_id text NOT NULL,
    bytes numeric(20,0) NOT NULL,
    consistent boolean DEFAULT true NOT NULL,
    complete boolean DEFAULT false NOT NULL,
    sampled_at timestamp with time zone NOT NULL,
    received timestamp with time zone DEFAULT now() NOT NULL,
    first_sampled_at timestamp with time zone NOT NULL,
    CONSTRAINT execution_egress_usage_bytes_check CHECK (((bytes >= (0)::numeric) AND (bytes <= '18446744073709551615'::numeric)))
);

CREATE VIEW execution_inputs_retirable AS
 SELECT id,
    updated
   FROM executions e
  WHERE ((NOT reserved) AND (inputs_retired_at IS NULL) AND (jsonb_typeof(spec) = 'object'::text) AND (spec ?| ARRAY['env'::text, 'endpoint_env'::text]) AND ((COALESCE((spec -> 'env'::text), '{}'::jsonb) <> '{}'::jsonb) OR (COALESCE((spec -> 'endpoint_env'::text), '{}'::jsonb) <> '{}'::jsonb)) AND (GREATEST(created, updated, finished_at) < (now() - '30 days'::interval)) AND (((state = 'stopped'::text) AND (node_id IS NULL)) OR ((state = ANY (ARRAY['exited'::text, 'failed'::text])) AND (finished_at IS NOT NULL) AND
        CASE
            WHEN ((observation ->> 'exit_code'::text) ~ '^[0-9]{1,3}$'::text) THEN ((((observation ->> 'exit_code'::text))::integer >= 0) AND (((observation ->> 'exit_code'::text))::integer <= 255))
            ELSE false
        END)) AND (NOT (EXISTS ( SELECT 1
           FROM (( SELECT e.id AS resource_id,
                    NULL::integer AS target_revision
                UNION ALL
                 SELECT e.deployment_id,
                    e.revision
                UNION ALL
                 SELECT r.id,
                    NULL::integer AS int4
                   FROM app_runs r
                  WHERE (r.execution_id = e.id)) refs
             JOIN operations o USING (resource_id))
          WHERE (((refs.target_revision IS NULL) OR (o.target_revision = refs.target_revision)) AND ((o.state = 'pending'::text) OR (GREATEST(o.created, o.updated) >= (now() - '30 days'::interval))))))) AND (NOT (EXISTS ( SELECT 1
           FROM (app_runs r
             LEFT JOIN app_run_dispatch d ON ((d.run_id = r.id)))
          WHERE ((r.execution_id = e.id) AND ((r.admission <> 'admitted'::text) OR (d.state = 'pending'::text) OR (GREATEST(r.created, r.admission_updated, d.created, d.updated, d.deadline) >= (now() - '30 days'::interval))))))) AND (NOT (EXISTS ( SELECT 1
           FROM execution_egress_budgets b
          WHERE ((b.execution_id = e.id) AND ((b.state <> 'frozen'::text) OR (b.held_bytes <> 0)))))));

CREATE SEQUENCE execution_log_records_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE execution_log_records_id_seq OWNED BY execution_log_records.id;

CREATE TABLE execution_placement (
    execution_id text NOT NULL,
    generation bigint NOT NULL,
    reason text NOT NULL,
    observed_at timestamp with time zone NOT NULL,
    CONSTRAINT execution_placement_generation_check CHECK ((generation > 0)),
    CONSTRAINT execution_placement_reason_check CHECK ((reason = ANY (ARRAY['placement-no-worker'::text, 'placement-confinement'::text, 'placement-private-network'::text, 'placement-public-https'::text, 'placement-egress-budget'::text, 'placement-size'::text, 'placement-capacity'::text, 'placement-public-policy'::text])))
);

CREATE TABLE ingress_reservations (
    id text NOT NULL,
    tenant_id text NOT NULL,
    project_id text NOT NULL,
    period date NOT NULL,
    bytes bigint NOT NULL,
    created timestamp with time zone DEFAULT now() NOT NULL,
    expires timestamp with time zone DEFAULT (now() + '00:01:30'::interval) NOT NULL,
    execution_id text,
    app_id text,
    release_id text,
    app_revision bigint,
    CONSTRAINT ingress_app_context CHECK ((((app_id IS NULL) AND (release_id IS NULL) AND (app_revision IS NULL)) OR ((app_id IS NOT NULL) AND (release_id IS NOT NULL) AND (app_revision IS NOT NULL))))
);

CREATE TABLE network_grants (
    id text NOT NULL,
    tenant_id text NOT NULL,
    project_id text NOT NULL,
    network_id text NOT NULL,
    endpoint_id text NOT NULL,
    deployment_id text,
    execution_id text,
    state text DEFAULT 'active'::text NOT NULL,
    created timestamp with time zone DEFAULT now() NOT NULL,
    revoked timestamp with time zone,
    CONSTRAINT network_grants_check CHECK (((deployment_id IS NULL) <> (execution_id IS NULL))),
    CONSTRAINT network_grants_state_check CHECK ((state = ANY (ARRAY['active'::text, 'revoking'::text, 'revoked'::text])))
);

CREATE TABLE network_revocations (
    operation_id text NOT NULL,
    execution_id text NOT NULL,
    required_revision bigint NOT NULL
);

CREATE TABLE networks (
    id text NOT NULL,
    tenant_id text NOT NULL,
    project_id text NOT NULL,
    name text NOT NULL,
    created timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE platform_format (
    singleton boolean DEFAULT true NOT NULL,
    format text NOT NULL,
    CONSTRAINT platform_format_format_check CHECK ((format = 'wasm-only-v1'::text)),
    CONSTRAINT platform_format_singleton_check CHECK (singleton)
);

CREATE TABLE projects (
    id text NOT NULL,
    tenant_id text NOT NULL,
    name text NOT NULL,
    created timestamp with time zone DEFAULT now() NOT NULL,
    display_name text NOT NULL,
    slug text NOT NULL,
    is_default boolean DEFAULT false NOT NULL
);

CREATE TABLE recovery_barrier (
    singleton boolean DEFAULT true NOT NULL,
    active boolean DEFAULT false NOT NULL,
    backup_id text,
    restored timestamp with time zone,
    activated timestamp with time zone,
    encryption_key_id text,
    CONSTRAINT recovery_barrier_encryption_key_id_check CHECK ((encryption_key_id ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT recovery_barrier_singleton_check CHECK (singleton)
);

CREATE VIEW release_inputs_retirable AS
 SELECT id,
    unreferenced_since
   FROM app_releases l
  WHERE ((inputs_retired_at IS NULL) AND (unreferenced_since < (now() - '30 days'::interval)) AND (state = ANY (ARRAY['ready'::text, 'failed'::text])) AND (GREATEST(created, updated) < (now() - '30 days'::interval)) AND (jsonb_typeof(configuration) = 'object'::text) AND (jsonb_typeof(spec) = 'object'::text) AND ((COALESCE((configuration -> 'env'::text), '{}'::jsonb) <> '{}'::jsonb) OR (COALESCE((spec -> 'env'::text), '{}'::jsonb) <> '{}'::jsonb) OR (COALESCE((spec -> 'endpoint_env'::text), '{}'::jsonb) <> '{}'::jsonb)) AND (NOT (EXISTS ( SELECT 1
           FROM apps a
          WHERE ((l.id = a.active_release_id) OR (l.id = a.target_release_id))))) AND (NOT (EXISTS ( SELECT 1
           FROM operations o
          WHERE ((o.resource_id = l.id) AND ((o.state = 'pending'::text) OR (GREATEST(o.created, o.updated) >= (now() - '30 days'::interval))))))) AND (NOT (EXISTS ( SELECT 1
           FROM ingress_reservations i
          WHERE (i.release_id = l.id)))) AND (NOT (EXISTS ( SELECT 1
           FROM (app_runs r
             LEFT JOIN app_run_dispatch d ON ((d.run_id = r.id)))
          WHERE ((r.release_id = l.id) AND ((r.admission = 'pending'::text) OR (d.state = 'pending'::text) OR (GREATEST(r.created, r.admission_updated, d.created, d.updated, d.deadline) >= (now() - '30 days'::interval))))))) AND (NOT (EXISTS ( SELECT 1
           FROM (app_runs r
             JOIN operations o ON ((o.resource_id = r.id)))
          WHERE ((r.release_id = l.id) AND ((o.state = 'pending'::text) OR (GREATEST(o.created, o.updated) >= (now() - '30 days'::interval))))))) AND (NOT (EXISTS ( SELECT 1
           FROM (( SELECT r.execution_id
                   FROM app_runs r
                  WHERE ((r.release_id = l.id) AND (r.execution_id IS NOT NULL))
                UNION
                 SELECT h.execution_id
                   FROM app_http_attempts h
                  WHERE (h.release_id = l.id)) refs
             JOIN executions e ON ((e.id = refs.execution_id)))
          WHERE (e.reserved OR (GREATEST(e.created, e.updated, e.finished_at) >= (now() - '30 days'::interval)) OR (NOT (((e.state = 'stopped'::text) AND (e.node_id IS NULL)) OR ((e.state = ANY (ARRAY['exited'::text, 'failed'::text])) AND (e.finished_at IS NOT NULL) AND
                CASE
                    WHEN ((e.observation ->> 'exit_code'::text) ~ '^[0-9]{1,3}$'::text) THEN ((((e.observation ->> 'exit_code'::text))::integer >= 0) AND (((e.observation ->> 'exit_code'::text))::integer <= 255))
                    ELSE false
                END))) OR (EXISTS ( SELECT 1
                   FROM execution_egress_budgets b
                  WHERE ((b.execution_id = e.id) AND ((b.state <> 'frozen'::text) OR (b.held_bytes <> 0))))) OR (EXISTS ( SELECT 1
                   FROM ingress_reservations i
                  WHERE (i.execution_id = e.id))) OR (EXISTS ( SELECT 1
                   FROM operations o
                  WHERE (((o.resource_id = e.id) OR ((o.resource_id = e.deployment_id) AND (o.target_revision = e.revision)) OR (o.resource_id IN ( SELECT r.id
                           FROM app_runs r
                          WHERE (r.execution_id = e.id)))) AND ((o.state = 'pending'::text) OR (GREATEST(o.created, o.updated) >= (now() - '30 days'::interval)))))))))));

CREATE TABLE routes (
    id text NOT NULL,
    tenant_id text NOT NULL,
    project_id text NOT NULL,
    hostname text NOT NULL,
    deployment_id text NOT NULL,
    created timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE schema_version (
    version integer NOT NULL
);

CREATE TABLE secrets (
    id text NOT NULL,
    tenant_id text NOT NULL,
    project_id text NOT NULL,
    name text NOT NULL,
    ciphertext bytea NOT NULL,
    created timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE tenants (
    id text NOT NULL,
    name text NOT NULL,
    cpu_percent bigint NOT NULL,
    memory_mib bigint NOT NULL,
    storage_bytes bigint NOT NULL,
    instances integer NOT NULL,
    transfer_bytes bigint NOT NULL,
    created timestamp with time zone DEFAULT now() NOT NULL,
    display_name text NOT NULL,
    default_app_size text DEFAULT 'small'::text NOT NULL,
    settings_revision bigint DEFAULT 1 NOT NULL,
    CONSTRAINT tenants_cpu_percent_check CHECK ((cpu_percent > 0)),
    CONSTRAINT tenants_default_app_size_check CHECK ((default_app_size = ANY (ARRAY['small'::text, 'medium'::text, 'large'::text]))),
    CONSTRAINT tenants_instances_check CHECK ((instances > 0)),
    CONSTRAINT tenants_memory_mib_check CHECK ((memory_mib > 0)),
    CONSTRAINT tenants_settings_revision_check CHECK ((settings_revision > 0)),
    CONSTRAINT tenants_storage_bytes_check CHECK ((storage_bytes > 0)),
    CONSTRAINT tenants_transfer_bytes_check CHECK ((transfer_bytes > 0))
);

CREATE TABLE traffic_usage (
    tenant_id text NOT NULL,
    project_id text NOT NULL,
    period date NOT NULL,
    bytes bigint DEFAULT 0 NOT NULL,
    requests bigint DEFAULT 0 NOT NULL
);

CREATE TABLE usage_compaction_queue (
    execution_id text NOT NULL,
    queued_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE usage_samples (
    execution_id text NOT NULL,
    generation bigint NOT NULL,
    sequence bigint NOT NULL,
    tenant_id text NOT NULL,
    cpu_usec bigint NOT NULL,
    memory_bytes bigint NOT NULL,
    observed timestamp with time zone DEFAULT now() NOT NULL,
    cpu_measured boolean DEFAULT false NOT NULL,
    memory_measured boolean DEFAULT false NOT NULL
);

ALTER TABLE ONLY audit ALTER COLUMN sequence SET DEFAULT nextval('audit_sequence_seq'::regclass);

ALTER TABLE ONLY execution_log_records ALTER COLUMN id SET DEFAULT nextval('execution_log_records_id_seq'::regclass);

ALTER TABLE ONLY accounting_month_rollups
    ADD CONSTRAINT accounting_month_rollups_pkey PRIMARY KEY (tenant_id, project_id, period);

ALTER TABLE ONLY app_endpoint_connections
    ADD CONSTRAINT app_endpoint_connections_pkey PRIMARY KEY (id);

ALTER TABLE ONLY app_endpoint_connections
    ADD CONSTRAINT app_endpoint_connections_tenant_id_project_id_app_id_id_key UNIQUE (tenant_id, project_id, app_id, id);

ALTER TABLE ONLY app_execution_connections
    ADD CONSTRAINT app_execution_connections_pkey PRIMARY KEY (execution_id, connection_id);

ALTER TABLE ONLY app_execution_https
    ADD CONSTRAINT app_execution_https_pkey PRIMARY KEY (execution_id, connection_id);

ALTER TABLE ONLY app_http_attempts
    ADD CONSTRAINT app_http_attempts_app_id_generation_key UNIQUE (app_id, generation);

ALTER TABLE ONLY app_http_attempts
    ADD CONSTRAINT app_http_attempts_pkey PRIMARY KEY (execution_id);

ALTER TABLE ONLY app_http
    ADD CONSTRAINT app_http_deployment_id_key UNIQUE (deployment_id);

ALTER TABLE ONLY app_http
    ADD CONSTRAINT app_http_hostname_key UNIQUE (hostname);

ALTER TABLE ONLY app_http_operations
    ADD CONSTRAINT app_http_operations_pkey PRIMARY KEY (operation_id);

ALTER TABLE ONLY app_http
    ADD CONSTRAINT app_http_pkey PRIMARY KEY (app_id);

ALTER TABLE ONLY app_http
    ADD CONSTRAINT app_http_tenant_id_project_id_app_id_key UNIQUE (tenant_id, project_id, app_id);

ALTER TABLE ONLY app_https_connections
    ADD CONSTRAINT app_https_connections_pkey PRIMARY KEY (id);

ALTER TABLE ONLY app_https_connections
    ADD CONSTRAINT app_https_connections_tenant_id_project_id_app_id_id_key UNIQUE (tenant_id, project_id, app_id, id);

ALTER TABLE ONLY app_lifecycle_coverage
    ADD CONSTRAINT app_lifecycle_coverage_pkey PRIMARY KEY (singleton);

ALTER TABLE ONLY app_lifecycle_events
    ADD CONSTRAINT app_lifecycle_events_pkey PRIMARY KEY (id);

ALTER TABLE ONLY app_releases
    ADD CONSTRAINT app_releases_pkey PRIMARY KEY (id);

ALTER TABLE ONLY app_releases
    ADD CONSTRAINT app_releases_tenant_id_project_id_app_id_id_key UNIQUE (tenant_id, project_id, app_id, id);

ALTER TABLE ONLY app_run_dispatch
    ADD CONSTRAINT app_run_dispatch_pkey PRIMARY KEY (run_id);

ALTER TABLE ONLY app_runs
    ADD CONSTRAINT app_runs_execution_id_key UNIQUE (execution_id);

ALTER TABLE ONLY app_runs
    ADD CONSTRAINT app_runs_occurrence UNIQUE (app_id, trigger_revision, scheduled_at);

ALTER TABLE ONLY app_runs
    ADD CONSTRAINT app_runs_pkey PRIMARY KEY (id);

ALTER TABLE ONLY app_runs
    ADD CONSTRAINT app_runs_tenant_id_project_id_app_id_id_key UNIQUE (tenant_id, project_id, app_id, id);

ALTER TABLE ONLY app_schedule_misses
    ADD CONSTRAINT app_schedule_misses_app_id_revision_first_at_key UNIQUE (app_id, revision, first_at);

ALTER TABLE ONLY app_schedule_misses
    ADD CONSTRAINT app_schedule_misses_pkey PRIMARY KEY (id);

ALTER TABLE ONLY app_schedule_revisions
    ADD CONSTRAINT app_schedule_revisions_pkey PRIMARY KEY (app_id, revision);

ALTER TABLE ONLY app_schedule_revisions
    ADD CONSTRAINT app_schedule_revisions_tenant_id_project_id_app_id_revision_key UNIQUE (tenant_id, project_id, app_id, revision);

ALTER TABLE ONLY app_schedules
    ADD CONSTRAINT app_schedules_pkey PRIMARY KEY (app_id);

ALTER TABLE ONLY app_triggers
    ADD CONSTRAINT app_triggers_pkey PRIMARY KEY (app_id);

ALTER TABLE ONLY app_versions
    ADD CONSTRAINT app_versions_app_id_artifact_id_key UNIQUE (app_id, artifact_id);

ALTER TABLE ONLY app_versions
    ADD CONSTRAINT app_versions_app_id_number_key UNIQUE (app_id, number);

ALTER TABLE ONLY app_versions
    ADD CONSTRAINT app_versions_pkey PRIMARY KEY (id);

ALTER TABLE ONLY app_versions
    ADD CONSTRAINT app_versions_tenant_id_project_id_app_id_id_key UNIQUE (tenant_id, project_id, app_id, id);

ALTER TABLE ONLY app_versions
    ADD CONSTRAINT app_versions_tenant_id_project_id_app_id_number_key UNIQUE (tenant_id, project_id, app_id, number);

ALTER TABLE ONLY apps
    ADD CONSTRAINT apps_pkey PRIMARY KEY (id);

ALTER TABLE ONLY apps
    ADD CONSTRAINT apps_tenant_id_project_id_id_key UNIQUE (tenant_id, project_id, id);

ALTER TABLE ONLY apps
    ADD CONSTRAINT apps_tenant_id_project_id_name_key UNIQUE (tenant_id, project_id, name);

ALTER TABLE ONLY artifact_blob_garbage
    ADD CONSTRAINT artifact_blob_garbage_pkey PRIMARY KEY (digest);

ALTER TABLE ONLY artifact_validations
    ADD CONSTRAINT artifact_validations_pkey PRIMARY KEY (artifact_id);

ALTER TABLE ONLY artifacts
    ADD CONSTRAINT artifacts_pkey PRIMARY KEY (id);

ALTER TABLE ONLY artifacts
    ADD CONSTRAINT artifacts_tenant_id_project_id_digest_key UNIQUE (tenant_id, project_id, digest);

ALTER TABLE ONLY artifacts
    ADD CONSTRAINT artifacts_tenant_id_project_id_id_key UNIQUE (tenant_id, project_id, id);

ALTER TABLE ONLY audit
    ADD CONSTRAINT audit_pkey PRIMARY KEY (sequence);

ALTER TABLE ONLY credentials
    ADD CONSTRAINT credentials_pkey PRIMARY KEY (id);

ALTER TABLE ONLY credentials
    ADD CONSTRAINT credentials_token_hash_key UNIQUE (token_hash);

ALTER TABLE ONLY deployments
    ADD CONSTRAINT deployments_pkey PRIMARY KEY (id);

ALTER TABLE ONLY deployments
    ADD CONSTRAINT deployments_tenant_id_project_id_id_key UNIQUE (tenant_id, project_id, id);

ALTER TABLE ONLY deployments
    ADD CONSTRAINT deployments_tenant_id_project_id_name_key UNIQUE (tenant_id, project_id, name);

ALTER TABLE ONLY egress_allowance_usage
    ADD CONSTRAINT egress_allowance_usage_pkey PRIMARY KEY (execution_id, period);

ALTER TABLE ONLY execution_egress_budgets
    ADD CONSTRAINT execution_egress_budgets_pkey PRIMARY KEY (execution_id);

ALTER TABLE ONLY execution_egress_period_sources
    ADD CONSTRAINT execution_egress_period_sources_pkey PRIMARY KEY (execution_id);

ALTER TABLE ONLY execution_egress_periods
    ADD CONSTRAINT execution_egress_periods_pkey PRIMARY KEY (execution_id, period);

ALTER TABLE ONLY execution_egress_usage
    ADD CONSTRAINT execution_egress_usage_pkey PRIMARY KEY (execution_id);

ALTER TABLE ONLY execution_https_bindings
    ADD CONSTRAINT execution_https_bindings_pkey PRIMARY KEY (execution_id);

ALTER TABLE ONLY execution_log_records
    ADD CONSTRAINT execution_log_records_execution_id_sequence_key UNIQUE (execution_id, sequence);

ALTER TABLE ONLY execution_log_records
    ADD CONSTRAINT execution_log_records_pkey PRIMARY KEY (id);

ALTER TABLE ONLY execution_log_sources
    ADD CONSTRAINT execution_log_sources_pkey PRIMARY KEY (execution_id);

ALTER TABLE ONLY execution_log_sources
    ADD CONSTRAINT execution_log_sources_tenant_id_project_id_execution_id_key UNIQUE (tenant_id, project_id, execution_id);

ALTER TABLE ONLY execution_placement
    ADD CONSTRAINT execution_placement_pkey PRIMARY KEY (execution_id);

ALTER TABLE ONLY executions
    ADD CONSTRAINT executions_pkey PRIMARY KEY (id);

ALTER TABLE ONLY executions
    ADD CONSTRAINT executions_tenant_id_project_id_id_key UNIQUE (tenant_id, project_id, id);

ALTER TABLE ONLY external_endpoints
    ADD CONSTRAINT external_endpoints_pkey PRIMARY KEY (id);

ALTER TABLE ONLY external_endpoints
    ADD CONSTRAINT external_endpoints_tenant_id_project_id_id_key UNIQUE (tenant_id, project_id, id);

ALTER TABLE ONLY external_endpoints
    ADD CONSTRAINT external_endpoints_tenant_id_project_id_name_key UNIQUE (tenant_id, project_id, name);

ALTER TABLE ONLY external_endpoints
    ADD CONSTRAINT external_endpoints_tenant_id_project_id_network_id_id_key UNIQUE (tenant_id, project_id, network_id, id);

ALTER TABLE ONLY https_revocations
    ADD CONSTRAINT https_revocations_pkey PRIMARY KEY (operation_id, execution_id);

ALTER TABLE ONLY ingress_reservations
    ADD CONSTRAINT ingress_reservations_pkey PRIMARY KEY (id);

ALTER TABLE ONLY network_grants
    ADD CONSTRAINT network_grants_pkey PRIMARY KEY (id);

ALTER TABLE ONLY network_grants
    ADD CONSTRAINT network_grants_tenant_id_project_id_id_key UNIQUE (tenant_id, project_id, id);

ALTER TABLE ONLY network_revocations
    ADD CONSTRAINT network_revocations_pkey PRIMARY KEY (operation_id, execution_id);

ALTER TABLE ONLY networks
    ADD CONSTRAINT networks_pkey PRIMARY KEY (id);

ALTER TABLE ONLY networks
    ADD CONSTRAINT networks_tenant_id_project_id_id_key UNIQUE (tenant_id, project_id, id);

ALTER TABLE ONLY networks
    ADD CONSTRAINT networks_tenant_id_project_id_name_key UNIQUE (tenant_id, project_id, name);

ALTER TABLE ONLY nodes
    ADD CONSTRAINT nodes_cert_sha256_key UNIQUE (cert_sha256);

ALTER TABLE ONLY nodes
    ADD CONSTRAINT nodes_name_key UNIQUE (name);

ALTER TABLE ONLY nodes
    ADD CONSTRAINT nodes_pkey PRIMARY KEY (id);

ALTER TABLE ONLY operations
    ADD CONSTRAINT operations_pkey PRIMARY KEY (id);

ALTER TABLE ONLY operations
    ADD CONSTRAINT operations_scoped_id UNIQUE (tenant_id, project_id, id);

ALTER TABLE ONLY operations
    ADD CONSTRAINT operations_tenant_id_project_id_request_key_key UNIQUE (tenant_id, project_id, request_key);

ALTER TABLE ONLY platform_format
    ADD CONSTRAINT platform_format_pkey PRIMARY KEY (singleton);

ALTER TABLE ONLY projects
    ADD CONSTRAINT projects_pkey PRIMARY KEY (id);

ALTER TABLE ONLY projects
    ADD CONSTRAINT projects_tenant_id_id_key UNIQUE (tenant_id, id);

ALTER TABLE ONLY projects
    ADD CONSTRAINT projects_tenant_id_name_key UNIQUE (tenant_id, name);

ALTER TABLE ONLY public_egress_policy
    ADD CONSTRAINT public_egress_policy_pkey PRIMARY KEY (singleton);

ALTER TABLE ONLY recovery_barrier
    ADD CONSTRAINT recovery_barrier_pkey PRIMARY KEY (singleton);

ALTER TABLE ONLY routes
    ADD CONSTRAINT routes_hostname_key UNIQUE (hostname);

ALTER TABLE ONLY routes
    ADD CONSTRAINT routes_pkey PRIMARY KEY (id);

ALTER TABLE ONLY schema_version
    ADD CONSTRAINT schema_version_pkey PRIMARY KEY (version);

ALTER TABLE ONLY secrets
    ADD CONSTRAINT secrets_pkey PRIMARY KEY (id);

ALTER TABLE ONLY secrets
    ADD CONSTRAINT secrets_tenant_id_project_id_id_key UNIQUE (tenant_id, project_id, id);

ALTER TABLE ONLY secrets
    ADD CONSTRAINT secrets_tenant_id_project_id_name_key UNIQUE (tenant_id, project_id, name);

ALTER TABLE ONLY tenants
    ADD CONSTRAINT tenants_pkey PRIMARY KEY (id);

ALTER TABLE ONLY traffic_usage
    ADD CONSTRAINT traffic_usage_pkey PRIMARY KEY (tenant_id, project_id, period);

ALTER TABLE ONLY usage_compaction_queue
    ADD CONSTRAINT usage_compaction_queue_pkey PRIMARY KEY (execution_id);

ALTER TABLE ONLY usage_samples
    ADD CONSTRAINT usage_samples_pkey PRIMARY KEY (execution_id, generation, sequence);

CREATE UNIQUE INDEX app_active_endpoint_connection ON app_endpoint_connections USING btree (app_id, endpoint_id) WHERE (state = 'active'::text);

CREATE UNIQUE INDEX app_active_https_connection ON app_https_connections USING btree (app_id, origin) WHERE (state = 'active'::text);

CREATE INDEX app_dispatch_retention ON app_run_dispatch USING btree (updated, run_id) WHERE (state <> 'pending'::text);

CREATE INDEX app_https_observation_scope ON app_https_connections USING btree (app_id, origin, created, id) WHERE (state <> 'revoked'::text);

CREATE INDEX app_lifecycle_expiry ON app_lifecycle_events USING btree (recorded_at, id);

CREATE INDEX app_lifecycle_history ON app_lifecycle_events USING btree (tenant_id, project_id, app_id, recorded_at DESC, id DESC);

CREATE INDEX app_release_history ON app_releases USING btree (app_id, created DESC, id DESC);

CREATE INDEX app_run_dispatch_pending ON app_run_dispatch USING btree (deadline, run_id) WHERE (state = 'pending'::text);

CREATE INDEX app_run_history ON app_runs USING btree (app_id, created DESC, id DESC);

CREATE INDEX app_schedule_misses_pending ON app_schedule_misses USING btree (updated, id) WHERE (NOT complete);

CREATE INDEX app_schedules_due ON app_schedules USING btree (next_at) WHERE (next_at IS NOT NULL);

CREATE INDEX app_version_artifact_reference ON app_versions USING btree (artifact_id);

CREATE INDEX apps_page ON apps USING btree (tenant_id, project_id, created DESC, id DESC);

CREATE INDEX artifact_expiration ON artifacts USING btree (last_uploaded_at, id) WHERE (retired_at IS NULL);

CREATE INDEX artifact_live_digest ON artifacts USING btree (digest) WHERE (retired_at IS NULL);

CREATE UNIQUE INDEX artifact_validation_one_per_node ON artifact_validations USING btree (node_id) WHERE (state = 'validating'::text);

CREATE INDEX artifact_validation_queue ON artifact_validations USING btree (available_at, created, artifact_id) WHERE (state = 'pending'::text);

CREATE INDEX audit_ingress_admission ON audit USING btree (tenant_id, created) WHERE (action = 'ingress.admit'::text);

CREATE INDEX connection_executions ON app_execution_connections USING btree (connection_id, execution_id);

CREATE INDEX deployment_artifact_reference ON deployments USING btree (((spec ->> 'artifact_id'::text)));

CREATE INDEX egress_allowance_retention ON egress_allowance_usage USING btree (period, execution_id);

CREATE INDEX egress_allowance_usage_scope ON egress_allowance_usage USING btree (tenant_id, period);

CREATE INDEX egress_period_retention ON execution_egress_periods USING btree (period, execution_id);

CREATE INDEX endpoint_connected_apps ON app_endpoint_connections USING btree (endpoint_id, app_id) WHERE (state <> 'revoked'::text);

CREATE INDEX execution_artifact_reference ON executions USING btree (((spec ->> 'artifact_id'::text)));

CREATE INDEX execution_egress_budgets_scope ON execution_egress_budgets USING btree (tenant_id, period);

CREATE INDEX execution_egress_period_scope ON execution_egress_periods USING btree (tenant_id, project_id, period);

CREATE INDEX execution_input_retention ON executions USING btree (updated, id) WHERE ((NOT reserved) AND (inputs_retired_at IS NULL) AND (spec ?| ARRAY['env'::text, 'endpoint_env'::text]));

CREATE INDEX execution_logs_expiry ON execution_log_records USING btree (received);

CREATE INDEX execution_logs_tenant_cursor ON execution_log_records USING btree (tenant_id, id);

CREATE INDEX execution_placement_expiry ON execution_placement USING btree (observed_at, execution_id);

CREATE INDEX executions_reservations ON executions USING btree (tenant_id, node_id) WHERE reserved;

CREATE INDEX https_connection_executions ON app_execution_https USING btree (connection_id, execution_id);

CREATE INDEX https_revocation_execution ON https_revocations USING btree (execution_id);

CREATE INDEX ingress_app_waiters ON ingress_reservations USING btree (app_id) WHERE (execution_id IS NULL);

CREATE INDEX ingress_execution_active ON ingress_reservations USING btree (execution_id);

CREATE UNIQUE INDEX network_grant_active ON network_grants USING btree (endpoint_id, COALESCE(deployment_id, execution_id)) WHERE (state <> 'revoked'::text);

CREATE INDEX operations_resource_history ON operations USING btree (resource_id, created DESC, id DESC);

CREATE UNIQUE INDEX projects_display_name_unique ON projects USING btree (tenant_id, lower(display_name));

CREATE UNIQUE INDEX projects_one_default ON projects USING btree (tenant_id) WHERE is_default;

CREATE UNIQUE INDEX projects_slug_unique ON projects USING btree (tenant_id, slug);

CREATE INDEX release_input_active_reference ON apps USING btree (active_release_id) WHERE (active_release_id IS NOT NULL);

CREATE INDEX release_input_http_reference ON app_http_attempts USING btree (release_id);

CREATE INDEX release_input_ingress_reference ON ingress_reservations USING btree (release_id) WHERE (release_id IS NOT NULL);

CREATE INDEX release_input_retention ON app_releases USING btree (unreferenced_since, id) WHERE ((inputs_retired_at IS NULL) AND (unreferenced_since IS NOT NULL));

CREATE INDEX release_input_run_reference ON app_runs USING btree (release_id);

CREATE INDEX release_input_target_reference ON apps USING btree (target_release_id) WHERE (target_release_id IS NOT NULL);

CREATE INDEX usage_compaction_order ON usage_compaction_queue USING btree (queued_at, execution_id);

CREATE INDEX usage_cpu_max ON usage_samples USING btree (execution_id, cpu_usec DESC, observed DESC, generation DESC, sequence DESC) WHERE cpu_measured;

CREATE INDEX usage_cpu_observed ON usage_samples USING btree (execution_id, observed DESC, generation DESC, sequence DESC) WHERE cpu_measured;

CREATE TRIGGER app_dispatch_delivery_guard BEFORE INSERT OR DELETE OR UPDATE ON app_run_dispatch FOR EACH ROW EXECUTE FUNCTION app_dispatch_delivery_guard();

CREATE CONSTRAINT TRIGGER app_dispatch_retirement_atomic AFTER UPDATE ON app_runs DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION app_dispatch_retirement_atomic();

CREATE TRIGGER app_dispatch_retirement_guard BEFORE INSERT OR DELETE OR UPDATE ON app_runs FOR EACH ROW EXECUTE FUNCTION app_dispatch_retirement_guard();

CREATE TRIGGER app_lifecycle AFTER INSERT OR UPDATE ON apps FOR EACH ROW EXECUTE FUNCTION app_lifecycle_changed();

CREATE TRIGGER app_release_immutable BEFORE UPDATE ON app_releases FOR EACH ROW EXECUTE FUNCTION immutable_app_release();

CREATE TRIGGER app_version_immutable BEFORE UPDATE ON app_versions FOR EACH ROW EXECUTE FUNCTION immutable_app_version();

CREATE TRIGGER execution_input_retirement_guard BEFORE INSERT OR DELETE OR UPDATE ON executions FOR EACH ROW EXECUTE FUNCTION execution_input_retirement_guard();

CREATE TRIGGER execution_lifecycle AFTER UPDATE ON executions FOR EACH ROW EXECUTE FUNCTION app_execution_lifecycle_changed();

CREATE TRIGGER http_attempt_lifecycle AFTER INSERT ON app_http_attempts FOR EACH ROW EXECUTE FUNCTION app_lifecycle_changed();

CREATE TRIGGER http_lifecycle AFTER INSERT OR UPDATE ON app_http FOR EACH ROW EXECUTE FUNCTION app_lifecycle_changed();

CREATE TRIGGER release_input_identity_guard BEFORE INSERT OR DELETE ON app_releases FOR EACH ROW EXECUTE FUNCTION release_input_identity_guard();

CREATE TRIGGER release_input_reference_clock AFTER INSERT OR UPDATE OF active_release_id, target_release_id ON apps FOR EACH ROW EXECUTE FUNCTION release_input_reference_clock();

CREATE TRIGGER release_input_reference_guard BEFORE INSERT OR UPDATE OF release_id ON app_http_attempts FOR EACH ROW EXECUTE FUNCTION release_input_reference_guard();

CREATE TRIGGER release_input_reference_guard BEFORE INSERT OR UPDATE OF release_id ON app_runs FOR EACH ROW EXECUTE FUNCTION release_input_reference_guard();

CREATE TRIGGER release_input_reference_guard BEFORE INSERT OR UPDATE OF active_release_id, target_release_id ON apps FOR EACH ROW EXECUTE FUNCTION release_input_reference_guard();

CREATE TRIGGER release_input_reference_guard BEFORE INSERT OR UPDATE OF release_id ON ingress_reservations FOR EACH ROW EXECUTE FUNCTION release_input_reference_guard();

CREATE TRIGGER release_lifecycle AFTER INSERT OR UPDATE ON app_releases FOR EACH ROW EXECUTE FUNCTION app_lifecycle_changed();

CREATE TRIGGER run_lifecycle AFTER INSERT OR UPDATE ON app_runs FOR EACH ROW EXECUTE FUNCTION app_lifecycle_changed();

CREATE TRIGGER schedule_revision_immutable BEFORE UPDATE ON app_schedule_revisions FOR EACH ROW EXECUTE FUNCTION immutable_schedule_revision();

ALTER TABLE ONLY accounting_month_rollups
    ADD CONSTRAINT accounting_month_rollups_tenant_id_project_id_fkey FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id);

ALTER TABLE ONLY app_endpoint_connections
    ADD CONSTRAINT app_endpoint_connections_tenant_id_project_id_app_id_fkey FOREIGN KEY (tenant_id, project_id, app_id) REFERENCES apps(tenant_id, project_id, id);

ALTER TABLE ONLY app_endpoint_connections
    ADD CONSTRAINT app_endpoint_connections_tenant_id_project_id_endpoint_id_fkey FOREIGN KEY (tenant_id, project_id, endpoint_id) REFERENCES external_endpoints(tenant_id, project_id, id);

ALTER TABLE ONLY app_endpoint_connections
    ADD CONSTRAINT app_endpoint_connections_tenant_id_project_id_revocation_o_fkey FOREIGN KEY (tenant_id, project_id, revocation_operation_id) REFERENCES operations(tenant_id, project_id, id);

ALTER TABLE ONLY app_execution_connections
    ADD CONSTRAINT app_execution_connections_tenant_id_project_id_app_id_conn_fkey FOREIGN KEY (tenant_id, project_id, app_id, connection_id) REFERENCES app_endpoint_connections(tenant_id, project_id, app_id, id);

ALTER TABLE ONLY app_execution_connections
    ADD CONSTRAINT app_execution_connections_tenant_id_project_id_execution_i_fkey FOREIGN KEY (tenant_id, project_id, execution_id) REFERENCES executions(tenant_id, project_id, id);

ALTER TABLE ONLY app_execution_https
    ADD CONSTRAINT app_execution_https_tenant_id_project_id_app_id_connection_fkey FOREIGN KEY (tenant_id, project_id, app_id, connection_id) REFERENCES app_https_connections(tenant_id, project_id, app_id, id);

ALTER TABLE ONLY app_execution_https
    ADD CONSTRAINT app_execution_https_tenant_id_project_id_execution_id_fkey FOREIGN KEY (tenant_id, project_id, execution_id) REFERENCES executions(tenant_id, project_id, id);

ALTER TABLE ONLY app_http_attempts
    ADD CONSTRAINT app_http_attempts_tenant_id_project_id_app_id_release_id_fkey FOREIGN KEY (tenant_id, project_id, app_id, release_id) REFERENCES app_releases(tenant_id, project_id, app_id, id);

ALTER TABLE ONLY app_http_attempts
    ADD CONSTRAINT app_http_attempts_tenant_id_project_id_execution_id_fkey FOREIGN KEY (tenant_id, project_id, execution_id) REFERENCES executions(tenant_id, project_id, id);

ALTER TABLE ONLY app_http_operations
    ADD CONSTRAINT app_http_operations_tenant_id_project_id_app_id_fkey FOREIGN KEY (tenant_id, project_id, app_id) REFERENCES app_http(tenant_id, project_id, app_id);

ALTER TABLE ONLY app_http_operations
    ADD CONSTRAINT app_http_operations_tenant_id_project_id_operation_id_fkey FOREIGN KEY (tenant_id, project_id, operation_id) REFERENCES operations(tenant_id, project_id, id);

ALTER TABLE ONLY app_http
    ADD CONSTRAINT app_http_tenant_id_project_id_app_id_fkey FOREIGN KEY (tenant_id, project_id, app_id) REFERENCES apps(tenant_id, project_id, id);

ALTER TABLE ONLY app_http
    ADD CONSTRAINT app_http_tenant_id_project_id_deployment_id_fkey FOREIGN KEY (tenant_id, project_id, deployment_id) REFERENCES deployments(tenant_id, project_id, id);

ALTER TABLE ONLY app_http
    ADD CONSTRAINT app_http_tenant_id_project_id_execution_id_fkey FOREIGN KEY (tenant_id, project_id, execution_id) REFERENCES executions(tenant_id, project_id, id);

ALTER TABLE ONLY app_https_connections
    ADD CONSTRAINT app_https_connections_tenant_id_project_id_app_id_fkey FOREIGN KEY (tenant_id, project_id, app_id) REFERENCES apps(tenant_id, project_id, id);

ALTER TABLE ONLY app_https_connections
    ADD CONSTRAINT app_https_connections_tenant_id_project_id_revocation_oper_fkey FOREIGN KEY (tenant_id, project_id, revocation_operation_id) REFERENCES operations(tenant_id, project_id, id);

ALTER TABLE ONLY app_lifecycle_events
    ADD CONSTRAINT app_lifecycle_events_tenant_id_project_id_app_id_fkey FOREIGN KEY (tenant_id, project_id, app_id) REFERENCES apps(tenant_id, project_id, id);

ALTER TABLE ONLY app_releases
    ADD CONSTRAINT app_releases_tenant_id_project_id_app_id_version_id_fkey FOREIGN KEY (tenant_id, project_id, app_id, version_id) REFERENCES app_versions(tenant_id, project_id, app_id, id);

ALTER TABLE ONLY app_run_dispatch
    ADD CONSTRAINT app_run_dispatch_tenant_id_project_id_app_id_run_id_fkey FOREIGN KEY (tenant_id, project_id, app_id, run_id) REFERENCES app_runs(tenant_id, project_id, app_id, id);

ALTER TABLE ONLY app_runs
    ADD CONSTRAINT app_runs_schedule_scope FOREIGN KEY (tenant_id, project_id, app_id, trigger_revision) REFERENCES app_schedule_revisions(tenant_id, project_id, app_id, revision);

ALTER TABLE ONLY app_runs
    ADD CONSTRAINT app_runs_tenant_id_project_id_app_id_release_id_fkey FOREIGN KEY (tenant_id, project_id, app_id, release_id) REFERENCES app_releases(tenant_id, project_id, app_id, id);

ALTER TABLE ONLY app_runs
    ADD CONSTRAINT app_runs_tenant_id_project_id_execution_id_fkey FOREIGN KEY (tenant_id, project_id, execution_id) REFERENCES executions(tenant_id, project_id, id);

ALTER TABLE ONLY app_schedule_misses
    ADD CONSTRAINT app_schedule_misses_tenant_id_project_id_app_id_release_id_fkey FOREIGN KEY (tenant_id, project_id, app_id, release_id) REFERENCES app_releases(tenant_id, project_id, app_id, id);

ALTER TABLE ONLY app_schedule_misses
    ADD CONSTRAINT app_schedule_misses_tenant_id_project_id_app_id_revision_fkey FOREIGN KEY (tenant_id, project_id, app_id, revision) REFERENCES app_schedule_revisions(tenant_id, project_id, app_id, revision);

ALTER TABLE ONLY app_schedule_revisions
    ADD CONSTRAINT app_schedule_revisions_tenant_id_project_id_app_id_fkey FOREIGN KEY (tenant_id, project_id, app_id) REFERENCES apps(tenant_id, project_id, id);

ALTER TABLE ONLY app_schedules
    ADD CONSTRAINT app_schedules_tenant_id_project_id_app_id_revision_fkey FOREIGN KEY (tenant_id, project_id, app_id, revision) REFERENCES app_schedule_revisions(tenant_id, project_id, app_id, revision);

ALTER TABLE ONLY app_triggers
    ADD CONSTRAINT app_triggers_tenant_id_project_id_app_id_fkey FOREIGN KEY (tenant_id, project_id, app_id) REFERENCES apps(tenant_id, project_id, id);

ALTER TABLE ONLY app_versions
    ADD CONSTRAINT app_versions_tenant_id_project_id_app_id_fkey FOREIGN KEY (tenant_id, project_id, app_id) REFERENCES apps(tenant_id, project_id, id);

ALTER TABLE ONLY app_versions
    ADD CONSTRAINT app_versions_tenant_id_project_id_artifact_id_fkey FOREIGN KEY (tenant_id, project_id, artifact_id) REFERENCES artifacts(tenant_id, project_id, id);

ALTER TABLE ONLY apps
    ADD CONSTRAINT apps_active_release FOREIGN KEY (tenant_id, project_id, id, active_release_id) REFERENCES app_releases(tenant_id, project_id, app_id, id);

ALTER TABLE ONLY apps
    ADD CONSTRAINT apps_latest_version FOREIGN KEY (tenant_id, project_id, id, latest_version) REFERENCES app_versions(tenant_id, project_id, app_id, number) DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY apps
    ADD CONSTRAINT apps_target_release FOREIGN KEY (tenant_id, project_id, id, target_release_id) REFERENCES app_releases(tenant_id, project_id, app_id, id);

ALTER TABLE ONLY apps
    ADD CONSTRAINT apps_tenant_id_project_id_fkey FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id);

ALTER TABLE ONLY artifact_validations
    ADD CONSTRAINT artifact_validations_node_id_fkey FOREIGN KEY (node_id) REFERENCES nodes(id);

ALTER TABLE ONLY artifact_validations
    ADD CONSTRAINT artifact_validations_tenant_id_project_id_artifact_id_fkey FOREIGN KEY (tenant_id, project_id, artifact_id) REFERENCES artifacts(tenant_id, project_id, id);

ALTER TABLE ONLY artifacts
    ADD CONSTRAINT artifacts_tenant_id_project_id_fkey FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id);

ALTER TABLE ONLY audit
    ADD CONSTRAINT audit_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id);

ALTER TABLE ONLY credentials
    ADD CONSTRAINT credentials_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id);

ALTER TABLE ONLY credentials
    ADD CONSTRAINT credentials_tenant_id_project_id_fkey FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id);

ALTER TABLE ONLY deployments
    ADD CONSTRAINT deployments_tenant_id_project_id_fkey FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id);

ALTER TABLE ONLY egress_allowance_usage
    ADD CONSTRAINT egress_allowance_usage_tenant_id_project_id_execution_id_fkey FOREIGN KEY (tenant_id, project_id, execution_id) REFERENCES executions(tenant_id, project_id, id);

ALTER TABLE ONLY execution_egress_budgets
    ADD CONSTRAINT execution_egress_budgets_execution_id_fkey FOREIGN KEY (execution_id) REFERENCES executions(id);

ALTER TABLE ONLY execution_egress_budgets
    ADD CONSTRAINT execution_egress_budgets_node_id_fkey FOREIGN KEY (node_id) REFERENCES nodes(id);

ALTER TABLE ONLY execution_egress_budgets
    ADD CONSTRAINT execution_egress_budgets_tenant_id_project_id_execution_id_fkey FOREIGN KEY (tenant_id, project_id, execution_id) REFERENCES executions(tenant_id, project_id, id);

ALTER TABLE ONLY execution_egress_period_sources
    ADD CONSTRAINT execution_egress_period_sourc_tenant_id_project_id_executi_fkey FOREIGN KEY (tenant_id, project_id, execution_id) REFERENCES executions(tenant_id, project_id, id);

ALTER TABLE ONLY execution_egress_periods
    ADD CONSTRAINT execution_egress_periods_execution_id_fkey FOREIGN KEY (execution_id) REFERENCES execution_egress_period_sources(execution_id);

ALTER TABLE ONLY execution_egress_periods
    ADD CONSTRAINT execution_egress_periods_tenant_id_project_id_execution_id_fkey FOREIGN KEY (tenant_id, project_id, execution_id) REFERENCES executions(tenant_id, project_id, id);

ALTER TABLE ONLY execution_egress_usage
    ADD CONSTRAINT execution_egress_usage_tenant_id_project_id_execution_id_fkey FOREIGN KEY (tenant_id, project_id, execution_id) REFERENCES executions(tenant_id, project_id, id);

ALTER TABLE ONLY execution_https_bindings
    ADD CONSTRAINT execution_https_bindings_execution_id_fkey FOREIGN KEY (execution_id) REFERENCES executions(id);

ALTER TABLE ONLY execution_log_records
    ADD CONSTRAINT execution_log_records_tenant_id_project_id_execution_id_fkey FOREIGN KEY (tenant_id, project_id, execution_id) REFERENCES execution_log_sources(tenant_id, project_id, execution_id);

ALTER TABLE ONLY execution_log_sources
    ADD CONSTRAINT execution_log_sources_tenant_id_project_id_execution_id_fkey FOREIGN KEY (tenant_id, project_id, execution_id) REFERENCES executions(tenant_id, project_id, id);

ALTER TABLE ONLY execution_placement
    ADD CONSTRAINT execution_placement_execution_id_fkey FOREIGN KEY (execution_id) REFERENCES executions(id) ON DELETE CASCADE;

ALTER TABLE ONLY executions
    ADD CONSTRAINT executions_node_id_fkey FOREIGN KEY (node_id) REFERENCES nodes(id);

ALTER TABLE ONLY executions
    ADD CONSTRAINT executions_tenant_id_project_id_deployment_id_fkey FOREIGN KEY (tenant_id, project_id, deployment_id) REFERENCES deployments(tenant_id, project_id, id);

ALTER TABLE ONLY executions
    ADD CONSTRAINT executions_tenant_id_project_id_fkey FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id);

ALTER TABLE ONLY external_endpoints
    ADD CONSTRAINT external_endpoints_tenant_id_project_id_network_id_fkey FOREIGN KEY (tenant_id, project_id, network_id) REFERENCES networks(tenant_id, project_id, id);

ALTER TABLE ONLY external_endpoints
    ADD CONSTRAINT external_endpoints_tenant_id_project_id_password_secret_id_fkey FOREIGN KEY (tenant_id, project_id, password_secret_id) REFERENCES secrets(tenant_id, project_id, id);

ALTER TABLE ONLY external_endpoints
    ADD CONSTRAINT external_endpoints_tenant_id_project_id_username_secret_id_fkey FOREIGN KEY (tenant_id, project_id, username_secret_id) REFERENCES secrets(tenant_id, project_id, id);

ALTER TABLE ONLY https_revocations
    ADD CONSTRAINT https_revocations_execution_id_fkey FOREIGN KEY (execution_id) REFERENCES executions(id);

ALTER TABLE ONLY https_revocations
    ADD CONSTRAINT https_revocations_operation_id_fkey FOREIGN KEY (operation_id) REFERENCES operations(id);

ALTER TABLE ONLY ingress_reservations
    ADD CONSTRAINT ingress_app_release FOREIGN KEY (tenant_id, project_id, app_id, release_id) REFERENCES app_releases(tenant_id, project_id, app_id, id);

ALTER TABLE ONLY ingress_reservations
    ADD CONSTRAINT ingress_execution FOREIGN KEY (tenant_id, project_id, execution_id) REFERENCES executions(tenant_id, project_id, id);

ALTER TABLE ONLY ingress_reservations
    ADD CONSTRAINT ingress_reservations_tenant_id_project_id_fkey FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id);

ALTER TABLE ONLY network_grants
    ADD CONSTRAINT network_grants_tenant_id_project_id_deployment_id_fkey FOREIGN KEY (tenant_id, project_id, deployment_id) REFERENCES deployments(tenant_id, project_id, id);

ALTER TABLE ONLY network_grants
    ADD CONSTRAINT network_grants_tenant_id_project_id_execution_id_fkey FOREIGN KEY (tenant_id, project_id, execution_id) REFERENCES executions(tenant_id, project_id, id);

ALTER TABLE ONLY network_grants
    ADD CONSTRAINT network_grants_tenant_id_project_id_network_id_endpoint_id_fkey FOREIGN KEY (tenant_id, project_id, network_id, endpoint_id) REFERENCES external_endpoints(tenant_id, project_id, network_id, id);

ALTER TABLE ONLY network_revocations
    ADD CONSTRAINT network_revocations_execution_id_fkey FOREIGN KEY (execution_id) REFERENCES executions(id);

ALTER TABLE ONLY network_revocations
    ADD CONSTRAINT network_revocations_operation_id_fkey FOREIGN KEY (operation_id) REFERENCES operations(id);

ALTER TABLE ONLY networks
    ADD CONSTRAINT networks_tenant_id_project_id_fkey FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id);

ALTER TABLE ONLY operations
    ADD CONSTRAINT operations_tenant_id_project_id_fkey FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id);

ALTER TABLE ONLY projects
    ADD CONSTRAINT projects_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id);

ALTER TABLE ONLY routes
    ADD CONSTRAINT routes_tenant_id_project_id_deployment_id_fkey FOREIGN KEY (tenant_id, project_id, deployment_id) REFERENCES deployments(tenant_id, project_id, id);

ALTER TABLE ONLY secrets
    ADD CONSTRAINT secrets_tenant_id_project_id_fkey FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id);

ALTER TABLE ONLY traffic_usage
    ADD CONSTRAINT traffic_usage_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id);

ALTER TABLE ONLY traffic_usage
    ADD CONSTRAINT traffic_usage_tenant_id_project_id_fkey FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id);

ALTER TABLE ONLY usage_compaction_queue
    ADD CONSTRAINT usage_compaction_queue_execution_id_fkey FOREIGN KEY (execution_id) REFERENCES executions(id);

ALTER TABLE ONLY usage_samples
    ADD CONSTRAINT usage_samples_execution_id_fkey FOREIGN KEY (execution_id) REFERENCES executions(id);

ALTER TABLE ONLY usage_samples
    ADD CONSTRAINT usage_samples_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id);

CREATE OR REPLACE VIEW transfer_allowance_accounting AS
    SELECT tenant_id,project_id,period,bytes::numeric used_bytes,0::numeric held_bytes FROM traffic_usage
    UNION ALL SELECT tenant_id,project_id,period,0::numeric,bytes::numeric FROM ingress_reservations
    UNION ALL SELECT tenant_id,project_id,period,bytes::numeric,0::numeric FROM egress_allowance_usage
    UNION ALL SELECT tenant_id,project_id,period,0::numeric,held_bytes::numeric FROM execution_egress_budgets
    UNION ALL SELECT tenant_id,project_id,period,outbound_accounted_bytes,0::numeric FROM accounting_month_rollups;

CREATE VIEW storage_reservations AS SELECT tenant_id,project_id,size AS bytes FROM artifacts WHERE retired_at IS NULL;
INSERT INTO schema_version VALUES(1);
INSERT INTO platform_format VALUES(true,'wasm-only-v1');
INSERT INTO recovery_barrier(singleton) VALUES(true);
INSERT INTO public_egress_policy(singleton) VALUES(true);
INSERT INTO app_lifecycle_coverage DEFAULT VALUES;
