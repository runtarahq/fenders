//! Release selection and manual event admission. Neither attaching code nor
//! activating a release invokes a command.
use crate::{
    args,
    artifacts::RUNTIME,
    db::*,
    error::{Error, Result},
    model::{Principal, identity, uid},
    store::{Store, Tx},
    workloads::wasm_spec,
};
pub use fenders_node_protocol::app_runtime::sizes;
use serde_json::{Value, json};

#[derive(Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryPage {
    pub before: Option<String>,
    pub limit: Option<i64>,
    pub trigger: Option<String>,
}

#[derive(Clone, Copy, Default, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RunSource {
    #[default]
    Manual,
    TestSchedule,
}
#[derive(Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunInvocation {
    #[serde(default)]
    pub source: RunSource,
    /// A schedule test may send one of the schedule's own times instead of now.
    pub trigger_time: Option<String>,
}
pub struct RunEvent<'a> {
    pub key: &'a str,
    pub source: RunSource,
    pub trigger_time: Option<&'a str>,
}

/// One of the schedule's own times, from the last 30 days through its next five.
fn occurrence(
    schedule: &crate::schedule::Schedule,
    value: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<chrono::DateTime<chrono::Utc>> {
    let refused = || {
        Error::invalid(
            "trigger time must be a schedule time from the last 30 days or one of the next five",
        )
    };
    let time = chrono::DateTime::parse_from_rfc3339(value)
        .map_err(|_| refused())?
        .with_timezone(&chrono::Utc);
    let upcoming = schedule.next(now, 5)?;
    let exact = schedule
        .next(time - chrono::Duration::nanoseconds(1), 1)?
        .first()
        == Some(&time);
    if !exact
        || time < now - chrono::Duration::days(30)
        || upcoming.last().is_some_and(|last| time > *last)
    {
        return Err(refused());
    }
    Ok(time)
}

/// The most executions one app may be given.
pub const MAX_SCALE: i64 = 8;

pub(crate) fn app_configuration(value: &Value, default_size: &str) -> Result<Value> {
    fields(
        value,
        &[
            "size",
            "env",
            "secret_env",
            "keep_warm",
            "concurrency",
            "scale",
            "websocket",
        ],
        &[],
    )?;
    if value.get("keep_warm").is_some_and(|v| !v.is_boolean()) {
        return Err(Error::invalid("keep_warm must be a boolean"));
    }
    let mut configuration = json!({"size":get(value,"size",json!(default_size)),"env":get(value,"env",json!({})),"secret_env":get(value,"secret_env",json!({}))});
    // Preserve legacy snapshots and request fingerprints. The customer wizard
    // selects on-demand explicitly; absent settings retain existing warm behavior.
    if let Some(warm) = value.get("keep_warm") {
        configuration["keep_warm"] = warm.clone();
    }
    // How many executions serve the app's HTTP requests: at least `min`
    // (none while idle when it is 0), more under load up to `max`. Saying
    // it also says whether the app is kept warm.
    if let Some(scale) = value.get("scale") {
        fields(scale, &["min", "max"], &["min", "max"])?;
        let max = fenders_node_protocol::value::integer(&scale["max"], 1, MAX_SCALE)
            .map_err(|_| Error::invalid("scale.max must be from 1 to 8"))?;
        let min = fenders_node_protocol::value::integer(&scale["min"], 0, max)
            .map_err(|_| Error::invalid("scale.min must be from 0 to scale.max"))?;
        if value
            .get("keep_warm")
            .is_some_and(|warm| *warm != (min > 0))
        {
            return Err(Error::invalid("keep_warm contradicts scale.min"));
        }
        configuration["keep_warm"] = json!(min > 0);
        configuration["scale"] = json!({"min":min,"max":max});
    }
    // Whether the gateway accepts WebSocket connections for the app and
    // gives it their events; its executions may then send to them.
    match value.get("websocket") {
        Some(Value::Bool(true)) => configuration["websocket"] = json!(true),
        Some(Value::Bool(false)) | None => {}
        Some(_) => return Err(Error::invalid("websocket must be a boolean")),
    }
    command_spec(&"0".repeat(32), &configuration)?;
    // The requests one execution serves at once. They must fit its size.
    if let Some(concurrency) = value.get("concurrency") {
        configuration["concurrency"] = concurrency.clone();
        http_spec(
            command_spec(&"0".repeat(32), &configuration)?,
            &configuration,
        )?;
    }
    Ok(configuration)
}

/// The launch spec of an app's HTTP execution, from its release's command
/// spec and configuration.
pub(crate) fn http_spec(mut spec: Value, configuration: &Value) -> Result<Value> {
    spec["mode"] = json!("http");
    spec["restart_policy"] = json!("never");
    if let Some(concurrency) = configuration.get("concurrency") {
        spec["http_concurrency"] = concurrency.clone();
    }
    Ok(wasm_spec(&spec, true)?)
}

pub(crate) fn command_spec(artifact: &str, configuration: &Value) -> Result<Value> {
    let size = sizes()
        .as_array()
        .unwrap()
        .iter()
        .find(|size| size["id"] == configuration["size"])
        .cloned()
        .ok_or_else(|| Error::invalid("unsupported app size"))?;
    Ok(wasm_spec(
        &json!({"artifact_id":artifact,"mode":"command","cpu_percent":size["cpu_percent"],"guest_memory_mib":size["guest_memory_mib"],"host_memory_mib":size["vm_memory_mib"],"wasm_memory_mib":size["wasm_linear_memory_mib"],"env":configuration["env"],"secret_env":configuration["secret_env"],"restart_policy":"never"}),
        false,
    )?)
}

async fn idle(tx: &mut Tx, app: &str) -> Result<()> {
    if optional(tx,"SELECT r.id FROM app_runs r LEFT JOIN executions e ON e.id=r.execution_id WHERE r.app_id=$1 AND (r.admission='pending' OR e.reserved) LIMIT 1",args![app]).await?.is_some() {
        return Err(conflict("app command is active or its outcome is uncertain"));
    }
    Ok(())
}

async fn completed(tx: &mut Tx, op: Value) -> Result<Value> {
    one(
        tx,
        "UPDATE operations SET state='succeeded',updated=now() WHERE id=$1 RETURNING *",
        args![op["id"]],
    )
    .await
}

impl Store {
    pub async fn app_history(
        &self,
        p: &Principal,
        tenant: &str,
        project: &str,
        app: &str,
        kind: &str,
        page: HistoryPage,
    ) -> Result<Value> {
        let (table, projection) = match kind {
            "runs" => ("customer_app_runs", "r.*"),
            "releases" => (
                "app_releases",
                "r.id,r.app_id,r.version_id,(SELECT number FROM app_versions WHERE id=r.version_id) AS version,r.configuration,r.inputs_retired_at,r.state,r.reason,r.created,r.updated",
            ),
            _ => return Err(Error::missing()),
        };
        let trigger = page.trigger.as_deref().unwrap_or("");
        if !matches!(trigger, "" | "http" | "manual" | "schedule")
            || kind != "runs" && !trigger.is_empty()
        {
            return Err(Error::invalid("unsupported run trigger filter"));
        }
        let filter = match trigger {
            "http" => " AND source='http'",
            "manual" => " AND source='manual'",
            "schedule" => " AND source IN ('schedule','test-schedule')",
            _ => "",
        };
        let limit = page.limit.unwrap_or(50);
        if !(1..=100).contains(&limit) {
            return Err(Error::invalid("page limit must be between 1 and 100"));
        }
        let mut tx = self.transaction(false, false).await?;
        Self::project(&mut tx, p, tenant, project, false).await?;
        Self::app_row(&mut tx, tenant, project, app).await?;
        let cursor = if let Some(before) = page.before {
            identity(&before)?;
            one(&mut tx,&format!("SELECT * FROM {table} WHERE tenant_id=$1 AND project_id=$2 AND app_id=$3 AND id=$4{filter}"),args![tenant,project,app,before]).await?
        } else {
            Value::Null
        };
        let event_time = if kind == "runs" {
            "COALESCE(r.scheduled_at,r.created)"
        } else {
            "r.created"
        };
        let event_cursor = if kind == "runs" && !cursor["scheduled_at"].is_null() {
            &cursor["scheduled_at"]
        } else {
            &cursor["created"]
        };
        let mut items = rows(&mut tx,&format!("SELECT {projection} FROM {table} r WHERE tenant_id=$1 AND project_id=$2 AND app_id=$3{filter} AND ($4::timestamptz IS NULL OR ({event_time},r.created,r.id)<($7::timestamptz,$4::timestamptz,$5)) ORDER BY {event_time} DESC,r.created DESC,r.id DESC LIMIT $6"),args![tenant,project,app,cursor["created"],cursor["id"],limit+1,event_cursor]).await?;
        let more = items.len() > limit as usize;
        items.truncate(limit as usize);
        let next = if more {
            items.last().unwrap()["id"].clone()
        } else {
            Value::Null
        };
        if kind == "runs" {
            crate::placement::project(&mut tx, tenant, project, &mut items).await?;
        }
        for item in &mut items {
            crate::app_diagnostics::decorate(item);
        }
        let mut result = json!({"items":items,"next":next});
        if kind == "runs" {
            result["missed_history_pending"] =
                json!(Self::missed_history_pending(&mut tx, app).await?);
        }
        Ok(result)
    }
    pub async fn app_sizes(&self, p: &Principal, tenant: &str, project: &str) -> Result<Value> {
        let mut tx = self.transaction(false, false).await?;
        Self::project(&mut tx, p, tenant, project, false).await?;
        let defaults = one(
            &mut tx,
            "SELECT default_app_size FROM tenants WHERE id=$1",
            args![tenant],
        )
        .await?;
        Ok(
            json!({"items":sizes(),"default_size":defaults["default_app_size"],"runtime":RUNTIME,"memory_contract":"limits, not measured resident memory; live size qualification remains pending"}),
        )
    }

    pub async fn app_triggers(
        &self,
        p: &Principal,
        tenant: &str,
        project: &str,
        app: &str,
    ) -> Result<Value> {
        let mut tx = self.transaction(false, false).await?;
        Self::project(&mut tx, p, tenant, project, false).await?;
        Self::app_row(&mut tx, tenant, project, app).await?;
        let mut result = one(
            &mut tx,
            "SELECT manual,http,revision,updated FROM app_triggers WHERE app_id=$1",
            args![app],
        )
        .await?;
        result["schedule"] = Self::schedule_summary(&mut tx, app).await?;
        Ok(result)
    }

    pub async fn update_app_triggers(
        &self,
        p: &Principal,
        tenant: &str,
        project: &str,
        app: &str,
        value: Value,
        key: &str,
    ) -> Result<Value> {
        self.update_app_triggers_at(
            p,
            tenant,
            project,
            app,
            crate::app_http::TriggerUpdate {
                value,
                key,
                domain: "apps.localhost",
            },
        )
        .await
    }

    pub async fn update_app_triggers_at(
        &self,
        p: &Principal,
        tenant: &str,
        project: &str,
        app: &str,
        update: crate::app_http::TriggerUpdate<'_>,
    ) -> Result<Value> {
        let crate::app_http::TriggerUpdate { value, key, domain } = update;
        fields(
            &value,
            &["manual", "http", "schedule", "expected_revision"],
            &["expected_revision"],
        )?;
        integer(&value["expected_revision"], 1, i64::MAX - 1)?;
        if ["manual", "http"]
            .iter()
            .any(|key| value.get(key).is_some_and(|v| !v.is_boolean()))
            || !["manual", "http", "schedule"]
                .iter()
                .any(|key| value.get(key).is_some())
        {
            return Err(Error::invalid("trigger values must be booleans"));
        }
        let request = json!({"kind":"app-triggers","app_id":app,"value":value});
        let mut tx = self.transaction(true, false).await?;
        Self::project(&mut tx, p, tenant, project, true).await?;
        let row = Self::app_row(&mut tx, tenant, project, app).await?;
        if let Some(op) = Self::idem(&mut tx, tenant, project, key, &request).await? {
            return Ok(op);
        }
        let triggers = one(
            &mut tx,
            "SELECT * FROM app_triggers WHERE app_id=$1",
            args![app],
        )
        .await?;
        if triggers["revision"] != value["expected_revision"] {
            return Err(conflict("trigger revision changed; reload before saving")
                .coded("revision_conflict"));
        }
        let schedule = Self::schedule_config(
            value.get("schedule"),
            &Self::schedule_row(&mut tx, app).await?,
        )?;
        Self::cancel_schedule_dispatch(&mut tx, app, "trigger-changed").await?;
        idle(&mut tx, app).await?;
        let manual = get(&value, "manual", triggers["manual"].clone());
        let http = get(&value, "http", triggers["http"].clone());
        if !row["target_release_id"].is_null() {
            let version = one(&mut tx,"SELECT v.inspection FROM app_releases l JOIN app_versions v ON v.id=l.version_id WHERE l.id=$1",args![row["target_release_id"]]).await?;
            if (manual == true || schedule["enabled"] == true)
                && version["inspection"]["command"] != true
            {
                return Err(conflict(
                    "active component has no compatible command entry point",
                ));
            }
            if http == true && version["inspection"]["http"] != true {
                return Err(conflict("component has no compatible HTTP entry point"));
            }
        }
        if http == true {
            Self::ensure_app_http(&mut tx, &row, domain).await?;
        }
        exec(
            &mut tx,
            "UPDATE app_triggers SET manual=$1,http=$2,revision=revision+1,updated=now() WHERE app_id=$3",
            args![manual,http,app],
        )
        .await?;
        Self::save_schedule(&mut tx, &row, n(&triggers["revision"]) + 1, &schedule).await?;
        exec(
            &mut tx,
            "UPDATE apps SET updated=now() WHERE id=$1",
            args![app],
        )
        .await?;
        if http != triggers["http"] && !row["target_release_id"].is_null() {
            // A fresh rollout keeps the previous failure/history intact and uses
            // current configuration; changing triggers never changes code version.
            self.copy_app_release(&mut tx, &row, http == true && row["desired"] == "enabled")
                .await?;
            exec(
                &mut tx,
                "UPDATE apps SET revision=revision+1 WHERE id=$1",
                args![app],
            )
            .await?;
        }
        let op =
            Self::operation(&mut tx, tenant, project, key, &request, app, "app-triggers").await?;
        let op = if http != triggers["http"] && Self::request_app_http(&mut tx, app, &op).await? {
            self.reconcile_app_http(&mut tx).await?;
            one(
                &mut tx,
                "SELECT * FROM operations WHERE id=$1",
                args![op["id"]],
            )
            .await?
        } else {
            completed(&mut tx, op).await?
        };
        Self::audit(
            &mut tx,
            p,
            "app.triggers",
            app,
            tenant,
            json!({"revision":n(&triggers["revision"])+1,"manual":manual,"http":http,"schedule":schedule["enabled"]}),
        )
        .await?;
        tx.commit().await?;
        Ok(op)
    }

    pub async fn activate_app_release(
        &self,
        p: &Principal,
        tenant: &str,
        project: &str,
        app: &str,
        value: Value,
        key: &str,
    ) -> Result<Value> {
        fields(
            &value,
            &["version_id", "configuration", "expected_revision"],
            &["version_id", "expected_revision"],
        )?;
        let version_id = id(&value["version_id"])?;
        integer(&value["expected_revision"], 1, i64::MAX - 1)?;
        let request = json!({"kind":"activate-app-release","app_id":app,"value":value});
        let mut tx = self.transaction(true, false).await?;
        Self::project(&mut tx, p, tenant, project, true).await?;
        let row = Self::app_row(&mut tx, tenant, project, app).await?;
        if let Some(op) = Self::idem(&mut tx, tenant, project, key, &request).await? {
            return Ok(op);
        }
        if row["revision"] != value["expected_revision"] {
            return Err(
                conflict("app revision changed; reload before saving").coded("revision_conflict")
            );
        }
        idle(&mut tx, app).await?;
        let version = one(&mut tx,"SELECT * FROM app_versions WHERE tenant_id=$1 AND project_id=$2 AND app_id=$3 AND id=$4",args![tenant,project,app,version_id]).await?;
        // Rollback uses today's configuration, not a historical release's secrets,
        // permissions or size. Code versions contain none of these settings.
        let configuration = if let Some(configuration) = value.get("configuration") {
            app_configuration(configuration, s(&row["configuration"]["size"]))?
        } else {
            row["configuration"].clone()
        };
        let release = self
            .stage_app_release(&mut tx, &row, &version, &configuration)
            .await?;
        let op = Self::operation(
            &mut tx,
            tenant,
            project,
            key,
            &request,
            s(&release["id"]),
            "activate-app-release",
        )
        .await?;
        // A release takes over from one that is serving without a gap.
        let op = if Self::replace_app_http(&mut tx, app, &op).await? {
            self.reconcile_app_http(&mut tx).await?;
            one(
                &mut tx,
                "SELECT * FROM operations WHERE id=$1",
                args![op["id"]],
            )
            .await?
        } else {
            completed(&mut tx, op).await?
        };
        Self::audit(
            &mut tx,
            p,
            "app.release",
            app,
            tenant,
            json!({"release_id":release["id"],"version":version["number"]}),
        )
        .await?;
        tx.commit().await?;
        Ok(op)
    }

    pub(crate) async fn stage_app_release(
        &self,
        tx: &mut Tx,
        row: &Value,
        version: &Value,
        configuration: &Value,
    ) -> Result<Value> {
        let app = s(&row["id"]);
        if version["app_id"] != row["id"]
            || version["tenant_id"] != row["tenant_id"]
            || version["project_id"] != row["project_id"]
        {
            return Err(Error::missing());
        }
        if version["inspection"]["runtime"] != RUNTIME {
            return Err(
                conflict("code version requires validation for the supported runtime")
                    .coded("not_validated"),
            );
        }
        let triggers = one(tx, "SELECT * FROM app_triggers WHERE app_id=$1", args![app]).await?;
        let scheduled = Self::schedule_row(tx, app).await?["enabled"] == true;
        if (triggers["manual"] == true || scheduled) && version["inspection"]["command"] != true {
            return Err(conflict("component has no compatible command entry point"));
        }
        if triggers["http"] == true && version["inspection"]["http"] != true {
            return Err(conflict("component has no compatible HTTP entry point"));
        }
        let spec = Self::compose_app_connections(
            tx,
            app,
            command_spec(s(&version["artifact_id"]), configuration)?,
        )
        .await?;
        self.check_refs(tx, s(&row["tenant_id"]), s(&row["project_id"]), &spec)
            .await?;
        let preparing = triggers["http"] == true
            && (row["desired"] == "enabled" || row["target_release_id"].is_null());
        exec(tx,"UPDATE app_releases SET state='failed',reason='superseded',updated=now() WHERE app_id=$1 AND state='preparing'",args![app]).await?;
        let release = one(tx,"INSERT INTO app_releases(id,tenant_id,project_id,app_id,version_id,configuration,spec,state) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *",args![uid(),row["tenant_id"],row["project_id"],app,version["id"],configuration,spec,if preparing {"preparing"} else {"ready"}]).await?;
        exec(tx,"UPDATE apps SET target_release_id=$1,active_release_id=CASE WHEN $4 THEN active_release_id ELSE $1 END,configuration=$2,revision=revision+1,desired=CASE WHEN target_release_id IS NULL THEN 'enabled' ELSE desired END,updated=now() WHERE id=$3",args![release["id"],configuration,app,preparing]).await?;
        if row["target_release_id"].is_null() {
            Self::reset_schedule_clock(tx, app, true).await?;
        }
        Ok(release)
    }

    pub async fn app_lifecycle(
        &self,
        p: &Principal,
        tenant: &str,
        project: &str,
        app: &str,
        value: Value,
        key: &str,
    ) -> Result<Value> {
        fields(
            &value,
            &["desired", "expected_revision"],
            &["desired", "expected_revision"],
        )?;
        integer(&value["expected_revision"], 1, i64::MAX - 1)?;
        if !matches!(s(&value["desired"]), "enabled" | "stopped") {
            return Err(Error::invalid("invalid app desired state"));
        }
        let request = json!({"kind":"app-lifecycle","app_id":app,"value":value});
        let mut tx = self.transaction(true, false).await?;
        Self::project(&mut tx, p, tenant, project, true).await?;
        let row = Self::app_row(&mut tx, tenant, project, app).await?;
        if let Some(op) = Self::idem(&mut tx, tenant, project, key, &request).await? {
            return Ok(op);
        }
        if row["revision"] != value["expected_revision"] {
            return Err(
                conflict("app revision changed; reload before saving").coded("revision_conflict")
            );
        }
        if value["desired"] == "stopped" {
            Self::cancel_schedule_dispatch(&mut tx, app, "app-stopped").await?;
        }
        idle(&mut tx, app).await?;
        if value["desired"] == "enabled" && row["target_release_id"].is_null() {
            return Err(conflict("app has no active release"));
        }
        let triggers = one(
            &mut tx,
            "SELECT * FROM app_triggers WHERE app_id=$1",
            args![app],
        )
        .await?;
        if value["desired"] == "enabled" && row["desired"] == "stopped" && triggers["http"] == true
        {
            self.copy_app_release(&mut tx, &row, true).await?;
        }
        let changed = value["desired"] != row["desired"];
        if changed && value["desired"] == "stopped" {
            exec(&mut tx,"UPDATE app_releases SET state='failed',reason='app-stopped',updated=now() WHERE app_id=$1 AND state='preparing'",args![app]).await?;
        }
        exec(
            &mut tx,
            "UPDATE apps SET desired=$1,revision=revision+1,updated=now() WHERE id=$2 AND desired<>$1",
            args![value["desired"], app],
        )
        .await?;
        if changed {
            Self::reset_schedule_clock(&mut tx, app, value["desired"] == "enabled").await?;
        }
        let op = Self::operation(
            &mut tx,
            tenant,
            project,
            key,
            &request,
            app,
            "app-lifecycle",
        )
        .await?;
        let tracked = if changed {
            Self::request_app_http(&mut tx, app, &op).await?
        } else {
            Self::track_app_http(&mut tx, app, &op).await?
        };
        let op = if tracked {
            self.reconcile_app_http(&mut tx).await?;
            one(
                &mut tx,
                "SELECT * FROM operations WHERE id=$1",
                args![op["id"]],
            )
            .await?
        } else {
            completed(&mut tx, op).await?
        };
        Self::audit(
            &mut tx,
            p,
            "app.lifecycle",
            app,
            tenant,
            json!({"desired":value["desired"]}),
        )
        .await?;
        tx.commit().await?;
        Ok(op)
    }

    pub async fn run_app(
        &self,
        p: &Principal,
        tenant: &str,
        project: &str,
        app: &str,
        key: &str,
    ) -> Result<Value> {
        self.run_app_event(
            p,
            tenant,
            project,
            app,
            RunEvent {
                key,
                source: RunSource::Manual,
                trigger_time: None,
            },
        )
        .await
    }
    pub async fn run_app_event(
        &self,
        p: &Principal,
        tenant: &str,
        project: &str,
        app: &str,
        event: RunEvent<'_>,
    ) -> Result<Value> {
        let RunEvent {
            key,
            source,
            trigger_time,
        } = event;
        let source = match source {
            RunSource::Manual => "manual",
            RunSource::TestSchedule => "test-schedule",
        };
        let mut request = json!({"kind":"run-app","app_id":app,"source":source});
        // Absent unless chosen, so earlier submissions still match on retry.
        if let Some(time) = trigger_time {
            request["trigger_time"] = json!(time);
        }
        let mut tx = self.transaction(true, false).await?;
        Self::project(&mut tx, p, tenant, project, true).await?;
        let row = Self::app_row(&mut tx, tenant, project, app).await?;
        // Retry returns the original run even after stop, code changes, trigger
        // disable or an uncertain outcome. It never replays command side effects.
        if let Some(op) = Self::idem(&mut tx, tenant, project, key, &request).await? {
            return Ok(op);
        }
        if row["desired"] != "enabled"
            || row["active_release_id"].is_null()
            || row["target_release_id"] != row["active_release_id"]
        {
            return Err(conflict("app is stopped or has no active release"));
        }
        let triggers = one(
            &mut tx,
            "SELECT * FROM app_triggers WHERE app_id=$1",
            args![app],
        )
        .await?;
        let schedule = Self::schedule_row(&mut tx, app).await?;
        if (source == "manual" && triggers["manual"] != true)
            || (source == "test-schedule" && schedule["enabled"] != true)
        {
            return Err(conflict("requested command trigger is disabled"));
        }
        let run_id = uid();
        let now = crate::app_schedules::clock(&mut tx).await?;
        let context = if source == "manual" {
            if trigger_time.is_some() {
                return Err(Error::invalid("a manual run uses the current time"));
            }
            json!({"trigger":"manual","trigger_time":now.to_rfc3339(),"run_id":run_id})
        } else {
            // The app receives what a scheduled run at that time receives.
            let parsed = crate::schedule::Schedule::parse(
                text(&schedule["expression"])?,
                text(&schedule["timezone"])?,
            )?;
            let time = match trigger_time {
                None => now,
                Some(value) => occurrence(&parsed, value, now)?,
            };
            json!({"trigger":"schedule","trigger_time":time.to_rfc3339(),"run_id":run_id,"schedule":schedule["expression"],"schedule_timezone":schedule["timezone"]})
        };
        idle(&mut tx, app).await?;
        let release = one(&mut tx,"SELECT l.*,v.inspection FROM app_releases l JOIN app_versions v ON v.id=l.version_id WHERE l.id=$1",args![row["active_release_id"]]).await?;
        if release["state"] != "ready"
            || release["inspection"]["command"] != true
            || release["inspection"]["runtime"] != RUNTIME
        {
            return Err(conflict("active release cannot accept command events"));
        }
        self.check_refs(&mut tx, tenant, project, &release["spec"])
            .await?;
        // Existing execution rows form the durable dispatch queue. Shared quota
        // reservation, execution and run identity commit together.
        let mut spec = release["spec"].clone();
        spec["run_context"] = crate::workloads::run_context(&context)?;
        let execution = Self::execution(&mut tx, tenant, project, &spec, None, 1).await?;
        Self::record_app_connections(&mut tx, app, &execution).await?;
        let run = one(&mut tx,"INSERT INTO app_runs(id,tenant_id,project_id,app_id,release_id,execution_id,source) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *",args![run_id,tenant,project,app,release["id"],execution["id"],source]).await?;
        let op = Self::operation(
            &mut tx,
            tenant,
            project,
            key,
            &request,
            s(&run["id"]),
            "run-app",
        )
        .await?;
        Self::audit(
            &mut tx,
            p,
            "app.run",
            app,
            tenant,
            json!({"run_id":run["id"],"release_id":release["id"],"source":source}),
        )
        .await?;
        tx.commit().await?;
        Ok(op)
    }

    pub(crate) async fn reconcile_app_runs(tx: &mut Tx) -> Result<()> {
        exec(tx,"UPDATE operations o SET state=CASE WHEN r.state='succeeded' THEN 'succeeded' ELSE 'failed' END,error=CASE WHEN r.state='succeeded' THEN NULL WHEN r.state='unknown' THEN 'outcome-unknown' ELSE 'command-failed-or-cancelled' END,updated=now() FROM app_run_observations r WHERE o.resource_id=r.id AND o.kind='run-app' AND o.state='pending' AND NOT r.reserved",args![]).await?;
        Self::reconcile_app_deletions(tx).await
    }

    pub async fn app_run(
        &self,
        p: &Principal,
        tenant: &str,
        project: &str,
        app: &str,
        run: &str,
    ) -> Result<Value> {
        let mut tx = self.transaction(false, false).await?;
        Self::project(&mut tx, p, tenant, project, false).await?;
        Self::app_row(&mut tx, tenant, project, app).await?;
        identity(run)?;
        let mut value=one(&mut tx,"SELECT * FROM customer_app_runs WHERE tenant_id=$1 AND project_id=$2 AND app_id=$3 AND id=$4",args![tenant,project,app,run]).await?;
        // What the command actually received; null until a scheduled run starts.
        value["context"] = optional(&mut tx,"SELECT spec->'run_context' AS context FROM executions WHERE tenant_id=$1 AND project_id=$2 AND id=$3",args![tenant,project,value["execution_id"]]).await?.map_or(Value::Null,|row|row["context"].clone());
        crate::placement::project(&mut tx, tenant, project, std::slice::from_mut(&mut value))
            .await?;
        crate::app_diagnostics::decorate(&mut value);
        Ok(value)
    }

    /// Stops a run of an app that has not ended.
    pub async fn cancel_app_run(
        &self,
        p: &Principal,
        tenant: &str,
        project: &str,
        app: &str,
        run: &str,
        key: &str,
    ) -> Result<Value> {
        let run = self.app_run(p, tenant, project, app, run).await?;
        let Some(execution) = run["execution_id"].as_str() else {
            return Err(Error::new(
                axum::http::StatusCode::CONFLICT,
                "run has nothing started to stop",
            ));
        };
        self.stop_execution(p, tenant, project, execution, key)
            .await
    }

    pub async fn app_release(
        &self,
        p: &Principal,
        tenant: &str,
        project: &str,
        app: &str,
        release: &str,
    ) -> Result<Value> {
        let mut tx = self.transaction(false, false).await?;
        Self::project(&mut tx, p, tenant, project, false).await?;
        Self::app_row(&mut tx, tenant, project, app).await?;
        identity(release)?;
        one(&mut tx,"SELECT r.id,r.app_id,r.version_id,(SELECT number FROM app_versions WHERE id=r.version_id) AS version,r.configuration,r.inputs_retired_at,r.state,r.reason,r.created,r.updated FROM app_releases r WHERE tenant_id=$1 AND project_id=$2 AND app_id=$3 AND id=$4",args![tenant,project,app,release]).await.map(|mut value| {crate::app_diagnostics::decorate(&mut value);value})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::WORKER_OVERHEAD_MIB;
    #[test]
    fn scale_and_concurrency_are_bounded_and_fit_the_size() {
        let size = s(&sizes().as_array().unwrap()[0]["id"]).to_owned();
        let configured = |value: Value| app_configuration(&value, &size);
        // Saying a scale says whether the app is kept warm.
        let scaled = configured(json!({"scale":{"min":0,"max":3}})).unwrap();
        assert_eq!(scaled["scale"], json!({"min":0,"max":3}));
        assert_eq!(scaled["keep_warm"], false);
        assert_eq!(
            configured(json!({"scale":{"min":2,"max":2}})).unwrap()["keep_warm"],
            true
        );
        // An app that says neither is as it was.
        let plain = configured(json!({})).unwrap();
        assert!(plain.get("scale").is_none() && plain.get("concurrency").is_none());
        for bad in [
            json!({"scale":{"min":0,"max":0}}),
            json!({"scale":{"min":3,"max":2}}),
            json!({"scale":{"min":0,"max":MAX_SCALE + 1}}),
            json!({"scale":{"max":2}}),
            json!({"scale":{"min":0,"max":2},"keep_warm":true}),
            json!({"concurrency":0}),
            json!({"concurrency":65}),
        ] {
            assert!(configured(bad.clone()).is_err(), "{bad}");
        }
        // Concurrency reaches the HTTP launch, and only that: a command of
        // the same app serves no requests.
        let one = configured(json!({"concurrency":1})).unwrap();
        let command = command_spec(&"0".repeat(32), &one).unwrap();
        assert!(command.get("http_concurrency").is_none());
        let http = http_spec(command, &one).unwrap();
        assert_eq!(http["mode"], "http");
        assert_eq!(http["http_concurrency"], 1);
        // More requests at once than the size's memory holds are refused.
        let limit =
            fenders_node_protocol::workloads::wasm_memory_limit_mib(n(&http["guest_memory_mib"]))
                / n(&http["wasm_memory_mib"]);
        assert!(configured(json!({"concurrency":limit.clamp(1, 64)})).is_ok());
        if limit < 64 {
            assert!(configured(json!({"concurrency":limit + 1})).is_err());
        }
    }

    #[test]
    fn sizes_distinguish_linear_vm_and_reserved_memory() {
        for size in sizes().as_array().unwrap() {
            let configuration = app_configuration(&json!({}), s(&size["id"])).unwrap();
            let spec = command_spec(&"0".repeat(32), &configuration).unwrap();
            assert_eq!(spec["cpu_percent"], size["cpu_percent"]);
            assert_eq!(spec["guest_memory_mib"], size["guest_memory_mib"]);
            assert_eq!(spec["wasm_memory_mib"], size["wasm_linear_memory_mib"]);
            assert_eq!(spec["host_memory_mib"], size["vm_memory_mib"]);
            assert_eq!(
                n(&size["reservation_memory_mib"]),
                n(&spec["host_memory_mib"]) + WORKER_OVERHEAD_MIB
            );
            assert_eq!(spec["restart_policy"], "never");
        }
        for bad in [
            json!({"size":"huge"}),
            json!({"size":null}),
            json!({"cpu_percent":10000}),
            json!({"network_id":"anything"}),
            json!({"env":{"FENDERS_SECRET":"x"}}),
            json!({"secret_env":{"TOKEN":"plaintext"}}),
        ] {
            assert!(app_configuration(&bad, "small").is_err());
        }
    }
}
