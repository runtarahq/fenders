//! Persistent customer app identities and immutable code versions. Attaching
//! code does not select a release, change permissions, or invoke a command.
use crate::{
    args,
    artifacts::{RUNTIME, validate_inspection},
    db::*,
    error::{Error, Result},
    model::{Principal, identity, uid},
    store::{Store, Tx},
};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppPage {
    pub search: Option<String>,
    pub before: Option<String>,
    pub limit: Option<i64>,
    pub trigger: Option<AppTriggerFilter>,
    pub status: Option<AppStatusFilter>,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AppStatusFilter {
    Ready,
    Stopped,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AppTriggerFilter {
    Http,
    Manual,
    Schedule,
    None,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionPage {
    pub before: Option<i64>,
}

pub struct AppSubmission<'a> {
    pub value: Value,
    pub key: &'a str,
    pub domain: &'a str,
}

impl Store {
    /// Recover an acknowledged or lost-response deployment without retaining its
    /// configuration in browser storage. Absence is not proof that an in-flight
    /// request failed; callers must not automatically submit a new intent.
    pub async fn app_submission(
        &self,
        p: &Principal,
        tenant: &str,
        project: &str,
        key: &str,
    ) -> Result<Value> {
        crate::customer_api::submitted_key(key)?;
        let mut tx = self.transaction(false, false).await?;
        Self::project(&mut tx, p, tenant, project, false).await?;
        one(&mut tx, "SELECT id,resource_id,kind,state,error,created,updated FROM operations WHERE tenant_id=$1 AND project_id=$2 AND request_key=$3 AND kind='deploy-app'", args![tenant,project,key]).await
    }

    /// Recover only an action belonging to this app. Request keys are not
    /// capabilities; both project membership and the resource association apply.
    pub async fn app_action_submission(
        &self,
        p: &Principal,
        tenant: &str,
        project: &str,
        app: &str,
        key: &str,
    ) -> Result<Value> {
        crate::customer_api::submitted_key(key)?;
        let mut tx = self.transaction(false, false).await?;
        Self::project(&mut tx, p, tenant, project, false).await?;
        identity(app)?;
        one(
            &mut tx,
            "SELECT id FROM apps WHERE tenant_id=$1 AND project_id=$2 AND id=$3",
            args![tenant, project, app],
        )
        .await?;
        one(&mut tx,"SELECT o.id,o.resource_id,o.kind,o.state,o.error,o.created,o.updated FROM operations o WHERE o.tenant_id=$1 AND o.project_id=$2 AND o.request_key=$4 AND ((o.kind IN ('delete-app','app-lifecycle','app-triggers','app-connections') AND o.resource_id=$3) OR (o.kind='run-app' AND EXISTS(SELECT 1 FROM app_runs r WHERE r.tenant_id=$1 AND r.project_id=$2 AND r.app_id=$3 AND r.id=o.resource_id)) OR (o.kind='activate-app-release' AND EXISTS(SELECT 1 FROM app_releases l WHERE l.tenant_id=$1 AND l.project_id=$2 AND l.app_id=$3 AND l.id=o.resource_id)) OR (o.kind='attach-app-version' AND EXISTS(SELECT 1 FROM app_versions v WHERE v.tenant_id=$1 AND v.project_id=$2 AND v.app_id=$3 AND v.id=o.resource_id)))",args![tenant,project,app,key]).await
    }

    pub(crate) async fn app_row(
        tx: &mut Tx,
        tenant: &str,
        project: &str,
        app: &str,
    ) -> Result<Value> {
        identity(app)?;
        one(
            tx,
            "SELECT * FROM apps WHERE tenant_id=$1 AND project_id=$2 AND id=$3 AND NOT deleted",
            args![tenant, project, app],
        )
        .await
    }

    async fn validated_code(
        tx: &mut Tx,
        tenant: &str,
        project: &str,
        artifact: &str,
    ) -> Result<Value> {
        identity(artifact)?;
        let row = one(tx, "SELECT v.state,v.inspection,a.digest,a.size FROM artifacts a JOIN artifact_validations v ON v.artifact_id=a.id WHERE a.tenant_id=$1 AND a.project_id=$2 AND a.id=$3 AND a.retired_at IS NULL", args![tenant,project,artifact]).await?;
        if row["state"] != "valid" {
            return Err(conflict(
                "component must finish validation before attaching code",
            ));
        }
        validate_inspection(
            &row["inspection"],
            s(&row["digest"]),
            n(&row["size"]) as usize,
        )?;
        if row["inspection"]["runtime"] != RUNTIME {
            return Err(conflict(
                "component requires validation for the supported runtime",
            ));
        }
        Ok(row["inspection"].clone())
    }

    async fn insert_code(
        tx: &mut Tx,
        app: &Value,
        artifact: &str,
        inspection: &Value,
        number: i64,
    ) -> Result<Value> {
        one(tx, "INSERT INTO app_versions(id,tenant_id,project_id,app_id,number,artifact_id,inspection) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *", args![uid(),app["tenant_id"],app["project_id"],app["id"],number,artifact,inspection]).await
    }

    pub async fn create_app(
        &self,
        p: &Principal,
        tenant: &str,
        project: &str,
        value: Value,
        key: &str,
    ) -> Result<Value> {
        fields(
            &value,
            &["name", "artifact_id", "configuration"],
            &["name", "artifact_id"],
        )?;
        named(&value["name"])?;
        let artifact = id(&value["artifact_id"])?;
        let mut request = json!({"kind":"create-app","name":value["name"],"artifact_id":artifact});
        // Preserve the version-four idempotency fingerprint for unchanged calls.
        if let Some(configuration) = value.get("configuration") {
            request["configuration"] = configuration.clone();
        }
        let mut tx = self.transaction(true, false).await?;
        Self::project(&mut tx, p, tenant, project, true).await?;
        if let Some(op) = Self::idem(&mut tx, tenant, project, key, &request).await? {
            return Ok(op);
        }
        let (app, _) = self
            .initialize_app(&mut tx, tenant, project, &value)
            .await?;
        let op = Self::operation(
            &mut tx,
            tenant,
            project,
            key,
            &request,
            s(&app["id"]),
            "create-app",
        )
        .await?;
        let op = one(
            &mut tx,
            "UPDATE operations SET state='succeeded',updated=now() WHERE id=$1 RETURNING *",
            args![op["id"]],
        )
        .await?;
        Self::audit(
            &mut tx,
            p,
            "app.create",
            s(&app["id"]),
            tenant,
            json!({"version":1}),
        )
        .await?;
        tx.commit().await?;
        Ok(op)
    }

    async fn initialize_app(
        &self,
        tx: &mut Tx,
        tenant: &str,
        project: &str,
        value: &Value,
    ) -> Result<(Value, Value)> {
        named(&value["name"])?;
        let artifact = id(&value["artifact_id"])?;
        let inspection = Self::validated_code(tx, tenant, project, artifact).await?;
        let defaults = one(
            tx,
            "SELECT default_app_size FROM tenants WHERE id=$1",
            args![tenant],
        )
        .await?;
        let configuration = crate::app_runtime::app_configuration(
            &get(value, "configuration", json!({})),
            s(&defaults["default_app_size"]),
        )?;
        self.check_refs(
            tx,
            tenant,
            project,
            &crate::app_runtime::command_spec(artifact, &configuration)?,
        )
        .await?;
        Self::metadata_limit(tx, tenant, "apps", crate::store::MAX_APPS).await?;
        let app = one(
            tx,
            "INSERT INTO apps(id,tenant_id,project_id,name,configuration) VALUES($1,$2,$3,$4,$5) RETURNING *",
            args![uid(), tenant, project, value["name"],configuration],
        )
        .await?;
        let version = Self::insert_code(tx, &app, artifact, &inspection, 1).await?;
        exec(
            tx,
            "INSERT INTO app_triggers(app_id,tenant_id,project_id) VALUES($1,$2,$3)",
            args![app["id"], tenant, project],
        )
        .await?;
        Ok((app, version))
    }

    /// The wizard submits one intent. All customer records and any initial HTTP
    /// reservation commit together; a command still requires a separate event.
    pub async fn deploy_app(
        &self,
        p: &Principal,
        tenant: &str,
        project: &str,
        submission: AppSubmission<'_>,
    ) -> Result<Value> {
        let AppSubmission { value, key, domain } = submission;
        fields(
            &value,
            &[
                "name",
                "artifact_id",
                "configuration",
                "triggers",
                "connections",
                "endpoints",
                "https_origins",
            ],
            &["name", "artifact_id", "triggers"],
        )?;
        fields(
            &value["triggers"],
            &["http", "manual", "schedule"],
            &["http", "manual"],
        )?;
        if !value["triggers"]["http"].is_boolean() || !value["triggers"]["manual"].is_boolean() {
            return Err(Error::invalid("trigger flags must be booleans"));
        }
        let request = json!({"kind":"deploy-app","value":value});
        let mut tx = self.transaction(true, false).await?;
        Self::project(&mut tx, p, tenant, project, true).await?;
        if let Some(op) = Self::idem(&mut tx, tenant, project, key, &request).await? {
            return Ok(op);
        }
        let (app, version) = self
            .initialize_app(&mut tx, tenant, project, &value)
            .await?;
        let (tcp, https) = Self::customer_connections(&mut tx, tenant, project, &value)
            .await?
            .unwrap_or_else(|| {
                (
                    get(&value, "endpoints", json!([])),
                    get(&value, "https_origins", json!([])),
                )
            });
        Self::initial_app_connections(&mut tx, &app, &tcp).await?;
        self.initial_app_https(&mut tx, &app, &https).await?;

        let schedule = Self::schedule_config(value["triggers"].get("schedule"), &Value::Null)?;
        Self::save_schedule(&mut tx, &app, 1, &schedule).await?;
        exec(
            &mut tx,
            "UPDATE app_triggers SET manual=$1,http=$2 WHERE app_id=$3",
            args![
                value["triggers"]["manual"],
                value["triggers"]["http"],
                app["id"]
            ],
        )
        .await?;
        let release = self
            .stage_app_release(&mut tx, &app, &version, &app["configuration"])
            .await?;
        if value["triggers"]["http"] == true {
            Self::ensure_app_http(&mut tx, &app, domain).await?;
        }
        let op = Self::operation(
            &mut tx,
            tenant,
            project,
            key,
            &request,
            s(&app["id"]),
            "deploy-app",
        )
        .await?;
        if Self::request_app_http(&mut tx, s(&app["id"]), &op).await? {
            self.reconcile_app_http(&mut tx).await?;
        } else {
            exec(
                &mut tx,
                "UPDATE operations SET state='succeeded',updated=now() WHERE id=$1",
                args![op["id"]],
            )
            .await?;
        }
        Self::audit(
            &mut tx,
            p,
            "app.deploy",
            s(&app["id"]),
            tenant,
            json!({"version":1,"release_id":release["id"],"triggers":value["triggers"]}),
        )
        .await?;
        let result = one(
            &mut tx,
            "SELECT * FROM operations WHERE id=$1",
            args![op["id"]],
        )
        .await?;
        tx.commit().await?;
        Ok(result)
    }

    pub async fn attach_app_version(
        &self,
        p: &Principal,
        tenant: &str,
        project: &str,
        app: &str,
        value: Value,
        key: &str,
    ) -> Result<Value> {
        identity(app)?;
        fields(
            &value,
            &["artifact_id", "expected_revision"],
            &["artifact_id", "expected_revision"],
        )?;
        let artifact = id(&value["artifact_id"])?;
        let revision = integer(&value["expected_revision"], 1, i64::MAX - 1)?;
        let request = json!({"kind":"attach-app-version","app_id":app,"artifact_id":artifact,"expected_revision":revision});
        let mut tx = self.transaction(true, false).await?;
        Self::project(&mut tx, p, tenant, project, true).await?;
        if let Some(op) = Self::idem(&mut tx, tenant, project, key, &request).await? {
            return Ok(op);
        }
        let current = Self::app_row(&mut tx, tenant, project, app).await?;
        if current["revision"] != revision {
            return Err(conflict("app revision changed; reload before saving"));
        }
        let inspection = Self::validated_code(&mut tx, tenant, project, artifact).await?;
        // Reattaching the same immutable artifact with a new request key points
        // to its existing version; it cannot create duplicate version numbers.
        let version = if let Some(version) = optional(
            &mut tx,
            "SELECT * FROM app_versions WHERE app_id=$1 AND artifact_id=$2",
            args![app, artifact],
        )
        .await?
        {
            version
        } else {
            let number = n(&current["latest_version"])
                .checked_add(1)
                .ok_or_else(|| conflict("version limit reached"))?;
            let version =
                Self::insert_code(&mut tx, &current, artifact, &inspection, number).await?;
            exec(
                &mut tx,
                "UPDATE apps SET revision=revision+1,latest_version=$1,updated=now() WHERE id=$2",
                args![number, app],
            )
            .await?;
            Self::audit(
                &mut tx,
                p,
                "app.version",
                app,
                tenant,
                json!({"version":number}),
            )
            .await?;
            version
        };
        let op = Self::operation(
            &mut tx,
            tenant,
            project,
            key,
            &request,
            s(&version["id"]),
            "attach-app-version",
        )
        .await?;
        let op = one(
            &mut tx,
            "UPDATE operations SET state='succeeded',updated=now() WHERE id=$1 RETURNING *",
            args![op["id"]],
        )
        .await?;
        tx.commit().await?;
        Ok(op)
    }

    pub async fn app(
        &self,
        p: &Principal,
        tenant: &str,
        project: &str,
        app: &str,
    ) -> Result<Value> {
        let mut tx = self.transaction(false, false).await?;
        Self::project(&mut tx, p, tenant, project, false).await?;
        identity(app)?;
        let mut value = one(
            &mut tx,
            "SELECT a.*,EXISTS(SELECT 1 FROM app_runs r LEFT JOIN executions e ON e.id=r.execution_id WHERE r.app_id=a.id AND (r.admission='pending' OR e.reserved)) AS command_busy,COALESCE((SELECT bool_and(r.source='schedule' AND (r.admission='pending' OR r.admission='admitted' AND e.node_id IS NULL AND e.reserved)) FROM app_runs r LEFT JOIN executions e ON e.id=r.execution_id WHERE r.app_id=a.id AND (r.admission='pending' OR e.reserved)),false) AS scheduled_work_cancellable FROM customer_app_summaries a WHERE tenant_id=$1 AND project_id=$2 AND id=$3",
            args![tenant, project, app],
        )
        .await?;
        Self::summarize_app_connections(&mut tx, tenant, project, std::slice::from_mut(&mut value))
            .await?;
        crate::placement::project(&mut tx, tenant, project, std::slice::from_mut(&mut value))
            .await?;
        crate::app_diagnostics::app(&mut value);
        Ok(value)
    }

    pub async fn apps(
        &self,
        p: &Principal,
        tenant: &str,
        project: &str,
        page: AppPage,
    ) -> Result<Value> {
        let limit = page.limit.unwrap_or(50);
        if !(1..=100).contains(&limit) {
            return Err(Error::invalid("page limit must be between 1 and 100"));
        }
        let search = page.search.unwrap_or_default();
        if search.len() > 128 || search.chars().any(char::is_control) {
            return Err(Error::invalid("invalid app search"));
        }
        let trigger = match page.trigger {
            Some(AppTriggerFilter::Http) => "http",
            Some(AppTriggerFilter::Manual) => "manual",
            Some(AppTriggerFilter::Schedule) => "schedule",
            Some(AppTriggerFilter::None) => "none",
            None => "",
        };
        let status = match page.status {
            Some(AppStatusFilter::Ready) => "ready",
            Some(AppStatusFilter::Stopped) => "stopped",
            None => "",
        };
        let mut tx = self.transaction(false, false).await?;
        Self::project(&mut tx, p, tenant, project, false).await?;
        let cursor = if let Some(before) = page.before {
            identity(&before)?;
            one(
                &mut tx,
                "SELECT id,created FROM apps WHERE tenant_id=$1 AND project_id=$2 AND id=$3",
                args![tenant, project, before],
            )
            .await?
        } else {
            Value::Null
        };
        let counts = one(
            &mut tx,
            include_str!("app_list_counts.sql"),
            args![
                tenant,
                project,
                search,
                trigger,
                status,
                cursor["created"],
                cursor["id"]
            ],
        )
        .await?;
        let mut items = rows(&mut tx,"SELECT a.*,EXISTS(SELECT 1 FROM app_runs r LEFT JOIN executions e ON e.id=r.execution_id WHERE r.app_id=a.id AND (r.admission='pending' OR e.reserved)) AS command_busy,COALESCE((SELECT bool_and(r.source='schedule' AND (r.admission='pending' OR r.admission='admitted' AND e.node_id IS NULL AND e.reserved)) FROM app_runs r LEFT JOIN executions e ON e.id=r.execution_id WHERE r.app_id=a.id AND (r.admission='pending' OR e.reserved)),false) AS scheduled_work_cancellable FROM customer_app_summaries a WHERE tenant_id=$1 AND project_id=$2 AND ($3::timestamptz IS NULL OR (created,id)<($3::timestamptz,$4)) AND position(lower($5) in lower(name))>0 AND CASE WHEN $7='' THEN true WHEN $7='none' THEN NOT (triggers->>'http')::boolean AND NOT (triggers->>'manual')::boolean AND NOT (triggers->>'schedule')::boolean ELSE (triggers->>$7)::boolean END AND ($8='' OR state=$8) ORDER BY created DESC,id DESC LIMIT $6",args![tenant,project,cursor["created"],cursor["id"],search,limit+1,trigger,status]).await?;
        let more = items.len() > limit as usize;
        items.truncate(limit as usize);
        Self::summarize_app_connections(&mut tx, tenant, project, &mut items).await?;
        crate::placement::project(&mut tx, tenant, project, &mut items).await?;
        let next = if more {
            items.last().unwrap()["id"].clone()
        } else {
            Value::Null
        };
        for item in &mut items {
            crate::app_diagnostics::app(item);
        }
        Ok(
            json!({"items":items,"next":next,"summary":counts["summary"],"total":counts["total"],"offset":counts["offset"]}),
        )
    }

    pub async fn app_versions(
        &self,
        p: &Principal,
        tenant: &str,
        project: &str,
        app: &str,
        before: Option<i64>,
    ) -> Result<Value> {
        if before.is_some_and(|v| v < 1) {
            return Err(Error::invalid("version cursor must be positive"));
        }
        let mut tx = self.transaction(false, false).await?;
        Self::project(&mut tx, p, tenant, project, false).await?;
        Self::app_row(&mut tx, tenant, project, app).await?;
        let mut items = rows(&mut tx,&format!("{VERSION_ROW} AND ($4::bigint IS NULL OR v.number<$4::bigint) ORDER BY v.number DESC LIMIT 101"),args![tenant,project,app,before]).await?;
        let more = items.len() > 100;
        items.truncate(100);
        items.iter_mut().for_each(last_release);
        let next = if more {
            items.last().unwrap()["number"].clone()
        } else {
            Value::Null
        };
        Ok(json!({"items":items,"next":next}))
    }

    pub async fn app_version(
        &self,
        p: &Principal,
        tenant: &str,
        project: &str,
        app: &str,
        version: &str,
    ) -> Result<Value> {
        let mut tx = self.transaction(false, false).await?;
        Self::project(&mut tx, p, tenant, project, false).await?;
        Self::app_row(&mut tx, tenant, project, app).await?;
        identity(version)?;
        let mut item = one(
            &mut tx,
            &format!("{VERSION_ROW} AND v.id=$4"),
            args![tenant, project, app, version],
        )
        .await?;
        last_release(&mut item);
        Ok(item)
    }
}

// Each version carries its latest release so deployment outcomes stay visible
// beside the code after lifecycle events age out.
const VERSION_ROW: &str = "SELECT v.*,(SELECT jsonb_build_object('id',r.id,'state',r.state,'reason',r.reason,'created',r.created,'updated',r.updated) FROM app_releases r WHERE r.tenant_id=v.tenant_id AND r.project_id=v.project_id AND r.app_id=v.app_id AND r.version_id=v.id ORDER BY r.created DESC,r.id DESC LIMIT 1) AS last_release FROM app_versions v WHERE v.tenant_id=$1 AND v.project_id=$2 AND v.app_id=$3";
fn last_release(item: &mut Value) {
    if let Some(release) = item.get_mut("last_release") {
        crate::app_diagnostics::decorate(release);
    }
}
