//! Real PostgreSQL tests. Node rows below are protocol fixtures, not VMs.
#[path = "cases/component_diagnostics.rs"]
mod component_diagnostics;
#[path = "cases/contract.rs"]
mod contract;
#[path = "cases/customer_api.rs"]
mod customer_api;
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use fenders_control_plane::{
    api,
    db::{exec, n, s},
    model::*,
    store::Store,
};
use serde_json::{Value, json};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use tower::ServiceExt;

#[path = "cases/accounting_retention.rs"]
mod accounting_retention;
#[path = "cases/agent_upgrade_live.rs"]
mod agent_upgrade_live;
#[path = "cases/app_connections.rs"]
mod app_connections;
#[path = "cases/app_delete.rs"]
mod app_delete;
#[path = "cases/app_deploy.rs"]
mod app_deploy;
#[path = "cases/app_diagnostics.rs"]
mod app_diagnostics;
#[path = "cases/app_events.rs"]
mod app_events;
#[path = "cases/app_http.rs"]
mod app_http;
#[path = "cases/app_https.rs"]
mod app_https;
#[path = "cases/app_logs.rs"]
mod app_logs;
#[path = "cases/app_on_demand.rs"]
mod app_on_demand;
#[path = "cases/app_schedules.rs"]
mod app_schedules;
#[path = "cases/control_plane_rollout.rs"]
mod control_plane_rollout;
#[path = "common/dns.rs"]
mod dns;
#[path = "cases/egress_budget.rs"]
mod egress_budget;
#[path = "cases/execution_input_retention.rs"]
mod execution_input_retention;
#[path = "cases/execution_logs.rs"]
mod execution_logs;
#[path = "cases/http_runs.rs"]
mod http_runs;
#[path = "cases/ingress_admission.rs"]
mod ingress_admission;
#[path = "cases/key_rotation.rs"]
mod key_rotation;
#[path = "cases/placement.rs"]
mod placement;
#[path = "cases/placement_retention.rs"]
mod placement_retention;
#[path = "cases/release_input_retention.rs"]
mod release_input_retention;
#[path = "cases/run_channel.rs"]
mod run_channel;
#[path = "cases/schema_migrations.rs"]
mod schema_migrations;
#[path = "cases/supervision.rs"]
mod supervision;
#[path = "cases/usage.rs"]
mod usage;
#[path = "cases/workspace_lifecycle.rs"]
mod workspace_lifecycle;

struct Lab {
    store: Store,
    root: tempfile::TempDir,
    schema: String,
    admin: sqlx::PgPool,
    operator: Principal,
    token: String,
    tenant: String,
    project: String,
    artifact: String,
}
impl Lab {
    async fn new() -> Self {
        let dsn = std::env::var("FENDERS_TEST_DATABASE_URL")
            .expect("set FENDERS_TEST_DATABASE_URL to a dedicated PostgreSQL database");
        Self::with_options(dsn.parse().unwrap()).await
    }
    async fn with_options(options: PgConnectOptions) -> Self {
        let admin = PgPoolOptions::new()
            .connect_with(options.clone())
            .await
            .unwrap();
        let schema = format!("rust_test_{}", uid());
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&admin)
            .await
            .unwrap();
        let pool = PgPoolOptions::new()
            .max_connections(16)
            .connect_with(options.options([("search_path", schema.as_str())]))
            .await
            .unwrap();
        let root = tempfile::tempdir().unwrap();
        let store = Store::from_pool(pool, root.path()).unwrap();
        store.migrate().await.unwrap();
        let token = std::fs::read_to_string(store.bootstrap().await.unwrap()).unwrap();
        let operator = store.authenticate(&token).await.unwrap();
        let t=store.create_tenant(&operator,serde_json::from_value(json!({"name":"alpha","allowance":{"cpu_percent":400,"memory_mib":4096,"instances":4,"storage_bytes":20000000000i64,"transfer_bytes":10000000}})).unwrap()).await.unwrap();
        let tenant = s(&t["id"]).to_owned();
        let p = store
            .create_project(
                &operator,
                &tenant,
                serde_json::from_value(json!({"name":"app"})).unwrap(),
            )
            .await
            .unwrap();
        let project = s(&p["id"]).to_owned();
        let a = store
            .upload(&operator, &tenant, &project, b"\0asm\x0d\0\x01\0")
            .await
            .unwrap();
        let artifact = s(&a["id"]).to_owned();
        Self {
            store,
            root,
            schema,
            admin,
            operator,
            token,
            tenant,
            project,
            artifact,
        }
    }
    async fn finish(self) {
        self.store.pool.close().await;
        sqlx::query(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .execute(&self.admin)
            .await
            .unwrap();
        self.admin.close().await;
    }
    /// A key for the lab's tenant, named as tests have always asked for
    /// one: a "viewer" reads, anything else also changes what its scope
    /// lets it. There are no roles; these are permissions.
    async fn credential(&self, role: &str, project: Option<&str>) -> (Principal, Value) {
        let mut permissions = vec!["read"];
        if role != "viewer" {
            permissions.extend([
                "apps:write",
                "runs:write",
                "connections:write",
                "secrets:write",
            ]);
            if project.is_none() {
                permissions.push("projects:write");
            }
        }
        let v = self
            .store
            .create_api_key(
                &self.operator,
                &self.tenant,
                serde_json::from_value(json!({"name":"test","project_id":project,"permissions":permissions,"ttl_seconds":86400})).unwrap(),
                &uid(),
            )
            .await
            .unwrap();
        (self.store.authenticate(s(&v["token"])).await.unwrap(), v)
    }
    /// Says of the lab's component what a node says once it has inspected
    /// it, for tests that are not about inspection.
    async fn validated(&self) {
        // No node inspected it: the one rule a fixture's row cannot keep.
        sqlx::query("ALTER TABLE artifact_validations DROP CONSTRAINT IF EXISTS artifact_validations_check2")
            .execute(&self.store.pool)
            .await
            .unwrap();
        sqlx::query("UPDATE artifact_validations v SET state='valid',lease_until=NULL,updated=now(),inspection=jsonb_build_object('format_version',1,'runtime',$2::text,'digest',a.digest,'bytes',a.size,'http',true,'command',true,'imports','[]'::jsonb,'exports','[]'::jsonb) FROM artifacts a WHERE a.id=v.artifact_id AND a.id=$1 AND v.state<>'valid'")
            .bind(&self.artifact)
            .bind(fenders_control_plane::artifacts::RUNTIME)
            .execute(&self.store.pool)
            .await
            .unwrap();
    }
    /// An app of the lab's component that runs on request, ready to.
    async fn command_app(&self) -> String {
        self.configured_app(json!({})).await
    }
    /// The same, with the environment and secrets its runs are given.
    async fn configured_app(&self, configuration: Value) -> String {
        self.try_configured_app(configuration).await.unwrap()
    }
    async fn try_configured_app(
        &self,
        configuration: Value,
    ) -> fenders_control_plane::error::Result<String> {
        self.validated().await;
        let name = format!("run-{}", &uid()[..12]);
        let (app, version) = define_app(self, &name).await;
        self.store
            .update_app_triggers(
                &self.operator,
                &self.tenant,
                &self.project,
                &app,
                json!({"manual":true,"expected_revision":1}),
                &uid(),
            )
            .await
            .unwrap();
        self.store
            .activate_app_release(
                &self.operator,
                &self.tenant,
                &self.project,
                &app,
                json!({"version_id":version,"expected_revision":1,"configuration":configuration}),
                &uid(),
            )
            .await?;
        Ok(app)
    }
    /// An app with a URL, deployed as a tenant deploys one. Answers with its
    /// id and hostname; its execution is `web_execution` once scheduled.
    async fn web_app(&self, name: &str, domain: &str) -> Value {
        self.validated().await;
        let op = self
            .store
            .deploy_app(
                &self.operator,
                &self.tenant,
                &self.project,
                fenders_control_plane::apps::AppSubmission {
                    value: json!({"name":name,"artifact_id":self.artifact,"triggers":{"manual":false,"http":true}}),
                    key: &uid(),
                    domain,
                },
            )
            .await
            .unwrap();
        let app = s(&op["resource_id"]).to_owned();
        let hostname = fenders_control_plane::app_http::hostname(&app, domain).unwrap();
        json!({"app_id":app,"hostname":hostname})
    }
    async fn web_execution(&self, web: &Value) -> Value {
        let status = self
            .store
            .app_http_status(
                &self.operator,
                &self.tenant,
                &self.project,
                s(&web["app_id"]),
            )
            .await
            .unwrap();
        self.run(&json!({"resource_id":status["execution_id"]}))
            .await
    }
    /// A run, started as a tenant starts one: of an app, on request. What a
    /// test of the engine beneath the apps begins from. `resource_id` is
    /// the run's execution.
    async fn start_app(&self, app: &str, key: &str) -> fenders_control_plane::error::Result<Value> {
        let op = self
            .store
            .run_app(&self.operator, &self.tenant, &self.project, app, key)
            .await?;
        let run = self
            .store
            .app_run(
                &self.operator,
                &self.tenant,
                &self.project,
                app,
                s(&op["resource_id"]),
            )
            .await?;
        Ok(json!({"resource_id":run["execution_id"],"run_id":run["id"],"app_id":app}))
    }
    /// `spec` names the lab's component and, at most, the environment and
    /// secrets of the app made for the run.
    async fn create(&self, key: &str, mut spec: Value) -> Value {
        let given = spec.as_object_mut().unwrap();
        assert_eq!(given.remove("artifact_id"), Some(json!(self.artifact)));
        let app = self.configured_app(spec).await;
        self.start_app(&app, key).await.unwrap()
    }
    /// Stops a run through its app, as a tenant does, by its execution.
    async fn stop(
        &self,
        execution: &str,
        key: &str,
    ) -> fenders_control_plane::error::Result<Value> {
        let (app, run): (String, String) =
            sqlx::query_as("SELECT app_id,id FROM customer_app_runs WHERE execution_id=$1")
                .bind(execution)
                .fetch_one(&self.store.pool)
                .await
                .unwrap();
        self.store
            .cancel_app_run(&self.operator, &self.tenant, &self.project, &app, &run, key)
            .await
    }
    async fn run(&self, op: &Value) -> Value {
        self.store
            .resources(
                &self.operator,
                &self.tenant,
                &self.project,
                "executions",
                Some(s(&op["resource_id"])),
            )
            .await
            .unwrap()
    }
    async fn node(&self, name: &str) -> Value {
        let node=self.store.register_node(&self.operator,json!({"name":name,"cert_sha256":digest(name),"endpoint":"https://node.example:9443","backend":"wasm","architecture":"x86_64","runtime":"wasmtime-50.0.0-fenders-v1","cpu_percent":100,"memory_mib":128,"instances":1})).await.unwrap();
        self.store
            .heartbeat(
                s(&node["id"]),
                json!({"boot_id":"test-boot","reports":[],"confinement":HOST_CONFINEMENT}),
            )
            .await
            .unwrap();
        node
    }
    async fn report(&self, node: &Value, e: &Value, state: &str, sequence: i64) {
        self.store.heartbeat(s(&node["id"]),json!({"boot_id":"test-boot","confinement":HOST_CONFINEMENT,"reports":[{"id":e["id"],"generation":e["generation"],"state":state,"sequence":sequence,"cpu_usec":12,"memory_bytes":512}]})).await.unwrap();
    }
}

#[tokio::test]
async fn tenant_credentials_roles_and_http_boundaries() {
    let l = Lab::new().await;
    let (viewer, credential) = l.credential("viewer", Some(&l.project)).await;
    assert_eq!(
        l.store
            .create_project(
                &viewer,
                &l.tenant,
                serde_json::from_value(json!({"name":"no"})).unwrap()
            )
            .await
            .unwrap_err()
            .status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        l.store
            .upload(&viewer, &l.tenant, &l.project, b"\0asm\x0d\0\x01\0")
            .await
            .unwrap_err()
            .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        l.store.projects(&viewer, &uid()).await.unwrap_err().status,
        StatusCode::NOT_FOUND
    );
    assert!(l.store.api_keys(&viewer, &l.tenant).await.is_err());
    let app = api::router(l.store.clone());
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/workspaces")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/me")
                .header(
                    "Authorization",
                    format!("Bearer {}", s(&credential["token"])),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let me: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(me["project_id"], l.project);
    l.store
        .revoke_credential(&l.operator, &l.tenant, s(&credential["id"]))
        .await
        .unwrap();
    assert_eq!(
        l.store
            .authenticate(s(&credential["token"]))
            .await
            .unwrap_err()
            .status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        l.store.authenticate(&l.token).await.unwrap().role,
        Role::Operator
    );
    l.finish().await;
}

#[tokio::test]
async fn concurrent_quota_and_idempotency() {
    let l = Lab::new().await;
    let app = l.command_app().await;
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..12 {
        let (st, p, t, project, app) = (
            l.store.clone(),
            l.operator.clone(),
            l.tenant.clone(),
            l.project.clone(),
            app.clone(),
        );
        tasks.spawn(async move { st.run_app(&p, &t, &project, &app, "same").await.unwrap() });
    }
    let mut ids = std::collections::BTreeSet::new();
    while let Some(v) = tasks.join_next().await {
        ids.insert(s(&v.unwrap()["id"]).to_owned());
    }
    assert_eq!(ids.len(), 1);
    // The same request made of another app is another request's key.
    let other = l.command_app().await;
    assert_eq!(
        l.store
            .run_app(&l.operator, &l.tenant, &l.project, &other, "same")
            .await
            .unwrap_err()
            .status,
        StatusCode::CONFLICT
    );
    // An app runs once at a time: ten apps, started together.
    for index in 0..10 {
        let app = l.command_app().await;
        let (st, p, t, project) = (
            l.store.clone(),
            l.operator.clone(),
            l.tenant.clone(),
            l.project.clone(),
        );
        tasks.spawn(async move {
            match st
                .run_app(&p, &t, &project, &app, &format!("run-{index}"))
                .await
            {
                Ok(v) => v,
                Err(e) => {
                    assert_eq!(e.status, StatusCode::TOO_MANY_REQUESTS);
                    Value::Null
                }
            }
        });
    }
    let mut admitted = 0;
    while let Some(v) = tasks.join_next().await {
        if !v.unwrap().is_null() {
            admitted += 1
        }
    }
    // Four at once is the tenant's allowance; one is running already.
    assert_eq!(admitted, 3);
    let usage = l.store.usage(&l.operator, &l.tenant, None).await.unwrap();
    assert_eq!(usage["reserved"]["instances"], 4);
    l.finish().await;
}

#[tokio::test]
async fn secret_delivery_generation_fencing_and_confinement() {
    let l = Lab::new().await;
    let node = l.node("node-a").await;
    let other = l.node("node-b").await;
    let secret = l
        .store
        .create_secret(
            &l.operator,
            &l.tenant,
            &l.project,
            json!({"name":"password","value":"sensitive-fixture"}),
        )
        .await
        .unwrap();
    let op = l
        .create(
            "secret",
            json!({"artifact_id":l.artifact,"secret_env":{"PASSWORD":secret["id"]}}),
        )
        .await;
    l.store.schedule().await.unwrap();
    let e = l.run(&op).await;
    let own = if e["node_id"] == node["id"] {
        &node
    } else {
        &other
    };
    let wrong = if e["node_id"] == node["id"] {
        &other
    } else {
        &node
    };
    let assignment = l
        .store
        .assignment(s(&own["id"]), s(&e["id"]), n(&e["generation"]))
        .await
        .unwrap();
    assert_eq!(assignment["spec"]["env"]["PASSWORD"], "sensitive-fixture");
    assert_eq!(
        l.store
            .assignment(s(&wrong["id"]), s(&e["id"]), 1)
            .await
            .unwrap_err()
            .status,
        StatusCode::CONFLICT
    );
    assert_eq!(
        l.store
            .assigned_artifact(s(&own["id"]), s(&e["id"]), 1)
            .await
            .unwrap(),
        b"\0asm\x0d\0\x01\0"
    );
    l.report(own, &e, "running", 1).await;
    l.stop(s(&e["id"]), "stop").await.unwrap();
    let stopped = l
        .store
        .assignment(s(&own["id"]), s(&e["id"]), 2)
        .await
        .unwrap();
    assert!(stopped["spec"].is_null());
    assert!(stopped["artifact"].is_null());
    let ciphertext = std::fs::read(l.root.path().join("encryption.key")).unwrap();
    assert!(!ciphertext.windows(17).any(|b| b == b"sensitive-fixture"));
    l.finish().await;
}

#[tokio::test]
async fn ingress_budget_and_recovery_barrier() {
    let l = Lab::new().await;
    let node = l.node("node-a").await;
    let route = l.web_app("web", "apps.test").await;
    assert!(
        l.store
            .ingress_start(s(&route["hostname"]), 0)
            .await
            .is_err()
    );
    l.store.schedule().await.unwrap();
    let serving = l.web_execution(&route).await;
    l.report(&node, &serving, "running", 1).await;
    let (_, lease) = l
        .store
        .ingress_start(s(&route["hostname"]), 4)
        .await
        .unwrap();
    l.store.ingress_finish(&lease, Some(100)).await.unwrap();
    l.store.ingress_finish(&lease, Some(100)).await.unwrap();
    assert_eq!(
        l.store.usage(&l.operator, &l.tenant, None).await.unwrap()["ingress_month"]["bytes"],
        100
    );
    l.store
        .heartbeat(s(&node["id"]), json!({"boot_id":"test-boot","reports":[]}))
        .await
        .unwrap();
    assert_eq!(
        l.store
            .ingress_start(s(&route["hostname"]), 0)
            .await
            .unwrap_err()
            .status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    let mut tx = l.store.transaction(true, false).await.unwrap();
    exec(
        &mut tx,
        "UPDATE recovery_barrier SET active=true WHERE singleton",
        &[],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        l.store
            .create_project(
                &l.operator,
                &l.tenant,
                serde_json::from_value(json!({"name":"blocked"})).unwrap()
            )
            .await
            .unwrap_err()
            .status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(l.store.tenants(&l.operator).await.is_ok());
    l.finish().await;
}

#[tokio::test]
async fn customer_projects_settings_and_authorization() {
    let l = Lab::new().await;
    // Every permission a key can hold, over the whole workspace.
    let (owner, _) = l.credential("owner", None).await;
    let (editor, _) = l.credential("editor", None).await;
    let (viewer, _) = l.credential("viewer", None).await;
    let (scoped, _) = l.credential("editor", Some(&l.project)).await;
    let projects = l.store.projects(&owner, &l.tenant).await.unwrap();
    let defaults: Vec<_> = projects
        .as_array()
        .unwrap()
        .iter()
        .filter(|p| p["is_default"] == true)
        .collect();
    assert_eq!(defaults.len(), 1);
    assert_eq!(defaults[0]["name"], "Production");
    assert_eq!(defaults[0]["slug"], "production");
    let input = || serde_json::from_value(json!({"name":"  Staging EU  "})).unwrap();
    let (a, b) = tokio::join!(
        l.store.create_project(&editor, &l.tenant, input()),
        l.store.create_project(&editor, &l.tenant, input())
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    let created = a.or(b).unwrap();
    // The name is the one given, trimmed; the slug is made of it.
    assert_eq!(created["name"], "Staging EU");
    assert_eq!(created["slug"], "staging-eu");
    for duplicate in ["staging eu", "Staging-EU", "PRODUCTION"] {
        assert_eq!(
            l.store
                .create_project(
                    &owner,
                    &l.tenant,
                    serde_json::from_value(json!({"name":duplicate})).unwrap()
                )
                .await
                .unwrap_err()
                .status,
            StatusCode::CONFLICT
        );
    }
    for invalid in [" ", "a", "你好", "Stage\nEU"] {
        assert_eq!(
            l.store
                .create_project(
                    &owner,
                    &l.tenant,
                    serde_json::from_value(json!({"name":invalid})).unwrap()
                )
                .await
                .unwrap_err()
                .status,
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(
        l.store
            .create_project(&scoped, &l.tenant, input())
            .await
            .unwrap_err()
            .status,
        StatusCode::NOT_FOUND
    );
    // The size a tenant's apps take by default is the operator's to set,
    // beside the allowance; a key reads it and sets nothing of the kind.
    let size = |size: &str| -> fenders_control_plane::model::UpdateAllowance {
        serde_json::from_value(json!({"default_app_size":size})).unwrap()
    };
    for key in [&owner, &editor, &viewer] {
        assert_eq!(
            l.store
                .update_allowance(key, &l.tenant, size("medium"))
                .await
                .unwrap_err()
                .status,
            StatusCode::FORBIDDEN
        );
    }
    let patch = |token: String, body: Value| {
        api::router(l.store.clone()).oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/v1/workspaces/{}", l.tenant))
                .header("Authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
    };
    for (body, expected) in [
        (json!({"default_app_size":"medium"}), StatusCode::OK),
        (json!({"default_app_size":"huge"}), StatusCode::BAD_REQUEST),
        (json!({}), StatusCode::BAD_REQUEST),
    ] {
        let response = patch(l.token.clone(), body.clone()).await.unwrap();
        assert_eq!(response.status(), expected, "{body}");
    }
    assert_eq!(
        l.store
            .app_sizes(&viewer, &l.tenant, &l.project)
            .await
            .unwrap()["default_size"],
        "medium"
    );
    // There are no workspace settings to read or write, for anyone.
    for method in ["GET", "PATCH"] {
        let response = api::router(l.store.clone())
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(format!("/v1/workspaces/{}/settings", l.tenant))
                    .header("Authorization", format!("Bearer {}", l.token))
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{method}");
    }
    // Reopen the store against the same database and encrypted state.
    let reopened = Store::from_pool(l.store.pool.clone(), l.root.path()).unwrap();
    reopened.migrate().await.unwrap();
    assert_eq!(
        reopened
            .app_sizes(&viewer, &l.tenant, &l.project)
            .await
            .unwrap()["default_size"],
        "medium"
    );
    assert_eq!(
        reopened
            .projects(&owner, &l.tenant)
            .await
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        3
    );
    assert_eq!(
        reopened
            .projects(&scoped, &l.tenant)
            .await
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        1
    );
    sqlx::query("UPDATE recovery_barrier SET active=true")
        .execute(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(
        l.store
            .create_project(&owner, &l.tenant, input())
            .await
            .unwrap_err()
            .status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        l.store
            .update_allowance(&l.operator, &l.tenant, size("large"))
            .await
            .unwrap_err()
            .status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    l.finish().await;
}

// Protocol receipts are deliberately synthetic here. The fenders-component
// suite tests actual imports/exports; these cases test the PostgreSQL authority.
fn inspection_receipt(job: &Value) -> Value {
    json!({"format_version":1,"runtime":fenders_control_plane::artifacts::RUNTIME,"digest":job["digest"],"bytes":job["size"],"http":true,"command":true,"imports":[],"exports":[]})
}

async fn approve_component(l: &Lab, node: &Value, http: bool, command: bool) -> Value {
    let job = l
        .store
        .claim_component(s(&node["id"]), json!({"boot_id":"test-boot"}))
        .await
        .unwrap()["job"]
        .clone();
    let mut receipt = inspection_receipt(&job);
    receipt["http"] = json!(http);
    receipt["command"] = json!(command);
    l.store
        .component_result(
            s(&node["id"]),
            s(&job["artifact_id"]),
            n(&job["generation"]),
            json!({"boot_id":"test-boot","inspection":receipt}),
        )
        .await
        .unwrap();
    job
}

async fn define_app(l: &Lab, name: &str) -> (String, String) {
    let op = l
        .store
        .create_app(
            &l.operator,
            &l.tenant,
            &l.project,
            json!({"name":name,"artifact_id":l.artifact}),
            &format!("define-{name}"),
        )
        .await
        .unwrap();
    let app = s(&op["resource_id"]).to_owned();
    let versions = l
        .store
        .app_versions(&l.operator, &l.tenant, &l.project, &app, None)
        .await
        .unwrap();
    (app, s(&versions["items"][0]["id"]).to_owned())
}

#[tokio::test]
async fn app_manual_runs_require_explicit_events_and_track_observed_outcomes() {
    use fenders_control_plane::app_runtime::HistoryPage;
    let l = Lab::new().await;
    let node = l.node("worker").await;
    approve_component(&l, &node, true, true).await;
    let (app, version) = define_app(&l, "manual-app").await;
    let (editor, credential) = l.credential("editor", Some(&l.project)).await;
    let (viewer, _) = l.credential("viewer", Some(&l.project)).await;
    assert_eq!(
        l.store
            .run_app(&editor, &l.tenant, &l.project, &app, "early")
            .await
            .unwrap_err()
            .status,
        StatusCode::CONFLICT
    );
    l.store
        .update_app_triggers(
            &editor,
            &l.tenant,
            &l.project,
            &app,
            json!({"manual":true,"expected_revision":1}),
            "manual-on",
        )
        .await
        .unwrap();
    let activation = || json!({"version_id":version,"expected_revision":1});
    let release_op = l
        .store
        .activate_app_release(
            &editor,
            &l.tenant,
            &l.project,
            &app,
            activation(),
            "activate",
        )
        .await
        .unwrap();
    assert_eq!(
        l.store
            .activate_app_release(
                &editor,
                &l.tenant,
                &l.project,
                &app,
                activation(),
                "activate"
            )
            .await
            .unwrap(),
        release_op
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM executions")
            .fetch_one(&l.store.pool)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        l.store
            .app(&viewer, &l.tenant, &l.project, &app)
            .await
            .unwrap()["desired"],
        "enabled"
    );
    assert_eq!(
        l.store
            .run_app(&viewer, &l.tenant, &l.project, &app, "viewer")
            .await
            .unwrap_err()
            .status,
        StatusCode::FORBIDDEN
    );
    let response = api::router(l.store.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/v1/workspaces/{}/projects/{}/apps/{app}/runs",
                    l.tenant, l.project
                ))
                .header(
                    "Authorization",
                    format!("Bearer {}", s(&credential["token"])),
                )
                .header("Idempotency-Key", "run-once")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let op: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 8192).await.unwrap()).unwrap();
    let (a, b) = tokio::join!(
        l.store
            .run_app(&editor, &l.tenant, &l.project, &app, "run-once"),
        l.store
            .run_app(&editor, &l.tenant, &l.project, &app, "run-once")
    );
    // The API shows of an operation what was asked and how it stands; the
    // store's own row has the request's key and hash besides. They are the
    // same operation.
    for retried in [a.unwrap(), b.unwrap()] {
        for shown in ["id", "kind", "resource_id", "state", "created"] {
            assert_eq!(retried[shown], op[shown], "{shown}");
        }
        assert_eq!(retried["request_key"], "run-once");
    }
    assert!(op.get("request_key").is_none() && op.get("request_hash").is_none());
    let run = s(&op["resource_id"]);
    let observed = l
        .store
        .app_run(&viewer, &l.tenant, &l.project, &app, run)
        .await
        .unwrap();
    assert_eq!(observed["state"], "queued");
    assert_eq!(observed["release_id"], release_op["resource_id"]);
    assert_eq!(
        l.store
            .usage(&viewer, &l.tenant, Some(&l.project))
            .await
            .unwrap()["reserved"],
        json!({"cpu_percent":25,"memory_mib":88,"instances":1})
    );
    assert_eq!(
        l.store
            .run_app(&editor, &l.tenant, &l.project, &app, "another-event")
            .await
            .unwrap_err()
            .status,
        StatusCode::CONFLICT
    );
    assert_eq!(
        l.store
            .app_lifecycle(
                &editor,
                &l.tenant,
                &l.project,
                &app,
                json!({"desired":"stopped","expected_revision":2}),
                "stop-busy"
            )
            .await
            .unwrap_err()
            .status,
        StatusCode::CONFLICT
    );
    assert_eq!(
        l.store
            .update_app_triggers(
                &editor,
                &l.tenant,
                &l.project,
                &app,
                json!({"manual":false,"expected_revision":2}),
                "edit-busy"
            )
            .await
            .unwrap_err()
            .status,
        StatusCode::CONFLICT
    );
    assert_eq!(
        l.store
            .activate_app_release(
                &editor,
                &l.tenant,
                &l.project,
                &app,
                json!({"version_id":version,"expected_revision":2}),
                "release-busy"
            )
            .await
            .unwrap_err()
            .status,
        StatusCode::CONFLICT
    );
    l.store.schedule().await.unwrap();
    let execution = l
        .store
        .resources(
            &l.operator,
            &l.tenant,
            &l.project,
            "executions",
            Some(s(&observed["execution_id"])),
        )
        .await
        .unwrap();
    l.report(&node, &execution, "running", 1).await;
    let started = l
        .store
        .app_run(&viewer, &l.tenant, &l.project, &app, run)
        .await
        .unwrap();
    assert_eq!(started["state"], "running");
    assert!(!started["started_at"].is_null());
    l.store.heartbeat(s(&node["id"]),json!({"boot_id":"test-boot","reports":[{"id":execution["id"],"generation":execution["generation"],"state":"exited","sequence":2,"cpu_usec":100,"memory_bytes":1000,"exit_code":7}],"confinement":HOST_CONFINEMENT})).await.unwrap();
    let ended = l
        .store
        .app_run(&viewer, &l.tenant, &l.project, &app, run)
        .await
        .unwrap();
    assert_eq!(ended["state"], "failed");
    assert_eq!(ended["exit_code"], 7);
    assert_eq!(ended["started_at"], started["started_at"]);
    assert!(!ended["finished_at"].is_null());
    let retried = l
        .store
        .run_app(&editor, &l.tenant, &l.project, &app, "run-once")
        .await
        .unwrap();
    assert_eq!(retried["id"], op["id"]);
    assert_eq!(retried["state"], "failed");
    let next = l
        .store
        .run_app(&editor, &l.tenant, &l.project, &app, "explicit-second-run")
        .await
        .unwrap();
    l.store.schedule().await.unwrap();
    let second = l
        .store
        .app_run(
            &viewer,
            &l.tenant,
            &l.project,
            &app,
            s(&next["resource_id"]),
        )
        .await
        .unwrap();
    l.store.heartbeat(s(&node["id"]),json!({"boot_id":"test-boot","reports":[{"id":second["execution_id"],"generation":1,"state":"exited","sequence":1,"cpu_usec":10,"memory_bytes":512,"exit_code":0}],"confinement":HOST_CONFINEMENT})).await.unwrap();
    assert_eq!(
        l.store
            .app_run(
                &viewer,
                &l.tenant,
                &l.project,
                &app,
                s(&next["resource_id"])
            )
            .await
            .unwrap()["state"],
        "succeeded"
    );
    assert_eq!(
        l.store
            .run_app(&editor, &l.tenant, &l.project, &app, "explicit-second-run")
            .await
            .unwrap()["state"],
        "succeeded"
    );
    let page = l
        .store
        .app_history(
            &viewer,
            &l.tenant,
            &l.project,
            &app,
            "runs",
            HistoryPage {
                trigger: None,
                limit: Some(1),
                before: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(page["items"][0]["id"], next["resource_id"]);
    let page = l
        .store
        .app_history(
            &viewer,
            &l.tenant,
            &l.project,
            &app,
            "runs",
            HistoryPage {
                trigger: None,
                limit: Some(1),
                before: Some(s(&page["next"]).into()),
            },
        )
        .await
        .unwrap();
    assert_eq!(page["items"][0]["id"], op["resource_id"]);
    assert!(page["next"].is_null());
    l.store
        .app_lifecycle(
            &editor,
            &l.tenant,
            &l.project,
            &app,
            json!({"desired":"stopped","expected_revision":2}),
            "stop",
        )
        .await
        .unwrap();
    assert_eq!(
        l.store
            .app_triggers(&viewer, &l.tenant, &l.project, &app)
            .await
            .unwrap()["manual"],
        true
    );
    assert_eq!(
        l.store
            .run_app(&editor, &l.tenant, &l.project, &app, "while-stopped")
            .await
            .unwrap_err()
            .status,
        StatusCode::CONFLICT
    );
    assert_eq!(
        l.store
            .run_app(&editor, &l.tenant, &l.project, &app, "run-once")
            .await
            .unwrap()["id"],
        op["id"]
    );
    l.store
        .app_lifecycle(
            &editor,
            &l.tenant,
            &l.project,
            &app,
            json!({"desired":"enabled","expected_revision":3}),
            "start",
        )
        .await
        .unwrap();
    l.store
        .update_app_triggers(
            &editor,
            &l.tenant,
            &l.project,
            &app,
            json!({"manual":false,"expected_revision":2}),
            "manual-off",
        )
        .await
        .unwrap();
    assert_eq!(
        l.store
            .run_app(&editor, &l.tenant, &l.project, &app, "disabled")
            .await
            .unwrap_err()
            .status,
        StatusCode::CONFLICT
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM executions")
            .fetch_one(&l.store.pool)
            .await
            .unwrap(),
        2
    );
    l.finish().await;
}

#[tokio::test]
async fn app_run_admission_shares_quota_and_retains_uncertain_reservations() {
    let l = Lab::new().await;
    let node = l.node("worker").await;
    approve_component(&l, &node, false, true).await;
    let mut apps = Vec::new();
    for name in ["first-app", "second-app"] {
        let (app, version) = define_app(&l, name).await;
        l.store
            .update_app_triggers(
                &l.operator,
                &l.tenant,
                &l.project,
                &app,
                json!({"manual":true,"expected_revision":1}),
                &format!("triggers-{name}"),
            )
            .await
            .unwrap();
        l.store
            .activate_app_release(
                &l.operator,
                &l.tenant,
                &l.project,
                &app,
                json!({"version_id":version,"expected_revision":1}),
                &format!("release-{name}"),
            )
            .await
            .unwrap();
        apps.push(app);
    }
    l.store.update_allowance(&l.operator,&l.tenant,serde_json::from_value(json!({"allowance":{"cpu_percent":100,"memory_mib":1024,"instances":1,"storage_bytes":1000000,"transfer_bytes":1000000}})).unwrap()).await.unwrap();
    let (a, b) = tokio::join!(
        l.store
            .run_app(&l.operator, &l.tenant, &l.project, &apps[0], "event-a"),
        l.store
            .run_app(&l.operator, &l.tenant, &l.project, &apps[1], "event-b")
    );
    let (app, other, op, key) = match (a, b) {
        (Ok(op), Err(error)) => {
            assert_eq!(error.status, StatusCode::TOO_MANY_REQUESTS);
            (&apps[0], &apps[1], op, "event-a")
        }
        (Err(error), Ok(op)) => {
            assert_eq!(error.status, StatusCode::TOO_MANY_REQUESTS);
            (&apps[1], &apps[0], op, "event-b")
        }
        other => panic!("expected one quota admission: {other:?}"),
    };
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM app_runs")
            .fetch_one(&l.store.pool)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM operations WHERE kind='run-app'")
            .fetch_one(&l.store.pool)
            .await
            .unwrap(),
        1
    );
    l.store.schedule().await.unwrap();
    let run = l
        .store
        .app_run(
            &l.operator,
            &l.tenant,
            &l.project,
            app,
            s(&op["resource_id"]),
        )
        .await
        .unwrap();
    let execution = l
        .store
        .resources(
            &l.operator,
            &l.tenant,
            &l.project,
            "executions",
            Some(s(&run["execution_id"])),
        )
        .await
        .unwrap();
    l.report(&node, &execution, "running", 1).await;
    sqlx::query("UPDATE nodes SET last_seen=now()-interval '1 minute'")
        .execute(&l.store.pool)
        .await
        .unwrap();
    l.store.schedule().await.unwrap();
    let unknown = l
        .store
        .app_run(
            &l.operator,
            &l.tenant,
            &l.project,
            app,
            s(&op["resource_id"]),
        )
        .await
        .unwrap();
    assert_eq!(unknown["state"], "unknown");
    assert_eq!(unknown["reserved"], true);
    assert!(unknown["finished_at"].is_null());
    assert_eq!(
        l.store
            .run_app(&l.operator, &l.tenant, &l.project, app, key)
            .await
            .unwrap()["id"],
        op["id"]
    );
    assert_eq!(
        l.store
            .run_app(&l.operator, &l.tenant, &l.project, app, "duplicate-work")
            .await
            .unwrap_err()
            .status,
        StatusCode::CONFLICT
    );
    assert_eq!(
        l.store
            .run_app(&l.operator, &l.tenant, &l.project, other, "over-quota")
            .await
            .unwrap_err()
            .status,
        StatusCode::TOO_MANY_REQUESTS
    );
    // A stale generation cannot complete the run or release its reservation.
    l.store.heartbeat(s(&node["id"]),json!({"boot_id":"test-boot","reports":[{"id":execution["id"],"generation":2,"state":"exited","sequence":2,"cpu_usec":12,"memory_bytes":512,"exit_code":0}],"confinement":HOST_CONFINEMENT})).await.unwrap();
    assert_eq!(
        l.store
            .app_run(
                &l.operator,
                &l.tenant,
                &l.project,
                app,
                s(&op["resource_id"])
            )
            .await
            .unwrap()["reserved"],
        true
    );
    // Terminal without an exit result remains unknown, not invented success.
    l.report(&node, &execution, "exited", 2).await;
    let ended = l
        .store
        .app_run(
            &l.operator,
            &l.tenant,
            &l.project,
            app,
            s(&op["resource_id"]),
        )
        .await
        .unwrap();
    assert_eq!(ended["state"], "unknown");
    assert_eq!(ended["reserved"], false);
    assert_eq!(
        l.store
            .run_app(&l.operator, &l.tenant, &l.project, app, key)
            .await
            .unwrap()["error"],
        "outcome-unknown"
    );
    let admitted = l
        .store
        .run_app(&l.operator, &l.tenant, &l.project, other, "after-release")
        .await
        .unwrap();
    assert_eq!(admitted["state"], "pending");
    sqlx::query("UPDATE recovery_barrier SET active=true")
        .execute(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(
        l.store
            .run_app(&l.operator, &l.tenant, &l.project, app, "restored")
            .await
            .unwrap_err()
            .status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    l.finish().await;
}

#[tokio::test]
async fn app_release_rollback_uses_current_configuration_and_enforces_scope() {
    use fenders_control_plane::app_runtime::HistoryPage;
    let l = Lab::new().await;
    let node = l.node("worker").await;
    approve_component(&l, &node, false, true).await;
    let (app, v1) = define_app(&l, "rollback-app").await;
    // Existing creation requests retain their fingerprint across this migration.
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT request_hash FROM operations WHERE resource_id=$1 AND kind='create-app'"
        )
        .bind(&app)
        .fetch_one(&l.store.pool)
        .await
        .unwrap(),
        fingerprint(&json!({"kind":"create-app","name":"rollback-app","artifact_id":l.artifact}))
    );
    let secret1 = l
        .store
        .create_secret(
            &l.operator,
            &l.tenant,
            &l.project,
            json!({"name":"old-token","value":"private-old-token"}),
        )
        .await
        .unwrap();
    let secret2 = l
        .store
        .create_secret(
            &l.operator,
            &l.tenant,
            &l.project,
            json!({"name":"new-token","value":"private-new-token"}),
        )
        .await
        .unwrap();
    let old = json!({"size":"medium","env":{"MODE":"old"},"secret_env":{"TOKEN":secret1["id"]}});
    let current =
        json!({"size":"small","env":{"MODE":"current"},"secret_env":{"TOKEN":secret2["id"]}});
    let first = l
        .store
        .activate_app_release(
            &l.operator,
            &l.tenant,
            &l.project,
            &app,
            json!({"version_id":v1,"expected_revision":1,"configuration":old}),
            "release-v1",
        )
        .await
        .unwrap();
    let new = l
        .store
        .upload(
            &l.operator,
            &l.tenant,
            &l.project,
            b"\0asm\x0d\0\x01\0version2",
        )
        .await
        .unwrap();
    approve_component(&l, &node, false, true).await;
    let version2 = l
        .store
        .attach_app_version(
            &l.operator,
            &l.tenant,
            &l.project,
            &app,
            json!({"artifact_id":new["id"],"expected_revision":2}),
            "version-2",
        )
        .await
        .unwrap();
    l.store.activate_app_release(&l.operator,&l.tenant,&l.project,&app,json!({"version_id":version2["resource_id"],"expected_revision":3,"configuration":current}),"release-v2").await.unwrap();
    let rolled = l
        .store
        .activate_app_release(
            &l.operator,
            &l.tenant,
            &l.project,
            &app,
            json!({"version_id":v1,"expected_revision":4}),
            "rollback",
        )
        .await
        .unwrap();
    let release = l
        .store
        .app_release(
            &l.operator,
            &l.tenant,
            &l.project,
            &app,
            s(&rolled["resource_id"]),
        )
        .await
        .unwrap();
    assert_eq!(release["version_id"], v1);
    assert_eq!(release["configuration"], current);
    let original = l
        .store
        .app_release(
            &l.operator,
            &l.tenant,
            &l.project,
            &app,
            s(&first["resource_id"]),
        )
        .await
        .unwrap();
    assert_eq!(original["configuration"], old);
    assert!(!release.to_string().contains("private-new-token"));
    assert!(!original.to_string().contains("private-old-token"));
    let error = sqlx::query("UPDATE app_releases SET configuration='{}' WHERE id=$1")
        .bind(s(&first["resource_id"]))
        .execute(&l.store.pool)
        .await
        .unwrap_err();
    assert_eq!(
        error.as_database_error().unwrap().code().as_deref(),
        Some("23514")
    );
    assert_eq!(
        l.store
            .app(&l.operator, &l.tenant, &l.project, &app)
            .await
            .unwrap()["active_release_id"],
        rolled["resource_id"]
    );
    assert_eq!(
        l.store
            .app(&l.operator, &l.tenant, &l.project, &app)
            .await
            .unwrap()["latest_version"],
        2
    );
    assert_eq!(
        l.store
            .app_history(
                &l.operator,
                &l.tenant,
                &l.project,
                &app,
                "releases",
                HistoryPage::default()
            )
            .await
            .unwrap()["items"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    // Trigger compatibility is checked against the active release, not latest upload.
    l.store
        .update_app_triggers(
            &l.operator,
            &l.tenant,
            &l.project,
            &app,
            json!({"manual":true,"expected_revision":1}),
            "enable-manual",
        )
        .await
        .unwrap();
    let http = l
        .store
        .upload(&l.operator, &l.tenant, &l.project, b"\0asm\x0d\0\x01\0http")
        .await
        .unwrap();
    approve_component(&l, &node, true, false).await;
    let vhttp = l
        .store
        .attach_app_version(
            &l.operator,
            &l.tenant,
            &l.project,
            &app,
            json!({"artifact_id":http["id"],"expected_revision":5}),
            "http-code",
        )
        .await
        .unwrap();
    assert_eq!(
        l.store
            .activate_app_release(
                &l.operator,
                &l.tenant,
                &l.project,
                &app,
                json!({"version_id":vhttp["resource_id"],"expected_revision":6}),
                "incompatible"
            )
            .await
            .unwrap_err()
            .status,
        StatusCode::CONFLICT
    );
    l.store
        .update_app_triggers(
            &l.operator,
            &l.tenant,
            &l.project,
            &app,
            json!({"manual":false,"expected_revision":2}),
            "disable-manual",
        )
        .await
        .unwrap();
    l.store
        .activate_app_release(
            &l.operator,
            &l.tenant,
            &l.project,
            &app,
            json!({"version_id":vhttp["resource_id"],"expected_revision":6}),
            "http-no-events",
        )
        .await
        .unwrap();
    assert_eq!(
        l.store
            .update_app_triggers(
                &l.operator,
                &l.tenant,
                &l.project,
                &app,
                json!({"manual":true,"expected_revision":3}),
                "invalid-trigger"
            )
            .await
            .unwrap_err()
            .status,
        StatusCode::CONFLICT
    );
    let (other, other_version) = define_app(&l, "other-app").await;
    assert_eq!(
        l.store
            .activate_app_release(
                &l.operator,
                &l.tenant,
                &l.project,
                &app,
                json!({"version_id":other_version,"expected_revision":7}),
                "foreign-version"
            )
            .await
            .unwrap_err()
            .status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        l.store
            .app_release(
                &l.operator,
                &l.tenant,
                &l.project,
                &other,
                s(&rolled["resource_id"])
            )
            .await
            .unwrap_err()
            .status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        l.store
            .app_history(
                &l.operator,
                &l.tenant,
                &l.project,
                &other,
                "releases",
                HistoryPage {
                    trigger: None,
                    before: Some(s(&rolled["resource_id"]).into()),
                    limit: None
                }
            )
            .await
            .unwrap_err()
            .status,
        StatusCode::NOT_FOUND
    );
    let (viewer, _) = l.credential("viewer", Some(&l.project)).await;
    assert_eq!(
        l.store
            .activate_app_release(
                &viewer,
                &l.tenant,
                &l.project,
                &app,
                json!({"version_id":v1,"expected_revision":7}),
                "viewer-release"
            )
            .await
            .unwrap_err()
            .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        l.store
            .update_app_triggers(
                &viewer,
                &l.tenant,
                &l.project,
                &app,
                json!({"manual":false,"expected_revision":3}),
                "viewer-triggers"
            )
            .await
            .unwrap_err()
            .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        l.store
            .app_lifecycle(
                &viewer,
                &l.tenant,
                &l.project,
                &app,
                json!({"desired":"stopped","expected_revision":7}),
                "viewer-stop"
            )
            .await
            .unwrap_err()
            .status,
        StatusCode::FORBIDDEN
    );
    let invalid = json!({"size":"small","env":{},"secret_env":{"TOKEN":uid()}});
    assert_eq!(
        l.store
            .activate_app_release(
                &l.operator,
                &l.tenant,
                &l.project,
                &app,
                json!({"version_id":v1,"expected_revision":7,"configuration":invalid}),
                "missing-secret"
            )
            .await
            .unwrap_err()
            .status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM executions")
            .fetch_one(&l.store.pool)
            .await
            .unwrap(),
        0
    );
    sqlx::query("UPDATE recovery_barrier SET active=true")
        .execute(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(
        l.store
            .activate_app_release(
                &l.operator,
                &l.tenant,
                &l.project,
                &app,
                json!({"version_id":v1,"expected_revision":7}),
                "barred-release"
            )
            .await
            .unwrap_err()
            .status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        l.store
            .update_app_triggers(
                &l.operator,
                &l.tenant,
                &l.project,
                &app,
                json!({"manual":false,"expected_revision":3}),
                "barred-trigger"
            )
            .await
            .unwrap_err()
            .status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        l.store
            .app_lifecycle(
                &l.operator,
                &l.tenant,
                &l.project,
                &app,
                json!({"desired":"stopped","expected_revision":7}),
                "barred-stop"
            )
            .await
            .unwrap_err()
            .status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    l.finish().await;
}

#[tokio::test]
async fn app_code_versions_are_validated_immutable_and_do_not_run_on_upload() {
    let l = Lab::new().await;
    let (editor, _) = l.credential("editor", Some(&l.project)).await;
    let (viewer, _) = l.credential("viewer", Some(&l.project)).await;
    let input = || json!({"name":"invoice-agent","artifact_id":l.artifact});
    assert_eq!(
        l.store
            .create_app(&editor, &l.tenant, &l.project, input(), "create-app")
            .await
            .unwrap_err()
            .status,
        StatusCode::CONFLICT
    );
    assert_eq!(
        l.store
            .create_app(&viewer, &l.tenant, &l.project, input(), "create-app")
            .await
            .unwrap_err()
            .status,
        StatusCode::FORBIDDEN
    );
    let node = l.node("compiler").await;
    approve_component(&l, &node, true, false).await;
    // Identical concurrent submissions create exactly one app and one operation.
    let (a, b) = tokio::join!(
        l.store
            .create_app(&editor, &l.tenant, &l.project, input(), "create-app"),
        l.store
            .create_app(&editor, &l.tenant, &l.project, input(), "create-app")
    );
    let op = a.unwrap();
    assert_eq!(op, b.unwrap());
    assert_eq!(op["state"], "succeeded");
    let app = s(&op["resource_id"]);
    let v1 = l
        .store
        .app_versions(&viewer, &l.tenant, &l.project, app, None)
        .await
        .unwrap()["items"][0]
        .clone();
    assert_eq!(v1["number"], 1);
    assert_eq!(v1["inspection"]["http"], true);
    assert_eq!(v1["inspection"]["command"], false);
    let mut wrong = input();
    wrong["name"] = json!("other-name");
    assert_eq!(
        l.store
            .create_app(&editor, &l.tenant, &l.project, wrong, "create-app")
            .await
            .unwrap_err()
            .status,
        StatusCode::CONFLICT
    );
    assert_eq!(
        l.store
            .create_app(&editor, &l.tenant, &l.project, input(), "duplicate-name")
            .await
            .unwrap_err()
            .status,
        StatusCode::CONFLICT
    );
    // Validation success cannot be declared in a customer request.
    let mut forged = input();
    forged["inspection"] = v1["inspection"].clone();
    assert_eq!(
        l.store
            .create_app(&editor, &l.tenant, &l.project, forged, "forged")
            .await
            .unwrap_err()
            .status,
        StatusCode::BAD_REQUEST
    );
    let new = l
        .store
        .upload(&editor, &l.tenant, &l.project, b"\0asm\x0d\0\x01\0new")
        .await
        .unwrap();
    let attach = || json!({"artifact_id":new["id"],"expected_revision":1});
    assert_eq!(
        l.store
            .attach_app_version(&editor, &l.tenant, &l.project, app, attach(), "attach")
            .await
            .unwrap_err()
            .status,
        StatusCode::CONFLICT
    );
    approve_component(&l, &node, false, true).await;
    let (a, b) = tokio::join!(
        l.store
            .attach_app_version(&editor, &l.tenant, &l.project, app, attach(), "attach-a"),
        l.store
            .attach_app_version(&editor, &l.tenant, &l.project, app, attach(), "attach-b")
    );
    let (attached, key) = match (a, b) {
        (Ok(op), Err(error)) => {
            assert_eq!(error.status, StatusCode::CONFLICT);
            (op, "attach-a")
        }
        (Err(error), Ok(op)) => {
            assert_eq!(error.status, StatusCode::CONFLICT);
            (op, "attach-b")
        }
        other => panic!("expected one successful revision update: {other:?}"),
    };
    // A lost response can be retried with its old expected revision.
    assert_eq!(
        l.store
            .attach_app_version(&editor, &l.tenant, &l.project, app, attach(), key)
            .await
            .unwrap(),
        attached
    );
    let app_row = l
        .store
        .app(&viewer, &l.tenant, &l.project, app)
        .await
        .unwrap();
    assert_eq!(app_row["revision"], 2);
    assert_eq!(app_row["latest_version"], 2);
    let reused = l
        .store
        .attach_app_version(
            &editor,
            &l.tenant,
            &l.project,
            app,
            json!({"artifact_id":new["id"],"expected_revision":2}),
            "reuse",
        )
        .await
        .unwrap();
    assert_eq!(reused["resource_id"], attached["resource_id"]);
    assert_eq!(
        l.store
            .app(&viewer, &l.tenant, &l.project, app)
            .await
            .unwrap()["revision"],
        2
    );
    let versions = l
        .store
        .app_versions(&viewer, &l.tenant, &l.project, app, None)
        .await
        .unwrap();
    assert_eq!(versions["items"].as_array().unwrap().len(), 2);
    assert_eq!(versions["items"][0]["inspection"]["command"], true);
    assert_eq!(versions["items"][1], v1);
    // Upload and attachment are not deployment: neither version reports a release.
    assert!(versions["items"][0]["last_release"].is_null());
    assert!(versions["items"][1]["last_release"].is_null());
    assert_eq!(
        l.store
            .app_versions(&viewer, &l.tenant, &l.project, app, Some(2))
            .await
            .unwrap()["items"],
        json!([v1])
    );
    assert_eq!(
        l.store
            .attach_app_version(
                &viewer,
                &l.tenant,
                &l.project,
                app,
                json!({"artifact_id":new["id"],"expected_revision":2}),
                "viewer"
            )
            .await
            .unwrap_err()
            .status,
        StatusCode::FORBIDDEN
    );
    // Enforce immutability below the API too.
    let error = sqlx::query("UPDATE app_versions SET artifact_id=$1 WHERE id=$2")
        .bind(s(&new["id"]))
        .bind(s(&v1["id"]))
        .execute(&l.store.pool)
        .await
        .unwrap_err();
    assert_eq!(
        error.as_database_error().unwrap().code().as_deref(),
        Some("23514")
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM executions")
            .fetch_one(&l.store.pool)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        l.store
            .usage(&viewer, &l.tenant, Some(&l.project))
            .await
            .unwrap()["reserved"]["instances"],
        0
    );
    let reopened = Store::from_pool(l.store.pool.clone(), l.root.path()).unwrap();
    reopened.migrate().await.unwrap();
    assert_eq!(
        reopened
            .app_version(&viewer, &l.tenant, &l.project, app, s(&v1["id"]))
            .await
            .unwrap(),
        v1
    );
    sqlx::query("UPDATE recovery_barrier SET active=true")
        .execute(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(
        l.store
            .create_app(&editor, &l.tenant, &l.project, input(), "barred")
            .await
            .unwrap_err()
            .status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        l.store
            .attach_app_version(
                &editor,
                &l.tenant,
                &l.project,
                app,
                json!({"artifact_id":new["id"],"expected_revision":2}),
                "barred"
            )
            .await
            .unwrap_err()
            .status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    l.finish().await;
}

#[tokio::test]
async fn customer_apps_have_scoped_pages_and_nested_version_boundaries() {
    use fenders_control_plane::apps::AppPage;
    let l = Lab::new().await;
    let node = l.node("compiler").await;
    approve_component(&l, &node, true, true).await;
    let (editor, credential) = l.credential("editor", Some(&l.project)).await;
    let mut apps = Vec::new();
    for name in ["invoice-agent", "daily-digest", "email-worker"] {
        let response = api::router(l.store.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!(
                        "/v1/workspaces/{}/projects/{}/apps",
                        l.tenant, l.project
                    ))
                    .header(
                        "Authorization",
                        format!("Bearer {}", s(&credential["token"])),
                    )
                    .header("Idempotency-Key", name)
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        json!({"name":name,"artifact_id":l.artifact}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let op: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 8192).await.unwrap()).unwrap();
        apps.push(s(&op["resource_id"]).to_owned());
    }
    let mut cursor = None;
    let mut listed = Vec::new();
    for index in 0..3 {
        let page = l
            .store
            .apps(
                &editor,
                &l.tenant,
                &l.project,
                AppPage {
                    limit: Some(1),
                    before: cursor,
                    search: None,
                    trigger: None,
                    status: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(page["items"].as_array().unwrap().len(), 1);
        assert_eq!(page["summary"]["total"], 3);
        assert_eq!(page["total"], 3);
        assert_eq!(page["offset"], index);
        listed.push(s(&page["items"][0]["id"]).to_owned());
        cursor = page["next"].as_str().map(str::to_owned);
    }
    assert!(cursor.is_none());
    assert_eq!(listed, apps.iter().rev().cloned().collect::<Vec<_>>());
    for (search, count) in [("INVOICE", 1), ("%", 0), ("", 3)] {
        assert_eq!(
            l.store
                .apps(
                    &editor,
                    &l.tenant,
                    &l.project,
                    AppPage {
                        search: Some(search.into()),
                        ..Default::default()
                    }
                )
                .await
                .unwrap()["items"]
                .as_array()
                .unwrap()
                .len(),
            count
        );
    }
    for query in [
        "status=not-a-state",
        "limit=101",
        "limit=0",
        "limit=1&limit=2",
        "unknown=1",
        "before=bad-id",
    ] {
        let response = api::router(l.store.clone())
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/v1/workspaces/{}/projects/{}/apps?{query}",
                        l.tenant, l.project
                    ))
                    .header(
                        "Authorization",
                        format!("Bearer {}", s(&credential["token"])),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            response.status().is_client_error(),
            "query unexpectedly accepted: {query}"
        );
    }
    let version = l
        .store
        .app_versions(&editor, &l.tenant, &l.project, &apps[0], None)
        .await
        .unwrap()["items"][0]
        .clone();
    assert_eq!(
        l.store
            .app_version(&editor, &l.tenant, &l.project, &apps[1], s(&version["id"]))
            .await
            .unwrap_err()
            .status,
        StatusCode::NOT_FOUND
    );
    let sibling = l
        .store
        .create_project(
            &l.operator,
            &l.tenant,
            serde_json::from_value(json!({"name":"staging"})).unwrap(),
        )
        .await
        .unwrap();
    let project = s(&sibling["id"]);
    assert_eq!(
        l.store
            .app(&l.operator, &l.tenant, project, &apps[0])
            .await
            .unwrap_err()
            .status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        l.store
            .apps(
                &l.operator,
                &l.tenant,
                project,
                AppPage {
                    before: Some(apps[0].clone()),
                    ..Default::default()
                }
            )
            .await
            .unwrap_err()
            .status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        l.store
            .create_app(
                &l.operator,
                &l.tenant,
                project,
                json!({"name":"foreign-artifact","artifact_id":l.artifact}),
                "foreign"
            )
            .await
            .unwrap_err()
            .status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        l.store
            .apps(&editor, &uid(), &l.project, AppPage::default())
            .await
            .unwrap_err()
            .status,
        StatusCode::NOT_FOUND
    );
    // The scoped FK rejects a forged cross-project relationship even below the API.
    let foreign = l
        .store
        .upload(&l.operator, &l.tenant, project, b"\0asm\x0d\0\x01\0foreign")
        .await
        .unwrap();
    let error = sqlx::query("INSERT INTO app_versions(id,tenant_id,project_id,app_id,number,artifact_id,inspection) VALUES($1,$2,$3,$4,2,$5,$6)")
        .bind(uid()).bind(&l.tenant).bind(project).bind(&apps[0]).bind(foreign["id"].as_str().unwrap()).bind(&version["inspection"]).execute(&l.store.pool).await.unwrap_err();
    assert_eq!(
        error.as_database_error().unwrap().code().as_deref(),
        Some("23503")
    );
    l.finish().await;
}

#[tokio::test]
async fn component_validation_claims_are_scoped_atomic_and_durable() {
    let l = Lab::new().await;
    let (viewer, credential) = l.credential("viewer", Some(&l.project)).await;
    let state = l
        .store
        .artifact_inspection(&viewer, &l.tenant, &l.project, &l.artifact)
        .await
        .unwrap();
    assert_eq!(state["state"], "pending");
    assert!(state.get("node_id").is_none());
    for (tenant, project) in [(&uid(), &l.project), (&l.tenant, &uid())] {
        assert_eq!(
            l.store
                .artifact_inspection(&viewer, tenant, project, &l.artifact)
                .await
                .unwrap_err()
                .status,
            StatusCode::NOT_FOUND
        );
    }
    let sibling = l
        .store
        .create_project(
            &l.operator,
            &l.tenant,
            serde_json::from_value(json!({"name":"another"})).unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        l.store
            .artifact_inspection(&l.operator, &l.tenant, s(&sibling["id"]), &l.artifact)
            .await
            .unwrap_err()
            .status,
        StatusCode::NOT_FOUND
    );
    // Same-project duplicate upload reuses the job; equal bytes in another project do not.
    let duplicate = l
        .store
        .upload(&l.operator, &l.tenant, &l.project, b"\0asm\x0d\0\x01\0")
        .await
        .unwrap();
    assert_eq!(duplicate["id"], l.artifact);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM artifact_validations")
            .fetch_one(&l.store.pool)
            .await
            .unwrap(),
        1
    );
    let a = l.node("inspector-a").await;
    let b = l.node("inspector-b").await;
    let boot = || json!({"boot_id":"test-boot"});
    let (first, second) = tokio::join!(
        l.store.claim_component(s(&a["id"]), boot()),
        l.store.claim_component(s(&b["id"]), boot())
    );
    let (first, second) = (first.unwrap(), second.unwrap());
    assert_ne!(first["job"].is_null(), second["job"].is_null());
    let (owner, other, job) = if first["job"].is_null() {
        (&b, &a, &second["job"])
    } else {
        (&a, &b, &first["job"])
    };
    let generation = n(&job["generation"]);
    assert_eq!(
        l.store
            .claim_component(s(&owner["id"]), boot())
            .await
            .unwrap()["job"],
        *job
    );
    assert_eq!(
        l.store
            .component_content(s(&owner["id"]), &l.artifact, generation, boot())
            .await
            .unwrap(),
        b"\0asm\x0d\0\x01\0"
    );
    assert_eq!(
        l.store
            .component_content(s(&other["id"]), &l.artifact, generation, boot())
            .await
            .unwrap_err()
            .status,
        StatusCode::CONFLICT
    );
    let receipt = inspection_receipt(job);
    for (key, value) in [
        ("digest", json!("0".repeat(64))),
        ("runtime", json!("other-runtime")),
        ("bytes", json!(9)),
        ("command", json!("true")),
    ] {
        let mut bad = receipt.clone();
        bad[key] = value;
        assert_eq!(
            l.store
                .component_result(
                    s(&owner["id"]),
                    &l.artifact,
                    generation,
                    json!({"boot_id":"test-boot","inspection":bad})
                )
                .await
                .unwrap_err()
                .status,
            StatusCode::BAD_REQUEST
        );
    }
    let result = json!({"boot_id":"test-boot","inspection":receipt});
    assert_eq!(
        l.store
            .component_result(s(&other["id"]), &l.artifact, generation, result.clone())
            .await
            .unwrap_err()
            .status,
        StatusCode::CONFLICT
    );
    for _ in 0..2 {
        assert_eq!(
            l.store
                .component_result(s(&owner["id"]), &l.artifact, generation, result.clone())
                .await
                .unwrap()["accepted"],
            true
        );
    }
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM audit WHERE action='artifact.inspect'")
            .fetch_one(&l.store.pool)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        l.store
            .component_result(
                s(&owner["id"]),
                &l.artifact,
                generation,
                json!({"boot_id":"test-boot","error":"component-not-accepted"})
            )
            .await
            .unwrap_err()
            .status,
        StatusCode::CONFLICT
    );
    assert_eq!(
        l.store
            .component_content(s(&owner["id"]), &l.artifact, generation, boot())
            .await
            .unwrap_err()
            .status,
        StatusCode::CONFLICT
    );
    let reopened = Store::from_pool(l.store.pool.clone(), l.root.path()).unwrap();
    reopened.migrate().await.unwrap();
    let response = api::router(reopened)
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/workspaces/{}/projects/{}/artifacts/{}/inspection",
                    l.tenant, l.project, l.artifact
                ))
                .header(
                    "Authorization",
                    format!("Bearer {}", s(&credential["token"])),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let response: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap();
    assert_eq!(response["state"], "valid");
    assert_eq!(response["inspection"], receipt);
    let sibling_artifact = l
        .store
        .upload(
            &l.operator,
            &l.tenant,
            s(&sibling["id"]),
            b"\0asm\x0d\0\x01\0",
        )
        .await
        .unwrap();
    assert_eq!(
        l.store
            .artifact_inspection(
                &l.operator,
                &l.tenant,
                s(&sibling["id"]),
                s(&sibling_artifact["id"])
            )
            .await
            .unwrap()["state"],
        "pending"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM executions")
            .fetch_one(&l.store.pool)
            .await
            .unwrap(),
        0
    );
    l.finish().await;
}

/// Components are compiled in turn among workspaces, not oldest first.
#[tokio::test]
async fn components_are_taken_up_in_turn_among_workspaces() {
    let l = Lab::new().await;
    let node = l.node("compiler").await;
    // The first workspace's component is taken up and done.
    let first = approve_component(&l, &node, false, true).await;
    assert_eq!(first["artifact_id"], l.artifact.as_str());
    // It uploads three more; then another workspace uploads one.
    let mut busy = Vec::new();
    for n in 0..3u8 {
        let mut bytes = b"\0asm\x0d\0\x01\0".to_vec();
        bytes.push(n);
        let uploaded = l
            .store
            .upload(&l.operator, &l.tenant, &l.project, &bytes)
            .await
            .unwrap();
        busy.push(s(&uploaded["id"]).to_owned());
    }
    let other = l.store.create_tenant(&l.operator,serde_json::from_value(json!({"name":"other","allowance":{"cpu_percent":100,"memory_mib":512,"instances":1,"storage_bytes":1000000000i64,"transfer_bytes":1000000}})).unwrap()).await.unwrap();
    let other_project = l
        .store
        .create_project(
            &l.operator,
            s(&other["id"]),
            serde_json::from_value(json!({"name":"app"})).unwrap(),
        )
        .await
        .unwrap();
    let waiting = l
        .store
        .upload(
            &l.operator,
            s(&other["id"]),
            s(&other_project["id"]),
            b"\0asm\x0d\0\x01\0other",
        )
        .await
        .unwrap();
    // The other workspace's, uploaded last, is next: the first workspace
    // has had a turn. Then the first workspace's three, oldest first.
    let mut order = Vec::new();
    for _ in 0..4 {
        let job = approve_component(&l, &node, false, true).await;
        order.push(s(&job["artifact_id"]).to_owned());
    }
    assert_eq!(order[0], s(&waiting["id"]));
    assert_eq!(&order[1..], &busy[..]);
    l.finish().await;
}

#[tokio::test]
async fn component_validation_fences_lost_workers_and_recovery() {
    let l = Lab::new().await;
    let a = l.node("compiler-a").await;
    let b = l.node("compiler-b").await;
    let boot = || json!({"boot_id":"test-boot"});
    let job = l.store.claim_component(s(&a["id"]), boot()).await.unwrap()["job"].clone();
    let receipt = inspection_receipt(&job);
    let result = || json!({"boot_id":"test-boot","inspection":receipt});
    sqlx::query("UPDATE artifact_validations SET lease_until=now()-interval '1 second'")
        .execute(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(
        l.store
            .artifact_inspection(&l.operator, &l.tenant, &l.project, &l.artifact)
            .await
            .unwrap()["state"],
        "pending"
    );
    assert_eq!(
        l.store
            .component_result(s(&a["id"]), &l.artifact, 1, result())
            .await
            .unwrap_err()
            .status,
        StatusCode::CONFLICT
    );
    assert_eq!(
        l.store
            .component_content(s(&a["id"]), &l.artifact, 1, boot())
            .await
            .unwrap_err()
            .status,
        StatusCode::CONFLICT
    );
    let job = l.store.claim_component(s(&b["id"]), boot()).await.unwrap()["job"].clone();
    assert_eq!(job["generation"], 2);
    assert_eq!(
        l.store
            .component_result(s(&a["id"]), &l.artifact, 1, result())
            .await
            .unwrap_err()
            .status,
        StatusCode::CONFLICT
    );
    l.store
        .heartbeat(
            s(&b["id"]),
            json!({"boot_id":"rebooted","reports":[],"confinement":HOST_CONFINEMENT}),
        )
        .await
        .unwrap();
    assert_eq!(
        l.store
            .component_result(s(&b["id"]), &l.artifact, 2, result())
            .await
            .unwrap_err()
            .status,
        StatusCode::CONFLICT
    );
    let job = l.store.claim_component(s(&a["id"]), boot()).await.unwrap()["job"].clone();
    assert_eq!(job["generation"], 3);
    // Infrastructure failure is pending with cooldown, never a rejected component.
    let retry = || json!({"boot_id":"test-boot","error":"compiler-unavailable"});
    l.store
        .component_result(s(&a["id"]), &l.artifact, 3, retry())
        .await
        .unwrap();
    l.store
        .component_result(s(&a["id"]), &l.artifact, 3, retry())
        .await
        .unwrap();
    assert!(l.store.claim_component(s(&a["id"]), boot()).await.unwrap()["job"].is_null());
    assert_eq!(
        l.store
            .artifact_inspection(&l.operator, &l.tenant, &l.project, &l.artifact)
            .await
            .unwrap()["state"],
        "pending"
    );
    sqlx::query("UPDATE artifact_validations SET available_at=now()")
        .execute(&l.store.pool)
        .await
        .unwrap();
    l.store
        .node_mode(&l.operator, s(&a["id"]), json!({"draining":true}))
        .await
        .unwrap();
    assert!(l.store.claim_component(s(&a["id"]), boot()).await.unwrap()["job"].is_null());
    l.store
        .node_mode(&l.operator, s(&a["id"]), json!({"draining":false}))
        .await
        .unwrap();
    assert_eq!(
        l.store.claim_component(s(&a["id"]), boot()).await.unwrap()["job"]["generation"],
        4
    );
    // Disable is immediate, even before another worker reclaims the assignment.
    l.store
        .node_mode(&l.operator, s(&a["id"]), json!({"disabled":true}))
        .await
        .unwrap();
    assert_eq!(
        l.store
            .component_result(s(&a["id"]), &l.artifact, 4, result())
            .await
            .unwrap_err()
            .status,
        StatusCode::CONFLICT
    );
    let rebooted = || json!({"boot_id":"rebooted"});
    assert_eq!(
        l.store
            .claim_component(s(&b["id"]), rebooted())
            .await
            .unwrap()["job"]["generation"],
        5
    );
    sqlx::query("UPDATE recovery_barrier SET active=true")
        .execute(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(
        l.store
            .claim_component(s(&b["id"]), rebooted())
            .await
            .unwrap_err()
            .status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        l.store
            .component_content(s(&b["id"]), &l.artifact, 5, rebooted())
            .await
            .unwrap_err()
            .status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        l.store
            .component_result(
                s(&b["id"]),
                &l.artifact,
                5,
                json!({"boot_id":"rebooted","inspection":receipt})
            )
            .await
            .unwrap_err()
            .status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    sqlx::query("UPDATE recovery_barrier SET active=false")
        .execute(&l.store.pool)
        .await
        .unwrap();
    l.store
        .component_result(
            s(&b["id"]),
            &l.artifact,
            5,
            json!({"boot_id":"rebooted","error":"component-not-accepted"}),
        )
        .await
        .unwrap();
    assert_eq!(
        l.store
            .artifact_inspection(&l.operator, &l.tenant, &l.project, &l.artifact)
            .await
            .unwrap()["state"],
        "rejected"
    );
    assert!(
        l.store
            .claim_component(s(&b["id"]), rebooted())
            .await
            .unwrap()["job"]
            .is_null()
    );
    l.finish().await;
}

#[tokio::test]
async fn schedule_preview_is_scoped_deterministic_and_read_only() {
    let l = Lab::new().await;
    let (viewer, token) = l.credential("viewer", Some(&l.project)).await;
    let preview = || {
        serde_json::from_value(json!({"expression":"30 1 * * *","timezone":"America/New_York","after":"2026-11-01T00:00:00Z"})).unwrap()
    };
    let response=api::router(l.store.clone()).oneshot(Request::builder().method("POST")
        .uri(format!("/v1/workspaces/{}/projects/{}/schedules/preview",l.tenant,l.project))
        .header("Authorization",format!("Bearer {}",s(&token["token"])))
        .header("Content-Type", "application/json")
.body(Body::from(json!({"expression":"30 1 * * *","timezone":"America/New_York","after":"2026-11-01T00:00:00Z"}).to_string())).unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 8192).await.unwrap()).unwrap();
    assert_eq!(body["occurrences"].as_array().unwrap().len(), 5);
    assert_eq!(body["occurrences"][0]["utc"], "2026-11-01T05:30:00+00:00");
    assert_eq!(body["occurrences"][0]["local"], "2026-11-01T01:30:00-04:00");
    assert_eq!(body["occurrences"][1]["utc"], "2026-11-02T06:30:00+00:00");
    assert_eq!(
        l.store
            .preview_schedule(&viewer, &l.tenant, &uid(), preview())
            .await
            .unwrap_err()
            .status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        l.store
            .preview_schedule(&viewer, &uid(), &l.project, preview())
            .await
            .unwrap_err()
            .status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        l.store
            .preview_schedule(
                &viewer,
                &l.tenant,
                &l.project,
                serde_json::from_value(json!({"expression":"bad","timezone":"UTC"})).unwrap()
            )
            .await
            .unwrap_err()
            .status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        l.store
            .preview_schedule(
                &viewer,
                &l.tenant,
                &l.project,
                serde_json::from_value(
                    json!({"expression":"* * * * *","timezone":"UTC","after":"yesterday"})
                )
                .unwrap()
            )
            .await
            .unwrap_err()
            .status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM executions")
            .fetch_one(&l.store.pool)
            .await
            .unwrap(),
        0
    );
    l.finish().await;
}

#[path = "cases/artifact_retention.rs"]
mod artifact_retention;
