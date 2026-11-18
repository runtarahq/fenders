use super::super::agent_upgrade_live::kernel_controls;
use super::*;

pub struct Schedule {
    app: String,
    receipt: Value,
    next: String,
    pub evidence: Value,
}
impl Schedule {
    pub async fn start(
        l: &Lab,
        client: &reqwest::Client,
        door: &FrontDoor,
        artifact: &str,
        worker: &mut Worker,
        alpha_hostname: &str,
        beta_hostname: &str,
    ) -> Self {
        // One real future UTC occurrence, at least 15 seconds ahead. No database
        // tick injection and no recurring invocation during later cutovers.
        let (expression, target): (String, String) = sqlx::query_as("SELECT to_char(target AT TIME ZONE 'UTC','MI HH24 DD MM')||' *',target::text FROM (SELECT date_trunc('minute',clock_timestamp()+interval '75 seconds') target) t")
            .fetch_one(&l.store.pool).await.unwrap();
        let base = format!("/v1/tenants/{}/projects/{}", l.tenant, l.project);
        let op = json_request(l, client, door, "POST", &format!("{base}/apps/deploy"), "scheduled-deploy",
            Some(json!({"name":"rollout-scheduled","artifact_id":artifact,"configuration":{"size":"medium","env":{"COMMAND_HOLD_MS":"5000"}},
                "triggers":{"http":false,"manual":false,"schedule":{"enabled":true,"expression":expression,"timezone":"UTC"}}}))).await;
        let app = s(&op["resource_id"]).to_owned();
        let next: String =
            sqlx::query_scalar("SELECT next_at::text FROM app_schedules WHERE app_id=$1")
                .bind(&app)
                .fetch_one(&l.store.pool)
                .await
                .unwrap();
        assert_eq!(next, target);
        let runs: i64 = sqlx::query_scalar("SELECT count(*) FROM app_runs WHERE app_id=$1")
            .bind(&app)
            .fetch_one(&l.store.pool)
            .await
            .unwrap();
        assert_eq!(
            runs, 0,
            "deployment invoked a scheduled command before its tick"
        );
        let mut last_traffic = std::time::Instant::now() - Duration::from_secs(5);
        let execution = tokio::time::timeout(Duration::from_secs(90), async {
            loop {
                let rows: Vec<(String, Option<String>)> =
                    sqlx::query_as("SELECT admission,execution_id FROM app_runs WHERE app_id=$1")
                        .bind(&app)
                        .fetch_all(&l.store.pool)
                        .await
                        .unwrap();
                assert!(
                    rows.len() <= 1,
                    "concurrent controllers duplicated an occurrence"
                );
                if let Some((admission, execution)) = rows.first() {
                    assert!(
                        matches!(admission.as_str(), "pending" | "admitted"),
                        "scheduled tick was not admitted: {admission}"
                    );
                    if let Some(execution) = execution {
                        break execution.clone();
                    }
                }
                if last_traffic.elapsed() >= Duration::from_secs(1) {
                    gateway(client.clone(), door.addresses[2], alpha_hostname.to_owned()).await;
                    gateway(client.clone(), door.addresses[2], beta_hostname.to_owned()).await;
                    last_traffic = std::time::Instant::now();
                }
                assert!(worker.alive());
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap();
        let backend = running(l, worker, &execution).await;
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let terminal: bool = sqlx::query_scalar(
                    "SELECT state='exited' AND NOT reserved FROM executions WHERE id=$1",
                )
                .bind(&execution)
                .fetch_one(&l.store.pool)
                .await
                .unwrap();
                if terminal {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap();
        let bytes = fs::read_to_string(backend.join("output.log")).unwrap();
        assert_eq!(
            bytes
                .lines()
                .filter(|line| *line == "FENDERS_DUAL_COMMAND_HOLD_STARTED")
                .count(),
            1
        );
        assert_eq!(
            bytes
                .lines()
                .filter(|line| *line == "FENDERS_DUAL_COMMAND_COMPLETE")
                .count(),
            1
        );
        let receipt = Self::receipt(l, &app).await;
        let assignments: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM audit WHERE action='execution.assign' AND resource_id=$1",
        )
        .bind(&execution)
        .fetch_one(&l.store.pool)
        .await
        .unwrap();
        assert_eq!(assignments, 1);
        let next: String =
            sqlx::query_scalar("SELECT next_at::text FROM app_schedules WHERE app_id=$1")
                .bind(&app)
                .fetch_one(&l.store.pool)
                .await
                .unwrap();
        let evidence = json!({"app":app,"occurrence":receipt,"future_next_at":next,
            "expression":expression,"real_clock":true,"deploy_invocations":0,"entrypoint_starts":1,
            "completions":1,"assignments":1,"native":ownership(&backend)});
        Self {
            app,
            receipt,
            next,
            evidence,
        }
    }
    async fn receipt(l: &Lab, app: &str) -> Value {
        sqlx::query_scalar("SELECT jsonb_agg(jsonb_build_object('id',id,'source',source,'scheduled_at',scheduled_at,'trigger_revision',trigger_revision,'release_id',release_id,'execution_id',execution_id,'admission',admission,'admission_reason',admission_reason) ORDER BY id) FROM app_runs WHERE app_id=$1")
            .bind(app).fetch_one(&l.store.pool).await.unwrap()
    }
    pub async fn observe(&self, l: &Lab) {
        assert_eq!(
            Self::receipt(l, &self.app).await,
            self.receipt,
            "rollback changed the scheduled occurrence"
        );
        let next: String =
            sqlx::query_scalar("SELECT next_at::text FROM app_schedules WHERE app_id=$1")
                .bind(&self.app)
                .fetch_one(&l.store.pool)
                .await
                .unwrap();
        assert_eq!(next, self.next, "startup reset the schedule clock");
    }
}

pub struct Tenant {
    tenant: String,
    principal: Principal,
    token: String,
    revoked_token: String,
    base: String,
    pub app: String,
    quota_app: String,
    pub backend: PathBuf,
    pub(super) hostname: String,
    initial: Value,
    controls: Value,
    config_hash: String,
    allowance: Value,
    pub phases: Vec<Value>,
}
impl Tenant {
    pub async fn start(
        l: &Lab,
        client: &reqwest::Client,
        door: &FrontDoor,
        build: &Path,
        worker: &mut Worker,
    ) -> Self {
        let allowance = json!({"cpu_percent":100,"memory_mib":512,"instances":2,"storage_bytes":20000000000i64,"transfer_bytes":10000000});
        let tenant = l
            .store
            .create_tenant(
                &l.operator,
                serde_json::from_value(json!({"name":"rollout-beta","allowance":allowance}))
                    .unwrap(),
            )
            .await
            .unwrap();
        let tenant = s(&tenant["id"]).to_owned();
        let project = l
            .store
            .create_project(
                &l.operator,
                &tenant,
                serde_json::from_value(json!({"name":"beta-apps"})).unwrap(),
            )
            .await
            .unwrap();
        let project = s(&project["id"]);
        let credential = l
            .store
            .create_api_key(&l.operator, &tenant, serde_json::from_value(json!({"name":"beta-editor","project_id":project,"permissions":["read","apps:write","runs:write","connections:write","secrets:write"],"ttl_seconds":86400})).unwrap(), &uid())
            .await
            .unwrap();
        let token = s(&credential["token"]).to_owned();
        let principal = l.store.authenticate(&token).await.unwrap();
        let revoked = l
            .store
            .create_api_key(&l.operator, &tenant, serde_json::from_value(json!({"name":"beta-withdrawn","project_id":project,"permissions":["read"],"ttl_seconds":86400})).unwrap(), &uid())
            .await
            .unwrap();
        l.store
            .revoke_credential(&l.operator, &tenant, s(&revoked["id"]))
            .await
            .unwrap();
        let mut artifacts = Vec::new();
        for file in ["example-http.wasm", "example-dual.wasm"] {
            let artifact = l
                .store
                .upload(
                    &l.operator,
                    &tenant,
                    project,
                    &fs::read(build.join(file)).unwrap(),
                )
                .await
                .unwrap();
            let id = s(&artifact["id"]).to_owned();
            tokio::time::timeout(Duration::from_secs(60), async {
                loop {
                    let state: String = sqlx::query_scalar(
                        "SELECT state FROM artifact_validations WHERE artifact_id=$1",
                    )
                    .bind(&id)
                    .fetch_one(&l.store.pool)
                    .await
                    .unwrap();
                    assert_ne!(state, "invalid");
                    if state == "valid" {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            })
            .await
            .unwrap();
            artifacts.push(id);
        }
        let base = format!("/v1/tenants/{tenant}/projects/{project}");
        let op = json_request(l, client, door, "POST", &format!("{base}/apps/deploy"), "beta-http-deploy",
            Some(json!({"name":"beta-http","artifact_id":artifacts[0],"configuration":{"size":"small","keep_warm":true},"triggers":{"http":true,"manual":false}}))).await;
        let app = s(&op["resource_id"]).to_owned();
        let (execution, hostname) = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let value = json_request(
                    l,
                    client,
                    door,
                    "GET",
                    &format!("{base}/apps/{app}/http"),
                    "",
                    None,
                )
                .await;
                if let Some(execution) = value["execution_id"].as_str() {
                    break (
                        execution.to_owned(),
                        s(&value["url"])
                            .strip_prefix("https://")
                            .unwrap()
                            .to_owned(),
                    );
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap();
        let backend = running(l, worker, &execution).await;
        let quota_app = json_request(l, client, door, "POST", &format!("{base}/apps/deploy"), "beta-quota-deploy",
            Some(json!({"name":"beta-quota","artifact_id":artifacts[1],"configuration":{"size":"small"},"triggers":{"http":false,"manual":true}}))).await;
        let initial = ownership(&backend);
        let controls = kernel_controls(&backend);
        let config_hash = digest(fs::read(backend.join("config.json")).unwrap());
        Self {
            tenant,
            principal,
            token,
            revoked_token: s(&revoked["token"]).to_owned(),
            base,
            app,
            quota_app: s(&quota_app["resource_id"]).to_owned(),
            backend,
            hostname,
            initial,
            controls,
            config_hash,
            allowance,
            phases: Vec::new(),
        }
    }
    pub async fn observe(
        &mut self,
        l: &Lab,
        client: &reqwest::Client,
        door: &FrontDoor,
        alpha_app_path: &str,
        phase: &str,
    ) {
        let own = format!(
            "https://{}{}/apps/{}",
            door.addresses[0], self.base, self.app
        );
        assert_eq!(
            client
                .get(&own)
                .bearer_auth(&self.token)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            client
                .get(format!("https://{}{alpha_app_path}", door.addresses[0]))
                .bearer_auth(&self.token)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            client
                .get(&own)
                .bearer_auth(&self.revoked_token)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        gateway(client.clone(), door.addresses[2], self.hostname.clone()).await;
        assert_eq!(ownership(&self.backend), self.initial);
        assert_eq!(kernel_controls(&self.backend), self.controls);
        assert_eq!(
            digest(fs::read(self.backend.join("config.json")).unwrap()),
            self.config_hash
        );
        let reservations: Value = sqlx::query_scalar("SELECT jsonb_agg(jsonb_build_object('id',id,'tenant',tenant_id,'cpu',cpu_percent,'memory',memory_mib,'node',node_id) ORDER BY id) FROM executions WHERE reserved")
            .fetch_one(&l.store.pool).await.unwrap();
        let usage = l
            .store
            .usage(
                &self.principal,
                &self.tenant,
                self.principal.project_id.as_deref(),
            )
            .await
            .unwrap();
        let mut checks = Vec::new();
        for field in ["cpu_percent", "memory_mib", "instances"] {
            let mut limit = self.allowance.clone();
            limit[field] = usage["reserved"][field].clone();
            l.store
                .update_allowance(
                    &l.operator,
                    &self.tenant,
                    serde_json::from_value(json!({"allowance":limit})).unwrap(),
                )
                .await
                .unwrap();
            let applied = l
                .store
                .usage(
                    &self.principal,
                    &self.tenant,
                    self.principal.project_id.as_deref(),
                )
                .await
                .unwrap();
            for (key, value) in limit.as_object().unwrap() {
                assert_eq!(&applied["allowance"][key], value);
            }
            let path = format!(
                "https://{}{}/apps/{}/runs",
                door.addresses[0], self.base, self.quota_app
            );
            let attempt = || {
                client
                    .post(&path)
                    .bearer_auth(&self.token)
                    .header("Idempotency-Key", uid())
                    .send()
            };
            let (a, b) = tokio::join!(attempt(), attempt());
            assert_eq!(a.unwrap().status(), StatusCode::TOO_MANY_REQUESTS);
            assert_eq!(b.unwrap().status(), StatusCode::TOO_MANY_REQUESTS);
            l.store
                .update_allowance(
                    &l.operator,
                    &self.tenant,
                    serde_json::from_value(json!({"allowance":self.allowance})).unwrap(),
                )
                .await
                .unwrap();
            let restored = l
                .store
                .usage(
                    &self.principal,
                    &self.tenant,
                    self.principal.project_id.as_deref(),
                )
                .await
                .unwrap();
            for (key, value) in self.allowance.as_object().unwrap() {
                assert_eq!(&restored["allowance"][key], value);
            }
            checks.push(
                json!({"dimension":field,"applied":limit,"restored":self.allowance,"refusals":2}),
            );
        }
        let after: Value = sqlx::query_scalar("SELECT jsonb_agg(jsonb_build_object('id',id,'tenant',tenant_id,'cpu',cpu_percent,'memory',memory_mib,'node',node_id) ORDER BY id) FROM executions WHERE reserved")
            .fetch_one(&l.store.pool).await.unwrap();
        assert_eq!(
            reservations, after,
            "refused admission changed reservations"
        );
        let runs: i64 = sqlx::query_scalar("SELECT count(*) FROM app_runs WHERE app_id=$1")
            .bind(&self.quota_app)
            .fetch_one(&l.store.pool)
            .await
            .unwrap();
        assert_eq!(runs, 0, "quota refusals created invocations");
        self.phases.push(json!({"phase":phase,"cross_tenant_denial":404,"revoked_credential_denial":401,
            "own_app_read":200,"gateway":200,"kernel":self.controls,"native":self.initial,"config_sha256":self.config_hash,
            "quotas":checks,"reservations_unchanged":true,"quota_probe_invocations":runs}));
    }
    pub async fn stop(&self, l: &Lab, client: &reqwest::Client, door: &FrontDoor) {
        let path = format!("{}/apps/{}", self.base, self.app);
        let app = json_request(l, client, door, "GET", &path, "", None).await;
        json_request(
            l,
            client,
            door,
            "PATCH",
            &path,
            "cleanup-beta",
            Some(json!({"desired":"stopped","expected_revision":app["revision"]})),
        )
        .await;
    }
    pub async fn log_reader(&self, l: &Lab) -> super::super::agent_upgrade_live::logs::RollingLogs {
        let execution: String =
            sqlx::query_scalar("SELECT execution_id FROM app_http WHERE app_id=$1")
                .bind(&self.app)
                .fetch_one(&l.store.pool)
                .await
                .unwrap();
        super::super::agent_upgrade_live::logs::RollingLogs::new(
            l,
            &self.tenant,
            self.principal.project_id.as_deref().unwrap(),
            &self.app,
            &execution,
            &self.backend,
        )
        .await
    }
}
