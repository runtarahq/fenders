//! Real tenant lifecycle actions while no manager owns a sealed worker. The
//! other tenants retain their original VMs/authority. Credentials stay private.
use super::*;
use fenders_control_plane::apps::AppSubmission;

pub(super) struct Suspension {
    tenant: String,
    project: String,
    app: String,
    execution: String,
    principal: Principal,
    token: String,
    backend: PathBuf,
    identity: Value,
    configuration_sha256: String,
    customer: reqwest::Client,
    customer_origin: String,
    operator: reqwest::Client,
    operator_url: String,
    operator_token: String,
    actor: String,
    input: Value,
    receipt: Option<Value>,
    internal: transport::Client,
    output_sha256: Option<String>,
    phases: Vec<Value>,
    deletion: bool,
    app_revision: i64,
    closed_authority: Option<Value>,
}

async fn post(
    client: &reqwest::Client,
    url: &str,
    token: &str,
    actor: &str,
    input: &Value,
) -> (StatusCode, Value) {
    let response = client
        .post(url)
        .bearer_auth(token)
        .header("Idempotency-Key", actor)
        .header("Content-Type", "application/json")
        .body(input.to_string())
        .send()
        .await
        .unwrap();
    let status = response.status();
    assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
    let bytes = response.bytes().await.unwrap();
    assert!(bytes.len() <= 8192);
    (status, serde_json::from_slice(&bytes).unwrap())
}
async fn workspace(l: &Lab, tenant: &str) -> Value {
    sqlx::query_scalar("SELECT jsonb_build_object('state',lifecycle_state,'revision',lifecycle_revision) FROM tenants WHERE id=$1")
        .bind(tenant).fetch_one(&l.store.pool).await.unwrap()
}
async fn budget(l: &Lab, execution: &str) -> Value {
    sqlx::query_scalar("SELECT jsonb_build_object('state',state,'revision',revision,'held_bytes',held_bytes,'base_bytes',base_bytes,'unexpired',COALESCE(expires>clock_timestamp(),false),'no_expiry',expires IS NULL) FROM execution_egress_budgets WHERE execution_id=$1")
        .bind(execution).fetch_one(&l.store.pool).await.unwrap()
}
#[allow(clippy::too_many_arguments)]
fn settled(
    workspace: &Value,
    row: &Value,
    native: &Value,
    journal: &Value,
    budget: &Value,
    backend: &str,
    deletion: bool,
    revision: i64,
) -> std::result::Result<(), &'static str> {
    // Revocation may terminate an active request before the supervisor sees the
    // stop file. Keep that actual terminal outcome; never relabel it as success.
    let fenced = if deletion {
        workspace["deleted"] == true
            && workspace["desired"] == "stopped"
            && workspace["revision"] == revision
    } else {
        workspace["state"] == "suspended" && workspace["revision"] == 3
    };
    if !fenced
        || row["desired"] != "stopped"
        || row["generation"] != 2
        || row["reserved"] != false
        || !matches!(s(&native["state"]), "stopped" | "exited" | "failed")
        || row["state"] != native["state"]
        || journal["generation"] != 2
        || journal["backend"] != backend
        || budget["state"] != "closed"
        || budget["held_bytes"] != 0
        || budget["no_expiry"] != true
    {
        return Err("workspace suspension lacks a fenced terminal observation or closed authority");
    }
    Ok(())
}

impl Suspension {
    pub async fn start(
        l: &Lab,
        worker: &mut Worker,
        component: &Path,
        api: (reqwest::Client, String),
        internal: transport::Client,
        deletion: bool,
    ) -> Self {
        let tenant = l.store.create_tenant(&l.operator, serde_json::from_value(json!({"name":"upgrade-suspension",
            "allowance":{"cpu_percent":100,"memory_mib":512,"instances":1,"storage_bytes":20000000000i64,"transfer_bytes":10000000}})).unwrap()).await.unwrap();
        let tenant = s(&tenant["id"]).to_owned();
        let project = l
            .store
            .create_project(
                &l.operator,
                &tenant,
                serde_json::from_value(json!({"name":"victim"})).unwrap(),
            )
            .await
            .unwrap();
        let project = s(&project["id"]).to_owned();
        let credential = l
            .store
            .create_api_key(&l.operator, &tenant, serde_json::from_value(json!({"name":"suspension-customer","project_id":project,"permissions":["read","apps:write","runs:write","connections:write","secrets:write"],"ttl_seconds":86400})).unwrap(), &uid())
            .await
            .unwrap();
        let principal = l.store.authenticate(s(&credential["token"])).await.unwrap();
        let uploaded = l
            .store
            .upload(&principal, &tenant, &project, &fs::read(component).unwrap())
            .await
            .unwrap();
        let artifact = s(&uploaded["id"]);
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let state: String =
                sqlx::query_scalar("SELECT state FROM artifact_validations WHERE artifact_id=$1")
                    .bind(artifact)
                    .fetch_one(&l.store.pool)
                    .await
                    .unwrap();
            if state == "valid" {
                break;
            }
            assert!(
                state != "invalid" && Instant::now() < deadline,
                "suspension fixture artifact did not validate"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let deployed = l.store.deploy_app(&principal, &tenant, &project, AppSubmission {
            value: json!({"name":"suspension-https","artifact_id":artifact,"configuration":{"size":"medium","env":{"TEST_MEMORY_MIB":"8"}},
                "triggers":{"manual":true,"http":false},"https_origins":["https://example.com"]}), key:&uid(), domain:"apps.test"
        }).await.unwrap();
        let app = s(&deployed["resource_id"]).to_owned();
        let invoked = l
            .store
            .run_app(&principal, &tenant, &project, &app, &uid())
            .await
            .unwrap();
        let run = l
            .store
            .app_run(
                &principal,
                &tenant,
                &project,
                &app,
                s(&invoked["resource_id"]),
            )
            .await
            .unwrap();
        let execution = s(&run["execution_id"]).to_owned();
        let backend = running(l, worker, &execution).await;
        let deadline = Instant::now() + Duration::from_secs(15);
        let progress = loop {
            let progress = https::progress(&fs::read(backend.join("output.log")).unwrap()).unwrap();
            if progress >= 2 {
                break progress;
            }
            assert!(
                Instant::now() < deadline,
                "suspension workload did not complete verified HTTPS requests"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        let identity = ownership(&backend);
        let kernel = limits::kernel(&backend);
        let configuration_sha256 = digest(fs::read(backend.join("config.json")).unwrap());
        let native = native_status(&backend);
        assert_eq!(native["network_active"], true);
        assert!(n(&native["egress_budget_revision"]) > 0);
        let authority = budget(l, &execution).await;
        assert_eq!(authority["state"], "active");
        assert_eq!(authority["unexpired"], true);
        assert!(n(&authority["held_bytes"]) > 0);
        let app_revision = n(&l
            .store
            .app(&principal, &tenant, &project, &app)
            .await
            .unwrap()["revision"]);
        let (operator, operator_url, actor, input) = if deletion {
            let url = format!(
                "{}/v1/workspaces/{tenant}/projects/{project}/apps/{app}",
                api.1
            );
            let actor = uid();
            let input = json!({"expected_revision":app_revision});
            let refused = api
                .0
                .delete(&url)
                .header("Idempotency-Key", &actor)
                .header("Content-Type", "application/json")
                .body(input.to_string())
                .send()
                .await
                .unwrap();
            assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
            (api.0.clone(), url, actor, input)
        } else {
            // A workspace's lifecycle is the operator's to change, on the
            // operator's own API: the workspace's key is refused it.
            let operator_url = format!("{}/v1/workspaces/{tenant}/lifecycle", api.1);
            let actor = uid();
            let input = json!({"request_key":uid(),"action":"suspend","expected_revision":1,"reason":"Sealed handover acceptance fixture"});
            let wrong = post(
                &api.0,
                &operator_url,
                s(&credential["token"]),
                &actor,
                &input,
            )
            .await;
            assert_eq!(wrong.0, StatusCode::FORBIDDEN);
            assert_eq!(
                workspace(l, &tenant).await,
                json!({"state":"active","revision":1})
            );
            (api.0.clone(), operator_url, actor, input)
        };
        Self {
            tenant,
            project,
            app,
            execution,
            principal,
            token: s(&credential["token"]).into(),
            backend,
            identity,
            configuration_sha256,
            customer: api.0,
            customer_origin: api.1,
            operator,
            operator_url,
            operator_token: l.token.clone(),
            actor,
            input,
            receipt: None,
            internal,
            output_sha256: None,
            phases: vec![json!({"phase":"source_active","https_progress":progress,
                "kernel":kernel,"authority":authority,"native_network_active":true,"worker_certificate_refused":!deletion,
                "customer_delete_https":deletion,"unauthenticated_delete_refused":deletion,"app_revision":app_revision})],
            deletion,
            app_revision,
            closed_authority: None,
        }
    }
    async fn submit(&self) -> (StatusCode, Value) {
        if !self.deletion {
            return post(
                &self.operator,
                &self.operator_url,
                &self.operator_token,
                &self.actor,
                &self.input,
            )
            .await;
        }
        let response = self
            .customer
            .delete(&self.operator_url)
            .bearer_auth(&self.token)
            .header("Idempotency-Key", &self.actor)
            .header("Content-Type", "application/json")
            .body(self.input.to_string())
            .send()
            .await
            .unwrap();
        let status = response.status();
        let bytes = response.bytes().await.unwrap();
        assert!(bytes.len() <= 8192);
        (status, serde_json::from_slice(&bytes).unwrap())
    }
    async fn action_state(&self, l: &Lab) -> Value {
        if !self.deletion {
            return workspace(l, &self.tenant).await;
        }
        sqlx::query_scalar("SELECT jsonb_build_object('deleted',deleted,'desired',desired,'revision',revision) FROM apps WHERE id=$1")
            .bind(&self.app).fetch_one(&l.store.pool).await.unwrap()
    }
    async fn row(&self, l: &Lab) -> Value {
        l.store
            .resources(
                &self.principal,
                &self.tenant,
                &self.project,
                "executions",
                Some(&self.execution),
            )
            .await
            .unwrap()
    }
    async fn deny_new_invocation(&self) {
        let url = format!(
            "{}/v1/workspaces/{}/projects/{}/apps/{}/runs",
            self.customer_origin, self.tenant, self.project, self.app
        );
        let response = self
            .customer
            .post(url)
            .bearer_auth(&self.token)
            .header("Idempotency-Key", uid())
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            if self.deletion {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::FORBIDDEN
            }
        );
    }
    pub async fn queue(&mut self, l: &Lab, worker: &Worker) {
        let (first, retry) = tokio::join!(self.submit(), self.submit());
        assert_eq!(
            first.0,
            if self.deletion {
                StatusCode::ACCEPTED
            } else {
                StatusCode::OK
            }
        );
        assert_eq!(first, retry);
        if self.deletion {
            assert_eq!(first.1["state"], "pending");
        } else {
            assert_eq!(first.1["status"], "suspending");
            assert_eq!(first.1["revision"], 2);
        }
        self.receipt = Some(first.1);
        let row = self.row(l).await;
        assert_eq!(row["generation"], 2);
        assert_eq!(row["desired"], "stopped");
        assert_eq!(row["state"], "running");
        assert_eq!(
            row["reserved"], true,
            "suspension released a live reservation"
        );
        let journal = stop::assignment(&worker.output, &self.execution);
        assert_eq!(journal["generation"], 1);
        assert_eq!(ownership(&self.backend), self.identity);
        assert_eq!(
            json_file(&self.backend.join("status.json"))["state"],
            "running"
        );
        for kind in ["worker", "vmm"] {
            assert!(stop::alive(
                &self.identity[format!("{kind}_pid")],
                &self.identity[format!("{kind}_identity")]
            ));
        }
        let state = self.action_state(l).await;
        if self.deletion {
            assert_eq!(
                state,
                json!({"deleted":true,"desired":"stopped","revision":self.app_revision+1})
            );
        } else {
            assert_eq!(state, json!({"state":"suspending","revision":2}));
        }
        self.deny_new_invocation().await;
        if self.deletion {
            for action in ["pause", "resume"] {
                let url = format!(
                    "{}/v1/workspaces/{}/projects/{}/executions/{}/{action}",
                    self.customer_origin, self.tenant, self.project, self.execution
                );
                let refused = self
                    .customer
                    .post(url)
                    .bearer_auth(&self.token)
                    .header("Idempotency-Key", uid())
                    .send()
                    .await
                    .unwrap();
                assert_eq!(
                    refused.status(),
                    StatusCode::CONFLICT,
                    "deleted app child action overrode stop"
                );
            }
            let after = self.row(l).await;
            assert_eq!(after["generation"], 2);
            assert_eq!(after["desired"], "stopped");
        }
        self.phases.push(json!({"phase":if self.deletion {"deleting_without_manager"} else {"suspending_without_manager"},"generation":row["generation"],"desired":row["desired"],
            "state":row["state"],"reserved":row["reserved"],"journal":journal,"original_processes_alive":true,
            "concurrent_retry_same_receipt":true,"new_customer_invocation_denied":true,"child_pause_resume_refused":self.deletion}));
    }
    pub async fn settle_sealed(
        &mut self,
        l: &Lab,
        worker: &Worker,
        client: &transport::Client,
        sealed: &Value,
    ) {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let state = self.action_state(l).await;
            let ready = if self.deletion {
                state["deleted"] == true && self.submit().await.1["state"] == "succeeded"
            } else {
                state["state"] == "suspended"
            };
            if ready && self.row(l).await["reserved"] == false {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "sealed fallback did not finish workspace suspension"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(
            client
                .json("POST", "/rpc/maintenance/status", Some(&json!({})))
                .await
                .unwrap(),
            *sealed
        );
        self.observe(l, worker, "sealed_fallback_before_resume")
            .await;
    }
    pub async fn observe(&mut self, l: &Lab, worker: &Worker, phase: &str) {
        let state = self.action_state(l).await;
        let row = self.row(l).await;
        let native = json_file(&self.backend.join("status.json"));
        let journal = stop::assignment(&worker.output, &self.execution);
        let authority = budget(l, &self.execution).await;
        settled(
            &state,
            &row,
            &native,
            &journal,
            &authority,
            s(&self.identity["id"]),
            self.deletion,
            self.app_revision + 1,
        )
        .unwrap();
        if let Some(before) = &self.closed_authority {
            assert_eq!(
                &authority, before,
                "closed byte accounting changed after adoption"
            );
        }
        self.closed_authority = Some(authority.clone());
        assert_eq!(ownership(&self.backend), self.identity);
        assert_eq!(
            digest(fs::read(self.backend.join("config.json")).unwrap()),
            self.configuration_sha256
        );
        for kind in ["worker", "vmm"] {
            assert!(!stop::alive(
                &self.identity[format!("{kind}_pid")],
                &self.identity[format!("{kind}_identity")]
            ));
        }
        let db = rusqlite::Connection::open_with_flags(
            worker.output.join("state/node/node.sqlite3"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .unwrap();
        let backends: Vec<String> = db
            .prepare("SELECT id FROM runs WHERE request_key=?")
            .unwrap()
            .query_map([format!("platform-{}", self.execution)], |r| r.get(0))
            .unwrap()
            .collect::<std::result::Result<_, _>>()
            .unwrap();
        assert_eq!(backends, vec![s(&self.identity["id"])]);
        let bytes = fs::read(self.backend.join("output.log")).unwrap();
        assert_eq!(
            String::from_utf8_lossy(&bytes)
                .lines()
                .filter(|line| *line == "FENDERS_HTTPS_STARTED")
                .count(),
            1
        );
        let output = digest(bytes);
        if let Some(before) = &self.output_sha256 {
            assert_eq!(&output, before, "suspended execution produced new output");
        }
        self.output_sha256 = Some(output.clone());
        let retry = self.submit().await;
        assert_eq!(
            retry.0,
            if self.deletion {
                StatusCode::ACCEPTED
            } else {
                StatusCode::OK
            }
        );
        if self.deletion {
            assert_eq!(retry.1["id"], self.receipt.as_ref().unwrap()["id"]);
            assert_eq!(retry.1["state"], "succeeded");
            assert_eq!(
                workspace(l, &self.tenant).await,
                json!({"state":"active","revision":1})
            );
            let receipt = self
                .customer
                .get(format!("{}/submissions/{}", self.operator_url, self.actor))
                .bearer_auth(&self.token)
                .send()
                .await
                .unwrap();
            assert_eq!(receipt.status(), StatusCode::OK);
            let receipt: Value = serde_json::from_slice(&receipt.bytes().await.unwrap()).unwrap();
            assert_eq!(receipt["id"], retry.1["id"]);
            assert_eq!(receipt["state"], "succeeded");
        } else {
            assert_eq!(&retry.1, self.receipt.as_ref().unwrap());
        }
        self.deny_new_invocation().await;
        for generation in [1, 2] {
            let refused = self
                .internal
                .json(
                    "GET",
                    &format!(
                        "/internal/executions/{}/{generation}/assignment",
                        self.execution
                    ),
                    None,
                )
                .await
                .unwrap_err();
            assert_eq!(refused.status, StatusCode::CONFLICT);
        }
        let status = self
            .internal
            .json(
                "GET",
                &format!("/internal/executions/{}/2/egress", self.execution),
                None,
            )
            .await
            .unwrap();
        assert_eq!(status["desired"], "stopped");
        assert_eq!(status["grant"]["state"], "closed");
        assert_eq!(status["grant"]["ttl_ms"], 0);
        let audits: i64 =
            sqlx::query_scalar("SELECT count(*) FROM audit WHERE tenant_id=$1 AND action=$2")
                .bind(&self.tenant)
                .bind(if self.deletion {
                    "app.delete"
                } else {
                    "operator.suspend"
                })
                .fetch_one(&l.store.pool)
                .await
                .unwrap();
        assert_eq!(audits, 1);
        let app_executions: i64 =
            sqlx::query_scalar("SELECT count(*) FROM app_execution_contexts WHERE app_id=$1")
                .bind(&self.app)
                .fetch_one(&l.store.pool)
                .await
                .unwrap();
        assert_eq!(
            app_executions, 1,
            "suspension or adoption implicitly invoked the app"
        );
        let mut observation = json!({"phase":phase,"generation":row["generation"],"desired":row["desired"],
            "state":row["state"],"reserved":row["reserved"],"native_state":native["state"],"native_reason":native["reason"],
            "journal":journal,"authority":authority,"native_backend_count":backends.len(),"original_processes_gone":true,
            "configuration_unchanged":true,"output_sha256":output,"same_action_receipt":true,"action_audit_count":audits,"app_execution_count":app_executions,
            "new_customer_invocation_denied":true,"both_assignment_generations_refused":true,"closed_credit_ttl_ms":status["grant"]["ttl_ms"]});
        if self.deletion {
            observation["app"] = state;
            observation["workspace"] = workspace(l, &self.tenant).await;
        } else {
            observation["workspace"] = state;
            observation["same_suspend_receipt"] = json!(true);
            observation["suspend_audit_count"] = json!(audits);
        }
        self.phases.push(observation);
    }
    pub fn report(&self) -> Value {
        json!({"tenant":self.tenant,"project":self.project,"app":self.app,"execution":self.execution,"identity":self.identity,
            "configuration_sha256":self.configuration_sha256,"private_operator_mtls":!self.deletion,"customer_delete_https":self.deletion,"initial_app_revision":self.app_revision,"phases":self.phases})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn deletion_proof_requires_a_stopped_tombstone_at_the_observed_revision() {
        let app = json!({"deleted":true,"desired":"stopped","revision":8});
        let row = json!({"desired":"stopped","generation":2,"state":"stopped","reserved":false});
        let native = json!({"state":"stopped"});
        let journal = json!({"generation":2,"backend":"original"});
        let budget = json!({"state":"closed","held_bytes":0,"no_expiry":true});
        assert!(settled(&app, &row, &native, &journal, &budget, "original", true, 8).is_ok());
        for (field, value) in [
            ("deleted", json!(false)),
            ("desired", json!("enabled")),
            ("revision", json!(7)),
            ("revision", json!(9)),
        ] {
            let mut invalid = app.clone();
            invalid[field] = value;
            assert!(
                settled(
                    &invalid, &row, &native, &journal, &budget, "original", true, 8
                )
                .is_err(),
                "{field}"
            );
        }
        assert!(
            settled(
                &app,
                &row,
                &native,
                &journal,
                &json!({"state":"active","held_bytes":1,"no_expiry":false}),
                "original",
                true,
                8
            )
            .is_err()
        );
        assert!(settled(&app, &row, &native, &journal, &budget, "recreated", true, 8).is_err());
    }
    #[test]
    fn suspension_proof_requires_confirmed_terminal_generation_and_closed_credit() {
        let workspace = json!({"state":"suspended","revision":3});
        let row = json!({"desired":"stopped","generation":2,"state":"stopped","reserved":false});
        let native = json!({"state":"stopped"});
        let journal = json!({"generation":2,"backend":"original"});
        let budget = json!({"state":"closed","held_bytes":0,"no_expiry":true});
        assert!(
            settled(
                &workspace, &row, &native, &journal, &budget, "original", false, 3
            )
            .is_ok()
        );
        for (field, value) in [
            ("reserved", json!(true)),
            ("generation", json!(1)),
            ("desired", json!("running")),
            ("state", json!("lost")),
        ] {
            let mut invalid = row.clone();
            invalid[field] = value;
            assert!(
                settled(
                    &workspace, &invalid, &native, &journal, &budget, "original", false, 3
                )
                .is_err(),
                "{field}"
            );
        }
        for invalid in [
            json!({"state":"active","revision":3}),
            json!({"state":"suspending","revision":2}),
        ] {
            assert!(
                settled(
                    &invalid, &row, &native, &journal, &budget, "original", false, 3
                )
                .is_err()
            );
        }
        for (field, value) in [
            ("state", json!("active")),
            ("held_bytes", json!(1)),
            ("no_expiry", json!(false)),
        ] {
            let mut invalid = budget.clone();
            invalid[field] = value;
            assert!(
                settled(
                    &workspace, &row, &native, &journal, &invalid, "original", false, 3
                )
                .is_err(),
                "{field}"
            );
        }
        assert!(
            settled(
                &workspace,
                &row,
                &native,
                &journal,
                &budget,
                "recreated",
                false,
                3
            )
            .is_err()
        );
        assert!(
            settled(
                &workspace,
                &row,
                &json!({"state":"running"}),
                &journal,
                &budget,
                "original",
                false,
                3
            )
            .is_err()
        );
        let mut honest = row.clone();
        honest["state"] = json!("failed");
        assert!(
            settled(
                &workspace,
                &honest,
                &json!({"state":"failed"}),
                &journal,
                &budget,
                "original",
                false,
                3
            )
            .is_ok()
        );
    }
}
