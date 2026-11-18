//! Generic TCP permission withdrawal during manager absence. Protocol/TLS stay
//! in the guest; this fixture's opaque relay never examines application bytes.
use super::*;
use std::sync::atomic::AtomicBool;

pub(super) struct Revocation {
    execution: String,
    grant: String,
    endpoint: String,
    backend: PathBuf,
    identity: Value,
    config_sha256: String,
    journal: Value,
    key: String,
    create_key: String,
    spec: Value,
    client: reqwest::Client,
    url: String,
    token: String,
    internal: transport::Client,
    connections: Arc<AtomicU64>,
    transferred: Arc<AtomicU64>,
    closed: Arc<AtomicBool>,
    required_revision: i64,
    settled_revision: Option<i64>,
    operation: Option<Value>,
    authority: Option<Value>,
    output_sha256: Option<String>,
    phases: Vec<Value>,
    _relay: Task<()>,
}

async fn budget(l: &Lab, execution: &str) -> Value {
    sqlx::query_scalar("SELECT jsonb_build_object('state',state,'revision',revision,'held_bytes',held_bytes,'base_bytes',base_bytes,'no_expiry',expires IS NULL) FROM execution_egress_budgets WHERE execution_id=$1")
        .bind(execution).fetch_one(&l.store.pool).await.unwrap()
}

#[allow(clippy::too_many_arguments)]
fn settled(
    row: &Value,
    native: &Value,
    journal: &Value,
    grant: &Value,
    credit: &Value,
    operation: &Value,
    revision: i64,
    backend: &str,
) -> std::result::Result<(), &'static str> {
    if row["generation"] != 1
        || row["desired"] != "running"
        || row["reserved"] != false
        || !matches!(native["state"].as_str(), Some("exited" | "failed"))
        || row["state"] != native["state"]
        || row["network_revision"]
            .as_i64()
            .is_none_or(|current| current < revision)
        || journal["generation"] != 1
        || journal["backend"] != backend
        || grant["state"] != "revoked"
        || operation["state"] != "succeeded"
        || credit["state"] != "closed"
        || credit["held_bytes"] != 0
        || credit["no_expiry"] != true
    {
        return Err(
            "revocation lacks current permission, original terminal execution or closed credit",
        );
    }
    // Acknowledged withdrawal or confirmed safe release completes revocation;
    // terminal reservation release is already required above.
    Ok(())
}

impl Revocation {
    #[allow(clippy::too_many_arguments)]
    pub async fn start(
        l: &Lab,
        worker: &mut Worker,
        pg: &Value,
        spec: &Value,
        address: &str,
        api: (reqwest::Client, String),
        internal: transport::Client,
        cpu_percent: i64,
    ) -> Self {
        let listener = tokio::net::TcpListener::bind((address, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let connections = Arc::new(AtomicU64::new(0));
        let transferred = Arc::new(AtomicU64::new(0));
        let closed = Arc::new(AtomicBool::new(false));
        let (accepted, bytes, finished) =
            (connections.clone(), transferred.clone(), closed.clone());
        let target = format!("{}:{}", s(&pg["host"]), n(&pg["port"]));
        let relay = Task(tokio::spawn(async move {
            while let Ok((mut source, _)) = listener.accept().await {
                accepted.fetch_add(1, Ordering::SeqCst);
                let mut destination = tokio::net::TcpStream::connect(&target).await.unwrap();
                let (mut from_guest, mut to_guest) = source.split();
                let (mut from_server, mut to_server) = destination.split();
                let upstream = async {
                    let mut buffer = [0u8; 8192];
                    loop {
                        let count = from_guest.read(&mut buffer).await?;
                        if count == 0 {
                            return Ok::<_, std::io::Error>(());
                        }
                        to_server.write_all(&buffer[..count]).await?;
                        bytes.fetch_add(count as u64, Ordering::SeqCst);
                    }
                };
                let downstream = tokio::io::copy(&mut from_server, &mut to_guest);
                tokio::select! { _=upstream=>{}, _=downstream=>{} }
                finished.store(true, Ordering::SeqCst);
            }
        }));
        let endpoint = l
            .store
            .create_endpoint(
                &l.operator,
                &l.tenant,
                &l.project,
                json!({"name":"cutover-tcp","host":address,"port":port}),
                &uid(),
            )
            .await
            .unwrap();
        let endpoint = l
            .store
            .resources(
                &l.operator,
                &l.tenant,
                &l.project,
                "external-endpoints",
                Some(s(&endpoint["resource_id"])),
            )
            .await
            .unwrap();
        let mut spec = spec.clone();
        spec["endpoint_ids"] = json!([endpoint["id"]]);
        spec["network_id"] = endpoint["network_id"].clone();
        spec["env"]["PGPORT"] = json!(port.to_string());
        spec["env"]["PG_READ_ONLY"] = json!("1");
        spec["env"]["PG_CREATE_TABLE"] = json!("0");
        // Read the original fixture row; never write another database record.
        spec["cpu_percent"] = json!(cpu_percent);
        let create_key = uid();
        let created = l.create(&create_key, spec.clone()).await;
        let execution = s(&created["resource_id"]).to_owned();
        let backend = running(l, worker, &execution).await;
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let output = fs::read_to_string(backend.join("output.log")).unwrap();
            if output.contains("FENDERS_PG_HOLD_OPEN") {
                break;
            }
            assert_eq!(json_file(&backend.join("status.json"))["state"], "running");
            assert!(
                Instant::now() < deadline,
                "auxiliary TCP guest did not authenticate and hold"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(connections.load(Ordering::SeqCst), 1);
        assert!(!closed.load(Ordering::SeqCst));
        let row = l.execution(&execution).await;
        let required_revision = n(&row["network_revision"]) + 1;
        let grant: String=sqlx::query_scalar("SELECT id FROM network_grants WHERE execution_id=$1 AND endpoint_id=$2 AND state='active'")
            .bind(&execution).bind(s(&endpoint["id"])).fetch_one(&l.store.pool).await.unwrap();
        let (_, credential) = l.credential("editor", Some(&l.project)).await;
        let identity = ownership(&backend);
        let config_sha256 = digest(fs::read(backend.join("config.json")).unwrap());
        let journal = stop::assignment(&worker.output, &execution);
        let authority = budget(l, &execution).await;
        assert_eq!(authority["state"], "active");
        assert!(n(&authority["held_bytes"]) > 0);
        let native = native_status(&backend);
        assert_eq!(native["network_active"], true);
        assert!(n(&native["egress_budget_revision"]) > 0);
        let kernel = limits::kernel(&backend);
        let url = format!(
            "{}/v1/workspaces/{}/projects/{}/grants/{}/revoke",
            api.1, l.tenant, l.project, grant
        );
        let bytes = transferred.load(Ordering::SeqCst);
        assert!(bytes > 0);
        Self {
            execution,
            grant,
            endpoint: s(&endpoint["id"]).to_owned(),
            backend,
            identity,
            config_sha256,
            journal,
            key: uid(),
            create_key,
            spec,
            client: api.0,
            url,
            token: s(&credential["token"]).to_owned(),
            internal,
            connections,
            transferred,
            closed,
            required_revision,
            settled_revision: None,
            operation: None,
            authority: None,
            output_sha256: None,
            phases: vec![
                json!({"phase":"source_active","generation":row["generation"],"network_revision":row["network_revision"],
                "network_ack":row["network_ack"],"reserved":row["reserved"],"native_network_active":native["network_active"],"authority":authority,
                "authenticated_tls":true,"connections":1,"bytes":bytes,"kernel":kernel}),
            ],
            _relay: relay,
        }
    }

    async fn request(&self) -> Value {
        let response = self
            .client
            .post(&self.url)
            .bearer_auth(&self.token)
            .header("Idempotency-Key", &self.key)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let bytes = response.bytes().await.unwrap();
        assert!(bytes.len() <= 64 * 1024);
        serde_json::from_slice(&bytes).unwrap()
    }
    async fn grant_state(&self, l: &Lab) -> Value {
        sqlx::query_scalar("SELECT jsonb_build_object('id',id,'state',state,'execution',execution_id,'endpoint',endpoint_id) FROM network_grants WHERE id=$1")
            .bind(&self.grant).fetch_one(&l.store.pool).await.unwrap()
    }
    pub async fn queue(&mut self, l: &Lab, worker: &Worker) {
        let denied = self
            .client
            .post(&self.url)
            .header("Idempotency-Key", uid())
            .send()
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
        let (a, b) = tokio::join!(self.request(), self.request());
        assert_eq!(a, b);
        assert_eq!(a["state"], "pending");
        self.operation = Some(a.clone());
        let row = l.execution(&self.execution).await;
        assert_eq!(row["generation"], 1);
        assert_eq!(row["desired"], "running");
        assert_eq!(row["state"], "running");
        assert_eq!(row["reserved"], true);
        assert_eq!(row["network_revision"], self.required_revision);
        let barrier:i64=sqlx::query_scalar("SELECT required_revision FROM network_revocations WHERE operation_id=$1 AND execution_id=$2")
            .bind(s(&a["id"])).bind(&self.execution).fetch_one(&l.store.pool).await.unwrap();
        assert_eq!(barrier, self.required_revision);
        assert!(n(&row["network_ack"]) < self.required_revision);
        assert_eq!(self.grant_state(l).await["state"], "revoking");
        assert_eq!(
            stop::assignment(&worker.output, &self.execution),
            self.journal
        );
        assert_eq!(ownership(&self.backend), self.identity);
        assert!(!self.closed.load(Ordering::SeqCst));
        for kind in ["worker", "vmm"] {
            assert!(stop::alive(
                &self.identity[format!("{kind}_pid")],
                &self.identity[format!("{kind}_identity")]
            ));
        }
        self.phases.push(json!({"phase":"revoking_without_manager","generation":row["generation"],"desired":row["desired"],"state":row["state"],
            "network_revision":row["network_revision"],"network_ack":row["network_ack"],"reserved":row["reserved"],"grant_state":"revoking",
            "concurrent_same_receipt":true,"unauthenticated_refused":true,"original_processes_alive":true,"connection_closed":false}));
    }
    pub async fn settle_sealed(
        &mut self,
        l: &Lab,
        worker: &Worker,
        client: &transport::Client,
        sealed: &Value,
    ) {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let row = l.execution(&self.execution).await;
            if row["reserved"] == false
                && self.grant_state(l).await["state"] == "revoked"
                && budget(l, &self.execution).await["state"] == "closed"
            {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "sealed fallback did not enforce TCP revocation"
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
        let row = l.execution(&self.execution).await;
        let native = json_file(&self.backend.join("status.json"));
        let journal = stop::assignment(&worker.output, &self.execution);
        let grant = self.grant_state(l).await;
        let credit = budget(l, &self.execution).await;
        let operation = self.request().await;
        assert_eq!(operation["id"], self.operation.as_ref().unwrap()["id"]);
        settled(
            &row,
            &native,
            &journal,
            &grant,
            &credit,
            &operation,
            self.required_revision,
            s(&self.identity["id"]),
        )
        .unwrap();
        // Computing the newly reduced policy can advance beyond the revoke
        // barrier. Once terminal, recovery must retain that observed revision.
        let revision = n(&row["network_revision"]);
        if let Some(previous) = self.settled_revision {
            assert_eq!(revision, previous);
        }
        self.settled_revision = Some(revision);
        assert_eq!(grant["execution"], self.execution);
        assert_eq!(grant["endpoint"], self.endpoint);
        assert_eq!(journal, self.journal);
        assert_eq!(ownership(&self.backend), self.identity);
        assert_eq!(
            digest(fs::read(self.backend.join("config.json")).unwrap()),
            self.config_sha256
        );
        assert!(self.closed.load(Ordering::SeqCst));
        assert_eq!(self.connections.load(Ordering::SeqCst), 1);
        for kind in ["worker", "vmm"] {
            assert!(!stop::alive(
                &self.identity[format!("{kind}_pid")],
                &self.identity[format!("{kind}_identity")]
            ));
        }
        let output = fs::read_to_string(self.backend.join("output.log")).unwrap();
        assert_eq!(output.matches("FENDERS_AUTHENTICATED").count(), 1);
        assert!(output.contains("FENDERS_TLS_SERVER TLSv1.3"));
        assert!(output.contains("FENDERS_PG_CONNECTION_CLOSED"));
        let output_sha256 = digest(output.as_bytes());
        if let Some(previous) = &self.output_sha256 {
            assert_eq!(&output_sha256, previous);
        }
        self.output_sha256 = Some(output_sha256.clone());
        if let Some(previous) = &self.authority {
            assert_eq!(&credit, previous);
        }
        self.authority = Some(credit.clone());
        let retry = l.create(&self.create_key, self.spec.clone()).await;
        assert_eq!(retry["resource_id"], self.execution);
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM network_grants WHERE execution_id=$1 AND endpoint_id=$2",
        )
        .bind(&self.execution)
        .bind(&self.endpoint)
        .fetch_one(&l.store.pool)
        .await
        .unwrap();
        assert_eq!(count, 1);
        let db = rusqlite::Connection::open_with_flags(
            worker.output.join("state/node/node.sqlite3"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .unwrap();
        let backends: i64 = db
            .query_row(
                "SELECT count(*) FROM runs WHERE request_key=?",
                [format!("platform-{}", self.execution)],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(backends, 1);
        let audits: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM audit WHERE action='grant.revoke' AND resource_id=$1",
        )
        .bind(&self.grant)
        .fetch_one(&l.store.pool)
        .await
        .unwrap();
        assert_eq!(audits, 1);
        let refused = self
            .internal
            .json(
                "GET",
                &format!("/internal/executions/{}/1/network", self.execution),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(refused.status, StatusCode::CONFLICT);
        let egress = self
            .internal
            .json(
                "GET",
                &format!("/internal/executions/{}/1/egress", self.execution),
                None,
            )
            .await
            .unwrap();
        assert_eq!(egress["grant"]["state"], "closed");
        assert_eq!(egress["grant"]["ttl_ms"], 0);
        self.phases.push(json!({"phase":phase,"generation":row["generation"],"desired":row["desired"],"state":row["state"],"native_state":native["state"],
            "network_revision":row["network_revision"],"network_ack":row["network_ack"],"reserved":row["reserved"],"grant_state":grant["state"],"operation":operation["id"],"operation_state":operation["state"],
            "authority":credit,"connection_closed":true,"connections":1,"original_processes_gone":true,"configuration_unchanged":true,"output_sha256":output_sha256,
            "native_backends":backends,"grant_count":count,"revoke_audits":audits,"same_key_no_recreation":true,"stale_network_request_refused":true,"closed_credit_ttl_ms":0}));
    }
    pub fn report(&self) -> Value {
        json!({"execution":self.execution,"grant":self.grant,"endpoint":self.endpoint,"identity":self.identity,
        "required_revision":self.required_revision,"customer_https":true,"guest_verified_tls":true,"opaque_tcp_relay":true,"connections":self.connections.load(Ordering::SeqCst),
        "bytes":self.transferred.load(Ordering::SeqCst),"phases":self.phases})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn revocation_proof_rejects_stale_permission_released_live_work_and_unsettled_credit() {
        let row = json!({"generation":1,"desired":"running","state":"exited","reserved":false,"network_revision":2});
        let native = json!({"state":"exited"});
        let journal = json!({"generation":1,"backend":"original"});
        let grant = json!({"state":"revoked"});
        let credit = json!({"state":"closed","held_bytes":0,"no_expiry":true});
        let operation = json!({"state":"succeeded"});
        settled(
            &row, &native, &journal, &grant, &credit, &operation, 2, "original",
        )
        .unwrap();
        let proof = json!({"row":row,"native":native,"journal":journal,"grant":grant,"credit":credit,"operation":operation});
        for (path, value) in [
            ("/row/network_revision", json!(1)),
            ("/row/generation", json!(2)),
            ("/row/reserved", json!(true)),
            ("/native/state", json!("running")),
            ("/journal/backend", json!("replacement")),
            ("/grant/state", json!("revoking")),
            ("/credit/held_bytes", json!(1)),
            ("/credit/no_expiry", json!(false)),
            ("/operation/state", json!("pending")),
        ] {
            let mut bad = proof.clone();
            *bad.pointer_mut(path).unwrap() = value;
            assert!(
                settled(
                    &bad["row"],
                    &bad["native"],
                    &bad["journal"],
                    &bad["grant"],
                    &bad["credit"],
                    &bad["operation"],
                    2,
                    "original"
                )
                .is_err(),
                "{path}"
            );
        }
    }
}
