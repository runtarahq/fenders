//! The maintained PostgreSQL WASM fixture over one opaque TCP relay. Credentials
//! stay in project secrets; TLS and the PostgreSQL protocol run inside WASM.
use super::*;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

pub struct Network {
    execution: String,
    grant: String,
    backend: PathBuf,
    initial: Value,
    kernel: Value,
    config_hash: String,
    connections: Arc<AtomicU64>,
    transferred: Arc<AtomicU64>,
    closed: Arc<AtomicBool>,
    relay: tokio::task::JoinHandle<()>,
    last_bytes: u64,
    phases: Vec<Value>,
    revoke: Option<Value>,
    revoke_key: String,
    create_path: String,
    create_key: String,
    spec: Value,
    receipt: Value,
}
impl Drop for Network {
    fn drop(&mut self) {
        self.relay.abort();
    }
}
impl Network {
    pub async fn start(
        l: &Lab,
        client: &reqwest::Client,
        door: &FrontDoor,
        pg: &Value,
        address: &str,
        worker: &mut Worker,
    ) -> Self {
        let artifact = upload(l, client, door, &input("FENDERS_ROLLOUT_POSTGRES_WASM")).await;
        let listener = tokio::net::TcpListener::bind((address, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let connections = Arc::new(AtomicU64::new(0));
        let transferred = Arc::new(AtomicU64::new(0));
        let closed = Arc::new(AtomicBool::new(false));
        let (accepted, bytes, finished) =
            (connections.clone(), transferred.clone(), closed.clone());
        let target = format!("{}:{}", s(&pg["host"]), n(&pg["port"]));
        let relay = tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                accepted.fetch_add(1, Ordering::SeqCst);
                super::super::agent_upgrade_live::proxy(socket, target.clone(), bytes.clone())
                    .await;
                finished.store(true, Ordering::SeqCst);
            }
        });
        let base = format!("/v1/workspaces/{}/projects/{}", l.tenant, l.project);
        let endpoint = json_request(
            l,
            client,
            door,
            "POST",
            &format!("{base}/connections"),
            "rollout-tcp",
            Some(json!({"name":"rollout-pg","host":address,"port":port})),
        )
        .await;
        let endpoint = json_request(
            l,
            client,
            door,
            "GET",
            &format!("{base}/connections/{}", s(&endpoint["resource_id"])),
            "",
            None,
        )
        .await;
        let username = l
            .store
            .create_secret(
                &l.operator,
                &l.tenant,
                &l.project,
                json!({"name":"rollout-pg-user","value":pg["user"]}),
            )
            .await
            .unwrap();
        let password = l
            .store
            .create_secret(
                &l.operator,
                &l.tenant,
                &l.project,
                json!({"name":"rollout-pg-password","value":pg["password"]}),
            )
            .await
            .unwrap();
        let spec = json!({"artifact_id":artifact,"cpu_percent":50,"wasm_memory_mib":8,"fuel":2000000000,
            "lifetime_seconds":180,"network_id":endpoint["network_id"],"endpoint_ids":[endpoint["id"]],
            "env":{"HTTP_CASE":"postgres","PGHOST":pg["host"],"PGHOSTADDR":address,"PGPORT":port.to_string(),
                "PGDATABASE":pg["database"],"PGSSLROOTCERT_PEM":pg["ca"],"PGOPTIONS":format!("-csearch_path={}",l.schema),
                "RUN_ID":"control-rollout-once","PG_CREATE_TABLE":"1","PG_HOLD":"1","PG_HOLD_SECONDS":"180"},
            "secret_env":{"PGUSER":username["id"],"PGPASSWORD":password["id"]}});
        let create_path = format!("{base}/executions");
        let create_key = uid();
        let receipt = json_request(
            l,
            client,
            door,
            "POST",
            &create_path,
            &create_key,
            Some(json!({"spec":spec})),
        )
        .await;
        let execution = s(&receipt["resource_id"]).to_owned();
        let backend = running(l, worker, &execution).await;
        tokio::time::timeout(Duration::from_secs(20), async {
            while !fs::read_to_string(backend.join("output.log"))
                .unwrap()
                .contains("FENDERS_PG_HOLD_OPEN")
            {
                assert!(worker.alive());
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap();
        let grant:String=sqlx::query_scalar("SELECT id FROM network_grants WHERE execution_id=$1 AND endpoint_id=$2 AND state='active'")
            .bind(&execution).bind(s(&endpoint["id"])).fetch_one(&l.store.pool).await.unwrap();
        Self {
            execution,
            grant,
            initial: ownership(&backend),
            kernel: super::super::agent_upgrade_live::kernel_controls(&backend),
            config_hash: digest(fs::read(backend.join("config.json")).unwrap()),
            backend,
            connections,
            transferred,
            closed,
            relay,
            last_bytes: 0,
            phases: vec![],
            revoke: None,
            revoke_key: uid(),
            create_path,
            create_key,
            spec,
            receipt,
        }
    }
    pub async fn observe(&mut self, l: &Lab, phase: &str) {
        assert_eq!(self.connections.load(Ordering::SeqCst), 1);
        assert!(!self.closed.load(Ordering::SeqCst));
        assert_eq!(ownership(&self.backend), self.initial);
        assert_eq!(
            super::super::agent_upgrade_live::kernel_controls(&self.backend),
            self.kernel
        );
        assert_eq!(
            digest(fs::read(self.backend.join("config.json")).unwrap()),
            self.config_hash
        );
        let cutoff: String = sqlx::query_scalar("SELECT clock_timestamp()::text")
            .fetch_one(&l.store.pool)
            .await
            .unwrap();
        let budget=tokio::time::timeout(Duration::from_secs(15),async {
            loop {
                let row:Value=sqlx::query_scalar("SELECT jsonb_build_object('state',state,'revision',revision,'base_bytes',base_bytes::text,'held_bytes',held_bytes,'expires',expires,'renewed_after_cutoff',expires>$2::timestamptz+interval '10 seconds') FROM execution_egress_budgets WHERE execution_id=$1")
                    .bind(&self.execution).bind(&cutoff).fetch_one(&l.store.pool).await.unwrap();
                assert_eq!(row["state"],"active");
                let native=super::super::agent_upgrade_live::native_status(&self.backend);
                if row["renewed_after_cutoff"]==true && n(&native["egress_budget_revision"])>=n(&row["revision"]) { break row; }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }).await.unwrap();
        let bytes = self.transferred.load(Ordering::SeqCst);
        assert!(
            bytes > self.last_bytes,
            "retained PostgreSQL TLS session stopped querying"
        );
        self.last_bytes = bytes;
        self.phases.push(json!({"phase":phase,"connections":1,"guest_to_database_bytes":bytes,
            "budget":budget,"native":self.initial,"kernel":self.kernel,"config_sha256":self.config_hash}));
    }
    pub async fn revoke(&mut self, l: &Lab, client: &reqwest::Client, door: &FrontDoor) {
        assert!(!self.closed.load(Ordering::SeqCst));
        let retried = json_request(
            l,
            client,
            door,
            "POST",
            &self.create_path,
            &self.create_key,
            Some(json!({"spec":self.spec})),
        )
        .await;
        assert_eq!(retried["resource_id"], self.receipt["resource_id"]);
        let path = format!(
            "/v1/workspaces/{}/projects/{}/grants/{}/revoke",
            l.tenant, l.project, self.grant
        );
        self.revoke =
            Some(json_request(l, client, door, "POST", &path, &self.revoke_key, None).await);
    }
    pub async fn finish(&self, l: &Lab, client: &reqwest::Client, door: &FrontDoor) -> Value {
        let terminal=tokio::time::timeout(Duration::from_secs(15),async {
            loop {
                let row:Value=sqlx::query_scalar("SELECT jsonb_build_object('state',state,'reserved',reserved,'generation',generation,'network_revision',network_revision) FROM executions WHERE id=$1")
                    .bind(&self.execution).fetch_one(&l.store.pool).await.unwrap();
                if row["reserved"]==false && matches!(row["state"].as_str(),Some("exited"|"failed")) && self.closed.load(Ordering::SeqCst) { break row; }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }).await.unwrap();
        assert_eq!(terminal["generation"], 1);
        assert_eq!(ownership(&self.backend), self.initial);
        assert_eq!(
            digest(fs::read(self.backend.join("config.json")).unwrap()),
            self.config_hash
        );
        assert_eq!(self.connections.load(Ordering::SeqCst), 1);
        let grant: String = sqlx::query_scalar("SELECT state FROM network_grants WHERE id=$1")
            .bind(&self.grant)
            .fetch_one(&l.store.pool)
            .await
            .unwrap();
        assert_eq!(grant, "revoked");
        let budget:Value=sqlx::query_scalar("SELECT jsonb_build_object('state',state,'base_bytes',base_bytes::text,'held_bytes',held_bytes,'no_expiry',expires IS NULL) FROM execution_egress_budgets WHERE execution_id=$1")
            .bind(&self.execution).fetch_one(&l.store.pool).await.unwrap();
        assert_eq!(budget["state"], "closed");
        assert_eq!(budget["held_bytes"], 0);
        assert_eq!(budget["no_expiry"], true);
        let path = format!(
            "/v1/workspaces/{}/projects/{}/grants/{}/revoke",
            l.tenant, l.project, self.grant
        );
        let operation = json_request(l, client, door, "POST", &path, &self.revoke_key, None).await;
        assert_eq!(operation["id"], self.revoke.as_ref().unwrap()["id"]);
        assert_eq!(operation["state"], "succeeded");
        let output = fs::read(self.backend.join("output.log")).unwrap();
        let text = std::str::from_utf8(&output).unwrap();
        assert_eq!(text.matches("FENDERS_AUTHENTICATED").count(), 1);
        assert!(text.contains("FENDERS_TLS_SERVER TLSv1.3"));
        assert!(text.contains("FENDERS_QUERY_VERIFIED"));
        assert!(text.contains("FENDERS_PG_HEARTBEAT"));
        json!({"execution":self.execution,"grant":self.grant,"phases":self.phases,"connections":1,
            "verified_postgres_tls":"TLSv1.3","authentication_count":1,"revocation_started_before_reupgrade":true,
            "terminal":terminal,"budget":budget,"revocation_receipt_id":operation["id"],"revocation_completed":true,
            "output_sha256":digest(output),"original_native":self.initial,"config_sha256":self.config_hash})
    }
}
