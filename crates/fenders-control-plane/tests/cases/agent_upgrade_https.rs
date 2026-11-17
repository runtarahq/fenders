//! Optional real public HTTPS coverage for the maintained upgrade harness.
//! All approval is scoped to its disposable database; no private-address bypass.
use super::*;
use fenders_control_plane::{apps::AppSubmission, public_egress::PublicEgressConfig};

pub async fn configure(l: &mut Lab) {
    l.store = l
        .store
        .clone()
        .with_public_egress(PublicEgressConfig {
            dns_address: "1.1.1.1:853".parse().unwrap(),
            dns_server_name: "cloudflare-dns.com".into(),
            dns_ca_pem: None,
            denied_ipv4: vec![], // Production special-use/private-address denial remains enabled.
        })
        .unwrap();
    let policy = l.store.public_egress_policy(&l.operator).await.unwrap();
    l.store
        .activate_public_egress(
            &l.operator,
            json!({"expected_revision":policy["revision"],
        "enabled":true,"digest":policy["configured_digest"]}),
        )
        .await
        .unwrap();
}

/// Parse only complete lines. Never accept replay, missing progress, HTTP
/// failure or capture truncation as evidence of a preserved invocation.
pub(super) fn progress(bytes: &[u8]) -> std::result::Result<u64, &'static str> {
    if bytes.len() > 64 * 1024 {
        return Err("HTTPS progress capture exceeded its bound");
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "invalid HTTPS progress encoding")?;
    let complete = text
        .rsplit_once('\n')
        .map(|(complete, _)| complete)
        .unwrap_or("");
    let mut starts = 0;
    let mut sequence = 0;
    for line in complete.lines() {
        if line == "FENDERS_HTTPS_STARTED" {
            starts += 1;
        }
        if line.starts_with("FENDERS_HTTPS_FAILED") {
            return Err("public HTTPS request failed");
        }
        if let Some(value) = line.strip_prefix("FENDERS_HTTPS_PROGRESS sequence=") {
            let value = value
                .strip_suffix(" status=200")
                .ok_or("invalid HTTPS success marker")?;
            let next: u64 = value
                .parse()
                .map_err(|_| "invalid HTTPS progress sequence")?;
            if starts != 1 || next != sequence + 1 {
                return Err("HTTPS invocation restarted or progress was lost");
            }
            sequence = next;
        }
    }
    if starts > 1 {
        return Err("HTTPS invocation restarted");
    }
    Ok(sequence)
}

async fn app_run(l: &Lab, artifact: &str, name: &str, size: &str) -> String {
    let profile = named_size(size);
    let deployed = l
        .store
        .deploy_app(
            &l.operator,
            &l.tenant,
            &l.project,
            AppSubmission {
                value: json!({"name":name,"artifact_id":artifact,"configuration":{"size":size,
                    "env":{"TEST_MEMORY_MIB":n(&profile["wasm_linear_memory_mib"]).to_string()}},
            "triggers":{"manual":true,"http":false},"https_origins":["https://example.com"]}),
                key: &uid(),
                domain: "apps.test",
            },
        )
        .await
        .unwrap();
    let app = s(&deployed["resource_id"]);
    let invoked = l
        .store
        .run_app(&l.operator, &l.tenant, &l.project, app, &uid())
        .await
        .unwrap();
    let run = l
        .store
        .app_run(
            &l.operator,
            &l.tenant,
            &l.project,
            app,
            s(&invoked["resource_id"]),
        )
        .await
        .unwrap();
    s(&run["execution_id"]).into()
}

async fn stop(l: &Lab, execution: &str) {
    l.store
        .action(
            &l.operator,
            &l.tenant,
            &l.project,
            execution,
            "stop",
            &uid(),
        )
        .await
        .unwrap();
    settled(l, execution).await;
}
async fn settled(l: &Lab, execution: &str) {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let reserved: bool = sqlx::query_scalar("SELECT reserved FROM executions WHERE id=$1")
            .bind(execution)
            .fetch_one(&l.store.pool)
            .await
            .unwrap();
        if !reserved {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "HTTPS reservation did not settle"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

pub struct Https {
    artifact: String,
    pub execution: String,
    pub backend: PathBuf,
    initial: Value,
    configuration: Vec<u8>,
    runtime: String,
    probe_size: String,
    pub phases: Vec<Value>,
    cutoff: Option<Value>,
}
impl Https {
    pub async fn start(
        l: &Lab,
        worker: &mut Worker,
        component: &Path,
        runtime: &str,
        size: &str,
        probe_size: &str,
    ) -> Self {
        let artifact = upload(l, component).await;
        let execution = app_run(l, &artifact, "upgrade-public-https", size).await;
        let backend = running(l, worker, &execution).await;
        let configuration = fs::read(backend.join("config.json")).unwrap();
        let config = json_file(&backend.join("config.json"));
        assert_named_spec(&config["spec"], size);
        assert_eq!(config["spec"]["http_runtime_digest"], runtime);
        assert_eq!(
            config["worker_release"]["runtime"]["runtime_sha256"],
            runtime
        );
        let this = Self {
            artifact,
            execution,
            initial: ownership(&backend),
            configuration,
            backend,
            runtime: runtime.into(),
            probe_size: probe_size.into(),
            phases: vec![],
            cutoff: None,
        };
        this.wait_progress(0).await;
        this
    }
    pub fn sequence(&self) -> u64 {
        progress(&fs::read(self.backend.join("output.log")).unwrap())
            .expect("public HTTPS continuity failed")
    }
    async fn wait_progress(&self, previous: u64) -> u64 {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let sequence = self.sequence();
            if sequence > previous {
                return sequence;
            }
            assert_eq!(
                json_file(&self.backend.join("status.json"))["state"],
                "running"
            );
            assert!(Instant::now() < deadline, "public HTTPS stopped advancing");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    pub fn cutover(&mut self) {
        let cutoff = native_status(&self.backend);
        assert!(
            n(&cutoff["network_deadline_ns"]) > 0 && n(&cutoff["egress_budget_revision"]) > 0,
            "source HTTPS authority was not acknowledged"
        );
        self.cutoff = Some(cutoff);
    }
    pub async fn observe(&mut self, l: &Lab, phase: &str, previous: u64) {
        let sequence = self.wait_progress(previous).await;
        let deadline = Instant::now() + Duration::from_secs(15);
        let native = loop {
            let native = native_status(&self.backend);
            if self.cutoff.as_ref().is_none_or(|old| {
                n(&native["egress_budget_revision"]) > n(&old["egress_budget_revision"])
                    && n(&native["network_deadline_ns"]) > n(&old["network_deadline_ns"])
            }) {
                break native;
            }
            assert!(
                Instant::now() < deadline,
                "replacement did not renew retained HTTPS network and byte authority"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        assert_eq!(ownership(&self.backend), self.initial);
        assert_eq!(native["network_active"], true);
        assert!(
            fs::read(self.backend.join("config.json")).unwrap() == self.configuration,
            "HTTPS configuration changed"
        );
        let row = l.execution(&self.execution).await;
        assert_eq!(row["generation"], 1);
        assert_eq!(row["public_https_runtime"], self.runtime);
        assert_eq!(
            row["observation"]["runtime_authority"]["runtime_digest"],
            self.runtime
        );
        assert_eq!(row["reserved"], true);
        self.phases.push(
            json!({"phase":phase,"identity":self.initial,"sequence":sequence,
            "runtime_digest":self.runtime,"network_deadline_ns":native["network_deadline_ns"],
            "budget_revision":native["egress_budget_revision"],"source_authority":self.cutoff}),
        );
        self.cutoff = None;
    }
    pub async fn probe(&self, l: &Lab, worker: &mut Worker, phase: &str, runtime: &str) -> Value {
        self.probe_at_size(l, worker, phase, runtime, &self.probe_size)
            .await
    }
    pub async fn probe_at_size(
        &self,
        l: &Lab,
        worker: &mut Worker,
        phase: &str,
        runtime: &str,
        size: &str,
    ) -> Value {
        let id = app_run(l, &self.artifact, &format!("https-{phase}"), size).await;
        let backend = running(l, worker, &id).await;
        let deadline = Instant::now() + Duration::from_secs(15);
        let sequence = loop {
            let sequence = progress(&fs::read(backend.join("output.log")).unwrap())
                .expect("new-runtime HTTPS request failed");
            if sequence > 0 {
                break sequence;
            }
            assert!(
                Instant::now() < deadline,
                "new runtime did not complete verified HTTPS"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        let config = json_file(&backend.join("config.json"));
        let profile = assert_named_spec(&config["spec"], size);
        assert_eq!(config["spec"]["http_runtime_digest"], runtime);
        assert_eq!(
            config["worker_release"]["runtime"]["runtime_sha256"],
            runtime
        );
        let identity = ownership(&backend);
        let kernel = limits::kernel(&backend);
        let memory_pages = n(&profile["wasm_linear_memory_mib"]) as u64 * 16;
        let memory =
            limits::memory_checks(&fs::read(backend.join("output.log")).unwrap(), memory_pages)
                .expect("fresh guest did not enforce its named memory upper bound");
        stop(l, &id).await;
        json!({"phase":phase,"execution":id,"identity":identity,"runtime_digest":runtime,"size":size,
            "kernel_scope":kernel,"memory_ceiling_pages":memory_pages,"memory_checks":memory,
            "sequence":sequence,"verified_public_https":true,"reservation_settled":true})
    }
    pub async fn revoke(&self, l: &Lab, node: &str) {
        self.sequence(); // Refuse any request failure before intentional revocation.
        assert_eq!(ownership(&self.backend), self.initial);
        assert_eq!(
            json_file(&self.backend.join("status.json"))["state"],
            "running"
        );
        l.store
            .node_mode(
                &l.operator,
                node,
                json!({"public_https_runtime":null,"retained_https_runtimes":[]}),
            )
            .await
            .unwrap();
        let row = l.execution(&self.execution).await;
        assert_eq!(row["desired"], "stopped");
        assert_eq!(row["generation"], 2);
        settled(l, &self.execution).await;
        let state = json_file(&self.backend.join("status.json"));
        assert!(matches!(
            s(&state["state"]),
            "stopped" | "exited" | "failed"
        ));
        assert_eq!(
            fs::read_to_string(self.backend.join("output.log"))
                .unwrap()
                .lines()
                .filter(|line| *line == "FENDERS_HTTPS_STARTED")
                .count(),
            1
        );
    }
    pub fn backend_id(&self) -> &str {
        s(&self.initial["id"])
    }
}

#[cfg(test)]
mod tests {
    use super::progress;
    #[test]
    fn continuity_parser_rejects_replay_loss_failure_and_unbounded_capture() {
        let start = "FENDERS_HTTPS_STARTED\n";
        let one = "FENDERS_HTTPS_PROGRESS sequence=1 status=200\n";
        assert_eq!(
            progress(format!("{start}{one}FENDERS_HTTPS_PROGRESS sequence=2").as_bytes()),
            Ok(1)
        );
        for value in [
            format!("{start}{one}{start}{one}"),
            format!("{start}{one}{one}"),
            format!("{start}FENDERS_HTTPS_PROGRESS sequence=2 status=200\n"),
            format!("{start}{one}FENDERS_HTTPS_FAILED denied\n"),
            format!("{start}FENDERS_HTTPS_PROGRESS sequence=1 status=500\n"),
            one.into(),
        ] {
            assert!(progress(value.as_bytes()).is_err());
        }
        assert!(progress(&vec![b'x'; 65537]).is_err());
    }
}
