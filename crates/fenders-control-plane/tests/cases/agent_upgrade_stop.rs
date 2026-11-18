//! A customer stop accepted with no manager must survive sealed fallback and
//! subsequent A/B ownership changes. Credentials and app configuration stay private.
use super::*;

pub(super) struct Stop {
    execution: String,
    backend: PathBuf,
    identity: Value,
    configuration_sha256: String,
    client: reqwest::Client,
    url: String,
    token: String,
    key: String,
    operation: Option<Value>,
    output_sha256: Option<String>,
    phases: Vec<Value>,
    initially_paused: bool,
    pause_key: String,
    pause_operation: Option<Value>,
    paused_kernel: Option<Value>,
}

pub(super) fn assignment(output: &Path, execution: &str) -> Value {
    let db = rusqlite::Connection::open_with_flags(
        output.join("state/agent/agent.sqlite3"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .unwrap();
    db.busy_timeout(Duration::from_secs(1)).unwrap();
    db.query_row("SELECT generation,backend_id,action_generation FROM assignments WHERE id=?", [execution], |r| {
        Ok(json!({"generation":r.get::<_,i64>(0)?,"backend":r.get::<_,String>(1)?,"action_generation":r.get::<_,i64>(2)?}))
    }).unwrap()
}

/// A PID may be reused, or remain as a zombie until its new parent reaps it.
/// Match the recorded boot/start identity and require a live non-zombie process.
pub(super) fn alive(pid: &Value, expected: &Value) -> bool {
    let stat = match fs::read_to_string(format!("/proc/{}/stat", n(pid))) {
        Ok(stat) => stat,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return false,
        Err(error) => panic!("cannot inspect stopped process: {error}"),
    };
    let fields: Vec<_> = stat
        .rsplit_once(')')
        .unwrap()
        .1
        .split_whitespace()
        .collect();
    fields[0] != "Z"
        && json!([
            fs::read_to_string("/proc/sys/kernel/random/boot_id")
                .unwrap()
                .trim(),
            fields[19]
        ]) == *expected
}

fn stopped(
    row: &Value,
    native: &Value,
    journal: &Value,
    backend: &str,
    generation: i64,
) -> std::result::Result<(), &'static str> {
    if row["state"] != "stopped"
        || row["desired"] != "stopped"
        || row["reserved"] != false
        || row["generation"] != generation
        || native["state"] != "stopped"
        || journal["generation"] != generation
        || journal["action_generation"] != generation
        || journal["backend"] != backend
    {
        return Err(
            "customer stop did not settle at its fenced generation on the original backend",
        );
    }
    Ok(())
}

fn paused(
    row: &Value,
    native: &Value,
    journal: &Value,
    backend: &str,
) -> std::result::Result<(), &'static str> {
    if row["state"] != "paused"
        || row["desired"] != "paused"
        || row["generation"] != 2
        || row["reserved"] != true
        || native["paused"] != true
        || native["idle"] != true
        || journal["generation"] != 2
        || journal["action_generation"] != 2
        || journal["backend"] != backend
    {
        return Err("paused execution lost its native pause, reservation or fenced backend");
    }
    Ok(())
}

impl Stop {
    pub async fn start(
        l: &Lab,
        worker: &mut Worker,
        artifact: &str,
        api: (reqwest::Client, String),
        initially_paused: bool,
    ) -> Self {
        let (principal, credential) = l.credential("editor", Some(&l.project)).await;
        let deployed = l
            .store
            .deploy_app(
                &principal,
                &l.tenant,
                &l.project,
                fenders_control_plane::apps::AppSubmission {
                    value: json!({"name":format!("stop-{}", &uid()[..8]),"artifact_id":artifact,"triggers":{"manual":false,"http":true}}),
                    key: &uid(),
                    domain: "apps.test",
                },
            )
            .await
            .unwrap();
        l.store.schedule().await.unwrap();
        let execution = s(&l.http(s(&deployed["resource_id"])).await["execution_id"]).to_owned();
        let backend = running(l, worker, &execution).await;
        let identity = ownership(&backend);
        let row = l.execution(&execution).await;
        assert_eq!(row["generation"], 1);
        assert_eq!(row["reserved"], true);
        assert_eq!(json_file(&backend.join("status.json"))["state"], "running");
        let configuration_sha256 = digest(fs::read(backend.join("config.json")).unwrap());
        Self {
            url: format!(
                "{}/v1/tenants/{}/projects/{}/executions/{execution}",
                api.1, l.tenant, l.project
            ),
            client: api.0,
            token: s(&credential["token"]).into(),
            key: uid(),
            execution,
            backend,
            identity,
            configuration_sha256,
            operation: None,
            output_sha256: None,
            phases: vec![],
            initially_paused,
            pause_key: uid(),
            pause_operation: None,
            paused_kernel: None,
        }
    }
    async fn request(&self) -> Value {
        self.request_action("stop", &self.key).await
    }
    async fn request_action(&self, action: &str, key: &str) -> Value {
        let response = self
            .client
            .post(format!("{}/{action}", self.url))
            .bearer_auth(&self.token)
            .header("Idempotency-Key", key)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let bytes = response.bytes().await.unwrap();
        assert!(
            bytes.len() <= 64 * 1024,
            "customer stop response exceeded bound"
        );
        serde_json::from_slice(&bytes).unwrap()
    }
    pub async fn prime(&mut self, l: &Lab, worker: &Worker, client: &transport::Client) {
        let reply = client
            .json(
                "POST",
                "/rpc/ingress",
                Some(&json!({"id":self.execution,"generation":1,
            "request":{"method":"GET","path":"/hello","headers":{},"body":""}})),
            )
            .await
            .unwrap();
        assert_eq!(reply["status"], 200);
        assert_eq!(reply["body"], "ZmVuZGVyczovaGVsbG8=");
        if self.initially_paused {
            let operation = self.request_action("pause", &self.pause_key).await;
            self.pause_operation = Some(operation);
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                let row = l.execution(&self.execution).await;
                if row["state"] == "paused" {
                    break;
                }
                assert!(
                    Instant::now() < deadline,
                    "customer pause did not settle before handover"
                );
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            let retry = self.request_action("pause", &self.pause_key).await;
            assert_eq!(retry["id"], self.pause_operation.as_ref().unwrap()["id"]);
            assert_eq!(retry["state"], "succeeded");
            self.paused_snapshot(l, worker, "paused_source").await;
        }
    }
    pub async fn queue(&mut self, l: &Lab, worker: &Worker) {
        if self.initially_paused {
            // Keep paused intent until the replacement reports that same native
            // pause under its sealed ownership. Only then submit the newer stop.
            self.paused_snapshot(l, worker, "paused_without_manager")
                .await;
            return;
        }
        self.queue_stop(l, worker, true).await;
    }
    fn stop_generation(&self) -> i64 {
        if self.initially_paused { 3 } else { 2 }
    }
    async fn paused_snapshot(&mut self, l: &Lab, worker: &Worker, phase: &str) {
        let row = l.execution(&self.execution).await;
        let native = native_status(&self.backend);
        let journal = assignment(&worker.output, &self.execution);
        paused(&row, &native, &journal, s(&self.identity["id"])).unwrap();
        assert_eq!(ownership(&self.backend), self.identity);
        assert_eq!(
            digest(fs::read(self.backend.join("config.json")).unwrap()),
            self.configuration_sha256
        );
        let kernel = limits::kernel(&self.backend);
        if let Some(before) = &self.paused_kernel {
            assert_eq!(&kernel, before);
        }
        self.paused_kernel = Some(kernel.clone());
        for kind in ["worker", "vmm"] {
            assert!(alive(
                &self.identity[format!("{kind}_pid")],
                &self.identity[format!("{kind}_identity")]
            ));
        }
        let output = digest(fs::read(self.backend.join("output.log")).unwrap());
        if let Some(before) = &self.output_sha256 {
            assert_eq!(&output, before, "paused VM produced new output");
        }
        self.output_sha256 = Some(output.clone());
        self.phases.push(json!({"phase":phase,"state":row["state"],"desired":row["desired"],"generation":row["generation"],
            "reserved":row["reserved"],"observation_sequence":row["observation"]["sequence"],"journal":journal,
            "native_paused":native["paused"],"native_idle":native["idle"],"kernel":kernel,
            "configuration_unchanged":true,"original_processes_alive":true,"output_sha256":output}));
    }
    async fn queue_stop(&mut self, l: &Lab, worker: &Worker, absent: bool) {
        assert_eq!(ownership(&self.backend), self.identity);
        self.operation = Some(self.request().await);
        assert_eq!(self.operation.as_ref().unwrap()["state"], "pending");
        let retry = self.request().await;
        assert_eq!(retry["id"], self.operation.as_ref().unwrap()["id"]);
        let row = l.execution(&self.execution).await;
        assert_eq!(row["desired"], "stopped");
        assert_eq!(row["generation"], self.stop_generation());
        let journal = assignment(&worker.output, &self.execution);
        if absent {
            assert_eq!(row["state"], "running");
            assert_eq!(
                row["reserved"], true,
                "stop acceptance prematurely freed capacity"
            );
            assert_eq!(journal["generation"], 1, "absent manager consumed the stop");
            assert_eq!(
                json_file(&self.backend.join("status.json"))["state"],
                "running"
            );
            for kind in ["worker", "vmm"] {
                assert!(alive(
                    &self.identity[format!("{kind}_pid")],
                    &self.identity[format!("{kind}_identity")]
                ));
            }
        } else if row["reserved"] == false {
            assert_eq!(row["state"], "stopped");
            assert_eq!(
                json_file(&self.backend.join("status.json"))["state"],
                "stopped",
                "reservation released without native termination"
            );
        }
        let reserved: i64 = sqlx::query_scalar("SELECT count(*) FROM executions WHERE reserved")
            .fetch_one(&l.store.pool)
            .await
            .unwrap();
        if absent {
            assert_eq!(reserved, 4);
        }
        self.phases.push(
            json!({"phase":if absent {"queued_without_manager"} else {"stop_queued_while_sealed"},"generation":row["generation"],
            "desired":row["desired"],"state":row["state"],"reserved":row["reserved"],
            "journal":journal,"total_reserved":reserved,"same_key_retry_operation":retry["id"],
            "manager_absent":absent}),
        );
    }
    pub async fn settle_sealed(
        &mut self,
        l: &Lab,
        worker: &Worker,
        client: &transport::Client,
        sealed: &Value,
    ) {
        if self.initially_paused {
            let previous = n(&self.phases.last().unwrap()["observation_sequence"]);
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                assert_eq!(
                    native_status(&self.backend)["paused"],
                    true,
                    "replacement resumed the paused VM"
                );
                let row = l.execution(&self.execution).await;
                if n(&row["observation"]["sequence"]) > previous {
                    break;
                }
                assert!(
                    Instant::now() < deadline,
                    "fallback did not report the retained pause"
                );
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            self.paused_snapshot(l, worker, "paused_fallback_before_stop")
                .await;
            assert_eq!(
                client
                    .json("POST", "/rpc/maintenance/status", Some(&json!({})))
                    .await
                    .unwrap(),
                *sealed
            );
            self.queue_stop(l, worker, false).await;
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let row = l.execution(&self.execution).await;
            let native = json_file(&self.backend.join("status.json"));
            if row["state"] == "stopped" && row["reserved"] == false && native["state"] == "stopped"
            {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "sealed fallback failed to apply the customer stop"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(
            client
                .json("POST", "/rpc/maintenance/status", Some(&json!({})))
                .await
                .unwrap(),
            *sealed,
            "stop processing implicitly reopened admission"
        );
        self.observe(l, worker, "sealed_fallback_before_resume")
            .await;
        // A stale request must not reach an already-stopped execution after the
        // generation changed, even though its original backend remains retained.
        for generation in 1..self.stop_generation() {
            let refused = client
                .json(
                    "POST",
                    "/rpc/ingress",
                    Some(&json!({"id":self.execution,"generation":generation,
            "request":{"method":"GET","path":"/hello","headers":{},"body":""}})),
                )
                .await
                .unwrap_err();
            assert_eq!(refused.status, StatusCode::CONFLICT);
        }
        self.phases.last_mut().unwrap()["stale_generation_ingress_refused"] = json!(true);
    }
    pub async fn observe(&mut self, l: &Lab, worker: &Worker, phase: &str) {
        let row = l.execution(&self.execution).await;
        let native = json_file(&self.backend.join("status.json"));
        let journal = assignment(&worker.output, &self.execution);
        stopped(
            &row,
            &native,
            &journal,
            s(&self.identity["id"]),
            self.stop_generation(),
        )
        .unwrap();
        assert_eq!(ownership(&self.backend), self.identity);
        assert_eq!(
            backend(&worker.output, &self.execution).as_ref(),
            Some(&self.backend)
        );
        assert_eq!(
            digest(fs::read(self.backend.join("config.json")).unwrap()),
            self.configuration_sha256
        );
        for kind in ["worker", "vmm"] {
            assert!(!alive(
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
                .filter(|line| *line == "request completed: /hello")
                .count(),
            1,
            "stopped VM request was replayed or never ran"
        );
        let output = digest(bytes);
        if let Some(previous) = &self.output_sha256 {
            assert_eq!(&output, previous, "stopped execution produced new output");
        }
        self.output_sha256 = Some(output.clone());
        let retry = self.request().await;
        assert_eq!(retry["id"], self.operation.as_ref().unwrap()["id"]);
        assert_eq!(retry["state"], "succeeded");
        if let Some(pause) = &self.pause_operation {
            let retry = self.request_action("pause", &self.pause_key).await;
            assert_eq!(retry["id"], pause["id"]);
            assert_eq!(retry["state"], "succeeded");
        }
        let row_after_retry = l.execution(&self.execution).await;
        assert_eq!(row_after_retry["generation"], self.stop_generation());
        assert_eq!(row_after_retry["desired"], "stopped");
        assert_eq!(row_after_retry["state"], "stopped");
        self.phases.push(json!({"phase":phase,"generation":row["generation"],"desired":row["desired"],
            "state":row["state"],"reserved":row["reserved"],"native_state":native["state"],"journal":journal,
            "same_key_retry_operation":retry["id"],"same_key_retry_state":retry["state"],
            "native_backend_count":backends.len(),"original_processes_gone":true,"configuration_unchanged":true,
            "output_sha256":output,"older_pause_retry_did_not_restore_intent":self.initially_paused}));
    }
    pub fn report(&self) -> Value {
        let mut report = json!({"execution":self.execution,"identity":self.identity,"configuration_sha256":self.configuration_sha256,
            "operation":self.operation.as_ref().unwrap()["id"],"customer_https_editor_stop":true,
            "initially_paused":self.initially_paused,"stop_generation":self.stop_generation(),"phases":self.phases});
        if let Some(pause) = &self.pause_operation {
            report["pause_operation"] = pause["id"].clone();
        }
        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pause_proof_requires_native_pause_idle_and_the_same_reserved_generation() {
        let row = json!({"state":"paused","desired":"paused","reserved":true,"generation":2});
        let native = json!({"paused":true,"idle":true});
        let journal = json!({"generation":2,"action_generation":2,"backend":"original"});
        assert!(paused(&row, &native, &journal, "original").is_ok());
        for (field, value) in [
            ("state", json!("running")),
            ("desired", json!("running")),
            ("reserved", json!(false)),
            ("generation", json!(1)),
            ("generation", json!(3)),
        ] {
            let mut invalid = row.clone();
            invalid[field] = value;
            assert!(
                paused(&invalid, &native, &journal, "original").is_err(),
                "{field}"
            );
        }
        for invalid in [
            json!({}),
            json!({"paused":false,"idle":true}),
            json!({"paused":true,"idle":false}),
        ] {
            assert!(paused(&row, &invalid, &journal, "original").is_err());
        }
        assert!(
            paused(
                &row,
                &native,
                &json!({"generation":2,"action_generation":1,"backend":"original"}),
                "original"
            )
            .is_err()
        );
        assert!(paused(&row, &native, &journal, "recreated").is_err());
        let stopped_row =
            json!({"state":"stopped","desired":"stopped","reserved":false,"generation":3});
        let stopped_journal = json!({"generation":3,"action_generation":3,"backend":"original"});
        assert!(
            stopped(
                &stopped_row,
                &json!({"state":"stopped"}),
                &stopped_journal,
                "original",
                3
            )
            .is_ok()
        );
        assert!(
            stopped(
                &stopped_row,
                &json!({"state":"stopped"}),
                &journal,
                "original",
                3
            )
            .is_err()
        );
        assert!(
            stopped(
                &stopped_row,
                &json!({"state":"stopped"}),
                &stopped_journal,
                "original",
                2
            )
            .is_err()
        );
    }
    #[test]
    fn stop_proof_requires_terminal_fenced_original_backend_and_settled_reservation() {
        let row = json!({"state":"stopped","desired":"stopped","reserved":false,"generation":2});
        let native = json!({"state":"stopped"});
        let journal = json!({"generation":2,"action_generation":2,"backend":"original"});
        assert!(stopped(&row, &native, &journal, "original", 2).is_ok());
        for (field, value) in [
            ("state", json!("running")),
            ("state", json!("lost")),
            ("desired", json!("running")),
            ("reserved", json!(true)),
            ("generation", json!(1)),
            ("generation", json!(3)),
        ] {
            let mut invalid = row.clone();
            invalid[field] = value;
            assert!(
                stopped(&invalid, &native, &journal, "original", 2).is_err(),
                "{field}"
            );
        }
        for (field, value) in [
            ("generation", json!(1)),
            ("action_generation", json!(1)),
            ("backend", json!("recreated")),
        ] {
            let mut invalid = journal.clone();
            invalid[field] = value;
            assert!(
                stopped(&row, &native, &invalid, "original", 2).is_err(),
                "{field}"
            );
        }
        assert!(stopped(&row, &json!({"state":"running"}), &journal, "original", 2).is_err());
    }
}
