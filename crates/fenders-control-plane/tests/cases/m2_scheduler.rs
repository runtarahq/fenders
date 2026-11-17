//! Acceptance-only process faults. Runs the production daemon against retained state.
//! No test routes, synthetic scheduler ticks or database timestamp changes.
use super::*;
use std::{
    path::Path,
    process::{Child, Command, Stdio},
    time::Duration,
};

struct Daemon {
    child: Child,
    origin: String,
}
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
impl Daemon {
    fn start(dsn: &str, state: &Path, output: &Path, name: &str) -> Self {
        let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = socket.local_addr().unwrap().port();
        drop(socket);
        let child = Command::new(
            std::env::var("FENDERS_M2_CONTROL_PLANE").expect("production daemon binary"),
        )
        .env("FENDERS_DATABASE_URL", dsn)
        .arg("--state")
        .arg(state)
        .args(["--dev-http", "--host", "127.0.0.1", "--port"])
        .arg(port.to_string())
        .stdout(Stdio::null())
        .stderr(fs::File::create(output.join(format!("scheduler-{name}.log"))).unwrap())
        .spawn()
        .unwrap();
        Self {
            child,
            origin: format!("http://127.0.0.1:{port}"),
        }
    }
    async fn status(&mut self, token: &str) -> Value {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        loop {
            assert!(
                self.child.try_wait().unwrap().is_none(),
                "scheduler process exited; inspect its log"
            );
            if let Ok(reply) = client
                .get(format!("{}/v1/control-plane/status", self.origin))
                .bearer_auth(token)
                .send()
                .await
                && reply.status().is_success()
            {
                let status: Value = serde_json::from_slice(&reply.bytes().await.unwrap()).unwrap();
                if status["components"].as_array().unwrap().iter().any(|c| {
                    c["component"] == "scheduler"
                        && c["iterations"].as_u64().unwrap_or(0) > 0
                        && c["failures"] == 0
                }) {
                    return json!({"pid":self.child.id(),"status":status});
                }
            }
            assert!(
                std::time::Instant::now() < deadline,
                "scheduler did not complete a healthy iteration"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

pub(super) async fn run(schema: String, state: PathBuf, output: PathBuf, token: String) {
    assert!(
        schema.starts_with("rust_test_")
            && schema
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    );
    let mut dsn = url::Url::parse(&std::env::var("FENDERS_TEST_DATABASE_URL").unwrap()).unwrap();
    assert!(
        !dsn.query_pairs().any(|(key, _)| key == "options"),
        "use a dedicated DSN without existing options"
    );
    dsn.query_pairs_mut()
        .append_pair("options", &format!("-csearch_path={schema}"));
    let binary = fs::read(std::env::var("FENDERS_M2_CONTROL_PLANE").unwrap()).unwrap();
    let mut daemons = vec![Daemon::start(dsn.as_str(), &state, &output, "initial")];
    let mut evidence =
        json!({"binary_sha256":digest(binary),"initial":daemons[0].status(&token).await});
    atomic_json(&output.join("scheduler-initial.json"), &evidence).unwrap();
    let mut stopped = false;
    let mut restarted = false;
    let mut sampled = false;
    loop {
        if output.join("finish-schedulers").exists() {
            break;
        }
        if !stopped && output.join("stop-scheduler").exists() {
            let mut exits = Vec::new();
            for daemon in &mut daemons {
                let pid = daemon.child.id();
                daemon.child.kill().unwrap();
                let exit = daemon.child.wait().unwrap();
                exits.push(json!({"pid":pid,"exit":exit.to_string()}));
            }
            daemons.clear();
            stopped = true;
            evidence["stopped"] =
                json!({"observed_at":chrono::Utc::now().to_rfc3339(),"exits":exits});
            atomic_json(&output.join("scheduler-stopped.json"), &evidence).unwrap();
        }
        if stopped && !restarted && output.join("restart-schedulers").exists() {
            daemons.push(Daemon::start(dsn.as_str(), &state, &output, "replica-a"));
            daemons.push(Daemon::start(dsn.as_str(), &state, &output, "replica-b"));
            let a = daemons[0].status(&token).await;
            let b = daemons[1].status(&token).await;
            evidence["restarted"] =
                json!({"observed_at":chrono::Utc::now().to_rfc3339(),"replicas":[a,b]});
            atomic_json(&output.join("scheduler-restarted.json"), &evidence).unwrap();
            restarted = true;
        }
        if restarted && !sampled && output.join("sample-schedulers").exists() {
            let a = daemons[0].status(&token).await;
            let b = daemons[1].status(&token).await;
            evidence["final"] = json!({"replicas":[a,b]});
            atomic_json(&output.join("scheduler-final.json"), &evidence).unwrap();
            sampled = true;
        }
        for daemon in &mut daemons {
            assert!(
                daemon.child.try_wait().unwrap().is_none(),
                "scheduler exited unexpectedly"
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
