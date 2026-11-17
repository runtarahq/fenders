//! Customer-visible logs from two real tenants sharing the upgrade worker.
//! Payload and credentials stay in memory; evidence contains only identities,
//! sequence bounds and hashes. Native capture reads never write its journal.
use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use fenders_control_plane::apps::AppSubmission;

#[derive(Clone, PartialEq, Eq)]
struct Record {
    sequence: i64,
    at_ms: i64,
    stream: String,
    bytes: Vec<u8>,
}
struct Capture {
    id: String,
    last: i64,
    closed: bool,
    records: Vec<Record>,
}
fn capture(backend: &Path) -> Capture {
    let mut db = rusqlite::Connection::open_with_flags(
        backend.join("output.sqlite3"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .unwrap();
    db.busy_timeout(Duration::from_secs(1)).unwrap();
    let tx = db.transaction().unwrap();
    let (id, last, closed): (String, i64, bool) = tx
        .query_row(
            "SELECT id,next_sequence-1,closed FROM capture WHERE singleton=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    let mut query = tx
        .prepare("SELECT sequence,at_ms,stream,data FROM records ORDER BY sequence LIMIT 1025")
        .unwrap();
    let records = query
        .query_map([], |r| {
            Ok(Record {
                sequence: r.get(0)?,
                at_ms: r.get(1)?,
                stream: r.get(2)?,
                bytes: r.get(3)?,
            })
        })
        .unwrap()
        .collect::<std::result::Result<Vec<_>, _>>()
        .unwrap();
    Capture {
        id,
        last,
        closed,
        records,
    }
}

struct View {
    tenant: String,
    project: String,
    app: String,
    execution: String,
    token: String,
    source: &'static str,
    cursor: Option<String>,
    records: Vec<Record>,
    capture: Option<String>,
    native_verified_through: i64,
}

/// The same bounded native verifier, pointed at a rolling service endpoint.
/// Reader credentials and payloads never enter the evidence object.
pub(crate) struct RollingLogs {
    view: View,
    backend: PathBuf,
}
impl RollingLogs {
    pub(crate) async fn new(
        l: &Lab,
        tenant: &str,
        project: &str,
        app: &str,
        execution: &str,
        backend: &Path,
    ) -> Self {
        let mut view = View::new(l, tenant, project, "http").await;
        view.app = app.into();
        view.execution = execution.into();
        Self {
            view,
            backend: backend.into(),
        }
    }
    async fn get(
        client: &reqwest::Client,
        origin: &str,
        view: &View,
        token: Option<&str>,
        cursor: Option<&str>,
    ) -> (StatusCode, Value) {
        let mut url = reqwest::Url::parse(&format!("{origin}{}", view.path())).unwrap();
        url.query_pairs_mut()
            .append_pair("execution_id", &view.execution)
            .append_pair("limit", "7");
        if let Some(cursor) = cursor {
            url.query_pairs_mut().append_pair("after", cursor);
        }
        let mut request = client.get(url);
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        let response = request.send().await.unwrap();
        let status = response.status();
        assert_eq!(response.headers()["cache-control"], "no-store");
        let body = response.bytes().await.unwrap();
        assert!(body.len() <= 256 * 1024);
        (status, serde_json::from_slice(&body).unwrap())
    }
    async fn observe(
        &mut self,
        l: &Lab,
        client: &reqwest::Client,
        origin: &str,
        complete: bool,
    ) -> Value {
        let source = capture(&self.backend);
        match &self.view.capture {
            Some(id) => assert_eq!(id, &source.id),
            None => self.view.capture = Some(source.id.clone()),
        }
        let previous = self.view.records.len();
        let page = tokio::time::timeout(Duration::from_secs(45), async {
            loop {
                let (status, page) = Self::get(
                    client,
                    origin,
                    &self.view,
                    Some(&self.view.token),
                    self.view.cursor.as_deref(),
                )
                .await;
                assert_eq!(status, StatusCode::OK);
                self.view
                    .append(&page["items"])
                    .expect("rolling logs lost sequence, scope or content");
                self.view.cursor = Some(s(&page["next"]).into());
                assert_eq!(page["collection"]["executions"], 1);
                assert_eq!(page["collection"]["source_gaps"], 0);
                assert_eq!(page["collection"]["truncated_captures"], 0);
                if self.view.records.len() as i64 >= source.last
                    && (!complete || page["collection"]["complete"] == 1)
                {
                    break page;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .unwrap();
        if !complete {
            assert!(
                self.view.records.len() > previous,
                "no new customer logs after rollout"
            );
        }
        self.view
            .verify_native(&source)
            .expect("rolling customer logs differ from bounded native capture");
        if complete {
            assert!(source.closed);
            assert_eq!(self.view.records.len() as i64, source.last);
        }
        let prefix: Vec<u8> = self
            .view
            .records
            .iter()
            .take(source.last as usize)
            .flat_map(|r| r.bytes.iter().copied())
            .collect();
        let acknowledged: i64 = sqlx::query_scalar(
            "SELECT acknowledged FROM execution_log_sources WHERE execution_id=$1",
        )
        .bind(&self.view.execution)
        .fetch_one(&l.store.pool)
        .await
        .unwrap();
        assert!(acknowledged >= source.last);
        json!({"tenant":self.view.tenant,"app":self.view.app,"execution":self.view.execution,
            "capture":source.id,"native_sequence":source.last,"verified_through":self.view.native_verified_through,
            "payload_sha256":digest(prefix),"source_acknowledged":acknowledged,"complete":page["collection"]["complete"]})
    }
    pub(crate) async fn observe_pair(
        l: &Lab,
        client: &reqwest::Client,
        origin: &str,
        alpha: &mut Self,
        beta: &mut Self,
        phase: &str,
    ) -> Value {
        let complete = phase == "closed";
        let a = alpha.observe(l, client, origin, complete).await;
        let b = beta.observe(l, client, origin, complete).await;
        for (view, foreign) in [(&alpha.view, &beta.view), (&beta.view, &alpha.view)] {
            assert_eq!(
                Self::get(client, origin, view, None, None).await.0,
                StatusCode::UNAUTHORIZED
            );
            assert_eq!(
                Self::get(client, origin, view, Some(&foreign.token), None)
                    .await
                    .0,
                StatusCode::NOT_FOUND
            );
            assert_eq!(
                Self::get(
                    client,
                    origin,
                    view,
                    Some(&view.token),
                    foreign.cursor.as_deref()
                )
                .await
                .0,
                StatusCode::BAD_REQUEST
            );
        }
        json!({"phase":phase,"views":[a,b],"anonymous_foreign_tenant_and_foreign_cursor_denied":true})
    }
}
impl View {
    async fn new(l: &Lab, tenant: &str, project: &str, source: &'static str) -> Self {
        let key = l
            .store
            .issue_credential(
                &l.operator,
                tenant,
                serde_json::from_value(json!({
            "name":"upgrade-log-reader","role":"viewer","project_id":project}))
                .unwrap(),
            )
            .await
            .unwrap();
        Self {
            tenant: tenant.into(),
            project: project.into(),
            app: String::new(),
            execution: String::new(),
            token: s(&key["token"]).into(),
            source,
            cursor: None,
            records: vec![],
            capture: None,
            native_verified_through: 0,
        }
    }
    fn path(&self) -> String {
        format!(
            "/v1/tenants/{}/projects/{}/apps/{}/logs",
            self.tenant, self.project, self.app
        )
    }
    fn append(&mut self, items: &Value) -> std::result::Result<(), &'static str> {
        for item in items.as_array().ok_or("invalid log page")? {
            let sequence = self.records.len() as i64 + 1;
            if item["execution_id"] != self.execution
                || item["sequence"] != sequence
                || item["id"] != format!("{}:{sequence}", self.execution)
                || item["source"] != self.source
                || !matches!(s(&item["stream"]), "stdout" | "stderr")
                || !item["gap_from"].is_null()
            {
                return Err("log replay, gap or scope mismatch");
            }
            self.records.push(Record {
                sequence,
                at_ms: item["at_ms"].as_i64().ok_or("invalid log timestamp")?,
                stream: s(&item["stream"]).into(),
                bytes: STANDARD
                    .decode(s(&item["bytes"]))
                    .map_err(|_| "invalid log encoding")?,
            });
        }
        Ok(())
    }
    fn body(&self) -> Vec<u8> {
        self.records
            .iter()
            .flat_map(|r| r.bytes.iter().copied())
            .collect()
    }
    /// The qualified native journal retains at most 1024 records / 1 MiB.
    /// Eviction is safe evidence only when this reader already compared every
    /// evicted record with an earlier native snapshot. Never infer that proof
    /// merely from a later successful customer API read.
    fn verify_native(&mut self, source: &Capture) -> std::result::Result<(), &'static str> {
        if self.capture.as_deref() != Some(source.id.as_str())
            || source.last < 1
            || source.last < self.native_verified_through
            || source.records.is_empty()
            || source.records.len() > 1024
        {
            return Err("native capture identity, sequence or retention bound changed");
        }
        let first = source.records[0].sequence;
        if first < 1 || first - 1 > self.native_verified_through {
            return Err("native records were evicted before independent verification");
        }
        let mut bytes = 0_usize;
        for (offset, record) in source.records.iter().enumerate() {
            let sequence = first
                .checked_add(offset as i64)
                .ok_or("native sequence overflow")?;
            bytes = bytes
                .checked_add(record.bytes.len())
                .ok_or("native payload overflow")?;
            if record.sequence != sequence
                || record.sequence > source.last
                || record.bytes.is_empty()
                || record.bytes.len() > 8192
                || bytes > 1024 * 1024
                || !matches!(record.stream.as_str(), "stdout" | "stderr")
            {
                return Err("native retained records are incomplete or out of bounds");
            }
            let index = usize::try_from(sequence - 1).map_err(|_| "invalid native sequence")?;
            if self.records.get(index) != Some(record) {
                return Err(
                    "customer bytes, timestamps or streams differ from retained native records",
                );
            }
        }
        if source.records.last().unwrap().sequence != source.last {
            return Err("native retained suffix does not reach its capture sequence");
        }
        self.native_verified_through = source.last;
        Ok(())
    }
}

pub struct Logs {
    alpha: View,
    beta: View,
    client: reqwest::Client,
    origin: String,
    _server: Task<()>,
    pub phases: Vec<Value>,
}
impl Logs {
    pub(super) fn customer_client(&self) -> (reqwest::Client, String) {
        (self.client.clone(), self.origin.clone())
    }
    pub async fn start(l: &Lab, pki: &Path) -> Self {
        let tenant = l
            .store
            .create_tenant(
                &l.operator,
                serde_json::from_value(json!({"name":"upgrade-beta",
            "allowance":{"cpu_percent":200,"memory_mib":1024,"instances":2,
                "storage_bytes":20000000000i64,"transfer_bytes":10000000}}))
                .unwrap(),
            )
            .await
            .unwrap();
        let tenant = s(&tenant["id"]);
        let project = l
            .store
            .create_project(
                &l.operator,
                tenant,
                serde_json::from_value(json!({"name":"logs"})).unwrap(),
            )
            .await
            .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("https://{}", listener.local_addr().unwrap());
        let config =
            transport::server_config(&pki.join("control.pem"), &pki.join("control.key"), None)
                .unwrap();
        let router = api::router(l.store.clone());
        let server = Task(tokio::spawn(async move {
            transport::serve_tls(listener, config, router)
                .await
                .unwrap()
        }));
        let client = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .add_root_certificate(
                reqwest::Certificate::from_pem(&fs::read(pki.join("ca.pem")).unwrap()).unwrap(),
            )
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        Self {
            alpha: View::new(l, &l.tenant, &l.project, "manual").await,
            beta: View::new(l, tenant, s(&project["id"]), "http").await,
            client,
            origin,
            _server: server,
            phases: vec![],
        }
    }
    pub async fn http(&mut self, l: &Lab, component: &Path, size: &str) -> Value {
        let artifact = l
            .store
            .upload(
                &l.operator,
                &self.beta.tenant,
                &self.beta.project,
                &fs::read(component).unwrap(),
            )
            .await
            .unwrap();
        let artifact = s(&artifact["id"]);
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
                "beta component did not validate"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let deployed = l
            .store
            .deploy_app(
                &l.operator,
                &self.beta.tenant,
                &self.beta.project,
                AppSubmission {
                    value: json!({"name":"beta-http-logs","artifact_id":artifact,
                "configuration":{"size":size,"keep_warm":true,"env":{"HTTP_HOLD_MS":"200"}},
                "triggers":{"http":true,"manual":false}}),
                    key: &uid(),
                    domain: "apps.test",
                },
            )
            .await
            .unwrap();
        self.beta.app = s(&deployed["resource_id"]).into();
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let http = l
                .store
                .app_http_status(
                    &l.operator,
                    &self.beta.tenant,
                    &self.beta.project,
                    &self.beta.app,
                )
                .await
                .unwrap();
            if let Some(execution) = http["execution_id"].as_str() {
                self.beta.execution = execution.into();
                return json!({"resource_id":execution});
            }
            assert!(
                Instant::now() < deadline,
                "beta HTTP placement did not appear"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    pub async fn bind_alpha(&mut self, l: &Lab, execution: &str) {
        self.alpha.execution = execution.into();
        self.alpha.app =
            sqlx::query_scalar("SELECT app_id FROM app_execution_contexts WHERE execution_id=$1")
                .bind(execution)
                .fetch_one(&l.store.pool)
                .await
                .unwrap();
    }
    async fn get(
        &self,
        view: &View,
        token: Option<&str>,
        cursor: Option<&str>,
    ) -> (StatusCode, Value) {
        let mut url = reqwest::Url::parse(&format!("{}{}", self.origin, view.path())).unwrap();
        url.query_pairs_mut()
            .append_pair("execution_id", &view.execution)
            .append_pair("limit", "7");
        if let Some(cursor) = cursor {
            url.query_pairs_mut().append_pair("after", cursor);
        }
        let mut request = self.client.get(url);
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        let response = request
            .send()
            .await
            .expect("customer log HTTPS request failed");
        let status = response.status();
        assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
        let bytes = response.bytes().await.unwrap();
        assert!(
            bytes.len() <= 256 * 1024,
            "customer log response exceeded its bound"
        );
        (
            status,
            serde_json::from_slice(&bytes).expect("invalid customer log JSON"),
        )
    }
    async fn pull(&self, view: &mut View, target: i64, complete: bool) -> Value {
        let deadline = Instant::now() + Duration::from_secs(45);
        loop {
            let (status, page) = self
                .get(view, Some(&view.token), view.cursor.as_deref())
                .await;
            assert_eq!(status, StatusCode::OK);
            view.append(&page["items"])
                .expect("customer logs lost identity, sequence or isolation");
            view.cursor = Some(s(&page["next"]).into());
            assert_eq!(page["collection"]["executions"], 1);
            assert_eq!(page["collection"]["source_gaps"], 0);
            assert_eq!(page["collection"]["truncated_captures"], 0);
            if view.records.len() as i64 >= target
                && (!complete || page["collection"]["complete"] == 1)
            {
                return page;
            }
            assert!(
                Instant::now() < deadline,
                "customer log delivery did not reach its native capture"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    pub async fn observe(
        &mut self,
        l: &Lab,
        phase: &str,
        alpha_backend: &Path,
        beta_backend: &Path,
    ) {
        // Move views out temporarily so network reads borrow neither mutable
        // cursor nor journal state across another collector's work.
        let mut alpha = std::mem::replace(&mut self.alpha, placeholder());
        let mut beta = std::mem::replace(&mut self.beta, placeholder());
        let mut measurements = vec![];
        for (view, backend) in [(&mut alpha, alpha_backend), (&mut beta, beta_backend)] {
            let source = capture(backend);
            if let Some(id) = &view.capture {
                assert_eq!(id, &source.id);
            } else {
                view.capture = Some(source.id.clone());
            }
            let old = view.records.len();
            self.pull(view, source.last, false).await;
            assert!(
                view.records.len() > old,
                "no customer-visible progress across handover"
            );
            let previously_verified = view.native_verified_through;
            view.verify_native(&source)
                .expect("customer/native retention continuity failed");
            let row: Value = sqlx::query_scalar(
                "SELECT to_jsonb(s) FROM execution_log_sources s WHERE execution_id=$1",
            )
            .bind(&view.execution)
            .fetch_one(&l.store.pool)
            .await
            .unwrap();
            assert_eq!(row["capture_id"], source.id);
            let body = view.body();
            let counter = if view.source == "manual" {
                Some(
                    https::progress(&body).expect("customer HTTPS log counter replayed or skipped"),
                )
            } else {
                None
            };
            measurements.push(json!({"tenant":view.tenant,"app":view.app,"execution":view.execution,
                "capture_id":source.id,"native_sequence":source.last,"customer_records":view.records.len(),
                "source_acknowledged":row["acknowledged"],"payload_sha256":digest(&body),"public_https_counter":counter,
                "native_first_sequence":source.records[0].sequence,"native_retained_records":source.records.len(),
                "previously_verified_prefix":previously_verified,"native_verified_through":view.native_verified_through}));
        }
        for (view, foreign) in [(&alpha, &beta), (&beta, &alpha)] {
            assert_eq!(self.get(view, None, None).await.0, StatusCode::UNAUTHORIZED);
            assert_eq!(
                self.get(view, Some(&foreign.token), None).await.0,
                StatusCode::NOT_FOUND
            );
            assert_eq!(
                self.get(view, Some(&view.token), foreign.cursor.as_deref())
                    .await
                    .0,
                StatusCode::BAD_REQUEST
            );
        }
        assert!(!String::from_utf8_lossy(&alpha.body()).contains("FENDERS_HTTP_HOLD_STARTED"));
        assert!(!String::from_utf8_lossy(&beta.body()).contains("FENDERS_HTTPS_PROGRESS"));
        self.phases.push(
            json!({"phase":phase,"views":measurements,"https_customer_api":true,
            "cross_tenant_and_cursor_denial":true,"unauthenticated_denial":true}),
        );
        self.alpha = alpha;
        self.beta = beta;
    }
    pub async fn stop_http(&self, l: &Lab) {
        let app = l
            .store
            .app(
                &l.operator,
                &self.beta.tenant,
                &self.beta.project,
                &self.beta.app,
            )
            .await
            .unwrap();
        l.store
            .app_lifecycle(
                &l.operator,
                &self.beta.tenant,
                &self.beta.project,
                &self.beta.app,
                json!({"expected_revision":app["revision"],"desired":"stopped"}),
                &uid(),
            )
            .await
            .unwrap();
    }
    pub async fn finish(&mut self, alpha_backend: &Path, beta_backend: &Path) -> Value {
        let mut alpha = std::mem::replace(&mut self.alpha, placeholder());
        let mut beta = std::mem::replace(&mut self.beta, placeholder());
        let mut final_views = vec![];
        for (view, backend) in [(&mut alpha, alpha_backend), (&mut beta, beta_backend)] {
            let deadline = Instant::now() + Duration::from_secs(15);
            let source = loop {
                let source = capture(backend);
                if source.closed {
                    break source;
                }
                assert!(
                    Instant::now() < deadline,
                    "native log capture did not close"
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
            };
            assert_eq!(view.capture.as_deref(), Some(source.id.as_str()));
            let page = self.pull(view, source.last, true).await;
            assert_eq!(view.records.len() as i64, source.last);
            let previously_verified = view.native_verified_through;
            view.verify_native(&source)
                .expect("final native retained suffix was not verified");
            final_views.push(json!({"tenant":view.tenant,"app":view.app,"execution":view.execution,
                "capture_id":source.id,"end_sequence":source.last,"customer_records":view.records.len(),
                "collection_complete":page["collection"]["complete"],"payload_sha256":digest(view.body()),
                "native_first_sequence":source.records[0].sequence,"native_retained_records":source.records.len(),
                "previously_verified_prefix":previously_verified,"native_verified_through":view.native_verified_through}));
        }
        self.alpha = alpha;
        self.beta = beta;
        json!({"phases":self.phases,"final":final_views,"two_tenants_shared_worker":true})
    }
}
fn placeholder() -> View {
    View {
        tenant: String::new(),
        project: String::new(),
        app: String::new(),
        execution: String::new(),
        token: String::new(),
        source: "",
        cursor: None,
        records: vec![],
        capture: None,
        native_verified_through: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_retention_requires_previously_verified_prefix_and_exact_bounded_suffix() {
        let records: Vec<_> = (1..=1025)
            .map(|sequence| Record {
                sequence,
                at_ms: sequence,
                stream: "stdout".into(),
                bytes: b"record\n".to_vec(),
            })
            .collect();
        let mut view = placeholder();
        view.capture = Some("capture".into());
        view.records = records.clone();
        let first = Capture {
            id: "capture".into(),
            last: 1000,
            closed: false,
            records: records[..1000].to_vec(),
        };
        view.verify_native(&first).unwrap();
        assert_eq!(view.native_verified_through, 1000);
        let suffix = || Capture {
            id: "capture".into(),
            last: 1025,
            closed: true,
            records: records[1..].to_vec(),
        };
        let mut unseen = placeholder();
        unseen.capture = Some("capture".into());
        unseen.records = records.clone();
        assert!(
            unseen.verify_native(&suffix()).is_err(),
            "customer API success alone cannot prove an evicted native prefix"
        );
        for fault in [
            "capture",
            "gap",
            "tail",
            "bytes",
            "timestamp",
            "stream",
            "unbounded",
            "regression",
        ] {
            let mut source = suffix();
            match fault {
                "capture" => source.id = "new-capture".into(),
                "gap" => {
                    source.records.remove(10);
                }
                "tail" => {
                    source.records.pop();
                }
                "bytes" => source.records[10].bytes = b"changed".to_vec(),
                "timestamp" => source.records[10].at_ms += 1,
                "stream" => source.records[10].stream = "stderr".into(),
                "unbounded" => source.records = records.clone(),
                "regression" => source.last = 999,
                _ => unreachable!(),
            }
            assert!(view.verify_native(&source).is_err(), "{fault}");
            assert_eq!(view.native_verified_through, 1000);
        }
        view.verify_native(&suffix()).unwrap();
        assert_eq!(view.native_verified_through, 1025);
    }
    #[test]
    fn customer_record_verifier_rejects_duplicates_gaps_foreign_context_and_invalid_bytes() {
        let mut view = placeholder();
        view.execution = "execution".into();
        view.source = "manual";
        let row = json!({"execution_id":"execution","sequence":1,"id":"execution:1","source":"manual",
            "stream":"stdout","gap_from":null,"at_ms":1,"bytes":"b25l"});
        for (key, value) in [
            ("execution_id", json!("foreign")),
            ("sequence", json!(2)),
            ("id", json!("foreign:1")),
            ("source", json!("http")),
            ("stream", json!("gap")),
            ("gap_from", json!(1)),
            ("bytes", json!("?")),
        ] {
            let mut invalid = row.clone();
            invalid[key] = value;
            assert!(view.append(&json!([invalid])).is_err(), "{key}");
        }
        view.append(&json!([row.clone()])).unwrap();
        assert!(view.append(&json!([row])).is_err());
        assert_eq!(view.body(), b"one");
    }
}
