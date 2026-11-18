//! Kernel controls and transactional admission on the same live upgrade worker.
//! Never export execution configurations, environment values or credentials.
use super::*;

fn expected_controls(spec: &Value) -> BTreeMap<&'static str, String> {
    BTreeMap::from([
        (
            "cpu.max",
            format!("{} 100000", n(&spec["cpu_percent"]) * 1000),
        ),
        (
            "memory.max",
            (n(&spec["host_memory_mib"]) * 1024 * 1024).to_string(),
        ),
        ("memory.swap.max", "0".into()),
        ("pids.max", "16".into()),
        ("memory.oom.group", "1".into()),
    ])
}

pub(super) fn kernel(backend: &Path) -> Value {
    let config = json_file(&backend.join("config.json"));
    let status = ownership(backend);
    let group = Path::new(s(&config["cgroup"]));
    let relative = group.strip_prefix("/sys/fs/cgroup").unwrap();
    assert!(
        relative
            .components()
            .all(|c| matches!(c, std::path::Component::Normal(_)))
    );
    let metadata = fs::symlink_metadata(group).unwrap();
    assert!(metadata.is_dir() && !metadata.file_type().is_symlink());
    let controls = expected_controls(&config["spec"]);
    for (file, expected) in &controls {
        assert_eq!(
            fs::read_to_string(group.join(file)).unwrap().trim(),
            expected
        );
    }
    let membership = fs::read_to_string(format!("/proc/{}/cgroup", n(&status["vmm_pid"]))).unwrap();
    assert!(
        membership
            .lines()
            .any(|line| line == format!("0::/{}", relative.display())),
        "VMM escaped its configured cgroup"
    );
    json!({"backend":status["id"],"cgroup":group,"device":metadata.dev(),"inode":metadata.ino(),
        "vmm_pid":status["vmm_pid"],"controls":controls})
}

/// Each successful HTTPS request must also reject growth just beyond the
/// declared ceiling. This does not fill or discard the allocator's live heap.
pub(super) fn memory_checks(bytes: &[u8], pages: u64) -> std::result::Result<u64, &'static str> {
    let progress = https::progress(bytes)?;
    let text = std::str::from_utf8(bytes).map_err(|_| "invalid memory receipt encoding")?;
    let complete = text.rsplit_once('\n').map(|(s, _)| s).unwrap_or("");
    let mut sequence = 0;
    for line in complete.lines() {
        if let Some(receipt) = line.strip_prefix("FENDERS_MEMORY_CEILING ") {
            let receipt: Value =
                serde_json::from_str(receipt).map_err(|_| "invalid memory receipt")?;
            if receipt["sequence"] != sequence + 1
                || receipt["maximum_pages"] != pages
                || receipt["beyond_limit_rejected"] != true
            {
                return Err("memory ceiling changed, skipped or replayed");
            }
            sequence += 1;
        }
    }
    if progress == 0 || sequence < progress || sequence > progress + 1 {
        return Err("missing memory ceiling evidence");
    }
    Ok(sequence)
}

async fn reservations(l: &Lab) -> Value {
    sqlx::query_scalar("SELECT COALESCE(jsonb_agg(jsonb_build_object('id',id,'tenant',tenant_id,'project',project_id,'node',node_id,'cpu_percent',cpu_percent,'memory_mib',memory_mib) ORDER BY id),'[]'::jsonb) FROM executions WHERE reserved")
        .fetch_one(&l.store.pool).await.unwrap()
}

pub struct Limits {
    kernels: Vec<(PathBuf, Value)>,
    reservations: Value,
    beta: Principal,
    scope: Value,
    allowance: Value,
    node: String,
    beta_size: Value,
    memory_pages: u64,
    pub phases: Vec<Value>,
}
impl Limits {
    pub async fn start(
        l: &Lab,
        node: &str,
        http: &str,
        backends: &[&Path],
        http_size: &str,
        public_size: &str,
    ) -> Self {
        let scope: Value = sqlx::query_scalar("SELECT jsonb_build_object('tenant',tenant_id,'project',project_id,'artifact',spec->>'artifact_id') FROM executions WHERE id=$1")
            .bind(http).fetch_one(&l.store.pool).await.unwrap();
        assert_ne!(scope["tenant"], l.tenant);
        let beta_config = json_file(&backends[0].join("config.json"));
        let beta_size = assert_named_spec(&beta_config["spec"], http_size);
        let key = l
            .store
            .create_api_key(&l.operator, s(&scope["tenant"]), serde_json::from_value(json!({"name":"upgrade-quota-check","project_id":scope["project"],"permissions":["read","apps:write","runs:write","connections:write","secrets:write"],"ttl_seconds":86400})).unwrap(), &uid())
            .await
            .unwrap();
        let beta = l.store.authenticate(s(&key["token"])).await.unwrap();
        let usage = l
            .store
            .usage(&beta, s(&scope["tenant"]), Some(s(&scope["project"])))
            .await
            .unwrap();
        let mut allowance = usage["allowance"].clone();
        allowance.as_object_mut().unwrap().remove("id");
        allowance.as_object_mut().unwrap().remove("name");
        let initial = reservations(l).await;
        assert_eq!(initial.as_array().unwrap().len(), 3);
        assert!(
            initial
                .as_array()
                .unwrap()
                .iter()
                .all(|r| r["node"] == node)
        );
        Self {
            kernels: backends
                .iter()
                .map(|b| (b.to_path_buf(), kernel(b)))
                .collect(),
            reservations: initial,
            beta,
            scope,
            allowance,
            node: node.into(),
            beta_size,
            memory_pages: n(&named_size(public_size)["wasm_linear_memory_mib"]) as u64 * 16,
            phases: vec![],
        }
    }

    pub async fn observe(
        &mut self,
        l: &Lab,
        phase: &str,
        output: &Path,
        https_backend: &Path,
        http_artifact: &str,
    ) {
        let mut kernels = vec![];
        for (backend, original) in &self.kernels {
            let current = kernel(backend);
            assert_eq!(
                &current, original,
                "execution resource scope changed across handover"
            );
            kernels.push(current);
        }
        assert_eq!(
            reservations(l).await,
            self.reservations,
            "continuity reservations changed"
        );
        let capacity:Value=sqlx::query_scalar("SELECT jsonb_build_object('cpu_percent',cpu_percent,'memory_mib',memory_mib,'instances',instances) FROM nodes WHERE id=$1")
            .bind(&self.node).fetch_one(&l.store.pool).await.unwrap();
        assert_eq!(
            capacity,
            json!({"cpu_percent":200,"memory_mib":1024,"instances":4})
        );
        let tenant = s(&self.scope["tenant"]);
        let project = s(&self.scope["project"]);
        let usage = l
            .store
            .usage(&self.beta, tenant, Some(project))
            .await
            .unwrap();
        assert_eq!(
            usage["reserved"],
            json!({"cpu_percent":self.beta_size["cpu_percent"],"memory_mib":self.beta_size["reservation_memory_mib"],"instances":1})
        );
        // Tighten one allowance dimension at a time to its actual reservation,
        // through the normal operator API. Other dimensions retain headroom.
        let mut quota_cases = vec![];
        for dimension in ["cpu_percent", "memory_mib", "instances"] {
            let mut limit = self.allowance.clone();
            limit[dimension] = usage["reserved"][dimension].clone();
            l.store
                .update_allowance(
                    &l.operator,
                    tenant,
                    serde_json::from_value(json!({"allowance":limit})).unwrap(),
                )
                .await
                .unwrap();
            let applied = l
                .store
                .usage(&self.beta, tenant, Some(project))
                .await
                .unwrap();
            for (field, expected) in limit.as_object().unwrap() {
                assert_eq!(
                    &applied["allowance"][field], expected,
                    "quota dimension did not apply independently"
                );
            }
            l.store
                .update_allowance(
                    &l.operator,
                    tenant,
                    serde_json::from_value(json!({"allowance":self.allowance})).unwrap(),
                )
                .await
                .unwrap();
            let restored = l
                .store
                .usage(&self.beta, tenant, Some(project))
                .await
                .unwrap();
            for (field, expected) in self.allowance.as_object().unwrap() {
                assert_eq!(
                    &restored["allowance"][field], expected,
                    "quota allowance was not restored"
                );
            }
            assert_eq!(reservations(l).await, self.reservations);
            quota_cases.push(json!({"dimension":dimension,"applied_allowance":limit,
                "restored_allowance":self.allowance,"concurrent_refusals":2,
                "independent_customer_usage_readback":true}));
        }
        // Alpha has quota headroom, but 100% cannot fit beside the original
        // profiles on the 200% node. No other node constraint may be binding.
        let used_cpu: i64 = self
            .reservations
            .as_array()
            .unwrap()
            .iter()
            .map(|r| n(&r["cpu_percent"]))
            .sum();
        let used_memory: i64 = self
            .reservations
            .as_array()
            .unwrap()
            .iter()
            .map(|r| n(&r["memory_mib"]))
            .sum();
        assert!(
            used_cpu + 100 > 200
                && used_memory + 88 <= 1024
                && self.reservations.as_array().unwrap().len() < 4
        );
        let queued = l.create(&uid(),json!({"artifact_id":http_artifact,"mode":"http","cpu_percent":100,"lifetime_seconds":180})).await;
        let id = s(&queued["resource_id"]);
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let reason: Option<String> =
                sqlx::query_scalar("SELECT reason FROM execution_placement WHERE execution_id=$1")
                    .bind(id)
                    .fetch_optional(&l.store.pool)
                    .await
                    .unwrap();
            if reason.as_deref() == Some("placement-capacity") {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "node capacity decision did not appear"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let placement:Value=sqlx::query_scalar("SELECT jsonb_build_object('node',node_id,'state',state,'reserved',reserved) FROM executions WHERE id=$1")
            .bind(id).fetch_one(&l.store.pool).await.unwrap();
        assert!(
            placement["node"].is_null()
                && placement["state"] == "queued"
                && placement["reserved"] == true
        );
        assert!(
            backend(output, id).is_none(),
            "over-capacity probe acquired a backend"
        );
        l.stop(id, &uid()).await.unwrap();
        assert_eq!(reservations(l).await, self.reservations);
        let memory = memory_checks(
            &fs::read(https_backend.join("output.log")).unwrap(),
            self.memory_pages,
        )
        .expect("guest memory limit did not survive handover");
        self.phases.push(json!({"phase":phase,"node":self.node,"node_capacity":capacity,"kernel_scopes":kernels,
            "reservations":self.reservations,"tenant_quota_cases":quota_cases,
            "node_cpu_capacity_probe":id,"node_cpu_capacity_refused":true,"memory_ceiling_pages":self.memory_pages,
            "continuity_cpu_percent":used_cpu,
            "memory_checks":memory,"tenant_allowance_restored":true}));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn memory_ceiling_evidence_requires_every_success_and_rejects_changed_limits_or_replay() {
        let receipt = json!({"sequence":1,"maximum_pages":128,"beyond_limit_rejected":true});
        let body = |r: &Value| {
            format!(
                "FENDERS_HTTPS_STARTED\nFENDERS_MEMORY_CEILING {r}\nFENDERS_HTTPS_PROGRESS sequence=1 status=200\n"
            )
        };
        assert_eq!(memory_checks(body(&receipt).as_bytes(), 128), Ok(1));
        let mut small = receipt.clone();
        small["maximum_pages"] = json!(64);
        assert_eq!(memory_checks(body(&small).as_bytes(), 64), Ok(1));
        assert!(memory_checks(body(&small).as_bytes(), 128).is_err());
        assert!(memory_checks(body(&receipt).as_bytes(), 64).is_err());
        for (key, value) in [
            ("sequence", json!(2)),
            ("maximum_pages", json!(129)),
            ("beyond_limit_rejected", json!(false)),
        ] {
            let mut invalid = receipt.clone();
            invalid[key] = value;
            assert!(memory_checks(body(&invalid).as_bytes(), 128).is_err());
        }
        assert!(
            memory_checks(
                b"FENDERS_HTTPS_STARTED\nFENDERS_HTTPS_PROGRESS sequence=1 status=200\n",
                128
            )
            .is_err()
        );
        assert!(
            memory_checks(
                format!("{}FENDERS_MEMORY_CEILING {receipt}\n", body(&receipt)).as_bytes(),
                128
            )
            .is_err()
        );
        assert!(
            memory_checks(
                b"FENDERS_HTTPS_STARTED\nFENDERS_MEMORY_CEILING broken\n",
                128
            )
            .is_err()
        );
    }
}
