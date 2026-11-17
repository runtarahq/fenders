//! A real selected-release startup failure, bounded to the test-owned service.
use super::*;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Direction {
    Upgrade,
    Rollback,
}
impl Direction {
    fn name(self) -> &'static str {
        match self {
            Self::Upgrade => "upgrade",
            Self::Rollback => "rollback",
        }
    }
    fn label(self) -> &'static str {
        match self {
            Self::Upgrade => "startup-recovery",
            Self::Rollback => "rollback-startup-recovery",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Stage {
    BeforeExec,
    AfterAdoption,
}
impl Stage {
    pub fn from_env(enabled: bool) -> Self {
        match std::env::var("FENDERS_UPGRADE_STARTUP_FAILURE_STAGE").as_deref() {
            Err(std::env::VarError::NotPresent) | Ok("before_exec") => Self::BeforeExec,
            Ok("after_adoption") if enabled => Self::AfterAdoption,
            _ => panic!(
                "startup failure stage must be before_exec or after_adoption with startup recovery enabled"
            ),
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::BeforeExec => "before_exec",
            Self::AfterAdoption => "after_adoption",
        }
    }
}

/// A failed process is insufficient evidence of adoption. Match every prepared
/// field, require a new positive owner PID and exactly one monotonic epoch claim.
fn verify_failure(
    source: &Value,
    failed: &Value,
    stage: Stage,
) -> std::result::Result<(), &'static str> {
    if source["mode"] != "sealed" {
        return Err("source was not sealed");
    }
    let mut expected = source.clone();
    if stage == Stage::AfterAdoption {
        let previous_pid = source["owner_pid"]
            .as_i64()
            .filter(|n| *n > 0)
            .ok_or("invalid source owner")?;
        let epoch = source["epoch"]
            .as_i64()
            .filter(|n| *n > 0)
            .and_then(|n| n.checked_add(1))
            .ok_or("invalid source epoch")?;
        let pid = failed["owner_pid"]
            .as_i64()
            .filter(|n| *n > 0 && previous_pid != *n)
            .ok_or("candidate did not claim a distinct owner")?;
        expected["epoch"] = json!(epoch);
        expected["owner_pid"] = json!(pid);
    }
    if *failed != expected {
        return Err("failed candidate changed or did not adopt the sealed intent");
    }
    Ok(())
}

/// Tie both failures to the intervening successful upgrade and final rollback.
/// Repeating the forward probe cannot stand in for the reverse direction.
pub(super) fn verify_bidirectional(
    forward: &Value,
    reverse: &Value,
    handovers: &[Value],
    original: &str,
    candidate: &str,
) -> std::result::Result<(), &'static str> {
    if original == candidate
        || [original, candidate].iter().any(|hash| {
            hash.len() != 64
                || !hash
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
    {
        return Err("invalid distinct release identities");
    }
    let base = forward["source"]["epoch"]
        .as_i64()
        .filter(|n| *n > 0)
        .filter(|n| n.checked_add(8).is_some())
        .ok_or("invalid source epoch")?;
    for (r, direction, source, target, epoch) in [
        (forward, "upgrade", original, candidate, base),
        (reverse, "rollback", candidate, original, base + 4),
    ] {
        if r["direction"] != direction
            || r["failure_stage"] != "after_adoption"
            || r["source_sha256"] != source
            || r["fallback_sha256"] != source
            || r["target_sha256"] != target
            || r["source"]["mode"] != "open"
            || r["source"]["epoch"] != epoch
        {
            return Err("recovery did not prove the requested direction and source release");
        }
        let direct = &r["publication_failure"]["stale_agent_entrypoint"];
        if direct["normal_agent_entrypoint"] != true
            || direct["ownership_conflict"] != true
            || direct["journal_unchanged"] != true
            || direct["exit_code"] != 1
            || direct["agent_sha256"] != target
        {
            return Err("stale agent entrypoint was not independently fenced");
        }
        for (snapshot, expected_epoch, pin, mode) in [
            (&r["sealed"], epoch, target, "sealed"),
            (&r["failed"], epoch + 1, target, "sealed"),
            (
                &r["publication_failure"]["committed_intent"],
                epoch + 2,
                source,
                "sealed",
            ),
            (&r["adopted"], epoch + 3, source, "sealed"),
            (&r["opened"], epoch + 3, source, "open"),
        ] {
            if snapshot["epoch"] != expected_epoch
                || snapshot["candidate_sha256"] != pin
                || snapshot["mode"] != mode
            {
                return Err("recovery ownership path did not preserve its release and epoch");
            }
        }
    }
    let hops: Vec<_> = handovers
        .iter()
        .filter(|h| h.get("adopted").is_some())
        .collect();
    if hops.len() != 2 {
        return Err("normal upgrade and rollback not both proven");
    }
    for (hop, phase, source_epoch, pin) in [
        (hops[0], "upgrade", base + 3, candidate),
        (hops[1], "rollback", base + 7, original),
    ] {
        if hop["phase"] != phase
            || hop["source"]["epoch"] != source_epoch
            || hop["adopted"]["epoch"] != source_epoch + 1
            || hop["opened"]["epoch"] != source_epoch + 1
            || hop["adopted"]["candidate_sha256"] != pin
            || hop["opened"]["candidate_sha256"] != pin
        {
            return Err("normal handover did not bridge the recovery directions");
        }
    }
    Ok(())
}

struct ExecuteFault {
    path: PathBuf,
    permissions: fs::Permissions,
}
impl ExecuteFault {
    fn install(path: PathBuf) -> Self {
        let permissions = fs::metadata(&path).unwrap().permissions();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();
        Self { path, permissions }
    }
}
impl Drop for ExecuteFault {
    fn drop(&mut self) {
        fs::set_permissions(&self.path, self.permissions.clone()).unwrap();
    }
}
fn management(output: &Path) -> Value {
    let db = rusqlite::Connection::open_with_flags(
        output.join("state/agent/agent.sqlite3"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .unwrap();
    db.query_row("SELECT epoch,owner_boot,owner_pid,mode,operation,candidate_sha256,origin_epoch FROM agent_management WHERE singleton=1",[],|r| {
        Ok(json!({"epoch":r.get::<_,i64>(0)?,"owner_boot":r.get::<_,String>(1)?,"owner_pid":r.get::<_,i64>(2)?,
            "mode":r.get::<_,String>(3)?,"operation":r.get::<_,String>(4)?,"candidate_sha256":r.get::<_,String>(5)?,"origin_epoch":r.get::<_,i64>(6)?}))
    }).unwrap()
}
#[allow(clippy::too_many_arguments)]
pub(super) async fn run(
    l: &Lab,
    worker: &mut Worker,
    client: &transport::Client,
    helper: &Path,
    target: &Path,
    fallback: &Path,
    node: &str,
    backends: [&Path; 3],
    stage: Stage,
    direction: Direction,
    publication_failure: bool,
    mut customer_stop: Option<&mut stop::Stop>,
    mut workspace_suspension: Option<&mut suspension::Suspension>,
    mut tcp_revocation: Option<&mut revocation::Revocation>,
) -> Value {
    let label = direction.label();
    let probe = |suffix: &str| format!("{label}-{suffix}");
    let target_sha256 = digest(fs::read(helper).unwrap());
    let target_manifest = json_file(&target.join("worker-release.json"));
    let fallback_manifest = json_file(&fallback.join("worker-release.json"));
    assert_eq!(target_manifest["agent_sha256"], target_sha256);
    if direction == Direction::Rollback {
        assert_eq!(target_manifest["management_protocol"], 1);
        assert_eq!(fallback_manifest["management_protocol"], 1);
    }
    if let Some(stop) = customer_stop.as_mut() {
        stop.prime(l, worker, client).await;
    }
    let before: Vec<_> = backends
        .iter()
        .map(|b| {
            (
                ownership(b),
                limits::kernel(b),
                fs::read(b.join("config.json")).unwrap(),
            )
        })
        .collect();
    let original_files = release_files(fallback);
    let candidate_files = release_files(target);
    l.store
        .node_mode(&l.operator, node, json!({"draining":true}))
        .await
        .unwrap();
    let current = client
        .json("POST", "/rpc/maintenance/status", Some(&json!({})))
        .await
        .unwrap();
    assert_eq!(current["mode"], "open");
    assert_eq!(n(&current["owner_pid"]), i64::from(worker.pid()));
    let source_sha256 = digest(fs::read(format!("/proc/{}/exe", worker.pid())).unwrap());
    assert_eq!(fallback_manifest["agent_sha256"], source_sha256);
    assert_ne!(source_sha256, target_sha256);
    let sealed = client
        .json(
            "POST",
            "/rpc/maintenance/prepare",
            Some(&json!({"expected_epoch":current["epoch"],
        "operation":uid(),"candidate_sha256":target_sha256})),
        )
        .await
        .unwrap();
    assert_eq!(sealed["mode"], "sealed");
    let preflight = worker
        .preflight(
            &target.join("fenders-node"),
            target,
            s(&sealed["candidate_sha256"]),
            &probe("candidate"),
            Some(&sealed),
        )
        .await;
    assert_eq!(preflight["success"], true);
    let service = worker.service.as_ref().unwrap();
    let selected = service.select(target, &sealed, &probe("candidate")).await;
    let pin = s(&selected["selection_sha256"]);
    let operation = uid();
    let live_refusal = service
        .recover(
            helper,
            fallback,
            &sealed,
            &operation,
            pin,
            &probe("live-owner-refusal"),
            false,
        )
        .await;
    assert_eq!(live_refusal["success"], false);
    assert_eq!(management(&worker.output), sealed);
    assert_eq!(digest(fs::read(service.selection()).unwrap()), pin);
    let (execute_fault, mut cgroup_fault) = match stage {
        Stage::BeforeExec => (
            Some(ExecuteFault::install(target.join("fenders-node"))),
            None,
        ),
        Stage::AfterAdoption => (None, Some(service.fail_cgroup_startup())),
    };
    wait_for_active_request(backends[0]).await;
    let gap = Instant::now();
    worker.stop_agent().await;
    let cutoff = native_status(backends[1]);
    let https_cutoff = native_status(backends[2]);
    let service = worker.service.as_ref().unwrap();
    let failure = service.failed_start().await;
    let failed = management(&worker.output);
    verify_failure(&sealed, &failed, stage)
        .expect("failure receipt did not prove its requested startup stage");
    assert!(
        !Path::new(&format!("/proc/{}", n(&failed["owner_pid"]))).exists(),
        "failed management owner is still alive"
    );
    let stale_epoch_refusal = if stage == Stage::AfterAdoption {
        let refused = service
            .recover(
                helper,
                fallback,
                &sealed,
                &operation,
                pin,
                &probe("stale-epoch-refusal"),
                false,
            )
            .await;
        assert_eq!(refused["success"], false);
        assert_eq!(management(&worker.output), failed);
        assert_eq!(digest(fs::read(service.selection()).unwrap()), pin);
        Some(refused)
    } else {
        None
    };
    let cas_refusal = service
        .recover(
            helper,
            fallback,
            &failed,
            &operation,
            &"f".repeat(64),
            &probe("cas-refusal"),
            false,
        )
        .await;
    assert_eq!(cas_refusal["success"], false);
    assert_eq!(management(&worker.output), failed);
    let mut unit_restoration = None;
    let publication_observation = if publication_failure {
        let mut fault = service.fail_publication();
        let refused = service
            .recover(
                helper,
                fallback,
                &failed,
                &operation,
                pin,
                &probe("publication-denied"),
                true,
            )
            .await;
        assert_eq!(
            refused["success"], false,
            "publication fault did not fail the real helper"
        );
        let committed = management(&worker.output);
        assert_eq!(n(&committed["epoch"]), n(&failed["epoch"]) + 1);
        assert_eq!(committed["mode"], "sealed");
        assert_eq!(committed["operation"], operation);
        assert_eq!(committed["origin_epoch"], committed["epoch"]);
        assert_eq!(
            committed["candidate_sha256"],
            json_file(&fallback.join("worker-release.json"))["agent_sha256"]
        );
        assert_eq!(
            digest(fs::read(service.selection()).unwrap()),
            pin,
            "failed publish changed the pointer"
        );
        let permissions_restored = fault.restore();
        drop(fault);
        // Restore the valid unit before this negative attempt: only the durable
        // fallback intent may prevent the stale selected binary from adopting.
        unit_restoration = cgroup_fault.take().map(|mut fault| fault.restore());
        assert_eq!(release_files(target), candidate_files);
        // Socket requests can consume the maintained burst. Clear it once for
        // this single adversarial start after the unit is valid and fallback
        // intent durable; retain the unit's normal limit and automatic policy.
        service.reset_failed();
        let stale = service.rejected_stale_start().await;
        assert_eq!(
            management(&worker.output),
            committed,
            "stale target adopted after a failed publish"
        );
        // The bootstrap may refuse before exec of the selected release. Also
        // execute that exact agent directly: its own claim must reject the
        // mismatched recovery intent before Node can reconcile preserved VMs.
        let mut args = worker.arguments.clone();
        let build = args.iter().position(|a| a == "--build").unwrap();
        args[build + 1] = target.as_os_str().to_owned();
        let mut direct = Command::new(target.join("fenders-node"));
        direct.args(args);
        let name = probe("stale-agent-entrypoint");
        let (status, _) = command_output(direct, &worker.output, &name).await;
        assert_eq!(status.code(), Some(1));
        assert!(
            fs::read_to_string(worker.output.join(format!("{name}.log")))
                .unwrap()
                .contains("stale or conflicting maintenance operation"),
            "direct candidate did not fail at its ownership fence"
        );
        assert_eq!(management(&worker.output), committed);
        let stale_agent = json!({"agent_sha256":target_sha256,"exit_code":status.code(),
            "normal_agent_entrypoint":true,"ownership_conflict":true,"journal_unchanged":true});
        for (backend, (identity, kernel, configuration)) in backends.iter().zip(&before) {
            assert_eq!(&ownership(backend), identity);
            assert_eq!(&limits::kernel(backend), kernel);
            assert!(
                fs::read(backend.join("config.json")).unwrap() == *configuration,
                "stale start changed private configuration"
            );
        }
        let other_operation = service
            .recover(
                helper,
                fallback,
                &failed,
                &uid(),
                pin,
                &probe("conflicting-operation"),
                false,
            )
            .await;
        assert_eq!(other_operation["success"], false);
        assert_eq!(management(&worker.output), committed);
        assert_eq!(digest(fs::read(service.selection()).unwrap()), pin);
        Some(
            json!({"failed_publication":refused,"committed_intent":committed,"unchanged_selection_sha256":pin,
            "directory_restoration":permissions_restored,"stale_selected_candidate":stale,
            "stale_agent_entrypoint":stale_agent,
            "start_limit_reset_for_single_stale_probe_after_valid_unit_and_durable_intent":true,
            "stale_start_preserved_vm_identities_configurations_and_kernel_scopes":true,"conflicting_operation":other_operation}),
        )
    } else {
        None
    };
    if let Some(stop) = customer_stop.as_mut() {
        // No manager is alive, the durable fallback intent is sealed, and B is
        // still selected. Customer intent must persist without freeing capacity.
        assert!(publication_observation.is_some());
        assert!(
            !Path::new(&format!(
                "/proc/{}",
                n(&management(&worker.output)["owner_pid"])
            ))
            .exists()
        );
        stop.queue(l, worker).await;
    }
    if let Some(suspension) = workspace_suspension.as_mut() {
        assert!(publication_observation.is_some());
        assert!(
            !Path::new(&format!(
                "/proc/{}",
                n(&management(&worker.output)["owner_pid"])
            ))
            .exists()
        );
        suspension.queue(l, worker).await;
    }
    if let Some(revocation) = tcp_revocation.as_mut() {
        assert!(publication_observation.is_some());
        assert!(
            !Path::new(&format!(
                "/proc/{}",
                n(&management(&worker.output)["owner_pid"])
            ))
            .exists()
        );
        revocation.queue(l, worker).await;
    }
    let service = worker.service.as_ref().unwrap();
    let recovered = service
        .recover(
            helper,
            fallback,
            &failed,
            &operation,
            pin,
            &probe("fallback"),
            false,
        )
        .await;
    assert_eq!(recovered["success"], true);
    let intent = management(&worker.output);
    assert_eq!(intent["mode"], "sealed");
    assert!(
        (n(&failed["epoch"]) + 1..=n(&failed["epoch"]) + 2).contains(&n(&intent["epoch"])),
        "socket activation advanced ownership beyond the fallback"
    );
    assert_eq!(intent["operation"], operation);
    assert_eq!(recovered["report"]["admission_resumed"], false);
    if let Some(observation) = &publication_observation {
        assert_eq!(
            recovered["report"]["recovery_intent_epoch"],
            observation["committed_intent"]["epoch"]
        );
        assert_eq!(
            recovered["report"]["selected"]["source_epoch"],
            observation["committed_intent"]["epoch"]
        );
    }
    drop(execute_fault);
    if unit_restoration.is_none() {
        unit_restoration = cgroup_fault.take().map(|mut fault| fault.restore());
    }
    assert_eq!(release_files(target), candidate_files);
    worker.service.as_ref().unwrap().reset_failed();
    worker.start(
        &fallback.join("fenders-node"),
        &probe("recovered"),
        fallback,
    );
    let adopted = client
        .json("POST", "/rpc/maintenance/status", Some(&json!({})))
        .await
        .unwrap();
    let gap_ms = gap.elapsed().as_secs_f64() * 1000.0;
    assert_eq!(adopted["mode"], "sealed");
    assert_eq!(adopted["operation"], operation);
    assert_eq!(n(&adopted["epoch"]), n(&failed["epoch"]) + 2);
    if let Some(stop) = customer_stop.as_mut() {
        stop.settle_sealed(l, worker, client, &adopted).await;
    }
    if let Some(suspension) = workspace_suspension.as_mut() {
        suspension.settle_sealed(l, worker, client, &adopted).await;
    }
    if let Some(revocation) = tcp_revocation.as_mut() {
        revocation.settle_sealed(l, worker, client, &adopted).await;
    }
    let stale = client
        .json(
            "POST",
            "/rpc/maintenance/resume",
            Some(&json!({"expected_epoch":sealed["epoch"],"operation":sealed["operation"]})),
        )
        .await
        .unwrap_err();
    assert_eq!(stale.status, StatusCode::CONFLICT);
    let opened = client
        .json(
            "POST",
            "/rpc/maintenance/resume",
            Some(&json!({"expected_epoch":adopted["epoch"],"operation":operation})),
        )
        .await
        .unwrap();
    assert_eq!(opened["mode"], "open");
    let retry = worker
        .service
        .as_ref()
        .unwrap()
        .recover(
            helper,
            fallback,
            &failed,
            &operation,
            pin,
            &probe("idempotent"),
            false,
        )
        .await;
    assert_eq!(retry["success"], true);
    assert_eq!(retry["report"]["changed"], false);
    assert_eq!(
        client
            .json("POST", "/rpc/maintenance/status", Some(&json!({})))
            .await
            .unwrap(),
        opened
    );
    // A reset while the failed unit is still activating can precede a queued
    // socket/manual start. Clear the recovery burst only after RPC proves the
    // fallback healthy; later planned upgrades retain the normal unit limit.
    worker.service.as_ref().unwrap().reset_failed();
    l.store
        .node_mode(&l.operator, node, json!({"draining":false}))
        .await
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if n(&native_status(backends[1])["egress_budget_revision"])
            > n(&cutoff["egress_budget_revision"])
            && n(&native_status(backends[2])["egress_budget_revision"])
                > n(&https_cutoff["egress_budget_revision"])
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "recovered agent failed to renew retained authority"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let mut preserved = Vec::new();
    for (backend, (identity, kernel, config)) in backends.iter().zip(before) {
        assert_eq!(ownership(backend), identity);
        assert_eq!(limits::kernel(backend), kernel);
        assert!(
            fs::read(backend.join("config.json")).unwrap() == config,
            "private configuration changed during failed start"
        );
        preserved.push(json!({"identity":identity,"kernel":kernel,"configuration_unchanged":true}));
    }
    assert_eq!(release_files(fallback), original_files);
    let reserved: i64 = sqlx::query_scalar("SELECT count(*) FROM executions WHERE reserved")
        .fetch_one(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(reserved, 3);
    let fault = match stage {
        Stage::BeforeExec => {
            "selected candidate execute bits removed after successful preflight and selection"
        }
        Stage::AfterAdoption => {
            "test-owned unit cgroup argument points at a regular file; candidate claims ownership then Node initialization fails"
        }
    };
    let result = json!({"direction":direction.name(),"source":current,"source_sha256":source_sha256,
        "target_sha256":target_sha256,"fallback_sha256":fallback_manifest["agent_sha256"],
        "failure_stage":stage.name(),"fault":fault,"unit_restoration":unit_restoration,
        "publication_failure_required":publication_failure,"publication_failure":publication_observation,
        "fault_restored":true,"original_files_unchanged":true,"candidate_files_restored":true,
        "failed_unit_reset_before_fallback_start":true,"start_limit_reset_after_healthy_fallback":true,
        "preflight":preflight,"selection":selected,"live_owner_refusal":live_refusal,"failure":failure,
        "stale_selection_refusal":cas_refusal,"stale_epoch_refusal":stale_epoch_refusal,"failed":failed,
        "recovery":recovered,"sealed":sealed,"intent":intent,"adopted":adopted,"opened":opened,
        "stale_resume_refused":true,"read_only_retry":retry,"cutover_to_fallback_rpc_ms":gap_ms,
        "preserved":preserved,"reserved":reserved,"source_pg_authority":cutoff,
        "recovered_pg_authority":native_status(backends[1]),"source_https_authority":https_cutoff,
        "recovered_https_authority":native_status(backends[2])});
    evidence(&worker.output.join(format!("{label}.json")), &result);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reverse_proof_rejects_repeated_forward_recovery_wrong_releases_and_broken_bridges() {
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        let snapshot = |epoch: i64, pin: &str, mode: &str| json!({"epoch":epoch,"candidate_sha256":pin,"mode":mode});
        let receipt = |direction: &str, epoch: i64, source: &str, target: &str| {
            json!({
            "direction":direction,"failure_stage":"after_adoption","source_sha256":source,
            "fallback_sha256":source,"target_sha256":target,"source":{"epoch":epoch,"mode":"open"},
            "sealed":snapshot(epoch,target,"sealed"),"failed":snapshot(epoch+1,target,"sealed"),
            "publication_failure":{"committed_intent":snapshot(epoch+2,source,"sealed"),
                "stale_agent_entrypoint":{"normal_agent_entrypoint":true,"ownership_conflict":true,
                    "journal_unchanged":true,"exit_code":1,"agent_sha256":target}},
            "adopted":snapshot(epoch+3,source,"sealed"),"opened":snapshot(epoch+3,source,"open")})
        };
        let hop = |phase: &str, epoch: i64, pin: &str| {
            json!({"phase":phase,"source":{"epoch":epoch},
            "adopted":snapshot(epoch+1,pin,"sealed"),"opened":snapshot(epoch+1,pin,"open")})
        };
        let proof = json!({"forward":receipt("upgrade",20,&a,&b),"reverse":receipt("rollback",24,&b,&a),
            "hops":[hop("upgrade",23,&b),hop("rollback",27,&a)]});
        let check = |v: &Value| {
            verify_bidirectional(
                &v["forward"],
                &v["reverse"],
                v["hops"].as_array().unwrap(),
                &a,
                &b,
            )
        };
        check(&proof).unwrap();
        let mut repeated = proof.clone();
        repeated["reverse"] = proof["forward"].clone();
        assert!(check(&repeated).is_err());
        for (path, value) in [
            ("/reverse/source_sha256", json!(a)),
            ("/reverse/target_sha256", json!(b)),
            ("/reverse/fallback_sha256", json!(a)),
            ("/reverse/source/epoch", json!(25)),
            ("/reverse/failed/epoch", json!(26)),
            ("/reverse/failed/candidate_sha256", json!(b)),
            (
                "/reverse/publication_failure/committed_intent/epoch",
                json!(27),
            ),
            (
                "/reverse/publication_failure/stale_agent_entrypoint/agent_sha256",
                json!(b),
            ),
            (
                "/reverse/publication_failure/stale_agent_entrypoint/normal_agent_entrypoint",
                json!(false),
            ),
            (
                "/reverse/publication_failure/stale_agent_entrypoint/exit_code",
                json!(0),
            ),
            ("/reverse/adopted/mode", json!("open")),
            ("/reverse/opened/candidate_sha256", json!(a)),
            ("/hops/0/phase", json!("rollback")),
            ("/hops/1/source/epoch", json!(24)),
            ("/hops/1/adopted/candidate_sha256", json!(b)),
            ("/forward/source/epoch", json!(i64::MAX)),
        ] {
            let mut invalid = proof.clone();
            *invalid.pointer_mut(path).unwrap() = value;
            assert!(check(&invalid).is_err(), "{path}");
        }
    }
    #[test]
    fn adoption_receipt_rejects_pre_exec_failure_repeated_claims_and_changed_intent() {
        let source = json!({"epoch":4,"owner_pid":100,"owner_boot":"boot","mode":"sealed",
            "operation":uid(),"origin_epoch":4,"candidate_sha256":"b".repeat(64)});
        assert!(verify_failure(&source, &source, Stage::BeforeExec).is_ok());
        assert!(verify_failure(&source, &source, Stage::AfterAdoption).is_err());
        let mut adopted = source.clone();
        adopted["epoch"] = json!(5);
        adopted["owner_pid"] = json!(101);
        assert!(verify_failure(&source, &adopted, Stage::AfterAdoption).is_ok());
        assert!(verify_failure(&source, &adopted, Stage::BeforeExec).is_err());
        for (field, value) in [
            ("epoch", json!(4)),
            ("epoch", json!(6)),
            ("epoch", json!("5")),
            ("owner_pid", json!(100)),
            ("owner_pid", json!(0)),
            ("owner_boot", json!("another-boot")),
            ("mode", json!("open")),
            ("operation", json!(uid())),
            ("origin_epoch", json!(5)),
            ("candidate_sha256", json!("a".repeat(64))),
        ] {
            let mut invalid = adopted.clone();
            invalid[field] = value;
            assert!(
                verify_failure(&source, &invalid, Stage::AfterAdoption).is_err(),
                "{field}"
            );
        }
    }
}
