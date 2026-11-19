use super::*;
use fenders_control_plane::egress_budget::CONTRACT;
const LAUNCHER: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
async fn fixture(l: &Lab) -> (Value, Value, Value) {
    let node = l.node("budget-node").await;
    let route = l.web_app("budget-web", "apps.test").await;
    l.store.schedule().await.unwrap();
    let all = l
        .store
        .resources(&l.operator, &l.tenant, &l.project, "executions", None)
        .await
        .unwrap();
    let e = all[0].clone();
    l.report(&node, &e, "running", 1).await;
    l.store
        .node_mode(
            &l.operator,
            s(&node["id"]),
            json!({"egress_budget_launcher":LAUNCHER}),
        )
        .await
        .unwrap();
    l.store.heartbeat(s(&node["id"]),json!({"boot_id":"test-boot","reports":[],"confinement":HOST_CONFINEMENT,"egress_budget_contract":CONTRACT,"launcher_digest":LAUNCHER})).await.unwrap();
    (node, e, route)
}
/// A run with a network of its own, as a run of an app with a connection
/// has. `resource_id` is its execution.
async fn networked(l: &mut Lab, key: &str) -> Value {
    l.store = l.store.clone().with_external_network(
        fenders_control_plane::external_endpoints::ExternalNetworkPolicy {
            allowed_cidrs: vec!["10.50.0.0/24".parse().unwrap()],
            denied_cidrs: vec![],
        },
    );
    let pki = l.root.path().join("external-pki");
    if !pki.exists() {
        fenders_control_plane::pki::create(
            &pki,
            &std::collections::BTreeMap::from([("database".into(), vec!["10.50.0.2".into()])]),
        )
        .unwrap();
    }
    let ca = json!(std::fs::read_to_string(pki.join("ca.pem")).unwrap());
    let known: i64 = sqlx::query_scalar("SELECT count(*) FROM external_endpoints")
        .fetch_one(&l.store.pool)
        .await
        .unwrap();
    let service = super::app_connections::endpoint(l, &ca, 2 + known as u8).await;
    l.validated().await;
    let app = super::app_connections::deploy(l, &service, false, key).await;
    l.start_app(s(&app["resource_id"]), &format!("run-{key}"))
        .await
        .unwrap()
}
fn request(action: &str, revision: i64, key: &str) -> Value {
    json!({"boot_id":"test-boot","expected_revision":revision,"request_id":key,"action":action})
}
fn grant(revision: i64, key: &str, bytes: i64) -> Value {
    let mut v = request("grant", revision, key);
    v["bytes"] = json!(bytes);
    v
}
fn settlement(g: &Value, accepted: u64, key: &str) -> Value {
    let mut v = request("settle", n(&g["revision"]), key);
    v["observation"] = json!({"egress_budget_enabled":true,"egress_budget_measured":true,
        "egress_budget_revision":g["revision"],"egress_budget_ceiling":g["ceiling_bytes"],
        "egress_budget_deadline_ns":0,"egress_budget_reserved":0,"egress_budget_in_flight":0,"egress_budget_bytes":accepted});
    v
}
async fn apply(l: &Lab, node: &Value, e: &Value, v: Value) -> Value {
    l.store
        .egress_budget(s(&node["id"]), s(&e["id"]), n(&e["generation"]), v)
        .await
        .unwrap()
}
async fn totals(l: &Lab) -> (i64, i64) {
    sqlx::query_as("SELECT COALESCE(sum(used_bytes),0)::bigint,COALESCE(sum(held_bytes),0)::bigint FROM transfer_allowance_accounting WHERE tenant_id=$1 AND period=date_trunc('month',now() AT TIME ZONE 'UTC')::date").bind(&l.tenant).fetch_one(&l.store.pool).await.unwrap()
}

#[tokio::test]
async fn retained_launcher_renewal_requires_explicit_approval_and_matching_execution() {
    let l = Lab::new().await;
    let (node, mut e, _) = fixture(&l).await;
    let nid = s(&node["id"]);
    let eid = s(&e["id"]).to_owned();
    // Protocol fixture: make the existing execution's placement pin explicit.
    sqlx::query("UPDATE executions SET egress_budget_launcher=$2 WHERE id=$1")
        .bind(&eid)
        .bind(LAUNCHER)
        .execute(&l.store.pool)
        .await
        .unwrap();
    e["egress_budget_launcher"] = json!(LAUNCHER);
    let first = apply(&l, &node, &e, grant(0, "before-upgrade", 4096)).await;
    let replacement = "b".repeat(64);
    l.store
        .node_mode(
            &l.operator,
            nid,
            json!({"egress_budget_launcher":replacement}),
        )
        .await
        .unwrap();
    let report = json!({"id":eid,"generation":1,"state":"running","sequence":2,"cpu_usec":12,"memory_bytes":512,
        "egress_authority":{"contract":CONTRACT,"boot_id":"test-boot","launcher_digest":LAUNCHER}});
    l.store.heartbeat(nid, json!({"boot_id":"test-boot","reports":[report],
        "confinement":HOST_CONFINEMENT,"egress_budget_contract":CONTRACT,"launcher_digest":replacement})).await.unwrap();
    let renewal = grant(1, "after-upgrade", 1024);
    assert!(
        l.store
            .egress_budget(nid, &eid, 1, renewal.clone())
            .await
            .is_err()
    );
    assert!(l.store.assignment(nid, &eid, 1).await.is_err());
    assert_eq!(totals(&l).await, (0, 4096));
    l.store
        .node_mode(
            &l.operator,
            nid,
            json!({"retained_egress_launchers":[LAUNCHER]}),
        )
        .await
        .unwrap();
    assert_eq!(
        l.store.assignment(nid, &eid, 1).await.unwrap()["egress"]["launcher_digest"],
        LAUNCHER
    );
    let renewed = apply(&l, &node, &e, renewal.clone()).await;
    assert_eq!(renewed["revision"], 2);
    assert_eq!(renewed["ceiling_bytes"], 5120);
    assert_eq!(totals(&l).await, (0, 5120));
    assert_eq!(apply(&l, &node, &e, renewal.clone()).await["revision"], 2);
    assert_eq!(
        totals(&l).await,
        (0, 5120),
        "retry cannot reset or duplicate credit"
    );
    assert_eq!(first["ceiling_bytes"], 4096);
    let retained: String = sqlx::query_scalar(
        "SELECT launcher_digest FROM execution_egress_budgets WHERE execution_id=$1",
    )
    .bind(&eid)
    .fetch_one(&l.store.pool)
    .await
    .unwrap();
    assert_eq!(retained, LAUNCHER);
    // Operator approval cannot invent an incarnation observation or revive a
    // different boot/generation. All refusals preserve the outstanding hold.
    for (sequence, generation, launcher) in [(3, 1, replacement.clone()), (4, 2, LAUNCHER.into())] {
        let mut bad = report.clone();
        bad["sequence"] = json!(sequence);
        bad["generation"] = json!(generation);
        bad["egress_authority"]["launcher_digest"] = json!(launcher);
        l.store.heartbeat(nid, json!({"boot_id":"test-boot","reports":[bad],
            "confinement":HOST_CONFINEMENT,"egress_budget_contract":CONTRACT,"launcher_digest":replacement})).await.unwrap();
        assert!(
            l.store
                .egress_budget(nid, &eid, 1, grant(2, "wrong-incarnation", 1))
                .await
                .is_err()
        );
        assert_eq!(totals(&l).await, (0, 5120));
    }
    let mut restored = report.clone();
    restored["sequence"] = json!(5);
    l.store.heartbeat(nid, json!({"boot_id":"test-boot","reports":[restored],
        "confinement":HOST_CONFINEMENT,"egress_budget_contract":CONTRACT,"launcher_digest":replacement})).await.unwrap();
    l.store
        .node_mode(&l.operator, nid, json!({"retained_egress_launchers":[]}))
        .await
        .unwrap();
    assert!(
        l.store.egress_budget(nid, &eid, 1, renewal).await.is_err(),
        "revocation also fences cached retries"
    );
    assert_eq!(totals(&l).await, (0, 5120));
    l.store
        .node_mode(
            &l.operator,
            nid,
            json!({"retained_egress_launchers":[LAUNCHER]}),
        )
        .await
        .unwrap();
    let freeze = apply(&l, &node, &e, request("freeze", 2, "retained-freeze")).await;
    apply(&l, &node, &e, settlement(&freeze, 123, "retained-settle")).await;
    assert_eq!(totals(&l).await, (123, 0));
    // Additive startup migration never reapproves a revoked launcher.
    l.store
        .node_mode(&l.operator, nid, json!({"retained_egress_launchers":[]}))
        .await
        .unwrap();
    l.store.migrate().await.unwrap();
    let retained: Value =
        sqlx::query_scalar("SELECT retained_egress_launchers FROM nodes WHERE id=$1")
            .bind(nid)
            .fetch_one(&l.store.pool)
            .await
            .unwrap();
    assert_eq!(retained, json!([]));
    l.finish().await;
}

#[tokio::test]
async fn retained_runtime_receives_lifecycle_intent_before_reporting_the_new_generation() {
    let mut l = Lab::new().await;
    let node = l.node("retained-lifecycle").await;
    let nid = s(&node["id"]);
    l.store
        .node_mode(
            &l.operator,
            nid,
            json!({"egress_budget_launcher":LAUNCHER,"egress_budget_required":true}),
        )
        .await
        .unwrap();
    l.store.heartbeat(nid, json!({"boot_id":"test-boot","reports":[],
        "confinement":HOST_CONFINEMENT,"egress_budget_contract":CONTRACT,"launcher_digest":LAUNCHER})).await.unwrap();
    let op = networked(&mut l, "lifecycle-execution").await;
    let eid = s(&op["resource_id"]).to_owned();
    let mut e = json!({"id":eid,"generation":1});
    l.store.schedule().await.unwrap();
    l.store.heartbeat(nid, json!({"boot_id":"test-boot",
        "confinement":HOST_CONFINEMENT,"egress_budget_contract":CONTRACT,"launcher_digest":LAUNCHER,
        "reports":[{"id":eid,"generation":1,"state":"running","sequence":1,"cpu_usec":12,"memory_bytes":512}]})).await.unwrap();
    apply(&l, &node, &e, grant(0, "initial", 4096)).await;
    let replacement = "b".repeat(64);
    l.store
        .node_mode(
            &l.operator,
            nid,
            json!({"egress_budget_launcher":replacement,
        "retained_egress_launchers":[LAUNCHER]}),
        )
        .await
        .unwrap();
    let heartbeat = |generation, state: &str, sequence| {
        json!({"boot_id":"test-boot",
        "confinement":HOST_CONFINEMENT,"egress_budget_contract":CONTRACT,"launcher_digest":replacement,
        "reports":[{"id":eid,"generation":generation,"state":state,"sequence":sequence,"cpu_usec":12,"memory_bytes":512,
            "egress_authority":{"contract":CONTRACT,"boot_id":"test-boot","launcher_digest":LAUNCHER}}]})
    };
    l.store
        .heartbeat(nid, heartbeat(1, "running", 2))
        .await
        .unwrap();
    // Stopping is the one change a tenant makes to a run in flight.
    for (generation, state, sequence) in [(2, "stopped", 3)] {
        l.stop(&eid, &uid()).await.unwrap();
        assert_eq!(
            l.store.assignment(nid, &eid, generation).await.unwrap()["desired"],
            state
        );
        assert!(
            l.store
                .egress_budget(
                    nid,
                    &eid,
                    generation - 1,
                    request("freeze", 1, "stale-control")
                )
                .await
                .is_err()
        );
        assert!(
            l.store
                .egress_budget(
                    nid,
                    &eid,
                    generation,
                    request("freeze", 1, "unacknowledged-control")
                )
                .await
                .is_err()
        );
        l.store
            .heartbeat(nid, heartbeat(generation, state, sequence))
            .await
            .unwrap();
        e["generation"] = json!(generation);
    }
    // It has ended: nothing more is granted to it.
    assert!(
        l.store
            .egress_budget(nid, &eid, 2, grant(1, "after-the-end", 1))
            .await
            .is_err()
    );
    l.finish().await;
}

#[tokio::test]
async fn retained_launcher_approval_is_bounded_operator_only_and_never_automatic() {
    let l = Lab::new().await;
    let node = l.node("retained-validation").await;
    let nid = s(&node["id"]);
    let (viewer, _) = l.credential("viewer", Some(&l.project)).await;
    assert!(
        l.store
            .node_mode(
                &viewer,
                nid,
                json!({"retained_egress_launchers":[LAUNCHER]})
            )
            .await
            .is_err()
    );
    for value in [
        Value::Null,
        json!(true),
        json!(LAUNCHER),
        json!(["bad"]),
        json!(["A".repeat(64)]),
        json!([LAUNCHER, LAUNCHER]),
        json!((0..33).map(|n| format!("{n:064x}")).collect::<Vec<_>>()),
    ] {
        assert!(
            l.store
                .node_mode(&l.operator, nid, json!({"retained_egress_launchers":value}))
                .await
                .is_err()
        );
    }
    l.store
        .node_mode(&l.operator, nid, json!({"egress_budget_launcher":LAUNCHER}))
        .await
        .unwrap();
    l.store
        .node_mode(
            &l.operator,
            nid,
            json!({"egress_budget_launcher":"b".repeat(64)}),
        )
        .await
        .unwrap();
    let retained: Value =
        sqlx::query_scalar("SELECT retained_egress_launchers FROM nodes WHERE id=$1")
            .bind(nid)
            .fetch_one(&l.store.pool)
            .await
            .unwrap();
    assert_eq!(retained, json!([]));
    l.finish().await;
}

#[tokio::test]
async fn retained_launcher_approval_cannot_select_the_runtime_for_a_new_placement() {
    let mut l = Lab::new().await;
    let node = l.node("mixed-placement").await;
    let nid = s(&node["id"]);
    let replacement = "b".repeat(64);
    l.store
        .node_mode(
            &l.operator,
            nid,
            json!({"egress_budget_launcher":replacement,
        "egress_budget_required":true,"retained_egress_launchers":[LAUNCHER]}),
        )
        .await
        .unwrap();
    let op = networked(&mut l, "mixed-placement").await;
    let eid = s(&op["resource_id"]);
    // Observing only the retained launcher cannot qualify new work.
    l.store.heartbeat(nid, json!({"boot_id":"test-boot","reports":[],
        "confinement":HOST_CONFINEMENT,"egress_budget_contract":CONTRACT,"launcher_digest":LAUNCHER})).await.unwrap();
    l.store.schedule().await.unwrap();
    let assigned: Option<String> = sqlx::query_scalar("SELECT node_id FROM executions WHERE id=$1")
        .bind(eid)
        .fetch_one(&l.store.pool)
        .await
        .unwrap();
    assert!(assigned.is_none());
    l.store.heartbeat(nid, json!({"boot_id":"test-boot","reports":[],
        "confinement":HOST_CONFINEMENT,"egress_budget_contract":CONTRACT,"launcher_digest":replacement})).await.unwrap();
    l.store.schedule().await.unwrap();
    assert_eq!(
        l.store.assignment(nid, eid, 1).await.unwrap()["egress"]["launcher_digest"],
        replacement
    );
    let granted = l
        .store
        .egress_budget(nid, eid, 1, grant(0, "new-runtime", 128))
        .await
        .unwrap();
    assert_eq!(granted["held_bytes"], 128);
    let pinned: String = sqlx::query_scalar(
        "SELECT launcher_digest FROM execution_egress_budgets WHERE execution_id=$1",
    )
    .bind(eid)
    .fetch_one(&l.store.pool)
    .await
    .unwrap();
    assert_eq!(pinned, replacement);
    l.finish().await;
}
#[tokio::test]
async fn outbound_grant_usage_counts_are_scoped_and_do_not_claim_fleet_enforcement() {
    let l = Lab::new().await;
    let (node, e, _) = fixture(&l).await;
    let before = l.store.usage(&l.operator, &l.tenant, None).await.unwrap();
    assert_eq!(before["totals"]["outbound_grant_executions"], 0);
    apply(&l, &node, &e, grant(0, "recorded", 1024)).await;
    let workspace = l.store.usage(&l.operator, &l.tenant, None).await.unwrap();
    let project = l
        .store
        .usage(&l.operator, &l.tenant, Some(&l.project))
        .await
        .unwrap();
    assert_eq!(workspace["totals"]["outbound_grant_executions"], 1);
    assert_eq!(project["totals"]["outbound_grant_executions"], 1);
    assert_eq!(
        workspace["transfer_allowance"]["outbound_fleet_enforcement"],
        false
    );
    let other = l
        .store
        .create_project(
            &l.operator,
            &l.tenant,
            serde_json::from_value(json!({"name":"No grants"})).unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        l.store
            .usage(&l.operator, &l.tenant, Some(s(&other["id"])))
            .await
            .unwrap()["totals"]["outbound_grant_executions"],
        0
    );
    // Calendar attribution follows the grant period, not execution creation.
    sqlx::query("UPDATE execution_egress_budgets SET period=(date_trunc('month',now() AT TIME ZONE 'UTC')-interval '1 month')::date WHERE execution_id=$1")
        .bind(s(&e["id"])).execute(&l.store.pool).await.unwrap();
    assert_eq!(
        l.store.usage(&l.operator, &l.tenant, None).await.unwrap()["totals"]["outbound_grant_executions"],
        0
    );
    l.finish().await;
}

#[tokio::test]
async fn egress_and_gateway_share_one_transactional_allowance() {
    let l = Lab::new().await;
    let (node, e, route) = fixture(&l).await;
    // Room for the grant or for the gateway's lease, which takes what there
    // is up to its least: not for both.
    sqlx::query("UPDATE tenants SET transfer_bytes=1000000 WHERE id=$1")
        .bind(&l.tenant)
        .execute(&l.store.pool)
        .await
        .unwrap();
    let a = l.store.clone();
    let b = l.store.clone();
    let nid = s(&node["id"]).to_owned();
    let eid = s(&e["id"]).to_owned();
    let hostname = s(&route["hostname"]).to_owned();
    let (outbound, inbound) = tokio::join!(
        a.egress_budget(&nid, &eid, 1, grant(0, "race", 1000000)),
        b.ingress_start(&hostname, 0)
    );
    assert_eq!(
        usize::from(outbound.is_ok()) + usize::from(inbound.is_ok()),
        1
    );
    if let Ok((_, lease)) = inbound {
        l.store.ingress_finish(&lease, Some(0)).await.unwrap();
        // The gateway gives its lease back when it stops.
        l.store.close_gateway().await.unwrap();
    } else {
        let freeze = apply(&l, &node, &e, request("freeze", 1, "freeze-race")).await;
        apply(&l, &node, &e, settlement(&freeze, 0, "settle-race")).await;
    }
    assert_eq!(totals(&l).await, (0, 0));
    let rev: i64 = sqlx::query_scalar(
        "SELECT COALESCE((SELECT revision FROM execution_egress_budgets WHERE execution_id=$1),0)",
    )
    .bind(&eid)
    .fetch_one(&l.store.pool)
    .await
    .unwrap();
    let g = apply(&l, &node, &e, grant(rev, "hold", 1000000)).await;
    let err=l.store.update_allowance(&l.operator,&l.tenant,serde_json::from_value(json!({"allowance":{"cpu_percent":400,"memory_mib":4096,"instances":4,"storage_bytes":20000000000_i64,"transfer_bytes":999999}})).unwrap()).await.unwrap_err();
    assert_eq!(err.status, StatusCode::CONFLICT);
    sqlx::query("UPDATE execution_egress_budgets SET expires=now()-interval '1 second' WHERE execution_id=$1").bind(&eid).execute(&l.store.pool).await.unwrap();
    assert!(l.store.ingress_start(&hostname, 0).await.is_err());
    assert_eq!(totals(&l).await, (0, 1000000), "expiry is not settlement");
    let freeze = apply(
        &l,
        &node,
        &e,
        request("freeze", n(&g["revision"]), "freeze"),
    )
    .await;
    assert_eq!(freeze["ttl_ms"], 0);
    let mut bad = settlement(&freeze, 123, "settle");
    bad["observation"]["egress_budget_in_flight"] = json!(1);
    assert!(l.store.egress_budget(&nid, &eid, 1, bad).await.is_err());
    assert_eq!(totals(&l).await, (0, 1000000));
    let final_receipt = settlement(&freeze, 123, "settle");
    let settled = apply(&l, &node, &e, final_receipt.clone()).await;
    assert_eq!(apply(&l, &node, &e, final_receipt).await, settled);
    assert_eq!(totals(&l).await, (123, 0));
    let usage = l.store.usage(&l.operator, &l.tenant, None).await.unwrap();
    assert_eq!(usage["transfer_allowance"]["bytes"], 123);
    assert_eq!(usage["transfer_allowance"]["reserved_bytes"], 0);
    assert_eq!(
        usage["transfer_allowance"]["outbound_fleet_enforcement"],
        false
    );
    apply(
        &l,
        &node,
        &e,
        request("freeze", n(&settled["revision"]), "already-frozen"),
    )
    .await;
    assert_eq!(
        totals(&l).await,
        (123, 0),
        "freezing twice never reinstates released credit"
    );
    let (_, lease) = l.store.ingress_start(&hostname, 0).await.unwrap();
    l.store.ingress_finish(&lease, Some(77)).await.unwrap();
    l.store.close_gateway().await.unwrap();
    assert_eq!(totals(&l).await, (200, 0));
    l.finish().await;
}
#[tokio::test]
async fn grant_replay_scope_generation_boot_and_recovery_are_fenced() {
    let l = Lab::new().await;
    let (node, e, _) = fixture(&l).await;
    let v = grant(0, "first", 5000);
    let g = apply(&l, &node, &e, v.clone()).await;
    let replay = apply(&l, &node, &e, v).await;
    assert_eq!(replay["revision"], g["revision"]);
    assert_eq!(totals(&l).await, (0, 5000));
    l.store.heartbeat(s(&node["id"]),json!({"boot_id":"test-boot","reports":[],"confinement":HOST_CONFINEMENT,"egress_budget_contract":"socket-payload-ceiling-v1","launcher_digest":LAUNCHER})).await.unwrap();
    assert!(
        l.store
            .egress_budget(s(&node["id"]), s(&e["id"]), 1, grant(1, "legacy", 1))
            .await
            .is_err()
    );
    l.store.heartbeat(s(&node["id"]),json!({"boot_id":"test-boot","reports":[],"confinement":HOST_CONFINEMENT,"egress_budget_contract":CONTRACT,"launcher_digest":LAUNCHER})).await.unwrap();
    let foreign = l.node("foreign").await;
    assert!(
        l.store
            .egress_budget(s(&foreign["id"]), s(&e["id"]), 1, grant(1, "foreign", 1))
            .await
            .is_err()
    );
    assert!(
        l.store
            .egress_budget(s(&node["id"]), s(&e["id"]), 2, grant(1, "generation", 1))
            .await
            .is_err()
    );
    for v in [grant(0, "first", 5001), grant(0, "stale", 1), {
        let mut v = grant(1, "boot", 1);
        v["boot_id"] = json!("old");
        v
    }] {
        assert!(
            l.store
                .egress_budget(s(&node["id"]), s(&e["id"]), 1, v)
                .await
                .is_err()
        );
    }
    let reopened = Store::from_pool(l.store.pool.clone(), l.root.path()).unwrap();
    assert_eq!(
        reopened
            .egress_budget(s(&node["id"]), s(&e["id"]), 1, grant(0, "first", 5000))
            .await
            .unwrap()["held_bytes"],
        5000
    );
    sqlx::query("UPDATE executions SET generation=2 WHERE id=$1")
        .bind(s(&e["id"]))
        .execute(&l.store.pool)
        .await
        .unwrap();
    assert!(
        l.store
            .egress_budget(
                s(&node["id"]),
                s(&e["id"]),
                2,
                grant(1, "new-generation", 1)
            )
            .await
            .is_err()
    );
    let mut current = e.clone();
    current["generation"] = json!(2);
    let frozen = apply(
        &l,
        &node,
        &current,
        request("freeze", 1, "generation-freeze"),
    )
    .await;
    apply(
        &l,
        &node,
        &current,
        settlement(&frozen, 10, "generation-settle"),
    )
    .await;
    let renewed = apply(
        &l,
        &node,
        &current,
        grant(n(&frozen["revision"]), "generation-grant", 20),
    )
    .await;
    assert_eq!(renewed["ceiling_bytes"], 30);
    assert_eq!(totals(&l).await, (10, 20));
    let replacement = digest("replacement launcher");
    l.store
        .node_mode(
            &l.operator,
            s(&node["id"]),
            json!({"egress_budget_launcher":replacement}),
        )
        .await
        .unwrap();
    l.store.heartbeat(s(&node["id"]),json!({"boot_id":"test-boot","reports":[],"confinement":HOST_CONFINEMENT,"egress_budget_contract":CONTRACT,"launcher_digest":replacement})).await.unwrap();
    assert_eq!(
        l.store
            .egress_budget(
                s(&node["id"]),
                s(&e["id"]),
                2,
                grant(n(&renewed["revision"]), "different-launcher", 1)
            )
            .await
            .unwrap_err()
            .status,
        StatusCode::CONFLICT
    );
    assert_eq!(totals(&l).await, (10, 20));
    l.store
        .node_mode(
            &l.operator,
            s(&node["id"]),
            json!({"egress_budget_launcher":Value::Null}),
        )
        .await
        .unwrap();
    assert!(
        l.store
            .egress_budget(
                s(&node["id"]),
                s(&e["id"]),
                2,
                grant(n(&renewed["revision"]), "unapproved", 1)
            )
            .await
            .is_err()
    );
    assert_eq!(totals(&l).await, (10, 20));
    sqlx::query("UPDATE recovery_barrier SET active=true WHERE singleton")
        .execute(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(
        l.store
            .egress_budget(
                s(&node["id"]),
                s(&e["id"]),
                2,
                request("freeze", n(&renewed["revision"]), "barrier")
            )
            .await
            .unwrap_err()
            .status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(totals(&l).await, (10, 20));
    l.finish().await;
}
#[tokio::test]
async fn rollover_requires_frozen_settlement_without_carrying_old_credit() {
    let l = Lab::new().await;
    let (node, e, _) = fixture(&l).await;
    apply(&l, &node, &e, grant(0, "old", 5000)).await;
    sqlx::query("UPDATE execution_egress_budgets SET period=(date_trunc('month',now() AT TIME ZONE 'UTC')-interval '1 month')::date,expires=now()-interval '1 second' WHERE execution_id=$1").bind(s(&e["id"])).execute(&l.store.pool).await.unwrap();
    assert!(
        l.store
            .egress_budget(
                s(&node["id"]),
                s(&e["id"]),
                1,
                grant(1, "unsafe-rollover", 1)
            )
            .await
            .is_err()
    );
    let freeze = apply(&l, &node, &e, request("freeze", 1, "boundary")).await;
    apply(&l, &node, &e, settlement(&freeze, 321, "boundary-receipt")).await;
    let previous: i64 =
        sqlx::query_scalar("SELECT bytes FROM egress_allowance_usage WHERE execution_id=$1")
            .bind(s(&e["id"]))
            .fetch_one(&l.store.pool)
            .await
            .unwrap();
    assert_eq!(previous, 321);
    assert_eq!(totals(&l).await, (0, 0));
    let next = apply(&l, &node, &e, grant(2, "current", 100)).await;
    assert_eq!(next["ceiling_bytes"], 421);
    assert_eq!(totals(&l).await, (0, 100));
    assert!(n(&next["ttl_ms"]) <= 10000);
    let pending = apply(&l, &node, &e, request("freeze", 3, "current-freeze")).await;
    for (field, invalid) in [
        ("egress_budget_bytes", json!(320)),
        ("egress_budget_bytes", json!(422)),
        ("egress_budget_reserved", json!(1)),
        ("egress_budget_revision", json!(2)),
        ("egress_budget_deadline_ns", json!(1)),
        ("egress_budget_measured", json!(false)),
    ] {
        let mut v = settlement(&pending, 400, "bad");
        v["observation"][field] = invalid;
        assert!(
            l.store
                .egress_budget(s(&node["id"]), s(&e["id"]), 1, v)
                .await
                .is_err()
        );
        assert_eq!(totals(&l).await, (0, 100));
    }
    apply(&l, &node, &e, settlement(&pending, 400, "current-settle")).await;
    assert_eq!(totals(&l).await, (79, 0));
    l.finish().await;
}

#[tokio::test]
async fn cumulative_unsigned_limits_do_not_overflow_or_block_final_settlement() {
    let l = Lab::new().await;
    let (node, e, _) = fixture(&l).await;
    apply(&l, &node, &e, request("freeze", 0, "initial")).await;
    sqlx::query("UPDATE execution_egress_budgets SET base_bytes=$2::numeric,ceiling_bytes=$2::numeric WHERE execution_id=$1").bind(s(&e["id"])).bind((u64::MAX-10).to_string()).execute(&l.store.pool).await.unwrap();
    assert!(
        l.store
            .egress_budget(s(&node["id"]), s(&e["id"]), 1, grant(0, "overflow", 11))
            .await
            .is_err()
    );
    assert_eq!(totals(&l).await, (0, 0));
    let g = apply(&l, &node, &e, grant(0, "last-ten", 10)).await;
    assert_eq!(g["ceiling_bytes"], u64::MAX);
    sqlx::query("UPDATE execution_egress_budgets SET revision=$2,state='freezing',expires=NULL WHERE execution_id=$1").bind(s(&e["id"])).bind(i64::MAX).execute(&l.store.pool).await.unwrap();
    let g = json!({"revision":i64::MAX,"ceiling_bytes":u64::MAX});
    apply(&l, &node, &e, settlement(&g, u64::MAX - 4, "final")).await;
    assert_eq!(totals(&l).await, (6, 0));
    assert!(
        l.store
            .egress_budget(
                s(&node["id"]),
                s(&e["id"]),
                1,
                grant(i64::MAX, "exhausted-revision", 1)
            )
            .await
            .is_err()
    );
    assert_eq!(totals(&l).await, (6, 0));
    l.finish().await;
}

fn final_report(e: &Value, sequence: i64, count: u64) -> Value {
    json!({"id":e["id"],"generation":e["generation"],"sequence":sequence,"state":"exited","cpu_usec":0,"memory_bytes":0,
        "egress":{"contract":"socket-payload-v1","boot_id":"test-boot","bytes":count,"in_flight":0,"complete":true,"observed":chrono::Utc::now().timestamp_micros() as f64/1e6},
        "egress_authority":{"contract":CONTRACT,"boot_id":"test-boot","launcher_digest":LAUNCHER}})
}
async fn heartbeat(
    l: &Lab,
    node: &Value,
    reports: Value,
) -> Result<Value, fenders_control_plane::error::Error> {
    l.store
        .heartbeat(
            s(&node["id"]),
            json!({"boot_id":"test-boot","confinement":HOST_CONFINEMENT,"reports":reports}),
        )
        .await
}
async fn closure(l: &Lab, e: &Value) -> String {
    sqlx::query_scalar("SELECT closure FROM execution_egress_budgets WHERE execution_id=$1")
        .bind(s(&e["id"]))
        .fetch_one(&l.store.pool)
        .await
        .unwrap()
}
#[tokio::test]
async fn final_counter_settles_once_and_late_validation_rolls_back_release() {
    let l = Lab::new().await;
    let (node, e, _) = fixture(&l).await;
    apply(&l, &node, &e, grant(0, "credit", 5000)).await;
    let report = final_report(&e, 2, 321);
    let mut invalid = report.clone();
    invalid["id"] = json!("bad-id");
    assert!(
        heartbeat(&l, &node, json!([report.clone(), invalid]))
            .await
            .is_err()
    );
    assert_eq!(totals(&l).await, (0, 5000));
    assert!(
        sqlx::query_scalar::<_, bool>("SELECT reserved FROM executions WHERE id=$1")
            .bind(s(&e["id"]))
            .fetch_one(&l.store.pool)
            .await
            .unwrap()
    );
    // A fresh owner report can settle an older grant generation after stop.
    sqlx::query("UPDATE executions SET generation=2,desired='stopped' WHERE id=$1")
        .bind(s(&e["id"]))
        .execute(&l.store.pool)
        .await
        .unwrap();
    heartbeat(&l, &node, json!([report.clone()])).await.unwrap();
    assert_eq!(totals(&l).await, (0, 5000));
    let mut report = report;
    report["generation"] = json!(2);
    heartbeat(&l, &node, json!([report.clone()])).await.unwrap();
    heartbeat(&l, &node, json!([report])).await.unwrap();
    assert_eq!(totals(&l).await, (321, 0));
    assert_eq!(closure(&l, &e).await, "terminal-exact");
    let usage = l.store.usage(&l.operator, &l.tenant, None).await.unwrap();
    assert_eq!(
        usage["transfer_allowance"]["outbound_conservative_bytes"],
        0
    );
    assert_eq!(usage["totals"]["egress_bytes"], 321);
    assert!(
        sqlx::query("UPDATE execution_egress_budgets SET ceiling_bytes=320 WHERE execution_id=$1")
            .bind(s(&e["id"]))
            .execute(&l.store.pool)
            .await
            .is_err(),
        "settlement migration must preserve the ceiling bound"
    );
    assert!(
        sqlx::query("UPDATE execution_egress_budgets SET closure=NULL WHERE execution_id=$1")
            .bind(s(&e["id"]))
            .execute(&l.store.pool)
            .await
            .is_err(),
        "closed authority must retain its settlement reason"
    );
    let reopened = Store::from_pool(l.store.pool.clone(), l.root.path()).unwrap();
    assert!(
        reopened
            .egress_budget(s(&node["id"]), s(&e["id"]), 2, grant(1, "resurrect", 1))
            .await
            .is_err()
    );
    l.finish().await;
}
#[tokio::test]
async fn terminal_unknown_or_contradictory_counters_charge_only_existing_hold() {
    for mode in [
        "missing",
        "incomplete",
        "launcher",
        "regression",
        "outside",
        "lost",
    ] {
        let l = Lab::new().await;
        let (node, e, _) = fixture(&l).await;
        apply(&l, &node, &e, grant(0, "credit", 5000)).await;
        let mut report = final_report(&e, 3, 321);
        match mode {
            "missing" => {
                report.as_object_mut().unwrap().remove("egress_authority");
            }
            "incomplete" => report["egress"]["complete"] = json!(false),
            "launcher" => report["egress_authority"]["launcher_digest"] = json!("b".repeat(64)),
            "regression" => {
                let mut prior = final_report(&e, 2, 400);
                prior["state"] = json!("running");
                prior["egress"]["complete"] = json!(false);
                heartbeat(&l, &node, json!([prior])).await.unwrap();
                report["egress"]["observed"] =
                    json!(chrono::Utc::now().timestamp_micros() as f64 / 1e6);
            }
            "outside" => report["egress"]["bytes"] = json!(5001),
            "lost" => {
                report["state"] = json!("lost");
                report.as_object_mut().unwrap().remove("egress");
            }
            _ => unreachable!(),
        }
        heartbeat(&l, &node, json!([report.clone()])).await.unwrap();
        assert_eq!(closure(&l, &e).await, "terminal-conservative", "{mode}");
        assert_eq!(totals(&l).await, (5000, 0), "{mode}");
        let usage = l
            .store
            .usage(&l.operator, &l.tenant, Some(&l.project))
            .await
            .unwrap();
        assert_eq!(
            usage["totals"]["outbound_conservative_bytes"], 5000,
            "{mode}"
        );
        heartbeat(&l, &node, json!([report])).await.unwrap();
        assert_eq!(totals(&l).await, (5000, 0));
        l.finish().await;
    }
}
#[tokio::test]
async fn exact_final_counter_preserves_admission_month_and_prior_settlements() {
    let l = Lab::new().await;
    let (node, e, _) = fixture(&l).await;
    apply(&l, &node, &e, grant(0, "credit", 1000)).await;
    let frozen = apply(&l, &node, &e, request("freeze", 1, "freeze")).await;
    apply(&l, &node, &e, settlement(&frozen, 100, "settle")).await;
    apply(&l, &node, &e, grant(2, "refill", 500)).await;
    sqlx::query("UPDATE execution_egress_budgets SET period=(date_trunc('month',now() AT TIME ZONE 'UTC')-interval '1 month')::date WHERE execution_id=$1").bind(s(&e["id"])).execute(&l.store.pool).await.unwrap();
    let mut report = final_report(&e, 2, 300);
    report["egress_authority"]["launcher_digest"] = json!("broken");
    assert!(heartbeat(&l, &node, json!([report])).await.is_err());
    assert_eq!(totals(&l).await, (100, 0));
    heartbeat(&l, &node, json!([final_report(&e, 2, 300)]))
        .await
        .unwrap();
    let records: Vec<i64> = sqlx::query_scalar(
        "SELECT bytes FROM egress_allowance_usage WHERE execution_id=$1 ORDER BY period",
    )
    .bind(s(&e["id"]))
    .fetch_all(&l.store.pool)
    .await
    .unwrap();
    assert_eq!(records, vec![200, 100]);
    assert_eq!(totals(&l).await, (100, 0));
    assert_eq!(closure(&l, &e).await, "terminal-exact");
    l.finish().await;
}

#[tokio::test]
async fn budgeted_placement_requires_approval_and_pins_only_new_networked_executions() {
    let mut l = Lab::new().await;
    let node = l.node("budget-placement").await;
    let nid = s(&node["id"]);
    sqlx::query("UPDATE nodes SET cpu_percent=400,memory_mib=4096,instances=4 WHERE id=$1")
        .bind(nid)
        .execute(&l.store.pool)
        .await
        .unwrap();
    assert!(
        l.store
            .node_mode(&l.operator, nid, json!({"egress_budget_required":true}))
            .await
            .is_err()
    );
    assert!(
        l.store
            .node_mode(&l.operator, nid, json!({"egress_budget_required":"true"}))
            .await
            .is_err()
    );
    l.store
        .node_mode(
            &l.operator,
            nid,
            json!({"egress_budget_launcher":LAUNCHER,"egress_budget_required":true}),
        )
        .await
        .unwrap();
    assert!(
        l.store
            .node_mode(
                &l.operator,
                nid,
                json!({"egress_budget_launcher":Value::Null})
            )
            .await
            .is_err()
    );
    let op = networked(&mut l, "budgeted").await;
    let eid = s(&op["resource_id"]);
    l.store.schedule().await.unwrap();
    let assigned: Option<String> = sqlx::query_scalar("SELECT node_id FROM executions WHERE id=$1")
        .bind(eid)
        .fetch_one(&l.store.pool)
        .await
        .unwrap();
    assert!(
        assigned.is_none(),
        "operator flag alone does not establish observed capability"
    );
    let placement = || {
        sqlx::query_scalar::<_, String>(
            "SELECT reason FROM execution_placement WHERE execution_id=$1",
        )
        .bind(eid)
        .fetch_one(&l.store.pool)
    };
    assert_eq!(placement().await.unwrap(), "placement-egress-budget");
    l.store.heartbeat(nid,json!({"boot_id":"test-boot","reports":[],"confinement":HOST_CONFINEMENT,"egress_budget_contract":CONTRACT,"launcher_digest":LAUNCHER})).await.unwrap();
    l.store.schedule().await.unwrap();
    let assignment = l.store.assignment(nid, eid, 1).await.unwrap();
    assert_eq!(assignment["egress"]["launcher_digest"], LAUNCHER);
    assert_eq!(assignment["spec"]["egress_budget"], true);
    let offline = l.create("offline", json!({"artifact_id":l.artifact})).await;
    l.store.schedule().await.unwrap();
    assert!(
        l.store
            .assignment(nid, s(&offline["resource_id"]), 1)
            .await
            .unwrap()["egress"]
            .is_null()
    );
    l.store
        .node_mode(&l.operator, nid, json!({"egress_budget_required":false}))
        .await
        .unwrap();
    assert_eq!(
        l.store.assignment(nid, eid, 1).await.unwrap()["spec"]["egress_budget"],
        true
    );
    let replacement = "b".repeat(64);
    l.store
        .node_mode(
            &l.operator,
            nid,
            json!({"egress_budget_launcher":replacement}),
        )
        .await
        .unwrap();
    l.store.heartbeat(nid,json!({"boot_id":"test-boot","reports":[],"confinement":HOST_CONFINEMENT,"egress_budget_contract":CONTRACT,"launcher_digest":replacement})).await.unwrap();
    assert_eq!(
        l.store.assignment(nid, eid, 1).await.unwrap_err().status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        l.store
            .egress_budget(nid, eid, 1, grant(0, "wrong-launcher", 1))
            .await
            .unwrap_err()
            .status,
        StatusCode::CONFLICT
    );
    l.stop(eid, "stop-budgeted").await.unwrap();
    assert_eq!(
        l.store.assignment(nid, eid, 2).await.unwrap()["desired"],
        "stopped"
    );
    l.finish().await;
}
