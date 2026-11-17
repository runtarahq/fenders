//! PostgreSQL authority and real authenticated DNS. Node observations remain
//! protocol fixtures; these tests do not assert live guest connectivity.
//! Public HTTPS is static launch policy: an execution is bound to its origins'
//! addresses once, when assigned, and removing an origin stops it.
use super::*;
use fenders_control_plane::{apps::AppSubmission, public_egress::PublicEgressConfig};
use std::{sync::atomic::Ordering, time::Duration};

const RUNTIME: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
async fn setup() -> (Lab, Value, dns::DnsLab) {
    let dns = dns::DnsLab::new().await;
    let mut l = Lab::new().await;
    l.store = l.store.with_public_egress(dns.config.clone()).unwrap();
    let policy = l.store.public_egress_policy(&l.operator).await.unwrap();
    assert_eq!(policy["configured_digest"], dns.resolver().policy_digest());
    l.store.activate_public_egress(&l.operator,json!({"expected_revision":policy["revision"],"enabled":true,"digest":policy["configured_digest"]})).await.unwrap();
    let node = l.node("worker").await;
    approve_component(&l, &node, true, true).await;
    heartbeat(&l, &node, json!([])).await;
    (l, node, dns)
}
async fn heartbeat(l: &Lab, node: &Value, reports: Value) {
    l.store.heartbeat(s(&node["id"]),json!({"boot_id":"test-boot","reports":reports,"confinement":HOST_CONFINEMENT,"runtime_digest":RUNTIME})).await.unwrap();
}
async fn deploy(l: &Lab, hosts: Value, key: &str) -> Value {
    l.store.deploy_app(&l.operator,&l.tenant,&l.project,AppSubmission{value:json!({"name":key,"artifact_id":l.artifact,"triggers":{"manual":true,"http":false},"https_origins":hosts}),key,domain:"apps.test"}).await.unwrap()
}
async fn connections(l: &Lab, app: &str) -> Value {
    l.store
        .app_connections(&l.operator, &l.tenant, &l.project, app)
        .await
        .unwrap()
}
async fn set(l: &Lab, app: &str, hosts: Value, key: &str) -> Value {
    l.store.update_app_connections(&l.operator,&l.tenant,&l.project,app,json!({"expected_revision":connections(l,app).await["revision"],"endpoints":[],"https_origins":hosts}),key).await.unwrap()
}
async fn run(l: &Lab, app: &str, key: &str) -> Value {
    let op = l
        .store
        .run_app(&l.operator, &l.tenant, &l.project, app, key)
        .await
        .unwrap();
    let row = l
        .store
        .app_run(
            &l.operator,
            &l.tenant,
            &l.project,
            app,
            s(&op["resource_id"]),
        )
        .await
        .unwrap();
    l.execution(s(&row["execution_id"])).await
}
async fn assign(l: &Lab, node: &Value, e: &Value) -> Value {
    l.store.schedule().await.unwrap();
    l.store
        .assignment(s(&node["id"]), s(&e["id"]), n(&e["generation"]))
        .await
        .unwrap()
}
fn report(e: &Value, state: &str, sequence: i64) -> Value {
    json!({"id":e["id"],"generation":e["generation"],"state":state,"sequence":sequence,"cpu_usec":0,"memory_bytes":0})
}
async fn operation(l: &Lab, id: &Value) -> Value {
    sqlx::query_scalar("SELECT to_jsonb(o) FROM operations o WHERE id=$1")
        .bind(s(id))
        .fetch_one(&l.store.pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn public_policy_requires_operator_activation_and_a_reported_runtime() {
    let (l, node, dns) = setup().await;
    let (viewer, _) = l.credential("viewer", Some(&l.project)).await;
    assert_eq!(
        l.store
            .public_egress_policy(&viewer)
            .await
            .unwrap_err()
            .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        l.store
            .activate_public_egress(&viewer, json!({"expected_revision":2,"enabled":false}))
            .await
            .unwrap_err()
            .status,
        StatusCode::FORBIDDEN
    );
    assert!(
        l.store
            .activate_public_egress(&l.operator, json!({"expected_revision":1,"enabled":false}))
            .await
            .is_err()
    );
    assert!(
        l.store
            .activate_public_egress(
                &l.operator,
                json!({"expected_revision":2,"enabled":true,"digest":"b".repeat(64)})
            )
            .await
            .is_err()
    );
    let op = deploy(&l, json!(["https://API.TEST"]), "public").await;
    assert_eq!(
        connections(&l, s(&op["resource_id"])).await["https_origins"][0]["origin"],
        "https://api.test:443"
    );
    let e = run(&l, s(&op["resource_id"]), "run").await;
    // A node that has not said which guest runtime it runs is not given the run.
    l.store
        .heartbeat(
            s(&node["id"]),
            json!({"boot_id":"test-boot","reports":[],"confinement":HOST_CONFINEMENT}),
        )
        .await
        .unwrap();
    l.store.schedule().await.unwrap();
    assert!(l.execution(s(&e["id"])).await["node_id"].is_null());
    assert!(dns.queries.lock().await.is_empty());
    let placement = || {
        sqlx::query_scalar::<_, String>(
            "SELECT reason FROM execution_placement WHERE execution_id=$1",
        )
        .bind(s(&e["id"]))
        .fetch_one(&l.store.pool)
    };
    assert_eq!(placement().await.unwrap(), "placement-public-https");
    let unconfigured = Store::from_pool(l.store.pool.clone(), l.root.path()).unwrap();
    unconfigured.schedule().await.unwrap();
    assert_eq!(placement().await.unwrap(), "placement-public-policy");
    heartbeat(&l, &node, json!([])).await;
    let assignment = assign(&l, &node, &e).await;
    assert_eq!(assignment["spec"]["http_runtime_digest"], RUNTIME);
    assert_eq!(
        assignment["spec"]["http_public_targets"],
        "https://api.test:443=1.1.1.1"
    );
    assert_eq!(assignment["spec"]["tcp_allow"], json!(["1.1.1.1:443"]));
    assert_eq!(
        assignment["spec"]["http_allow"],
        json!(["https://api.test:443"])
    );
    // The whole policy is in the launch: no lease, deadline or start gate.
    for absent in ["network_start_blocked", "network_deadline_ns"] {
        assert!(assignment["spec"].get(absent).is_none(), "{absent}");
    }
    assert!(assignment.get("network").is_none());
    // A process with no resolver configuration assigns no public access.
    let old = Store::from_pool(l.store.pool.clone(), l.root.path()).unwrap();
    assert_eq!(
        old.assignment(s(&node["id"]), s(&e["id"]), 1)
            .await
            .unwrap_err()
            .status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    l.store
        .node_mode(&l.operator, s(&node["id"]), json!({"disabled":true}))
        .await
        .unwrap();
    let fenced = l.execution(s(&e["id"])).await;
    assert_eq!(fenced["desired"], "stopped");
    assert_eq!(fenced["reserved"], true);
    assert_eq!(fenced["generation"], 2);
    l.finish().await;
}

#[tokio::test]
async fn shared_ip_withdrawal_waits_for_fence_and_readding_never_reauthorizes_old_execution() {
    let (l, node, _dns) = setup().await;
    let hosts = json!(["https://a.test", "https://b.test"]);
    let (one, two) = tokio::join!(
        deploy(&l, hosts.clone(), "public"),
        deploy(&l, hosts.clone(), "public")
    );
    assert_eq!(one, two);
    let app = s(&one["resource_id"]);
    let initial = connections(&l, app).await;
    let e = run(&l, app, "run").await;
    let assignment = assign(&l, &node, &e).await;
    assert_eq!(assignment["spec"]["tcp_allow"], json!(["1.1.1.1:443"]));
    let op = set(&l, app, json!(["https://b.test"]), "remove-a").await;
    assert_eq!(op["state"], "pending");
    let fenced = l.execution(s(&e["id"])).await;
    assert_eq!(fenced["desired"], "stopped");
    assert_eq!(
        l.store
            .assignment(s(&node["id"]), s(&e["id"]), 1)
            .await
            .unwrap_err()
            .status,
        StatusCode::CONFLICT
    );
    let stopped = l
        .store
        .assignment(s(&node["id"]), s(&e["id"]), n(&fenced["generation"]))
        .await
        .unwrap();
    assert_eq!(stopped["desired"], "stopped");
    assert!(stopped["spec"].is_null());
    set(&l, app, hosts, "readd").await;
    let now = connections(&l, app).await;
    assert_eq!(now["https_origins"].as_array().unwrap().len(), 3);
    assert_ne!(
        now["https_origins"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["origin"] == "https://a.test:443" && v["desired"] == true)
            .unwrap()["id"],
        initial["https_origins"][0]["id"]
    );
    // Neither an old-generation terminal report nor a report that it still
    // runs proves that a worker holding the withdrawn origin stopped.
    heartbeat(&l, &node, json!([report(&e, "exited", 100)])).await;
    assert_eq!(l.execution(s(&e["id"])).await["reserved"], true);
    let fenced = l.execution(s(&e["id"])).await;
    heartbeat(&l, &node, json!([report(&fenced, "running", 101)])).await;
    assert_eq!(operation(&l, &op["id"]).await["state"], "pending");
    let mut stopped_report = report(&fenced, "stopped", 102);
    stopped_report["reason"] = json!("requested-stop");
    heartbeat(&l, &node, json!([stopped_report])).await;
    l.store.schedule().await.unwrap();
    assert_eq!(operation(&l, &op["id"]).await["state"], "succeeded");
    let history = l
        .store
        .app_history(
            &l.operator,
            &l.tenant,
            &l.project,
            app,
            "runs",
            Default::default(),
        )
        .await
        .unwrap();
    let observed_run = &history["items"][0];
    assert_eq!(observed_run["state"], "cancelled");
    assert_eq!(observed_run["reason"], "connection-removed");
    assert_eq!(observed_run["reserved"], false);
    assert_eq!(
        l.execution(s(&e["id"])).await["observation"]["reason"],
        "requested-stop"
    );
    assert_eq!(
        l.store
            .app_run(
                &l.operator,
                &l.tenant,
                &l.project,
                app,
                s(&observed_run["id"])
            )
            .await
            .unwrap()["diagnostic"],
        observed_run["diagnostic"]
    );
    assert_eq!(
        l.store
            .app(&l.operator, &l.tenant, &l.project, app)
            .await
            .unwrap()["latest_run"]["diagnostic"],
        observed_run["diagnostic"]
    );
    // Projection fixtures: even with a durable revocation relation, neither an
    // unknown outcome nor an independent completion becomes a cancellation.
    for (state, observation, expected) in [
        ("failed", json!({"reason":"worker-lost"}), "unknown"),
        (
            "exited",
            json!({"reason":"guest-exited","exit_code":0}),
            "succeeded",
        ),
        (
            "failed",
            json!({"reason":"guest-failed","exit_code":7}),
            "failed",
        ),
    ] {
        sqlx::query("UPDATE executions SET state=$1,observation=$2 WHERE id=$3")
            .bind(state)
            .bind(&observation)
            .bind(s(&e["id"]))
            .execute(&l.store.pool)
            .await
            .unwrap();
        let projected = l
            .store
            .app_run(
                &l.operator,
                &l.tenant,
                &l.project,
                app,
                s(&observed_run["id"]),
            )
            .await
            .unwrap();
        assert_eq!(projected["state"], expected);
        assert_eq!(projected["reason"], observation["reason"]);
        assert_eq!(projected["exit_code"], observation["exit_code"]);
    }
    assert_eq!(
        connections(&l, app).await["https_origins"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let next = run(&l, app, "next").await;
    assert_ne!(next["id"], e["id"]);
    assert_eq!(
        assign(&l, &node, &next).await["spec"]["http_allow"],
        json!(["https://a.test:443", "https://b.test:443"])
    );
    // An endpoint-only update preserves HTTPS intent.
    l.store
        .update_app_connections(
            &l.operator,
            &l.tenant,
            &l.project,
            app,
            json!({"expected_revision":connections(&l,app).await["revision"],"endpoints":[]}),
            "legacy",
        )
        .await
        .unwrap();
    assert_eq!(
        connections(&l, app).await["https_origins"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    // The same worker stop reason without an app revocation must not imply
    // that the customer removed a saved destination (e.g. a platform fence).
    let policy = l.store.public_egress_policy(&l.operator).await.unwrap();
    l.store
        .activate_public_egress(
            &l.operator,
            json!({"expected_revision":policy["revision"],"enabled":false}),
        )
        .await
        .unwrap();
    let fenced = l.execution(s(&next["id"])).await;
    let mut report = report(&fenced, "stopped", 1);
    report["reason"] = json!("requested-stop");
    heartbeat(&l, &node, json!([report])).await;
    assert_eq!(
        l.store
            .app(&l.operator, &l.tenant, &l.project, app)
            .await
            .unwrap()["latest_run"]["reason"],
        "requested-stop"
    );
    l.finish().await;
}

#[tokio::test]
async fn a_run_keeps_the_addresses_it_was_bound_to_and_the_next_run_resolves_again() {
    let (l, node, dns) = setup().await;
    let op = deploy(&l, json!(["https://changing.test"]), "public").await;
    let app = s(&op["resource_id"]);
    let e = run(&l, app, "run").await;
    let first = assign(&l, &node, &e).await;
    assert_eq!(
        first["spec"]["http_public_targets"],
        "https://changing.test:443=1.1.1.1"
    );
    let asked = dns.queries.lock().await.len();
    // The name now answers differently, or not at all: the run's policy is
    // what it was launched with, and asking for its assignment again (as the
    // node does for the artifact) neither resolves nor changes it.
    for mode in [1, 2] {
        dns.answer_mode.store(mode, Ordering::SeqCst);
        let again = l
            .store
            .assignment(s(&node["id"]), s(&e["id"]), 1)
            .await
            .unwrap();
        assert_eq!(again["spec"], first["spec"]);
    }
    assert_eq!(dns.queries.lock().await.len(), asked);
    let row = l.execution(s(&e["id"])).await;
    assert_eq!(row["desired"], "running");
    assert_eq!(row["generation"], 1);
    // While the name does not resolve, a new run is not started without it.
    heartbeat(&l, &node, json!([report(&row, "exited", 1)])).await;
    let next = run(&l, app, "next").await;
    l.store.schedule().await.unwrap();
    assert_eq!(
        l.store
            .assignment(s(&node["id"]), s(&next["id"]), 1)
            .await
            .unwrap_err()
            .status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM execution_https_bindings WHERE execution_id=$1"
        )
        .bind(s(&next["id"]))
        .fetch_one(&l.store.pool)
        .await
        .unwrap(),
        0
    );
    // Resolved again, the new run gets the new address; the old binding stays.
    dns.answer_mode.store(1, Ordering::SeqCst);
    let second = l
        .store
        .assignment(s(&node["id"]), s(&next["id"]), 1)
        .await
        .unwrap();
    assert_ne!(
        second["spec"]["http_public_targets"],
        first["spec"]["http_public_targets"]
    );
    assert_ne!(second["spec"]["tcp_allow"], first["spec"]["tcp_allow"]);
    let targets: String =
        sqlx::query_scalar("SELECT targets FROM execution_https_bindings WHERE execution_id=$1")
            .bind(s(&e["id"]))
            .fetch_one(&l.store.pool)
            .await
            .unwrap();
    assert_eq!(targets, "https://changing.test:443=1.1.1.1");
    l.finish().await;
}

#[tokio::test]
async fn resolution_does_not_hold_admission_and_withdrawal_wins_inflight_assignment() {
    let (l, node, dns) = setup().await;
    let op = deploy(&l, json!(["https://held.test"]), "public").await;
    let app = s(&op["resource_id"]);
    let e = run(&l, app, "run").await;
    l.store.schedule().await.unwrap();
    let assignment = l.store.assignment(s(&node["id"]), s(&e["id"]), 1);
    let removal = async {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if !dns.queries.lock().await.is_empty() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let op = tokio::time::timeout(Duration::from_secs(1), set(&l, app, json!([]), "remove"))
            .await
            .expect("DNS must not hold admission lock");
        assert_eq!(op["state"], "pending");
        dns.gate.add_permits(1);
    };
    let (result, ()) = tokio::join!(assignment, removal);
    assert_eq!(result.unwrap_err().status, StatusCode::CONFLICT);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM execution_https_bindings")
            .fetch_one(&l.store.pool)
            .await
            .unwrap(),
        0
    );
    assert_eq!(l.execution(s(&e["id"])).await["desired"], "stopped");
    l.finish().await;
}

#[tokio::test]
async fn disabled_policy_releases_unassigned_work_and_keeps_desired_connections() {
    let (l, node, _dns) = setup().await;
    let op = deploy(&l, json!(["https://api.test"]), "public").await;
    let app = s(&op["resource_id"]);
    let e = run(&l, app, "run").await;
    let policy = l
        .store
        .activate_public_egress(&l.operator, json!({"enabled":false,"expected_revision":2}))
        .await
        .unwrap();
    assert_eq!(policy["enabled"], false);
    assert_eq!(l.execution(s(&e["id"])).await["reserved"], false);
    assert_eq!(
        connections(&l, app).await["https_origins"][0]["desired"],
        true
    );
    assert_eq!(
        connections(&l, app).await["https_origins"][0]["reason"],
        "public-policy-disabled"
    );
    assert!(l.store.deploy_app(&l.operator,&l.tenant,&l.project,AppSubmission{value:json!({"name":"blocked","artifact_id":l.artifact,"triggers":{"http":false,"manual":true},"https_origins":["https://other.test"]}),key:"blocked",domain:"apps.test"}).await.is_err());
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM apps")
            .fetch_one(&l.store.pool)
            .await
            .unwrap(),
        1
    );
    // Even a configured alternate policy cannot be used without activation.
    let other = Store::from_pool(l.store.pool.clone(), l.root.path())
        .unwrap()
        .with_public_egress(PublicEgressConfig {
            dns_address: "127.0.0.1:853".parse().unwrap(),
            dns_server_name: "resolver.test".into(),
            dns_ca_pem: None,
            denied_ipv4: vec![],
        })
        .unwrap();
    assert!(
        other
            .activate_public_egress(
                &l.operator,
                json!({"expected_revision":3,"enabled":true,"digest":policy["digest"]})
            )
            .await
            .is_err()
    );
    assert!(
        l.store
            .assignment(s(&node["id"]), s(&e["id"]), 1)
            .await
            .is_err()
    );
    l.finish().await;
}

#[tokio::test]
async fn a_resolution_that_expires_before_it_is_bound_is_not_used() {
    let (l, node, dns) = setup().await;
    let held = deploy(&l, json!(["https://held-ttl.test"]), "held").await;
    let e = run(&l, s(&held["resource_id"]), "held-run").await;
    l.store.schedule().await.unwrap();
    let assignment = l.store.assignment(s(&node["id"]), s(&e["id"]), 1);
    let lock = async {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if dns
                    .queries
                    .lock()
                    .await
                    .iter()
                    .any(|(n, _)| n == "held-ttl.test.")
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let tx = l.store.transaction(true, false).await.unwrap();
        dns.gate.add_permits(1);
        tokio::time::sleep(Duration::from_millis(1200)).await;
        tx.commit().await.unwrap();
    };
    let (result, ()) = tokio::join!(assignment, lock);
    assert_eq!(result.unwrap_err().status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM execution_https_bindings WHERE execution_id=$1"
        )
        .bind(s(&e["id"]))
        .fetch_one(&l.store.pool)
        .await
        .unwrap(),
        0
    );
    l.finish().await;
}

#[tokio::test]
async fn an_endpoint_and_an_origin_make_one_launch_policy() {
    let (mut l, node, catalog) = super::app_connections::setup().await;
    let dns = dns::DnsLab::new().await;
    l.store = l.store.with_public_egress(dns.config.clone()).unwrap();
    let policy = l.store.public_egress_policy(&l.operator).await.unwrap();
    l.store
        .activate_public_egress(
            &l.operator,
            json!({"expected_revision":1,"enabled":true,"digest":policy["configured_digest"]}),
        )
        .await
        .unwrap();
    heartbeat(&l, &node, json!([])).await;
    let service = super::app_connections::endpoint(&l, &catalog, 2).await;
    let op = super::app_connections::deploy(&l, &service, false, "mixed").await;
    let app = s(&op["resource_id"]);
    l.store.update_app_connections(&l.operator,&l.tenant,&l.project,app,json!({"expected_revision":connections(&l,app).await["revision"],"endpoints":[{"endpoint_id":service["id"]}],"https_origins":["https://changing.test"]}),"public").await.unwrap();
    let e = run(&l, app, "run").await;
    let assigned = assign(&l, &node, &e).await;
    assert_eq!(
        assigned["spec"]["tcp_allow"],
        json!(["1.1.1.1:443", "10.50.0.2:5432"])
    );
    assert_eq!(
        assigned["spec"]["http_allow"],
        json!(["https://changing.test:443"])
    );
    assert!(s(&assigned["spec"]["env"]["PGPASSWORD"]).starts_with("s_"));
    assert_eq!(
        connections(&l, app).await["https_origins"][0]["state"],
        "allowed"
    );
    // Removing the origin alone stops the run that also holds the endpoint.
    let removed = l.store.update_app_connections(&l.operator,&l.tenant,&l.project,app,json!({"expected_revision":connections(&l,app).await["revision"],"endpoints":[{"endpoint_id":service["id"]}],"https_origins":[]}),"private").await.unwrap();
    assert_eq!(removed["state"], "pending");
    let stopped = l.execution(s(&e["id"])).await;
    assert_eq!(stopped["desired"], "stopped");
    heartbeat(&l, &node, json!([report(&stopped, "stopped", 1)])).await;
    assert_eq!(operation(&l, &removed["id"]).await["state"], "succeeded");
    let next = run(&l, app, "next").await;
    let assigned = assign(&l, &node, &next).await;
    assert_eq!(assigned["spec"]["tcp_allow"], json!(["10.50.0.2:5432"]));
    assert_eq!(assigned["spec"]["http_allow"], json!([]));
    assert!(assigned["spec"].get("http_public_targets").is_none());
    l.finish().await;
}

#[tokio::test]
async fn https_intent_is_scoped_revisioned_and_blocked_during_recovery() {
    let (l, node, dns) = setup().await;
    let op = deploy(&l, json!(["https://api.test"]), "public").await;
    let app = s(&op["resource_id"]);
    let (viewer, _) = l.credential("viewer", Some(&l.project)).await;
    let input = json!({"expected_revision":connections(&l,app).await["revision"],"endpoints":[],"https_origins":["https://a.test"]});
    assert_eq!(
        l.store
            .update_app_connections(&viewer, &l.tenant, &l.project, app, input.clone(), "denied")
            .await
            .unwrap_err()
            .status,
        StatusCode::FORBIDDEN
    );
    assert!(
        l.store
            .app_connections(&l.operator, &l.tenant, &uid(), app)
            .await
            .is_err()
    );
    for origins in [
        json!(["http://api.test"]),
        json!(["https://127.0.0.1"]),
        json!(["https://api.test", "https://API.TEST:443"]),
        json!(["https://api.test/path"]),
        json!(vec!["https://api.test"; 17]),
    ] {
        let mut bad = input.clone();
        bad["https_origins"] = origins;
        assert_eq!(
            l.store
                .update_app_connections(&l.operator, &l.tenant, &l.project, app, bad, "invalid")
                .await
                .unwrap_err()
                .status,
            StatusCode::BAD_REQUEST
        );
    }
    let update = l
        .store
        .update_app_connections(
            &l.operator,
            &l.tenant,
            &l.project,
            app,
            input.clone(),
            "save",
        )
        .await
        .unwrap();
    assert_eq!(
        l.store
            .update_app_connections(
                &l.operator,
                &l.tenant,
                &l.project,
                app,
                input.clone(),
                "save"
            )
            .await
            .unwrap(),
        update
    );
    assert_eq!(
        l.store
            .update_app_connections(
                &l.operator,
                &l.tenant,
                &l.project,
                app,
                input.clone(),
                "stale"
            )
            .await
            .unwrap_err()
            .status,
        StatusCode::CONFLICT
    );
    let e = run(&l, app, "run").await;
    l.store.schedule().await.unwrap();
    sqlx::query("UPDATE recovery_barrier SET active=true")
        .execute(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(
        l.store
            .assignment(s(&node["id"]), s(&e["id"]), 1)
            .await
            .unwrap_err()
            .status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(dns.queries.lock().await.is_empty());
    assert_eq!(
        l.store
            .update_app_connections(&l.operator, &l.tenant, &l.project, app, input, "recovery")
            .await
            .unwrap_err()
            .status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        connections(&l, app).await["https_origins"][0]["origin"],
        "https://a.test:443"
    );
    l.finish().await;
}

#[tokio::test]
async fn origin_removal_waits_for_both_http_and_command_then_replaces_http_without_access() {
    let (l, node, _dns) = setup().await;
    sqlx::query("UPDATE nodes SET memory_mib=512,cpu_percent=400,instances=4 WHERE id=$1")
        .bind(s(&node["id"]))
        .execute(&l.store.pool)
        .await
        .unwrap();
    let op=l.store.deploy_app(&l.operator,&l.tenant,&l.project,AppSubmission{value:json!({"name":"dual","artifact_id":l.artifact,"triggers":{"manual":true,"http":true},"https_origins":["https://api.test"],"configuration":{"keep_warm":true}}),key:"dual",domain:"apps.test"}).await.unwrap();
    let app = s(&op["resource_id"]);
    let http = l.execution(s(&l.http(app).await["execution_id"])).await;
    assign(&l, &node, &http).await;
    let http = l.execution(s(&http["id"])).await;
    heartbeat(&l, &node, json!([report(&http, "running", 1)])).await;
    assert_eq!(l.http(app).await["state"], "serving");
    let command = run(&l, app, "command").await;
    assign(&l, &node, &command).await;
    let removed = set(&l, app, json!([]), "remove").await;
    assert_eq!(removed["state"], "pending");
    let old = l.execution(s(&http["id"])).await;
    assert_eq!(old["desired"], "stopped");
    assert_eq!(l.execution(s(&command["id"])).await["desired"], "stopped");
    heartbeat(&l, &node, json!([report(&old, "stopped", 2)])).await;
    l.store.schedule().await.unwrap();
    let new = l.execution(s(&l.http(app).await["execution_id"])).await;
    assert_ne!(new["id"], http["id"]);
    let assigned = assign(&l, &node, &new).await;
    assert_eq!(assigned["spec"]["http_allow"], json!([]));
    assert!(assigned["network"].is_null());
    heartbeat(&l, &node, json!([report(&new, "running", 1)])).await;
    assert_eq!(operation(&l, &removed["id"]).await["state"], "pending");
    let old = l.execution(s(&command["id"])).await;
    heartbeat(&l, &node, json!([report(&old, "stopped", 2)])).await;
    assert_eq!(operation(&l, &removed["id"]).await["state"], "succeeded");
    assert_eq!(connections(&l, app).await["https_origins"], json!([]));
    l.finish().await;
}

#[tokio::test]
async fn scheduled_runs_pin_current_grants_and_code_reactivation_does_not_restore_them() {
    let (l, node, _dns) = setup().await;
    let op=l.store.deploy_app(&l.operator,&l.tenant,&l.project,AppSubmission{value:json!({"name":"scheduled","artifact_id":l.artifact,"triggers":{"manual":true,"http":false,"schedule":{"enabled":true,"expression":"* * * * *","timezone":"UTC"}},"https_origins":["https://api.test"]}),key:"schedule",domain:"apps.test"}).await.unwrap();
    let app = s(&op["resource_id"]);
    sqlx::query("UPDATE app_schedules SET next_at=date_trunc('minute',now()) WHERE app_id=$1")
        .bind(app)
        .execute(&l.store.pool)
        .await
        .unwrap();
    l.store.claim_schedule_occurrences().await.unwrap();
    sqlx::query("UPDATE app_run_dispatch SET deadline=now()+interval '5 minutes'")
        .execute(&l.store.pool)
        .await
        .unwrap();
    l.store.dispatch_schedule_runs().await.unwrap();
    let execution: String = sqlx::query_scalar("SELECT execution_id FROM app_runs WHERE app_id=$1")
        .bind(app)
        .fetch_one(&l.store.pool)
        .await
        .unwrap();
    let e = l.execution(&execution).await;
    assert_eq!(
        assign(&l, &node, &e).await["spec"]["http_public_targets"],
        "https://api.test:443=1.1.1.1"
    );
    let removed = set(&l, app, json!([]), "remove").await;
    let e = l.execution(&execution).await;
    heartbeat(&l, &node, json!([report(&e, "stopped", 1)])).await;
    assert_eq!(operation(&l, &removed["id"]).await["state"], "succeeded");
    let version = l
        .store
        .app_versions(&l.operator, &l.tenant, &l.project, app, None)
        .await
        .unwrap()["items"][0]["id"]
        .clone();
    l.store
        .activate_app_release(
            &l.operator,
            &l.tenant,
            &l.project,
            app,
            json!({"version_id":version,"expected_revision":connections(&l,app).await["revision"]}),
            "reactivate-code",
        )
        .await
        .unwrap();
    let next = run(&l, app, "manual").await;
    assert_eq!(
        assign(&l, &node, &next).await["spec"]["http_allow"],
        json!([])
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM app_execution_https WHERE execution_id=$1"
        )
        .bind(s(&next["id"]))
        .fetch_one(&l.store.pool)
        .await
        .unwrap(),
        0
    );
    l.finish().await;
}

#[tokio::test]
async fn customer_https_metadata_and_validation_are_scoped_reads_without_resolution_or_grants() {
    let (l, _node, dns) = setup().await;
    let (viewer, credential) = l.credential("viewer", Some(&l.project)).await;
    assert_eq!(
        l.store
            .https_access(&viewer, &l.tenant, &l.project)
            .await
            .unwrap(),
        json!({"available":true,"max_origins":16,"reason":null})
    );
    let api = api::router(l.store.clone());
    let response = api
        .clone()
        .oneshot(
            Request::get(format!(
                "/v1/tenants/{}/projects/{}/https-access",
                l.tenant, l.project
            ))
            .header(
                "Authorization",
                format!("Bearer {}", s(&credential["token"])),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(
        body,
        json!({"available":true,"max_origins":16,"reason":null})
    );
    let valid = api
        .oneshot(
            Request::post(format!(
                "/v1/tenants/{}/projects/{}/https-access/validate",
                l.tenant, l.project
            ))
            .header(
                "Authorization",
                format!("Bearer {}", s(&credential["token"])),
            )
            .header("Content-Type", "application/json")
            .body(Body::from(
                json!({"origins":["https://API.TEST","https://b.test:8443"]}).to_string(),
            ))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(valid.status(), StatusCode::OK);
    assert_eq!(
        serde_json::from_slice::<Value>(&to_bytes(valid.into_body(), 4096).await.unwrap()).unwrap(),
        json!({"origins":["https://api.test:443","https://b.test:8443"]})
    );
    assert!(dns.queries.lock().await.is_empty());
    for table in [
        "app_https_connections",
        "execution_https_bindings",
        "executions",
    ] {
        assert_eq!(
            sqlx::query_scalar::<_, i64>(&format!("SELECT count(*) FROM {table}"))
                .fetch_one(&l.store.pool)
                .await
                .unwrap(),
            0
        );
    }
    assert_eq!(
        l.store
            .https_access(&viewer, &l.tenant, &uid())
            .await
            .unwrap_err()
            .status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        l.store
            .validate_https_access(&viewer, &uid(), &l.project, json!({"origins":[]}))
            .await
            .unwrap_err()
            .status,
        StatusCode::NOT_FOUND
    );
    for body in [
        json!({"origins":["https://api.test","https://API.TEST:443"]}),
        json!({"origins":["https://api.test/path"]}),
        json!({"origins":["https://0x01010101"]}),
        json!({"origins":["https://*.test"]}),
        json!({"origins":[],"grant":true}),
    ] {
        assert_eq!(
            l.store
                .validate_https_access(&viewer, &l.tenant, &l.project, body)
                .await
                .unwrap_err()
                .status,
            StatusCode::BAD_REQUEST
        );
    }
    sqlx::query("UPDATE recovery_barrier SET active=true")
        .execute(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(
        l.store
            .https_access(&viewer, &l.tenant, &l.project)
            .await
            .unwrap()["available"],
        false
    );
    sqlx::query("UPDATE recovery_barrier SET active=false")
        .execute(&l.store.pool)
        .await
        .unwrap();
    let unconfigured = Store::from_pool(l.store.pool.clone(), l.root.path()).unwrap();
    assert_eq!(
        unconfigured
            .https_access(&viewer, &l.tenant, &l.project)
            .await
            .unwrap()["available"],
        false
    );
    l.store
        .activate_public_egress(&l.operator, json!({"enabled":false,"expected_revision":2}))
        .await
        .unwrap();
    assert_eq!(
        l.store
            .https_access(&viewer, &l.tenant, &l.project)
            .await
            .unwrap()["available"],
        false
    );
    // Syntax checking still works during an outage and never grants access.
    assert_eq!(
        l.store
            .validate_https_access(
                &viewer,
                &l.tenant,
                &l.project,
                json!({"origins":["https://API.TEST"]})
            )
            .await
            .unwrap()["origins"],
        json!(["https://api.test:443"])
    );
    l.finish().await;
}

#[tokio::test]
async fn https_summaries_share_detail_states_and_bound_scoped_origin_previews() {
    let (l, node, _dns) = setup().await;
    let origins = json!([
        "https://a.test",
        "https://b.test",
        "https://c.test",
        "https://d.test",
        "https://e.test"
    ]);
    let op = deploy(&l, origins.clone(), "summaries").await;
    let app = s(&op["resource_id"]);
    let e = run(&l, app, "run").await;
    assign(&l, &node, &e).await;
    let summary = l
        .store
        .app(&l.operator, &l.tenant, &l.project, app)
        .await
        .unwrap()["https_connections"]
        .clone();
    assert_eq!(summary["total"], 5);
    assert_eq!(summary["destinations"], 5);
    assert_eq!(summary["allowed"], 5);
    assert_eq!(summary["pending"], 0);
    assert_eq!(summary["items"].as_array().unwrap().len(), 3);
    let detail = connections(&l, app).await;
    for item in summary["items"].as_array().unwrap() {
        let full = detail["https_origins"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == item["id"])
            .unwrap();
        for key in ["origin", "state", "reason", "desired"] {
            assert_eq!(item[key], full[key]);
        }
    }
    assert!(!summary.to_string().contains("1.1.1.1"));
    assert!(!summary.to_string().contains(RUNTIME));
    let (viewer, _) = l.credential("viewer", Some(&l.project)).await;
    assert_eq!(
        l.store
            .app(&viewer, &l.tenant, &l.project, app)
            .await
            .unwrap()["https_connections"],
        summary
    );
    assert_eq!(
        l.store
            .app(&viewer, &l.tenant, &uid(), app)
            .await
            .unwrap_err()
            .status,
        StatusCode::NOT_FOUND
    );
    let page = l
        .store
        .apps(&viewer, &l.tenant, &l.project, Default::default())
        .await
        .unwrap();
    assert_eq!(page["items"][0]["https_connections"], summary);
    let removed = set(&l, app, json!([]), "remove").await;
    assert_eq!(removed["state"], "pending");
    let summary = l
        .store
        .app(&viewer, &l.tenant, &l.project, app)
        .await
        .unwrap()["https_connections"]
        .clone();
    assert_eq!(summary["revoking"], 5);
    assert_eq!(summary["items"].as_array().unwrap().len(), 3);
    set(&l, app, origins, "readd").await;
    let summary = l
        .store
        .app(&viewer, &l.tenant, &l.project, app)
        .await
        .unwrap()["https_connections"]
        .clone();
    assert_eq!(summary["total"], 10);
    assert_eq!(summary["destinations"], 5);
    // What is saved again is allowed for the next run at once.
    assert_eq!(summary["allowed"], 5);
    assert_eq!(summary["revoking"], 5);
    let fenced = l.execution(s(&e["id"])).await;
    heartbeat(&l, &node, json!([report(&fenced, "stopped", 1)])).await;
    assert_eq!(
        l.store
            .app(&viewer, &l.tenant, &l.project, app)
            .await
            .unwrap()["https_connections"]["total"],
        5
    );
    l.finish().await;
}
