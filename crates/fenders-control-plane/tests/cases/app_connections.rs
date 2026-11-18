//! Real database/admission/assignment proofs with external endpoint metadata and
//! synthetic node observations. These cases do not claim live VM or socket closure evidence.
//! Connections are static launch policy: an assignment carries what the run
//! may reach, and removing a connection stops the runs that hold it.
use super::*;
use fenders_control_plane::apps::AppSubmission;

pub(super) async fn setup() -> (Lab, Value, Value) {
    let mut l = Lab::new().await;
    l.store = l.store.with_external_network(
        fenders_control_plane::external_endpoints::ExternalNetworkPolicy {
            allowed_cidrs: vec!["10.50.0.0/24".parse().unwrap()],
            denied_cidrs: vec![],
        },
    );
    let node = l.node("worker").await;
    sqlx::query("UPDATE nodes SET memory_mib=512,instances=4 WHERE id=$1")
        .bind(s(&node["id"]))
        .execute(&l.store.pool)
        .await
        .unwrap();
    approve_component(&l, &node, true, true).await;
    let pki = l.root.path().join("external-pki");
    fenders_control_plane::pki::create(
        &pki,
        &std::collections::BTreeMap::from([("database".into(), vec!["10.50.0.2".into()])]),
    )
    .unwrap();
    let ca = json!(std::fs::read_to_string(pki.join("ca.pem")).unwrap());
    (l, node, ca)
}
pub(super) async fn endpoint(l: &Lab, ca: &Value, suffix: u8) -> Value {
    endpoint_in_project(l, &l.project, ca, suffix).await
}
async fn endpoint_in_project(l: &Lab, project: &str, ca: &Value, suffix: u8) -> Value {
    let name = format!("db-{suffix}");
    let username = l
        .store
        .create_secret(
            &l.operator,
            &l.tenant,
            project,
            json!({"name":format!("{name}-user"),"value":format!("user-{suffix}")}),
        )
        .await
        .unwrap();
    let password = l
        .store
        .create_secret(
            &l.operator,
            &l.tenant,
            project,
            json!({"name":format!("{name}-password"),"value":format!("s_password-{suffix}")}),
        )
        .await
        .unwrap();
    let op = l.store.create_endpoint(&l.operator, &l.tenant, project,
        json!({"name":name,"host":format!("10.50.0.{suffix}"),"port":5432,"database":"demo",
            "username_secret_id":username["id"],"password_secret_id":password["id"],"ca_certificate":ca}), &name).await.unwrap();
    l.store
        .resources(
            &l.operator,
            &l.tenant,
            project,
            "external-endpoints",
            Some(s(&op["resource_id"])),
        )
        .await
        .unwrap()
}
pub(super) async fn deploy(l: &Lab, service: &Value, http: bool, key: &str) -> Value {
    l.store.deploy_app(&l.operator,&l.tenant,&l.project,AppSubmission{value:json!({"name":key,"artifact_id":l.artifact,"triggers":{"manual":true,"http":http},"configuration":{"env":{"MODE":"current"},"keep_warm":false},"endpoints":[{"endpoint_id":service["id"]}]}),key,domain:"apps.test"}).await.unwrap()
}
async fn connections(l: &Lab, app: &str) -> Value {
    l.store
        .app_connections(&l.operator, &l.tenant, &l.project, app)
        .await
        .unwrap()
}

async fn set(l: &Lab, app: &str, services: Value, key: &str) -> Value {
    l.store
        .update_app_connections(
            &l.operator,
            &l.tenant,
            &l.project,
            app,
            json!({"expected_revision":connections(l,app).await["revision"],"endpoints":services}),
            key,
        )
        .await
        .unwrap()
}
async fn run(l: &Lab, app: &str, key: &str) -> Value {
    let op = l
        .store
        .run_app(&l.operator, &l.tenant, &l.project, app, key)
        .await
        .unwrap();
    let run = l
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
    l.execution(s(&run["execution_id"])).await
}
async fn assign(l: &Lab, node: &Value, e: &Value) -> Value {
    l.store.schedule().await.unwrap();
    l.store
        .assignment(s(&node["id"]), s(&e["id"]), n(&e["generation"]))
        .await
        .unwrap()
}
#[tokio::test]
async fn deploy_connections_are_atomic_idempotent_and_generate_scoped_fields() {
    let (l, node, ca) = setup().await;
    let service = endpoint(&l, &ca, 2).await;
    let (a, b) = tokio::join!(
        deploy(&l, &service, false, "app"),
        deploy(&l, &service, false, "app")
    );
    assert_eq!(a, b);
    let app = s(&a["resource_id"]);
    assert_eq!(
        connections(&l, app).await["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM executions")
            .fetch_one(&l.store.pool)
            .await
            .unwrap(),
        0
    );
    let e = run(&l, app, "run").await;
    let assignment = assign(&l, &node, &e).await;
    assert_eq!(assignment["spec"]["env"]["PGHOST"], "10.50.0.2");
    assert_eq!(assignment["spec"]["env"]["MODE"], "current");
    assert!(
        s(&assignment["spec"]["env"]["PGSSLROOTCERT_PEM"])
            .starts_with("-----BEGIN CERTIFICATE-----")
    );
    assert!(s(&assignment["spec"]["env"]["PGPASSWORD"]).starts_with("s_"));
    assert_eq!(
        assignment["spec"]["log_redact_env"],
        json!(["PGPASSWORD", "PGUSER"])
    );
    assert_eq!(assignment["spec"]["tcp_allow"], json!(["10.50.0.2:5432"]));
    assert_eq!(assignment["spec"]["http_allow"], json!([]));
    // Nothing to renew: no lease, deadline or start gate.
    assert!(assignment.get("network").is_none());
    for absent in ["network_start_blocked", "network_deadline_ns"] {
        assert!(assignment["spec"].get(absent).is_none(), "{absent}");
    }
    assert!(e["spec"]["env"]["PGPASSWORD"].is_null());
    let public = connections(&l, app).await;
    assert!(
        !public
            .to_string()
            .contains(s(&assignment["spec"]["env"]["PGPASSWORD"]))
    );
    l.finish().await;
}

#[tokio::test]
async fn removal_stops_the_run_that_holds_it_and_readding_never_reopens_it() {
    let (l, node, ca) = setup().await;
    let service = endpoint(&l, &ca, 2).await;
    let deployed = deploy(&l, &service, false, "app").await;
    let app = s(&deployed["resource_id"]);
    let first = connections(&l, app).await["items"][0]["id"].clone();
    let e = run(&l, app, "first").await;
    assign(&l, &node, &e).await;
    l.report(&node, &e, "running", 1).await;
    let removed = set(&l, app, json!([]), "remove").await;
    assert_eq!(removed["state"], "pending");
    assert_eq!(connections(&l, app).await["items"][0]["state"], "revoking");
    assert_eq!(summary(&l, app).await["revoking"], 1);
    let stopped = l.execution(s(&e["id"])).await;
    assert_eq!(stopped["desired"], "stopped");
    assert_eq!(stopped["generation"], 2);
    assert_eq!(stopped["reserved"], true);
    assert_eq!(
        l.store
            .assignment(s(&node["id"]), s(&e["id"]), 1)
            .await
            .unwrap_err()
            .status,
        StatusCode::CONFLICT
    );
    let told = l
        .store
        .assignment(s(&node["id"]), s(&e["id"]), 2)
        .await
        .unwrap();
    assert_eq!(told["desired"], "stopped");
    assert!(told["spec"].is_null());
    let added = set(&l, app, json!([{"endpoint_id":service["id"]}]), "readd").await;
    assert_eq!(added["state"], "succeeded");
    let counts = summary(&l, app).await;
    assert_eq!(counts["total"], 2);
    assert_eq!(counts["allowed"], 1);
    assert_eq!(counts["revoking"], 1);
    // The connection saved again belongs to later runs, not to this one.
    assert_eq!(l.execution(s(&e["id"])).await["desired"], "stopped");
    // Only the run's end finishes the removal: not a report that it runs.
    l.report(&node, &stopped, "running", 2).await;
    assert_eq!(l.operation(&removed).await["state"], "pending");
    l.store.heartbeat(s(&node["id"]),json!({"boot_id":"test-boot","confinement":HOST_CONFINEMENT,"reports":[{"id":stopped["id"],"generation":stopped["generation"],"state":"stopped","sequence":3,"cpu_usec":0,"memory_bytes":0,"reason":"requested-stop"}]})).await.unwrap();
    assert_eq!(l.operation(&removed).await["state"], "succeeded");
    let current = connections(&l, app).await;
    assert_eq!(current["items"].as_array().unwrap().len(), 1);
    assert_eq!(summary(&l, app).await["revoking"], 0);
    assert_ne!(current["items"][0]["id"], first);
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT state FROM network_grants WHERE execution_id=$1")
            .bind(s(&e["id"]))
            .fetch_one(&l.store.pool)
            .await
            .unwrap(),
        "revoked"
    );
    // The customer reads why the run was cancelled.
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
    assert_eq!(history["items"][0]["state"], "cancelled");
    assert_eq!(history["items"][0]["reason"], "connection-removed");
    let next = run(&l, app, "next-explicit-event").await;
    assert_eq!(
        assign(&l, &node, &next).await["spec"]["tcp_allow"],
        json!(["10.50.0.2:5432"])
    );
    l.finish().await;
}

#[tokio::test]
async fn a_destination_outside_the_operators_ranges_is_refused_at_launch() {
    let (mut l, node, ca) = setup().await;
    let service = endpoint(&l, &ca, 2).await;
    let deployed = deploy(&l, &service, false, "ranges").await;
    let e = run(&l, s(&deployed["resource_id"]), "run").await;
    l.store.schedule().await.unwrap();
    // The operator narrows the ranges after the endpoint was registered.
    l.store = l.store.with_external_network(
        fenders_control_plane::external_endpoints::ExternalNetworkPolicy {
            allowed_cidrs: vec!["10.50.0.0/24".parse().unwrap()],
            denied_cidrs: vec!["10.50.0.2/32".parse().unwrap()],
        },
    );
    assert_eq!(
        l.store
            .assignment(s(&node["id"]), s(&e["id"]), 1)
            .await
            .unwrap_err()
            .status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    // A control plane with no ranges at all gives no run a connection.
    let unconfigured = Store::from_pool(l.store.pool.clone(), l.root.path()).unwrap();
    assert_eq!(
        unconfigured
            .assignment(s(&node["id"]), s(&e["id"]), 1)
            .await
            .unwrap_err()
            .status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    l.finish().await;
}

#[tokio::test]
async fn removing_before_assignment_cancels_queued_work_and_rollback_keeps_current_access() {
    let (l, node, ca) = setup().await;
    let service = endpoint(&l, &ca, 2).await;
    let deployed = deploy(&l, &service, false, "app").await;
    let app = s(&deployed["resource_id"]);
    let e = run(&l, app, "queued").await;
    let removed = set(&l, app, json!([]), "remove").await;
    assert_eq!(removed["state"], "succeeded");
    assert_eq!(l.execution(s(&e["id"])).await["reserved"], false);
    let summary = l
        .store
        .app(&l.operator, &l.tenant, &l.project, app)
        .await
        .unwrap();
    l.store.activate_app_release(&l.operator,&l.tenant,&l.project,app,json!({"expected_revision":summary["revision"],"version_id":summary["active_release"]["version_id"]}),"rollback").await.unwrap();
    let next = run(&l, app, "after-rollback").await;
    let assigned = assign(&l, &node, &next).await;
    assert_eq!(assigned["spec"]["env"], json!({"MODE":"current"}));
    assert_eq!(assigned["spec"]["tcp_allow"], json!([]));
    assert!(assigned["network"].is_null());
    assert_eq!(connections(&l, app).await["items"], json!([]));
    l.finish().await;
}

#[tokio::test]
async fn connection_completion_waits_for_http_replacement_and_the_commands_end() {
    let (l, node, ca) = setup().await;
    let service = endpoint(&l, &ca, 2).await;
    let deployed = deploy(&l, &service, true, "dual").await;
    let app = s(&deployed["resource_id"]);
    let http = l.execution(s(&l.http(app).await["execution_id"])).await;
    assert_eq!(
        connections(&l, app).await["items"][0]["reason"],
        "http-release-pending"
    );
    assign(&l, &node, &http).await;
    l.report(&node, &http, "running", 1).await;
    assert_eq!(l.http(app).await["state"], "serving");
    assert_eq!(connections(&l, app).await["items"][0]["state"], "allowed");
    assert_eq!(summary(&l, app).await["allowed"], 1);
    sqlx::query("UPDATE nodes SET last_seen=now()-interval '1 minute' WHERE id=$1")
        .bind(s(&node["id"]))
        .execute(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(summary(&l, app).await["pending"], 1);
    assert_eq!(
        connections(&l, app).await["items"][0]["reason"],
        "http-release-pending"
    );
    sqlx::query("UPDATE nodes SET last_seen=now() WHERE id=$1")
        .bind(s(&node["id"]))
        .execute(&l.store.pool)
        .await
        .unwrap();
    let command = run(&l, app, "command").await;
    assign(&l, &node, &command).await;
    l.report(&node, &command, "running", 1).await;
    let removed = set(&l, app, json!([]), "remove").await;
    assert_eq!(removed["state"], "pending");
    // Both the serving execution and the command hold the connection.
    let old = l.execution(s(&http["id"])).await;
    assert_eq!(old["desired"], "stopped");
    assert_eq!(l.execution(s(&command["id"])).await["desired"], "stopped");
    l.report(&node, &old, "stopped", 2).await;
    let fresh = l.http_running(app, &node).await;
    assert_ne!(fresh["id"], http["id"]);
    assert!(
        fresh["spec"]["endpoint_ids"]
            .as_array()
            .is_none_or(Vec::is_empty)
    );
    assert_eq!(l.operation(&removed).await["state"], "pending");
    assert_eq!(connections(&l, app).await["items"][0]["state"], "revoking");
    // A later autonomous HTTP wake must not lose the saved rollout outcome
    // while this operation still waits for an independent command to end.
    sqlx::query("UPDATE app_http SET last_activity=now()-interval '61 seconds' WHERE app_id=$1")
        .bind(app)
        .execute(&l.store.pool)
        .await
        .unwrap();
    l.store.schedule().await.unwrap();
    let idle = l.execution(s(&fresh["id"])).await;
    assert_eq!(idle["desired"], "stopped");
    l.report(&node, &idle, "stopped", 3).await;
    assert_eq!(l.http(app).await["state"], "idle");
    let (_, request) = l
        .store
        .ingress_begin(&format!("app-{app}.apps.test"), 0, true)
        .await
        .unwrap();
    assert_eq!(l.http(app).await["state"], "starting");
    assert_eq!(l.operation(&removed).await["state"], "pending");
    let command = l.execution(s(&command["id"])).await;
    l.report(&node, &command, "stopped", 2).await;
    assert_eq!(l.operation(&removed).await["state"], "succeeded");
    assert_eq!(connections(&l, app).await["items"], json!([]));
    l.store.ingress_finish(&request, Some(0)).await.unwrap();
    l.finish().await;
}

#[tokio::test]
async fn connection_edits_are_scoped_atomic_revisioned_and_durable() {
    let (l, _, ca) = setup().await;
    let service = endpoint(&l, &ca, 2).await;
    let deployed = deploy(&l, &service, false, "scoped").await;
    let app = s(&deployed["resource_id"]);
    let original = connections(&l, app).await;
    let revision = original["revision"].clone();
    let input = json!({"expected_revision":revision,"endpoints":[]});
    let (viewer, token) = l.credential("viewer", Some(&l.project)).await;
    assert_eq!(
        l.store
            .app_connections(&viewer, &l.tenant, &l.project, app)
            .await
            .unwrap(),
        original
    );
    assert_eq!(
        l.store
            .update_app_connections(&viewer, &l.tenant, &l.project, app, input.clone(), "viewer")
            .await
            .unwrap_err()
            .status,
        StatusCode::FORBIDDEN
    );
    let other = l
        .store
        .create_project(
            &l.operator,
            &l.tenant,
            serde_json::from_value(json!({"name":"other"})).unwrap(),
        )
        .await
        .unwrap();
    for (tenant, project, app_id) in [
        (uid(), l.project.clone(), app.to_owned()),
        (l.tenant.clone(), s(&other["id"]).to_owned(), app.to_owned()),
        (l.tenant.clone(), l.project.clone(), uid()),
    ] {
        assert_eq!(
            l.store
                .app_connections(&l.operator, &tenant, &project, &app_id)
                .await
                .unwrap_err()
                .status,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            l.store
                .update_app_connections(
                    &l.operator,
                    &tenant,
                    &project,
                    &app_id,
                    input.clone(),
                    &uid()
                )
                .await
                .unwrap_err()
                .status,
            StatusCode::NOT_FOUND
        );
    }
    let foreign = endpoint_in_project(&l, s(&other["id"]), &ca, 9).await;
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM operations")
        .fetch_one(&l.store.pool)
        .await
        .unwrap();
    for (services, status) in [
        (
            json!([{"endpoint_id":foreign["id"]}]),
            StatusCode::NOT_FOUND,
        ),
        (json!([{"endpoint_id":uid()}]), StatusCode::NOT_FOUND),
        (
            json!([{"endpoint_id":service["id"],"prefix":"lowercase"}]),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!([{"endpoint_id":service["id"],"prefix":"A1_"}]),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!([{"endpoint_id":service["id"],"prefix":"ABCDEFGHIJKLMNOPQ"}]),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!([{"endpoint_id":service["id"],"extra":true}]),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!([{"endpoint_id":service["id"]},{"endpoint_id":service["id"]}]),
            StatusCode::BAD_REQUEST,
        ),
    ] {
        assert_eq!(
            l.store
                .update_app_connections(
                    &l.operator,
                    &l.tenant,
                    &l.project,
                    app,
                    json!({"expected_revision":revision,"endpoints":services}),
                    &uid()
                )
                .await
                .unwrap_err()
                .status,
            status
        );
        assert_eq!(connections(&l, app).await, original);
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM operations")
                .fetch_one(&l.store.pool)
                .await
                .unwrap(),
            before
        );
    }
    // Distinct submissions cannot both overwrite the same revision.
    let key_a = uid();
    let key_b = uid();
    let (a, b) = tokio::join!(
        l.store.update_app_connections(
            &l.operator,
            &l.tenant,
            &l.project,
            app,
            input.clone(),
            &key_a
        ),
        l.store.update_app_connections(
            &l.operator,
            &l.tenant,
            &l.project,
            app,
            input.clone(),
            &key_b
        )
    );
    let (op, key) = match (a, b) {
        (Ok(op), Err(error)) => {
            assert_eq!(error.status, StatusCode::CONFLICT);
            (op, key_a.as_str())
        }
        (Err(error), Ok(op)) => {
            assert_eq!(error.status, StatusCode::CONFLICT);
            (op, key_b.as_str())
        }
        _ => panic!("exactly one revision edit must win"),
    };
    let reopened = Store::from_pool(l.store.pool.clone(), l.root.path()).unwrap();
    assert_eq!(
        reopened
            .update_app_connections(&l.operator, &l.tenant, &l.project, app, input.clone(), key)
            .await
            .unwrap(),
        op
    );
    assert_eq!(
        reopened
            .update_app_connections(
                &l.operator,
                &l.tenant,
                &l.project,
                app,
                json!({"expected_revision":revision,"endpoints":[{"endpoint_id":service["id"]}]}),
                key
            )
            .await
            .unwrap_err()
            .status,
        StatusCode::CONFLICT
    );
    // Receipt/read APIs remain usable during recovery; writes remain fenced.
    sqlx::query("UPDATE recovery_barrier SET active=true")
        .execute(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(
        reopened
            .app_action_submission(&viewer, &l.tenant, &l.project, app, key)
            .await
            .unwrap()["id"],
        op["id"]
    );
    let response = api::router(reopened.clone())
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/tenants/{}/projects/{}/apps/{app}/connections",
                    l.tenant, l.project
                ))
                .header("authorization", format!("Bearer {}", s(&token["token"])))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        reopened
            .update_app_connections(&l.operator, &l.tenant, &l.project, app, input, key)
            .await
            .unwrap_err()
            .status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    l.finish().await;
}

#[tokio::test]
async fn connection_collisions_roll_back_and_prefix_changes_only_authorize_new_runs() {
    let (l, node, ca) = setup().await;
    let a = endpoint(&l, &ca, 2).await;
    let b = endpoint(&l, &ca, 3).await;
    let deployed = deploy(&l, &a, false, "prefix").await;
    let app = s(&deployed["resource_id"]);
    let old = connections(&l, app).await;
    let e = run(&l, app, "old").await;
    assign(&l, &node, &e).await;
    l.report(&node, &e, "running", 1).await;
    // Both the old withdrawal and the newly inserted connections must roll
    // back if composing the resulting environment fails later in admission.
    let selected =
        json!([{"endpoint_id":a["id"],"prefix":"B_"},{"endpoint_id":b["id"],"prefix":"B_"}]);
    assert_eq!(
        l.store
            .update_app_connections(
                &l.operator,
                &l.tenant,
                &l.project,
                app,
                json!({"expected_revision":old["revision"],"endpoints":selected}),
                "collision"
            )
            .await
            .unwrap_err()
            .status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(connections(&l, app).await, old);
    let untouched = l.execution(s(&e["id"])).await;
    assert_eq!(untouched["desired"], "running");
    assert_eq!(untouched["generation"], 1);
    let op = set(
        &l,
        app,
        json!([{"endpoint_id":a["id"]},{"endpoint_id":b["id"],"prefix":"B_"}]),
        "add-b",
    )
    .await;
    assert_eq!(op["state"], "succeeded");
    // Adding to the app neither stops a run nor widens what it was launched with.
    assert_eq!(l.execution(s(&e["id"])).await["desired"], "running");
    assert_eq!(
        l.store
            .assignment(s(&node["id"]), s(&e["id"]), 1)
            .await
            .unwrap()["spec"]["tcp_allow"],
        json!(["10.50.0.2:5432"])
    );
    l.report(&node, &e, "exited", 2).await;
    let fresh = run(&l, app, "new").await;
    let assigned = assign(&l, &node, &fresh).await;
    assert_eq!(
        assigned["spec"]["tcp_allow"],
        json!(["10.50.0.2:5432", "10.50.0.3:5432"])
    );
    assert_eq!(assigned["spec"]["env"]["B_PGHOST"], "10.50.0.3");
    assert_ne!(
        assigned["spec"]["env"]["B_PGPASSWORD"],
        assigned["spec"]["env"]["PGPASSWORD"]
    );
    let op = set(
        &l,
        app,
        json!([{"endpoint_id":a["id"],"prefix":"A_"},{"endpoint_id":b["id"],"prefix":"B_"}]),
        "rename-a",
    )
    .await;
    // A changed prefix is a new connection: the run with the old one ends.
    assert_eq!(op["state"], "pending");
    let renamed = l.execution(s(&fresh["id"])).await;
    assert_eq!(renamed["desired"], "stopped");
    l.report(&node, &renamed, "stopped", 1).await;
    assert_eq!(l.operation(&op).await["state"], "succeeded");
    l.finish().await;
}

#[tokio::test]
async fn schedule_connection_changes_cancel_stale_dispatch_and_pin_new_intent() {
    let (l, node, ca) = setup().await;
    let service = endpoint(&l, &ca, 2).await;
    let deployed=l.store.deploy_app(&l.operator,&l.tenant,&l.project,AppSubmission{value:json!({"name":"scheduled","artifact_id":l.artifact,"triggers":{"http":false,"manual":true,"schedule":{"enabled":true,"expression":"* * * * *","timezone":"UTC"}},"endpoints":[{"endpoint_id":service["id"]}]}),key:"scheduled",domain:"apps.test"}).await.unwrap();
    let app = s(&deployed["resource_id"]);
    sqlx::query("UPDATE app_schedules SET next_at=date_trunc('minute',now()) WHERE app_id=$1")
        .bind(app)
        .execute(&l.store.pool)
        .await
        .unwrap();
    l.store.claim_schedule_occurrences().await.unwrap();
    let first: String = sqlx::query_scalar("SELECT id FROM app_runs WHERE app_id=$1")
        .bind(app)
        .fetch_one(&l.store.pool)
        .await
        .unwrap();
    set(
        &l,
        app,
        json!([{"endpoint_id":service["id"],"prefix":"DB_"}]),
        "prefix",
    )
    .await;
    l.store.dispatch_schedule_runs().await.unwrap();
    let old = l
        .store
        .app_run(&l.operator, &l.tenant, &l.project, app, &first)
        .await
        .unwrap();
    assert_eq!(old["admission"], "cancelled");
    assert_eq!(old["reason"], "connections-changed");
    assert!(old["execution_id"].is_null());
    // Give the cancelled occurrence an earlier timestamp, then let the real
    // scheduler claim the current minute under the edited connection intent.
    sqlx::query("UPDATE app_runs SET scheduled_at=scheduled_at-interval '1 minute' WHERE id=$1")
        .bind(&first)
        .execute(&l.store.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE app_schedules SET next_at=date_trunc('minute',now()) WHERE app_id=$1")
        .bind(app)
        .execute(&l.store.pool)
        .await
        .unwrap();
    l.store.claim_schedule_occurrences().await.unwrap();
    l.store.dispatch_schedule_runs().await.unwrap();
    let execution: String = sqlx::query_scalar(
        "SELECT execution_id FROM app_runs WHERE app_id=$1 AND execution_id IS NOT NULL",
    )
    .bind(app)
    .fetch_one(&l.store.pool)
    .await
    .unwrap();
    let e = l.execution(&execution).await;
    let assigned = assign(&l, &node, &e).await;
    assert_eq!(assigned["spec"]["env"]["DB_PGHOST"], "10.50.0.2");
    assert!(assigned["spec"]["env"]["PGHOST"].is_null());
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM app_execution_connections WHERE execution_id=$1"
        )
        .bind(&execution)
        .fetch_one(&l.store.pool)
        .await
        .unwrap(),
        1
    );
    l.finish().await;
}

#[tokio::test]
async fn composed_deploy_and_draft_validation_leave_no_partial_connection_state() {
    let (l, _, ca) = setup().await;
    let service = endpoint(&l, &ca, 2).await;
    let counts = || async {
        sqlx::query_scalar::<_,Value>("SELECT jsonb_build_object('apps',(SELECT count(*) FROM apps),'connections',(SELECT count(*) FROM app_endpoint_connections),'mappings',(SELECT count(*) FROM app_execution_connections),'grants',(SELECT count(*) FROM network_grants),'executions',(SELECT count(*) FROM executions),'operations',(SELECT count(*) FROM operations))").fetch_one(&l.store.pool).await.unwrap()
    };
    let before = counts().await;
    let request = json!({"name":"atomic","artifact_id":l.artifact,"triggers":{"manual":true,"http":true},"endpoints":[{"endpoint_id":service["id"]}]});
    let mut invalid = request.clone();
    invalid["configuration"] = json!({"env":{"PGHOST":"collision"}});
    assert_eq!(
        l.store
            .deploy_app(
                &l.operator,
                &l.tenant,
                &l.project,
                AppSubmission {
                    value: invalid,
                    key: "bad-variable",
                    domain: "apps.test"
                }
            )
            .await
            .unwrap_err()
            .status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(counts().await, before);
    sqlx::raw_sql("CREATE FUNCTION fail_connected_deploy() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected failure'; END $$; CREATE TRIGGER fail_connected_deploy BEFORE INSERT ON audit FOR EACH ROW WHEN (NEW.action='app.deploy') EXECUTE FUNCTION fail_connected_deploy()").execute(&l.store.pool).await.unwrap();
    assert_eq!(
        l.store
            .deploy_app(
                &l.operator,
                &l.tenant,
                &l.project,
                AppSubmission {
                    value: request.clone(),
                    key: "atomic",
                    domain: "apps.test"
                }
            )
            .await
            .unwrap_err()
            .status,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(counts().await, before);
    sqlx::query("DROP TRIGGER fail_connected_deploy ON audit")
        .execute(&l.store.pool)
        .await
        .unwrap();
    let submitted = l
        .store
        .deploy_app(
            &l.operator,
            &l.tenant,
            &l.project,
            AppSubmission {
                value: request,
                key: "atomic",
                domain: "apps.test",
            },
        )
        .await
        .unwrap();
    assert_eq!(submitted["state"], "pending");
    assert_eq!(counts().await["connections"], 1);
    assert_eq!(counts().await["mappings"], 1);
    assert_eq!(counts().await["grants"], 1);
    let secret = l
        .store
        .create_secret(
            &l.operator,
            &l.tenant,
            &l.project,
            json!({"name":"big","value":"s".repeat(1024)}),
        )
        .await
        .unwrap();
    for configuration in [
        json!({"secret_env":{"PGHOST":secret["id"]}}),
        json!({"secret_env":{"LARGE_SECRET":secret["id"]},"env":{"LARGE":"e".repeat(800)}}),
    ] {
        let draft=l.store.create_app(&l.operator,&l.tenant,&l.project,json!({"name":format!("draft-{}",uid()),"artifact_id":l.artifact,"configuration":configuration}),&uid()).await.unwrap();
        let app = s(&draft["resource_id"]);
        let original = connections(&l, app).await;
        let before = counts().await;
        assert_eq!(l.store.update_app_connections(&l.operator,&l.tenant,&l.project,app,json!({"expected_revision":original["revision"],"endpoints":[{"endpoint_id":service["id"]}]}),&uid()).await.unwrap_err().status,StatusCode::BAD_REQUEST);
        assert_eq!(counts().await, before);
        assert_eq!(connections(&l, app).await, original);
    }
    l.finish().await;
}

async fn summary(l: &Lab, app: &str) -> Value {
    l.store
        .app(&l.operator, &l.tenant, &l.project, app)
        .await
        .unwrap()["connections"]
        .clone()
}

#[tokio::test]
async fn app_connection_summaries_are_bounded_scoped_and_share_detail_observations() {
    let (l, _, _) = setup().await;
    // Summary pagination needs four endpoints, not four copies of a private CA.
    let ca = json!("");
    let mut selected = Vec::new();
    let mut instances = Vec::new();
    for (suffix, prefix) in [(2, "A_"), (3, "B_"), (4, "C_"), (5, "D_")] {
        let instance = endpoint(&l, &ca, suffix).await;
        selected.push(json!({"endpoint_id":instance["id"],"prefix":prefix}));
        instances.push(instance);
    }
    let op=l.store.deploy_app(&l.operator,&l.tenant,&l.project,AppSubmission{value:json!({"name":"connected","artifact_id":l.artifact,"triggers":{"manual":true,"http":false},"endpoints":selected}),key:"summary",domain:"apps.test"}).await.unwrap();
    let app = s(&op["resource_id"]);
    sqlx::query("UPDATE external_endpoints SET deleted=true WHERE id=$1")
        .bind(s(&instances[3]["id"]))
        .execute(&l.store.pool)
        .await
        .unwrap();
    let first = summary(&l, app).await;
    assert_eq!(first["total"], 4);
    assert_eq!(first["allowed"], 3);
    assert_eq!(first["pending"], 1);
    assert_eq!(first["revoking"], 0);
    assert_eq!(first["items"].as_array().unwrap().len(), 3);
    assert_eq!(first["items"][0]["name"], "db-2");
    assert_eq!(first["items"][2]["name"], "db-4");
    assert!(!first.to_string().contains("secret"));
    assert!(!first.to_string().contains("fields"));
    assert!(!first.to_string().contains("certificate"));
    let full = connections(&l, app).await;
    for preview in first["items"].as_array().unwrap() {
        let item = full["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["id"] == preview["id"])
            .unwrap();
        for field in ["name", "state", "reason", "desired", "prefix"] {
            assert_eq!(preview[field], item[field]);
        }
    }
    let empty = l
        .store
        .create_app(
            &l.operator,
            &l.tenant,
            &l.project,
            json!({"name":"no-dependencies","artifact_id":l.artifact}),
            "empty",
        )
        .await
        .unwrap();
    let (viewer, _) = l.credential("viewer", Some(&l.project)).await;
    let page = l
        .store
        .apps(
            &viewer,
            &l.tenant,
            &l.project,
            serde_json::from_value(json!({"limit":1})).unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(page["items"][0]["id"], empty["resource_id"]);
    assert_eq!(
        page["items"][0]["connections"],
        json!({"total":0,"allowed":0,"pending":0,"revoking":0,"items":[]})
    );
    let next = l
        .store
        .apps(
            &viewer,
            &l.tenant,
            &l.project,
            serde_json::from_value(json!({"limit":1,"before":page["next"]})).unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(next["items"][0]["id"], app);
    assert_eq!(next["items"][0]["connections"], first);
    let other = l
        .store
        .create_project(
            &l.operator,
            &l.tenant,
            serde_json::from_value(json!({"name":"other"})).unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        l.store
            .apps(&l.operator, &l.tenant, s(&other["id"]), Default::default())
            .await
            .unwrap()["items"],
        json!([])
    );
    assert_eq!(
        l.store
            .app(&l.operator, &l.tenant, s(&other["id"]), app)
            .await
            .unwrap_err()
            .status,
        StatusCode::NOT_FOUND
    );
    // State changes beyond the three visible names must still change counts.
    sqlx::query("UPDATE external_endpoints SET deleted=true WHERE id=$1")
        .bind(s(&instances[0]["id"]))
        .execute(&l.store.pool)
        .await
        .unwrap();
    let observed = summary(&l, app).await;
    assert_eq!(observed["pending"], 2);
    assert_eq!(observed["items"][0]["reason"], "endpoint-deleted");
    sqlx::query("UPDATE recovery_barrier SET active=true")
        .execute(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(summary(&l, app).await, observed);
    l.finish().await;
}

#[tokio::test]
async fn a_deleted_endpoint_reads_as_pending_and_is_not_given_to_a_launch() {
    let (l, node, ca) = setup().await;
    let service = endpoint(&l, &ca, 2).await;
    let deployed = deploy(&l, &service, false, "eligibility").await;
    let app = s(&deployed["resource_id"]);
    let e = run(&l, app, "explicit-run").await;
    l.store.schedule().await.unwrap();
    sqlx::query("UPDATE external_endpoints SET deleted=true")
        .execute(&l.store.pool)
        .await
        .unwrap();
    let observed = summary(&l, app).await;
    assert_eq!(observed["allowed"], 0);
    assert_eq!(observed["pending"], 1);
    assert_eq!(
        connections(&l, app).await["items"][0]["reason"],
        "endpoint-deleted"
    );
    assert_eq!(
        l.store
            .assignment(s(&node["id"]), s(&e["id"]), 1)
            .await
            .unwrap_err()
            .status,
        StatusCode::CONFLICT
    );
    sqlx::query("UPDATE external_endpoints SET deleted=false")
        .execute(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(summary(&l, app).await["allowed"], 1);
    assert_eq!(
        assign(&l, &node, &e).await["spec"]["tcp_allow"],
        json!(["10.50.0.2:5432"])
    );
    l.finish().await;
}
