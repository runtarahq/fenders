//! Real PostgreSQL: the launch a shim node is given names a run channel, and
//! the channel answers that launch's credential only.
use super::*;
use fenders_control_plane::run_channel::{self, RunChannel};
use tower::ServiceExt;

async fn call(router: &axum::Router, method: &str, path: &str, bearer: Option<&str>) -> StatusCode {
    let mut request = Request::builder().method(method).uri(path);
    if let Some(bearer) = bearer {
        request = request.header("Authorization", format!("Bearer {bearer}"));
    }
    router
        .clone()
        .oneshot(request.body(Body::from("{}")).unwrap())
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn a_launch_names_its_run_channel_and_only_its_credential_is_answered() {
    let l = Lab::new().await;
    l.node("worker").await;
    // Each node holds one execution, so the second is placed on its own.
    l.node("second-worker").await;
    let secret = l
        .store
        .create_secret(
            &l.operator,
            &l.tenant,
            &l.project,
            json!({"name":"token","value":"sensitive-run-channel-fixture"}),
        )
        .await
        .unwrap();
    let op = l
        .create(
            "first",
            json!({"artifact_id":l.artifact,"secret_env":{"TOKEN":secret["id"]}}),
        )
        .await;
    let other = l.create("second", json!({"artifact_id":l.artifact})).await;
    l.store.schedule().await.unwrap();
    let (e, other) = (l.run(&op).await, l.run(&other).await);
    let (id, generation) = (s(&e["id"]), n(&e["generation"]));

    // Without a configured channel the launch names none, as before.
    let node = s(&e["node_id"]);
    let plain = l.store.assignment(node, id, generation).await.unwrap();
    assert!(plain["spec"].get("channel").is_none());
    assert_eq!(plain["spec"]["log_redact_env"], json!(["TOKEN"]));

    assert!(RunChannel::new("http://control.test:9093", "ca".into(), None).is_err());
    assert!(RunChannel::new("https://control.test:9093/prefix", "ca".into(), None).is_err());
    assert!(RunChannel::new("https://control.test:9093", String::new(), None).is_err());
    let store = l.store.clone().with_run_channel(
        RunChannel::new(
            "https://control.test:9093/",
            "-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----\n".into(),
            Some("fenders-control".into()),
        )
        .unwrap(),
    );
    let spec = store.assignment(node, id, generation).await.unwrap()["spec"].clone();
    assert_eq!(spec["protocol"], 1);
    assert_eq!(spec["run"], json!({"execution":id,"generation":generation}));
    assert_eq!(
        spec["channel"]["endpoint"],
        format!("https://control.test:9093/run/{id}/{generation}")
    );
    assert_eq!(spec["channel"]["trust"]["server_name"], "fenders-control");
    assert!(s(&spec["channel"]["trust"]["ca_pem"]).contains("fixture"));
    // A shim is asked for the guest's output, and told there what to mask;
    // it refuses the older field.
    assert!(spec.get("log_redact_env").is_none());
    assert_eq!(spec["output"], json!({"redact_env":["TOKEN"]}));
    let other_spec = store
        .assignment(
            s(&other["node_id"]),
            s(&other["id"]),
            n(&other["generation"]),
        )
        .await
        .unwrap()["spec"]
        .clone();
    assert_eq!(other_spec["output"], json!({"redact_env":[]}));
    assert_eq!(spec["env"]["TOKEN"], "sensitive-run-channel-fixture");
    let credential = s(&spec["channel"]["credential"]);
    assert!(!credential.contains("sensitive") && credential.bytes().all(|b| b.is_ascii_graphic()));

    let router = run_channel::router(store.clone());
    let outcome = format!("/run/{id}/{generation}/v1/run/outcome");
    assert_eq!(
        call(&router, "POST", &outcome, Some(credential)).await,
        StatusCode::OK
    );
    assert_eq!(
        call(&router, "POST", &outcome, None).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(&router, "POST", &outcome, Some("not-a-credential")).await,
        StatusCode::UNAUTHORIZED
    );
    // What a tenant can have the control plane encrypt is never a credential:
    // a secret whose value is a launch's claim, read back from the database
    // as someone with a copy of it could, is refused.
    let forged = l
        .store
        .create_secret(
            &l.operator,
            &l.tenant,
            &l.project,
            json!({"name":"forged","value":format!("fenders-run-channel-v1\n{id}\n{generation}")}),
        )
        .await
        .unwrap();
    let ciphertext: String =
        sqlx::query_scalar("SELECT convert_from(ciphertext,'UTF8') FROM secrets WHERE id=$1")
            .bind(s(&forged["id"]))
            .fetch_one(&l.store.pool)
            .await
            .unwrap();
    assert_eq!(
        call(&router, "POST", &outcome, Some(&ciphertext)).await,
        StatusCode::UNAUTHORIZED
    );
    // The credential is for this execution and generation alone.
    for path in [
        format!(
            "/run/{}/{}/v1/run/outcome",
            s(&other["id"]),
            n(&other["generation"])
        ),
        format!("/run/{id}/{}/v1/run/outcome", generation + 1),
    ] {
        assert_eq!(
            call(&router, "POST", &path, Some(credential)).await,
            StatusCode::UNAUTHORIZED
        );
    }
    // Nothing else is served yet, and nothing outside a launch's path.
    for (method, path) in [
        ("GET", outcome.clone()),
        ("POST", format!("/run/{id}/{generation}/v1/anything")),
        ("GET", format!("/run/{id}/{generation}/v1/run/output")),
        ("POST", format!("/run/{id}/{generation}")),
        ("POST", "/internal/heartbeat".to_owned()),
    ] {
        assert_eq!(
            call(&router, method, &path, Some(credential)).await,
            StatusCode::NOT_FOUND,
            "{method} {path}"
        );
    }
    // Output: a batch from this launch's shim is stored for its execution,
    // and read back by the customer with the secret's variable named.
    let output = format!("/run/{id}/{generation}/v1/run/output");
    let capture = uid();
    let batch = |first: i64, text: &str, covers: &[&str], closed: bool| {
        json!({"format_version":1,"capture_id":capture,"first_sequence":first,
            "last_sequence":first,"closed":closed,"interrupted":false,
            "redaction":fenders_control_plane::model::LOG_REDACTION,"redacted_env":covers,
            "records":[{"sequence":first,"at_ms":1794300000000_i64,"stream":"stderr",
                "bytes":base64::Engine::encode(&base64::engine::general_purpose::STANDARD, text)}]})
    };
    let post = |path: String, bearer: String, body: Value| {
        let router = router.clone();
        async move {
            let response = router
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(path)
                        .header("Authorization", format!("Bearer {bearer}"))
                        .body(Body::from(body.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = response.status();
            let bytes = axum::body::to_bytes(response.into_body(), 65536)
                .await
                .unwrap();
            (
                status,
                serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null),
            )
        }
    };
    let first = batch(1, "failed: [REDACTED]\n", &["TOKEN"], false);
    let (status, accepted) = post(output.clone(), credential.to_owned(), first.clone()).await;
    assert_eq!(status, StatusCode::OK, "{accepted}");
    assert_eq!(accepted["cursor"]["acknowledged"], 1);
    // Sent again (its answer was lost), it is accepted once.
    let (status, again) = post(output.clone(), credential.to_owned(), first).await;
    assert_eq!(
        (status, &again["cursor"]["acknowledged"]),
        (StatusCode::OK, &json!(1))
    );
    // A later batch that begins further on is stored with the gap marked.
    let (status, gapped) = post(
        output.clone(),
        credential.to_owned(),
        batch(5, "after a gap\n", &["TOKEN"], true),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{gapped}");
    assert_eq!(gapped["cursor"]["source_gap"], true);
    assert_eq!(gapped["cursor"]["complete"], true);
    let stored: Vec<(i64, String, Vec<u8>)> = sqlx::query_as(
        "SELECT sequence,stream,payload FROM execution_log_records WHERE execution_id=$1 ORDER BY sequence",
    )
    .bind(id)
    .fetch_all(&l.store.pool)
    .await
    .unwrap();
    assert_eq!(
        stored,
        [
            (1, "stderr".to_owned(), b"failed: [REDACTED]\n".to_vec()),
            (4, "gap".to_owned(), Vec::new()),
            (5, "stderr".to_owned(), b"after a gap\n".to_vec()),
        ]
    );
    // Refused: a batch that does not cover the execution's secret, a batch
    // naming a node of its own, another launch's credential, and a batch
    // for an execution that takes no more output.
    let other_output = format!(
        "/run/{}/{}/v1/run/output",
        s(&other["id"]),
        n(&other["generation"])
    );
    let other_credential = s(&other_spec["channel"]["credential"]).to_owned();
    let uncovered = json!({"format_version":1,"capture_id":uid(),"first_sequence":1,
        "last_sequence":0,"closed":true,"interrupted":false,
        "redaction":fenders_control_plane::model::LOG_REDACTION,"redacted_env":[],"records":[]});
    let (status, refusal) = post(output.clone(), credential.to_owned(), uncovered.clone()).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(
        refusal
            .to_string()
            .contains("does not cover injected secrets"),
        "{refusal}"
    );
    let mut named = uncovered.clone();
    named["boot_id"] = json!("another-boot");
    assert_eq!(
        post(other_output.clone(), other_credential.clone(), named)
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        post(
            other_output.clone(),
            credential.to_owned(),
            uncovered.clone()
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    // The execution without secrets accepts the same batch.
    assert_eq!(
        post(
            other_output.clone(),
            other_credential.clone(),
            uncovered.clone()
        )
        .await
        .0,
        StatusCode::OK
    );
    sqlx::query("UPDATE executions SET log_ingestion_fenced=true WHERE id=$1")
        .bind(s(&other["id"]))
        .execute(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(
        post(other_output, other_credential, uncovered).await.0,
        StatusCode::CONFLICT
    );
    // Once the execution has released its reservation the launch is over.
    sqlx::query("UPDATE executions SET reserved=false WHERE id=$1")
        .bind(id)
        .execute(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(
        call(&router, "POST", &outcome, Some(credential)).await,
        StatusCode::CONFLICT
    );
    l.finish().await;
}

/// Real PostgreSQL: a launch placed under the outbound byte limit is granted
/// bytes over its run channel, held against the workspace's transfer
/// allowance; an ask the allowance cannot cover is answered with what is
/// left; a launch not under the limit is granted nothing; and the run's
/// final count settles what was held.
#[tokio::test]
async fn a_launch_under_the_outbound_byte_limit_is_granted_bytes_over_its_run_channel() {
    use fenders_control_plane::egress_budget::CONTRACT;
    const LAUNCHER: &str = "abababababababababababababababababababababababababababababababab";
    let l = Lab::new().await;
    l.node("worker").await;
    l.node("second-worker").await;
    let op = l.create("limited", json!({"artifact_id":l.artifact})).await;
    let other = l
        .create("unlimited", json!({"artifact_id":l.artifact}))
        .await;
    l.store.schedule().await.unwrap();
    let (e, other) = (l.run(&op).await, l.run(&other).await);
    let (id, generation, node) = (s(&e["id"]), n(&e["generation"]), s(&e["node_id"]));
    // The operator approved the node's launcher, the node says it serves the
    // limit, and the execution was placed under it.
    l.store
        .node_mode(
            &l.operator,
            node,
            json!({"egress_budget_launcher":LAUNCHER}),
        )
        .await
        .unwrap();
    l.store.heartbeat(node, json!({"boot_id":"test-boot","reports":[],"confinement":HOST_CONFINEMENT,"egress_budget_contract":CONTRACT,"launcher_digest":LAUNCHER})).await.unwrap();
    sqlx::query("UPDATE executions SET egress_budget_launcher=$1 WHERE id=$2")
        .bind(LAUNCHER)
        .bind(id)
        .execute(&l.store.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE tenants SET transfer_bytes=5000 WHERE id=$1")
        .bind(&l.tenant)
        .execute(&l.store.pool)
        .await
        .unwrap();
    let store = l.store.clone().with_run_channel(
        RunChannel::new("https://control.test:9093", "fixture ca".into(), None).unwrap(),
    );
    let credential = |e: &Value| {
        let store = store.clone();
        let (node, id, generation) = (
            s(&e["node_id"]).to_owned(),
            s(&e["id"]).to_owned(),
            n(&e["generation"]),
        );
        async move {
            s(&store.assignment(&node, &id, generation).await.unwrap()["spec"]["channel"]
                ["credential"])
            .to_owned()
        }
    };
    let router = run_channel::router(store.clone());
    let ask = |path: String, bearer: String, body: Value| {
        let router = router.clone();
        async move {
            let response = router
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(path)
                        .header("Authorization", format!("Bearer {bearer}"))
                        .body(Body::from(body.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = response.status();
            let bytes = axum::body::to_bytes(response.into_body(), 65536)
                .await
                .unwrap();
            (
                status,
                serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null),
            )
        }
    };
    let held = || async {
        sqlx::query_as::<_, (i64, i64)>("SELECT COALESCE(sum(used_bytes),0)::bigint,COALESCE(sum(held_bytes),0)::bigint FROM transfer_allowance_accounting WHERE tenant_id=$1 AND period=date_trunc('month',now() AT TIME ZONE 'UTC')::date").bind(&l.tenant).fetch_one(&l.store.pool).await.unwrap()
    };
    let path = format!("/run/{id}/{generation}/v1/run/egress");
    let bearer = credential(&e).await;
    let grant = |revision: i64, request: &str, bytes: i64| {
        ask(
            path.clone(),
            bearer.clone(),
            json!({"expected_revision":revision,"request_id":request,"bytes":bytes}),
        )
    };

    // Bytes are granted and held; the same ask again changes nothing.
    for _ in 0..2 {
        let (status, granted) = grant(0, "shim-1", 4000).await;
        assert_eq!(status, StatusCode::OK, "{granted}");
        assert_eq!(granted["revision"], 1);
        assert_eq!(granted["state"], "active");
        assert_eq!(granted["ceiling_bytes"], 4000);
        assert!(n(&granted["ttl_ms"]) > 5000 && n(&granted["ttl_ms"]) <= 10000);
    }
    assert_eq!(held().await, (0, 4000));
    // More than is left: refused, with what is left, which can then be had.
    let (status, short) = grant(1, "shim-2", 2000).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(short["available_bytes"], 1000);
    assert_eq!(held().await, (0, 4000));
    let (status, granted) = grant(1, "shim-3", 1000).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        (n(&granted["revision"]), n(&granted["ceiling_bytes"])),
        (2, 5000)
    );
    // What it holds is renewed for nothing; nothing more is to be had.
    let (status, renewed) = grant(2, "shim-4", 0).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        (n(&renewed["revision"]), n(&renewed["ceiling_bytes"])),
        (3, 5000)
    );
    let (status, short) = grant(3, "shim-5", 1).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(short["available_bytes"], 0);
    assert_eq!(held().await, (0, 5000));
    // An ask from behind is refused, as is anything but an ask for bytes.
    assert_eq!(grant(1, "shim-6", 0).await.0, StatusCode::CONFLICT);
    for body in [
        json!({"expected_revision":3,"request_id":"x","bytes":0,"action":"settle"}),
        json!({"expected_revision":3,"request_id":"x","bytes":0,"boot_id":"test-boot"}),
        json!({"expected_revision":3,"request_id":"x"}),
        json!({"expected_revision":3,"request_id":"x","bytes":-1}),
    ] {
        assert_eq!(
            ask(path.clone(), bearer.clone(), body.clone()).await.0,
            StatusCode::BAD_REQUEST,
            "{body}"
        );
    }
    // A launch not placed under the limit is granted nothing.
    let (status, _) = ask(
        format!(
            "/run/{}/{}/v1/run/egress",
            s(&other["id"]),
            n(&other["generation"])
        ),
        credential(&other).await,
        json!({"expected_revision":0,"request_id":"other-1","bytes":1}),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(held().await, (0, 5000));

    // The run ends having sent 1234 bytes: those are used, the rest released,
    // and its credential is granted nothing more.
    l.store.heartbeat(node, json!({"boot_id":"test-boot","confinement":HOST_CONFINEMENT,"egress_budget_contract":CONTRACT,"launcher_digest":LAUNCHER,"reports":[
        {"id":id,"generation":generation,"sequence":9,"state":"exited","exit_code":0,"cpu_usec":0,"memory_bytes":0,
         "egress":{"contract":"socket-payload-v1","boot_id":"test-boot","bytes":1234,"in_flight":0,"complete":true,"observed":chrono::Utc::now().timestamp_micros() as f64/1e6},
         "egress_authority":{"contract":CONTRACT,"boot_id":"test-boot","launcher_digest":LAUNCHER}}]})).await.unwrap();
    assert_eq!(held().await, (1234, 0));
    assert_eq!(grant(3, "shim-7", 1).await.0, StatusCode::CONFLICT);
    l.finish().await;
}

/// A node the operator disabled holds the credentials of the runs it was
/// given. They are refused while it is disabled.
#[tokio::test]
async fn a_disabled_nodes_launches_are_refused_on_the_run_channel() {
    let mut l = Lab::new().await;
    l.store = l.store.clone().with_run_channel(
        RunChannel::new("https://control.test:9093", "fixture ca".into(), None).unwrap(),
    );
    let node = l.node("worker").await;
    let op = l.create("held", json!({"artifact_id":l.artifact})).await;
    l.store.schedule().await.unwrap();
    let e = l.run(&op).await;
    let (id, generation) = (s(&e["id"]), n(&e["generation"]));
    let spec = l
        .store
        .assignment(s(&node["id"]), id, generation)
        .await
        .unwrap()["spec"]
        .clone();
    let credential = s(&spec["channel"]["credential"]);
    let router = run_channel::router(l.store.clone());
    let path = format!("/run/{id}/{generation}/v1/run/http/next");
    let authorized = || async {
        l.store
            .run_channel_authorize(id, generation, credential)
            .await
            .map_err(|error| error.status)
    };
    assert_eq!(authorized().await, Ok(()));
    l.store
        .node_mode(&l.operator, s(&node["id"]), json!({"disabled":true}))
        .await
        .unwrap();
    assert_eq!(authorized().await, Err(StatusCode::FORBIDDEN));
    assert_eq!(
        call(&router, "POST", &path, Some(credential)).await,
        StatusCode::FORBIDDEN
    );
    // Enabled again, its runs are its own again: nothing was lost.
    l.store
        .node_mode(&l.operator, s(&node["id"]), json!({"disabled":false}))
        .await
        .unwrap();
    assert_eq!(authorized().await, Ok(()));
    l.finish().await;
}
