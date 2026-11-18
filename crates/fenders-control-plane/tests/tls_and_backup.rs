use axum::{Json, Router, extract::Request, http::StatusCode};
use fenders_control_plane::{
    api, backup,
    model::{HOST_CONFINEMENT, LOG_REDACTION, digest, uid},
    pki,
    store::Store,
    transport,
};
use serde_json::{Value, json};
use std::{collections::BTreeMap, path::Path};

#[tokio::test]
async fn tls_shutdown_finishes_an_authenticated_inflight_request_without_replay() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let root = tempfile::tempdir().unwrap();
    let pins = pki::create(
        root.path(),
        &BTreeMap::from([
            ("control".into(), vec!["127.0.0.1".into()]),
            ("node".into(), vec!["node.test".into()]),
        ]),
    )
    .unwrap();
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let count = Arc::new(AtomicUsize::new(0));
    let (started, resume, calls) = (entered.clone(), release.clone(), count.clone());
    let app = Router::new().fallback(move |request: Request| {
        let (started, resume, calls) = (started.clone(), resume.clone(), calls.clone());
        async move {
            assert!(
                request
                    .extensions()
                    .get::<transport::PeerIdentity>()
                    .unwrap()
                    .0
                    .is_some()
            );
            calls.fetch_add(1, Ordering::SeqCst);
            started.notify_one();
            resume.notified().await;
            Json(json!({"finished":true}))
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let endpoint = format!("https://{address}");
    let config = transport::server_config(
        &root.path().join("control.pem"),
        &root.path().join("control.key"),
        Some(&root.path().join("ca.pem")),
    )
    .unwrap();
    let (stop, shutdown) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(transport::serve_tls_until(listener, config, app, async {
        let _ = shutdown.await;
    }));
    let client = transport::Client::new(
        &endpoint,
        &root.path().join("ca.pem"),
        &root.path().join("node.pem"),
        &root.path().join("node.key"),
        pins["control"].as_str().unwrap(),
    )
    .unwrap();
    let request = tokio::spawn(async move {
        client
            .json("POST", "/inflight", Some(&json!({"once":true})))
            .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), entered.notified())
        .await
        .unwrap();
    stop.send(()).unwrap();
    // Shutdown must stop accepting, while keeping the dispatched request alive.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        if tokio::net::TcpStream::connect(address).await.is_err() {
            break;
        }
        assert!(tokio::time::Instant::now() < deadline);
        tokio::task::yield_now().await;
    }
    assert!(!server.is_finished());
    assert!(!request.is_finished());
    release.notify_one();
    assert_eq!(request.await.unwrap().unwrap()["finished"], true);
    tokio::time::timeout(std::time::Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn mtls_requires_ca_identity_and_pin_before_payload_delivery() {
    let root = tempfile::tempdir().unwrap();
    let pins = pki::create(
        root.path(),
        &BTreeMap::from([
            (
                "control".to_owned(),
                vec!["localhost".to_owned(), "127.0.0.1".to_owned()],
            ),
            ("node".to_owned(), vec!["node.test".to_owned()]),
        ]),
    )
    .unwrap();
    let config = transport::server_config(
        &root.path().join("control.pem"),
        &root.path().join("control.key"),
        Some(&root.path().join("ca.pem")),
    )
    .unwrap();
    let count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let received = count.clone();
    let app = Router::new().fallback(move |req: Request| {
        let received = received.clone();
        async move {
            received.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            assert!(
                req.extensions()
                    .get::<transport::PeerIdentity>()
                    .unwrap()
                    .0
                    .is_some()
            );
            Json(json!({"ok":true}))
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("https://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(transport::serve_tls(listener, config, app));
    let client = |pin: &str| {
        transport::Client::new(
            &endpoint,
            &root.path().join("ca.pem"),
            &root.path().join("node.pem"),
            &root.path().join("node.key"),
            pin,
        )
        .unwrap()
    };
    assert_eq!(
        client(pins["control"].as_str().unwrap())
            .json("POST", "/test", Some(&json!({"payload":"fixture"})))
            .await
            .unwrap()["ok"],
        true
    );
    assert!(
        client(&"0".repeat(64))
            .json("POST", "/test", Some(&json!({"payload":"must-not-send"})))
            .await
            .is_err()
    );
    assert_eq!(
        client(pins["control"].as_str().unwrap())
            .with_server_name("localhost")
            .unwrap()
            .json("POST", "/test", Some(&json!({"payload":"explicit-name"})))
            .await
            .unwrap()["ok"],
        true
    );
    assert!(
        client(pins["control"].as_str().unwrap())
            .with_server_name("wrong.test")
            .unwrap()
            .json("POST", "/test", Some(&json!({"payload":"must-not-send"})))
            .await
            .is_err()
    );
    assert!(
        client(&"0".repeat(64))
            .with_server_name("localhost")
            .unwrap()
            .json("POST", "/test", Some(&json!({"payload":"must-not-send"})))
            .await
            .is_err()
    );
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 2);
    let public = reqwest::Client::builder()
        .add_root_certificate(
            reqwest::Certificate::from_pem(&std::fs::read(root.path().join("ca.pem")).unwrap())
                .unwrap(),
        )
        .build()
        .unwrap();
    assert!(public.get(&endpoint).send().await.is_err());
    server.abort();
}

#[test]
fn encrypted_archive_detects_tampering_truncation_wrong_key_and_trailing_data() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("plain");
    let encrypted = root.path().join("archive");
    let key = [17u8; 32];
    let plain = vec![123u8; backup::CHUNK + 47];
    std::fs::write(&source, &plain).unwrap();
    backup::encrypt(&source, &encrypted, &key).unwrap();
    backup::decrypt(
        &encrypted,
        &root.path().join("roundtrip"),
        &key,
        plain.len() as u64,
    )
    .unwrap();
    assert_eq!(std::fs::read(root.path().join("roundtrip")).unwrap(), plain);
    assert!(
        backup::decrypt(
            &encrypted,
            &root.path().join("wrong-key"),
            &[9; 32],
            backup::DEFAULT_LIMIT
        )
        .is_err()
    );
    assert!(backup::decrypt(&encrypted, &root.path().join("too-large"), &key, 5).is_err());
    let original = std::fs::read(&encrypted).unwrap();
    for (name, bytes) in [
        ("truncated", original[..original.len() - 1].to_vec()),
        ("trailing", [original.clone(), vec![0]].concat()),
        ("modified", {
            let mut v = original.clone();
            v[100] ^= 1;
            v
        }),
    ] {
        let path = root.path().join(name);
        std::fs::write(&path, bytes).unwrap();
        assert!(
            backup::decrypt(
                &path,
                &root.path().join(format!("out-{name}")),
                &key,
                backup::DEFAULT_LIMIT
            )
            .is_err()
        );
    }
}

#[tokio::test]
async fn real_database_backup_and_fenced_restore() {
    let dsn = std::env::var("FENDERS_TEST_DATABASE_URL").expect("set dedicated test database URL");
    let admin = sqlx::PgPool::connect(&dsn).await.unwrap();
    let source_name = format!("fd_rust_src_{}", uid());
    let destination_name = format!("fd_rust_dst_{}", uid());
    for name in [&source_name, &destination_name] {
        sqlx::query(&format!("CREATE DATABASE {name}"))
            .execute(&admin)
            .await
            .unwrap();
    }
    let url = |name: &str| {
        let mut u = url::Url::parse(&dsn).unwrap();
        u.set_path(name);
        u.to_string()
    };
    let source_dsn = url(&source_name);
    let target_dsn = url(&destination_name);
    let root = tempfile::tempdir().unwrap();
    let source = Store::connect(&source_dsn, &root.path().join("source"))
        .await
        .unwrap();
    source.migrate().await.unwrap();
    let token = std::fs::read_to_string(source.bootstrap().await.unwrap()).unwrap();
    let operator = source.authenticate(&token).await.unwrap();
    let tenant=source.create_tenant(&operator,serde_json::from_value(json!({"name":"backup","allowance":{"cpu_percent":100,"memory_mib":1024,"instances":2,"storage_bytes":1000000,"transfer_bytes":1000000}})).unwrap()).await.unwrap();
    let t = tenant["id"].as_str().unwrap();
    let project = source
        .create_project(
            &operator,
            t,
            serde_json::from_value(json!({"name":"app"})).unwrap(),
        )
        .await
        .unwrap();
    let p = project["id"].as_str().unwrap();
    let endpoint_tenant=source.create_tenant(&operator,serde_json::from_value(json!({"name":"external-endpoint-backup","allowance":{"cpu_percent":200,"memory_mib":2048,"instances":2,"storage_bytes":3_000_000_000_i64,"transfer_bytes":1000000}})).unwrap()).await.unwrap();
    let endpoint_t = endpoint_tenant["id"].as_str().unwrap();
    let endpoint_projects = source.projects(&operator, endpoint_t).await.unwrap();
    let endpoint_p = endpoint_projects[0]["id"].as_str().unwrap();
    let username = source
        .create_secret(
            &operator,
            endpoint_t,
            endpoint_p,
            json!({"name":"postgres-user","value":"backup-user"}),
        )
        .await
        .unwrap();
    let password = source
        .create_secret(
            &operator,
            endpoint_t,
            endpoint_p,
            json!({"name":"postgres-password","value":"backup-password"}),
        )
        .await
        .unwrap();
    let endpoint_pki = root.path().join("external-pki");
    pki::create(
        &endpoint_pki,
        &BTreeMap::from([("postgres".into(), vec!["10.50.0.2".into()])]),
    )
    .unwrap();
    let ca = std::fs::read_to_string(endpoint_pki.join("ca.pem")).unwrap();
    let source = source.with_external_network(
        fenders_control_plane::external_endpoints::ExternalNetworkPolicy {
            allowed_cidrs: vec!["10.50.0.2/32".parse().unwrap()],
            denied_cidrs: vec![],
        },
    );
    let endpoint = source.create_endpoint(&operator, endpoint_t, endpoint_p,
        json!({"name":"external-postgres","host":"10.50.0.2","port":5432,"database":"demo",
            "username_secret_id":username["id"],"password_secret_id":password["id"],"ca_certificate":ca}), "endpoint").await.unwrap();
    let endpoint_before = source
        .resources(
            &operator,
            endpoint_t,
            endpoint_p,
            "external-endpoints",
            Some(endpoint["resource_id"].as_str().unwrap()),
        )
        .await
        .unwrap();
    let endpoint_secret = password["id"].as_str().unwrap();
    let endpoint_ciphertext: String =
        sqlx::query_scalar("SELECT convert_from(ciphertext,'UTF8') FROM secrets WHERE id=$1")
            .bind(endpoint_secret)
            .fetch_one(&source.pool)
            .await
            .unwrap();
    let artifact = source
        .upload(&operator, t, p, b"\0asm\x0d\0\x01\0")
        .await
        .unwrap();
    let node = source.register_node(&operator,json!({"name":"compiler","cert_sha256":digest("compiler"),"endpoint":"https://node.example:9443","backend":"wasm","architecture":"x86_64","runtime":fenders_control_plane::artifacts::RUNTIME,"cpu_percent":100,"memory_mib":128,"instances":1})).await.unwrap();
    let node_id = node["id"].as_str().unwrap();
    let boot = || json!({"boot_id":"backup-boot"});
    source
        .heartbeat(
            node_id,
            json!({"boot_id":"backup-boot","reports":[],"confinement":HOST_CONFINEMENT}),
        )
        .await
        .unwrap();
    assert_eq!(
        source.claim_component(node_id, boot()).await.unwrap()["job"]["generation"],
        1
    );
    // Trusted-worker protocol receipt; real component parsing is tested separately.
    source.component_result(node_id,artifact["id"].as_str().unwrap(),1,json!({"boot_id":"backup-boot","inspection":{"format_version":1,"runtime":fenders_control_plane::artifacts::RUNTIME,"digest":artifact["digest"],"bytes":8,"command":true,"http":true,"imports":[],"exports":[]}})).await.unwrap();
    let app = source
        .create_app(
            &operator,
            t,
            p,
            json!({"name":"backed-up-app","artifact_id":artifact["id"]}),
            "app",
        )
        .await
        .unwrap();
    let versions = source
        .app_versions(&operator, t, p, app["resource_id"].as_str().unwrap(), None)
        .await
        .unwrap();
    let dependency_artifact = source
        .upload(&operator, endpoint_t, endpoint_p, b"\0asm\x0d\0\x01\0")
        .await
        .unwrap();
    assert_eq!(
        source.claim_component(node_id, boot()).await.unwrap()["job"]["artifact_id"],
        dependency_artifact["id"]
    );
    source.component_result(node_id,dependency_artifact["id"].as_str().unwrap(),1,json!({"boot_id":"backup-boot","inspection":{"format_version":1,"runtime":fenders_control_plane::artifacts::RUNTIME,"digest":dependency_artifact["digest"],"bytes":8,"command":true,"http":true,"imports":[],"exports":[]}})).await.unwrap();
    let inspecting = source
        .upload(&operator, t, p, b"\0asm\x0d\0\x01\0pending")
        .await
        .unwrap();
    assert_eq!(
        source.claim_component(node_id, boot()).await.unwrap()["job"]["artifact_id"],
        inspecting["id"]
    );
    source
        .create_secret(
            &operator,
            t,
            p,
            json!({"name":"test","value":"secret-restored"}),
        )
        .await
        .unwrap();
    let app_id = app["resource_id"].as_str().unwrap();
    source
        .update_app_triggers(
            &operator,
            t,
            p,
            app_id,
            json!({"manual":true,"expected_revision":1}),
            "manual",
        )
        .await
        .unwrap();
    let release = source
        .activate_app_release(
            &operator,
            t,
            p,
            app_id,
            json!({"version_id":versions["items"][0]["id"],"expected_revision":1}),
            "release",
        )
        .await
        .unwrap();
    let run = source
        .run_app(&operator, t, p, app_id, "queued")
        .await
        .unwrap();
    source.schedule().await.unwrap();
    let log_execution = source
        .app_run(
            &operator,
            t,
            p,
            app_id,
            run["resource_id"].as_str().unwrap(),
        )
        .await
        .unwrap()["execution_id"]
        .as_str()
        .unwrap()
        .to_owned();
    sqlx::query("INSERT INTO execution_egress_usage(execution_id,tenant_id,project_id,generation,boot_id,bytes,complete,sampled_at,first_sampled_at) SELECT id,tenant_id,project_id,generation,'backup-boot',12345,false,now(),now() FROM executions WHERE id=$1").bind(&log_execution).execute(&source.pool).await.unwrap();
    sqlx::query("INSERT INTO execution_egress_period_sources(execution_id,tenant_id,project_id,generation,boot_id,bytes,complete,payload,sampled_at) SELECT id,tenant_id,project_id,generation,'backup-boot',12345,false,jsonb_build_object('contract','socket-payload-utc-month-v1','bytes',12345,'expired_bytes',0,'periods',jsonb_build_array(jsonb_build_object('period',to_char(now() AT TIME ZONE 'UTC','YYYY-MM-01'),'bytes',12345)),'complete',false,'in_flight',0,'observed',extract(epoch FROM now()),'boot_id','backup-boot'),now() FROM executions WHERE id=$1").bind(&log_execution).execute(&source.pool).await.unwrap();
    sqlx::query("INSERT INTO execution_egress_periods(execution_id,tenant_id,project_id,period,bytes,sampled_at) SELECT execution_id,tenant_id,project_id,date_trunc('month',now() AT TIME ZONE 'UTC')::date,bytes,sampled_at FROM execution_egress_period_sources WHERE execution_id=$1").bind(&log_execution).execute(&source.pool).await.unwrap();
    sqlx::query("INSERT INTO execution_egress_budgets(execution_id,tenant_id,project_id,node_id,boot_id,launcher_digest,generation,revision,state,ceiling_bytes,held_bytes,expires) SELECT id,tenant_id,project_id,$2,'backup-boot',repeat('a',64),generation,1,'active',900,900,now()+interval '10 seconds' FROM executions WHERE id=$1").bind(&log_execution).bind(node_id).execute(&source.pool).await.unwrap();
    sqlx::query("INSERT INTO egress_allowance_usage(execution_id,tenant_id,project_id,period,bytes) SELECT id,tenant_id,project_id,date_trunc('month',now() AT TIME ZONE 'UTC')::date,321 FROM executions WHERE id=$1").bind(&log_execution).execute(&source.pool).await.unwrap();
    let log_batch = json!({"boot_id":"backup-boot","format_version":1,"capture_id":uid(),"first_sequence":1,"last_sequence":1,"closed":true,"interrupted":true,"redaction":LOG_REDACTION,"redacted_env":[],"records":[{"sequence":1,"at_ms":1791300000000_i64,"stream":"stdout","bytes":"YmVmb3JlLWJhY2t1cA=="}]});
    // Retain an earlier wait observation; its old generation must not authorize
    // a current placement projection after restore fences the execution.
    sqlx::query("INSERT INTO execution_placement(execution_id,generation,reason,observed_at) VALUES($1,1,'placement-capacity',now())")
        .bind(&log_execution).execute(&source.pool).await.unwrap();
    source
        .ingest_execution_logs(node_id, &log_execution, 1, log_batch.clone())
        .await
        .unwrap();
    let before_logs = source
        .app_logs(&operator, t, p, app_id, Default::default())
        .await
        .unwrap();
    let http_app = source
        .create_app(
            &operator,
            t,
            p,
            json!({"name":"http-app","artifact_id":artifact["id"]}),
            "http-app",
        )
        .await
        .unwrap();
    let http_app_id = http_app["resource_id"].as_str().unwrap();
    let http_version = source
        .app_versions(&operator, t, p, http_app_id, None)
        .await
        .unwrap()["items"][0]["id"]
        .clone();
    source
        .update_app_triggers(
            &operator,
            t,
            p,
            http_app_id,
            json!({"manual":false,"http":true,"expected_revision":1}),
            "http-trigger",
        )
        .await
        .unwrap();
    let http_release = source
        .activate_app_release(
            &operator,
            t,
            p,
            http_app_id,
            json!({"version_id":http_version,"expected_revision":1}),
            "http-release",
        )
        .await
        .unwrap();
    assert_eq!(http_release["state"], "pending");
    let http_before = source
        .app_http_status(&operator, t, p, http_app_id)
        .await
        .unwrap();
    // Durable request metadata, including both sides of the dispatch boundary.
    let http_run_ids = [uid(), uid(), uid()];
    for (index, id) in http_run_ids.iter().enumerate() {
        sqlx::query("INSERT INTO app_http_runs(id,tenant_id,project_id,app_id,release_id,execution_id,method,path,state,started_at,finished_at,http_status) VALUES($1,$2,$3,$4,$5,$6,'GET','/backup',$7,CASE WHEN $8 THEN now() END,CASE WHEN $9 THEN now() END,CASE WHEN $9 THEN 200 END)")
            .bind(id).bind(t).bind(p).bind(http_app_id).bind(http_release["resource_id"].as_str().unwrap()).bind(http_before["execution_id"].as_str())
            .bind(["queued","running","succeeded"][index]).bind(index>0).bind(index==2)
            .execute(&source.pool).await.unwrap();
    }
    let schedule_app=source.deploy_app(&operator,t,p,fenders_control_plane::apps::AppSubmission{value:json!({"name":"scheduled-app","artifact_id":artifact["id"],"triggers":{"http":false,"manual":false,"schedule":{"enabled":true,"expression":"* * * * *","timezone":"UTC"}}}),key:"scheduled-app",domain:"apps.test"}).await.unwrap();
    let schedule_app_id = schedule_app["resource_id"].as_str().unwrap();
    sqlx::query("UPDATE app_schedules SET next_at=date_trunc('minute',now())-interval '2 hours' WHERE app_id=$1")
        .bind(schedule_app_id)
        .execute(&source.pool)
        .await
        .unwrap();
    source.claim_schedule_occurrences().await.unwrap();
    let schedule_history = source
        .app_history(&operator, t, p, schedule_app_id, "runs", Default::default())
        .await
        .unwrap();
    let schedule_run = schedule_history["items"][0]["id"].as_str().unwrap();
    assert_eq!(schedule_history["items"][0]["admission"], "pending");
    assert_eq!(schedule_history["missed_history_pending"], true);
    let retired_schedule_run = uid();
    sqlx::query("INSERT INTO app_runs(id,tenant_id,project_id,app_id,release_id,source,admission,admission_reason,created,admission_updated,scheduled_at,trigger_revision) SELECT $1,tenant_id,project_id,id,target_release_id,'schedule','skipped','missed-deadline',now()-interval '40 days',now()-interval '40 days',now()-interval '40 days',1 FROM apps WHERE id=$2").bind(&retired_schedule_run).bind(schedule_app_id).execute(&source.pool).await.unwrap();
    sqlx::query("INSERT INTO app_run_dispatch(run_id,tenant_id,project_id,app_id,state,deadline,created,updated) SELECT id,tenant_id,project_id,app_id,'cancelled',created,created,created FROM app_runs WHERE id=$1").bind(&retired_schedule_run).execute(&source.pool).await.unwrap();
    let mut retirement = source.pool.begin().await.unwrap();
    sqlx::query("UPDATE app_runs SET dispatch_retired_at=now() WHERE id=$1")
        .bind(&retired_schedule_run)
        .execute(&mut *retirement)
        .await
        .unwrap();
    sqlx::query("DELETE FROM app_run_dispatch WHERE run_id=$1")
        .bind(&retired_schedule_run)
        .execute(&mut *retirement)
        .await
        .unwrap();
    retirement.commit().await.unwrap();
    let retired_before: Value =
        sqlx::query_scalar("SELECT to_jsonb(r) FROM app_runs r WHERE id=$1")
            .bind(&retired_schedule_run)
            .fetch_one(&source.pool)
            .await
            .unwrap();
    let retired_input_execution = uid();
    let pending_input_execution = uid();
    for id in [&retired_input_execution, &pending_input_execution] {
        sqlx::query("INSERT INTO executions(id,tenant_id,project_id,spec,cpu_percent,memory_mib,state,desired,reserved,observation,created,updated,finished_at) VALUES($1,$2,$3,'{\"env\":{\"INPUT\":\"duplicate\"},\"secret_env\":{\"TOKEN\":\"retained-reference\"}}',1,64,'exited','stopped',false,'{\"exit_code\":0}',now()-interval '40 days',now()-interval '40 days',now()-interval '40 days')")
            .bind(id).bind(t).bind(p).execute(&source.pool).await.unwrap();
    }
    sqlx::query("UPDATE executions SET inputs_retired_at=now(),original_spec_sha256=encode(sha256(convert_to(spec::text,'UTF8')),'hex'),spec=spec-ARRAY['env','endpoint_env'] WHERE id=$1")
        .bind(&retired_input_execution).execute(&source.pool).await.unwrap();
    let input_receipt: Value = sqlx::query_scalar("SELECT jsonb_build_object('spec',spec,'retired_at',inputs_retired_at,'sha256',original_spec_sha256) FROM executions WHERE id=$1")
        .bind(&retired_input_execution).fetch_one(&source.pool).await.unwrap();
    // A metadata-only wake lease is not a durable HTTP request. Restore must
    // discard it; no retained body or reservation may trigger a new worker.
    let wake_lease = uid();
    sqlx::query("INSERT INTO ingress_reservations(id,tenant_id,project_id,period,bytes,app_id,release_id,app_revision) SELECT $1,tenant_id,project_id,date_trunc('month',now())::date,1048576,id,target_release_id,revision FROM apps WHERE id=$2")
        .bind(&wake_lease).bind(http_app_id).execute(&source.pool).await.unwrap();
    let dependency_app = source.deploy_app(&operator,endpoint_t,endpoint_p,fenders_control_plane::apps::AppSubmission{value:json!({"name":"connected","artifact_id":dependency_artifact["id"],"triggers":{"manual":true,"http":false},"endpoints":[{"endpoint_id":endpoint["resource_id"]}]}),key:"connected",domain:"apps.test"}).await.unwrap();
    let dependency_app_id = dependency_app["resource_id"].as_str().unwrap();
    let dependency_run = source
        .run_app(
            &operator,
            endpoint_t,
            endpoint_p,
            dependency_app_id,
            "connected-run",
        )
        .await
        .unwrap();
    let dependency_execution = source
        .app_run(
            &operator,
            endpoint_t,
            endpoint_p,
            dependency_app_id,
            dependency_run["resource_id"].as_str().unwrap(),
        )
        .await
        .unwrap()["execution_id"]
        .as_str()
        .unwrap()
        .to_owned();
    // Synthetic assigned-run fixture: restore must keep this uncertain
    // owner fenced until the operator confirms external resources are stopped.
    sqlx::query("UPDATE executions SET node_id=$1 WHERE id=$2")
        .bind(node_id)
        .bind(&dependency_execution)
        .execute(&source.pool)
        .await
        .unwrap();
    let connection_revision = source
        .app_connections(&operator, endpoint_t, endpoint_p, dependency_app_id)
        .await
        .unwrap()["revision"]
        .as_i64()
        .unwrap();
    let connection_remove = source
        .update_app_connections(
            &operator,
            endpoint_t,
            endpoint_p,
            dependency_app_id,
            json!({"expected_revision":connection_revision,"endpoints":[]}),
            "connection-remove",
        )
        .await
        .unwrap();
    assert_eq!(connection_remove["state"], "pending");
    source
        .update_app_connections(
            &operator,
            endpoint_t,
            endpoint_p,
            dependency_app_id,
            json!({"expected_revision":connection_revision+1,"endpoints":[{"endpoint_id":endpoint["resource_id"]}]}),
            "connection-readd",
        )
        .await
        .unwrap();
    let connections_before: Value = sqlx::query_scalar(
        "SELECT jsonb_agg(to_jsonb(c) ORDER BY c.id) FROM app_endpoint_connections c",
    )
    .fetch_one(&source.pool)
    .await
    .unwrap();
    let execution_connections_before: Value =
        sqlx::query_scalar("SELECT jsonb_agg(to_jsonb(c)) FROM app_execution_connections c")
            .fetch_one(&source.pool)
            .await
            .unwrap();
    let revocations_before: Value =
        sqlx::query_scalar("SELECT jsonb_agg(to_jsonb(r)) FROM connection_revocations r")
            .fetch_one(&source.pool)
            .await
            .unwrap();
    // Preserve desired and withdrawn origin identities, but never restore a
    // usable binding or a node's reported runtime from an archive.
    let public_connection = uid();
    sqlx::query("UPDATE public_egress_policy SET enabled=true,digest=$1")
        .bind(digest("fixture-policy"))
        .execute(&source.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE nodes SET observed_runtime_digest=$1 WHERE id=$2")
        .bind(digest("fixture-runtime"))
        .bind(node_id)
        .execute(&source.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO app_https_connections(id,tenant_id,project_id,app_id,origin,state,revocation_operation_id) VALUES($1,$2,$3,$4,'https://api.test:443','revoking',$5)").bind(&public_connection).bind(endpoint_t).bind(endpoint_p).bind(dependency_app_id).bind(connection_remove["id"].as_str().unwrap()).execute(&source.pool).await.unwrap();
    sqlx::query("INSERT INTO app_execution_https(tenant_id,project_id,app_id,execution_id,connection_id) VALUES($1,$2,$3,$4,$5)").bind(endpoint_t).bind(endpoint_p).bind(dependency_app_id).bind(&dependency_execution).bind(&public_connection).execute(&source.pool).await.unwrap();
    sqlx::query("INSERT INTO execution_https_bindings(execution_id,targets,policy_digest) VALUES($1,'https://api.test:443=1.1.1.1',$2)").bind(&dependency_execution).bind(digest("fixture-policy")).execute(&source.pool).await.unwrap();
    // Removing the endpoint connection already recorded this execution as
    // stopped by that operation; the origin shares the record.
    let public_before: Value =
        sqlx::query_scalar("SELECT jsonb_agg(to_jsonb(c)) FROM app_https_connections c")
            .fetch_one(&source.pool)
            .await
            .unwrap();
    let key = root.path().join("key");
    let source_cipher = fernet::Fernet::new(
        std::fs::read_to_string(root.path().join("source/encryption.key"))
            .unwrap()
            .trim(),
    )
    .unwrap();
    sqlx::query("INSERT INTO usage_samples(execution_id,generation,sequence,tenant_id,cpu_usec,memory_bytes,cpu_measured,memory_measured,observed) SELECT $1,1,n,$2,CASE WHEN n=200 THEN 9999 ELSE n END,n,n<600,n<600,now()-interval '1 day'+n*interval '1 second' FROM generate_series(1,600) n").bind(&log_execution).bind(t).execute(&source.pool).await.unwrap();
    sqlx::query("INSERT INTO usage_compaction_queue(execution_id) VALUES($1)")
        .bind(&log_execution)
        .execute(&source.pool)
        .await
        .unwrap();
    // Archive both already compacted history and sealed detail awaiting cleanup.
    let compacted_execution = uid();
    let pending_accounting = uid();
    for (id, bytes, archived) in [
        (&compacted_execution, 600_i64, true),
        (&pending_accounting, 80_i64, false),
    ] {
        sqlx::query("INSERT INTO executions(id,tenant_id,project_id,spec,node_id,cpu_percent,memory_mib,reserved,state,desired,created) VALUES($1,$2,$3,'{}',$4,1,1,false,'exited','stopped',now()-interval '3 years')")
            .bind(id).bind(t).bind(p).bind(node_id).execute(&source.pool).await.unwrap();
        sqlx::query("INSERT INTO execution_egress_period_sources(execution_id,tenant_id,project_id,generation,boot_id,bytes,complete,payload,sampled_at,archived_bytes,archived_periods) VALUES($1,$2,$3,1,'backup-boot',$4,true,'{}',now()-interval '14 months',$5,$6)")
            .bind(id).bind(t).bind(p).bind(bytes).bind(if archived {bytes} else {0}).bind(i64::from(archived)).execute(&source.pool).await.unwrap();
        sqlx::query("INSERT INTO execution_egress_budgets(execution_id,tenant_id,project_id,node_id,boot_id,launcher_digest,generation,state,base_bytes,ceiling_bytes,closure,closed_at) VALUES($1,$2,$3,$4,'backup-boot',repeat('a',64),1,'closed',50,50,'terminal-exact',now()-interval '14 months')")
            .bind(id).bind(t).bind(p).bind(node_id).execute(&source.pool).await.unwrap();
    }
    sqlx::query("INSERT INTO execution_egress_periods(execution_id,tenant_id,project_id,period,bytes,sampled_at) SELECT execution_id,tenant_id,project_id,date_trunc('month',sampled_at AT TIME ZONE 'UTC')::date,bytes,sampled_at FROM execution_egress_period_sources WHERE execution_id=$1")
        .bind(&pending_accounting).execute(&source.pool).await.unwrap();
    sqlx::query("INSERT INTO egress_allowance_usage(execution_id,tenant_id,project_id,period,bytes) SELECT execution_id,tenant_id,project_id,period,50 FROM execution_egress_periods WHERE execution_id=$1")
        .bind(&pending_accounting).execute(&source.pool).await.unwrap();
    sqlx::query("INSERT INTO accounting_month_rollups(tenant_id,project_id,period,outbound_accounted_bytes,outbound_conservative_bytes,settlement_records,observed_outbound_bytes,observed_period_records,observed_at) SELECT tenant_id,project_id,date_trunc('month',sampled_at AT TIME ZONE 'UTC')::date,1000,100,1,600,1,sampled_at FROM execution_egress_period_sources WHERE execution_id=$1")
        .bind(&compacted_execution).execute(&source.pool).await.unwrap();
    let old_accounting = source
        .usage_history(&operator, t, Some(p), Default::default())
        .await
        .unwrap()["items"]
        .as_array()
        .unwrap()
        .last()
        .unwrap()
        .clone();
    // Expired metadata survives restore without requiring its reclaimed bytes.
    // The pending cleanup intent must remain safe when the file is already gone.
    let expired_bytes = b"\0asm\x0d\0\x01\0expired";
    let expired = source.upload(&operator, t, p, expired_bytes).await.unwrap();
    sqlx::query("UPDATE artifacts SET retired_at=now() WHERE id=$1")
        .bind(expired["id"].as_str().unwrap())
        .execute(&source.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO artifact_blob_garbage(digest) VALUES($1)")
        .bind(digest(expired_bytes))
        .execute(&source.pool)
        .await
        .unwrap();
    std::fs::remove_file(root.path().join("source/blobs").join(digest(expired_bytes))).unwrap();
    backup::random_key(&key).unwrap();
    let archive = root.path().join("backup.fnd");
    // Capture the read model after activation has populated last_release; the
    // earlier draft snapshot is intentionally no longer the backup state.
    let versions = source
        .app_versions(&operator, t, p, app["resource_id"].as_str().unwrap(), None)
        .await
        .unwrap();
    let lifecycle_before = source
        .app_events(
            &operator,
            t,
            p,
            http_app_id,
            fenders_control_plane::app_events::EventPage {
                entry_type: Some("lifecycle".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(!lifecycle_before["items"].as_array().unwrap().is_empty());
    let rotated_key = root.path().join("rotated-control.key");
    fenders_control_plane::key_rotation::generate(&rotated_key).unwrap();
    fenders_control_plane::key_rotation::rotate(
        &source.pool,
        &root.path().join("source"),
        &rotated_key,
        true,
    )
    .await
    .unwrap();
    let rotated_endpoint_ciphertext: String =
        sqlx::query_scalar("SELECT convert_from(ciphertext,'UTF8') FROM secrets WHERE id=$1")
            .bind(endpoint_secret)
            .fetch_one(&source.pool)
            .await
            .unwrap();
    assert_ne!(rotated_endpoint_ciphertext, endpoint_ciphertext);
    // A stale file after DB commit must never produce an inconsistent archive.
    let current_key = std::fs::read(root.path().join("source/encryption.key")).unwrap();
    let stale_key = fernet::Fernet::generate_key();
    std::fs::write(root.path().join("source/encryption.key"), stale_key).unwrap();
    assert!(
        backup::create(
            &source_dsn,
            &root.path().join("source"),
            &archive,
            &key,
            100000000
        )
        .await
        .is_err()
    );
    assert!(!archive.exists());
    std::fs::write(root.path().join("source/encryption.key"), &current_key).unwrap();
    let retired_release_input = uid();
    let pending_release_input = uid();
    for id in [&retired_release_input, &pending_release_input] {
        sqlx::query("INSERT INTO app_releases(id,tenant_id,project_id,app_id,version_id,configuration,spec,state) SELECT $1,tenant_id,project_id,app_id,version_id,configuration||'{\"env\":{\"INPUT\":\"old-release-input\"}}'::jsonb,spec||'{\"env\":{\"INPUT\":\"old-release-input\"}}'::jsonb,'ready' FROM app_releases WHERE id=$2")
            .bind(id).bind(release["resource_id"].as_str().unwrap()).execute(&source.pool).await.unwrap();
        // Fixture-only time travel; every production guard is restored before
        // retirement, archive creation or recovery is exercised.
        let mut tx = source.pool.begin().await.unwrap();
        sqlx::raw_sql("ALTER TABLE app_releases DISABLE TRIGGER app_release_immutable")
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query("UPDATE app_releases SET created=now()-interval '40 days',updated=now()-interval '40 days',unreferenced_since=now()-interval '40 days' WHERE id=$1").bind(id).execute(&mut *tx).await.unwrap();
        sqlx::raw_sql("ALTER TABLE app_releases ENABLE TRIGGER app_release_immutable")
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        if id == &retired_release_input {
            sqlx::raw_sql(include_str!("../src/release_input_retention.sql"))
                .execute(&source.pool)
                .await
                .unwrap();
        }
    }
    let release_input_receipt: Value =
        sqlx::query_scalar("SELECT to_jsonb(r) FROM app_releases r WHERE id=$1")
            .bind(&retired_release_input)
            .fetch_one(&source.pool)
            .await
            .unwrap();
    assert!(release_input_receipt["inputs_retired_at"].is_string());
    let info = backup::create(
        &source_dsn,
        &root.path().join("source"),
        &archive,
        &key,
        100000000,
    )
    .await
    .unwrap();
    assert_eq!(info["files"], 4);
    let restored = root.path().join("restored");
    let result = backup::restore(&target_dsn, &restored, &archive, &key, 100000000)
        .await
        .unwrap();
    assert_eq!(result["mode"], "fenced");
    let target = Store::connect(&target_dsn, &restored).await.unwrap();
    for (index, id) in http_run_ids.iter().enumerate() {
        let state: String = sqlx::query_scalar("SELECT state FROM app_http_runs WHERE id=$1")
            .bind(id)
            .fetch_one(&target.pool)
            .await
            .unwrap();
        assert_eq!(state, ["failed", "unknown", "succeeded"][index]);
    }
    let restored_release_input: Value =
        sqlx::query_scalar("SELECT to_jsonb(r) FROM app_releases r WHERE id=$1")
            .bind(&retired_release_input)
            .fetch_one(&target.pool)
            .await
            .unwrap();
    assert_eq!(restored_release_input, release_input_receipt);
    assert!(
        sqlx::raw_sql(include_str!("../src/release_input_retention.sql"))
            .execute(&target.pool)
            .await
            .is_err()
    );
    let pending_release:bool=sqlx::query_scalar("SELECT inputs_retired_at IS NULL AND configuration->'env'->>'INPUT'='old-release-input' FROM app_releases WHERE id=$1").bind(&pending_release_input).fetch_one(&target.pool).await.unwrap();
    assert!(pending_release);
    let restored_input: Value = sqlx::query_scalar("SELECT jsonb_build_object('spec',spec,'retired_at',inputs_retired_at,'sha256',original_spec_sha256) FROM executions WHERE id=$1")
        .bind(&retired_input_execution).fetch_one(&target.pool).await.unwrap();
    assert_eq!(restored_input, input_receipt);
    assert!(
        sqlx::raw_sql(include_str!("../src/execution_input_retention.sql"))
            .execute(&target.pool)
            .await
            .is_err()
    );
    let waiting_input: bool = sqlx::query_scalar("SELECT inputs_retired_at IS NULL AND spec->'env'->>'INPUT'='duplicate' FROM executions WHERE id=$1")
        .bind(&pending_input_execution).fetch_one(&target.pool).await.unwrap();
    assert!(waiting_input);
    let retired_after: Value = sqlx::query_scalar("SELECT to_jsonb(r) FROM app_runs r WHERE id=$1")
        .bind(&retired_schedule_run)
        .fetch_one(&target.pool)
        .await
        .unwrap();
    assert_eq!(retired_after, retired_before);
    assert!(sqlx::query("INSERT INTO app_run_dispatch(run_id,tenant_id,project_id,app_id,deadline) SELECT id,tenant_id,project_id,app_id,now() FROM app_runs WHERE id=$1").bind(&retired_schedule_run).execute(&target.pool).await.is_err());
    assert_eq!(
        std::fs::read(restored.join("encryption.key")).unwrap(),
        current_key
    );
    let lifecycle_after = target
        .app_events(
            &operator,
            t,
            p,
            http_app_id,
            fenders_control_plane::app_events::EventPage {
                entry_type: Some("lifecycle".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(
        lifecycle_before["coverage"]["recording_started_at"],
        lifecycle_after["coverage"]["recording_started_at"]
    );
    for event in lifecycle_before["items"].as_array().unwrap() {
        assert!(lifecycle_after["items"].as_array().unwrap().contains(event));
    }
    assert!(
        lifecycle_after["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["kind"] == "app" && e["state"] == "stopped")
    );
    assert!(
        sqlx::query_scalar::<_, bool>("SELECT retired_at IS NOT NULL FROM artifacts WHERE id=$1")
            .bind(expired["id"].as_str().unwrap())
            .fetch_one(&target.pool)
            .await
            .unwrap()
    );
    assert!(!restored.join("blobs").join(digest(expired_bytes)).exists());
    assert!(
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM artifact_blob_garbage WHERE digest=$1)"
        )
        .bind(digest(expired_bytes))
        .fetch_one(&target.pool)
        .await
        .unwrap()
    );
    assert!(
        !sqlx::query_scalar::<_, bool>("SELECT enabled FROM public_egress_policy")
            .fetch_one(&target.pool)
            .await
            .unwrap()
    );
    assert!(
        sqlx::query_scalar::<_, bool>("SELECT bool_and(fenced) FROM execution_https_bindings")
            .fetch_one(&target.pool)
            .await
            .unwrap()
    );
    assert!(
        sqlx::query_scalar::<_, bool>(
            "SELECT bool_and(observed_runtime_digest IS NULL) FROM nodes"
        )
        .fetch_one(&target.pool)
        .await
        .unwrap()
    );
    assert_eq!(
        sqlx::query_scalar::<_, Value>(
            "SELECT jsonb_agg(to_jsonb(c)) FROM app_https_connections c"
        )
        .fetch_one(&target.pool)
        .await
        .unwrap(),
        public_before
    );
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT connection_id FROM app_execution_https")
            .fetch_one(&target.pool)
            .await
            .unwrap(),
        public_connection
    );
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT execution_id FROM connection_revocations")
            .fetch_one(&target.pool)
            .await
            .unwrap(),
        dependency_execution
    );

    assert_eq!(
        sqlx::query_scalar::<_, Value>(
            "SELECT jsonb_agg(to_jsonb(c) ORDER BY c.id) FROM app_endpoint_connections c"
        )
        .fetch_one(&target.pool)
        .await
        .unwrap(),
        connections_before
    );
    assert_eq!(
        sqlx::query_scalar::<_, Value>(
            "SELECT jsonb_agg(to_jsonb(c)) FROM app_execution_connections c"
        )
        .fetch_one(&target.pool)
        .await
        .unwrap(),
        execution_connections_before
    );
    assert_eq!(
        sqlx::query_scalar::<_, Value>(
            "SELECT jsonb_agg(to_jsonb(r)) FROM connection_revocations r"
        )
        .fetch_one(&target.pool)
        .await
        .unwrap(),
        revocations_before
    );
    assert!(
        sqlx::query_scalar::<_, bool>("SELECT reserved FROM executions WHERE id=$1")
            .bind(&dependency_execution)
            .fetch_one(&target.pool)
            .await
            .unwrap()
    );
    let endpoint_after = target
        .resources(
            &operator,
            endpoint_t,
            endpoint_p,
            "external-endpoints",
            Some(endpoint["resource_id"].as_str().unwrap()),
        )
        .await
        .unwrap();
    assert_eq!(endpoint_after, endpoint_before);
    let restored_cipher =
        fernet::Fernet::new(&std::fs::read_to_string(restored.join("encryption.key")).unwrap())
            .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT convert_from(ciphertext,'UTF8') FROM secrets WHERE id=$1"
        )
        .bind(endpoint_secret)
        .fetch_one(&target.pool)
        .await
        .unwrap(),
        rotated_endpoint_ciphertext
    );
    assert_eq!(
        restored_cipher
            .decrypt(&rotated_endpoint_ciphertext)
            .unwrap(),
        source_cipher.decrypt(&endpoint_ciphertext).unwrap()
    );
    assert_eq!(
        target
            .usage_history(&operator, t, Some(p), Default::default())
            .await
            .unwrap()["items"]
            .as_array()
            .unwrap()
            .last()
            .unwrap(),
        &old_accounting
    );
    let saved_egress = target.usage(&operator, t, Some(p)).await.unwrap();
    assert_eq!(saved_egress["totals"]["egress_bytes"], 12345);
    assert_eq!(saved_egress["totals"]["egress_month_bytes"], 12345);
    assert_eq!(saved_egress["totals"]["egress_unassigned_bytes"], 0);
    assert_eq!(saved_egress["totals"]["transfer_reserved_bytes"], 900);
    assert_eq!(saved_egress["totals"]["transfer_accounted_bytes"], 321);
    assert_eq!(saved_egress["cpu_usec"], 9999);
    let queued: i64 =
        sqlx::query_scalar("SELECT count(*) FROM usage_compaction_queue WHERE execution_id=$1")
            .bind(&log_execution)
            .fetch_one(&target.pool)
            .await
            .unwrap();
    assert_eq!(queued, 1);
    assert!(target.schedule().await.is_err());
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM execution_egress_periods WHERE execution_id=$1"
        )
        .bind(&pending_accounting)
        .fetch_one(&target.pool)
        .await
        .unwrap(),
        1
    );
    let retained: i64 =
        sqlx::query_scalar("SELECT count(*) FROM usage_samples WHERE execution_id=$1")
            .bind(&log_execution)
            .fetch_one(&target.pool)
            .await
            .unwrap();
    assert_eq!(retained, 600);
    assert_eq!(saved_egress["totals"]["egress_complete"], 0);
    let saved_logs: Value = sqlx::query_scalar("SELECT jsonb_build_object('acknowledged',s.acknowledged,'capture_id',s.capture_id,'interrupted',s.interrupted,'bytes',encode(r.payload,'base64'),'fenced',e.log_ingestion_fenced) FROM execution_log_sources s JOIN execution_log_records r USING(execution_id) JOIN executions e ON e.id=s.execution_id WHERE s.execution_id=$1")
        .bind(&log_execution).fetch_one(&target.pool).await.unwrap();
    assert_eq!(saved_logs["acknowledged"], 1);
    assert_eq!(saved_logs["interrupted"], true);
    assert_eq!(saved_logs["capture_id"], log_batch["capture_id"]);
    assert_eq!(saved_logs["bytes"], "YmVmb3JlLWJhY2t1cA==");
    assert_eq!(saved_logs["fenced"], true);
    let saved_placement:Value=sqlx::query_scalar("SELECT jsonb_build_object('reason',p.reason,'old_generation',p.generation<>e.generation) FROM execution_placement p JOIN executions e ON e.id=p.execution_id WHERE p.execution_id=$1")
        .bind(&log_execution).fetch_one(&target.pool).await.unwrap();
    assert_eq!(
        saved_placement,
        json!({"reason":"placement-capacity","old_generation":true})
    );
    let scheduled_after = target
        .app_run(&operator, t, p, schedule_app_id, schedule_run)
        .await
        .unwrap();
    assert_eq!(scheduled_after["state"], "cancelled");
    assert_eq!(scheduled_after["reason"], "restored-control-plane");
    assert!(scheduled_after["execution_id"].is_null());
    let restored_schedule = target
        .app_triggers(&operator, t, p, schedule_app_id)
        .await
        .unwrap();
    assert_eq!(restored_schedule["schedule"]["enabled"], true);
    assert!(restored_schedule["schedule"]["next_at"].is_null());
    let outbox_state: String =
        sqlx::query_scalar("SELECT state FROM app_run_dispatch WHERE run_id=$1")
            .bind(schedule_run)
            .fetch_one(&target.pool)
            .await
            .unwrap();
    assert_eq!(outbox_state, "cancelled");
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM ingress_reservations WHERE id=$1")
            .bind(&wake_lease)
            .fetch_one(&target.pool)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        target
            .app_history(&operator, t, p, schedule_app_id, "runs", Default::default())
            .await
            .unwrap()["missed_history_pending"],
        true
    );
    let restored_logs = target
        .app_logs(&operator, t, p, app_id, Default::default())
        .await
        .unwrap();
    assert_eq!(restored_logs["items"], before_logs["items"]);
    assert_eq!(restored_logs["collection"]["fenced"], 1);
    assert!(
        target
            .app_logs(
                &operator,
                t,
                p,
                app_id,
                fenders_control_plane::app_logs::LogPage {
                    after: Some(before_logs["next"].as_str().unwrap().to_owned()),
                    ..Default::default()
                }
            )
            .await
            .is_err()
    );
    assert_eq!(
        target
            .ingest_execution_logs(node_id, &log_execution, 1, log_batch.clone())
            .await
            .unwrap_err()
            .status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    let validation: Value =
        sqlx::query_scalar("SELECT to_jsonb(v) FROM artifact_validations v WHERE artifact_id=$1")
            .bind(inspecting["id"].as_str().unwrap())
            .fetch_one(&target.pool)
            .await
            .unwrap();
    assert_eq!(validation["state"], "pending");
    assert_eq!(validation["generation"], 2);
    assert!(validation["node_id"].is_null());
    assert_eq!(
        target
            .app_versions(&operator, t, p, app["resource_id"].as_str().unwrap(), None)
            .await
            .unwrap(),
        versions
    );
    assert_eq!(
        target
            .claim_component(node_id, boot())
            .await
            .unwrap_err()
            .status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        target.authenticate(&token).await.unwrap_err().status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        target
            .create_project(
                &operator,
                t,
                serde_json::from_value(json!({"name":"blocked"})).unwrap()
            )
            .await
            .unwrap_err()
            .status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    let used = target.usage(&operator, t, None).await.unwrap();
    assert_eq!(used["reserved"]["instances"], 2);
    let http_after = target
        .app_http_status(&operator, t, p, http_app_id)
        .await
        .unwrap();
    assert_eq!(http_after["url"], http_before["url"]);
    assert_eq!(http_after["state"], "disabled");
    assert!(http_after["execution_id"].is_null());
    assert_eq!(
        target.app(&operator, t, p, http_app_id).await.unwrap()["desired"],
        "stopped"
    );
    assert_eq!(
        target
            .app_triggers(&operator, t, p, http_app_id)
            .await
            .unwrap()["http"],
        true
    );
    assert_eq!(
        target
            .app_release(
                &operator,
                t,
                p,
                http_app_id,
                http_release["resource_id"].as_str().unwrap()
            )
            .await
            .unwrap()["state"],
        "failed"
    );
    assert_eq!(
        target.schedule().await.unwrap_err().status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        target.app(&operator, t, p, app_id).await.unwrap()["desired"],
        "stopped"
    );
    assert_eq!(
        target.app(&operator, t, p, app_id).await.unwrap()["active_release_id"],
        release["resource_id"]
    );
    assert_eq!(
        target.app_triggers(&operator, t, p, app_id).await.unwrap()["manual"],
        true
    );
    assert_eq!(
        target
            .run_app(&operator, t, p, app_id, "barred")
            .await
            .unwrap_err()
            .status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(backup::activate(&target_dsn, false).await.is_err());
    assert_eq!(
        target.usage(&operator, t, Some(p)).await.unwrap()["totals"]["transfer_reserved_bytes"],
        900
    );
    let activation = backup::activate(&target_dsn, true).await.unwrap();
    sqlx::raw_sql(include_str!("../src/release_input_retention.sql"))
        .execute(&target.pool)
        .await
        .unwrap();
    let retired_release:bool=sqlx::query_scalar("SELECT inputs_retired_at IS NOT NULL AND NOT configuration ? 'env' AND NOT spec ? 'env' FROM app_releases WHERE id=$1").bind(&pending_release_input).fetch_one(&target.pool).await.unwrap();
    assert!(retired_release);
    sqlx::raw_sql(include_str!("../src/execution_input_retention.sql"))
        .execute(&target.pool)
        .await
        .unwrap();
    let retired_input: bool = sqlx::query_scalar("SELECT inputs_retired_at IS NOT NULL AND NOT spec ? 'env' AND spec->'secret_env'->>'TOKEN'='retained-reference' FROM executions WHERE id=$1")
        .bind(&pending_input_execution).fetch_one(&target.pool).await.unwrap();
    assert!(retired_input);
    let settled = target.usage(&operator, t, Some(p)).await.unwrap();
    assert_eq!(settled["totals"]["transfer_reserved_bytes"], 0);
    assert_eq!(settled["totals"]["transfer_accounted_bytes"], 1221);
    assert_eq!(settled["totals"]["outbound_conservative_bytes"], 900);
    assert!(backup::activate(&target_dsn, true).await.is_err());
    assert_eq!(
        target.usage(&operator, t, Some(p)).await.unwrap()["totals"]["transfer_accounted_bytes"],
        1221
    );
    assert_eq!(activation["lost_executions"], 3);
    for _ in 0..3 {
        target.schedule().await.unwrap();
    }
    assert!(
        !sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM artifact_blob_garbage WHERE digest=$1)"
        )
        .bind(digest(expired_bytes))
        .fetch_one(&target.pool)
        .await
        .unwrap()
    );
    assert_eq!(
        target
            .usage_history(&operator, t, Some(p), Default::default())
            .await
            .unwrap()["items"]
            .as_array()
            .unwrap()
            .last()
            .unwrap(),
        &old_accounting
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM execution_egress_periods WHERE execution_id=$1"
        )
        .bind(&pending_accounting)
        .fetch_one(&target.pool)
        .await
        .unwrap(),
        0
    );
    assert_eq!(sqlx::query_scalar::<_,i64>("SELECT archived_bytes::bigint FROM execution_egress_period_sources WHERE execution_id=$1").bind(&pending_accounting).fetch_one(&target.pool).await.unwrap(),80);
    let retained: i64 =
        sqlx::query_scalar("SELECT count(*) FROM usage_samples WHERE execution_id=$1")
            .bind(&log_execution)
            .fetch_one(&target.pool)
            .await
            .unwrap();
    assert!(retained <= 3);
    assert_eq!(
        target.usage(&operator, t, Some(p)).await.unwrap()["cpu_usec"],
        9999
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM app_endpoint_connections WHERE state='revoking'"
        )
        .fetch_one(&target.pool)
        .await
        .unwrap(),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM app_endpoint_connections WHERE state='active'"
        )
        .fetch_one(&target.pool)
        .await
        .unwrap(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT state FROM operations WHERE id=$1")
            .bind(connection_remove["id"].as_str().unwrap())
            .fetch_one(&target.pool)
            .await
            .unwrap(),
        "failed"
    );
    assert_eq!(
        target
            .app_http_status(&operator, t, p, http_app_id)
            .await
            .unwrap(),
        http_after
    );
    assert_eq!(
        target
            .app_run(
                &operator,
                t,
                p,
                app_id,
                run["resource_id"].as_str().unwrap()
            )
            .await
            .unwrap()["state"],
        "unknown"
    );
    assert_eq!(
        target
            .run_app(&operator, t, p, app_id, "queued")
            .await
            .unwrap()["id"],
        run["id"]
    );
    assert_eq!(
        target
            .run_app(&operator, t, p, app_id, "must-not-replay")
            .await
            .unwrap_err()
            .status,
        StatusCode::CONFLICT
    );
    assert_eq!(
        target.usage(&operator, t, None).await.unwrap()["reserved"]["instances"],
        0
    );
    let bytes = std::fs::read(restored.join("blobs").join(digest(b"\0asm\x0d\0\x01\0"))).unwrap();
    assert_eq!(bytes, b"\0asm\x0d\0\x01\0");
    target
        .node_mode(
            &operator,
            node_id,
            json!({"disabled":false,"draining":false}),
        )
        .await
        .unwrap();
    target
        .heartbeat(
            node_id,
            json!({"boot_id":"backup-boot","reports":[],"confinement":HOST_CONFINEMENT}),
        )
        .await
        .unwrap();
    assert_eq!(
        target
            .component_content(node_id, inspecting["id"].as_str().unwrap(), 1, boot())
            .await
            .unwrap_err()
            .status,
        StatusCode::CONFLICT
    );
    // Even a re-enrolled worker using the restored generation cannot append to
    // pre-restore history, including executions without an existing log source.
    assert_eq!(
        target
            .ingest_execution_logs(node_id, &log_execution, 2, log_batch)
            .await
            .unwrap_err()
            .status,
        StatusCode::CONFLICT
    );
    assert_eq!(
        target.claim_component(node_id, boot()).await.unwrap()["job"]["generation"],
        3
    );
    source.pool.close().await;
    target.pool.close().await;
    for name in [&source_name, &destination_name] {
        sqlx::query(&format!("DROP DATABASE {name}"))
            .execute(&admin)
            .await
            .unwrap();
    }
    admin.close().await;
}

#[tokio::test]
async fn public_gateway_and_secret_logs_preserve_credential_boundaries() {
    /// Stands in for the shim of `execution`: takes its requests from the
    /// exchange and answers as `mode` says, by default with the request it
    /// was given. This verifies the gateway, not guest execution.
    fn fixture_shim(
        store: Store,
        key: String,
        execution: String,
        mode: std::sync::Arc<std::sync::atomic::AtomicU8>,
        calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) {
        use fenders_control_plane::http_exchange::Message;
        use std::sync::atomic::Ordering::SeqCst;
        tokio::spawn(async move {
            loop {
                // Mode 11: a shim that takes nothing.
                if mode.load(SeqCst) == 11 {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    continue;
                }
                let wait = std::time::Duration::from_millis(200);
                let Some(request) = store.exchange.next(&key, &execution, wait).await else {
                    continue;
                };
                calls.fetch_add(1, SeqCst);
                let id = request.head["id"].as_str().unwrap().to_owned();
                let body = axum::body::to_bytes(request.body, 4 << 20).await.unwrap();
                let mut echo = request.head.clone();
                echo.as_object_mut().unwrap().remove("id");
                echo["body"] = json!(STANDARD.encode(&body));
                let (head, data): (Value, Vec<u8>) = match mode.load(SeqCst) {
                    3 => (json!({"headers":{}}), vec![]),
                    4 => (
                        json!({"status":200,"headers":{"content-type":"text/html","set-cookie":"stolen=1"}}),
                        "<script>not executable</script>".repeat(1000).into_bytes(),
                    ),
                    5 => (
                        json!({"status":302,"headers":{"location":"https://untrusted.invalid/","cache-control":"public"}}),
                        b"redirect only".to_vec(),
                    ),
                    6 => (
                        json!({"status":503,"headers":{}}),
                        b"application unavailable".to_vec(),
                    ),
                    7 => (json!({"status":65736,"headers":{}}), vec![]),
                    8 => (
                        json!({"status":200,"headers":{"location":"x".repeat(8193)}}),
                        vec![],
                    ),
                    9 => (json!({"status":200,"headers":{}}), vec![0; 2 * 1024 * 1024]),
                    _ => (
                        json!({"status":200,"headers":{"content-type":"application/json"}}),
                        serde_json::to_vec(&echo).unwrap(),
                    ),
                };
                store.exchange.respond(
                    &execution,
                    &id,
                    Message {
                        head,
                        body: axum::body::Body::from(data),
                    },
                );
                store.exchange.finished(&execution, &id);
            }
        });
    }

    use base64::{Engine, engine::general_purpose::STANDARD};
    use tower::ServiceExt;
    let dsn = std::env::var("FENDERS_TEST_DATABASE_URL").unwrap();
    let admin = sqlx::PgPool::connect(&dsn).await.unwrap();
    let schema = format!("rust_gateway_{}", uid());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&admin)
        .await
        .unwrap();
    let opts: sqlx::postgres::PgConnectOptions = dsn.parse().unwrap();
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_with(opts.options([("search_path", schema.as_str())]))
        .await
        .unwrap();
    let root = tempfile::tempdir().unwrap();
    let store = Store::from_pool(pool, root.path()).unwrap();
    store.migrate().await.unwrap();
    let token = std::fs::read_to_string(store.bootstrap().await.unwrap()).unwrap();
    let operator = store.authenticate(&token).await.unwrap();
    let pki_path = root.path().join("pki");
    let pins = pki::create(
        &pki_path,
        &BTreeMap::from([
            ("control".to_owned(), vec!["127.0.0.1".to_owned()]),
            ("node".to_owned(), vec!["127.0.0.1".to_owned()]),
        ]),
    )
    .unwrap();
    let cfg = transport::server_config(
        &pki_path.join("node.pem"),
        &pki_path.join("node.key"),
        Some(&pki_path.join("ca.pem")),
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("https://{}", listener.local_addr().unwrap());
    // Labelled RPC echo fixture: this is transport verification, not guest execution.
    let redacting = std::sync::Arc::new(std::sync::atomic::AtomicU8::new(0));
    let worker_redacting = redacting.clone();
    let ingress_calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let worker_calls = ingress_calls.clone();
    let fixture=Router::new().fallback(move |uri:axum::http::Uri,Json(v):Json<serde_json::Value>| {
        let redacting=worker_redacting.clone();
        let calls=worker_calls.clone();
        async move {
            if uri.path()=="/rpc/logs" {
                let mode=redacting.load(std::sync::atomic::Ordering::SeqCst);
                if mode==2 {
                    Json(json!({"text":"[REDACTED]","total_bytes":10,"redaction":fenders_control_plane::model::LOG_REDACTION,"redacted_env":["TOKEN"]}))
                } else if mode==1 {
                    Json(json!({"text":"sensitive-gateway-fixture","total_bytes":25,"redaction":fenders_control_plane::model::LOG_REDACTION,"redacted_env":[]}))
                } else {Json(json!({"text":"sensitive-gateway-fixture","total_bytes":25}))}
            } else {
                calls.fetch_add(1,std::sync::atomic::Ordering::SeqCst);
                let mode = redacting.load(std::sync::atomic::Ordering::SeqCst);
                if mode==4 { Json(json!({"status":200,"headers":{"content-type":"text/html","set-cookie":"stolen=1"},"body":STANDARD.encode("<script>not executable</script>".repeat(1000))})) }
                else if mode==5 { Json(json!({"status":302,"headers":{"location":"https://untrusted.invalid/","cache-control":"public"},"body":STANDARD.encode("redirect only")})) }
                else if mode==6 { Json(json!({"status":503,"headers":{},"body":STANDARD.encode("application unavailable")})) }
                else if mode==7 { Json(json!({"status":65736,"headers":{},"body":""})) }
                else if mode==8 { Json(json!({"status":200,"headers":{"location":"x".repeat(8193)},"body":""})) }
                else if mode==9 { Json(json!({"status":200,"headers":{},"body":STANDARD.encode(vec![0;2*1024*1024])})) }
                else if mode==10 { Json(json!({"status":200,"headers":{},"body":STANDARD.encode(vec![0;1024*1024+1])})) }
                else {Json(json!({"status":200,"headers":{"content-type":"application/json"},"body":if mode==3 {"invalid base64!".to_owned()} else {STANDARD.encode(serde_json::to_vec(&v["request"]).unwrap())}}))}
            }
        }
    });
    let server = tokio::spawn(transport::serve_tls(listener, cfg, fixture));
    let t=store.create_tenant(&operator,serde_json::from_value(json!({"name":"gateway","allowance":{"cpu_percent":100,"memory_mib":1024,"instances":2,"storage_bytes":1000000,"transfer_bytes":10000000}})).unwrap()).await.unwrap();
    let tenant = t["id"].as_str().unwrap();
    let p = store
        .create_project(
            &operator,
            tenant,
            serde_json::from_value(json!({"name":"app"})).unwrap(),
        )
        .await
        .unwrap();
    let project = p["id"].as_str().unwrap();
    let a = store
        .upload(&operator, tenant, project, b"\0asm\x0d\0\x01\0")
        .await
        .unwrap();
    let node=store.register_node(&operator,json!({"name":"node","cert_sha256":pins["node"],"endpoint":endpoint,"backend":"wasm","architecture":"x86_64","runtime":"wasmtime-50.0.0-fenders-v1","cpu_percent":100,"memory_mib":128,"instances":1})).await.unwrap();
    let node_id = node["id"].as_str().unwrap();
    store.heartbeat(node_id,json!({"boot_id":"fixture","reports":[],"confinement":fenders_control_plane::model::HOST_CONFINEMENT})).await.unwrap();
    let secret = store
        .create_secret(
            &operator,
            tenant,
            project,
            json!({"name":"log-secret","value":"sensitive-gateway-fixture"}),
        )
        .await
        .unwrap();
    let op = store
        .create_workload(
            &operator,
            tenant,
            project,
            json!({"name":"web","spec":{"artifact_id":a["id"],"secret_env":{"TOKEN":secret["id"]}}}),
            "web",
            true,
        )
        .await
        .unwrap();
    let route = store
        .create_route(
            &operator,
            tenant,
            project,
            json!({"name":"web","deployment_id":op["resource_id"]}),
            "apps.test",
        )
        .await
        .unwrap();
    store.schedule().await.unwrap();
    let executions = store
        .resources(&operator, tenant, project, "executions", None)
        .await
        .unwrap();
    store.heartbeat(node_id,json!({"boot_id":"fixture","confinement":fenders_control_plane::model::HOST_CONFINEMENT,"reports":[{"id":executions[0]["id"],"generation":1,"sequence":1,"state":"running","cpu_usec":0,"memory_bytes":0}]})).await.unwrap();
    // An execution of no app takes its own requests; an app's take the app's.
    fixture_shim(
        store.clone(),
        executions[0]["id"].as_str().unwrap().to_owned(),
        executions[0]["id"].as_str().unwrap().to_owned(),
        redacting.clone(),
        ingress_calls.clone(),
    );
    let app = api::gateway(api::ApiState {
        store: store.clone(),
        domain: "apps.test".into(),
        tls: Some(api::PeerCredentials {
            ca: pki_path.join("ca.pem"),
            cert: pki_path.join("control.pem"),
            key: pki_path.join("control.key"),
        }),
    });
    for auth in [
        format!("Bearer {token}"),
        "Bearer application-secret".to_owned(),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/hello?q=world")
                    .header("Host", route["hostname"].as_str().unwrap())
                    .header("Authorization", &auth)
                    .body(axum::body::Body::from("body"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        if auth.starts_with("Bearer fnd_") {
            assert!(v["headers"]["authorization"].is_null())
        } else {
            assert_eq!(v["headers"]["authorization"], auth)
        }
        assert_eq!(v["path"], "/hello?q=world");
    }
    // A request is settled once its response has ended.
    for _ in 0..200 {
        if store.usage(&operator, tenant, None).await.unwrap()["ingress_month"]["requests"] == 2 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(
        store.usage(&operator, tenant, None).await.unwrap()["ingress_month"]["requests"],
        2
    );
    let viewer = store
        .create_api_key(&operator, tenant, serde_json::from_value(json!({"name":"viewer","project_id":project,"permissions":["read"],"ttl_seconds":86400})).unwrap(), &uid())
        .await
        .unwrap();
    let management = api::management(api::ApiState {
        store: store.clone(),
        domain: "apps.test".into(),
        tls: Some(api::PeerCredentials {
            ca: pki_path.join("ca.pem"),
            cert: pki_path.join("control.pem"),
            key: pki_path.join("control.key"),
        }),
    });
    // The real gateway holds two requests while this protocol fixture wakes.
    // Each is taken exactly once, after a fresh running observation.
    sqlx::query("UPDATE tenants SET cpu_percent=400,instances=4 WHERE id=$1")
        .bind(tenant)
        .execute(&store.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE nodes SET cpu_percent=400,memory_mib=4096,instances=4 WHERE id=$1")
        .bind(node_id)
        .execute(&store.pool)
        .await
        .unwrap();
    let job = store
        .claim_component(node_id, json!({"boot_id":"fixture"}))
        .await
        .unwrap()["job"]
        .clone();
    store.component_result(node_id,a["id"].as_str().unwrap(),job["generation"].as_i64().unwrap(),json!({"boot_id":"fixture","inspection":{"format_version":1,"runtime":fenders_control_plane::artifacts::RUNTIME,"digest":a["digest"],"bytes":8,"command":false,"http":true,"imports":[],"exports":[]}})).await.unwrap();
    let demand=store.deploy_app(&operator,tenant,project,fenders_control_plane::apps::AppSubmission{value:json!({"name":"demand-gateway","artifact_id":a["id"],"configuration":{"keep_warm":false},"triggers":{"http":true,"manual":false}}),key:"demand-gateway",domain:"apps.test"}).await.unwrap();
    let demand_id = demand["resource_id"].as_str().unwrap();
    store.schedule().await.unwrap();
    let demand_execution = store
        .app_http_status(&operator, tenant, project, demand_id)
        .await
        .unwrap()["execution_id"]
        .clone();
    store.heartbeat(node_id,json!({"boot_id":"fixture","confinement":HOST_CONFINEMENT,"reports":[{"id":demand_execution,"generation":1,"sequence":1,"state":"running","cpu_usec":0,"memory_bytes":0}]})).await.unwrap();
    sqlx::query("UPDATE app_http SET last_activity=now()-interval '61 seconds' WHERE app_id=$1")
        .bind(demand_id)
        .execute(&store.pool)
        .await
        .unwrap();
    store.schedule().await.unwrap();
    for (state, sequence) in [("stopped", 3)] {
        let generation: i64 = sqlx::query_scalar("SELECT generation FROM executions WHERE id=$1")
            .bind(demand_execution.as_str().unwrap())
            .fetch_one(&store.pool)
            .await
            .unwrap();
        store.heartbeat(node_id,json!({"boot_id":"fixture","confinement":HOST_CONFINEMENT,"reports":[{"id":demand_execution,"generation":generation,"sequence":sequence,"state":state,"cpu_usec":0,"memory_bytes":0}]})).await.unwrap();
    }
    assert_eq!(
        store
            .app_http_status(&operator, tenant, project, demand_id)
            .await
            .unwrap()["state"],
        "idle"
    );
    let host = format!("app-{demand_id}.apps.test");
    let request = |path: &str| {
        Request::builder()
            .method("POST")
            .uri(path)
            .header("Host", &host)
            .body(axum::body::Body::from("wake-body"))
            .unwrap()
    };
    let first = tokio::spawn(app.clone().oneshot(request("/wake/one")));
    let second = tokio::spawn(app.clone().oneshot(request("/wake/two")));
    tokio::time::timeout(std::time::Duration::from_secs(5),async {
        loop {
            let waiting:i64=sqlx::query_scalar("SELECT count(*) FROM ingress_reservations WHERE app_id=$1 AND execution_id IS NULL").bind(demand_id).fetch_one(&store.pool).await.unwrap();
            if waiting==2 {break;}
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }).await.unwrap();
    assert_eq!(ingress_calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    store.schedule().await.unwrap();
    let wake_execution = store
        .app_http_status(&operator, tenant, project, demand_id)
        .await
        .unwrap()["execution_id"]
        .clone();
    assert_ne!(wake_execution, demand_execution);
    fixture_shim(
        store.clone(),
        demand_id.to_owned(),
        wake_execution.as_str().unwrap().to_owned(),
        redacting.clone(),
        ingress_calls.clone(),
    );
    store.heartbeat(node_id,json!({"boot_id":"fixture","confinement":HOST_CONFINEMENT,"reports":[{"id":wake_execution,"generation":1,"sequence":1,"state":"running","cpu_usec":0,"memory_bytes":0}]})).await.unwrap();
    for (task, path) in [(first, "/wake/one"), (second, "/wake/two")] {
        let response = task.await.unwrap().unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let data = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let result: Value = serde_json::from_slice(&data).unwrap();
        assert_eq!(result["path"], path);
        assert_eq!(result["body"], STANDARD.encode("wake-body"));
    }
    assert_eq!(ingress_calls.load(std::sync::atomic::Ordering::SeqCst), 4);
    // Once forwarded, even an invalid response must not replay the request.
    redacting.store(3, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        app.clone()
            .oneshot(request("/uncertain"))
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_GATEWAY
    );
    assert_eq!(ingress_calls.load(std::sync::atomic::Ordering::SeqCst), 5);
    let sample_url =
        format!("/v1/tenants/{tenant}/projects/{project}/apps/{demand_id}/http-sample");
    let sample = |url: &str, token: &str, body: Value| {
        Request::builder()
            .method("POST")
            .uri(url)
            .header("Authorization", format!("Bearer {token}"))
            .header("Cookie", "management-secret=never-forward")
            .header("X-CSRF-Token", "never-forward")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap()
    };
    // Real management authorization and the gateway, with no chosen target or
    // forwarded customer-console credentials.
    redacting.store(0, std::sync::atomic::Ordering::SeqCst);
    let response = management
        .clone()
        .oneshot(sample(&sample_url, &token, json!({})))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert!(response.headers().get("set-cookie").is_none());
    let value: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(value["outcome"], "response");
    assert_eq!(value["status"], 200);
    let echo: Value =
        serde_json::from_slice(&STANDARD.decode(value["body"].as_str().unwrap()).unwrap()).unwrap();
    assert_eq!(echo["method"], "GET");
    assert_eq!(echo["path"], "/");
    assert_eq!(echo["body"], "");
    assert_eq!(echo["headers"].as_object().unwrap().len(), 2);
    assert_eq!(echo["headers"]["accept"], "*/*");
    assert_eq!(echo["headers"]["x-request-id"], value["request_id"]);
    let before_denial = ingress_calls.load(std::sync::atomic::Ordering::SeqCst);
    for (url, credential, body, expected) in [
        (
            sample_url.clone(),
            viewer["token"].as_str().unwrap(),
            json!({}),
            StatusCode::FORBIDDEN,
        ),
        (
            sample_url.replace(demand_id, &uid()),
            token.as_str(),
            json!({}),
            StatusCode::NOT_FOUND,
        ),
        (
            sample_url.replace(project, &uid()),
            token.as_str(),
            json!({}),
            StatusCode::NOT_FOUND,
        ),
        (
            sample_url.replace(tenant, &uid()),
            token.as_str(),
            json!({}),
            StatusCode::NOT_FOUND,
        ),
        (
            sample_url.clone(),
            token.as_str(),
            json!({"url":"http://127.0.0.1/"}),
            StatusCode::BAD_REQUEST,
        ),
    ] {
        assert_eq!(
            management
                .clone()
                .oneshot(sample(&url, credential, body))
                .await
                .unwrap()
                .status(),
            expected
        );
    }
    assert_eq!(
        ingress_calls.load(std::sync::atomic::Ordering::SeqCst),
        before_denial
    );
    // A request no shim takes never reached the app: that is distinct from a
    // malformed answer after the app was given it (the cases below), and it
    // is not charged.
    let charged = || async {
        sqlx::query_scalar::<_, i64>(
            "SELECT COALESCE(sum(bytes),0)::bigint FROM traffic_usage WHERE tenant_id=$1",
        )
        .bind(tenant)
        .fetch_one(&store.pool)
        .await
        .unwrap()
    };
    // Settled once the response before has ended.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let charged_before = charged().await;
    redacting.store(11, std::sync::atomic::Ordering::SeqCst);
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    let response = management
        .clone()
        .oneshot(sample(&sample_url, &token, json!({})))
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(value["outcome"], "refused");
    assert_eq!(value["gateway_status"], 503);
    assert_eq!(value["error"], "the application did not take the request");
    assert_eq!(
        ingress_calls.load(std::sync::atomic::Ordering::SeqCst),
        before_denial
    );
    assert_eq!(
        charged().await,
        charged_before,
        "a request the app was never given must not be charged"
    );
    for mode in [4, 5, 6, 3, 7, 8, 9] {
        redacting.store(mode, std::sync::atomic::Ordering::SeqCst);
        let calls = ingress_calls.load(std::sync::atomic::Ordering::SeqCst);
        let response = management
            .clone()
            .oneshot(sample(&sample_url, &token, json!({})))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get("location").is_none());
        assert!(response.headers().get("set-cookie").is_none());
        let value: Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 65536)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            ingress_calls.load(std::sync::atomic::Ordering::SeqCst),
            calls + 1
        );
        match mode {
            4 => {
                assert_eq!(value["truncated"], true);
                assert_eq!(
                    STANDARD
                        .decode(value["body"].as_str().unwrap())
                        .unwrap()
                        .len(),
                    16384
                );
                assert!(value["body_bytes"].as_u64().unwrap() > 16384);
                assert!(value["headers"].get("set-cookie").is_none());
            }
            5 => {
                assert_eq!(value["status"], 302);
                assert_eq!(value["headers"]["location"], "https://untrusted.invalid/");
            }
            6 => {
                assert_eq!(value["status"], 503);
                assert_eq!(value["outcome"], "response");
            }
            // A body of any size is passed on as it comes; the sample reads
            // its start and stops at 1 MiB.
            9 => {
                assert_eq!(value["outcome"], "response");
                assert_eq!(value["truncated"], true);
                assert!(value["body_bytes"].as_u64().unwrap() > 1024 * 1024);
            }
            _ => {
                assert_eq!(value["outcome"], "unconfirmed");
                assert_eq!(value["gateway_status"], 502);
            }
        }
    }
    let current = store
        .app(&operator, tenant, project, demand_id)
        .await
        .unwrap();
    store
        .app_lifecycle(
            &operator,
            tenant,
            project,
            demand_id,
            json!({"desired":"stopped","expected_revision":current["revision"]}),
            "stop-sample",
        )
        .await
        .unwrap();
    assert_eq!(
        management
            .clone()
            .oneshot(sample(&sample_url, &token, json!({})))
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );
    sqlx::query("UPDATE recovery_barrier SET active=true")
        .execute(&store.pool)
        .await
        .unwrap();
    assert_eq!(
        management
            .oneshot(sample(&sample_url, &token, json!({})))
            .await
            .unwrap()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    server.abort();
    store.pool.close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
}

#[test]
fn pki_refuses_overwrite() {
    let root = tempfile::tempdir().unwrap();
    let names = BTreeMap::from([("node".into(), vec!["node.example".into()])]);
    pki::create(root.path(), &names).unwrap();
    assert!(pki::create(root.path(), &names).is_err());
    assert!(Path::new(root.path()).join("ca.key").is_file());
}
