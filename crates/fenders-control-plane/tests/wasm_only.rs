//! Real PostgreSQL checks for the Incus-free baseline and external connection API.
//! These do not substitute for the console/real-worker PostgreSQL TLS journey.
use fenders_control_plane::{
    db::s, external_endpoints::ExternalNetworkPolicy, model::uid, store::Store,
};
use serde_json::json;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

#[tokio::test]
async fn external_endpoints_are_scoped_idempotent_and_do_not_provision() {
    let dsn = std::env::var("FENDERS_TEST_DATABASE_URL")
        .expect("dedicated PostgreSQL test database required");
    let admin = sqlx::PgPool::connect(&dsn).await.unwrap();
    let schema = format!("external_test_{}", uid());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&admin)
        .await
        .unwrap();
    let options: PgConnectOptions = dsn.parse().unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect_with(options.options([("search_path", schema.as_str())]))
        .await
        .unwrap();
    let root = tempfile::tempdir().unwrap();
    let store = Store::from_pool(pool, root.path())
        .unwrap()
        .with_external_network(ExternalNetworkPolicy {
            allowed_cidrs: vec!["192.0.2.2/32".parse().unwrap()],
            denied_cidrs: vec![],
        });
    store.migrate().await.unwrap();
    store.migrate().await.unwrap();
    let token = std::fs::read_to_string(store.bootstrap().await.unwrap()).unwrap();
    let operator = store.authenticate(&token).await.unwrap();
    let tenant=store.create_tenant(&operator,serde_json::from_value(json!({"name":"external-test","allowance":{"cpu_percent":200,"memory_mib":1024,"instances":4,"storage_bytes":10000000,"transfer_bytes":10000000}})).unwrap()).await.unwrap();
    let tenant = s(&tenant["id"]);
    let project = store
        .create_project(
            &operator,
            tenant,
            serde_json::from_value(json!({"name":"app"})).unwrap(),
        )
        .await
        .unwrap();
    let project = s(&project["id"]);
    let username = store
        .create_secret(
            &operator,
            tenant,
            project,
            json!({"name":"database-user","value":"test-user"}),
        )
        .await
        .unwrap();
    let password = store
        .create_secret(
            &operator,
            tenant,
            project,
            json!({"name":"database-password","value":"not-an-actual-database-password"}),
        )
        .await
        .unwrap();
    let legacy = json!({"name":"external-pg","host":"192.0.2.2","port":5432,"database":"demo","username_secret_id":username["id"],"password_secret_id":password["id"]});
    let value = json!({"name":"tcp-echo","host":"192.0.2.2","port":6379});
    let credential = store
        .create_api_key(&operator, tenant, serde_json::from_value(json!({"name":"editor","project_id":project,"permissions":["read","apps:write","runs:write","connections:write","secrets:write"],"ttl_seconds":86400})).unwrap(), &uid())
        .await
        .unwrap();
    let editor = store.authenticate(s(&credential["token"])).await.unwrap();
    let key = uid();
    let created = store
        .create_endpoint(&editor, tenant, project, value.clone(), &key)
        .await
        .unwrap();
    assert_eq!(created["state"], "succeeded");
    assert_eq!(
        store
            .create_endpoint(&editor, tenant, project, value.clone(), &key)
            .await
            .unwrap()["id"],
        created["id"]
    );
    let mut changed = value.clone();
    changed["port"] = json!(6432);
    assert_eq!(
        store
            .create_endpoint(&editor, tenant, project, changed, &key)
            .await
            .unwrap_err()
            .status
            .as_u16(),
        409
    );
    let list = store
        .resources(&editor, tenant, project, "external-endpoints", None)
        .await
        .unwrap();
    assert_eq!(list.as_array().unwrap().len(), 1);
    assert!(!list.to_string().contains("not-an-actual-database-password"));
    assert!(!list.to_string().contains("test-user"));
    let viewer_credential = store
        .create_api_key(&operator, tenant, serde_json::from_value(json!({"name":"viewer","project_id":project,"permissions":["read"],"ttl_seconds":86400})).unwrap(), &uid())
        .await
        .unwrap();
    let viewer = store
        .authenticate(s(&viewer_credential["token"]))
        .await
        .unwrap();
    assert_eq!(
        store
            .create_endpoint(&viewer, tenant, project, value.clone(), &uid())
            .await
            .unwrap_err()
            .status
            .as_u16(),
        403
    );
    let other = store
        .create_project(
            &operator,
            tenant,
            serde_json::from_value(json!({"name":"other"})).unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        store
            .resources(&editor, tenant, s(&other["id"]), "external-endpoints", None)
            .await
            .unwrap_err()
            .status
            .as_u16(),
        404
    );
    // One catalog, but HTTPS registrations never create socket endpoints,
    // app authority, DNS bindings or executions.
    let https_value =
        json!({"type":"https","name":"public-api","origin":"https://api.example.com:443"});
    let https_key = uid();
    let https = store
        .create_endpoint(&editor, tenant, project, https_value.clone(), &https_key)
        .await
        .unwrap();
    assert_eq!(
        store
            .create_endpoint(&editor, tenant, project, https_value, &https_key)
            .await
            .unwrap()["id"],
        https["id"]
    );
    let https_id = s(&https["resource_id"]);
    let registered = store
        .resources(
            &editor,
            tenant,
            project,
            "external-endpoints",
            Some(https_id),
        )
        .await
        .unwrap();
    assert_eq!(registered["type"], "https");
    assert_eq!(registered["origin"], "https://api.example.com:443");
    assert!(registered.get("address").is_none());
    assert_eq!(
        store
            .resources(
                &operator,
                tenant,
                s(&other["id"]),
                "external-endpoints",
                Some(https_id)
            )
            .await
            .unwrap_err()
            .status
            .as_u16(),
        404
    );
    assert_eq!(
        store
            .create_endpoint(
                &viewer,
                tenant,
                project,
                json!({"type":"https","name":"viewer-api","origin":"https://example.com"}),
                &uid()
            )
            .await
            .unwrap_err()
            .status
            .as_u16(),
        403
    );
    for origin in [
        "http://example.com",
        "https://127.0.0.1",
        "https://example.com/path",
        "https://*.example.com",
    ] {
        assert_eq!(
            store
                .create_endpoint(
                    &editor,
                    tenant,
                    project,
                    json!({"type":"https","name":"invalid","origin":origin}),
                    &uid()
                )
                .await
                .unwrap_err()
                .status
                .as_u16(),
            400
        );
    }
    assert_eq!(
        store
            .create_endpoint(
                &editor,
                tenant,
                project,
                json!({"type":"https","name":"tcp-echo","origin":"https://example.com"}),
                &uid()
            )
            .await
            .unwrap_err()
            .status
            .as_u16(),
        409
    );
    let socket_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM external_endpoints WHERE id=$1")
            .bind(https_id)
            .fetch_one(&store.pool)
            .await
            .unwrap();
    assert_eq!(socket_count, 0);
    let authority: i64 = sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM app_https_connections)+(SELECT count(*) FROM network_grants)",
    )
    .fetch_one(&store.pool)
    .await
    .unwrap();
    assert_eq!(authority, 0);
    let remove_key = uid();
    let removed_https = store
        .remove_endpoint(&editor, tenant, project, https_id, &remove_key)
        .await
        .unwrap();
    assert_eq!(
        store
            .remove_endpoint(&editor, tenant, project, https_id, &remove_key)
            .await
            .unwrap()["id"],
        removed_https["id"]
    );
    assert_eq!(
        store
            .resources(
                &editor,
                tenant,
                project,
                "external-endpoints",
                Some(https_id)
            )
            .await
            .unwrap()["deleted"],
        true
    );
    // A project owner still cannot import credential references from another project.
    assert_eq!(
        store
            .create_endpoint(&operator, tenant, s(&other["id"]), legacy, &uid())
            .await
            .unwrap_err()
            .status
            .as_u16(),
        404
    );
    let mut denied = value;
    denied["name"] = json!("denied");
    denied["host"] = json!("127.0.0.1");
    assert_eq!(
        store
            .create_endpoint(&editor, tenant, project, denied, &uid())
            .await
            .unwrap_err()
            .status
            .as_u16(),
        400
    );
    store.schedule().await.unwrap();
    let usage = store.usage(&editor, tenant, Some(project)).await.unwrap();
    assert_eq!(usage["reserved"]["instances"], 0);
    assert_eq!(usage["storage_bytes"], 0);
    assert_eq!(
        store
            .resources(&editor, tenant, project, "executions", None)
            .await
            .unwrap(),
        json!([])
    );
    store
        .usage_history(&editor, tenant, Some(project), Default::default())
        .await
        .unwrap();
    let removed:i64=sqlx::query_scalar("SELECT count(*) FROM pg_tables WHERE schemaname=current_schema() AND (tablename LIKE 'service_%' OR tablename LIKE 'vm_%' OR tablename IN ('managed_vms','volumes'))").fetch_one(&store.pool).await.unwrap();
    assert_eq!(removed, 0);
    let endpoint = s(&created["resource_id"]);
    assert_eq!(
        store
            .endpoint_submission(&editor, tenant, project, &key)
            .await
            .unwrap()["resource_id"],
        endpoint
    );
    assert_eq!(
        store
            .endpoint_submission(&editor, tenant, s(&other["id"]), &key)
            .await
            .unwrap_err()
            .status
            .as_u16(),
        404
    );
    // A compiler protocol fixture validates admission semantics only. Real
    // component inspection and TLS execution remain a separate live journey.
    let artifact = store
        .upload(&editor, tenant, project, b"\0asm\x0d\0\x01\0")
        .await
        .unwrap();
    let node=store.register_node(&operator,json!({"name":"compiler","cert_sha256":fenders_control_plane::model::digest("compiler"),"endpoint":"https://node.example:9443","backend":"wasm","architecture":"x86_64","runtime":fenders_control_plane::artifacts::RUNTIME,"cpu_percent":100,"memory_mib":512,"instances":2})).await.unwrap();
    store.heartbeat(s(&node["id"]),json!({"boot_id":"test-boot","reports":[],"confinement":fenders_control_plane::model::HOST_CONFINEMENT})).await.unwrap();
    let job = store
        .claim_component(s(&node["id"]), json!({"boot_id":"test-boot"}))
        .await
        .unwrap()["job"]
        .clone();
    let receipt = json!({"format_version":1,"runtime":fenders_control_plane::artifacts::RUNTIME,"digest":job["digest"],"bytes":job["size"],"http":false,"command":true,"imports":[],"exports":[]});
    store
        .component_result(
            s(&node["id"]),
            s(&artifact["id"]),
            job["generation"].as_i64().unwrap(),
            json!({"boot_id":"test-boot","inspection":receipt}),
        )
        .await
        .unwrap();
    let deployed=store.deploy_app(&editor,tenant,project,fenders_control_plane::apps::AppSubmission{value:json!({"name":"pg-client","artifact_id":artifact["id"],"triggers":{"manual":true,"http":false},"endpoints":[{"endpoint_id":endpoint,"prefix":"TARGET_"}]}),key:"deploy-fixture",domain:"apps.test"}).await.unwrap();
    let app = s(&deployed["resource_id"]);
    let connections = store
        .app_connections(&editor, tenant, project, app)
        .await
        .unwrap();
    assert_eq!(connections["items"][0]["endpoint_id"], endpoint);
    let fields = connections["items"][0]["fields"].as_array().unwrap();
    assert!(
        fields
            .iter()
            .any(|f| f["name"] == "TARGET_HOSTADDR" && f["source"]["value"] == "192.0.2.2")
    );
    assert_eq!(fields.len(), 3);
    assert!(
        fields
            .iter()
            .all(|f| f["source"]["kind"] == "configuration")
    );
    assert!(
        fields
            .iter()
            .any(|f| f["name"] == "TARGET_PORT" && f["source"]["value"] == "6379")
    );
    assert_eq!(
        store
            .remove_endpoint(&editor, tenant, project, endpoint, &uid())
            .await
            .unwrap_err()
            .status
            .as_u16(),
        409
    );
    store
        .update_app_connections(
            &editor,
            tenant,
            project,
            app,
            json!({"expected_revision":connections["revision"],"endpoints":[]}),
            "disconnect-fixture",
        )
        .await
        .unwrap();
    assert_eq!(
        store
            .resources(&editor, tenant, project, "executions", None)
            .await
            .unwrap(),
        json!([]),
        "registration, deployment and connection edits never invoke a command"
    );
    let remove_key = uid();
    let removed = store
        .remove_endpoint(&editor, tenant, project, endpoint, &remove_key)
        .await
        .unwrap();
    assert_eq!(
        store
            .remove_endpoint(&editor, tenant, project, endpoint, &remove_key)
            .await
            .unwrap()["id"],
        removed["id"]
    );
    assert_eq!(
        store
            .endpoint_submission(&editor, tenant, project, &remove_key)
            .await
            .unwrap()["state"],
        "succeeded"
    );
    assert_eq!(
        store
            .resources(
                &editor,
                tenant,
                project,
                "external-endpoints",
                Some(endpoint)
            )
            .await
            .unwrap()["deleted"],
        true
    );
    store.pool.close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
}
