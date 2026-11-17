use super::*;
use fenders_control_plane::demos::DEMOS;
#[tokio::test]
async fn demo_catalog_selection_is_scoped_digest_pinned_and_uses_upload_admission() {
    let l = Lab::new().await;
    let catalog = l
        .store
        .demo_components(&l.operator, &l.tenant, &l.project)
        .await
        .unwrap();
    assert_eq!(catalog["items"].as_array().unwrap().len(), 2);
    let demo = &DEMOS[0];
    let request = json!({"digest":digest(demo.bytes)});
    let (viewer, _) = l.credential("viewer", Some(&l.project)).await;
    assert!(
        l.store
            .demo_components(&viewer, &l.tenant, &l.project)
            .await
            .is_ok()
    );
    assert_eq!(
        l.store
            .select_demo(&viewer, &l.tenant, &l.project, demo.id, request.clone())
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
    assert!(
        l.store
            .demo_components(&viewer, &l.tenant, s(&other["id"]))
            .await
            .is_err()
    );
    assert_eq!(
        l.store
            .select_demo(
                &l.operator,
                &l.tenant,
                &l.project,
                "unknown",
                request.clone()
            )
            .await
            .unwrap_err()
            .status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        l.store
            .select_demo(
                &l.operator,
                &l.tenant,
                &l.project,
                demo.id,
                json!({"digest":"0".repeat(64)})
            )
            .await
            .unwrap_err()
            .status,
        StatusCode::CONFLICT
    );
    assert!(
        l.store
            .select_demo(
                &l.operator,
                &l.tenant,
                &l.project,
                demo.id,
                json!({"digest":digest(demo.bytes),"inspection":{"http":true}})
            )
            .await
            .is_err()
    );
    sqlx::query("UPDATE tenants SET storage_bytes=8 WHERE id=$1")
        .bind(&l.tenant)
        .execute(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(
        l.store
            .select_demo(&l.operator, &l.tenant, &l.project, demo.id, request.clone())
            .await
            .unwrap_err()
            .status,
        StatusCode::TOO_MANY_REQUESTS
    );
    sqlx::query("UPDATE tenants SET storage_bytes=1000000 WHERE id=$1")
        .bind(&l.tenant)
        .execute(&l.store.pool)
        .await
        .unwrap();
    let (a, b) = tokio::join!(
        l.store
            .select_demo(&l.operator, &l.tenant, &l.project, demo.id, request.clone()),
        l.store
            .select_demo(&l.operator, &l.tenant, &l.project, demo.id, request.clone())
    );
    let artifact = a.unwrap();
    assert_eq!(artifact["id"], b.unwrap()["id"]);
    assert_eq!(
        l.store
            .artifact_inspection(&l.operator, &l.tenant, &l.project, s(&artifact["id"]))
            .await
            .unwrap()["state"],
        "pending"
    );
    let direct = l
        .store
        .upload(&l.operator, &l.tenant, &l.project, demo.bytes)
        .await
        .unwrap();
    assert_eq!(direct["id"], artifact["id"]);
    assert_eq!(
        l.store.usage(&l.operator, &l.tenant, None).await.unwrap()["artifact_bytes"],
        demo.bytes.len() + 8
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM executions")
            .fetch_one(&l.store.pool)
            .await
            .unwrap(),
        0
    );
    sqlx::query("UPDATE recovery_barrier SET active=true")
        .execute(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(
        l.store
            .select_demo(&l.operator, &l.tenant, &l.project, demo.id, request)
            .await
            .unwrap_err()
            .status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    l.finish().await;
}
#[tokio::test]
async fn selected_command_demo_passes_real_inspection_and_deploys_without_invocation() {
    let l = Lab::new().await;
    let node = l.node("compiler").await;
    let first = l
        .store
        .claim_component(s(&node["id"]), json!({"boot_id":"test-boot"}))
        .await
        .unwrap()["job"]
        .clone();
    l.store
        .component_result(
            s(&node["id"]),
            s(&first["artifact_id"]),
            n(&first["generation"]),
            json!({"boot_id":"test-boot","error":"component-not-accepted"}),
        )
        .await
        .unwrap();
    let demo = &DEMOS[1];
    let route = format!(
        "/v1/tenants/{}/projects/{}/demo-components/{}/artifacts",
        l.tenant, l.project, demo.id
    );
    let response = api::router(l.store.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(route)
                .header("Authorization", format!("Bearer {}", l.token))
                .header("Content-Type", "application/json")
                .body(Body::from(json!({"digest":digest(demo.bytes)}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let artifact: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap();
    let job = l
        .store
        .claim_component(s(&node["id"]), json!({"boot_id":"test-boot"}))
        .await
        .unwrap()["job"]
        .clone();
    assert_eq!(job["artifact_id"], artifact["id"]);
    let bytes = l
        .store
        .component_content(
            s(&node["id"]),
            s(&artifact["id"]),
            n(&job["generation"]),
            json!({"boot_id":"test-boot"}),
        )
        .await
        .unwrap();
    assert_eq!(bytes, demo.bytes);
    let inspection = fenders_component::inspect(&bytes).unwrap();
    assert!(inspection.command && !inspection.http);
    l.store
        .component_result(
            s(&node["id"]),
            s(&artifact["id"]),
            n(&job["generation"]),
            json!({"boot_id":"test-boot","inspection":inspection}),
        )
        .await
        .unwrap();
    let result=l.store.deploy_app(&l.operator,&l.tenant,&l.project,fenders_control_plane::apps::AppSubmission{value:json!({"name":"hello","artifact_id":artifact["id"],"triggers":{"manual":true,"http":false}}),key:"demo",domain:"apps.test"}).await.unwrap();
    assert_eq!(result["state"], "succeeded");
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM executions")
            .fetch_one(&l.store.pool)
            .await
            .unwrap(),
        0
    );
    l.finish().await;
}
