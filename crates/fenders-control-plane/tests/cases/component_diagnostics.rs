use super::*;
#[tokio::test]
async fn rejection_categories_are_durable_scoped_and_generation_fenced() {
    let l = Lab::new().await;
    let node = l.node("compiler").await;
    for (i, code) in [
        "invalid-component",
        "unsupported-imports",
        "incompatible-entry-points",
        "interface-limits",
        "component-not-accepted",
    ]
    .iter()
    .enumerate()
    {
        if i > 0 {
            let mut bytes = b"\0asm\x0d\0\x01\0".to_vec();
            bytes.push(i as u8);
            l.store
                .upload(&l.operator, &l.tenant, &l.project, &bytes)
                .await
                .unwrap();
        }
        let job = l
            .store
            .claim_component(s(&node["id"]), json!({"boot_id":"test-boot"}))
            .await
            .unwrap()["job"]
            .clone();
        let id = s(&job["artifact_id"]);
        let generation = n(&job["generation"]);
        assert!(l.store.component_result(s(&node["id"]),id,generation,json!({"boot_id":"test-boot","error":"<script>private compiler stderr</script>"})).await.is_err());
        let result = json!({"boot_id":"test-boot","error":code});
        assert!(
            l.store
                .component_result(s(&node["id"]), id, generation + 1, result.clone())
                .await
                .is_err()
        );
        l.store
            .component_result(s(&node["id"]), id, generation, result.clone())
            .await
            .unwrap();
        l.store
            .component_result(s(&node["id"]), id, generation, result)
            .await
            .unwrap();
        assert!(
            l.store
                .component_result(
                    s(&node["id"]),
                    id,
                    generation,
                    json!({"boot_id":"test-boot","error":"compiler-unavailable"})
                )
                .await
                .is_err()
        );
        l.store.migrate().await.unwrap();
        let (viewer, _) = l.credential("viewer", Some(&l.project)).await;
        let inspected = l
            .store
            .artifact_inspection(&viewer, &l.tenant, &l.project, id)
            .await
            .unwrap();
        assert_eq!(inspected["state"], "rejected");
        assert_eq!(inspected["error"], *code);
        assert!(inspected["inspection"].is_null());
        let other = l
            .store
            .create_project(
                &l.operator,
                &l.tenant,
                serde_json::from_value(json!({"name":format!("other-{i}")})).unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            l.store
                .artifact_inspection(&l.operator, &l.tenant, s(&other["id"]), id)
                .await
                .unwrap_err()
                .status,
            StatusCode::NOT_FOUND
        );
        assert!(
            l.store
                .create_app(
                    &l.operator,
                    &l.tenant,
                    &l.project,
                    json!({"name":format!("bad-{i}"),"artifact_id":id}),
                    &format!("bad-{i}")
                )
                .await
                .is_err()
        );
    }
    l.finish().await;
}
