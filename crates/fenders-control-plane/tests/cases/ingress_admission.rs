use super::*;

#[tokio::test]
async fn a_workspaces_request_limits_are_its_plans_and_admission_is_audited_once_a_minute() {
    let l = Lab::new().await;
    let node = l.node("rate-worker").await;
    let op = l
        .store
        .create_workload(
            &l.operator,
            &l.tenant,
            &l.project,
            json!({"name":"web","spec":{"artifact_id":l.artifact}}),
            "web",
            true,
        )
        .await
        .unwrap();
    let route = l
        .store
        .create_route(
            &l.operator,
            &l.tenant,
            &l.project,
            json!({"name":"web","deployment_id":op["resource_id"]}),
            "apps.test",
        )
        .await
        .unwrap();
    l.store.schedule().await.unwrap();
    let all = l
        .store
        .resources(&l.operator, &l.tenant, &l.project, "executions", None)
        .await
        .unwrap();
    l.report(&node, &all[0], "running", 1).await;
    let hostname = s(&route["hostname"]);
    let audited = || async {
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM audit WHERE action='ingress.admit'")
            .fetch_one(&l.store.pool)
            .await
            .unwrap()
    };
    let limits = |concurrent: i64, rate: i64| {
        l.store.update_http_limits(
            &l.operator,
            &l.tenant,
            json!({"concurrent_requests":concurrent,"requests_per_minute":rate}),
        )
    };
    // Until an operator says otherwise: 16 at once, 600 a minute.
    let usage = l.store.usage(&l.operator, &l.tenant, None).await.unwrap();
    assert_eq!(
        usage["http_limits"],
        json!({"concurrent_requests":16,"requests_per_minute":600})
    );
    for bad in [
        json!({"concurrent_requests":0,"requests_per_minute":10}),
        json!({"concurrent_requests":10,"requests_per_minute":0}),
        json!({"concurrent_requests":10}),
    ] {
        assert!(
            l.store
                .update_http_limits(&l.operator, &l.tenant, bad)
                .await
                .is_err()
        );
    }

    // Three a minute: the last slot goes to one of two that ask together,
    // and finishing a request does not give its slot back.
    limits(16, 3).await.unwrap();
    let first = l.store.ingress_start(hostname, 0).await.unwrap().1;
    let second = l.store.ingress_start(hostname, 0).await.unwrap().1;
    let (a, b) = tokio::join!(
        l.store.ingress_start(hostname, 0),
        l.store.ingress_start(hostname, 0)
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    let (accepted, refused) = if a.is_ok() { (a, b) } else { (b, a) };
    assert_eq!(refused.unwrap_err().status, StatusCode::TOO_MANY_REQUESTS);
    for lease in [first, second, accepted.unwrap().1] {
        l.store.ingress_finish(&lease, Some(0)).await.unwrap();
    }
    assert!(
        l.store.ingress_start(hostname, 0).await.is_err(),
        "finishing does not reset the rate window"
    );
    // Admission was audited once for the minute, not once a request; each
    // request has its own usage.
    assert_eq!(audited().await, 1);
    assert_eq!(
        l.store.usage(&l.operator, &l.tenant, None).await.unwrap()["ingress_month"]["requests"],
        3
    );
    // A minute on, the window has passed: admitted again, and audited again.
    l.store.http_rates.advance(61);
    let lease = l.store.ingress_start(hostname, 0).await.unwrap().1;
    assert_eq!(audited().await, 2);

    // Two at once: a third is refused while two are in flight, whatever the
    // rate allows, and admitted when one has ended.
    limits(2, 1000).await.unwrap();
    let held = l.store.ingress_start(hostname, 0).await.unwrap().1;
    assert_eq!(
        l.store.ingress_start(hostname, 0).await.unwrap_err().status,
        StatusCode::TOO_MANY_REQUESTS
    );
    l.store.ingress_finish(&lease, Some(0)).await.unwrap();
    let after = l.store.ingress_start(hostname, 0).await.unwrap().1;
    for lease in [held, after] {
        l.store.ingress_finish(&lease, Some(0)).await.unwrap();
    }
    l.finish().await;
}

/// A request for a host name that is nobody's, or of a workspace that has
/// had its requests for the minute, is refused without the lock every
/// mutation takes: a flood of them queues nothing behind it.
#[tokio::test]
async fn requests_that_cannot_be_admitted_are_refused_without_the_mutation_lock() {
    let l = Lab::new().await;
    let node = l.node("gate-worker").await;
    let op = l
        .store
        .create_workload(
            &l.operator,
            &l.tenant,
            &l.project,
            json!({"name":"web","spec":{"artifact_id":l.artifact}}),
            "web",
            true,
        )
        .await
        .unwrap();
    let route = l
        .store
        .create_route(
            &l.operator,
            &l.tenant,
            &l.project,
            json!({"name":"web","deployment_id":op["resource_id"]}),
            "apps.test",
        )
        .await
        .unwrap();
    l.store.schedule().await.unwrap();
    let all = l
        .store
        .resources(&l.operator, &l.tenant, &l.project, "executions", None)
        .await
        .unwrap();
    l.report(&node, &all[0], "running", 1).await;
    let hostname = s(&route["hostname"]).to_owned();
    sqlx::query("UPDATE tenants SET http_requests_per_minute=2 WHERE id=$1")
        .bind(&l.tenant)
        .execute(&l.store.pool)
        .await
        .unwrap();
    // Two are admitted; the workspace has then had its minute's requests.
    for _ in 0..2 {
        let (_, lease) = l.store.ingress_start(&hostname, 0).await.unwrap();
        l.store.ingress_finish(&lease, Some(0)).await.unwrap();
    }

    // Someone else holds the lock all mutations take, for as long as this
    // test goes on: an admission that needed it would wait five seconds and
    // fail with a conflict.
    let mut holder = l.store.pool.acquire().await.unwrap();
    sqlx::query("SELECT pg_advisory_lock(184923781)")
        .execute(&mut *holder)
        .await
        .unwrap();
    let started = std::time::Instant::now();
    for _ in 0..50 {
        assert_eq!(
            l.store
                .ingress_start("nobody.apps.test", 0)
                .await
                .unwrap_err()
                .status,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            l.store
                .ingress_start(&hostname, 0)
                .await
                .unwrap_err()
                .status,
            StatusCode::TOO_MANY_REQUESTS
        );
    }
    assert!(
        started.elapsed() < std::time::Duration::from_secs(3),
        "refusals waited for the mutation lock: {:?}",
        started.elapsed()
    );
    sqlx::query("SELECT pg_advisory_unlock(184923781)")
        .execute(&mut *holder)
        .await
        .unwrap();
    drop(holder);
    l.finish().await;
}
