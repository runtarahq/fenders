//! The gateway's leases of the transfer allowance, against real PostgreSQL:
//! taken when a project has traffic, written down and brought to size by
//! the flush, and given back.
use super::*;
use fenders_control_plane::lease::{BLOCK, IDLE, LEAST};

/// An app that serves, its host name, and the key of its lease.
async fn serving(l: &Lab) -> (String, (String, String)) {
    let node = l.node("lease-worker").await;
    let route = l.web_app("web", "apps.test").await;
    l.store.schedule().await.unwrap();
    let all = l
        .store
        .resources(&l.operator, &l.tenant, &l.project, "executions", None)
        .await
        .unwrap();
    l.report(&node, &all[0], "running", 1).await;
    (
        s(&route["hostname"]).to_owned(),
        (l.tenant.clone(), l.project.clone()),
    )
}

/// What the database says is leased, used and counted.
async fn written(l: &Lab) -> (i64, i64, i64) {
    sqlx::query_as(
        "SELECT (SELECT COALESCE(sum(held_bytes),0)::bigint FROM gateway_transfer_leases),
            (SELECT COALESCE(sum(bytes),0)::bigint FROM traffic_usage),
            (SELECT COALESCE(sum(requests),0)::bigint FROM traffic_usage)",
    )
    .fetch_one(&l.store.pool)
    .await
    .unwrap()
}

#[tokio::test]
async fn a_lease_is_taken_with_the_first_request_and_given_back_when_idle() {
    let l = Lab::new().await;
    let (host, key) = serving(&l).await;
    assert_eq!(written(&l).await, (0, 0, 0));
    // Ten requests, 100 bytes each: one lease, taken by the first.
    for _ in 0..10 {
        let (_, request) = l.store.ingress_start(&host, 0).await.unwrap();
        l.store.ingress_finish(&request, Some(100)).await.unwrap();
    }
    assert_eq!(written(&l).await, (LEAST, 0, 0));
    assert_eq!(
        l.store.gateway.budgets.holds(&key),
        Some((LEAST - 1000, 0, 1000))
    );
    // The flush records what was used and takes it off the lease, which is
    // still more than half its size: nothing is asked.
    l.store.flush_gateway().await.unwrap();
    assert_eq!(written(&l).await, (LEAST - 1000, 1000, 10));
    assert_eq!(
        l.store.gateway.budgets.holds(&key),
        Some((LEAST - 1000, 0, 0))
    );
    // The usage report has them as used and as reserved.
    let usage = l.store.usage(&l.operator, &l.tenant, None).await.unwrap();
    assert_eq!(usage["transfer_allowance"]["bytes"], 1000);
    assert_eq!(usage["transfer_allowance"]["reserved_bytes"], LEAST - 1000);
    // No request for a while: the lease is given back whole, and the flush
    // after that has forgotten the project.
    l.store.gateway.budgets.rewind(IDLE);
    l.store.flush_gateway().await.unwrap();
    assert_eq!(written(&l).await, (0, 1000, 10));
    l.store.flush_gateway().await.unwrap();
    assert_eq!(l.store.gateway.budgets.holds(&key), None);
    l.finish().await;
}

#[tokio::test]
async fn a_gateway_that_stops_gives_every_lease_back_and_forgets_its_session() {
    let l = Lab::new().await;
    let (host, _) = serving(&l).await;
    let (_, request) = l.store.ingress_start(&host, 0).await.unwrap();
    l.store.ingress_finish(&request, Some(40)).await.unwrap();
    l.store.flush_gateway().await.unwrap();
    let sessions = || async {
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM gateway_sessions")
            .fetch_one(&l.store.pool)
            .await
            .unwrap()
    };
    assert_eq!(sessions().await, 1);
    assert_eq!(written(&l).await, (LEAST - 40, 40, 1));
    l.store.close_gateway().await.unwrap();
    assert_eq!(written(&l).await, (0, 40, 1));
    assert_eq!(sessions().await, 0);
    // Nothing is left for the scheduler to charge as a dead session's.
    l.store.schedule().await.unwrap();
    assert_eq!(written(&l).await, (0, 40, 1));
    l.finish().await;
}

/// A process that did not flush for too long is taken for gone, and its
/// leases are charged. If it is there after all, it finds its lease gone
/// when it next flushes, and takes another: what it had leased was charged
/// once, conservatively, and nothing passes that is not leased again.
#[tokio::test]
async fn a_lease_charged_as_a_dead_sessions_is_taken_again_by_a_session_that_lives() {
    let l = Lab::new().await;
    let (host, key) = serving(&l).await;
    let (_, request) = l.store.ingress_start(&host, 0).await.unwrap();
    l.store.ingress_finish(&request, Some(300)).await.unwrap();
    assert_eq!(written(&l).await, (LEAST, 0, 0));
    sqlx::query("UPDATE gateway_sessions SET seen=seen-interval '1 minute'")
        .execute(&l.store.pool)
        .await
        .unwrap();
    l.store.schedule().await.unwrap();
    // All of the lease is used, as far as anyone knows.
    assert_eq!(written(&l).await, (0, LEAST, 0));
    // The flush writes the 300 it knows were used and finds no lease to
    // take them off: it holds nothing, and the next asks for a new lease.
    l.store.flush_gateway().await.unwrap();
    assert_eq!(l.store.gateway.budgets.holds(&key), Some((0, 0, 0)));
    assert_eq!(written(&l).await, (0, LEAST + 300, 1));
    l.store.flush_gateway().await.unwrap();
    assert_eq!(l.store.gateway.budgets.holds(&key), Some((LEAST, 0, 0)));
    assert_eq!(written(&l).await, (LEAST, LEAST + 300, 1));
    let conservative: i64 =
        sqlx::query_scalar("SELECT sum(conservative_bytes)::bigint FROM traffic_usage")
            .fetch_one(&l.store.pool)
            .await
            .unwrap();
    assert_eq!(conservative, LEAST);
    l.finish().await;
}

#[tokio::test]
async fn a_request_whose_reservation_lapsed_is_charged_what_it_reserved_and_counted_once() {
    let l = Lab::new().await;
    let (host, key) = serving(&l).await;
    let (_, request) = l.store.ingress_start(&host, 0).await.unwrap();
    assert_eq!(
        l.store.gateway.budgets.holds(&key),
        Some((LEAST - BLOCK, BLOCK, 0))
    );
    sqlx::query("UPDATE ingress_reservations SET expires=now()-interval '1 second'")
        .execute(&l.store.pool)
        .await
        .unwrap();
    l.store.schedule().await.unwrap();
    // What it passed is not known: all it had reserved.
    assert_eq!(
        l.store.gateway.budgets.holds(&key),
        Some((LEAST - BLOCK, 0, BLOCK))
    );
    // A completion that comes late changes nothing.
    l.store.ingress_finish(&request, Some(5)).await.unwrap();
    l.store.flush_gateway().await.unwrap();
    assert_eq!(written(&l).await, (LEAST - BLOCK, BLOCK, 1));
    l.finish().await;
}

#[tokio::test]
async fn a_suspended_workspace_is_leased_nothing() {
    let l = Lab::new().await;
    let (_, key) = serving(&l).await;
    sqlx::query("UPDATE tenants SET lifecycle_state='suspended' WHERE id=$1")
        .bind(&l.tenant)
        .execute(&l.store.pool)
        .await
        .unwrap();
    assert!(!l.store.lease_extend(&key, 1, LEAST).await);
    assert_eq!(written(&l).await, (0, 0, 0));
    sqlx::query("UPDATE tenants SET lifecycle_state='active' WHERE id=$1")
        .bind(&l.tenant)
        .execute(&l.store.pool)
        .await
        .unwrap();
    // Refused once, it is not asked again until a flush has looked.
    assert!(!l.store.lease_extend(&key, 1, LEAST).await);
    l.store.flush_gateway().await.unwrap();
    assert!(l.store.lease_extend(&key, 1, LEAST).await);
    l.finish().await;
}

/// Two projects of a workspace have a lease each, of the one allowance.
#[tokio::test]
async fn the_leases_of_a_workspaces_projects_are_of_one_allowance() {
    let l = Lab::new().await;
    let (_, first) = serving(&l).await;
    let second = l
        .store
        .create_project(
            &l.operator,
            &l.tenant,
            serde_json::from_value(json!({"name":"second"})).unwrap(),
        )
        .await
        .unwrap();
    let second = (l.tenant.clone(), s(&second["id"]).to_owned());
    sqlx::query("UPDATE tenants SET transfer_bytes=$2 WHERE id=$1")
        .bind(&l.tenant)
        .bind(LEAST + 1000)
        .execute(&l.store.pool)
        .await
        .unwrap();
    assert!(l.store.lease_extend(&first, BLOCK, LEAST).await);
    // A thousand bytes are left: the second project's lease is those.
    assert!(!l.store.lease_extend(&second, BLOCK, LEAST).await);
    assert_eq!(l.store.gateway.budgets.holds(&second), Some((1000, 0, 0)));
    assert_eq!(written(&l).await.0, LEAST + 1000);
    l.finish().await;
}
