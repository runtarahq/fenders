use super::*;
use fenders_control_plane::{app_runtime::HistoryPage, apps::AppSubmission};
const RETIRE: &str = include_str!("../../src/release_input_retention.sql");

#[tokio::test]
async fn release_input_retention_bounds_each_pass_and_restarts_without_changing_outcomes() {
    let (l, _, id) = setup().await;
    sqlx::query("INSERT INTO app_releases(id,tenant_id,project_id,app_id,version_id,configuration,spec,state,created,updated) SELECT md5($1||n::text),r.tenant_id,r.project_id,r.app_id,r.version_id,r.configuration,r.spec,'ready',r.created,r.updated FROM app_releases r CROSS JOIN generate_series(1,599) n WHERE r.id=$1").bind(&id).execute(&l.store.pool).await.unwrap();
    age(&l, "*").await;
    l.store.schedule().await.unwrap();
    let count = || {
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM app_releases WHERE inputs_retired_at IS NOT NULL",
        )
        .fetch_one(&l.store.pool)
    };
    assert_eq!(count().await.unwrap(), 256);
    let reopened = Store::from_pool(l.store.pool.clone(), l.root.path()).unwrap();
    let (a, b) = tokio::join!(l.store.schedule(), reopened.schedule());
    a.unwrap();
    b.unwrap();
    assert_eq!(count().await.unwrap(), 600);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM app_releases WHERE state='ready'")
            .fetch_one(&l.store.pool)
            .await
            .unwrap(),
        601
    );
    l.finish().await;
}

#[tokio::test]
async fn release_input_retention_clock_restarts_after_selection_and_bootstrap_retains_detail() {
    let (l, app, id) = setup().await;
    age(&l, &id).await;
    let active: String = sqlx::query_scalar("SELECT active_release_id FROM apps WHERE id=$1")
        .bind(&app)
        .fetch_one(&l.store.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE apps SET active_release_id=$1 WHERE id=$2")
        .bind(&id)
        .bind(&app)
        .execute(&l.store.pool)
        .await
        .unwrap();
    assert!(row(&l, &id).await["unreferenced_since"].is_null());
    retire(&l).await;
    assert!(row(&l, &id).await["inputs_retired_at"].is_null());
    sqlx::query("UPDATE apps SET active_release_id=$1 WHERE id=$2")
        .bind(&active)
        .bind(&app)
        .execute(&l.store.pool)
        .await
        .unwrap();
    assert!(row(&l, &id).await["unreferenced_since"].is_string());
    retire(&l).await;
    assert!(
        row(&l, &id).await["inputs_retired_at"].is_null(),
        "recent deselection restarts the hold even for an old release"
    );
    l.store.migrate().await.unwrap();
    retire(&l).await;
    let original = row(&l, &id).await;
    assert_eq!(original["configuration"]["env"]["INPUT"], "original-input");
    assert!(
        original["inputs_retired_at"].is_null(),
        "bootstrap preserves the recent deselection hold"
    );
    assert!(row(&l, &active).await["unreferenced_since"].is_null());
    l.store.migrate().await.unwrap();
    assert_eq!(row(&l, &id).await, original);
    l.finish().await;
}

async fn setup() -> (Lab, String, String) {
    let l = Lab::new().await;
    let node = l.node("compiler").await;
    approve_component(&l, &node, false, true).await;
    let op=l.store.deploy_app(&l.operator,&l.tenant,&l.project,AppSubmission {
        value:json!({"name":"input-history","artifact_id":l.artifact,"triggers":{"http":false,"manual":true},"configuration":{"env":{"INPUT":"original-input"}}}),key:"initial-release",domain:"apps.test"
    }).await.unwrap();
    let app = s(&op["resource_id"]).to_owned();
    let old = l
        .store
        .app(&l.operator, &l.tenant, &l.project, &app)
        .await
        .unwrap();
    let old_id = s(&old["active_release"]["id"]).to_owned();
    l.store.activate_app_release(&l.operator,&l.tenant,&l.project,&app,json!({"version_id":old["latest_code"]["id"],"expected_revision":old["revision"],"configuration":{"env":{"INPUT":"current-input"}}}),"replace-release").await.unwrap();
    (l, app, old_id)
}
async fn row(l: &Lab, id: &str) -> Value {
    sqlx::query_scalar("SELECT to_jsonb(r) FROM app_releases r WHERE id=$1")
        .bind(id)
        .fetch_one(&l.store.pool)
        .await
        .unwrap()
}
pub(super) async fn age(l: &Lab, id: &str) {
    // Time travel belongs only to fixture construction. Restore the production
    // guard before exercising retirement, concurrency, references or SQL abuse.
    let mut tx = l.store.pool.begin().await.unwrap();
    sqlx::raw_sql("ALTER TABLE app_releases DISABLE TRIGGER app_release_immutable")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("UPDATE app_releases SET created=now()-interval '40 days',updated=now()-interval '40 days',unreferenced_since=CASE WHEN unreferenced_since IS NULL THEN NULL ELSE now()-interval '40 days' END WHERE id=$1 OR $1='*'").bind(id).execute(&mut *tx).await.unwrap();
    sqlx::raw_sql("ALTER TABLE app_releases ENABLE TRIGGER app_release_immutable")
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
}
async fn retire(l: &Lab) {
    sqlx::raw_sql(RETIRE).execute(&l.store.pool).await.unwrap();
}

#[tokio::test]
async fn release_input_retention_preserves_history_scope_retries_and_current_config_rollback() {
    let (l, app, id) = setup().await;
    let before = row(&l, &id).await;
    assert!(before["unreferenced_since"].is_string());
    retire(&l).await;
    assert_eq!(row(&l, &id).await, before);
    age(&l, &id).await;
    let before = row(&l, &id).await;
    let original:String=sqlx::query_scalar("SELECT jsonb_build_object('configuration',configuration,'spec',spec)::text FROM app_releases WHERE id=$1").bind(&id).fetch_one(&l.store.pool).await.unwrap();
    let usage = l.store.usage(&l.operator, &l.tenant, None).await.unwrap();
    l.store.schedule().await.unwrap();
    let after = row(&l, &id).await;
    assert!(after["inputs_retired_at"].is_string());
    assert_eq!(after["original_inputs_sha256"], digest(original));
    let mut expected = before;
    expected["configuration"]
        .as_object_mut()
        .unwrap()
        .remove("env");
    expected["spec"].as_object_mut().unwrap().remove("env");
    expected["spec"]
        .as_object_mut()
        .unwrap()
        .remove("endpoint_env");
    expected["inputs_retired_at"] = after["inputs_retired_at"].clone();
    expected["original_inputs_sha256"] = after["original_inputs_sha256"].clone();
    assert_eq!(after, expected);
    assert_eq!(
        l.store.usage(&l.operator, &l.tenant, None).await.unwrap()["totals"],
        usage["totals"]
    );
    let history = l
        .store
        .app_history(
            &l.operator,
            &l.tenant,
            &l.project,
            &app,
            "releases",
            HistoryPage {
                trigger: None,
                limit: Some(100),
                before: None,
            },
        )
        .await
        .unwrap();
    let item = history["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == id)
        .unwrap();
    assert_eq!(item["inputs_retired_at"], after["inputs_retired_at"]);
    let detail = l
        .store
        .app_release(&l.operator, &l.tenant, &l.project, &app, &id)
        .await
        .unwrap();
    assert_eq!(&detail, item);
    assert!(!detail.to_string().contains("original-input"));
    assert!(
        l.store
            .app_release(&l.operator, &l.tenant, &uid(), &app, &id)
            .await
            .is_err()
    );
    let current = l
        .store
        .app(&l.operator, &l.tenant, &l.project, &app)
        .await
        .unwrap();
    assert_eq!(current["configuration"]["env"]["INPUT"], "current-input");
    // Rollback selects code and constructs a fresh release with today's inputs.
    let body = json!({"version_id":after["version_id"],"expected_revision":current["revision"]});
    let op = l
        .store
        .activate_app_release(
            &l.operator,
            &l.tenant,
            &l.project,
            &app,
            body.clone(),
            "rollback-after-retirement",
        )
        .await
        .unwrap();
    assert_ne!(op["resource_id"], id);
    let fresh = row(&l, s(&op["resource_id"])).await;
    assert_eq!(fresh["configuration"]["env"]["INPUT"], "current-input");
    assert!(fresh["inputs_retired_at"].is_null());
    assert!(fresh["unreferenced_since"].is_null());
    let reopened = Store::from_pool(l.store.pool.clone(), l.root.path()).unwrap();
    assert_eq!(
        reopened
            .activate_app_release(
                &l.operator,
                &l.tenant,
                &l.project,
                &app,
                body,
                "rollback-after-retirement"
            )
            .await
            .unwrap(),
        op
    );
    let original = l
        .deploy("input-history", false, true, "initial-release")
        .await;
    assert!(
        original.is_err(),
        "changed original body must still conflict"
    );
    retire(&l).await;
    assert_eq!(row(&l, &id).await, after);
    l.finish().await;
}

#[tokio::test]
async fn release_input_retention_fences_current_pending_recent_and_uncertain_work() {
    let (l, app, id) = setup().await;
    age(&l, &id).await;
    let current = l
        .store
        .app(&l.operator, &l.tenant, &l.project, &app)
        .await
        .unwrap();
    let active = s(&current["active_release"]["id"]);
    age(&l, active).await;
    let pending = uid();
    sqlx::query("INSERT INTO app_runs(id,tenant_id,project_id,app_id,release_id,source,admission,created,admission_updated) VALUES($1,$2,$3,$4,$5,'manual','pending',now()-interval '40 days',now()-interval '40 days')").bind(&pending).bind(&l.tenant).bind(&l.project).bind(&app).bind(&id).execute(&l.store.pool).await.unwrap();
    retire(&l).await;
    assert!(
        row(&l, &id).await["inputs_retired_at"].is_null(),
        "undispatched work retains its release inputs"
    );
    sqlx::query("UPDATE app_runs SET admission='cancelled' WHERE id=$1")
        .bind(&pending)
        .execute(&l.store.pool)
        .await
        .unwrap();
    let pending_op = uid();
    sqlx::query("INSERT INTO operations(id,tenant_id,project_id,request_key,request_hash,resource_id,kind,state,created,updated) VALUES($1,$2,$3,$1,$1,$4,'run-app','pending',now()-interval '40 days',now()-interval '40 days')").bind(&pending_op).bind(&l.tenant).bind(&l.project).bind(&pending).execute(&l.store.pool).await.unwrap();
    retire(&l).await;
    assert!(
        row(&l, &id).await["inputs_retired_at"].is_null(),
        "pending receipt with no execution still retains inputs"
    );
    sqlx::query("UPDATE operations SET state='succeeded' WHERE id=$1")
        .bind(&pending_op)
        .execute(&l.store.pool)
        .await
        .unwrap();
    let execution = uid();
    sqlx::query("INSERT INTO executions(id,tenant_id,project_id,spec,cpu_percent,memory_mib,reserved,state,desired,created,updated,finished_at) VALUES($1,$2,$3,'{}',1,64,false,'failed','stopped',now()-interval '40 days',now()-interval '40 days',now()-interval '40 days')").bind(&execution).bind(&l.tenant).bind(&l.project).execute(&l.store.pool).await.unwrap();
    sqlx::query("INSERT INTO app_http_attempts(execution_id,tenant_id,project_id,app_id,release_id,generation) VALUES($1,$2,$3,$4,$5,1)").bind(&execution).bind(&l.tenant).bind(&l.project).bind(&app).bind(&id).execute(&l.store.pool).await.unwrap();
    retire(&l).await;
    assert!(
        row(&l, &id).await["inputs_retired_at"].is_null(),
        "unknown outcome must retain inputs"
    );
    sqlx::query("UPDATE executions SET observation='{\"exit_code\":0}',reserved=true WHERE id=$1")
        .bind(&execution)
        .execute(&l.store.pool)
        .await
        .unwrap();
    retire(&l).await;
    assert!(
        row(&l, &id).await["inputs_retired_at"].is_null(),
        "held capacity must retain inputs"
    );
    sqlx::query("UPDATE executions SET reserved=false,updated=now() WHERE id=$1")
        .bind(&execution)
        .execute(&l.store.pool)
        .await
        .unwrap();
    retire(&l).await;
    assert!(
        row(&l, &id).await["inputs_retired_at"].is_null(),
        "recent settlement must retain inputs"
    );
    sqlx::query("UPDATE executions SET updated=now()-interval '40 days' WHERE id=$1")
        .bind(&execution)
        .execute(&l.store.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO ingress_reservations(id,tenant_id,project_id,period,bytes,app_id,release_id,app_revision) VALUES($1,$2,$3,date_trunc('month',now()),1,$4,$5,1)").bind(uid()).bind(&l.tenant).bind(&l.project).bind(&app).bind(&id).execute(&l.store.pool).await.unwrap();
    retire(&l).await;
    assert!(
        row(&l, &id).await["inputs_retired_at"].is_null(),
        "even unassigned HTTP admission retains inputs"
    );
    sqlx::query("DELETE FROM ingress_reservations WHERE release_id=$1")
        .bind(&id)
        .execute(&l.store.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE app_releases SET state='preparing' WHERE id=$1")
        .bind(&id)
        .execute(&l.store.pool)
        .await
        .unwrap();
    retire(&l).await;
    assert!(row(&l, &id).await["inputs_retired_at"].is_null());
    sqlx::query("UPDATE app_releases SET state='failed' WHERE id=$1")
        .bind(&id)
        .execute(&l.store.pool)
        .await
        .unwrap();
    retire(&l).await;
    assert!(row(&l, &id).await["inputs_retired_at"].is_string());
    assert!(
        row(&l, active).await["inputs_retired_at"].is_null(),
        "active release never expires"
    );
    l.finish().await;
}

#[tokio::test]
async fn release_input_retention_has_independent_sql_recovery_immutability_and_revival_guards() {
    let (l, app, id) = setup().await;
    age(&l, &id).await;
    let before = row(&l, &id).await;
    assert!(
        sqlx::query(
            "UPDATE app_releases SET unreferenced_since=now()-interval '90 days' WHERE id=$1"
        )
        .bind(&id)
        .execute(&l.store.pool)
        .await
        .is_err()
    );
    assert!(
        sqlx::query("UPDATE app_releases SET configuration=configuration-'env' WHERE id=$1")
            .bind(&id)
            .execute(&l.store.pool)
            .await
            .is_err()
    );
    sqlx::query("UPDATE recovery_barrier SET active=true")
        .execute(&l.store.pool)
        .await
        .unwrap();
    assert!(sqlx::raw_sql(RETIRE).execute(&l.store.pool).await.is_err());
    assert_eq!(row(&l, &id).await, before);
    sqlx::query("UPDATE recovery_barrier SET active=false")
        .execute(&l.store.pool)
        .await
        .unwrap();
    let mut tx = l.store.pool.begin().await.unwrap();
    sqlx::raw_sql(RETIRE).execute(&mut *tx).await.unwrap();
    tx.rollback().await.unwrap();
    assert_eq!(row(&l, &id).await, before);
    retire(&l).await;
    for query in [
        "UPDATE app_releases SET inputs_retired_at=NULL,original_inputs_sha256=NULL WHERE id=$1",
        "UPDATE app_releases SET state='preparing' WHERE id=$1",
        "DELETE FROM app_releases WHERE id=$1",
    ] {
        assert!(
            sqlx::query(query)
                .bind(&id)
                .execute(&l.store.pool)
                .await
                .is_err()
        );
    }
    assert!(
        sqlx::query("UPDATE apps SET active_release_id=$1 WHERE id=$2")
            .bind(&id)
            .bind(&app)
            .execute(&l.store.pool)
            .await
            .is_err()
    );
    assert!(
        sqlx::query("UPDATE apps SET target_release_id=$1 WHERE id=$2")
            .bind(&id)
            .bind(&app)
            .execute(&l.store.pool)
            .await
            .is_err()
    );
    assert!(sqlx::query("INSERT INTO app_runs(id,tenant_id,project_id,app_id,release_id,source) VALUES($1,$2,$3,$4,$5,'manual')").bind(uid()).bind(&l.tenant).bind(&l.project).bind(&app).bind(&id).execute(&l.store.pool).await.is_err());
    assert!(sqlx::query("INSERT INTO ingress_reservations(id,tenant_id,project_id,period,bytes,app_id,release_id,app_revision) VALUES($1,$2,$3,date_trunc('month',now()),1,$4,$5,1)").bind(uid()).bind(&l.tenant).bind(&l.project).bind(&app).bind(&id).execute(&l.store.pool).await.is_err());
    l.finish().await;
}
