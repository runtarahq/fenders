//! Real database schedule/dispatch races. No browser clock or guest fixture drives ticks.
use super::*;
#[path = "dispatch_retention.rs"]
mod dispatch_retention;
use fenders_control_plane::{
    app_runtime::{HistoryPage, RunEvent, RunSource},
    apps::AppSubmission,
    error::Result,
};
impl Lab {
    async fn scheduled_app(&self, name: &str, manual: bool) -> Result<String> {
        let op=self.store.deploy_app(&self.operator,&self.tenant,&self.project,AppSubmission{value:json!({"name":name,"artifact_id":self.artifact,"triggers":{"manual":manual,"http":false,"schedule":{"enabled":true,"expression":"* * * * *","timezone":"UTC"}}}),key:name,domain:"apps.test"}).await?;
        Ok(s(&op["resource_id"]).to_owned())
    }
    async fn due(&self, app: &str) {
        sqlx::query("UPDATE app_schedules SET next_at=date_trunc('minute',now()) WHERE app_id=$1")
            .bind(app)
            .execute(&self.store.pool)
            .await
            .unwrap();
    }
    async fn runs(&self, app: &str) -> Value {
        self.store
            .app_history(
                &self.operator,
                &self.tenant,
                &self.project,
                app,
                "runs",
                HistoryPage {
                    limit: Some(100),
                    ..Default::default()
                },
            )
            .await
            .unwrap()
    }
    async fn schedule_edit(&self, app: &str, schedule: Value, key: &str) -> Result<Value> {
        let rev = self
            .store
            .app_triggers(&self.operator, &self.tenant, &self.project, app)
            .await?["revision"]
            .clone();
        self.store
            .update_app_triggers(
                &self.operator,
                &self.tenant,
                &self.project,
                app,
                json!({"expected_revision":rev,"schedule":schedule}),
                key,
            )
            .await
    }
    async fn scheduled_lifecycle(&self, app: &str, desired: &str, key: &str) -> Result<Value> {
        let revision = self
            .store
            .app(&self.operator, &self.tenant, &self.project, app)
            .await?["revision"]
            .clone();
        self.store
            .app_lifecycle(
                &self.operator,
                &self.tenant,
                &self.project,
                app,
                json!({"expected_revision":revision,"desired":desired}),
                key,
            )
            .await
    }
}

#[tokio::test]
async fn schedules_persist_configuration_preview_scope_and_atomic_revision_edits() {
    let l = Lab::new().await;
    let node = l.node("worker").await;
    approve_component(&l, &node, false, true).await;
    let app = l.scheduled_app("scheduled", false).await.unwrap();
    let triggers = l
        .store
        .app_triggers(&l.operator, &l.tenant, &l.project, &app)
        .await
        .unwrap();
    assert_eq!(triggers["schedule"]["expression"], "* * * * *");
    assert_eq!(
        triggers["schedule"]["occurrences"]
            .as_array()
            .unwrap()
            .len(),
        5
    );
    assert!(triggers["schedule"]["next_at"].is_string());
    assert!(l.runs(&app).await["items"].as_array().unwrap().is_empty());
    let summary = l
        .store
        .app(&l.operator, &l.tenant, &l.project, &app)
        .await
        .unwrap();
    assert_eq!(summary["triggers"]["schedule"], true);
    let filtered = l
        .store
        .apps(
            &l.operator,
            &l.tenant,
            &l.project,
            serde_json::from_value(json!({"trigger":"schedule"})).unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(filtered["items"].as_array().unwrap().len(), 1);
    let input = json!({"expected_revision":1,"schedule":{"enabled":false}});
    let (one, two) = tokio::join!(
        l.store.update_app_triggers(
            &l.operator,
            &l.tenant,
            &l.project,
            &app,
            input.clone(),
            "same"
        ),
        l.store.update_app_triggers(
            &l.operator,
            &l.tenant,
            &l.project,
            &app,
            input.clone(),
            "same"
        )
    );
    assert_eq!(one.unwrap(), two.unwrap());
    assert_eq!(
        l.store
            .update_app_triggers(&l.operator, &l.tenant, &l.project, &app, input, "different")
            .await
            .unwrap_err()
            .status,
        StatusCode::CONFLICT
    );
    let disabled = l
        .store
        .app_triggers(&l.operator, &l.tenant, &l.project, &app)
        .await
        .unwrap();
    assert_eq!(disabled["schedule"]["enabled"], false);
    assert_eq!(disabled["schedule"]["expression"], "* * * * *");
    assert!(disabled["schedule"]["next_at"].is_null());
    for invalid in [
        json!({"enabled":true,"expression":"0 0 30 2 *"}),
        json!({"enabled":true,"timezone":"bad/timezone"}),
        json!({"enabled":"yes"}),
        json!({"enabled":true,"injected":true}),
        Value::Null,
    ] {
        assert!(l.schedule_edit(&app, invalid, &uid()).await.is_err());
    }
    let (viewer, _) = l.credential("viewer", Some(&l.project)).await;
    assert_eq!(
        l.store
            .update_app_triggers(
                &viewer,
                &l.tenant,
                &l.project,
                &app,
                json!({"expected_revision":2,"schedule":{"enabled":true}}),
                "viewer"
            )
            .await
            .unwrap_err()
            .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        l.store
            .app_triggers(&viewer, &l.tenant, &uid(), &app)
            .await
            .unwrap_err()
            .status,
        StatusCode::NOT_FOUND
    );
    l.schedule_edit(
        &app,
        json!({"enabled":true,"expression":"30 2 * * *","timezone":"Europe/Zagreb"}),
        "enable",
    )
    .await
    .unwrap();
    let reopened = Store::from_pool(l.store.pool.clone(), l.root.path()).unwrap();
    assert_eq!(
        reopened
            .app_triggers(&viewer, &l.tenant, &l.project, &app)
            .await
            .unwrap()["schedule"]["timezone"],
        "Europe/Zagreb"
    );
    assert!(
        sqlx::query("UPDATE app_schedule_revisions SET expression='0 0 * * *'")
            .execute(&l.store.pool)
            .await
            .is_err()
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM app_schedule_revisions")
        .fetch_one(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(count, 3);
    // Model a persisted revision produced by a different timezone database.
    sqlx::query("INSERT INTO app_schedule_revisions(app_id,tenant_id,project_id,revision,enabled,expression,timezone,timezone_database) SELECT app_id,tenant_id,project_id,4,enabled,expression,timezone,'previous-tzdb' FROM app_schedule_revisions WHERE app_id=$1 AND revision=3").bind(&app).execute(&l.store.pool).await.unwrap();
    sqlx::query("UPDATE app_schedules SET revision=4 WHERE app_id=$1")
        .bind(&app)
        .execute(&l.store.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE app_triggers SET revision=4 WHERE app_id=$1")
        .bind(&app)
        .execute(&l.store.pool)
        .await
        .unwrap();
    l.due(&app).await;
    let incompatible = l
        .store
        .app_triggers(&viewer, &l.tenant, &l.project, &app)
        .await
        .unwrap();
    assert_eq!(incompatible["schedule"]["compatible"], false);
    assert_eq!(
        incompatible["schedule"]["reason"],
        "timezone-database-changed"
    );
    let compatible = l.scheduled_app("compatible", false).await.unwrap();
    l.due(&compatible).await;
    l.store.claim_schedule_occurrences().await.unwrap();
    assert!(l.runs(&app).await["items"].as_array().unwrap().is_empty());
    assert_eq!(
        l.runs(&compatible).await["items"].as_array().unwrap().len(),
        1
    );
    l.finish().await;
}

#[tokio::test]
async fn concurrent_schedule_claims_dispatch_and_restarts_admit_one_pinned_run() {
    let l = Lab::new().await;
    let node = l.node("worker").await;
    approve_component(&l, &node, false, true).await;
    let app = l.scheduled_app("scheduled", true).await.unwrap();
    l.due(&app).await;
    sqlx::raw_sql("CREATE FUNCTION reject_claim() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected outbox failure'; END $$; CREATE TRIGGER reject_claim BEFORE INSERT ON app_run_dispatch FOR EACH ROW EXECUTE FUNCTION reject_claim();").execute(&l.store.pool).await.unwrap();
    assert!(l.store.claim_schedule_occurrences().await.is_err());
    assert!(l.runs(&app).await["items"].as_array().unwrap().is_empty());
    let remains_due: bool =
        sqlx::query_scalar("SELECT next_at<=now() FROM app_schedules WHERE app_id=$1")
            .bind(&app)
            .fetch_one(&l.store.pool)
            .await
            .unwrap();
    assert!(remains_due);
    sqlx::query("DROP TRIGGER reject_claim ON app_run_dispatch")
        .execute(&l.store.pool)
        .await
        .unwrap();
    let (a, b) = tokio::join!(
        l.store.claim_schedule_occurrences(),
        l.store.claim_schedule_occurrences()
    );
    a.unwrap();
    b.unwrap();
    let runs = l.runs(&app).await;
    assert_eq!(runs["items"].as_array().unwrap().len(), 1);
    let run = &runs["items"][0];
    assert_eq!(run["state"], "queued");
    assert_eq!(run["admission"], "pending");
    assert!(run["execution_id"].is_null());
    assert_eq!(run["source"], "schedule");
    assert_eq!(run["trigger_revision"], 1);
    // Keep this restart/dispatch case focused on the claimed occurrence.
    // Crossing a real minute may otherwise add a correctly skipped busy tick
    // ahead of it in history. Tick advancement/busy handling have their own cases.
    sqlx::query("UPDATE app_schedules SET next_at=now()+interval '1 day' WHERE app_id=$1")
        .bind(&app)
        .execute(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(
        l.store.usage(&l.operator, &l.tenant, None).await.unwrap()["reserved"]["instances"],
        0
    );
    assert_eq!(
        l.store
            .run_app(&l.operator, &l.tenant, &l.project, &app, "manual")
            .await
            .unwrap_err()
            .status,
        StatusCode::CONFLICT
    );
    let restarted = Store::from_pool(l.store.pool.clone(), l.root.path()).unwrap();
    // This case tests competing dispatchers/restart, not minute-boundary
    // expiry. The claimed tick may be almost a minute old by now; expiry is
    // exercised separately with an explicit past deadline below.
    sqlx::query("UPDATE app_run_dispatch SET deadline=now()+interval '1 minute' WHERE run_id=$1")
        .bind(s(&run["id"]))
        .execute(&l.store.pool)
        .await
        .unwrap();
    let (a, b) = tokio::join!(
        l.store.dispatch_schedule_runs(),
        restarted.dispatch_schedule_runs()
    );
    a.unwrap();
    b.unwrap();
    let dispatched = l.runs(&app).await;
    assert_eq!(dispatched["items"][0]["id"], run["id"]);
    assert_eq!(dispatched["items"][0]["release_id"], run["release_id"]);
    assert_eq!(
        dispatched["items"][0]["admission"], "admitted",
        "{dispatched}"
    );
    let e = dispatched["items"][0]["execution_id"].clone();
    assert!(e.is_string());
    // A dispatched tick tells the command which schedule time it is.
    let context = l
        .store
        .app_run(&l.operator, &l.tenant, &l.project, &app, s(&run["id"]))
        .await
        .unwrap()["context"]
        .clone();
    assert_eq!(context["trigger"], "schedule");
    assert_eq!(context["run_id"], run["id"]);
    assert_eq!(context["schedule"], "* * * * *");
    assert_eq!(context["schedule_timezone"], "UTC");
    assert_eq!(
        instant(&context["trigger_time"]),
        instant(&run["scheduled_at"])
    );
    l.store.schedule().await.unwrap();
    l.store.schedule().await.unwrap();
    assert_eq!(l.runs(&app).await["items"][0]["execution_id"], e);
    assert_eq!(
        l.store.usage(&l.operator, &l.tenant, None).await.unwrap()["reserved"]["instances"],
        1
    );
    let execution = l.execution(s(&e)).await;
    l.report(&node, &execution, "running", 1).await;
    sqlx::query("UPDATE nodes SET last_seen=now()-interval '1 minute'")
        .execute(&l.store.pool)
        .await
        .unwrap();
    l.store.schedule().await.unwrap();
    assert_eq!(l.runs(&app).await["items"][0]["state"], "unknown");
    assert_eq!(
        l.store
            .run_app(&l.operator, &l.tenant, &l.project, &app, "uncertain")
            .await
            .unwrap_err()
            .status,
        StatusCode::CONFLICT
    );
    assert_eq!(
        l.schedule_edit(&app, json!({"enabled":false}), "busy-edit")
            .await
            .unwrap_err()
            .status,
        StatusCode::CONFLICT
    );
    l.finish().await;
}

#[tokio::test]
async fn schedule_outage_skips_and_manual_busy_ticks_have_no_execution_side_effects() {
    let l = Lab::new().await;
    let node = l.node("worker").await;
    approve_component(&l, &node, false, true).await;
    let app = l.scheduled_app("backlog", true).await.unwrap();
    sqlx::query("UPDATE app_schedules SET next_at=date_trunc('minute',now())-interval '2 hours' WHERE app_id=$1").bind(&app).execute(&l.store.pool).await.unwrap();
    l.store.claim_schedule_occurrences().await.unwrap();
    let history = l.runs(&app).await;
    assert!(history["items"].as_array().unwrap().len() >= 33);
    assert_eq!(history["missed_history_pending"], true);
    assert_eq!(history["items"][0]["admission"], "pending");
    assert!(
        history["items"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["admission"] != "pending" && r["reason"] != "command-busy")
            .all(|r| r["state"] == "skipped"
                && r["reason"] == "missed-deadline"
                && r["execution_id"].is_null())
    );
    assert!(
        history["items"]
            .as_array()
            .unwrap()
            .windows(2)
            .all(|pair| s(&pair[0]["scheduled_at"]) > s(&pair[1]["scheduled_at"]))
    );
    assert_eq!(
        l.store
            .app(&l.operator, &l.tenant, &l.project, &app)
            .await
            .unwrap()["latest_run"]["scheduled_at"],
        history["items"][0]["scheduled_at"]
    );
    let mut cursor = None;
    let mut listed = Vec::new();
    loop {
        let page = l
            .store
            .app_history(
                &l.operator,
                &l.tenant,
                &l.project,
                &app,
                "runs",
                HistoryPage {
                    trigger: None,
                    before: cursor,
                    limit: Some(5),
                },
            )
            .await
            .unwrap();
        listed.extend(
            page["items"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| r["id"].clone()),
        );
        cursor = page["next"].as_str().map(str::to_owned);
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(
        listed,
        history["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["id"].clone())
            .collect::<Vec<_>>()
    );
    let pending: i64 = sqlx::query_scalar("SELECT count(*) FROM app_run_dispatch")
        .fetch_one(&l.store.pool)
        .await
        .unwrap();
    assert_eq!(pending, 1);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM executions")
            .fetch_one(&l.store.pool)
            .await
            .unwrap(),
        0
    );
    assert!(
        sqlx::query_scalar::<_, bool>("SELECT next_at>now() FROM app_schedules WHERE app_id=$1")
            .bind(&app)
            .fetch_one(&l.store.pool)
            .await
            .unwrap()
    );
    // Stopping the schedule cancels live intent, but historical missed ticks
    // continue to materialize without any execution or dispatch side effects.
    l.schedule_edit(&app, json!({"enabled":false}), "pause-backlog")
        .await
        .unwrap();
    for _ in 0..4 {
        l.store.claim_schedule_occurrences().await.unwrap();
    }
    assert_eq!(l.runs(&app).await["missed_history_pending"], false);
    let occurrences: i64 = sqlx::query_scalar("SELECT count(*) FROM app_runs WHERE app_id=$1")
        .bind(&app)
        .fetch_one(&l.store.pool)
        .await
        .unwrap();
    assert!(occurrences >= 120);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM executions")
            .fetch_one(&l.store.pool)
            .await
            .unwrap(),
        0
    );
    l.schedule_edit(&app, json!({"enabled":true}), "resume-backlog")
        .await
        .unwrap();
    let manual = l
        .store
        .run_app(&l.operator, &l.tenant, &l.project, &app, "manual-busy")
        .await
        .unwrap();
    l.due(&app).await;
    l.store.claim_schedule_occurrences().await.unwrap();
    let busy:i64=sqlx::query_scalar("SELECT count(*) FROM app_runs WHERE admission='skipped' AND admission_reason='command-busy'").fetch_one(&l.store.pool).await.unwrap();
    assert_eq!(busy, 1);
    let execution = l
        .store
        .app_run(
            &l.operator,
            &l.tenant,
            &l.project,
            &app,
            s(&manual["resource_id"]),
        )
        .await
        .unwrap()["execution_id"]
        .clone();
    l.store.schedule().await.unwrap();
    let e = l.execution(s(&execution)).await;
    l.report(&node, &e, "exited", 1).await;
    l.schedule_edit(&app, json!({"enabled":false}), "disabled")
        .await
        .unwrap();
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM app_runs")
        .fetch_one(&l.store.pool)
        .await
        .unwrap();
    l.store.schedule().await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM app_runs")
            .fetch_one(&l.store.pool)
            .await
            .unwrap(),
        count
    );
    l.finish().await;
}

#[tokio::test]
async fn schedule_edits_stop_and_deadlines_cancel_only_unassigned_work() {
    let l = Lab::new().await;
    let node = l.node("worker").await;
    approve_component(&l, &node, false, true).await;
    let app = l.scheduled_app("editable", false).await.unwrap();
    l.due(&app).await;
    l.store.claim_schedule_occurrences().await.unwrap();
    let first = l.runs(&app).await["items"][0].clone();
    let pending = l
        .store
        .app(&l.operator, &l.tenant, &l.project, &app)
        .await
        .unwrap();
    assert_eq!(pending["command_busy"], true);
    assert_eq!(pending["scheduled_work_cancellable"], true);
    l.schedule_edit(&app, json!({"enabled":false}), "disable")
        .await
        .unwrap();
    l.store.dispatch_schedule_runs().await.unwrap();
    let cancelled = l
        .store
        .app_run(&l.operator, &l.tenant, &l.project, &app, s(&first["id"]))
        .await
        .unwrap();
    assert_eq!(cancelled["state"], "cancelled");
    assert_eq!(cancelled["reason"], "trigger-changed");
    assert_eq!(
        cancelled["diagnostic"]["summary"],
        "The schedule was disabled or changed before execution."
    );
    assert!(cancelled["execution_id"].is_null());
    l.schedule_edit(&app, json!({"enabled":true}), "enable")
        .await
        .unwrap();
    l.due(&app).await;
    l.store.claim_schedule_occurrences().await.unwrap();
    sqlx::query("UPDATE app_run_dispatch SET deadline=now()+interval '1 minute' WHERE app_id=$1 AND state='pending'").bind(&app).execute(&l.store.pool).await.unwrap();
    l.store.dispatch_schedule_runs().await.unwrap();
    let assigned_later = l.runs(&app).await["items"][0].clone();
    assert_eq!(assigned_later["admission"], "admitted");
    assert!(l.execution(s(&assigned_later["execution_id"])).await["node_id"].is_null());
    let queued = l
        .store
        .app(&l.operator, &l.tenant, &l.project, &app)
        .await
        .unwrap();
    assert_eq!(queued["scheduled_work_cancellable"], true);
    l.scheduled_lifecycle(&app, "stopped", "stop")
        .await
        .unwrap();
    let e = l.execution(s(&assigned_later["execution_id"])).await;
    assert_eq!(e["state"], "stopped");
    assert_eq!(e["reserved"], false);
    assert_eq!(
        l.store
            .app(&l.operator, &l.tenant, &l.project, &app)
            .await
            .unwrap()["scheduled_work_cancellable"],
        false
    );
    assert!(
        l.store
            .app_triggers(&l.operator, &l.tenant, &l.project, &app)
            .await
            .unwrap()["schedule"]["next_at"]
            .is_null()
    );
    l.store.schedule().await.unwrap();
    l.scheduled_lifecycle(&app, "enabled", "start")
        .await
        .unwrap();
    let next = l
        .store
        .app_triggers(&l.operator, &l.tenant, &l.project, &app)
        .await
        .unwrap();
    assert!(next["schedule"]["next_at"].is_string());
    assert_eq!(next["schedule"]["enabled"], true);
    // Start restores a future tick. Keep that tick in the fixture's future
    // while checking that reconciliation itself does not invoke a command:
    // crossing a real minute boundary would legitimately dispatch the tick.
    sqlx::query("UPDATE app_schedules SET next_at=now()+interval '1 hour' WHERE app_id=$1")
        .bind(&app)
        .execute(&l.store.pool)
        .await
        .unwrap();
    let before = l.runs(&app).await["items"].as_array().unwrap().len();
    l.store.schedule().await.unwrap();
    assert_eq!(
        l.runs(&app).await["items"].as_array().unwrap().len(),
        before
    );
    // A fresh trigger revision supplies a distinct occurrence identity.
    l.schedule_edit(&app, json!({"enabled":true}), "next-revision")
        .await
        .unwrap();
    l.due(&app).await;
    l.store.claim_schedule_occurrences().await.unwrap();
    // This case tests expiry AFTER execution admission. Give the dispatcher a
    // full fixture window even if the real clock just crossed a minute boundary.
    sqlx::query("UPDATE app_run_dispatch SET deadline=now()+interval '1 minute' WHERE app_id=$1 AND state='pending'").bind(&app).execute(&l.store.pool).await.unwrap();
    l.store.dispatch_schedule_runs().await.unwrap();
    let queued = l.runs(&app).await["items"][0].clone();
    assert_eq!(queued["admission"], "admitted");
    sqlx::query("UPDATE app_run_dispatch SET deadline=now()-interval '1 second' WHERE run_id=$1")
        .bind(s(&queued["id"]))
        .execute(&l.store.pool)
        .await
        .unwrap();
    l.store.schedule().await.unwrap();
    let skipped = l
        .store
        .app_run(&l.operator, &l.tenant, &l.project, &app, s(&queued["id"]))
        .await
        .unwrap();
    assert_eq!(skipped["state"], "skipped");
    assert_eq!(skipped["reason"], "capacity-deadline");
    assert_eq!(skipped["reserved"], false);
    l.schedule_edit(&app, json!({"enabled":true}), "assigned-revision")
        .await
        .unwrap();
    l.due(&app).await;
    l.store.claim_schedule_occurrences().await.unwrap();
    sqlx::query("UPDATE app_run_dispatch SET deadline=now()+interval '1 minute' WHERE app_id=$1 AND state='pending'").bind(&app).execute(&l.store.pool).await.unwrap();
    sqlx::query("UPDATE app_schedules SET next_at=now()+interval '1 hour' WHERE app_id=$1")
        .bind(&app)
        .execute(&l.store.pool)
        .await
        .unwrap();
    l.store.schedule().await.unwrap();
    let active = l.runs(&app).await["items"][0].clone();
    assert!(l.execution(s(&active["execution_id"])).await["node_id"].is_string());
    let assigned = l
        .store
        .app(&l.operator, &l.tenant, &l.project, &app)
        .await
        .unwrap();
    assert_eq!(assigned["command_busy"], true);
    assert_eq!(assigned["scheduled_work_cancellable"], false);
    sqlx::query("UPDATE app_run_dispatch SET deadline=now()-interval '1 second' WHERE run_id=$1")
        .bind(s(&active["id"]))
        .execute(&l.store.pool)
        .await
        .unwrap();
    l.store.schedule().await.unwrap();
    assert_eq!(
        l.execution(s(&active["execution_id"])).await["reserved"],
        true
    );
    l.finish().await;
}

#[tokio::test]
async fn scheduled_allowance_waits_and_late_dispatch_failure_do_not_duplicate_reservations() {
    let l = Lab::new().await;
    let node = l.node("worker").await;
    approve_component(&l, &node, false, true).await;
    let app = l.scheduled_app("quota", false).await.unwrap();
    l.store.update_allowance(&l.operator,&l.tenant,serde_json::from_value(json!({"allowance":{"cpu_percent":100,"memory_mib":1024,"instances":1,"storage_bytes":1000000,"transfer_bytes":1000000}})).unwrap()).await.unwrap();
    let external = l
        .create("external", json!({"artifact_id":l.artifact}))
        .await;
    l.due(&app).await;
    l.store.claim_schedule_occurrences().await.unwrap();
    // Exercise allowance/retry independently of how close the claimed cron
    // minute is to expiry. The expiry branch is explicitly driven below.
    sqlx::query("UPDATE app_run_dispatch SET deadline=now()+interval '1 minute' WHERE app_id=$1 AND state='pending'").bind(&app).execute(&l.store.pool).await.unwrap();
    l.store.dispatch_schedule_runs().await.unwrap();
    let run = l.runs(&app).await["items"][0].clone();
    assert_eq!(run["admission"], "pending");
    assert_eq!(run["reason"], "allowance-exhausted");
    assert!(run["execution_id"].is_null());
    l.store.dispatch_schedule_runs().await.unwrap();
    assert_eq!(
        l.store.usage(&l.operator, &l.tenant, None).await.unwrap()["reserved"]["instances"],
        1
    );
    sqlx::query("UPDATE app_run_dispatch SET deadline=now()-interval '1 second' WHERE run_id=$1")
        .bind(s(&run["id"]))
        .execute(&l.store.pool)
        .await
        .unwrap();
    l.store.dispatch_schedule_runs().await.unwrap();
    assert_eq!(l.runs(&app).await["items"][0]["reason"], "missed-deadline");
    l.stop(s(&external["resource_id"]), "stop-external")
        .await
        .unwrap();
    l.schedule_edit(&app, json!({"enabled":true}), "revision")
        .await
        .unwrap();
    l.due(&app).await;
    l.store.claim_schedule_occurrences().await.unwrap();
    sqlx::query("UPDATE app_run_dispatch SET deadline=now()+interval '1 minute' WHERE app_id=$1 AND state='pending'").bind(&app).execute(&l.store.pool).await.unwrap();
    sqlx::raw_sql("CREATE FUNCTION reject_dispatch_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='app.scheduled-run' THEN RAISE EXCEPTION 'injected dispatch failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_dispatch_audit BEFORE INSERT ON audit FOR EACH ROW EXECUTE FUNCTION reject_dispatch_audit();").execute(&l.store.pool).await.unwrap();
    assert!(l.store.dispatch_schedule_runs().await.is_err());
    let pending = l.runs(&app).await["items"][0].clone();
    assert_eq!(pending["admission"], "pending");
    assert!(pending["execution_id"].is_null());
    assert_eq!(
        l.store.usage(&l.operator, &l.tenant, None).await.unwrap()["reserved"]["instances"],
        0
    );
    sqlx::query("DROP TRIGGER reject_dispatch_audit ON audit")
        .execute(&l.store.pool)
        .await
        .unwrap();
    l.store.dispatch_schedule_runs().await.unwrap();
    l.store.dispatch_schedule_runs().await.unwrap();
    assert_eq!(
        l.store.usage(&l.operator, &l.tenant, None).await.unwrap()["reserved"]["instances"],
        1
    );
    assert_eq!(l.runs(&app).await["items"][0]["id"], pending["id"]);
    l.finish().await;
}

async fn schedule_test(l: &Lab, app: &str, key: &str, time: Option<String>) -> Result<Value> {
    l.store
        .run_app_event(
            &l.operator,
            &l.tenant,
            &l.project,
            app,
            RunEvent {
                key,
                source: RunSource::TestSchedule,
                trigger_time: time.as_deref(),
            },
        )
        .await
}
fn instant(value: &Value) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339(s(value))
        .unwrap()
        .with_timezone(&chrono::Utc)
}

#[tokio::test]
async fn command_runs_receive_their_trigger_context() {
    let l = Lab::new().await;
    let node = l.node("worker").await;
    approve_component(&l, &node, false, true).await;
    let manual = l.scheduled_app("manual-context", true).await.unwrap();
    let op = l
        .store
        .run_app(&l.operator, &l.tenant, &l.project, &manual, "manual-run")
        .await
        .unwrap();
    let context = l
        .store
        .app_run(
            &l.operator,
            &l.tenant,
            &l.project,
            &manual,
            s(&op["resource_id"]),
        )
        .await
        .unwrap()["context"]
        .clone();
    assert_eq!(context["trigger"], "manual");
    assert_eq!(context["run_id"], op["resource_id"]);
    assert!(s(&context["trigger_time"]).ends_with('Z'));
    assert!(context.get("schedule").is_none());

    let app = l.scheduled_app("schedule-context", false).await.unwrap();
    let upcoming = l
        .store
        .app_triggers(&l.operator, &l.tenant, &l.project, &app)
        .await
        .unwrap()["schedule"]["occurrences"]
        .clone();
    let second = instant(&upcoming[1]["utc"]);
    let refused = [
        second + chrono::Duration::seconds(30),
        instant(&upcoming[4]["utc"]) + chrono::Duration::minutes(10),
        second - chrono::Duration::days(31),
    ];
    for time in refused {
        assert_eq!(
            schedule_test(&l, &app, "refused", Some(time.to_rfc3339()))
                .await
                .unwrap_err()
                .status,
            StatusCode::BAD_REQUEST,
            "{time}"
        );
    }
    // A past schedule time is sent as that tick would have been.
    let past = second - chrono::Duration::days(1);
    let chosen = past.to_rfc3339();
    let op = schedule_test(&l, &app, "chosen", Some(chosen.clone()))
        .await
        .unwrap();
    // A valid upcoming time is accepted too; this app is now busy with the first run.
    assert_eq!(
        schedule_test(&l, &app, "upcoming", Some(second.to_rfc3339()))
            .await
            .unwrap_err()
            .status,
        StatusCode::CONFLICT
    );
    // A retried key may not change the time it sends.
    assert!(
        schedule_test(
            &l,
            &app,
            "chosen",
            Some((past + chrono::Duration::minutes(1)).to_rfc3339())
        )
        .await
        .unwrap_err()
        .status
        .is_client_error()
    );
    assert_eq!(
        schedule_test(&l, &app, "chosen", Some(chosen))
            .await
            .unwrap()["id"],
        op["id"]
    );
    let run = l
        .store
        .app_run(
            &l.operator,
            &l.tenant,
            &l.project,
            &app,
            s(&op["resource_id"]),
        )
        .await
        .unwrap();
    assert_eq!(run["source"], "test-schedule");
    assert!(run["scheduled_at"].is_null());
    assert_eq!(
        run["context"],
        json!({"trigger":"schedule","trigger_time":past.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),"run_id":op["resource_id"],"schedule":"* * * * *","schedule_timezone":"UTC"})
    );
    l.finish().await;
}

#[tokio::test]
async fn schedule_test_events_are_explicit_idempotent_and_recovery_fenced() {
    let l = Lab::new().await;
    let node = l.node("worker").await;
    approve_component(&l, &node, false, true).await;
    let app = l.scheduled_app("schedule-only", false).await.unwrap();
    assert_eq!(
        l.store
            .run_app(&l.operator, &l.tenant, &l.project, &app, "manual")
            .await
            .unwrap_err()
            .status,
        StatusCode::CONFLICT
    );
    let before = l
        .store
        .app_triggers(&l.operator, &l.tenant, &l.project, &app)
        .await
        .unwrap();
    let router = api::router(l.store.clone());
    let path = format!(
        "/v1/workspaces/{}/projects/{}/apps/{}/runs",
        l.tenant, l.project, app
    );
    let request = || {
        Request::builder()
            .method("POST")
            .uri(&path)
            .header("Authorization", format!("Bearer {}", l.token))
            .header("Idempotency-Key", "test-schedule")
            .header("Content-Type", "application/json")
            .body(Body::from(json!({"source":"test-schedule"}).to_string()))
            .unwrap()
    };
    let response = router.clone().oneshot(request()).await.unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let op: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap();
    let retry = router.oneshot(request()).await.unwrap();
    let retry: Value =
        serde_json::from_slice(&to_bytes(retry.into_body(), 65536).await.unwrap()).unwrap();
    assert_eq!(op["id"], retry["id"]);
    let run = l
        .store
        .app_run(
            &l.operator,
            &l.tenant,
            &l.project,
            &app,
            s(&op["resource_id"]),
        )
        .await
        .unwrap();
    assert_eq!(run["source"], "test-schedule");
    assert!(run["scheduled_at"].is_null());
    assert_eq!(
        l.store
            .app_triggers(&l.operator, &l.tenant, &l.project, &app)
            .await
            .unwrap()["schedule"]["next_at"],
        before["schedule"]["next_at"]
    );
    assert_eq!(
        l.store
            .run_app_event(
                &l.operator,
                &l.tenant,
                &l.project,
                &app,
                RunEvent {
                    key: "another-test",
                    source: RunSource::TestSchedule,
                    trigger_time: None,
                }
            )
            .await
            .unwrap_err()
            .status,
        StatusCode::CONFLICT
    );
    sqlx::query("UPDATE recovery_barrier SET active=true")
        .execute(&l.store.pool)
        .await
        .unwrap();
    for result in [
        l.store.claim_schedule_occurrences().await,
        l.store.dispatch_schedule_runs().await,
        l.store.schedule().await,
    ] {
        assert_eq!(result.unwrap_err().status, StatusCode::SERVICE_UNAVAILABLE);
    }
    l.finish().await;
}

#[tokio::test]
async fn schedule_mutations_race_dispatch_without_leaving_unassigned_reservations() {
    let l = Lab::new().await;
    let node = l.node("worker").await;
    approve_component(&l, &node, false, true).await;
    let app = l.scheduled_app("racing", false).await.unwrap();
    l.due(&app).await;
    l.store.claim_schedule_occurrences().await.unwrap();
    let (dispatch, edit) = tokio::join!(
        l.store.dispatch_schedule_runs(),
        l.schedule_edit(&app, json!({"enabled":false}), "disable-race")
    );
    dispatch.unwrap();
    edit.unwrap();
    assert_eq!(l.runs(&app).await["items"][0]["state"], "cancelled");
    assert_eq!(
        l.store.usage(&l.operator, &l.tenant, None).await.unwrap()["reserved"]["instances"],
        0
    );
    l.schedule_edit(&app, json!({"enabled":true}), "enable")
        .await
        .unwrap();
    l.due(&app).await;
    l.store.claim_schedule_occurrences().await.unwrap();
    let (dispatch, stop) = tokio::join!(
        l.store.dispatch_schedule_runs(),
        l.scheduled_lifecycle(&app, "stopped", "stop-race")
    );
    dispatch.unwrap();
    stop.unwrap();
    l.store.schedule().await.unwrap();
    assert_eq!(l.runs(&app).await["items"][0]["state"], "cancelled");
    assert_eq!(
        l.store.usage(&l.operator, &l.tenant, None).await.unwrap()["reserved"]["instances"],
        0
    );
    let assigned: i64 =
        sqlx::query_scalar("SELECT count(*) FROM executions WHERE node_id IS NOT NULL")
            .fetch_one(&l.store.pool)
            .await
            .unwrap();
    assert_eq!(assigned, 0);
    l.finish().await;
}

#[tokio::test]
async fn schedules_require_command_capability_and_revalidate_dependencies_before_dispatch() {
    let l = Lab::new().await;
    let node = l.node("worker").await;
    approve_component(&l, &node, true, false).await;
    assert_eq!(
        l.scheduled_app("http-only", false)
            .await
            .unwrap_err()
            .status,
        StatusCode::CONFLICT
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM apps")
            .fetch_one(&l.store.pool)
            .await
            .unwrap(),
        0
    );
    // Trusted compiler fixture is changed before any immutable app code snapshot.
    sqlx::query(
        "UPDATE artifact_validations SET inspection=jsonb_set(inspection,'{command}','true')",
    )
    .execute(&l.store.pool)
    .await
    .unwrap();
    let secret = l
        .store
        .create_secret(
            &l.operator,
            &l.tenant,
            &l.project,
            json!({"name":"revoked","value":"private"}),
        )
        .await
        .unwrap();
    let op=l.store.deploy_app(&l.operator,&l.tenant,&l.project,AppSubmission{value:json!({"name":"dependent","artifact_id":l.artifact,"triggers":{"http":false,"manual":false,"schedule":{"enabled":true,"expression":"* * * * *","timezone":"UTC"}},"configuration":{"size":"small","secret_env":{"TOKEN":secret["id"]}}}),key:"dependent",domain:"apps.test"}).await.unwrap();
    let app = s(&op["resource_id"]);
    l.due(app).await;
    l.store.claim_schedule_occurrences().await.unwrap();
    sqlx::query("DELETE FROM secrets WHERE id=$1")
        .bind(s(&secret["id"]))
        .execute(&l.store.pool)
        .await
        .unwrap();
    l.store.dispatch_schedule_runs().await.unwrap();
    let run = l.runs(app).await["items"][0].clone();
    assert_eq!(run["state"], "skipped");
    assert_eq!(run["reason"], "dependency-unavailable");
    assert!(run["execution_id"].is_null());
    assert_eq!(
        l.store.usage(&l.operator, &l.tenant, None).await.unwrap()["reserved"]["instances"],
        0
    );
    l.finish().await;
}

/// Calendar/persistence qualification, not a claim of observing a DST transition
/// on the worker clock. Restore a historical cursor and let the real claim and
/// missed-history paths recover it, including a restarted competing scheduler.
#[tokio::test]
async fn dst_previews_and_recovered_occurrence_identity_agree() {
    use fenders_control_plane::schedule::SchedulePreview;
    let l = Lab::new().await;
    let node = l.node("worker").await;
    approve_component(&l, &node, false, true).await;
    let cases = [
        (
            "warsaw-gap",
            "30 2 29-31 3 *",
            "Europe/Warsaw",
            "2025-03-29T00:00:00Z",
            "2025-04-01T00:00:00Z",
            vec!["2025-03-29T01:30:00+00:00", "2025-03-31T00:30:00+00:00"],
        ),
        (
            "warsaw-fold",
            "30 2 25-27 10 *",
            "Europe/Warsaw",
            "2025-10-25T00:00:00Z",
            "2025-10-28T00:00:00Z",
            vec![
                "2025-10-25T00:30:00+00:00",
                "2025-10-26T00:30:00+00:00",
                "2025-10-27T01:30:00+00:00",
            ],
        ),
        (
            "lord-howe-gap",
            "15 2 4-6 10 *",
            "Australia/Lord_Howe",
            "2025-10-03T00:00:00Z",
            "2025-10-06T00:00:00Z",
            vec!["2025-10-03T15:45:00+00:00", "2025-10-05T15:15:00+00:00"],
        ),
        (
            "lord-howe-fold",
            "45 1 5-7 4 *",
            "Australia/Lord_Howe",
            "2025-04-04T00:00:00Z",
            "2025-04-07T00:00:00Z",
            vec![
                "2025-04-04T14:45:00+00:00",
                "2025-04-05T14:45:00+00:00",
                "2025-04-06T15:15:00+00:00",
            ],
        ),
    ];
    for (name, expression, timezone, after, until, expected) in cases {
        let app = l.scheduled_app(name, false).await.unwrap();
        l.schedule_edit(
            &app,
            json!({"enabled":true,"expression":expression,"timezone":timezone}),
            &format!("{name}-configure"),
        )
        .await
        .unwrap();
        let preview = l
            .store
            .preview_schedule(
                &l.operator,
                &l.tenant,
                &l.project,
                SchedulePreview {
                    expression: expression.into(),
                    timezone: timezone.into(),
                    after: Some(after.into()),
                },
            )
            .await
            .unwrap();
        let actual: Vec<_> = preview["occurrences"]
            .as_array()
            .unwrap()
            .iter()
            .take(expected.len())
            .map(|v| s(&v["utc"]))
            .collect();
        assert_eq!(actual, expected, "{name} preview");
        // Restarting after the earlier fold instant must not offer its second
        // UTC representation as another occurrence of the same wall minute.
        for pair in expected.windows(2) {
            let resumed = l
                .store
                .preview_schedule(
                    &l.operator,
                    &l.tenant,
                    &l.project,
                    SchedulePreview {
                        expression: expression.into(),
                        timezone: timezone.into(),
                        after: Some(pair[0].into()),
                    },
                )
                .await
                .unwrap();
            assert_eq!(
                resumed["occurrences"][0]["utc"], pair[1],
                "{name} resumed preview"
            );
        }
        sqlx::query("UPDATE app_schedules SET next_at=$2::timestamptz WHERE app_id=$1")
            .bind(&app)
            .bind(expected[0])
            .execute(&l.store.pool)
            .await
            .unwrap();
        let reopened = Store::from_pool(l.store.pool.clone(), l.root.path()).unwrap();
        let (a, b) = tokio::join!(
            l.store.claim_schedule_occurrences(),
            reopened.claim_schedule_occurrences()
        );
        a.unwrap();
        b.unwrap();
        let read = || {
            sqlx::query_scalar::<_,Value>("SELECT jsonb_build_object('id',id,'at',scheduled_at,'admission',admission,'reason',admission_reason,'execution_id',execution_id,'revision',trigger_revision) FROM app_runs WHERE app_id=$1 AND scheduled_at>=$2::timestamptz AND scheduled_at<$3::timestamptz ORDER BY scheduled_at")
            .bind(&app).bind(after).bind(until).fetch_all(&l.store.pool)
        };
        let rows = read().await.unwrap();
        assert_eq!(rows.len(), expected.len(), "{name} persisted count");
        for (row, time) in rows.iter().zip(expected) {
            assert_eq!(
                chrono::DateTime::parse_from_rfc3339(s(&row["at"])).unwrap(),
                chrono::DateTime::parse_from_rfc3339(time).unwrap()
            );
            assert_eq!(row["admission"], "skipped");
            assert_eq!(row["reason"], "missed-deadline");
            assert_eq!(row["revision"], 2);
            assert!(row["execution_id"].is_null());
        }
        reopened.claim_schedule_occurrences().await.unwrap();
        reopened.dispatch_schedule_runs().await.unwrap();
        assert_eq!(
            read().await.unwrap(),
            rows,
            "{name} restart preserves exact identities without replay"
        );
        l.schedule_edit(&app, json!({"enabled":false}), &format!("{name}-disable"))
            .await
            .unwrap();
    }
    l.finish().await;
}
