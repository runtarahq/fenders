//! PostgreSQL occurrence claims and dispatch outbox. The global mutation lock
//! serializes admission with manual runs, quotas, trigger edits and recovery.
use crate::{
    args,
    artifacts::RUNTIME,
    db::*,
    error::{Error, Result},
    model::uid,
    schedule::Schedule,
    store::{Store, Tx},
    workloads::run_context,
};
use chrono::{DateTime, Duration, Utc};
use serde_json::{Value, json};

fn instant(value: &Value) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(text(value)?)
        .map(|v| v.with_timezone(&Utc))
        .map_err(|_| Error::internal())
}
pub(crate) async fn clock(tx: &mut Tx) -> Result<DateTime<Utc>> {
    instant(&one(tx, "SELECT now() AS time", args![]).await?["time"])
}

impl Store {
    pub(crate) async fn schedule_row(tx: &mut Tx, app: &str) -> Result<Value> {
        Ok(optional(tx,"SELECT r.*,s.next_at FROM app_schedules s JOIN app_schedule_revisions r ON r.app_id=s.app_id AND r.revision=s.revision WHERE s.app_id=$1",args![app]).await?.unwrap_or(Value::Null))
    }
    pub(crate) fn schedule_config(value: Option<&Value>, current: &Value) -> Result<Value> {
        let Some(value) = value else {
            return Ok(current.clone());
        };
        fields(value, &["enabled", "expression", "timezone"], &["enabled"])?;
        if !value["enabled"].is_boolean() {
            return Err(Error::invalid("schedule enabled must be a boolean"));
        }
        let expression = get(value, "expression", current["expression"].clone());
        let timezone = get(value, "timezone", current["timezone"].clone());
        let schedule = Schedule::parse(text(&expression)?, text(&timezone)?)?;
        Ok(
            json!({"enabled":value["enabled"],"expression":schedule.expression,"timezone":schedule.timezone.name(),"timezone_database":chrono_tz::IANA_TZDB_VERSION}),
        )
    }
    pub(crate) async fn save_schedule(
        tx: &mut Tx,
        app: &Value,
        revision: i64,
        config: &Value,
    ) -> Result<()> {
        if config.is_null() {
            return Ok(());
        }
        let schedule = Schedule::parse(s(&config["expression"]), s(&config["timezone"]))?;
        let next = schedule.next(clock(tx).await?, 1)?[0].to_rfc3339(); // Validate impossible calendars even when disabled.
        exec(tx,"INSERT INTO app_schedule_revisions(app_id,tenant_id,project_id,revision,enabled,expression,timezone,timezone_database) VALUES($1,$2,$3,$4,$5,$6,$7,$8)",args![app["id"],app["tenant_id"],app["project_id"],revision,config["enabled"],schedule.expression,schedule.timezone.name(),chrono_tz::IANA_TZDB_VERSION]).await?;
        exec(tx,"INSERT INTO app_schedules(app_id,tenant_id,project_id,revision,next_at) VALUES($1,$2,$3,$4,CASE WHEN $5 THEN $6::timestamptz END) ON CONFLICT(app_id) DO UPDATE SET revision=excluded.revision,next_at=excluded.next_at,updated=now()",args![app["id"],app["tenant_id"],app["project_id"],revision,config["enabled"]==true&&app["desired"]=="enabled",next]).await?;
        Ok(())
    }
    pub(crate) async fn reset_schedule_clock(tx: &mut Tx, app: &str, enabled: bool) -> Result<()> {
        let config = Self::schedule_row(tx, app).await?;
        if config.is_null() {
            return Ok(());
        }
        let next = if enabled
            && config["enabled"] == true
            && config["timezone_database"] == chrono_tz::IANA_TZDB_VERSION
        {
            json!(
                Schedule::parse(s(&config["expression"]), s(&config["timezone"]))?
                    .next(clock(tx).await?, 1)?[0]
                    .to_rfc3339()
            )
        } else {
            Value::Null
        };
        exec(
            tx,
            "UPDATE app_schedules SET next_at=$1::timestamptz,updated=now() WHERE app_id=$2",
            args![next, app],
        )
        .await?;
        Ok(())
    }
    pub(crate) async fn cancel_schedule_dispatch(
        tx: &mut Tx,
        app: &str,
        reason: &str,
    ) -> Result<()> {
        // An unassigned execution has never been delivered to a node. Once an
        // assignment exists, normal observation/fencing barriers retain quota.
        exec(tx,"UPDATE app_runs r SET admission='cancelled',admission_reason=$2,admission_updated=now() WHERE r.app_id=$1 AND r.source='schedule' AND (r.admission='pending' OR r.admission='admitted' AND EXISTS(SELECT 1 FROM executions e WHERE e.id=r.execution_id AND e.node_id IS NULL AND e.reserved))",args![app,reason]).await?;
        exec(tx,"UPDATE executions e SET desired='stopped',state='stopped',reserved=false,generation=generation+1,updated=now(),finished_at=now() FROM app_runs r WHERE r.execution_id=e.id AND r.app_id=$1 AND r.admission='cancelled' AND e.node_id IS NULL AND e.reserved",args![app]).await?;
        exec(tx,"UPDATE app_run_dispatch d SET state='cancelled',last_error=$2,updated=now() FROM app_runs r WHERE r.id=d.run_id AND r.app_id=$1 AND r.admission='cancelled' AND d.state='pending'",args![app,reason]).await?;
        Ok(())
    }
    pub(crate) async fn schedule_summary(tx: &mut Tx, app: &str) -> Result<Value> {
        let row = Self::schedule_row(tx, app).await?;
        if row.is_null() {
            return Ok(Value::Null);
        }
        let schedule = Schedule::parse(s(&row["expression"]), s(&row["timezone"]))?;
        let occurrences = schedule.next(clock(tx).await?, 5)?;
        let compatible = row["timezone_database"] == chrono_tz::IANA_TZDB_VERSION;
        let missed_history_pending = Self::missed_history_pending(tx, app).await?;
        Ok(
            json!({"enabled":row["enabled"],"expression":row["expression"],"timezone":row["timezone"],"timezone_database":row["timezone_database"],"runtime_timezone_database":chrono_tz::IANA_TZDB_VERSION,"compatible":compatible,"reason":if compatible{Value::Null}else{json!("timezone-database-changed")},"next_at":row["next_at"],"missed_history_pending":missed_history_pending,"occurrences":occurrences.iter().map(|t|json!({"utc":t.to_rfc3339(),"local":t.with_timezone(&schedule.timezone).to_rfc3339()})).collect::<Vec<_>>()}),
        )
    }
    pub(crate) async fn missed_history_pending(tx: &mut Tx, app: &str) -> Result<bool> {
        Ok(one(tx,"SELECT EXISTS(SELECT 1 FROM app_schedule_misses WHERE app_id=$1 AND NOT complete) AS pending",args![app]).await?["pending"] == true)
    }
    /// Claim at most sixteen schedules. Cursor and run
    /// intent/outbox commit together. No node is contacted in this transaction.
    pub async fn claim_schedule_occurrences(&self) -> Result<()> {
        let mut tx = self.watched_transaction().await?;
        let now = clock(&mut tx).await?;
        let schedules=rows(&mut tx,"SELECT s.*,c.expression,c.timezone,c.timezone_database,a.active_release_id,a.target_release_id,l.state AS release_state,v.inspection FROM app_schedules s JOIN app_schedule_revisions c ON c.app_id=s.app_id AND c.revision=s.revision JOIN apps a ON a.id=s.app_id JOIN app_releases l ON l.id=a.active_release_id JOIN app_versions v ON v.id=l.version_id WHERE EXISTS(SELECT 1 FROM tenants tenant WHERE tenant.id=s.tenant_id AND tenant.lifecycle_state='active') AND c.enabled AND c.timezone_database=$1 AND a.desired='enabled' AND s.next_at<=now() ORDER BY s.updated,s.app_id LIMIT 16 FOR UPDATE OF s",args![chrono_tz::IANA_TZDB_VERSION]).await?;
        for row in schedules {
            let schedule = Schedule::parse(s(&row["expression"]), s(&row["timezone"]))?;
            let mut due = instant(&row["next_at"])?;
            if now - due > Duration::seconds(60) {
                // Record the old interval atomically, then advance directly to
                // the inclusive admission window. History cannot delay live work.
                let first_live =
                    schedule.next(now - Duration::seconds(60) - Duration::nanoseconds(1), 1)?[0];
                exec(&mut tx,"INSERT INTO app_schedule_misses(id,tenant_id,project_id,app_id,revision,release_id,first_at,next_at,until_at) VALUES($1,$2,$3,$4,$5,$6,$7::timestamptz,$7::timestamptz,$8::timestamptz) ON CONFLICT(app_id,revision,first_at) DO NOTHING",args![uid(),row["tenant_id"],row["project_id"],row["app_id"],row["revision"],row["active_release_id"],due.to_rfc3339(),first_live.to_rfc3339()]).await?;
                due = first_live;
            }
            for _ in 0..32 {
                if due > now {
                    break;
                }
                let busy=optional(&mut tx,"SELECT r.id FROM app_runs r LEFT JOIN executions e ON e.id=r.execution_id WHERE r.app_id=$1 AND (r.admission='pending' OR e.reserved) LIMIT 1",args![row["app_id"]]).await?.is_some();
                let reason = if now - due > Duration::seconds(60) {
                    Some("missed-deadline")
                } else if busy {
                    Some("command-busy")
                } else if row["active_release_id"] != row["target_release_id"]
                    || row["release_state"] != "ready"
                    || row["inspection"]["command"] != true
                    || row["inspection"]["runtime"] != RUNTIME
                {
                    Some("release-unavailable")
                } else {
                    None
                };
                let run=optional(&mut tx,"INSERT INTO app_runs(id,tenant_id,project_id,app_id,release_id,source,admission,admission_reason,scheduled_at,trigger_revision) VALUES($1,$2,$3,$4,$5,'schedule',$6,$7,$8::timestamptz,$9) ON CONFLICT(app_id,trigger_revision,scheduled_at) DO NOTHING RETURNING id",args![uid(),row["tenant_id"],row["project_id"],row["app_id"],row["active_release_id"],if reason.is_none(){"pending"}else{"skipped"},reason,due.to_rfc3339(),row["revision"]]).await?;
                if reason.is_none()
                    && let Some(run) = run
                {
                    exec(&mut tx,"INSERT INTO app_run_dispatch(run_id,tenant_id,project_id,app_id,deadline) VALUES($1,$2,$3,$4,$5::timestamptz)",args![run["id"],row["tenant_id"],row["project_id"],row["app_id"],(due+Duration::seconds(60)).to_rfc3339()]).await?;
                }
                due = schedule.next(due, 1)?[0];
            }
            exec(
                &mut tx,
                "UPDATE app_schedules SET next_at=$1::timestamptz,updated=now() WHERE app_id=$2",
                args![due.to_rfc3339(), row["app_id"]],
            )
            .await?;
        }
        Self::materialize_missed_ticks(&mut tx).await?;
        self.commit_watched(tx).await?;
        Ok(())
    }
    async fn materialize_missed_ticks(tx: &mut Tx) -> Result<()> {
        let ranges=rows(tx,"SELECT m.*,r.expression,r.timezone FROM app_schedule_misses m JOIN app_schedule_revisions r ON r.app_id=m.app_id AND r.revision=m.revision WHERE NOT m.complete AND r.timezone_database=$1 ORDER BY m.updated,m.id LIMIT 16 FOR UPDATE OF m",args![chrono_tz::IANA_TZDB_VERSION]).await?;
        for range in ranges {
            let schedule = Schedule::parse(s(&range["expression"]), s(&range["timezone"]))?;
            let mut due = instant(&range["next_at"])?;
            let until = instant(&range["until_at"])?;
            for _ in 0..32 {
                if due >= until {
                    break;
                }
                exec(tx,"INSERT INTO app_runs(id,tenant_id,project_id,app_id,release_id,source,admission,admission_reason,scheduled_at,trigger_revision) VALUES($1,$2,$3,$4,$5,'schedule','skipped','missed-deadline',$6::timestamptz,$7) ON CONFLICT(app_id,trigger_revision,scheduled_at) DO NOTHING",args![uid(),range["tenant_id"],range["project_id"],range["app_id"],range["release_id"],due.to_rfc3339(),range["revision"]]).await?;
                due = schedule.next(due, 1)?[0];
            }
            exec(tx,"UPDATE app_schedule_misses SET next_at=$1::timestamptz,complete=$2,updated=now() WHERE id=$3",args![due.to_rfc3339(),due>=until,range["id"]]).await?;
        }
        Ok(())
    }
    pub async fn dispatch_schedule_runs(&self) -> Result<()> {
        let mut tx = self.watched_transaction().await?;
        let runs=rows(&mut tx,"SELECT r.*,d.deadline,(d.deadline<now()) AS expired,a.desired,a.active_release_id,a.target_release_id,s.revision AS current_revision,c.enabled,c.expression,c.timezone,c.timezone_database,l.spec,l.state AS release_state,v.inspection FROM app_run_dispatch d JOIN app_runs r ON r.id=d.run_id JOIN apps a ON a.id=r.app_id JOIN app_schedules s ON s.app_id=r.app_id JOIN app_schedule_revisions c ON c.app_id=s.app_id AND c.revision=s.revision JOIN app_releases l ON l.id=r.release_id JOIN app_versions v ON v.id=l.version_id WHERE d.state='pending' ORDER BY d.updated,d.run_id LIMIT 64 FOR UPDATE OF d",args![]).await?;
        for run in runs {
            let reason = if !Self::workspace_active(&mut tx, s(&run["tenant_id"])).await? {
                Some("workspace-suspended")
            } else if run["admission"] != "pending"
                || run["desired"] != "enabled"
                || run["enabled"] != true
                || run["trigger_revision"] != run["current_revision"]
            {
                Some("trigger-disabled-or-changed")
            } else if run["timezone_database"] != chrono_tz::IANA_TZDB_VERSION {
                Some("timezone-database-changed")
            } else if run["expired"] == true {
                Some("missed-deadline")
            } else if run["release_id"] != run["active_release_id"]
                || run["active_release_id"] != run["target_release_id"]
                || run["release_state"] != "ready"
                || run["inspection"]["command"] != true
                || run["inspection"]["runtime"] != RUNTIME
            {
                Some("release-unavailable")
            } else {
                None
            };
            exec(
                &mut tx,
                "UPDATE app_run_dispatch SET attempts=attempts+1,updated=now() WHERE run_id=$1",
                args![run["id"]],
            )
            .await?;
            if let Some(reason) = reason {
                Self::skip_scheduled_run(&mut tx, &run, reason).await?;
                continue;
            }
            if optional(&mut tx,"SELECT r.id FROM app_runs r LEFT JOIN executions e ON e.id=r.execution_id WHERE r.app_id=$1 AND r.id<>$2 AND (r.admission='pending' OR e.reserved) LIMIT 1",args![run["app_id"],run["id"]]).await?.is_some() {Self::skip_scheduled_run(&mut tx,&run,"command-busy").await?;continue;}
            if let Err(e) = self
                .check_refs(
                    &mut tx,
                    s(&run["tenant_id"]),
                    s(&run["project_id"]),
                    &run["spec"],
                )
                .await
            {
                if e.status.is_client_error() {
                    Self::skip_scheduled_run(&mut tx, &run, "dependency-unavailable").await?;
                    continue;
                } else {
                    return Err(e);
                }
            }
            // Revision equality above makes the joined schedule the one that produced this run.
            let mut spec = run["spec"].clone();
            spec["run_context"] = run_context(
                &json!({"trigger":"schedule","trigger_time":run["scheduled_at"],"run_id":run["id"],"schedule":run["expression"],"schedule_timezone":run["timezone"]}),
            )?;
            let execution = match Self::execution(
                &mut tx,
                s(&run["tenant_id"]),
                s(&run["project_id"]),
                &spec,
                None,
                1,
            )
            .await
            {
                Ok(e) => e,
                Err(e) if e.status == axum::http::StatusCode::TOO_MANY_REQUESTS => {
                    exec(&mut tx,"UPDATE app_run_dispatch SET last_error='allowance-exhausted' WHERE run_id=$1",args![run["id"]]).await?;
                    continue;
                }
                Err(e) => return Err(e),
            };
            Self::record_app_connections(&mut tx, s(&run["app_id"]), &execution).await?;
            exec(&mut tx,"UPDATE app_runs SET execution_id=$1,admission='admitted',admission_updated=now() WHERE id=$2",args![execution["id"],run["id"]]).await?;
            exec(&mut tx,"UPDATE app_run_dispatch SET state='dispatched',last_error=NULL,updated=now() WHERE run_id=$1",args![run["id"]]).await?;
            Self::audit_system(&mut tx,"scheduler","app.scheduled-run",&run["app_id"],&run["tenant_id"],json!({"run_id":run["id"],"execution_id":execution["id"],"scheduled_at":run["scheduled_at"],"trigger_revision":run["trigger_revision"]})).await?;
        }
        self.commit_watched(tx).await?;
        Ok(())
    }
    async fn skip_scheduled_run(tx: &mut Tx, run: &Value, reason: &str) -> Result<()> {
        exec(tx,"UPDATE app_runs SET admission='skipped',admission_reason=$1,admission_updated=now() WHERE id=$2 AND admission='pending'",args![reason,run["id"]]).await?;
        exec(tx,"UPDATE app_run_dispatch SET state='cancelled',last_error=$1,updated=now() WHERE run_id=$2",args![reason,run["id"]]).await?;
        Ok(())
    }
    pub(crate) async fn expire_schedule_queue(tx: &mut Tx) -> Result<()> {
        exec(tx,"UPDATE app_runs r SET admission='skipped',admission_reason='capacity-deadline',admission_updated=now() FROM executions e,app_run_dispatch d WHERE r.execution_id=e.id AND d.run_id=r.id AND r.source='schedule' AND r.admission='admitted' AND e.node_id IS NULL AND e.reserved AND d.deadline<now()",args![]).await?;
        exec(tx,"UPDATE executions e SET desired='stopped',state='stopped',reserved=false,generation=generation+1,updated=now(),finished_at=now() FROM app_runs r WHERE r.execution_id=e.id AND r.admission='skipped' AND e.node_id IS NULL AND e.reserved",args![]).await?;
        Ok(())
    }
}
