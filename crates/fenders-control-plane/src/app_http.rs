//! One warm HTTP execution per app, with sequential replacement, bounded drain,
//! observation-based publication and stable routing. Never replay ingress.
use crate::{
    args,
    db::*,
    error::{Error, Result},
    model::{HOST_CONFINEMENT, Principal, identity, uid},
    store::{Store, Tx},
    workloads::terminal,
};
use axum::http::StatusCode;
use serde_json::{Value, json};

/// How long a request waits for a taker, and how long every execution is
/// busy, before an app is given another execution; and how long an extra
/// execution has nothing to do before it is stopped.
const SCALE_WAITING: std::time::Duration = std::time::Duration::from_secs(1);
const SCALE_SATURATED: std::time::Duration = std::time::Duration::from_secs(10);
const SCALE_IDLE: std::time::Duration = std::time::Duration::from_secs(60);

pub struct TriggerUpdate<'a> {
    pub value: Value,
    pub key: &'a str,
    pub domain: &'a str,
}

pub fn hostname(app: &str, domain: &str) -> Result<String> {
    identity(app)?;
    let hostname = format!("app-{app}.{domain}");
    if hostname.len() > 253
        || !domain.contains('.')
        || domain.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        })
    {
        return Err(Error::invalid("invalid application domain"));
    }
    Ok(hostname)
}

impl Store {
    /// Authorize an explicit diagnostic invocation. The caller cannot choose a
    /// hostname, method, headers or destination; these come from the scoped app.
    pub async fn app_sample_hostname(
        &self,
        p: &Principal,
        tenant: &str,
        project: &str,
        app: &str,
    ) -> Result<String> {
        self.app_sample_hostname_for(p, tenant, project, app, "GET", "/")
            .await
    }

    /// [`app_sample_hostname`](Self::app_sample_hostname), recording the
    /// method and path that will be sent: the audit record of a sample says
    /// what was asked of the app, without its query.
    pub async fn app_sample_hostname_for(
        &self,
        p: &Principal,
        tenant: &str,
        project: &str,
        app: &str,
        method: &str,
        path: &str,
    ) -> Result<String> {
        let mut tx = self.transaction(true, false).await?;
        Self::project(&mut tx, p, tenant, project, true).await?;
        Self::app_row(&mut tx, tenant, project, app).await?;
        let route = optional(&mut tx, "SELECT h.hostname FROM app_http h JOIN apps a ON a.id=h.app_id JOIN app_triggers t ON t.app_id=a.id WHERE a.id=$1 AND a.tenant_id=$2 AND a.project_id=$3 AND a.desired='enabled' AND t.http", args![app,tenant,project]).await?.ok_or_else(|| Error::new(StatusCode::CONFLICT,"enable the app and its HTTP trigger before sending a sample request"))?;
        Self::audit(
            &mut tx,
            p,
            "app.http-sample",
            app,
            tenant,
            json!({
                "method": method.chars().take(16).collect::<String>(),
                "path": path.split('?').next().unwrap_or("/").chars().take(2048).collect::<String>(),
            }),
        )
        .await?;
        tx.commit().await?;
        Ok(s(&route["hostname"]).to_owned())
    }

    pub(crate) async fn copy_app_release(
        &self,
        tx: &mut Tx,
        app: &Value,
        preparing: bool,
    ) -> Result<()> {
        let old=one(tx,"SELECT l.version_id,v.artifact_id,v.inspection FROM app_releases l JOIN app_versions v ON v.id=l.version_id WHERE l.id=$1",args![app["target_release_id"]]).await?;
        if old["inspection"]["runtime"] != crate::artifacts::RUNTIME
            || preparing && old["inspection"]["http"] != true
        {
            return Err(conflict("release has no compatible HTTP entry point"));
        }
        let spec = Self::compose_app_connections(
            tx,
            s(&app["id"]),
            crate::app_runtime::command_spec(s(&old["artifact_id"]), &app["configuration"])?,
        )
        .await?;
        self.check_refs(tx, s(&app["tenant_id"]), s(&app["project_id"]), &spec)
            .await?;
        exec(tx,"UPDATE app_releases SET state='failed',reason='superseded',updated=now() WHERE app_id=$1 AND state='preparing'",args![app["id"]]).await?;
        let id = uid();
        exec(tx,"INSERT INTO app_releases(id,tenant_id,project_id,app_id,version_id,configuration,spec,state) VALUES($1,$2,$3,$4,$5,$6,$7,$8)",args![id,app["tenant_id"],app["project_id"],app["id"],old["version_id"],app["configuration"],spec,if preparing {"preparing"} else {"ready"}]).await?;
        exec(tx,"UPDATE apps SET target_release_id=$1,active_release_id=CASE WHEN $2 THEN active_release_id ELSE $1 END,updated=now() WHERE id=$3",args![id,preparing,app["id"]]).await?;
        Ok(())
    }

    pub(crate) async fn independent_deployment(tx: &mut Tx, deployment: &Value) -> Result<()> {
        if optional(
            tx,
            "SELECT app_id FROM app_http WHERE deployment_id=$1",
            args![deployment],
        )
        .await?
        .is_some()
        {
            return Err(conflict("deployment is managed by an app; use the app API"));
        }
        Ok(())
    }
    pub(crate) async fn ensure_app_http(tx: &mut Tx, app: &Value, domain: &str) -> Result<()> {
        let host = hostname(s(&app["id"]), domain)?;
        exec(tx,"INSERT INTO app_http(app_id,tenant_id,project_id,hostname) VALUES($1,$2,$3,$4) ON CONFLICT(app_id) DO NOTHING",args![app["id"],app["tenant_id"],app["project_id"],host]).await?;
        Ok(())
    }

    pub(crate) async fn request_app_http(tx: &mut Tx, app: &str, op: &Value) -> Result<bool> {
        let Some(binding) =
            optional(tx, "SELECT * FROM app_http WHERE app_id=$1", args![app]).await?
        else {
            return Ok(false);
        };
        if n(&binding["generation"]) >= i32::MAX as i64 {
            return Err(conflict("HTTP generation limit reached"));
        }
        exec(tx,"UPDATE operations o SET state='failed',error='superseded',updated=now() FROM app_http_operations h WHERE h.operation_id=o.id AND h.app_id=$1 AND o.state='pending'",args![app]).await?;
        let next = n(&binding["generation"]) + 1;
        exec(tx,"UPDATE app_http SET generation=$1,state='stopping',reason='draining-http',blocked=false,idle_draining=false,drain_until=now()+interval '30 seconds',ready_until=now()+interval '5 minutes',execution_id=NULL,failures=0,restart_after=NULL,failure_window=now(),updated=now() WHERE app_id=$2",args![next,app]).await?;
        if !binding["deployment_id"].is_null() {
            exec(
                tx,
                "UPDATE deployments SET desired='stopped' WHERE id=$1",
                args![binding["deployment_id"]],
            )
            .await?;
        }
        Self::track_app_http(tx, app, op).await?;
        Ok(true)
    }

    /// As [`request_app_http`](Self::request_app_http), for a change the
    /// app can go on serving through: when it is serving, the execution it
    /// has stays where it is and the next generation's is brought up beside
    /// it (the reconciler's candidate), taking over once it is ready.
    pub(crate) async fn replace_app_http(tx: &mut Tx, app: &str, op: &Value) -> Result<bool> {
        let serving = optional(tx,"SELECT * FROM app_http WHERE app_id=$1 AND state='serving' AND execution_id IS NOT NULL AND NOT blocked AND NOT idle_draining AND generation<2147483647",args![app]).await?;
        let Some(binding) = serving else {
            return Self::request_app_http(tx, app, op).await;
        };
        exec(tx,"UPDATE operations o SET state='failed',error='superseded',updated=now() FROM app_http_operations h WHERE h.operation_id=o.id AND h.app_id=$1 AND o.state='pending'",args![app]).await?;
        // A candidate of an earlier change is given up for this one.
        exec(tx,"UPDATE executions SET desired='stopped',generation=generation+1,updated=now() WHERE id=$1 AND reserved AND desired<>'stopped'",args![binding["candidate_execution_id"]]).await?;
        exec(tx,"UPDATE app_http SET generation=generation+1,reason='replacing-http',candidate_execution_id=NULL,candidate_until=now()+interval '5 minutes',failures=0,restart_after=NULL,failure_window=now(),updated=now() WHERE app_id=$1",args![app]).await?;
        Self::track_app_http(tx, app, op).await?;
        Ok(true)
    }

    pub(crate) async fn track_app_http(tx: &mut Tx, app: &str, op: &Value) -> Result<bool> {
        Ok(exec(tx,"INSERT INTO app_http_operations(operation_id,tenant_id,project_id,app_id,generation) SELECT $1,tenant_id,project_id,app_id,generation FROM app_http WHERE app_id=$2 AND generation>0",args![op["id"],app]).await? > 0)
    }

    async fn http_state(tx: &mut Tx, app: &str, state: &str, reason: Option<&str>) -> Result<()> {
        exec(tx,"UPDATE app_http SET state=$1,reason=$2,updated=now() WHERE app_id=$3 AND (state,reason) IS DISTINCT FROM ($1,$2)",args![state,reason,app]).await?;
        Ok(())
    }

    async fn http_failure(tx: &mut Tx, app: &Value, reason: &str) -> Result<()> {
        Self::http_state(tx, s(&app["id"]), "unavailable", Some(reason)).await?;
        exec(
            tx,
            "UPDATE app_http SET blocked=true WHERE app_id=$1",
            args![app["id"]],
        )
        .await?;
        exec(tx,"UPDATE app_releases SET state='failed',reason=$1,updated=now() WHERE id=$2 AND state='preparing'",args![reason,app["target_release_id"]]).await?;
        Ok(())
    }

    async fn drain_http(&self, tx: &mut Tx, binding: &Value) -> Result<bool> {
        // The app is leaving service: from here its requests are admitted
        // under the lock this transaction holds, and so after it.
        let app = s(&binding["app_id"]);
        self.gateway.gates.close(app);
        let pending=rows(tx,"SELECT e.*,($2::timestamptz<=now()) AS deadline FROM executions e WHERE deployment_id=$1 AND reserved",args![binding["deployment_id"],binding["drain_until"]]).await?;
        for e in &pending {
            if e["node_id"].is_null() {
                exec(tx,"UPDATE executions SET desired='stopped',state='stopped',reserved=false,generation=generation+1,finished_at=now(),updated=now() WHERE id=$1",args![e["id"]]).await?;
                continue;
            }
            if e["desired"] == "stopped" {
                continue;
            }
            // The app's executions are busy while it has a request that
            // was given one of them, which the gateway counts
            // ([`crate::gate`]); one that waited for the app to start has a
            // reservation for the execution it was given. With none they
            // are idle, and admission is serialized with this, the gate
            // being closed, so they stay idle: stopped at once. A busy one
            // is stopped at the deadline.
            let busy = self.exchange.busy(s(&e["id"]))
                || self.gateway.gates.serving(app) > 0
                || optional(
                    tx,
                    "SELECT id FROM ingress_reservations WHERE execution_id=$1 LIMIT 1",
                    args![e["id"]],
                )
                .await?
                .is_some();
            if e["deadline"] == true || !busy || matches!(s(&e["state"]), "queued" | "starting") {
                exec(tx,"UPDATE executions SET desired='stopped',generation=generation+1,updated=now() WHERE id=$1",args![e["id"]]).await?;
            }
        }
        Ok(optional(
            tx,
            "SELECT id FROM executions WHERE deployment_id=$1 AND reserved LIMIT 1",
            args![binding["deployment_id"]],
        )
        .await?
        .is_none())
    }

    pub(crate) async fn reconcile_app_http(&self, tx: &mut Tx) -> Result<()> {
        for binding in rows(tx,"SELECT h.*,ready_until<=now() AS expired,restart_after<=now() AS retry_due,failure_window<now()-interval '5 minutes' AS reset_failures FROM app_http h",args![]).await? {
            let app=one(tx,"SELECT a.*,t.http FROM apps a JOIN app_triggers t ON t.app_id=a.id WHERE a.id=$1",args![binding["app_id"]]).await?;
            let app_id=s(&app["id"]);
            if !Self::workspace_active(tx,s(&app["tenant_id"])).await? {continue;}
            let want=app["desired"]=="enabled" && app["http"]==true && !app["target_release_id"].is_null();
            // Extra executions belong to one generation of the binding: the
            // one that serves, which while a candidate is brought up is the
            // one before. Those of any other are stopped, ended ones forgotten.
            let replacing=!binding["candidate_until"].is_null();
            let serving_generation=json!(n(&binding["generation"])-i64::from(replacing));
            exec(tx,"UPDATE executions SET desired='stopped',generation=generation+1,updated=now() WHERE reserved AND desired<>'stopped' AND node_id IS NOT NULL AND id IN (SELECT execution_id FROM app_http_extras WHERE app_id=$1 AND generation<>$2)",args![app_id,serving_generation]).await?;
            exec(tx,"UPDATE executions SET desired='stopped',state='stopped',reserved=false,generation=generation+1,finished_at=now(),updated=now() WHERE reserved AND node_id IS NULL AND id IN (SELECT execution_id FROM app_http_extras WHERE app_id=$1 AND generation<>$2)",args![app_id,serving_generation]).await?;
            exec(tx,"DELETE FROM app_http_extras x WHERE x.app_id=$1 AND NOT EXISTS(SELECT 1 FROM executions e WHERE e.id=x.execution_id AND e.reserved)",args![app_id]).await?;
            if replacing {
                self.replace_http(tx,&app,&binding,want).await?;
                continue;
            }
            if binding["blocked"]==true {
                // Cleanup survives rollout failure, including transient worker
                // control errors that require a new stop generation.
                self.drain_http(tx,&binding).await?;
                continue;
            }
            if binding["idle_draining"]==true {
                if self.drain_http(tx,&binding).await? {
                    exec(tx,"UPDATE app_http SET state='idle',reason=NULL,execution_id=NULL,idle_draining=false,drain_until=NULL,ready_until=NULL,updated=now() WHERE app_id=$1",args![app_id]).await?;
                    Self::wake_http(tx,app_id).await?;
                }
                continue;
            }
            if binding["state"]=="idle" {
                Self::wake_http(tx,app_id).await?;
                continue;
            }
            if binding["state"]=="stopping" {
                if !self.drain_http(tx,&binding).await? {
                    if want && binding["expired"]==true {Self::http_failure(tx,&app,"previous-worker-not-stopped").await?;}
                    continue;
                }
                Self::http_state(tx,app_id,if want {"starting"} else {"disabled"},None).await?;
            }
            if !want {continue;}
            // A failed startup is sticky until a new explicit release is selected.
            let release=one(tx,"SELECT l.*,v.inspection FROM app_releases l JOIN app_versions v ON v.id=l.version_id WHERE l.id=$1",args![app["target_release_id"]]).await?;
            if release["state"]=="failed" {continue;}
            // Even after a drain deadline failed the rollout, keep stopping the
            // old worker; reservations cannot be released on a timer alone.
            let old=optional(tx,"SELECT id FROM executions WHERE deployment_id=$1 AND reserved AND ($2 IS NULL OR id<>$2) AND id NOT IN (SELECT execution_id FROM app_http_extras WHERE app_id=$3 AND generation=$4) LIMIT 1",args![binding["deployment_id"],binding["execution_id"],app_id,serving_generation]).await?;
            if old.is_some() {
                // What a candidate took over from is stopped once it holds
                // no request, or at the drain deadline.
                if binding["state"]=="serving" {self.drain_others(tx,&binding).await?;}
                continue;
            }
            if let Some(e)=optional(tx,"SELECT e.*,n.last_seen>now()-interval '15 seconds' AND NOT n.disabled AND n.observed_confinement=$2 AS healthy FROM executions e LEFT JOIN nodes n ON n.id=e.node_id WHERE e.id=$1",args![binding["execution_id"],HOST_CONFINEMENT]).await? {
                if app["configuration"]["keep_warm"]==false && release["state"]=="ready" && binding["expired"]==true {
                    Self::http_failure(tx,&app,"http-readiness-timeout").await?;
                    exec(tx,"UPDATE executions SET desired='stopped',generation=generation+1,updated=now() WHERE id=$1 AND reserved AND desired<>'stopped'",args![e["id"]]).await?;
                    if e["node_id"].is_null() {exec(tx,"UPDATE executions SET state='stopped',reserved=false,finished_at=now() WHERE id=$1",args![e["id"]]).await?;}
                    continue;
                }
                // A node says a run is running when its VM starts. An app
                // serves once its shim asks the run channel for a request,
                // which it does only when the component is loaded; one that
                // was serving stays so while its shim is briefly not asking.
                let taking=self.run_channel.is_none() || binding["state"]=="serving" || self.exchange.ready(s(&e["id"]));
                if e["state"]=="running" && e["desired"]=="running" && e["reserved"]==true && e["healthy"]==true && taking {
                    if binding["state"]=="serving" && app["configuration"]["keep_warm"]==false
                        && one(tx,"SELECT $1::timestamptz<now()-interval '60 seconds' AND NOT EXISTS(SELECT 1 FROM ingress_reservations WHERE execution_id=$2 OR app_id=$3) AS idle",args![binding["last_activity"],e["id"],app_id]).await?["idle"]==true
                        // And nothing of it in the gateway's memory that a
                        // flush has yet to write: its gate closes with that.
                        && self.gateway.gates.close_if_idle(app_id) {
                        // Idle teardown has no forced deadline: the execution is
                        // stopped once it holds no request.
                        exec(tx,"UPDATE app_http SET state='stopping',reason='idle-drain',idle_draining=true,drain_until=NULL,updated=now() WHERE app_id=$1",args![app_id]).await?;
                        exec(tx,"UPDATE deployments SET desired='stopped' WHERE id=$1",args![binding["deployment_id"]]).await?;
                        let mut drain=binding.clone();drain["drain_until"]=Value::Null;
                        self.drain_http(tx,&drain).await?;
                        continue;
                    }
                    if binding["state"]!="serving" {exec(tx,"UPDATE app_http SET last_activity=now() WHERE app_id=$1",args![app_id]).await?;}
                    Self::http_state(tx,app_id,"serving",None).await?;
                    exec(tx,"UPDATE app_http SET ready_until=NULL WHERE app_id=$1 AND ready_until IS NOT NULL",args![app_id]).await?;
                    exec(tx,"UPDATE app_releases SET state='ready',reason=NULL,updated=now() WHERE id=$1 AND state='preparing'",args![release["id"]]).await?;
                    exec(tx,"UPDATE apps SET active_release_id=$1,updated=now() WHERE id=$2 AND active_release_id IS DISTINCT FROM $1",args![release["id"],app_id]).await?;
                    if binding["reset_failures"]==true {exec(tx,"UPDATE app_http SET failures=0,failure_window=now() WHERE app_id=$1",args![app_id]).await?;}
                    self.scale_http(tx,&app,&binding,&release,&e).await?;
                    continue;
                }
                if terminal(s(&e["state"])) && e["reserved"]==false {
                    if release["state"]=="preparing" {Self::http_failure(tx,&app,"http-startup-failed").await?;continue;}
                    let failures=if binding["reset_failures"]==true {0} else {n(&binding["failures"])};
                    if binding["restart_after"].is_null() {
                        if failures+1>=3 {Self::http_failure(tx,&app,"http-restart-limit").await?;continue;}
                        exec(tx,"UPDATE app_http SET failures=$1,restart_after=now()+interval '5 seconds',failure_window=CASE WHEN $2 THEN now() ELSE failure_window END,state='starting',reason='restarting-http',updated=now() WHERE app_id=$3",args![failures+1,binding["reset_failures"],app_id]).await?;
                    } else if binding["retry_due"]==true {
                        if n(&binding["generation"])>=i32::MAX as i64 {Self::http_failure(tx,&app,"http-generation-limit").await?;continue;}
                        exec(tx,"UPDATE app_http SET generation=generation+1,execution_id=NULL,restart_after=NULL,ready_until=now()+interval '5 minutes',updated=now() WHERE app_id=$1",args![app_id]).await?;
                    }
                    continue;
                }
                if binding["expired"]==true {
                    Self::http_failure(tx,&app,"http-readiness-timeout").await?;
                    exec(tx,"UPDATE executions SET desired='stopped',generation=generation+1,updated=now() WHERE id=$1 AND reserved AND desired<>'stopped'",args![e["id"]]).await?;
                    if e["node_id"].is_null() {exec(tx,"UPDATE executions SET state='stopped',reserved=false,finished_at=now() WHERE id=$1",args![e["id"]]).await?;}
                } else {
                    let reason=if e["state"]=="unreachable" {"worker-unreachable"} else if e["node_id"].is_null() {"waiting-for-capacity"} else {"starting-http"};
                    Self::http_state(tx,app_id,if e["state"]=="unreachable" {"unavailable"} else {"starting"},Some(reason)).await?;
                }
                continue;
            }
            if binding["expired"]==true {Self::http_failure(tx,&app,"http-readiness-timeout").await?;continue;}
            if release["inspection"]["http"]!=true {Self::http_failure(tx,&app,"incompatible-http-entry-point").await?;continue;}
            let spec=crate::app_runtime::http_spec(release["spec"].clone(),&release["configuration"])?;
            if let Err(error)=self.check_refs(tx,s(&app["tenant_id"]),s(&app["project_id"]),&spec).await {
                if matches!(error.status,StatusCode::BAD_REQUEST|StatusCode::NOT_FOUND) {Self::http_failure(tx,&app,"configuration-unavailable").await?;continue;}
                return Err(error);
            }
            let deployment=if let Some(id)=binding["deployment_id"].as_str() {id.to_owned()} else {
                let id=uid();
                exec(tx,"INSERT INTO deployments(id,tenant_id,project_id,name,spec,desired) VALUES($1,$2,$3,$4,$5,'stopped')",args![id,app["tenant_id"],app["project_id"],format!("app-{id}"),spec]).await?;
                exec(tx,"INSERT INTO routes(id,tenant_id,project_id,hostname,deployment_id) VALUES($1,$2,$3,$4,$5)",args![uid(),app["tenant_id"],app["project_id"],binding["hostname"],id]).await?;
                exec(tx,"UPDATE app_http SET deployment_id=$1 WHERE app_id=$2",args![id,app_id]).await?;
                id
            };
            exec(tx,"UPDATE deployments SET spec=$1,revision=$2,desired='running' WHERE id=$3",args![spec,binding["generation"],deployment]).await?;
            match Self::execution(tx,s(&app["tenant_id"]),s(&app["project_id"]),&spec,Some(&deployment),n(&binding["generation"])).await {
                Ok(e)=>{
                    Self::record_app_connections(tx,app_id,&e).await?;
                    exec(tx,"INSERT INTO app_http_attempts(execution_id,tenant_id,project_id,app_id,release_id,generation) VALUES($1,$2,$3,$4,$5,$6)",args![e["id"],app["tenant_id"],app["project_id"],app_id,release["id"],binding["generation"]]).await?;
                    exec(tx,"UPDATE app_http SET execution_id=$1,state='starting',reason='waiting-for-capacity',updated=now() WHERE app_id=$2",args![e["id"],app_id]).await?;
                },
                Err(e) if e.status==StatusCode::TOO_MANY_REQUESTS=>{Self::http_state(tx,app_id,"starting",Some("allowance-exhausted")).await?;},
                Err(e)=>return Err(e),
            }
        }
        exec(tx,"UPDATE operations o SET state=CASE WHEN h.blocked THEN 'failed' ELSE 'succeeded' END,error=CASE WHEN h.blocked THEN h.reason ELSE NULL END,updated=now() FROM app_http_operations x JOIN app_http h ON h.app_id=x.app_id AND h.generation=x.generation WHERE o.id=x.operation_id AND o.state='pending' AND o.kind<>'app-connections' AND ((h.state IN ('serving','disabled','idle') AND h.candidate_until IS NULL) OR h.blocked)",args![]).await?;
        Self::reconcile_app_connections(tx).await?;
        Ok(())
    }

    /// Stops the executions of an app's deployment that are neither the one
    /// its binding names, nor a candidate, nor its extras: each when it
    /// holds no request, or when the binding's drain deadline has passed.
    async fn drain_others(&self, tx: &mut Tx, binding: &Value) -> Result<()> {
        let others=rows(tx,"SELECT e.id,e.node_id,e.state,COALESCE($5::timestamptz<=now(),true) AS deadline,COALESCE($5::timestamptz-interval '26 seconds'<=now(),true) AS settled FROM executions e WHERE e.deployment_id=$1 AND e.reserved AND e.desired<>'stopped' AND e.id IS DISTINCT FROM $2 AND e.id IS DISTINCT FROM $3 AND e.id NOT IN (SELECT execution_id FROM app_http_extras WHERE app_id=$4)",args![binding["deployment_id"],binding["execution_id"],binding["candidate_execution_id"],binding["app_id"],binding["drain_until"]]).await?;
        for e in &others {
            if e["node_id"].is_null() {
                exec(tx,"UPDATE executions SET desired='stopped',state='stopped',reserved=false,generation=generation+1,finished_at=now(),updated=now() WHERE id=$1",args![e["id"]]).await?;
                continue;
            }
            let busy = self.exchange.busy(s(&e["id"]))
                || optional(
                    tx,
                    "SELECT id FROM ingress_reservations WHERE execution_id=$1 LIMIT 1",
                    args![e["id"]],
                )
                .await?
                .is_some();
            // For the first seconds after a candidate took over, an ask the
            // old execution made before that may still be given a request:
            // it is not stopped as idle until that can no longer happen.
            if e["deadline"] == true || (!busy && e["settled"] == true) {
                exec(tx,"UPDATE executions SET desired='stopped',generation=generation+1,updated=now() WHERE id=$1",args![e["id"]]).await?;
            }
        }
        Ok(())
    }

    /// Brings up the next generation's execution beside the one that
    /// serves, and has it take over once it is ready: running, and its shim
    /// asking. If it never is, the release is failed and the app goes on as
    /// it was. If the workspace's allowance has no room for both, or the
    /// no node has had room for it within ten seconds, or the app is no
    /// longer to serve, the old way is taken: stop, then start.
    async fn replace_http(
        &self,
        tx: &mut Tx,
        app: &Value,
        binding: &Value,
        want: bool,
    ) -> Result<()> {
        let app_id = s(&app["id"]);
        let sequential = "UPDATE app_http SET state='stopping',reason='draining-http',drain_until=now()+interval '30 seconds',ready_until=now()+interval '5 minutes',execution_id=NULL,candidate_execution_id=NULL,candidate_until=NULL,updated=now() WHERE app_id=$1";
        let stop = "UPDATE executions SET desired='stopped',generation=generation+1,updated=now() WHERE id=$1 AND reserved AND desired<>'stopped'";
        if !want {
            exec(tx, sequential, args![app_id]).await?;
            exec(
                tx,
                "UPDATE deployments SET desired='stopped' WHERE id=$1",
                args![binding["deployment_id"]],
            )
            .await?;
            return Ok(());
        }
        let release=one(tx,"SELECT l.*,v.inspection FROM app_releases l JOIN app_versions v ON v.id=l.version_id WHERE l.id=$1",args![app["target_release_id"]]).await?;
        let failed = if release["state"] == "failed" {
            Some("superseded")
        } else if release["inspection"]["http"] != true {
            Some("incompatible-http-entry-point")
        } else if binding["candidate_execution_id"].is_null() {
            // An earlier change's candidate may still be stopping.
            self.drain_others(tx, binding).await?;
            let spec =
                crate::app_runtime::http_spec(release["spec"].clone(), &release["configuration"])?;
            match self
                .check_refs(tx, s(&app["tenant_id"]), s(&app["project_id"]), &spec)
                .await
            {
                Err(error)
                    if matches!(
                        error.status,
                        StatusCode::BAD_REQUEST | StatusCode::NOT_FOUND
                    ) =>
                {
                    Some("configuration-unavailable")
                }
                Err(error) => return Err(error),
                Ok(()) => {
                    exec(
                        tx,
                        "UPDATE deployments SET spec=$1,revision=$2,desired='running' WHERE id=$3",
                        args![spec, binding["generation"], binding["deployment_id"]],
                    )
                    .await?;
                    match Self::execution(
                        tx,
                        s(&app["tenant_id"]),
                        s(&app["project_id"]),
                        &spec,
                        binding["deployment_id"].as_str(),
                        n(&binding["generation"]),
                    )
                    .await
                    {
                        Ok(e) => {
                            Self::record_app_connections(tx, app_id, &e).await?;
                            exec(tx,"INSERT INTO app_http_attempts(execution_id,tenant_id,project_id,app_id,release_id,generation) VALUES($1,$2,$3,$4,$5,$6)",args![e["id"],app["tenant_id"],app["project_id"],app_id,release["id"],binding["generation"]]).await?;
                            exec(tx,"UPDATE app_http SET candidate_execution_id=$1,updated=now() WHERE app_id=$2",args![e["id"],app_id]).await?;
                        }
                        // No room for both: stop the old, then start the new.
                        Err(e) if e.status == StatusCode::TOO_MANY_REQUESTS => {
                            exec(tx, sequential, args![app_id]).await?;
                            exec(
                                tx,
                                "UPDATE deployments SET desired='stopped' WHERE id=$1",
                                args![binding["deployment_id"]],
                            )
                            .await?;
                        }
                        Err(e) => return Err(e),
                    }
                    None
                }
            }
        } else {
            let candidate = &binding["candidate_execution_id"];
            let e=one(tx,"SELECT e.*,n.last_seen>now()-interval '15 seconds' AND NOT n.disabled AND n.observed_confinement=$2 AS healthy,$3::timestamptz<=now() AS overdue,e.created<now()-interval '10 seconds' AS waited FROM executions e LEFT JOIN nodes n ON n.id=e.node_id WHERE e.id=$1",args![candidate,HOST_CONFINEMENT,binding["candidate_until"]]).await?;
            let taking = self.run_channel.is_none() || self.exchange.ready(s(candidate));
            if e["state"] == "running"
                && e["desired"] == "running"
                && e["reserved"] == true
                && e["healthy"] == true
                && taking
            {
                // It takes over. Asks waiting on either queue are told to
                // ask again, so the old execution takes nothing more and
                // the new one takes from the app's queue.
                exec(tx,"UPDATE app_http SET execution_id=$1,candidate_execution_id=NULL,candidate_until=NULL,state='serving',reason=NULL,ready_until=NULL,drain_until=now()+interval '30 seconds',last_activity=now(),updated=now() WHERE app_id=$2",args![candidate,app_id]).await?;
                exec(tx,"UPDATE app_releases SET state='ready',reason=NULL,updated=now() WHERE id=$1 AND state='preparing'",args![release["id"]]).await?;
                exec(tx,"UPDATE apps SET active_release_id=$1,updated=now() WHERE id=$2 AND active_release_id IS DISTINCT FROM $1",args![release["id"],app_id]).await?;
                // They are told once this change is committed (a moment
                // from now) and again a little later: an ask made before
                // the commit is still answered by what was true before it.
                let exchange = self.exchange.clone();
                let keys = [
                    crate::run_channel::candidate_key(s(candidate)),
                    app_id.to_owned(),
                ];
                tokio::spawn(async move {
                    for wait in [200, 800, 2000] {
                        tokio::time::sleep(std::time::Duration::from_millis(wait)).await;
                        keys.iter().for_each(|key| exchange.close(key));
                    }
                });
                None
            } else if e["node_id"].is_null() && e["reserved"] == true && e["waited"] == true {
                // No node has had room for it beside the one that serves:
                // stop the old, then start the new.
                exec(tx,"UPDATE executions SET desired='stopped',state='stopped',reserved=false,generation=generation+1,finished_at=now(),updated=now() WHERE id=$1",args![candidate]).await?;
                exec(tx, sequential, args![app_id]).await?;
                exec(
                    tx,
                    "UPDATE deployments SET desired='stopped' WHERE id=$1",
                    args![binding["deployment_id"]],
                )
                .await?;
                None
            } else if terminal(s(&e["state"])) && e["reserved"] == false {
                Some("http-startup-failed")
            } else if e["overdue"] == true {
                Some("http-readiness-timeout")
            } else {
                None
            }
        };
        if let Some(reason) = failed {
            // The app goes on as it was; the release and its operation fail.
            exec(tx, stop, args![binding["candidate_execution_id"]]).await?;
            exec(tx,"UPDATE executions SET state='stopped',reserved=false,finished_at=now() WHERE id=$1 AND node_id IS NULL AND reserved",args![binding["candidate_execution_id"]]).await?;
            exec(tx,"UPDATE app_releases SET state='failed',reason=$1,updated=now() WHERE id=$2 AND state='preparing'",args![reason,release["id"]]).await?;
            exec(tx,"UPDATE operations o SET state='failed',error=$1,updated=now() FROM app_http_operations x WHERE x.operation_id=o.id AND x.app_id=$2 AND x.generation=$3 AND o.state='pending' AND o.kind<>'app-connections'",args![reason,app_id,binding["generation"]]).await?;
            exec(tx,"UPDATE app_http SET candidate_execution_id=NULL,candidate_until=NULL,reason=NULL,updated=now() WHERE app_id=$1",args![app_id]).await?;
        }
        Ok(())
    }

    /// Gives a serving app more executions while its requests wait or all
    /// its executions are busy, up to its `scale.max`, and stops the extra
    /// ones that have had nothing to do, down to its `scale.min`. One is
    /// started at a time; each is created like the first, so the workspace's
    /// compute allowance is checked for it.
    async fn scale_http(
        &self,
        tx: &mut Tx,
        app: &Value,
        binding: &Value,
        release: &Value,
        primary: &Value,
    ) -> Result<()> {
        let app_id = s(&app["id"]);
        let scale = &app["configuration"]["scale"];
        let max = scale["max"].as_i64().unwrap_or(1);
        let keep = (scale["min"].as_i64().unwrap_or(1) - 1).max(0);
        let extras = rows(tx,"SELECT e.id,e.node_id,e.created<now()-interval '5 minutes' AS overdue FROM app_http_extras x JOIN executions e ON e.id=x.execution_id WHERE x.app_id=$1 AND x.generation=$2 AND e.reserved AND e.desired='running' ORDER BY e.created",args![app_id,binding["generation"]]).await?;
        if max <= 1 && extras.is_empty() {
            return Ok(());
        }
        let pressure = self.exchange.pressure(app_id);
        let pressed = pressure.waiting.is_some_and(|d| d >= SCALE_WAITING)
            || pressure.saturated.is_some_and(|d| d >= SCALE_SATURATED);
        let (mut live, mut starting, mut stopping) = (0i64, false, Vec::new());
        for extra in &extras {
            let id = s(&extra["id"]);
            if !self.exchange.ready(id) {
                // Not asking yet: starting, unless it has taken too long.
                if extra["overdue"] == true {
                    stopping.push(extra);
                } else {
                    starting = true;
                    live += 1;
                }
            } else if 1 + live >= max
                || (!pressed
                    && live >= keep
                    && self.exchange.idle(id).is_some_and(|d| d >= SCALE_IDLE))
            {
                // Over the maximum, or with nothing to do beyond the minimum.
                stopping.push(extra);
            } else {
                live += 1;
            }
        }
        for extra in stopping {
            if extra["node_id"].is_null() {
                exec(tx,"UPDATE executions SET desired='stopped',state='stopped',reserved=false,generation=generation+1,finished_at=now(),updated=now() WHERE id=$1",args![extra["id"]]).await?;
            } else {
                exec(tx,"UPDATE executions SET desired='stopped',generation=generation+1,updated=now() WHERE id=$1 AND reserved AND desired<>'stopped'",args![extra["id"]]).await?;
            }
        }
        if 1 + live < max
            && !starting
            && (pressed || live < keep)
            && release["state"] == "ready"
            && self.exchange.ready(s(&primary["id"]))
        {
            match Self::execution(
                tx,
                s(&app["tenant_id"]),
                s(&app["project_id"]),
                &primary["spec"],
                binding["deployment_id"].as_str(),
                n(&binding["generation"]),
            )
            .await
            {
                Ok(e) => {
                    Self::record_app_connections(tx, app_id, &e).await?;
                    exec(tx,"INSERT INTO app_http_attempts(execution_id,tenant_id,project_id,app_id,release_id,generation) VALUES($1,$2,$3,$4,$5,$6)",args![e["id"],app["tenant_id"],app["project_id"],app_id,release["id"],binding["generation"]]).await?;
                    exec(tx,"INSERT INTO app_http_extras(execution_id,app_id,tenant_id,project_id,generation) VALUES($1,$2,$3,$4,$5)",args![e["id"],app_id,app["tenant_id"],app["project_id"],binding["generation"]]).await?;
                }
                // The allowance has no room: the app stays at its size.
                Err(e) if e.status == StatusCode::TOO_MANY_REQUESTS => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    pub(crate) async fn wake_http(tx: &mut Tx, app: &str) -> Result<()> {
        // Observing an already-enabled app may have joined its idle drain. That
        // operation completes before a queued request advances the generation.
        Self::reconcile_app_connections(tx).await?;
        exec(tx,"UPDATE operations o SET state='succeeded',updated=now() FROM app_http_operations x JOIN app_http h ON h.app_id=x.app_id AND h.generation=x.generation WHERE h.app_id=$1 AND h.state='idle' AND NOT h.blocked AND o.id=x.operation_id AND o.state='pending' AND o.kind<>'app-connections'",args![app]).await?;
        // One generation transition per wake, serialized with admission and stop.
        exec(tx,"UPDATE app_http h SET generation=generation+1,state='starting',reason='waking-http',ready_until=now()+interval '10 seconds',restart_after=NULL,updated=now() FROM apps a JOIN app_triggers t ON t.app_id=a.id WHERE h.app_id=a.id AND a.id=$1 AND a.desired='enabled' AND EXISTS(SELECT 1 FROM tenants tenant WHERE tenant.id=a.tenant_id AND tenant.lifecycle_state='active') AND t.http AND h.state='idle' AND NOT h.blocked AND h.generation<2147483647 AND EXISTS(SELECT 1 FROM ingress_reservations q WHERE q.app_id=a.id AND q.execution_id IS NULL AND q.release_id=a.target_release_id AND q.app_revision=a.revision AND q.expires>now())",args![app]).await?;
        Ok(())
    }

    pub async fn app_http_status(
        &self,
        p: &Principal,
        tenant: &str,
        project: &str,
        app: &str,
    ) -> Result<Value> {
        let mut tx = self.transaction(false, false).await?;
        Self::project(&mut tx, p, tenant, project, false).await?;
        Self::app_row(&mut tx, tenant, project, app).await?;
        let row = optional(
            &mut tx,
            "SELECT hostname,execution_id,state,reason FROM app_http_observations WHERE app_id=$1",
            args![app],
        )
        .await?;
        let mut value = row.map(|r|json!({"url":format!("https://{}",s(&r["hostname"])),"state":r["state"],"reason":r["reason"],"execution_id":r["execution_id"]})).unwrap_or(json!({"url":null,"state":"disabled","reason":null,"execution_id":null}));
        // How many executions serve it now: its first, and the extras of
        // this generation that are running.
        let extras = one(&mut tx,"SELECT count(*) n FROM app_http_extras x JOIN app_http h ON h.app_id=x.app_id AND x.generation=h.generation-CASE WHEN h.candidate_until IS NOT NULL THEN 1 ELSE 0 END JOIN executions e ON e.id=x.execution_id WHERE x.app_id=$1 AND e.reserved AND e.desired='running' AND e.state='running'",args![app]).await?;
        value["executions"] = json!(if value["state"] == "serving" {
            1 + n(&extras["n"])
        } else {
            0
        });
        crate::placement::project(&mut tx, tenant, project, std::slice::from_mut(&mut value))
            .await?;
        crate::app_diagnostics::decorate(&mut value);
        Ok(value)
    }
}
