//! Customer connection intent is independent of code history. Each execution
//! pins the connections it was launched with; removing one stops the runs
//! that hold it, so remove/re-add cannot reauthorize an old run.
use crate::{
    args,
    db::*,
    error::{Error, Result},
    model::*,
    store::{Store, Tx},
    workloads::wasm_spec,
};
use serde_json::{Value, json};
use std::collections::BTreeSet;

fn selections(value: &Value) -> Result<Vec<Value>> {
    let mut entries = value
        .as_array()
        .filter(|v| v.len() <= 32)
        .ok_or_else(|| Error::invalid("expected at most 32 service connections"))?
        .clone();
    let mut seen = BTreeSet::new();
    for entry in &mut entries {
        fields(entry, &["endpoint_id", "prefix"], &["endpoint_id"])?;
        id(&entry["endpoint_id"])?;
        if !seen.insert(s(&entry["endpoint_id"]).to_owned()) {
            return Err(Error::invalid("duplicate service connection"));
        }
        let prefix = get(entry, "prefix", json!(""));
        let prefix = text(&prefix)?;
        if prefix.len() > 16 || !prefix.bytes().all(|b| b.is_ascii_uppercase() || b == b'_') {
            return Err(Error::invalid(
                "connection prefix must be up to 16 uppercase letters or underscores",
            ));
        }
        entry["prefix"] = json!(prefix);
    }
    entries.sort_by(|a, b| s(&a["endpoint_id"]).cmp(s(&b["endpoint_id"])));
    Ok(entries)
}

impl Store {
    /// Resolve the public connection list inside the admitting transaction.
    /// An omitted list preserves legacy input semantics; an empty list removes
    /// both HTTPS and TCP access. Catalog registration itself grants nothing.
    pub(crate) async fn customer_connections(
        tx: &mut Tx,
        tenant: &str,
        project: &str,
        value: &Value,
    ) -> Result<Option<(Value, Value)>> {
        let Some(entries) = value.get("connections") else {
            return Ok(None);
        };
        if value.get("endpoints").is_some() || value.get("https_origins").is_some() {
            return Err(Error::invalid(
                "use connections or legacy connection fields, not both",
            ));
        }
        let entries = entries
            .as_array()
            .filter(|a| a.len() <= 32)
            .ok_or_else(|| Error::invalid("expected at most 32 connections"))?;
        let mut ids = BTreeSet::new();
        let mut tcp = Vec::new();
        let mut https = Vec::new();
        for entry in entries {
            fields(entry, &["connection_id", "prefix"], &["connection_id"])?;
            let connection = id(&entry["connection_id"])?;
            if !ids.insert(connection.to_owned()) {
                return Err(Error::invalid("duplicate connection"));
            }
            if let Some(row) = optional(tx,"SELECT origin FROM external_https_endpoints WHERE tenant_id=$1 AND project_id=$2 AND id=$3 AND NOT deleted",args![tenant,project,connection]).await? {
                if entry.get("prefix").is_some_and(|v| v != "") { return Err(Error::invalid("HTTPS connections do not have environment prefixes")); }
                https.push(row["origin"].clone());
            } else {
                one(tx,"SELECT id FROM external_endpoints WHERE tenant_id=$1 AND project_id=$2 AND id=$3 AND NOT deleted",args![tenant,project,connection]).await?;
                tcp.push(json!({"endpoint_id":connection,"prefix":get(entry,"prefix",json!(""))}));
            }
        }
        let tcp = selections(&json!(tcp))?;
        https.sort_by(|a, b| s(a).cmp(s(b)));
        https.dedup();
        Ok(Some((json!(tcp), json!(https))))
    }

    /// Enrich only the authorized, already-paginated app page in two bounded queries.
    /// Full counts survive the three-item display bound and include revocations.
    pub(crate) async fn summarize_app_connections(
        tx: &mut Tx,
        tenant: &str,
        project: &str,
        apps: &mut [Value],
    ) -> Result<()> {
        if apps.is_empty() {
            return Ok(());
        }
        let ids = apps.iter().map(|app| app["id"].clone()).collect::<Vec<_>>();
        let values = rows(tx, "SELECT app_id,jsonb_build_object('total',count(*),'allowed',count(*) FILTER(WHERE state='allowed'),'pending',count(*) FILTER(WHERE state='pending'),'revoking',count(*) FILTER(WHERE state='revoking'),'items',jsonb_agg(jsonb_build_object('id',id,'endpoint_id',endpoint_id,'name',name,'prefix',prefix,'state',state,'reason',reason,'desired',desired) ORDER BY ordinal) FILTER(WHERE ordinal<=3)) AS summary FROM (SELECT o.*,row_number() OVER(PARTITION BY app_id ORDER BY name,created,id) ordinal FROM app_connection_observations o WHERE tenant_id=$1 AND project_id=$2 AND app_id IN (SELECT jsonb_array_elements_text($3::jsonb))) ranked GROUP BY app_id", args![tenant,project,json!(ids)]).await?;
        let mut summaries = values
            .into_iter()
            .map(|row| (s(&row["app_id"]).to_owned(), row["summary"].clone()))
            .collect::<std::collections::BTreeMap<_, _>>();
        let https = rows(tx,"SELECT app_id,jsonb_build_object('total',count(*),'destinations',count(DISTINCT origin),'allowed',count(*) FILTER(WHERE state='allowed'),'pending',count(*) FILTER(WHERE state='pending'),'revoking',count(*) FILTER(WHERE state='revoking'),'items',jsonb_agg(jsonb_build_object('id',id,'origin',origin,'state',state,'reason',reason,'desired',desired) ORDER BY ordinal) FILTER(WHERE ordinal<=3)) summary FROM (SELECT o.*,row_number() OVER(PARTITION BY app_id ORDER BY origin,created,id) ordinal FROM app_https_observations o WHERE tenant_id=$1 AND project_id=$2 AND app_id IN(SELECT jsonb_array_elements_text($3::jsonb))) ranked GROUP BY app_id",args![tenant,project,json!(ids)]).await?;
        let mut https_summaries = https
            .into_iter()
            .map(|row| (s(&row["app_id"]).to_owned(), row["summary"].clone()))
            .collect::<std::collections::BTreeMap<_, _>>();
        for app in apps {
            app["https_connections"] = https_summaries.remove(s(&app["id"])).unwrap_or_else(
                || json!({"total":0,"destinations":0,"allowed":0,"pending":0,"revoking":0,"items":[]}),
            );
            app["connections"] = summaries.remove(s(&app["id"])).unwrap_or_else(
                || json!({"total":0,"allowed":0,"pending":0,"revoking":0,"items":[]}),
            );
        }
        Ok(())
    }

    pub(crate) async fn compose_app_connections(
        tx: &mut Tx,
        app: &str,
        mut spec: Value,
    ) -> Result<Value> {
        let connections = rows(tx,"SELECT c.prefix,e.* FROM app_endpoint_connections c JOIN external_endpoints e ON e.id=c.endpoint_id WHERE c.app_id=$1 AND c.state='active' ORDER BY e.id",args![app]).await?;
        if connections.is_empty() {
            return Ok(spec);
        }
        spec["network_id"] = connections[0]["network_id"].clone();
        spec["endpoint_ids"] = json!([]);
        spec["endpoint_env"] = json!({});
        for c in connections {
            if b(&c["deleted"]) || spec["network_id"] != c["network_id"] {
                return Err(conflict("external connection is unavailable"));
            }
            spec["endpoint_ids"]
                .as_array_mut()
                .unwrap()
                .push(c["id"].clone());
            for (name, source) in crate::external_endpoints::connection_fields(&c) {
                let variable = format!("{}{name}", s(&c["prefix"]));
                if ["env", "secret_env", "endpoint_env"]
                    .iter()
                    .any(|field| spec[*field].get(&variable).is_some())
                {
                    return Err(Error::invalid(
                        "connection variables conflict with another setting; choose a prefix",
                    ));
                }
                if source["kind"] == "secret" {
                    spec["secret_env"][&variable] = source["id"].clone();
                } else {
                    spec["env"][&variable] = source["value"].clone();
                }
            }
        }
        Ok(wasm_spec(&spec, false)?)
    }

    pub(crate) async fn initial_app_connections(
        tx: &mut Tx,
        app: &Value,
        value: &Value,
    ) -> Result<()> {
        for selected in selections(value)? {
            Self::insert_app_connection(tx, app, &selected).await?;
        }
        Ok(())
    }
    async fn insert_app_connection(tx: &mut Tx, app: &Value, selected: &Value) -> Result<()> {
        one(tx,"SELECT id FROM external_endpoints WHERE id=$1 AND tenant_id=$2 AND project_id=$3 AND NOT deleted",args![selected["endpoint_id"],app["tenant_id"],app["project_id"]]).await?;
        if one(
            tx,
            "SELECT count(*) n FROM app_endpoint_connections WHERE app_id=$1",
            args![app["id"]],
        )
        .await?["n"]
            .as_i64()
            .unwrap_or(0)
            >= 1024
        {
            return Err(quota("app connection history limit reached"));
        }
        exec(tx,"INSERT INTO app_endpoint_connections(id,tenant_id,project_id,app_id,endpoint_id,prefix) VALUES($1,$2,$3,$4,$5,$6)",args![uid(),app["tenant_id"],app["project_id"],app["id"],selected["endpoint_id"],selected["prefix"]]).await?;
        Ok(())
    }

    pub async fn app_connections(
        &self,
        p: &Principal,
        tenant: &str,
        project: &str,
        app: &str,
    ) -> Result<Value> {
        let mut tx = self.transaction(false, false).await?;
        Self::project(&mut tx, p, tenant, project, false).await?;
        let app_row = Self::app_row(&mut tx, tenant, project, app).await?;
        let values=rows(&mut tx,"SELECT o.*,e.host,host(e.address) address,e.port,e.database,e.username_secret_id,e.password_secret_id,e.ca_certificate FROM app_connection_observations o JOIN external_endpoints e ON e.id=o.endpoint_id WHERE o.tenant_id=$1 AND o.project_id=$2 AND o.app_id=$3 ORDER BY o.name,o.created,o.id",args![tenant,project,app]).await?;
        let mut items = Vec::new();
        for c in values {
            let fields=crate::external_endpoints::connection_fields(&c).into_iter().map(|(name,source)| json!({"name":format!("{}{name}",s(&c["prefix"])),"source":source})).collect::<Vec<_>>();
            items.push(json!({"id":c["id"],"endpoint_id":c["endpoint_id"],"name":c["name"],"prefix":c["prefix"],"desired":c["desired"],"state":c["state"],"reason":c["reason"],"fields":fields,"revocation_operation_id":c["revocation_operation_id"],"updated":c["updated"]}));
        }
        Ok(
            json!({"revision":app_row["revision"],"items":items,"https_origins":Self::https_items(&mut tx,app).await?}),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn update_app_connections(
        &self,
        p: &Principal,
        tenant: &str,
        project: &str,
        app: &str,
        value: Value,
        key: &str,
    ) -> Result<Value> {
        fields(
            &value,
            &[
                "expected_revision",
                "connections",
                "endpoints",
                "https_origins",
            ],
            &["expected_revision"],
        )?;
        integer(&value["expected_revision"], 1, i64::MAX - 1)?;
        if value.get("connections").is_none() && value.get("endpoints").is_none() {
            return Err(Error::invalid("connections are required"));
        }
        let mut selected = selections(&get(&value, "endpoints", json!([])))?;

        let mut https = value
            .get("https_origins")
            .map(crate::app_https::origins)
            .transpose()?;
        let mut request = json!({"kind":"app-connections","app_id":app,"expected_revision":value["expected_revision"],"endpoints":selected});
        if let Some(connections) = value.get("connections") {
            request["connections"] = connections.clone();
        }
        if let Some(origins) = &https {
            request["https_origins"] = json!(origins);
        }
        let mut tx = self.transaction(true, false).await?;
        Self::project(&mut tx, p, tenant, project, true).await?;
        let row = Self::app_row(&mut tx, tenant, project, app).await?;
        if let Some(op) = Self::idem(&mut tx, tenant, project, key, &request).await? {
            return Ok(op);
        }
        if let Some((tcp, origins)) =
            Self::customer_connections(&mut tx, tenant, project, &value).await?
        {
            selected = selections(&tcp)?;
            https = Some(crate::app_https::origins(&origins)?);
        }
        if row["revision"] != value["expected_revision"] {
            return Err(
                conflict("app revision changed; reload before saving").coded("revision_conflict")
            );
        }
        let old=rows(&mut tx,"SELECT * FROM app_endpoint_connections WHERE app_id=$1 AND state='active' ORDER BY endpoint_id",args![app]).await?;
        let op = Self::operation(
            &mut tx,
            tenant,
            project,
            key,
            &request,
            app,
            "app-connections",
        )
        .await?;
        let same = |c: &Value, v: &Value| {
            c["endpoint_id"] == v["endpoint_id"] && c["prefix"] == v["prefix"]
        };
        let https_changed = if let Some(origins) = &https {
            self.update_app_https(&mut tx, &row, origins, s(&op["id"]))
                .await?
        } else {
            false
        };
        let changed = https_changed
            || old.len() != selected.len()
            || old.iter().zip(&selected).any(|(c, v)| !same(c, v));
        if changed {
            for connection in old.iter().filter(|c| !selected.iter().any(|v| same(c, v))) {
                Self::withdraw_app_connection(&mut tx, connection, s(&op["id"])).await?;
            }
            for entry in selected.iter().filter(|v| !old.iter().any(|c| same(c, v))) {
                Self::insert_app_connection(&mut tx, &row, entry).await?;
            }
            Self::cancel_schedule_dispatch(&mut tx, app, "connections-changed").await?;
            if row["target_release_id"].is_null() {
                let code = one(&mut tx, "SELECT artifact_id FROM app_versions WHERE app_id=$1 ORDER BY number DESC LIMIT 1", args![app]).await?;
                let spec = Self::compose_app_connections(
                    &mut tx,
                    app,
                    crate::app_runtime::command_spec(
                        s(&code["artifact_id"]),
                        &row["configuration"],
                    )?,
                )
                .await?;
                self.check_refs(&mut tx, tenant, project, &spec).await?;
            } else {
                let http = one(
                    &mut tx,
                    "SELECT http FROM app_triggers WHERE app_id=$1",
                    args![app],
                )
                .await?["http"]
                    == true;
                self.copy_app_release(&mut tx, &row, http && row["desired"] == "enabled")
                    .await?;
                if Self::request_app_http(&mut tx, app, &op).await? {
                    self.reconcile_app_http(&mut tx).await?;
                }
            }
            exec(
                &mut tx,
                "UPDATE apps SET revision=revision+1,updated=now() WHERE id=$1",
                args![app],
            )
            .await?;
        }
        Self::reconcile_app_connections(&mut tx).await?;
        Self::audit(
            &mut tx,
            p,
            "app.connections",
            app,
            tenant,
            json!({"endpoints":selected,"https_origins":https,"changed":changed}),
        )
        .await?;
        let op = one(
            &mut tx,
            "SELECT * FROM operations WHERE id=$1",
            args![op["id"]],
        )
        .await?;
        tx.commit().await?;
        Ok(op)
    }

    pub(crate) async fn withdraw_app_connection(
        tx: &mut Tx,
        connection: &Value,
        operation: &str,
    ) -> Result<()> {
        exec(tx,"UPDATE app_endpoint_connections SET state='revoking',revocation_operation_id=$1,updated=now() WHERE id=$2",args![operation,connection["id"]]).await?;
        exec(tx,"UPDATE network_grants g SET state='revoking',revoked=COALESCE(revoked,now()) FROM app_execution_connections x,external_endpoints i WHERE x.connection_id=$1 AND x.execution_id=g.execution_id AND i.id=$2 AND i.id=g.endpoint_id AND g.state='active'",args![connection["id"],connection["endpoint_id"]]).await?;
        // A launch's policy is fixed, so the runs holding the connection end.
        for e in rows(tx,"SELECT e.id FROM app_execution_connections x JOIN executions e ON e.id=x.execution_id WHERE x.connection_id=$1 AND e.reserved",args![connection["id"]]).await? {
            Self::revoke_execution(tx, operation, s(&e["id"])).await?;
        }
        Ok(())
    }

    pub(crate) async fn record_app_connections(
        tx: &mut Tx,
        app: &str,
        execution: &Value,
    ) -> Result<()> {
        let connections=rows(tx,"SELECT c.*,i.id AS endpoint_id FROM app_endpoint_connections c JOIN external_endpoints i ON i.id=c.endpoint_id WHERE c.app_id=$1 AND c.state='active' AND NOT i.deleted ORDER BY i.id",args![app]).await?;
        let services = get(&execution["spec"], "endpoint_ids", json!([]));
        if json!(
            connections
                .iter()
                .map(|c| c["endpoint_id"].clone())
                .collect::<Vec<_>>()
        ) != services
        {
            return Err(conflict("release connection policy is stale"));
        }
        for c in connections {
            exec(tx,"INSERT INTO app_execution_connections(tenant_id,project_id,app_id,execution_id,connection_id) VALUES($1,$2,$3,$4,$5)",args![c["tenant_id"],c["project_id"],app,execution["id"],c["id"]]).await?;
        }
        Self::record_app_https(tx, app, s(&execution["id"])).await?;
        Self::initial_grants(
            tx,
            s(&execution["tenant_id"]),
            s(&execution["project_id"]),
            "execution",
            s(&execution["id"]),
            &execution["spec"],
        )
        .await
    }

    pub(crate) async fn check_app_connection_assignment(
        tx: &mut Tx,
        execution: &str,
    ) -> Result<()> {
        if one(tx,"SELECT EXISTS(SELECT 1 FROM app_execution_connections x JOIN app_endpoint_connections c ON c.id=x.connection_id JOIN external_endpoints i ON i.id=c.endpoint_id WHERE x.execution_id=$1 AND (c.state<>'active' OR i.deleted)) blocked",args![execution]).await?["blocked"]==true {return Err(conflict("execution connection access was withdrawn"));}
        if Self::https_connections(tx, execution)
            .await?
            .iter()
            .any(|c| c["state"] != "active")
        {
            return Err(conflict("execution HTTPS access was withdrawn"));
        }
        Ok(())
    }

    pub(crate) async fn reconcile_app_connections(tx: &mut Tx) -> Result<()> {
        exec(tx,"UPDATE app_https_connections c SET state='revoked',updated=now() WHERE state='revoking' AND NOT EXISTS(SELECT 1 FROM app_execution_https x JOIN executions e ON e.id=x.execution_id WHERE x.connection_id=c.id AND e.reserved)",args![]).await?;
        exec(tx,"UPDATE app_endpoint_connections c SET state='revoked',updated=now() WHERE state='revoking' AND NOT EXISTS(SELECT 1 FROM app_execution_connections x JOIN executions e ON e.id=x.execution_id WHERE x.connection_id=c.id AND e.reserved)",args![]).await?;
        exec(tx,"UPDATE network_grants g SET state='revoked' FROM app_execution_connections x JOIN app_endpoint_connections c ON c.id=x.connection_id JOIN external_endpoints i ON i.id=c.endpoint_id WHERE g.execution_id=x.execution_id AND g.endpoint_id=i.id AND g.state='revoking' AND c.state='revoked'",args![]).await?;
        exec(tx,"UPDATE app_http_operations x SET rollout_state=CASE WHEN h.blocked THEN 'failed' ELSE 'succeeded' END,rollout_error=CASE WHEN h.blocked THEN h.reason ELSE NULL END FROM app_http h,operations o WHERE x.operation_id=o.id AND o.kind='app-connections' AND o.state='pending' AND x.rollout_state IS NULL AND h.app_id=x.app_id AND h.generation=x.generation AND (h.state IN ('serving','disabled','idle') OR h.blocked)",args![]).await?;
        exec(tx,"UPDATE operations o SET state=COALESCE(h.rollout_state,'succeeded'),error=h.rollout_error,updated=now() FROM (SELECT q.id,x.rollout_state,x.rollout_error FROM operations q LEFT JOIN app_http_operations x ON x.operation_id=q.id WHERE q.kind='app-connections' AND q.state='pending' AND (x.operation_id IS NULL OR x.rollout_state IS NOT NULL)) h WHERE o.id=h.id AND NOT EXISTS(SELECT 1 FROM connection_revocations r JOIN executions e ON e.id=r.execution_id WHERE r.operation_id=o.id AND e.reserved)",args![]).await?;
        Ok(())
    }
}
