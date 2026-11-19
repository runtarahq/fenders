//! Edges: the processes that serve the gateway and the run channel, as
//! the operator registers them, and which apps each owns.
//!
//! An app's requests, its runs' calls and its WebSocket connections meet in
//! one process's memory, so each app is one edge's (E7). The operator
//! registers an edge (its name, the pin of the certificate it serves its
//! internal port with, and that port's address), and starts it with that
//! name (`--edge-name`). The scheduler gives an app with the HTTP trigger to
//! the live edge that owns the fewest, and moves the apps of one that is gone
//! or draining (`app_edges`). An edge serves the apps it owns, and passes
//! any other's requests to their owner ([`crate::forward`]).
//!
//! An edge started with no name owns every app, as before there were edges
//! to choose between: one edge needs no registering.
use crate::{
    args,
    db::*,
    error::{Error, Result},
    model::*,
    store::{Store, Tx},
};
use serde_json::{Value, json};

/// How many idle apps a scheduler pass moves between edges at most.
const REBALANCE_PER_PASS: i64 = 64;

pub(crate) const MIGRATION: &str = "CREATE TABLE IF NOT EXISTS edges (
    id text PRIMARY KEY CHECK(id ~ '^[a-f0-9]{32}$'),
    name text NOT NULL, cert_sha256 text NOT NULL, endpoint text NOT NULL,
    draining boolean NOT NULL DEFAULT false, deleted boolean NOT NULL DEFAULT false,
    created timestamptz NOT NULL DEFAULT clock_timestamp());
CREATE UNIQUE INDEX IF NOT EXISTS edges_name ON edges(name) WHERE NOT deleted;
CREATE UNIQUE INDEX IF NOT EXISTS edges_pin ON edges(cert_sha256) WHERE NOT deleted;
CREATE TABLE IF NOT EXISTS app_edges (
    app_id text PRIMARY KEY, edge_id text NOT NULL REFERENCES edges(id),
    revision bigint NOT NULL DEFAULT 1, updated timestamptz NOT NULL DEFAULT clock_timestamp());
CREATE INDEX IF NOT EXISTS app_edges_edge ON app_edges(edge_id);
ALTER TABLE gateway_sessions ADD COLUMN IF NOT EXISTS edge_id text;
DROP TRIGGER IF EXISTS app_edges_gates ON app_edges;
CREATE TRIGGER app_edges_gates AFTER INSERT OR DELETE OR UPDATE ON app_edges
    FOR EACH ROW EXECUTE FUNCTION fenders_gates_changed();";

/// An edge `r` as the API shows it: what it was registered with, whether
/// it drains, whether a process serves as it now, and how many apps it owns.
const EDGE: &str = "jsonb_build_object('id',r.id,'name',r.name,'cert_sha256',r.cert_sha256,'endpoint',r.endpoint,'draining',r.draining,'created',r.created,
    'live',EXISTS(SELECT 1 FROM gateway_sessions g WHERE g.edge_id=r.id AND g.seen>clock_timestamp()-interval '15 seconds'),
    'apps',(SELECT count(*) FROM app_edges a WHERE a.edge_id=r.id))";

impl Store {
    pub async fn register_edge_keyed(
        &self,
        p: &Principal,
        value: Value,
        key: Option<&str>,
    ) -> Result<Value> {
        p.operator()?;
        fields(
            &value,
            &["name", "cert_sha256", "endpoint"],
            &["name", "cert_sha256", "endpoint"],
        )?;
        named(&value["name"])?;
        let pin = text(&value["cert_sha256"])?;
        if pin.len() != 64
            || !pin
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::invalid("invalid certificate fingerprint"));
        }
        let endpoint = https_origin(text(&value["endpoint"])?)?;
        let request = json!({"kind":"edge.register","value":value});
        let mut tx = self.transaction(true, false).await?;
        if let Some(key) = key
            && let Some(row) =
                crate::customer_api::operator_receipt(&mut tx, &p.id, key, &request).await?
        {
            return Ok(row);
        }
        let id = uid();
        exec(
            &mut tx,
            "INSERT INTO edges(id,name,cert_sha256,endpoint) VALUES($1,$2,$3,$4)",
            args![id, value["name"], pin, endpoint],
        )
        .await?;
        let row = Self::edge_row(&mut tx, &id).await?;
        Self::audit_system(
            &mut tx,
            &p.id,
            "edge.register",
            &json!(id),
            &Value::Null,
            json!({}),
        )
        .await?;
        if let Some(key) = key {
            crate::customer_api::save_operator_receipt(&mut tx, &p.id, key, None, &request, &row)
                .await?;
        }
        tx.commit().await?;
        Ok(row)
    }

    async fn edge_row(tx: &mut Tx, edge: &str) -> Result<Value> {
        one(
            tx,
            &format!("SELECT {EDGE} AS edge FROM edges r WHERE r.id=$1 AND NOT r.deleted"),
            args![edge],
        )
        .await
        .map(|row| row["edge"].clone())
    }

    pub async fn edge_page(&self, p: &Principal, page: crate::store::ListPage) -> Result<Value> {
        p.operator()?;
        let (before, limit) = page.bounds(1000)?;
        let mut tx = self.transaction(false, false).await?;
        let found: Vec<Value> = rows(
            &mut tx,
            &format!("SELECT {EDGE} AS edge FROM edges r WHERE NOT r.deleted AND ($1::text IS NULL OR (r.created,r.id)<(SELECT c.created,c.id FROM edges c WHERE c.id=$1)) ORDER BY r.created DESC,r.id DESC LIMIT $2"),
            args![before, limit + 1],
        )
        .await?
        .into_iter()
        .map(|row| row["edge"].clone())
        .collect();
        Ok(crate::store::ListPage::page(found, limit))
    }

    /// Drains an edge, or stops draining it. Draining, it is given no app,
    /// and the scheduler moves those it owns to others.
    pub async fn edge_mode_keyed(
        &self,
        p: &Principal,
        edge: &str,
        value: Value,
        key: Option<&str>,
    ) -> Result<Value> {
        p.operator()?;
        identity(edge)?;
        fields(&value, &["draining"], &["draining"])?;
        if !value["draining"].is_boolean() {
            return Err(Error::invalid("draining must be a boolean"));
        }
        let request = json!({"kind":"edge.mode","edge":edge,"value":value});
        let mut tx = self.transaction(true, false).await?;
        if let Some(key) = key
            && let Some(row) =
                crate::customer_api::operator_receipt(&mut tx, &p.id, key, &request).await?
        {
            return Ok(row);
        }
        if exec(
            &mut tx,
            "UPDATE edges SET draining=$2 WHERE id=$1 AND NOT deleted",
            args![edge, value["draining"]],
        )
        .await?
            == 0
        {
            return Err(Error::missing());
        }
        let row = Self::edge_row(&mut tx, edge).await?;
        Self::audit_system(
            &mut tx,
            &p.id,
            "edge.mode",
            &json!(edge),
            &Value::Null,
            value.clone(),
        )
        .await?;
        if let Some(key) = key {
            crate::customer_api::save_operator_receipt(&mut tx, &p.id, key, None, &request, &row)
                .await?;
        }
        tx.commit().await?;
        Ok(row)
    }

    /// Deletes an edge that drains and owns no app any more.
    pub async fn delete_edge(&self, p: &Principal, edge: &str, key: &str) -> Result<Value> {
        p.operator()?;
        identity(edge)?;
        let request = json!({"kind":"edge.delete","edge":edge});
        let mut tx = self.transaction(true, false).await?;
        if let Some(row) =
            crate::customer_api::operator_receipt(&mut tx, &p.id, key, &request).await?
        {
            return Ok(row);
        }
        let found = one(
            &mut tx,
            "SELECT e.draining,EXISTS(SELECT 1 FROM app_edges a WHERE a.edge_id=e.id) AS owns FROM edges e WHERE e.id=$1 AND NOT e.deleted FOR UPDATE OF e",
            args![edge],
        )
        .await?;
        if found["draining"] != true {
            return Err(conflict("drain the edge before deleting it").coded("in_use"));
        }
        if found["owns"] == true {
            return Err(conflict("the edge still owns apps").coded("in_use"));
        }
        exec(&mut tx,"UPDATE edges SET deleted=true,name='deleted-'||id,cert_sha256='deleted-'||id WHERE id=$1",args![edge]).await?;
        let row = json!({"id":edge});
        Self::audit_system(
            &mut tx,
            &p.id,
            "edge.delete",
            &json!(edge),
            &Value::Null,
            json!({}),
        )
        .await?;
        crate::customer_api::save_operator_receipt(&mut tx, &p.id, key, None, &request, &row)
            .await?;
        tx.commit().await?;
        Ok(row)
    }

    /// Which edge owns each app's host name, and where it is: for a
    /// balancer that sends a request to its owner, saving the edge it lands
    /// on the forwarding.
    pub async fn edge_routes(&self, p: &Principal, page: crate::store::ListPage) -> Result<Value> {
        p.operator()?;
        let (before, limit) = page.bounds(1000)?;
        let mut tx = self.transaction(false, false).await?;
        let found: Vec<Value> = rows(
            &mut tx,
            "SELECT jsonb_build_object('id',a.app_id,'app_id',a.app_id,'hostname',h.hostname,'edge_id',e.id,'endpoint',e.endpoint) AS route
             FROM app_edges a JOIN app_http h ON h.app_id=a.app_id JOIN edges e ON e.id=a.edge_id AND NOT e.deleted
             WHERE ($1::text IS NULL OR a.app_id>$1) ORDER BY a.app_id LIMIT $2",
            args![before, limit + 1],
        )
        .await?
        .into_iter()
        .map(|row| row["route"].clone())
        .collect();
        Ok(crate::store::ListPage::page(found, limit))
    }

    /// The registered edge named `name`, for a process started as it.
    pub async fn edge_named(&self, name: &str) -> Result<String> {
        let mut tx = self.transaction(false, false).await?;
        let found = optional(
            &mut tx,
            "SELECT id FROM edges WHERE name=$1 AND NOT deleted",
            args![name],
        )
        .await?
        .ok_or_else(|| Error::invalid("no edge of that name is registered"))?;
        Ok(s(&found["id"]).to_owned())
    }

    /// Gives every app with the HTTP trigger an edge that serves, and moves
    /// those of an edge that is gone or draining: to the live edge that owns
    /// the fewest. Nothing, while no registered edge is live.
    pub(crate) async fn place_apps(tx: &mut Tx) -> Result<()> {
        let live = rows(tx,&format!("SELECT e.id,(SELECT count(*) FROM app_edges a WHERE a.edge_id=e.id) AS apps FROM edges e
            WHERE NOT e.deleted AND NOT e.draining AND (e.seen>clock_timestamp()-interval '{0}' OR EXISTS(SELECT 1 FROM gateway_sessions g WHERE g.edge_id=e.id AND g.seen>clock_timestamp()-interval '{0}'))
            ORDER BY e.id",crate::gateway::SESSION_DEAD),args![]).await?;
        if live.is_empty() {
            return Ok(());
        }
        let mut load: Vec<(String, i64)> = live
            .iter()
            .map(|e| (s(&e["id"]).to_owned(), n(&e["apps"])))
            .collect();
        let homeless = rows(tx,"SELECT h.app_id FROM app_http h JOIN apps a ON a.id=h.app_id JOIN app_triggers t ON t.app_id=a.id
            WHERE t.http AND a.desired='enabled' AND NOT EXISTS(SELECT 1 FROM app_edges x WHERE x.app_id=h.app_id AND x.edge_id=ANY(ARRAY(SELECT jsonb_array_elements_text($1))))
            ORDER BY h.app_id LIMIT 512",args![json!(load.iter().map(|(id,_)|id.clone()).collect::<Vec<_>>())]).await?;
        for app in homeless {
            let (edge, apps) = load
                .iter_mut()
                .min_by_key(|(id, apps)| (*apps, id.clone()))
                .expect("a live edge");
            exec(tx,"INSERT INTO app_edges(app_id,edge_id) VALUES($1,$2) ON CONFLICT(app_id) DO UPDATE SET edge_id=excluded.edge_id,revision=app_edges.revision+1,updated=clock_timestamp()",args![app["app_id"],edge]).await?;
            *apps += 1;
        }
        // Apps placed while an edge was away stay where they went: idle
        // ones, which hold nothing on their edge, move back toward the
        // edge with the fewest, some at a time.
        let mut moves = REBALANCE_PER_PASS;
        while moves > 0 {
            let most = load
                .iter()
                .max_by_key(|(id, apps)| (*apps, std::cmp::Reverse(id.clone())))
                .cloned()
                .expect("a live edge");
            let least = load
                .iter()
                .min_by_key(|(id, apps)| (*apps, id.clone()))
                .cloned()
                .expect("a live edge");
            let wanted = ((most.1 - least.1) / 2).min(moves);
            if wanted < 1 {
                break;
            }
            let moved = exec(tx,"UPDATE app_edges SET edge_id=$2,revision=revision+1,updated=clock_timestamp() WHERE app_id IN (SELECT x.app_id FROM app_edges x JOIN app_http h ON h.app_id=x.app_id WHERE x.edge_id=$1 AND h.state='idle' AND NOT h.idle_draining AND NOT EXISTS(SELECT 1 FROM ingress_reservations q WHERE q.app_id=x.app_id) ORDER BY x.app_id LIMIT $3)",args![most.0,least.0,wanted]).await? as i64;
            if moved < 1 {
                break;
            }
            for (id, apps) in load.iter_mut() {
                if *id == most.0 {
                    *apps -= moved;
                }
                if *id == least.0 {
                    *apps += moved;
                }
            }
            moves -= moved;
        }
        // An app that has no HTTP trigger any more, or is gone, is no one's.
        exec(tx,"DELETE FROM app_edges x WHERE NOT EXISTS(SELECT 1 FROM app_http h JOIN apps a ON a.id=h.app_id JOIN app_triggers t ON t.app_id=a.id WHERE h.app_id=x.app_id AND t.http AND a.desired='enabled')",args![]).await?;
        Ok(())
    }
}

/// An HTTPS origin, as an edge's internal address is given.
fn https_origin(value: &str) -> Result<String> {
    let url = url::Url::parse(value).map_err(|_| Error::invalid("invalid edge endpoint"))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::invalid("edge endpoint must be an HTTPS origin"));
    }
    Ok(url.as_str().trim_end_matches('/').to_owned())
}
