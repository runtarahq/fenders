//! What a run's launch is, as the run channel needs it, kept for a moment.
//!
//! Every call a shim makes on the run channel used to read the database to
//! learn whether its launch (execution and generation) was still current,
//! and most read it again for what the call itself needed: the node and its
//! boot, whether the run is under the outbound limit, the queue an HTTP run
//! takes requests from, the app a WebSocket message is sent for. An HTTP
//! request was three such reads.
//!
//! All of it is read once, in one query, and kept for [`FRESH`]: the same
//! two seconds a gate is believed ([`crate::gate`]), and dropped as a gate
//! is when the epoch moves, which a change to any of it makes happen
//! (`sql/gate_changes.sql`). What a call writes is still checked again in
//! its own transaction; only what decided whether to answer is kept.
//!
//! A launch that is not current is not kept: it is read again at its next
//! call, which a run that has ended does not make.
use serde_json::Value;
use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

/// How long what was read of a launch is believed.
pub const FRESH: Duration = crate::gate::FRESH;
/// Launches kept at once: past it, those no longer fresh are dropped, and
/// all of them if that is not enough.
const MOST: usize = 65536;

/// What a current launch names.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Launch {
    pub tenant: String,
    pub project: String,
    /// The node it is on and the node's boot, when it is placed.
    pub node: Option<String>,
    pub boot: Option<String>,
    /// Whether the operator disabled that node; true when there is none.
    pub disabled: bool,
    /// Whether it is under the outbound byte limit.
    pub egress: bool,
    /// Whether its outbound grant may be renewed from memory: it is to run,
    /// its node is heard from, confined and serves the limit, and its
    /// workspace is active. Otherwise the database decides.
    pub renewable: bool,
    /// The queue it takes HTTP requests from, when it takes any.
    pub queue: Option<String>,
    /// The app it may send WebSocket messages for, when that app takes
    /// connections.
    pub websocket_app: Option<String>,
}

/// One query for all of it. `$1` the execution, `$2` the generation.
/// `$3` the confinement a node must have, `$4` the outbound limit's
/// contract.
pub(crate) const QUERY: &str = "SELECT e.tenant_id,e.project_id,e.node_id,n.boot_id,COALESCE(n.disabled,true) AS disabled,e.egress_budget_launcher IS NOT NULL AS egress,
    (e.desired='running' AND NOT COALESCE(n.disabled,true) AND n.last_seen>now()-interval '15 seconds' AND n.observed_confinement=$3 AND n.observed_egress_budget=$4
        AND EXISTS(SELECT 1 FROM tenants t WHERE t.id=e.tenant_id AND t.lifecycle_state='active')) AS renewable,
    (e.desired='running' AND e.spec->>'mode'='http') AS http,m.app_id AS managed,m.execution_id=e.id AS serves,m.candidate_execution_id=e.id AS candidate,
    EXISTS(SELECT 1 FROM app_http_extras x WHERE x.execution_id=e.id AND x.app_id=m.app_id AND x.generation=m.generation-CASE WHEN m.candidate_until IS NOT NULL THEN 1 ELSE 0 END) AS extra,
    (SELECT a.id FROM apps a WHERE a.configuration->>'websocket'='true' AND a.id=COALESCE((SELECT app_id FROM app_http_attempts WHERE execution_id=e.id),(SELECT app_id FROM app_runs WHERE execution_id=e.id))) AS websocket_app
    FROM executions e LEFT JOIN nodes n ON n.id=e.node_id LEFT JOIN app_http m ON m.deployment_id=e.deployment_id
    WHERE e.id=$1 AND e.generation=$2 AND e.reserved";

impl Launch {
    /// What the query found of `execution`.
    pub(crate) fn of(execution: &str, row: &Value) -> Self {
        let text = |key: &str| row[key].as_str().map(str::to_owned);
        let yes = |key: &str| row[key] == true;
        // An app's executions share the app's queue: the one its binding
        // names and the extras of that binding's generation. One being
        // brought up beside it has a queue of its own, which nothing is
        // offered to. An execution of no app takes its own requests.
        let queue = if !yes("http") {
            None
        } else if let Some(app) = text("managed") {
            if yes("serves") || yes("extra") {
                Some(app)
            } else if yes("candidate") {
                Some(crate::run_channel::candidate_key(execution))
            } else {
                None
            }
        } else {
            Some(execution.to_owned())
        };
        Self {
            tenant: text("tenant_id").unwrap_or_default(),
            project: text("project_id").unwrap_or_default(),
            node: text("node_id"),
            boot: text("boot_id"),
            disabled: row["disabled"] != false,
            egress: yes("egress"),
            renewable: yes("egress") && yes("renewable"),
            queue,
            websocket_app: text("websocket_app"),
        }
    }
}

/// Each launch, keyed by execution and generation: what was read, when, and
/// at which epoch.
type Kept = HashMap<(String, i64), (Launch, Instant, u64)>;

#[derive(Default)]
pub struct Launches {
    inner: Mutex<Kept>,
}

impl Launches {
    fn lock(&self) -> std::sync::MutexGuard<'_, Kept> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// What is believed of a launch at `epoch`.
    pub fn look(&self, execution: &str, generation: i64, epoch: u64) -> Option<Launch> {
        let inner = self.lock();
        match inner.get(&(execution.to_owned(), generation)) {
            Some((launch, read, at)) if *at == epoch && read.elapsed() < FRESH => {
                Some(launch.clone())
            }
            _ => None,
        }
    }

    /// What was read of a launch, from `epoch` on.
    pub fn keep(&self, execution: &str, generation: i64, launch: Launch, epoch: u64) {
        let mut inner = self.lock();
        if inner.len() >= MOST {
            inner.retain(|_, (_, read, _)| read.elapsed() < FRESH);
            if inner.len() >= MOST {
                inner.clear();
            }
        }
        inner.insert(
            (execution.to_owned(), generation),
            (launch, Instant::now(), epoch),
        );
    }

    /// Nothing is believed of any launch any more.
    pub fn forget_all(&self) {
        self.lock().clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_launch_is_believed_at_its_epoch_and_not_after() {
        let launches = Launches::default();
        let launch = Launch {
            tenant: "t".into(),
            ..Default::default()
        };
        assert_eq!(launches.look("e", 1, 0), None);
        launches.keep("e", 1, launch.clone(), 0);
        assert_eq!(launches.look("e", 1, 0), Some(launch));
        // Another generation is another launch; another epoch is after a
        // change.
        assert_eq!(launches.look("e", 2, 0), None);
        assert_eq!(launches.look("e", 1, 1), None);
    }

    #[test]
    fn the_queue_an_http_run_takes_from_is_its_apps_or_its_own() {
        let row = |fields: Value| {
            let mut row = json!({"http":true,"tenant_id":"t","project_id":"p","disabled":false});
            for (key, value) in fields.as_object().unwrap() {
                row[key] = value.clone();
            }
            Launch::of("e", &row).queue
        };
        assert_eq!(row(json!({})), Some("e".into()));
        assert_eq!(row(json!({"managed":"a","serves":true})), Some("a".into()));
        assert_eq!(row(json!({"managed":"a","extra":true})), Some("a".into()));
        assert_eq!(
            row(json!({"managed":"a","candidate":true})),
            Some(crate::run_channel::candidate_key("e"))
        );
        assert_eq!(row(json!({"managed":"a"})), None);
        assert_eq!(row(json!({"http":false})), None);
        // No node, or a node of unknown standing, is a disabled one.
        assert!(Launch::of("e", &json!({})).disabled);
    }
}
