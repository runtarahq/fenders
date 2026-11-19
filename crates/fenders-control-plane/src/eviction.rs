//! Idle executions give way to work waiting for room.
//!
//! An HTTP app that serves keeps its executions while it has no request to
//! handle: it is warm, and it holds what they reserve. When work of the same
//! workspace waits for room, in the workspace's compute allowance or on a
//! node, the workspace's executions that have handled no request for
//! [`IDLE_FOR`] are stopped to make it: the longest idle first, and no more
//! of them than the waiting work needs. If all of them would not make
//! enough, none is stopped.
//!
//! What gives way:
//!
//! - an app whose every execution is idle, which is stopped as an app with
//!   `keep_warm: false` is after a minute without a request (reason
//!   `evicted`) and wakes again on its next request, whatever its
//!   `keep_warm`;
//! - an extra execution an app was scaled out to, when the app's others are
//!   busy, down to what its `scale.min` keeps, which the scaler would only
//!   start again.
//!
//! What makes way: an app waking (its execution refused by the allowance,
//! or not placed for lack of room on a node), and a command run not placed
//! for lack of room on a node. An app scaling out does not: busy apps do
//! not push idle ones out to grow.
//!
//! Only a workspace's own executions give way to its work: one workspace
//! never stops another's.
//!
//! Idle is read from what the gateway knows: no request in flight or waiting
//! for the app, no request since [`IDLE_FOR`] ago (`last_activity`, written
//! by the gateway's flush), and, where shims ask a run channel, the
//! exchange's own word that each execution has had nothing to do for as
//! long ([`crate::observed`]).
use crate::{
    args,
    db::*,
    error::Result,
    model::WORKER_OVERHEAD_MIB,
    observed::Observed,
    store::{Store, Tx},
};
use serde_json::{Value, json};
use std::time::Duration;

/// How long an execution has handled no request before it may give way.
pub const IDLE_FOR: Duration = Duration::from_secs(5);

/// Compute: what an execution reserves, or what is short of room for it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Room {
    pub cpu: i64,
    pub memory: i64,
    pub instances: i64,
}

impl Room {
    /// What an execution row reserves.
    pub(crate) fn of(execution: &Value) -> Self {
        Self {
            cpu: n(&execution["cpu_percent"]),
            memory: n(&execution["memory_mib"]),
            instances: 1,
        }
    }
    /// What an execution of `spec` would reserve.
    pub(crate) fn of_spec(spec: &Value) -> Self {
        Self {
            cpu: n(&spec["cpu_percent"]),
            memory: n(&spec["host_memory_mib"]) + WORKER_OVERHEAD_MIB,
            instances: 1,
        }
    }
    fn zip(self, other: Self, f: impl Fn(i64, i64) -> i64) -> Self {
        Self {
            cpu: f(self.cpu, other.cpu),
            memory: f(self.memory, other.memory),
            instances: f(self.instances, other.instances),
        }
    }
    pub fn plus(self, other: Self) -> Self {
        self.zip(other, |a, b| a + b)
    }
    /// What is short of room for `need`, where `used` of `limit` is
    /// reserved and `coming` of that is being given back.
    pub fn short(need: Self, used: Self, coming: Self, limit: Self) -> Self {
        used.zip(coming, |u, c| u - c)
            .plus(need)
            .zip(limit, |wanted, limit| (wanted - limit).max(0))
    }
    /// Whether it is no more than `other`, in everything.
    pub fn within(&self, other: Self) -> bool {
        self.cpu <= other.cpu && self.memory <= other.memory && self.instances <= other.instances
    }
    /// The least of each.
    pub fn least(self, other: Self) -> Self {
        self.zip(other, i64::min)
    }
    pub fn is_zero(&self) -> bool {
        self.cpu <= 0 && self.memory <= 0 && self.instances <= 0
    }
    fn frees_any_of(&self, short: Self) -> bool {
        (short.cpu > 0 && self.cpu > 0)
            || (short.memory > 0 && self.memory > 0)
            || (short.instances > 0 && self.instances > 0)
    }
}

/// Which of the candidates (each what it would free, the longest idle
/// first) give way for `short` to be made up: the first ones that free any
/// of what is short, until it is. None when all of them do not make it up.
pub fn choose(freed: &[Room], short: Room) -> Option<Vec<usize>> {
    let mut left = short;
    let mut chosen = Vec::new();
    for (index, room) in freed.iter().enumerate() {
        if left.is_zero() {
            break;
        }
        if !room.frees_any_of(left) {
            continue;
        }
        left = left.zip(*room, |l, r| (l - r).max(0));
        chosen.push(index);
    }
    left.is_zero().then_some(chosen)
}

/// What may give way: a whole app, or one extra execution of an app.
#[derive(Clone, Debug)]
pub(crate) struct Idle {
    app: String,
    tenant: String,
    /// The app's binding, when the whole app gives way.
    whole: Option<Value>,
    /// Its executions: id, node, what each reserves.
    executions: Vec<(String, Option<String>, Room)>,
    quiet: Duration,
}

impl Idle {
    fn frees(&self, node: Option<&str>) -> Room {
        self.executions
            .iter()
            .filter(|(_, at, _)| node.is_none() || at.as_deref() == node)
            .fold(Room::default(), |sum, (_, _, room)| sum.plus(*room))
    }
}

/// Executions of `tenant`, reserved: all of them, and those being given
/// back.
const RESERVED: &str = "SELECT COALESCE(sum(cpu_percent),0) cpu,COALESCE(sum(memory_mib),0) memory,count(*) instances,COALESCE(sum(cpu_percent) FILTER (WHERE desired='stopped'),0) coming_cpu,COALESCE(sum(memory_mib) FILTER (WHERE desired='stopped'),0) coming_memory,count(*) FILTER (WHERE desired='stopped') coming_instances FROM executions WHERE reserved AND ";

fn reserved(row: &Value) -> (Room, Room) {
    (
        Room {
            cpu: n(&row["cpu"]),
            memory: n(&row["memory"]),
            instances: n(&row["instances"]),
        },
        Room {
            cpu: n(&row["coming_cpu"]),
            memory: n(&row["coming_memory"]),
            instances: n(&row["coming_instances"]),
        },
    )
}

impl Store {
    /// What of `tenant` may give way, the longest idle first.
    async fn idle_of(&self, tx: &mut Tx, tenant: &str, seen: &Observed) -> Result<Vec<Idle>> {
        // Where shims ask a run channel, its exchange says how long each
        // execution has had nothing to do; where none do, only the app's
        // last request does.
        let watched = self.run_channel.is_some();
        let quiet = |id: &str| -> Option<Duration> {
            if seen.busy(id) {
                return None;
            }
            match seen.idle(id) {
                Some(idle) if idle >= IDLE_FOR => Some(idle),
                Some(_) => None,
                None if watched => None,
                None => Some(IDLE_FOR),
            }
        };
        let mut found = Vec::new();
        for binding in rows(tx,"SELECT h.*,a.tenant_id,a.configuration,(extract(epoch FROM now()-h.last_activity)*1000)::bigint AS quiet_ms FROM app_http h JOIN apps a ON a.id=h.app_id WHERE a.tenant_id=$1 AND h.state='serving' AND h.candidate_until IS NULL AND NOT h.blocked AND NOT h.idle_draining AND h.execution_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM ingress_reservations q WHERE q.app_id=h.app_id OR q.execution_id IN (SELECT id FROM executions e WHERE e.deployment_id=h.deployment_id)) ORDER BY h.last_activity,h.app_id",args![tenant]).await? {
            let app = s(&binding["app_id"]).to_owned();
            if self.gateway.gates.serving(&app) > 0 {
                continue;
            }
            let executions = rows(tx,"SELECT id,node_id,cpu_percent,memory_mib,state,id=$2 AS is_primary FROM executions WHERE deployment_id=$1 AND reserved AND desired='running' ORDER BY created,id",args![binding["deployment_id"],binding["execution_id"]]).await?;
            let idle: Vec<_> = executions
                .iter()
                .filter(|e| e["state"] == "running")
                .filter_map(|e| quiet(s(&e["id"])).map(|q| (e, q)))
                .collect();
            let entry = |e: &Value| (s(&e["id"]).to_owned(), e["node_id"].as_str().map(str::to_owned), Room::of(e));
            let app_quiet = Duration::from_millis(n(&binding["quiet_ms"]).max(0) as u64);
            if !executions.is_empty() && idle.len() == executions.len() && app_quiet >= IDLE_FOR {
                let quiet = idle.iter().map(|(_, q)| *q).min().unwrap_or(app_quiet).min(app_quiet);
                found.push(Idle { app, tenant: tenant.to_owned(), whole: Some(binding), executions: executions.iter().map(entry).collect(), quiet });
                continue;
            }
            // Extra executions, known idle only from the exchange, beyond
            // what the app's `scale.min` keeps of them.
            if !watched {
                continue;
            }
            let keep = (binding["configuration"]["scale"]["min"].as_i64().unwrap_or(1) - 1).max(0);
            let extras = executions.iter().filter(|e| e["is_primary"] != true).count() as i64;
            let mut idle_extras: Vec<_> = idle.into_iter().filter(|(e, _)| e["is_primary"] != true).collect();
            idle_extras.sort_by_key(|e| std::cmp::Reverse(e.1));
            for (e, quiet) in idle_extras.into_iter().take((extras - keep).max(0) as usize) {
                found.push(Idle { app: app.clone(), tenant: tenant.to_owned(), whole: None, executions: vec![entry(e)], quiet });
            }
        }
        found.sort_by_key(|i| std::cmp::Reverse(i.quiet));
        Ok(found)
    }

    /// Stops what gives way, for `waiting` (what it is stopped for, as the
    /// audit says). Whether it was stopped: an app that took a request
    /// since it was found idle is not.
    async fn give_way(
        &self,
        tx: &mut Tx,
        idle: &Idle,
        seen: &Observed,
        waiting: &Value,
    ) -> Result<bool> {
        let ids: Vec<&str> = idle
            .executions
            .iter()
            .map(|(id, _, _)| id.as_str())
            .collect();
        match &idle.whole {
            Some(binding) => {
                // Its gate closes, so that a request that comes now waits
                // for it to wake, as one to an app stopped as idle does.
                if !self.gateway.gates.close_if_idle(&idle.app) {
                    return Ok(false);
                }
                exec(tx,"UPDATE app_http SET state='stopping',reason='evicted',idle_draining=true,drain_until=NULL,updated=now() WHERE app_id=$1",args![idle.app]).await?;
                exec(
                    tx,
                    "UPDATE deployments SET desired='stopped' WHERE id=$1",
                    args![binding["deployment_id"]],
                )
                .await?;
                let mut drain = binding.clone();
                drain["drain_until"] = Value::Null;
                self.drain_http(tx, &drain, seen).await?;
            }
            None => {
                exec(tx,"UPDATE executions SET desired='stopped',generation=generation+1,updated=now() WHERE id IN (SELECT jsonb_array_elements_text($1)) AND reserved AND desired<>'stopped'",args![ids]).await?;
            }
        }
        Self::audit_system(
            tx,
            "scheduler",
            "app.evict",
            &json!(idle.app),
            &json!(idle.tenant),
            json!({"executions":ids,"idle_ms":idle.quiet.as_millis() as u64,"for":waiting}),
        )
        .await?;
        Ok(true)
    }

    /// Makes room in `tenant`'s compute allowance for an execution that
    /// reserves `need`, for `waiting`. Whether room is coming: being given
    /// back already, or by what this stopped.
    pub(crate) async fn make_room_in_allowance(
        &self,
        tx: &mut Tx,
        tenant: &str,
        need: Room,
        seen: &Observed,
        waiting: &Value,
    ) -> Result<bool> {
        let limit = one(
            tx,
            "SELECT cpu_percent cpu,memory_mib memory,instances FROM tenants WHERE id=$1",
            args![tenant],
        )
        .await?;
        let limit = Room {
            cpu: n(&limit["cpu"]),
            memory: n(&limit["memory"]),
            instances: n(&limit["instances"]),
        };
        let (used, coming) =
            reserved(&one(tx, &format!("{RESERVED}tenant_id=$1"), args![tenant]).await?);
        let short = Room::short(need, used, coming, limit);
        if short.is_zero() {
            return Ok(true);
        }
        let idle = self.idle_of(tx, tenant, seen).await?;
        let freed: Vec<Room> = idle.iter().map(|i| i.frees(None)).collect();
        let Some(chosen) = choose(&freed, short) else {
            return Ok(false);
        };
        let mut stopped = true;
        for index in chosen {
            stopped &= self.give_way(tx, &idle[index], seen, waiting).await?;
        }
        Ok(stopped)
    }

    /// Makes room for `execution` on one of `full`, the nodes it was not
    /// placed on for lack of room (each with what is reserved on it), in
    /// the order they would be chosen. Whether room is coming on one.
    pub(crate) async fn make_room_on_nodes(
        &self,
        tx: &mut Tx,
        execution: &Value,
        full: &[Value],
        seen: &Observed,
    ) -> Result<bool> {
        if full.is_empty() {
            return Ok(false);
        }
        let need = Room::of(execution);
        let tenant = s(&execution["tenant_id"]);
        let mut idle: Option<Vec<Idle>> = None;
        for node in full {
            let limit = Room {
                cpu: n(&node["cpu_percent"]),
                memory: n(&node["memory_mib"]),
                instances: n(&node["instances"]),
            };
            let (used, coming) =
                reserved(&one(tx, &format!("{RESERVED}node_id=$1"), args![node["id"]]).await?);
            let short = Room::short(need, used, coming, limit);
            if short.is_zero() {
                return Ok(true);
            }
            if idle.is_none() {
                idle = Some(self.idle_of(tx, tenant, seen).await?);
            }
            let idle = idle.as_ref().unwrap();
            let freed: Vec<Room> = idle.iter().map(|i| i.frees(node["id"].as_str())).collect();
            if let Some(chosen) = choose(&freed, short) {
                let mut stopped = true;
                for index in chosen {
                    stopped &= self
                        .give_way(
                            tx,
                            &idle[index],
                            seen,
                            &json!({"execution_id":execution["id"],"node_id":node["id"]}),
                        )
                        .await?;
                }
                return Ok(stopped);
            }
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(cpu: i64, memory: i64, instances: i64) -> Room {
        Room {
            cpu,
            memory,
            instances,
        }
    }

    #[test]
    fn what_is_short_counts_what_is_being_given_back() {
        // 75 of 100 reserved, 25 more wanted: none short.
        assert!(Room::short(r(25, 88, 1), r(75, 264, 3), r(0, 0, 0), r(100, 352, 4)).is_zero());
        // 100 of 100 reserved: 25 short, unless 25 is being given back.
        assert_eq!(
            Room::short(r(25, 88, 1), r(100, 352, 4), r(0, 0, 0), r(100, 352, 4)),
            r(25, 88, 1)
        );
        assert!(Room::short(r(25, 88, 1), r(100, 352, 4), r(25, 88, 1), r(100, 352, 4)).is_zero());
    }

    #[test]
    fn the_longest_idle_give_way_and_no_more_than_is_short() {
        let freed = [r(25, 88, 1), r(25, 88, 1), r(25, 88, 1)];
        assert_eq!(choose(&freed, r(25, 88, 1)), Some(vec![0]));
        assert_eq!(choose(&freed, r(50, 100, 1)), Some(vec![0, 1]));
        assert_eq!(choose(&freed, r(0, 0, 0)), Some(vec![]));
    }

    #[test]
    fn none_gives_way_when_all_of_them_would_not_make_room() {
        assert_eq!(choose(&[r(25, 88, 1)], r(50, 88, 1)), None);
        assert_eq!(choose(&[], r(25, 88, 1)), None);
    }

    #[test]
    fn what_frees_nothing_that_is_short_is_passed_over() {
        // Elsewhere, so it frees nothing on this node.
        let freed = [r(0, 0, 0), r(25, 88, 1)];
        assert_eq!(choose(&freed, r(25, 88, 1)), Some(vec![1]));
    }
}
