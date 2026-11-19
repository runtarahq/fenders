use crate::{
    args,
    db::*,
    error::{Error, Result},
    model::*,
    store::{Store, Tx},
};
use axum::http::StatusCode;
use serde_json::{Value, json};

/// What a request is refused with when this process's share of its
/// workspace's limits has no room for it.
const SHARE_SHORT: &str = "ingress allowance exhausted";

/// The largest request body and the largest response body passed on.
pub const MAX_REQUEST_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_RESPONSE_BYTES: u64 = 1024 * 1024 * 1024;

/// Whose a gateway host name is, remembered for a moment.
///
/// Every admission is a transaction under the lock all mutations share. A
/// request for a host name that is nobody's, or of a workspace already past
/// its requests for the minute, needs none: what a host name is, and its
/// workspace's limit, are read without the lock and kept here briefly, so
/// such requests are refused before they can queue anything else behind them.
#[derive(Default)]
pub struct Hosts {
    known: std::sync::Mutex<std::collections::HashMap<String, (std::time::Instant, Whose)>>,
}

/// Nobody's, or a workspace's with its requests a minute.
type Whose = Option<(String, i64)>;

impl Hosts {
    /// How long a host name is remembered as nobody's, and as a workspace's.
    const UNKNOWN: std::time::Duration = std::time::Duration::from_secs(1);
    const KNOWN: std::time::Duration = std::time::Duration::from_secs(5);
    /// Host names remembered at once: a flood of made-up names evicts, it
    /// does not grow.
    const MOST: usize = 8192;

    /// `Some(None)`: nobody's. `Some(Some((workspace, requests a minute)))`.
    /// `None`: not remembered.
    fn get(&self, hostname: &str) -> Option<Whose> {
        let known = self.known.lock().unwrap_or_else(|e| e.into_inner());
        let (at, whose) = known.get(hostname)?;
        let kept = if whose.is_some() {
            Self::KNOWN
        } else {
            Self::UNKNOWN
        };
        (at.elapsed() < kept).then(|| whose.clone())
    }

    fn remember(&self, hostname: &str, whose: Whose) {
        let mut known = self.known.lock().unwrap_or_else(|e| e.into_inner());
        if known.len() >= Self::MOST {
            known.retain(|_, (at, _)| at.elapsed() < Self::UNKNOWN);
            if known.len() >= Self::MOST {
                known.clear();
            }
        }
        known.insert(hostname.to_owned(), (std::time::Instant::now(), whose));
    }
}

/// The requests each workspace was admitted in the last minute, counted in
/// memory: a request is not a row to count. A restart forgets the count, so
/// a workspace may then be admitted up to a minute's requests again.
#[derive(Default)]
pub struct Rates {
    inner: std::sync::Mutex<RatesInner>,
}

#[derive(Default)]
struct RatesInner {
    /// For each workspace, the seconds it was admitted requests in and how
    /// many, oldest first.
    admitted: std::collections::HashMap<String, std::collections::VecDeque<(u64, u32)>>,
    /// For each workspace and what was admitted, the minute last audited.
    audited: std::collections::HashMap<(String, String), u64>,
    /// Seconds added to the clock by [`Rates::advance`].
    advanced: u64,
}

impl Rates {
    fn now(inner: &RatesInner) -> u64 {
        static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
        START
            .get_or_init(std::time::Instant::now)
            .elapsed()
            .as_secs()
            + inner.advanced
    }

    /// Admits one request of `tenant` unless `limit` were admitted in the
    /// last minute.
    pub fn admit(&self, tenant: &str, limit: i64) -> bool {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let now = Self::now(&inner);
        let seconds = inner.admitted.entry(tenant.to_owned()).or_default();
        while seconds
            .front()
            .is_some_and(|(second, _)| second + 60 <= now)
        {
            seconds.pop_front();
        }
        let recent: i64 = seconds.iter().map(|(_, count)| *count as i64).sum();
        if recent >= limit {
            return false;
        }
        match seconds.back_mut() {
            Some((second, count)) if *second == now => *count += 1,
            _ => seconds.push_back((now, 1)),
        }
        true
    }

    /// How many seconds until `tenant` may be admitted a request again,
    /// once [`admit`](Self::admit) has refused one: when the oldest second
    /// still counted leaves the minute. At least one.
    pub fn retry_after(&self, tenant: &str) -> u64 {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let now = Self::now(&inner);
        inner
            .admitted
            .get(tenant)
            .and_then(|seconds| seconds.front())
            .map_or(1, |(second, _)| (second + 60).saturating_sub(now).max(1))
    }

    /// How many requests of `tenant` were admitted in the last minute.
    pub fn count(&self, tenant: &str) -> i64 {
        let inner = self.lock_inner();
        let now = Self::now(&inner);
        inner.admitted.get(tenant).map_or(0, |seconds| {
            seconds
                .iter()
                .filter(|(second, _)| second + 60 > now)
                .map(|(_, count)| *count as i64)
                .sum()
        })
    }

    fn lock_inner(&self) -> std::sync::MutexGuard<'_, RatesInner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Whether `limit` requests of `tenant` were admitted in the last minute:
    /// what [`admit`](Self::admit) would answer, without admitting one.
    pub fn exhausted(&self, tenant: &str, limit: i64) -> bool {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let now = Self::now(&inner);
        let recent: i64 = inner.admitted.get(tenant).map_or(0, |seconds| {
            seconds
                .iter()
                .filter(|(second, _)| second + 60 > now)
                .map(|(_, count)| *count as i64)
                .sum()
        });
        recent >= limit
    }

    /// Whether this is the first request admitted to `what` of `tenant` in
    /// the current minute.
    pub fn first_this_minute(&self, tenant: &str, what: &str) -> bool {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let minute = Self::now(&inner) / 60;
        inner.audited.retain(|_, audited| *audited + 1 >= minute);
        inner
            .audited
            .insert((tenant.to_owned(), what.to_owned()), minute)
            != Some(minute)
    }

    /// Moves the clock on: for tests of what a minute's passing does.
    #[doc(hidden)]
    pub fn advance(&self, seconds: u64) {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .advanced += seconds;
    }
}

pub use crate::lease::Way;

/// A request of an app another edge owns ([`crate::edges`]).
pub(crate) fn misdirected() -> Error {
    Error::new(
        StatusCode::MISDIRECTED_REQUEST,
        "another edge serves this app",
    )
}

/// The app a host name is for, when it is one that may be served: enabled,
/// with the HTTP trigger, not blocked, and of a release that did not fail.
const APP_OF_HOST: &str = "SELECT a.*,h.hostname,h.state AS http_state,h.blocked,h.idle_draining,t.http FROM app_http h JOIN apps a ON a.id=h.app_id JOIN app_triggers t ON t.app_id=a.id JOIN app_releases l ON l.id=a.target_release_id WHERE h.hostname=$1 AND a.desired='enabled' AND t.http AND NOT h.blocked AND l.state<>'failed'";

/// What a request's record keeps of its target: the path, never the query,
/// which may hold a secret.
fn record_path(target: &str) -> String {
    target
        .split('?')
        .next()
        .unwrap_or("/")
        .chars()
        .take(2048)
        .collect()
}

/// The bytes of one request in flight, both ways, counted against its
/// workspace's transfer allowance. Bytes pass only when the gateway's lease
/// of that allowance has room for them ([`crate::lease`]): a body is cut
/// where the allowance, or its size limit, would be passed.
pub struct Meter {
    store: Store,
    reservation: String,
}

impl Meter {
    pub fn new(store: Store, reservation: &str) -> Self {
        Self {
            store,
            reservation: reservation.to_owned(),
        }
    }

    /// Whether `bytes` more may pass `way`. In memory, unless the lease is
    /// short: it is then asked to be extended, once, before they pass.
    pub async fn admit(&self, way: Way, bytes: usize) -> bool {
        use crate::lease::Pass;
        let limit = match way {
            Way::In => MAX_REQUEST_BYTES,
            Way::Out => MAX_RESPONSE_BYTES,
        };
        let budgets = &self.store.gateway.budgets;
        loop {
            match budgets.pass(&self.reservation, way, bytes, limit) {
                Pass::Passed => return true,
                Pass::Refused => return false,
                Pass::Short { key, need, want } => {
                    if !self.store.lease_extend(&key, need, want).await {
                        budgets.refuse(&self.reservation);
                        return false;
                    }
                }
            }
        }
    }

    /// Keeps the reservation from expiring while a body is slow. A
    /// reservation that cannot be kept admits nothing more.
    pub async fn renew(&self) {
        if self.store.ingress_renew(&self.reservation).await.is_err() {
            self.store.gateway.budgets.refuse(&self.reservation);
        }
    }

    /// The bytes passed so far, both ways.
    pub async fn passed(&self) -> i64 {
        self.store.gateway.budgets.passed(&self.reservation)
    }
}
impl Store {
    /// Settles the reservations that lapsed, and says which they were: a
    /// record of one this process still holds is then ended
    /// ([`Store::ingress_expired`]), once the transaction has committed.
    pub(crate) async fn expire_ingress(tx: &mut Tx) -> Result<Vec<String>> {
        let mut expired = Vec::new();
        exec(tx,"DELETE FROM app_http_runs WHERE id IN (SELECT id FROM app_http_runs WHERE finished_at IS NOT NULL AND created<now()-interval '30 days' ORDER BY created,id LIMIT 512)",args![]).await?;
        for row in rows(
            tx,
            "DELETE FROM ingress_reservations WHERE expires<now() RETURNING *",
            args![],
        )
        .await?
        {
            expired.push(s(&row["id"]).to_owned());
            // The row of a request another process had in flight, written
            // while it was: that process is not there to finish it.
            exec(tx,"UPDATE app_http_runs SET state=CASE WHEN started_at IS NULL THEN 'failed' ELSE 'unknown' END,finished_at=clock_timestamp() WHERE id=$1 AND finished_at IS NULL",args![row["id"]]).await?;
            let bytes = if !row["app_id"].is_null() && row["execution_id"].is_null() {
                json!(0)
            } else {
                row["bytes"].clone()
            };
            exec(tx,"INSERT INTO traffic_usage(tenant_id,project_id,period,bytes,requests) VALUES($1,$2,$3::date,$4,1) ON CONFLICT(tenant_id,project_id,period) DO UPDATE SET bytes=traffic_usage.bytes+excluded.bytes,requests=traffic_usage.requests+1",args![row["tenant_id"],row["project_id"],row["period"],bytes]).await?;
        }
        Ok(expired)
    }
    /// Ends the records of requests whose reservations lapsed: never given
    /// to an app, they did not run; given to one, they may have, and are
    /// charged all they had reserved of their lease. The request itself
    /// was counted when its reservation was settled.
    pub(crate) fn ingress_expired(&self, expired: &[String]) {
        for request in expired {
            self.gateway.gates.leave(request);
            self.gateway.ended(request, None);
            self.gateway.budgets.land(request, None, false);
        }
    }
    pub async fn ingress_start(
        &self,
        hostname: &str,
        request_bytes: usize,
    ) -> Result<(Value, String)> {
        let (route, lease) = self.ingress_begin(hostname, request_bytes, false).await?;
        Ok((route.ok_or_else(Error::internal)?, lease))
    }
    async fn ingress_route(tx: &mut Tx, hostname: &str) -> Result<Option<Value>> {
        optional(tx,"SELECT r.*,e.id execution_id,e.generation,e.spec->>'request_timeout_ms' AS request_timeout_ms,h.app_id AS http_app_id,n.endpoint,n.cert_sha256 FROM routes r JOIN deployments d ON d.id=r.deployment_id LEFT JOIN app_http h ON h.deployment_id=d.id JOIN executions e ON e.deployment_id=d.id AND (e.revision=d.revision OR h.execution_id=e.id) JOIN nodes n ON n.id=e.node_id LEFT JOIN apps a ON a.id=h.app_id LEFT JOIN app_triggers t ON t.app_id=a.id WHERE r.hostname=$1 AND d.desired='running' AND e.desired='running' AND e.state='running' AND e.reserved AND NOT n.disabled AND n.last_seen>now()-interval '15 seconds' AND n.observed_confinement=$2 AND (h.app_id IS NULL OR (a.desired='enabled' AND t.http AND h.state='serving' AND h.execution_id=e.id)) ORDER BY e.created DESC LIMIT 1",args![hostname,HOST_CONFINEMENT]).await
    }
    /// Trusted gateway admission. Waiting stores only bounded lease metadata;
    /// the request body remains in the live gateway and is never replayed.
    pub async fn ingress_begin(
        &self,
        hostname: &str,
        request_bytes: usize,
        allow_wait: bool,
    ) -> Result<(Option<Value>, String)> {
        self.ingress_begin_request(hostname, request_bytes, allow_wait, None)
            .await
    }
    async fn ingress_begin_request(
        &self,
        hostname: &str,
        request_bytes: usize,
        allow_wait: bool,
        request: Option<(&str, &str)>,
    ) -> Result<(Option<Value>, String)> {
        let admitted = self
            .ingress_admit(hostname, request_bytes, allow_wait, request)
            .await;
        self.load.admission(admitted.is_ok());
        admitted
    }
    async fn ingress_admit(
        &self,
        hostname: &str,
        request_bytes: usize,
        allow_wait: bool,
        request: Option<(&str, &str)>,
    ) -> Result<(Option<Value>, String)> {
        if request_bytes as u64 > MAX_REQUEST_BYTES {
            return Err(Error::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request body too large",
            ));
        }
        // Refused without the mutation lock: a host name that is nobody's,
        // and a workspace past its requests for this minute. Not asked
        // while the database cannot be reached: what is known of the host
        // name, below, decides.
        let whose = match self.ingress_hosts.get(hostname) {
            _ if self.gateway.outage.down_for().is_some() => Some((String::new(), i64::MAX)),
            Some(whose) => whose,
            None => match crate::outage::within(
                crate::outage::READ_WITHIN,
                self.ingress_whose(hostname),
            )
            .await
            {
                Ok(whose) => {
                    self.ingress_hosts.remember(hostname, whose.clone());
                    whose
                }
                // The database went away: what the gates know decides.
                Err(error) if self.gateway.outage.failed(&error) => Some((String::new(), i64::MAX)),
                Err(error) => return Err(error),
            },
        };
        let tenant = whose.as_ref().map(|(tenant, _)| tenant.clone());
        match whose {
            None => {
                return Err(Error::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "service unavailable",
                ));
            }
            Some((tenant, limit)) if self.http_rates.exhausted(&tenant, limit) => {
                return Err(quota("ingress allowance exhausted"));
            }
            Some(_) => {}
        }
        // An app that is serving admits its requests from what the gateway
        // knows of it in memory ([`crate::gate`]): no transaction. What is
        // known is read again, without the lock, once it is old.
        use crate::gate::Look;
        let gate = match self.gateway.gates.look(hostname) {
            Look::Warm(gate) => Some(gate),
            Look::Closed => None,
            Look::Unknown => self.gate_read(hostname).await?,
        };
        if let Some(gate) = gate {
            if !self.owns(gate.owner.as_deref()) {
                return Err(misdirected());
            }
            let reservation = self.ingress_warm(&gate, request).await?;
            return Ok((Some(gate.route), reservation));
        }
        // The cold path needs the database; while it cannot be reached it
        // is refused at once rather than left to wait for a connection.
        if self.gateway.outage.down_for().is_some() {
            return Err(Error::database_unavailable());
        }
        self.load.cold();
        // The request is counted as in flight from the moment it is
        // admitted; one that is not admitted after all is not.
        let reservation = uid();
        let mut admitted = self
            .ingress_cold(hostname, allow_wait, request, &reservation)
            .await;
        // This process's share of the workspace's limits had no room for
        // it. With the lock let go, it waits for one the workspace has room
        // for, as a warm request does, and is admitted once more.
        if matches!(&admitted, Err(e) if e.status == StatusCode::TOO_MANY_REQUESTS && e.message == SHARE_SHORT)
            && let Some(tenant) = tenant.filter(|t| !t.is_empty())
        {
            self.gateway.gates.leave(&reservation);
            if self.share_with_room(&tenant).await {
                admitted = self
                    .ingress_cold(hostname, allow_wait, request, &reservation)
                    .await;
            }
        }
        if admitted.is_err() {
            self.gateway.gates.leave(&reservation);
        }
        admitted.map(|route| (route, reservation))
    }

    /// Takes this process's share of `tenant`'s limits again, until it has
    /// room for one more request or the workspace has none to give, for
    /// two seconds at most: another process gives back what it does not
    /// use at its next flush ([`crate::shares`]). Whether it has room.
    async fn share_with_room(&self, tenant: &str) -> bool {
        let until = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            let taken = crate::outage::within(crate::outage::READ_WITHIN, async {
                let mut tx = self.gateway_transaction().await?;
                let limits = one(&mut tx,"SELECT http_concurrent_requests concurrent,http_requests_per_minute per_minute FROM tenants WHERE id=$1",args![tenant]).await?;
                let taken = self
                    .take_share(&mut tx, tenant, n(&limits["concurrent"]), n(&limits["per_minute"]))
                    .await?;
                tx.commit().await?;
                Ok::<_, Error>(taken)
            })
            .await;
            let Ok((share, room)) = taken else {
                return false;
            };
            self.gateway.shares.set(tenant, (share, room));
            if share.concurrent > self.gateway.gates.in_flight_of(tenant) as i64
                && share.per_minute > self.http_rates.count(tenant)
            {
                return true;
            }
            if room.concurrent < 1 && room.per_minute < 1 || tokio::time::Instant::now() >= until {
                return false;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }
    /// Whose `hostname` is, and its workspace's requests a minute.
    async fn ingress_whose(&self, hostname: &str) -> Result<Option<(String, i64)>> {
        let mut tx = self.transaction(false, false).await?;
        Ok(optional(&mut tx,"SELECT t.id,t.http_requests_per_minute FROM tenants t WHERE t.id=COALESCE((SELECT tenant_id FROM routes WHERE hostname=$1 LIMIT 1),(SELECT tenant_id FROM app_http WHERE hostname=$1 LIMIT 1))",args![hostname]).await?
            .map(|row| (s(&row["id"]).to_owned(), n(&row["http_requests_per_minute"]))))
    }
    /// What is to be known of `hostname` for its requests to be admitted
    /// in memory, read without the lock: `None` when nothing serves it, its
    /// workspace is not active, or its app's gate is closed.
    async fn gate_read(&self, hostname: &str) -> Result<Option<crate::gate::Gate>> {
        // While the database cannot be reached, what was last read is
        // believed, for as long as the outage is within its bound.
        let outage = &self.gateway.outage;
        let stale = || {
            if outage.serving_stale() {
                Ok(self.gateway.gates.stale(hostname))
            } else {
                Err(Error::database_unavailable())
            }
        };
        if outage.down_for().is_some() {
            return stale();
        }
        match crate::outage::within(crate::outage::READ_WITHIN, self.gate_fetch(hostname)).await {
            Err(error) if outage.failed(&error) => stale(),
            read => read,
        }
    }
    async fn gate_fetch(&self, hostname: &str) -> Result<Option<crate::gate::Gate>> {
        let epoch = self.gateway.gates.epoch();
        let mut tx = self.transaction(false, false).await?;
        let Some(route) = Self::ingress_route(&mut tx, hostname).await? else {
            self.gateway.gates.forget(hostname);
            return Ok(None);
        };
        let app = optional(&mut tx, APP_OF_HOST, args![hostname]).await?;
        let limits = one(
            &mut tx,
            "SELECT t.lifecycle_state='active' AS active,t.http_concurrent_requests,t.http_requests_per_minute,(SELECT edge_id FROM app_edges WHERE app_id=$2) AS owner FROM tenants t WHERE t.id=$1",
            args![
                route["tenant_id"],
                route["http_app_id"]
                    .as_str()
                    .or(app.as_ref().and_then(|app| app["id"].as_str()))
            ],
        )
        .await?;
        drop(tx);
        if limits["active"] != true {
            self.gateway.gates.forget(hostname);
            return Ok(None);
        }
        let gate = Self::gate_of(hostname, &route, app.as_ref(), &limits);
        Ok(self
            .gateway
            .gates
            .read(hostname, gate.clone(), epoch)
            .then_some(gate))
    }
    fn gate_of(
        hostname: &str,
        route: &Value,
        app: Option<&Value>,
        limits: &Value,
    ) -> crate::gate::Gate {
        let id = |value: &Value| value.as_str().map(str::to_owned);
        crate::gate::Gate {
            tenant: s(&route["tenant_id"]).to_owned(),
            project: s(&route["project_id"]).to_owned(),
            app: id(&route["http_app_id"]).or_else(|| app.and_then(|app| id(&app["id"]))),
            release: app.and_then(|app| id(&app["target_release_id"])),
            hostname: route["hostname"].as_str().unwrap_or(hostname).to_owned(),
            route: route.clone(),
            concurrent: n(&limits["http_concurrent_requests"]),
            per_minute: n(&limits["http_requests_per_minute"]),
            owner: id(&limits["owner"]),
        }
    }
    /// Admission in memory, for an app that is serving: its workspace's
    /// allowance, limits and rate are what the gateway holds and counts.
    /// The only transaction is one that extends a lease that has run out.
    async fn ingress_warm(
        &self,
        gate: &crate::gate::Gate,
        request: Option<(&str, &str)>,
    ) -> Result<String> {
        let key = (gate.tenant.clone(), gate.project.clone());
        let (budgets, gates) = (&self.gateway.budgets, &self.gateway.gates);
        if budgets.exhausted(&key) {
            return Err(quota("transfer allowance exhausted"));
        }
        // A request is admitted while a block of the allowance is left.
        if let Some(want) = budgets.short(&key)
            && !self.lease_extend(&key, crate::lease::BLOCK, want).await
        {
            // Run dry while the database cannot be reached: not the
            // allowance's end, and to be asked again.
            if self.gateway.outage.down_for().is_some() {
                return Err(Error::database_unavailable());
            }
            return Err(quota("transfer allowance exhausted"));
        }
        // This process's share of the workspace's limits ([`crate::shares`]).
        let share = self
            .share(&gate.tenant, gate.concurrent, gate.per_minute)
            .await?;
        let reservation = uid();
        let entered = crate::gate::Entered {
            tenant: gate.tenant.clone(),
            app: gate.app.clone(),
            row: false,
            bound: true,
        };
        let mut share = share;
        let mut entered = Some(entered);
        loop {
            let entering = entered.take().expect("not yet entered");
            if gates.enter(&reservation, entering.clone(), share.concurrent) {
                if self.http_rates.admit(&gate.tenant, share.per_minute) {
                    break;
                }
                gates.leave(&reservation);
            }
            // This edge's share has no room, but the workspace may have:
            // other edges give back what they do not use at their next
            // flush ([`crate::shares`]).
            let (in_flight, admitted) = (
                gates.in_flight_of(&gate.tenant) as i64,
                self.http_rates.count(&gate.tenant),
            );
            match self
                .grow_share(&gate.tenant, gate.concurrent, gate.per_minute, |grown| {
                    grown.concurrent > in_flight && grown.per_minute > admitted
                })
                .await
            {
                Some(grown) => {
                    share = grown;
                    entered = Some(entering);
                }
                None => return Err(quota("ingress allowance exhausted")),
            }
        }
        budgets.take_off(&reservation, &key, true);
        if let (Some((method, path)), Some(app), Some(release)) =
            (request, &gate.app, &gate.release)
        {
            self.gateway.opened(
                &reservation,
                crate::gateway::Opened {
                    tenant: gate.tenant.clone(),
                    project: gate.project.clone(),
                    app: app.clone(),
                    release: release.clone(),
                    execution: gate.route["execution_id"].as_str().map(str::to_owned),
                    method: method.to_owned(),
                    path: record_path(path),
                },
            );
        }
        if self
            .http_rates
            .first_this_minute(&gate.tenant, &gate.hostname)
        {
            self.gateway
                .admitted(&reservation, &gate.tenant, &gate.hostname);
        }
        Ok(reservation)
    }
    /// Admission in a transaction under the mutation lock: what admits a
    /// request to an app that is not serving, starts one that is idle, and
    /// holds the request while it starts.
    async fn ingress_cold(
        &self,
        hostname: &str,
        allow_wait: bool,
        request: Option<(&str, &str)>,
        reservation: &str,
    ) -> Result<Option<Value>> {
        let epoch = self.gateway.gates.epoch();
        let mut tx = self.gateway_transaction().await?;
        let route = Self::ingress_route(&mut tx, hostname).await?;
        let app = optional(&mut tx, APP_OF_HOST, args![hostname]).await?;
        // A request waits while its app has nothing ready to serve it but
        // is on its way to having: starting, being replaced in turn,
        // restarting after a failure, or idle and about to be woken.
        if route.is_none()
            && (!allow_wait
                || app.as_ref().is_none_or(|a| {
                    !matches!(s(&a["http_state"]), "idle" | "starting" | "stopping")
                        && a["idle_draining"] != true
                }))
        {
            return Err(Error::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "service unavailable",
            ));
        }
        let expired = Self::expire_ingress(&mut tx).await?;
        let context = route
            .as_ref()
            .or(app.as_ref())
            .ok_or_else(Error::internal)?;
        let tenant = &context["tenant_id"];
        Self::require_workspace_active(&mut tx, s(tenant)).await?;
        // The workspace's plan: requests in flight at once and requests
        // admitted in a minute, both counted in memory ([`crate::gate`],
        // [`Rates`]).
        let limits = one(
            &mut tx,
            "SELECT true AS active,t.http_concurrent_requests,t.http_requests_per_minute,(SELECT edge_id FROM app_edges WHERE app_id=$2) AS owner FROM tenants t WHERE t.id=$1",
            args![
                tenant,
                context["http_app_id"]
                    .as_str()
                    .or(app.as_ref().and_then(|app| app["id"].as_str()))
            ],
        )
        .await?;
        // Another edge's app: its requests are that edge's to admit.
        if !self.owns(limits["owner"].as_str()) {
            return Err(misdirected());
        }
        let entered = crate::gate::Entered {
            tenant: s(tenant).to_owned(),
            app: context["http_app_id"]
                .as_str()
                .or(app.as_ref().and_then(|app| app["id"].as_str()))
                .map(str::to_owned),
            // Only a request that waits for its app to start has a
            // reservation: it is what starts the app.
            row: route.is_none(),
            bound: route.is_some(),
        };
        let (share, taken) = match self.gateway.shares.of(s(tenant)) {
            Some(share) => (share, None),
            None => {
                let taken = self
                    .take_share(
                        &mut tx,
                        s(tenant),
                        n(&limits["http_concurrent_requests"]),
                        n(&limits["http_requests_per_minute"]),
                    )
                    .await?;
                (taken.0, Some(taken))
            }
        };
        if !self
            .gateway
            .gates
            .enter(reservation, entered, share.concurrent)
        {
            return Err(quota(SHARE_SHORT));
        }
        // The request's bytes come out of the gateway's lease of the
        // workspace's transfer allowance. A lease with not a block left is
        // extended here, where the lock is already held; one that cannot
        // be, and has nothing, admits no request.
        let key = (s(tenant).to_owned(), s(&context["project_id"]).to_owned());
        let grant = match self.gateway.budgets.short(&key) {
            Some(want) => {
                let (period, granted) = self.lease_grant(&mut tx, &key, want).await?;
                // A request is admitted while a block of the allowance is
                // left: what the lease has and what it was just granted.
                if granted < crate::lease::BLOCK
                    && !self
                        .gateway
                        .budgets
                        .has(&key, crate::lease::BLOCK - granted)
                {
                    return Err(quota("transfer allowance exhausted"));
                }
                Some((period, granted, want))
            }
            None => None,
        };
        if !self.http_rates.admit(s(tenant), share.per_minute) {
            return Err(quota(SHARE_SHORT));
        }
        // What was read here, under the lock, is what the gateway now
        // knows of the host name: its next requests come in warm.
        let gate = route
            .as_ref()
            .map(|route| Self::gate_of(hostname, route, app.as_ref(), &limits));
        let app = app.as_ref().unwrap_or(&Value::Null);
        if route.is_none() {
            exec(&mut tx,"INSERT INTO ingress_reservations(id,tenant_id,project_id,period,bytes,execution_id,app_id,release_id,app_revision,expires) VALUES($1,$2,$3,date_trunc('month',now() AT TIME ZONE 'UTC')::date,$4,$5,$6,$7,$8::bigint,now()+CASE WHEN $9 THEN interval '10 seconds' ELSE interval '90 seconds' END)",args![reservation,tenant,context["project_id"],0,route.as_ref().map(|r|r["execution_id"].clone()),app["id"],app["target_release_id"],app["revision"],route.is_none()]).await?;
        }
        // The request's record is kept in memory and written when it ends
        // ([`crate::gateway`]): made here, and held once this has committed.
        let record =
            request
                .filter(|_| !app.is_null())
                .map(|(method, path)| crate::gateway::Opened {
                    tenant: s(tenant).to_owned(),
                    project: s(&context["project_id"]).to_owned(),
                    app: s(&app["id"]).to_owned(),
                    release: s(&app["target_release_id"]).to_owned(),
                    execution: route
                        .as_ref()
                        .and_then(|route| route["execution_id"].as_str())
                        .map(str::to_owned),
                    method: method.to_owned(),
                    path: record_path(path),
                });
        // Admission is audited once a minute for each app or route, with
        // the first request of that minute; each request has its own record
        // (`app_http_runs`) and its usage. The audit row is the flusher's
        // to write too.
        let admitted = context["hostname"].as_str().unwrap_or(hostname);
        let audited = self.http_rates.first_this_minute(s(tenant), admitted);
        if !app.is_null() {
            exec(
                &mut tx,
                "UPDATE app_http SET last_activity=now() WHERE app_id=$1",
                args![app["id"]],
            )
            .await?;
            Self::wake_http(&mut tx, s(&app["id"])).await?;
        }
        tx.commit().await?;
        if let Some(taken) = taken {
            self.gateway.shares.set(s(tenant), taken);
        }
        self.ingress_expired(&expired);
        if let Some(gate) = gate {
            self.gateway.gates.open(hostname, gate, epoch);
        }
        if let Some((period, granted, want)) = grant {
            self.gateway.budgets.granted(&key, &period, granted, want);
        }
        // A request of an app that has nothing serving yet has no
        // execution to pass bytes to until it is given one.
        self.gateway
            .budgets
            .take_off(reservation, &key, route.is_some() || app.is_null());
        if let Some(record) = record {
            self.gateway.opened(reservation, record);
        }
        if audited {
            self.gateway.admitted(reservation, s(tenant), admitted);
        }
        Ok(route)
    }
    pub async fn ingress_poll(&self, reservation: &str) -> Result<Option<Value>> {
        let mut tx = self.gateway_transaction().await?;
        let q=optional(&mut tx,"SELECT q.*,h.hostname,h.blocked,a.desired,t.http,a.target_release_id,a.revision FROM ingress_reservations q JOIN apps a ON a.id=q.app_id JOIN app_http h ON h.app_id=a.id JOIN app_triggers t ON t.app_id=a.id WHERE q.id=$1 AND q.expires>now()",args![reservation]).await?.ok_or_else(||Error::new(StatusCode::SERVICE_UNAVAILABLE,"HTTP wake request expired"))?;
        Self::require_workspace_active(&mut tx, s(&q["tenant_id"])).await?;
        if !q["execution_id"].is_null()
            || q["desired"] != "enabled"
            || q["http"] != true
            || q["blocked"] == true
            || q["target_release_id"] != q["release_id"]
            || q["revision"] != q["app_revision"]
        {
            return Err(Error::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "HTTP activation changed or failed",
            ));
        }
        let route = Self::ingress_route(&mut tx, s(&q["hostname"])).await?;
        if let Some(route) = &route {
            exec(&mut tx,"UPDATE ingress_reservations SET execution_id=$1,expires=now()+interval '90 seconds' WHERE id=$2",args![route["execution_id"],reservation]).await?;
            exec(
                &mut tx,
                "UPDATE app_http SET last_activity=now() WHERE app_id=$1",
                args![q["app_id"]],
            )
            .await?;
        }
        tx.commit().await?;
        if let Some(execution) = route.as_ref().and_then(|r| r["execution_id"].as_str()) {
            self.gateway.bound(reservation, execution);
            self.gateway.budgets.bound(reservation);
            self.gateway.gates.bound(reservation);
        }
        Ok(route)
    }
    pub async fn ingress_wait_request(
        &self,
        hostname: &str,
        request_bytes: usize,
        request: Option<(&str, &str)>,
    ) -> Result<(Value, String)> {
        let (route, lease) = self
            .ingress_begin_request(hostname, request_bytes, true, request)
            .await?;
        if let Some(route) = route {
            return Ok((route, lease));
        }
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let polled = tokio::time::timeout_at(deadline, self.ingress_poll(&lease))
                .await
                .unwrap_or_else(|_| {
                    Err(Error::new(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "HTTP wake deadline exceeded",
                    ))
                });
            match polled {
                Ok(Some(route)) => return Ok((route, lease)),
                Ok(None) if tokio::time::Instant::now() < deadline => {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await
                }
                result => {
                    self.ingress_finish(&lease, Some(0)).await?;
                    return Err(result.err().unwrap_or_else(|| {
                        Error::new(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "HTTP wake deadline exceeded",
                        )
                    }));
                }
            }
        }
    }
    /// Keeps a request's reservation from expiring while its bodies
    /// stream. Refused when the reservation is gone or the workspace is not
    /// active: the request's bodies must then stop.
    pub async fn ingress_renew(&self, reservation: &str) -> Result<()> {
        // A request that came in warm has no reservation to keep: only
        // that its workspace is still active is asked, without the lock.
        if self.gateway.gates.has_row(reservation) == Some(false) {
            let tenant = self
                .gateway
                .gates
                .tenant_of(reservation)
                .ok_or_else(Error::missing)?;
            // While the database cannot be reached the workspace is as it
            // was: nothing can suspend it.
            if self.gateway.outage.serving_stale() {
                return Ok(());
            }
            let mut tx = self.transaction(false, false).await?;
            return Self::require_workspace_active(&mut tx, &tenant).await;
        }
        let mut tx = self.gateway_transaction().await?;
        let lease = optional(
            &mut tx,
            "SELECT tenant_id FROM ingress_reservations WHERE id=$1 AND expires>now() FOR UPDATE",
            args![reservation],
        )
        .await?
        .ok_or_else(|| Error::new(StatusCode::SERVICE_UNAVAILABLE, "request expired"))?;
        Self::require_workspace_active(&mut tx, s(&lease["tenant_id"])).await?;
        exec(
            &mut tx,
            "UPDATE ingress_reservations SET expires=now()+interval '90 seconds' WHERE id=$1",
            args![reservation],
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }
    /// Sets how many requests of a workspace's HTTP apps may be in flight at
    /// once and how many may be admitted in a minute. An operator's.
    pub async fn update_http_limits(
        &self,
        p: &Principal,
        tenant: &str,
        value: Value,
    ) -> Result<Value> {
        self.update_http_limits_keyed(p, tenant, value, None).await
    }
    pub async fn update_http_limits_keyed(
        &self,
        p: &Principal,
        tenant: &str,
        value: Value,
        key: Option<&str>,
    ) -> Result<Value> {
        p.operator()?;
        crate::model::identity(tenant)?;
        let names = ["concurrent_requests", "requests_per_minute"];
        fields(&value, &names, &names)?;
        let concurrent =
            fenders_node_protocol::value::integer(&value["concurrent_requests"], 1, 10_000)?;
        let rate =
            fenders_node_protocol::value::integer(&value["requests_per_minute"], 1, 10_000_000)?;
        let request = json!({"kind":"tenant.http-limits","tenant":tenant,"value":value});
        let mut tx = self.transaction(true, false).await?;
        Self::live_principal(&mut tx, p).await?;
        if let Some(key) = key
            && let Some(row) =
                crate::customer_api::operator_receipt(&mut tx, &p.id, key, &request).await?
        {
            return Ok(row);
        }
        let row = optional(&mut tx,"UPDATE tenants SET http_concurrent_requests=$2,http_requests_per_minute=$3 WHERE id=$1 RETURNING http_concurrent_requests AS concurrent_requests,http_requests_per_minute AS requests_per_minute",args![tenant,concurrent,rate]).await?.ok_or_else(Error::missing)?;
        Self::audit(
            &mut tx,
            p,
            "tenant.http-limits",
            tenant,
            tenant,
            row.clone(),
        )
        .await?;
        if let Some(key) = key {
            crate::customer_api::save_operator_receipt(
                &mut tx,
                &p.id,
                key,
                Some(tenant),
                &request,
                &row,
            )
            .await?;
        }
        tx.commit().await?;
        // The limits the gateway holds for the workspace are the old ones,
        // and so is this process's share of them: taken again at the next
        // request. Another process's is brought to them by its next flush.
        self.gateway.gates.forget_all();
        self.gateway.shares.drop_share(tenant);
        Ok(row)
    }
    pub async fn ingress_finish(&self, reservation: &str, used: Option<i64>) -> Result<()> {
        self.ingress_complete(reservation, used, None).await
    }
    /// The request is being offered to its app: from here, only its not
    /// being taken proves that it did not run. Kept in the request's record,
    /// in memory; nothing is written until a flush.
    pub fn ingress_dispatched(&self, reservation: &str) {
        self.gateway.dispatched(reservation);
    }
    pub async fn ingress_complete(
        &self,
        reservation: &str,
        used: Option<i64>,
        status: Option<u16>,
    ) -> Result<()> {
        // No longer in flight; that its app was active is written by the
        // next flush. A request that came in warm has nothing in the
        // database to settle: it ends here, in memory.
        let settled = match self.gateway.gates.leave(reservation) {
            Some(entered) if !entered.row => true,
            _ => {
                let mut tx = self.gateway_transaction().await?;
                let row = optional(
                    &mut tx,
                    "DELETE FROM ingress_reservations WHERE id=$1 RETURNING id",
                    args![reservation],
                )
                .await?;
                tx.commit().await?;
                row.is_some()
            }
        };
        // Its record ends with it, and what it used of its lease is used:
        // written, with the request itself, by the next flush. One that
        // already ended, because its reservation lapsed, is not ended
        // otherwise.
        self.gateway.ended(reservation, status);
        // A request whose reservation had lapsed was counted when that was
        // settled.
        self.gateway.budgets.land(reservation, used, settled);
        Ok(())
    }
}

#[cfg(test)]
mod rate_tests {
    use super::Rates;

    #[test]
    fn a_refused_rate_says_when_its_minute_turns() {
        let rates = Rates::default();
        assert!(rates.admit("w", 2));
        rates.advance(20);
        assert!(rates.admit("w", 2));
        assert!(!rates.admit("w", 2));
        // The first admitted leaves the minute 40 seconds from now.
        assert_eq!(rates.retry_after("w"), 40);
        rates.advance(39);
        assert_eq!(rates.retry_after("w"), 1);
        rates.advance(1);
        assert!(rates.admit("w", 2));
        // Never none: a caller told to wait no time would not wait.
        assert_eq!(rates.retry_after("nobody"), 1);
    }
}
