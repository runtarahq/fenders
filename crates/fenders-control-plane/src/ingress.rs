use crate::{
    args,
    db::*,
    error::{Error, Result},
    model::*,
    store::{Store, Tx},
};
use axum::http::StatusCode;
use serde_json::{Value, json};

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
        // and a workspace past its requests for this minute.
        let whose = match self.ingress_hosts.get(hostname) {
            Some(whose) => whose,
            None => {
                let mut tx = self.transaction(false, false).await?;
                let whose = optional(&mut tx,"SELECT t.id,t.http_requests_per_minute FROM tenants t WHERE t.id=COALESCE((SELECT tenant_id FROM routes WHERE hostname=$1 LIMIT 1),(SELECT tenant_id FROM app_http WHERE hostname=$1 LIMIT 1))",args![hostname]).await?
                    .map(|row| (s(&row["id"]).to_owned(), n(&row["http_requests_per_minute"])));
                drop(tx);
                self.ingress_hosts.remember(hostname, whose.clone());
                whose
            }
        };
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
        let mut tx = self.transaction(true, false).await?;
        let route = Self::ingress_route(&mut tx, hostname).await?;
        let app=optional(&mut tx,"SELECT a.*,h.hostname,h.state AS http_state,h.blocked,h.idle_draining,t.http FROM app_http h JOIN apps a ON a.id=h.app_id JOIN app_triggers t ON t.app_id=a.id JOIN app_releases l ON l.id=a.target_release_id WHERE h.hostname=$1 AND a.desired='enabled' AND t.http AND NOT h.blocked AND l.state<>'failed'",args![hostname]).await?;
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
        // The workspace's plan: requests in flight at once, which are the
        // reservations held, and requests admitted in a minute, which are
        // counted in memory ([`Rates`]).
        let limits = one(
            &mut tx,
            "SELECT (SELECT count(*) FROM ingress_reservations WHERE tenant_id=t.id) held,t.http_concurrent_requests,t.http_requests_per_minute FROM tenants t WHERE t.id=$1",
            args![tenant],
        )
        .await?;
        if n(&limits["held"]) >= n(&limits["http_concurrent_requests"]) {
            return Err(quota("ingress allowance exhausted"));
        }
        // The request's bytes come out of the gateway's lease of the
        // workspace's transfer allowance. A lease with not a block left is
        // extended here, where the lock is already held; one that cannot
        // be, and has nothing, admits no request.
        let key = (s(tenant).to_owned(), s(&context["project_id"]).to_owned());
        let grant = match self.gateway.budgets.short(&key) {
            Some(want) => {
                let (period, granted) = self.lease_grant(&mut tx, &key, want).await?;
                if granted == 0 && !self.gateway.budgets.has(&key, 1) {
                    return Err(quota("transfer allowance exhausted"));
                }
                Some((period, granted, want))
            }
            None => None,
        };
        if !self
            .http_rates
            .admit(s(tenant), n(&limits["http_requests_per_minute"]))
        {
            return Err(quota("ingress allowance exhausted"));
        }
        let reservation = uid();
        let app = app.as_ref().unwrap_or(&Value::Null);
        exec(&mut tx,"INSERT INTO ingress_reservations(id,tenant_id,project_id,period,bytes,execution_id,app_id,release_id,app_revision,expires) VALUES($1,$2,$3,date_trunc('month',now() AT TIME ZONE 'UTC')::date,$4,$5,$6,$7,$8::bigint,now()+CASE WHEN $9 THEN interval '10 seconds' ELSE interval '90 seconds' END)",args![reservation,tenant,context["project_id"],0,route.as_ref().map(|r|r["execution_id"].clone()),app["id"],app["target_release_id"],app["revision"],route.is_none()]).await?;
        // The request's record is kept in memory and written when it ends
        // ([`crate::gateway`]): made here, and held once this has committed.
        let record = request.filter(|_| !app.is_null()).map(|(method, path)| {
            crate::gateway::Opened {
                tenant: s(tenant).to_owned(),
                project: s(&context["project_id"]).to_owned(),
                app: s(&app["id"]).to_owned(),
                release: s(&app["target_release_id"]).to_owned(),
                execution: route
                    .as_ref()
                    .and_then(|route| route["execution_id"].as_str())
                    .map(str::to_owned),
                method: method.to_owned(),
                // The gateway supplies the URI path, never its potentially secret query.
                path: path
                    .split('?')
                    .next()
                    .unwrap_or("/")
                    .chars()
                    .take(2048)
                    .collect(),
            }
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
        self.ingress_expired(&expired);
        if let Some((period, granted, want)) = grant {
            self.gateway.budgets.granted(&key, &period, granted, want);
        }
        // A request of an app that has nothing serving yet has no
        // execution to pass bytes to until it is given one.
        self.gateway
            .budgets
            .take_off(&reservation, &key, route.is_some() || app.is_null());
        if let Some(record) = record {
            self.gateway.opened(&reservation, record);
        }
        if audited {
            self.gateway.admitted(&reservation, s(tenant), admitted);
        }
        Ok((route, reservation))
    }
    pub async fn ingress_poll(&self, reservation: &str) -> Result<Option<Value>> {
        let mut tx = self.transaction(true, false).await?;
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
        let mut tx = self.transaction(true, false).await?;
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
        let mut tx = self.transaction(true, false).await?;
        let row = optional(
            &mut tx,
            "DELETE FROM ingress_reservations WHERE id=$1 RETURNING *",
            args![reservation],
        )
        .await?;
        if let Some(row) = &row {
            let queued = !row["app_id"].is_null() && row["execution_id"].is_null();
            if !queued {
                exec(
                    &mut tx,
                    "UPDATE app_http SET last_activity=now() WHERE execution_id=$1",
                    args![row["execution_id"]],
                )
                .await?;
            }
        }
        tx.commit().await?;
        // Its record ends with it, and what it used of its lease is used:
        // written, with the request itself, by the next flush. One that
        // already ended, because its reservation lapsed, is not ended
        // otherwise.
        self.gateway.ended(reservation, status);
        // A request whose reservation had lapsed was counted when that was
        // settled.
        self.gateway.budgets.land(reservation, used, row.is_some());
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
