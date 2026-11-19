//! The run channel: the HTTPS endpoint a run's `fenders-shim` calls.
//!
//! A shim node starts a run only when its launch spec names a run channel
//! (`protocol`, `run`, `channel`). The shim verifies the endpoint against the
//! trust in the spec and sends the per-launch credential as a bearer token; it
//! presents no client certificate, so the channel has a listener of its own
//! rather than the node listener's mutual TLS.
//!
//! Each launch gets its own endpoint path, `/run/EXECUTION/GENERATION`, and a
//! credential that authenticates that execution and generation only. The
//! credential is a token under the control plane's encryption key, so nothing
//! is stored for it; a request is also refused once the execution has moved to
//! another generation or released its reservation.
//!
//! Three calls are served. The outcome a shim posts when its VM ended without
//! the guest posting one is acknowledged and not recorded: the control plane
//! takes a run's end from its node's heartbeat. A batch of the guest's output
//! (`v1/run/output`, sent only by a launch whose spec asked with `output`)
//! is stored by [`Store::ingest_execution_logs`], with every check it makes of
//! a batch: the capture covers the execution's secrets, the sequence is
//! consistent, the bounds hold. An ask for outbound bytes (`v1/run/egress`,
//! sent only by a launch placed under the outbound byte limit) is answered by
//! [`Store::egress_budget`], the grant authority, as from the node the
//! execution is on: what it grants is held against the workspace's transfer
//! allowance in the same transaction, and an ask the allowance cannot cover
//! is answered 429 with what is left. The shim of an HTTP run takes its
//! requests here (`v1/run/http/next`, which waits for one) and posts their
//! answers (`v1/run/http/response/ID`): see [`crate::http_exchange`].
use crate::{
    args,
    db::optional,
    error::{Error, Result},
    model::identity,
    store::Store,
};
use axum::{
    Json, Router,
    body::to_bytes,
    extract::{Request, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};

/// The run protocol version the shim speaks.
const PROTOCOL: i64 = 1;
pub(crate) const PURPOSE: &str = "fenders-run-channel-v1";
/// Where a shim posts a run's outcome, under the launch's endpoint.
const OUTCOME: &str = "v1/run/outcome";
const MAX_OUTCOME_BYTES: usize = 64 * 1024;
/// Where a shim posts a batch of its guest's output.
const OUTPUT: &str = "v1/run/output";
/// Where a shim asks for outbound bytes.
const EGRESS: &str = "v1/run/egress";
const MAX_EGRESS_BYTES: usize = 4096;
/// Where the shim of an HTTP run asks for its next request, and where it
/// posts the answer to request `ID` (appended).
const HTTP_NEXT: &str = "v1/run/http/next";
const HTTP_RESPONSE: &str = "v1/run/http/response/";
/// How long an ask for the next request waits before it is told to ask again.
const HTTP_WAIT: std::time::Duration = std::time::Duration::from_secs(25);
const HTTP_CANDIDATE_WAIT: std::time::Duration = std::time::Duration::from_secs(1);
/// Where an execution lists its app's WebSocket connections, and where it
/// sends to or closes connection `ID` (appended).
const WS: &str = "v1/run/ws";
const WS_ONE: &str = "v1/run/ws/";

/// How nodes' shims reach and verify the run channel.
#[derive(Clone, Debug)]
pub struct RunChannel {
    /// `https://host[:port]`, as shims reach the run-channel listener.
    endpoint: String,
    /// PEM certificates the listener's chain leads to.
    ca_pem: String,
    /// The name the listener's certificate is for, when not the endpoint's host.
    server_name: Option<String>,
}

impl RunChannel {
    pub fn new(endpoint: &str, ca_pem: String, server_name: Option<String>) -> Result<Self> {
        let url = url::Url::parse(endpoint)
            .map_err(|_| Error::invalid("run channel endpoint is not a URL"))?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || !matches!(url.path(), "" | "/")
        {
            return Err(Error::invalid(
                "run channel endpoint must be https://host[:port]",
            ));
        }
        if ca_pem.is_empty() || server_name.as_deref().is_some_and(str::is_empty) {
            return Err(Error::invalid("run channel trust is incomplete"));
        }
        Ok(Self {
            endpoint: endpoint.trim_end_matches('/').to_owned(),
            ca_pem,
            server_name,
        })
    }
}

fn claim(execution: &str, generation: i64) -> String {
    format!("{PURPOSE}\n{execution}\n{generation}")
}

impl Store {
    pub fn with_run_channel(mut self, channel: RunChannel) -> Self {
        self.run_channel = Some(std::sync::Arc::new(channel));
        self
    }

    /// Stores a batch of output from the shim of this execution's current
    /// launch. The shim names no node: the batch is taken as from the node the
    /// execution is on, as that node last announced itself.
    async fn run_channel_output(
        &self,
        execution: &str,
        generation: i64,
        launch: &crate::launch::Launch,
        mut batch: Value,
    ) -> Result<Value> {
        if !batch.is_object() || batch.get("boot_id").is_some() {
            return Err(Error::invalid("invalid log batch fields"));
        }
        let (Some(node), Some(boot)) = (&launch.node, &launch.boot) else {
            return Err(Error::new(
                StatusCode::CONFLICT,
                "launch is no longer current",
            ));
        };
        batch["boot_id"] = json!(boot);
        self.ingest_execution_logs(node, execution, generation, batch)
            .await
    }

    /// Grants outbound bytes to the shim of this execution's current launch,
    /// or renews what it holds (`bytes` 0). The shim names no node and no
    /// boot: the ask is taken as from the node the execution is on, as that
    /// node last announced itself, and only for an execution placed under the
    /// limit. Only grants are asked for here; a run's bytes are settled from
    /// its node's final report.
    async fn run_channel_egress(
        &self,
        execution: &str,
        generation: i64,
        launch: &crate::launch::Launch,
        ask: Value,
    ) -> Result<Value> {
        // `sent`, which a shim may give, is what the launcher's meter says
        // the run has sent: a grant is then held to what is yet to be sent.
        crate::db::fields(
            &ask,
            &["expected_revision", "request_id", "bytes", "sent"],
            &["expected_revision", "request_id", "bytes"],
        )?;
        let (true, Some(node), Some(boot)) = (launch.egress, &launch.node, &launch.boot) else {
            return Err(Error::new(
                StatusCode::CONFLICT,
                "launch is not under the outbound byte limit",
            ));
        };
        // A renewal, asking for no more bytes, is answered from memory
        // when this process has the run's grant ([`crate::renewal`]).
        if launch.renewable
            && ask["bytes"].as_i64() == Some(0)
            && let (Some(expected), Some(request)) = (
                ask["expected_revision"].as_i64(),
                ask["request_id"].as_str(),
            )
            && let Some(answer) = self
                .gateway
                .renewals
                .renew(execution, generation, boot, expected, request, &ask)
        {
            return Ok(answer);
        }
        let mut request = json!({
            "boot_id": boot,
            "action": "grant",
            "expected_revision": ask["expected_revision"],
            "request_id": ask["request_id"],
            "bytes": ask["bytes"],
        });
        if let Some(sent) = ask.get("sent") {
            request["sent"] = sent.clone();
        }
        match self
            .egress_budget(node, execution, generation, request)
            .await
        {
            // What the allowance has left, so the shim can ask for that.
            Err(error) if error.status == StatusCode::TOO_MANY_REQUESTS => {
                let status = self
                    .egress_budget_status(node, execution, generation)
                    .await?;
                Ok(json!({"error": error.message, "available_bytes": status["available_bytes"]}))
            }
            result => result,
        }
    }

    /// The run protocol fields of a launch spec, or `None` when no run channel
    /// is configured (no shim node will then start the run).
    pub(crate) fn run_channel_fields(&self, execution: &str, generation: i64) -> Option<Value> {
        let channel = self.run_channel.as_ref()?;
        let mut trust = json!({"ca_pem": channel.ca_pem});
        if let Some(name) = &channel.server_name {
            trust["server_name"] = json!(name);
        }
        Some(json!({
            "protocol": PROTOCOL,
            "run": {"execution": execution, "generation": generation},
            "channel": {
                "endpoint": format!("{}/run/{execution}/{generation}", channel.endpoint),
                "credential": self.channel_cipher.encrypt(claim(execution, generation).as_bytes()),
                "trust": trust,
            },
        }))
    }

    /// What the launch `credential` was issued for is, when it is the
    /// execution's current one. Read from the database at most once in
    /// [`crate::launch::FRESH`], and at once after a change to it.
    pub async fn run_channel_authorize(
        &self,
        execution: &str,
        generation: i64,
        credential: &str,
    ) -> Result<crate::launch::Launch> {
        identity(execution)?;
        let issued = self
            .channel_cipher
            .decrypt(credential)
            .map_err(|_| Error::unauthorized())?;
        if issued != claim(execution, generation).as_bytes() {
            return Err(Error::unauthorized());
        }
        let launch = self.launch(execution, generation).await?;
        // A disabled node is told nothing more and heard from no more, so
        // nothing moves its runs on: their credentials, which it holds, are
        // refused for as long as it is disabled.
        if launch.disabled {
            return Err(Error::new(
                StatusCode::FORBIDDEN,
                "the launch's node is disabled",
            ));
        }
        Ok(launch)
    }

    /// What the launch is, as last read, or read now.
    async fn launch(&self, execution: &str, generation: i64) -> Result<crate::launch::Launch> {
        let epoch = self.gateway.gates.epoch();
        if let Some(launch) = self.gateway.launches.look(execution, generation, epoch) {
            self.load.run_channel(false);
            return Ok(launch);
        }
        // While the database cannot be reached, what was last read of the
        // launch is believed, within the outage's bound.
        let outage = &self.gateway.outage;
        let stale = || match self.gateway.launches.stale(execution, generation) {
            Some(launch) if outage.serving_stale() => Ok(launch),
            _ => Err(Error::database_unavailable()),
        };
        if outage.down_for().is_some() {
            self.load.run_channel(false);
            return stale();
        }
        match crate::outage::within(
            crate::outage::READ_WITHIN,
            self.launch_fetch(execution, generation, epoch),
        )
        .await
        {
            Err(error) if outage.failed(&error) => stale(),
            read => read,
        }
    }
    async fn launch_fetch(
        &self,
        execution: &str,
        generation: i64,
        epoch: u64,
    ) -> Result<crate::launch::Launch> {
        self.load.run_channel(true);
        let mut tx = self.transaction(false, false).await?;
        let row = optional(
            &mut tx,
            crate::launch::QUERY,
            args![
                execution,
                generation,
                crate::model::HOST_CONFINEMENT,
                crate::egress_budget::CONTRACT
            ],
        )
        .await?
        .ok_or_else(|| Error::new(StatusCode::CONFLICT, "launch is no longer current"))?;
        drop(tx);
        let launch = crate::launch::Launch::of(execution, &row);
        self.gateway
            .launches
            .keep(execution, generation, launch.clone(), epoch);
        Ok(launch)
    }
}

/// The queue of an execution that is being brought up beside the one that
/// serves: asked of, never offered to.
pub(crate) fn candidate_key(execution: &str) -> String {
    format!("candidate:{execution}")
}

/// The run-channel listener's routes. Serve it without client authentication.
pub fn router(store: Store) -> Router {
    Router::new().fallback(dispatch).with_state(store)
}

async fn dispatch(State(store): State<Store>, request: Request) -> Result<Response> {
    let (parts, body) = request.into_parts();
    let path = parts.uri.path().trim_matches('/').to_owned();
    let mut segments = path.splitn(4, '/');
    let (Some("run"), Some(execution), Some(generation)) =
        (segments.next(), segments.next(), segments.next())
    else {
        return Err(Error::missing());
    };
    let rest = segments.next().unwrap_or("");
    let generation = generation
        .parse::<i64>()
        .ok()
        .filter(|n| *n > 0)
        .ok_or_else(Error::missing)?;
    let credential = parts
        .headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .filter(|v| !v.is_empty() && v.len() <= 4096)
        .ok_or_else(Error::unauthorized)?;
    let launch = store
        .run_channel_authorize(execution, generation, credential)
        .await?;
    if parts.method == "POST" && rest == OUTCOME {
        to_bytes(body, MAX_OUTCOME_BYTES)
            .await
            .map_err(|_| Error::new(StatusCode::PAYLOAD_TOO_LARGE, "outcome too large"))?;
        return Ok(Json(json!({"acknowledged": true})).into_response());
    }
    if parts.method == "POST" && rest == OUTPUT {
        let bytes = to_bytes(body, crate::execution_logs::MAX_REQUEST)
            .await
            .map_err(|_| Error::new(StatusCode::PAYLOAD_TOO_LARGE, "log batch too large"))?;
        let batch = serde_json::from_slice(&bytes)
            .map_err(|_| Error::invalid("invalid log batch fields"))?;
        return Ok(Json(
            store
                .run_channel_output(execution, generation, &launch, batch)
                .await?,
        )
        .into_response());
    }
    if parts.method == "POST" && rest == EGRESS {
        let bytes = to_bytes(body, MAX_EGRESS_BYTES)
            .await
            .map_err(|_| Error::new(StatusCode::PAYLOAD_TOO_LARGE, "grant request too large"))?;
        let ask =
            serde_json::from_slice(&bytes).map_err(|_| Error::invalid("invalid grant request"))?;
        let answer = store
            .run_channel_egress(execution, generation, &launch, ask)
            .await?;
        let status = if answer.get("available_bytes").is_some() {
            StatusCode::TOO_MANY_REQUESTS
        } else {
            StatusCode::OK
        };
        return Ok((status, Json(answer)).into_response());
    }
    // An HTTP run's requests, and its WebSocket messages, meet the gateway
    // in the memory of the edge that owns its app.
    if (rest == HTTP_NEXT
        || rest.starts_with(HTTP_RESPONSE)
        || rest == WS
        || rest.starts_with(WS_ONE))
        && !store.owns(launch.owner.as_deref())
    {
        return Err(crate::ingress::misdirected());
    }
    if parts.method == "POST" && rest == HTTP_NEXT {
        let key = launch
            .queue
            .clone()
            .ok_or_else(|| Error::new(StatusCode::CONFLICT, "launch takes no requests"))?;
        use crate::http_exchange::{Prefixed, head_frame};
        // A candidate's queue is never offered to: its asks only show that
        // it is ready, and are kept short so that it learns soon after it
        // takes over that it now takes the app's requests.
        let wait = if key == candidate_key(execution) {
            HTTP_CANDIDATE_WAIT
        } else {
            HTTP_WAIT
        };
        return Ok(match store.exchange.next(&key, execution, wait).await {
            // The head, then the request's body as the client sends it.
            Some(request) => (
                [(header::CONTENT_TYPE, "application/octet-stream")],
                axum::body::Body::new(Prefixed::new(head_frame(&request.head), request.body)),
            )
                .into_response(),
            None => StatusCode::NO_CONTENT.into_response(),
        });
    }
    if parts.method == "POST"
        && let Some(id) = rest.strip_prefix(HTTP_RESPONSE)
    {
        use crate::http_exchange::{Message, Prefixed, pipe, pump, read_head};
        // Any current launch may answer what it took: an execution that a
        // new release took over from still finishes the requests it has.
        // The exchange gives an answer only to the request its taker took.
        let mut body = body;
        let Some((head, rest)) = read_head(&mut body).await else {
            // An answer that cannot be read is still the end of what its
            // taker had to do with the request.
            store.exchange.finished(execution, id);
            return Err(Error::invalid("invalid response"));
        };
        // The gateway is given the head now and the body as the shim sends
        // it; this call answers when the body has ended or nobody reads it.
        let (tx, piped) = pipe();
        if !store
            .exchange
            .respond(execution, id, Message { head, body: piped })
        {
            store.exchange.finished(execution, id);
            return Err(Error::new(
                StatusCode::GONE,
                "no request is waiting for this response",
            ));
        }
        let body = axum::body::Body::new(Prefixed::new(rest, body));
        let (_, cut) = pump(body, tx, None, |_| async { true }).await;
        store.exchange.finished(execution, id);
        return Ok(Json(json!({"delivered": cut.is_none()})).into_response());
    }
    // An execution of an app that accepts WebSocket connections sends to
    // them here, over its host-bound origin: `GET v1/run/ws` lists the
    // app's open connections, `POST v1/run/ws/ID` sends one the body as a
    // message (text or binary by content type), `DELETE` closes it.
    if rest == WS || rest.starts_with(WS_ONE) {
        use crate::websocket::{MAX_MESSAGE, Push};
        let app = launch.websocket_app.clone().ok_or_else(|| {
            Error::new(
                StatusCode::FORBIDDEN,
                "this app accepts no WebSocket connections",
            )
        })?;
        let id = rest.strip_prefix(WS_ONE);
        return match (parts.method.as_str(), id) {
            ("GET", None) => {
                Ok(Json(json!({"connections": store.sockets.list(&app)})).into_response())
            }
            ("POST" | "DELETE", Some(id)) => {
                let (tenant, project) = store.sockets.owner(&app, id).ok_or_else(Error::missing)?;
                let push = if parts.method == "DELETE" {
                    Push::Close
                } else {
                    let text = parts
                        .headers
                        .get(header::CONTENT_TYPE)
                        .and_then(|v| v.to_str().ok())
                        .is_some_and(|v| v.starts_with("text/"));
                    let message = to_bytes(body, MAX_MESSAGE).await.map_err(|_| {
                        Error::new(StatusCode::PAYLOAD_TOO_LARGE, "message too large")
                    })?;
                    // What it sends is counted against the transfer allowance.
                    store
                        .websocket_sent(&tenant, &project, message.len() as i64)
                        .await?;
                    match String::from_utf8(message.to_vec()) {
                        Ok(message) if text => Push::Text(message),
                        _ => Push::Binary(message),
                    }
                };
                if !store.sockets.push(&app, id, push).await {
                    return Err(Error::missing());
                }
                Ok(Json(json!({"sent": true})).into_response())
            }
            _ => Err(Error::new(
                StatusCode::METHOD_NOT_ALLOWED,
                "unsupported method",
            )),
        };
    }
    Err(Error::missing())
}
