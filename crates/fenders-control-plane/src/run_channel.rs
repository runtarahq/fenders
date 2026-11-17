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
        mut batch: Value,
    ) -> Result<Value> {
        if !batch.is_object() || batch.get("boot_id").is_some() {
            return Err(Error::invalid("invalid log batch fields"));
        }
        let mut tx = self.transaction(false, false).await?;
        let placed = optional(
            &mut tx,
            "SELECT e.node_id,n.boot_id FROM executions e JOIN nodes n ON n.id=e.node_id WHERE e.id=$1 AND e.generation=$2 AND e.reserved",
            args![execution, generation],
        )
        .await?
        .ok_or_else(|| Error::new(StatusCode::CONFLICT, "launch is no longer current"))?;
        drop(tx);
        batch["boot_id"] = placed["boot_id"].clone();
        let node = placed["node_id"]
            .as_str()
            .ok_or_else(|| Error::new(StatusCode::CONFLICT, "launch is no longer current"))?;
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
        ask: Value,
    ) -> Result<Value> {
        crate::db::fields(
            &ask,
            &["expected_revision", "request_id", "bytes"],
            &["expected_revision", "request_id", "bytes"],
        )?;
        let mut tx = self.transaction(false, false).await?;
        let placed = optional(
            &mut tx,
            "SELECT e.node_id,n.boot_id FROM executions e JOIN nodes n ON n.id=e.node_id WHERE e.id=$1 AND e.generation=$2 AND e.reserved AND e.egress_budget_launcher IS NOT NULL",
            args![execution, generation],
        )
        .await?
        .ok_or_else(|| Error::new(StatusCode::CONFLICT, "launch is not under the outbound byte limit"))?;
        drop(tx);
        let node = placed["node_id"]
            .as_str()
            .ok_or_else(|| Error::new(StatusCode::CONFLICT, "launch is no longer current"))?;
        let request = json!({
            "boot_id": placed["boot_id"],
            "action": "grant",
            "expected_revision": ask["expected_revision"],
            "request_id": ask["request_id"],
            "bytes": ask["bytes"],
        });
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

    /// What this execution's current launch takes requests from, when it is
    /// an HTTP run: the key of its queue in the exchange. An app's
    /// executions share the app's queue: the one its binding names and the
    /// extras of that binding's generation. An execution of a release still
    /// being brought up has a queue of its own, which nothing is offered to,
    /// so its asking shows it is ready and takes nothing. An execution that
    /// belongs to no app takes its own requests.
    async fn run_channel_http(&self, execution: &str, generation: i64) -> Result<String> {
        let mut tx = self.transaction(false, false).await?;
        let found = optional(
            &mut tx,
            "SELECT m.app_id AS managed,m.execution_id=e.id AS serves,m.candidate_execution_id=e.id AS candidate,EXISTS(SELECT 1 FROM app_http_extras x WHERE x.execution_id=e.id AND x.app_id=m.app_id AND x.generation=m.generation-CASE WHEN m.candidate_until IS NOT NULL THEN 1 ELSE 0 END) AS extra FROM executions e LEFT JOIN app_http m ON m.deployment_id=e.deployment_id WHERE e.id=$1 AND e.generation=$2 AND e.reserved AND e.desired='running' AND e.spec->>'mode'='http'",
            args![execution, generation],
        )
        .await?
        .ok_or_else(|| Error::new(StatusCode::CONFLICT, "launch takes no requests"))?;
        if found["managed"].is_null() {
            Ok(execution.to_owned())
        } else if found["serves"] == true || found["extra"] == true {
            Ok(crate::db::s(&found["managed"]).to_owned())
        } else if found["candidate"] == true {
            Ok(candidate_key(execution))
        } else {
            Err(Error::new(StatusCode::CONFLICT, "launch takes no requests"))
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

    /// Whether `credential` is the one issued for this execution and
    /// generation, and that launch is still the execution's current one.
    pub async fn run_channel_authorize(
        &self,
        execution: &str,
        generation: i64,
        credential: &str,
    ) -> Result<()> {
        identity(execution)?;
        let issued = self
            .channel_cipher
            .decrypt(credential)
            .map_err(|_| Error::unauthorized())?;
        if issued != claim(execution, generation).as_bytes() {
            return Err(Error::unauthorized());
        }
        let mut tx = self.transaction(false, false).await?;
        let launch = optional(
            &mut tx,
            "SELECT n.disabled FROM executions e LEFT JOIN nodes n ON n.id=e.node_id WHERE e.id=$1 AND e.generation=$2 AND e.reserved",
            args![execution, generation],
        )
        .await?
        .ok_or_else(|| Error::new(StatusCode::CONFLICT, "launch is no longer current"))?;
        // A disabled node is told nothing more and heard from no more, so
        // nothing moves its runs on: their credentials, which it holds, are
        // refused for as long as it is disabled.
        if launch["disabled"] != false {
            return Err(Error::new(
                StatusCode::FORBIDDEN,
                "the launch's node is disabled",
            ));
        }
        Ok(())
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
    store
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
                .run_channel_output(execution, generation, batch)
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
        let answer = store.run_channel_egress(execution, generation, ask).await?;
        let status = if answer.get("available_bytes").is_some() {
            StatusCode::TOO_MANY_REQUESTS
        } else {
            StatusCode::OK
        };
        return Ok((status, Json(answer)).into_response());
    }
    if parts.method == "POST" && rest == HTTP_NEXT {
        let key = store.run_channel_http(execution, generation).await?;
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
        let app = store.websocket_sender(execution).await?.ok_or_else(|| {
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
