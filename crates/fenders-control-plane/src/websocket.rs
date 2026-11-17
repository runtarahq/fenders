//! WebSocket for HTTP apps, terminated at the gateway.
//!
//! `wasi:http` has no connection upgrade, so a component cannot accept a
//! WebSocket. The gateway does it for an app that asks (`websocket: true` in
//! its configuration): it holds the client's connection and gives the app
//! each event as an ordinary request to a reserved path of the app's own
//! handler, with the connection's id in the `fenders-connection` header:
//!
//! - `POST /_fenders/ws/connect` when a client asks to connect, with the
//!   path and query it asked for in `fenders-path`. A 2xx answer accepts the
//!   client; any other refuses the upgrade with that status.
//! - `POST /_fenders/ws/message` for each message, as the body: text or
//!   binary by content type. A body in the answer is sent back on the same
//!   connection.
//! - `POST /_fenders/ws/disconnect` when the connection has closed: once,
//!   best effort, its answer ignored.
//!
//! A client cannot ask for `/_fenders/…` itself. The app sends to a
//! connection, closes one or lists those open by calling the run channel
//! over its host-bound origin ([`ORIGIN`]), from any of its executions:
//! see [`crate::run_channel`].
//!
//! Events are requests like any other: admitted, counted against the
//! workspace's limits and transfer allowance, taken by whichever execution
//! is free. So a connection belongs to no execution, and outlives a new
//! release, scaling in and a restart of the app. A connection's messages
//! are given to the app one at a time, in order; while one is with the app
//! the gateway reads no more from that client.
//!
//! Connections are held in this process's memory: a restart closes them.
//! Each is one row among the app's requests (`app_http_runs`, its
//! `websocket` column): opened when the app accepted it, finished when it
//! closed with how many messages and bytes passed each way. Its events are
//! not rows. A row left open by a restart is finished as unknown.
use crate::{
    api::ApiState,
    error::{Error, Result},
    model::uid,
};
use axum::{
    body::{Body, Bytes},
    extract::{
        FromRequestParts, Request,
        ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};
use tokio::sync::mpsc;

/// The host-bound origin an app with WebSocket calls the run channel at.
pub const ORIGIN: &str = "http://fenders.internal";
/// Paths under this are the platform's: events go to them, clients cannot.
pub const RESERVED: &str = "/_fenders/";
/// The largest message, either way.
pub const MAX_MESSAGE: usize = 1024 * 1024;
/// Connections one app and one workspace may have open.
const MAX_PER_APP: usize = 1000;
const MAX_PER_WORKSPACE: usize = 4000;
/// Messages a connection may send in one second.
const MAX_PER_SECOND: u32 = 20;
/// How often a quiet connection is pinged, and how long one may send
/// nothing at all, a pong included.
const PING: Duration = Duration::from_secs(30);
const SILENT: Duration = Duration::from_secs(75);

/// What the app sends a connection.
pub enum Push {
    Text(String),
    Binary(Bytes),
    Close,
}

struct Open {
    app: String,
    tenant: String,
    project: String,
    push: mpsc::Sender<Push>,
}

/// The connections open now.
#[derive(Default)]
pub struct Sockets {
    open: Mutex<HashMap<String, Open>>,
}

impl Sockets {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Open>> {
        self.open.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Opens connection `id` of `app`, unless the app or its workspace has
    /// as many as it may. Public for tests, which stand in for a client.
    #[doc(hidden)]
    pub fn open(
        &self,
        id: &str,
        app: &str,
        tenant: &str,
        project: &str,
    ) -> Option<mpsc::Receiver<Push>> {
        let mut open = self.lock();
        if open.values().filter(|c| c.app == app).count() >= MAX_PER_APP
            || open.values().filter(|c| c.tenant == tenant).count() >= MAX_PER_WORKSPACE
        {
            return None;
        }
        let (push, pushed) = mpsc::channel(32);
        open.insert(
            id.to_owned(),
            Open {
                app: app.to_owned(),
                tenant: tenant.to_owned(),
                project: project.to_owned(),
                push,
            },
        );
        Some(pushed)
    }

    fn closed(&self, id: &str) {
        self.lock().remove(id);
    }

    /// The workspace and project of connection `id`, if `app` has it open.
    pub fn owner(&self, app: &str, id: &str) -> Option<(String, String)> {
        let open = self.lock();
        let found = open.get(id).filter(|c| c.app == app)?;
        Some((found.tenant.clone(), found.project.clone()))
    }

    /// Sends `push` to connection `id` of `app`. False when the app has no
    /// such connection open, or it is not taking what it is sent.
    pub async fn push(&self, app: &str, id: &str, push: Push) -> bool {
        let sender = {
            let open = self.lock();
            match open.get(id).filter(|c| c.app == app) {
                Some(found) => found.push.clone(),
                None => return false,
            }
        };
        tokio::time::timeout(Duration::from_secs(5), sender.send(push))
            .await
            .is_ok_and(|sent| sent.is_ok())
    }

    /// The ids of `app`'s open connections.
    pub fn list(&self, app: &str) -> Vec<String> {
        let open = self.lock();
        let mut ids: Vec<String> = open
            .iter()
            .filter(|(_, c)| c.app == app)
            .map(|(id, _)| id.clone())
            .collect();
        ids.sort();
        ids
    }
}

/// Headers an event carries to the app beside those any request may: set
/// by the gateway, never taken from a client.
#[derive(Clone)]
pub struct EventHeaders(pub Vec<(&'static str, String)>);
/// Marks an event that is not listed among the app's requests.
#[derive(Clone)]
pub struct Unlisted;

/// An app's answer to an event, and an event that is with the app.
type Answer = Result<(StatusCode, HeaderMap, Bytes)>;
type Answering = std::pin::Pin<Box<dyn Future<Output = Answer> + Send>>;

/// Whether `headers` ask for a WebSocket.
pub fn wanted(headers: &HeaderMap) -> bool {
    headers
        .get(header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"))
}

/// Gives the app one event of connection `id` and returns its answer.
async fn event(
    state: &ApiState,
    host: &str,
    id: &str,
    name: &str,
    path: Option<&str>,
    content_type: Option<&str>,
    body: Bytes,
) -> Result<(StatusCode, HeaderMap, Bytes)> {
    let mut headers = vec![("fenders-connection", id.to_owned())];
    if let Some(path) = path {
        headers.push(("fenders-path", path.to_owned()));
    }
    let mut request = Request::builder()
        .method("POST")
        .uri(format!("{RESERVED}ws/{name}"))
        .header(header::HOST, host)
        .extension(EventHeaders(headers));
    if let Some(content_type) = content_type {
        request = request.header(header::CONTENT_TYPE, content_type);
    }
    // Events are counted, not listed: a connection is one line in Events.
    let request = request.extension(Unlisted);
    let request = request
        .body(Body::from(body))
        .map_err(|_| Error::internal())?;
    let response = crate::api::gateway_event(state.clone(), request).await?;
    let (parts, body) = response.into_parts();
    let body = axum::body::to_bytes(body, MAX_MESSAGE).await.map_err(|_| {
        Error::new(
            StatusCode::BAD_GATEWAY,
            "the app's answer was cut short or too large",
        )
    })?;
    Ok((parts.status, parts.headers, body))
}

/// Answers a client's request for a WebSocket to the app at `host`.
pub async fn accept(state: ApiState, host: String, request: Request) -> Result<Response> {
    let (mut parts, _) = request.into_parts();
    let app = state.store.websocket_app(&host).await?.ok_or_else(|| {
        Error::new(
            StatusCode::UPGRADE_REQUIRED,
            "this app accepts no WebSocket connections",
        )
    })?;
    let upgrade = WebSocketUpgrade::from_request_parts(&mut parts, &())
        .await
        .map_err(|_| Error::invalid("not a WebSocket request"))?;
    let id = uid();
    let path = parts
        .uri
        .path_and_query()
        .map_or("/", |p| p.as_str())
        .to_owned();
    // The app decides whether the client may connect.
    let (status, ..) = event(
        &state,
        &host,
        &id,
        "connect",
        Some(&path),
        None,
        Bytes::new(),
    )
    .await?;
    if !status.is_success() {
        state
            .store
            .websocket_refused(&id, &app.0, &path, status)
            .await?;
        return Ok(status.into_response());
    }
    let Some(pushed) = state.store.sockets.open(&id, &app.0, &app.1, &app.2) else {
        let _ = event(&state, &host, &id, "disconnect", None, None, Bytes::new()).await;
        return Err(Error::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too many connections are open",
        ));
    };
    // The connection has a place now. It is given up when the connection is
    // served to its end, and also when it never is: recording it fails, this
    // call is dropped with its client, or the upgrade is not completed.
    let held = held(state.clone(), &host, &id);
    state.store.websocket_opened(&id, &app.0, &path).await?;
    Ok(upgrade
        .max_message_size(MAX_MESSAGE)
        .max_frame_size(MAX_MESSAGE)
        .on_upgrade(move |socket| serve(state, host, id, socket, pushed, held)))
}

/// An open connection's place among those of its app and workspace. Dropped
/// before the connection was served, it gives the place back, closes its
/// record and tells the app the client is gone, as the end of serving does.
pub struct Held {
    state: ApiState,
    host: String,
    id: String,
    served: bool,
}

/// The place of connection `id`, which [`Sockets::open`] opened. Public for
/// tests, which stand in for a client that goes away before its upgrade.
#[doc(hidden)]
pub fn held(state: ApiState, host: &str, id: &str) -> Held {
    Held {
        state,
        host: host.to_owned(),
        id: id.to_owned(),
        served: false,
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        self.state.store.sockets.closed(&self.id);
        if self.served {
            return;
        }
        let (state, host, id) = (self.state.clone(), self.host.clone(), self.id.clone());
        tokio::spawn(async move {
            let _ = state.store.websocket_closed(&id, [0; 4]).await;
            let _ = event(&state, &host, &id, "disconnect", None, None, Bytes::new()).await;
        });
    }
}

/// Serves one connection until it closes.
async fn serve(
    state: ApiState,
    host: String,
    id: String,
    mut socket: WebSocket,
    mut pushed: mpsc::Receiver<Push>,
    mut held: Held,
) {
    // Served from here: this function closes it.
    held.served = true;
    let closing = |code: u16, reason: &'static str| {
        Message::Close(Some(CloseFrame {
            code,
            reason: reason.into(),
        }))
    };
    let mut ping = tokio::time::interval(PING);
    ping.tick().await;
    let mut heard = Instant::now();
    let (mut second, mut count) = (Instant::now(), 0u32);
    // What passed over it: messages and bytes from the client, then to it.
    let mut passed = [0u64; 4];
    // The message that is with the app, if one is.
    let mut answering: Option<Answering> = None;
    loop {
        tokio::select! {
            // Its answer, sent back on the same connection when it has a body.
            answer = async { answering.as_mut().unwrap().await }, if answering.is_some() => {
                answering = None;
                match answer {
                    Ok((status, headers, body)) if status.is_success() && !body.is_empty() => {
                        let text = headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).is_some_and(|v| v.starts_with("text/"));
                        passed[2] += 1;
                        passed[3] += body.len() as u64;
                        let reply = match String::from_utf8(body.to_vec()) {
                            Ok(text_body) if text => Message::Text(text_body.into()),
                            _ => Message::Binary(body),
                        };
                        if socket.send(reply).await.is_err() { break; }
                    }
                    Ok(_) => {}
                    // The workspace's limits or allowance: the client is told to stop.
                    Err(error) if error.status == StatusCode::TOO_MANY_REQUESTS => {
                        let _ = socket.send(closing(1013, "try again later")).await;
                        break;
                    }
                    Err(_) => {}
                }
            }
            // What the app sends this connection.
            push = pushed.recv() => {
                if let Some(Push::Text(_) | Push::Binary(_)) = &push {
                    passed[2] += 1;
                }
                passed[3] += match &push {
                    Some(Push::Text(text)) => text.len() as u64,
                    Some(Push::Binary(bytes)) => bytes.len() as u64,
                    _ => 0,
                };
                let sent = match push {
                    Some(Push::Text(text)) => socket.send(Message::Text(text.into())).await,
                    Some(Push::Binary(bytes)) => socket.send(Message::Binary(bytes)).await,
                    Some(Push::Close) | None => {
                        let _ = socket.send(closing(1000, "closed by the app")).await;
                        break;
                    }
                };
                if sent.is_err() { break; }
            }
            // The client's next message, read only when the last has been answered.
            received = socket.recv(), if answering.is_none() => {
                let Some(Ok(message)) = received else { break };
                heard = Instant::now();
                let (content_type, body) = match message {
                    Message::Text(text) => ("text/plain; charset=utf-8", Bytes::from(text.as_str().to_owned())),
                    Message::Binary(bytes) => ("application/octet-stream", bytes),
                    Message::Close(_) => break,
                    Message::Ping(_) | Message::Pong(_) => continue,
                };
                if second.elapsed() >= Duration::from_secs(1) {
                    (second, count) = (Instant::now(), 0);
                }
                passed[0] += 1;
                passed[1] += body.len() as u64;
                count += 1;
                if count > MAX_PER_SECOND {
                    let _ = socket.send(closing(1008, "too many messages")).await;
                    break;
                }
                let (state, host, id) = (state.clone(), host.clone(), id.clone());
                answering = Some(Box::pin(async move {
                    event(&state, &host, &id, "message", None, Some(content_type), body).await
                }));
            }
            _ = ping.tick() => {
                if heard.elapsed() >= SILENT || socket.send(Message::Ping(Bytes::new())).await.is_err() {
                    break;
                }
            }
        }
    }
    drop(held);
    // A message still with the app is seen to its end: dropping it would
    // leave its request unsettled until its reservation lapsed.
    if let Some(answer) = answering {
        let _ = answer.await;
    }
    let _ = state.store.websocket_closed(&id, passed).await;
    let _ = event(&state, &host, &id, "disconnect", None, None, Bytes::new()).await;
}

impl crate::store::Store {
    /// The app at `host`, its workspace and project, when it is enabled,
    /// serves HTTP and accepts WebSocket connections.
    pub(crate) async fn websocket_app(
        &self,
        host: &str,
    ) -> Result<Option<(String, String, String)>> {
        use crate::{
            args,
            db::{optional, s},
        };
        let mut tx = self.transaction(false, false).await?;
        Ok(optional(&mut tx,"SELECT a.id,a.tenant_id,a.project_id FROM app_http h JOIN apps a ON a.id=h.app_id JOIN app_triggers t ON t.app_id=a.id WHERE h.hostname=$1 AND a.desired='enabled' AND t.http AND a.configuration->>'websocket'='true'",args![host]).await?
            .map(|a| (s(&a["id"]).to_owned(), s(&a["tenant_id"]).to_owned(), s(&a["project_id"]).to_owned())))
    }

    /// The app an execution belongs to, when that app accepts WebSocket
    /// connections: an execution of it may send to them.
    pub(crate) async fn websocket_sender(&self, execution: &str) -> Result<Option<String>> {
        use crate::{
            args,
            db::{optional, s},
        };
        let mut tx = self.transaction(false, false).await?;
        Ok(optional(&mut tx,"SELECT a.id FROM apps a WHERE a.configuration->>'websocket'='true' AND a.id=COALESCE((SELECT app_id FROM app_http_attempts WHERE execution_id=$1),(SELECT app_id FROM app_runs WHERE execution_id=$1))",args![execution]).await?
            .map(|a| s(&a["id"]).to_owned()))
    }

    /// Counts `bytes` an app sent a connection against its workspace's
    /// transfer allowance, or refuses them when it has no room.
    pub(crate) async fn websocket_sent(
        &self,
        tenant: &str,
        project: &str,
        bytes: i64,
    ) -> Result<()> {
        use crate::{args, db::exec};
        let mut tx = self.transaction(true, false).await?;
        Self::require_workspace_active(&mut tx, tenant).await?;
        Self::transfer_capacity(&mut tx, tenant, bytes).await?;
        exec(&mut tx,"INSERT INTO traffic_usage(tenant_id,project_id,period,bytes,requests) VALUES($1,$2,date_trunc('month',now() AT TIME ZONE 'UTC')::date,$3,0) ON CONFLICT(tenant_id,project_id,period) DO UPDATE SET bytes=traffic_usage.bytes+excluded.bytes",args![tenant,project,bytes]).await?;
        tx.commit().await?;
        Ok(())
    }
}

impl crate::store::Store {
    /// Records connection `id` of `app` as open, among the app's requests.
    /// Public, like the two after it, for tests that stand in for a client.
    #[doc(hidden)]
    pub async fn websocket_opened(&self, id: &str, app: &str, path: &str) -> Result<()> {
        self.websocket_row(id, app, path, None).await
    }

    /// Records a client the app refused, with the status it was refused with.
    #[doc(hidden)]
    pub async fn websocket_refused(
        &self,
        id: &str,
        app: &str,
        path: &str,
        status: StatusCode,
    ) -> Result<()> {
        self.websocket_row(id, app, path, Some(status)).await
    }

    async fn websocket_row(
        &self,
        id: &str,
        app: &str,
        path: &str,
        refused: Option<StatusCode>,
    ) -> Result<()> {
        use crate::{args, db::exec};
        // As for any request, the path without its query.
        let path: String = path
            .split('?')
            .next()
            .unwrap_or("/")
            .chars()
            .take(2048)
            .collect();
        let status = refused
            .map(|status| status.as_u16())
            .filter(|status| (200..=599).contains(status));
        let mut tx = self.transaction(true, false).await?;
        exec(&mut tx,"INSERT INTO app_http_runs(id,tenant_id,project_id,app_id,release_id,method,path,state,http_status,started_at,finished_at,websocket) SELECT $1,a.tenant_id,a.project_id,a.id,COALESCE(a.active_release_id,a.target_release_id),'GET',$3,CASE WHEN $4 THEN 'failed' ELSE 'running' END,$5::integer,clock_timestamp(),CASE WHEN $4 THEN clock_timestamp() END,'{}'::jsonb FROM apps a WHERE a.id=$2 AND COALESCE(a.active_release_id,a.target_release_id) IS NOT NULL ON CONFLICT(id) DO NOTHING",args![id,app,path,refused.is_some(),status]).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Finishes connection `id`'s row with what passed over it: messages
    /// and bytes from the client, then messages and bytes to it.
    #[doc(hidden)]
    pub async fn websocket_closed(&self, id: &str, passed: [u64; 4]) -> Result<()> {
        use crate::{args, db::exec};
        let counts = serde_json::json!({"messages_in":passed[0],"bytes_in":passed[1],"messages_out":passed[2],"bytes_out":passed[3]});
        let mut tx = self.transaction(true, false).await?;
        exec(&mut tx,"UPDATE app_http_runs SET state='succeeded',finished_at=clock_timestamp(),websocket=$2 WHERE id=$1 AND websocket IS NOT NULL AND finished_at IS NULL",args![id,counts]).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Finishes, as unknown, the rows of connections this process does not
    /// hold: those a restart closed.
    pub async fn websocket_sweep(&self) -> Result<()> {
        use crate::{
            args,
            db::{exec, rows, s},
        };
        let mut tx = self.transaction(false, false).await?;
        let open = rows(&mut tx,"SELECT id FROM app_http_runs WHERE websocket IS NOT NULL AND finished_at IS NULL AND created<now()-interval '1 minute' LIMIT 512",args![]).await?;
        drop(tx);
        let lost: Vec<&str> = {
            let held = self.sockets.lock();
            open.iter()
                .map(|row| s(&row["id"]))
                .filter(|id| !held.contains_key(*id))
                .collect()
        };
        if lost.is_empty() {
            return Ok(());
        }
        let mut tx = self.transaction(true, false).await?;
        exec(&mut tx,"UPDATE app_http_runs SET state='unknown',finished_at=clock_timestamp() WHERE websocket IS NOT NULL AND finished_at IS NULL AND id=ANY(ARRAY(SELECT jsonb_array_elements_text($1)))",args![serde_json::json!(lost)]).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Whether an app accepts WebSocket connections, and those open now.
    pub async fn app_websocket(
        &self,
        p: &crate::model::Principal,
        tenant: &str,
        project: &str,
        app: &str,
    ) -> Result<serde_json::Value> {
        use crate::{args, db::rows};
        let mut tx = self.transaction(false, false).await?;
        Self::project(&mut tx, p, tenant, project, false).await?;
        let found = Self::app_row(&mut tx, tenant, project, app).await?;
        let open = self.sockets.list(app);
        let connections = rows(&mut tx,"SELECT id,path,created AS opened FROM app_http_runs WHERE app_id=$1 AND websocket IS NOT NULL AND finished_at IS NULL AND id=ANY(ARRAY(SELECT jsonb_array_elements_text($2))) ORDER BY created,id",args![app,serde_json::json!(open)]).await?;
        Ok(
            serde_json::json!({"enabled":found["configuration"]["websocket"]==true,"open":open.len(),"connections":connections}),
        )
    }
}
