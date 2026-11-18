use crate::{
    error::{Error, Result},
    model::MAX_UPLOAD,
    store::Store,
    transport::{Client, PeerIdentity},
};
use axum::{
    Json, Router,
    body::{Bytes, to_bytes},
    extract::{Request, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::de::DeserializeOwned;
use serde_json::Value;
use serde_json::json;
use std::path::PathBuf;

#[derive(Clone)]
pub struct ApiState {
    pub store: Store,
    pub domain: String,
    pub tls: Option<PeerCredentials>,
}
#[derive(Clone)]
pub struct PeerCredentials {
    pub ca: PathBuf,
    pub cert: PathBuf,
    pub key: PathBuf,
}
impl PeerCredentials {
    pub fn client(&self, endpoint: &str, pin: &str) -> Result<Client> {
        Ok(Client::new(endpoint, &self.ca, &self.cert, &self.key, pin)?)
    }
}

pub fn router(store: Store) -> Router {
    management(ApiState {
        store,
        domain: "apps.localhost".to_owned(),
        tls: None,
    })
}
pub fn management(state: ApiState) -> Router {
    Router::new()
        .fallback(dispatch)
        .with_state(state)
        .layer(axum::middleware::map_response(management_headers))
}

/// Headers of every answer from the management listener, an error's among
/// them: the API and a console's pages are served over TLS only, are never
/// framed by another site, and their content type is not guessed at.
async fn management_headers(mut response: Response) -> Response {
    let headers = response.headers_mut();
    for (name, value) in [
        (header::STRICT_TRANSPORT_SECURITY, "max-age=31536000"),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (header::X_FRAME_OPTIONS, "DENY"),
        (header::REFERRER_POLICY, "no-referrer"),
    ] {
        if !headers.contains_key(&name) {
            headers.insert(name, header::HeaderValue::from_static(value));
        }
    }
    response
}
pub fn internal(store: Store) -> Router {
    Router::new().fallback(internal_dispatch).with_state(store)
}
pub fn gateway(state: ApiState) -> Router {
    Router::new().fallback(gateway_dispatch).with_state(state)
}

/// A request key as a path names it. A key is whatever its caller chose,
/// so one with a `/` or a space in it arrives percent-encoded.
fn path_key(segment: &str) -> Result<String> {
    percent_encoding::percent_decode_str(segment)
        .decode_utf8()
        .map(|key| key.into_owned())
        .map_err(|_| Error::missing())
}
/// The key of a change that does not require one: none when none was sent.
fn offered(key: &str) -> Option<&str> {
    (!key.is_empty()).then_some(key)
}
fn parse<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    serde_json::from_slice(bytes).map_err(|_| Error::invalid("invalid or missing fields"))
}
async fn dispatch(State(state): State<ApiState>, req: Request) -> Result<Response> {
    let request_id = crate::model::uid();
    let mut response = match dispatch_inner(State(state), req).await {
        Ok(response) => response,
        Err(error) => {
            // Out of allowance is not too many requests: nothing is cured
            // by asking again later, so it is not answered as a rate is.
            let status = if error.code() == crate::db::QUOTA {
                StatusCode::CONFLICT
            } else {
                error.status
            };
            let mut response = (
                status,
                Json(json!({"error":error.message,"code":error.code(),"request_id":request_id})),
            )
                .into_response();
            if let Some((name, value)) = error.header
                && let Ok(value) = header::HeaderValue::from_str(&value)
            {
                response.headers_mut().insert(name, value);
            }
            // A rate that does not say when it turns is one of things in
            // progress (uploads, lookups): there is room in a moment.
            if status == StatusCode::TOO_MANY_REQUESTS
                && !response.headers().contains_key(header::RETRY_AFTER)
            {
                response
                    .headers_mut()
                    .insert(header::RETRY_AFTER, header::HeaderValue::from_static("1"));
            }
            response
        }
    };
    let headers = response.headers_mut();
    headers.insert(
        "X-Request-Id",
        request_id.parse().map_err(|_| Error::internal())?,
    );
    // What the API answers is its caller's alone: no cache keeps it.
    headers.insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    Ok(response)
}
async fn dispatch_inner(State(state): State<ApiState>, req: Request) -> Result<Response> {
    let store = &state.store;
    let (parts, body) = req.into_parts();
    let method = parts.method.as_str();
    let path = parts.uri.path();
    // The contract, and nothing else that is not the API: the control plane
    // hosts no pages.
    if method == "GET" && path == "/api/openapi.json" {
        return Ok((
            [(header::CONTENT_TYPE, "application/json")],
            include_bytes!("../static/api/openapi.json").as_slice(),
        )
            .into_response());
    }
    let mut segments: Vec<_> = path.trim_matches('/').split('/').collect();
    let public_api = segments.get(1) == Some(&"workspaces");
    if public_api {
        segments[1] = "tenants";
        if segments.get(3) == Some(&"projects") && segments.get(5) == Some(&"connections") {
            segments[5] = "external-endpoints";
        }
        if crate::customer_api::permission(method, &segments).is_none() {
            return Err(Error::missing());
        }
    }
    // One way in: a bearer credential. Who a person is, and what they may
    // do, is the business of whatever is built on this API; it calls with a
    // key that carries the answer.
    let token = parts
        .headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(Error::unauthorized)?;
    let p = store.authenticate(token).await?;
    crate::customer_api::authorize(&p, method, &segments)?;
    // Every route is one a tenant's key may be given, or one of the
    // operator's own. There is no third kind.
    if crate::customer_api::permission(method, &segments).is_none()
        && !crate::customer_api::operators(method, &segments)
    {
        return Err(Error::missing());
    }
    // Every mutation leaves an audit record, and most a receipt, for good. A
    // workspace's credentials make so many a minute between them; an
    // operator's are its own to pace.
    if !matches!(method, "GET" | "HEAD" | "OPTIONS")
        && let Some(tenant) = &p.tenant_id
        && !store.api_rates.admit(tenant, MUTATIONS_A_MINUTE)
    {
        return Err(Error::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too many changes in a minute",
        )
        .with_header(
            header::RETRY_AFTER,
            store.api_rates.retry_after(tenant).to_string(),
        ));
    }
    let key = parts
        .headers
        .get("Idempotency-Key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let is_upload = method == "POST"
        && matches!(
            segments.as_slice(),
            ["v1", "tenants", _, "projects", _, "artifacts"]
        );
    // An upload's body is held whole, up to 16 MiB of it. Before any of it
    // is read: the credential must be one that may upload there, the body
    // must say it fits, and its workspace and the control plane must have a
    // place for one more.
    let limit = if is_upload { MAX_UPLOAD } else { 64 * 1024 };
    let _uploading = if let ["v1", "tenants", tenant, "projects", project, "artifacts"] =
        segments.as_slice()
        && is_upload
    {
        p.scope(tenant, Some(project), true, false)?;
        Some(UPLOADS.begin(tenant).ok_or_else(|| {
            Error::new(
                StatusCode::TOO_MANY_REQUESTS,
                "too many uploads in progress",
            )
        })?)
    } else {
        None
    };
    if parts
        .headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok())
        .is_some_and(|length| length > limit)
    {
        return Err(Error::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "request body too large",
        ));
    }
    let bytes: Bytes = tokio::time::timeout(BODY_WITHIN, to_bytes(body, limit))
        .await
        .map_err(|_| {
            Error::new(
                StatusCode::REQUEST_TIMEOUT,
                "request body not received in time",
            )
        })?
        .map_err(|_| Error::new(StatusCode::PAYLOAD_TOO_LARGE, "request body too large"))?;
    if (public_api || p.api_permissions.is_some())
        && matches!(
            (method, segments.as_slice()),
            (
                "POST",
                ["v1", "tenants", _, "projects", _, "apps", "deploy"]
            ) | (
                "PUT",
                ["v1", "tenants", _, "projects", _, "apps", _, "connections"]
            )
        )
    {
        let value: Value = parse(&bytes)?;
        if value.get("endpoints").is_some() || value.get("https_origins").is_some() {
            return Err(Error::invalid(
                "use connections with registered connection IDs",
            ));
        }
    }
    let mut status = StatusCode::OK;
    let value: Value = match (method, segments.as_slice()) {
        (
            "POST",
            [
                "v1",
                "tenants",
                tenant,
                "projects",
                project,
                "apps",
                app,
                "http-sample",
            ],
        ) => {
            let sample = parse::<HttpSample>(&bytes)?;
            let hostname = store
                .app_sample_hostname_for(&p, tenant, project, app, &sample.method, &sample.path)
                .await?;
            http_sample(&state, &hostname, sample).await?
        }
        ("GET", ["v1", "me"]) => serde_json::to_value(&p).map_err(|_| Error::internal())?,
        ("GET", ["v1", "control-plane", "status"]) => store.background_status(&p)?,
        ("GET", ["v1", "tenants"]) => store.tenants(&p).await?,
        ("GET", ["v1", "nodes"]) => store.nodes(&p).await?,
        ("GET", ["v1", "public-egress-policy"]) => store.public_egress_policy(&p).await?,
        ("PUT", ["v1", "public-egress-policy"]) => {
            store
                .activate_public_egress_keyed(&p, parse(&bytes)?, offered(key))
                .await?
        }
        ("POST", ["v1", "nodes"]) => {
            status = StatusCode::CREATED;
            store
                .register_node_keyed(&p, parse(&bytes)?, Some(key))
                .await?
        }
        ("PATCH", ["v1", "nodes", node]) => {
            store
                .node_mode_keyed(&p, node, parse(&bytes)?, offered(key))
                .await?
        }
        ("POST", ["v1", "tenants"]) => {
            status = StatusCode::CREATED;
            store
                .create_tenant_keyed(&p, parse(&bytes)?, Some(key))
                .await?
        }
        // A tenant's allowance, and the size its apps take when they name none.
        ("PATCH", ["v1", "tenants", tenant]) => {
            store
                .update_allowance_keyed(&p, tenant, parse(&bytes)?, offered(key))
                .await?
        }
        // Suspend a workspace, or resume it: the operator's, with a reason.
        ("POST", ["v1", "tenants", tenant, "lifecycle"]) => {
            p.operator()?;
            let mut action =
                parse::<crate::workspace_lifecycle::WorkspaceAction>(&bytes)?.keyed(key)?;
            action.id = (*tenant).to_owned();
            store.operator_workspace_action(&p.id, action).await?
        }
        ("PATCH", ["v1", "tenants", tenant, "http-limits"]) => {
            store
                .update_http_limits_keyed(&p, tenant, parse(&bytes)?, offered(key))
                .await?
        }
        ("GET", ["v1", "tenants", tenant, "projects"]) => store.projects(&p, tenant).await?,
        ("POST", ["v1", "tenants", tenant, "projects"]) => {
            status = StatusCode::CREATED;
            store
                .create_project_keyed(
                    &p,
                    tenant,
                    parse(&bytes)?,
                    (public_api || p.api_permissions.is_some() || !key.is_empty()).then_some(key),
                )
                .await?
        }
        ("GET", ["v1", "tenants", tenant, "api-keys"]) => store.api_keys(&p, tenant).await?,
        ("POST", ["v1", "tenants", tenant, "api-keys"]) => {
            let issued = store
                .create_api_key(&p, tenant, parse(&bytes)?, key)
                .await?;
            // A retry made nothing, and has no token to show for it.
            if issued["replayed"] != true {
                status = StatusCode::CREATED;
            }
            issued
        }
        ("DELETE", ["v1", "tenants", tenant, "api-keys", id]) => {
            store.revoke_credential(&p, tenant, id).await?
        }
        ("GET", ["v1", "tenants", tenant, "usage", "history"]) => {
            let page = axum::extract::Query::<crate::usage::HistoryPage>::try_from_uri(&parts.uri)
                .map_err(|_| Error::invalid("invalid history query"))?
                .0;
            store.usage_history(&p, tenant, None, page).await?
        }
        (
            "GET",
            [
                "v1",
                "tenants",
                tenant,
                "projects",
                project,
                "usage",
                "history",
            ],
        ) => {
            let page = axum::extract::Query::<crate::usage::HistoryPage>::try_from_uri(&parts.uri)
                .map_err(|_| Error::invalid("invalid history query"))?
                .0;
            store.usage_history(&p, tenant, Some(project), page).await?
        }
        ("GET", ["v1", "tenants", tenant, "usage"]) => store.usage(&p, tenant, None).await?,
        ("GET", ["v1", "tenants", tenant, "projects", project, "usage"]) => {
            store.usage(&p, tenant, Some(project)).await?
        }
        ("GET", ["v1", "tenants", tenant, "projects", project, "https-access"]) => {
            store.https_access(&p, tenant, project).await?
        }
        (
            "POST",
            [
                "v1",
                "tenants",
                tenant,
                "projects",
                project,
                "https-access",
                "validate",
            ],
        ) => {
            store
                .validate_https_access(&p, tenant, project, parse(&bytes)?)
                .await?
        }
        ("GET", ["v1", "tenants", tenant, "projects", project, "app-sizes"]) => {
            store.app_sizes(&p, tenant, project).await?
        }
        (
            "GET",
            [
                "v1",
                "tenants",
                tenant,
                "projects",
                project,
                "apps",
                app,
                "connections",
            ],
        ) => store.app_connections(&p, tenant, project, app).await?,
        (
            "PUT",
            [
                "v1",
                "tenants",
                tenant,
                "projects",
                project,
                "apps",
                app,
                "connections",
            ],
        ) => {
            status = StatusCode::ACCEPTED;
            store
                .update_app_connections(&p, tenant, project, app, parse(&bytes)?, key)
                .await?
        }
        (
            "GET",
            [
                "v1",
                "tenants",
                tenant,
                "projects",
                project,
                "app-submissions",
                key,
            ],
        ) => {
            store
                .app_submission(&p, tenant, project, &path_key(key)?)
                .await?
        }
        (
            "GET",
            [
                "v1",
                "tenants",
                tenant,
                "projects",
                project,
                "apps",
                app,
                "submissions",
                key,
            ],
        ) => {
            store
                .app_action_submission(&p, tenant, project, app, &path_key(key)?)
                .await?
        }
        (
            "GET",
            [
                "v1",
                "tenants",
                tenant,
                "projects",
                project,
                "apps",
                app,
                kind,
            ],
        ) if matches!(*kind, "runs" | "releases") => {
            let page =
                axum::extract::Query::<crate::app_runtime::HistoryPage>::try_from_uri(&parts.uri)
                    .map_err(|_| Error::invalid("invalid history query"))?
                    .0;
            store
                .app_history(&p, tenant, project, app, kind, page)
                .await?
        }
        (
            "GET",
            [
                "v1",
                "tenants",
                tenant,
                "projects",
                project,
                "apps",
                app,
                "triggers",
            ],
        ) => store.app_triggers(&p, tenant, project, app).await?,
        (
            "PUT",
            [
                "v1",
                "tenants",
                tenant,
                "projects",
                project,
                "apps",
                app,
                "triggers",
            ],
        ) => {
            store
                .update_app_triggers_at(
                    &p,
                    tenant,
                    project,
                    app,
                    crate::app_http::TriggerUpdate {
                        value: parse(&bytes)?,
                        key,
                        domain: &state.domain,
                    },
                )
                .await?
        }
        (
            "GET",
            [
                "v1",
                "tenants",
                tenant,
                "projects",
                project,
                "apps",
                app,
                "http",
            ],
        ) => store.app_http_status(&p, tenant, project, app).await?,
        (
            "GET",
            [
                "v1",
                "tenants",
                tenant,
                "projects",
                project,
                "apps",
                app,
                "websocket",
            ],
        ) => store.app_websocket(&p, tenant, project, app).await?,
        ("PATCH", ["v1", "tenants", tenant, "projects", project, "apps", app]) => {
            store
                .app_lifecycle(&p, tenant, project, app, parse(&bytes)?, key)
                .await?
        }
        ("DELETE", ["v1", "tenants", tenant, "projects", project, "apps", app]) => {
            status = StatusCode::ACCEPTED;
            store
                .delete_app(&p, tenant, project, app, parse(&bytes)?, key)
                .await?
        }
        (
            "POST",
            [
                "v1",
                "tenants",
                tenant,
                "projects",
                project,
                "apps",
                app,
                "releases",
            ],
        ) => {
            status = StatusCode::CREATED;
            store
                .activate_app_release(&p, tenant, project, app, parse(&bytes)?, key)
                .await?
        }
        (
            "GET",
            [
                "v1",
                "tenants",
                tenant,
                "projects",
                project,
                "apps",
                app,
                "releases",
                release,
            ],
        ) => store.app_release(&p, tenant, project, app, release).await?,
        (
            "POST",
            [
                "v1",
                "tenants",
                tenant,
                "projects",
                project,
                "apps",
                app,
                "runs",
            ],
        ) => {
            status = StatusCode::ACCEPTED;
            let invocation = if bytes.is_empty() {
                crate::app_runtime::RunInvocation::default()
            } else {
                parse::<crate::app_runtime::RunInvocation>(&bytes)?
            };
            store
                .run_app_event(
                    &p,
                    tenant,
                    project,
                    app,
                    crate::app_runtime::RunEvent {
                        key,
                        source: invocation.source,
                        trigger_time: invocation.trigger_time.as_deref(),
                    },
                )
                .await?
        }
        (
            "GET",
            [
                "v1",
                "tenants",
                tenant,
                "projects",
                project,
                "apps",
                app,
                "runs",
                run,
            ],
        ) => store.app_run(&p, tenant, project, app, run).await?,
        // Stop a run that has not ended.
        (
            "POST",
            [
                "v1",
                "tenants",
                tenant,
                "projects",
                project,
                "apps",
                app,
                "runs",
                run,
                "cancel",
            ],
        ) => {
            status = StatusCode::ACCEPTED;
            store
                .cancel_app_run(&p, tenant, project, app, run, key)
                .await?
        }
        (
            "POST",
            [
                "v1",
                "tenants",
                tenant,
                "projects",
                project,
                "apps",
                "deploy",
            ],
        ) => {
            status = StatusCode::CREATED;
            store
                .deploy_app(
                    &p,
                    tenant,
                    project,
                    crate::apps::AppSubmission {
                        value: parse(&bytes)?,
                        key,
                        domain: &state.domain,
                    },
                )
                .await?
        }
        ("POST", ["v1", "tenants", tenant, "projects", project, "apps"]) => {
            status = StatusCode::CREATED;
            store
                .create_app(&p, tenant, project, parse(&bytes)?, key)
                .await?
        }
        ("GET", ["v1", "tenants", tenant, "projects", project, "apps"]) => {
            let page = axum::extract::Query::<crate::apps::AppPage>::try_from_uri(&parts.uri)
                .map_err(|_| Error::invalid("invalid app page query"))?
                .0;
            store.apps(&p, tenant, project, page).await?
        }
        (
            "GET",
            [
                "v1",
                "tenants",
                tenant,
                "projects",
                project,
                "apps",
                app,
                "events",
            ],
        ) => {
            let page =
                axum::extract::Query::<crate::app_events::EventPage>::try_from_uri(&parts.uri)
                    .map_err(|_| Error::invalid("invalid lifecycle event query"))?
                    .0;
            store.app_events(&p, tenant, project, app, page).await?
        }
        ("GET", ["v1", "tenants", tenant, "projects", project, "apps", app]) => {
            store.app(&p, tenant, project, app).await?
        }
        (
            "GET",
            [
                "v1",
                "tenants",
                tenant,
                "projects",
                project,
                "apps",
                app,
                "logs",
            ],
        ) => {
            let page = axum::extract::Query::<crate::app_logs::LogPage>::try_from_uri(&parts.uri)
                .map_err(|_| Error::invalid("invalid app log query"))?
                .0;
            store.app_logs(&p, tenant, project, app, page).await?
        }
        (
            "POST",
            [
                "v1",
                "tenants",
                tenant,
                "projects",
                project,
                "apps",
                app,
                "versions",
            ],
        ) => {
            status = StatusCode::CREATED;
            store
                .attach_app_version(&p, tenant, project, app, parse(&bytes)?, key)
                .await?
        }
        (
            "GET",
            [
                "v1",
                "tenants",
                tenant,
                "projects",
                project,
                "apps",
                app,
                "versions",
            ],
        ) => {
            let page = axum::extract::Query::<crate::apps::VersionPage>::try_from_uri(&parts.uri)
                .map_err(|_| Error::invalid("invalid version page query"))?
                .0;
            store
                .app_versions(&p, tenant, project, app, page.before)
                .await?
        }
        (
            "GET",
            [
                "v1",
                "tenants",
                tenant,
                "projects",
                project,
                "apps",
                app,
                "versions",
                version,
            ],
        ) => store.app_version(&p, tenant, project, app, version).await?,
        ("POST", ["v1", "tenants", tenant, "projects", project, "artifacts"]) => {
            status = StatusCode::CREATED;
            store.upload(&p, tenant, project, &bytes).await?
        }
        (
            "GET",
            [
                "v1",
                "tenants",
                tenant,
                "projects",
                project,
                "artifacts",
                artifact,
                "inspection",
            ],
        ) => {
            store
                .artifact_inspection(&p, tenant, project, artifact)
                .await?
        }
        (
            "POST",
            [
                "v1",
                "tenants",
                tenant,
                "projects",
                project,
                "schedules",
                "preview",
            ],
        ) => {
            store
                .preview_schedule(&p, tenant, project, parse(&bytes)?)
                .await?
        }
        ("POST", ["v1", "tenants", tenant, "projects", project, "secrets"]) => {
            status = StatusCode::CREATED;
            store
                .create_secret_keyed(
                    &p,
                    tenant,
                    project,
                    parse(&bytes)?,
                    (public_api || p.api_permissions.is_some() || !key.is_empty()).then_some(key),
                )
                .await?
        }
        (
            "POST",
            [
                "v1",
                "tenants",
                tenant,
                "projects",
                project,
                "external-endpoints",
            ],
        ) => {
            status = StatusCode::ACCEPTED;
            store
                .create_endpoint(&p, tenant, project, parse(&bytes)?, key)
                .await?
        }
        (
            "GET",
            [
                "v1",
                "tenants",
                tenant,
                "projects",
                project,
                "endpoint-submissions",
                key,
            ],
        ) => {
            store
                .endpoint_submission(&p, tenant, project, &path_key(key)?)
                .await?
        }
        (
            "DELETE",
            [
                "v1",
                "tenants",
                tenant,
                "projects",
                project,
                "external-endpoints",
                endpoint,
            ],
        ) => {
            if !bytes.is_empty() {
                return Err(Error::invalid("expected empty body"));
            }
            store
                .remove_endpoint(&p, tenant, project, endpoint, key)
                .await?
        }
        // What a project holds beside its apps, by kind.
        (
            "GET",
            [
                "v1",
                "tenants",
                tenant,
                "projects",
                project,
                kind @ ("artifacts" | "external-endpoints" | "secrets" | "operations"),
            ],
        ) => store.resources(&p, tenant, project, kind, None).await?,
        (
            "GET",
            [
                "v1",
                "tenants",
                tenant,
                "projects",
                project,
                kind @ ("artifacts" | "external-endpoints" | "secrets" | "operations"),
                id,
            ],
        ) => store.resources(&p, tenant, project, kind, Some(id)).await?,
        _ => return Err(Error::missing()),
    };
    if method != "GET"
        && segments.get(5) == Some(&"apps")
        && value["state"] == "pending"
        && value.get("kind").is_some()
    {
        status = StatusCode::ACCEPTED;
    }
    Ok((
        status,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        Json(value),
    )
        .into_response())
}

async fn internal_dispatch(State(store): State<Store>, req: Request) -> Result<Response> {
    let (parts, body) = req.into_parts();
    let pin = parts
        .extensions
        .get::<PeerIdentity>()
        .and_then(|p| p.0.as_deref())
        .ok_or_else(Error::unauthorized)?;
    let node = store.node_identity(pin).await?;
    let node = node["id"].as_str().ok_or_else(Error::internal)?;
    let path = parts.uri.path();
    if path == "/internal/heartbeat" && parts.method == "POST" {
        let data = to_bytes(body, 1024 * 1024)
            .await
            .map_err(|_| Error::new(StatusCode::PAYLOAD_TOO_LARGE, "heartbeat too large"))?;
        // One heartbeat of a node at a time, and one more waiting: each is
        // a transaction under the lock every mutation shares, and a node
        // that sent many at once would hold that lock from everyone.
        let _turn = store.node_turns.take(node).await.ok_or_else(|| {
            Error::new(
                StatusCode::TOO_MANY_REQUESTS,
                "a heartbeat of this node is already waiting",
            )
        })?;
        let assignments = store.heartbeat(node, parse(&data)?).await?;
        let (prewarm, prewarm_scopes) = store.prewarm_offer(node).await?;
        return Ok(Json(
            json!({"assignments":assignments,"prewarm":prewarm,"prewarm_scopes":prewarm_scopes}),
        )
        .into_response());
    }
    if let Some(digest) = path.strip_prefix("/internal/prewarm/")
        && parts.method == "GET"
    {
        return Ok((
            [(header::CONTENT_TYPE, "application/wasm")],
            store.prewarm_artifact(node, digest).await?,
        )
            .into_response());
    }
    // Wakes as soon as this node's assignments change; the heartbeat reads them.
    if path == "/internal/assignments/wait" && parts.method == "GET" {
        let after = parts
            .uri
            .query()
            .and_then(|query| query.strip_prefix("after="))
            .map(|after| after.parse::<u64>())
            .transpose()
            .map_err(|_| Error::invalid("invalid wake count"))?
            .unwrap_or(0);
        let wake = store
            .pickup()
            .wait(node, after, crate::pickup::LONG_POLL)
            .await;
        return Ok(Json(json!({"wake":wake})).into_response());
    }
    let segments: Vec<_> = path.trim_matches('/').split('/').collect();
    if parts.method == "POST" && segments.get(1) == Some(&"component-jobs") {
        let data = to_bytes(body, crate::artifacts::MAX_INSPECTION_BYTES + 1024)
            .await
            .map_err(|_| {
                Error::new(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "inspection request too large",
                )
            })?;
        let value = parse(&data)?;
        if segments == ["internal", "component-jobs", "claim"] {
            return Ok(Json(store.claim_component(node, value).await?).into_response());
        }
        if let ["internal", "component-jobs", artifact, generation, kind] = segments.as_slice() {
            let generation = generation
                .parse::<i64>()
                .ok()
                .filter(|n| *n > 0)
                .ok_or_else(|| Error::invalid("invalid validation generation"))?;
            return match *kind {
                "content" => Ok((
                    [(header::CONTENT_TYPE, "application/wasm")],
                    store
                        .component_content(node, artifact, generation, value)
                        .await?,
                )
                    .into_response()),
                "result" => Ok(Json(
                    store
                        .component_result(node, artifact, generation, value)
                        .await?,
                )
                .into_response()),
                _ => Err(Error::missing()),
            };
        }
        return Err(Error::missing());
    }
    if let ["internal", "executions", execution, generation, kind] = segments.as_slice()
        && parts.method == "GET"
    {
        let generation = generation
            .parse::<i64>()
            .ok()
            .filter(|n| *n > 0)
            .ok_or_else(|| Error::invalid("invalid generation"))?;
        return match *kind {
            "assignment" => {
                Ok(Json(store.assignment(node, execution, generation).await?).into_response())
            }
            "artifact" => Ok((
                [(header::CONTENT_TYPE, "application/wasm")],
                store.assigned_artifact(node, execution, generation).await?,
            )
                .into_response()),
            _ => Err(Error::missing()),
        };
    }
    Err(Error::missing())
}
/// One console test request. An empty object sends `GET /`; the gateway still
/// applies its method, size, admission and header rules.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpSample {
    #[serde(default = "sample_method")]
    method: String,
    #[serde(default = "sample_path")]
    path: String,
    content_type: Option<String>,
    body: Option<String>,
}
fn sample_method() -> String {
    "GET".into()
}
fn sample_path() -> String {
    "/".into()
}
async fn http_sample(state: &ApiState, hostname: &str, sample: HttpSample) -> Result<Value> {
    let request_id = crate::model::uid();
    if !matches!(
        sample.method.as_str(),
        "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS"
    ) {
        return Err(Error::invalid("unsupported sample method"));
    }
    // An origin-form path only: never an authority, fragment or control character.
    let path = axum::http::uri::PathAndQuery::try_from(sample.path.as_str())
        .ok()
        .filter(|p| {
            sample.path.len() <= 2048
                && p.as_str().starts_with('/')
                && !p.as_str().starts_with("//")
                && !sample.path.contains('#')
                && !sample.path.starts_with(crate::websocket::RESERVED)
        })
        .ok_or_else(|| {
            Error::invalid("sample path must start with / and be at most 2048 characters")
        })?;
    let body = sample.body.unwrap_or_default();
    if body.len() > 64 * 1024 {
        return Err(Error::invalid("sample body must be at most 64 KiB"));
    }
    if !body.is_empty() && matches!(sample.method.as_str(), "GET" | "HEAD") {
        return Err(Error::invalid("GET and HEAD sample requests have no body"));
    }
    let sent = json!({"method":sample.method,"path":path.as_str()});
    let mut request = Request::builder()
        .method(sample.method.as_str())
        .uri(path)
        .header(header::HOST, hostname)
        .header(header::ACCEPT, "*/*")
        .header("x-request-id", &request_id);
    if let Some(content_type) = sample.content_type.filter(|v| !v.is_empty()) {
        let value = header::HeaderValue::from_str(&content_type)
            .ok()
            .filter(|_| content_type.len() <= 256)
            .ok_or_else(|| Error::invalid("invalid sample content type"))?;
        request = request.header(header::CONTENT_TYPE, value);
    }
    let request = request
        .body(axum::body::Body::from(body))
        .map_err(|_| Error::internal())?;
    let started = std::time::Instant::now();
    let mut dispatched = false;
    // Reuse admission, wake, readiness, transfer accounting and pinned node
    // transport. Never copy management headers or follow application redirects.
    match gateway_dispatch_tracked(State(state.clone()), request, &mut dispatched).await {
        Ok(response) => {
            let status = response.status().as_u16();
            let headers: serde_json::Map<String, Value> = response
                .headers()
                .iter()
                .filter_map(|(key, value)| value.to_str().ok().map(|v| (key.to_string(), json!(v))))
                .collect();
            // The start of the body is shown; a body over 1 MiB, or one cut
            // short, is not read further.
            use http_body_util::BodyExt;
            let mut body = response.into_body();
            let (mut preview, mut bytes, mut whole) = (Vec::new(), 0usize, true);
            while let Some(frame) = body.frame().await {
                let Ok(frame) = frame else {
                    whole = false;
                    break;
                };
                if let Ok(data) = frame.into_data() {
                    bytes += data.len();
                    let room = (16 * 1024usize).saturating_sub(preview.len());
                    preview.extend_from_slice(&data[..data.len().min(room)]);
                    if bytes > 1024 * 1024 {
                        whole = false;
                        break;
                    }
                }
            }
            Ok(
                json!({"outcome":"response","request_id":request_id,"method":sent["method"],"path":sent["path"],"duration_ms":started.elapsed().as_millis() as u64,"status":status,"headers":headers,"body":STANDARD.encode(&preview),"body_bytes":bytes,"truncated":!whole || preview.len()<bytes}),
            )
        }
        Err(error) => Ok(
            json!({"outcome":if dispatched {"unconfirmed"} else {"refused"},"request_id":request_id,"method":sent["method"],"path":sent["path"],"duration_ms":started.elapsed().as_millis() as u64,"gateway_status":error.status.as_u16(),"error":error.message}),
        ),
    }
}

async fn gateway_dispatch(State(state): State<ApiState>, req: Request) -> Result<Response> {
    // Paths under `/_fenders/` are the platform's: the gateway asks an app
    // for them itself (a WebSocket's events), a client cannot.
    if req.uri().path().starts_with(crate::websocket::RESERVED) {
        return Err(Error::missing());
    }
    // A request's head is given to the app's shim in one bounded frame: a
    // target that could not fit beside its headers is refused here, before
    // anything is admitted or an execution is woken for it.
    if req
        .uri()
        .path_and_query()
        .is_some_and(|target| target.as_str().len() > GATEWAY_MAX_TARGET)
    {
        return Err(Error::new(
            StatusCode::URI_TOO_LONG,
            "request target too long",
        ));
    }
    if crate::websocket::wanted(req.headers()) {
        let (parts, body) = req.into_parts();
        let host = gateway_host(&parts, &state.domain)?;
        return crate::websocket::accept(state, host, Request::from_parts(parts, body)).await;
    }
    gateway_dispatch_tracked(State(state), req, &mut false).await
}

/// One event of a WebSocket connection, as a request to its app: through
/// the same admission, accounting and exchange as a client's.
pub(crate) async fn gateway_event(state: ApiState, request: Request) -> Result<Response> {
    gateway_dispatch_tracked(State(state), request, &mut false).await
}

/// The app host a request names, when it is under the application domain.
fn gateway_host(parts: &axum::http::request::Parts, domain: &str) -> Result<String> {
    // HTTP/2 names the host in the request's authority and sends no Host
    // header; HTTP/1.1 sends exactly one.
    let host = match (
        parts.headers.get_all(header::HOST).iter().count(),
        parts.uri.authority(),
    ) {
        (1, _) => parts
            .headers
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| Error::invalid("invalid Host header"))?,
        (0, Some(authority)) if parts.version == axum::http::Version::HTTP_2 => authority.as_str(),
        _ => return Err(Error::invalid("one Host header is required")),
    };
    let host = host
        .rsplit('@')
        .next()
        .unwrap()
        .split(':')
        .next()
        .unwrap()
        .to_lowercase();
    let host = host.trim_end_matches('.');
    if !host.ends_with(&format!(".{domain}")) {
        return Err(Error::missing());
    }
    Ok(host.to_owned())
}

async fn gateway_dispatch_tracked(
    State(state): State<ApiState>,
    req: Request,
    dispatched: &mut bool,
) -> Result<Response> {
    use crate::db::s;
    static REQUESTS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(128);
    let permit = REQUESTS.try_acquire().map_err(|_| {
        Error::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "gateway capacity exhausted",
        )
    })?;
    let (parts, body) = req.into_parts();
    let host = gateway_host(&parts, &state.domain)?;
    let host = host.as_str();
    // An event of a WebSocket connection carries what the gateway says of
    // it, and all but the first of a connection are not listed.
    let event = parts
        .extensions
        .get::<crate::websocket::EventHeaders>()
        .cloned();
    let listed = parts
        .extensions
        .get::<crate::websocket::Unlisted>()
        .is_none();
    if !matches!(
        parts.method.as_str(),
        "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS"
    ) {
        return Err(Error::new(
            StatusCode::METHOD_NOT_ALLOWED,
            "unsupported method",
        ));
    }
    use crate::ingress::{MAX_REQUEST_BYTES, Meter, Way};
    if parts
        .headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .is_some_and(|length| length > MAX_REQUEST_BYTES)
    {
        return Err(Error::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "request body too large",
        ));
    }
    // Admitted before any of the body is read: its bytes are reserved, a
    // block at a time, as they are passed on.
    //
    // From its admission the request holds a reservation, and a guard that
    // settles it if this call is dropped (its client went away) before it
    // reaches an outcome: for what passed, so that it neither counts as in
    // flight until it lapses nor is charged the whole of what it had
    // reserved. The two are made in a task of their own, which a client that
    // goes away does not stop: dropped here between the reservation being
    // committed and its guard being made, a request would have had the one
    // and not the other.
    let admission = {
        let store = state.store.clone();
        let host = host.to_owned();
        let listed = listed.then(|| {
            (
                parts.method.as_str().to_owned(),
                parts.uri.path().to_owned(),
            )
        });
        tokio::spawn(async move {
            let listed = listed
                .as_ref()
                .map(|(method, path)| (method.as_str(), path.as_str()));
            let (route, lease) = store.ingress_wait_request(&host, 0, listed).await?;
            let meter = std::sync::Arc::new(Meter::new(store.clone(), &lease));
            let settle = Settle {
                store,
                lease: lease.clone(),
                meter: meter.clone(),
                armed: true,
            };
            Ok::<_, Error>((route, lease, meter, settle))
        })
    };
    let (route, lease, meter, settle) = admission.await.map_err(|_| Error::internal())??;
    use crate::http_exchange::{Message, Offer, pipe, pump};
    // The app's shim takes the request from the exchange and posts the
    // answer there: no node is called. Neither body is held whole.
    let mut upload = None;
    // Whether the outcome is known: never given to the app, or failed by it.
    let mut known = false;
    let result = async {
        let mut headers = crate::application_headers::request(&parts.headers, true)?;
        for (name, value) in event.iter().flat_map(|event| &event.0) {
            headers.insert((*name).to_owned(), json!(value));
        }
        let head = json!({"id":lease,"method":parts.method.as_str(),"path":parts.uri.path_and_query().map(|p|p.as_str()).unwrap_or("/"),"headers":headers});
        // A head its shim would refuse to read is never offered: nothing ran.
        if !crate::http_exchange::head_fits(&head) {
            known = true;
            return Err(Error::new(
                StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
                "request head too large",
            ));
        }
        let timeout = std::time::Duration::from_millis(
            s(&route["request_timeout_ms"]).parse().unwrap_or(10_000),
        );
        // Once the request is offered, only its not being taken proves that
        // the app did not run. Admission failures occur before this point.
        state.store.ingress_dispatched(&lease).await?;
        *dispatched = true;
        let (tx, request_body) = pipe();
        let admit = meter.clone();
        upload = Some(AbortOnDrop(tokio::spawn(pump(body, tx, Some(GATEWAY_UPLOAD_IDLE), move |bytes| {
            let admit = admit.clone();
            async move { admit.admit(Way::In, bytes).await }
        }))));
        let offered = state
            .store
            .exchange
            .offer(
                // An app's requests go to whichever of its executions is
                // free; an execution of no app takes its own.
                route["http_app_id"]
                    .as_str()
                    .unwrap_or(s(&route["execution_id"])),
                &lease,
                Message {
                    head,
                    body: request_body,
                },
                GATEWAY_TAKE,
                timeout + GATEWAY_MARGIN,
            )
            .await;
        let answer = match offered {
            Offer::Answered(answer) => answer,
            Offer::NotTaken => {
                known = true;
                *dispatched = false;
                return Err(Error::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "the application did not take the request",
                ));
            }
            Offer::Lost => {
                return Err(Error::new(
                    StatusCode::GATEWAY_TIMEOUT,
                    "the application did not answer",
                ));
            }
        };
        if let Some(error) = answer.head["error"].as_str() {
            let status = if error.contains("in time") {
                StatusCode::GATEWAY_TIMEOUT
            } else {
                StatusCode::BAD_GATEWAY
            };
            known = true;
            return Err(Error::new(status, "the application failed the request"));
        }
        let out = gateway_reply(&answer.head["status"], &answer.head["headers"])?;
        Ok::<_, Error>((out, answer.body))
    }
    .await;
    match result {
        Ok((mut response, answer)) => {
            // The response's head goes to the client now; its body follows
            // as the app sends it, and the request is settled when that ends.
            let (tx, response_body) = pipe();
            *response.body_mut() = response_body;
            let status = response.status().as_u16();
            let store = state.store.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let admit = meter.clone();
                let download = pump(answer, tx, Some(GATEWAY_STREAM_IDLE), move |bytes| {
                    let admit = admit.clone();
                    async move { admit.admit(Way::Out, bytes).await }
                });
                tokio::pin!(download);
                let limit = tokio::time::sleep(GATEWAY_STREAM_LIMIT);
                tokio::pin!(limit);
                let mut renew = tokio::time::interval(GATEWAY_RENEW);
                renew.tick().await;
                let whole = loop {
                    tokio::select! {
                        (_, cut) = &mut download => break cut.is_none(),
                        _ = &mut limit => break false,
                        _ = renew.tick() => meter.renew().await,
                    }
                };
                // A request body the app did not read to its end is not
                // waited for.
                drop(upload);
                // A response cut short was not what the app sent: recorded
                // without a status, as an outcome that is not known.
                let recorded = whole.then_some(status);
                if let Err(error) = store
                    .ingress_complete(&lease, Some(meter.passed().await), recorded)
                    .await
                {
                    eprintln!("gateway request {lease} was not settled: {}", error.message);
                }
                // Settled here: this task is not dropped with the client's
                // connection, and held the guard until now.
                settle.done();
            });
            Ok(response)
        }
        Err(error) => {
            drop(upload);
            settle.done();
            // What an app never took was not transferred to it; what it took
            // and did not answer is charged what passed, not what was held.
            let used = if *dispatched { meter.passed().await } else { 0 };
            // Never given to the app (nothing ran), or failed by it: the
            // outcome is known. Otherwise it may have run.
            if known {
                state
                    .store
                    .ingress_complete(&lease, Some(used), Some(error.status.as_u16()))
                    .await?;
            } else {
                state.store.ingress_finish(&lease, Some(used)).await?;
            }
            Err(error)
        }
    }
}

/// Mutating management requests a workspace's credentials may make in a
/// minute, counted in memory as the gateway's are.
const MUTATIONS_A_MINUTE: i64 = 600;

/// How long a management request's body may take to arrive.
const BODY_WITHIN: std::time::Duration = std::time::Duration::from_secs(120);

/// Uploads whose bodies are being received: each may hold 16 MiB.
static UPLOADS: Uploads = Uploads {
    receiving: std::sync::Mutex::new(None),
};

struct Uploads {
    /// For each workspace with any, how many.
    receiving: std::sync::Mutex<Option<std::collections::HashMap<String, usize>>>,
}

/// One upload being received; no longer counted when dropped.
struct Uploading(String);

impl Uploads {
    /// Uploads received at once, and for one workspace.
    const MOST: usize = 16;
    const MOST_OF_ONE: usize = 4;

    fn begin(&'static self, tenant: &str) -> Option<Uploading> {
        let mut receiving = self.receiving.lock().unwrap_or_else(|e| e.into_inner());
        let receiving = receiving.get_or_insert_with(Default::default);
        if receiving.values().sum::<usize>() >= Self::MOST
            || receiving.get(tenant).copied().unwrap_or(0) >= Self::MOST_OF_ONE
        {
            return None;
        }
        *receiving.entry(tenant.to_owned()).or_default() += 1;
        Some(Uploading(tenant.to_owned()))
    }
}

impl Drop for Uploading {
    fn drop(&mut self) {
        let mut receiving = UPLOADS.receiving.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(receiving) = receiving.as_mut()
            && let Some(count) = receiving.get_mut(&self.0)
        {
            *count -= 1;
            if *count == 0 {
                receiving.remove(&self.0);
            }
        }
    }
}

/// Settles an admitted request whose handling was dropped before it reached
/// an outcome.
struct Settle {
    store: Store,
    lease: String,
    meter: std::sync::Arc<crate::ingress::Meter>,
    armed: bool,
}
impl Settle {
    /// The request was settled by the code that held this.
    fn done(mut self) {
        self.armed = false;
    }
}
impl Drop for Settle {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let (store, lease, meter) = (self.store.clone(), self.lease.clone(), self.meter.clone());
        tokio::spawn(async move {
            let used = meter.passed().await;
            if let Err(error) = store.ingress_finish(&lease, Some(used)).await {
                eprintln!(
                    "abandoned gateway request {lease} was not settled: {}",
                    error.message
                );
            }
        });
    }
}

/// A task that ends with whoever held it.
struct AbortOnDrop<T>(tokio::task::JoinHandle<T>);
impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// The longest path and query the gateway passes to an app.
const GATEWAY_MAX_TARGET: usize = 8 * 1024;
/// How long the gateway waits for the next piece of a request's body.
const GATEWAY_UPLOAD_IDLE: std::time::Duration = std::time::Duration::from_secs(10);
/// How long a response may send nothing, and how long it may last in all.
const GATEWAY_STREAM_IDLE: std::time::Duration = std::time::Duration::from_secs(60);
const GATEWAY_STREAM_LIMIT: std::time::Duration = std::time::Duration::from_secs(900);
/// How often a request in flight renews its reservation, which lapses in 90
/// seconds.
const GATEWAY_RENEW: std::time::Duration = std::time::Duration::from_secs(30);
/// How long an admitted request waits for the app's shim to take it.
const GATEWAY_TAKE: std::time::Duration = std::time::Duration::from_secs(10);
/// How long the gateway waits for an answer beyond the app's own timeout.
const GATEWAY_MARGIN: std::time::Duration = std::time::Duration::from_secs(10);

#[cfg(test)]
fn gateway_response(response: Value) -> Result<(Response, usize)> {
    let invalid = || Error::new(StatusCode::BAD_GATEWAY, "invalid application response");
    let encoded = response["body"].as_str().ok_or_else(invalid)?;
    let data = STANDARD.decode(encoded).map_err(|_| invalid())?;
    let size = data.len();
    let mut out = gateway_reply(&response["status"], &response["headers"])?;
    *out.body_mut() = axum::body::Body::from(data);
    Ok((out, size))
}

/// The head of the response a client gets for an app's answer: its status
/// and the headers allowed to leave an app. Its body is set by the caller.
fn gateway_reply(status: &Value, headers: &Value) -> Result<Response> {
    let invalid = || Error::new(StatusCode::BAD_GATEWAY, "invalid application response");
    let status = status
        .as_u64()
        .filter(|n| (200..=599).contains(n))
        .and_then(|n| StatusCode::from_u16(n as u16).ok())
        .ok_or_else(invalid)?;
    let mut out = status.into_response();
    let headers = crate::application_headers::from_json(headers)
        .and_then(|headers| crate::application_headers::response(&headers))
        .map_err(|_| invalid())?;
    for (key, value) in headers {
        let value = value.as_str().ok_or_else(invalid)?;
        // The edge can negotiate a different content coding after this hop.
        // Publish only weak validators, including on identity/pre-encoded and
        // bodyless HEAD/304 responses, so validation never promises byte identity
        // across edge representations. Keep the app's opaque tag unchanged.
        let value = if key == "etag" && !value.trim().starts_with("W/") {
            format!("W/{}", value.trim())
        } else {
            value.to_owned()
        };
        out.headers_mut().insert(
            axum::http::HeaderName::from_bytes(key.as_bytes()).map_err(|_| invalid())?,
            value.parse().map_err(|_| invalid())?,
        );
    }
    Ok(out)
}

#[cfg(test)]
mod application_response_tests {
    use super::*;
    #[test]
    fn public_validators_are_weak_for_every_representation_and_status() {
        for status in [200, 304] {
            for encoding in [None, Some("gzip"), Some("br"), Some("zstd")] {
                for tag in ["\"version\"", "W/\"version\""] {
                    let mut headers = json!({"etag":tag});
                    if let Some(encoding) = encoding {
                        headers["content-encoding"] = json!(encoding);
                    }
                    let (response, _) =
                        gateway_response(json!({"status":status,"headers":headers,"body":""}))
                            .unwrap();
                    assert_eq!(response.headers()["etag"], "W/\"version\"");
                }
            }
        }
    }
    #[tokio::test]
    async fn encoded_bytes_and_cache_headers_are_forwarded_together() {
        let bytes = [0x1f, 0x8b, 0x08, 0x00, 0xff];
        let (out, size) = gateway_response(json!({"status":200,"body":STANDARD.encode(bytes),"headers":{"content-encoding":"gzip","vary":"Accept-Encoding, Origin","etag":"\"compressed\"","last-modified":"Wed, 21 Oct 2015 07:28:00 GMT","expires":"Wed, 21 Oct 2030 07:28:00 GMT","set-cookie":"bad=1; Domain=apps.example.com"}})).unwrap();
        assert_eq!(size, bytes.len());
        assert_eq!(out.headers()["content-encoding"], "gzip");
        assert_eq!(out.headers()["vary"], "Accept-Encoding, Origin");
        assert_eq!(out.headers()["etag"], "W/\"compressed\"");
        assert!(out.headers().contains_key("expires"));
        assert!(out.headers().contains_key("last-modified"));
        assert!(!out.headers().contains_key("set-cookie"));
        assert_eq!(
            to_bytes(out.into_body(), 1024).await.unwrap().as_ref(),
            bytes
        );
        let (out, size) = gateway_response(json!({"status":304,"body":"","headers":{"etag":"\"compressed\"","vary":"Accept-Encoding"}})).unwrap();
        assert_eq!(out.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(out.headers()["etag"], "W/\"compressed\"");
        assert_eq!(size, 0);
        assert!(to_bytes(out.into_body(), 1024).await.unwrap().is_empty());
    }
}
