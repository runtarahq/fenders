//! Loopback-only single-node API. The fleet agent uses a separate pinned mTLS interface.
use crate::agent::Backend;
use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::{Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use fenders_node_protocol::{
    error::{Error, Result},
    model::digest,
};
use serde_json::json;
use std::sync::Arc;
use subtle::ConstantTimeEq;
#[derive(Clone)]
struct Api {
    node: Arc<dyn Backend>,
    token_hash: [u8; 64],
    slots: Arc<tokio::sync::Semaphore>,
}
pub fn router(node: Arc<dyn Backend>, token: &str) -> Router {
    let token_hash = digest(format!("Bearer {token}"))
        .as_bytes()
        .try_into()
        .unwrap();
    Router::new().fallback(handle).with_state(Api {
        node,
        token_hash,
        slots: Arc::new(tokio::sync::Semaphore::new(32)),
    })
}
async fn read(body: Body, limit: usize) -> Result<Vec<u8>> {
    tokio::time::timeout(std::time::Duration::from_secs(10), to_bytes(body, limit))
        .await
        .map_err(|_| Error::new(StatusCode::REQUEST_TIMEOUT, "request timed out"))?
        .map(|b| b.to_vec())
        .map_err(|_| Error::new(StatusCode::PAYLOAD_TOO_LARGE, "request too large"))
}
async fn handle(State(api): State<Api>, req: Request) -> Result<Response> {
    let (parts, body) = req.into_parts();
    let hash = digest(
        parts
            .headers
            .get("authorization")
            .map(|h| h.as_bytes())
            .unwrap_or_default(),
    );
    if hash.as_bytes().ct_eq(&api.token_hash).unwrap_u8() != 1 {
        return Err(Error::new(StatusCode::UNAUTHORIZED, "unauthorized"));
    }
    let _slot = api.slots.try_acquire().map_err(|_| {
        Error::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "node request capacity exhausted",
        )
    })?;
    let method = parts.method.as_str();
    let path: Vec<_> = parts
        .uri
        .path()
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();
    let node = api.node.clone();
    if method == "GET" && path == ["v1", "health"] {
        return Ok(Json(json!({"status":"ok","backend":"kvm-kernel-free","guest_ram_mib":32,"guest_ram_mib_max":1024,"network_leases":false,"egress_budget_supported":false,"confinement":fenders_node_protocol::model::HOST_CONFINEMENT})).into_response());
    }
    if method == "POST" && path == ["v1", "artifacts"] {
        let bytes = read(body, node.max_upload()).await?;
        let v = tokio::task::spawn_blocking(move || node.upload(&bytes))
            .await
            .map_err(|_| Error::internal())??;
        return Ok((StatusCode::CREATED, Json(v)).into_response());
    }
    if path == ["v1", "instances"] {
        if method == "GET" {
            return Ok(Json(json!({"instances":node.list()?})).into_response());
        }
        if method == "POST" {
            let value = serde_json::from_slice(&read(body, 16384).await?)
                .map_err(|_| Error::invalid("invalid JSON"))?;
            let key = parts
                .headers
                .get("idempotency-key")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_owned();
            let v = tokio::task::spawn_blocking(move || node.create(&value, &key))
                .await
                .map_err(|_| Error::internal())??;
            return Ok((StatusCode::ACCEPTED, Json(v)).into_response());
        }
    }
    if path.len() >= 3 && path[..2] == ["v1", "instances"] {
        let id = path[2];
        fenders_node_protocol::model::identity(id)?;
        if path.len() == 3 && method == "GET" {
            return Ok(Json(node.status(id)?).into_response());
        }
        if path.len() == 4 && method == "POST" && path[3] == "stop" {
            read(body, 0).await?;
            return Ok(Json(node.action(id, "stop")?).into_response());
        }
    }
    Err(Error::missing())
}
