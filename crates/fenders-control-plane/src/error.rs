use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;

#[derive(Debug)]
pub struct Error {
    pub status: StatusCode,
    pub message: &'static str,
    /// The reason, where it is one a caller can act on apart from others of
    /// its status. Without one, [`Error::code`] is the status's own.
    pub reason: Option<&'static str>,
    /// A header the answer carries with it: when to try again, or which
    /// methods a path takes.
    pub header: Option<(axum::http::HeaderName, String)>,
}
pub type Result<T> = std::result::Result<T, Error>;

/// Every reason an error may be given, beside the names of the statuses.
/// The contract lists them: one given here and not there fails a test.
pub const REASONS: &[&str] = &[
    "idempotency_key_required",
    "idempotency_key_reused",
    "revision_conflict",
    "already_exists",
    "not_validated",
    "workspace_suspended",
    "permission_denied",
    "quota_exhausted",
];

impl Error {
    pub fn new(status: StatusCode, message: &'static str) -> Self {
        Self {
            status,
            message,
            reason: None,
            header: None,
        }
    }
    /// The same error with the reason `code`.
    pub fn coded(mut self, code: &'static str) -> Self {
        debug_assert!(REASONS.contains(&code), "{code} is not a listed reason");
        self.reason = Some(code);
        self
    }
    /// The same error, answered with `header`.
    pub fn with_header(mut self, name: axum::http::HeaderName, value: impl Into<String>) -> Self {
        self.header = Some((name, value.into()));
        self
    }
    /// What a caller branches on: the reason where there is one, and the
    /// status's own name where there is not.
    pub fn code(&self) -> &'static str {
        self.reason
            .unwrap_or_else(|| fenders_node_protocol::error::status_code(self.status))
    }
    pub fn invalid(message: &'static str) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }
    pub fn missing() -> Self {
        Self::new(StatusCode::NOT_FOUND, "resource not found")
    }
    pub fn unauthorized() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "unauthorized")
    }
    pub fn internal() -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.status, self.message)
    }
}
impl std::error::Error for Error {}
impl From<sqlx::Error> for Error {
    fn from(error: sqlx::Error) -> Self {
        // Database errors may contain tenant data and connection details. Never echo them.
        match error {
            sqlx::Error::Database(ref e) if e.code().is_some_and(|c| c == "23505") => {
                Self::new(StatusCode::CONFLICT, "resource already exists").coded("already_exists")
            }
            sqlx::Error::Database(ref e) if e.code().is_some_and(|c| c == "23503") => {
                Self::missing()
            }
            sqlx::Error::PoolTimedOut => {
                Self::new(StatusCode::SERVICE_UNAVAILABLE, "database unavailable")
            }
            _ => Self::internal(),
        }
    }
}
impl From<std::io::Error> for Error {
    fn from(_: std::io::Error) -> Self {
        Self::internal()
    }
}
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        (self.status, Json(json!({"error": self.message}))).into_response()
    }
}
impl From<fenders_node_protocol::error::Error> for Error {
    fn from(error: fenders_node_protocol::error::Error) -> Self {
        Self {
            reason: error.reason,
            ..Self::new(error.status, error.message)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_code_is_the_reason_given_or_else_the_status_named() {
        for (status, code) in [
            (StatusCode::BAD_REQUEST, "invalid_request"),
            (StatusCode::NOT_FOUND, "not_found"),
            (StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed"),
            (StatusCode::REQUEST_TIMEOUT, "request_timeout"),
            (StatusCode::UNSUPPORTED_MEDIA_TYPE, "unsupported_media_type"),
            (StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
            (StatusCode::BAD_GATEWAY, "bad_gateway"),
            (StatusCode::GATEWAY_TIMEOUT, "gateway_timeout"),
            (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        ] {
            assert_eq!(Error::new(status, "refused").code(), code);
        }
        let conflict = Error::new(StatusCode::CONFLICT, "refused");
        assert_eq!(conflict.code(), "conflict");
        assert_eq!(
            conflict.coded("revision_conflict").code(),
            "revision_conflict"
        );
        // A node's error keeps its reason on the way through.
        let node = fenders_node_protocol::error::Error::invalid("refused").coded("specific");
        assert_eq!(Error::from(node).code(), "specific");
    }

    #[test]
    fn the_contract_lists_every_code() {
        let spec: serde_json::Value =
            serde_json::from_str(include_str!("../static/api/openapi.json")).unwrap();
        let listed: Vec<&str> =
            spec["components"]["schemas"]["Error"]["properties"]["code"]["enum"]
                .as_array()
                .unwrap()
                .iter()
                .map(|code| code.as_str().unwrap())
                .collect();
        for reason in REASONS {
            assert!(listed.contains(reason), "{reason} is not in the contract");
        }
        // And what the contract lists is a reason, or a status this names.
        let statuses: Vec<&str> = (400..600)
            .filter_map(|status| StatusCode::from_u16(status).ok())
            .map(fenders_node_protocol::error::status_code)
            .collect();
        for code in listed {
            assert!(
                REASONS.contains(&code) || statuses.contains(&code),
                "the contract lists {code}, which nothing answers"
            );
        }
    }
}
