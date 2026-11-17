//! What the shipped control plane refuses because no shim node can serve it.
//!
//! Nodes cannot pause a run (docs/STATUS.md). The code behind
//! that is kept, so the shipped binary answers 501 for it here rather than
//! accept work that would queue for ever. Tests of the kept code use a store
//! without this refusal. HTTP apps were refused here until shims served them.
//!
//! Remove a rule when its feature is served again; delete this module when
//! [`FEATURES`] is empty.
use crate::error::{Error, Result};
use axum::http::StatusCode;

/// The features refused, as the customer console reads them from its session.
pub const FEATURES: &[&str] = &["pause"];

const PAUSE: &str = "pausing and resuming a run are not available yet";

fn refused(message: &'static str) -> Error {
    Error::new(StatusCode::NOT_IMPLEMENTED, message)
}

/// Refuses a management request for a feature in [`FEATURES`]. `path` is the
/// normalized path (`v1/tenants/T/projects/P/...`); the request's bytes are
/// not needed by any rule now.
pub fn refuse(method: &str, path: &[&str], _body: &[u8]) -> Result<()> {
    let ["v1", "tenants", _, "projects", _, rest @ ..] = path else {
        return Ok(());
    };
    match (method, rest) {
        ("POST", ["executions", _, "pause" | "resume"]) => Err(refused(PAUSE)),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn check(method: &str, tail: &[&str], body: Value) -> Result<()> {
        let mut path = vec!["v1", "tenants", "t", "projects", "p"];
        path.extend_from_slice(tail);
        refuse(method, &path, body.to_string().as_bytes())
    }

    #[test]
    fn commands_schedules_reads_and_removals_pass() {
        let app = json!({"name":"a","artifact_id":"x","triggers":{"http":false,"manual":true,
            "schedule":{"expression":"0 * * * *","timezone":"UTC"}},"connections":[]});
        for (method, tail, body) in [
            ("POST", &["apps"][..], app.clone()),
            ("POST", &["apps", "deploy"], app),
            (
                "PUT",
                &["apps", "a", "triggers"],
                json!({"http":false,"manual":true}),
            ),
            (
                "PUT",
                &["apps", "a", "connections"],
                json!({"connections":[]}),
            ),
            ("POST", &["apps", "a", "runs"], json!({})),
            ("POST", &["executions", "e", "stop"], json!({})),
            ("GET", &["apps", "a", "events"], Value::Null),
            ("GET", &["apps", "a", "logs"], Value::Null),
            ("GET", &["external-endpoints"], Value::Null),
            (
                "POST",
                &["external-endpoints"],
                json!({"name":"db","host":"192.0.2.10","port":5432}),
            ),
            ("DELETE", &["external-endpoints", "e"], Value::Null),
            ("POST", &["grants", "g", "revoke"], json!({})),
            ("POST", &["secrets"], json!({"name":"s","value":"v"})),
            (
                "POST",
                &["executions"],
                json!({"spec":{"mode":"command","artifact_id":"x"}}),
            ),
            // HTTP apps are served: their shims pull requests.
            (
                "POST",
                &["apps"],
                json!({"triggers":{"http":true,"manual":false}}),
            ),
            (
                "PUT",
                &["apps", "a", "triggers"],
                json!({"http":true,"manual":true}),
            ),
            ("POST", &["apps", "a", "http-sample"], json!({})),
            ("POST", &["executions"], json!({"spec":{"mode":"http"}})),
            (
                "POST",
                &["deployments"],
                json!({"spec":{"mode":"http","network_id":"n"}}),
            ),
            // Connections are served: static launch policy.
            (
                "POST",
                &["apps", "deploy"],
                json!({"triggers":{"http":false,"manual":true},
                "connections":[{"connection_id":"c"}]}),
            ),
            (
                "POST",
                &["apps", "deploy"],
                json!({"https_origins":["https://example.com"]}),
            ),
            (
                "PUT",
                &["apps", "a", "connections"],
                json!({"connections":[{"connection_id":"c"}]}),
            ),
            ("POST", &["https-access", "validate"], json!({})),
            ("POST", &["grants"], json!({})),
            (
                "POST",
                &["deployments"],
                json!({"spec":{"mode":"command","network_id":"n"}}),
            ),
        ] {
            assert!(check(method, tail, body).is_ok(), "{method} {tail:?}");
        }
        assert!(refuse("POST", &["v1", "tenants"], b"{}").is_ok());
    }

    #[test]
    fn unserved_features_are_refused_with_501() {
        for (method, tail, body) in [
            ("POST", &["executions", "e", "pause"][..], json!({})),
            ("POST", &["executions", "e", "resume"], json!({})),
        ] {
            let error = check(method, tail, body).unwrap_err();
            assert_eq!(
                error.status,
                StatusCode::NOT_IMPLEMENTED,
                "{method} {tail:?}"
            );
            assert!(error.message.ends_with("not available yet"));
        }
    }
}
