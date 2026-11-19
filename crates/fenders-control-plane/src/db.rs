//! Parameterized JSON projection helpers for internal SQL. SQL text is always
//! authored by the platform; tenant data is bound, never interpolated.
use crate::{
    error::{Error, Result},
    store::Tx,
};
pub use fenders_node_protocol::value::*;
use serde_json::Value;
use sqlx::{Postgres, postgres::PgArguments, query::Query};

fn bind<'a>(sql: &'a str, args: &[Value]) -> Query<'a, Postgres, PgArguments> {
    let mut query = sqlx::query(sql);
    for value in args {
        query = match value {
            Value::Null => query.bind(Option::<String>::None),
            Value::String(s) => query.bind(s.clone()),
            Value::Bool(b) => query.bind(*b),
            Value::Number(n) => query.bind(n.as_i64().expect("internal SQL integer must fit i64")),
            other => query.bind(other.clone()),
        };
    }
    query
}
fn typed(sql: &str, args: &[Value]) -> String {
    let mut out = String::new();
    let mut chars = sql.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '$' || !chars.peek().is_some_and(|c| c.is_ascii_digit()) {
            out.push(c);
            continue;
        }
        let mut digits = String::new();
        while chars.peek().is_some_and(|c| c.is_ascii_digit()) {
            digits.push(chars.next().unwrap());
        }
        let index = digits.parse::<usize>().unwrap();
        let ty = match &args[index - 1] {
            Value::Number(_) => "bigint",
            Value::Bool(_) => "boolean",
            Value::Object(_) | Value::Array(_) => "jsonb",
            _ => "text",
        };
        out.push_str(&format!("(${index}::{ty})"));
    }
    out
}
pub async fn rows(tx: &mut Tx, sql: &str, args: &[Value]) -> Result<Vec<Value>> {
    use sqlx::Row;
    let wrapped = format!(
        "WITH fenders_rows AS ({}) SELECT to_jsonb(fenders_rows) AS row FROM fenders_rows",
        typed(sql, args)
    );
    bind(&wrapped, args)
        .fetch_all(&mut **tx)
        .await?
        .iter()
        .map(|r| r.try_get("row").map_err(Into::into))
        .collect()
}
pub async fn one(tx: &mut Tx, sql: &str, args: &[Value]) -> Result<Value> {
    rows(tx, sql, args)
        .await?
        .into_iter()
        .next()
        .ok_or_else(Error::missing)
}
pub async fn optional(tx: &mut Tx, sql: &str, args: &[Value]) -> Result<Option<Value>> {
    Ok(rows(tx, sql, args).await?.into_iter().next())
}
pub async fn exec(tx: &mut Tx, sql: &str, args: &[Value]) -> Result<u64> {
    Ok(bind(&typed(sql, args), args)
        .execute(&mut **tx)
        .await?
        .rows_affected())
}
/// An id that a request's body names. One that could be no id is a
/// malformed request and is said to be: `404` is for an id that could be
/// one and names nothing, and for anything a path names.
pub fn id(value: &Value) -> Result<&str> {
    fenders_node_protocol::value::id(value)
        .map_err(|_| Error::invalid("expected an id: 32 lowercase hexadecimal characters"))
}
// Control-plane errors carry the database classification, so these constructors
// shadow the protocol versions for code that also returns database errors.
pub fn conflict(message: &'static str) -> Error {
    Error::new(axum::http::StatusCode::CONFLICT, message)
}
/// A refusal for want of allowance, or at a limit on what a workspace may
/// have: not a rate, so waiting does not cure it.
///
/// Within the control plane it keeps the status it has always had, which
/// the scheduler, the gateway and the run channel tell it by, and which the
/// gateway and the run channel answer with. The management API answers it
/// `409` ([`QUOTA`] is how it knows one).
pub fn quota(message: &'static str) -> Error {
    Error::new(axum::http::StatusCode::TOO_MANY_REQUESTS, message).coded(QUOTA)
}
pub const QUOTA: &str = "quota_exhausted";
#[macro_export]
macro_rules! args { ($($value:expr),* $(,)?) => { &[$(serde_json::json!($value)),*] }; }

/// Refuses a database URL that names a server on another host and does not
/// say how its connection is secured.
///
/// Left unsaid, a PostgreSQL client tries TLS, checks no certificate and
/// falls back to none: whoever is on the path reads and changes everything
/// the control plane stores. For a server that is not this host the URL must
/// carry `sslmode`: `verify-full` (or `verify-ca`) to require a verified
/// connection, or one of the weaker modes to accept one knowingly.
pub fn database_url(dsn: &str) -> crate::error::Result<()> {
    use crate::error::Error;
    let url = url::Url::parse(dsn).map_err(|_| Error::invalid("PostgreSQL URL required"))?;
    let options: std::collections::BTreeMap<_, _> = url.query_pairs().collect();
    // A Unix socket directory, as `?host=/run/postgresql`, is this host.
    let host = options
        .get("host")
        .map(|host| host.to_string())
        .or_else(|| url.host_str().map(str::to_owned))
        .unwrap_or_default();
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let local = host.is_empty()
        || host.starts_with('/')
        || host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback());
    if local || options.contains_key("sslmode") {
        return Ok(());
    }
    Err(Error::invalid(
        "the database is on another host: add sslmode=verify-full (with sslrootcert) to its URL, or another sslmode to accept a connection that is not verified",
    ))
}

#[cfg(test)]
mod database_url_tests {
    use super::database_url;

    #[test]
    fn a_database_on_another_host_must_say_how_it_is_secured() {
        for local in [
            "postgresql://u:p@localhost/db",
            "postgresql://u:p@127.0.0.1:5432/db",
            "postgresql://u:p@[::1]/db",
            "postgresql:///db?host=/run/postgresql",
            "postgresql://u@localhost/db?host=%2Fvar%2Frun%2Fpostgresql",
            "postgres:///db",
        ] {
            assert!(database_url(local).is_ok(), "{local}");
        }
        for remote in [
            "postgresql://u:p@db.internal/db",
            "postgresql://u:p@10.0.0.5:5432/db",
            "postgresql://u:p@db.internal/db?application_name=x",
            // A socket directory is local; a host given as an option is not.
            "postgresql://u:p@localhost/db?host=db.internal",
        ] {
            let refused = database_url(remote).unwrap_err();
            assert!(refused.message.contains("sslmode"), "{remote}");
            // The URL, which holds a password, is never repeated.
            assert!(!refused.message.contains("db.internal") && !refused.message.contains("u:p"));
        }
        for stated in [
            "postgresql://u:p@db.internal/db?sslmode=verify-full&sslrootcert=/etc/ca.pem",
            "postgresql://u:p@db.internal/db?sslmode=require",
            "postgresql://u:p@db.internal/db?sslmode=disable",
        ] {
            assert!(database_url(stated).is_ok(), "{stated}");
        }
        assert!(database_url("not a url").is_err());
    }
}
