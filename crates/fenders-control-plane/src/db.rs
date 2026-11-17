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
// Control-plane errors carry the database classification, so these constructors
// shadow the protocol versions for code that also returns database errors.
pub fn conflict(message: &'static str) -> Error {
    Error::new(axum::http::StatusCode::CONFLICT, message)
}
pub fn quota(message: &'static str) -> Error {
    Error::new(axum::http::StatusCode::TOO_MANY_REQUESTS, message)
}
#[macro_export]
macro_rules! args { ($($value:expr),* $(,)?) => { &[$(serde_json::json!($value)),*] }; }
