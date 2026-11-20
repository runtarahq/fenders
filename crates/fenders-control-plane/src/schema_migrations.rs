//! Applied under Store's existing mutation transaction/advisory lock. A startup
//! records a schema change only after its SQL succeeds; rollback never rewinds it.
use crate::{
    error::{Error, Result},
    model::digest,
    store::{SCHEMA, Tx},
};

// Version 1 freezes the existing WASM-only startup updates. Append future
// migrations with an explicitly qualified reader/rollback window; do not edit
// an applied migration or silently accept an unknown database revision.
const BASELINE: &[&str] = &[
    crate::egress_budget::RETAINED_LAUNCHERS_MIGRATION,
    crate::app_https::RUNTIME_MIGRATION,
    include_str!("../sql/app_https_observations.sql"),
    "ALTER TABLE external_endpoints ALTER COLUMN username_secret_id DROP NOT NULL, ALTER COLUMN password_secret_id DROP NOT NULL",
    "CREATE TABLE IF NOT EXISTS external_https_endpoints (
            id text PRIMARY KEY, tenant_id text NOT NULL, project_id text NOT NULL,
            name text NOT NULL, origin text NOT NULL, deleted boolean NOT NULL DEFAULT false,
            created timestamptz NOT NULL DEFAULT now(),
            UNIQUE(tenant_id,project_id,name),
            FOREIGN KEY(tenant_id,project_id) REFERENCES projects(tenant_id,id))",
    crate::customer_api::MIGRATION,
    crate::workspace_lifecycle::MIGRATION,
    crate::app_delete::MIGRATION,
];

/// The migrations this binary knows, in order: each a checksum and its
/// statements.
fn migrations() -> Vec<(String, Vec<&'static str>)> {
    let http_runs = [include_str!("http_runs.sql")];
    let pickup = [crate::pickup::MIGRATION];
    let static_connections = [include_str!("../sql/static_connections.sql")];
    let http_scale = [include_str!("../sql/http_scale.sql")];
    let http_limits = [include_str!("../sql/http_limits.sql")];
    let websocket_connections = [include_str!("../sql/websocket_connections.sql")];
    let secret_binding = [crate::secret_binding::MIGRATION];
    let operator_receipts = [crate::customer_api::OPERATOR_RECEIPTS_MIGRATION];
    let audit_trail = [crate::audit_trail::MIGRATION];
    let project_deletion = [crate::store::Store::PROJECT_MIGRATION];
    let node_deletion = [crate::nodes::DELETION_MIGRATION];
    let workspace_deletion = [crate::workspace_lifecycle::DELETION_MIGRATION];
    let gateway_sessions = [crate::gateway::MIGRATION];
    let gateway_leases = [crate::gateway::LEASES_MIGRATION];
    let gate_changes = [include_str!("../sql/gate_changes.sql")];
    let egress_renewals = [include_str!("../sql/egress_renewals.sql")];
    let gateway_observations = [crate::observed::MIGRATION];
    let lease_recalls = [include_str!("../sql/lease_recalls.sql")];
    let websocket_sessions = [include_str!("../sql/websocket_sessions.sql")];
    let limit_shares = [crate::shares::MIGRATION];
    let edges = [crate::edges::MIGRATION];
    let app_takeovers = [include_str!("../sql/app_takeovers.sql")];
    let edge_seen = [include_str!("../sql/edge_seen.sql")];
    let release_guard = [include_str!("../sql/release_guard.sql")];
    vec![
        (
            digest(format!("{SCHEMA}\0{}", BASELINE.join("\0"))),
            BASELINE.to_vec(),
        ),
        (digest(http_runs[0]), http_runs.to_vec()),
        (digest(pickup[0]), pickup.to_vec()),
        (digest(static_connections[0]), static_connections.to_vec()),
        (digest(http_scale[0]), http_scale.to_vec()),
        (digest(http_limits[0]), http_limits.to_vec()),
        (
            digest(websocket_connections[0]),
            websocket_connections.to_vec(),
        ),
        (digest(secret_binding[0]), secret_binding.to_vec()),
        (digest(operator_receipts[0]), operator_receipts.to_vec()),
        (digest(audit_trail[0]), audit_trail.to_vec()),
        (digest(project_deletion[0]), project_deletion.to_vec()),
        (digest(node_deletion[0]), node_deletion.to_vec()),
        (digest(workspace_deletion[0]), workspace_deletion.to_vec()),
        (digest(gateway_sessions[0]), gateway_sessions.to_vec()),
        (digest(gateway_leases[0]), gateway_leases.to_vec()),
        (digest(gate_changes[0]), gate_changes.to_vec()),
        (digest(egress_renewals[0]), egress_renewals.to_vec()),
        (
            digest(gateway_observations[0]),
            gateway_observations.to_vec(),
        ),
        (digest(lease_recalls[0]), lease_recalls.to_vec()),
        (digest(websocket_sessions[0]), websocket_sessions.to_vec()),
        (digest(limit_shares[0]), limit_shares.to_vec()),
        (digest(edges[0]), edges.to_vec()),
        (digest(app_takeovers[0]), app_takeovers.to_vec()),
        (digest(edge_seen[0]), edge_seen.to_vec()),
        (digest(release_guard[0]), release_guard.to_vec()),
    ]
}

/// Whether the database has exactly the migrations this binary knows, for a
/// process that does not apply them.
pub(crate) async fn verify(tx: &mut Tx) -> Result<()> {
    let applied: Vec<(i64, String)> = sqlx::query_as(
        "SELECT version,checksum FROM control_schema_migrations ORDER BY version LIMIT 64",
    )
    .fetch_all(&mut **tx)
    .await?;
    let known = migrations();
    if applied.len() != known.len()
        || applied
            .iter()
            .zip(known.iter())
            .any(|((version, checksum), (expected, _))| checksum != expected || *version < 1)
    {
        return Err(Error::invalid(
            "the database's schema is not this binary's: migrate it with the control plane first",
        ));
    }
    Ok(())
}

pub(crate) async fn apply(tx: &mut Tx) -> Result<()> {
    sqlx::raw_sql(
        "CREATE TABLE IF NOT EXISTS control_schema_migrations (
        version bigint PRIMARY KEY CHECK(version>0),
        checksum text NOT NULL CHECK(checksum ~ '^[a-f0-9]{64}$'),
        applied_at timestamptz NOT NULL DEFAULT clock_timestamp())",
    )
    .execute(&mut **tx)
    .await?;
    // Keep the qualified baseline immutable. Main's HTTP-run schema is a new
    // additive migration, including when upgrading an existing version-1 ledger.
    let migrations = migrations();
    let applied: Vec<(i64, String)> = sqlx::query_as(
        "SELECT version,checksum FROM control_schema_migrations ORDER BY version LIMIT 64",
    )
    .fetch_all(&mut **tx)
    .await?;
    if applied.len() > migrations.len()
        || applied
            .iter()
            .enumerate()
            .any(|(index, (version, checksum))| {
                *version != index as i64 + 1 || *checksum != migrations[index].0
            })
    {
        return Err(Error::invalid(
            "unsupported control-plane schema migration history",
        ));
    }
    for (index, (checksum, statements)) in migrations.iter().enumerate().skip(applied.len()) {
        for statement in statements.iter() {
            sqlx::raw_sql(statement).execute(&mut **tx).await?;
        }
        sqlx::query("INSERT INTO control_schema_migrations(version,checksum) VALUES($1,$2)")
            .bind(index as i64 + 1)
            .bind(checksum)
            .execute(&mut **tx)
            .await?;
    }
    Ok(())
}
