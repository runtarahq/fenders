use crate::{
    db::s,
    error::{Error, Result},
    model::*,
};
use axum::http::StatusCode;
use serde_json::{Value, json};
use sqlx::{PgPool, Postgres, Transaction, postgres::PgPoolOptions};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

pub const SCHEMA: &str = include_str!("../schema.sql");
pub type Tx = Transaction<'static, Postgres>;

/// Keep the admission transaction alive even if the awaiting request is cancelled.
/// Dropping a spawn_blocking handle does not stop its filesystem worker.
pub(crate) async fn guarded_blocking<G, T, F>(guard: G, work: F) -> Result<(G, T)>
where
    G: Send + 'static,
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        let result = work();
        (guard, result)
    })
    .await
    .map_err(|_| Error::internal())
}

#[derive(Clone)]
pub struct Store {
    pub pool: PgPool,
    pub(crate) state: PathBuf,
    pub(crate) cipher: fernet::Fernet,
    /// For run-channel credentials alone, under a key of its own: nothing
    /// encrypted with `cipher`, a tenant's secret among it, is one.
    pub(crate) channel_cipher: fernet::Fernet,
    pub(crate) encryption_key_id: String,
    pub(crate) external_network:
        Option<std::sync::Arc<crate::external_endpoints::ExternalNetworkPolicy>>,
    pub(crate) public_egress: Option<std::sync::Arc<crate::public_egress::PublicEgress>>,
    pub(crate) orphan_upload_scan: std::sync::Arc<std::sync::Mutex<crate::orphan_uploads::Scan>>,
    pub(crate) background: std::sync::Arc<crate::supervision::Monitor>,
    pub(crate) pickup: std::sync::Arc<crate::pickup::Pickup>,
    pub(crate) run_channel: Option<std::sync::Arc<crate::run_channel::RunChannel>>,
    /// Requests for HTTP apps, between the gateway and the run channel.
    pub exchange: std::sync::Arc<crate::http_exchange::Exchange>,
    /// The WebSocket connections the gateway holds for apps.
    pub sockets: std::sync::Arc<crate::websocket::Sockets>,
    /// How many requests each workspace was admitted lately.
    pub http_rates: std::sync::Arc<crate::ingress::Rates>,
    /// One heartbeat of each node at a time.
    pub node_turns: std::sync::Arc<crate::nodes::NodeTurns>,
    /// Mutating management requests admitted for each workspace.
    pub api_rates: std::sync::Arc<crate::ingress::Rates>,
    /// Whose each gateway host name is, for refusing without a transaction.
    pub ingress_hosts: std::sync::Arc<crate::ingress::Hosts>,
}

fn private_directory(path: &Path) -> Result<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)?;
    if fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(Error::invalid(
            "state directories must not be symbolic links",
        ));
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}
fn private_file(path: &Path, content: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(content)?;
    file.sync_all()?;
    fs::File::open(path.parent().ok_or_else(Error::internal)?)?.sync_all()?;
    Ok(())
}
pub(crate) fn token(prefix: &str) -> Result<String> {
    let mut entropy = [0u8; 32];
    fs::File::open("/dev/urandom")?.read_exact(&mut entropy)?;
    Ok(format!(
        "{prefix}{}",
        entropy
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ))
}
/// Which page of a list is asked for: the `limit` newest, or the `limit`
/// next after the cursor a page before gave as its `next`.
#[derive(Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListPage {
    pub before: Option<String>,
    pub limit: Option<i64>,
}
impl ListPage {
    /// As many as a list held before it was paged: for the control plane's
    /// own reads, which are not the API's.
    pub(crate) fn whole() -> Self {
        Self {
            before: None,
            limit: Some(1000),
        }
    }
    /// The page, if it asks for no more than the API gives at once.
    pub fn at_most(self, most: i64) -> Result<Self> {
        if self.limit.is_some_and(|limit| !(1..=most).contains(&limit)) {
            return Err(Error::invalid("page limit must be between 1 and 100"));
        }
        Ok(self)
    }
    /// The cursor and the limit, once they are known to be ones. A cursor
    /// is the id of the last thing a page showed. That is not said to a
    /// caller, who passes back what it was given.
    pub(crate) fn bounds(&self, most: i64) -> Result<(Option<&str>, i64)> {
        let limit = self.limit.unwrap_or(100);
        if !(1..=most).contains(&limit) {
            return Err(Error::invalid("page limit must be between 1 and 100"));
        }
        if let Some(before) = &self.before
            && identity(before).is_err()
        {
            return Err(Error::invalid("invalid page cursor"));
        }
        Ok((self.before.as_deref(), limit))
    }
    /// `{items, next}` of rows read one past the limit: `next` is the
    /// cursor to the page after this one, or null when there is none.
    pub(crate) fn page(mut items: Vec<Value>, limit: i64) -> Value {
        let more = items.len() > limit as usize;
        items.truncate(limit as usize);
        let next = match (more, items.last()) {
            (true, Some(last)) => last["id"].clone(),
            _ => Value::Null,
        };
        json!({"items":items,"next":next})
    }
}
/// Newest first, and after a cursor: for a list of rows `r` of `table`.
/// `$b` is the cursor's parameter.
fn after_cursor(table: &str, b: usize) -> String {
    format!(
        "(${b}::text IS NULL OR (r.created,r.id)<(SELECT c.created,c.id FROM {table} c WHERE c.id=${b}))"
    )
}

/// A workspace `t` as the API shows it to the operator: what it is called,
/// what it may use, how it stands, and the revisions the operator's own
/// changes expect. Not a column more: a column added to the table is not
/// thereby added to the API.
pub(crate) const WORKSPACE: &str = "jsonb_build_object('id',t.id,'name',t.name,'cpu_percent',t.cpu_percent,'memory_mib',t.memory_mib,'storage_bytes',t.storage_bytes,'instances',t.instances,'transfer_bytes',t.transfer_bytes,'default_app_size',t.default_app_size,'http_concurrent_requests',t.http_concurrent_requests,'http_requests_per_minute',t.http_requests_per_minute,'lifecycle_state',t.lifecycle_state,'lifecycle_revision',t.lifecycle_revision,'lifecycle_reason',t.lifecycle_reason,'allowance_revision',t.allowance_revision,'created',t.created)";
/// A project `p`: its name as it was given, and the slug made of it.
pub(crate) const PROJECT: &str = "jsonb_build_object('id',p.id,'tenant_id',p.tenant_id,'name',p.display_name,'slug',p.slug,'is_default',p.is_default,'created',p.created)";
/// An artifact `a`.
pub(crate) const ARTIFACT: &str = "jsonb_build_object('id',a.id,'tenant_id',a.tenant_id,'project_id',a.project_id,'digest',a.digest,'size',a.size,'created',a.created,'last_uploaded_at',a.last_uploaded_at)";

/// The same of a row called `r`, as the list of a project's things has it.
const ARTIFACT_OF_R: &str = "jsonb_build_object('id',r.id,'tenant_id',r.tenant_id,'project_id',r.project_id,'digest',r.digest,'size',r.size,'created',r.created,'last_uploaded_at',r.last_uploaded_at)";

/// An operation `o` as the API shows it. Stopping an execution that is a
/// run's is shown as what was asked for: cancelling that run.
pub(crate) const OPERATION: &str = "jsonb_build_object('id',o.id,'kind',CASE WHEN cancelled.id IS NULL THEN o.kind ELSE 'cancel-run' END,'resource_id',COALESCE(cancelled.id,o.resource_id),'state',o.state,'error',o.error,'created',o.created,'updated',o.updated)";
/// The run an operation `o` cancels, where it is one that does.
pub(crate) const OPERATION_RUN: &str = "LEFT JOIN LATERAL (SELECT r.id FROM app_runs r WHERE o.kind='stop' AND r.execution_id=o.resource_id LIMIT 1) cancelled ON true";

/// The most rows of each kind a workspace may have: projects, secrets, apps,
/// and credentials (API keys among them) that still open anything.
pub(crate) const MAX_PROJECTS: i64 = 256;
pub(crate) const MAX_SECRETS: i64 = 4096;
pub(crate) const MAX_APPS: i64 = 4096;
pub(crate) const MAX_CREDENTIALS: i64 = 1024;

/// A cipher for one `purpose`, under a key derived from the encryption key
/// `key`: what it encrypts is nothing to the encryption key's own cipher or
/// to another purpose's, and the reverse.
pub(crate) fn purpose_cipher(key: &str, purpose: &str) -> Result<fernet::Fernet> {
    use base64::Engine;
    let invalid = || Error::invalid("invalid encryption key");
    let engine = base64::engine::general_purpose::URL_SAFE;
    let secret = engine.decode(key.trim()).map_err(|_| invalid())?;
    let mut derived = [0u8; 32];
    hkdf::Hkdf::<sha2::Sha256>::new(Some(b"fenders-purpose-key-v1"), &secret)
        .expand(purpose.as_bytes(), &mut derived)
        .map_err(|_| invalid())?;
    let cipher = fernet::Fernet::new(&engine.encode(derived)).ok_or_else(invalid);
    derived.fill(0);
    cipher
}

impl Store {
    pub async fn connect(dsn: &str, state: &Path) -> Result<Self> {
        crate::db::database_url(dsn)?;
        let pool = PgPoolOptions::new()
            .max_connections(16)
            .acquire_timeout(Duration::from_secs(5))
            .connect(dsn)
            .await?;
        Self::from_pool(pool, state)
    }
    pub fn from_pool(pool: PgPool, state: &Path) -> Result<Self> {
        private_directory(state)?;
        private_directory(&state.join("blobs"))?;
        let key = state.join("encryption.key");
        if !key.try_exists()? {
            match private_file(&key, fernet::Fernet::generate_key().as_bytes()) {
                Ok(()) => (),
                Err(e) if !key.try_exists()? => return Err(e),
                Err(_) => (),
            }
        }
        let key = crate::key_rotation::read_key(&key)?;
        let cipher =
            fernet::Fernet::new(&key).ok_or_else(|| Error::invalid("invalid encryption key"))?;
        Ok(Self {
            pool,
            state: state.canonicalize()?,
            cipher,
            channel_cipher: purpose_cipher(&key, crate::run_channel::PURPOSE)?,
            encryption_key_id: digest(&key),
            public_egress: None,
            external_network: None,
            orphan_upload_scan: Default::default(),
            background: Default::default(),
            pickup: Default::default(),
            run_channel: None,
            exchange: Default::default(),
            http_rates: Default::default(),
            ingress_hosts: Default::default(),
            api_rates: Default::default(),
            node_turns: Default::default(),
            sockets: Default::default(),
        })
    }

    pub async fn transaction(&self, mutate: bool, recovery: bool) -> Result<Tx> {
        self.begin_transaction(mutate, recovery, false).await
    }
    pub fn background_monitor(&self) -> std::sync::Arc<crate::supervision::Monitor> {
        self.background.clone()
    }
    pub fn background_status(&self, p: &Principal) -> Result<Value> {
        p.operator()?;
        self.background.snapshot()
    }
    pub(crate) async fn snapshot(&self) -> Result<Tx> {
        self.begin_transaction(false, false, true).await
    }
    async fn begin_transaction(&self, mutate: bool, recovery: bool, snapshot: bool) -> Result<Tx> {
        let mut tx = self.pool.begin().await?;
        if snapshot {
            sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
                .execute(&mut *tx)
                .await?;
        }
        sqlx::query("SET LOCAL statement_timeout = '10s'")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SET LOCAL lock_timeout = '5s'")
            .execute(&mut *tx)
            .await?;
        if mutate {
            sqlx::query("SELECT pg_advisory_xact_lock(184923781), set_config('fenders.mutation','true',true)")
                .execute(&mut *tx)
                .await?;
        }
        if !recovery {
            let barrier: Value =
                sqlx::query_scalar("SELECT to_jsonb(b) FROM recovery_barrier b WHERE singleton")
                    .fetch_one(&mut *tx)
                    .await?;
            crate::key_rotation::check_identity(&barrier, &self.encryption_key_id)?;
            if mutate && barrier["active"] == true {
                return Err(Error::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "restored control plane awaits external-resource fencing and operator activation",
                ));
            }
        }
        Ok(tx)
    }
    pub async fn migrate(&self) -> Result<()> {
        let mut tx = self.transaction(true, true).await?;
        let initialized: bool =
            sqlx::query_scalar("SELECT to_regclass('platform_format') IS NOT NULL")
                .fetch_one(&mut *tx)
                .await?;
        if initialized {
            let format: String =
                sqlx::query_scalar("SELECT format FROM platform_format WHERE singleton")
                    .fetch_one(&mut *tx)
                    .await?;
            if format != "wasm-only-v1" {
                return Err(Error::invalid("unsupported platform database format"));
            }
        } else {
            let legacy: bool =
                sqlx::query_scalar("SELECT to_regclass('schema_version') IS NOT NULL")
                    .fetch_one(&mut *tx)
                    .await?;
            if legacy {
                return Err(Error::invalid(
                    "managed-service databases are not supported; configure a fresh database and state directory for the WASM-only MVP",
                ));
            }
            sqlx::raw_sql(SCHEMA).execute(&mut *tx).await?;
        }
        crate::schema_migrations::apply(&mut tx).await?;
        // Secrets stored before their ciphertexts named their rows.
        crate::secret_binding::bind_stored(&mut tx, &self.cipher).await?;
        let unbound: bool = sqlx::query_scalar(
            "SELECT encryption_key_id IS NULL FROM recovery_barrier WHERE singleton",
        )
        .fetch_one(&mut *tx)
        .await?;
        if unbound {
            crate::key_rotation::validate_or_reencrypt(&mut tx, &self.cipher, None).await?;
        }
        sqlx::query("UPDATE recovery_barrier SET encryption_key_id=$1 WHERE singleton AND encryption_key_id IS NULL")
            .bind(&self.encryption_key_id).execute(&mut *tx).await?;
        let barrier: Value =
            sqlx::query_scalar("SELECT to_jsonb(b) FROM recovery_barrier b WHERE singleton")
                .fetch_one(&mut *tx)
                .await?;
        crate::key_rotation::check_identity(&barrier, &self.encryption_key_id)?;
        tx.commit().await?;
        Ok(())
    }
    pub async fn bootstrap(&self) -> Result<PathBuf> {
        let mut tx = self.transaction(true, true).await?;
        let path = self.state.join("operator.token");
        if !path.try_exists()? {
            private_file(&path, token("fnd_op_")?.as_bytes())?;
        }
        let credential = fs::read_to_string(&path)?;
        let credential = credential.trim();
        if !credential.starts_with("fnd_op_") || credential.len() > 256 {
            return Err(Error::invalid("invalid operator credential file"));
        }
        // The file is the operator credential: it is valid for as long as it
        // is the file's, not for thirty days from the first start (after
        // which nothing could issue or renew a tenant's credentials). One
        // that was revoked, as a restore revokes every credential, stays so.
        sqlx::query("INSERT INTO credentials (id,token_hash,name,role,expires) VALUES ($1,$2,'bootstrap','operator','infinity') ON CONFLICT (token_hash) DO UPDATE SET expires='infinity' WHERE NOT credentials.revoked")
            .bind(uid()).bind(digest(credential)).execute(&mut *tx).await?;
        // And only it: a credential the file held before is revoked, so that
        // replacing the file and starting again is how one that leaked ends.
        sqlx::query("UPDATE credentials SET revoked=true WHERE role='operator' AND name='bootstrap' AND token_hash<>$1 AND NOT revoked")
            .bind(digest(credential)).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(path)
    }
    /// Whether the credential `p` was made from still stands, as it stood:
    /// not revoked or expired, with the scope and permissions it had. Asked
    /// in the transaction that acts for it, and before a change, whether its
    /// workspace may still be changed.
    pub(crate) async fn live_principal(tx: &mut Tx, p: &Principal) -> Result<()> {
        if let Some(tenant) = &p.tenant_id {
            let valid: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM credentials WHERE id=$1 AND NOT revoked AND expires>now() AND role=$2 AND tenant_id=$3 AND project_id IS NOT DISTINCT FROM $4 AND api_permissions IS NOT DISTINCT FROM $5)")
                .bind(&p.id).bind(p.role.as_str()).bind(tenant).bind(&p.project_id).bind(p.api_permissions.as_ref().map(|permissions| serde_json::json!(permissions))).fetch_one(&mut **tx).await?;
            if !valid {
                return Err(Error::unauthorized());
            }
            let writing: bool = sqlx::query_scalar(
                "SELECT COALESCE(current_setting('fenders.mutation',true),'')='true'",
            )
            .fetch_one(&mut **tx)
            .await?;
            if writing {
                Self::require_workspace_active(tx, tenant).await?;
            }
        }
        Ok(())
    }
    pub async fn authenticate(&self, token: &str) -> Result<Principal> {
        if token.is_empty() || token.len() > 256 {
            return Err(Error::unauthorized());
        }
        let mut tx = self.transaction(false, false).await?;
        let row = sqlx::query_scalar::<_, Value>("SELECT jsonb_build_object('id',id,'role',role,'tenant_id',tenant_id,'project_id',project_id,'api_permissions',api_permissions,'label',label) FROM credentials WHERE token_hash=$1 AND NOT revoked AND expires>now()")
            .bind(digest(token)).fetch_optional(&mut *tx).await?.ok_or_else(Error::unauthorized)?;
        // Metadata only; never persist or log the bearer value. Throttle writes.
        sqlx::query("UPDATE credentials SET last_used=now() WHERE id=$1 AND api_permissions IS NOT NULL AND (last_used IS NULL OR last_used<now()-interval '1 minute')")
            .bind(row["id"].as_str()).execute(&mut *tx).await?;
        tx.commit().await?;
        serde_json::from_value(row).map_err(|_| Error::internal())
    }
    pub(crate) async fn audit(
        tx: &mut Tx,
        actor: &Principal,
        action: &str,
        resource: &str,
        tenant: &str,
        detail: Value,
    ) -> Result<()> {
        sqlx::query(
            // With the label of the key that did it, where a key did.
            "INSERT INTO audit (tenant_id,actor,action,resource_id,detail,actor_label) VALUES ($1,$2,$3,$4,$5,(SELECT label FROM credentials WHERE id=$2))",
        )
        .bind(tenant)
        .bind(&actor.id)
        .bind(action)
        .bind(resource)
        .bind(detail)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }
    pub(crate) async fn project(
        tx: &mut Tx,
        p: &Principal,
        tenant: &str,
        project: &str,
        write: bool,
    ) -> Result<()> {
        Self::live_principal(tx, p).await?;
        p.scope(tenant, Some(project), write, false)?;
        if write {
            Self::require_workspace_active(tx, tenant).await?;
        }
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM projects WHERE tenant_id=$1 AND id=$2)",
        )
        .bind(tenant)
        .bind(project)
        .fetch_one(&mut **tx)
        .await?;
        if !exists {
            return Err(Error::missing());
        }
        Ok(())
    }
    /// Every workspace, for the control plane's own reads.
    pub async fn tenants(&self, p: &Principal) -> Result<Value> {
        Ok(self.workspaces(p, ListPage::whole()).await?["items"].take())
    }
    /// A page of the workspaces a credential may see: all of them to the
    /// operator, and a key its own.
    pub async fn workspaces(&self, p: &Principal, page: ListPage) -> Result<Value> {
        let (before, limit) = page.bounds(1000)?;
        let mut tx = self.transaction(false, false).await?;
        Self::live_principal(&mut tx, p).await?;
        let rows = sqlx::query_scalar::<_, Value>(
            // A workspace's own credentials see its plan and its state, not
            // what the operator wrote of it for itself: the reason it gave
            // for a suspension, and the revisions of its own edits.
            &format!("SELECT CASE WHEN $1 THEN {WORKSPACE} ELSE {WORKSPACE}-ARRAY['lifecycle_reason','lifecycle_revision','allowance_revision'] END FROM tenants t WHERE ($1 OR t.id=$2) AND ($3::text IS NULL OR (t.created,t.id)<(SELECT c.created,c.id FROM tenants c WHERE c.id=$3)) ORDER BY t.created DESC,t.id DESC LIMIT $4"),
        )
        .bind(p.role == Role::Operator)
        .bind(&p.tenant_id)
        .bind(before)
        .bind(limit + 1)
        .fetch_all(&mut *tx)
        .await?;
        Ok(ListPage::page(rows, limit))
    }
    pub async fn create_tenant(&self, p: &Principal, value: CreateTenant) -> Result<Value> {
        self.create_tenant_keyed(p, value, None).await
    }
    /// With a key, a retry is answered with the tenant the first call made
    /// and makes no second one. Two tenants may share a name; nothing but
    /// the key tells a retry from another tenant.
    pub async fn create_tenant_keyed(
        &self,
        p: &Principal,
        value: CreateTenant,
        key: Option<&str>,
    ) -> Result<Value> {
        p.operator()?;
        name(&value.name)?;
        value.allowance.validate()?;
        let request = json!({"kind":"tenant.create","name":value.name,"allowance":value.allowance});
        let mut tx = self.transaction(true, false).await?;
        if let Some(key) = key
            && let Some(row) =
                crate::customer_api::operator_receipt(&mut tx, &p.id, key, &request).await?
        {
            return Ok(row);
        }
        let (row, project_id) =
            Self::create_workspace_records(&mut tx, &value.name, &value.name, &value.allowance)
                .await?;
        let id = s(&row["id"]);
        Self::audit(&mut tx, p, "tenant.create", id, id, json!({})).await?;
        Self::audit(
            &mut tx,
            p,
            "project.create",
            &project_id,
            id,
            json!({"default":true}),
        )
        .await?;
        if let Some(key) = key {
            crate::customer_api::save_operator_receipt(
                &mut tx,
                &p.id,
                key,
                Some(id),
                &request,
                &row,
            )
            .await?;
        }
        tx.commit().await?;
        Ok(row)
    }
    /// Caller authorizes admission and writes its audit in the same transaction.
    pub(crate) async fn create_workspace_records(
        tx: &mut Tx,
        name: &str,
        display_name: &str,
        a: &Allowance,
    ) -> Result<(Value, String)> {
        let id = uid();
        let row = sqlx::query_scalar::<_, Value>(&format!("INSERT INTO tenants AS t (id,name,display_name,cpu_percent,memory_mib,storage_bytes,instances,transfer_bytes) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING {WORKSPACE}"))
            .bind(&id).bind(name).bind(display_name).bind(a.cpu_percent).bind(a.memory_mib).bind(a.storage_bytes).bind(a.instances).bind(a.transfer_bytes).fetch_one(&mut **tx).await?;
        let project_id = uid();
        sqlx::query("INSERT INTO projects(id,tenant_id,name,display_name,slug,is_default) VALUES ($1,$2,'production','Production','production',true)")
            .bind(&project_id).bind(&id).execute(&mut **tx).await?;
        Ok((row, project_id))
    }
    pub async fn update_allowance(
        &self,
        p: &Principal,
        tenant: &str,
        value: UpdateAllowance,
    ) -> Result<Value> {
        self.update_allowance_keyed(p, tenant, value, None).await
    }
    /// A key is not required. With one, a retry is answered as the first
    /// call was, where without it a lowered allowance might by then be
    /// refused as below what is in use.
    pub async fn update_allowance_keyed(
        &self,
        p: &Principal,
        tenant: &str,
        value: UpdateAllowance,
        key: Option<&str>,
    ) -> Result<Value> {
        p.operator()?;
        identity(tenant)?;
        if value.allowance.is_none() && value.default_app_size.is_none() {
            return Err(Error::invalid("nothing to change"));
        }
        if let Some(allowance) = &value.allowance {
            allowance.validate()?;
        }
        if let Some(size) = &value.default_app_size
            && !matches!(size.as_str(), "small" | "medium" | "large")
        {
            return Err(Error::invalid("default app size is small, medium or large"));
        }
        let request = json!({"kind":"tenant.update","tenant":tenant,"allowance":value.allowance,"default_app_size":value.default_app_size});
        let mut tx = self.transaction(true, false).await?;
        Self::live_principal(&mut tx, p).await?;
        if let Some(key) = key
            && let Some(row) =
                crate::customer_api::operator_receipt(&mut tx, &p.id, key, &request).await?
        {
            return Ok(row);
        }
        if let Some(size) = &value.default_app_size {
            let changed = sqlx::query("UPDATE tenants SET default_app_size=$2 WHERE id=$1")
                .bind(tenant)
                .bind(size)
                .execute(&mut *tx)
                .await?;
            if changed.rows_affected() == 0 {
                return Err(Error::missing());
            }
            Self::audit(
                &mut tx,
                p,
                "tenant.default_app_size",
                tenant,
                tenant,
                json!({"default_app_size":size}),
            )
            .await?;
        }
        let row = match &value.allowance {
            Some(allowance) => {
                let row = Self::set_allowance(&mut tx, tenant, allowance).await?;
                Self::audit(
                    &mut tx,
                    p,
                    "tenant.allowance",
                    tenant,
                    tenant,
                    json!(allowance),
                )
                .await?;
                row
            }
            None => {
                sqlx::query_scalar::<_, Value>(&format!(
                    "SELECT {WORKSPACE} FROM tenants t WHERE id=$1"
                ))
                .bind(tenant)
                .fetch_one(&mut *tx)
                .await?
            }
        };
        if let Some(key) = key {
            crate::customer_api::save_operator_receipt(
                &mut tx,
                &p.id,
                key,
                Some(tenant),
                &request,
                &row,
            )
            .await?;
        }
        tx.commit().await?;
        Ok(row)
    }
    /// The caller authorizes the operation and records its audit in this transaction.
    pub(crate) async fn set_allowance(tx: &mut Tx, tenant: &str, a: &Allowance) -> Result<Value> {
        a.validate()?;
        let allowed: bool = sqlx::query_scalar("SELECT (SELECT COALESCE(sum(cpu_percent),0)<=$2 AND COALESCE(sum(memory_mib),0)<=$3 AND count(*)<=$4 FROM compute_reservations WHERE tenant_id=$1) AND (SELECT COALESCE(sum(bytes),0)<=$5 FROM storage_reservations WHERE tenant_id=$1) AND ((SELECT COALESCE(sum(used_bytes+held_bytes),0) FROM transfer_allowance_accounting WHERE tenant_id=$1 AND period=date_trunc('month',now() AT TIME ZONE 'UTC')::date)<=$6)")
            .bind(tenant).bind(a.cpu_percent).bind(a.memory_mib).bind(a.instances as i64).bind(a.storage_bytes).bind(a.transfer_bytes).fetch_one(&mut **tx).await?;
        if !allowed {
            return Err(Error::new(
                StatusCode::CONFLICT,
                "allowance is below current usage or reservations",
            ));
        }
        let row = sqlx::query_scalar::<_, Value>(&format!("UPDATE tenants AS t SET cpu_percent=$2,memory_mib=$3,storage_bytes=$4,instances=$5,transfer_bytes=$6 WHERE id=$1 RETURNING {WORKSPACE}"))
            .bind(tenant).bind(a.cpu_percent).bind(a.memory_mib).bind(a.storage_bytes).bind(a.instances).bind(a.transfer_bytes).fetch_optional(&mut **tx).await?.ok_or_else(Error::missing)?;
        Ok(row)
    }
    /// Every project of a workspace that a credential may see.
    pub async fn projects(&self, p: &Principal, tenant: &str) -> Result<Value> {
        Ok(self.project_page(p, tenant, ListPage::whole()).await?["items"].take())
    }
    pub async fn project_page(&self, p: &Principal, tenant: &str, page: ListPage) -> Result<Value> {
        p.scope(tenant, p.project_id.as_deref(), false, false)?;
        let (before, limit) = page.bounds(1000)?;
        let mut tx = self.transaction(false, false).await?;
        Self::live_principal(&mut tx, p).await?;
        let rows = sqlx::query_scalar::<_, Value>(&format!("SELECT {PROJECT} FROM projects p WHERE p.tenant_id=$1 AND ($2::text IS NULL OR p.id=$2) AND ($3::text IS NULL OR (p.created,p.id)<(SELECT c.created,c.id FROM projects c WHERE c.id=$3)) ORDER BY p.created DESC,p.id DESC LIMIT $4"))
            .bind(tenant).bind(&p.project_id).bind(before).bind(limit + 1).fetch_all(&mut *tx).await?;
        Ok(ListPage::page(rows, limit))
    }
    pub async fn create_project(&self, p: &Principal, tenant: &str, value: Named) -> Result<Value> {
        self.create_project_keyed(p, tenant, value, None).await
    }
    pub async fn create_project_keyed(
        &self,
        p: &Principal,
        tenant: &str,
        value: Named,
        key: Option<&str>,
    ) -> Result<Value> {
        p.scope(tenant, None, true, false)?;
        let request = json!({"kind":"project.create","name":value.name});
        let (display_name, slug) = crate::workspaces::project_name(&value.name)?;
        let mut tx = self.transaction(true, false).await?;
        Self::live_principal(&mut tx, p).await?;
        if let Some(key) = key
            && let Some(row) = crate::customer_api::receipt(&mut tx, tenant, key, &request).await?
        {
            return Ok(row);
        }
        Self::metadata_limit(&mut tx, tenant, "projects", MAX_PROJECTS).await?;
        let id = uid();
        let row = sqlx::query_scalar::<_, Value>(
            &format!("INSERT INTO projects AS p (id,tenant_id,name,display_name,slug) VALUES ($1,$2,$3,$4,$3) RETURNING {PROJECT}"),
        )
        .bind(&id)
        .bind(tenant)
        .bind(slug)
        .bind(display_name)
        .fetch_one(&mut *tx)
        .await?;
        Self::audit(&mut tx, p, "project.create", &id, tenant, json!({})).await?;
        if let Some(key) = key {
            crate::customer_api::save_receipt(&mut tx, tenant, key, &request, &row).await?;
        }

        tx.commit().await?;
        Ok(row)
    }
    pub async fn revoke_credential(
        &self,
        p: &Principal,
        tenant: &str,
        credential: &str,
    ) -> Result<Value> {
        p.scope(tenant, None, false, true)?;
        identity(credential)?;
        let mut tx = self.transaction(true, false).await?;
        Self::live_principal(&mut tx, p).await?;
        let row = Self::revoke_credential_in_tx(&mut tx, tenant, credential).await?;
        Self::audit(
            &mut tx,
            p,
            "credential.revoke",
            credential,
            tenant,
            json!({}),
        )
        .await?;
        tx.commit().await?;
        Ok(row)
    }
    pub(crate) async fn revoke_credential_in_tx(
        tx: &mut Tx,
        tenant: &str,
        credential: &str,
    ) -> Result<Value> {
        let row = sqlx::query_scalar::<_, Value>("UPDATE credentials SET revoked=true WHERE tenant_id=$1 AND id=$2 RETURNING jsonb_build_object('id',id)")
            .bind(tenant).bind(credential).fetch_optional(&mut **tx).await?.ok_or_else(Error::missing)?;
        Ok(row)
    }
    #[doc(hidden)]
    /// Refuses another row of `table` for `tenant` once it has `limit`.
    ///
    /// None of these rows is charged to an allowance, and some are never
    /// deleted: without a bound, one workspace could fill the database that
    /// every workspace shares.
    pub(crate) async fn metadata_limit(
        tx: &mut Tx,
        tenant: &str,
        table: &str,
        limit: i64,
    ) -> Result<()> {
        let counted = match table {
            "secrets" | "projects" | "apps" => format!("SELECT count(*) FROM {table} WHERE tenant_id=$1"),
            // Those that still open anything.
            "credentials" => "SELECT count(*) FROM credentials WHERE tenant_id=$1 AND NOT revoked AND expires>now()".to_owned(),
            _ => return Err(Error::internal()),
        };
        let count: i64 = sqlx::query_scalar(&counted)
            .bind(tenant)
            .fetch_one(&mut **tx)
            .await?;
        if count >= limit {
            return Err(crate::db::quota("workspace metadata limit exhausted"));
        }
        Ok(())
    }
    pub async fn upload(
        &self,
        p: &Principal,
        tenant: &str,
        project: &str,
        data: &[u8],
    ) -> Result<Value> {
        p.scope(tenant, Some(project), true, false)?;
        if !(8..=MAX_UPLOAD).contains(&data.len()) || &data[..8] != b"\0asm\x0d\0\x01\0" {
            return Err(Error::invalid("expected a WASI component, maximum 16 MiB"));
        }
        let digest = digest(data);
        let mut tx = self.transaction(true, false).await?;
        Self::project(&mut tx, p, tenant, project, true).await?;
        let existing = sqlx::query_scalar::<_, Value>("SELECT to_jsonb(a) FROM artifacts a WHERE tenant_id=$1 AND project_id=$2 AND digest=$3")
            .bind(tenant).bind(project).bind(&digest).fetch_optional(&mut *tx).await?;
        if let Some(row) = &existing
            && row["retired_at"].is_null()
        {
            let row = sqlx::query_scalar::<_, Value>(&format!(
                "UPDATE artifacts a SET last_uploaded_at=now() WHERE id=$1 RETURNING {ARTIFACT}"
            ))
            .bind(s(&row["id"]))
            .fetch_one(&mut *tx)
            .await?;
            tx.commit().await?;
            return Ok(row);
        }
        let fits: bool = sqlx::query_scalar("SELECT storage_bytes >= $2+(SELECT COALESCE(sum(bytes),0) FROM storage_reservations WHERE tenant_id=$1) FROM tenants WHERE id=$1")
            .bind(tenant).bind(data.len() as i64).fetch_one(&mut *tx).await?;
        if !fits {
            return Err(crate::db::quota("tenant storage allowance exhausted"));
        }
        // Durable bytes precede the metadata commit. Failed transactions can leave an
        // unreferenced blob, but never a database record pointing to incomplete bytes.
        let target = self.state.join("blobs").join(&digest);
        let dir = self.state.join("blobs");
        let content = data.to_vec();
        let (mut tx, written) = guarded_blocking(tx, move || -> Result<()> {
            if target.try_exists()? {
                if crate::model::digest(fs::read(&target)?) != digest {
                    return Err(Error::internal());
                }
                return Ok(());
            }
            let temporary = dir.join(format!(".upload-{}", uid()));
            let result = (|| {
                private_file(&temporary, &content)?;
                fs::rename(&temporary, &target)?;
                fs::File::open(&dir)?.sync_all()?;
                Ok(())
            })();
            if temporary.exists() {
                let _ = fs::remove_file(&temporary);
            }
            result
        })
        .await?;
        written?;
        let id = existing
            .as_ref()
            .map(|v| s(&v["id"]).to_owned())
            .unwrap_or_else(uid);
        let digest = crate::model::digest(data);
        let row = sqlx::query_scalar::<_, Value>(&format!("INSERT INTO artifacts AS a (id,tenant_id,project_id,digest,size) VALUES ($1,$2,$3,$4,$5) ON CONFLICT(id) DO UPDATE SET retired_at=NULL,last_uploaded_at=now() RETURNING {ARTIFACT}"))
            .bind(&id).bind(tenant).bind(project).bind(&digest).bind(data.len() as i64).fetch_one(&mut *tx).await?;
        sqlx::query("INSERT INTO artifact_validations(artifact_id,tenant_id,project_id,runtime) VALUES($1,$2,$3,$4) ON CONFLICT(artifact_id) DO UPDATE SET state='pending',inspection=NULL,error=NULL,node_id=NULL,node_boot=NULL,lease_until=NULL,generation=artifact_validations.generation+1,available_at=now(),updated=now()")
            .bind(&id).bind(tenant).bind(project).bind(crate::artifacts::RUNTIME).execute(&mut *tx).await?;
        Self::audit(
            &mut tx,
            p,
            "artifact.upload",
            &id,
            tenant,
            json!({"digest": digest, "bytes": data.len()}),
        )
        .await?;
        tx.commit().await?;
        Ok(row)
    }
    /// A project's operations, as the API shows one: what was asked, of
    /// what, and how it stands. Not the key or the hash of the request that
    /// asked it, which are the caller's own and nobody else's to read.
    async fn operations(
        &self,
        p: &Principal,
        tenant: &str,
        project: &str,
        id: Option<&str>,
        page: ListPage,
    ) -> Result<Value> {
        if let Some(id) = id {
            identity(id)?;
        }
        let (before, limit) = page.bounds(1000)?;
        let mut tx = self.transaction(false, false).await?;
        Self::project(&mut tx, p, tenant, project, false).await?;
        let mut rows = sqlx::query_scalar::<_, Value>(&format!(
            "SELECT {OPERATION} FROM operations o {OPERATION_RUN} WHERE o.tenant_id=$1 AND o.project_id=$2 AND ($3::text IS NULL OR o.id=$3) AND ($4::text IS NULL OR (o.created,o.id)<(SELECT c.created,c.id FROM operations c WHERE c.id=$4)) ORDER BY o.created DESC,o.id DESC LIMIT $5"
        ))
        .bind(tenant)
        .bind(project)
        .bind(id)
        .bind(before)
        .bind(limit + 1)
        .fetch_all(&mut *tx)
        .await?;
        if id.is_some() {
            rows.pop().ok_or_else(Error::missing)
        } else {
            Ok(ListPage::page(rows, limit))
        }
    }
    /// One thing of a kind a project holds, or all of that kind: for the
    /// control plane's own reads.
    pub async fn resources(
        &self,
        p: &Principal,
        tenant: &str,
        project: &str,
        kind: &str,
        id: Option<&str>,
    ) -> Result<Value> {
        let mut found = self
            .resource_page(p, tenant, project, kind, id, ListPage::whole())
            .await?;
        Ok(if id.is_some() {
            found
        } else {
            found["items"].take()
        })
    }
    /// One thing of a kind a project holds, or a page of that kind.
    pub async fn resource_page(
        &self,
        p: &Principal,
        tenant: &str,
        project: &str,
        kind: &str,
        id: Option<&str>,
        page: ListPage,
    ) -> Result<Value> {
        // Only this exhaustive mapping may introduce an SQL identifier.
        if kind == "external-endpoints" {
            return self
                .external_connections(p, tenant, project, id, page)
                .await;
        }
        if kind == "operations" {
            return self.operations(p, tenant, project, id, page).await;
        }
        let (table, projection) = match kind {
            "artifacts" => ("artifacts", ARTIFACT_OF_R),
            "deployments" => ("deployments", "to_jsonb(r)"),
            "executions" => ("executions", "to_jsonb(r)"),
            "operations" => ("operations", "to_jsonb(r)"),
            "routes" => ("routes", "to_jsonb(r)"),
            "networks" => ("networks", "to_jsonb(r)"),
            "external-endpoints" => ("external_endpoints", "to_jsonb(r)"),
            "grants" => ("network_grants", "to_jsonb(r)"),
            "secrets" => (
                "secrets",
                "jsonb_build_object('id',id,'name',name,'created',created)",
            ),
            _ => return Err(Error::missing()),
        };
        if let Some(id) = id {
            identity(id)?;
        }
        let mut tx = self.transaction(false, false).await?;
        Self::project(&mut tx, p, tenant, project, false).await?;
        let (before, limit) = page.bounds(1000)?;
        let query = format!(
            "SELECT {projection} FROM {table} r WHERE r.tenant_id=$1 AND r.project_id=$2 AND ($3::text IS NULL OR r.id=$3) AND ($4<>'artifacts' OR to_jsonb(r)->>'retired_at' IS NULL) AND {} ORDER BY r.created DESC,r.id DESC LIMIT $6",
            after_cursor(table, 5)
        );
        let mut rows = sqlx::query_scalar::<_, Value>(&query)
            .bind(tenant)
            .bind(project)
            .bind(id)
            .bind(kind)
            .bind(before)
            .bind(limit + 1)
            .fetch_all(&mut *tx)
            .await?;
        if id.is_some() {
            rows.pop().ok_or_else(Error::missing)
        } else {
            Ok(ListPage::page(rows, limit))
        }
    }
}

#[cfg(test)]
mod purpose_cipher_tests {
    use super::purpose_cipher;

    #[test]
    fn a_purposes_cipher_opens_nothing_of_anothers_or_of_the_keys_own() {
        let key = fernet::Fernet::generate_key();
        let own = fernet::Fernet::new(&key).unwrap();
        let channel = purpose_cipher(&key, "run-channel").unwrap();
        let other = purpose_cipher(&key, "something-else").unwrap();
        let sealed = channel.encrypt(b"credential");
        assert_eq!(channel.decrypt(&sealed).unwrap(), b"credential");
        // The same purpose under the same key is the same cipher.
        assert_eq!(
            purpose_cipher(&key, "run-channel")
                .unwrap()
                .decrypt(&sealed)
                .unwrap(),
            b"credential"
        );
        assert!(other.decrypt(&sealed).is_err());
        assert!(own.decrypt(&sealed).is_err());
        assert!(channel.decrypt(&own.encrypt(b"secret")).is_err());
        // Another key's cipher for the purpose opens nothing either.
        let elsewhere = purpose_cipher(&fernet::Fernet::generate_key(), "run-channel").unwrap();
        assert!(elsewhere.decrypt(&sealed).is_err());
        assert!(purpose_cipher("not a key", "run-channel").is_err());
    }
}
#[cfg(test)]
mod guarded_io_tests {
    use super::guarded_blocking;
    use tokio::sync::oneshot;
    #[derive(Debug)]
    struct Guard(Option<oneshot::Sender<()>>);
    impl Drop for Guard {
        fn drop(&mut self) {
            let _ = self.0.take().unwrap().send(());
        }
    }
    #[tokio::test]
    async fn cancellation_keeps_guard_until_blocking_work_has_finished() {
        let (dropped, mut drop_rx) = oneshot::channel();
        let (started, start_rx) = oneshot::channel();
        let (release, release_rx) = std::sync::mpsc::channel();
        let task = tokio::spawn(guarded_blocking(Guard(Some(dropped)), move || {
            started.send(()).unwrap();
            release_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap();
        }));
        start_rx.await.unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        let before = drop_rx.try_recv();
        release.send(()).unwrap();
        assert!(matches!(before, Err(oneshot::error::TryRecvError::Empty)));
        tokio::time::timeout(std::time::Duration::from_secs(5), drop_rx)
            .await
            .unwrap()
            .unwrap();
    }
}
