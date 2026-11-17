//! Operator recovery of a selected candidate that failed before admission resumed.
//! The stopped source's lock, sealed journal and exact failed selection are required.
use super::*;
use rusqlite::params;

#[derive(Parser)]
#[command(
    name = "fenders-node release-recover",
    about = "Select a compatible fallback after a failed candidate start; never starts or resumes"
)]
pub(super) struct Args {
    #[arg(long)]
    pub state: PathBuf,
    #[arg(long)]
    releases: PathBuf,
    #[arg(long)]
    selection: PathBuf,
    #[arg(long)]
    manifest_sha256: String,
    #[arg(long)]
    expected_selection_sha256: String,
    #[arg(long,value_parser=clap::value_parser!(i64).range(1..))]
    maintenance_epoch: i64,
    #[arg(long)]
    maintenance_operation: String,
    #[arg(long)]
    failed_candidate_sha256: String,
    #[arg(long)]
    recovery_operation: String,
}

fn agent_lock(state: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(directory(&state.join("agent"))?.join("agent.lock"))?;
    let m = file.metadata()?;
    if !m.is_file()
        || m.uid() != unsafe { libc::geteuid() }
        || m.nlink() != 1
        || m.mode() & 0o077 != 0
    {
        return Err(invalid());
    }
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(conflict());
    }
    Ok(file)
}

pub(super) fn recover_with(
    args: &Args,
    helper_sha256: &str,
    check: impl FnOnce(&staging::Receipt, &Snapshot) -> Result<Value>,
    publish: impl FnOnce(&Path, &Value) -> Result<()>,
) -> Result<Value> {
    // Use a verified copy of the failed, candidate-fencing binary as the helper.
    // A legacy executable cannot safely stand in for this recovery contract.
    if !hash(&args.manifest_sha256)
        || !hash(&args.expected_selection_sha256)
        || !hash(&args.failed_candidate_sha256)
        || args.failed_candidate_sha256 != helper_sha256
        || identity(&args.maintenance_operation).is_err()
        || identity(&args.recovery_operation).is_err()
        || args.maintenance_operation == args.recovery_operation
        || args.maintenance_epoch < 1
    {
        return Err(invalid());
    }
    let epoch = args.maintenance_epoch.checked_add(1).ok_or_else(invalid)?;
    let state = directory(&args.state)?;
    let store = directory(&args.releases)?;
    let target = staging::retained(&store, &args.manifest_sha256)?;
    target.release.validate_management()?;
    if target.release.agent_sha256 == args.failed_candidate_sha256 {
        return Err(conflict());
    }
    let path = record_path(&args.selection)?;
    let _selection_lock = selection_lock(&path)?;
    let old = read(&path)?.ok_or_else(conflict)?;
    let desired = Selection {
        schema: 1,
        state: state.clone(),
        manifest_sha256: args.manifest_sha256.clone(),
        source_epoch: epoch,
        operation: args.recovery_operation.clone(),
    };
    let value = serde_json::to_value(&desired).map_err(|_| invalid())?;
    let pin = digest(serde_json::to_vec(&value).map_err(|_| invalid())?);
    let receipt = |changed| {
        json!({"schema":1,"selection_sha256":pin,"selected":desired,
        "path":target.path,"changed":changed,"recovery_intent_epoch":epoch,
        "activation_verified":false,"admission_resumed":false})
    };
    let is_recovered = |s: &Snapshot| {
        s.epoch >= epoch
            && s.origin_epoch == Some(epoch)
            && s.operation.as_deref() == Some(&args.recovery_operation)
            && s.candidate_sha256.as_deref() == Some(&target.release.agent_sha256)
    };
    if old.0 == desired {
        // Retry after publication/adoption is read-only, even with a live owner.
        if !is_recovered(&crate::upgrade::management(&state)?) {
            return Err(conflict());
        }
        return Ok(receipt(false));
    }
    if old.1 != args.expected_selection_sha256
        || old.0.state != state
        || old.0.operation != args.maintenance_operation
    {
        return Err(conflict());
    }
    let _agent_lock = agent_lock(&state)?;
    let previous = crate::upgrade::management(&state)?;
    if previous.mode != Mode::Sealed
        || previous.owner_boot != crate::core::boot_id()?
        || crate::core::process_identity(previous.owner_pid)?.is_some()
    {
        return Err(conflict());
    }
    let retry = is_recovered(&previous) && previous.epoch == epoch;
    if !retry
        && (previous.epoch != args.maintenance_epoch
            || previous.operation.as_deref() != Some(&args.maintenance_operation)
            || previous.candidate_sha256.as_deref() != Some(&args.failed_candidate_sha256)
            || previous.origin_epoch != Some(old.0.source_epoch))
    {
        return Err(conflict());
    }
    // The fallback may differ from the failed candidate; unbound preflight is
    // permitted only here, while exclusive ownership and sealed admission hold.
    let report = check(&target, &previous)?;
    validate_report(&report, &target, &previous, true)?;
    staging::retained(&store, &args.manifest_sha256)?;
    let mut db = Connection::open_with_flags(
        state.join("agent/agent.sqlite3"),
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|_| invalid())?;
    db.busy_timeout(Duration::from_millis(250))
        .map_err(|_| invalid())?;
    db.execute_batch("PRAGMA synchronous=FULL")
        .map_err(|_| invalid())?;
    let tx = db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| conflict())?;
    if maintenance::read(&tx)? != previous || read(&path)?.as_ref() != Some(&old) {
        return Err(conflict());
    }
    if !retry {
        tx.execute("UPDATE agent_management SET epoch=?,operation=?,candidate_sha256=?,origin_epoch=? WHERE singleton=1",
            params![epoch,args.recovery_operation,target.release.agent_sha256,epoch]).map_err(|_| invalid())?;
    }
    // Publish intent first: new candidates refuse a stale pointer at adoption,
    // and service-run refuses it before exec. A retry finishes only this intent.
    tx.commit().map_err(|_| invalid())?;
    publish(&path, &value)?;
    Ok(receipt(true))
}

#[cfg(all(test, target_os = "linux"))]
mod tests;
