//! Durable acceptance receipts; no provider dependency.
use fenders_control_plane::{
    error::{Error, Result},
    model::uid,
};
use serde_json::Value;
use std::path::Path;
pub fn atomic_json(path: &Path, value: &Value) -> Result<()> {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    let parent = path.parent().ok_or_else(Error::internal)?;
    let temporary = parent.join(format!(".write-{}", uid()));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(&serde_json::to_vec(value).map_err(|_| Error::internal())?)?;
        file.sync_all()?;
        std::fs::rename(&temporary, path)?;
        std::fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if temporary.exists() {
        let _ = std::fs::remove_file(temporary);
    }
    result
}
