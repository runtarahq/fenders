//! Durable owner-only files for key material and tokens.
use crate::error::{Error, Result};
use std::{io::Write, os::unix::fs::OpenOptionsExt, path::Path};
pub fn private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    std::fs::File::open(path.parent().ok_or_else(Error::internal)?)?.sync_all()?;
    Ok(())
}
