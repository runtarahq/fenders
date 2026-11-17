//! Durable JSON receipts shared by the WASM node and its worker.
use fenders_node_protocol::{
    error::{Error, Result},
    model::uid,
};
use serde_json::Value;
use std::path::Path;

/// Syncs `file` to the disk.
pub fn sync_file(file: &std::fs::File) -> std::io::Result<()> {
    file.sync_all()
}

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
        sync_file(&file)?;
        std::fs::rename(&temporary, path)?;
        sync_file(&std::fs::File::open(parent)?)?;
        Ok(())
    })();
    if temporary.exists() {
        let _ = std::fs::remove_file(temporary);
    }
    result
}

/// Makes everything written to the filesystem holding `path` durable: one
/// journal commit for whatever was written since, where syncing each file and
/// directory commits once apiece.
pub fn sync_filesystem(path: &Path) -> Result<()> {
    let file = std::fs::File::open(path)?;
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        if unsafe { libc::syncfs(file.as_raw_fd()) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    // Elsewhere (development hosts) every filesystem, which is no weaker.
    #[cfg(not(target_os = "linux"))]
    {
        drop(file);
        unsafe { libc::sync() };
    }
    Ok(())
}

/// Writes the JSON files `files` into the directory `dir` it has just
/// created: all are written and their bytes made durable, then all are renamed
/// into place and the names made durable, so the directory's own entry is as
/// durable as what is in it. Two filesystem syncs however many files, where
/// syncing each file, `dir` and its parent took four for a new run's two.
pub fn new_dir_json(dir: &Path, files: &[(&str, &Value)]) -> Result<()> {
    new_dir_json_with(dir, files, true)
}

/// [`new_dir_json`], without the filesystem syncs when not `durable`: for
/// an ephemeral run, whose directory an OS crash may lose with its VM.
pub fn new_dir_json_with(dir: &Path, files: &[(&str, &Value)], durable: bool) -> Result<()> {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    let parent = dir.parent().ok_or_else(Error::internal)?;
    let staged: Vec<_> = files
        .iter()
        .map(|(name, _)| (dir.join(format!(".write-{}", uid())), dir.join(name)))
        .collect();
    let result = (|| {
        for ((temporary, _), (_, value)) in staged.iter().zip(files) {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(temporary)?;
            file.write_all(&serde_json::to_vec(value).map_err(|_| Error::internal())?)?;
        }
        // Every file's bytes before any name, so a name never outlives them.
        if durable {
            sync_filesystem(parent)?;
        }
        for (temporary, path) in &staged {
            std::fs::rename(temporary, path)?;
        }
        if durable {
            sync_filesystem(parent)?;
        }
        Ok(())
    })();
    for (temporary, _) in staged {
        if temporary.exists() {
            let _ = std::fs::remove_file(temporary);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_directorys_files_are_written_together() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("run");
        std::fs::create_dir(&dir).unwrap();
        let (config, status) = (
            serde_json::json!({"id": "r"}),
            serde_json::json!({"state": "pending"}),
        );
        new_dir_json(&dir, &[("config.json", &config), ("status.json", &status)]).unwrap();
        let read = |name: &str| -> Value {
            serde_json::from_slice(&std::fs::read(dir.join(name)).unwrap()).unwrap()
        };
        assert_eq!(
            (read("config.json"), read("status.json")),
            (config.clone(), status)
        );
        let names: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(names.len(), 2, "no staged file is left: {names:?}");
        assert!(new_dir_json(&root.path().join("absent"), &[("a.json", &config)]).is_err());
    }

    #[test]
    fn an_unsynced_directory_is_written_just_as_whole() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("run");
        std::fs::create_dir(&dir).unwrap();
        let config = serde_json::json!({"id": "r", "spec": {"durability": "ephemeral"}});
        new_dir_json_with(&dir, &[("config.json", &config)], false).unwrap();
        let read: Value =
            serde_json::from_slice(&std::fs::read(dir.join("config.json")).unwrap()).unwrap();
        assert_eq!(read, config);
        assert_eq!(
            std::fs::read_dir(&dir).unwrap().count(),
            1,
            "no staged file is left"
        );
    }
}
