//! Metadata retirement commits before physical deletion. Shared digests and
//! backup/upload operations are protected by the existing admission lock.
use crate::{
    args,
    db::*,
    error::{Error, Result},
    store::{Store, Tx, guarded_blocking},
};
impl Store {
    pub(crate) async fn expire_artifacts(tx: &mut Tx) -> Result<()> {
        exec(tx, include_str!("artifact_retention.sql"), args![]).await?;
        Ok(())
    }
    pub(crate) async fn reclaim_artifact_blobs(&self) -> Result<()> {
        let mut tx = self.transaction(true, false).await?;
        let candidates=rows(&mut tx,"SELECT digest FROM artifact_blob_garbage WHERE next_attempt<=now() ORDER BY next_attempt,digest LIMIT 16 FOR UPDATE",args![]).await?;
        for entry in candidates {
            let digest = s(&entry["digest"]);
            let active=one(&mut tx,"SELECT EXISTS(SELECT 1 FROM artifacts WHERE digest=$1 AND retired_at IS NULL) present",args![digest]).await?;
            if !b(&active["present"]) {
                let file = self.state.join("blobs").join(digest);
                let (held, removed) = guarded_blocking(tx, move || -> Result<()> {
                    match std::fs::symlink_metadata(&file) {
                        Ok(meta) if meta.file_type().is_file() => std::fs::remove_file(&file)?,
                        Ok(_) => return Err(Error::invalid("unexpected artifact blob type")),
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(e) => return Err(e.into()),
                    }
                    std::fs::File::open(file.parent().ok_or_else(Error::internal)?)?.sync_all()?;
                    Ok(())
                })
                .await?;
                tx = held;
                if removed.is_err() {
                    exec(&mut tx,"UPDATE artifact_blob_garbage SET next_attempt=now()+interval '1 minute',error='blob-cleanup-unavailable' WHERE digest=$1",args![digest]).await?;
                    continue;
                }
            }
            exec(
                &mut tx,
                "DELETE FROM artifact_blob_garbage WHERE digest=$1",
                args![digest],
            )
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }
}
