//! Reclaim upload bytes that never acquired metadata. The local directory cursor
//! is only an optimization: restarting or rescanning cannot change eligibility.
use crate::{
    error::{Error, Result},
    store::{Store, guarded_blocking},
};
use std::{
    fs::{self, ReadDir},
    path::Path,
    time::{Duration, Instant, SystemTime},
};

const GRACE: Duration = Duration::from_secs(24 * 60 * 60);
const RESCAN: Duration = Duration::from_secs(60);
const ENTRIES: usize = 128;
const CANDIDATES: usize = 16;

#[derive(Default)]
pub(crate) struct Scan {
    directory: Option<ReadDir>,
    next: Option<Instant>,
}

fn lower_hex(name: &str, len: usize) -> bool {
    name.len() == len
        && name
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn recognized(name: &str) -> bool {
    lower_hex(name, 64)
        || name
            .strip_prefix(".upload-")
            .is_some_and(|id| lower_hex(id, 32))
}
fn old_regular_file(path: &Path, now: SystemTime) -> std::io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(meta) => Ok(meta.file_type().is_file()
            && now
                .duration_since(meta.modified()?)
                .is_ok_and(|age| age >= GRACE)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}
impl Scan {
    fn batch(
        &mut self,
        root: &Path,
        clock: Instant,
        now: SystemTime,
    ) -> std::io::Result<Vec<String>> {
        if self.next.is_some_and(|next| clock < next) {
            return Ok(Vec::new());
        }
        let result = (|| {
            if self.directory.is_none() {
                self.directory = Some(fs::read_dir(root)?);
            }
            let mut result = Vec::new();
            for _ in 0..ENTRIES {
                let Some(entry) = self.directory.as_mut().expect("opened directory").next() else {
                    self.directory = None;
                    self.next = Some(clock + RESCAN);
                    break;
                };
                let entry = entry?;
                let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                    continue;
                };
                if recognized(&name) && old_regular_file(&entry.path(), now)? {
                    result.push(name);
                    if result.len() == CANDIDATES {
                        break;
                    }
                }
            }
            Ok(result)
        })();
        if result.is_err() {
            self.directory = None;
            self.next = Some(clock + RESCAN);
        }
        result
    }
}

impl Store {
    pub(crate) async fn reclaim_orphan_uploads(&self) -> Result<()> {
        // The lock covers discovery, reference checks and unlink. In-flight upload
        // writes and backup reads hold this same lock, including before DB commit.
        let mut tx = self.transaction(true, false).await?;
        let scan = self.orphan_upload_scan.clone();
        let root = self.state.join("blobs");
        let candidates = tokio::task::spawn_blocking(move || {
            scan.lock()
                .map_err(|_| Error::internal())?
                .batch(&root, Instant::now(), SystemTime::now())
                .map_err(Error::from)
        })
        .await
        .map_err(|_| Error::internal())??;
        if candidates.is_empty() {
            tx.commit().await?;
            return Ok(());
        }
        let referenced: Vec<String> =
            sqlx::query_scalar("SELECT DISTINCT digest FROM artifacts WHERE digest=ANY($1)")
                .bind(&candidates)
                .fetch_all(&mut *tx)
                .await?;
        let root = self.state.join("blobs");
        let (tx, failed) = guarded_blocking(tx, move || {
            let mut failed = false;
            for name in candidates {
                if referenced.contains(&name) {
                    continue;
                }
                let path = root.join(name);
                // Refuse leaf symlinks and recheck age even after discovery.
                match old_regular_file(&path, SystemTime::now()) {
                    Ok(true) => {
                        if fs::remove_file(&path).is_err() {
                            failed = true;
                        }
                    }
                    Ok(false) => (),
                    Err(_) => failed = true,
                }
            }
            if fs::File::open(root).and_then(|dir| dir.sync_all()).is_err() {
                failed = true;
            }
            failed
        })
        .await?;
        tx.commit().await?;
        // Cursor progress survives filesystem failure; other candidates can be
        // examined next pass. Failed files return on the next full sweep.
        if failed {
            return Err(Error::internal());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn directory_work_is_bounded_even_without_candidates_and_errors_back_off() {
        let root = tempfile::tempdir().unwrap();
        for i in 0..300 {
            fs::write(root.path().join(format!("unrecognized-{i}")), b"keep").unwrap();
        }
        let clock = Instant::now();
        let now = SystemTime::now();
        let mut scan = Scan::default();
        assert!(scan.batch(root.path(), clock, now).unwrap().is_empty());
        assert_eq!(scan.directory.take().unwrap().count(), 300 - ENTRIES);
        let missing = root.path().join("missing");
        let mut scan = Scan::default();
        assert!(scan.batch(&missing, clock, now).is_err());
        fs::create_dir(&missing).unwrap();
        let name = "d".repeat(64);
        fs::write(missing.join(&name), b"orphan").unwrap();
        assert!(
            scan.batch(&missing, clock, now + GRACE + RESCAN)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            scan.batch(&missing, clock + RESCAN, now + GRACE + RESCAN)
                .unwrap(),
            vec![name]
        );
    }
    #[test]
    fn scanner_bounds_work_and_rescans_after_grace_or_restart() {
        let root = tempfile::tempdir().unwrap();
        let now = SystemTime::now();
        let clock = Instant::now();
        for i in 0..40 {
            fs::write(root.path().join(format!("{i:064x}")), b"orphan").unwrap();
        }
        let mut scan = Scan::default();
        assert!(scan.batch(root.path(), clock, now).unwrap().is_empty());
        assert!(
            scan.batch(
                root.path(),
                clock + Duration::from_secs(1),
                now + GRACE + RESCAN
            )
            .unwrap()
            .is_empty()
        );
        let later = clock + RESCAN;
        let wall = now + GRACE + RESCAN;
        let mut names = Vec::new();
        for _ in 0..3 {
            let batch = scan.batch(root.path(), later, wall).unwrap();
            assert!(batch.len() <= CANDIDATES);
            names.extend(batch);
        }
        names.sort();
        names.dedup();
        assert_eq!(names.len(), 40);
        assert!(scan.batch(root.path(), later, wall).unwrap().is_empty());
        assert_eq!(
            Scan::default()
                .batch(root.path(), later, wall)
                .unwrap()
                .len(),
            CANDIDATES
        );
    }
    #[test]
    fn scanner_never_follows_links_or_accepts_arbitrary_names() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        let link = root.path().join("a".repeat(64));
        std::os::unix::fs::symlink(outside.path(), &link).unwrap();
        fs::create_dir(root.path().join("b".repeat(64))).unwrap();
        fs::write(root.path().join("README"), b"keep").unwrap();
        fs::write(root.path().join(".upload-not-an-id"), b"keep").unwrap();
        let temp = format!(".upload-{}", "c".repeat(32));
        fs::write(root.path().join(&temp), b"partial").unwrap();
        assert_eq!(
            Scan::default()
                .batch(
                    root.path(),
                    Instant::now(),
                    SystemTime::now() + GRACE + RESCAN
                )
                .unwrap(),
            vec![temp]
        );
        assert!(outside.path().exists());
    }
}
