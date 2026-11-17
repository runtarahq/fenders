//! Admission headroom, not an OS disk reservation or permission to delete logs.
//! Call under Node::admission. Always account for one compiler, so compilation
//! can release the admission lock without racing a new execution's budget.
use super::*;
use std::os::unix::ffi::OsStrExt;

const MIB: u64 = 1024 * 1024;
pub(super) const DEFAULT_FREE_BYTES: u64 = 256 * MIB;
// Two writable compiler outputs each have a 128 MiB RLIMIT_FSIZE, plus the
// maximum input and publication metadata. Do not trust inspection's JSON limit
// as a physical bound on a compromised compiler's output file.
const COMPILER_BYTES: u64 = 2 * 128 * MIB + MAX_UPLOAD as u64 + MIB;
// Raw tail, SQLite records/pages/rollback journal, cleanup VACUUM and metadata.
// Conservatively keep the whole allowance even when some is already allocated.
const CAPTURE_BYTES: u64 = 16 * MIB;
const FREE_FILES: u64 = 1024;

#[derive(Clone, Copy)]
struct Space {
    bytes: u64,
    files: Option<u64>,
}
#[allow(clippy::unnecessary_cast)] // libc counter widths differ across Unix targets.
fn available(path: &Path) -> Result<Space> {
    let path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| Error::invalid("invalid node state path"))?;
    let mut out = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // statvfs initializes the entire output only on success. Use user-available
    // blocks, never blocks reserved for root, even when the node runs as root.
    if unsafe { libc::statvfs(path.as_ptr(), out.as_mut_ptr()) } != 0 {
        return Err(Error::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "node disk capacity unavailable",
        ));
    }
    let out = unsafe { out.assume_init() };
    let bytes = (out.f_bavail as u128)
        .checked_mul(out.f_frsize as u128)
        .and_then(|n| u64::try_from(n).ok())
        .filter(|_| out.f_frsize > 0)
        .ok_or_else(Error::internal)?;
    Ok(Space {
        bytes,
        files: (out.f_files != 0).then_some(out.f_favail as u64),
    })
}
fn directory(path: &Path) -> Result<()> {
    if !fs::symlink_metadata(path)?.is_dir() {
        return Err(Error::invalid(
            "node disk inventory requires real directories",
        ));
    }
    Ok(())
}
// With a compile cache, a compile also writes two record files, each under
// the same 128 MiB limit, and the node then stores at most a bounded share of
// their entries, each a file of its own.
const CACHE_BYTES: u64 = 2 * 128 * MIB + super::compile_cache::MERGE_BYTES;
const CACHE_FILES: u64 = super::compile_cache::MERGE_ENTRIES as u64 + 512;
#[cfg(test)]
fn fits(space: Space, floor: u64, writers: u64) -> bool {
    fits_compiling(space, floor, writers, false)
}
fn fits_compiling(space: Space, floor: u64, writers: u64, cached: bool) -> bool {
    let (cache_bytes, cache_files) = if cached {
        (CACHE_BYTES, CACHE_FILES)
    } else {
        (0, 0)
    };
    let bytes = writers
        .checked_mul(CAPTURE_BYTES)
        .and_then(|n| n.checked_add(COMPILER_BYTES))
        .and_then(|n| n.checked_add(cache_bytes))
        .and_then(|n| n.checked_add(floor));
    let files = writers
        .checked_mul(16)
        .and_then(|n| n.checked_add(FREE_FILES))
        .and_then(|n| n.checked_add(cache_files));
    bytes.is_some_and(|n| space.bytes >= n)
        && files.is_some_and(|n| space.files.is_none_or(|available| available >= n))
}
impl Node {
    pub fn with_state_quota(mut self, quota: crate::project_quota::ProjectQuota) -> Result<Self> {
        if !quota.contains(&self.state)? {
            return Err(Error::invalid(
                "node state is outside the configured quota tree",
            ));
        }
        quota.remaining()?;
        for status in self.list()? {
            for field in ["worker_pid", "vmm_pid"] {
                if status[field].is_null() {
                    continue;
                }
                let pid = status[field]
                    .as_i64()
                    .filter(|p| *p > 0)
                    .ok_or_else(|| Error::invalid("existing producer identity is unavailable"))?;
                if process_identity(pid)?.is_some() {
                    crate::project_quota::verify_producer_capabilities(pid)?;
                }
            }
        }
        self.state_quota = Some(quota);
        Ok(self)
    }
    pub fn with_disk_free_mib(mut self, mib: u64) -> Result<Self> {
        if !(64..=1_048_576).contains(&mib) {
            return Err(Error::invalid("disk free headroom must be 64–1048576 MiB"));
        }
        self.disk_free_bytes = mib * MIB;
        Ok(self)
    }
    /// Headroom plus any upload cap above the default the compiler budget assumes.
    fn disk_floor(&self) -> u64 {
        self.disk_free_bytes + self.max_upload.saturating_sub(MAX_UPLOAD) as u64
    }
    pub(super) fn check_disk_capacity(&self, new_runs: u64) -> Result<()> {
        // A compile's cache records and their entries may be written while
        // anything else is.
        let cached = self.compile_cache_bytes > 0;
        // A run writes nothing to the node's disk: only compiles count.
        let counted = 0u64;
        let writers = counted.checked_add(new_runs).ok_or_else(Error::internal)?;
        if let Some(quota) = &self.state_quota {
            let left = quota.remaining().map_err(|_| {
                Error::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "node project quota verification unavailable",
                )
            })?;
            if !fits_compiling(
                Space {
                    bytes: left.bytes,
                    files: Some(left.inodes),
                },
                self.disk_floor(),
                writers,
                cached,
            ) {
                return Err(Error::new(
                    StatusCode::INSUFFICIENT_STORAGE,
                    "node project quota headroom exhausted",
                ));
            }
        }
        // Check each writable filesystem, including an independently mounted
        // artifact namespace. Do not assume free space on / also covers state.
        let mut paths = vec![self.state.clone(), self.state.join("artifacts")];
        let namespace = self.state.join("artifacts").join(&self.compiler_id);
        if namespace.try_exists()? {
            paths.push(namespace);
        }
        for path in paths {
            directory(&path)?;
            if !fits_compiling(available(&path)?, self.disk_floor(), writers, cached) {
                return Err(Error::new(
                    StatusCode::INSUFFICIENT_STORAGE,
                    "node disk headroom exhausted",
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn node(root: &Path) -> Node {
        private_dir(&root.join("artifacts")).unwrap();
        Node::for_tests(root)
    }
    #[test]
    fn a_compile_cache_reserves_its_record_files_and_entries() {
        let needed = DEFAULT_FREE_BYTES + COMPILER_BYTES + CACHE_BYTES;
        let space = Space {
            bytes: needed,
            files: Some(FREE_FILES + CACHE_FILES),
        };
        assert!(fits_compiling(space, DEFAULT_FREE_BYTES, 0, true));
        assert!(!fits_compiling(
            Space {
                bytes: needed - 1,
                ..space
            },
            DEFAULT_FREE_BYTES,
            0,
            true
        ));
        assert!(!fits_compiling(
            Space {
                files: Some(FREE_FILES + CACHE_FILES - 1),
                ..space
            },
            DEFAULT_FREE_BYTES,
            0,
            true
        ));
        // Without a cache, the plain reservation stands.
        assert!(fits_compiling(
            Space {
                bytes: needed - CACHE_BYTES,
                files: Some(FREE_FILES)
            },
            DEFAULT_FREE_BYTES,
            0,
            false
        ));
    }
    #[test]
    fn budgets_include_both_compiler_outputs_capture_growth_and_inodes() {
        let needed = DEFAULT_FREE_BYTES + COMPILER_BYTES + 3 * CAPTURE_BYTES;
        let space = Space {
            bytes: needed,
            files: Some(FREE_FILES + 3 * 16),
        };
        assert!(fits(space, DEFAULT_FREE_BYTES, 3));
        assert!(!fits(
            Space {
                bytes: needed - 1,
                ..space
            },
            DEFAULT_FREE_BYTES,
            3
        ));
        assert!(!fits(
            Space {
                files: Some(FREE_FILES + 3 * 16 - 1),
                ..space
            },
            DEFAULT_FREE_BYTES,
            3
        ));
        assert!(!fits(space, DEFAULT_FREE_BYTES, 4));
        assert!(!fits(space, u64::MAX, 0));
        assert!(!fits(space, 0, u64::MAX));
        assert!(fits(
            Space {
                files: None,
                ..space
            },
            DEFAULT_FREE_BYTES,
            3
        ));
        assert!(
            available(tempfile::tempdir().unwrap().path())
                .unwrap()
                .bytes
                > 0
        );
        assert!(available(Path::new("/nonexistent-fenders-disk-check")).is_err());
    }
    #[test]
    fn policy_bounds_and_real_filesystem_check_survive_node_reopen() {
        let root = tempfile::tempdir().unwrap();
        let initial = node(root.path()).with_disk_free_mib(64).unwrap();
        assert_eq!(initial.disk_free_bytes, 64 * MIB);
        initial.check_disk_capacity(1).unwrap();
        drop(initial);
        let mut reopened = node(root.path());
        reopened.disk_free_bytes = u64::MAX;
        assert_eq!(
            reopened.check_disk_capacity(0).unwrap_err().status,
            StatusCode::INSUFFICIENT_STORAGE
        );
        assert!(reopened.with_disk_free_mib(63).is_err());
        let another = tempfile::tempdir().unwrap();
        assert!(node(another.path()).with_disk_free_mib(1_048_577).is_err());
    }
}
