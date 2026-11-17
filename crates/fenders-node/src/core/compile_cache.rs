//! The per-function compile cache: a component nested unchanged in many
//! others compiles once per scope. A scope is the isolation unit the control
//! plane names with each compile (its tenant): a compile reads only its own
//! scope's store, and only compiles in a scope add to it.
//!
//! The compiler gets its store read-only and appends what it compiled to two
//! record files the node created; after a successful compile the node stores
//! those entries. The record format and store layout are the compiler's too
//! (`fenders-component`'s `cache`): keep the two in step.
//!
//! Like compiled artifacts, the store is a reconstructible cache: any error
//! here leaves a compile uncached, never failed.
use super::*;
use std::io::Read;

/// The default store budget; a node sets its own (`--compile-cache-mib`).
pub(super) const BUDGET: u64 = 1024 * 1024 * 1024;
const MAX_SCOPE: usize = 256;
const MAX_KEY: usize = 256;
const MAX_VALUE: usize = 64 * 1024 * 1024;
const MAX_RECORDS: u64 = 120 * 1024 * 1024;
/// The record files of one compile, in its staging directory.
pub(super) const RECORDS: [(&str, &str); 2] = [
    (
        "FENDERS_COMPILE_CACHE_INSPECTION",
        "cache-inspection.records",
    ),
    ("FENDERS_COMPILE_CACHE_CODE", "cache-code.records"),
];
// Bound inventory work, as for compiled artifacts.
const MAX_INVENTORY: usize = 1_000_000;
/// The most entries one compile adds to its store: a large first compile
/// adds about 14,000 across its two passes.
pub(super) const MERGE_ENTRIES: usize = 32_768;
/// The most space one compile's entries take on disk, counting each as the
/// blocks it occupies: an entry of a few bytes still takes a block.
pub(super) const MERGE_BYTES: u64 = 256 * 1024 * 1024;
/// The space a file of `len` bytes takes, in whole blocks.
fn allocated(len: u64) -> u64 {
    const BLOCK: u64 = 4096;
    len.div_ceil(BLOCK).max(1) * BLOCK
}

/// What one compile may still add to its store, across both record files.
pub(super) struct Merge {
    entries: usize,
    bytes: u64,
}
impl Default for Merge {
    fn default() -> Self {
        Self {
            entries: MERGE_ENTRIES,
            bytes: MERGE_BYTES,
        }
    }
}

/// The store of `scope` for this node's compiler, created if missing.
pub(super) fn store(node: &Node, scope: &str) -> Result<PathBuf> {
    if scope.is_empty() || scope.len() > MAX_SCOPE || scope.chars().any(char::is_control) {
        return Err(Error::invalid("invalid compile scope"));
    }
    let store = node
        .state
        .join("compile-cache")
        .join(&node.compiler_id)
        .join(digest(scope));
    private_dir(&store)?;
    // Least recently used scopes are evicted first.
    fs::File::open(&store)?.set_modified(SystemTime::now())?;
    Ok(store)
}

fn entry(store: &Path, key: &[u8]) -> PathBuf {
    let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
    store.join(&hex[..2]).join(hex)
}

/// Stores each whole record in `records` that the store lacks, up to the
/// first that is malformed or cut short, or until `merge` allows no more.
/// Returns how many it stored.
pub(super) fn store_records(store: &Path, records: &Path, merge: &mut Merge) -> Result<usize> {
    fn length(records: &mut impl Read) -> Option<usize> {
        let mut len = [0u8; 4];
        records.read_exact(&mut len).ok()?;
        Some(u32::from_le_bytes(len) as usize)
    }
    fn bytes(records: &mut impl Read, len: usize) -> Option<Vec<u8>> {
        let mut buf = vec![0; len];
        records.read_exact(&mut buf).ok()?;
        Some(buf)
    }
    let mut file = std::io::BufReader::new(fs::File::open(records)?.take(MAX_RECORDS));
    let mut stored = 0;
    while let Some(key) = length(&mut file).filter(|n| (1..=MAX_KEY).contains(n))
        && let Some(key) = bytes(&mut file, key)
        && let Some(value) = length(&mut file).filter(|n| *n <= MAX_VALUE)
        && let Some(value) = bytes(&mut file, value)
    {
        let path = entry(store, &key);
        if fs::symlink_metadata(&path).is_ok() {
            continue;
        }
        let space = allocated(value.len() as u64);
        if merge.entries == 0 || merge.bytes < space {
            break;
        }
        merge.entries -= 1;
        merge.bytes -= space;
        let dir = path.parent().unwrap();
        private_dir(dir)?;
        let staged = dir.join(format!(".{}", uid()));
        let mut out = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&staged)?;
        out.write_all(&value)?;
        fs::rename(&staged, &path)?;
        stored += 1;
    }
    Ok(stored)
}

/// Keeps the cache within its budget, counting the space its files take:
/// removes stores of other compilers, then whole scopes, least recently used
/// first. A store too large to take stock of goes whole: it is only a cache.
pub(super) fn prune(node: &Node) -> Result<()> {
    prune_within(node, MAX_INVENTORY)
}

pub(super) fn prune_within(node: &Node, inventory: usize) -> Result<()> {
    match prune_scopes(node, inventory) {
        Err(error) if error.status == StatusCode::SERVICE_UNAVAILABLE => {
            let store = node.state.join("compile-cache").join(&node.compiler_id);
            if fs::symlink_metadata(&store).is_ok() {
                remove(&store)?;
            }
            Ok(())
        }
        other => other,
    }
}

fn prune_scopes(node: &Node, inventory: usize) -> Result<()> {
    let root = node.state.join("compile-cache");
    if !root.is_dir() {
        return Ok(());
    }
    let mut seen = 0;
    let mut scopes = Vec::new();
    for compiler in fs::read_dir(&root)? {
        let compiler = compiler?;
        if compiler.file_name().to_str() != Some(node.compiler_id.as_str()) {
            remove(&compiler.path())?;
            continue;
        }
        for scope in fs::read_dir(compiler.path())? {
            let scope = scope?;
            let metadata = fs::symlink_metadata(scope.path())?;
            let mut bytes = 0;
            if metadata.is_dir() {
                for shard in fs::read_dir(scope.path())? {
                    let shard = shard?;
                    if !fs::symlink_metadata(shard.path())?.is_dir() {
                        continue;
                    }
                    for file in fs::read_dir(shard.path())? {
                        seen += 1;
                        if seen > inventory {
                            return Err(Error::new(
                                StatusCode::SERVICE_UNAVAILABLE,
                                "compile cache inventory limit exceeded",
                            ));
                        }
                        use std::os::unix::fs::MetadataExt;
                        let metadata = fs::symlink_metadata(file?.path())?;
                        bytes += (metadata.blocks() * 512).max(allocated(metadata.len()));
                    }
                }
            }
            scopes.push((metadata.modified()?, bytes, scope.path()));
        }
    }
    let mut total: u64 = scopes.iter().map(|(_, bytes, _)| bytes).sum();
    scopes.sort();
    for (_, bytes, path) in scopes {
        if total <= node.compile_cache_bytes {
            break;
        }
        remove(&path)?;
        total -= bytes;
    }
    Ok(())
}

fn remove(path: &Path) -> Result<()> {
    if fs::symlink_metadata(path)?.is_dir() {
        fs::remove_dir_all(path)?;
    } else {
        fs::remove_file(path)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn record(key: &[u8], value: &[u8]) -> Vec<u8> {
        let mut out = (key.len() as u32).to_le_bytes().to_vec();
        out.extend(key);
        out.extend((value.len() as u32).to_le_bytes());
        out.extend(value);
        out
    }
    #[test]
    fn whole_records_are_stored_up_to_the_first_cut_short() {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("store");
        let records = dir.path().join("records");
        let mut data = record(&[1; 32], b"one");
        data.extend(record(&[2; 32], b"two"));
        let cut = record(&[3; 32], b"three");
        data.extend(&cut[..cut.len() - 1]);
        fs::write(&records, &data).unwrap();
        assert_eq!(
            store_records(&store, &records, &mut Merge::default()).unwrap(),
            2
        );
        assert_eq!(fs::read(entry(&store, &[1; 32])).unwrap(), b"one");
        assert_eq!(fs::read(entry(&store, &[2; 32])).unwrap(), b"two");
        assert!(!entry(&store, &[3; 32]).exists());
    }
    #[test]
    fn a_stored_entry_is_kept_and_bad_lengths_end_the_records() {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("store");
        let records = dir.path().join("records");
        fs::write(&records, record(&[1; 32], b"first")).unwrap();
        store_records(&store, &records, &mut Merge::default()).unwrap();
        let mut data = record(&[1; 32], b"second");
        data.extend(record(&[0; MAX_KEY + 1], b"long key"));
        data.extend(record(&[4; 32], b"after"));
        fs::write(&records, data).unwrap();
        assert_eq!(
            store_records(&store, &records, &mut Merge::default()).unwrap(),
            0
        );
        assert_eq!(fs::read(entry(&store, &[1; 32])).unwrap(), b"first");
        assert!(!entry(&store, &[4; 32]).exists());
    }
    #[test]
    fn a_compile_adds_no_more_entries_or_space_than_its_merge_allows() {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("store");
        let records = dir.path().join("records");
        let data: Vec<u8> = (0..10u8).flat_map(|i| record(&[i + 1; 32], b"x")).collect();
        fs::write(&records, &data).unwrap();
        // Each tiny entry takes a whole block.
        let mut merge = Merge {
            entries: MERGE_ENTRIES,
            bytes: 3 * 4096,
        };
        assert_eq!(store_records(&store, &records, &mut merge).unwrap(), 3);
        let mut merge = Merge {
            entries: 2,
            bytes: MERGE_BYTES,
        };
        assert_eq!(store_records(&store, &records, &mut merge).unwrap(), 2);
        // What is stored already costs nothing.
        assert_eq!(merge.entries, 0);
        assert_eq!(store_records(&store, &records, &mut merge).unwrap(), 0);
    }
}
