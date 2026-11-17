//! Per-function compile cache. A component nested unchanged in many others
//! (a shared library composed into each app) compiles once per cache scope:
//! Cranelift looks each function up by a key derived from its contents.
//!
//! The compiler only reads the scope's entries and appends what it compiled
//! to a bounded record file; the node, not the compiler, writes the store.
//! So a compiler never alters another compile's entries, and a scope's
//! entries come only from compiles in that scope.
//!
//! The record format and store layout are the node's too
//! (`fenders-node`'s `compile_cache`): keep the two in step.
use std::borrow::Cow;
use std::fs::File;
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

/// The longest key the store accepts.
pub const MAX_KEY: usize = 256;
/// The largest entry the store accepts.
pub const MAX_VALUE: usize = 64 * 1024 * 1024;
/// What one compile appends to its record file, under the compiler's
/// 128 MiB file-size limit; entries past it are not recorded.
pub const MAX_RECORDS: u64 = 120 * 1024 * 1024;

/// An entry's path in a store: `<store>/<first byte>/<key>`, in hex.
pub fn entry_path(store: &Path, key: &[u8]) -> Option<PathBuf> {
    if key.is_empty() || key.len() > MAX_KEY {
        return None;
    }
    let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
    Some(store.join(&hex[..2]).join(hex))
}

/// One compile's view of a scope: its store, read-only, and the record file
/// the node merges into it afterwards.
pub struct Cache {
    store: PathBuf,
    records: Mutex<Option<(BufWriter<File>, u64)>>,
    hits: AtomicUsize,
    misses: AtomicUsize,
}

impl Cache {
    pub fn new(store: PathBuf, records: File) -> Self {
        Self {
            store,
            records: Mutex::new(Some((BufWriter::new(records), 0))),
            hits: AtomicUsize::new(0),
            misses: AtomicUsize::new(0),
        }
    }
    /// Flushes the record file. An error drops the records, never the compile.
    pub fn finish(&self) {
        if let Ok(mut records) = self.records.lock()
            && let Some((mut file, _)) = records.take()
        {
            let _ = file.flush();
        }
    }
    /// Functions found in the store, and functions looked up and not found.
    pub fn counts(&self) -> (usize, usize) {
        (
            self.hits.load(Ordering::Relaxed),
            self.misses.load(Ordering::Relaxed),
        )
    }
}

impl std::fmt::Debug for Cache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cache").field("store", &self.store).finish()
    }
}

impl wasmtime::CacheStore for Cache {
    fn get(&self, key: &[u8]) -> Option<Cow<'_, [u8]>> {
        let found = entry_path(&self.store, key).and_then(|path| {
            let file = File::open(path).ok()?;
            let mut value = Vec::new();
            file.take(MAX_VALUE as u64 + 1)
                .read_to_end(&mut value)
                .ok()?;
            (value.len() <= MAX_VALUE).then_some(value)
        });
        let counter = if found.is_some() {
            &self.hits
        } else {
            &self.misses
        };
        counter.fetch_add(1, Ordering::Relaxed);
        found.map(Cow::Owned)
    }
    fn insert(&self, key: &[u8], value: Vec<u8>) -> bool {
        if key.is_empty() || key.len() > MAX_KEY || value.len() > MAX_VALUE {
            return false;
        }
        let Ok(mut records) = self.records.lock() else {
            return false;
        };
        let Some((file, written)) = records.as_mut() else {
            return false;
        };
        let size = 8 + (key.len() + value.len()) as u64;
        if *written + size > MAX_RECORDS {
            return false;
        }
        let ok = file
            .write_all(&(key.len() as u32).to_le_bytes())
            .and_then(|_| file.write_all(key))
            .and_then(|_| file.write_all(&(value.len() as u32).to_le_bytes()))
            .and_then(|_| file.write_all(&value))
            .is_ok();
        if ok {
            *written += size;
        } else {
            // A partial record makes the file malformed; the node drops it.
            *records = None;
        }
        ok
    }
}
