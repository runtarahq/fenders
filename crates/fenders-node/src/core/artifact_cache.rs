//! Local compiled code is a reconstructible cache, never the source of record.
//! Callers serialize compilation, cache access and launch admission in that order.
use super::*;
use std::collections::HashSet;

/// The default compiled-artifact budget; a node sets its own
/// (`--artifact-cache-mib`).
pub(super) const BUDGET: u64 = 512 * 1024 * 1024;
const IDLE: Duration = Duration::from_secs(7 * 24 * 60 * 60);
const PRESSURE_GRACE: Duration = Duration::from_secs(60 * 60);
const PARTIAL_GRACE: Duration = Duration::from_secs(24 * 60 * 60);
const MAX_REMOVE: usize = 8;
// Bound inventory work. Ambiguous/incomplete inventories never authorize deletion.
const MAX_INVENTORY: usize = 100_000;

pub(super) struct Collection {
    pub fits: bool,
    removed: usize,
}

impl Node {
    /// Reconciliation skips cleanup while compilation or admission is busy.
    /// It must not delay VM control waiting for a compiler's 60-second deadline.
    pub fn prune_artifacts(&self) -> Result<()> {
        let Ok(mut checked) = self.cache_check.try_lock() else {
            return Ok(());
        };
        if checked.is_some_and(|at| at.elapsed() < Duration::from_secs(60)) {
            return Ok(());
        }
        let Ok(_compiler) = self.compilation.try_lock() else {
            return Ok(());
        };
        let Ok(_cache) = self.cache_access.try_lock() else {
            return Ok(());
        };
        let Ok(_admission) = self.admission.try_lock() else {
            return Ok(());
        };
        *checked = Some(Instant::now());
        let result = collect(self, 0)?;
        if result.removed > 0 {
            tracing::info!(
                removed = result.removed,
                "removed unused compiled cache entries"
            );
        }
        Ok(())
    }
}

fn regular(path: &Path) -> Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() {
        return Err(Error::invalid("cache inventory requires regular files"));
    }
    Ok(metadata)
}
fn directory(path: &Path) -> Result<()> {
    if !fs::symlink_metadata(path)?.is_dir() {
        return Err(Error::invalid("cache inventory requires real directories"));
    }
    Ok(())
}
fn json(path: &Path) -> Result<Value> {
    if regular(path)?.len() > 128 * 1024 {
        return Err(Error::invalid("cache ownership metadata is oversized"));
    }
    load(path)
}
pub(super) fn touch(path: &Path) -> Result<()> {
    let path = path.join("artifact.json");
    regular(&path)?;
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?
        .set_modified(SystemTime::now())?;
    Ok(())
}
fn hash(name: &str) -> bool {
    name.len() == 64
        && name
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
/// The digest a compiled artifact's directory is named for: its digest, or,
/// compiled with a tenant's compile cache, its digest and that scope's
/// (`Node::scoped_artifact_dir`).
fn artifact_name(name: &str) -> Option<&str> {
    match name.split_once('-') {
        None => hash(name).then_some(name),
        Some((digest, scope)) => (hash(digest) && hash(scope)).then_some(digest),
    }
}
fn count(seen: &mut usize) -> Result<()> {
    *seen += 1;
    if *seen > MAX_INVENTORY {
        return Err(Error::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "cache inventory limit exceeded",
        ));
    }
    Ok(())
}

fn pins(node: &Node, seen: &mut usize) -> Result<HashSet<PathBuf>> {
    // The artifacts of the node's live runs, and of runs being created.
    let mut pins = HashSet::new();
    for artifact in node
        .run_artifacts()?
        .into_iter()
        .chain(node.creating_artifacts()?)
    {
        count(seen)?;
        pins.insert(artifact);
    }
    Ok(pins)
}

pub(super) fn collect(node: &Node, required: u64) -> Result<Collection> {
    collect_at(node, required, SystemTime::now())
}
fn collect_at(node: &Node, required: u64, now: SystemTime) -> Result<Collection> {
    let mut seen = 0;
    let pins = pins(node, &mut seen)?;
    let root = node.state.join("artifacts");
    directory(&root)?;
    // Interrupted compilation is reclaimable only after its cgroup is empty.
    let compiler_empty = fs::read_to_string(node.compiler_cgroup.join("cgroup.events"))
        .is_ok_and(|v| v.lines().any(|line| line == "populated 0"));
    let mut total = 0u64;
    let mut candidates = Vec::new();
    for compiler in fs::read_dir(&root)? {
        count(&mut seen)?;
        let compiler = compiler?;
        directory(&compiler.path())?;
        let compiler_name = compiler.file_name().to_string_lossy().into_owned();
        if !hash(&compiler_name) {
            return Err(Error::invalid("unknown compiler cache directory"));
        }
        for entry in fs::read_dir(compiler.path())? {
            count(&mut seen)?;
            let entry = entry?;
            let path = entry.path();
            directory(&path)?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let staging = name
                .strip_prefix(".compile-")
                .is_some_and(|id| identity(id).is_ok());
            let retired = name
                .strip_prefix(".evicted-")
                .is_some_and(|id| identity(id).is_ok());
            if artifact_name(&name).is_none() && !staging && !retired {
                return Err(Error::invalid("unknown compiled cache directory"));
            }
            let mut bytes = 0u64;
            let mut updated = fs::symlink_metadata(&path)?.modified()?;
            let mut manifest = None;
            for file in fs::read_dir(&path)? {
                count(&mut seen)?;
                let file = file?;
                let metadata = regular(&file.path())?;
                if !matches!(
                    file.file_name().to_str(),
                    Some("input.wasm" | "component.cwasm" | "inspection.json" | "artifact.json")
                ) && !(staging
                    && file.file_name().to_str().is_some_and(|name| {
                        super::compile_cache::RECORDS
                            .iter()
                            .any(|(_, file)| *file == name)
                    }))
                    && !((staging || retired)
                        && file
                            .file_name()
                            .to_str()
                            .and_then(|name| name.strip_prefix(".write-"))
                            .is_some_and(|id| identity(id).is_ok()))
                {
                    return Err(Error::invalid("unknown compiled cache file"));
                }
                bytes = bytes
                    .checked_add(metadata.len())
                    .ok_or_else(Error::internal)?;
                if file.file_name() == "artifact.json" {
                    manifest = Some((json(&file.path())?, metadata.modified()?));
                }
                updated = updated.max(metadata.modified()?);
            }
            total = total.checked_add(bytes).ok_or_else(Error::internal)?;
            let complete = if let Some((value, used)) = manifest {
                if value["compiler"] != compiler_name
                    || !value["artifact"].as_str().is_some_and(hash)
                    || !staging && !retired && value["artifact"].as_str() != artifact_name(&name)
                {
                    return Err(Error::invalid("compiled cache identity mismatch"));
                }
                if !staging && !retired {
                    updated = used;
                }
                !staging && !retired
            } else {
                false
            };
            let age = now.duration_since(updated).unwrap_or_default();
            if pins.contains(&path) {
                continue;
            }
            if retired
                || complete && age >= PRESSURE_GRACE
                || !complete && compiler_empty && age >= PARTIAL_GRACE
            {
                candidates.push((updated, path, bytes, !complete || age >= IDLE, retired));
            }
        }
    }
    // Complete the entire ownership/inventory validation before the first deletion.
    candidates.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    let mut removed = 0;
    for (_, path, bytes, expired, retired) in candidates {
        if removed == MAX_REMOVE {
            break;
        }
        if !expired && total.saturating_add(required) <= node.artifact_cache_bytes {
            continue;
        }
        let parent = path.parent().unwrap();
        // Unpublish atomically. A crash during recursive removal must not leave
        // a partially valid digest directory that breaks the next upload.
        let tombstone = if retired {
            path.clone()
        } else {
            parent.join(format!(".evicted-{}", uid()))
        };
        if !retired {
            fs::rename(&path, &tombstone)?;
            fs::File::open(parent)?.sync_all()?;
        }
        fs::remove_dir_all(tombstone)?;
        fs::File::open(parent)?.sync_all()?;
        total = total.saturating_sub(bytes);
        removed += 1;
    }
    Ok(Collection {
        fits: total.saturating_add(required) <= node.artifact_cache_bytes,
        removed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(root: &Path) -> Node {
        private_dir(&root.join("artifacts")).unwrap();
        Node::for_tests(root)
    }
    fn age(path: &Path, duration: Duration) {
        fs::File::open(path)
            .unwrap()
            .set_modified(SystemTime::now() - duration)
            .unwrap();
    }
    fn entry(node: &Node, compiler: char, number: u32, size: u64, old: Duration) -> PathBuf {
        let compiler = compiler.to_string().repeat(64);
        let hash = format!("{number:064x}");
        let path = node.state.join("artifacts").join(&compiler).join(&hash);
        private_dir(&path).unwrap();
        fs::File::create(path.join("component.cwasm"))
            .unwrap()
            .set_len(size)
            .unwrap();
        atomic_json(
            &path.join("artifact.json"),
            &json!({"artifact":hash,"compiler":compiler}),
        )
        .unwrap();
        age(&path.join("artifact.json"), old);
        path
    }
    fn run(node: &Node, path: &Path, state: &str) {
        node.insert_test_run(path, terminal(state));
    }
    #[test]
    fn a_cache_assisted_artifact_serves_only_the_tenant_whose_cache_shaped_it() {
        let root = tempfile::tempdir().unwrap();
        let node = node(root.path());
        let digest = format!("{:064x}", 7);
        let compiled = |dir: &Path, artifact: &str| {
            private_dir(dir).unwrap();
            atomic_json(
                &dir.join("artifact.json"),
                &json!({"artifact":artifact,"compiler":node.compiler_id}),
            )
            .unwrap();
        };
        let scoped = node.scoped_artifact_dir(&digest, "alpha").unwrap();
        compiled(&scoped, &digest);
        assert_eq!(
            node.compiled_dir(&digest, Some("alpha")).unwrap(),
            Some(scoped.clone())
        );
        assert_eq!(node.compiled_dir(&digest, Some("beta")).unwrap(), None);
        assert_eq!(node.compiled_dir(&digest, None).unwrap(), None);
        // An uncached compile serves every tenant.
        let shared = node.artifact_dir(&digest).unwrap();
        compiled(&shared, &digest);
        assert_eq!(
            node.compiled_dir(&digest, Some("beta")).unwrap(),
            Some(shared.clone())
        );
        // The inventory takes both, a run pins the scoped one, and a compile
        // interrupted with its cache records open is only partial.
        run(&node, &scoped, "running");
        let stage = shared.parent().unwrap().join(format!(".compile-{}", uid()));
        private_dir(&stage).unwrap();
        fs::write(stage.join(super::super::compile_cache::RECORDS[1].1), b"").unwrap();
        collect(&node, 0).unwrap();
        assert!(scoped.join("artifact.json").is_file());
        // A scoped directory must name the artifact it holds.
        let other = node
            .scoped_artifact_dir(&format!("{:064x}", 8), "alpha")
            .unwrap();
        compiled(&other, &digest);
        assert!(collect(&node, 0).is_err());
    }
    #[test]
    fn the_compile_cache_keeps_its_budget_dropping_least_recently_used_scopes() {
        use super::super::compile_cache::{prune, store};
        let root = tempfile::tempdir().unwrap();
        let mut node = node(root.path());
        // Room for one 2000-byte entry's block, not two.
        node.compile_cache_bytes = 6000;
        let entry = |store: &Path, name: &str| {
            private_dir(&store.join(&name[..2])).unwrap();
            fs::write(store.join(&name[..2]).join(name), [0u8; 2000]).unwrap();
        };
        let alpha = store(&node, "alpha").unwrap();
        entry(&alpha, "aa01");
        let beta = store(&node, "beta").unwrap();
        entry(&beta, "bb01");
        age(&alpha, Duration::from_secs(3600));
        // A store of another compiler is never used again.
        let stale = root.path().join("compile-cache").join("b".repeat(64));
        private_dir(&stale.join("scope")).unwrap();
        prune(&node).unwrap();
        assert!(!alpha.exists(), "the least recently used scope goes first");
        assert!(beta.join("bb").join("bb01").is_file());
        assert!(!stale.exists());
        // Using a scope makes it the most recently used.
        let alpha = store(&node, "alpha").unwrap();
        entry(&alpha, "aa02");
        age(&beta, Duration::from_secs(3600));
        prune(&node).unwrap();
        assert!(alpha.join("aa").join("aa02").is_file());
        assert!(!beta.exists());
        // A store too large to take stock of goes whole: it is only a cache.
        entry(&alpha, "aa03");
        super::super::compile_cache::prune_within(&node, 1).unwrap();
        assert!(!alpha.exists());
    }
    #[test]
    fn idle_cache_reclamation_spans_compilers_and_preserves_recent_use() {
        let root = tempfile::tempdir().unwrap();
        let n = node(root.path());
        let old = entry(&n, 'a', 1, 32, IDLE + Duration::from_secs(2));
        let previous = entry(&n, 'b', 2, 32, IDLE + Duration::from_secs(2));
        let reused = entry(&n, 'a', 3, 32, IDLE + Duration::from_secs(2));
        touch(&reused).unwrap();
        let future = entry(&n, 'a', 4, 32, IDLE + Duration::from_secs(2));
        fs::File::open(future.join("artifact.json"))
            .unwrap()
            .set_modified(SystemTime::now() + IDLE)
            .unwrap();
        let r = collect(&n, 0).unwrap();
        assert_eq!(r.removed, 2);
        assert!(r.fits);
        assert!(!old.exists() && !previous.exists());
        assert!(reused.exists() && future.exists());
        drop(n);
        let n = node(root.path());
        assert_eq!(collect(&n, 0).unwrap().removed, 0);
    }
    #[test]
    fn pressure_reclaims_oldest_unpinned_entries_but_refuses_recent_or_owned_space() {
        let root = tempfile::tempdir().unwrap();
        let n = node(root.path());
        let old = entry(&n, 'a', 1, 100 * 1024 * 1024, Duration::from_secs(7200));
        let newer = entry(&n, 'a', 2, 100 * 1024 * 1024, Duration::from_secs(4000));
        let active = entry(&n, 'b', 3, 200 * 1024 * 1024, IDLE + Duration::from_secs(1));
        run(&n, &active, "running");
        let result = collect(&n, 128 * 1024 * 1024).unwrap();
        assert!(result.fits);
        assert_eq!(result.removed, 1);
        assert!(!old.exists() && newer.exists() && active.exists());
        touch(&newer).unwrap();
        let result = collect(&n, BUDGET).unwrap();
        assert!(!result.fits);
        assert_eq!(result.removed, 0);
        assert!(newer.exists() && active.exists());
        entry(&n, 'a', 4, 200 * 1024 * 1024, Duration::ZERO);
        assert_eq!(
            n.upload(b"\0asm\x0d\0\x01\0").unwrap_err().status,
            StatusCode::INSUFFICIENT_STORAGE
        );
    }
    #[test]
    fn a_run_still_being_created_pins_its_artifact_until_it_is_in_runs() {
        let root = tempfile::tempdir().unwrap();
        let n = node(root.path());
        let creating = entry(&n, 'a', 1, 100 * 1024 * 1024, Duration::from_secs(7200));
        let unused = entry(&n, 'a', 2, 100 * 1024 * 1024, Duration::from_secs(7200));
        // Admitted, being written under `staging`: no run in `runs` names it.
        n.creating
            .lock()
            .unwrap()
            .insert("platform-key".into(), creating.clone());
        let result = collect(&n, BUDGET).unwrap();
        assert_eq!(result.removed, 1);
        assert!(creating.exists() && !unused.exists());
        // Once the creation ends it is the run that pins it, or nothing.
        n.creating.lock().unwrap().clear();
        collect(&n, BUDGET).unwrap();
        assert!(!creating.exists());
    }

    #[test]
    fn partial_compilations_require_age_and_an_empty_compiler_cgroup() {
        let root = tempfile::tempdir().unwrap();
        let n = node(root.path());
        let path = n
            .state
            .join("artifacts")
            .join(&n.compiler_id)
            .join(format!(".compile-{}", uid()));
        private_dir(&path).unwrap();
        fs::write(path.join("input.wasm"), b"partial").unwrap();
        // Both crash points are valid: a temporary metadata write and a complete
        // manifest whose staging directory has not yet been atomically published.
        let temporary = path.join(format!(".write-{}", uid()));
        fs::write(&temporary, b"partial metadata").unwrap();
        atomic_json(
            &path.join("artifact.json"),
            &json!({"artifact":"b".repeat(64),"compiler":n.compiler_id}),
        )
        .unwrap();
        age(&temporary, PARTIAL_GRACE + Duration::from_secs(10));
        age(
            &path.join("artifact.json"),
            PARTIAL_GRACE + Duration::from_secs(10),
        );
        age(
            &path.join("input.wasm"),
            PARTIAL_GRACE + Duration::from_secs(10),
        );
        age(&path, PARTIAL_GRACE + Duration::from_secs(10));
        assert_eq!(collect(&n, 0).unwrap().removed, 0);
        fs::write(
            n.compiler_cgroup.join("cgroup.events"),
            "populated 1\nfrozen 0\n",
        )
        .unwrap();
        assert_eq!(collect(&n, 0).unwrap().removed, 0);
        fs::write(
            n.compiler_cgroup.join("cgroup.events"),
            "populated 0\nfrozen 0\n",
        )
        .unwrap();
        assert_eq!(collect(&n, 0).unwrap().removed, 1);
        assert!(!path.exists());
        // Restart after atomic eviction but before recursive deletion. A fresh
        // copy of the same digest may already be owned by a new execution.
        let original = entry(&n, 'a', 21, 32, Duration::ZERO);
        let retired = original
            .parent()
            .unwrap()
            .join(format!(".evicted-{}", uid()));
        fs::rename(&original, &retired).unwrap();
        let replacement = entry(&n, 'a', 21, 32, Duration::ZERO);
        run(&n, &replacement, "pending");
        fs::write(n.compiler_cgroup.join("cgroup.events"), "populated 1\n").unwrap();
        assert_eq!(collect(&n, 0).unwrap().removed, 1);
        assert!(!retired.exists() && replacement.exists());
    }
    #[test]
    fn unsafe_inventory_aborts_before_any_deletion_and_passes_remove_at_most_eight() {
        let root = tempfile::tempdir().unwrap();
        let n = node(root.path());
        for i in 0..10 {
            entry(&n, 'a', i, 32, IDLE + Duration::from_secs(1));
        }
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("sentinel"), b"keep").unwrap();
        let link = n.state.join("artifacts").join("b".repeat(64));
        std::os::unix::fs::symlink(outside.path(), &link).unwrap();
        assert!(collect(&n, 0).is_err());
        assert_eq!(
            fs::read_dir(n.state.join("artifacts").join(&n.compiler_id))
                .unwrap()
                .count(),
            10
        );
        assert_eq!(fs::read(outside.path().join("sentinel")).unwrap(), b"keep");
        fs::remove_file(link).unwrap();
        assert_eq!(collect(&n, 0).unwrap().removed, 8);
        assert_eq!(collect(&n, 0).unwrap().removed, 2);
        // Reconciliation never waits behind a long-running compiler.
        let _compiling = n.compilation.lock().unwrap();
        n.prune_artifacts().unwrap();
        assert!(n.cache_check.lock().unwrap().is_none());
    }

    #[test]
    fn real_inspection_cache_hit_refreshes_retention_without_a_compiler_process() {
        let root = tempfile::tempdir().unwrap();
        let n = node(root.path());
        let bytes = wat::parse_str(
            r#"(component
          (core module $m (func (export "run") (result i32) i32.const 0))
          (core instance $i (instantiate $m))
          (func $run (result (result)) (canon lift (core func $i "run")))
          (instance $cli (export "run" (func $run)))
          (export "wasi:cli/run@0.2.0" (instance $cli)))"#,
        )
        .unwrap();
        let inspection = fenders_component::inspect(&bytes).unwrap();
        let path = n.artifact_dir(&digest(&bytes)).unwrap();
        private_dir(&path).unwrap();
        let metadata =
            json!({"artifact":digest(&bytes),"compiler":n.compiler_id,"inspection":inspection});
        atomic_json(&path.join("artifact.json"), &metadata).unwrap();
        age(&path.join("artifact.json"), IDLE + Duration::from_secs(1));
        assert_eq!(n.upload(&bytes).unwrap(), metadata);
        assert_eq!(collect(&n, 0).unwrap().removed, 0);
        assert!(path.exists());
    }
}
