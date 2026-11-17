//! Execution-bound runtime identities. Compatibility does not imply live acceptance.
use clap::Parser;
use fenders_node_protocol::{
    error::{Error, Result},
    model::HOST_CONFINEMENT,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs::OpenOptions,
    io::Read,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

pub(crate) const MAX_BINARY_BYTES: u64 = 1024 * 1024 * 1024;
const RUNTIME_ABI: &str = "wasmtime-50.0.0-fenders-v1";
// Protocol 1 binds adoption before Node initialization and supports sealed
// recovery intent before selection publication. Missing means unqualified.
const MANAGEMENT_PROTOCOL: u32 = 1;
fn legacy_management(protocol: &u32) -> bool {
    *protocol == 0
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeRelease {
    pub schema: u32,
    pub runtime_abi: String,
    pub control_protocol: u32,
    pub execution_protocol: u32,
    pub journal_format: u32,
    pub host_confinement: String,
    pub checkpoint_formats: Vec<u32>,
    pub runtime_sha256: String,
    pub launcher_sha256: String,
    pub compiler_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerRelease {
    pub schema: u32,
    pub agent_build: String,
    pub agent_sha256: String,
    #[serde(default, skip_serializing_if = "legacy_management")]
    pub management_protocol: u32,
    pub runtime: RuntimeRelease,
}

fn open_release_file(path: &Path) -> Result<(std::fs::File, std::fs::Metadata)> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_BINARY_BYTES {
        return Err(Error::invalid(
            "release component must be a bounded nonempty regular file",
        ));
    }
    Ok((file, metadata))
}
/// What identifies a release file's bytes without reading them: replacing the
/// file changes its inode and writing to it changes its ctime, which no process
/// can set back without the clock (CAP_SYS_TIME) or raw device writes, both
/// already root on the node. Its device number may differ after a reboot,
/// which only costs a rehash.
fn identity(metadata: &std::fs::Metadata) -> String {
    use std::os::unix::fs::MetadataExt;
    format!(
        "{}:{}:{}:{}.{}:{}.{}",
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec()
    )
}
/// How long since its last change a file must be before its identity stands
/// for its bytes. Linux stamps a change from a clock that ticks every few
/// milliseconds (and some filesystems keep whole or even seconds), so a
/// same-size write in the tick a file last changed in keeps its identity; a
/// write after the file has settled this long cannot.
const SETTLED: std::time::Duration = std::time::Duration::from_secs(2);
/// Whether the file last changed at least [`SETTLED`] ago, so a later match of
/// its identity stands for what is read from it now.
fn settled(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    let changed = std::time::UNIX_EPOCH
        + std::time::Duration::new(metadata.ctime().max(0) as u64, metadata.ctime_nsec() as u32);
    changed.elapsed().is_ok_and(|elapsed| elapsed >= SETTLED)
}
/// Digests by path, valid while the file keeps the identity it was hashed under.
type Hashed = std::collections::HashMap<PathBuf, (String, String)>;
static HASHED: std::sync::LazyLock<std::sync::Mutex<Hashed>> =
    std::sync::LazyLock::new(Default::default);

pub(crate) fn file_digest(path: &Path) -> Result<String> {
    Ok(hashed(path)?.0)
}
/// The digest and the identity it was read under, from the same descriptor.
/// A file hashed once it had settled is not reread while its identity holds.
fn hashed(path: &Path) -> Result<(String, String)> {
    let (mut file, metadata) = open_release_file(path)?;
    let current = identity(&metadata);
    if let Some((known, digest)) = HASHED.lock().map_err(|_| Error::internal())?.get(path)
        && *known == current
    {
        return Ok((digest.clone(), current));
    }
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total += count as u64;
        if total > MAX_BINARY_BYTES {
            return Err(Error::invalid("release component exceeds size limit"));
        }
        digest.update(&buffer[..count]);
    }
    let digest = format!("{:x}", digest.finalize());
    if total != metadata.len() || identity(&file.metadata()?) != current {
        return Err(Error::invalid("release component changed while hashing"));
    }
    if settled(&metadata) {
        HASHED
            .lock()
            .map_err(|_| Error::internal())?
            .insert(path.to_owned(), (current.clone(), digest.clone()));
    }
    Ok((digest, current))
}
const RUNTIME_FILES: [&str; 3] = ["runtime.elf", "launch", "compile"];
/// The identities of `release`'s runtime files, each read while its bytes still
/// hash to the digest the release records. A run's own processes compare these
/// instead of rehashing. `null` when a file changed too recently for its
/// identity to stand for its bytes: the run's processes then hash them.
pub fn runtime_identity(build: &Path, release: &RuntimeRelease) -> Result<Value> {
    let mut identities = serde_json::Map::new();
    let mut all_settled = true;
    for (name, expected) in RUNTIME_FILES.iter().zip([
        &release.runtime_sha256,
        &release.launcher_sha256,
        &release.compiler_sha256,
    ]) {
        let path = build.join(name);
        let (digest, hashed_as) = hashed(&path)?;
        if digest != *expected {
            return Err(Error::invalid("execution runtime release bytes changed"));
        }
        // Settled under the identity just hashed, or it is not recorded.
        all_settled &= open_release_file(&path)
            .is_ok_and(|(_, metadata)| settled(&metadata) && identity(&metadata) == hashed_as);
        identities.insert((*name).into(), Value::String(hashed_as));
    }
    Ok(if all_settled {
        Value::Object(identities)
    } else {
        Value::Null
    })
}

fn sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl RuntimeRelease {
    pub fn capture(build: &Path) -> Result<Self> {
        Ok(Self {
            schema: 1,
            runtime_abi: RUNTIME_ABI.into(),
            control_protocol: 1,
            execution_protocol: 1,
            journal_format: 1,
            host_confinement: HOST_CONFINEMENT.into(),
            // No checkpoint format is implemented; do not advertise restore capability.
            checkpoint_formats: vec![],
            runtime_sha256: file_digest(&build.join("runtime.elf"))?,
            launcher_sha256: file_digest(&build.join("launch"))?,
            compiler_sha256: file_digest(&build.join("compile"))?,
        })
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema != 1
            || self.runtime_abi != RUNTIME_ABI
            || self.control_protocol != 1
            || self.execution_protocol != 1
            || self.journal_format != 1
            || self.host_confinement != HOST_CONFINEMENT
            || !self.checkpoint_formats.is_empty()
            || !sha256(&self.runtime_sha256)
            || !sha256(&self.launcher_sha256)
            || !sha256(&self.compiler_sha256)
        {
            return Err(Error::invalid(
                "execution release requires unsupported contracts",
            ));
        }
        Ok(())
    }

    pub fn verify(&self, build: &Path) -> Result<()> {
        self.validate()?;
        if self != &Self::capture(build)? {
            return Err(Error::invalid("execution runtime release bytes changed"));
        }
        Ok(())
    }
}

impl WorkerRelease {
    pub fn capture(build: &Path, executable: &Path) -> Result<Self> {
        Ok(Self {
            schema: 1,
            agent_build: option_env!("FENDERS_BUILD_ID")
                .unwrap_or(env!("CARGO_PKG_VERSION"))
                .into(),
            agent_sha256: file_digest(executable)?,
            management_protocol: MANAGEMENT_PROTOCOL,
            runtime: RuntimeRelease::capture(build)?,
        })
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema != 1
            || self.agent_build.is_empty()
            || self.agent_build.len() > 256
            || self.agent_build.chars().any(char::is_control)
            || !sha256(&self.agent_sha256)
            || self.management_protocol > MANAGEMENT_PROTOCOL
        {
            return Err(Error::invalid("invalid worker release identity"));
        }
        self.runtime.validate()
    }

    /// A retained execution receipt is not permission to activate its creator.
    /// Unadvertised agents may reconcile Node before claiming fenced ownership.
    pub(crate) fn validate_management(&self) -> Result<()> {
        self.validate()?;
        if self.management_protocol != MANAGEMENT_PROTOCOL {
            return Err(Error::invalid(
                "worker release requires a qualified management protocol",
            ));
        }
        Ok(())
    }

    /// The creator's agent may differ after adoption. Runtime bytes and contracts may not.
    pub fn verify_execution(config: &Value) -> Result<()> {
        let Some(value) = config.get("worker_release") else {
            // Existing executions predate this receipt. Preserve the legacy path;
            // installer barriers still prevent unqualified mixed-release updates.
            return Ok(());
        };
        let release: Self = serde_json::from_value(value.clone())
            .map_err(|_| Error::invalid("invalid execution release receipt"))?;
        release.validate()?;
        let build = config["build"]
            .as_str()
            .ok_or_else(|| Error::invalid("execution release build path missing"))?;
        // Files with the identities the node recorded hold the bytes it hashed.
        if let Some(recorded) = config["release_identity"].as_object()
            && recorded.len() == RUNTIME_FILES.len()
            && RUNTIME_FILES.iter().all(|name| {
                open_release_file(&Path::new(build).join(name)).is_ok_and(|(_, metadata)| {
                    recorded.get(*name).and_then(Value::as_str) == Some(&identity(&metadata))
                })
            })
        {
            return Ok(());
        }
        release.runtime.verify(Path::new(build))
    }
}

#[derive(Parser)]
#[command(
    name = "fenders-node release-manifest",
    about = "Print exact worker release identity without starting a node"
)]
struct ManifestArgs {
    #[arg(long)]
    build: PathBuf,
}

pub fn dispatch(args: &[String]) -> Option<Result<()>> {
    if args.get(1).map(String::as_str) != Some("release-manifest") {
        return None;
    }
    Some((|| {
        let args = ManifestArgs::try_parse_from(&args[1..])
            .map_err(|_| Error::invalid("release-manifest requires --build PATH"))?;
        let manifest = WorkerRelease::capture(&args.build, &std::env::current_exe()?)?;
        println!(
            "{}",
            serde_json::to_string_pretty(&manifest).map_err(|_| Error::internal())?
        );
        Ok(())
    })())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::symlink};

    fn build(root: &Path) -> WorkerRelease {
        for name in ["runtime.elf", "launch", "compile", "agent"] {
            fs::write(root.join(name), format!("fixture {name}")).unwrap();
        }
        WorkerRelease::capture(root, &root.join("agent")).unwrap()
    }

    #[test]
    fn execution_retains_runtime_identity_across_agent_replacement_and_rollback() {
        let root = tempfile::tempdir().unwrap();
        let original = build(root.path());
        let config = serde_json::json!({"build":root.path(),"worker_release":original});
        fs::write(root.path().join("agent"), "replacement agent").unwrap();
        let replacement = WorkerRelease::capture(root.path(), &root.path().join("agent")).unwrap();
        assert_ne!(replacement.agent_sha256, original.agent_sha256);
        assert_eq!(replacement.runtime, original.runtime);
        WorkerRelease::verify_execution(&config).unwrap();
        fs::write(root.path().join("agent"), "fixture agent").unwrap();
        assert_eq!(
            WorkerRelease::capture(root.path(), &root.path().join("agent")).unwrap(),
            original
        );
        WorkerRelease::verify_execution(&config).unwrap();
    }

    #[test]
    fn streaming_hashes_match_the_independent_complete_input_digest() {
        let root = tempfile::tempdir().unwrap();
        let bytes: Vec<u8> = (0..200_000).map(|index| (index % 251) as u8).collect();
        let path = root.path().join("component");
        fs::write(&path, &bytes).unwrap();
        assert_eq!(
            file_digest(&path).unwrap(),
            fenders_node_protocol::model::digest(&bytes)
        );
    }

    #[test]
    fn every_runtime_component_is_bound_to_the_execution_receipt() {
        let root = tempfile::tempdir().unwrap();
        for name in ["runtime.elf", "launch", "compile"] {
            let release = build(root.path());
            let config = serde_json::json!({"build":root.path(),"worker_release":release});
            fs::write(root.path().join(name), "changed bytes").unwrap();
            assert!(WorkerRelease::verify_execution(&config).is_err(), "{name}");
        }
    }

    #[test]
    fn legacy_receipts_remain_readable_without_qualifying_their_agent_for_activation() {
        let root = tempfile::tempdir().unwrap();
        let release = build(root.path());
        release.validate_management().unwrap();
        let mut old = serde_json::to_value(&release).unwrap();
        old.as_object_mut().unwrap().remove("management_protocol");
        let legacy: WorkerRelease = serde_json::from_value(old.clone()).unwrap();
        assert_eq!(serde_json::to_value(&legacy).unwrap(), old);
        assert!(legacy.validate_management().is_err());
        WorkerRelease::verify_execution(&serde_json::json!({
            "build":root.path(),"worker_release":old
        }))
        .unwrap();
        let mut future = release;
        future.management_protocol += 1;
        assert!(future.validate().is_err());
    }

    #[test]
    fn unsupported_contracts_and_malformed_receipts_refuse_adoption() {
        let root = tempfile::tempdir().unwrap();
        let release = build(root.path());
        let config = serde_json::json!({"build":root.path(),"worker_release":release});
        for (field, value) in [
            ("schema", serde_json::json!(2)),
            ("runtime_abi", serde_json::json!("other")),
            ("control_protocol", serde_json::json!(2)),
            ("execution_protocol", serde_json::json!(2)),
            ("journal_format", serde_json::json!(2)),
            ("host_confinement", serde_json::json!("other")),
            ("checkpoint_formats", serde_json::json!([1])),
            ("runtime_sha256", serde_json::json!("A".repeat(64))),
        ] {
            let mut invalid = config.clone();
            invalid["worker_release"]["runtime"][field] = value;
            assert!(
                WorkerRelease::verify_execution(&invalid).is_err(),
                "{field}"
            );
        }
        for value in [Value::Null, serde_json::json!({}), serde_json::json!("bad")] {
            let mut invalid = config.clone();
            invalid["worker_release"] = value;
            assert!(WorkerRelease::verify_execution(&invalid).is_err());
        }
        assert!(WorkerRelease::verify_execution(&serde_json::json!({})).is_ok());
    }

    #[test]
    fn symlinks_empty_files_and_oversized_components_refuse_capture() {
        let root = tempfile::tempdir().unwrap();
        build(root.path());
        fs::remove_file(root.path().join("launch")).unwrap();
        symlink(root.path().join("agent"), root.path().join("launch")).unwrap();
        assert!(RuntimeRelease::capture(root.path()).is_err());
        fs::remove_file(root.path().join("launch")).unwrap();
        fs::write(root.path().join("launch"), "").unwrap();
        assert!(RuntimeRelease::capture(root.path()).is_err());
        fs::File::create(root.path().join("launch"))
            .unwrap()
            .set_len(MAX_BINARY_BYTES + 1)
            .unwrap();
        assert!(RuntimeRelease::capture(root.path()).is_err());
    }

    #[test]
    fn identities_stand_for_the_bytes_only_of_settled_files() {
        let root = tempfile::tempdir().unwrap();
        let release = build(root.path());
        // Just written: a rewrite in the same clock tick would keep the
        // identity, so none is recorded and the run's processes hash.
        assert!(
            runtime_identity(root.path(), &release.runtime)
                .unwrap()
                .is_null()
        );
        let fresh = serde_json::json!({"build":root.path(),"worker_release":release.clone(),
            "release_identity":null});
        fs::write(root.path().join("launch"), "fixture LAUNCH").unwrap();
        assert!(WorkerRelease::verify_execution(&fresh).is_err());
        fs::write(root.path().join("launch"), "fixture launch").unwrap();

        std::thread::sleep(SETTLED + std::time::Duration::from_millis(100));
        let identities = runtime_identity(root.path(), &release.runtime).unwrap();
        assert!(identities.is_object());
        let config = serde_json::json!({"build":root.path(),"worker_release":release.clone(),
            "release_identity":identities});
        WorkerRelease::verify_execution(&config).unwrap();
        // Rewritten in place at the same size once settled: its identity no
        // longer matches, so the bytes are hashed again and refused.
        fs::write(root.path().join("launch"), "fixture LAUNCH").unwrap();
        assert!(WorkerRelease::verify_execution(&config).is_err());
        fs::write(root.path().join("launch"), "fixture launch").unwrap();
        WorkerRelease::verify_execution(&config).unwrap();
    }
}
