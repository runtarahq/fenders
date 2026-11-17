//! Copy verified releases into a content-addressed, read-only store. Staging
//! never activates an agent, modifies VM state or removes retained releases.
use crate::release::{MAX_BINARY_BYTES, WorkerRelease, file_digest};
use axum::http::StatusCode;
use clap::Parser;
use fenders_node_protocol::{
    error::{Error, Result},
    model::uid,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::{
            ffi::OsStrExt,
            fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
        },
    },
    path::{Path, PathBuf},
};

#[cfg(test)]
mod tests;
const MANIFEST: &str = "worker-release.json";
const MAX_MANIFEST: u64 = 64 * 1024;
const COMPONENTS: [&str; 4] = ["fenders-node", "compile", "launch", "runtime.elf"];
fn invalid() -> Error {
    Error::invalid("release staging input or retained release is invalid")
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn regular(path: &Path, max: u64) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > max {
        return Err(invalid());
    }
    Ok(file)
}
fn manifest(path: &Path, expected: &str) -> Result<(Vec<u8>, WorkerRelease)> {
    let mut bytes = Vec::new();
    regular(path, MAX_MANIFEST)?
        .take(MAX_MANIFEST + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_MANIFEST || digest(&bytes) != expected {
        return Err(invalid());
    }
    let release: WorkerRelease = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    release.validate()?;
    Ok((bytes, release))
}
fn real_directory(path: &Path) -> Result<()> {
    if !fs::symlink_metadata(path)?.is_dir() {
        return Err(invalid());
    }
    Ok(())
}
fn protected_root(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o700 != 0o700
        || metadata.mode() & 0o022 != 0
    {
        return Err(invalid());
    }
    Ok(())
}
fn expected<'a>(release: &'a WorkerRelease, name: &str) -> &'a str {
    match name {
        "fenders-node" => &release.agent_sha256,
        "compile" => &release.runtime.compiler_sha256,
        "launch" => &release.runtime.launcher_sha256,
        "runtime.elf" => &release.runtime.runtime_sha256,
        _ => unreachable!(),
    }
}
fn copy(source: &Path, target: &Path, expected: &str) -> Result<()> {
    let mut input = regular(source, MAX_BINARY_BYTES)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(target)?;
    let mut hash = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        size += count as u64;
        if size > MAX_BINARY_BYTES {
            return Err(invalid());
        }
        output.write_all(&buffer[..count])?;
        hash.update(&buffer[..count]);
    }
    if format!("{:x}", hash.finalize()) != expected {
        return Err(invalid());
    }
    output.set_permissions(fs::Permissions::from_mode(0o555))?;
    output.sync_all()?;
    Ok(())
}
fn lock(root: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(root.join(".stage.lock"))?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o022 != 0
    {
        return Err(invalid());
    }
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(Error::new(
            StatusCode::CONFLICT,
            "another release staging operation owns the store",
        ));
    }
    Ok(file)
}
fn sealed(path: &Path, mode: u32, directory: bool) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o7777 != mode
        || if directory {
            !metadata.is_dir()
        } else {
            !metadata.is_file() || metadata.nlink() != 1
        }
    {
        return Err(invalid());
    }
    Ok(())
}
fn verify(path: &Path, pin: &str, release: &WorkerRelease) -> Result<()> {
    sealed(path, 0o555, true)?;
    let names = fs::read_dir(path)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<std::io::Result<BTreeSet<_>>>()?;
    let allowed: BTreeSet<_> = COMPONENTS
        .into_iter()
        .chain([MANIFEST])
        .map(std::ffi::OsString::from)
        .collect();
    if names != allowed {
        return Err(invalid());
    }
    sealed(&path.join(MANIFEST), 0o444, false)?;
    if manifest(&path.join(MANIFEST), pin)?.1 != *release {
        return Err(invalid());
    }
    for name in COMPONENTS {
        sealed(&path.join(name), 0o555, false)?;
        if file_digest(&path.join(name))? != expected(release, name) {
            return Err(invalid());
        }
    }
    Ok(())
}
fn publish(source: &Path, target: &Path) -> Result<()> {
    let source = CString::new(source.as_os_str().as_bytes()).map_err(|_| invalid())?;
    let target = CString::new(target.as_os_str().as_bytes()).map_err(|_| invalid())?;
    #[cfg(target_os = "linux")]
    let status = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            target.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    #[cfg(target_os = "macos")]
    let status = unsafe { libc::renamex_np(source.as_ptr(), target.as_ptr(), libc::RENAME_EXCL) };
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    return Err(Error::invalid(
        "atomic release publication is unsupported on this OS",
    ));
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if status != 0 {
        return Err(Error::new(
            StatusCode::CONFLICT,
            "release publication refused; destination was not overwritten",
        ));
    }
    Ok(())
}
struct Temporary {
    path: PathBuf,
    published: bool,
}
impl Drop for Temporary {
    fn drop(&mut self) {
        if !self.published {
            let _ = fs::set_permissions(&self.path, fs::Permissions::from_mode(0o700));
            // Only the new private directory allocated by this call is ours.
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}
#[derive(Debug, Serialize)]
pub struct Receipt {
    pub schema: u32,
    pub manifest_sha256: String,
    pub path: PathBuf,
    pub release: WorkerRelease,
    pub created: bool,
}

/// Verify an already published release without copying or changing any file.
pub(crate) fn retained(root: &Path, pin: &str) -> Result<Receipt> {
    if pin.len() != 64
        || !pin
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid());
    }
    protected_root(root)?;
    let path = root.canonicalize()?.join(pin);
    let (_, release) = manifest(&path.join(MANIFEST), pin)?;
    verify(&path, pin, &release)?;
    Ok(Receipt {
        schema: 1,
        manifest_sha256: pin.into(),
        path,
        release,
        created: false,
    })
}

/// `root` must already exist, be owned by the operator and not be writable by
/// group/others. The manifest digest comes from independently verified artifacts.
pub fn stage(source: &Path, root: &Path, pin: &str) -> Result<Receipt> {
    real_directory(source)?;
    let source = source.canonicalize()?;
    let (bytes, release) = manifest(&source.join(MANIFEST), pin)?;
    release.validate_management()?;
    protected_root(root)?;
    let root = root.canonicalize()?;
    let _lock = lock(&root)?;
    let destination = root.join(pin);
    match fs::symlink_metadata(&destination) {
        Ok(_) => {
            verify(&destination, pin, &release)?;
            File::open(&root)?.sync_all()?;
            return Ok(Receipt {
                schema: 1,
                manifest_sha256: pin.into(),
                path: destination,
                release,
                created: false,
            });
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(error) => return Err(error.into()),
    }
    let path = root.join(format!(".stage-{}", uid()));
    fs::DirBuilder::new().mode(0o700).create(&path)?;
    let mut temporary = Temporary {
        path,
        published: false,
    };
    for name in COMPONENTS {
        copy(
            &source.join(name),
            &temporary.path.join(name),
            expected(&release, name),
        )?;
    }
    let file = temporary.path.join(MANIFEST);
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&file)?;
    output.write_all(&bytes)?;
    output.set_permissions(fs::Permissions::from_mode(0o444))?;
    output.sync_all()?;
    drop(output);
    fs::set_permissions(&temporary.path, fs::Permissions::from_mode(0o555))?;
    verify(&temporary.path, pin, &release)?;
    File::open(&temporary.path)?.sync_all()?;
    publish(&temporary.path, &destination)?;
    temporary.published = true;
    // If this sync fails, the published valid release remains for a verified
    // retry; never remove it merely because its acknowledgement was lost.
    File::open(&root)?.sync_all()?;
    Ok(Receipt {
        schema: 1,
        manifest_sha256: pin.into(),
        path: destination,
        release,
        created: true,
    })
}

#[derive(Parser)]
#[command(
    name = "fenders-node release-stage",
    about = "Verify and atomically stage a retained worker release; never activate it"
)]
struct Args {
    #[arg(long)]
    source: PathBuf,
    #[arg(long)]
    releases: PathBuf,
    #[arg(long)]
    expected_manifest_sha256: String,
}
pub fn dispatch(args: &[String]) -> Option<Result<()>> {
    if args.get(1).map(String::as_str) != Some("release-stage") {
        return None;
    }
    Some((|| {
        let args = match Args::try_parse_from(&args[1..]) {
            Ok(args) => args,
            Err(error) if error.kind() == clap::error::ErrorKind::DisplayHelp => {
                print!("{error}");
                return Ok(());
            }
            Err(_) => {
                return Err(Error::invalid(
                    "release-stage requires source, releases and expected manifest hash",
                ));
            }
        };
        if !cfg!(target_os = "linux") || unsafe { libc::geteuid() } != 0 {
            return Err(Error::invalid("worker release staging requires Linux root"));
        }
        let receipt = stage(&args.source, &args.releases, &args.expected_manifest_sha256)?;
        println!(
            "{}",
            serde_json::to_string_pretty(&receipt).map_err(|_| Error::internal())?
        );
        Ok(())
    })())
}
