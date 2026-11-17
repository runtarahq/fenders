//! Read-only verification of an operator-provisioned Linux project quota.
//! Never enables quotas, changes project IDs, formats storage or removes data.
use fenders_node_protocol::error::{Error, Result};
use std::path::{Path, PathBuf};

/// Call before creating threads or workers. The node must not retain the kernel
/// quota bypass, including across exec of another root-owned executable.
pub fn drop_quota_bypass() -> Result<()> {
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    {
        linux::drop_bypass()
    }
    #[cfg(not(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )))]
    {
        Err(Error::invalid(
            "quota capability confinement requires Linux",
        ))
    }
}

pub(crate) fn verify_producer_capabilities(pid: i64) -> Result<()> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))?;
    verify_capability_status(&status)
}
fn verify_capability_status(status: &str) -> Result<()> {
    for field in ["CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"] {
        let value = status
            .lines()
            .find_map(|line| line.strip_prefix(field))
            .and_then(|v| u64::from_str_radix(v.trim(), 16).ok())
            .ok_or_else(|| Error::invalid("producer capability observation unavailable"))?;
        if value & (1 << 24) != 0 {
            return Err(Error::invalid(
                "existing producer retains quota bypass; stop it before enabling quota mode",
            ));
        }
    }
    Ok(())
}

pub struct ProjectQuota {
    root: PathBuf,
    project: u32,
    max_bytes: u64,
    max_inodes: u64,
}
#[derive(Debug)]
pub struct Remaining {
    pub bytes: u64,
    pub inodes: u64,
}
impl ProjectQuota {
    pub fn open(root: &Path, project: u32, max_bytes: u64, max_inodes: u64) -> Result<Self> {
        if project == 0 || project > i32::MAX as u32 || max_bytes == 0 || max_inodes == 0 {
            return Err(Error::invalid("invalid state project quota requirement"));
        }
        if std::fs::symlink_metadata(root)?.file_type().is_symlink() {
            return Err(Error::invalid("state quota root must be a real directory"));
        }
        let value = Self {
            root: root.canonicalize()?,
            project,
            max_bytes,
            max_inodes,
        };
        value.remaining()?;
        Ok(value)
    }
    /// Check the entire existing tree and actual quota enforcement, not mount
    /// option text. Reject uncertainty; this does not gate stopping existing work.
    pub fn remaining(&self) -> Result<Remaining> {
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        {
            linux::remaining(self)
        }
        #[cfg(not(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )))]
        {
            let _ = (&self.root, self.project, self.max_bytes, self.max_inodes);
            Err(Error::invalid(
                "state project quota verification requires Linux x86_64 or aarch64",
            ))
        }
    }
    pub fn contains(&self, path: &Path) -> Result<bool> {
        Ok(path.canonicalize()?.starts_with(&self.root))
    }
}
#[cfg(any(
    test,
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
fn capacity(
    flags: u16,
    hard_blocks: u64,
    hard_inodes: u64,
    bytes: u64,
    inodes: u64,
    maximum_bytes: u64,
    maximum_inodes: u64,
) -> Result<Remaining> {
    let limit = hard_blocks.checked_mul(1024).ok_or_else(Error::internal)?;
    if flags & 0x30 != 0x30
        || limit == 0
        || hard_inodes == 0
        || limit > maximum_bytes
        || hard_inodes > maximum_inodes
    {
        return Err(Error::invalid(
            "state project quota is unenforced, unlimited or exceeds configured ceilings",
        ));
    }
    Ok(Remaining {
        bytes: limit.saturating_sub(bytes),
        inodes: hard_inodes.saturating_sub(inodes),
    })
}
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod linux {
    use super::*;
    use std::{
        fs::{self, File, OpenOptions},
        os::{
            fd::AsRawFd,
            unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt},
        },
    };
    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct Caps {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    fn capabilities() -> Result<(CapHeader, [Caps; 2])> {
        let mut header = CapHeader {
            version: 0x20080522,
            pid: 0,
        };
        let mut caps = [Caps::default(); 2];
        if unsafe { libc::syscall(libc::SYS_capget, &mut header, caps.as_mut_ptr()) } != 0 {
            return Err(Error::invalid("quota bypass capabilities unavailable"));
        }
        Ok((header, caps))
    }
    fn no_bypass() -> Result<()> {
        let (_, caps) = capabilities()?;
        if (caps[0].effective | caps[0].permitted | caps[0].inheritable) & (1 << 24) != 0
            || unsafe { libc::prctl(libc::PR_CAPBSET_READ, 24, 0, 0, 0) } != 0
        {
            return Err(Error::invalid(
                "state quota requires CAP_SYS_RESOURCE removed from all capability sets",
            ));
        }
        Ok(())
    }
    pub(super) fn drop_bypass() -> Result<()> {
        let (header, mut caps) = capabilities()?;
        if unsafe { libc::prctl(libc::PR_CAPBSET_READ, 24, 0, 0, 0) } != 0
            && unsafe { libc::prctl(libc::PR_CAPBSET_DROP, 24, 0, 0, 0) } != 0
        {
            return Err(Error::invalid(
                "cannot remove quota bypass from capability bounding set",
            ));
        }
        caps[0].effective &= !(1 << 24);
        caps[0].permitted &= !(1 << 24);
        caps[0].inheritable &= !(1 << 24);
        if unsafe { libc::syscall(libc::SYS_capset, &header, caps.as_ptr()) } != 0 {
            return Err(Error::invalid("cannot drop quota bypass capability"));
        }
        no_bypass()
    }
    // Linux UAPI fsxattr and fs_quota_statv v1; restricted to the two supported
    // 64-bit node ABIs. quotactl_fd binds queries to the opened filesystem.
    #[repr(C)]
    #[derive(Default)]
    struct Attributes {
        flags: u32,
        extent: u32,
        extents: u32,
        project: u32,
        cow: u32,
        pad: [u8; 8],
    }
    #[repr(C)]
    #[derive(Default)]
    struct QuotaFile {
        inode: u64,
        blocks: u64,
        extents: u32,
        pad: u32,
    }
    #[repr(C)]
    #[derive(Default)]
    struct State {
        version: i8,
        pad1: u8,
        flags: u16,
        count: u32,
        user: QuotaFile,
        group: QuotaFile,
        project: QuotaFile,
        block_time: i32,
        inode_time: i32,
        rt_time: i32,
        block_warn: u16,
        inode_warn: u16,
        rt_warn: u16,
        pad3: u16,
        pad4: u32,
        pad2: [u64; 7],
    }
    const _: () =
        assert!(std::mem::size_of::<Attributes>() == 28 && std::mem::size_of::<State>() == 160);
    fn open(path: &Path) -> Result<File> {
        Ok(OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)?)
    }
    fn attribute(file: &File, project: u32, directory: bool) -> Result<()> {
        let mut value = Attributes::default();
        // FS_IOC_FSGETXATTR = _IOR('X',31,struct fsxattr).
        if unsafe { libc::ioctl(file.as_raw_fd(), 0x801c581f_u64, &mut value) } != 0 {
            return Err(Error::invalid("filesystem project attributes unavailable"));
        }
        if value.project != project
            || directory && value.flags & 0x200 == 0
            || value.flags & 0x101 != 0
        {
            return Err(Error::invalid(
                "state entry lacks the required project or directory inheritance",
            ));
        }
        Ok(())
    }
    fn query<T>(root: &File, op: u32, id: u32, value: &mut T) -> Result<()> {
        let command = (op << 8) | 2; // QCMD(op, PRJQUOTA).
        if unsafe {
            libc::syscall(
                libc::SYS_quotactl_fd,
                root.as_raw_fd(),
                command,
                id,
                value as *mut T,
            )
        } != 0
        {
            return Err(Error::invalid("filesystem project quota query unavailable"));
        }
        Ok(())
    }
    fn tree(path: &Path, device: u64, project: u32, count: &mut usize) -> Result<()> {
        *count += 1;
        if *count > 100_000 {
            return Err(Error::invalid("state quota inventory limit exceeded"));
        }
        let before = fs::symlink_metadata(path)?;
        if before.dev() != device || before.file_type().is_symlink() {
            return Err(Error::invalid(
                "state quota tree crosses a mount or symlink",
            ));
        }
        // Unix sockets carry no payload. Their parent must still have verified
        // project inheritance. Never open FIFOs/devices during inventory.
        if before.file_type().is_socket() {
            return Ok(());
        }
        if !before.is_dir() && !before.is_file() {
            return Err(Error::invalid("unsupported state quota entry"));
        }
        let file = open(path)?;
        let current = file.metadata()?;
        if current.dev() != device || current.ino() != before.ino() {
            return Err(Error::invalid("state quota entry changed during inventory"));
        }
        attribute(&file, project, current.is_dir())?;
        if current.is_dir() {
            for entry in fs::read_dir(path)? {
                tree(&entry?.path(), device, project, count)?;
            }
        }
        Ok(())
    }
    pub(super) fn remaining(value: &ProjectQuota) -> Result<Remaining> {
        no_bypass()?;
        let root = open(&value.root)?;
        let metadata = root.metadata()?;
        if !metadata.is_dir()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o022 != 0
        {
            return Err(Error::invalid("state quota root is not a directory"));
        }
        tree(&value.root, metadata.dev(), value.project, &mut 0)?;
        let after = fs::symlink_metadata(&value.root)?;
        if after.dev() != metadata.dev() || after.ino() != metadata.ino() {
            return Err(Error::invalid("state quota root changed"));
        }
        let mut state = State {
            version: 1,
            ..Default::default()
        };
        query(&root, (b'X' as u32) << 8 | 8, 0, &mut state)?; // Q_XGETQSTATV.
        if state.version != 1 {
            return Err(Error::invalid("unsupported project quota state version"));
        }
        let mut quota: libc::dqblk = unsafe { std::mem::zeroed() };
        query(&root, 0x800007, value.project, &mut quota)?; // Q_GETQUOTA.
        if quota.dqb_valid & 15 != 15 {
            return Err(Error::invalid("incomplete project quota accounting"));
        }
        capacity(
            state.flags,
            quota.dqb_bhardlimit,
            quota.dqb_ihardlimit,
            quota.dqb_curspace,
            quota.dqb_curinodes,
            value.max_bytes,
            value.max_inodes,
        )
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn legacy_producer_capability_sets_must_all_be_observed_and_clear() {
        let fields = ["CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"];
        let good = fields
            .map(|field| format!("{field}\t0000000000000000\n"))
            .concat();
        assert!(verify_capability_status(&good).is_ok());
        for field in fields {
            assert!(
                verify_capability_status(&good.replace(
                    &format!("{field}\t0000000000000000"),
                    &format!("{field}\t0000000001000000")
                ))
                .is_err()
            );
            assert!(
                verify_capability_status(
                    &good.replace(&format!("{field}\t0000000000000000\n"), "")
                )
                .is_err()
            );
        }
    }
    #[test]
    fn requires_enforcement_and_both_finite_ceilings() {
        for (flags, blocks, inodes) in [
            (0, 8, 20),
            (0x10, 8, 20),
            (0x20, 8, 20),
            (0x30, 0, 20),
            (0x30, 8, 0),
            (0x30, 9, 20),
            (0x30, 8, 21),
        ] {
            assert!(capacity(flags, blocks, inodes, 0, 0, 8192, 20).is_err());
        }
        let left = capacity(0x30, 8, 20, 4096, 7, 8192, 20).unwrap();
        assert_eq!((left.bytes, left.inodes), (4096, 13));
        let exhausted = capacity(0x30, 8, 20, 9999, 99, 8192, 20).unwrap();
        assert_eq!((exhausted.bytes, exhausted.inodes), (0, 0));
        assert!(capacity(0x30, u64::MAX, 20, 0, 0, u64::MAX, 20).is_err());
    }
    #[test]
    fn invalid_requirements_and_symlink_roots_refuse() {
        let dir = tempfile::tempdir().unwrap();
        assert!(ProjectQuota::open(dir.path(), 0, 1024, 1).is_err());
        assert!(ProjectQuota::open(dir.path(), 1, 0, 1).is_err());
        assert!(ProjectQuota::open(dir.path(), 1, 1024, 0).is_err());
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(dir.path(), &link).unwrap();
        assert!(ProjectQuota::open(&link, 1, 1024, 1).is_err());
    }
}
