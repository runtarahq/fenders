//! Applied only in a fresh single-threaded worker before executing native code.
use fenders_node_protocol::error::{Error, Result};
use libloading::Library;
use std::{
    ffi::{CString, c_void},
    io::{Read, Seek, SeekFrom},
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
};
pub const VERSION: &str = "landlock6-seccomp-v2";
#[repr(C)]
struct Ruleset {
    fs: u64,
    net: u64,
    scoped: u64,
}
#[repr(C, packed)]
struct PathRule {
    access: u64,
    fd: i32,
}
#[repr(C)]
struct NetRule {
    access: u64,
    port: u64,
}
#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}
#[repr(C)]
#[derive(Default, Copy, Clone)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct Compare {
    arg: u32,
    op: i32,
    a: u64,
    b: u64,
}
fn check(value: i64) -> Result<i64> {
    if value < 0 {
        Err(Error::internal())
    } else {
        Ok(value)
    }
}
pub fn abi() -> Result<i64> {
    let abi = check(unsafe { libc::syscall(444, 0, 0, 1) })?;
    if abi < 6 {
        return Err(Error::invalid("Landlock ABI 6 or newer is required"));
    }
    Ok(abi)
}
fn privileges() -> Result<()> {
    unsafe {
        check(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) as i64)?;
        check(libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        ) as i64)?;
        let header = CapHeader {
            version: 0x20080522,
            pid: 0,
        };
        let data = [CapData::default(); 2];
        check(libc::syscall(libc::SYS_capset, &header, data.as_ptr()))?;
    }
    Ok(())
}
fn landlock(paths: &[(PathBuf, u64)], ports: &[u16]) -> Result<i64> {
    let abi = abi()?;
    let attr = Ruleset {
        fs: (1 << 16) - 1,
        net: 3,
        scoped: 3,
    };
    let fd = check(unsafe { libc::syscall(444, &attr, std::mem::size_of::<Ruleset>(), 0) })? as i32;
    struct Fd(i32);
    impl Drop for Fd {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.0);
            }
        }
    }
    let guard = Fd(fd);
    for (path, access) in paths {
        let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| Error::internal())?;
        let opened =
            check(unsafe { libc::open(path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) as i64 })?
                as i32;
        let _opened = Fd(opened);
        let rule = PathRule {
            access: *access,
            fd: opened,
        };
        check(unsafe { libc::syscall(445, guard.0, 1, &rule, 0) })?;
    }
    for port in ports
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>()
    {
        if port == 0 {
            return Err(Error::invalid("invalid TCP ceiling port"));
        }
        let rule = NetRule {
            access: 2,
            port: port as u64,
        };
        check(unsafe { libc::syscall(445, guard.0, 2, &rule, 0) })?;
    }
    check(unsafe { libc::syscall(446, guard.0, 0) })?;
    Ok(abi)
}
const COMMON: &str = "read write readv writev pread64 pwrite64 close close_range fstat newfstatat stat lstat statx lseek open openat access faccessat faccessat2 readlink readlinkat getdents64 mmap mprotect munmap mremap madvise brk rt_sigaction rt_sigprocmask rt_sigreturn sigaltstack futex futex_time64 set_robust_list set_tid_address rseq getrandom clock_gettime clock_gettime64 clock_nanosleep clock_nanosleep_time64 nanosleep getpid getppid gettid getuid geteuid getgid getegid getresuid getresgid getrusage getrlimit sysinfo uname sched_getaffinity sched_yield fcntl fcntl64 dup dup2 dup3 restart_syscall exit exit_group execve fadvise64 fadvise64_64 ftruncate fsync fdatasync poll ppoll ppoll_time64 select pselect6 epoll_create epoll_create1 epoll_ctl epoll_wait epoll_pwait epoll_pwait2 eventfd eventfd2";
fn seccomp(library: &Library, profile: &str, dns: bool) -> Result<()> {
    unsafe {
        let init: libloading::Symbol<unsafe extern "C" fn(u32) -> *mut c_void> = library
            .get(b"seccomp_init")
            .map_err(|_| Error::internal())?;
        let resolve: libloading::Symbol<unsafe extern "C" fn(*const libc::c_char) -> i32> = library
            .get(b"seccomp_syscall_resolve_name")
            .map_err(|_| Error::internal())?;
        let add: libloading::Symbol<
            unsafe extern "C" fn(*mut c_void, u32, i32, u32, *const Compare) -> i32,
        > = library
            .get(b"seccomp_rule_add_array")
            .map_err(|_| Error::internal())?;
        let load: libloading::Symbol<unsafe extern "C" fn(*mut c_void) -> i32> = library
            .get(b"seccomp_load")
            .map_err(|_| Error::internal())?;
        let release: libloading::Symbol<unsafe extern "C" fn(*mut c_void)> = library
            .get(b"seccomp_release")
            .map_err(|_| Error::internal())?;
        let context = init(0x00050000 | libc::EPERM as u32);
        if context.is_null() {
            return Err(Error::internal());
        }
        let allow = 0x7fff0000;
        let rule = |name: &str, cmp: &[Compare], action: u32| -> Result<()> {
            let name = CString::new(name).unwrap();
            let number = resolve(name.as_ptr());
            if number < 0 {
                return Ok(());
            }
            if add(context, action, number, cmp.len() as u32, cmp.as_ptr()) != 0 {
                return Err(Error::internal());
            }
            Ok(())
        };
        let eq = |arg, a| Compare {
            arg,
            op: 4,
            a,
            b: 0,
        };
        let masked = |arg, a, b| Compare { arg, op: 7, a, b };
        let result = (|| {
            for name in COMMON.split_whitespace() {
                rule(name, &[], allow)?;
            }
            rule("prlimit64", &[eq(0, 0), eq(2, 0)], allow)?;
            for op in [0x1002, 0x1003] {
                rule("arch_prctl", &[eq(0, op)], allow)?;
            }
            rule("tgkill", &[eq(0, libc::getpid() as u64)], allow)?;
            rule("clone3", &[], 0x00050000 | libc::ENOSYS as u32)?;
            rule(
                "clone",
                &[masked(
                    0,
                    0x00020000
                        | 0x02000000
                        | 0x04000000
                        | 0x08000000
                        | 0x10000000
                        | 0x20000000
                        | 0x40000000
                        | 0x10000,
                    0x10000,
                )],
                allow,
            )?;
            if profile == "vmm" {
                // The trusted launcher pins its current thread before KVM setup.
                // Keep affinity changes for every other process/thread forbidden.
                rule("sched_setaffinity", &[eq(0, 0)], allow)?;
                // The launcher makes itself non-dumpable (execve made it
                // dumpable again); it may only clear the flag, never set it.
                rule(
                    "prctl",
                    &[eq(0, libc::PR_SET_DUMPABLE as u64), eq(1, 0)],
                    allow,
                )?;
                for name in "accept accept4 connect bind shutdown sendto recvfrom sendmsg recvmsg getsockname getpeername getsockopt setsockopt memfd_create".split_whitespace(){rule(name,&[],allow)?;}
                for (kind, protocols) in [(1, [0, 6]), (2, [0, 17])] {
                    if kind == 2 && !dns {
                        continue;
                    }
                    for protocol in protocols {
                        rule(
                            "socket",
                            &[
                                eq(0, 2),
                                masked(1, !(0x80000 | 0x800), kind),
                                eq(2, protocol),
                            ],
                            allow,
                        )?;
                    }
                }
                // KVM_GET_TSC_KHZ (0xa3) and KVM_{SET,GET}_DEVICE_ATTR (0xe1,
                // 0xe2) calibrate the guest vDSO's clock page and keep every
                // vCPU on one TSC offset: attributes of the VMM's own VM.
                for command in [
                    0x00, 0x01, 0x03, 0x04, 0x05, 0x41, 0x46, 0x47, 0x80, 0x81, 0x82, 0x83, 0x84,
                    0x89, 0x8c, 0x8d, 0x90, 0xa3, 0xa6, 0xa7, 0xe1, 0xe2,
                ] {
                    rule("ioctl", &[masked(1, 0xffff, 0xae00 | command)], allow)?;
                }
                rule("ioctl", &[eq(1, 0x5421)], allow)?;
            }
            if load(context) != 0 {
                return Err(Error::internal());
            }
            Ok(())
        })();
        release(context);
        result
    }
}
fn executable_paths(binary: &Path) -> Result<Vec<(PathBuf, u64)>> {
    let binary = binary.canonicalize()?;
    let mut file = std::fs::File::open(&binary)?;
    let mut header = [0u8; 64];
    file.read_exact(&mut header)?;
    if &header[..6] != b"\x7fELF\x02\x01" {
        return Err(Error::invalid(
            "trusted executable must be ELF64 little-endian",
        ));
    }
    let offset = u64::from_le_bytes(header[32..40].try_into().unwrap());
    let size = u16::from_le_bytes(header[54..56].try_into().unwrap());
    let count = u16::from_le_bytes(header[56..58].try_into().unwrap());
    if size != 56 || count > 128 {
        return Err(Error::invalid("invalid trusted ELF program headers"));
    }
    let mut paths = vec![(binary, 5)];
    for index in 0..count {
        file.seek(SeekFrom::Start(offset + index as u64 * size as u64))?;
        let mut ph = [0u8; 56];
        file.read_exact(&mut ph)?;
        if u32::from_le_bytes(ph[..4].try_into().unwrap()) != 3 {
            continue;
        }
        let position = u64::from_le_bytes(ph[8..16].try_into().unwrap());
        let length = u64::from_le_bytes(ph[32..40].try_into().unwrap());
        if !(1..=4096).contains(&length) {
            return Err(Error::invalid("invalid ELF interpreter"));
        }
        file.seek(SeekFrom::Start(position))?;
        let mut bytes = vec![0; length as usize];
        file.read_exact(&mut bytes)?;
        while bytes.last() == Some(&0) {
            bytes.pop();
        }
        let interpreter = PathBuf::from(String::from_utf8(bytes).map_err(|_| Error::internal())?);
        if !interpreter.is_absolute() {
            return Err(Error::invalid("absolute ELF interpreter required"));
        }
        paths.push((interpreter.canonicalize()?, 5));
    }
    for dir in ["/lib", "/lib64", "/usr/lib", "/usr/lib64"] {
        let path = Path::new(dir);
        if path.exists() {
            paths.push((path.canonicalize()?, 12));
        }
    }
    if Path::new("/etc/ld.so.cache").is_file() {
        paths.push((PathBuf::from("/etc/ld.so.cache"), 4));
    }
    Ok(paths)
}
pub fn apply(
    profile: &str,
    binary: &Path,
    reads: &[PathBuf],
    writes: &[PathBuf],
    ports: &[u16],
    dns: bool,
    kvm: bool,
) -> Result<i64> {
    if !matches!(profile, "compiler" | "vmm") {
        return Err(Error::invalid("invalid confinement profile"));
    }
    if std::fs::read_dir("/proc/self/task")?.count() != 1 {
        return Err(Error::invalid(
            "confinement requires a fresh single-threaded process",
        ));
    }
    let mut paths = executable_paths(binary)?;
    let library = unsafe { Library::new("libseccomp.so.2") }
        .map_err(|_| Error::invalid("libseccomp is required"))?;
    for path in reads {
        paths.push((path.canonicalize()?, 4));
    }
    for path in writes {
        paths.push((path.canonicalize()?, 4 | 2 | (1 << 14)));
    }
    if kvm {
        paths.push((PathBuf::from("/dev/kvm"), 4 | 2 | (1 << 15)));
    }
    privileges()?;
    let abi = landlock(&paths, ports)?;
    seccomp(&library, profile, dns)?;
    Ok(abi)
}
pub fn probe() -> Result<serde_json::Value> {
    let library = unsafe { Library::new("libseccomp.so.2") }
        .map_err(|_| Error::invalid("libseccomp is required"))?;
    privileges()?;
    let abi = landlock(&[], &[])?;
    seccomp(&library, "probe", false)?;
    Ok(serde_json::json!({"version":VERSION,"landlock_abi":abi,"seccomp":true}))
}
