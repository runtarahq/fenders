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
    // Abstract Unix sockets and signals of other domains are both out of
    // reach.
    landlock_scoped(paths, ports, 3)
}
fn landlock_scoped(paths: &[(PathBuf, u64)], ports: &[u16], scoped: u64) -> Result<i64> {
    let abi = abi()?;
    let attr = Ruleset {
        fs: (1 << 16) - 1,
        net: 3,
        scoped,
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
/// Gives this process a core-scheduling cookie of its own, which its threads
/// and children inherit: the kernel then never runs it on one hardware
/// thread of a core while a process with another cookie (another run's VM,
/// or the node itself) runs on the core's other thread. Two guests in ring 0
/// on sibling threads share what the threads share; this is what keeps them
/// off each other's core at the same moment, at the cost of the sibling
/// standing idle when no thread of the same run wants it.
///
/// `Ok(false)` where there is nothing to do it with: a host without
/// simultaneous multithreading, or a kernel built without core scheduling.
pub fn core_alone() -> std::io::Result<bool> {
    // PR_SCHED_CORE, PR_SCHED_CORE_CREATE, this process, its whole thread group.
    if unsafe { libc::prctl(62, 1, 0, 1, 0) } == 0 {
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ENODEV) | Some(libc::EINVAL) => Ok(false),
        _ => Err(error),
    }
}
/// The core-scheduling cookie of `pid` (0 for this thread): 0 when it has none.
pub fn core_cookie(pid: libc::pid_t) -> std::io::Result<u64> {
    let mut cookie = 0u64;
    // PR_SCHED_CORE, PR_SCHED_CORE_GET, the one task.
    match unsafe { libc::prctl(62, 0, pid, 0, &mut cookie as *mut u64) } {
        0 => Ok(cookie),
        _ => Err(std::io::Error::last_os_error()),
    }
}
/// Every KVM `ioctl` request the launcher makes: `linux/kvm.h` on x86-64.
const VMM_KVM_REQUESTS: &[u64] = &[
    0x0000_ae00, // KVM_GET_API_VERSION
    0x0000_ae01, // KVM_CREATE_VM
    0x0000_ae03, // KVM_CHECK_EXTENSION
    0x0000_ae04, // KVM_GET_VCPU_MMAP_SIZE
    0xc008_ae05, // KVM_GET_SUPPORTED_CPUID
    0x0000_ae41, // KVM_CREATE_VCPU
    0x4020_ae46, // KVM_SET_USER_MEMORY_REGION
    0x0000_ae47, // KVM_SET_TSS_ADDR
    0x0000_ae80, // KVM_RUN
    0x8090_ae81, // KVM_GET_REGS
    0x4090_ae82, // KVM_SET_REGS
    0x8138_ae83, // KVM_GET_SREGS
    0x4138_ae84, // KVM_SET_SREGS
    0x4008_ae89, // KVM_SET_MSRS
    0x81a0_ae8c, // KVM_GET_FPU
    0x41a0_ae8d, // KVM_SET_FPU
    0x4008_ae90, // KVM_SET_CPUID2
    0x0000_aea3, // KVM_GET_TSC_KHZ
    0x4068_aea3, // KVM_ENABLE_CAP
    0x8188_aea6, // KVM_GET_XCRS
    0x4188_aea7, // KVM_SET_XCRS
    0x4188_aec6, // KVM_X86_SET_MSR_FILTER
    0x4018_aee1, // KVM_SET_DEVICE_ATTR
    0x4018_aee2, // KVM_GET_DEVICE_ATTR
];
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
                // The launcher's descriptor control is allowed by command.
                if profile == "vmm" && name.starts_with("fcntl") {
                    continue;
                }
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
                // What the launcher calls on sockets, and no more: it accepts
                // with accept4 and sends and receives with sendto and
                // recvfrom, never with accept, sendmsg or recvmsg (which
                // would also pass descriptors).
                for name in "accept4 connect bind shutdown getsockname getpeername memfd_create"
                    .split_whitespace()
                {
                    rule(name, &[], allow)?;
                }
                // And with what arguments. An `int` argument is compared in
                // its low half: the high half of its register is not the
                // caller's to have set.
                let int = |arg, value: u64| masked(arg, 0xffff_ffff, value);
                // Message flags: those a guest may pass (guest_args.inc)
                // and the launcher's own MSG_NOSIGNAL; never MSG_FASTOPEN,
                // which connects, or MSG_OOB and MSG_ERRQUEUE.
                for name in ["sendto", "recvfrom"] {
                    rule(
                        name,
                        &[masked(
                            3,
                            0xffff_ffff & !(0x40 | 0x2 | 0x100 | 0x20 | 0x4000),
                            0,
                        )],
                        allow,
                    )?;
                }
                // Socket options: the ones the launcher reads and sets for
                // itself and passes on for a guest, by level and name.
                const SOCKET: u64 = 1;
                const TCP: u64 = 6;
                for (level, name) in [
                    (SOCKET, 2),  // SO_REUSEADDR
                    (SOCKET, 7),  // SO_SNDBUF
                    (SOCKET, 8),  // SO_RCVBUF
                    (SOCKET, 9),  // SO_KEEPALIVE
                    (SOCKET, 20), // SO_RCVTIMEO
                    (SOCKET, 21), // SO_SNDTIMEO
                    (TCP, 1),     // TCP_NODELAY
                    (TCP, 4),     // TCP_KEEPIDLE
                    (TCP, 5),     // TCP_KEEPINTVL
                    (TCP, 6),     // TCP_KEEPCNT
                ] {
                    rule("setsockopt", &[int(1, level), int(2, name)], allow)?;
                    rule("getsockopt", &[int(1, level), int(2, name)], allow)?;
                }
                for (level, name) in [
                    (SOCKET, 3),  // SO_TYPE
                    (SOCKET, 4),  // SO_ERROR
                    (SOCKET, 30), // SO_ACCEPTCONN
                    (SOCKET, 38), // SO_PROTOCOL
                    (SOCKET, 39), // SO_DOMAIN
                    (0, 2),       // IPPROTO_IP, IP_TTL
                ] {
                    rule("getsockopt", &[int(1, level), int(2, name)], allow)?;
                }
                // Descriptor control: duplicate, and the descriptor and
                // status flags. No owner, signal, lock, lease or pipe size.
                for command in [0, 1, 2, 3, 4, 1030] {
                    rule("fcntl", &[int(1, command)], allow)?;
                }
                // The launcher adds a filter of its own before its guest
                // first runs (runtime/native/running_filter.inc), which
                // refuses what only setting up takes. A filter can be added
                // and never removed: allowing that widens nothing.
                rule("seccomp", &[eq(0, 1)], allow)?;
                rule(
                    "prctl",
                    &[eq(0, libc::PR_SET_NO_NEW_PRIVS as u64), eq(1, 1)],
                    allow,
                )?;
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
                // The launcher's KVM calls, each by its whole request
                // value: direction and size as well as number. Matched on
                // the number alone, 0xa3 was KVM_ENABLE_CAP as much as the
                // KVM_GET_TSC_KHZ that was meant. KVM_GET_TSC_KHZ and
                // KVM_{SET,GET}_DEVICE_ATTR calibrate the guest vDSO's clock
                // page and keep every vCPU on one TSC offset;
                // KVM_X86_SET_MSR_FILTER refuses the guest every MSR.
                // KVM_ENABLE_CAP is here for one capability, set on each
                // vCPU as it is made (holding the guest to its paravirtual
                // feature leaf); the launcher's own filter refuses it, with
                // every other call that makes or shapes a VM, before the
                // guest first runs.
                for request in VMM_KVM_REQUESTS {
                    rule("ioctl", &[eq(1, *request)], allow)?;
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
/// What a run's shim is confined to once it has started its VMM and dropped
/// to the run's uid, for the rest of its life. It relays and reports; it
/// needs to read, to speak to its run channel on `ports`, and to signal its
/// VMM. So:
///
/// - no new privileges, and no capabilities;
/// - Landlock: the filesystem read-only (nothing created, written, removed
///   or executed), TCP connections only to `ports`, no TCP listening, no
///   abstract Unix socket of another domain. Signals are not scoped: its
///   VMM, started before this, is not in its domain;
/// - seccomp: what such a process has no use for is refused (see
///   [`SHIM_REFUSED`]), with every other call allowed. An allowlist, as the
///   compiler and the VMM have, would be tighter; the shim is an async
///   runtime with TLS, and what that calls changes with its dependencies.
///
/// Call it in the shim's single thread, before any other is started.
pub fn apply_shim(ports: &[u16]) -> Result<i64> {
    if std::fs::read_dir("/proc/self/task")?.count() != 1 {
        return Err(Error::invalid(
            "confinement requires a single-threaded process",
        ));
    }
    let library = unsafe { Library::new("libseccomp.so.2") }
        .map_err(|_| Error::invalid("libseccomp is required"))?;
    privileges()?;
    // READ_FILE and READ_DIR, everywhere; nothing else, anywhere.
    let abi = landlock_scoped(&[(PathBuf::from("/"), 4 | 8)], ports, 1)?;
    seccomp_refusing(&library)?;
    Ok(abi)
}

/// System calls a run's shim is refused. Not what it must not reach (its uid
/// and Landlock decide that) but what widens what a process can do to the
/// kernel or to other processes.
const SHIM_REFUSED: &str = "execve execveat ptrace process_vm_readv process_vm_writev kcmp pidfd_getfd process_madvise mount umount2 pivot_root chroot unshare setns bpf perf_event_open userfaultfd io_uring_setup io_uring_enter io_uring_register keyctl add_key request_key init_module finit_module delete_module kexec_load kexec_file_load open_by_handle_at name_to_handle_at swapon swapoff reboot acct quotactl quotactl_fd fanotify_init personality shmget shmat shmdt shmctl semget semop semtimedop semctl msgget msgsnd msgrcv msgctl mq_open mq_unlink mq_timedsend mq_timedreceive mq_notify mq_getsetattr memfd_secret mbind set_mempolicy migrate_pages move_pages setuid setgid setreuid setregid setresuid setresgid setgroups setfsuid setfsgid capset fsopen fsconfig fsmount fspick move_mount open_tree mount_setattr landlock_create_ruleset";

fn seccomp_refusing(library: &Library) -> Result<()> {
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
        // Allowed unless a rule refuses it.
        let context = init(0x7fff0000);
        if context.is_null() {
            return Err(Error::internal());
        }
        let refuse = 0x00050000 | libc::EPERM as u32;
        let rule = |name: &str, cmp: &[Compare], action: u32| -> Result<()> {
            let name = CString::new(name).unwrap();
            let number = resolve(name.as_ptr());
            // A call this architecture or this libseccomp does not know is
            // not one the shim could make by name either.
            if number < 0 {
                return Ok(());
            }
            if add(context, action, number, cmp.len() as u32, cmp.as_ptr()) != 0 {
                return Err(Error::internal());
            }
            Ok(())
        };
        let compare = |arg, op, a, b| Compare { arg, op, a, b };
        let result = (|| {
            for name in SHIM_REFUSED.split_whitespace() {
                rule(name, &[], refuse)?;
            }
            // Threads, not processes in new namespaces: one rule for each
            // namespace flag of `clone`, and `clone3` as unknown, so that
            // libc falls back to `clone`.
            rule("clone3", &[], 0x00050000 | libc::ENOSYS as u32)?;
            for flag in [
                0x00020000u64, // CLONE_NEWNS
                0x02000000,    // CLONE_NEWCGROUP
                0x04000000,    // CLONE_NEWUTS
                0x08000000,    // CLONE_NEWIPC
                0x10000000,    // CLONE_NEWUSER
                0x20000000,    // CLONE_NEWPID
                0x40000000,    // CLONE_NEWNET
                0x00000080,    // CLONE_NEWTIME
            ] {
                rule("clone", &[compare(0, 7, flag, flag)], refuse)?;
            }
            // Sockets: Unix, IPv4, IPv6, and netlink's routing protocol,
            // which the resolver asks for the host's addresses. Families 3
            // to 9, and every family over IPv6 but that one, are refused.
            for family in 3..=9u64 {
                rule("socket", &[compare(0, 4, family, 0)], refuse)?;
            }
            for family in 11..=15u64 {
                rule("socket", &[compare(0, 4, family, 0)], refuse)?;
            }
            rule("socket", &[compare(0, 5, 17, 0)], refuse)?;
            rule(
                "socket",
                &[compare(0, 4, 16, 0), compare(2, 1, 0, 0)],
                refuse,
            )?;
            if load(context) != 0 {
                return Err(Error::internal());
            }
            Ok(())
        })();
        release(context);
        result
    }
}

pub fn probe() -> Result<serde_json::Value> {
    let library = unsafe { Library::new("libseccomp.so.2") }
        .map_err(|_| Error::invalid("libseccomp is required"))?;
    privileges()?;
    let abi = landlock(&[], &[])?;
    seccomp(&library, "probe", false)?;
    Ok(serde_json::json!({"version":VERSION,"landlock_abi":abi,"seccomp":true}))
}
