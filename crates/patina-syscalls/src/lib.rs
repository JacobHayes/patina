//! Native-target syscall identity and reviewed runtime support metadata.
//! No runtime dependency, source parser, build-time fetch, or foreign inventory.
#[cfg(target_os = "macos")]
mod darwin;
pub mod generated;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub use generated::darwin_aarch64::{ENTRIES, Syscall};
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use generated::linux_aarch64::{ENTRIES, Syscall};
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub use generated::linux_x86_64::{ENTRIES, Syscall};
#[cfg(not(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    all(target_os = "macos", target_arch = "aarch64")
)))]
compile_error!("syscall registry requires Linux x86_64/aarch64 or Darwin aarch64");
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub use linux::SYSCALLS;
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinuxEntry {
    pub id: Syscall,
    pub nr: u32,
    pub abi: &'static str,
    pub name: &'static str,
    pub entry: Option<&'static str>,
}

#[cfg(target_os = "linux")]
impl LinuxEntry {
    pub fn is_implemented(&self) -> bool {
        self.entry.is_some()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Variant {
    pub entry: &'static str,
    pub condition: Option<&'static str>,
    /// A source declaration, never an observed errno or runtime disposition.
    pub table_status: &'static str,
    pub declaration: &'static str,
}

#[cfg(target_os = "macos")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DarwinEntry {
    pub id: Syscall,
    pub namespace: &'static str,
    pub nr: i64,
    pub subcode: Option<u32>,
    pub variants: &'static [Variant],
}

/// The Linux kernel release whose ABI the virtual kernel declares: the pinned
/// kernel, Ubuntu 24.04's GA kernel (Ubuntu's 6.8 build, not upstream 6.8),
/// whose answers the conformance scenarios assert. A number the vendored
/// table lists but that first appeared in a newer release is
/// [`Disposition::Absent`] — `ENOSYS`, byte-identical to what a kernel of this
/// release answers. Raising it is one explicit, wholesale migration: it moves
/// every row whose `since` it passes back to its family's arc (the rule test
/// names them), and every scenario's answers to the new kernel's.
pub const VIRTUAL_ABI: &str = "6.8";

/// The virtual kernel's configuration: the sysctls whose values decide what
/// the rows answer, fixed as part of the pinned kernel ([`VIRTUAL_ABI`]) and
/// never read from the host. The values are the defaults of Ubuntu 24.04's
/// kernel (upstream's where Ubuntu keeps them). A conformance scenario whose answers depend on one declares
/// a need that the host restricts the same way (`Need::RestrictedBpf`,
/// `Need::RestrictedPerf`, `Need::RestrictedUserfaultfd`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KernelConfig {
    /// `kernel.perf_event_paranoid`. At 4 or more (Ubuntu's patch) every
    /// `perf_event_open` needs `CAP_PERFMON` or `CAP_SYS_ADMIN`, refused as
    /// `EACCES` after the flags and before the attribute is read.
    pub perf_event_paranoid: i32,
    /// `kernel.unprivileged_bpf_disabled`. Nonzero refuses BPF map creation
    /// and program loading (`EPERM`) to a caller without `CAP_BPF` or
    /// `CAP_SYS_ADMIN`, after their argument checks.
    pub unprivileged_bpf_disabled: u32,
    /// `vm.unprivileged_userfaultfd`. Off, handling kernel faults needs
    /// `CAP_SYS_PTRACE` (`EPERM`, before the flags are checked).
    pub unprivileged_userfaultfd: bool,
    /// `kernel.yama.ptrace_scope`. 1 lets a tracer attach only to its
    /// descendants (the guest has none); 3 refuses every attach.
    pub yama_ptrace_scope: u32,
    /// `kernel.unprivileged_userns_clone` (Ubuntu's patch). Off, a new user
    /// namespace needs `CAP_SYS_ADMIN` (`EPERM`) before `unshare`'s flags
    /// are checked; on, the flags come first.
    pub unprivileged_userns_clone: bool,
    /// `user.max_user_namespaces`. 0: the virtual credential gets no user
    /// namespace (`unshare(CLONE_NEWUSER)` is `ENOSPC`).
    pub max_user_namespaces: u32,
    /// `kernel.dmesg_restrict`. On, every `syslog` action needs
    /// `CAP_SYSLOG` (`EPERM`, before the action is looked at).
    pub dmesg_restrict: bool,
    /// `fs.nr_open`: the highest `RLIMIT_NOFILE` a hard limit may name.
    pub nr_open: u64,
    /// `fs.pipe-max-size`: the largest pipe buffer `F_SETPIPE_SZ` gives a
    /// caller without `CAP_SYS_RESOURCE` (`EPERM` past it).
    pub pipe_max_size: u64,
    /// `net.core.somaxconn`: the most a `listen` backlog is taken as.
    pub somaxconn: i32,
    /// `kernel.shmmni` and `kernel.shmmax`: the most shared memory segments,
    /// and the largest one.
    pub shmmni: i32,
    pub shmmax: u64,
    /// `kernel.sem`'s `SEMMSL`, `SEMOPM` and `SEMMNI`: the most semaphores
    /// in a set, operations in one `semop`, and sets.
    pub semmsl: i32,
    pub semopm: u32,
    pub semmni: i32,
    /// `kernel.msgmni`, `kernel.msgmax` and `kernel.msgmnb`: the most message
    /// queues, the largest message, and a new queue's byte limit.
    pub msgmni: i32,
    pub msgmax: u32,
    pub msgmnb: u32,
    /// The Landlock ABI version `landlock_create_ruleset` reports (4 on
    /// 6.7–6.9: network port rules), and the errata mask Ubuntu's backport
    /// of `LANDLOCK_CREATE_RULESET_ERRATA` (6.15's) reports.
    pub landlock_abi: i64,
    pub landlock_errata: i64,
    /// The Linux Security Modules the kernel runs, as `lsm_list_modules`
    /// lists their ids, in the order they initialized. None of them keeps
    /// a process attribute (`LSM_ATTR_*`): no `getselfattr` or
    /// `setselfattr` hook.
    pub lsm_modules: &'static [u64],
}

/// The one configuration the virtual kernel runs with; see [`KernelConfig`].
pub const KERNEL_CONFIG: KernelConfig = KernelConfig {
    // Ubuntu's default (upstream's is 2).
    perf_event_paranoid: 4,
    // `CONFIG_BPF_UNPRIV_DEFAULT_OFF`: only root may lower it, to 1.
    unprivileged_bpf_disabled: 2,
    unprivileged_userfaultfd: false,
    // Ubuntu's default.
    yama_ptrace_scope: 1,
    // Ubuntu's default.
    unprivileged_userns_clone: true,
    // Ubuntu 24.04 allows single-threaded callers a user namespace (then
    // restricts it through AppArmor); the virtual machine declares none.
    max_user_namespaces: 0,
    // Ubuntu's default.
    dmesg_restrict: true,
    nr_open: 1 << 20,
    pipe_max_size: 1 << 20,
    somaxconn: 4096,
    shmmni: 4096,
    // `ULONG_MAX - (1UL << 24)`.
    shmmax: u64::MAX - (1 << 24),
    semmsl: 32_000,
    semopm: 500,
    semmni: 32_000,
    msgmni: 32_000,
    msgmax: 8192,
    msgmnb: 16_384,
    landlock_abi: 4,
    // Errata 1 and 3, as 6.8.0-139 answers.
    landlock_errata: 5,
    // `capability` (100) first, then `landlock` (110) and `yama` (105):
    // Ubuntu's `lsm=` order without lockdown, integrity or AppArmor, which
    // are host policy.
    lsm_modules: &[100, 110, 105],
};

/// The Darwin kernel release the virtual machine reports on macOS (`uname`'s
/// release, and inside its version): Darwin 25.0.0, the macOS 26.0 kernel,
/// built from [`DARWIN_XNU`], the xnu the vendored Darwin tables
/// (`generated::SOURCES`) come from. A model constant like [`VIRTUAL_ABI`],
/// never the host's release.
pub const DARWIN_RELEASE: &str = "25.0.0";
/// The xnu build of [`DARWIN_RELEASE`], named in the Darwin `uname` version.
pub const DARWIN_XNU: &str = "xnu-12377.1.9";

/// The user the virtual kernel runs the guest as: an ordinary non-root user
/// that owns every entry of the deterministic filesystem. On Linux it is the
/// uid of the shim's virtual credential, which the id rows, `st_uid` and
/// `chown` read; on macOS, which has no credential yet, those read it
/// directly.
pub const IDENTITY_UID: u32 = 1000;
/// The guest process: the child of the pid namespace's init
/// ([`INIT_PID`]), leading its own process group in init's session, as a
/// program a container's init started. Its main thread's id is its pid.
pub const IDENTITY_PID: u32 = 2;
/// The pid namespace's init: the guest's parent, leader of process group 1
/// and session 1, running as root (uid and gid 0, every capability) as a
/// machine's init does, so the guest may not signal it (but for `SIGCONT`
/// within its session, which init, with no signal handlers, drops), reach it
/// in ptrace mode, change its scheduling, or read or change its limits;
/// asleep (its CPU time is its startup's).
pub const INIT_PID: u32 = 1;
/// The group of [`IDENTITY_UID`]; see there.
pub const IDENTITY_GID: u32 = 1000;
/// The virtual machine's node name: what `uname` reports and `gethostname`
/// answers.
pub const IDENTITY_HOSTNAME: &str = "patina";
/// [`IDENTITY_UID`]'s home directory, as its [`PASSWD`] entry names it. The
/// native filesystem image holds it (mode 0750 under a 0755 `/home`, as the
/// pinned system's image has them), so the home `getpwuid_r` answers exists.
pub const IDENTITY_HOME: &str = "/home/ubuntu";

/// The virtual machine's passwd database, what the libc passwd readers
/// (`getpwuid_r`, the `getpwent` walk) answer from, in file order: the
/// pinned system's container image's `/etc/passwd` (`ubuntu:24.04`), whose
/// uid 1000 is [`IDENTITY_UID`]'s entry and whose first entry is root.
pub const PASSWD: &[&core::ffi::CStr] = &[
    c"root:x:0:0:root:/root:/bin/bash",
    c"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
    c"bin:x:2:2:bin:/bin:/usr/sbin/nologin",
    c"sys:x:3:3:sys:/dev:/usr/sbin/nologin",
    c"sync:x:4:65534:sync:/bin:/bin/sync",
    c"games:x:5:60:games:/usr/games:/usr/sbin/nologin",
    c"man:x:6:12:man:/var/cache/man:/usr/sbin/nologin",
    c"lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin",
    c"mail:x:8:8:mail:/var/mail:/usr/sbin/nologin",
    c"news:x:9:9:news:/var/spool/news:/usr/sbin/nologin",
    c"uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin",
    c"proxy:x:13:13:proxy:/bin:/usr/sbin/nologin",
    c"www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
    c"backup:x:34:34:backup:/var/backups:/usr/sbin/nologin",
    c"list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin",
    c"irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin",
    c"_apt:x:42:65534::/nonexistent:/usr/sbin/nologin",
    c"nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin",
    c"ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash",
];

/// `6.8.0-139-generic` → `(6, 8, 0)`; `6.10` → `(6, 10, 0)`. `None` when the
/// text does not start with a dotted release number.
pub fn parse_release(text: &str) -> Option<(u64, u64, u64)> {
    let numeric: String = text
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    let mut parts = numeric.split('.').filter(|part| !part.is_empty());
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next().map_or(Some(0), |part| part.parse().ok())?;
    let patch = parts.next().map_or(Some(0), |part| part.parse().ok())?;
    Some((major, minor, patch))
}

/// Whether a row first appearing in kernel `since` is outside the virtual ABI
/// level: `since` is newer than [`VIRTUAL_ABI`]. An unparsable `since` is
/// treated as newer (fail closed: a row nobody can date is not claimed).
pub fn newer_than_virtual_abi(since: &str) -> bool {
    match (parse_release(since), parse_release(VIRTUAL_ABI)) {
        (Some(since), Some(virtual_abi)) => since > virtual_abi,
        _ => true,
    }
}

/// An operating system whose syscall table the registry keys rows by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Os {
    Linux,
    Darwin,
}

impl Os {
    pub fn name(self) -> &'static str {
        match self {
            Os::Linux => "linux",
            Os::Darwin => "darwin",
        }
    }

    /// The OS this build runs on.
    pub const fn host() -> Self {
        if cfg!(target_os = "macos") {
            Os::Darwin
        } else {
            Os::Linux
        }
    }
}

/// An architecture with its own syscall numbering.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arch {
    X86_64,
    Aarch64,
}

impl Arch {
    pub fn name(self) -> &'static str {
        match self {
            Arch::X86_64 => "x86_64",
            Arch::Aarch64 => "aarch64",
        }
    }

    /// The architecture this build runs on.
    pub const fn host() -> Self {
        if cfg!(target_arch = "aarch64") {
            Arch::Aarch64
        } else {
            Arch::X86_64
        }
    }
}

/// The family a syscall row belongs to. Families group rows for display and
/// name the arc (`SyscallRow::closes_in`) that models the ones not yet modeled.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Family {
    /// Paths, metadata, directory namespace, xattrs, sync, file copies.
    Fs,
    /// Descriptor I/O and descriptor-table operations.
    FdIo,
    /// Process-local memory management.
    Mem,
    /// Clocks, sleeps, timers.
    Time,
    /// Scheduling parameters, affinity, priorities, CPU identity.
    Sched,
    /// Process identity: pids, credentials, limits, usage, uname/hostname.
    Identity,
    /// Signal generation, delivery, masks, dispositions, signal fds.
    Signal,
    /// Thread-local kernel state (tid address, arch state).
    Thread,
    /// Futex-family synchronization and restartable sequences.
    Sync,
    /// Process lifecycle: fork/exec/wait/clone-as-process and pidfds.
    Process,
    /// Kernel configuration and privileged operations.
    Privileged,
    /// Sockets and the virtual network.
    Net,
    /// Readiness multiplexing and fs event notification.
    Readiness,
    /// Cross-process IPC (SysV, POSIX mq) modeled with single-process semantics.
    Ipc,
    /// Seeded entropy.
    Entropy,
    /// Submission/completion rings (Linux AIO, io_uring).
    AsyncIo,
    /// Numbers the kernel lists without an implementation (answers `ENOSYS`).
    Removed,
}

impl Family {
    pub fn name(self) -> &'static str {
        match self {
            Family::Fs => "fs",
            Family::FdIo => "fd_io",
            Family::Mem => "mem",
            Family::Time => "time",
            Family::Sched => "sched",
            Family::Identity => "identity",
            Family::Signal => "signal",
            Family::Thread => "thread",
            Family::Sync => "sync",
            Family::Process => "process",
            Family::Privileged => "privileged",
            Family::Net => "net",
            Family::Readiness => "readiness",
            Family::Ipc => "ipc",
            Family::Entropy => "entropy",
            Family::AsyncIo => "async_io",
            Family::Removed => "removed",
        }
    }
}

/// What the runtime does with a syscall number today. The dispositions are the
/// design's (docs/arcs/syscall-conformance.md §3); each names the gate that
/// keeps it honest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disposition {
    /// Routed to a runtime entry; semantics host-checked by a conformance
    /// scenario.
    Modeled,
    /// Process-local memory only, passed to the host kernel through the glibc
    /// `syscall(2)` host alias.
    Passthrough,
    /// A deterministic fixed answer (pids, uids, no-op successes).
    Constant(i64),
    /// A real kernel outcome callers already handle: `-errno`, optionally with
    /// a bound handler that also prints the byte-identical C deny diagnostic.
    SoftDeny(i32),
    /// A named, deterministic abort. The class is one of [`TRAP_CLASSES`].
    Trap(&'static str),
    /// Not in this kernel ABI: `ENOSYS`, byte-identical to what a
    /// [`VIRTUAL_ABI`] kernel answers. Today exactly the rows whose `since` is
    /// newer than the virtual ABI level; the signals arc flips the `Removed`
    /// rows to it too.
    Absent,
}

/// Process lifecycle: a second process is outside the scheduler, the trace and
/// the fs model; the guest's contract is one process (§7).
pub const TRAP_PROCESS: &str = "process";
/// Kernel configuration / privileged: changes kernel state or needs `CAP_*`;
/// nothing a DST guest legitimately needs (§7).
pub const TRAP_PRIVILEGED: &str = "privileged";
/// Not modeled yet; `closes_in` names the arc that models it.
pub const TRAP_UNMODELED: &str = "unmodeled";
/// A number the kernel lists without an implementation; answers `ENOSYS`
/// natively. Aborts today, becomes `Absent` in the signals arc.
pub const TRAP_REMOVED: &str = "removed";
/// Every trap class a row may name.
pub const TRAP_CLASSES: &[&str] = &[TRAP_PROCESS, TRAP_PRIVILEGED, TRAP_UNMODELED, TRAP_REMOVED];

impl Disposition {
    /// The disposition's kind, as printed by `cargo patina syscalls`.
    pub fn kind(&self) -> &'static str {
        match self {
            Disposition::Modeled => "modeled",
            Disposition::Passthrough => "passthrough",
            Disposition::Constant(_) => "constant",
            Disposition::SoftDeny(_) => "soft-deny",
            Disposition::Trap(_) => "trap",
            Disposition::Absent => "absent",
        }
    }

    /// Whether the dispatcher routes this row to a bound handler (as opposed to
    /// answering it generically from the row alone).
    pub const fn is_routed(&self) -> bool {
        matches!(self, Disposition::Modeled | Disposition::Passthrough)
    }

    /// Whether a handler binding is permitted for this row: routed rows require
    /// one; `Constant`/`SoftDeny` may carry one (a diagnostic-printing deny, a
    /// constant that the C interposer computes); `Trap`/`Absent` never do.
    pub const fn may_bind(&self) -> bool {
        !matches!(self, Disposition::Trap(_) | Disposition::Absent)
    }

    /// Human rendering, e.g. `constant(1000)`, `soft-deny(ENOSYS)`,
    /// `trap(process)`.
    pub fn render(&self) -> String {
        match self {
            Disposition::Modeled | Disposition::Passthrough | Disposition::Absent => {
                self.kind().to_string()
            }
            Disposition::Constant(value) => format!("constant({value})"),
            Disposition::SoftDeny(errno) => format!("soft-deny({})", errno_name(*errno)),
            Disposition::Trap(class) => format!("trap({class})"),
        }
    }
}

/// The symbolic name of an errno a `SoftDeny` row answers with. Only the
/// values rows use are named; a new one is added here with its row.
pub fn errno_name(errno: i32) -> String {
    match errno {
        1 => "EPERM".to_string(),
        3 => "ESRCH".to_string(),
        10 => "ECHILD".to_string(),
        22 => "EINVAL".to_string(),
        38 => "ENOSYS".to_string(),
        95 => "EOPNOTSUPP".to_string(),
        other => format!("errno {other}"),
    }
}

/// A Linux capability (`include/uapi/linux/capability.h`), numbered as the
/// kernel numbers it: a privileged row names the ones its kernel code checks
/// ([`SyscallRow::capabilities`]), and the virtual credential's sets are
/// masks of their bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Capability {
    Chown = 0,
    DacOverride = 1,
    DacReadSearch = 2,
    Fowner = 3,
    Fsetid = 4,
    Kill = 5,
    Setgid = 6,
    Setuid = 7,
    Setpcap = 8,
    LinuxImmutable = 9,
    NetBindService = 10,
    NetBroadcast = 11,
    NetAdmin = 12,
    NetRaw = 13,
    IpcLock = 14,
    IpcOwner = 15,
    SysModule = 16,
    SysRawio = 17,
    SysChroot = 18,
    SysPtrace = 19,
    SysPacct = 20,
    SysAdmin = 21,
    SysBoot = 22,
    SysNice = 23,
    SysResource = 24,
    SysTime = 25,
    SysTtyConfig = 26,
    Mknod = 27,
    Lease = 28,
    AuditWrite = 29,
    AuditControl = 30,
    Setfcap = 31,
    MacOverride = 32,
    MacAdmin = 33,
    Syslog = 34,
    WakeAlarm = 35,
    BlockSuspend = 36,
    AuditRead = 37,
    Perfmon = 38,
    Bpf = 39,
    CheckpointRestore = 40,
}

impl Capability {
    /// `CAP_LAST_CAP` of the [`VIRTUAL_ABI`] kernel.
    pub const LAST: Capability = Capability::CheckpointRestore;
    /// Every capability the virtual kernel knows, as a set: the bounding set
    /// a process starts with.
    pub const ALL: u64 = (1u64 << (Capability::LAST as u8 + 1)) - 1;

    /// The capability's bit in a capability set.
    pub const fn bit(self) -> u64 {
        1u64 << self as u8
    }

    /// The kernel's name, e.g. `CAP_SYS_ADMIN`.
    pub fn name(self) -> &'static str {
        match self {
            Capability::Chown => "CAP_CHOWN",
            Capability::DacOverride => "CAP_DAC_OVERRIDE",
            Capability::DacReadSearch => "CAP_DAC_READ_SEARCH",
            Capability::Fowner => "CAP_FOWNER",
            Capability::Fsetid => "CAP_FSETID",
            Capability::Kill => "CAP_KILL",
            Capability::Setgid => "CAP_SETGID",
            Capability::Setuid => "CAP_SETUID",
            Capability::Setpcap => "CAP_SETPCAP",
            Capability::LinuxImmutable => "CAP_LINUX_IMMUTABLE",
            Capability::NetBindService => "CAP_NET_BIND_SERVICE",
            Capability::NetBroadcast => "CAP_NET_BROADCAST",
            Capability::NetAdmin => "CAP_NET_ADMIN",
            Capability::NetRaw => "CAP_NET_RAW",
            Capability::IpcLock => "CAP_IPC_LOCK",
            Capability::IpcOwner => "CAP_IPC_OWNER",
            Capability::SysModule => "CAP_SYS_MODULE",
            Capability::SysRawio => "CAP_SYS_RAWIO",
            Capability::SysChroot => "CAP_SYS_CHROOT",
            Capability::SysPtrace => "CAP_SYS_PTRACE",
            Capability::SysPacct => "CAP_SYS_PACCT",
            Capability::SysAdmin => "CAP_SYS_ADMIN",
            Capability::SysBoot => "CAP_SYS_BOOT",
            Capability::SysNice => "CAP_SYS_NICE",
            Capability::SysResource => "CAP_SYS_RESOURCE",
            Capability::SysTime => "CAP_SYS_TIME",
            Capability::SysTtyConfig => "CAP_SYS_TTY_CONFIG",
            Capability::Mknod => "CAP_MKNOD",
            Capability::Lease => "CAP_LEASE",
            Capability::AuditWrite => "CAP_AUDIT_WRITE",
            Capability::AuditControl => "CAP_AUDIT_CONTROL",
            Capability::Setfcap => "CAP_SETFCAP",
            Capability::MacOverride => "CAP_MAC_OVERRIDE",
            Capability::MacAdmin => "CAP_MAC_ADMIN",
            Capability::Syslog => "CAP_SYSLOG",
            Capability::WakeAlarm => "CAP_WAKE_ALARM",
            Capability::BlockSuspend => "CAP_BLOCK_SUSPEND",
            Capability::AuditRead => "CAP_AUDIT_READ",
            Capability::Perfmon => "CAP_PERFMON",
            Capability::Bpf => "CAP_BPF",
            Capability::CheckpointRestore => "CAP_CHECKPOINT_RESTORE",
        }
    }
}

#[cfg(target_os = "linux")]
/// One syscall number (per arch) and what the runtime does with it.
#[derive(Clone, Copy, Debug)]
pub struct SyscallRow {
    pub id: Syscall,
    /// The kernel's name for the number (the table's name column).
    pub name: &'static str,
    pub nr: u32,
    pub family: Family,
    pub disposition: Disposition,
    /// Why this disposition: what is modeled, or why the row stays a trap.
    pub reasoning: &'static str,
    /// The arc (docs/arcs/syscall-conformance.md §6) that changes this row's
    /// disposition, or `None` when the disposition is final.
    pub closes_in: Option<&'static str>,
    /// The first mainline kernel release carrying this number, when it is
    /// newer than the table's baseline (docs/arcs/syscall-conformance.md; the
    /// prior-art drift table). `None` means the number predates every host the
    /// harness runs on. A `since` newer than [`VIRTUAL_ABI`] makes the row
    /// `Absent`.
    pub since: Option<&'static str>,
    /// The capabilities the kernel's code for this row checks (`capable`,
    /// `ns_capable`), primary first. The dispatcher answers such a row from
    /// the virtual credential: the checks the kernel makes before the
    /// capability, then the kernel's refusal when the credential lacks it,
    /// and a named fatal when it holds one whose effect is not modeled.
    pub capabilities: &'static [Capability],
}

#[cfg(target_os = "linux")]
impl SyscallRow {
    /// Record the first kernel release carrying this number.
    pub const fn since(mut self, release: &'static str) -> Self {
        self.since = Some(release);
        self
    }

    /// Record the capabilities the row's kernel code checks.
    pub const fn capabilities(mut self, capabilities: &'static [Capability]) -> Self {
        self.capabilities = capabilities;
        self
    }

    /// Whether the row's `since` places it outside the virtual ABI level, in
    /// which case its disposition must be `Absent` (the rule test pins it).
    pub fn absent_by_abi(&self) -> bool {
        self.since.is_some_and(newer_than_virtual_abi)
    }
}

/// The row for a syscall name, if any.
#[cfg(target_os = "linux")]
pub fn syscall(name: &str) -> Option<&'static SyscallRow> {
    SYSCALLS.iter().find(|row| row.name == name)
}

/// The rows an arch dispatches, sorted by that arch's number.
#[cfg(target_os = "linux")]
pub fn rows_for() -> Vec<(u32, &'static SyscallRow)> {
    let mut rows: Vec<(u32, &'static SyscallRow)> =
        SYSCALLS.iter().map(|row| (row.id.number(), row)).collect();
    rows.sort_by_key(|(nr, _)| *nr);
    rows
}

pub mod cancellation;
pub mod symbols;
pub use symbols::SYMBOLS;
/// Which platform's shim objects define a symbol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Platform {
    Linux,
    Darwin,
    Both,
}

impl Platform {
    pub fn defines_on(self, os: Os) -> bool {
        matches!(
            (self, os),
            (Platform::Both, _) | (Platform::Linux, Os::Linux) | (Platform::Darwin, Os::Darwin)
        )
    }

    pub fn name(self) -> &'static str {
        match self {
            Platform::Linux => "linux",
            Platform::Darwin => "darwin",
            Platform::Both => "both",
        }
    }
}

/// The syscall rows a libc/pthread symbol serves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Serves {
    /// The wrapper (or the model behind it) is the libc face of these Linux
    /// rows — the semantic operation, not a claim that glibc issues exactly
    /// that instruction.
    Syscalls(&'static [&'static str]),
    /// A Darwin-only symbol's explicit BSD, Mach, or ARM-special entry names.
    /// These semantic associations do not claim raw-entry interposition.
    Darwin(&'static [&'static str]),
    /// The libc `syscall(2)` vehicle: every row, through the dispatcher.
    Dispatcher,
    /// Pure libc-side state or a control-plane entry; no kernel row.
    LibcOnly,
}

impl Serves {
    pub fn render(&self) -> String {
        match self {
            Serves::Syscalls(rows) => rows.join(","),
            Serves::Darwin(rows) => rows.join(","),
            Serves::Dispatcher => "*".to_string(),
            Serves::LibcOnly => "libc-only".to_string(),
        }
    }
}

/// What the shim's definition of a symbol does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SymbolStatus {
    /// The full contract is modeled deterministically.
    Modeled,
    /// A subset is modeled; the rest answers a loud deterministic refusal
    /// (`ENOSYS` + diagnostic, or `EINVAL`) without reaching the host.
    Partial,
    /// A deny-trap: linking is inert, the first call aborts naming the symbol.
    /// The class is the audit's escape category for the surface
    /// (`process`, `macos-framework`, `host-introspection`).
    Deny(&'static str),
    /// Shim control plane: not a libc contract (startup, the trace channel,
    /// the SUD/TSC arming entries, weak-hook stubs, sentinel data).
    ControlPlane,
    /// A known ABI spelling the shim does NOT define (a fortified or
    /// large-file alias, a wrapper with a raw row but no C face). A guest
    /// importing it reaches the host or is audit-refused; enumerated so the
    /// gap is visible, and gated so a definition cannot appear unnoticed.
    Absent,
}

impl SymbolStatus {
    pub fn render(&self) -> String {
        match self {
            SymbolStatus::Modeled => "modeled".to_string(),
            SymbolStatus::Partial => "partial".to_string(),
            SymbolStatus::Deny(class) => format!("deny({class})"),
            SymbolStatus::ControlPlane => "control-plane".to_string(),
            SymbolStatus::Absent => "absent".to_string(),
        }
    }
}

/// One public symbol the shim objects define (or, for `Absent`, deliberately
/// do not), mapped onto the syscall rows it serves.
#[derive(Clone, Copy, Debug)]
pub struct SymbolRow {
    pub name: &'static str,
    pub platform: Platform,
    pub serves: Serves,
    pub status: SymbolStatus,
}

/// The symbol rows that serve a syscall name.
pub fn symbols_serving(name: &str) -> Vec<&'static SymbolRow> {
    SYMBOLS
        .iter()
        .filter(|symbol| match symbol.serves {
            Serves::Syscalls(ids) => ids.contains(&name),
            Serves::Dispatcher => true,
            Serves::Darwin(_) | Serves::LibcOnly => false,
        })
        .collect()
}

/// A symbol is part of the runtime's own C ABI (declared in
/// `include/patina_native.h` and defined in Rust or in the C slices) rather
/// than a libc contract, and is excluded from the symbol rows by this prefix
/// rule. The object scan checks every other defined public symbol has a row.
pub fn is_control_plane_abi(symbol: &str) -> bool {
    symbol.starts_with("patina_") || symbol.starts_with("PATINA_")
}

#[cfg(all(test, target_os = "linux"))]
mod tests;
