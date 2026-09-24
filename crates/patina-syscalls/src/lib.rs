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

/// The Linux kernel release whose ABI the virtual kernel declares. A number the
/// vendored table lists but that first appeared in a newer release is
/// [`Disposition::Absent`] — `ENOSYS`, byte-identical to what a kernel of this
/// release answers. Raising it moves every row whose `since` it passes back to
/// its family's arc (the rule test names them).
pub const VIRTUAL_ABI: &str = "6.8";

/// The one identity the virtual kernel runs the guest as: an ordinary
/// non-root user that owns every entry of the deterministic filesystem. The
/// single source `getuid`/`geteuid` (the `Constant` rows below and the C
/// interposers) and every `st_uid` are answered from, and what `chown` is a
/// comparison against. The identity arc makes it a `--host-*` knob.
pub const IDENTITY_UID: u32 = 1000;
/// The guest process: the child of the pid namespace's init
/// ([`INIT_PID`]), leading its own process group in init's session, as a
/// program a container's init started. Its main thread's id is its pid.
pub const IDENTITY_PID: u32 = 2;
/// The pid namespace's init: the guest's parent, leader of process group 1
/// and session 1, running as [`IDENTITY_UID`] with no signal handlers (so
/// every signal the guest sends it is dropped), not dumpable (so ptrace-mode
/// access to it is refused), and asleep (its CPU time is its startup's).
pub const INIT_PID: u32 = 1;
/// The group of [`IDENTITY_UID`]; see there.
pub const IDENTITY_GID: u32 = 1000;
/// The virtual machine's node name: what `uname` reports and `gethostname`
/// answers.
pub const IDENTITY_HOSTNAME: &str = "patina";

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
/// Final: host-only kernel frame/restart protocols have no guest raw ABI.
pub const TRAP_SIGNAL_ABI: &str = "signal-abi";
/// Not modeled yet; `closes_in` names the arc that models it.
pub const TRAP_UNMODELED: &str = "unmodeled";
/// A number the kernel lists without an implementation; answers `ENOSYS`
/// natively. Aborts today, becomes `Absent` in the signals arc.
pub const TRAP_REMOVED: &str = "removed";
/// Every trap class a row may name.
pub const TRAP_CLASSES: &[&str] = &[
    TRAP_PROCESS,
    TRAP_PRIVILEGED,
    TRAP_SIGNAL_ABI,
    TRAP_UNMODELED,
    TRAP_REMOVED,
];

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
}

#[cfg(target_os = "linux")]
impl SyscallRow {
    /// Record the first kernel release carrying this number.
    pub const fn since(mut self, release: &'static str) -> Self {
        self.since = Some(release);
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
