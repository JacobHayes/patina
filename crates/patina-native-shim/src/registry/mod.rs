//! The syscall registry: every kernel syscall number the shim's platforms
//! dispatch, its disposition, and the libc/pthread symbol layer mapped onto
//! those rows. Registry as code, not a static doc (docs/arcs/
//! syscall-conformance.md §3): these rows drive the SUD dispatcher
//! (`sud::dispatch` is generated from them, so a number without a row cannot be
//! routed), `cargo patina syscalls`, and the completeness gates against the
//! vendored upstream tables under `abi/`.
//!
//! Rows are data. The dispositions here encode what the runtime does TODAY; a
//! builder that models a row flips its disposition in the same change that
//! lands the handler and the conformance probe, and the gates hold the three
//! together:
//!
//! * (a) every number in the vendored table for an arch has exactly one row,
//!   and (b) every row's numbers exist in the table (`syscalls::tests`);
//! * every row with a routed disposition has exactly one handler binding and
//!   every `Trap`/`Absent` row has none (a compile-time check in `sud`);
//! * (d) every [`SymbolRow`] names a symbol the compiled shim objects define
//!   (or, for `Absent`, provably do not) and every defined public symbol has a
//!   row; (e) `patina-target`'s classification lists agree with the symbol
//!   rows (`cargo-patina/tests/syscall_registry.rs`);
//! * (c) every `Modeled` row names a probe in the conformance testbed — the
//!   `probe` field exists for it; the gate lands with the testbed.

pub mod symbols;
pub mod syscalls;
pub mod table;
#[cfg(test)]
mod tests;

pub use symbols::SYMBOLS;
pub use syscalls::SYSCALLS;

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

    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "linux" => Some(Os::Linux),
            "darwin" | "macos" => Some(Os::Darwin),
            _ => None,
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

    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "x86_64" | "x86-64" | "amd64" => Some(Arch::X86_64),
            "aarch64" | "arm64" => Some(Arch::Aarch64),
            _ => None,
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

    pub const ALL: &'static [Arch] = &[Arch::X86_64, Arch::Aarch64];
}

/// A syscall's number per architecture. `None` means the arch has no such
/// number (the x86_64 legacy non-`*at` forms do not exist on arm64).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Nr {
    pub x86_64: Option<u32>,
    pub aarch64: Option<u32>,
}

impl Nr {
    pub const fn for_arch(&self, arch: Arch) -> Option<u32> {
        match arch {
            Arch::X86_64 => self.x86_64,
            Arch::Aarch64 => self.aarch64,
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
    /// Routed to a runtime entry; semantics host-checked by a probe.
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
    /// Not in this kernel ABI: `ENOSYS`, byte-identical to the host. No row
    /// carries this yet — the signals arc flips the `Removed` rows to it.
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

/// One syscall number (per arch) and what the runtime does with it.
#[derive(Clone, Copy, Debug)]
pub struct SyscallRow {
    /// The kernel's name for the number (the table's name column).
    pub name: &'static str,
    pub nr: Nr,
    pub family: Family,
    pub disposition: Disposition,
    /// Why this disposition: what is modeled, or why the row stays a trap.
    pub reasoning: &'static str,
    /// The arc (docs/arcs/syscall-conformance.md §6) that changes this row's
    /// disposition, or `None` when the disposition is final.
    pub closes_in: Option<&'static str>,
    /// The conformance probe id that host-checks a `Modeled` row. `None` until
    /// the testbed lands; the "Modeled rows need a probe" gate arrives with it.
    pub probe: Option<&'static str>,
}

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
    /// A Darwin-only symbol's xnu operations (`syscalls.master` names), kept as
    /// names until the Darwin table gets rows of its own.
    Darwin(&'static [&'static str]),
    /// The libc `syscall(2)` vehicle: every row, through the dispatcher.
    Dispatcher,
    /// Pure libc-side state or a control-plane entry; no kernel row.
    LibcOnly,
}

impl Serves {
    pub fn render(&self) -> String {
        match self {
            Serves::Syscalls(rows) | Serves::Darwin(rows) => rows.join(","),
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

/// The row for a syscall name, if any.
pub fn syscall(name: &str) -> Option<&'static SyscallRow> {
    SYSCALLS.iter().find(|row| row.name == name)
}

/// The rows an arch dispatches, sorted by that arch's number.
pub fn rows_for(arch: Arch) -> Vec<(u32, &'static SyscallRow)> {
    let mut rows: Vec<(u32, &'static SyscallRow)> = SYSCALLS
        .iter()
        .filter_map(|row| row.nr.for_arch(arch).map(|nr| (nr, row)))
        .collect();
    rows.sort_by_key(|(nr, _)| *nr);
    rows
}

/// The symbol rows that serve a syscall name.
pub fn symbols_serving(name: &str) -> Vec<&'static SymbolRow> {
    SYMBOLS
        .iter()
        .filter(|symbol| match symbol.serves {
            Serves::Syscalls(names) => names.contains(&name),
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
