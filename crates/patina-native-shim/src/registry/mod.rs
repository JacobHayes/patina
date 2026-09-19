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
//! * (c) every `probe` a row names is a probe in the conformance testbed's
//!   `probes.toml`, every row that manifest names exists here, and a `Modeled`
//!   row without a probe is reported — a failure under
//!   `PATINA_CONFORMANCE_STRICT=1` (`cargo-patina/tests/syscall_registry.rs`);
//! * a row whose `since` is newer than [`VIRTUAL_ABI`] is `Absent`
//!   (`syscalls::tests`): the virtual kernel answers `ENOSYS` exactly as a
//!   kernel of that release does.

pub mod symbols;
pub mod syscalls;
pub mod table;
#[cfg(test)]
mod tests;

pub use symbols::SYMBOLS;
pub use syscalls::SYSCALLS;

/// The Linux kernel release whose ABI the virtual kernel declares. A number the
/// vendored table lists but that first appeared in a newer release is
/// [`Disposition::Absent`] — `ENOSYS`, byte-identical to what a kernel of this
/// release answers — and a probe's blessing header records it. Raising it moves
/// every row whose `since` it passes back to its family's arc (the rule test
/// names them).
pub const VIRTUAL_ABI: &str = "6.8";

/// The one identity the virtual kernel runs the guest as: an ordinary
/// non-root user that owns every entry of the deterministic filesystem. The
/// single source `getuid`/`geteuid` (the `Constant` rows below and the C
/// interposers) and every `st_uid` are answered from, and what `chown` is a
/// comparison against. The identity arc makes it a `--host-*` knob.
pub const IDENTITY_UID: u32 = 1000;
/// The sole virtual process; also its group/session leader.
pub const IDENTITY_PID: u32 = 1;
/// The group of [`IDENTITY_UID`]; see there.
pub const IDENTITY_GID: u32 = 1000;

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
    /// The primary conformance probe (`testbeds/syscall-conformance/probes.toml`
    /// id) that host-checks this row. Gated both ways against the manifest; a
    /// `Modeled` row with `None` is reported by `cargo patina syscalls` and by
    /// the cross-gate (a failure under `PATINA_CONFORMANCE_STRICT=1`).
    pub probe: Option<&'static str>,
    /// The first mainline kernel release carrying this number, when it is
    /// newer than the table's baseline (docs/arcs/syscall-conformance.md; the
    /// prior-art drift table). `None` means the number predates every host the
    /// harness runs on. A `since` newer than [`VIRTUAL_ABI`] makes the row
    /// `Absent`.
    pub since: Option<&'static str>,
}

impl SyscallRow {
    /// Name the primary conformance probe for this row.
    pub const fn probe(mut self, id: &'static str) -> Self {
        self.probe = Some(id);
        self
    }

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
    /// The primary conformance probe that exercises this symbol through the
    /// `libc` vehicle (`probes.toml` `symbols`), gated both ways against the
    /// manifest like [`SyscallRow::probe`].
    pub probe: Option<&'static str>,
}

impl SymbolRow {
    /// Name the primary conformance probe for this symbol.
    pub const fn probe(mut self, id: &'static str) -> Self {
        self.probe = Some(id);
        self
    }
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

/// The `Modeled` syscall rows no conformance probe covers yet, by name in
/// x86_64 number order — the set `cargo patina syscalls` reports and the
/// cross-gate counts (and refuses under `PATINA_CONFORMANCE_STRICT=1`).
pub fn modeled_rows_without_probe() -> Vec<&'static str> {
    SYSCALLS
        .iter()
        .filter(|row| row.disposition == Disposition::Modeled && row.probe.is_none())
        .map(|row| row.name)
        .collect()
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
