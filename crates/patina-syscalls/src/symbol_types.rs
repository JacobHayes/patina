//! Host-independent symbol inventory types, shared with metadata generation.

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
