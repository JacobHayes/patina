//! Serializable contracts at Patina's deterministic effect boundary.
//!
//! Internal crate: this is the shared vocabulary — [`Operation`], [`Outcome`],
//! error codes, descriptor/socket/task ids — that the runtime, drivers, trace
//! format, and native shim all speak. Adopters interact with these
//! types only indirectly (through `patina-dst-runtime`'s `Context` or by reading
//! recorded traces); depend on `patina-dst` or `patina-dst-runtime` instead.
//! See [ARCHITECTURE.md] for how the boundary fits the wider system.
//!
//! [ARCHITECTURE.md]: https://github.com/JacobHayes/patina/blob/main/ARCHITECTURE.md

use serde::{Deserialize, Serialize};

/// Base64 (RFC 4648 standard alphabet, padded) codec for the byte payloads that
/// cross the effect boundary.
///
/// Byte payloads - `fs_write`/`net_send` inputs, `bytes` outcomes, and datagram
/// bodies - are the bulk of a recorded trace. Serialized as JSON arrays of
/// integers they cost several characters per byte (and far more once pretty
/// printed); base64 costs ~1.37 characters per byte while staying valid,
/// greppable JSON. Fields tagged `#[serde(with = "bytes_base64")]` therefore
/// always write, and only read, a base64 string. Decoding is fail-closed: a
/// malformed base64 string is a hard deserialization error.
mod bytes_base64;
mod charge;
mod crash;
mod effect;
mod error;
mod filesystem;
/// Signed nanoseconds on the wire: a JSON number where a 64-bit one holds it
/// (every time a clock stamps, and every set time on the volume, which ends
/// before `u64::MAX` nanoseconds), else its decimal string (a memfd's time
/// past 64-bit nanoseconds). serde's buffering of tagged enums carries no
/// 128-bit integers, so an `i128` never reaches it as one.
pub mod nanos;
mod network;
/// `Option` wrapper over [`bytes_base64`]: `None` serializes as JSON null,
/// `Some(bytes)` as the base64 payload, exactly like `bytes_base64`.
mod option_bytes_base64;
mod verdict;

pub use charge::{COMPUTE_UNIT_NS, ChargeClass, ChargeCounts, CpuCharge, STARTUP_CPU_CHARGE};
pub use crash::{CrashKind, EffectClass};
pub use effect::{EntropyWait, Operation, Outcome};
pub use error::{EffectError, ErrorCode};
pub use filesystem::{
    AtimePolicy, CREATE_MODE_UNUSED, DEFAULT_DIRECTORY_CREATE_MODE, DEFAULT_FILE_CREATE_MODE,
    DEFAULT_UMASK, FsAllocateMode, FsClock, FsDirectoryEntry, FsEntryKind, FsMetadata, FsNode,
    OpenFlags, SeekWhence, XattrTarget, seals,
};
pub use network::{Datagram, SendDisposition, SendReport, ShutdownHow, TcpAccepted};
pub use verdict::VerdictKind;

/// A virtual filesystem handle. Handles are scoped to one runtime.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Fd(pub u64);

/// A scheduler task identifier scoped to one runtime.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TaskId(pub u64);

/// The target class of a generated signal: process-directed or a specific task.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalTarget {
    Process,
    Task(TaskId),
}

/// A virtual network socket identifier scoped to one runtime.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SocketId(pub u64);

/// Clock domains exposed by the deterministic boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClockKind {
    Monotonic,
    Realtime,
}

/// The default virtual realtime epoch: the Unix time, in nanoseconds, that
/// [`ClockKind::Realtime`] reads at monotonic zero unless a run configures its
/// own (`--realtime-epoch`).
///
/// It is the author timestamp of Patina's first commit, 2026-07-22T23:00:09Z
/// (Unix seconds 1784761209): a fixed present-day wall clock, so a guest that
/// formats or validates dates sees a plausible time rather than 1970, while
/// every run still starts at the same instant. Every default construction path
/// — `VirtualClock::default` and the runtime's default drivers — uses this one
/// constant.
pub const DEFAULT_REALTIME_EPOCH_NANOS: u64 = 1_784_761_209_000_000_000;

/// Default machine uptime at guest start: 3h 25m 45.678901234s.
/// Fixed across seeds and platforms. The non-round fractional value exercises
/// unit conversion and absolute-deadline arithmetic instead of hiding errors
/// behind a zero or whole-second origin. CPU clocks do not use this origin.
pub const DEFAULT_BOOT_ORIGIN_NANOS: u64 = 12_345_678_901_234;

/// The number of CPUs the virtual machine has unless a run configures its own
/// (`--cpus`): what the guest's affinity mask, `getcpu`,
/// `sysconf(_SC_NPROCESSORS_*)` and Darwin's `hw.*cpu` report. Enough that a
/// runtime sizing its pool from the CPU count (tokio's multi-thread default,
/// rayon) starts several workers. The scheduler still runs one task at a time;
/// only what the guest sees changes. A recorded run fact: every trace states
/// its count, and a replay restores it.
pub const DEFAULT_CPUS: u32 = 4;

/// The most CPUs a run may configure: `CONFIG_NR_CPUS=1024`, the CPUs glibc's
/// `cpu_set_t` holds.
pub const MAX_CPUS: u32 = 1024;

/// The modeled machine's soft `RLIMIT_STACK`, `_STK_LIM`: 8 MiB. The virtual
/// limit table answers it, and the native supervisor pins the host's soft limit
/// to it for the guest, since Linux sizes the gap below the stack, and glibc a
/// default thread stack, from the real one.
pub const STACK_SOFT_LIMIT: u64 = 8 << 20;

/// The modeled CPU time, in nanoseconds, a Linux process has already used when
/// `main` starts. A real process reaches `main` only after `exec`, the dynamic
/// loader and libc's own setup have run on its CPU clock; the model runs none
/// of them, so the virtual CPU clocks of the process and of its main thread
/// start here instead of at zero. A model constant (like the virtual kernel's
/// `HZ` or its memory size), not a recorded run fact: no trace carries it, so
/// changing it changes what every earlier recording's guest read.
pub const STARTUP_CPU_NANOS: u64 = 1_000_000;

/// The version of the virtual-time model a trace was recorded under: what
/// moves the clock, what expires a timer, and what counts as progress for the
/// advance-on-spin rescue and the liveness watchdog. Every trace states it
/// (`RunMetadata::time_model`), and a trace recorded under another model is
/// refused by name instead of replaying into a divergence. Bump it for every
/// semantic change to time; no field needs to change.
///
/// - 1: timed parks expire at registration and at every clock advance
///   (trace format 16, which predates this field).
/// - 2: progress is classified by an operation's outcome: an empty network
///   poll (`net_recv`, `net_tcp_recv` or `net_tcp_accept` with nothing
///   available) is not progress.
/// - 3: guest calls cost time ([`ChargeClass`]): the monotonic clock follows
///   every charge, stopping at the earliest pending deadline and carrying the
///   rest; the CPU clocks, resource usage and CPU-time timers read the user
///   and system totals; a poll loop is escalated by charging the iterations it
///   would spend, not by a recorded advance.
/// - 4: metered computation costs time ([`ChargeClass::Compute`]): a guest
///   built with a compute meter (every Go guest) charges each batch of
///   counted comparisons as user time and takes a scheduling point.
pub const TIME_MODEL: u32 = 4;
