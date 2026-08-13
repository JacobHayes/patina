//! The [Patina] deterministic runtime: seeded drivers, record/replay traces,
//! and the explicit [`Context`] API.
//!
//! This crate *is* the simulator. It assembles the deterministic drivers —
//! virtual clock, in-memory filesystem, simulated network, seeded entropy, and
//! the deterministic scheduler — behind one [`Context`], makes every effect a
//! pure function of a root seed, and records/replays those effects as traces.
//! Every Patina usage mode ultimately drives this runtime: the native shim and
//! WASI host route interposed `std` calls into it, and this crate's own API
//! exposes it directly.
//!
//! # Where this crate sits (the SDK / runtime split)
//!
//! Application code should *not* depend on this crate. The crate an application
//! ships is `patina-dst` — dependency-light, every macro a no-op outside a
//! Patina build. `patina-dst-runtime` is the other side of the split: the
//! simulator itself, for code that *knows* it is simulator-shaped —
//!
//! - **Mode 3 (this crate):** tests and simulators written against the
//!   explicit-context API. [`run`]/[`run_with`] build a [`Context`] and the code
//!   performs effects *through it* — nothing is interposed, so plain
//!   `std::fs`/`std::net` calls in the same program do **not** go through
//!   Patina. Ordinary code called from this mode must stay deterministic from
//!   the simulator's inputs, or have its effects injected by the simulator; host
//!   files, host sockets, host time/randomness, real-thread schedules, tokio
//!   reactors, FFI, and syscalls are outside this explicit boundary. Use the
//!   native shim/harness path for ordinary applications that perform those
//!   effects directly. Deterministic async ([`block_on`]/`spawn`, virtual-time
//!   sleep/timeout) layers over the same `Context` in `patina-dst-async`.
//! - **Modes 1–2 (via `cargo patina`):** unmodified programs run under the
//!   native shim or WASI host, which drive this same runtime below ordinary
//!   `std` calls; `patina-dst-harness` configures such a run in code.
//!
//! See [USAGE-MODES.md] for the full map and [ARCHITECTURE.md] for the design.
//!
//! # Example
//!
//! Effects performed through the `Context` are deterministic and free of host
//! I/O — the filesystem is in-memory, and time is virtual:
//!
//! ```
//! use patina_dst_runtime::run;
//!
//! let contents = run(|ctx| {
//!     ctx.write_file("/greeting", b"hello")?; // deterministic in-memory fs
//!     ctx.sleep_for(3_600_000_000_000)?; // an hour of virtual time, instantly
//!     ctx.read_file("/greeting")
//! })?;
//! assert_eq!(contents, b"hello");
//! # Ok::<(), patina_dst_runtime::RuntimeError>(())
//! ```
//!
//! # Configuration and the `PATINA_*` control plane
//!
//! [`run`] configures itself from [`RuntimeConfig::from_env`]: the `PATINA_*`
//! environment variables documented on the `ENV_*` constants in this crate
//! (seed, record/replay mode, fault knobs, buggify, schedule exploration,
//! liveness watchdogs). `cargo patina run`/`test` set exactly these variables
//! from its CLI flags, so an in-process test picks up `--seed`, `--record`,
//! `--fs-crash-at`, and friends with no extra plumbing. With nothing set, the
//! default is a seeded run with seed 0. For full control, build a
//! [`RuntimeConfig`] directly (e.g. [`RuntimeConfig::seeded`]) and hand it to a
//! [`RuntimeBuilder`], which can also swap individual drivers.
//!
//! # Record, replay, fail closed
//!
//! In record mode every boundary decision is captured into a versioned trace
//! bundle; replay is strict — a diverging operation, changed fingerprint, or
//! conflicting configuration is a loud error, never a silent divergence
//! (see [`ExecutionMode`] and the fail-closed doctrine in the [README]).
//!
//! [Patina]: https://github.com/JacobHayes/patina
//! [README]: https://github.com/JacobHayes/patina/blob/main/README.md
//! [USAGE-MODES.md]: https://github.com/JacobHayes/patina/blob/main/USAGE-MODES.md
//! [ARCHITECTURE.md]: https://github.com/JacobHayes/patina/blob/main/ARCHITECTURE.md
//! [`block_on`]: https://docs.rs/patina-dst-async

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::OsString;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};

pub use patina_dst_abi::VerdictKind;
use patina_dst_abi::{
    ClockKind, Datagram, EffectError, ErrorCode, Fd, FsDirectoryEntry, FsMetadata, OpenFlags,
    Operation, Outcome, SeekWhence, SendReport, ShutdownHow, SocketId, TaskId, TcpAccepted,
    verdict_line,
};
use patina_dst_driver_api::{ClockDriver, EntropyDriver, FsDriver, NetDriver, SchedulerDriver};
use patina_dst_fs_crash::CrashFs;
pub use patina_dst_fs_crash::TornGranularity;
use patina_dst_fs_mem::MemFs;
use patina_dst_net_sim::SimNet;
use patina_dst_rng_seeded::{SeededEntropy, SplitMix64, domain_seed, fault_domain};
use patina_dst_sched_det::{DetScheduler, PctConfig, SchedulePolicy, StarvationConfig};
use patina_dst_time_virtual::VirtualClock;
pub use patina_dst_trace::MAX_TRACE_BYTES;
use patina_dst_trace::{BranchSession, Recorder, Replayer, RunMetadata, TraceBundle, TraceError};
use patina_dst_wrapper_fault::FaultFs;

mod fault_knob;
pub use fault_knob::{FaultKnob, KnobMeta, Masks, Plane, Plumbing, SWARM_CLASSES, SwarmClass};

mod facts;
pub use facts::{FACTS_SCHEMA, FactsSink};

pub const ENV_MODE: &str = "PATINA_MODE";
pub const ENV_SEED: &str = "PATINA_SEED";
pub const ENV_TRACE: &str = "PATINA_TRACE";
pub const ENV_TRACE_FD: &str = "PATINA_TRACE_FD";
/// Inherited host descriptor receiving a `patina.covmap/v1` native edge-coverage
/// counter map. Set only by `run --coverage-out PATH` for yield-point-instrumented
/// native binaries, so the fully interposed guest writes coverage through the
/// supervisor-owned host descriptor rather than through the deterministic FS.
pub const ENV_COVERAGE_FD: &str = "PATINA_COVERAGE_FD";
/// Path the runtime writes this run's structured
/// [`patina.runfacts/v1`](FACTS_SCHEMA) document to at finalization. Set by
/// `cargo patina` for the families whose guest can write host files directly
/// (the cargo family), and by any in-process embedder that wants the facts. The
/// document carries the same per-plane accounting the `PATINA_*_REPORT` lines
/// carry, built from the report structs rather than from the lines. Unset =
/// no document is produced and the run is byte-for-byte unchanged.
pub const ENV_FACTS: &str = "PATINA_FACTS";
/// Inherited host descriptor receiving the same [`patina.runfacts/v1`](FACTS_SCHEMA)
/// document as [`ENV_FACTS`]. Used by the native family, whose guest filesystem
/// is fully interposed, so the shim writes the document through a
/// supervisor-owned host descriptor rather than through the deterministic FS —
/// exactly the split between [`ENV_TRACE`] and [`ENV_TRACE_FD`]. Setting both
/// [`ENV_FACTS`] and this variable is refused.
pub const ENV_FACTS_FD: &str = "PATINA_FACTS_FD";
/// Suppress the default-on native yield-point coverage diagnostic when set to a
/// false-y value (`0`, `off`, `false`, `no`). The diagnostic is emitted by the
/// native shim at the same finalization point as the runtime reports.
pub const ENV_COVERAGE_REPORT: &str = "PATINA_COVERAGE_REPORT";
/// Suppress the default-on WASI depth diagnostic when set to a false-y value
/// (`0`, `off`, `false`, `no`). WASI guests execute in-process, so the line is
/// emitted by `cargo-patina` rather than by a shim, but the gate spelling matches
/// [`ENV_COVERAGE_REPORT`] so both diagnostics are silenced the same way.
pub const ENV_DEPTH_REPORT: &str = "PATINA_DEPTH_REPORT";
/// Inherited host descriptor carrying an encoded `patina_dst_fs_mem::FsImage`. When
/// set, `native-run` streams a read-only host directory tree into the guest and
/// the shim rebuilds it as the deterministic filesystem instead of an empty one,
/// so a fully interposed guest sees a fixed corpus without touching the host.
/// The image's hash is folded into the run fingerprint, so replay rejects a
/// different corpus. Off when unset.
pub const ENV_FS_IMAGE_FD: &str = "PATINA_FS_IMAGE_FD";
pub const ENV_FINGERPRINT: &str = "PATINA_FINGERPRINT";
/// Deferred-initialization flag for the shim-backed harness (see
/// `patina-dst-harness`, USAGE-MODES.md startup Option B). When present (`=1`)
/// alongside `PATINA_MODE`, the packaged native constructor captures and scrubs
/// the control plane and registers finalization but does NOT install the runtime;
/// `patina_dst_harness::run`/`run_with` installs it explicitly, after applying
/// the harness's configuration overlay. An interposed effect that reaches the
/// boundary before the harness installs fails closed loudly (never auto-inits).
/// Set by `cargo patina run --harness` (and the matching `replay`). Off when
/// unset (the ordinary constructor-installs-at-startup path).
pub const ENV_DEFER_INIT: &str = "PATINA_DEFER_INIT";
pub const ENV_BRANCH_FROM: &str = "PATINA_BRANCH_FROM";
pub const ENV_BRANCH_SEED: &str = "PATINA_BRANCH_SEED";
pub const ENV_BRANCH_ID: &str = "PATINA_BRANCH_ID";
pub const ENV_PARENT_TIMELINE: &str = "PATINA_PARENT_TIMELINE";
pub const ENV_TIMELINE: &str = "PATINA_TIMELINE";
pub const ENV_STEP_BUDGET: &str = "PATINA_STEP_BUDGET";
pub const ENV_PARAMS_JSON: &str = "PATINA_PARAMS_JSON";
/// The guest program arguments (`argv[1..]`, i.e. everything after `--`) as a
/// JSON string array. The supervisor forwards this in record mode so the run's
/// arguments are captured into the trace metadata; the runtime records them and
/// a later `replay` restores them without re-passing the `--` section. Absent
/// leaves the recorded argv unset. Malformed JSON is rejected fail-closed.
pub const ENV_GUEST_ARGV: &str = "PATINA_GUEST_ARGV";
/// Deterministic guest environment values as a JSON object (`KEY` -> `VALUE`).
/// Set by native `run --env KEY=VALUE`; recorded into trace metadata and restored
/// on replay so environment-dependent native guests reproduce without re-supplying
/// flags. Malformed JSON, empty keys, keys containing `=`, or NUL bytes fail closed.
pub const ENV_GUEST_ENV: &str = "PATINA_GUEST_ENV_JSON";
/// Base link latency in nanoseconds applied to the default `SimNet` network
/// (datagrams and TCP segments). Blocking receives under a non-zero value park
/// on the virtual-clock timer queue until delivery. Invalid values are rejected fail-closed.
pub const ENV_NET_LATENCY: &str = "PATINA_NET_LATENCY_NANOS";
/// Seeded per-datagram delivery jitter range `MIN..MAX` in nanoseconds applied
/// to the default `SimNet`. Varying jitter reorders datagrams relative to their
/// send order — the UDP-reorder fault. Off when unset.
pub const ENV_NET_JITTER: &str = "PATINA_NET_JITTER_NANOS";
/// Seeded datagram drop probability in per-mille (0..=1000) applied to the
/// default `SimNet`. Off (zero) when unset.
pub const ENV_NET_DROP_PERMILLE: &str = "PATINA_NET_DROP_PERMILLE";
/// Seeded datagram duplication probability in per-mille (0..=1000). Each
/// duplicate is an independent copy with its own jitter draw, so the twins can
/// arrive apart — the at-least-once delivery hazard. Off (zero) when unset.
pub const ENV_NET_DUPLICATE_PERMILLE: &str = "PATINA_NET_DUPLICATE_PERMILLE";
/// Seeded probability in per-mille (0..=1000) that an otherwise-establishable
/// TCP connection is refused. Off (zero) when unset.
pub const ENV_NET_CONNECT_REFUSE_PERMILLE: &str = "PATINA_NET_CONNECT_REFUSE_PERMILLE";
/// Seeded probability in per-mille (0..=1000) that a fault-eligible established
/// TCP stream operation tears the stream down with a reset. Off (zero) when unset.
pub const ENV_NET_RESET_PERMILLE: &str = "PATINA_NET_RESET_PERMILLE";
/// Statically partitioned address pairs as a JSON array of two-element arrays
/// (`[["a","b"],…]`). Both directions of each pair are blocked. Deterministic
/// topology configuration rather than a seeded rate. Empty when unset.
pub const ENV_NET_PARTITIONS: &str = "PATINA_NET_PARTITIONS_JSON";
/// Virtual TCP receive-buffer size in bytes. Smaller buffers make would-block
/// behavior reachable. The driver default applies when unset.
pub const ENV_NET_TCP_BUFFER_BYTES: &str = "PATINA_NET_TCP_BUFFER_BYTES";
/// Seeded extra latency `MIN..MAX` in nanoseconds added to every guest sleep,
/// inflating virtual elapsed time to trip wall-clock deadline assumptions. Off
/// when unset.
pub const ENV_SLEEP_JITTER: &str = "PATINA_SLEEP_JITTER_NANOS";
/// Filesystem crash-injection point, e.g. `close:1`, `write:3`, `sync:2`,
/// `open:1`. When set the default filesystem becomes a `CrashFs` and the runtime
/// injects a crash immediately after the selected boundary operation, dropping
/// unsynced data. Off when unset.
pub const ENV_FS_CRASH_AT: &str = "PATINA_FS_CRASH_AT";
/// Torn-write granularity for an injected crash: `block` (default, whole-block
/// revert) or `byte` (the final unsynced write may survive partially at
/// sub-block byte granularity, modeling a torn in-flight page). Only meaningful
/// alongside [`ENV_FS_CRASH_AT`]. Off (block) when unset.
pub const ENV_FS_TORN_GRANULARITY: &str = "PATINA_FS_TORN_GRANULARITY";
/// Seeded filesystem error probability in per-mille (0..=1000), applied to
/// eligible filesystem operations by the default `FaultFs` wrapper. Off (zero)
/// when unset.
pub const ENV_FS_ERROR_PERMILLE: &str = "PATINA_FS_ERROR_PERMILLE";
/// Seeded short-read/short-write probability in per-mille (0..=1000), applied
/// to read/write operations by the default `FaultFs` wrapper. Off (zero) when
/// unset.
pub const ENV_FS_SHORT_PERMILLE: &str = "PATINA_FS_SHORT_PERMILLE";
/// Seeded extra latency `MIN..MAX` in nanoseconds added to every fault-eligible
/// filesystem operation before it executes, applied by the `Context` (the only
/// site that owns the clock). Slow I/O reorders against timers and peers. Off
/// when unset.
pub const ENV_FS_LATENCY: &str = "PATINA_FS_LATENCY_NANOS";
/// Seeded DNS resolution-failure probability in per-mille (0..=1000), applied to
/// lookups of names the host table defines. Off (zero) when unset.
pub const ENV_DNS_FAIL_PERMILLE: &str = "PATINA_DNS_FAIL_PERMILLE";
/// Seeded guest entropy-request failure probability in per-mille (0..=1000),
/// applied to every `Context::entropy_bytes` call. Off (zero) when unset.
pub const ENV_ENTROPY_FAIL_PERMILLE: &str = "PATINA_ENTROPY_FAIL_PERMILLE";
/// Seeded realtime-epoch jump magnitude in nanoseconds. Every
/// `Context::now(ClockKind::Realtime)` read draws a signed offset uniformly in
/// `[-hi, hi]` and applies it to that one read (saturating at 0), so wall time
/// can regress or leap between adjacent reads — never applied to
/// `ClockKind::Monotonic`, which drives timers and the liveness watchdog. Off
/// (zero) when unset.
pub const ENV_EPOCH_JUMP_NANOS: &str = "PATINA_EPOCH_JUMP_NANOS";
/// Seeded extra latency `MIN..MAX` in nanoseconds added to every eligible name
/// resolution, applied by the `Context`. Off when unset.
pub const ENV_DNS_LATENCY: &str = "PATINA_DNS_LATENCY_NANOS";
/// The run's DNS host table as a JSON object (`NAME` -> dotted-quad `ADDR`).
/// Semantic configuration, not a fault knob: names outside it are NXDOMAIN.
pub const ENV_DNS_ENTRIES: &str = "PATINA_DNS_ENTRIES_JSON";
/// Suppress the default-on end-of-run schedule diagnostic when set to a false-y
/// value (`0`, `off`, `false`, `no`). The diagnostic is on by default.
pub const ENV_SCHEDULE_REPORT: &str = "PATINA_SCHEDULE_REPORT";
/// Suppress the default-on end-of-run network fault-injection diagnostic when
/// set to a false-y value (`0`, `off`, `false`, `no`). The diagnostic is on by
/// default: it fires a loud warning when the net fault knobs could perturb
/// delivery and fault-eligible traffic occurred, yet ZERO fault effects landed
/// (the silent-inertness class — historically the inert TCP stream path).
pub const ENV_NET_FAULT_REPORT: &str = "PATINA_NET_FAULT_REPORT";
/// Suppress the default-on end-of-run filesystem fault-injection diagnostic
/// when set to a false-y value (`0`, `off`, `false`, `no`). The diagnostic is on
/// by default when fs fault knobs had eligible traffic.
pub const ENV_FS_FAULT_REPORT: &str = "PATINA_FS_FAULT_REPORT";
/// Suppress the default-on end-of-run DNS fault-injection diagnostic when set to
/// a false-y value (`0`, `off`, `false`, `no`).
pub const ENV_DNS_FAULT_REPORT: &str = "PATINA_DNS_FAULT_REPORT";
/// Suppress the default-on end-of-run entropy fault-injection diagnostic when set
/// to a false-y value (`0`, `off`, `false`, `no`).
pub const ENV_ENTROPY_FAULT_REPORT: &str = "PATINA_ENTROPY_FAULT_REPORT";
/// Suppress the default-on end-of-run clock (realtime-epoch jump)
/// fault-injection diagnostic when set to a false-y value (`0`, `off`, `false`,
/// `no`).
pub const ENV_CLOCK_FAULT_REPORT: &str = "PATINA_CLOCK_FAULT_REPORT";
/// Enable cooperative-SUT (buggify) fault injection. Its value is the
/// per-evaluation firing probability in per-mille for an active site (0..=1000);
/// an empty value uses the FoundationDB default of 25% (250). Presence of the
/// variable enables buggify; absence disables it (zero behavior change).
pub const ENV_BUGGIFY: &str = "PATINA_BUGGIFY";
/// Per-run site activation probability in per-mille (0..=1000): the fraction of
/// buggify sites made active for the run. Default 25% (250). Inert without
/// [`ENV_BUGGIFY`].
pub const ENV_BUGGIFY_ACTIVATION: &str = "PATINA_BUGGIFY_ACTIVATION_PERMILLE";
/// Virtual-time monotonic-nanoseconds cutoff after which buggify stops firing
/// (the FoundationDB damage-control window). Default 300 virtual seconds. Inert
/// without [`ENV_BUGGIFY`].
pub const ENV_BUGGIFY_CUTOFF: &str = "PATINA_BUGGIFY_CUTOFF_NANOS";
/// Declare that the guest calls `patina_dst::lifecycle::setup_complete()`, gating
/// buggify off until that call. A false-y value (or absence) leaves it off.
/// Inert without [`ENV_BUGGIFY`]. When set and the guest never calls
/// `setup_complete()`, the run fails loudly at finalization.
pub const ENV_BUGGIFY_AFTER_SETUP: &str = "PATINA_BUGGIFY_AFTER_SETUP";
/// Suppress the default-on end-of-run cooperative-SUT diagnostic when set to a
/// false-y value (`0`, `off`, `false`, `no`). On by default when buggify is
/// enabled.
pub const ENV_SDK_REPORT: &str = "PATINA_SDK_REPORT";
/// Enable the PCT (Probabilistic Concurrency Testing) exploration scheduling
/// policy. Its value is the target bug depth `d` (>= 1); an empty value uses the
/// default depth. Presence enables PCT; absence leaves the default uniform
/// policy (zero behavior change). Folds a `+pct` fingerprint component.
pub const ENV_SCHED_PCT: &str = "PATINA_SCHED_PCT";
/// Expected schedule length over which PCT distributes its `d-1` priority-change
/// points. Default [`DEFAULT_PCT_STEPS`]. Inert without [`ENV_SCHED_PCT`].
pub const ENV_SCHED_PCT_STEPS: &str = "PATINA_SCHED_PCT_STEPS";
/// Enable the starvation-interval exploration scheduling policy. Its value is the
/// number of bounded intervals to place (>= 1); an empty value uses the default
/// count. Presence enables starvation; absence leaves it off. Folds a `+starve`
/// fingerprint component.
pub const ENV_SCHED_STARVE: &str = "PATINA_SCHED_STARVE";
/// Maximum length (scheduling decisions) of any starvation interval — the bound
/// that keeps starvation liveness-safe. Default [`DEFAULT_STARVE_MAX_LEN`]. Inert
/// without [`ENV_SCHED_STARVE`].
pub const ENV_SCHED_STARVE_MAX_LEN: &str = "PATINA_SCHED_STARVE_MAX_LEN";
/// Window `[1, N]` over which starvation interval starts are placed. Default
/// [`DEFAULT_STARVE_WINDOW`]. Inert without [`ENV_SCHED_STARVE`].
pub const ENV_SCHED_STARVE_WINDOW: &str = "PATINA_SCHED_STARVE_WINDOW";
/// Enable swarm fault-class selection: a seed-derived subset of the enabled fault
/// classes is applied this generation instead of all of them. A false-y value
/// (or absence) keeps the existing always-all behavior. Folds a `+swarm`
/// fingerprint component.
pub const ENV_SWARM: &str = "PATINA_SWARM";
/// Suppress the default-on end-of-run swarm-selection diagnostic
/// (`PATINA_SWARM_REPORT`) when set to a false-y value. On by default for every
/// run that applied swarm selection.
pub const ENV_SWARM_REPORT: &str = "PATINA_SWARM_REPORT";
/// Suppress the default-on end-of-run exploration-policy diagnostic
/// (`PATINA_SCHEDULE_POLICY`) when set to a false-y value. On by default when a
/// policy is active.
pub const ENV_SCHEDULE_POLICY_REPORT: &str = "PATINA_SCHEDULE_POLICY_REPORT";

/// The compatibility-fingerprint component a supervisor folds (as `+buggify`)
/// when a run arms cooperative-SUT injection, and the component swarm strips
/// again when a generation deselects the `buggify` class.
///
/// Both sides read this one constant so the declaration and the retraction can
/// never disagree: `cargo patina`'s fingerprint composer appends it, and
/// [`RuntimeConfig`]'s swarm mask removes it. A fingerprint component that is
/// also a swarm-maskable class MUST live here and be registered in the swarm
/// class table (see the `swarm_class_table_declares_every_fingerprint_component`
/// test), or a masked run would keep declaring coverage it no longer has.
pub const FINGERPRINT_BUGGIFY: &str = "buggify";

/// Enable the generic liveness watchdog with a virtual-time no-progress budget in
/// nanoseconds (armed from run start). A bare/empty value uses
/// [`DEFAULT_LIVENESS_BUDGET_NANOS`].
pub const ENV_LIVENESS_WATCHDOG: &str = "PATINA_LIVENESS_WATCHDOG_NANOS";
/// Enable the heal-then-converge watchdog with a virtual-time convergence budget
/// in nanoseconds, armed at the fault-window end. A bare/empty value uses
/// [`DEFAULT_CONVERGE_BUDGET_NANOS`].
pub const ENV_CONVERGE_WITHIN: &str = "PATINA_CONVERGE_WITHIN_NANOS";
/// Explicit override for the heal-then-converge arm-time (virtual nanoseconds).
/// When unset and converge is enabled, the runtime derives it from the buggify
/// damage-control cutoff (if buggify is enabled) else 0.
pub const ENV_HEAL_AFTER: &str = "PATINA_HEAL_AFTER_NANOS";
/// Suppress the default-on end-of-run liveness-watchdog diagnostic
/// (`PATINA_LIVENESS_REPORT`) when set to a false-y value.
pub const ENV_LIVENESS_REPORT: &str = "PATINA_LIVENESS_REPORT";

/// One end-of-run diagnostic report, and the `PATINA_*` variable that silences
/// it. Every report any layer emits — the runtime's own, the native shim's
/// coverage line, the supervisor's WASI depth line — has a variant here, so the
/// set of suppression knobs is enumerable rather than a per-emitter habit.
///
/// Suppression is presentation, never run semantics: no variant is a fingerprint
/// input, none is recorded into a trace, and none participates in replay
/// reconciliation. A replay with different suppression settings reconciles
/// against the recording and produces the identical op stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Report {
    /// `PATINA_SCHEDULE_REPORT` — per-task scheduling boundaries and vacuity.
    Schedule,
    /// `PATINA_SCHEDULE_POLICY_REPORT` — the realized PCT/starvation selection.
    SchedulePolicy,
    /// `PATINA_SWARM_REPORT` — the swarm fault-class draw.
    Swarm,
    /// `PATINA_LIVENESS_REPORT` — the liveness watchdog's armed/fired state.
    Liveness,
    /// `PATINA_SDK_REPORT` — cooperative-SUT site registration/activation/firing.
    Sdk,
    /// `PATINA_FS_FAULT_REPORT` — filesystem fault-injection accounting.
    FsFault,
    /// `PATINA_DNS_FAULT_REPORT` — DNS fault-injection accounting.
    DnsFault,
    /// `PATINA_NET_FAULT_REPORT` — network fault-injection accounting.
    NetFault,
    /// `PATINA_ENTROPY_FAULT_REPORT` — guest entropy-request fault-injection
    /// accounting.
    EntropyFault,
    /// `PATINA_CLOCK_FAULT_REPORT` — guest realtime-epoch jump fault-injection
    /// accounting.
    ClockFault,
    /// `PATINA_COVERAGE_REPORT` — native yield-point edge coverage, emitted by
    /// the shim at its own finalization point rather than by [`Context::finish`].
    Coverage,
    /// `PATINA_DEPTH_REPORT` — WASI fuel/hostcall depth, emitted by the
    /// supervisor because WASI guests execute in its process.
    Depth,
}

impl Report {
    /// Every report, in declaration order. Family plumbing (the native child's
    /// environment, a campaign's pinned child diagnostics) iterates THIS, so a
    /// report added here cannot be carried by one family and dropped by another.
    pub const ALL: [Self; 12] = [
        Self::Schedule,
        Self::SchedulePolicy,
        Self::Swarm,
        Self::Liveness,
        Self::Sdk,
        Self::FsFault,
        Self::DnsFault,
        Self::NetFault,
        Self::EntropyFault,
        Self::ClockFault,
        Self::Coverage,
        Self::Depth,
    ];

    /// The `PATINA_*` variable that suppresses this report.
    #[must_use]
    pub const fn env(self) -> &'static str {
        match self {
            Self::Schedule => ENV_SCHEDULE_REPORT,
            Self::SchedulePolicy => ENV_SCHEDULE_POLICY_REPORT,
            Self::Swarm => ENV_SWARM_REPORT,
            Self::Liveness => ENV_LIVENESS_REPORT,
            Self::Sdk => ENV_SDK_REPORT,
            Self::FsFault => ENV_FS_FAULT_REPORT,
            Self::DnsFault => ENV_DNS_FAULT_REPORT,
            Self::NetFault => ENV_NET_FAULT_REPORT,
            Self::EntropyFault => ENV_ENTROPY_FAULT_REPORT,
            Self::ClockFault => ENV_CLOCK_FAULT_REPORT,
            Self::Coverage => ENV_COVERAGE_REPORT,
            Self::Depth => ENV_DEPTH_REPORT,
        }
    }
}

/// Which end-of-run diagnostic reports this run prints. Every report is on by
/// default; a false-y value (`0`, `off`, `false`, `no`) for a [`Report`]'s
/// variable turns that one off.
///
/// Resolved ONCE, at configuration time, from whatever control plane the family
/// supplies — the native shim's pre-scrub environment snapshot, the process
/// environment for the cargo family, the supervisor's environment for WASI.
/// Nothing consults the process environment at finalization: on native the
/// public `getenv` is interposed and the deterministic environment is long gone
/// by then, so a late read returns NULL and every knob reads as absent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReportConfig {
    enabled: [bool; Report::ALL.len()],
}

impl Default for ReportConfig {
    fn default() -> Self {
        Self {
            enabled: [true; Report::ALL.len()],
        }
    }
}

impl ReportConfig {
    /// Whether `report` prints.
    #[must_use]
    pub const fn enabled(&self, report: Report) -> bool {
        self.enabled[report as usize]
    }

    /// Turn one report on or off explicitly (the harness overlay path).
    pub const fn set(&mut self, report: Report, enabled: bool) {
        self.enabled[report as usize] = enabled;
    }

    /// Resolve every report knob through one control-plane accessor. An absent
    /// variable leaves the current setting; a false-y value suppresses; anything
    /// else (including an empty value) enables, so a pinned `=1` re-enables a
    /// report an ambient `=0` had suppressed.
    #[must_use]
    pub fn applied<F>(mut self, get: F) -> Self
    where
        F: Fn(&str) -> Option<String>,
    {
        for report in Report::ALL {
            if let Some(value) = get(report.env()) {
                self.set(report, !is_false_y(value.trim()));
            }
        }
        self
    }
}

/// The false-y spellings a default-ON knob accepts. Deliberately excludes the
/// empty string: `PATINA_SDK_REPORT=` asks for the default, which is on. The
/// default-OFF enable knobs ([`ENV_SWARM`], [`ENV_BUGGIFY_AFTER_SETUP`]) use the
/// opposite convention — a bare, valueless variable means off — so they keep
/// their own predicate rather than sharing this one.
fn is_false_y(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "0" | "off" | "false" | "no"
    )
}

// Return codes for the shim's `patina_harness_install` C ABI, shared by the
// native shim (which returns them) and `patina-dst-harness` (which maps them to
// its `HarnessError` variants). Distinct, stable sentinels so the harness can
// discriminate the fail-closed reasons without parsing stderr; the shim also
// prints a loud diagnostic for each nonzero case.
/// Harness install succeeded: the runtime is installed with the overlay applied.
pub const HARNESS_OK: i32 = 0;
/// No `PATINA_MODE` in the control plane: the harness binary was not run under
/// `cargo patina run --harness` (plain execution or missing supervisor protocol).
pub const HARNESS_ERR_NOT_UNDER_PATINA: i32 = -1;
/// The runtime is already installed (a non-deferred startup, or a second
/// `run`/`run_with`): the harness cannot install a second context.
pub const HARNESS_ERR_ALREADY_INSTALLED: i32 = -2;
/// A deterministic boundary effect was already observed before the harness
/// installed: reconfiguring after events would make replay semantics ambiguous.
pub const HARNESS_ERR_BOUNDARY_BEFORE_INSTALL: i32 = -3;
/// The runtime configuration built from the (overlaid) control plane failed to
/// validate/build (bad knob value, fingerprint/replay reconciliation conflict).
pub const HARNESS_ERR_CONFIG: i32 = -4;

/// Default generic no-progress budget: 600 virtual seconds. Generous by design —
/// the budget must exceed the longest legitimate quiescent (single-sleep) period,
/// so a real workload's ordinary waiting never trips it.
pub const DEFAULT_LIVENESS_BUDGET_NANOS: u64 = 600_000_000_000;
/// Default heal-then-converge budget: 300 virtual seconds after the fault window.
pub const DEFAULT_CONVERGE_BUDGET_NANOS: u64 = 300_000_000_000;
/// Minimum number of consecutive non-progress operations a no-progress window must
/// contain before the watchdog may fire, so a single long-but-legitimate sleep
/// (one non-progress op) can never trip it — only genuine churn (a timer/park spin
/// issuing many scheduling ops) does.
const LIVENESS_MIN_STALL_OPS: u64 = 4;

/// Default PCT target bug depth when `--sched-pct` is given without a value.
pub const DEFAULT_PCT_DEPTH: u32 = 3;
/// Default PCT expected schedule length.
pub const DEFAULT_PCT_STEPS: u64 = 2_000;
/// Default number of starvation intervals when `--starve` is given bare.
pub const DEFAULT_STARVE_INTERVALS: u32 = 3;
/// Default maximum starvation interval length (bounded → liveness-safe).
pub const DEFAULT_STARVE_MAX_LEN: u64 = 32;
/// Default starvation interval start window.
pub const DEFAULT_STARVE_WINDOW: u64 = 512;

const DEFAULT_FINGERPRINT: &str = "direct-seeded-run-v1";

/// FoundationDB's default per-evaluation buggify firing probability, in per-mille.
pub const DEFAULT_BUGGIFY_FIRE_PERMILLE: u16 = 250;
/// FoundationDB's default per-run buggify site activation probability, in per-mille.
pub const DEFAULT_BUGGIFY_ACTIVATION_PERMILLE: u16 = 250;
/// Default buggify damage-control cutoff: 300 virtual seconds, in nanoseconds.
pub const DEFAULT_BUGGIFY_CUTOFF_NANOS: u64 = 300_000_000_000;
const READ_CHUNK_SIZE: usize = 4096;
const MAX_READ_FILE_BYTES: usize = 64 * 1024 * 1024;

/// Byte-level trace channel supplied by an embedder when the runtime must not
/// open trace files itself (for example inside a fully interposed native
/// process whose ambient file symbols route back into Patina).
pub trait TraceTransport: Send {
    /// Read the complete serialized trace bundle for replay.
    fn read_bundle(&mut self) -> std::io::Result<Vec<u8>>;
    /// Deliver the complete serialized trace bundle at record finalization.
    fn write_bundle(&mut self, bytes: &[u8]) -> std::io::Result<()>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExecutionMode {
    Seeded,
    Record {
        path: PathBuf,
    },
    /// Record through an installed [`TraceTransport`] instead of a path.
    RecordTransport,
    Replay {
        path: PathBuf,
        timeline: String,
    },
    /// Replay through an installed [`TraceTransport`] instead of a path.
    ReplayTransport {
        timeline: String,
    },
    Branch {
        path: PathBuf,
        parent: String,
        from_sequence: u64,
        branch_id: String,
        branch_seed: u64,
    },
}

/// A boundary operation kind that a filesystem crash can be pinned to. The
/// runtime crashes immediately after the Nth matching operation completes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrashOp {
    Open,
    Write,
    Sync,
    Close,
}

/// Where a filesystem crash is injected: after the `ordinal`-th (1-based)
/// occurrence of `op`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CrashPoint {
    pub op: CrashOp,
    pub ordinal: u64,
}

/// How a task's schedule accounting ended. Derived purely from the task-lifecycle
/// shadow at report time — driven by the same recorded ops on record and replay,
/// so it reproduces exactly. There is no panic/abort cause at this layer: a guest
/// panic aborts the process, so a task the runtime observed is either one it saw
/// completed or one still live when the run ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskCompletionCause {
    /// The task ran a `TaskComplete` boundary (a std thread body returned and was
    /// joined, or the guest completed the task explicitly).
    Completed,
    /// The task was still live when the run ended — the initial thread of control
    /// that reached process exit, or a detached worker never joined.
    LiveAtExit,
}

impl TaskCompletionCause {
    /// Stable machine-readable token used in the `PATINA_SCHEDULE_REPORT` line.
    fn as_str(self) -> &'static str {
        match self {
            TaskCompletionCause::Completed => "completed",
            TaskCompletionCause::LiveAtExit => "live-at-exit",
        }
    }
}

/// Per-task scheduling-boundary count and whether the task's body was
/// effectively unexplorable — it ran from first scheduled to completion without
/// ever passing a scheduling boundary (yield or park), so no seed could
/// interleave anything inside it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TaskScheduleStat {
    pub task: TaskId,
    /// Voluntary reschedules taken on the interposed effect surface. Scale with a
    /// genuine concurrent loop; zero means an atomics-only (unschedulable) body.
    pub yields: u64,
    /// Blocking waits. For an atomics-only worker these are only spawn/join
    /// housekeeping and do not scale with its work.
    pub parks: u64,
    /// Total scheduling boundaries (`yields + parks`) between spawn and
    /// completion.
    pub boundaries: u64,
    /// Global scheduling-event steps the task was live for: the span of
    /// task-lifecycle boundaries (across all tasks) between this task's spawn and
    /// its completion (or the run's end, for a task still live). Orthogonal to
    /// `boundaries` (this task's own activity): it captures longevity/overlap, so
    /// a short-lived helper and a run-long coordinator are distinguishable even
    /// when their own boundary counts match.
    pub lifetime: u64,
    /// How the task's accounting ended (completed vs still live at run end).
    pub cause: TaskCompletionCause,
    /// A spawned worker (not the initial task) that completed without ever
    /// yielding on the effect surface: its interleavings are unreachable at any
    /// seed.
    pub vacuous: bool,
}

/// End-of-run schedule-exploration diagnostics. Surfaces whether a multithreaded
/// guest's schedule was actually explorable, so "N seeds explored, all clean"
/// can never silently mean "nothing inside a thread was ever schedulable".
/// Computed from the runtime's task-lifecycle shadow, which is maintained
/// identically on record and replay, so the diagnostic reproduces on replay.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScheduleDiagnostics {
    /// Distinct tasks the guest spawned, including the initial task.
    pub tasks_spawned: u64,
    /// High-water mark of concurrently-live tasks.
    pub max_concurrent: u64,
    /// Total yield/park boundaries across every task.
    pub total_boundaries: u64,
    /// Per-completed-task boundary counts, in spawn order.
    pub tasks: Vec<TaskScheduleStat>,
    /// Spawned workers that ran start-to-finish with zero boundaries.
    pub vacuous: Vec<TaskId>,
}

impl ScheduleDiagnostics {
    /// Whether there was any concurrency to explore at all. A single-task run
    /// has no schedule, so the diagnostic stays silent for it.
    pub fn had_concurrency(&self) -> bool {
        self.tasks_spawned >= 2
    }
}

/// Seed-driven, default-off fault knobs layered onto the deterministic drivers.
/// Every field is inert at its default so a run that configures no fault behaves
/// exactly as before. Knobs are grouped by domain so new domains add a sub-struct
/// instead of more loose top-level fields.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FaultConfig {
    pub fs: FsFaultConfig,
    pub net: NetFaultConfig,
    pub clock: ClockFaultConfig,
    pub dns: DnsFaultConfig,
    pub entropy: EntropyFaultConfig,
}

/// Filesystem fault knobs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FsFaultConfig {
    /// Inject a filesystem crash after a chosen boundary operation.
    pub crash_at: Option<CrashPoint>,
    /// Granularity at which the injected crash tears the final unsynced write.
    /// Inert without `crash_at`; defaults to whole-block.
    pub torn_granularity: TornGranularity,
    /// Seeded filesystem error probability in per-mille (0..=1000).
    pub error_permille: u16,
    /// Seeded short-read/short-write probability in per-mille (0..=1000).
    pub short_permille: u16,
    /// Inclusive `[min, max]` nanoseconds of seeded extra latency applied to
    /// every fault-eligible filesystem operation before it executes.
    pub latency_nanos: Option<(u64, u64)>,
}

/// Network fault knobs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NetFaultConfig {
    /// Base link latency in nanoseconds applied to the default `SimNet` network.
    pub latency_nanos: u64,
    /// Inclusive `[min, max]` nanoseconds of seeded per-datagram/segment delivery jitter.
    pub jitter_nanos: Option<(u64, u64)>,
    /// Seeded datagram drop probability in per-mille (0..=1000).
    pub drop_permille: u16,
    /// Seeded datagram duplication probability in per-mille (0..=1000). A
    /// duplicate is an independent copy with its own jitter draw.
    pub duplicate_permille: u16,
    /// Seeded probability in per-mille (0..=1000) that an otherwise-establishable
    /// TCP connection is refused.
    pub connect_refuse_permille: u16,
    /// Seeded probability in per-mille (0..=1000) that a fault-eligible
    /// established-stream operation tears the stream down with a reset.
    pub reset_permille: u16,
    /// Statically partitioned address pairs. Both directions of each pair are
    /// blocked: a datagram addressed across it is dropped and a connect across it
    /// is refused. Deterministic (rate 1.0), unlike the seeded knobs above.
    pub partitions: BTreeSet<(String, String)>,
    /// Virtual TCP receive-buffer size in bytes. `None` uses the driver default.
    /// Not a fault: a capacity setting whose smaller values make would-block
    /// behavior — and the guest's backpressure handling — reachable, so it has a
    /// swarm class (an environment shape a generation may or may not adopt) but
    /// no vacuity class (there is no "should have fired N times" rate to judge).
    pub tcp_buffer_bytes: Option<usize>,
}

/// DNS fault knobs. They act only on names the run's host table DEFINES: an
/// undefined name is NXDOMAIN as semantics, not as an injected fault.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DnsFaultConfig {
    /// Seeded resolution-failure probability in per-mille (0..=1000). On fire, a
    /// second draw picks NXDOMAIN (a stale or deleted record) or a transient
    /// timeout (a slow or unreachable resolver).
    pub fail_permille: u16,
    /// Inclusive `[min, max]` nanoseconds of seeded latency applied before every
    /// eligible resolution.
    pub latency_nanos: Option<(u64, u64)>,
}

/// Entropy fault knobs. Guest entropy has no undefined-input exemption the way
/// DNS does — every `Context::entropy_bytes` call is fault-eligible — so there is
/// only the one knob, no host-table-shaped semantic configuration alongside it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EntropyFaultConfig {
    /// Seeded entropy-request failure probability in per-mille (0..=1000). On
    /// fire, the request returns a deterministic named error instead of bytes.
    pub fail_permille: u16,
}

/// Clock fault knobs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClockFaultConfig {
    /// Inclusive `[min, max]` nanoseconds of seeded extra latency per guest sleep.
    pub sleep_jitter_nanos: Option<(u64, u64)>,
    /// Magnitude in nanoseconds of the seeded signed realtime-epoch jump applied
    /// to each `ClockKind::Realtime` read: an offset drawn uniformly in `[-hi,
    /// hi]`, independently per read. Zero (the default) is off.
    pub epoch_jump_nanos: u64,
}

/// Seed-driven cooperative-SUT (buggify) configuration. Inert (`enabled =
/// false`) by default, so a run that does not opt in behaves exactly as before.
/// When enabled, activation and firing are pure deterministic functions of the
/// root seed, the site label, and these knobs; the internal `Buggify` state uses
/// this configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BuggifyConfig {
    /// Whether buggify is active this run.
    pub enabled: bool,
    /// Per-evaluation firing probability (per-mille) for an active site.
    pub fire_permille: u16,
    /// Per-run site activation probability (per-mille).
    pub activation_permille: u16,
    /// Virtual monotonic-time cutoff (nanoseconds) after which firing stops.
    pub cutoff_nanos: u64,
    /// When set, the runner has declared that the guest calls
    /// `patina_dst::lifecycle::setup_complete()`, so buggify stays inert until that
    /// call (a causal gate — intent comes from the flag, not from predicting the
    /// guest). If the guest never calls it, the run fails loudly at finalization.
    pub after_setup: bool,
}

impl Default for BuggifyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            fire_permille: DEFAULT_BUGGIFY_FIRE_PERMILLE,
            activation_permille: DEFAULT_BUGGIFY_ACTIVATION_PERMILLE,
            cutoff_nanos: DEFAULT_BUGGIFY_CUTOFF_NANOS,
            after_setup: false,
        }
    }
}

/// Liveness-watchdog configuration: a deterministic, virtual-time-only no-progress
/// detector. Default (all `None`) is disabled, so a run that does not opt in is
/// byte-for-byte unchanged. The internal liveness watchdog owns the detection
/// semantics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LivenessConfig {
    /// Generic no-progress budget (virtual nanoseconds), armed from run start.
    /// `Some(0)` is rejected at parse time. `None` disables the generic arm.
    pub no_progress_budget_nanos: Option<u64>,
    /// Heal-then-converge budget (virtual nanoseconds), armed at the fault-window
    /// end (the buggify cutoff when buggify is enabled, else 0, unless
    /// [`heal_after_nanos`](Self::heal_after_nanos) overrides). `None` disables it.
    pub converge_budget_nanos: Option<u64>,
    /// Explicit override for the converge arm's arm-time (virtual nanoseconds).
    /// `None` derives it from the buggify cutoff / run start.
    pub heal_after_nanos: Option<u64>,
}

impl LivenessConfig {
    /// Whether any watchdog arm is configured.
    pub fn is_enabled(&self) -> bool {
        self.no_progress_budget_nanos.is_some() || self.converge_budget_nanos.is_some()
    }
}

/// Everything that determines a run: seed, [`ExecutionMode`], compatibility
/// fingerprint, fault/buggify/schedule/liveness knobs, and optional trace
/// metadata (guest argv, params).
///
/// Construct one with [`RuntimeConfig::seeded`] (or
/// [`record`](RuntimeConfig::record)/[`replay`](RuntimeConfig::replay)/
/// [`branch`](RuntimeConfig::branch)) and refine it with the `with_*` builder
/// methods, or read the whole thing from the `PATINA_*` control plane with
/// [`RuntimeConfig::from_env`]. Two runs with equal configs (and an identical
/// guest) produce byte-identical effect sequences.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeConfig {
    seed: u64,
    mode: ExecutionMode,
    fingerprint: String,
    step_budget: Option<u64>,
    params: BTreeMap<String, String>,
    faults: FaultConfig,
    buggify: BuggifyConfig,
    /// The exploration scheduling policy (PCT / starvation). Default is the
    /// uniform-random policy, byte-for-byte the historical scheduler.
    schedule_policy: SchedulePolicy,
    /// Whether swarm fault-class selection is enabled: a seed-derived subset of
    /// the enabled fault classes is applied this run instead of all of them.
    swarm: bool,
    /// The guest program arguments (`argv[1..]`) recorded into the trace so a
    /// `replay` restores them flag-free. `None` records nothing (unset); `Some`
    /// (possibly empty) records the exact list. Not a fingerprint input.
    guest_argv: Option<Vec<String>>,
    /// Deterministic guest environment values supplied at run startup. Empty by
    /// default; recorded into trace metadata when non-empty and restored on
    /// replay. Not a fingerprint input.
    guest_env: BTreeMap<String, String>,
    /// The DNS host table: the names this run resolves, and the virtual IPv4
    /// address each resolves to. Semantic configuration rather than a fault knob
    /// (like `params`): an undefined name is NXDOMAIN deterministically, and the
    /// `--dns-*` fault knobs act only on the names defined here. Recorded into
    /// trace metadata and reconciled on replay so a resolution reproduces without
    /// re-supplying the table. Not a fingerprint input — the recorded op stream
    /// already reflects every resolution outcome.
    dns_entries: BTreeMap<String, String>,
    /// The liveness-watchdog configuration. Default (disabled) leaves a run
    /// byte-for-byte unchanged; enabling it only ADDS a possible violation report
    /// and is deliberately NOT a fingerprint input (schedule-invariant).
    liveness: LivenessConfig,
    /// Which end-of-run diagnostic reports print. Presentation only: resolved
    /// once from the family's control plane, never fingerprinted, never recorded,
    /// never reconciled — a replay may silence a report the recording printed and
    /// still produce the identical op stream.
    reports: ReportConfig,
    /// Whether syscall-user-dispatch was armed for this run (Linux/x86_64 managed
    /// run on a SUD kernel). Recorded into the trace's [`RunMetadata::sud`] so a
    /// cross-kernel replay is refused up front. `None` on every non-SUD run
    /// (macOS, non-SUD kernel, standalone). Set by the native shim from the C
    /// arming state; not a fingerprint input. SUD-DESIGN.md §7.3.
    sud: Option<bool>,
    /// Whether the timestamp-counter trap (`prctl(PR_SET_TSC, PR_TSC_SIGSEGV)`)
    /// was armed for this run, so `rdtsc`/`rdtscp` were answered from the virtual
    /// clock. Recorded into the trace's [`RunMetadata::tsc`] and reconciled on
    /// replay for the same reason as `sud`: the two states observe the counter at
    /// different boundaries. `None` on every run that did not arm it.
    tsc: Option<bool>,
    /// Where the runtime writes this run's structured facts document, or `None`
    /// (the default) to produce none. Presentation-adjacent like `reports`: it
    /// reaches no recorded byte, is never fingerprinted, and is never reconciled
    /// on replay.
    facts_path: Option<std::path::PathBuf>,
}

impl RuntimeConfig {
    pub fn seeded(seed: u64) -> Self {
        Self {
            seed,
            mode: ExecutionMode::Seeded,
            fingerprint: DEFAULT_FINGERPRINT.into(),
            step_budget: None,
            params: BTreeMap::new(),
            faults: FaultConfig::default(),
            buggify: BuggifyConfig::default(),
            schedule_policy: SchedulePolicy::default(),
            swarm: false,
            guest_argv: None,
            guest_env: BTreeMap::new(),
            dns_entries: BTreeMap::new(),
            liveness: LivenessConfig::default(),
            reports: ReportConfig::default(),
            sud: None,
            tsc: None,
            facts_path: None,
        }
    }

    pub fn record(seed: u64, path: impl Into<PathBuf>, fingerprint: impl Into<String>) -> Self {
        Self {
            seed,
            mode: ExecutionMode::Record { path: path.into() },
            fingerprint: fingerprint.into(),
            step_budget: None,
            params: BTreeMap::new(),
            faults: FaultConfig::default(),
            buggify: BuggifyConfig::default(),
            schedule_policy: SchedulePolicy::default(),
            swarm: false,
            guest_argv: None,
            guest_env: BTreeMap::new(),
            dns_entries: BTreeMap::new(),
            liveness: LivenessConfig::default(),
            reports: ReportConfig::default(),
            sud: None,
            tsc: None,
            facts_path: None,
        }
    }

    pub fn replay(path: impl Into<PathBuf>, fingerprint: impl Into<String>) -> Self {
        Self::replay_timeline(path, "main", fingerprint)
    }

    /// Record through a [`TraceTransport`] installed on the builder.
    pub fn record_transport(seed: u64, fingerprint: impl Into<String>) -> Self {
        Self {
            seed,
            mode: ExecutionMode::RecordTransport,
            fingerprint: fingerprint.into(),
            step_budget: None,
            params: BTreeMap::new(),
            faults: FaultConfig::default(),
            buggify: BuggifyConfig::default(),
            schedule_policy: SchedulePolicy::default(),
            swarm: false,
            guest_argv: None,
            guest_env: BTreeMap::new(),
            dns_entries: BTreeMap::new(),
            liveness: LivenessConfig::default(),
            reports: ReportConfig::default(),
            sud: None,
            tsc: None,
            facts_path: None,
        }
    }

    /// Replay a timeline through a [`TraceTransport`] installed on the builder.
    pub fn replay_transport_timeline(
        timeline: impl Into<String>,
        fingerprint: impl Into<String>,
    ) -> Self {
        Self {
            seed: 0,
            mode: ExecutionMode::ReplayTransport {
                timeline: timeline.into(),
            },
            fingerprint: fingerprint.into(),
            step_budget: None,
            params: BTreeMap::new(),
            faults: FaultConfig::default(),
            buggify: BuggifyConfig::default(),
            schedule_policy: SchedulePolicy::default(),
            swarm: false,
            guest_argv: None,
            guest_env: BTreeMap::new(),
            dns_entries: BTreeMap::new(),
            liveness: LivenessConfig::default(),
            reports: ReportConfig::default(),
            sud: None,
            tsc: None,
            facts_path: None,
        }
    }

    pub fn replay_timeline(
        path: impl Into<PathBuf>,
        timeline: impl Into<String>,
        fingerprint: impl Into<String>,
    ) -> Self {
        Self {
            seed: 0,
            mode: ExecutionMode::Replay {
                path: path.into(),
                timeline: timeline.into(),
            },
            fingerprint: fingerprint.into(),
            step_budget: None,
            params: BTreeMap::new(),
            faults: FaultConfig::default(),
            buggify: BuggifyConfig::default(),
            schedule_policy: SchedulePolicy::default(),
            swarm: false,
            guest_argv: None,
            guest_env: BTreeMap::new(),
            dns_entries: BTreeMap::new(),
            liveness: LivenessConfig::default(),
            reports: ReportConfig::default(),
            sud: None,
            tsc: None,
            facts_path: None,
        }
    }

    pub fn branch(
        path: impl Into<PathBuf>,
        parent: impl Into<String>,
        from_sequence: u64,
        branch_id: impl Into<String>,
        branch_seed: u64,
        fingerprint: impl Into<String>,
    ) -> Self {
        Self {
            seed: branch_seed,
            mode: ExecutionMode::Branch {
                path: path.into(),
                parent: parent.into(),
                from_sequence,
                branch_id: branch_id.into(),
                branch_seed,
            },
            fingerprint: fingerprint.into(),
            step_budget: None,
            params: BTreeMap::new(),
            faults: FaultConfig::default(),
            buggify: BuggifyConfig::default(),
            schedule_policy: SchedulePolicy::default(),
            swarm: false,
            guest_argv: None,
            guest_env: BTreeMap::new(),
            dns_entries: BTreeMap::new(),
            liveness: LivenessConfig::default(),
            reports: ReportConfig::default(),
            sud: None,
            tsc: None,
            facts_path: None,
        }
    }

    pub fn with_step_budget(mut self, budget: u64) -> Self {
        self.step_budget = Some(budget);
        self
    }

    /// Set the base link latency applied to the default `SimNet` network.
    pub fn with_net_latency_nanos(mut self, nanos: u64) -> Self {
        self.faults.net.latency_nanos = nanos;
        self
    }

    pub const fn net_latency_nanos(&self) -> u64 {
        self.faults.net.latency_nanos
    }

    /// Inject a filesystem crash after the `ordinal`-th (1-based) `op` boundary.
    pub fn with_crash_at(mut self, op: CrashOp, ordinal: u64) -> Self {
        self.faults.fs.crash_at = Some(CrashPoint { op, ordinal });
        self
    }

    /// Select whole-block or sub-block byte-granularity tearing for an injected
    /// crash. Inert without [`RuntimeConfig::with_crash_at`].
    pub fn with_fs_torn_granularity(mut self, granularity: TornGranularity) -> Self {
        self.faults.fs.torn_granularity = granularity;
        self
    }

    /// Fail eligible filesystem operations with the given per-mille (0..=1000)
    /// probability, choosing a seeded errno from the operation's error set.
    pub fn with_fs_error_permille(mut self, permille: u16) -> Self {
        self.faults.fs.error_permille = permille;
        self
    }

    /// Truncate filesystem reads and writes with the given per-mille (0..=1000)
    /// probability.
    pub fn with_fs_short_permille(mut self, permille: u16) -> Self {
        self.faults.fs.short_permille = permille;
        self
    }

    /// Add seeded extra latency to every fault-eligible filesystem operation,
    /// drawn from `[min, max]` and applied before the operation executes.
    pub fn with_fs_latency_nanos(mut self, min: u64, max: u64) -> Self {
        self.faults.fs.latency_nanos = Some((min, max));
        self
    }

    /// Fail eligible DNS resolutions with the given per-mille (0..=1000)
    /// probability, choosing NXDOMAIN or a transient timeout on each fire.
    pub fn with_dns_fail_permille(mut self, permille: u16) -> Self {
        self.faults.dns.fail_permille = permille;
        self
    }

    /// Add seeded extra latency to every eligible name resolution.
    pub fn with_dns_latency_nanos(mut self, min: u64, max: u64) -> Self {
        self.faults.dns.latency_nanos = Some((min, max));
        self
    }

    /// Fail guest entropy requests with the given per-mille (0..=1000)
    /// probability, returning a deterministic named error instead of bytes.
    pub fn with_entropy_fail_permille(mut self, permille: u16) -> Self {
        self.faults.entropy.fail_permille = permille;
        self
    }

    /// Define a name in the run's DNS host table. Names not defined here are
    /// NXDOMAIN; the `--dns-*` fault knobs act only on defined ones.
    pub fn with_dns_entry(
        mut self,
        name: impl Into<String>,
        address: impl Into<String>,
    ) -> Result<Self, RuntimeError> {
        let (name, address) = (name.into(), address.into());
        validate_dns_entry(&name, &address)?;
        self.dns_entries.insert(name, address);
        Ok(self)
    }

    /// The run's DNS host table.
    pub const fn dns_entries(&self) -> &BTreeMap<String, String> {
        &self.dns_entries
    }

    /// Apply the DNS host table from a control-plane accessor, mirroring
    /// [`RuntimeConfig::apply_fault_env`]. The table is a JSON object; a
    /// malformed entry fails closed rather than silently resolving nothing.
    ///
    /// Separate from [`RuntimeConfig::apply_fault_env`] because a family may
    /// offer the host table WITHOUT the DNS fault knobs — `campaign` does, since
    /// it draws the knobs per generation — so the two planes are applied
    /// independently. [`Plane`] is where each knob records which one it lands on.
    pub fn apply_dns_env<F>(self, get: F) -> Result<Self, RuntimeError>
    where
        F: Fn(&str) -> Option<String>,
    {
        self.apply_knob_env(Plane::DnsTable, get)
    }

    /// Add seeded extra latency to every guest sleep, drawn from `[min, max]`.
    pub fn with_sleep_jitter_nanos(mut self, min: u64, max: u64) -> Self {
        self.faults.clock.sleep_jitter_nanos = Some((min, max));
        self
    }

    /// Jump each realtime-epoch read by a seeded signed offset drawn uniformly
    /// in `[-hi, hi]`, saturating at 0.
    pub fn with_epoch_jump_nanos(mut self, hi: u64) -> Self {
        self.faults.clock.epoch_jump_nanos = hi;
        self
    }

    /// Add seeded per-datagram delivery jitter drawn from `[min, max]`.
    pub fn with_net_jitter_nanos(mut self, min: u64, max: u64) -> Self {
        self.faults.net.jitter_nanos = Some((min, max));
        self
    }

    /// Drop datagrams with the given per-mille (0..=1000) probability.
    pub fn with_net_drop_permille(mut self, permille: u16) -> Self {
        self.faults.net.drop_permille = permille;
        self
    }

    /// Deliver datagrams twice with the given per-mille (0..=1000) probability.
    pub fn with_net_duplicate_permille(mut self, permille: u16) -> Self {
        self.faults.net.duplicate_permille = permille;
        self
    }

    /// Refuse otherwise-establishable TCP connections with the given per-mille
    /// (0..=1000) probability.
    pub fn with_net_connect_refuse_permille(mut self, permille: u16) -> Self {
        self.faults.net.connect_refuse_permille = permille;
        self
    }

    /// Reset established TCP streams with the given per-mille (0..=1000)
    /// probability per fault-eligible stream operation.
    pub fn with_net_reset_permille(mut self, permille: u16) -> Self {
        self.faults.net.reset_permille = permille;
        self
    }

    /// Partition both directions between two exact virtual addresses.
    pub fn with_net_partition(mut self, left: impl Into<String>, right: impl Into<String>) -> Self {
        let left = left.into();
        let right = right.into();
        self.faults
            .net
            .partitions
            .insert((left.clone(), right.clone()));
        self.faults.net.partitions.insert((right, left));
        self
    }

    /// Set the virtual TCP receive-buffer size in bytes.
    pub fn with_net_tcp_buffer_bytes(mut self, bytes: usize) -> Self {
        self.faults.net.tcp_buffer_bytes = Some(bytes);
        self
    }

    pub const fn crash_at(&self) -> Option<CrashPoint> {
        self.faults.fs.crash_at
    }

    /// The configured torn-write granularity for `--fs-crash-at`. `Block`
    /// (whole-block revert) unless `--fs-torn-granularity byte` selected the
    /// sub-block model.
    pub const fn torn_granularity(&self) -> TornGranularity {
        self.faults.fs.torn_granularity
    }

    /// Apply the fault-injection knobs from a control-plane accessor. Shared by
    /// [`RuntimeConfig::from_env`] (reading the process environment) and the
    /// native shim (reading its scrubbed constructor-time control plane), so both
    /// entry points parse the fault protocol identically and fail closed on any
    /// malformed value. Each knob defaults off when its variable is absent.
    pub fn apply_fault_env<F>(self, get: F) -> Result<Self, RuntimeError>
    where
        F: Fn(&str) -> Option<String>,
    {
        self.apply_knob_env(Plane::Fault, get)
    }

    /// Read every knob on one configuration plane off the control plane, in
    /// [`FaultKnob::ALL`] order, and layer it onto this configuration. The knob
    /// table decides WHICH variable carries each knob and which plane it lands
    /// on; [`RuntimeConfig::apply_one_knob`] decides how its value is parsed.
    fn apply_knob_env<F>(mut self, plane: Plane, get: F) -> Result<Self, RuntimeError>
    where
        F: Fn(&str) -> Option<String>,
    {
        for knob in FaultKnob::ALL {
            let meta = knob.meta();
            if meta.plane != plane {
                continue;
            }
            if let Some(value) = get(meta.env) {
                self.apply_one_knob(*knob, &value)?;
            }
        }
        Ok(self)
    }

    /// Parse one knob's control-plane value and apply it. The exhaustive match is
    /// the pairing: a knob added to [`FaultKnob`] has no way into a
    /// configuration until its protocol is written here, so it cannot be
    /// advertised by the CLI, forwarded by a family, and then silently ignored by
    /// the runtime — the silent-inertness class, which looks exactly like a clean
    /// run.
    fn apply_one_knob(&mut self, knob: FaultKnob, value: &str) -> Result<(), RuntimeError> {
        let env = knob.meta().env;
        match knob {
            FaultKnob::FsCrashAt => self.faults.fs.crash_at = Some(parse_crash_point(value)?),
            FaultKnob::FsTornGranularity => {
                self.faults.fs.torn_granularity = parse_torn_granularity(value)?;
            }
            FaultKnob::FsErrorPermille => {
                self.faults.fs.error_permille = parse_permille(env, value)?;
            }
            FaultKnob::FsShortPermille => {
                self.faults.fs.short_permille = parse_permille(env, value)?;
            }
            FaultKnob::FsLatencyNanos => {
                self.faults.fs.latency_nanos = Some(parse_nanos_range(env, value)?);
            }
            FaultKnob::SleepJitterNanos => {
                self.faults.clock.sleep_jitter_nanos = Some(parse_nanos_range(env, value)?);
            }
            FaultKnob::NetJitterNanos => {
                self.faults.net.jitter_nanos = Some(parse_nanos_range(env, value)?);
            }
            FaultKnob::NetDropPermille => {
                self.faults.net.drop_permille = parse_permille(env, value)?;
            }
            FaultKnob::NetLatencyNanos => {
                self.faults.net.latency_nanos = value.trim().parse().map_err(|_| {
                    RuntimeError::Config(format!("{env} must be an unsigned 64-bit integer"))
                })?;
            }
            FaultKnob::NetDuplicatePermille => {
                self.faults.net.duplicate_permille = parse_permille(env, value)?;
            }
            FaultKnob::NetConnectRefusePermille => {
                self.faults.net.connect_refuse_permille = parse_permille(env, value)?;
            }
            FaultKnob::NetResetPermille => {
                self.faults.net.reset_permille = parse_permille(env, value)?;
            }
            FaultKnob::NetPartition => {
                let pairs: Vec<(String, String)> = serde_json::from_str(value)
                    .map_err(|error| RuntimeError::Config(format!("{env} is invalid: {error}")))?;
                for (left, right) in pairs {
                    validate_partition(&left, &right)?;
                    self.faults
                        .net
                        .partitions
                        .insert((left.clone(), right.clone()));
                    self.faults.net.partitions.insert((right, left));
                }
            }
            FaultKnob::NetTcpBufferBytes => {
                let bytes: usize = value.trim().parse().map_err(|_| {
                    RuntimeError::Config(format!("{env} must be a non-negative machine integer"))
                })?;
                if bytes == 0 {
                    return Err(RuntimeError::Config(format!(
                        "{env} must be greater than zero"
                    )));
                }
                self.faults.net.tcp_buffer_bytes = Some(bytes);
            }
            FaultKnob::DnsEntry => {
                let entries: BTreeMap<String, String> = serde_json::from_str(value)
                    .map_err(|error| RuntimeError::Config(format!("{env} is invalid: {error}")))?;
                for (name, address) in &entries {
                    validate_dns_entry(name, address)?;
                }
                self.dns_entries = entries;
            }
            FaultKnob::DnsFailPermille => {
                self.faults.dns.fail_permille = parse_permille(env, value)?;
            }
            FaultKnob::DnsLatencyNanos => {
                self.faults.dns.latency_nanos = Some(parse_nanos_range(env, value)?);
            }
            FaultKnob::EntropyFailPermille => {
                self.faults.entropy.fail_permille = parse_permille(env, value)?;
            }
            FaultKnob::EpochJumpNanos => {
                self.faults.clock.epoch_jump_nanos = value.trim().parse().map_err(|_| {
                    RuntimeError::Config(format!("{env} must be an unsigned 64-bit integer"))
                })?;
            }
        }
        Ok(())
    }

    /// The run's cooperative-SUT (buggify) configuration.
    pub const fn buggify(&self) -> BuggifyConfig {
        self.buggify
    }

    /// Set the run's cooperative-SUT (buggify) configuration directly (used by
    /// tests and explicit-API embedders).
    #[must_use]
    pub fn with_buggify(mut self, buggify: BuggifyConfig) -> Self {
        self.buggify = buggify;
        self
    }

    /// Apply the cooperative-SUT (buggify) knobs from a control-plane accessor,
    /// mirroring [`RuntimeConfig::apply_fault_env`]. Presence of [`ENV_BUGGIFY`]
    /// enables buggify; its value (if non-empty) is the per-evaluation firing
    /// per-mille. Activation and cutoff come from their own variables, defaulting
    /// to the FoundationDB defaults. Absence leaves buggify disabled (zero
    /// behavior change).
    pub fn apply_buggify_env<F>(mut self, get: F) -> Result<Self, RuntimeError>
    where
        F: Fn(&str) -> Option<String>,
    {
        let Some(fire) = get(ENV_BUGGIFY) else {
            return Ok(self);
        };
        self.buggify.enabled = true;
        let fire = fire.trim();
        if !fire.is_empty() {
            self.buggify.fire_permille = parse_permille(ENV_BUGGIFY, fire)?;
        }
        if let Some(value) = get(ENV_BUGGIFY_ACTIVATION) {
            self.buggify.activation_permille =
                parse_permille(ENV_BUGGIFY_ACTIVATION, value.trim())?;
        }
        if let Some(value) = get(ENV_BUGGIFY_CUTOFF) {
            self.buggify.cutoff_nanos = value.trim().parse().map_err(|_| {
                RuntimeError::Config(format!(
                    "{ENV_BUGGIFY_CUTOFF} must be an unsigned 64-bit integer"
                ))
            })?;
        }
        if let Some(value) = get(ENV_BUGGIFY_AFTER_SETUP) {
            self.buggify.after_setup = !matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "" | "0" | "off" | "false" | "no"
            );
        }
        Ok(self)
    }

    /// The recorded guest program arguments (`argv[1..]`), or `None` when unset.
    pub fn guest_argv(&self) -> Option<&[String]> {
        self.guest_argv.as_deref()
    }

    /// Set the guest program arguments recorded into the trace directly (used by
    /// tests and explicit-API embedders).
    #[must_use]
    pub fn with_guest_argv(mut self, guest_argv: Option<Vec<String>>) -> Self {
        self.guest_argv = guest_argv;
        self
    }

    /// Deterministic guest environment values supplied at startup.
    pub fn guest_env(&self) -> &BTreeMap<String, String> {
        &self.guest_env
    }

    /// Set deterministic guest environment values directly (tests and embedders).
    #[must_use]
    pub fn with_guest_env(mut self, guest_env: BTreeMap<String, String>) -> Self {
        self.guest_env = guest_env;
        self
    }

    /// Whether syscall-user-dispatch was armed for this run, or `None` when SUD
    /// is not applicable.
    pub const fn sud(&self) -> Option<bool> {
        self.sud
    }

    /// Whether the timestamp-counter trap was armed for this run, or `None` when
    /// it was not (see the field docs).
    pub const fn tsc(&self) -> Option<bool> {
        self.tsc
    }

    /// Set whether syscall-user-dispatch was armed for this run. The native shim
    /// calls this from the C arming state so record captures it into the trace
    /// and replay reconciles it. `Some(true)` when armed; `None` otherwise.
    #[must_use]
    pub fn with_sud(mut self, sud: Option<bool>) -> Self {
        self.sud = sud;
        self
    }

    /// Record whether this run armed the timestamp-counter trap.
    #[must_use]
    pub fn with_tsc(mut self, tsc: Option<bool>) -> Self {
        self.tsc = tsc;
        self
    }

    /// Apply the guest program arguments from a control-plane accessor, mirroring
    /// [`RuntimeConfig::apply_fault_env`]. Presence of [`ENV_GUEST_ARGV`] sets the
    /// recorded argv from its JSON string-array value; absence leaves it unset
    /// (zero behavior change). Malformed JSON is rejected fail-closed. Shared by
    /// [`RuntimeConfig::from_env`] and the native shim so both entry points parse
    /// the argv protocol identically.
    pub fn apply_guest_argv_env<F>(mut self, get: F) -> Result<Self, RuntimeError>
    where
        F: Fn(&str) -> Option<String>,
    {
        if let Some(value) = get(ENV_GUEST_ARGV) {
            let argv: Vec<String> = serde_json::from_str(&value).map_err(|error| {
                RuntimeError::Config(format!("{ENV_GUEST_ARGV} is invalid: {error}"))
            })?;
            self.guest_argv = Some(argv);
        }
        Ok(self)
    }

    /// Apply deterministic guest environment values from a control-plane
    /// accessor. Presence of [`ENV_GUEST_ENV`] sets the environment from its JSON
    /// object value; absence leaves it empty. Malformed JSON or invalid keys/values
    /// fail closed. Shared by [`RuntimeConfig::from_env`] and the native shim.
    pub fn apply_guest_env_env<F>(mut self, get: F) -> Result<Self, RuntimeError>
    where
        F: Fn(&str) -> Option<String>,
    {
        if let Some(value) = get(ENV_GUEST_ENV) {
            let guest_env: BTreeMap<String, String> =
                serde_json::from_str(&value).map_err(|error| {
                    RuntimeError::Config(format!("{ENV_GUEST_ENV} is invalid: {error}"))
                })?;
            validate_guest_env(&guest_env)?;
            self.guest_env = guest_env;
        }
        Ok(self)
    }

    /// The run's exploration scheduling policy.
    pub const fn schedule_policy(&self) -> SchedulePolicy {
        self.schedule_policy
    }

    /// Set the exploration scheduling policy directly (tests, explicit embedders).
    #[must_use]
    pub fn with_schedule_policy(mut self, policy: SchedulePolicy) -> Self {
        self.schedule_policy = policy;
        self
    }

    /// Whether swarm fault-class selection is enabled for this run.
    pub const fn swarm(&self) -> bool {
        self.swarm
    }

    /// Enable or disable swarm fault-class selection directly.
    #[must_use]
    pub fn with_swarm(mut self, swarm: bool) -> Self {
        self.swarm = swarm;
        self
    }

    /// Apply the exploration scheduling-policy knobs from a control-plane
    /// accessor, mirroring [`RuntimeConfig::apply_fault_env`]. Presence of
    /// [`ENV_SCHED_PCT`] enables PCT (its value is the bug depth `d`, empty =
    /// default); presence of [`ENV_SCHED_STARVE`] enables starvation intervals
    /// (its value is the interval count). Absence leaves the default uniform
    /// policy (zero behavior change). Malformed values are rejected fail-closed.
    pub fn apply_schedule_env<F>(mut self, get: F) -> Result<Self, RuntimeError>
    where
        F: Fn(&str) -> Option<String>,
    {
        if let Some(value) = get(ENV_SCHED_PCT) {
            let value = value.trim();
            let depth = if value.is_empty() {
                DEFAULT_PCT_DEPTH
            } else {
                let depth: u32 = value.parse().map_err(|_| {
                    RuntimeError::Config(format!(
                        "{ENV_SCHED_PCT} must be an unsigned integer >= 1"
                    ))
                })?;
                if depth < 1 {
                    return Err(RuntimeError::Config(format!(
                        "{ENV_SCHED_PCT} bug depth must be >= 1"
                    )));
                }
                depth
            };
            let steps = match get(ENV_SCHED_PCT_STEPS) {
                Some(value) => value.trim().parse().map_err(|_| {
                    RuntimeError::Config(format!(
                        "{ENV_SCHED_PCT_STEPS} must be an unsigned 64-bit integer"
                    ))
                })?,
                None => DEFAULT_PCT_STEPS,
            };
            if steps < 1 {
                return Err(RuntimeError::Config(format!(
                    "{ENV_SCHED_PCT_STEPS} must be >= 1"
                )));
            }
            self.schedule_policy.pct = Some(PctConfig { depth, steps });
        }
        if let Some(value) = get(ENV_SCHED_STARVE) {
            let value = value.trim();
            let intervals = if value.is_empty() {
                DEFAULT_STARVE_INTERVALS
            } else {
                value.parse().map_err(|_| {
                    RuntimeError::Config(format!(
                        "{ENV_SCHED_STARVE} must be an unsigned integer >= 1"
                    ))
                })?
            };
            if intervals < 1 {
                return Err(RuntimeError::Config(format!(
                    "{ENV_SCHED_STARVE} interval count must be >= 1"
                )));
            }
            let max_len = match get(ENV_SCHED_STARVE_MAX_LEN) {
                Some(value) => value.trim().parse().map_err(|_| {
                    RuntimeError::Config(format!(
                        "{ENV_SCHED_STARVE_MAX_LEN} must be an unsigned 64-bit integer"
                    ))
                })?,
                None => DEFAULT_STARVE_MAX_LEN,
            };
            let window = match get(ENV_SCHED_STARVE_WINDOW) {
                Some(value) => value.trim().parse().map_err(|_| {
                    RuntimeError::Config(format!(
                        "{ENV_SCHED_STARVE_WINDOW} must be an unsigned 64-bit integer"
                    ))
                })?,
                None => DEFAULT_STARVE_WINDOW,
            };
            if max_len < 1 || window < 1 {
                return Err(RuntimeError::Config(format!(
                    "{ENV_SCHED_STARVE_MAX_LEN} and {ENV_SCHED_STARVE_WINDOW} must be >= 1 so \
                     intervals are bounded and placeable"
                )));
            }
            self.schedule_policy.starvation = Some(StarvationConfig {
                intervals,
                max_len,
                window,
            });
        }
        Ok(self)
    }

    /// Apply the swarm fault-class-selection knob from a control-plane accessor.
    /// Presence of a truthy [`ENV_SWARM`] enables swarm; a false-y value (or
    /// absence) leaves it off (the existing always-all behavior).
    pub fn apply_swarm_env<F>(mut self, get: F) -> Result<Self, RuntimeError>
    where
        F: Fn(&str) -> Option<String>,
    {
        if let Some(value) = get(ENV_SWARM) {
            self.swarm = !matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "" | "0" | "off" | "false" | "no"
            );
        }
        Ok(self)
    }

    /// Install the end-of-run report-suppression preferences wholesale, for a
    /// family that resolved them from its own control plane (the native shim
    /// parses its pre-scrub environment snapshot once and shares the result with
    /// its own coverage finalization).
    #[must_use]
    pub const fn with_reports(mut self, reports: ReportConfig) -> Self {
        self.reports = reports;
        self
    }

    /// Write this run's structured [`patina.runfacts/v1`](FACTS_SCHEMA) document
    /// to `path` at finalization. The document carries the same per-plane
    /// accounting the `PATINA_*_REPORT` lines carry, built from the report
    /// structs; the lines still print. Independent of [`ReportConfig`], which
    /// governs printing only.
    #[must_use]
    pub fn with_facts_path(mut self, path: impl Into<std::path::PathBuf>) -> Self {
        self.facts_path = Some(path.into());
        self
    }

    /// Read the facts-document path from the control plane ([`ENV_FACTS`]).
    pub fn apply_facts_env<F>(mut self, get: F) -> Self
    where
        F: Fn(&str) -> Option<String>,
    {
        if let Some(value) = get(ENV_FACTS) {
            if !value.trim().is_empty() {
                self.facts_path = Some(std::path::PathBuf::from(value));
            }
        }
        self
    }

    /// Which end-of-run diagnostic reports this run prints.
    #[must_use]
    pub const fn reports(&self) -> ReportConfig {
        self.reports
    }

    /// Apply the end-of-run report-suppression knobs from a control-plane
    /// accessor, mirroring [`RuntimeConfig::apply_fault_env`]. Every [`Report`]'s
    /// variable is resolved here, ONCE, because finalization has no usable view
    /// of the process environment on the native path.
    #[must_use]
    pub fn apply_report_env<F>(mut self, get: F) -> Self
    where
        F: Fn(&str) -> Option<String>,
    {
        self.reports = self.reports.applied(get);
        self
    }

    /// Install the liveness-watchdog configuration.
    #[must_use]
    pub fn with_liveness(mut self, liveness: LivenessConfig) -> Self {
        self.liveness = liveness;
        self
    }

    /// The configured liveness-watchdog knobs.
    pub const fn liveness(&self) -> LivenessConfig {
        self.liveness
    }

    /// Apply the liveness-watchdog knobs from a control-plane accessor. A present
    /// [`ENV_LIVENESS_WATCHDOG`] enables the generic no-progress arm (its value, if
    /// non-empty, being the budget in nanoseconds); [`ENV_CONVERGE_WITHIN`] enables
    /// the heal-then-converge arm; [`ENV_HEAL_AFTER`] overrides its arm-time. A
    /// zero budget is rejected so the watchdog cannot be armed to fire vacuously.
    pub fn apply_liveness_env<F>(mut self, get: F) -> Result<Self, RuntimeError>
    where
        F: Fn(&str) -> Option<String>,
    {
        let parse_budget = |name: &str, value: String, default: u64| -> Result<u64, RuntimeError> {
            let value = value.trim();
            if value.is_empty() {
                return Ok(default);
            }
            let nanos: u64 = value.parse().map_err(|_| {
                RuntimeError::Config(format!("{name} must be an unsigned 64-bit integer"))
            })?;
            if nanos == 0 {
                return Err(RuntimeError::Config(format!(
                    "{name} budget must be > 0 so the watchdog cannot fire vacuously"
                )));
            }
            Ok(nanos)
        };
        if let Some(value) = get(ENV_LIVENESS_WATCHDOG) {
            self.liveness.no_progress_budget_nanos = Some(parse_budget(
                ENV_LIVENESS_WATCHDOG,
                value,
                DEFAULT_LIVENESS_BUDGET_NANOS,
            )?);
        }
        if let Some(value) = get(ENV_CONVERGE_WITHIN) {
            self.liveness.converge_budget_nanos = Some(parse_budget(
                ENV_CONVERGE_WITHIN,
                value,
                DEFAULT_CONVERGE_BUDGET_NANOS,
            )?);
        }
        if let Some(value) = get(ENV_HEAL_AFTER) {
            let value = value.trim();
            if !value.is_empty() {
                self.liveness.heal_after_nanos = Some(value.parse().map_err(|_| {
                    RuntimeError::Config(format!(
                        "{ENV_HEAL_AFTER} must be an unsigned 64-bit integer"
                    ))
                })?);
            }
        }
        Ok(self)
    }

    pub fn with_param(
        mut self,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<Self, RuntimeError> {
        let key = key.into();
        if key.is_empty() {
            return Err(RuntimeError::Config(
                "runtime parameter key must not be empty".into(),
            ));
        }
        self.params.insert(key, value.into());
        Ok(self)
    }

    pub fn from_env() -> Result<Self, RuntimeError> {
        let mode = env::var(ENV_MODE).unwrap_or_else(|_| "seeded".into());
        let seed = parse_seed(env::var(ENV_SEED).ok())?;
        let trace_fd = trace_fd_from_env()?;
        if trace_fd.is_some() && env::var_os(ENV_TRACE).is_some_and(|value| !value.is_empty()) {
            return Err(RuntimeError::Config(format!(
                "{ENV_TRACE} and {ENV_TRACE_FD} must not both be set"
            )));
        }
        let config = match (mode.as_str(), trace_fd) {
            ("seeded", None) => Self::seeded(seed),
            ("seeded", Some(_)) => {
                return Err(RuntimeError::Config(format!(
                    "{ENV_TRACE_FD} is only meaningful in record or replay mode"
                )));
            }
            ("record", None) => Self::record(
                seed,
                required_path(ENV_TRACE)?,
                required_string(ENV_FINGERPRINT)?,
            ),
            ("record", Some(_)) => Self::record_transport(seed, required_string(ENV_FINGERPRINT)?),
            ("replay", None) => Self::replay_timeline(
                required_path(ENV_TRACE)?,
                env::var(ENV_TIMELINE).unwrap_or_else(|_| "main".into()),
                required_string(ENV_FINGERPRINT)?,
            ),
            ("replay", Some(_)) => Self::replay_transport_timeline(
                env::var(ENV_TIMELINE).unwrap_or_else(|_| "main".into()),
                required_string(ENV_FINGERPRINT)?,
            ),
            ("branch", None) => Self::branch(
                required_path(ENV_TRACE)?,
                env::var(ENV_PARENT_TIMELINE).unwrap_or_else(|_| "main".into()),
                required_u64(ENV_BRANCH_FROM)?,
                required_string(ENV_BRANCH_ID)?,
                required_u64(ENV_BRANCH_SEED)?,
                required_string(ENV_FINGERPRINT)?,
            ),
            ("branch", Some(_)) => {
                return Err(RuntimeError::Config(format!(
                    "branch mode requires a {ENV_TRACE} path; {ENV_TRACE_FD} is unsupported"
                )));
            }
            (value, _) => {
                return Err(RuntimeError::Config(format!(
                    "{ENV_MODE} must be seeded, record, replay, or branch; got {value:?}"
                )));
            }
        };
        let mut config = match env::var(ENV_STEP_BUDGET) {
            Ok(value) => config.with_step_budget(value.parse().map_err(|_| {
                RuntimeError::Config(format!(
                    "{ENV_STEP_BUDGET} must be an unsigned 64-bit integer"
                ))
            })?),
            Err(env::VarError::NotPresent) => config,
            Err(env::VarError::NotUnicode(_)) => {
                return Err(RuntimeError::Config(format!(
                    "{ENV_STEP_BUDGET} must be valid UTF-8"
                )));
            }
        };
        if let Some(value) = env::var_os(ENV_PARAMS_JSON) {
            let value = value.into_string().map_err(|_| {
                RuntimeError::Config(format!("{ENV_PARAMS_JSON} must be valid UTF-8"))
            })?;
            let params: BTreeMap<String, String> =
                serde_json::from_str(&value).map_err(|error| {
                    RuntimeError::Config(format!("{ENV_PARAMS_JSON} is invalid: {error}"))
                })?;
            if params.keys().any(String::is_empty) {
                return Err(RuntimeError::Config(
                    "runtime parameter key must not be empty".into(),
                ));
            }
            config.params = params;
        }
        let config = config.apply_fault_env(|name| env::var(name).ok())?;
        let config = config.apply_dns_env(|name| env::var(name).ok())?;
        let config = config.apply_buggify_env(|name| env::var(name).ok())?;
        let config = config.apply_schedule_env(|name| env::var(name).ok())?;
        let config = config.apply_swarm_env(|name| env::var(name).ok())?;
        let config = config.apply_liveness_env(|name| env::var(name).ok())?;
        let config = config.apply_guest_argv_env(|name| env::var(name).ok())?;
        let config = config.apply_guest_env_env(|name| env::var(name).ok())?;
        // The report-suppression knobs are resolved HERE, with every other knob,
        // and never again: finalization must not reach for the process
        // environment (see `ReportConfig`).
        let config = config.apply_report_env(|name| env::var(name).ok());
        // The facts channel, resolved with every other knob. A descriptor
        // channel ([`ENV_FACTS_FD`]) is installed by the embedder that owns the
        // descriptor (the native shim), so the two must never both be live.
        if env::var_os(ENV_FACTS_FD).is_some_and(|value| !value.is_empty())
            && env::var_os(ENV_FACTS).is_some_and(|value| !value.is_empty())
        {
            return Err(RuntimeError::Config(format!(
                "{ENV_FACTS} and {ENV_FACTS_FD} must not both be set"
            )));
        }
        let config = config.apply_facts_env(|name| env::var(name).ok());
        Ok(config)
    }

    pub const fn seed(&self) -> u64 {
        self.seed
    }

    pub const fn mode(&self) -> &ExecutionMode {
        &self.mode
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
}

/// Low-level explicit-context entry point: run a closure against a [`Context`]
/// with deterministic default drivers configured from `PATINA_*`.
///
/// This is the mode-3 explicit-context API of `USAGE-MODES.md`. It creates an
/// explicit context and does **not** control unrelated `std::fs`/`std::net`/clock
/// calls in the rest of the program — those are interposed by the native shim or
/// WASI host under `cargo patina build`/`run`. To configure Patina and then drive
/// ordinary application code, use the shim-backed `patina-dst-harness` crate.
///
/// The context is always finalized. If both the closure and finalization fail,
/// the returned error retains both failures.
pub fn run<T>(
    operation: impl FnOnce(&mut Context) -> Result<T, RuntimeError>,
) -> Result<T, RuntimeError> {
    run_with(|builder| builder, operation)
}

/// Like [`run`] but allows typed driver replacement before the context is built.
///
/// The builder starts from [`RuntimeConfig::from_env`] with the default drivers
/// installed; `configure` may swap in alternative drivers (network, filesystem,
/// clock, …) before the context runs.
pub fn run_with<T>(
    configure: impl FnOnce(RuntimeBuilder) -> RuntimeBuilder,
    operation: impl FnOnce(&mut Context) -> Result<T, RuntimeError>,
) -> Result<T, RuntimeError> {
    let builder = RuntimeBuilder::new(RuntimeConfig::from_env()?).with_default_drivers();
    run_with_context(configure(builder).build()?, operation)
}

fn run_with_context<T>(
    mut context: Context,
    operation: impl FnOnce(&mut Context) -> Result<T, RuntimeError>,
) -> Result<T, RuntimeError> {
    let run_result = operation(&mut context);
    let finish_result = context.finish();
    match (run_result, finish_result) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Err(run), Err(finalize)) => Err(RuntimeError::RunAndFinalize {
            run: Box::new(run),
            finalize: Box::new(finalize),
        }),
    }
}

/// Assembles a [`Context`] from a [`RuntimeConfig`] plus a driver per effect
/// family (filesystem, clock, entropy, scheduler, network).
///
/// [`with_default_drivers`](RuntimeBuilder::with_default_drivers) installs the
/// standard deterministic set; any `with_*` driver call overrides one slot with
/// a caller-supplied implementation of the `patina-dst-driver-api` trait —
/// this is how [`run_with`] callers add latency/fault wrapper drivers or a
/// custom network. [`build`](RuntimeBuilder::build) validates the combination
/// and is the single choke point that wires config-driven fault injection
/// (e.g. the crash filesystem) so a parsed knob can never be silently dropped.
pub struct RuntimeBuilder {
    config: RuntimeConfig,
    install_defaults: bool,
    trace_transport: Option<Box<dyn TraceTransport>>,
    filesystem: Option<Box<dyn FsDriver>>,
    filesystem_is_capture: bool,
    /// Durable base image for the runtime-built crash/mem filesystem. Callers
    /// that want config-driven crash-consistency (the shim, and any operator
    /// path) supply the image here rather than pre-installing a filesystem, so
    /// `build` is the single choke point that constructs the `CrashFs` from
    /// `config.faults`. A pre-installed `filesystem` and an `fs_image` are
    /// mutually exclusive.
    fs_image: Option<MemFs>,
    clock: Option<Box<dyn ClockDriver>>,
    entropy: Option<Box<dyn EntropyDriver>>,
    scheduler: Option<Box<dyn SchedulerDriver>>,
    network: Option<Box<dyn NetDriver>>,
    /// Byte channel for the run's structured facts document, for embedders whose
    /// guest cannot write a host file directly (the native shim).
    facts_sink: Option<Box<dyn FactsSink>>,
}

impl RuntimeBuilder {
    pub fn new(config: RuntimeConfig) -> Self {
        Self {
            config,
            install_defaults: false,
            trace_transport: None,
            filesystem: None,
            filesystem_is_capture: false,
            fs_image: None,
            clock: None,
            entropy: None,
            scheduler: None,
            network: None,
            facts_sink: None,
        }
    }

    /// Install the byte channel the run's structured facts document is written
    /// to. Mutually exclusive with [`RuntimeConfig::with_facts_path`]: two live
    /// destinations would mean one silently wins, so `build` refuses both.
    pub fn with_facts_sink(mut self, sink: impl FactsSink + 'static) -> Self {
        self.facts_sink = Some(Box::new(sink));
        self
    }

    pub fn with_default_drivers(mut self) -> Self {
        self.install_defaults = true;
        self
    }

    /// Install the byte-level trace channel required by the transport modes.
    pub fn with_trace_transport(mut self, transport: impl TraceTransport + 'static) -> Self {
        self.trace_transport = Some(Box::new(transport));
        self
    }

    pub fn with_filesystem(mut self, driver: impl FsDriver + 'static) -> Self {
        self.filesystem = Some(Box::new(driver));
        self.filesystem_is_capture = false;
        self
    }

    /// Supply the durable base image the runtime wraps in its own
    /// config-driven filesystem. When `--fs-crash-at` is configured, `build`
    /// wraps this image in a [`CrashFs`] seeded and torn-write-configured from
    /// `config.faults`; otherwise the image is used directly. This is the path
    /// production callers (the shim) must use so no parsed fault knob can be
    /// silently dropped by a pre-installed filesystem — the crash filesystem is
    /// only ever constructed at the single choke point in `build`.
    pub fn with_fs_image(mut self, image: MemFs) -> Self {
        self.fs_image = Some(image);
        self
    }

    /// Install an explicitly allowlisted host-capture filesystem.
    ///
    /// Replay returns recorded filesystem outcomes without contacting the
    /// host. A branch that reaches an unrecorded filesystem operation fails.
    pub fn with_captured_filesystem(mut self, driver: impl FsDriver + 'static) -> Self {
        self.filesystem = Some(Box::new(driver));
        self.filesystem_is_capture = true;
        self
    }

    pub fn with_clock(mut self, driver: impl ClockDriver + 'static) -> Self {
        self.clock = Some(Box::new(driver));
        self
    }

    pub fn with_entropy(mut self, driver: impl EntropyDriver + 'static) -> Self {
        self.entropy = Some(Box::new(driver));
        self
    }

    pub fn with_scheduler(mut self, driver: impl SchedulerDriver + 'static) -> Self {
        self.scheduler = Some(Box::new(driver));
        self
    }

    pub fn with_network(mut self, driver: impl NetDriver + 'static) -> Self {
        self.network = Some(Box::new(driver));
        self
    }

    pub fn build(mut self) -> Result<Context, RuntimeError> {
        if self.config.fingerprint.is_empty() {
            return Err(RuntimeError::Config(
                "runtime compatibility fingerprint must not be empty".into(),
            ));
        }
        validate_guest_env(&self.config.guest_env)?;

        match self.config.mode {
            ExecutionMode::RecordTransport | ExecutionMode::ReplayTransport { .. } => {
                if self.trace_transport.is_none() {
                    return Err(RuntimeError::Config(
                        "trace transport mode requires an installed trace transport".into(),
                    ));
                }
            }
            _ => {
                if self.trace_transport.is_some() {
                    return Err(RuntimeError::Config(
                        "a trace transport is only usable with transport record/replay modes"
                            .into(),
                    ));
                }
            }
        }
        if matches!(
            self.config.mode,
            ExecutionMode::Seeded | ExecutionMode::Record { .. } | ExecutionMode::RecordTransport
        ) {
            validate_buggify_fingerprint_contract(&self.config)?;
        }

        // Swarm fault-class selection: for a record/seeded run, mask the enabled
        // fault classes down to a seed-derived subset BEFORE any driver or
        // metadata record consumes `self.config.faults`. Not applied on
        // replay/branch, where the trace's recorded (already-masked) fault config
        // is authoritative and re-masking would double-select. The record is
        // attached to the recorder metadata below.
        let mut swarm_record = if self.config.swarm
            && matches!(
                self.config.mode,
                ExecutionMode::Seeded
                    | ExecutionMode::Record { .. }
                    | ExecutionMode::RecordTransport
            ) {
            Some(apply_swarm_mask(&mut self.config))
        } else {
            None
        };

        // A replayed or branched trace supplies its own authoritative fault
        // configuration, applied to `self.config` after the match releases its
        // borrow. `None` leaves the operator-supplied configuration in place.
        let mut replay_fault_override: Option<FaultConfig> = None;
        // Same contract for the cooperative-SUT (buggify) configuration: a
        // replayed/branched trace's recorded config is authoritative.
        let mut replay_buggify_override: Option<BuggifyConfig> = None;
        // Same contract for deterministic guest environment values.
        let mut replay_guest_env_override: Option<BTreeMap<String, String>> = None;
        let mut replay_dns_override: Option<BTreeMap<String, String>> = None;
        // Same contract for the exploration scheduling policy.
        let mut replay_schedule_override: Option<SchedulePolicy> = None;
        let (execution, root_seed) = match &self.config.mode {
            ExecutionMode::Seeded => (Execution::Seeded, self.config.seed),
            ExecutionMode::Record { path } => (
                Execution::Record {
                    recorder: Recorder::new(
                        RunMetadata::new(self.config.seed, self.config.fingerprint.clone())
                            .with_faults(Some(fault_record(&self.config)))
                            .with_buggify(buggify_record(&self.config))
                            .with_schedule_policy(schedule_policy_record(&self.config))
                            .with_swarm(swarm_record.clone())
                            .with_watchdog(watchdog_record(&self.config))
                            .with_guest_argv(self.config.guest_argv.clone())
                            .with_guest_env(guest_env_record(&self.config))
                            .with_dns(dns_record(&self.config))
                            .with_sud(self.config.sud)
                            .with_tsc(self.config.tsc),
                    ),
                    sink: RecordSink::Path {
                        path: path.clone(),
                        _reservation: RecordReservation::acquire(path)?,
                    },
                },
                self.config.seed,
            ),
            ExecutionMode::RecordTransport => (
                Execution::Record {
                    recorder: Recorder::new(
                        RunMetadata::new(self.config.seed, self.config.fingerprint.clone())
                            .with_faults(Some(fault_record(&self.config)))
                            .with_buggify(buggify_record(&self.config))
                            .with_schedule_policy(schedule_policy_record(&self.config))
                            .with_swarm(swarm_record.clone())
                            .with_watchdog(watchdog_record(&self.config))
                            .with_guest_argv(self.config.guest_argv.clone())
                            .with_guest_env(guest_env_record(&self.config))
                            .with_dns(dns_record(&self.config))
                            .with_sud(self.config.sud)
                            .with_tsc(self.config.tsc),
                    ),
                    sink: RecordSink::Transport(
                        self.trace_transport.take().expect("transport was checked"),
                    ),
                },
                self.config.seed,
            ),
            ExecutionMode::Replay { path, timeline } => {
                let replayer = Replayer::open_timeline(path, &self.config.fingerprint, timeline)?;
                let root_seed = replayer.root_seed();
                // The trace's fault configuration is authoritative on replay.
                replay_fault_override =
                    reconcile_replay_faults(&self.config, replayer.fault_config())?;
                replay_buggify_override =
                    reconcile_replay_buggify(&self.config, replayer.buggify_config())?;
                replay_guest_env_override =
                    reconcile_replay_guest_env(&self.config, replayer.guest_env())?;
                replay_dns_override = reconcile_replay_dns(&self.config, replayer.dns_config())?;
                replay_schedule_override =
                    reconcile_replay_schedule_policy(&self.config, replayer.schedule_policy())?;
                reconcile_replay_sud(&self.config, replayer.sud())?;
                reconcile_replay_tsc(&self.config, replayer.tsc())?;
                // The recording's swarm decision is authoritative and purely
                // descriptive on replay (the trace's already-masked fault/buggify
                // records drive the drivers). Adopting it makes a replay emit the
                // same PATINA_SWARM_REPORT and swarm_deselected the recording did.
                swarm_record = replayer.swarm_config().cloned();
                (Execution::Replay(replayer), root_seed)
            }
            ExecutionMode::ReplayTransport { timeline } => {
                let mut transport = self.trace_transport.take().expect("transport was checked");
                let bytes = transport.read_bundle().map_err(|source| RuntimeError::Io {
                    action: "read trace bundle from trace transport".into(),
                    source,
                })?;
                let bundle = TraceBundle::from_slice(&bytes)?;
                let replayer = Replayer::from_bundle(bundle, &self.config.fingerprint, timeline)?;
                let root_seed = replayer.root_seed();
                replay_fault_override =
                    reconcile_replay_faults(&self.config, replayer.fault_config())?;
                replay_buggify_override =
                    reconcile_replay_buggify(&self.config, replayer.buggify_config())?;
                replay_guest_env_override =
                    reconcile_replay_guest_env(&self.config, replayer.guest_env())?;
                replay_dns_override = reconcile_replay_dns(&self.config, replayer.dns_config())?;
                replay_schedule_override =
                    reconcile_replay_schedule_policy(&self.config, replayer.schedule_policy())?;
                reconcile_replay_sud(&self.config, replayer.sud())?;
                reconcile_replay_tsc(&self.config, replayer.tsc())?;
                swarm_record = replayer.swarm_config().cloned();
                (Execution::Replay(replayer), root_seed)
            }
            ExecutionMode::Branch {
                path,
                parent,
                from_sequence,
                branch_id,
                branch_seed,
            } => {
                let reservation = RecordReservation::acquire_branch(path)?;
                let session = BranchSession::open(
                    path,
                    &self.config.fingerprint,
                    parent,
                    *from_sequence,
                    branch_id.clone(),
                    *branch_seed,
                )?;
                // A branch replays the parent prefix, so it inherits the parent
                // trace's fault configuration for the replayed drivers.
                replay_fault_override =
                    reconcile_replay_faults(&self.config, session.fault_config())?;
                replay_buggify_override =
                    reconcile_replay_buggify(&self.config, session.buggify_config())?;
                replay_guest_env_override =
                    reconcile_replay_guest_env(&self.config, session.guest_env())?;
                replay_dns_override = reconcile_replay_dns(&self.config, session.dns_config())?;
                replay_schedule_override =
                    reconcile_replay_schedule_policy(&self.config, session.schedule_policy())?;
                // A branch inherits the parent's swarm decision along with its
                // fault configuration; it does not re-draw the mask.
                swarm_record = session.swarm_config().cloned();
                (
                    Execution::Branch {
                        session: Box::new(session),
                        _reservation: reservation,
                    },
                    *branch_seed,
                )
            }
        };

        // Adopt the trace's authoritative fault configuration before any driver
        // is constructed from it, so a flag-free replay rebuilds the same
        // CrashFs/SimNet the recording used.
        if let Some(faults) = replay_fault_override {
            self.config.faults = faults;
        }
        // Adopt the trace's authoritative buggify configuration so a flag-free
        // replay re-derives the same activation and firing decisions.
        if let Some(buggify) = replay_buggify_override {
            self.config.buggify = buggify;
        }
        // Adopt the trace's authoritative guest environment values so a flag-free
        // replay reproduces environment-dependent guest behavior.
        if let Some(guest_env) = replay_guest_env_override {
            self.config.guest_env = guest_env;
        }
        // Likewise the trace's authoritative DNS host table, so a flag-free
        // replay resolves exactly the names the recording could.
        if let Some(entries) = replay_dns_override {
            self.config.dns_entries = entries;
        }
        // Adopt the trace's authoritative exploration scheduling policy. Replay
        // consumes recorded task selections directly (through `select`), so the
        // policy does not steer replay; adopting it keeps the built scheduler
        // consistent and the reconcile above provides the fail-closed guard.
        if let Some(policy) = replay_schedule_override {
            self.config.schedule_policy = policy;
        }
        validate_buggify_fingerprint_contract(&self.config)?;

        // The crash-consistency filesystem is built HERE, and only here, from
        // `config.faults` — the single choke point that always consumes the
        // parsed crash knobs. Callers pass the durable base image via
        // `with_fs_image`; they must not pre-install the final filesystem, so a
        // knob like `--fs-torn-granularity` can never be silently dropped by a
        // filesystem that bypassed the fault config (the gap this replaced).
        let fs_fault_knobs_set = self.config.faults.fs.crash_at.is_some()
            || self.config.faults.fs.torn_granularity != TornGranularity::default()
            || self.config.faults.fs.error_permille != 0
            || self.config.faults.fs.short_permille != 0;
        if self.filesystem.is_some() {
            // An explicit filesystem (`with_filesystem`/`with_captured_filesystem`)
            // cannot reflect config-driven fs fault knobs, and an accompanying base
            // image would be ignored. Fail closed rather than proceed silently.
            if fs_fault_knobs_set {
                return Err(RuntimeError::Config(
                    "a filesystem was installed explicitly while filesystem fault \
                     knobs (--fs-crash-at / --fs-torn-granularity / \
                     --fs-error-permille / --fs-short-permille) are set; those \
                     knobs would be silently ignored. Supply the durable image via \
                     RuntimeBuilder::with_fs_image so the runtime builds the \
                     filesystem from the fault configuration."
                        .into(),
                ));
            }
            if self.fs_image.is_some() {
                return Err(RuntimeError::Config(
                    "both an explicit filesystem and a base image were provided; \
                     use exactly one"
                        .into(),
                ));
            }
        }
        if self.install_defaults {
            // The base image is ALWAYS wrapped in a config-driven `CrashFs`,
            // whether or not `--fs-crash-at` is set. This preserves the historical
            // always-`CrashFs` behavior the shim relied on: a `CrashFs` is
            // crashable, so imperative callers that trigger `fs_crash()` manually
            // (the C-ABI `patina_init_crash` path, the WASI-host crash probes)
            // keep working. A bare `MemFs` cannot crash — `FsDriver::crash`
            // returns `InvalidState` — so installing one here regressed those
            // paths. An un-crashed `CrashFs` reads/writes identically to its inner
            // `MemFs` and consumes no seeded entropy, so non-crash runs are
            // byte-for-byte unchanged.
            if self.filesystem.is_none() {
                // NOT `unwrap_or_default()`: `MemFs::new()` seeds the root `/`
                // directory, while `MemFs::default()` is ROOTLESS. A caller that
                // uses `with_default_drivers` without `with_fs_image` (e.g.
                // `Context::from_config`) would otherwise get a rootless
                // filesystem and fail every path op with NotFound. Clippy's
                // `unwrap_or_default` suggestion is wrong here because the two
                // constructors are not equivalent.
                #[allow(clippy::unwrap_or_default)]
                let base = self.fs_image.take().unwrap_or_else(MemFs::new);
                let crash_fs = CrashFs::builder()
                    .filesystem(base)
                    .seed(domain_seed(root_seed, fault_domain::FS_CRASH))
                    .torn_granularity(self.config.faults.fs.torn_granularity)
                    .build()
                    .map_err(RuntimeError::Effect)?;
                self.filesystem = Some(Box::new(
                    FaultFs::new(crash_fs, root_seed)
                        .error_permille(self.config.faults.fs.error_permille)
                        .short_permille(self.config.faults.fs.short_permille)
                        .latency_live(self.config.faults.fs.latency_nanos.is_some()),
                ));
            }
            self.clock
                .get_or_insert_with(|| Box::new(VirtualClock::default()));
            self.entropy.get_or_insert_with(|| {
                Box::new(SeededEntropy::new(domain_seed(
                    root_seed,
                    fault_domain::ENTROPY,
                )))
            });
            self.scheduler.get_or_insert_with(|| {
                Box::new(DetScheduler::with_policy(
                    root_seed,
                    self.config.schedule_policy,
                ))
            });
            if self.network.is_none() {
                let net = &self.config.faults.net;
                let mut network = SimNet::builder()
                    .base_latency_nanos(net.latency_nanos)
                    .fault_seed(domain_seed(root_seed, fault_domain::NET_FAULT))
                    .drop_permille(net.drop_permille)
                    .duplicate_permille(net.duplicate_permille)
                    .connect_refuse_permille(net.connect_refuse_permille)
                    .reset_permille(net.reset_permille);
                if let Some((min, max)) = net.jitter_nanos {
                    network = network.jitter_nanos(min, max);
                }
                if let Some(bytes) = net.tcp_buffer_bytes {
                    network = network.tcp_buffer_bytes(bytes);
                }
                for (left, right) in &net.partitions {
                    network = network.partition(left.clone(), right.clone());
                }
                self.network = Some(Box::new(network.build().map_err(RuntimeError::Effect)?));
            }
        }

        // A base image is only ever consumed by the default-driver choke point
        // above. If one survives, `with_fs_image` was used without
        // `with_default_drivers`, so it would be silently dropped — fail closed.
        if self.fs_image.is_some() {
            return Err(RuntimeError::Config(
                "with_fs_image requires with_default_drivers so the runtime can \
                 build the filesystem from it"
                    .into(),
            ));
        }

        // Build the liveness watchdog before the Context literal consumes
        // `self.config` fields. The heal-then-converge arm arms at the fault-window
        // end: an explicit override, else the buggify damage-control cutoff (when
        // buggify is enabled), else run start. Detection is live only on a
        // record/seeded run; a replay consumes the authoritative trace.
        let liveness = LivenessWatchdog::new(
            self.config.liveness,
            resolve_heal_after(&self.config),
            matches!(
                self.config.mode,
                ExecutionMode::Seeded
                    | ExecutionMode::Record { .. }
                    | ExecutionMode::RecordTransport
            ),
        );

        // The facts channel: exactly one destination, or none. Two live
        // destinations would silently drop one document, so refuse.
        let facts = match (self.facts_sink.take(), self.config.facts_path.take()) {
            (None, None) => None,
            (Some(sink), None) => Some(facts::FactsOutput::Sink(sink)),
            (None, Some(path)) => Some(facts::FactsOutput::Path(path)),
            (Some(_), Some(_)) => {
                return Err(RuntimeError::Config(format!(
                    "a run-facts sink and a facts path ({ENV_FACTS}) were both installed; use exactly one"
                )));
            }
        };

        Ok(Context {
            root_seed,
            step_budget: self.config.step_budget,
            steps: 0,
            params: self.config.params,
            guest_env: self.config.guest_env,
            execution,
            filesystem: self.filesystem,
            filesystem_is_capture: self.filesystem_is_capture,
            clock: self.clock,
            entropy: self.entropy,
            scheduler: self.scheduler,
            network: self.network,
            timers: BTreeMap::new(),
            timer_by_task: BTreeMap::new(),
            timer_seq: 0,
            scheduler_tasks: std::collections::BTreeSet::new(),
            parked_tasks: std::collections::BTreeSet::new(),
            rescued: Vec::new(),
            crash_at: self.config.faults.fs.crash_at,
            crash_counts: CrashCounts::default(),
            crash_fired: false,
            sleep_jitter_nanos: self.config.faults.clock.sleep_jitter_nanos,
            // Domain-separated seed so sleep-jitter draws do not correlate with
            // the entropy or network-fault streams that also derive from root_seed.
            sleep_jitter_rng: SplitMix64::new(domain_seed(root_seed, fault_domain::SLEEP_JITTER)),
            fs_latency_nanos: self.config.faults.fs.latency_nanos,
            fs_latency_rng: SplitMix64::new(domain_seed(root_seed, fault_domain::FS_LATENCY)),
            fs_latency_eligible_ops: 0,
            fs_latency_applied: 0,
            dns_entries: self.config.dns_entries,
            dns_fail_permille: self.config.faults.dns.fail_permille,
            dns_fault_rng: SplitMix64::new(domain_seed(root_seed, fault_domain::DNS_FAULT)),
            dns_latency_nanos: self.config.faults.dns.latency_nanos,
            dns_latency_rng: SplitMix64::new(domain_seed(root_seed, fault_domain::DNS_LATENCY)),
            dns_report: patina_dst_driver_api::DnsFaultReport::default(),
            entropy_fail_permille: self.config.faults.entropy.fail_permille,
            entropy_fault_rng: SplitMix64::new(domain_seed(root_seed, fault_domain::ENTROPY_FAULT)),
            entropy_report: patina_dst_driver_api::EntropyFaultReport::default(),
            epoch_jump_nanos: self.config.faults.clock.epoch_jump_nanos,
            epoch_jump_rng: SplitMix64::new(domain_seed(root_seed, fault_domain::EPOCH_JUMP)),
            clock_report: patina_dst_driver_api::ClockFaultReport::default(),
            schedule: ScheduleTracker::default(),
            buggify: Buggify::new(self.config.buggify, root_seed),
            verdicts: Vec::new(),
            custom_op: None,
            pending_diagnostics: Vec::new(),
            liveness,
            swarm: swarm_record,
            reports: self.config.reports,
            facts,
            facts_emitted: false,
            spin: SpinRescue::default(),
            recording_flushed: false,
        })
    }
}

/// A task still running (spawned, not yet completed) with its spawn order and
/// the scheduling boundaries it has passed so far, split by kind. `yields` are
/// voluntary reschedules the guest takes every time it touches the interposed
/// effect surface (a lock/unlock, syscall, sleep, …); they scale with a genuine
/// concurrent loop. `parks` are blocking waits, which for an atomics-only worker
/// are only spawn/join housekeeping and do not scale with its work.
struct LiveTask {
    order: u64,
    yields: u64,
    parks: u64,
    /// Global scheduling-step clock value when this task was spawned.
    spawn_step: u64,
}

/// A completed task's final schedule accounting.
struct CompletedTask {
    task: TaskId,
    order: u64,
    yields: u64,
    parks: u64,
    /// Global scheduling-step clock value at spawn and at completion; their
    /// difference is the task's lifetime in scheduling steps.
    spawn_step: u64,
    complete_step: u64,
}

/// Yield count that spawning and joining a std thread incurs on its own —
/// independent of what the thread's body does. A spawned worker whose yields do
/// not exceed this baseline performed zero interposed operations of its own: it
/// never touched the effect surface at a schedulable point, so any loop it ran
/// was atomics-only (a `std::sync::RwLock` fast-path read-modify-write, say) and
/// completely invisible to the runtime. Yields are the stable signal — blocking
/// parks vary by seed, but the scaffolding yield count is invariant to the body's
/// iteration count. A worker at or below it is unexplorable; one real interposed
/// op lifts it above, a `--yield-points` build to tens, an interposed sync loop
/// (contended mutexes) to hundreds.
///
/// The baseline is platform-specific and measured with the do-nothing-thread
/// experiment (spawn a worker with an empty body, read its yields from
/// `PATINA_SCHEDULE_REPORT`):
///
/// - **macOS = 4.** Rust std's Darwin thread `Parker` spins on the interposed
///   `dispatch_semaphore` during the spawn/join handshake, so the *worker* incurs
///   four scheduling boundaries before its body runs.
/// - **Linux = 0.** Std lowers parking to raw `futex`, and the join handshake
///   parks the *main* thread, not the worker; a do-nothing worker reaches
///   completion with zero worker-side boundaries. Measured on glibc 2.39/aarch64:
///   an empty-body worker reports `0y+0p`, an uncontended-`Mutex` worker likewise
///   `0y+0p` (uncontended locks are pure userspace atomics), and a `--yield-points`
///   worker reports tens — so a floor of 0 flags exactly the atomics-only workers
///   (an atomics-only lost-update race) while one interposed boundary clears it.
#[cfg(target_os = "macos")]
const SCAFFOLDING_YIELD_FLOOR: u64 = 4;
#[cfg(not(target_os = "macos"))]
const SCAFFOLDING_YIELD_FLOOR: u64 = 0;

/// Whether a boundary operation represents *genuine progress* (guest-driven state
/// advancement) rather than pure scheduling/time housekeeping. The liveness
/// watchdog resets its no-progress clock on a progress op and accumulates only on
/// non-progress ops.
///
/// Non-progress = the pure scheduling/time/wait ops the runtime uses to rotate
/// tasks and advance virtual time without any guest state change: reading the
/// clock, sleeping, yielding, parking (timed or not), waking, the scheduler
/// decision itself, and the park-until-delivery probe. Everything else — every
/// filesystem effect, entropy draw, task spawn/completion, and network data
/// movement — is genuine progress.
///
/// Consequence (documented): a system that keeps doing real I/O (e.g. exchanging
/// network messages) but never reaches an application-level goal is NOT caught by
/// this generic detector, because its I/O counts as progress; that requires an
/// application-level oracle. The watchdog catches the *pure-churn wedge* — a run
/// that has stopped issuing genuine effects and only spins on timers/parks while
/// virtual time marches on.
fn operation_is_progress(operation: &Operation) -> bool {
    !matches!(
        operation,
        Operation::ClockNow { .. }
            | Operation::SleepUntil { .. }
            | Operation::TaskYield { .. }
            | Operation::TaskPark { .. }
            | Operation::TaskParkTimed { .. }
            | Operation::TaskWake { .. }
            | Operation::SchedulerNext
            | Operation::NetNextDelivery { .. }
    )
}

/// Which watchdog arm fired.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LivenessKind {
    /// The generic no-progress arm (armed from run start).
    NoProgress,
    /// The heal-then-converge arm (armed at the fault-window end).
    HealThenConverge,
}

impl LivenessKind {
    /// The stable category token (the second field of the `PATINA_VIOLATION`
    /// line): `liveness` for the generic no-progress arm, `converge` for the
    /// heal-then-converge arm. A downstream campaign classifier keys on it.
    pub const fn as_str(&self) -> &'static str {
        match self {
            LivenessKind::NoProgress => "liveness",
            LivenessKind::HealThenConverge => "converge",
        }
    }

    /// The short kebab-case reason (`detail=…`) describing the specific failure.
    pub const fn reason(&self) -> &'static str {
        match self {
            LivenessKind::NoProgress => "no-progress",
            LivenessKind::HealThenConverge => "did-not-converge",
        }
    }
}

/// A structured liveness-watchdog violation, formatted into the stable
/// `PATINA_VIOLATION` interface-contract line a downstream campaign consumer
/// parses. `vtime_ns` is the absolute virtual-monotonic time at the fire;
/// `last_fault_vtime_ns` is the converge arm's fault-window-end arm time (the
/// `--heal-after` / buggify-cutoff instant), meaningful only for the converge arm.
#[derive(Clone, Copy, Debug)]
struct LivenessViolation {
    kind: LivenessKind,
    vtime_ns: u64,
    budget_ns: u64,
    last_fault_vtime_ns: u64,
}

impl LivenessViolation {
    /// The single stderr line per the interface contract:
    /// `PATINA_VIOLATION liveness detail=no-progress vtime_ns=<n> budget_ns=<n>` and
    /// `PATINA_VIOLATION converge detail=did-not-converge vtime_ns=<n> budget_ns=<n> last_fault_vtime_ns=<n>`.
    fn marker_line(&self) -> String {
        match self.kind {
            LivenessKind::NoProgress => format!(
                "PATINA_VIOLATION liveness detail={} vtime_ns={} budget_ns={}",
                self.kind.reason(),
                self.vtime_ns,
                self.budget_ns,
            ),
            LivenessKind::HealThenConverge => format!(
                "PATINA_VIOLATION converge detail={} vtime_ns={} budget_ns={} last_fault_vtime_ns={}",
                self.kind.reason(),
                self.vtime_ns,
                self.budget_ns,
                self.last_fault_vtime_ns,
            ),
        }
    }
}

/// One virtual-time no-progress budget the watchdog enforces. Each arm tracks the
/// virtual time of the last genuine progress (its `baseline`) and the count of
/// consecutive non-progress ops since then; it fires when the run has churned
/// (`>= LIVENESS_MIN_STALL_OPS` non-progress ops) for more than `budget` virtual
/// nanoseconds past the baseline without any progress and without a
/// policy-explained deferral.
#[derive(Clone, Copy, Debug)]
struct WatchdogArm {
    kind: LivenessKind,
    /// Virtual time (nanoseconds) at which this arm becomes active. The generic
    /// arm arms at 0; the converge arm arms at the fault-window end.
    arm_time_nanos: u64,
    budget_nanos: u64,
    /// Whether virtual time has reached `arm_time_nanos` yet.
    armed: bool,
    /// Virtual time of the last progress (or of arming), from which the budget is
    /// measured.
    baseline_nanos: u64,
    /// Consecutive non-progress ops since the baseline.
    stall_ops: u64,
}

impl WatchdogArm {
    /// Observe one boundary op at virtual time `now`. Returns a
    /// [`LivenessViolation`] if this arm fires. `progress` is whether the op
    /// advanced genuine state; `deferring` is whether the scheduler is deliberately
    /// withholding a runnable task (a policy-explained window that must not count
    /// as no-progress).
    fn observe(&mut self, now: u64, progress: bool, deferring: bool) -> Option<LivenessViolation> {
        if !self.armed {
            if now < self.arm_time_nanos {
                return None;
            }
            // Arm now: start measuring no-progress from this instant, so nothing
            // before the arm-time counts against the budget.
            self.armed = true;
            self.baseline_nanos = now;
            self.stall_ops = 0;
        }
        if progress || deferring {
            self.baseline_nanos = now;
            self.stall_ops = 0;
            return None;
        }
        self.stall_ops += 1;
        let elapsed = now.saturating_sub(self.baseline_nanos);
        if self.stall_ops >= LIVENESS_MIN_STALL_OPS && elapsed > self.budget_nanos {
            Some(LivenessViolation {
                kind: self.kind,
                vtime_ns: now,
                budget_ns: self.budget_nanos,
                last_fault_vtime_ns: self.arm_time_nanos,
            })
        } else {
            None
        }
    }
}

/// The deterministic, virtual-time-only liveness watchdog. It never records a
/// boundary operation and never perturbs scheduler selection — it only READS the
/// virtual clock and the scheduler's policy-deferral state and, on a genuine
/// no-progress wedge, ADDS a structured `PATINA_VIOLATION` line. That is why
/// enabling it is schedule-invariant (byte-identical trace when no violation
/// fires) and needs no fingerprint component.
///
/// Detection is live-selection only (record/seeded), like the exploration-policy
/// report: on replay the recorded trace is authoritative and already reflects any
/// abort, and the scheduler's live deferral state is not available, so the
/// watchdog stays inert on replay.
struct LivenessWatchdog {
    arms: Vec<WatchdogArm>,
    /// Whether detection is live this run (record/seeded and at least one arm).
    active: bool,
    fired: bool,
    /// The violation that fired, kept so the structured facts document can carry
    /// the same fields the `PATINA_VIOLATION` line carries.
    violation: Option<LivenessViolation>,
}

impl LivenessWatchdog {
    /// Build the watchdog from the resolved config. `heal_after_nanos` is the
    /// converge arm's arm-time already resolved by the caller (buggify cutoff or
    /// override). `active` gates whether detection actually runs.
    fn new(config: LivenessConfig, heal_after_nanos: u64, active: bool) -> Self {
        let mut arms = Vec::new();
        if let Some(budget) = config.no_progress_budget_nanos {
            arms.push(WatchdogArm {
                kind: LivenessKind::NoProgress,
                arm_time_nanos: 0,
                budget_nanos: budget,
                armed: false,
                baseline_nanos: 0,
                stall_ops: 0,
            });
        }
        if let Some(budget) = config.converge_budget_nanos {
            arms.push(WatchdogArm {
                kind: LivenessKind::HealThenConverge,
                arm_time_nanos: heal_after_nanos,
                budget_nanos: budget,
                armed: false,
                baseline_nanos: heal_after_nanos,
                stall_ops: 0,
            });
        }
        Self {
            active: active && !arms.is_empty(),
            arms,
            fired: false,
            violation: None,
        }
    }

    /// Observe one boundary op across every arm; return the first arm that fires.
    fn observe(&mut self, now: u64, progress: bool, deferring: bool) -> Option<LivenessViolation> {
        for arm in &mut self.arms {
            if let Some(violation) = arm.observe(now, progress, deferring) {
                self.fired = true;
                self.violation = Some(violation);
                return Some(violation);
            }
        }
        None
    }
}

/// Consecutive clock-observation boundary ops — at unchanged virtual time and
/// with no intervening progress op — that the runtime treats as a spin.
///
/// Why 1024. The streak is only broken by a *progress* op (see
/// [`operation_is_progress`]) or by virtual time actually moving, so real code
/// cannot accumulate it: any effect, entropy draw, spawn, or sleep resets it,
/// and a clock read is nearly always followed by one of those. 1024 puts the
/// trigger an order of magnitude beyond even a pathological polling loop that
/// re-reads the clock a few dozen times per decision, which is what keeps the
/// rescue invisible to every existing workload (the acceptance constraint: no
/// recorded artifact anywhere in the tree may change). It is simultaneously
/// cheap for a genuine spin: the canonical calibration loop issues two clock
/// ops per iteration, so 1024 is 512 iterations — microseconds of host time.
const SPIN_RESCUE_CLOCK_OPS: u64 = 1_024;

/// The first rescue's advance within a spin episode: 1 µs, deliberately tiny.
/// A guest that is merely polling hard — a 100 µs busy-wait, say — must see a
/// nudge rather than a jump, so the elapsed time it eventually derives is close
/// to what it asked for instead of being rounded up to the rescue granularity.
const SPIN_RESCUE_TOKEN_MIN_NANOS: u64 = 1_000;

/// The per-rescue ceiling the token escalates to: 1 ms. The escalation (doubling
/// per rescue) is what makes a real wedge converge in tens of rescues instead of
/// millions of loop iterations; the ceiling is what bounds the resulting
/// overshoot. The calibration pattern in the wild measures a 10 ms window, so a
/// 1 ms ceiling caps the overshoot on that window at 10%.
///
/// Worked example (the fastant calibration loop, 10 ms window): tokens
/// 1, 2, 4, … 512 µs sum to ~1.02 ms over ten rescues, then the ceiling carries
/// the remaining ~9 ms in nine more — ~19 rescues, ~19 × 1024 ≈ 20k recorded
/// clock ops per window. Well under [`patina_dst_trace::MAX_TIMELINE_EVENTS`].
const SPIN_RESCUE_TOKEN_MAX_NANOS: u64 = 1_000_000;

/// Rescues within one spin episode after which the run is aborted as
/// frozen-clock churn: 256.
///
/// Why 256. At the token ceiling this is >250 ms of virtual time advanced with
/// zero genuine progress — 25× the 10 ms window the calibration pattern uses,
/// and ~5× the longest window (50 ms) seen in the crates that use it. A loop
/// still spinning after that is not *waiting* for time, it is *ignoring* it, and
/// no amount of further advancing will unwedge it. Bounded trace cost: at most
/// 256 × 1024 ≈ 262k recorded clock ops before the named abort, so the trace
/// that explains the wedge is still writable and loadable.
const SPIN_CHURN_ABORT_RESCUES: u64 = 256;

/// Advance-on-spin state: the runnable-churn counterpart to the deadlock rescue.
///
/// The deadlock rescue advances virtual time when the guest *waits* — every task
/// parked with a timer pending. The gap it leaves is a guest that is *runnable*
/// and doing nothing but reading the clock: virtual time only moves through a
/// recorded `SleepUntil`, so a loop whose exit condition is "10 ms of monotonic
/// progress" and whose body performs no wait never terminates. That is the
/// pre-`main` calibration shape (`fastant`/`minstant`/`quanta` measure the
/// timestamp counter against the OS clock over a fixed window at startup), and
/// it is common in exactly the crates a DST user wants to instrument.
///
/// Two levels of state, deliberately distinct:
///
/// - The **streak** (`clock_ops` measured from `baseline_nanos`) is the trigger.
///   It counts consecutive clock observations at unchanged virtual time; it is
///   reset by a genuine progress op, and by virtual time moving for any reason
///   other than this rescue's own advance.
/// - The **episode** (`rescues`, `advanced_nanos`) survives across rescues and
///   drives both the token escalation and the frozen-clock-churn backstop. Only
///   a progress op — or a time move the guest itself caused — ends an episode.
///
/// Every input is a recorded boundary op or the driver's monotonic value, both
/// maintained identically on record and replay, so the rescue re-executes at the
/// same point on replay and the trace is byte-identical.
#[derive(Debug, Default)]
struct SpinRescue {
    /// Consecutive clock-observation ops since `baseline_nanos`.
    clock_ops: u64,
    /// The virtual time the current streak is measured at. A clock op observing
    /// a different time means time moved, which ends the streak (and, unless
    /// this rescue moved it, the episode).
    baseline_nanos: u64,
    /// Rescues performed in the current episode; drives the token escalation and
    /// is what [`SPIN_CHURN_ABORT_RESCUES`] bounds.
    rescues: u64,
    /// Virtual nanoseconds this episode's rescues have advanced in total, for
    /// the churn diagnostic.
    advanced_nanos: u64,
    /// Set while the rescue emits its own `SleepUntil`, so that op does not
    /// disturb the state the rescue is about to update itself.
    rescuing: bool,
    /// The virtual time the frozen-clock-churn backstop fired at, so the facts
    /// document can carry the same finding the marker line carries.
    churn_vtime_nanos: Option<u64>,
}

impl SpinRescue {
    /// The next rescue's advance: [`SPIN_RESCUE_TOKEN_MIN_NANOS`] doubled once
    /// per rescue already taken in this episode, saturating at
    /// [`SPIN_RESCUE_TOKEN_MAX_NANOS`].
    fn token_nanos(&self) -> u64 {
        // The shift is clamped to the last doubling that can matter (ten of them
        // take the token past the ceiling). Leaving it unclamped is a trap:
        // `1_000 << rescues` overflows u64 around rescue 55 and WRAPS to a
        // SMALLER token, silently slowing convergence at exactly the point the
        // churn backstop is counting on it.
        const MAX_SHIFT: u32 = SPIN_RESCUE_TOKEN_MAX_NANOS.ilog2() + 1;
        let shift = u32::try_from(self.rescues)
            .unwrap_or(MAX_SHIFT)
            .min(MAX_SHIFT);
        (SPIN_RESCUE_TOKEN_MIN_NANOS << shift).min(SPIN_RESCUE_TOKEN_MAX_NANOS)
    }

    /// End the episode entirely: the guest made genuine progress, or time moved
    /// without this rescue moving it.
    fn end_episode(&mut self, now: u64) {
        self.clock_ops = 0;
        self.baseline_nanos = now;
        self.rescues = 0;
        self.advanced_nanos = 0;
    }

    /// Record one completed rescue: the streak restarts at the new virtual time
    /// while the episode carries on.
    fn on_rescued(&mut self, target: u64, token: u64) {
        self.clock_ops = 0;
        self.baseline_nanos = target;
        self.rescues += 1;
        self.advanced_nanos = self.advanced_nanos.saturating_add(token);
    }

    /// The loud, machine-parseable line the frozen-clock-churn abort emits. It
    /// reuses the established `PATINA_VIOLATION liveness …` interface contract —
    /// this IS a liveness failure, and a downstream campaign consumer already
    /// classifies that prefix — with its own `detail=` reason and its own facts.
    fn churn_marker_line(&self, vtime_nanos: u64) -> String {
        format!(
            "PATINA_VIOLATION liveness detail=frozen-clock-churn vtime_ns={} rescues={} \
advanced_ns={} clock_ops_per_rescue={}",
            vtime_nanos, self.rescues, self.advanced_nanos, SPIN_RESCUE_CLOCK_OPS,
        )
    }
}

/// Per-task scheduling-boundary accounting backing [`ScheduleDiagnostics`].
/// Every field is driven by the recorded task-lifecycle ops, so it is populated
/// identically on record and replay.
#[derive(Default)]
struct ScheduleTracker {
    live: BTreeMap<TaskId, LiveTask>,
    completed: Vec<CompletedTask>,
    spawned: u64,
    max_concurrent: u64,
    /// Monotonic global scheduling-event clock: every task-lifecycle boundary
    /// (spawn/yield/park/complete, on any task) advances it by one. Stamped at a
    /// task's spawn and completion to derive its lifetime. Driven entirely by the
    /// recorded ops, so it advances identically on record and replay.
    steps: u64,
}

impl ScheduleTracker {
    fn on_spawn(&mut self, task: TaskId) {
        let order = self.spawned;
        self.spawned += 1;
        self.steps += 1;
        self.live.insert(
            task,
            LiveTask {
                order,
                yields: 0,
                parks: 0,
                spawn_step: self.steps,
            },
        );
        self.max_concurrent = self.max_concurrent.max(self.live.len() as u64);
    }

    fn on_yield(&mut self, task: TaskId) {
        self.steps += 1;
        if let Some(live) = self.live.get_mut(&task) {
            live.yields += 1;
        }
    }

    fn on_park(&mut self, task: TaskId) {
        self.steps += 1;
        if let Some(live) = self.live.get_mut(&task) {
            live.parks += 1;
        }
    }

    fn on_complete(&mut self, task: TaskId) {
        self.steps += 1;
        if let Some(live) = self.live.remove(&task) {
            self.completed.push(CompletedTask {
                task,
                order: live.order,
                yields: live.yields,
                parks: live.parks,
                spawn_step: live.spawn_step,
                complete_step: self.steps,
            });
        }
    }

    /// Total `TaskYield` boundaries this run has taken for `task` so far,
    /// whether the task is still live or already completed. Divergence
    /// diagnostics use this for record-vs-replay yield accounting.
    fn yields_for(&self, task: TaskId) -> u64 {
        self.live
            .get(&task)
            .map(|live| live.yields)
            .or_else(|| {
                self.completed
                    .iter()
                    .find(|done| done.task == task)
                    .map(|done| done.yields)
            })
            .unwrap_or(0)
    }

    fn diagnostics(&self) -> ScheduleDiagnostics {
        // Each record carries the completion step as `Option`: `Some` for a task
        // the runtime saw complete, `None` for one still live at run end (whose
        // lifetime runs to the current step clock).
        let mut records: Vec<(u64, TaskId, u64, u64, u64, Option<u64>)> = self
            .completed
            .iter()
            .map(|done| {
                (
                    done.order,
                    done.task,
                    done.yields,
                    done.parks,
                    done.spawn_step,
                    Some(done.complete_step),
                )
            })
            .chain(self.live.iter().map(|(task, live)| {
                (
                    live.order,
                    *task,
                    live.yields,
                    live.parks,
                    live.spawn_step,
                    None,
                )
            }))
            .collect();
        records.sort_by_key(|(order, _, _, _, _, _)| *order);
        let total_boundaries = records
            .iter()
            .map(|(_, _, yields, parks, _, _)| yields + parks)
            .sum();
        let mut vacuous = Vec::new();
        let tasks = records
            .iter()
            .map(|&(order, task, yields, parks, spawn_step, complete_step)| {
                // Lifetime spans global scheduling steps from spawn to completion
                // (or to the run's end for a still-live task). Cause distinguishes
                // the two.
                let (lifetime, cause) = match complete_step {
                    Some(end) => (
                        end.saturating_sub(spawn_step),
                        TaskCompletionCause::Completed,
                    ),
                    None => (
                        self.steps.saturating_sub(spawn_step),
                        TaskCompletionCause::LiveAtExit,
                    ),
                };
                // The initial task (spawn order 0) is the guest's own thread of
                // control, not a spawned worker, so it is not a vacuity signal.
                // A spawned worker whose yields do not clear the thread-lifecycle
                // scaffolding floor exposed no schedulable body: any loop it ran
                // was atomics-only and unschedulable at any seed. That is the
                // exact shape of an atomics-only lost-update race window, and
                // the yield count is invariant to its iteration count.
                // A spawned worker (order > 0) is vacuous when its yields do not
                // exceed the platform scaffolding floor. Written as `!(> floor)`
                // rather than `<= floor` so the comparison stays valid when the
                // floor is the type minimum (Linux = 0), where `<= 0` would trip
                // clippy::absurd_extreme_comparisons; newer clippy flags this
                // form as nonminimal_bool instead, hence the scoped allow.
                #[allow(clippy::nonminimal_bool)]
                let is_vacuous = order > 0 && !(yields > SCAFFOLDING_YIELD_FLOOR);
                if is_vacuous {
                    vacuous.push(task);
                }
                TaskScheduleStat {
                    task,
                    yields,
                    parks,
                    boundaries: yields + parks,
                    lifetime,
                    cause,
                    vacuous: is_vacuous,
                }
            })
            .collect();
        ScheduleDiagnostics {
            tasks_spawned: self.spawned,
            max_concurrent: self.max_concurrent,
            total_boundaries,
            tasks,
            vacuous,
        }
    }
}

/// Per-operation-kind occurrence counters used to fire a crash at the Nth
/// boundary op of a chosen kind.
#[derive(Default)]
struct CrashCounts {
    open: u64,
    write: u64,
    sync: u64,
    close: u64,
}

enum Execution {
    Seeded,
    Record {
        recorder: Recorder,
        sink: RecordSink,
    },
    Replay(Replayer),
    Branch {
        // Boxed: a `BranchSession` is by far the largest variant payload, and
        // branch runs are the rare path, so keeping it out of line avoids
        // inflating every `Execution` (clippy::large_enum_variant).
        session: Box<BranchSession>,
        _reservation: RecordReservation,
    },
}

enum RecordSink {
    Path {
        path: PathBuf,
        _reservation: RecordReservation,
    },
    Transport(Box<dyn TraceTransport>),
}

struct RecordReservation {
    lock_path: PathBuf,
}

impl RecordReservation {
    fn acquire(trace_path: &Path) -> Result<Self, RuntimeError> {
        let reservation = Self::acquire_lock(trace_path)?;
        if trace_path.exists() {
            return Err(RuntimeError::Config(format!(
                "refusing to overwrite existing trace {}",
                trace_path.display()
            )));
        }
        Ok(reservation)
    }

    fn acquire_branch(trace_path: &Path) -> Result<Self, RuntimeError> {
        if !trace_path.is_file() {
            return Err(RuntimeError::Config(format!(
                "cannot branch from missing trace {}",
                trace_path.display()
            )));
        }
        Self::acquire_lock(trace_path)
    }

    fn acquire_lock(trace_path: &Path) -> Result<Self, RuntimeError> {
        let parent = trace_path
            .parent()
            .filter(|value| !value.as_os_str().is_empty());
        if let Some(parent) = parent {
            fs::create_dir_all(parent).map_err(|source| RuntimeError::Io {
                action: format!("create trace directory {}", parent.display()),
                source,
            })?;
        }
        let lock_path = record_lock_path(trace_path)?;
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
            .map_err(|source| RuntimeError::Io {
                action: format!(
                    "reserve trace {} using {}; another Patina recorder may be active",
                    trace_path.display(),
                    lock_path.display()
                ),
                source,
            })?;
        Ok(Self { lock_path })
    }
}

impl Drop for RecordReservation {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.lock_path);
    }
}

enum FilesystemExpected {
    Execute(Option<(u64, Outcome)>),
    Captured(Outcome),
}

/// Domain separators for the buggify PRF, so activation, firing, knob, and delay
/// draws for one site never correlate.
mod buggify_domain {
    pub const ACTIVATION: u64 = 0x4143_5449_5641_5445; // "ACTIVATE"
    pub const FIRING: u64 = 0x4649_5249_4e47_5f5f; // "FIRING__"
    pub const KNOB: u64 = 0x4b4e_4f42_5f5f_5f5f; // "KNOB____"
    pub const DELAY: u64 = 0x4445_4c41_595f_5f5f; // "DELAY___"
    pub const RNG: u64 = 0x524e_475f_5f5f_5f5f; // "RNG_____"
}

/// A deterministic 64-bit hash of a site label, stable across builds, platforms,
/// and Rust versions (unlike `DefaultHasher`) so cross-machine replay agrees.
/// FNV-1a over the UTF-8 bytes.
fn label_hash(label: &str) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in label.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// A domain-separated deterministic pseudo-random value from a set of 64-bit
/// inputs, built from the specified SplitMix64 finalizer so it needs no state
/// beyond the inputs and reproduces exactly across processes.
fn buggify_prf(inputs: &[u64]) -> u64 {
    let mut acc = 0xa5a5_a5a5_5a5a_5a5a_u64;
    for &value in inputs {
        acc = SplitMix64::new(acc ^ value).next_u64();
        acc = acc.wrapping_add(value.rotate_left(17));
    }
    SplitMix64::new(acc).next_u64()
}

/// What a registered buggify site is used for. Purely descriptive: it drives the
/// `PATINA_SDK_REPORT` categorization and never the firing decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuggifyKind {
    /// `buggify!` / `buggify_with_prob!` — a probabilistic fault trigger.
    Fault,
    /// `buggify_delay!` — a probabilistic deterministic delay.
    Delay,
    /// `buggify_knob!` — a per-run perturbed value.
    Knob,
    /// `always!` — an invariant whose violation is fatal.
    Always,
    /// `sometimes!` — a coverage oracle (should be true at least once).
    Sometimes,
    /// `reachable!` — a coverage oracle (this site should be reached).
    Reachable,
}

impl BuggifyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            BuggifyKind::Fault => "fault",
            BuggifyKind::Delay => "delay",
            BuggifyKind::Knob => "knob",
            BuggifyKind::Always => "always",
            BuggifyKind::Sometimes => "sometimes",
            BuggifyKind::Reachable => "reachable",
        }
    }

    pub const fn from_static_site_kind(value: u8) -> Option<Self> {
        match value {
            1 => Some(BuggifyKind::Fault),
            2 => Some(BuggifyKind::Delay),
            3 => Some(BuggifyKind::Knob),
            4 => Some(BuggifyKind::Always),
            5 => Some(BuggifyKind::Sometimes),
            6 => Some(BuggifyKind::Reachable),
            _ => None,
        }
    }
}

/// The result of evaluating a cooperative-SUT site, for the embedder (the native
/// shim) to act on. The runtime never performs process I/O or aborts itself; it
/// returns the signal and the embedder emits the marker line and aborts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SiteOutcome {
    /// Proceed normally: the buggify site did not fire, or the oracle was noted.
    Ok,
    /// The buggify site fired — the embedder injects the fault / takes the branch.
    Fire,
    /// An `always!` invariant was violated: the violation has already been
    /// reported through the verdict ABI (a `PATINA_VERDICT … kind=violation`
    /// line), and the embedder aborts the run.
    AlwaysViolation,
    /// The label is reused at a different call site: a fatal duplicate. The
    /// embedder emits the `PATINA_BUGGIFY_DUPLICATE_LABEL` marker and aborts.
    DuplicateLabel,
}

/// One verdict a guest reported through the verdict ABI, in call order.
///
/// `seq` is the run-scoped call index (from 0), so a verdict stream is ordered
/// and countable without timestamps. The record is what the trace's
/// [`Operation::Verdict`] event and the `PATINA_VERDICT` marker line both
/// describe; see [`Context::verdict`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerdictRecord {
    pub seq: u64,
    pub kind: VerdictKind,
    pub label: String,
    pub detail: String,
}

impl VerdictRecord {
    /// The `PATINA_VERDICT` diagnostic line for this verdict (no trailing
    /// newline). Rendered by the shared ABI codec so the producer here and the
    /// `patina.result/v1` envelope's parser cannot drift.
    pub fn marker_line(&self) -> String {
        verdict_line::render(self.seq, self.kind, &self.label, &self.detail)
    }
}

/// What [`Context::custom_op_begin`] tells the caller to do next — the whole
/// point of the custom-op protocol being two calls rather than one.
///
/// The guest's `perform` closure runs on exactly one of the two paths, and the
/// runtime, not the guest, decides which: that is what makes a custom op
/// deterministic by construction rather than by the guest's good behavior.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CustomOpMode {
    /// Record (or plain seeded) execution: run `perform` and hand its result
    /// bytes to [`Context::custom_op_record`].
    Record,
    /// Replay: the recording already holds this operation's result. `perform`
    /// MUST NOT run; take the bytes from [`Context::custom_op_replay_result`].
    /// `len` is their length, so a `(pointer, capacity)` ABI caller can size its
    /// buffer before fetching.
    Replay { len: usize },
}

/// A custom operation announced by [`Context::custom_op_begin`] and not yet
/// closed out. It carries what the closing half needs to verify rather than
/// trust: the trace event to record, and the step counter at announce time.
struct PendingCustomOp {
    label: String,
    key: Vec<u8>,
    /// `self.steps` when the operation was announced. `perform` runs *outside*
    /// Patina's modeled boundary by definition, so a recorded operation landing
    /// between the two halves means the guest wrapped an effect Patina already
    /// models — a trace that cannot replay, because replay skips `perform` and
    /// therefore skips those events. Caught at record time instead of surfacing
    /// as an unexplained operation mismatch on some later replay.
    steps_at_begin: u64,
    /// The recorded result on replay, `None` on the record path. Also the
    /// discriminator the closing half checks, so a `record` on a replay pass (or
    /// a `replay_result` on a record pass) is refused rather than silently
    /// producing a divergent trace.
    replay_result: Option<Vec<u8>>,
}

/// One link-time declared cooperative-SUT site, keyed by its unique explicit
/// label. Declarations come from SDK macro linker sections and do not imply that
/// the site was evaluated in this run.
#[derive(Clone, Debug)]
struct BuggifyDeclaredSite {
    site: String,
    kind: BuggifyKind,
}

/// One registered cooperative-SUT site, keyed by its unique explicit label.
#[derive(Clone, Debug)]
struct BuggifySite {
    /// The `file:line` identity captured by the macro, used only to detect a
    /// duplicate label reused at a different call site.
    site: String,
    kind: BuggifyKind,
    /// Per-run activation decision (fault/delay/knob sites). Pure function of
    /// `(seed, label, activation_permille)`.
    active: bool,
    /// Firing-PRF counter, incremented on every evaluation. Advances identically
    /// on record and replay because the same code runs on both.
    eval_count: u64,
    fire_count: u64,
    reachable: bool,
    sometimes_satisfied: bool,
    always_violated: bool,
    knob: Option<i64>,
}

/// End-of-run cooperative-SUT diagnostics, surfaced in `PATINA_SDK_REPORT` and,
/// via the internal buggify trace record, in the trace metadata.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BuggifyDiagnostics {
    pub enabled: bool,
    pub fire_permille: u16,
    pub activation_permille: u16,
    pub cutoff_nanos: u64,
    pub cutoff_reached: bool,
    pub sites_registered: u64,
    pub sites_activated: u64,
    pub total_firings: u64,
    pub cutoff_suppressed: u64,
    pub after_setup: bool,
    pub setup_complete: bool,
    /// Whether swarm selection deselected the `buggify` class this generation.
    /// True only when the run asked for buggify AND the seed's swarm draw dropped
    /// it, so `enabled == false && swarm_deselected == true` reads "requested,
    /// masked out this generation" while `enabled == false && swarm_deselected ==
    /// false` reads "never requested".
    pub swarm_deselected: bool,
    /// Link-time declared SDK sites in label order. These rows describe the full
    /// literal-label site universe and do not imply per-run evaluation.
    pub declared_sites: Vec<BuggifyDeclaredSiteReport>,
    /// Per-site rows in label order: (label, site, kind, active, evals, fires,
    /// reachable, sometimes_satisfied, always_violated, knob).
    pub sites: Vec<BuggifySiteReport>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuggifyDeclaredSiteReport {
    pub label: String,
    /// The `file:line` identity captured by the SDK macro.
    pub site: String,
    pub kind: BuggifyKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuggifySiteReport {
    pub label: String,
    /// The `file:line` identity captured by the SDK macro / WASI import.
    pub site: String,
    pub kind: BuggifyKind,
    pub active: bool,
    pub evals: u64,
    pub fires: u64,
    pub reachable: bool,
    pub sometimes_satisfied: bool,
    pub always_violated: bool,
    pub knob: Option<i64>,
}

/// The cooperative-SUT (buggify) site registry and deterministic decision
/// engine. All randomness derives from the root seed and the site's explicit
/// label through [`buggify_prf`]; nothing is recorded per-evaluation, so replay
/// re-derives every decision from the seed and the trace's recorded config.
struct Buggify {
    config: BuggifyConfig,
    seed: u64,
    /// Lifecycle marker state. Firing is not gated on it (see the crate/module
    /// docs on the causal limitation); it is reported and, for a guest that
    /// places its workload sites after the call, marks the setup boundary.
    setup_complete: bool,
    declared_sites: BTreeMap<String, BuggifyDeclaredSite>,
    sites: BTreeMap<String, BuggifySite>,
    rng: SplitMix64,
    cutoff_suppressed: u64,
    /// Set once the cutoff has been observed passed at a firing check.
    cutoff_reached: bool,
}

impl Buggify {
    fn new(config: BuggifyConfig, seed: u64) -> Self {
        Self {
            config,
            seed,
            setup_complete: false,
            declared_sites: BTreeMap::new(),
            sites: BTreeMap::new(),
            rng: SplitMix64::new(buggify_prf(&[seed, buggify_domain::RNG])),
            cutoff_suppressed: 0,
            cutoff_reached: false,
        }
    }

    /// Whether a site's label activates it this run. Pure function of the seed,
    /// the label, and the activation per-mille.
    fn label_is_active(&self, label_hash: u64) -> bool {
        (buggify_prf(&[self.seed, label_hash, buggify_domain::ACTIVATION]) % 1000)
            < u64::from(self.config.activation_permille)
    }

    /// Declare a literal-label site discovered from the SDK's link-time table.
    /// This makes a site visible to reports before it is ever evaluated. It does
    /// not compute activation or firing decisions, so unchanged guests keep the
    /// same replay/fingerprint behavior.
    ///
    /// A label declared at two different call sites (or for two different kinds)
    /// is the same fatal duplicate the evaluation path rejects, returned as
    /// [`SiteOutcome::DuplicateLabel`] so the embedder emits the one named
    /// `PATINA_BUGGIFY_DUPLICATE_LABEL` marker. `Err` is reserved for a malformed
    /// declaration (empty label or missing `file:line`).
    fn declare(
        &mut self,
        label: &str,
        site: &str,
        kind: BuggifyKind,
    ) -> Result<SiteOutcome, String> {
        if label.is_empty() {
            return Err("static SDK site label must not be empty".to_string());
        }
        if site.is_empty() {
            return Err(format!(
                "static SDK site {label:?} must carry a file:line identity"
            ));
        }
        match self.declared_sites.get(label) {
            Some(existing) if existing.site != site || existing.kind != kind => {
                return Ok(SiteOutcome::DuplicateLabel);
            }
            Some(_) => return Ok(SiteOutcome::Ok),
            None => {}
        }
        if let Some(existing) = self.sites.get(label) {
            if existing.site != site || existing.kind != kind {
                return Ok(SiteOutcome::DuplicateLabel);
            }
        }
        self.declared_sites.insert(
            label.to_string(),
            BuggifyDeclaredSite {
                site: site.to_string(),
                kind,
            },
        );
        Ok(SiteOutcome::Ok)
    }

    /// Register (or revisit) a site under `label`, returning its stable label
    /// hash. A label reused at a different call `site` (or for a different SDK
    /// kind) is a fatal duplicate (returned as `Err(existing_site)`). On first
    /// registration the activation decision is computed once and frozen.
    fn register(&mut self, label: &str, site: &str, kind: BuggifyKind) -> Result<u64, String> {
        let hash = label_hash(label);
        if let Some(declared) = self.declared_sites.get(label) {
            if declared.site != site || declared.kind != kind {
                return Err(declared.site.clone());
            }
        }
        match self.sites.get(label) {
            Some(existing) if existing.site != site || existing.kind != kind => {
                return Err(existing.site.clone());
            }
            Some(_) => {}
            None => {
                let active = self.label_is_active(hash);
                self.sites.insert(
                    label.to_string(),
                    BuggifySite {
                        site: site.to_string(),
                        kind,
                        active,
                        eval_count: 0,
                        fire_count: 0,
                        reachable: false,
                        sometimes_satisfied: false,
                        always_violated: false,
                        knob: None,
                    },
                );
            }
        }
        Ok(hash)
    }

    /// The firing decision for an active site at its current evaluation, given a
    /// (possibly overridden) firing per-mille. Increments the evaluation counter
    /// as a side effect so consecutive evaluations use independent draws.
    fn fire_draw(hash: u64, seed: u64, eval_count: u64, fire_permille: u16) -> bool {
        (buggify_prf(&[seed, hash, buggify_domain::FIRING, eval_count]) % 1000)
            < u64::from(fire_permille)
    }

    fn diagnostics(&self, cutoff_reached_now: bool) -> BuggifyDiagnostics {
        let mut declared_sites = Vec::with_capacity(self.declared_sites.len());
        for (label, site) in &self.declared_sites {
            declared_sites.push(BuggifyDeclaredSiteReport {
                label: label.clone(),
                site: site.site.clone(),
                kind: site.kind,
            });
        }
        let mut sites = Vec::with_capacity(self.sites.len());
        let mut activated = 0_u64;
        let mut firings = 0_u64;
        for (label, site) in &self.sites {
            if site.active {
                activated += 1;
            }
            firings += site.fire_count;
            sites.push(BuggifySiteReport {
                label: label.clone(),
                site: site.site.clone(),
                kind: site.kind,
                active: site.active,
                evals: site.eval_count,
                fires: site.fire_count,
                reachable: site.reachable,
                sometimes_satisfied: site.sometimes_satisfied,
                always_violated: site.always_violated,
                knob: site.knob,
            });
        }
        BuggifyDiagnostics {
            enabled: self.config.enabled,
            fire_permille: self.config.fire_permille,
            activation_permille: self.config.activation_permille,
            cutoff_nanos: self.config.cutoff_nanos,
            cutoff_reached: self.cutoff_reached || cutoff_reached_now,
            sites_registered: self.sites.len() as u64,
            sites_activated: activated,
            total_firings: firings,
            cutoff_suppressed: self.cutoff_suppressed,
            after_setup: self.config.after_setup,
            setup_complete: self.setup_complete,
            // The engine has no view of the swarm draw; `Context::buggify_diagnostics`
            // fills this in from the run's swarm record.
            swarm_deselected: false,
            declared_sites,
            sites,
        }
    }

    /// The realized configuration and per-site picks recorded into the trace
    /// metadata, or `None` when buggify is disabled.
    fn to_record(&self) -> Option<patina_dst_trace::BuggifyConfigRecord> {
        if !self.config.enabled {
            return None;
        }
        let active_sites = self
            .sites
            .iter()
            .filter(|(_, site)| site.active)
            .map(|(label, _)| label.clone())
            .collect();
        let knobs = self
            .sites
            .iter()
            .filter_map(|(label, site)| site.knob.map(|value| (label.clone(), value)))
            .collect();
        Some(patina_dst_trace::BuggifyConfigRecord {
            fire_permille: self.config.fire_permille,
            activation_permille: self.config.activation_permille,
            cutoff_nanos: self.config.cutoff_nanos,
            after_setup: self.config.after_setup,
            active_sites,
            knobs,
        })
    }

    /// Whether the run declared `--buggify-after-setup` but the guest never
    /// reached `setup_complete()`: a harness bug that must fail loudly, not a
    /// silent no-fault run.
    fn setup_violation(&self) -> bool {
        self.config.enabled && self.config.after_setup && !self.setup_complete
    }

    /// Whether firing is currently armed: always, unless gated behind a
    /// setup-complete the guest has not reached yet.
    fn armed(&self) -> bool {
        !self.config.after_setup || self.setup_complete
    }
}

/// The runtime context through which initial Patina effects are performed.
/// The installed deterministic world: one seeded run's clock, filesystem,
/// network, entropy, scheduler, and (in record/replay modes) its trace.
///
/// Every method that performs an effect is a *boundary operation*: it consults
/// the deterministic drivers, records the outcome when recording, and — on
/// replay — reconciles against the recorded outcome, failing closed on any
/// divergence. Effects are grouped by prefix: `fs_*` (plus the
/// [`write_file`](Context::write_file)/[`read_file`](Context::read_file)
/// conveniences), `net_*` and `net_tcp_*`, `task_*` for scheduler-visible
/// tasks, [`now`](Context::now)/[`sleep_for`](Context::sleep_for)/
/// [`sleep_until`](Context::sleep_until) for the virtual clock, and
/// [`entropy_bytes`](Context::entropy_bytes).
///
/// Obtain one through [`run`]/[`run_with`] (which also finalize it) or
/// [`Context::from_config`]; when managing it manually, call
/// [`finish`](Context::finish) so diagnostics and any recorded trace are
/// written. A `Context` controls only effects performed through its own
/// methods — it does not interpose the rest of the process.
pub struct Context {
    root_seed: u64,
    step_budget: Option<u64>,
    steps: u64,
    params: BTreeMap<String, String>,
    guest_env: BTreeMap<String, String>,
    execution: Execution,
    filesystem: Option<Box<dyn FsDriver>>,
    filesystem_is_capture: bool,
    clock: Option<Box<dyn ClockDriver>>,
    entropy: Option<Box<dyn EntropyDriver>>,
    scheduler: Option<Box<dyn SchedulerDriver>>,
    network: Option<Box<dyn NetDriver>>,
    /// Virtual-clock timer queue. Ordered by `(monotonic_deadline_nanos,
    /// registration_seq)` so the deadlock-rescue path advances to the single
    /// earliest deadline and wakes due tasks in a stable order. Maintained
    /// identically on record and replay because every park/wake runs on both.
    timers: BTreeMap<(u64, u64), TaskId>,
    /// Reverse index enforcing at most one live timer per task and enabling
    /// deregistration when a task is woken early (by signal or data).
    timer_by_task: BTreeMap<TaskId, (u64, u64)>,
    timer_seq: u64,
    /// Shadow of the scheduler's task set and which tasks are parked, so the
    /// runtime can tell — without a new `SchedulerDriver` method — when
    /// `scheduler.next()` would deadlock and a timer rescue is warranted.
    scheduler_tasks: std::collections::BTreeSet<TaskId>,
    parked_tasks: std::collections::BTreeSet<TaskId>,
    /// Tasks woken by the most recent deadlock-rescue (their timers fired), for
    /// an embedder to drain and resolve as timeouts.
    rescued: Vec<TaskId>,
    /// Configured filesystem crash point, or `None` when crash injection is off.
    /// Consulted after each matching boundary operation; the crash fires exactly
    /// once. The op sequence is identical on record and replay, so the injected
    /// `FsCrash` lands at the same position and reconciles.
    crash_at: Option<CrashPoint>,
    crash_counts: CrashCounts,
    crash_fired: bool,
    /// Inclusive `[min, max]` nanoseconds of seeded latency added to each guest
    /// sleep, or `None` when latency injection is off.
    sleep_jitter_nanos: Option<(u64, u64)>,
    sleep_jitter_rng: SplitMix64,
    /// Inclusive `[min, max]` nanoseconds of seeded latency added to each
    /// fault-eligible filesystem operation, or `None` when fs latency is off.
    /// Latency needs the clock, so the Context is the ONE site that applies it —
    /// no embedder may add a second (see the family-parity rules).
    fs_latency_nanos: Option<(u64, u64)>,
    fs_latency_rng: SplitMix64,
    /// Fault-eligible filesystem operations this Context routed, and how many of
    /// them an fs-latency draw actually delayed. Folded into the driver's
    /// [`patina_dst_driver_api::FsFaultReport`] at finalization: the driver and
    /// the Context are independent observers of the same op stream, so eligible
    /// traffic the Context never delayed is exactly the inert-knob signal.
    fs_latency_eligible_ops: u64,
    fs_latency_applied: u64,
    /// The run's DNS host table: the only names that resolve to an address.
    dns_entries: BTreeMap<String, String>,
    /// Seeded DNS resolution-failure knob and its domain-separated stream.
    dns_fail_permille: u16,
    dns_fault_rng: SplitMix64,
    /// Seeded DNS resolution latency, applied Context-side like fs latency
    /// because it too needs the clock.
    dns_latency_nanos: Option<(u64, u64)>,
    dns_latency_rng: SplitMix64,
    /// Per-class DNS fault accounting for the end-of-run vacuity diagnostic.
    dns_report: patina_dst_driver_api::DnsFaultReport,
    /// Seeded entropy-request failure knob and its domain-separated stream. The
    /// stream is deliberately NOT the entropy stream itself (see
    /// [`fault_domain::ENTROPY_FAULT`]): drawing the fire/no-fire decision from
    /// the guest-visible bytes would perturb every non-faulted request's bytes
    /// the moment the knob was armed.
    entropy_fail_permille: u16,
    entropy_fault_rng: SplitMix64,
    /// Per-class entropy fault accounting for the end-of-run vacuity diagnostic.
    entropy_report: patina_dst_driver_api::EntropyFaultReport,
    /// Magnitude in nanoseconds of the seeded signed realtime-epoch jump and its
    /// domain-separated stream. Zero means the knob is off. The stream is its
    /// own label ([`fault_domain::EPOCH_JUMP`]), never the clock driver's own
    /// state, so the jump decision cannot correlate with any other fault plane.
    epoch_jump_nanos: u64,
    epoch_jump_rng: SplitMix64,
    /// Per-class clock (epoch-jump) fault accounting for the end-of-run vacuity
    /// diagnostic.
    clock_report: patina_dst_driver_api::ClockFaultReport,
    /// Per-task scheduling-boundary accounting for the vacuous-schedule
    /// diagnostic emitted at [`Context::finish`].
    schedule: ScheduleTracker,
    /// Cooperative-SUT (buggify) site registry and decision engine. Inert when
    /// buggify is disabled, so a run that does not opt in is unaffected.
    buggify: Buggify,
    /// Every verdict the guest reported this run, in call order. Also recorded in
    /// the trace as [`Operation::Verdict`], so a replay reproduces the stream.
    verdicts: Vec<VerdictRecord>,
    /// The custom operation currently between its `begin` and its `record`/
    /// `replay_result` half, if any. `Some` only for the duration of one
    /// `custom_op` call; anything that would leave it set across another
    /// `begin` — or across [`Context::finish`] — is refused (see
    /// [`Context::custom_op_begin`]).
    custom_op: Option<PendingCustomOp>,
    /// Diagnostic lines the runtime produced but has not printed. The runtime
    /// performs no process I/O in the middle of a run — the same doctrine
    /// [`SiteOutcome`] follows — so the embedder drains this after each entry
    /// point and writes the lines into its own captured stderr, where they
    /// interleave with guest output and survive an abort's flush. Whatever is
    /// still pending at [`Context::finish`] is printed there, which is what makes
    /// the in-process (cargo-family) path work with no embedder to drain it.
    pending_diagnostics: Vec<String>,
    /// Virtual-time liveness watchdog. Inert (`active == false`) unless a budget is
    /// configured on a record/seeded run, so a run that does not opt in — and every
    /// replay — is byte-for-byte unchanged.
    liveness: LivenessWatchdog,
    /// The swarm fault-class selection this run carried, or `None` when swarm was
    /// not enabled. A record/seeded run draws it; a replay or branch adopts the
    /// recording's, so a replayed generation reports the same decision rather
    /// than re-drawing one. Drives `PATINA_SWARM_REPORT` and the
    /// `swarm_deselected` field of `PATINA_SDK_REPORT`.
    swarm: Option<patina_dst_trace::SwarmConfigRecord>,
    /// Which end-of-run diagnostic reports [`Context::finish`] prints, resolved
    /// at configuration time. Presentation only — it reaches no recorded byte.
    reports: ReportConfig,
    /// Where this run's structured facts document goes, or `None` when nobody
    /// asked for one. Like `reports`, it reaches no recorded byte.
    facts: Option<facts::FactsOutput>,
    /// Whether the facts document has already been written. The document is
    /// emitted at [`Context::finish`] on the ordinary path, but a fired liveness
    /// watchdog aborts the process before `finish` on the interposed families,
    /// so that path emits it early — this flag keeps it at exactly one write.
    facts_emitted: bool,
    /// Advance-on-spin state. See [`SpinRescue`]; inert until a guest actually
    /// churns on the clock, so a run that never spins is byte-for-byte unchanged.
    spin: SpinRescue,
    /// Whether the recording has already been written out by
    /// [`Context::flush_recording`] on a runtime-initiated stop. The trace
    /// transport is an append-only descriptor in the interposed families, so a
    /// second write would corrupt the bundle: this flag keeps it at exactly one.
    recording_flushed: bool,
}

impl Context {
    /// A context over `config` with the default deterministic drivers. The
    /// caller owns finalization: call [`Context::finish`] when done (or use
    /// [`run`]/[`run_with`], which do).
    pub fn from_config(config: RuntimeConfig) -> Result<Self, RuntimeError> {
        RuntimeBuilder::new(config).with_default_drivers().build()
    }

    /// Like [`Context::from_config`] with a config read from the `PATINA_*`
    /// control plane ([`RuntimeConfig::from_env`]).
    pub fn from_env() -> Result<Self, RuntimeError> {
        Self::from_config(RuntimeConfig::from_env()?)
    }

    /// The run's root seed — the single input every deterministic decision
    /// derives from.
    pub const fn root_seed(&self) -> u64 {
        self.root_seed
    }

    /// Boundary operations performed so far (the step counter the optional
    /// step budget is enforced against).
    pub const fn steps(&self) -> u64 {
        self.steps
    }

    /// End-of-run schedule-exploration diagnostics. See [`ScheduleDiagnostics`].
    /// Also emitted to stderr by [`Context::finish`] for multithreaded runs.
    pub fn schedule_diagnostics(&self) -> ScheduleDiagnostics {
        self.schedule.diagnostics()
    }

    pub fn param(&self, key: &str) -> Option<&str> {
        self.params.get(key).map(String::as_str)
    }

    /// Return one deterministic guest environment value.
    pub fn guest_env_var(&self, key: &str) -> Option<&str> {
        self.guest_env.get(key).map(String::as_str)
    }

    /// The whole live deterministic guest environment, in key order.
    ///
    /// This is the run's single source of truth for environment reads, seeded
    /// from the recorded startup map and updated by [`guest_env_set`] and
    /// [`guest_env_remove`]. The native shim republishes the process `environ`
    /// array from it so direct `environ` walkers and the `getenv` interposer
    /// never disagree.
    ///
    /// [`guest_env_set`]: Context::guest_env_set
    /// [`guest_env_remove`]: Context::guest_env_remove
    pub const fn guest_env(&self) -> &BTreeMap<String, String> {
        &self.guest_env
    }

    /// Set one deterministic guest environment value, returning whether the map
    /// changed. With `overwrite` false an existing key is left alone (POSIX
    /// `setenv` semantics).
    ///
    /// Guest environment mutation is process memory, not a host effect: it is
    /// derived entirely from guest control flow, so it takes no boundary step,
    /// records nothing, and reproduces on replay by re-executing the guest. The
    /// trace metadata keeps only the startup map the run was configured with.
    pub fn guest_env_set(
        &mut self,
        key: &str,
        value: &str,
        overwrite: bool,
    ) -> Result<bool, RuntimeError> {
        validate_guest_env_entry(key, value)?;
        if !overwrite && self.guest_env.contains_key(key) {
            return Ok(false);
        }
        Ok(self
            .guest_env
            .insert(key.to_owned(), value.to_owned())
            .is_none_or(|previous| previous != value))
    }

    /// Remove one deterministic guest environment value, returning whether the
    /// key was present. Removing an absent key succeeds (POSIX `unsetenv`).
    /// See [`guest_env_set`](Context::guest_env_set) for why this is unrecorded.
    pub fn guest_env_remove(&mut self, key: &str) -> Result<bool, RuntimeError> {
        validate_guest_env_key(key)?;
        Ok(self.guest_env.remove(key).is_some())
    }

    /// Drop every deterministic guest environment value, returning whether the
    /// map was non-empty. Backs the native `clearenv` interposer.
    pub fn guest_env_clear(&mut self) -> bool {
        let changed = !self.guest_env.is_empty();
        self.guest_env.clear();
        changed
    }

    // ---- Cooperative-SUT (buggify) surface -----------------------------------
    //
    // These methods are the runtime side of the `patina` crate's `buggify!`,
    // `always!`, `sometimes!`, `reachable!`, and lifecycle macros, invoked
    // through thin C-ABI wrappers in the native shim. All randomness derives from
    // the root seed and the site's explicit label; nothing is recorded per
    // evaluation, so replay re-derives every decision. The only recorded effect
    // is `buggify_delay!`'s virtual-time advance, which rides the existing
    // `SleepUntil` boundary op and therefore reproduces exactly on replay.

    /// Whether execution is under the deterministic simulator. Always true for an
    /// installed [`Context`] — the `patina_dst::is_simulated()` hook.
    pub const fn is_simulated(&self) -> bool {
        true
    }

    /// Whether cooperative-SUT fault injection is enabled this run.
    pub const fn buggify_enabled(&self) -> bool {
        self.buggify.config.enabled
    }

    /// Declare one SDK site discovered from a link-time site table. Declarations
    /// make never-reached sites visible in diagnostics but do not evaluate the
    /// site, compute activation, advance counters, or enter the trace.
    ///
    /// Returns [`SiteOutcome::DuplicateLabel`] when the label is already bound to
    /// a different call site or kind — the embedder emits the same
    /// `PATINA_BUGGIFY_DUPLICATE_LABEL` marker the evaluation path uses. `Err`
    /// means the declaration itself is malformed.
    pub fn declare_static_site(
        &mut self,
        label: &str,
        site: &str,
        kind: BuggifyKind,
    ) -> Result<SiteOutcome, RuntimeError> {
        self.buggify.declare(label, site, kind).map_err(|error| {
            RuntimeError::Config(format!("invalid static SDK site declaration: {error}"))
        })
    }

    /// Evaluate a `buggify!` / `buggify_with_prob!` site. `prob_permille`
    /// overrides the run-default firing probability when `Some`. Fires only when
    /// buggify is enabled, the label activated this run, and the virtual clock is
    /// before the damage-control cutoff.
    pub fn buggify_evaluate(
        &mut self,
        label: &str,
        site: &str,
        prob_permille: Option<u16>,
    ) -> Result<SiteOutcome, RuntimeError> {
        let enabled = self.buggify.config.enabled;
        let now = if enabled {
            Some(self.current_monotonic()?)
        } else {
            None
        };
        let hash = match self.buggify.register(label, site, BuggifyKind::Fault) {
            Ok(hash) => hash,
            Err(_) => return Ok(SiteOutcome::DuplicateLabel),
        };
        let (active, eval) = {
            let entry = self.buggify.sites.get_mut(label).expect("registered");
            entry.reachable = true;
            let eval = entry.eval_count;
            entry.eval_count += 1;
            (entry.active, eval)
        };
        if !enabled || !active || !self.buggify.armed() {
            return Ok(SiteOutcome::Ok);
        }
        if now.is_some_and(|now| now >= self.buggify.config.cutoff_nanos) {
            self.buggify.cutoff_reached = true;
            self.buggify.cutoff_suppressed += 1;
            return Ok(SiteOutcome::Ok);
        }
        let permille = prob_permille.unwrap_or(self.buggify.config.fire_permille);
        if Buggify::fire_draw(hash, self.buggify.seed, eval, permille) {
            self.buggify
                .sites
                .get_mut(label)
                .expect("registered")
                .fire_count += 1;
            Ok(SiteOutcome::Fire)
        } else {
            Ok(SiteOutcome::Ok)
        }
    }

    /// Evaluate a `buggify_delay!` site. On firing, advance the virtual clock by
    /// a seed-derived amount through the recorded `SleepUntil` path — never a real
    /// sleep — so the perturbation reproduces on replay. Returns [`SiteOutcome::Fire`]
    /// when it delayed.
    pub fn buggify_delay(&mut self, label: &str, site: &str) -> Result<SiteOutcome, RuntimeError> {
        let enabled = self.buggify.config.enabled;
        let now = if enabled {
            Some(self.current_monotonic()?)
        } else {
            None
        };
        let hash = match self.buggify.register(label, site, BuggifyKind::Delay) {
            Ok(hash) => hash,
            Err(_) => return Ok(SiteOutcome::DuplicateLabel),
        };
        let (active, eval) = {
            let entry = self.buggify.sites.get_mut(label).expect("registered");
            entry.reachable = true;
            let eval = entry.eval_count;
            entry.eval_count += 1;
            (entry.active, eval)
        };
        if !enabled || !active || !self.buggify.armed() {
            return Ok(SiteOutcome::Ok);
        }
        let now = now.expect("time read when enabled");
        if now >= self.buggify.config.cutoff_nanos {
            self.buggify.cutoff_reached = true;
            self.buggify.cutoff_suppressed += 1;
            return Ok(SiteOutcome::Ok);
        }
        if !Buggify::fire_draw(
            hash,
            self.buggify.seed,
            eval,
            self.buggify.config.fire_permille,
        ) {
            return Ok(SiteOutcome::Ok);
        }
        // A seed-derived delay in [1ms, 5s], deterministic per (seed, label,
        // eval). Routed through the recorded clock path so replay reproduces it.
        const MIN_DELAY_NANOS: u64 = 1_000_000;
        const MAX_DELAY_NANOS: u64 = 5_000_000_000;
        let span = MAX_DELAY_NANOS - MIN_DELAY_NANOS + 1;
        let delay = MIN_DELAY_NANOS
            + (buggify_prf(&[self.buggify.seed, hash, buggify_domain::DELAY, eval]) % span);
        self.buggify
            .sites
            .get_mut(label)
            .expect("registered")
            .fire_count += 1;
        let deadline = now.saturating_add(delay);
        self.sleep_until(ClockKind::Monotonic, deadline)?;
        Ok(SiteOutcome::Fire)
    }

    /// Evaluate a `buggify_knob!` site: return a per-run perturbed value within
    /// `[lo, hi]` (deterministic from seed and label) for an active site under an
    /// enabled run, or `default` otherwise. `Err(())` marks a duplicate label.
    pub fn buggify_knob(
        &mut self,
        label: &str,
        site: &str,
        default: i64,
        lo: i64,
        hi: i64,
    ) -> Result<Result<i64, ()>, RuntimeError> {
        let hash = match self.buggify.register(label, site, BuggifyKind::Knob) {
            Ok(hash) => hash,
            Err(_) => return Ok(Err(())),
        };
        let (lo, hi) = if lo <= hi { (lo, hi) } else { (hi, lo) };
        let enabled = self.buggify.config.enabled;
        let entry = self.buggify.sites.get_mut(label).expect("registered");
        entry.reachable = true;
        let value = if enabled && entry.active {
            let span = (hi as i128 - lo as i128 + 1) as u128;
            let draw = buggify_prf(&[self.buggify.seed, hash, buggify_domain::KNOB]) as u128;
            (lo as i128 + (draw % span) as i128) as i64
        } else {
            default.clamp(lo, hi)
        };
        entry.knob = Some(value);
        Ok(Ok(value))
    }

    /// Report one guest verdict — the runtime half of the verdict ABI
    /// (`patina_verdict` natively, the `patina_sdk` `verdict` import on WASI, and
    /// this method directly for an in-process cargo-family guest).
    ///
    /// The call is recorded as an [`Operation::Verdict`] boundary event, so a
    /// replay whose verdict stream diverges from the recording fails closed like
    /// any other operation mismatch, and the run's `PATINA_VERDICT` marker line
    /// is queued for the embedder to surface (see `pending_diagnostics`). The
    /// verdict itself has no effect on control flow: a `Violation` does not
    /// abort, and an `AbortIntent` does not abort — it *attributes* an abort the
    /// guest is about to perform itself.
    pub fn verdict(
        &mut self,
        kind: VerdictKind,
        label: &str,
        detail: &str,
    ) -> Result<VerdictRecord, RuntimeError> {
        let operation = Operation::Verdict {
            verdict_kind: kind,
            label: label.to_string(),
            detail: detail.to_string(),
        };
        let expected = self.replay_expected(&operation)?;
        self.reconcile(operation, expected, Outcome::Unit)?;
        let record = VerdictRecord {
            seq: self.verdicts.len() as u64,
            kind,
            label: label.to_string(),
            detail: detail.to_string(),
        };
        self.pending_diagnostics.push(record.marker_line());
        self.verdicts.push(record.clone());
        Ok(record)
    }

    /// Every verdict reported so far, in call order.
    pub fn verdicts(&self) -> &[VerdictRecord] {
        &self.verdicts
    }

    /// Announce a custom operation and learn whether to run it — the opening
    /// half of the custom-op ABI (`patina_custom_op_begin` natively, the
    /// `patina_sdk` `custom_op_begin` import on WASI, this method directly for an
    /// in-process cargo-family guest).
    ///
    /// `label` names the operation class and `key` is its logical input; both are
    /// recorded, so a replay asserts the guest asked the *same* question of the
    /// same class before handing back an answer. A mismatch in either refuses,
    /// naming the label — the trace is authoritative, exactly as it is for a
    /// replayed `--env` value.
    ///
    /// Every `begin` must be closed by exactly one [`Context::custom_op_record`]
    /// (on [`CustomOpMode::Record`]) or [`Context::custom_op_replay_result`] (on
    /// [`CustomOpMode::Replay`]). A second `begin` while one is open is refused:
    /// a nested custom op would record an inner event that replay — which never
    /// runs the outer `perform` — could never produce.
    ///
    /// Prefer [`Context::custom_op`], which drives this protocol correctly and
    /// types the key and result; these three methods are the raw ABI shape the
    /// embedders lower to.
    pub fn custom_op_begin(
        &mut self,
        label: &str,
        key: &[u8],
    ) -> Result<CustomOpMode, RuntimeError> {
        if let Some(open) = self.custom_op.as_ref() {
            return Err(RuntimeError::CustomOp {
                label: label.to_string(),
                detail: format!(
                    "custom op {label:?} was begun while custom op {:?} is still open; a custom \
operation may not nest or be left unclosed, because replay does not run the outer `perform` and \
so could never reproduce the inner operation",
                    open.label
                ),
            });
        }
        let operation = Operation::CustomOp {
            label: label.to_string(),
            key: key.to_vec(),
        };
        let expected = self
            .replay_expected(&operation)
            .map_err(|error| classify_custom_op_divergence(label, key, error))?;
        let steps_at_begin = self.steps;
        match expected {
            Some((_, Outcome::Bytes(recorded))) => {
                let len = recorded.len();
                self.custom_op = Some(PendingCustomOp {
                    label: label.to_string(),
                    key: key.to_vec(),
                    steps_at_begin,
                    replay_result: Some(recorded),
                });
                Ok(CustomOpMode::Replay { len })
            }
            Some((_, outcome)) => Err(RuntimeError::InvalidOutcome {
                operation: Box::new(operation),
                outcome: Box::new(outcome),
            }),
            None => {
                self.custom_op = Some(PendingCustomOp {
                    label: label.to_string(),
                    key: key.to_vec(),
                    steps_at_begin,
                    replay_result: None,
                });
                Ok(CustomOpMode::Record)
            }
        }
    }

    /// The length of the open custom operation's recorded result, or `None` when
    /// no operation is open or the open one is on the record path. A read-only
    /// peek: a `(pointer, capacity)` ABI caller uses it to refuse a short buffer
    /// *without* consuming the recorded result, so the call can be retried.
    pub fn custom_op_pending_len(&self) -> Option<usize> {
        self.custom_op
            .as_ref()?
            .replay_result
            .as_ref()
            .map(Vec::len)
    }

    /// Take the recorded result of the open custom operation, closing it. Only
    /// valid after a [`CustomOpMode::Replay`]; on a record pass there is no
    /// recorded answer and the call is refused rather than answered with
    /// something invented.
    pub fn custom_op_replay_result(&mut self) -> Result<Vec<u8>, RuntimeError> {
        let Some(pending) = self.custom_op.take() else {
            return Err(RuntimeError::CustomOp {
                label: String::new(),
                detail: "custom-op replay result requested with no custom operation open; every \
fetch must follow its own `begin`"
                    .into(),
            });
        };
        let label = pending.label;
        pending.replay_result.ok_or(RuntimeError::CustomOp {
            detail: format!(
                "custom op {label:?} asked for a recorded result on a pass that is not a replay; \
the record pass must run `perform` and report its bytes instead"
            ),
            label,
        })
    }

    /// Record what the guest's `perform` produced, closing the open custom
    /// operation and appending its trace event. Only valid after a
    /// [`CustomOpMode::Record`].
    ///
    /// Refuses if any modeled boundary operation ran between the two halves: the
    /// wrapped effect is supposed to be one Patina does *not* model, and a
    /// recorded operation inside `perform` yields a trace that cannot replay
    /// (replay skips `perform`, so it would never produce those events). Failing
    /// here names the cause; failing on replay would only report an operation
    /// mismatch at an unrelated-looking index.
    pub fn custom_op_record(&mut self, result: Vec<u8>) -> Result<(), RuntimeError> {
        let Some(pending) = self.custom_op.take() else {
            return Err(RuntimeError::CustomOp {
                label: String::new(),
                detail: "custom-op result reported with no custom operation open; every result \
must follow its own `begin`"
                    .into(),
            });
        };
        if pending.replay_result.is_some() {
            return Err(RuntimeError::CustomOp {
                detail: format!(
                    "custom op {:?} reported a freshly performed result on a replay pass, where \
the recording is authoritative and `perform` must not run",
                    pending.label
                ),
                label: pending.label,
            });
        }
        let inner = self.steps - pending.steps_at_begin;
        if inner != 0 {
            return Err(RuntimeError::CustomOp {
                detail: format!(
                    "custom op {:?} performed {inner} modeled boundary operation(s) inside its \
`perform`; a custom op must wrap an effect Patina does NOT model, because replay returns the \
recorded bytes without running `perform` and could never reproduce those operations",
                    pending.label
                ),
                label: pending.label,
            });
        }
        let operation = Operation::CustomOp {
            label: pending.label,
            key: pending.key,
        };
        self.complete(operation, Outcome::Bytes(result));
        Ok(())
    }

    /// Perform one custom operation: a guest-declared effect Patina does not
    /// model, recorded on the record pass and reproduced from the recording on
    /// replay. The cargo-family mirror of the SDK's `patina_dst::custom_op`.
    ///
    /// On a record or plain seeded pass `perform` runs and its value is encoded
    /// and recorded. On replay `perform` is **not** run — the recorded bytes are
    /// decoded and returned — so the operation is deterministic by construction
    /// even though the real effect is not.
    ///
    /// `key` is the operation's logical input. It is recorded alongside the
    /// result and checked on replay, so a guest that asks a different question
    /// under the same label is refused rather than handed a stale answer.
    ///
    /// Values are encoded with `serde_json`, matching the SDK. That choice is
    /// **build-owned, not ABI-owned**: the boundary and the trace carry opaque
    /// bytes (see [`Operation::CustomOp`]), and a trace only ever replays against
    /// the guest binary that recorded it, which the fingerprint already enforces.
    /// JSON over a denser format because a custom op's whole value is triage: the
    /// key and result stay legible in `cargo patina trace`, which a
    /// non-self-describing encoding would make opaque.
    pub fn custom_op<T, K>(
        &mut self,
        label: &str,
        key: &K,
        perform: impl FnOnce() -> T,
    ) -> Result<T, RuntimeError>
    where
        T: serde::Serialize + serde::de::DeserializeOwned,
        K: serde::Serialize + ?Sized,
    {
        let key_bytes = serde_json::to_vec(key).map_err(|error| RuntimeError::CustomOp {
            label: label.to_string(),
            detail: format!("custom op {label:?} could not encode its key: {error}"),
        })?;
        match self.custom_op_begin(label, &key_bytes)? {
            CustomOpMode::Replay { .. } => {
                let bytes = self.custom_op_replay_result()?;
                serde_json::from_slice(&bytes).map_err(|error| RuntimeError::CustomOp {
                    label: label.to_string(),
                    detail: format!(
                        "custom op {label:?} could not decode its recorded result: {error}; the \
recording was produced by a guest whose result type no longer matches this one"
                    ),
                })
            }
            CustomOpMode::Record => {
                let value = perform();
                let bytes = serde_json::to_vec(&value).map_err(|error| RuntimeError::CustomOp {
                    label: label.to_string(),
                    detail: format!("custom op {label:?} could not encode its result: {error}"),
                })?;
                self.custom_op_record(bytes)?;
                Ok(value)
            }
        }
    }

    /// Take the diagnostic lines the runtime has queued but not printed. The
    /// embedder calls this after every SDK entry point and writes each line to
    /// its captured stderr; see `Context::pending_diagnostics`.
    pub fn take_pending_diagnostics(&mut self) -> Vec<String> {
        std::mem::take(&mut self.pending_diagnostics)
    }

    /// Evaluate an `always!` invariant. A false condition is a fatal violation
    /// whenever running under the simulator, independent of buggify being
    /// enabled — the embedder emits the marker and aborts.
    ///
    /// A violation lowers to the verdict ABI: it reports
    /// `VerdictKind::Violation` under the site's label (with the `file:line`
    /// identity as the detail) before returning, so the failure reaches the trace
    /// and the result envelope structurally. This is the SDK-surface lowering
    /// §4.1 of the outcome-channel arc calls for, and it is the violation's ONLY
    /// announcement: the embedders drain the verdict line and abort, printing no
    /// marker of their own.
    pub fn always_check(
        &mut self,
        label: &str,
        site: &str,
        condition: bool,
    ) -> Result<SiteOutcome, RuntimeError> {
        if self
            .buggify
            .register(label, site, BuggifyKind::Always)
            .is_err()
        {
            return Ok(SiteOutcome::DuplicateLabel);
        }
        let entry = self.buggify.sites.get_mut(label).expect("registered");
        entry.reachable = true;
        entry.eval_count += 1;
        if condition {
            return Ok(SiteOutcome::Ok);
        }
        entry.always_violated = true;
        self.verdict(VerdictKind::Violation, label, site)?;
        Ok(SiteOutcome::AlwaysViolation)
    }

    /// Evaluate a `sometimes!` coverage oracle: note the site reached, and
    /// satisfied when `condition` is true at least once across the run.
    pub fn sometimes_check(
        &mut self,
        label: &str,
        site: &str,
        condition: bool,
    ) -> Result<SiteOutcome, RuntimeError> {
        if self
            .buggify
            .register(label, site, BuggifyKind::Sometimes)
            .is_err()
        {
            return Ok(SiteOutcome::DuplicateLabel);
        }
        let entry = self.buggify.sites.get_mut(label).expect("registered");
        entry.reachable = true;
        entry.eval_count += 1;
        if condition {
            entry.sometimes_satisfied = true;
        }
        Ok(SiteOutcome::Ok)
    }

    /// Mark a `reachable!` coverage site reached.
    pub fn reachable_mark(&mut self, label: &str, site: &str) -> Result<SiteOutcome, RuntimeError> {
        if self
            .buggify
            .register(label, site, BuggifyKind::Reachable)
            .is_err()
        {
            return Ok(SiteOutcome::DuplicateLabel);
        }
        let entry = self.buggify.sites.get_mut(label).expect("registered");
        entry.reachable = true;
        entry.eval_count += 1;
        Ok(SiteOutcome::Ok)
    }

    /// Draw a deterministic 64-bit value from the buggify entropy stream — the
    /// `patina_dst::rng()` hook, bridged to the root seed. Not recorded: it is a pure
    /// function of the seed and the call count, so replay reproduces it.
    pub fn buggify_rng(&mut self) -> u64 {
        self.buggify.rng.next_u64()
    }

    /// Mark the `patina_dst::lifecycle::setup_complete()` boundary.
    pub fn lifecycle_setup_complete(&mut self) {
        self.buggify.setup_complete = true;
    }

    /// Whether the run declared `--buggify-after-setup` but the guest never
    /// reached `setup_complete()`. The embedder checks this at finalization and
    /// fails the run loudly — a declared-but-never-called gate is a harness bug,
    /// not a silent no-fault run.
    pub fn buggify_setup_violation(&self) -> bool {
        self.buggify.setup_violation()
    }

    /// End-of-run cooperative-SUT diagnostics. See [`BuggifyDiagnostics`]. Also
    /// emitted to stderr by [`Context::finish`] via `PATINA_SDK_REPORT`.
    pub fn buggify_diagnostics(&mut self) -> BuggifyDiagnostics {
        let cutoff_reached_now = self.buggify.config.enabled
            && self
                .current_monotonic()
                .is_ok_and(|now| now >= self.buggify.config.cutoff_nanos);
        // Whether buggify is off because THIS generation's swarm draw dropped it,
        // as opposed to never having been requested. Both report `enabled=0`, and
        // conflating them is what turned a working `--buggify=N` into a phantom
        // bug report; the flag makes the two states distinguishable in one line.
        let swarm_deselected = self
            .swarm
            .as_ref()
            .is_some_and(|swarm| swarm.deselected(FINGERPRINT_BUGGIFY));
        let mut diagnostics = self.buggify.diagnostics(cutoff_reached_now);
        diagnostics.swarm_deselected = swarm_deselected;
        diagnostics
    }

    pub fn entropy_bytes(&mut self, len: usize) -> Result<Vec<u8>, RuntimeError> {
        if self.entropy.is_none() {
            return Err(EffectError::missing_driver("entropy").into());
        }
        let operation = Operation::EntropyFill { len };
        if let Some((_, recorded)) = self.replay_expected(&operation)? {
            return decode_bytes(&operation, recorded);
        }

        self.entropy_report.requests += 1;
        let outcome = match self.draw_entropy_failure() {
            Some(error) => {
                self.entropy_report.failures_injected += 1;
                Outcome::Error(error)
            }
            None => {
                let mut bytes = vec![0; len];
                let result = self
                    .entropy
                    .as_mut()
                    .expect("driver was checked")
                    .fill(&mut bytes);
                match result {
                    Ok(()) => Outcome::Bytes(bytes),
                    Err(error) => Outcome::Error(error),
                }
            }
        };
        let outcome = self.complete(operation.clone(), outcome);
        decode_bytes(&operation, outcome)
    }

    /// Draw the seeded entropy-request failure for one eligible call, or `None`
    /// when the knob does not fire. Extreme rates are decision-free so the
    /// never-fail default perturbs no stream, mirroring [`Context::draw_dns_failure`].
    fn draw_entropy_failure(&mut self) -> Option<EffectError> {
        let fires = match self.entropy_fail_permille {
            0 => false,
            1000 => true,
            permille => (self.entropy_fault_rng.next_u64() % 1000) < u64::from(permille),
        };
        fires.then(|| {
            EffectError::new(
                ErrorCode::Interrupted,
                "injected entropy failure: request did not complete",
            )
        })
    }

    /// The end-of-run entropy fault summary, or `None` when the knob was never
    /// live. Filled entirely by the Context: entropy has no driver-side fault
    /// model of its own.
    pub fn entropy_fault_report(&self) -> Option<patina_dst_driver_api::EntropyFaultReport> {
        if self.entropy_fail_permille == 0 {
            return None;
        }
        let mut report = self.entropy_report;
        report.fail_vacuity_diagnosable = patina_dst_driver_api::vacuity_is_diagnosable(
            report.requests,
            self.entropy_fail_permille,
        );
        Some(report)
    }

    pub fn now(&mut self, clock: ClockKind) -> Result<u64, RuntimeError> {
        if self.clock.is_none() {
            return Err(EffectError::missing_driver("clock").into());
        }
        // Advance-on-spin: a guest that has done nothing but read the clock for
        // `SPIN_RESCUE_CLOCK_OPS` ops at frozen virtual time gets a recorded
        // token advance BEFORE this observation, so the value it is about to
        // read has moved. Ordered here, ahead of the `ClockNow`, so the recorded
        // stream for a rescued read is `SleepUntil` then `ClockNow`.
        self.spin_rescue()?;
        let operation = Operation::ClockNow { clock };
        if let Some((_, recorded)) = self.replay_expected(&operation)? {
            return decode_u64(&operation, recorded);
        }

        let result = self.clock.as_mut().expect("driver was checked").now(clock);
        let outcome = match result {
            Ok(nanos) => {
                let nanos = match clock {
                    ClockKind::Realtime => self.apply_epoch_jump(nanos),
                    ClockKind::Monotonic => nanos,
                };
                Outcome::U64(nanos)
            }
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.complete(operation.clone(), outcome);
        decode_u64(&operation, outcome)
    }

    /// Perturb one realtime-epoch read with a seeded signed offset in `[-hi,
    /// hi]`, saturating at 0 (no negative epochs). Draws from its own
    /// domain-separated stream ([`fault_domain::EPOCH_JUMP`]), never the clock
    /// driver's own state, so a knob-off run is unperturbed and arming the knob
    /// never correlates with any other fault plane. No cumulative walk: the
    /// result is a pure function of this one draw and the true epoch, so a jump
    /// on one read never carries into the next. The perturbed value flows
    /// through the same recorded [`Operation::ClockNow`]/[`Outcome::U64`] every
    /// epoch read already uses, so replay reproduces it without redrawing.
    fn apply_epoch_jump(&mut self, true_epoch_nanos: u64) -> u64 {
        self.clock_report.reads += 1;
        let hi = match self.epoch_jump_nanos {
            0 => return true_epoch_nanos,
            hi => hi,
        };
        // u128 throughout: `hi` is an unconstrained CLI-supplied u64, so a span
        // of `2*hi + 1` could overflow u64 for a `hi` near its max.
        let span = 2u128 * u128::from(hi) + 1;
        let draw = u128::from(self.epoch_jump_rng.next_u64()) % span;
        let offset = draw as i128 - i128::from(hi); // in [-hi, hi]
        let perturbed = i128::from(true_epoch_nanos) + offset;
        let perturbed = perturbed.clamp(0, i128::from(u64::MAX)) as u64;
        if perturbed != true_epoch_nanos {
            self.clock_report.jumps_applied += 1;
        }
        perturbed
    }

    /// The end-of-run clock (epoch-jump) fault summary, or `None` when the knob
    /// was never live. Filled entirely by the Context: every realtime-epoch read
    /// is a single-site operation, so there is no driver-side fault model of its
    /// own.
    pub fn clock_fault_report(&self) -> Option<patina_dst_driver_api::ClockFaultReport> {
        if self.epoch_jump_nanos == 0 {
            return None;
        }
        let mut report = self.clock_report;
        report.jump_vacuity_diagnosable = patina_dst_driver_api::epoch_jump_vacuity_is_diagnosable(
            report.reads,
            self.epoch_jump_nanos,
        );
        Some(report)
    }

    /// Sleep until `deadline_nanos`. Plain: latency jitter is applied by the
    /// caller through [`Context::apply_sleep_jitter`] so that the single
    /// guest-sleep entry point (which may park managed tasks rather than route
    /// through this method) jitters exactly once, while runtime-internal sleeps
    /// (the deadlock-rescue advancing to a timer) never do.
    pub fn sleep_until(
        &mut self,
        clock: ClockKind,
        deadline_nanos: u64,
    ) -> Result<(), RuntimeError> {
        if self.clock.is_none() {
            return Err(EffectError::missing_driver("clock").into());
        }
        let operation = Operation::SleepUntil {
            clock,
            deadline_nanos,
        };
        let expected = self.replay_expected(&operation)?;
        let result = self
            .clock
            .as_mut()
            .expect("driver was checked")
            .sleep_until(clock, deadline_nanos);
        let actual = match result {
            Ok(()) => Outcome::Unit,
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_unit(&operation, outcome)
    }

    /// Add the configured seeded sleep-latency jitter to an absolute sleep
    /// deadline, returning it unchanged when latency injection is off. Drawn from
    /// a domain-separated seeded stream so the inflation is deterministic per seed
    /// and reproduced on replay. A single decision-free range value consumes no
    /// draw. The embedder applies this once, at the guest-facing sleep entry,
    /// before parking a managed task or calling [`Context::sleep_until`].
    pub fn apply_sleep_jitter(&mut self, deadline_nanos: u64) -> u64 {
        let jitter = match self.sleep_jitter_nanos {
            None => return deadline_nanos,
            Some((min, max)) if min == max => min,
            Some((min, max)) => {
                let span = max - min + 1;
                min + (self.sleep_jitter_rng.next_u64() % span)
            }
        };
        deadline_nanos.saturating_add(jitter)
    }

    /// Delay one fault-eligible filesystem operation by a seeded draw from the
    /// configured `[min, max]` range, before the operation executes. Latency is
    /// the one fs fault that needs the clock, so it lives here rather than in the
    /// `FaultFs` wrapper — and here ONLY: no embedder adds a second site, or the
    /// same guest operation would be delayed twice in one family and once in the
    /// other.
    ///
    /// The decision-point law: a draw is consumed if and only if the knob is live
    /// and the range is not a single decision-free value, so a run without the
    /// knob is byte-identical and a fixed `N..N` latency perturbs no stream.
    /// Applying it before the operation means the op is slow and THEN fails when
    /// error injection also fires, and virtual time has already advanced when the
    /// I/O result lands — which is what reorders fs completions against timers.
    fn apply_fs_latency(&mut self) -> Result<(), RuntimeError> {
        let Some((min, max)) = self.fs_latency_nanos else {
            return Ok(());
        };
        self.fs_latency_eligible_ops += 1;
        let latency = if min == max {
            min
        } else {
            min + (self.fs_latency_rng.next_u64() % (max - min + 1))
        };
        if latency == 0 {
            return Ok(());
        }
        // Read the clock UNRECORDED (as the timer rescue does): the recorded
        // effect is the sleep itself, so an fs op under this knob costs one extra
        // trace op rather than two, and the driver's monotonic value is
        // maintained identically on record and replay by that same sleep.
        let now = self.current_monotonic()?;
        let deadline = now.saturating_add(latency);
        self.sleep_until(ClockKind::Monotonic, deadline)?;
        self.fs_latency_applied += 1;
        Ok(())
    }

    /// The end-of-run filesystem fault summary: the driver's own per-class
    /// counters merged with the Context's fs-latency counters. `None` when no
    /// filesystem fault class was live at all. This is what
    /// `PATINA_FS_FAULT_REPORT` prints at finalization; embedders and tests read
    /// it directly to assert a knob was non-vacuous.
    ///
    /// Eligible-op count prefers the driver's, because the driver and the Context
    /// observe the same operation stream independently: eligible traffic the
    /// driver saw that the Context never delayed is a filesystem path that
    /// bypassed the latency choke point, and the latency verdict is judged
    /// against that larger count precisely so the bypass shows up as vacuity
    /// rather than as silence.
    pub fn fs_fault_report(&self) -> Option<patina_dst_driver_api::FsFaultReport> {
        let driver = self.filesystem.as_ref().and_then(|fs| fs.fault_report());
        if driver.is_none() && self.fs_latency_nanos.is_none() {
            return None;
        }
        let mut report = driver.unwrap_or_default();
        report.eligible_ops = report.eligible_ops.max(self.fs_latency_eligible_ops);
        report.latency_applied = self.fs_latency_applied;
        report.latency_vacuity_diagnosable = self.fs_latency_nanos.is_some_and(|range| {
            patina_dst_driver_api::range_vacuity_is_diagnosable(report.eligible_ops, range)
        });
        Some(report)
    }

    pub fn sleep_for(&mut self, duration_nanos: u64) -> Result<(), RuntimeError> {
        let now = self.now(ClockKind::Monotonic)?;
        let deadline = now.checked_add(duration_nanos).ok_or_else(|| {
            EffectError::new(ErrorCode::InvalidInput, "virtual sleep deadline overflowed")
        })?;
        // Direct-API sleeps jitter here (the native embedder jitters at its own
        // sleep entry instead); either way a guest sleep is jittered exactly once.
        let deadline = self.apply_sleep_jitter(deadline);
        self.sleep_until(ClockKind::Monotonic, deadline)
    }

    pub fn fs_open(&mut self, path: &str, flags: OpenFlags) -> Result<Fd, RuntimeError> {
        if self.filesystem.is_none() {
            return Err(EffectError::missing_driver("filesystem").into());
        }
        self.apply_fs_latency()?;
        let operation = Operation::FsOpen {
            path: path.into(),
            flags,
        };
        let expected = match self.filesystem_expected(&operation)? {
            FilesystemExpected::Execute(expected) => expected,
            FilesystemExpected::Captured(outcome) => return decode_handle(&operation, outcome),
        };
        let result = self
            .filesystem
            .as_mut()
            .expect("driver was checked")
            .open(path, flags);
        let actual = match result {
            Ok(fd) => Outcome::Handle(fd),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        let decoded = decode_handle(&operation, outcome);
        self.maybe_inject_crash(CrashOp::Open)?;
        decoded
    }

    pub fn fs_read(&mut self, fd: Fd, max_len: usize) -> Result<Vec<u8>, RuntimeError> {
        if self.filesystem.is_none() {
            return Err(EffectError::missing_driver("filesystem").into());
        }
        self.apply_fs_latency()?;
        let operation = Operation::FsRead { fd, max_len };
        let expected = match self.filesystem_expected(&operation)? {
            FilesystemExpected::Execute(expected) => expected,
            FilesystemExpected::Captured(outcome) => return decode_bytes(&operation, outcome),
        };
        let result = self
            .filesystem
            .as_mut()
            .expect("driver was checked")
            .read(fd, max_len);
        let actual = match result {
            Ok(bytes) => Outcome::Bytes(bytes),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_bytes(&operation, outcome)
    }

    pub fn fs_write(&mut self, fd: Fd, bytes: &[u8]) -> Result<usize, RuntimeError> {
        if self.filesystem.is_none() {
            return Err(EffectError::missing_driver("filesystem").into());
        }
        self.apply_fs_latency()?;
        let operation = Operation::FsWrite {
            fd,
            bytes: bytes.to_vec(),
        };
        let expected = match self.filesystem_expected(&operation)? {
            FilesystemExpected::Execute(expected) => expected,
            FilesystemExpected::Captured(outcome) => return decode_usize(&operation, outcome),
        };
        let result = self
            .filesystem
            .as_mut()
            .expect("driver was checked")
            .write(fd, bytes);
        let actual = match result {
            Ok(written) => Outcome::Usize(written),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        let decoded = decode_usize(&operation, outcome);
        self.maybe_inject_crash(CrashOp::Write)?;
        decoded
    }

    /// Positional read (`pread`): read at an explicit offset without moving the
    /// file cursor. Recorded as [`Operation::FsReadAt`], distinct from a cursor
    /// read, and -- like a cursor read -- fires no crash-injection boundary.
    pub fn fs_read_at(
        &mut self,
        fd: Fd,
        offset: u64,
        max_len: usize,
    ) -> Result<Vec<u8>, RuntimeError> {
        if self.filesystem.is_none() {
            return Err(EffectError::missing_driver("filesystem").into());
        }
        self.apply_fs_latency()?;
        let operation = Operation::FsReadAt {
            fd,
            offset,
            max_len,
        };
        let expected = match self.filesystem_expected(&operation)? {
            FilesystemExpected::Execute(expected) => expected,
            FilesystemExpected::Captured(outcome) => return decode_bytes(&operation, outcome),
        };
        let result = self
            .filesystem
            .as_mut()
            .expect("driver was checked")
            .read_at(fd, offset, max_len);
        let actual = match result {
            Ok(bytes) => Outcome::Bytes(bytes),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_bytes(&operation, outcome)
    }

    /// Positional write (`pwrite`): write at an explicit offset without moving
    /// the file cursor. Recorded as [`Operation::FsWriteAt`] and counts toward
    /// the `write` crash ordinal, so `--fs-crash-at write:N` fires on a guest's
    /// positional page writes.
    pub fn fs_write_at(
        &mut self,
        fd: Fd,
        offset: u64,
        bytes: &[u8],
    ) -> Result<usize, RuntimeError> {
        if self.filesystem.is_none() {
            return Err(EffectError::missing_driver("filesystem").into());
        }
        self.apply_fs_latency()?;
        let operation = Operation::FsWriteAt {
            fd,
            offset,
            bytes: bytes.to_vec(),
        };
        let expected = match self.filesystem_expected(&operation)? {
            FilesystemExpected::Execute(expected) => expected,
            FilesystemExpected::Captured(outcome) => return decode_usize(&operation, outcome),
        };
        let result = self
            .filesystem
            .as_mut()
            .expect("driver was checked")
            .write_at(fd, offset, bytes);
        let actual = match result {
            Ok(written) => Outcome::Usize(written),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        let decoded = decode_usize(&operation, outcome);
        self.maybe_inject_crash(CrashOp::Write)?;
        decoded
    }

    pub fn fs_close(&mut self, fd: Fd) -> Result<(), RuntimeError> {
        if self.filesystem.is_none() {
            return Err(EffectError::missing_driver("filesystem").into());
        }
        let operation = Operation::FsClose { fd };
        let expected = match self.filesystem_expected(&operation)? {
            FilesystemExpected::Execute(expected) => expected,
            FilesystemExpected::Captured(outcome) => return decode_unit(&operation, outcome),
        };
        let result = self
            .filesystem
            .as_mut()
            .expect("driver was checked")
            .close(fd);
        let actual = match result {
            Ok(()) => Outcome::Unit,
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        let decoded = decode_unit(&operation, outcome);
        self.maybe_inject_crash(CrashOp::Close)?;
        decoded
    }

    pub fn fs_dup(&mut self, fd: Fd) -> Result<Fd, RuntimeError> {
        if self.filesystem.is_none() {
            return Err(EffectError::missing_driver("filesystem").into());
        }
        let operation = Operation::FsDup { fd };
        let expected = match self.filesystem_expected(&operation)? {
            FilesystemExpected::Execute(expected) => expected,
            FilesystemExpected::Captured(outcome) => return decode_handle(&operation, outcome),
        };
        let result = self
            .filesystem
            .as_mut()
            .expect("driver was checked")
            .dup(fd);
        let actual = match result {
            Ok(fd) => Outcome::Handle(fd),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_handle(&operation, outcome)
    }

    pub fn fs_seek(
        &mut self,
        fd: Fd,
        offset: i64,
        whence: SeekWhence,
    ) -> Result<u64, RuntimeError> {
        if self.filesystem.is_none() {
            return Err(EffectError::missing_driver("filesystem").into());
        }
        let operation = Operation::FsSeek { fd, offset, whence };
        let expected = match self.filesystem_expected(&operation)? {
            FilesystemExpected::Execute(expected) => expected,
            FilesystemExpected::Captured(outcome) => return decode_u64(&operation, outcome),
        };
        let result = self
            .filesystem
            .as_mut()
            .expect("driver was checked")
            .seek(fd, offset, whence);
        let actual = match result {
            Ok(position) => Outcome::U64(position),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_u64(&operation, outcome)
    }

    pub fn fs_metadata(&mut self, path: &str) -> Result<FsMetadata, RuntimeError> {
        if self.filesystem.is_none() {
            return Err(EffectError::missing_driver("filesystem").into());
        }
        self.apply_fs_latency()?;
        let operation = Operation::FsMetadata { path: path.into() };
        let expected = match self.filesystem_expected(&operation)? {
            FilesystemExpected::Execute(expected) => expected,
            FilesystemExpected::Captured(outcome) => return decode_metadata(&operation, outcome),
        };
        let result = self
            .filesystem
            .as_mut()
            .expect("driver was checked")
            .metadata(path);
        let actual = match result {
            Ok(metadata) => Outcome::Metadata(metadata),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_metadata(&operation, outcome)
    }

    pub fn fs_fd_metadata(&mut self, fd: Fd) -> Result<FsMetadata, RuntimeError> {
        if self.filesystem.is_none() {
            return Err(EffectError::missing_driver("filesystem").into());
        }
        self.apply_fs_latency()?;
        let operation = Operation::FsFdMetadata { fd };
        let expected = match self.filesystem_expected(&operation)? {
            FilesystemExpected::Execute(expected) => expected,
            FilesystemExpected::Captured(outcome) => return decode_metadata(&operation, outcome),
        };
        let result = self
            .filesystem
            .as_mut()
            .expect("driver was checked")
            .fd_metadata(fd);
        let actual = match result {
            Ok(metadata) => Outcome::Metadata(metadata),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_metadata(&operation, outcome)
    }

    pub fn fs_create_directory(&mut self, path: &str) -> Result<(), RuntimeError> {
        self.filesystem_unit(
            Operation::FsCreateDirectory { path: path.into() },
            |filesystem| filesystem.create_directory(path),
        )
    }

    pub fn fs_remove_file(&mut self, path: &str) -> Result<(), RuntimeError> {
        self.filesystem_unit(
            Operation::FsRemoveFile { path: path.into() },
            |filesystem| filesystem.remove_file(path),
        )
    }

    pub fn fs_sync(&mut self, fd: Fd) -> Result<(), RuntimeError> {
        let result =
            self.filesystem_unit(Operation::FsSync { fd }, |filesystem| filesystem.sync(fd));
        self.maybe_inject_crash(CrashOp::Sync)?;
        result
    }

    pub fn fs_set_len(&mut self, fd: Fd, len: u64) -> Result<(), RuntimeError> {
        self.filesystem_unit(Operation::FsSetLength { fd, len }, |filesystem| {
            filesystem.set_len(fd, len)
        })
    }

    pub fn fs_set_times(
        &mut self,
        fd: Fd,
        atime_nanos: Option<u64>,
        mtime_nanos: Option<u64>,
    ) -> Result<(), RuntimeError> {
        self.filesystem_unit(
            Operation::FsSetTimes {
                fd,
                atime_nanos,
                mtime_nanos,
            },
            |filesystem| filesystem.set_times(fd, atime_nanos, mtime_nanos),
        )
    }

    pub fn fs_set_times_by_path(
        &mut self,
        path: &str,
        atime_nanos: Option<u64>,
        mtime_nanos: Option<u64>,
    ) -> Result<(), RuntimeError> {
        self.filesystem_unit(
            Operation::FsSetTimesByPath {
                path: path.into(),
                atime_nanos,
                mtime_nanos,
            },
            |filesystem| filesystem.set_times_by_path(path, atime_nanos, mtime_nanos),
        )
    }

    pub fn fs_read_directory(&mut self, path: &str) -> Result<Vec<FsDirectoryEntry>, RuntimeError> {
        if self.filesystem.is_none() {
            return Err(EffectError::missing_driver("filesystem").into());
        }
        self.apply_fs_latency()?;
        let operation = Operation::FsReadDirectory { path: path.into() };
        let expected = match self.filesystem_expected(&operation)? {
            FilesystemExpected::Execute(expected) => expected,
            FilesystemExpected::Captured(outcome) => {
                return decode_directory_entries(&operation, outcome);
            }
        };
        let result = self
            .filesystem
            .as_mut()
            .expect("driver was checked")
            .read_directory(path);
        let actual = match result {
            Ok(entries) => Outcome::DirectoryEntries(entries),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_directory_entries(&operation, outcome)
    }

    pub fn fs_remove_directory(&mut self, path: &str) -> Result<(), RuntimeError> {
        self.filesystem_unit(
            Operation::FsRemoveDirectory { path: path.into() },
            |filesystem| filesystem.remove_directory(path),
        )
    }

    pub fn fs_rename(&mut self, from: &str, to: &str) -> Result<(), RuntimeError> {
        self.filesystem_unit(
            Operation::FsRename {
                from: from.into(),
                to: to.into(),
            },
            |filesystem| filesystem.rename(from, to),
        )
    }

    pub fn fs_link(&mut self, from: &str, to: &str) -> Result<(), RuntimeError> {
        self.filesystem_unit(
            Operation::FsLink {
                from: from.into(),
                to: to.into(),
            },
            |filesystem| filesystem.link(from, to),
        )
    }

    pub fn fs_symlink(&mut self, target: &str, link_path: &str) -> Result<(), RuntimeError> {
        self.filesystem_unit(
            Operation::FsSymlink {
                target: target.into(),
                link_path: link_path.into(),
            },
            |filesystem| filesystem.symlink(target, link_path),
        )
    }

    pub fn fs_read_link(&mut self, path: &str) -> Result<String, RuntimeError> {
        if self.filesystem.is_none() {
            return Err(EffectError::missing_driver("filesystem").into());
        }
        self.apply_fs_latency()?;
        let operation = Operation::FsReadLink { path: path.into() };
        let expected = match self.filesystem_expected(&operation)? {
            FilesystemExpected::Execute(expected) => expected,
            FilesystemExpected::Captured(outcome) => return decode_string(&operation, outcome),
        };
        let result = self
            .filesystem
            .as_mut()
            .expect("driver was checked")
            .read_link(path);
        let actual = match result {
            Ok(target) => Outcome::Bytes(target.into_bytes()),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_string(&operation, outcome)
    }

    /// Resolve a host name to a virtual IPv4 address, as a recorded boundary
    /// operation so a replay reproduces the resolution — including an injected
    /// failure — straight from the trace.
    ///
    /// Three resolution classes, only the last of which the fault knobs touch:
    ///
    /// - **Built-ins**, resolved locally and fault-exempt: a dotted-quad literal
    ///   (libc resolves a numeric node without consulting a resolver) and
    ///   `localhost`.
    /// - **Undefined names**, which are NXDOMAIN. That is SEMANTICS, not a
    ///   fault: it fires at rate 1.0, deterministically, with no knob set. A run
    ///   that resolves only undefined names has had no fault opportunities at
    ///   all, which is why those lookups are not counted as eligible.
    /// - **Defined names**, from the run's host table. These are the
    ///   fault-eligible resolutions: latency applies before the lookup and the
    ///   failure knob can turn one into NXDOMAIN or a transient timeout.
    pub fn dns_resolve(&mut self, name: &str) -> Result<String, RuntimeError> {
        if let Some(builtin) = builtin_dns_resolution(name) {
            return Ok(builtin);
        }
        let defined = self.dns_entries.get(name).cloned();
        if defined.is_some() {
            self.dns_report.resolutions += 1;
            self.apply_dns_latency()?;
        }
        let operation = Operation::DnsResolve { name: name.into() };
        let expected = self.replay_expected(&operation)?;
        let actual = match defined {
            None => Outcome::Error(nxdomain(name)),
            Some(address) => match self.draw_dns_failure() {
                Some(error) => {
                    self.dns_report.failures_injected += 1;
                    Outcome::Error(error)
                }
                None => Outcome::Bytes(address.into_bytes()),
            },
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_string(&operation, outcome)
    }

    /// Delay one eligible resolution by a seeded draw, mirroring
    /// [`Context::apply_fs_latency`] — same decision-point law, same single-site
    /// rule, because name resolution is the other classic reorderer (services
    /// racing on startup lookups).
    fn apply_dns_latency(&mut self) -> Result<(), RuntimeError> {
        let Some((min, max)) = self.dns_latency_nanos else {
            return Ok(());
        };
        let latency = if min == max {
            min
        } else {
            min + (self.dns_latency_rng.next_u64() % (max - min + 1))
        };
        if latency == 0 {
            return Ok(());
        }
        let now = self.current_monotonic()?;
        let deadline = now.saturating_add(latency);
        self.sleep_until(ClockKind::Monotonic, deadline)?;
        self.dns_report.latency_applied += 1;
        Ok(())
    }

    /// Draw the seeded resolution failure for one eligible lookup, or `None`
    /// when the knob does not fire. Extreme rates are decision-free so the
    /// never-fail default perturbs no stream.
    fn draw_dns_failure(&mut self) -> Option<EffectError> {
        let fires = match self.dns_fail_permille {
            0 => false,
            1000 => true,
            permille => (self.dns_fault_rng.next_u64() % 1000) < u64::from(permille),
        };
        if !fires {
            return None;
        }
        // A second draw picks the failure MODE: a vanished record, or a resolver
        // that did not answer in time. They exercise different guest code —
        // NXDOMAIN is usually terminal, a timeout is what retry discipline is
        // for — so a campaign wants both.
        if self.dns_fault_rng.next_u64() & 1 == 0 {
            Some(EffectError::new(
                ErrorCode::NotFound,
                "injected DNS failure: name does not resolve",
            ))
        } else {
            Some(EffectError::new(
                ErrorCode::Interrupted,
                "injected DNS failure: resolver timed out",
            ))
        }
    }

    /// The end-of-run DNS fault summary, or `None` when neither knob was live.
    /// Filled entirely by the Context: resolution has no driver.
    pub fn dns_fault_report(&self) -> Option<patina_dst_driver_api::DnsFaultReport> {
        if self.dns_fail_permille == 0 && self.dns_latency_nanos.is_none() {
            return None;
        }
        let mut report = self.dns_report;
        report.fail_vacuity_diagnosable = patina_dst_driver_api::vacuity_is_diagnosable(
            report.resolutions,
            self.dns_fail_permille,
        );
        report.latency_vacuity_diagnosable = self.dns_latency_nanos.is_some_and(|range| {
            patina_dst_driver_api::range_vacuity_is_diagnosable(report.resolutions, range)
        });
        Some(report)
    }

    /// The end-of-run network fault summary, or `None` when the installed
    /// network driver models no faults. Owned entirely by the driver — unlike
    /// filesystem and DNS latency, every network knob acts inside the driver —
    /// so the Context merely forwards it. This is what `PATINA_NET_FAULT_REPORT`
    /// prints at finalization; embedders and tests read it directly to assert a
    /// knob was non-vacuous.
    pub fn net_fault_report(&self) -> Option<patina_dst_driver_api::NetFaultReport> {
        self.network.as_ref().and_then(|net| net.fault_report())
    }

    pub fn fs_crash(&mut self) -> Result<(), RuntimeError> {
        self.filesystem_unit_undelayed(Operation::FsCrash, |filesystem| filesystem.crash())
    }

    /// Fire the configured filesystem crash if the just-completed boundary
    /// operation is the selected Nth occurrence. Called after each counted fs op
    /// completes; the crash is injected exactly once. Because the boundary-op
    /// sequence is identical on record and replay, the injected `FsCrash` lands
    /// at the same position and reconciles without the flag being re-supplied
    /// having any different effect (a mismatched flag fails closed like any other
    /// operation divergence).
    fn maybe_inject_crash(&mut self, op: CrashOp) -> Result<(), RuntimeError> {
        if self.crash_fired {
            return Ok(());
        }
        let Some(point) = self.crash_at else {
            return Ok(());
        };
        let count = match op {
            CrashOp::Open => {
                self.crash_counts.open += 1;
                self.crash_counts.open
            }
            CrashOp::Write => {
                self.crash_counts.write += 1;
                self.crash_counts.write
            }
            CrashOp::Sync => {
                self.crash_counts.sync += 1;
                self.crash_counts.sync
            }
            CrashOp::Close => {
                self.crash_counts.close += 1;
                self.crash_counts.close
            }
        };
        if point.op == op && count == point.ordinal {
            self.crash_fired = true;
            self.fs_crash()?;
        }
        Ok(())
    }

    pub fn task_spawn(&mut self, label: &str) -> Result<TaskId, RuntimeError> {
        if self.scheduler.is_none() {
            return Err(EffectError::missing_driver("scheduler").into());
        }
        let operation = Operation::TaskSpawn {
            label: label.into(),
        };
        let expected = self.replay_expected(&operation)?;
        let result = self
            .scheduler
            .as_mut()
            .expect("driver was checked")
            .spawn(label);
        let actual = match result {
            Ok(task) => Outcome::Task(task),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        let task = decode_task(&operation, outcome)?;
        self.scheduler_tasks.insert(task);
        self.schedule.on_spawn(task);
        Ok(task)
    }

    pub fn task_yield(&mut self, task: TaskId) -> Result<(), RuntimeError> {
        self.scheduler_unit(Operation::TaskYield { task }, |scheduler| {
            scheduler.yield_task(task)
        })?;
        // A yield leaves the task runnable; a yielded task is never parked.
        self.parked_tasks.remove(&task);
        self.schedule.on_yield(task);
        Ok(())
    }

    pub fn task_park(&mut self, task: TaskId, reason: &str) -> Result<(), RuntimeError> {
        self.scheduler_unit(
            Operation::TaskPark {
                task,
                reason: reason.into(),
            },
            |scheduler| scheduler.park(task, reason),
        )?;
        self.parked_tasks.insert(task);
        self.schedule.on_park(task);
        Ok(())
    }

    /// Park `task` with a virtual-clock deadline. The scheduler parks it exactly
    /// like [`Context::task_park`]; the runtime additionally registers a timer
    /// so the deadlock-rescue in [`Context::scheduler_next`] wakes it when
    /// virtual time reaches the deadline. `deadline_nanos` is interpreted in the
    /// `clock` domain and converted to monotonic at registration through
    /// recorded clock reads, so the registry key is stable across record and
    /// replay.
    pub fn task_park_timed(
        &mut self,
        task: TaskId,
        reason: &str,
        clock: ClockKind,
        deadline_nanos: u64,
    ) -> Result<(), RuntimeError> {
        if self.scheduler.is_none() {
            return Err(EffectError::missing_driver("scheduler").into());
        }
        // Reserve the registration sequence up front so an exhausted counter
        // fails closed before the task is parked with no way to wake it.
        let seq = self.timer_seq;
        let next_seq = seq.checked_add(1).ok_or_else(|| {
            EffectError::new(
                ErrorCode::InvalidInput,
                "virtual timer registration sequence exhausted",
            )
        })?;
        let monotonic_deadline = self.monotonic_deadline(clock, deadline_nanos)?;
        let operation = Operation::TaskParkTimed {
            task,
            reason: reason.into(),
            deadline_nanos: monotonic_deadline,
        };
        let expected = self.replay_expected(&operation)?;
        let result = self
            .scheduler
            .as_mut()
            .expect("driver was checked")
            .park(task, reason);
        let actual = match result {
            Ok(()) => Outcome::Unit,
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_unit(&operation, outcome)?;
        self.parked_tasks.insert(task);
        self.schedule.on_park(task);
        self.timer_seq = next_seq;
        let key = (monotonic_deadline, seq);
        if let Some(previous) = self.timer_by_task.insert(task, key) {
            self.timers.remove(&previous);
        }
        self.timers.insert(key, task);
        Ok(())
    }

    pub fn task_wake(&mut self, task: TaskId) -> Result<(), RuntimeError> {
        self.scheduler_unit(Operation::TaskWake { task }, |scheduler| {
            scheduler.wake(task)
        })?;
        self.parked_tasks.remove(&task);
        self.deregister_timer(task);
        Ok(())
    }

    pub fn task_complete(&mut self, task: TaskId) -> Result<(), RuntimeError> {
        self.scheduler_unit(Operation::TaskComplete { task }, |scheduler| {
            scheduler.complete(task)
        })?;
        self.scheduler_tasks.remove(&task);
        self.parked_tasks.remove(&task);
        self.deregister_timer(task);
        self.schedule.on_complete(task);
        Ok(())
    }

    /// Convert an absolute `deadline_nanos` in the `clock` domain to the
    /// monotonic domain used by the timer registry. Realtime deadlines read
    /// both clocks (recorded boundary observations) so the epoch is consistent
    /// across record and replay; monotonic deadlines pass through unchanged.
    fn monotonic_deadline(
        &mut self,
        clock: ClockKind,
        deadline_nanos: u64,
    ) -> Result<u64, RuntimeError> {
        match clock {
            ClockKind::Monotonic => Ok(deadline_nanos),
            ClockKind::Realtime => {
                let realtime = self.now(ClockKind::Realtime)?;
                let monotonic = self.now(ClockKind::Monotonic)?;
                let epoch = realtime.saturating_sub(monotonic);
                Ok(deadline_nanos.saturating_sub(epoch))
            }
        }
    }

    fn deregister_timer(&mut self, task: TaskId) {
        if let Some(key) = self.timer_by_task.remove(&task) {
            self.timers.remove(&key);
        }
    }

    /// Read the current monotonic virtual time directly from the clock driver
    /// without recording a boundary observation. The rescue path uses this to
    /// determine which timers are due after advancing the clock; the driver's
    /// monotonic value is maintained identically on record and replay by the
    /// recorded `SleepUntil`, so the result is deterministic.
    fn current_monotonic(&mut self) -> Result<u64, RuntimeError> {
        self.clock
            .as_mut()
            .ok_or_else(|| EffectError::missing_driver("clock"))?
            .now(ClockKind::Monotonic)
            .map_err(Into::into)
    }

    /// Whether `scheduler.next()` would report a deadlock: tasks exist but every
    /// one is parked. Derived from the runtime's shadow of scheduler state,
    /// which mirrors the driver op-for-op on both record and replay.
    fn scheduler_would_deadlock(&self) -> bool {
        !self.scheduler_tasks.is_empty()
            && self
                .scheduler_tasks
                .iter()
                .all(|task| self.parked_tasks.contains(task))
    }

    /// Drain the tasks woken by the most recent deadlock-rescue so an embedder
    /// (the native shim) can resolve their timed waits as timeouts. Deterministic
    /// and unrecorded: the rescue populates this identically on record/replay.
    pub fn take_rescued_timeouts(&mut self) -> Vec<TaskId> {
        std::mem::take(&mut self.rescued)
    }

    pub fn scheduler_next(&mut self) -> Result<Option<TaskId>, RuntimeError> {
        if self.scheduler.is_none() {
            return Err(EffectError::missing_driver("scheduler").into());
        }
        // Deadlock-rescue: while every task is parked but a timer pends, advance
        // virtual time to the single earliest deadline and wake every task due
        // at the new time, in ascending `(deadline, seq)` order. This runs
        // before the `SchedulerNext` boundary op is recorded/matched, so the
        // recorded stream for a rescued step is `SleepUntil`, the due `TaskWake`s,
        // then `SchedulerNext`. Because the shadow scheduler state and the timer
        // registry are maintained identically on record and replay, the rescue
        // re-executes deterministically and consumes those events in order.
        while !self.timers.is_empty() && self.scheduler_would_deadlock() {
            let (earliest_deadline, _) = *self
                .timers
                .keys()
                .next()
                .expect("timer registry is non-empty");
            self.sleep_until(ClockKind::Monotonic, earliest_deadline)?;
            let now = self.current_monotonic()?;
            let due: Vec<TaskId> = self
                .timers
                .iter()
                .take_while(|((deadline, _), _)| *deadline <= now)
                .map(|(_, task)| *task)
                .collect();
            for task in due {
                self.task_wake(task)?;
                self.rescued.push(task);
            }
        }
        let operation = Operation::SchedulerNext;
        let expected = self.replay_expected(&operation)?;
        let result = match expected.as_ref().map(|(_, outcome)| outcome) {
            Some(Outcome::OptionalTask(task)) => self
                .scheduler
                .as_mut()
                .expect("driver was checked")
                .select(*task)
                .map(|()| *task),
            _ => self.scheduler.as_mut().expect("driver was checked").next(),
        };
        let actual = match result {
            Ok(task) => Outcome::OptionalTask(task),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_optional_task(&operation, outcome)
    }

    pub fn net_bind(&mut self, address: &str) -> Result<SocketId, RuntimeError> {
        if self.network.is_none() {
            return Err(EffectError::missing_driver("network").into());
        }
        let operation = Operation::NetBind {
            address: address.into(),
        };
        let expected = self.replay_expected(&operation)?;
        let result = self
            .network
            .as_mut()
            .expect("driver was checked")
            .bind(address);
        let actual = match result {
            Ok(socket) => Outcome::Socket(socket),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_socket(&operation, outcome)
    }

    pub fn net_send(
        &mut self,
        socket: SocketId,
        to: &str,
        bytes: &[u8],
    ) -> Result<SendReport, RuntimeError> {
        if self.network.is_none() {
            return Err(EffectError::missing_driver("network").into());
        }
        let now_nanos = self.now(ClockKind::Monotonic)?;
        let operation = Operation::NetSend {
            socket,
            to: to.into(),
            bytes: bytes.to_vec(),
            now_nanos,
        };
        let expected = self.replay_expected(&operation)?;
        let result = self
            .network
            .as_mut()
            .expect("driver was checked")
            .send(socket, to, bytes, now_nanos);
        let actual = match result {
            Ok(report) => Outcome::SendReport(report),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_send_report(&operation, outcome)
    }

    pub fn net_recv(&mut self, socket: SocketId) -> Result<Option<Datagram>, RuntimeError> {
        if self.network.is_none() {
            return Err(EffectError::missing_driver("network").into());
        }
        let now_nanos = self.now(ClockKind::Monotonic)?;
        let operation = Operation::NetRecv { socket, now_nanos };
        let expected = self.replay_expected(&operation)?;
        let result = self
            .network
            .as_mut()
            .expect("driver was checked")
            .recv(socket, now_nanos);
        let actual = match result {
            Ok(datagram) => Outcome::Datagram(datagram),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_datagram(&operation, outcome)
    }

    pub fn net_next_delivery(&mut self, socket: SocketId) -> Result<Option<u64>, RuntimeError> {
        if self.network.is_none() {
            return Err(EffectError::missing_driver("network").into());
        }
        let now_nanos = self.now(ClockKind::Monotonic)?;
        let operation = Operation::NetNextDelivery { socket, now_nanos };
        let expected = self.replay_expected(&operation)?;
        let result = self
            .network
            .as_ref()
            .expect("driver was checked")
            .next_delivery(socket, now_nanos);
        let actual = match result {
            Ok(deadline) => Outcome::OptionalU64(deadline),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_optional_u64(&operation, outcome)
    }

    /// Level-triggered readiness of `socket` as a bitmask, for a `kqueue`/
    /// `kevent` readiness reactor in an embedder (the native shim): bit 0
    /// readable, bit 1 writable, bit 2 read-EOF (`EV_EOF` on read), bit 3
    /// write-EOF (`EV_EOF` on write). Deliberately UNRECORDED: readiness is a
    /// pure function of the recorded send/recv/shutdown history and the virtual
    /// clock — both reconstructed identically on replay — so a reactor may poll
    /// it every scheduling scan without emitting a boundary op, exactly as pipe
    /// readiness and mutex words carry no trace of their own. Virtual time is
    /// read through [`Self::current_monotonic`], the same unrecorded clock read
    /// the deadlock rescue uses.
    pub fn net_readiness(&mut self, socket: SocketId) -> Result<u32, RuntimeError> {
        if self.network.is_none() {
            return Err(EffectError::missing_driver("network").into());
        }
        let now_nanos = self.current_monotonic()?;
        let readiness = self
            .network
            .as_ref()
            .expect("driver was checked")
            .readiness(socket, now_nanos)?;
        let mut bits = 0u32;
        if readiness.readable {
            bits |= 1 << 0;
        }
        if readiness.writable {
            bits |= 1 << 1;
        }
        if readiness.read_eof {
            bits |= 1 << 2;
        }
        if readiness.write_eof {
            bits |= 1 << 3;
        }
        Ok(bits)
    }

    /// The current monotonic virtual time in nanoseconds, UNRECORDED. A
    /// readiness reactor (the native shim's `kqueue`/`kevent`) compares
    /// `EVFILT_TIMER` deadlines against it every scan; recording those reads
    /// would emit a `ClockNow` op per poll and diverge record from replay. Safe
    /// because virtual time only advances through recorded `SleepUntil`/rescue,
    /// so a bare read reproduces identically (see [`Self::current_monotonic`]).
    pub fn monotonic_now_unrecorded(&mut self) -> Result<u64, RuntimeError> {
        self.current_monotonic()
    }

    pub fn net_close(&mut self, socket: SocketId) -> Result<(), RuntimeError> {
        if self.network.is_none() {
            return Err(EffectError::missing_driver("network").into());
        }
        let operation = Operation::NetClose { socket };
        let expected = self.replay_expected(&operation)?;
        let result = self
            .network
            .as_mut()
            .expect("driver was checked")
            .close(socket);
        let actual = match result {
            Ok(()) => Outcome::Unit,
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_unit(&operation, outcome)
    }

    pub fn net_tcp_listen(
        &mut self,
        address: &str,
        backlog: usize,
    ) -> Result<SocketId, RuntimeError> {
        if self.network.is_none() {
            return Err(EffectError::missing_driver("network").into());
        }
        let operation = Operation::NetTcpListen {
            address: address.into(),
            backlog,
        };
        let expected = self.replay_expected(&operation)?;
        let result = self
            .network
            .as_mut()
            .expect("driver was checked")
            .tcp_listen(address, backlog);
        let actual = match result {
            Ok(socket) => Outcome::Socket(socket),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_socket(&operation, outcome)
    }

    pub fn net_tcp_accept(
        &mut self,
        listener: SocketId,
    ) -> Result<Option<TcpAccepted>, RuntimeError> {
        if self.network.is_none() {
            return Err(EffectError::missing_driver("network").into());
        }
        let now_nanos = self.now(ClockKind::Monotonic)?;
        let operation = Operation::NetTcpAccept {
            listener,
            now_nanos,
        };
        let expected = self.replay_expected(&operation)?;
        let result = self
            .network
            .as_mut()
            .expect("driver was checked")
            .tcp_accept(listener, now_nanos);
        let actual = match result {
            Ok(accepted) => Outcome::TcpAccepted(accepted),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_tcp_accepted(&operation, outcome)
    }

    pub fn net_tcp_connect(&mut self, address: &str, to: &str) -> Result<SocketId, RuntimeError> {
        if self.network.is_none() {
            return Err(EffectError::missing_driver("network").into());
        }
        let now_nanos = self.now(ClockKind::Monotonic)?;
        let operation = Operation::NetTcpConnect {
            address: address.into(),
            to: to.into(),
            now_nanos,
        };
        let expected = self.replay_expected(&operation)?;
        let result = self
            .network
            .as_mut()
            .expect("driver was checked")
            .tcp_connect(address, to, now_nanos);
        let actual = match result {
            Ok(socket) => Outcome::Socket(socket),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_socket(&operation, outcome)
    }

    pub fn net_tcp_send(&mut self, socket: SocketId, bytes: &[u8]) -> Result<usize, RuntimeError> {
        if self.network.is_none() {
            return Err(EffectError::missing_driver("network").into());
        }
        let now_nanos = self.now(ClockKind::Monotonic)?;
        let operation = Operation::NetTcpSend {
            socket,
            bytes: bytes.to_vec(),
            now_nanos,
        };
        let expected = self.replay_expected(&operation)?;
        let result = self
            .network
            .as_mut()
            .expect("driver was checked")
            .tcp_send(socket, bytes, now_nanos);
        let actual = match result {
            Ok(written) => Outcome::Usize(written),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_usize(&operation, outcome)
    }

    pub fn net_tcp_recv(
        &mut self,
        socket: SocketId,
        max_len: usize,
    ) -> Result<Option<Vec<u8>>, RuntimeError> {
        if self.network.is_none() {
            return Err(EffectError::missing_driver("network").into());
        }
        let now_nanos = self.now(ClockKind::Monotonic)?;
        let operation = Operation::NetTcpRecv {
            socket,
            max_len,
            now_nanos,
        };
        let expected = self.replay_expected(&operation)?;
        let result = self
            .network
            .as_mut()
            .expect("driver was checked")
            .tcp_recv(socket, max_len, now_nanos);
        let actual = match result {
            Ok(bytes) => Outcome::OptionalBytes(bytes),
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_optional_bytes(&operation, outcome)
    }

    pub fn net_tcp_shutdown(
        &mut self,
        socket: SocketId,
        how: ShutdownHow,
    ) -> Result<(), RuntimeError> {
        if self.network.is_none() {
            return Err(EffectError::missing_driver("network").into());
        }
        let operation = Operation::NetTcpShutdown { socket, how };
        let expected = self.replay_expected(&operation)?;
        let result = self
            .network
            .as_mut()
            .expect("driver was checked")
            .tcp_shutdown(socket, how);
        let actual = match result {
            Ok(()) => Outcome::Unit,
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_unit(&operation, outcome)
    }

    /// Convenience: create/truncate `path` and write `bytes` through the
    /// ordinary `fs_open`/`fs_write`/`fs_close` boundary operations.
    pub fn write_file(&mut self, path: &str, bytes: &[u8]) -> Result<(), RuntimeError> {
        let fd = self.fs_open(path, OpenFlags::create_truncate_write())?;
        let written = self.fs_write(fd, bytes)?;
        if written != bytes.len() {
            return Err(EffectError::new(
                ErrorCode::InvalidInput,
                format!(
                    "short virtual write to {path}: wrote {written} of {} bytes",
                    bytes.len()
                ),
            )
            .into());
        }
        self.fs_close(fd)
    }

    /// Convenience: read all of `path` through the ordinary
    /// `fs_open`/`fs_read`/`fs_close` boundary operations.
    pub fn read_file(&mut self, path: &str) -> Result<Vec<u8>, RuntimeError> {
        let fd = self.fs_open(path, OpenFlags::read_only())?;
        let mut contents = Vec::new();
        loop {
            let chunk = self.fs_read(fd, READ_CHUNK_SIZE)?;
            if chunk.is_empty() {
                break;
            }
            if contents.len().saturating_add(chunk.len()) > MAX_READ_FILE_BYTES {
                return Err(EffectError::new(
                    ErrorCode::InvalidInput,
                    format!("virtual file exceeds read_file limit of {MAX_READ_FILE_BYTES} bytes"),
                )
                .into());
            }
            contents.extend_from_slice(&chunk);
        }
        self.fs_close(fd)?;
        Ok(contents)
    }

    /// This run's structured facts document ([`patina.runfacts/v1`](FACTS_SCHEMA)):
    /// the per-plane fault accounting and the runtime-detected findings, built
    /// from the very same report structs the `PATINA_*_REPORT` stderr lines are
    /// formatted from.
    ///
    /// A plane is present exactly when its human line would have had something to
    /// say (the plane saw at least one opportunity) — absent means the feature
    /// did not fire, never "zero". Deliberately independent of
    /// [`ReportConfig`]: silencing a printed diagnostic must not blind the
    /// structured channel.
    pub fn run_facts(&self) -> serde_json::Value {
        let mut planes = serde_json::Map::new();
        if let Some(report) = self.fs_fault_report().filter(|r| r.eligible_ops > 0) {
            planes.insert("fs".into(), facts::fs_plane(&report));
        }
        if let Some(report) = self.dns_fault_report().filter(|r| r.resolutions > 0) {
            planes.insert("dns".into(), facts::dns_plane(&report));
        }
        if let Some(report) = self
            .net_fault_report()
            .filter(patina_dst_driver_api::NetFaultReport::had_opportunities)
        {
            planes.insert("net".into(), facts::net_plane(&report));
        }
        if let Some(report) = self.entropy_fault_report().filter(|r| r.requests > 0) {
            planes.insert("entropy".into(), facts::entropy_plane(&report));
        }
        if let Some(report) = self.clock_fault_report().filter(|r| r.reads > 0) {
            planes.insert("clock".into(), facts::clock_plane(&report));
        }
        if let Some(swarm) = self.swarm.as_ref() {
            planes.insert("swarm".into(), facts::swarm_plane(swarm));
        }
        let schedule = self.schedule.diagnostics();
        if schedule.had_concurrency() {
            planes.insert("schedule".into(), facts::schedule_plane(&schedule));
        }

        let mut findings = Vec::new();
        if let Some(violation) = self.liveness.violation.as_ref() {
            findings.push(facts::liveness_finding(violation));
        }
        if let Some(vtime) = self.spin.churn_vtime_nanos {
            findings.push(facts::frozen_clock_churn_finding(
                vtime,
                self.spin.rescues,
                self.spin.advanced_nanos,
                SPIN_RESCUE_CLOCK_OPS,
            ));
        }
        if !schedule.vacuous.is_empty() {
            findings.push(facts::vacuous_schedule_finding(&schedule));
        }
        if let Some(report) = self.scheduler.as_ref().and_then(|s| s.policy_report()) {
            if report.starve_vacuous > 0 {
                findings.push(facts::vacuous_starvation_finding(report.starve_vacuous));
            }
        }
        facts::document(planes, findings)
    }

    /// Write the facts document to the installed channel, at most once per run.
    /// A write failure is loud and classifiable (`PATINA_INFRA`) rather than
    /// silent — a consumer that asked for the structured channel must never read
    /// a missing document as "nothing happened".
    fn emit_facts(&mut self) {
        if self.facts_emitted || self.facts.is_none() {
            return;
        }
        self.facts_emitted = true;
        let document = self.run_facts();
        let mut bytes = match serde_json::to_vec(&document) {
            Ok(bytes) => bytes,
            Err(error) => {
                eprintln!("PATINA_INFRA run_facts serialize_failed reason={error:?}");
                return;
            }
        };
        bytes.push(b'\n');
        if let Some(output) = self.facts.as_mut() {
            if let Err(error) = output.write(&bytes) {
                eprintln!("PATINA_INFRA run_facts write_failed reason={error:?}");
            }
        }
    }

    /// Finalize the run: emit the end-of-run diagnostics (schedule, buggify,
    /// liveness, net-fault), enforce end-of-run oracles, and — in record mode —
    /// write the trace. Consumes the context; [`run`]/[`run_with`] call this
    /// automatically, on error paths too.
    pub fn finish(mut self) -> Result<(), RuntimeError> {
        // A custom operation still open at the end of the run means its `begin`
        // was never closed out — on the record pass the trace is missing an event
        // the guest logically performed, and on replay a recorded result was
        // consumed and dropped. Either way the trace no longer describes the run,
        // so say so here instead of letting it fail as an unexplained mismatch on
        // some later replay.
        if let Some(pending) = self.custom_op.take() {
            return Err(RuntimeError::CustomOp {
                detail: format!(
                    "the run ended with custom op {:?} still open: its `begin` was never closed by \
a recorded result or a replay fetch",
                    pending.label
                ),
                label: pending.label,
            });
        }
        // Any runtime diagnostic no embedder drained. The shim and the WASI host
        // drain after each SDK entry point so the lines interleave with guest
        // output; an in-process (cargo-family) guest has no embedder, and this is
        // where its verdicts reach stderr. Drained, so nothing can print twice.
        // Deliberately not gated by `ReportConfig`: a verdict is the run's
        // result, not a diagnostic, and a suppressible result is a silent hole.
        for line in self.take_pending_diagnostics() {
            eprintln!("{line}");
        }
        emit_schedule_report(self.reports, &self.schedule.diagnostics());
        // Swarm selection diagnostic. Default-on for every masked run so which
        // classes this generation actually carried is never left to inference
        // from an absent knob effect.
        if let Some(swarm) = self.swarm.as_ref() {
            emit_swarm_report(self.reports, swarm);
        }
        // Exploration-policy diagnostic (PCT / starvation). Populated from live
        // selection, so it reflects a record/seeded run; a replay reports the
        // inert default because recorded selections bypass the policy.
        if let Some(report) = self.scheduler.as_ref().and_then(|s| s.policy_report()) {
            emit_schedule_policy_report(self.reports, &report);
        }
        // Filesystem fault-injection diagnostic. Default-on so a run configured
        // with fs fault knobs that never actually perturb eligible I/O is never a
        // false green.
        if let Some(report) = self.fs_fault_report() {
            emit_fs_fault_report(self.reports, &report);
        }
        // DNS fault-injection diagnostic, on the same default-on terms.
        if let Some(report) = self.dns_fault_report() {
            emit_dns_fault_report(self.reports, &report);
        }
        // Network fault-injection diagnostic. Default-on so a run configured with
        // net fault knobs that never actually perturbed any send (the knobs being
        // silently inert on the exercised code path) is never a false green.
        if let Some(report) = self.net_fault_report() {
            emit_net_fault_report(self.reports, &report);
        }
        // Entropy fault-injection diagnostic, on the same default-on terms.
        if let Some(report) = self.entropy_fault_report() {
            emit_entropy_fault_report(self.reports, &report);
        }
        // Clock (epoch-jump) fault-injection diagnostic, on the same
        // default-on terms.
        if let Some(report) = self.clock_fault_report() {
            emit_clock_fault_report(self.reports, &report);
        }
        // Liveness-watchdog diagnostic: prove the watchdog was actually armed and
        // ran to a clean finish (it did NOT fire — a fired watchdog aborts before
        // finish()). Default-on so "watchdog enabled, run OK" is never silently
        // vacuous; suppressed by a false-y PATINA_LIVENESS_REPORT.
        if self.liveness.active {
            emit_liveness_report(self.reports, &self.liveness);
        }
        // Cooperative-SUT diagnostic + metadata. Computed before the execution is
        // consumed so the record sink can fold in the run's realized active-site
        // set and knob picks.
        let buggify_diag = self.buggify_diagnostics();
        emit_sdk_report(self.reports, &buggify_diag);
        // The structured parallel of every line emitted above, from the same
        // structs. Written before the trace so a trace-write failure still
        // leaves the run's facts on the channel.
        self.emit_facts();
        let buggify_record = self.buggify.to_record();
        // A runtime-initiated stop already wrote the recording out (a truncated
        // but valid trace, see `flush_recording`); the transport is append-only,
        // so writing a second bundle would corrupt it. Nothing is recorded after
        // such a stop, so the flushed snapshot is the complete artifact.
        if self.recording_flushed {
            return Ok(());
        }
        match self.execution {
            Execution::Seeded => Ok(()),
            Execution::Record { mut recorder, sink } => match sink {
                RecordSink::Path { path, _reservation } => {
                    recorder.set_buggify(buggify_record);
                    recorder.finish(path).map_err(Into::into)
                }
                RecordSink::Transport(mut transport) => {
                    recorder.set_buggify(buggify_record);
                    let bytes = recorder.into_bundle().to_bytes()?;
                    transport
                        .write_bundle(&bytes)
                        .map_err(|source| RuntimeError::Io {
                            action: "write trace bundle to trace transport".into(),
                            source,
                        })
                }
            },
            Execution::Replay(replayer) => replayer.finish().map_err(Into::into),
            Execution::Branch {
                session,
                _reservation,
            } => session.finish().map_err(Into::into),
        }
    }

    fn filesystem_expected(
        &mut self,
        operation: &Operation,
    ) -> Result<FilesystemExpected, RuntimeError> {
        let expected = self.replay_expected(operation)?;
        if !self.filesystem_is_capture {
            return Ok(FilesystemExpected::Execute(expected));
        }
        if let Some((_, outcome)) = expected {
            return Ok(FilesystemExpected::Captured(outcome));
        }
        if matches!(self.execution, Execution::Branch { .. }) {
            return Err(EffectError::new(
                ErrorCode::Denied,
                format!(
                    "host-capture replay reached unrecorded filesystem operation {operation:?}"
                ),
            )
            .into());
        }
        Ok(FilesystemExpected::Execute(None))
    }

    /// The unit-outcome filesystem choke point for FAULT-ELIGIBLE operations:
    /// seeded fs latency applies here, once, before the operation executes.
    fn filesystem_unit(
        &mut self,
        operation: Operation,
        invoke: impl FnOnce(&mut dyn FsDriver) -> Result<(), EffectError>,
    ) -> Result<(), RuntimeError> {
        if self.filesystem.is_none() {
            return Err(EffectError::missing_driver("filesystem").into());
        }
        self.apply_fs_latency()?;
        self.filesystem_unit_undelayed(operation, invoke)
    }

    /// The same choke point without fault latency, for the administrative
    /// operations outside the eligible set (`crash`).
    fn filesystem_unit_undelayed(
        &mut self,
        operation: Operation,
        invoke: impl FnOnce(&mut dyn FsDriver) -> Result<(), EffectError>,
    ) -> Result<(), RuntimeError> {
        if self.filesystem.is_none() {
            return Err(EffectError::missing_driver("filesystem").into());
        }
        let expected = match self.filesystem_expected(&operation)? {
            FilesystemExpected::Execute(expected) => expected,
            FilesystemExpected::Captured(outcome) => return decode_unit(&operation, outcome),
        };
        let result = invoke(
            self.filesystem
                .as_mut()
                .expect("driver was checked")
                .as_mut(),
        );
        let actual = match result {
            Ok(()) => Outcome::Unit,
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_unit(&operation, outcome)
    }

    fn scheduler_unit(
        &mut self,
        operation: Operation,
        invoke: impl FnOnce(&mut dyn SchedulerDriver) -> Result<(), EffectError>,
    ) -> Result<(), RuntimeError> {
        if self.scheduler.is_none() {
            return Err(EffectError::missing_driver("scheduler").into());
        }
        let expected = self.replay_expected(&operation)?;
        let result = invoke(
            self.scheduler
                .as_mut()
                .expect("driver was checked")
                .as_mut(),
        );
        let actual = match result {
            Ok(()) => Outcome::Unit,
            Err(error) => Outcome::Error(error),
        };
        let outcome = self.reconcile(operation.clone(), expected, actual)?;
        decode_unit(&operation, outcome)
    }

    /// Advance the liveness watchdog for one boundary op. Reads virtual time and
    /// the scheduler's policy-deferral state WITHOUT recording anything or
    /// perturbing selection; returns a [`RuntimeError::Liveness`] (after emitting
    /// the loud, classifiable `PATINA_VIOLATION` line) when a no-progress budget is
    /// exceeded. Inert unless the watchdog is active (record/seeded with a budget
    /// configured), so a plain run and every replay are unaffected.
    fn liveness_track(&mut self, operation: &Operation) -> Result<(), RuntimeError> {
        if !self.liveness.active || self.clock.is_none() {
            return Ok(());
        }
        let now = self.current_monotonic()?;
        let progress = operation_is_progress(operation);
        let deferring = self
            .scheduler
            .as_ref()
            .map(|scheduler| scheduler.liveness_deferring())
            .unwrap_or(false);
        if let Some(violation) = self.liveness.observe(now, progress, deferring) {
            // The single interface-contract line, loud and machine-parseable.
            // Emitted from the runtime so it reaches stderr regardless of the
            // driving surface, exactly like the vacuous-starvation `PATINA WARNING`.
            let marker = violation.marker_line();
            eprintln!("{marker}");
            // The interposed families abort the process on this error without
            // ever reaching `finish`, so the facts document — which carries this
            // very violation as a `runtime_findings` entry — has to be written
            // here or it is never written at all. Idempotent: `finish` will not
            // write a second one.
            self.emit_facts();
            return Err(RuntimeError::Liveness {
                kind: violation.kind,
                detail: marker,
            });
        }
        Ok(())
    }

    /// Advance the spin tracker for one boundary op, on both record and replay.
    /// Pure bookkeeping over the recorded op stream and the driver's monotonic
    /// value — it records nothing and reads no host state — so the trigger point
    /// is reproduced exactly on replay.
    ///
    /// Three cases, in the order the trigger is defined (K consecutive clock
    /// observations, zero virtual-time advance, no intervening progress op):
    /// a progress op ends the episode; a scheduling/wait op is neutral (it
    /// neither counts nor breaks the streak, so a spinning thread in a
    /// multi-task run still accumulates); a clock op counts, unless virtual time
    /// has moved since the streak began, which ends the episode instead.
    fn spin_track(&mut self, operation: &Operation) -> Result<(), RuntimeError> {
        // The rescue's own `SleepUntil`: the rescue updates the state itself.
        if self.spin.rescuing {
            return Ok(());
        }
        if operation_is_progress(operation) {
            // Genuine state advancement. Whatever this guest is doing, it is not
            // churning on the clock — drop the whole episode, escalation included.
            self.spin.end_episode(self.spin.baseline_nanos);
            return Ok(());
        }
        if !matches!(operation, Operation::ClockNow { .. }) {
            return Ok(());
        }
        if self.clock.is_none() {
            return Ok(());
        }
        let now = self.current_monotonic()?;
        if now != self.spin.baseline_nanos {
            // Virtual time moved and this rescue did not move it, so the guest
            // waited: that is the wait the rescue exists to substitute for.
            self.spin.end_episode(now);
        }
        self.spin.clock_ops += 1;
        Ok(())
    }

    /// The advance-on-spin rescue itself, invoked from [`Context::now`] before
    /// the clock observation is recorded. A no-op until the streak reaches
    /// [`SPIN_RESCUE_CLOCK_OPS`], which is why a run that never spins is
    /// byte-for-byte unchanged.
    ///
    /// It rides the same mechanism as the deadlock rescue: a recorded
    /// `SleepUntil` on the monotonic clock, replayed from the trace like any
    /// other. The advance is clamped so it never steps over a pending timer
    /// deadline — the deadlock rescue owns that boundary, and jumping past it
    /// here would deliver a sleeping task's wake later than its deadline.
    fn spin_rescue(&mut self) -> Result<(), RuntimeError> {
        if self.spin.clock_ops < SPIN_RESCUE_CLOCK_OPS {
            return Ok(());
        }
        let now = self.current_monotonic()?;
        // The streak counts reads; this is the trigger's other half — that
        // virtual time did not move across them. It is enforced HERE and not
        // only in `spin_track` because the op between the streak's last read and
        // this one may have been the guest's own sleep: `sleep_for` reads the
        // clock (counted) and only then advances it. Without this check a
        // poll-and-sleep loop would be rescued on its very next read.
        if now != self.spin.baseline_nanos {
            self.spin.end_episode(now);
            return Ok(());
        }
        // Backstop first: a loop that ignores time rather than waiting for it
        // must become a named abort, not an unbounded stream of rescues.
        if self.spin.rescues >= SPIN_CHURN_ABORT_RESCUES {
            return Err(self.frozen_clock_churn(now));
        }
        let token = self.spin.token_nanos();
        let target = now.saturating_add(token);
        // Never advance past the earliest still-future timer deadline.
        let target = match self.timers.keys().next() {
            Some((deadline, _)) if *deadline > now => target.min(*deadline),
            _ => target,
        };
        self.spin.rescuing = true;
        let result = self.sleep_until(ClockKind::Monotonic, target);
        self.spin.rescuing = false;
        result?;
        self.spin.on_rescued(target, target.saturating_sub(now));
        Ok(())
    }

    /// The frozen-clock churn abort: [`SPIN_CHURN_ABORT_RESCUES`] token advances
    /// bought no genuine progress, so the guest is in a loop that ignores the
    /// clock it is reading. Loud (a `PATINA_VIOLATION liveness` line naming the
    /// pattern and what the guest was doing) and fail-closed, in the shape the
    /// liveness watchdog established.
    fn frozen_clock_churn(&mut self, now: u64) -> RuntimeError {
        self.spin.churn_vtime_nanos = Some(now);
        let marker = self.spin.churn_marker_line(now);
        eprintln!("{marker}");
        eprintln!(
            "patina: frozen-clock churn — the guest has issued {} clock observations per rescue \
across {} advance-on-spin rescues ({} ns of virtual time) without one genuine boundary effect \
in between. It is not waiting for the clock it is reading, it is ignoring it: a busy-wait whose \
exit condition never depends on the value, or one waiting on state only another task can \
publish. Give the loop a wait the runtime can see (sleep/yield/park), or bound the run with \
--budget.",
            SPIN_RESCUE_CLOCK_OPS, self.spin.rescues, self.spin.advanced_nanos,
        );
        // The interposed families abort on this without reaching `finish`, so
        // the artifacts that explain the wedge have to be written here.
        self.emit_facts();
        self.flush_recording();
        RuntimeError::FrozenClockChurn { detail: marker }
    }

    /// Write the recording as it stands, WITHOUT consuming the context, so a
    /// runtime-initiated stop leaves a truncated-but-valid trace instead of the
    /// empty file the supervisor pre-created. The interposed families reach the
    /// stop through `std::process::abort()`, which skips the atexit-driven
    /// shutdown that is [`Context::finish`]'s only caller there — so without
    /// this, the one artifact that would explain the wedge is exactly what is
    /// lost. At most one write per run ([`Context::recording_flushed`]): the
    /// native transport is an append-only descriptor.
    ///
    /// Deliberately scoped to stops the RUNTIME initiates (step-budget
    /// exhaustion, frozen-clock churn). A guest that calls `abort()` itself is
    /// untouched, and still leaves no trace.
    fn flush_recording(&mut self) {
        if self.recording_flushed || !matches!(self.execution, Execution::Record { .. }) {
            return;
        }
        self.recording_flushed = true;
        let buggify_record = self.buggify.to_record();
        let Execution::Record { recorder, sink } = &mut self.execution else {
            unreachable!("execution was checked to be Record");
        };
        recorder.set_buggify(buggify_record);
        let bundle = recorder.to_bundle();
        let result = match sink {
            RecordSink::Path { path, .. } => bundle
                .write_atomic(&*path)
                .map_err(|error| format!("write truncated trace to {}: {error}", path.display())),
            RecordSink::Transport(transport) => bundle
                .to_bytes()
                .map_err(|error| format!("serialize truncated trace: {error}"))
                .and_then(|bytes| {
                    transport
                        .write_bundle(&bytes)
                        .map_err(|error| format!("write truncated trace to transport: {error}"))
                }),
        };
        if let Err(reason) = result {
            eprintln!("PATINA_INFRA truncated_trace write_failed reason={reason:?}");
        }
    }

    fn replay_expected(
        &mut self,
        operation: &Operation,
    ) -> Result<Option<(u64, Outcome)>, RuntimeError> {
        if self.step_budget.is_some_and(|budget| self.steps >= budget) {
            // Preserve the artifacts before the stop: the interposed families
            // abort without reaching `finish`, and a budget abort is precisely
            // the case where the partial trace is the evidence (see
            // [`Context::flush_recording`]).
            self.emit_facts();
            self.flush_recording();
            return Err(RuntimeError::StepBudgetExceeded {
                budget: self.step_budget.expect("budget was checked"),
            });
        }
        self.steps += 1;
        self.liveness_track(operation)?;
        self.spin_track(operation)?;
        match &mut self.execution {
            Execution::Replay(replayer) => {
                let sequence = replayer.consumed();
                match replayer.expect(operation) {
                    Ok(outcome) => Ok(Some((sequence, outcome))),
                    Err(error) => Err(classify_yield_divergence(&self.schedule, replayer, error)),
                }
            }
            Execution::Branch { session, .. } => {
                session.expect_prefix(operation).map_err(Into::into)
            }
            _ => Ok(None),
        }
    }

    fn complete(&mut self, operation: Operation, actual: Outcome) -> Outcome {
        match &mut self.execution {
            Execution::Record { recorder, .. } => {
                recorder.observe(operation, actual.clone());
            }
            Execution::Branch { session, .. } => {
                session.observe(operation, actual.clone());
            }
            _ => {}
        }
        actual
    }

    fn reconcile(
        &mut self,
        operation: Operation,
        expected: Option<(u64, Outcome)>,
        actual: Outcome,
    ) -> Result<Outcome, RuntimeError> {
        if let Some((sequence, recorded)) = expected {
            match &self.execution {
                Execution::Replay(replayer) => {
                    replayer.compare_outcome(sequence, &recorded, &actual)?;
                }
                Execution::Branch { session, .. } => {
                    session.compare_outcome(sequence, &recorded, &actual)?;
                }
                _ => {}
            }
            Ok(recorded)
        } else {
            Ok(self.complete(operation, actual))
        }
    }
}

/// Name a replay divergence at a custom operation for what it is.
///
/// The bare trace error says "operation N did not match"; for a custom op the
/// interesting fact is *which* part of the guest's question changed — the op
/// class (`label`) or the logical input (`key`) — because the answer the
/// recording holds is only valid for the exact question that produced it. Same
/// contract as the replayed `--env` reconcile: the trace is authoritative, and a
/// guest asking something else is refused rather than handed a stale answer.
///
/// A `key` is arbitrary guest bytes, so it is rendered as UTF-8 when it is text
/// (the SDK's serde encoding is) and as a byte count otherwise, never as lossy
/// text that would misreport what was compared.
fn classify_custom_op_divergence(label: &str, key: &[u8], error: RuntimeError) -> RuntimeError {
    let RuntimeError::Trace(error) = error else {
        return error;
    };
    let show = |bytes: &[u8]| match std::str::from_utf8(bytes) {
        Ok(text) => format!("{text:?}"),
        Err(_) => format!("<{} non-UTF-8 bytes>", bytes.len()),
    };
    let recorded = match &error {
        TraceError::OperationMismatch { expected, .. } => match expected.as_ref() {
            Operation::CustomOp {
                label: recorded_label,
                key: recorded_key,
            } => {
                if recorded_label != label {
                    format!(
                        "the recording expects custom op {recorded_label:?} at this point, not \
{label:?}"
                    )
                } else {
                    format!(
                        "the recording holds key {} for custom op {label:?}, but this run asked \
with {}",
                        show(recorded_key),
                        show(key)
                    )
                }
            }
            other => format!(
                "the recording expects a different operation entirely at this point: {other:?}"
            ),
        },
        TraceError::ReplayExhausted { .. } => {
            "the recording ended before this custom op; the run performed one the recording does \
not have"
                .to_string()
        }
        _ => return error.into(),
    };
    RuntimeError::CustomOp {
        label: label.to_string(),
        detail: format!(
            "custom op {label:?} diverged on replay: {recorded}. A recorded result answers exactly \
one question, so the trace is authoritative and a changed label or key is refused rather than \
answered from the recording. Underlying trace error: {error}"
        ),
    }
}

/// Detection for the yield-accounting failure class: a replayed scheduler-op
/// stream that stops matching the recording at a `TaskYield`. The bare trace
/// error ("trace ended before operation N") says nothing about WHY; when a
/// `TaskYield` sits on either side of the divergence, fold in per-task
/// record-vs-replay yield accounting so a guard hit count that is not a pure
/// function of the program surfaces as a specific, self-explaining failure.
/// Any other divergence passes through unchanged.
fn classify_yield_divergence(
    schedule: &ScheduleTracker,
    replayer: &Replayer,
    error: TraceError,
) -> RuntimeError {
    let yield_task = |operation: &Operation| match operation {
        Operation::TaskYield { task } => Some(*task),
        _ => None,
    };
    let (task, run_ahead) = match &error {
        // The run produced a TaskYield the recording does not have (either past
        // the end of the trace or where the recording expects a different op).
        TraceError::ReplayExhausted { actual, .. } => match yield_task(actual) {
            Some(task) => (task, true),
            None => return error.into(),
        },
        TraceError::OperationMismatch {
            expected, actual, ..
        } => match (yield_task(actual), yield_task(expected)) {
            (Some(task), _) => (task, true),
            // The recording expects a TaskYield the run did not produce.
            (None, Some(task)) => (task, false),
            (None, None) => return error.into(),
        },
        _ => return error.into(),
    };
    let executed = schedule.yields_for(task);
    let recorded = replayer.recorded_yields_for(task);
    let direction = if run_ahead {
        format!("this run reached TaskYield #{} for that task", executed + 1)
    } else {
        format!(
            "this run has taken {executed} TaskYield operations for that task and now performs a \
different operation where the recording expects another TaskYield"
        )
    };
    RuntimeError::ScheduleDivergence {
        detail: format!(
            "yield-point replay divergence on task {}: {direction}, but the recording holds \
{recorded} TaskYield operations for it ({} recorded operations in total). Yield-point guard hits \
must be a pure function of the program; a record/replay count difference means instrumented guest \
code branched differently between the two runs (canonical cause: a host-timing-dependent branch, \
e.g. racing reference-count drops against a still-exiting host thread). Underlying trace error: \
{error}",
            task.0,
            replayer.total(),
        ),
    }
}

#[derive(Debug)]
pub enum RuntimeError {
    Config(String),
    Io {
        action: String,
        source: std::io::Error,
    },
    Effect(EffectError),
    Trace(TraceError),
    StepBudgetExceeded {
        budget: u64,
    },
    /// The liveness watchdog observed a genuine no-progress wedge: virtual time
    /// advanced past the configured budget with only scheduling/wait churn and no
    /// policy-explained deferral. Loud (a `PATINA_VIOLATION` line was emitted) and
    /// classifiable. `detail` holds the emitted marker line.
    Liveness {
        kind: LivenessKind,
        detail: String,
    },
    InvalidOutcome {
        operation: Box<Operation>,
        outcome: Box<Outcome>,
    },
    RunAndFinalize {
        run: Box<RuntimeError>,
        finalize: Box<RuntimeError>,
    },
    /// A replayed scheduler-op stream diverged from the recording at a
    /// `TaskYield` (see [`classify_yield_divergence`]). `detail` carries the
    /// full record-vs-replay yield accounting and the underlying trace error.
    ScheduleDivergence {
        detail: String,
    },
    /// A custom operation was refused: a replay divergence on its label or key, a
    /// nested or unclosed `begin`, a modeled effect performed inside `perform`,
    /// or a value the SDK encoding could not carry. Every variant is fatal by
    /// design — none of them has an answer the guest could safely be handed — so
    /// the interposed embedders abort on it rather than returning an errno the
    /// guest could ignore. `label` names the op class for triage; `detail` is the
    /// full message.
    CustomOp {
        label: String,
        detail: String,
    },
    /// The frozen-clock churn backstop fired: advance-on-spin fed the guest
    /// [`SPIN_CHURN_ABORT_RESCUES`] token advances and it still made no genuine
    /// progress, so the loop ignores the clock it reads rather than waiting for
    /// it. Loud (the `PATINA_VIOLATION liveness detail=frozen-clock-churn` line
    /// was emitted, and the partial trace flushed); `detail` holds that marker.
    FrozenClockChurn {
        detail: String,
    },
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(message) => write!(f, "invalid Patina configuration: {message}"),
            Self::Io { action, source } => write!(f, "failed to {action}: {source}"),
            Self::Effect(error) => error.fmt(f),
            Self::Trace(error) => error.fmt(f),
            Self::StepBudgetExceeded { budget } => {
                write!(
                    f,
                    "Patina step budget of {budget} boundary operations was exhausted"
                )
            }
            Self::Liveness { detail, .. } => {
                write!(f, "Patina liveness watchdog violation: {detail}")
            }
            Self::InvalidOutcome { operation, outcome } => write!(
                f,
                "invalid outcome {outcome:?} for Patina operation {operation:?}"
            ),
            Self::RunAndFinalize { run, finalize } => write!(
                f,
                "Patina run failed ({run}) and trace finalization also failed ({finalize})"
            ),
            Self::ScheduleDivergence { detail } => f.write_str(detail),
            Self::CustomOp { detail, .. } => f.write_str(detail),
            Self::FrozenClockChurn { detail } => {
                write!(f, "Patina frozen-clock churn: {detail}")
            }
        }
    }
}

impl std::error::Error for RuntimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Effect(error) => Some(error),
            Self::Trace(error) => Some(error),
            Self::RunAndFinalize { run, .. } => Some(run),
            _ => None,
        }
    }
}

impl From<EffectError> for RuntimeError {
    fn from(value: EffectError) -> Self {
        Self::Effect(value)
    }
}

impl From<TraceError> for RuntimeError {
    fn from(value: TraceError) -> Self {
        Self::Trace(value)
    }
}

fn record_lock_path(trace_path: &Path) -> Result<PathBuf, RuntimeError> {
    let file_name = trace_path.file_name().ok_or_else(|| {
        RuntimeError::Config(format!(
            "trace path has no file name: {}",
            trace_path.display()
        ))
    })?;
    let mut lock_name = OsString::from(".");
    lock_name.push(file_name);
    lock_name.push(".lock");
    Ok(trace_path.with_file_name(lock_name))
}

/// Parse the documented `PATINA_TRACE_FD` variable into a raw descriptor.
///
/// Embedders that can service the descriptor (for example the native shim)
/// use this to build a [`TraceTransport`]; `RuntimeConfig::from_env` uses it
/// to select the transport execution modes.
pub fn trace_fd_from_env() -> Result<Option<i32>, RuntimeError> {
    match env::var(ENV_TRACE_FD) {
        Ok(value) => {
            let fd: i32 = value.parse().map_err(|_| {
                RuntimeError::Config(format!("{ENV_TRACE_FD} must be a non-negative descriptor"))
            })?;
            if fd < 0 {
                return Err(RuntimeError::Config(format!(
                    "{ENV_TRACE_FD} must be a non-negative descriptor"
                )));
            }
            Ok(Some(fd))
        }
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(_)) => Err(RuntimeError::Config(format!(
            "{ENV_TRACE_FD} must be valid UTF-8"
        ))),
    }
}

/// Parse a `close:1`/`write:3`/`sync:2`/`open:1` crash point. A bare op name
/// (`close`) means the first occurrence.
fn parse_crash_point(value: &str) -> Result<CrashPoint, RuntimeError> {
    let (op_text, ordinal) = match value.split_once(':') {
        Some((op_text, ordinal_text)) => {
            let ordinal = ordinal_text.parse::<u64>().map_err(|_| {
                RuntimeError::Config(format!(
                    "{ENV_FS_CRASH_AT} ordinal must be a positive integer: {value:?}"
                ))
            })?;
            (op_text, ordinal)
        }
        None => (value, 1),
    };
    if ordinal == 0 {
        return Err(RuntimeError::Config(format!(
            "{ENV_FS_CRASH_AT} ordinal is 1-based and must be at least 1: {value:?}"
        )));
    }
    let op = match op_text {
        "open" => CrashOp::Open,
        "write" => CrashOp::Write,
        "sync" => CrashOp::Sync,
        "close" => CrashOp::Close,
        other => {
            return Err(RuntimeError::Config(format!(
                "{ENV_FS_CRASH_AT} op must be open, write, sync, or close; got {other:?}"
            )));
        }
    };
    Ok(CrashPoint { op, ordinal })
}

fn parse_torn_granularity(value: &str) -> Result<TornGranularity, RuntimeError> {
    match value {
        "block" => Ok(TornGranularity::Block),
        "byte" => Ok(TornGranularity::Byte),
        other => Err(RuntimeError::Config(format!(
            "{ENV_FS_TORN_GRANULARITY} must be block or byte; got {other:?}"
        ))),
    }
}

/// Map the runtime crash op to the serializable trace-record op.
fn crash_op_to_record(op: CrashOp) -> patina_dst_trace::FaultCrashOp {
    match op {
        CrashOp::Open => patina_dst_trace::FaultCrashOp::Open,
        CrashOp::Write => patina_dst_trace::FaultCrashOp::Write,
        CrashOp::Sync => patina_dst_trace::FaultCrashOp::Sync,
        CrashOp::Close => patina_dst_trace::FaultCrashOp::Close,
    }
}

fn crash_op_from_record(op: patina_dst_trace::FaultCrashOp) -> CrashOp {
    match op {
        patina_dst_trace::FaultCrashOp::Open => CrashOp::Open,
        patina_dst_trace::FaultCrashOp::Write => CrashOp::Write,
        patina_dst_trace::FaultCrashOp::Sync => CrashOp::Sync,
        patina_dst_trace::FaultCrashOp::Close => CrashOp::Close,
    }
}

fn torn_granularity_to_record(granularity: TornGranularity) -> patina_dst_trace::TornGranularity {
    match granularity {
        TornGranularity::Block => patina_dst_trace::TornGranularity::Block,
        TornGranularity::Byte => patina_dst_trace::TornGranularity::Byte,
    }
}

fn torn_granularity_from_record(granularity: patina_dst_trace::TornGranularity) -> TornGranularity {
    match granularity {
        patina_dst_trace::TornGranularity::Block => TornGranularity::Block,
        patina_dst_trace::TornGranularity::Byte => TornGranularity::Byte,
    }
}

/// Resolve the heal-then-converge arm-time for a config: an explicit override,
/// else the buggify damage-control cutoff (when buggify is enabled), else run
/// start. Shared by the metadata record and the built watchdog so they agree.
fn resolve_heal_after(config: &RuntimeConfig) -> u64 {
    match config.liveness.heal_after_nanos {
        Some(nanos) => nanos,
        None if config.buggify.enabled => config.buggify.cutoff_nanos,
        None => 0,
    }
}

/// Serialize the run's liveness-watchdog configuration into the trace metadata.
/// Informational only — NOT a fingerprint input and NOT reconciled on replay,
/// because the watchdog is schedule-invariant. `None` when the watchdog is off.
fn watchdog_record(config: &RuntimeConfig) -> Option<patina_dst_trace::WatchdogConfigRecord> {
    if !config.liveness.is_enabled() {
        return None;
    }
    Some(patina_dst_trace::WatchdogConfigRecord {
        no_progress_budget_nanos: config.liveness.no_progress_budget_nanos,
        converge_budget_nanos: config.liveness.converge_budget_nanos,
        heal_after_nanos: config
            .liveness
            .converge_budget_nanos
            .map(|_| resolve_heal_after(config)),
    })
}

/// Serialize the run's DNS host table into the trace record, or `None` when the
/// run defined no names — an empty table records nothing, so a DNS-free run's
/// metadata is byte-identical to before.
fn dns_record(config: &RuntimeConfig) -> Option<patina_dst_trace::DnsConfigRecord> {
    (!config.dns_entries.is_empty()).then(|| patina_dst_trace::DnsConfigRecord {
        entries: config.dns_entries.clone(),
    })
}

/// Serialize the run's effective fault configuration into the trace record so a
/// fault run replays self-contained. `net_latency_nanos` is folded in because it
/// too shapes the recorded operation stream, so a flag-free replay must restore
/// it as well.
fn fault_record(config: &RuntimeConfig) -> patina_dst_trace::FaultConfigRecord {
    patina_dst_trace::FaultConfigRecord {
        crash_at: config
            .faults
            .fs
            .crash_at
            .map(|point| patina_dst_trace::CrashPointRecord {
                op: crash_op_to_record(point.op),
                ordinal: point.ordinal,
            }),
        torn_granularity: torn_granularity_to_record(config.faults.fs.torn_granularity),
        fs_error_permille: config.faults.fs.error_permille,
        fs_short_permille: config.faults.fs.short_permille,
        fs_latency_nanos: config.faults.fs.latency_nanos,
        sleep_jitter_nanos: config.faults.clock.sleep_jitter_nanos,
        net_jitter_nanos: config.faults.net.jitter_nanos,
        net_drop_permille: config.faults.net.drop_permille,
        net_latency_nanos: config.faults.net.latency_nanos,
        net_duplicate_permille: config.faults.net.duplicate_permille,
        net_connect_refuse_permille: config.faults.net.connect_refuse_permille,
        net_reset_permille: config.faults.net.reset_permille,
        net_partitions: config.faults.net.partitions.clone(),
        net_tcp_buffer_bytes: config.faults.net.tcp_buffer_bytes.map(|bytes| bytes as u64),
        dns_fail_permille: config.faults.dns.fail_permille,
        dns_latency_nanos: config.faults.dns.latency_nanos,
        entropy_fail_permille: config.faults.entropy.fail_permille,
        epoch_jump_nanos: config.faults.clock.epoch_jump_nanos,
    }
}

/// Rebuild the runtime fault configuration from a recorded trace's authoritative
/// fault metadata.
fn fault_config_from_record(record: &patina_dst_trace::FaultConfigRecord) -> FaultConfig {
    FaultConfig {
        fs: FsFaultConfig {
            crash_at: record.crash_at.map(|point| CrashPoint {
                op: crash_op_from_record(point.op),
                ordinal: point.ordinal,
            }),
            torn_granularity: torn_granularity_from_record(record.torn_granularity),
            error_permille: record.fs_error_permille,
            short_permille: record.fs_short_permille,
            latency_nanos: record.fs_latency_nanos,
        },
        net: NetFaultConfig {
            latency_nanos: record.net_latency_nanos,
            jitter_nanos: record.net_jitter_nanos,
            drop_permille: record.net_drop_permille,
            duplicate_permille: record.net_duplicate_permille,
            connect_refuse_permille: record.net_connect_refuse_permille,
            reset_permille: record.net_reset_permille,
            partitions: record.net_partitions.clone(),
            // A recorded buffer size cannot exceed this target's `usize` in any
            // realistic trace, but saturate rather than wrap if one ever does:
            // a wrapped buffer would silently change would-block behavior.
            tcp_buffer_bytes: record
                .net_tcp_buffer_bytes
                .map(|bytes| usize::try_from(bytes).unwrap_or(usize::MAX)),
        },
        clock: ClockFaultConfig {
            sleep_jitter_nanos: record.sleep_jitter_nanos,
            epoch_jump_nanos: record.epoch_jump_nanos,
        },
        dns: DnsFaultConfig {
            fail_permille: record.dns_fail_permille,
            latency_nanos: record.dns_latency_nanos,
        },
        entropy: EntropyFaultConfig {
            fail_permille: record.entropy_fail_permille,
        },
    }
}

/// Reconcile a recorded trace's authoritative fault configuration with any fault
/// knobs the operator also supplied at replay. The trace is authoritative: when
/// no knobs are supplied (the default), the stored configuration is adopted
/// verbatim so replay is byte-identical; when knobs ARE supplied they must match
/// the recording exactly or replay fails closed rather than silently running a
/// different fault schedule. A pre-metadata trace (`None`) keeps the historical
/// re-supply behavior.
fn reconcile_replay_faults(
    config: &RuntimeConfig,
    recorded: Option<&patina_dst_trace::FaultConfigRecord>,
) -> Result<Option<FaultConfig>, RuntimeError> {
    let Some(record) = recorded else {
        return Ok(None);
    };
    let stored_faults = fault_config_from_record(record);
    let supplied_any = config.faults != FaultConfig::default();
    if supplied_any && config.faults != stored_faults {
        return Err(RuntimeError::Config(
            "replay fault knobs conflict with the trace's recorded configuration; \
             the trace is authoritative, so omit the flags (or supply matching values)"
                .into(),
        ));
    }
    Ok(Some(stored_faults))
}

/// The buggify configuration recorded into a trace at build time. `active_sites`
/// and `knobs` are filled in at finalization from the run's realized picks; here
/// they start empty. `None` when buggify is disabled, so a disabled run records
/// no buggify metadata at all and is indistinguishable from an old trace.
fn buggify_record(config: &RuntimeConfig) -> Option<patina_dst_trace::BuggifyConfigRecord> {
    if !config.buggify.enabled {
        return None;
    }
    Some(patina_dst_trace::BuggifyConfigRecord {
        fire_permille: config.buggify.fire_permille,
        activation_permille: config.buggify.activation_permille,
        cutoff_nanos: config.buggify.cutoff_nanos,
        after_setup: config.buggify.after_setup,
        active_sites: Vec::new(),
        knobs: BTreeMap::new(),
    })
}

/// Refuse a run whose fingerprint claims cooperative-SUT coverage the config
/// cannot deliver. This stays exactly as strict as it was for genuine
/// incoherence; a swarm-masked generation passes because [`apply_swarm_mask`] has
/// already retracted [`FINGERPRINT_BUGGIFY`] from the fingerprint, so the run's
/// declared state is truthful rather than merely tolerated.
fn validate_buggify_fingerprint_contract(config: &RuntimeConfig) -> Result<(), RuntimeError> {
    if fingerprint_declares_component(&config.fingerprint, FINGERPRINT_BUGGIFY)
        && !config.buggify.enabled
    {
        return Err(RuntimeError::Config(
            "fingerprint declares +buggify but buggify is not enabled; refusing vacuous SDK buggify coverage"
                .into(),
        ));
    }
    Ok(())
}

fn fingerprint_declares_component(fingerprint: &str, component: &str) -> bool {
    fingerprint.split('+').skip(1).any(|part| part == component)
}

/// Rebuild a [`BuggifyConfig`] from a recorded trace's authoritative buggify
/// metadata.
fn buggify_config_from_record(record: &patina_dst_trace::BuggifyConfigRecord) -> BuggifyConfig {
    BuggifyConfig {
        enabled: true,
        fire_permille: record.fire_permille,
        activation_permille: record.activation_permille,
        cutoff_nanos: record.cutoff_nanos,
        after_setup: record.after_setup,
    }
}

/// Reconcile a recorded trace's authoritative buggify configuration with any
/// buggify knobs the operator also supplied at replay, mirroring
/// [`reconcile_replay_faults`]. The trace is authoritative: with no knobs the
/// stored config is adopted verbatim (byte-identical replay); supplied knobs
/// must match exactly or replay fails closed. A trace recorded without buggify
/// (`None`) means the operator's configuration stands — and if the operator
/// tries to enable buggify on a non-buggify trace, that is caught earlier by the
/// `+buggify` fingerprint mismatch.
fn reconcile_replay_buggify(
    config: &RuntimeConfig,
    recorded: Option<&patina_dst_trace::BuggifyConfigRecord>,
) -> Result<Option<BuggifyConfig>, RuntimeError> {
    let Some(record) = recorded else {
        return Ok(None);
    };
    let stored = buggify_config_from_record(record);
    if config.buggify.enabled && config.buggify != stored {
        return Err(RuntimeError::Config(
            "replay buggify knobs conflict with the trace's recorded configuration; \
             the trace is authoritative, so omit the flags (or supply matching values)"
                .into(),
        ));
    }
    Ok(Some(stored))
}

/// The deterministic guest environment recorded into a trace. `None` when no
/// values were supplied, so env-free runs keep compact old-shape metadata.
fn guest_env_record(config: &RuntimeConfig) -> Option<BTreeMap<String, String>> {
    if config.guest_env.is_empty() {
        None
    } else {
        Some(config.guest_env.clone())
    }
}

/// Reconcile a recorded trace's authoritative guest environment with any values
/// supplied to the replaying process. The trace is authoritative: with no values
/// supplied the stored map is adopted verbatim; if values are supplied they must
/// match exactly or replay fails closed. A pre-env trace (`None`) keeps the
/// historical re-supply behavior for embedders.
fn reconcile_replay_guest_env(
    config: &RuntimeConfig,
    recorded: Option<&BTreeMap<String, String>>,
) -> Result<Option<BTreeMap<String, String>>, RuntimeError> {
    let Some(stored) = recorded else {
        return Ok(None);
    };
    if !config.guest_env.is_empty() && &config.guest_env != stored {
        return Err(RuntimeError::Config(
            "replay --env values conflict with the trace's recorded guest environment; \
             the trace is authoritative, so omit the flags (or supply matching values)"
                .into(),
        ));
    }
    Ok(Some(stored.clone()))
}

/// The exploration scheduling policy recorded into a trace at build time. `None`
/// under the default uniform policy, so a default run records no policy metadata
/// at all and is indistinguishable from an old trace.
fn schedule_policy_record(
    config: &RuntimeConfig,
) -> Option<patina_dst_trace::SchedulePolicyRecord> {
    let policy = config.schedule_policy;
    if policy.is_default() {
        return None;
    }
    Some(patina_dst_trace::SchedulePolicyRecord {
        pct: policy.pct.map(|pct| patina_dst_trace::PctPolicyRecord {
            depth: pct.depth,
            steps: pct.steps,
        }),
        starvation: policy
            .starvation
            .map(|starve| patina_dst_trace::StarvationPolicyRecord {
                intervals: starve.intervals,
                max_len: starve.max_len,
                window: starve.window,
            }),
    })
}

/// Rebuild a [`SchedulePolicy`] from a recorded trace's authoritative policy
/// metadata.
fn schedule_policy_from_record(record: &patina_dst_trace::SchedulePolicyRecord) -> SchedulePolicy {
    SchedulePolicy {
        pct: record.pct.map(|pct| PctConfig {
            depth: pct.depth,
            steps: pct.steps,
        }),
        starvation: record.starvation.map(|starve| StarvationConfig {
            intervals: starve.intervals,
            max_len: starve.max_len,
            window: starve.window,
        }),
    }
}

/// Reconcile a recorded trace's authoritative exploration scheduling policy with
/// any policy the operator also supplied at replay, mirroring
/// [`reconcile_replay_faults`]. The trace is authoritative: with no policy
/// supplied the stored one is adopted verbatim; a conflicting supplied policy
/// fails closed. A trace recorded under the default policy (`None`) leaves the
/// operator's configuration in place — and an operator trying to *enable* a
/// policy on a default trace is caught earlier by the `+pct`/`+starve`
/// fingerprint mismatch.
fn reconcile_replay_schedule_policy(
    config: &RuntimeConfig,
    recorded: Option<&patina_dst_trace::SchedulePolicyRecord>,
) -> Result<Option<SchedulePolicy>, RuntimeError> {
    let Some(record) = recorded else {
        return Ok(None);
    };
    let stored = schedule_policy_from_record(record);
    if !config.schedule_policy.is_default() && config.schedule_policy != stored {
        return Err(RuntimeError::Config(
            "replay scheduling-policy knobs conflict with the trace's recorded configuration; \
             the trace is authoritative, so omit the flags (or supply matching values)"
                .into(),
        ));
    }
    Ok(Some(stored))
}

/// Reconcile the trace's recorded syscall-user-dispatch state against this
/// replay run's arming, and REFUSE a mismatch UP FRONT (before the first op is
/// replayed) rather than diverging mid-run. A binary with raw inline syscalls
/// can only run armed, so replaying its `sud:true` trace on a kernel without SUD
/// (or replaying a non-SUD trace on a run that armed SUD) cannot reproduce the
/// recorded op-stream — the message names the real situation. `Some(true)` means
/// armed; `None` (absent) means not armed (macOS / non-SUD kernel / standalone /
/// pre-SUD trace). SUD-DESIGN.md §7.3.
fn reconcile_replay_sud(
    config: &RuntimeConfig,
    recorded: Option<bool>,
) -> Result<(), RuntimeError> {
    let recorded_armed = recorded == Some(true);
    let now_armed = config.sud == Some(true);
    if recorded_armed && !now_armed {
        return Err(RuntimeError::Config(
            "this trace was recorded under syscall-user-dispatch (SUD), but this run did not arm \
             it — the kernel lacks SUD (arm64 needs the generic-entry kernels; x86_64 needs \
             >= 5.11), or this is macOS. Replay on a matching x86_64 SUD kernel, or rebuild the \
             guest with `--cfg rustix_use_libc` and re-record."
                .into(),
        ));
    }
    if !recorded_armed && now_armed {
        return Err(RuntimeError::Config(
            "this run armed syscall-user-dispatch (SUD), but the trace was recorded WITHOUT it — \
             the two observe raw syscalls at different boundaries, so the recorded op-stream \
             cannot be reproduced. Replay on the kernel/platform the trace was recorded on."
                .into(),
        ));
    }
    Ok(())
}

/// Reconcile the trace's recorded timestamp-counter-trap state against this
/// replay run's arming, and REFUSE a mismatch UP FRONT, for the same reason as
/// [`reconcile_replay_sud`]: an armed run answers `rdtsc`/`rdtscp` from the
/// virtual clock (recording a `ClockNow` op per read), while an unarmed run lets
/// the instruction read the HOST counter — nondeterministically, and without a
/// recorded op. Neither direction can reproduce the other's op-stream, and the
/// unarmed direction is a silent host escape, so both refuse. `Some(true)` means
/// armed; `None` (absent) means not armed (macOS / arm64 / no `PR_SET_TSC` /
/// standalone / a trace predating the trap).
fn reconcile_replay_tsc(
    config: &RuntimeConfig,
    recorded: Option<bool>,
) -> Result<(), RuntimeError> {
    let recorded_armed = recorded == Some(true);
    let now_armed = config.tsc == Some(true);
    if recorded_armed && !now_armed {
        return Err(RuntimeError::Config(
            "this trace was recorded with the timestamp-counter trap armed (rdtsc/rdtscp answered \
             from the virtual clock), but this run did not arm it — this is not x86-64 Linux, the \
             kernel lacks PR_SET_TSC, or the guest was built against a shim without the trap. \
             Replay on a matching x86-64 Linux host, or rebuild the guest without the inline \
             counter read and re-record."
                .into(),
        ));
    }
    if !recorded_armed && now_armed {
        return Err(RuntimeError::Config(
            "this run armed the timestamp-counter trap, but the trace was recorded WITHOUT it — \
             the two observe rdtsc/rdtscp at different boundaries (one records a clock read, the \
             other reads the host counter), so the recorded op-stream cannot be reproduced. \
             Replay on the platform the trace was recorded on."
                .into(),
        ));
    }
    Ok(())
}

/// Apply swarm fault-class selection to a record/seeded run's configuration: for
/// each enabled fault class, a domain-separated seed-derived coin decides whether
/// it stays active this generation. The masked configuration is what every driver
/// and the recorded `FaultConfigRecord` then consume, so replay reproduces the
/// selected subset verbatim; the returned `SwarmConfigRecord` documents the
/// candidate set and the seed's selection so the trace is self-describing. Each
/// class draws independently, so subsets vary across generations (seeds).
///
/// **Deselection is retracted from the fingerprint too.** A class whose
/// capability the supervisor declared as a compatibility-fingerprint component
/// (today only [`FINGERPRINT_BUGGIFY`]) has that component stripped from
/// `config.fingerprint` when the seed deselects it, because the fingerprint
/// describes the run that actually happened, not the run that was requested.
/// Without this the run would declare `+buggify` while carrying a disarmed
/// buggify config — exactly the incoherence
/// [`validate_buggify_fingerprint_contract`] refuses — so a legitimate
/// swarm-masked generation aborted. The trace metadata stays coherent by the same
/// rule: the recorded fault/buggify records are derived from the masked config,
/// and the swarm record names the class as a candidate that was not selected.
fn apply_swarm_mask(config: &mut RuntimeConfig) -> patina_dst_trace::SwarmConfigRecord {
    let mut draw = SwarmDraw::default();
    let seed = config.seed;

    // [`SWARM_CLASSES`] is the draw order, and what each class masks decides both
    // its candidacy and its dropper — so a knob joins swarm by naming a class in
    // the knob table, never by growing this function.
    for class in SWARM_CLASSES {
        let candidate = match class.masks {
            Masks::Knobs(knobs) => knobs.iter().any(|knob| knob.is_set(&config.faults)),
            Masks::Buggify => config.buggify.enabled,
        };
        if !candidate {
            continue;
        }
        apply_swarm_class(
            seed,
            class.token,
            class.domain,
            class.fingerprint_component,
            &mut draw,
            || match class.masks {
                Masks::Knobs(knobs) => {
                    for knob in knobs {
                        knob.clear(&mut config.faults);
                    }
                }
                // The WHOLE buggify config is reset, not just `enabled`. Clearing
                // only the flag left the requested permilles behind, so the run
                // reported `enabled=0 fire_permille=372` — a half-masked state
                // that reads like "buggify was asked for and silently ignored".
                // That line is what the original investigation drew its (wrong)
                // conclusion from. A dropped class now leaves no residue at all;
                // the fact that it was requested and dropped is carried
                // explicitly by the swarm record, the `PATINA_SWARM_REPORT` line,
                // and `swarm_deselected=1`. Resetting also makes record and
                // replay agree: the trace records no buggify config for a dropped
                // class, so a replay that rebuilt one from residue could not
                // reproduce the recording's diagnostics.
                Masks::Buggify => config.buggify = BuggifyConfig::default(),
            },
        );
    }

    for component in draw.retract {
        config.fingerprint = remove_fingerprint_component(&config.fingerprint, component);
    }

    patina_dst_trace::SwarmConfigRecord {
        candidate_classes: draw.candidates.into_iter().map(String::from).collect(),
        selected_classes: draw.selected,
    }
}

/// What one run's swarm draw accumulated: the classes it considered, the ones it
/// kept, and the fingerprint components of the ones it dropped. Collected in a
/// struct rather than three out-parameters so the per-class droppers — which each
/// borrow the config mutably — stay independent of the accumulation.
#[derive(Default)]
struct SwarmDraw {
    candidates: Vec<&'static str>,
    selected: Vec<String>,
    /// Retracted from the fingerprint only after every dropper has run, so the
    /// config borrow the droppers hold is released first.
    retract: Vec<&'static str>,
}

fn apply_swarm_class(
    seed: u64,
    token: &'static str,
    domain: &'static str,
    fingerprint_component: Option<&'static str>,
    draw: &mut SwarmDraw,
    drop: impl FnOnce(),
) {
    draw.candidates.push(token);
    let mut rng = SplitMix64::new(domain_seed(seed, domain));
    if rng.next_u64() & 1 == 1 {
        draw.selected.push(token.into());
    } else {
        drop();
        if let Some(component) = fingerprint_component {
            draw.retract.push(component);
        }
    }
}

/// Remove every `+component` occurrence from a compatibility fingerprint,
/// preserving the base label and the order of the remaining components. The
/// result is exactly the string a supervisor composes for a run that never
/// declared the component, so a flag-free replay — which reconstructs the
/// component set from the trace metadata — recomputes an identical fingerprint.
fn remove_fingerprint_component(fingerprint: &str, component: &str) -> String {
    let mut parts = fingerprint.split('+');
    let mut out = String::from(parts.next().unwrap_or_default());
    for part in parts {
        if part == component {
            continue;
        }
        out.push('+');
        out.push_str(part);
    }
    out
}

/// Emit the default-on swarm-selection diagnostic for a run that applied swarm
/// fault-class masking. One machine-readable line, in the same shape as
/// `PATINA_SDK_REPORT`: the candidate/selected/deselected counts followed by one
/// `class=<token>|<0|1>` row per candidate in table order.
///
/// This is the uniform surface for every swarm-maskable class, so a consumer can
/// tell "this generation ran without fs error injection because swarm dropped it"
/// from "fs error injection was never requested" without re-deriving the mask.
/// A `vacuous=1` run (no candidate at all) also gets a loud warning, in the same
/// shape as the fs/net inert-knob warnings: `--swarm` with nothing to select from
/// explores exactly what a run without `--swarm` explores, so a clean result must
/// not read as swarm coverage. Suppressed by a false-y [`ENV_SWARM_REPORT`].
fn emit_swarm_report(reports: ReportConfig, record: &patina_dst_trace::SwarmConfigRecord) {
    if !reports.enabled(Report::Swarm) {
        return;
    }
    eprintln!("{}", swarm_report_line(record));
    if record.is_vacuous() {
        eprintln!("{SWARM_VACUOUS_WARNING}");
    }
}

/// The `PATINA_SWARM_REPORT` line for a swarm draw. Pure, so the exact wire shape
/// the campaign classifier reads is unit-testable without capturing stderr.
fn swarm_report_line(record: &patina_dst_trace::SwarmConfigRecord) -> String {
    let selected = record.selected_classes.len();
    let mut line = format!(
        "PATINA_SWARM_REPORT candidates={} selected={} deselected={} vacuous={}",
        record.candidate_classes.len(),
        selected,
        record.candidate_classes.len() - selected,
        u8::from(record.is_vacuous()),
    );
    for class in &record.candidate_classes {
        line.push_str(&format!(
            " class={class}|{}",
            u8::from(!record.deselected(class)),
        ));
    }
    line
}

/// The inert-`--swarm` warning. A constant so the runtime and the tests that pin
/// it (and the campaign/sweep classifiers that key on its leading phrase) cannot
/// drift apart.
const SWARM_VACUOUS_WARNING: &str = "PATINA WARNING: swarm fault-class selection inert — \
--swarm was requested but NO swarm-maskable fault class was enabled, so the draw had nothing to \
keep or drop and this run explored exactly the configuration it would have explored without \
--swarm. A clean result here does NOT mean fault-class subsets were tested. Enable the fault or \
buggify knobs the swarm should choose among, or drop --swarm.";

/// Emit the default-on liveness-watchdog diagnostic at a clean finish. Proves the
/// watchdog was armed and did not fire (a fired watchdog aborts before finish), so
/// "watchdog on, run OK" is demonstrably non-vacuous. Suppressed by a false-y
/// `PATINA_LIVENESS_REPORT`.
fn emit_liveness_report(reports: ReportConfig, watchdog: &LivenessWatchdog) {
    if !reports.enabled(Report::Liveness) {
        return;
    }
    let mut line = format!(
        "PATINA_LIVENESS_REPORT armed={} fired={}",
        watchdog.arms.len(),
        u8::from(watchdog.fired),
    );
    for arm in &watchdog.arms {
        line.push_str(&format!(
            " {}=budget{}/armed{}/stall{}",
            arm.kind.as_str(),
            arm.budget_nanos,
            u8::from(arm.armed),
            arm.stall_ops,
        ));
    }
    eprintln!("{line}");
}

/// Emit the default-on schedule-exploration diagnostic to stderr for a
/// multithreaded run. Single-task runs (no concurrency to explore) stay silent.
/// The machine-readable `PATINA_SCHEDULE_REPORT` line lets a campaign tell a
/// genuinely-explored "all clean" from a vacuous one; a loud warning fires when
/// a spawned worker ran start-to-finish with zero scheduling boundaries.
fn emit_schedule_report(reports: ReportConfig, diag: &ScheduleDiagnostics) {
    if !diag.had_concurrency() {
        return;
    }
    if !reports.enabled(Report::Schedule) {
        return;
    }
    let mut line = format!(
        "PATINA_SCHEDULE_REPORT tasks_spawned={} max_concurrent={} total_boundaries={} vacuous_threads={}",
        diag.tasks_spawned,
        diag.max_concurrent,
        diag.total_boundaries,
        diag.vacuous.len(),
    );
    for stat in &diag.tasks {
        line.push_str(&format!(
            " task{}={}y+{}p/life={}/cause={}",
            stat.task.0,
            stat.yields,
            stat.parks,
            stat.lifetime,
            stat.cause.as_str()
        ));
    }
    eprintln!("{line}");
    if !diag.vacuous.is_empty() {
        let ids = diag
            .vacuous
            .iter()
            .map(|task| task.0.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        eprintln!(
            "PATINA WARNING: vacuous schedule exploration — {} spawned thread(s) (task id {ids}) ran \
to completion with no more scheduling boundaries than thread spawn/join alone incurs. Any loop in \
their body was atomics-only and thus invisible to the scheduler, so their internal interleavings \
are UNREACHABLE at any seed and a clean result here does NOT mean the concurrency was tested. \
Rebuild with `cargo patina build --yield-points` to make atomics-only race windows \
schedulable.",
            diag.vacuous.len(),
        );
    }
}

/// Reject a partition the network could not honor: an empty address on either
/// side, or a pair that partitions an address from itself. Fails closed at
/// configuration time, like [`validate_dns_entry`] — but note that a partition
/// naming addresses the run never uses is NOT rejected here (it cannot be known
/// up front); the network fault report's partition class diagnoses that at the
/// end of the run instead.
fn validate_partition(left: &str, right: &str) -> Result<(), RuntimeError> {
    if left.trim().is_empty() || right.trim().is_empty() {
        return Err(RuntimeError::Config(
            "a network partition needs two non-empty virtual addresses".into(),
        ));
    }
    if left == right {
        return Err(RuntimeError::Config(format!(
            "a network partition needs two DIFFERENT addresses; got {left:?} twice"
        )));
    }
    Ok(())
}

/// Reject a DNS entry the resolver could not honor: an empty or address-shaped
/// name, or an address that is not a dotted-quad IPv4 literal. Fails closed at
/// configuration time rather than at the first lookup, so a typo in
/// `--dns-entry` is reported before the guest runs.
fn validate_dns_entry(name: &str, address: &str) -> Result<(), RuntimeError> {
    if name.trim().is_empty() {
        return Err(RuntimeError::Config(
            "DNS entry name must not be empty".into(),
        ));
    }
    if builtin_dns_resolution(name).is_some() {
        return Err(RuntimeError::Config(format!(
            "DNS entry {name:?} shadows a built-in resolution (a numeric literal or localhost), \
             which resolves without the host table"
        )));
    }
    let octets: Vec<&str> = address.split('.').collect();
    if octets.len() != 4 || !octets.iter().all(|o| o.parse::<u8>().is_ok()) {
        return Err(RuntimeError::Config(format!(
            "DNS entry {name:?} must resolve to a dotted-quad IPv4 address; got {address:?}"
        )));
    }
    Ok(())
}

/// Reconcile a recorded trace's authoritative DNS host table with any table the
/// operator also supplied at replay, exactly like [`reconcile_replay_faults`].
fn reconcile_replay_dns(
    config: &RuntimeConfig,
    recorded: Option<&patina_dst_trace::DnsConfigRecord>,
) -> Result<Option<BTreeMap<String, String>>, RuntimeError> {
    let Some(record) = recorded else {
        return Ok(None);
    };
    if !config.dns_entries.is_empty() && config.dns_entries != record.entries {
        return Err(RuntimeError::Config(
            "the supplied DNS host table does not match the one recorded in the trace; the trace \
             is authoritative, so replay without --dns-entry"
                .into(),
        ));
    }
    Ok(Some(record.entries.clone()))
}

/// Emit the default-on DNS fault-injection diagnostic. Silent when no eligible
/// resolution happened at all — a workload that never looks up a defined name
/// gave the knobs no opportunity, which is not the same as a knob being inert.
/// Suppressed by a false-y [`ENV_DNS_FAULT_REPORT`].
fn emit_dns_fault_report(reports: ReportConfig, report: &patina_dst_driver_api::DnsFaultReport) {
    if report.resolutions == 0 {
        return;
    }
    if !reports.enabled(Report::DnsFault) {
        return;
    }
    eprintln!(
        "PATINA_DNS_FAULT_REPORT resolutions={} fail_vacuity_diagnosable={} failures_injected={} \
latency_vacuity_diagnosable={} latency_applied={} vacuous={}",
        report.resolutions,
        u8::from(report.fail_vacuity_diagnosable),
        report.failures_injected,
        u8::from(report.latency_vacuity_diagnosable),
        report.latency_applied,
        u8::from(report.is_vacuous()),
    );
    if report.is_vacuous() {
        eprintln!(
            "PATINA WARNING: DNS fault knobs inert — {} fault-eligible name resolution(s) \
occurred, enough that the configured rate should have fired an enabled DNS fault class several \
times over, yet it applied ZERO effects. A clean result here does NOT mean name-resolution \
failure was tested. Verify the guest resolves names the host table DEFINES — a lookup of an \
undefined name is NXDOMAIN by semantics and is never fault-eligible.",
            report.resolutions,
        );
    }
}

/// Emit the default-on entropy fault-injection diagnostic. Silent when the knob
/// was never live at all. Suppressed by a false-y [`ENV_ENTROPY_FAULT_REPORT`].
fn emit_entropy_fault_report(
    reports: ReportConfig,
    report: &patina_dst_driver_api::EntropyFaultReport,
) {
    if report.requests == 0 {
        return;
    }
    if !reports.enabled(Report::EntropyFault) {
        return;
    }
    eprintln!(
        "PATINA_ENTROPY_FAULT_REPORT requests={} fail_vacuity_diagnosable={} failures_injected={} vacuous={}",
        report.requests,
        u8::from(report.fail_vacuity_diagnosable),
        report.failures_injected,
        u8::from(report.is_vacuous()),
    );
    if report.is_vacuous() {
        eprintln!(
            "PATINA WARNING: entropy fault knobs inert — {} fault-eligible entropy request(s) \
occurred, enough that the configured rate should have fired several times over, yet it applied \
ZERO effects.",
            report.requests,
        );
    }
}

/// Emit the default-on clock (epoch-jump) fault-injection diagnostic. Silent
/// when the knob was never live at all. Suppressed by a false-y
/// [`ENV_CLOCK_FAULT_REPORT`].
fn emit_clock_fault_report(
    reports: ReportConfig,
    report: &patina_dst_driver_api::ClockFaultReport,
) {
    if report.reads == 0 {
        return;
    }
    if !reports.enabled(Report::ClockFault) {
        return;
    }
    eprintln!(
        "PATINA_CLOCK_FAULT_REPORT reads={} jump_vacuity_diagnosable={} jumps_applied={} vacuous={}",
        report.reads,
        u8::from(report.jump_vacuity_diagnosable),
        report.jumps_applied,
        u8::from(report.is_vacuous()),
    );
    if report.is_vacuous() {
        eprintln!(
            "PATINA WARNING: clock fault knobs inert — {} fault-eligible realtime-epoch read(s) \
occurred, enough that the configured jump range should have applied a non-zero offset several \
times over, yet it applied ZERO effects.",
            report.reads,
        );
    }
}

/// The resolution a name gets without consulting the host table or the fault
/// knobs: a dotted-quad literal resolves to itself (libc parses a numeric node
/// locally rather than asking a resolver) and `localhost` is the loopback
/// address. Everything else goes through the table.
fn builtin_dns_resolution(name: &str) -> Option<String> {
    if name == "localhost" {
        return Some("127.0.0.1".to_string());
    }
    let octets: Vec<&str> = name.split('.').collect();
    if octets.len() == 4 && octets.iter().all(|o| o.parse::<u8>().is_ok()) {
        return Some(name.to_string());
    }
    None
}

/// The failure a name outside the host table resolves to. Deterministic
/// semantics, not an injected fault.
fn nxdomain(name: &str) -> EffectError {
    EffectError::new(
        ErrorCode::NotFound,
        format!("no virtual DNS entry for {name}"),
    )
}

/// Emit the default-on filesystem fault-injection diagnostic to stderr. A driver
/// with no fault model reports `None` and stays silent, as does a live knob that
/// saw no fault-eligible traffic at all. Otherwise the machine-readable
/// `PATINA_FS_FAULT_REPORT` line lets a campaign tell a genuinely-perturbed run
/// from an inert one, and a loud warning fires when a class that was expected to
/// fire repeatedly (see `vacuity_is_diagnosable`) applied zero effects.
/// Suppressed by a false-y [`ENV_FS_FAULT_REPORT`].
fn emit_fs_fault_report(reports: ReportConfig, report: &patina_dst_driver_api::FsFaultReport) {
    if report.eligible_ops == 0 {
        return;
    }
    if !reports.enabled(Report::FsFault) {
        return;
    }
    eprintln!("{}", fs_fault_report_line(report));
    if report.is_vacuous() {
        eprintln!(
            "PATINA WARNING: filesystem fault knobs inert — {} fault-eligible filesystem op(s) \
occurred, enough that the configured rate should have fired an enabled fs fault class several \
times over, yet it applied ZERO effects. A clean result here does NOT mean every configured \
filesystem fault was tested. Verify the fs fault knobs reach the I/O path the workload uses — a \
short-I/O knob applies nothing to a guest whose reads never fill their buffer.",
            report.eligible_ops,
        );
    }
}

/// The `PATINA_FS_FAULT_REPORT` line for a filesystem fault summary. Pure, so the
/// exact wire shape the campaign classifier and the testbed scripts read is
/// unit-testable without capturing stderr.
///
/// Each rate class contributes its scalar count and, immediately after it, the
/// per-operation-kind breakdown of where those effects landed
/// (`errors_by_op=open:1,read:2`, or `-` when none did). The breakdown answers
/// the question the scalar cannot: a knob that fired plenty but only ever on
/// `open` left every post-open failure path untested, and that reads as healthy
/// coverage without it. `vacuous=` stays last, and every field stays a
/// whitespace-delimited `k=v` token, so the campaign classifier and the testbed
/// greps that read this line are unaffected.
fn fs_fault_report_line(report: &patina_dst_driver_api::FsFaultReport) -> String {
    format!(
        "PATINA_FS_FAULT_REPORT eligible_ops={} error_vacuity_diagnosable={} errors_injected={} \
errors_by_op={} short_vacuity_diagnosable={} shorts_applied={} shorts_by_op={} \
latency_vacuity_diagnosable={} latency_applied={} vacuous={}",
        report.eligible_ops,
        u8::from(report.error_vacuity_diagnosable),
        report.errors_injected,
        report.errors_by_op,
        u8::from(report.short_vacuity_diagnosable),
        report.shorts_applied,
        report.shorts_by_op,
        u8::from(report.latency_vacuity_diagnosable),
        report.latency_applied,
        u8::from(report.is_vacuous()),
    )
}

/// Emit the default-on network fault-injection diagnostic to stderr. A driver
/// with no fault model reports `None` and stays silent; a driver whose knobs
/// cannot perturb anything (`could_apply == false`) is also silent. When the
/// knobs could perturb delivery, the machine-readable `PATINA_NET_FAULT_REPORT`
/// line lets a campaign tell a genuinely-perturbed run from an inert one, and a
/// loud warning fires when fault-eligible traffic occurred yet ZERO fault
/// effects landed — the silent-inertness class (historically: the SimNet TCP
/// stream path ignoring the datagram-only fault knobs). Suppressed by a false-y
/// [`ENV_NET_FAULT_REPORT`].
fn emit_net_fault_report(reports: ReportConfig, report: &patina_dst_driver_api::NetFaultReport) {
    if !report.had_opportunities() {
        return;
    }
    if !reports.enabled(Report::NetFault) {
        return;
    }
    eprintln!(
        "PATINA_NET_FAULT_REPORT send_ops={} drop_vacuity_diagnosable={} drops_applied={} \
jitter_vacuity_diagnosable={} jitter_applied={} latency_vacuity_diagnosable={} latency_applied={} \
duplicate_vacuity_diagnosable={} duplicates_applied={} connect_ops={} \
connect_refuse_vacuity_diagnosable={} connects_refused={} stream_ops={} \
reset_vacuity_diagnosable={} resets_injected={} partition_vacuity_diagnosable={} \
partition_blocks={} vacuous={}",
        report.send_ops,
        u8::from(report.drop_vacuity_diagnosable),
        report.drops_applied,
        u8::from(report.jitter_vacuity_diagnosable),
        report.jitter_applied,
        u8::from(report.latency_vacuity_diagnosable),
        report.latency_applied,
        u8::from(report.duplicate_vacuity_diagnosable),
        report.duplicates_applied,
        report.connect_ops,
        u8::from(report.connect_refuse_vacuity_diagnosable),
        report.connects_refused,
        report.stream_ops,
        u8::from(report.reset_vacuity_diagnosable),
        report.resets_injected,
        u8::from(report.partition_vacuity_diagnosable),
        report.partition_blocks,
        u8::from(report.is_vacuous()),
    );
    if report.is_vacuous() {
        eprintln!(
            "PATINA WARNING: net fault knobs inert — fault-eligible network traffic occurred \
({} send(s), {} connect(s), {} stream op(s)), enough that an enabled net fault class should have \
fired several times over, yet that class applied ZERO effects. The configured network fault is \
SILENTLY INERT on the code path this run exercised (historically the SimNet TCP stream path \
ignored the datagram-only fault knobs), so a clean result here does NOT mean the faults were \
tested. Verify the knob reaches the path the workload uses — and, for a partition, that it names \
addresses this run actually connects between.",
            report.send_ops, report.connect_ops, report.stream_ops,
        );
    }
}

/// Emit the machine-readable `PATINA_SCHEDULE_POLICY` line for a run that used an
/// exploration scheduling policy (PCT / starvation). One line, same spirit as
/// `PATINA_SCHEDULE_REPORT`: a sweep parses it to annotate a found failure with a
/// bug-depth estimate and to detect a vacuous starvation configuration. Suppressed
/// by a false-y [`ENV_SCHEDULE_POLICY_REPORT`].
fn emit_schedule_policy_report(
    reports: ReportConfig,
    report: &patina_dst_driver_api::SchedulePolicyReport,
) {
    if !report.is_active() {
        return;
    }
    if !reports.enabled(Report::SchedulePolicy) {
        return;
    }
    eprintln!(
        "PATINA_SCHEDULE_POLICY pct={} pct_depth={} pct_change_points={} pct_change_points_hit={} \
starvation={} starve_events={} starve_vacuous={} decisions={} bug_depth={}",
        u8::from(report.pct),
        report.pct_depth,
        report.pct_change_points,
        report.pct_change_points_hit,
        u8::from(report.starvation),
        report.starve_events,
        report.starve_vacuous,
        report.decisions,
        report.bug_depth(),
    );
    if report.starve_vacuous > 0 {
        eprintln!(
            "PATINA WARNING: vacuous starvation configuration — {} scheduling decision(s) would have \
starved every runnable task and were forced to schedule anyway to preserve liveness. A starvation \
configuration that routinely starves the only runnable task is testing nothing; narrow the starved \
subset or the interval window.",
            report.starve_vacuous,
        );
    }
}

/// Emit the machine-readable `PATINA_SDK_REPORT` line for a run that registered
/// any cooperative-SUT sites (or enabled buggify). One line, same spirit as
/// `PATINA_SCHEDULE_REPORT`: a campaign parses it to accumulate per-site coverage
/// across generations. Suppressed by a false-y [`ENV_SDK_REPORT`]. Link-time
/// declarations use `declared_site=<label>|<kind>|@<file:line>` and do not imply
/// evaluation. Per-evaluated-site token is
/// `site=<label>|<kind>|a<0|1>|e<evals>|f<fires>|r<0|1>|s<0|1>|v<0|1>|k<knob|->|@<file:line>`.
fn emit_sdk_report(reports: ReportConfig, diag: &BuggifyDiagnostics) {
    if !diag.enabled && diag.sites_registered == 0 && diag.declared_sites.is_empty() {
        return;
    }
    if !reports.enabled(Report::Sdk) {
        return;
    }
    let mut line = format!(
        "PATINA_SDK_REPORT enabled={} swarm_deselected={} fire_permille={} activation_permille={} \
cutoff_nanos={} cutoff_reached={} sites_declared={} sites_registered={} sites_activated={} \
total_firings={} cutoff_suppressed={} after_setup={} setup_complete={}",
        u8::from(diag.enabled),
        u8::from(diag.swarm_deselected),
        diag.fire_permille,
        diag.activation_permille,
        diag.cutoff_nanos,
        u8::from(diag.cutoff_reached),
        diag.declared_sites.len(),
        diag.sites_registered,
        diag.sites_activated,
        diag.total_firings,
        diag.cutoff_suppressed,
        u8::from(diag.after_setup),
        u8::from(diag.setup_complete),
    );
    for site in &diag.declared_sites {
        line.push_str(&format!(
            " declared_site={}|{}|@{}",
            site.label,
            site.kind.as_str(),
            site.site,
        ));
    }
    for site in &diag.sites {
        let knob = site
            .knob
            .map(|value| value.to_string())
            .unwrap_or_else(|| "-".to_string());
        line.push_str(&format!(
            " site={}|{}|a{}|e{}|f{}|r{}|s{}|v{}|k{}|@{}",
            site.label,
            site.kind.as_str(),
            u8::from(site.active),
            site.evals,
            site.fires,
            u8::from(site.reachable),
            u8::from(site.sometimes_satisfied),
            u8::from(site.always_violated),
            knob,
            site.site,
        ));
    }
    eprintln!("{line}");
}

/// Parse a per-mille probability, requiring an integer in [0, 1000].
fn parse_permille(name: &str, value: &str) -> Result<u16, RuntimeError> {
    let permille: u16 = value
        .parse()
        .map_err(|_| RuntimeError::Config(format!("{name} must be an integer in [0, 1000]")))?;
    if permille > 1000 {
        return Err(RuntimeError::Config(format!(
            "{name} must be within [0, 1000] per-mille"
        )));
    }
    Ok(permille)
}

/// Parse an inclusive `MIN..MAX` nanosecond range, requiring `MIN <= MAX`.
fn parse_nanos_range(name: &str, value: &str) -> Result<(u64, u64), RuntimeError> {
    let (min_text, max_text) = value.split_once("..").ok_or_else(|| {
        RuntimeError::Config(format!("{name} must be a MIN..MAX range; got {value:?}"))
    })?;
    let min = min_text
        .parse::<u64>()
        .map_err(|_| RuntimeError::Config(format!("{name} MIN must be an unsigned integer")))?;
    let max = max_text
        .parse::<u64>()
        .map_err(|_| RuntimeError::Config(format!("{name} MAX must be an unsigned integer")))?;
    if min > max {
        return Err(RuntimeError::Config(format!(
            "{name} requires MIN <= MAX; got {value:?}"
        )));
    }
    Ok((min, max))
}

fn validate_guest_env(env: &BTreeMap<String, String>) -> Result<(), RuntimeError> {
    for (key, value) in env {
        validate_guest_env_entry(key, value)?;
    }
    Ok(())
}

/// The key half of the guest-environment invariant, shared by startup validation
/// and the in-run mutators so a `setenv` can never install an entry the startup
/// path would have rejected.
fn validate_guest_env_key(key: &str) -> Result<(), RuntimeError> {
    if key.is_empty() {
        return Err(RuntimeError::Config(
            "guest environment keys must not be empty".into(),
        ));
    }
    if key.contains('=') {
        return Err(RuntimeError::Config(format!(
            "guest environment key {key:?} must not contain '='"
        )));
    }
    if key.contains('\0') {
        return Err(RuntimeError::Config(format!(
            "guest environment entry {key:?} must not contain NUL bytes"
        )));
    }
    Ok(())
}

fn validate_guest_env_entry(key: &str, value: &str) -> Result<(), RuntimeError> {
    validate_guest_env_key(key)?;
    if value.contains('\0') {
        return Err(RuntimeError::Config(format!(
            "guest environment entry {key:?} must not contain NUL bytes"
        )));
    }
    Ok(())
}

fn parse_seed(value: Option<String>) -> Result<u64, RuntimeError> {
    value.map_or(Ok(0), |value| {
        value.parse().map_err(|_| {
            RuntimeError::Config(format!("{ENV_SEED} must be an unsigned 64-bit integer"))
        })
    })
}

fn required_u64(name: &str) -> Result<u64, RuntimeError> {
    required_string(name)?
        .parse()
        .map_err(|_| RuntimeError::Config(format!("{name} must be an unsigned 64-bit integer")))
}

fn required_path(name: &str) -> Result<PathBuf, RuntimeError> {
    env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| RuntimeError::Config(format!("{name} is required for this mode")))
}

fn required_string(name: &str) -> Result<String, RuntimeError> {
    env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| RuntimeError::Config(format!("{name} is required for this mode")))
}

fn invalid_outcome(operation: &Operation, outcome: Outcome) -> RuntimeError {
    RuntimeError::InvalidOutcome {
        operation: Box::new(operation.clone()),
        outcome: Box::new(outcome),
    }
}

fn decode_unit(operation: &Operation, outcome: Outcome) -> Result<(), RuntimeError> {
    match outcome {
        Outcome::Unit => Ok(()),
        Outcome::Error(error) => Err(error.into()),
        other => Err(invalid_outcome(operation, other)),
    }
}

fn decode_handle(operation: &Operation, outcome: Outcome) -> Result<Fd, RuntimeError> {
    match outcome {
        Outcome::Handle(fd) => Ok(fd),
        Outcome::Error(error) => Err(error.into()),
        other => Err(invalid_outcome(operation, other)),
    }
}

fn decode_bytes(operation: &Operation, outcome: Outcome) -> Result<Vec<u8>, RuntimeError> {
    match outcome {
        Outcome::Bytes(bytes) => Ok(bytes),
        Outcome::Error(error) => Err(error.into()),
        other => Err(invalid_outcome(operation, other)),
    }
}

fn decode_string(operation: &Operation, outcome: Outcome) -> Result<String, RuntimeError> {
    let bytes = decode_bytes(operation, outcome)?;
    String::from_utf8(bytes).map_err(|error| {
        EffectError::new(
            ErrorCode::InvalidInput,
            format!("filesystem read_link target is not UTF-8: {error}"),
        )
        .into()
    })
}

fn decode_u64(operation: &Operation, outcome: Outcome) -> Result<u64, RuntimeError> {
    match outcome {
        Outcome::U64(value) => Ok(value),
        Outcome::Error(error) => Err(error.into()),
        other => Err(invalid_outcome(operation, other)),
    }
}

fn decode_usize(operation: &Operation, outcome: Outcome) -> Result<usize, RuntimeError> {
    match outcome {
        Outcome::Usize(value) => Ok(value),
        Outcome::Error(error) => Err(error.into()),
        other => Err(invalid_outcome(operation, other)),
    }
}

fn decode_metadata(operation: &Operation, outcome: Outcome) -> Result<FsMetadata, RuntimeError> {
    match outcome {
        Outcome::Metadata(metadata) => Ok(metadata),
        Outcome::Error(error) => Err(error.into()),
        other => Err(invalid_outcome(operation, other)),
    }
}

fn decode_directory_entries(
    operation: &Operation,
    outcome: Outcome,
) -> Result<Vec<FsDirectoryEntry>, RuntimeError> {
    match outcome {
        Outcome::DirectoryEntries(entries) => Ok(entries),
        Outcome::Error(error) => Err(error.into()),
        other => Err(invalid_outcome(operation, other)),
    }
}

fn decode_task(operation: &Operation, outcome: Outcome) -> Result<TaskId, RuntimeError> {
    match outcome {
        Outcome::Task(task) => Ok(task),
        Outcome::Error(error) => Err(error.into()),
        other => Err(invalid_outcome(operation, other)),
    }
}

fn decode_optional_task(
    operation: &Operation,
    outcome: Outcome,
) -> Result<Option<TaskId>, RuntimeError> {
    match outcome {
        Outcome::OptionalTask(task) => Ok(task),
        Outcome::Error(error) => Err(error.into()),
        other => Err(invalid_outcome(operation, other)),
    }
}

fn decode_socket(operation: &Operation, outcome: Outcome) -> Result<SocketId, RuntimeError> {
    match outcome {
        Outcome::Socket(socket) => Ok(socket),
        Outcome::Error(error) => Err(error.into()),
        other => Err(invalid_outcome(operation, other)),
    }
}

fn decode_send_report(operation: &Operation, outcome: Outcome) -> Result<SendReport, RuntimeError> {
    match outcome {
        Outcome::SendReport(report) => Ok(report),
        Outcome::Error(error) => Err(error.into()),
        other => Err(invalid_outcome(operation, other)),
    }
}

fn decode_optional_u64(
    operation: &Operation,
    outcome: Outcome,
) -> Result<Option<u64>, RuntimeError> {
    match outcome {
        Outcome::OptionalU64(value) => Ok(value),
        Outcome::Error(error) => Err(error.into()),
        other => Err(invalid_outcome(operation, other)),
    }
}

fn decode_datagram(
    operation: &Operation,
    outcome: Outcome,
) -> Result<Option<Datagram>, RuntimeError> {
    match outcome {
        Outcome::Datagram(datagram) => Ok(datagram),
        Outcome::Error(error) => Err(error.into()),
        other => Err(invalid_outcome(operation, other)),
    }
}

fn decode_tcp_accepted(
    operation: &Operation,
    outcome: Outcome,
) -> Result<Option<TcpAccepted>, RuntimeError> {
    match outcome {
        Outcome::TcpAccepted(accepted) => Ok(accepted),
        Outcome::Error(error) => Err(error.into()),
        other => Err(invalid_outcome(operation, other)),
    }
}

fn decode_optional_bytes(
    operation: &Operation,
    outcome: Outcome,
) -> Result<Option<Vec<u8>>, RuntimeError> {
    match outcome {
        Outcome::OptionalBytes(bytes) => Ok(bytes),
        Outcome::Error(error) => Err(error.into()),
        other => Err(invalid_outcome(operation, other)),
    }
}

#[cfg(test)]
mod tests {
    use patina_dst_abi::{ErrorCode, SendDisposition};
    use patina_dst_fs_crash::CrashFs;
    use patina_dst_fs_host::HostCaptureFs;
    use tempfile::tempdir;

    use super::*;

    fn buggify_context(seed: u64, config: BuggifyConfig) -> Context {
        Context::from_config(RuntimeConfig::seeded(seed).with_buggify(config)).unwrap()
    }

    const BUGGIFY_ALL_ACTIVE: BuggifyConfig = BuggifyConfig {
        enabled: true,
        fire_permille: DEFAULT_BUGGIFY_FIRE_PERMILLE,
        activation_permille: 1000,
        cutoff_nanos: DEFAULT_BUGGIFY_CUTOFF_NANOS,
        after_setup: false,
    };

    /// The facts channel is sourced from the same structs the report lines are
    /// formatted from. Red before the channel existed: the document is absent
    /// while `PATINA_FS_FAULT_REPORT` reports the very same numbers.
    #[test]
    fn a_run_writes_its_fault_planes_to_the_facts_channel() {
        let directory = tempdir().unwrap();
        let facts = directory.path().join("facts.json");
        let config = RuntimeConfig::seeded(9)
            .with_facts_path(&facts)
            .apply_fault_env(|name| (name == ENV_FS_ERROR_PERMILLE).then(|| "300".to_string()))
            .unwrap();
        let mut context = Context::from_config(config).unwrap();
        for index in 0..40u32 {
            let _ = context.write_file(&format!("/entry-{index}"), b"payload");
        }
        // The structured plane and the printed line must agree, so capture the
        // report the line is built from before finalization consumes the context.
        let report = context.fs_fault_report().expect("fs faults are modeled");
        let line = fs_fault_report_line(&report);
        context.finish().unwrap();

        let bytes = std::fs::read(&facts).expect("the facts channel was written");
        let document: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(document["schema"], FACTS_SCHEMA);
        let plane = &document["fault_reports"]["fs"];
        assert_eq!(plane["eligible_ops"], report.eligible_ops);
        assert_eq!(plane["errors_injected"], report.errors_injected);
        assert_eq!(plane["vacuous"], report.is_vacuous());
        assert!(
            report.errors_injected > 0,
            "the knob must have fired for this to prove anything: {line}"
        );
        // The breakdown the scalar cannot express reaches the document too.
        assert_eq!(
            plane["errors_by_op"]
                .as_object()
                .unwrap()
                .values()
                .map(|value| value.as_u64().unwrap())
                .sum::<u64>(),
            report.errors_injected
        );
    }

    /// Same seed, same document — byte for byte. The envelope built from it
    /// inherits that determinism.
    #[test]
    fn the_facts_document_repeats_byte_identically() {
        let directory = tempdir().unwrap();
        let write_once = |name: &str| {
            let facts = directory.path().join(name);
            let config = RuntimeConfig::seeded(3)
                .with_facts_path(&facts)
                .apply_fault_env(|name| (name == ENV_FS_ERROR_PERMILLE).then(|| "250".to_string()))
                .unwrap();
            let mut context = Context::from_config(config).unwrap();
            for index in 0..20u32 {
                let _ = context.write_file(&format!("/entry-{index}"), b"payload");
            }
            context.finish().unwrap();
            std::fs::read(&facts).unwrap()
        };
        assert_eq!(write_once("first.json"), write_once("second.json"));
    }

    /// A run nobody asked facts of writes nothing and is otherwise unchanged.
    #[test]
    fn no_channel_means_no_document() {
        let mut context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
        context.write_file("/data", b"payload").unwrap();
        // The facts are still computable on demand; only the emission is opt-in.
        let facts = context.run_facts();
        assert_eq!(facts["schema"], FACTS_SCHEMA);
        context.finish().unwrap();
    }

    /// Two live destinations would silently drop one document.
    #[test]
    fn a_path_and_a_sink_together_are_refused() {
        struct Discard;
        impl FactsSink for Discard {
            fn write_facts(&mut self, _bytes: &[u8]) -> std::io::Result<()> {
                Ok(())
            }
        }
        let built = RuntimeBuilder::new(RuntimeConfig::seeded(1).with_facts_path("/facts.json"))
            .with_default_drivers()
            .with_facts_sink(Discard)
            .build();
        let Err(error) = built else {
            panic!("both destinations must be refused");
        };
        assert!(
            error.to_string().contains("use exactly one"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn buggify_activation_is_a_deterministic_function_of_seed_and_label() {
        // Same (seed, label, permille) always agrees; the realized fraction of
        // active sites tracks the activation per-mille.
        let buggify = Buggify::new(
            BuggifyConfig {
                enabled: true,
                activation_permille: 250,
                ..BuggifyConfig::default()
            },
            7,
        );
        let mut active = 0;
        for index in 0..2000 {
            let hash = label_hash(&format!("site-{index}"));
            let decision = buggify.label_is_active(hash);
            assert_eq!(
                decision,
                buggify.label_is_active(hash),
                "activation is stable"
            );
            if decision {
                active += 1;
            }
        }
        // ~25% of 2000, generous band for a 2000-sample draw.
        assert!(
            (400..=600).contains(&active),
            "activation fraction off: {active}"
        );

        // A different seed reshuffles which labels are active.
        let other = Buggify::new(
            BuggifyConfig {
                enabled: true,
                activation_permille: 250,
                ..BuggifyConfig::default()
            },
            8,
        );
        let differ = (0..2000).any(|index| {
            let hash = label_hash(&format!("site-{index}"));
            buggify.label_is_active(hash) != other.label_is_active(hash)
        });
        assert!(differ, "distinct seeds must reshuffle activation");
    }

    #[test]
    fn buggify_firing_prf_is_deterministic_and_seed_varying() {
        let fire_pattern = |seed: u64| {
            let mut context = buggify_context(seed, BUGGIFY_ALL_ACTIVE);
            (0..40)
                .map(|_| {
                    matches!(
                        context
                            .buggify_evaluate("commit-early-return", "f.rs:1", None)
                            .unwrap(),
                        SiteOutcome::Fire
                    )
                })
                .collect::<Vec<_>>()
        };
        // Byte-identical across two fresh contexts at the same seed.
        assert_eq!(fire_pattern(5), fire_pattern(5));
        // Some firings occurred (fire_permille = 250 over 40 evals).
        assert!(
            fire_pattern(5).iter().any(|fired| *fired),
            "no firing at seed 5"
        );
        // A different seed yields a different firing pattern.
        assert_ne!(fire_pattern(5), fire_pattern(6));
    }

    #[test]
    fn buggify_duplicate_label_is_detected() {
        let mut context = buggify_context(1, BUGGIFY_ALL_ACTIVE);
        // Same label, same call site: fine (re-evaluation).
        assert_ne!(
            context.buggify_evaluate("dup", "a.rs:1", None).unwrap(),
            SiteOutcome::DuplicateLabel
        );
        assert_ne!(
            context.buggify_evaluate("dup", "a.rs:1", None).unwrap(),
            SiteOutcome::DuplicateLabel
        );
        // Same label at a DIFFERENT call site: fatal duplicate.
        assert_eq!(
            context.buggify_evaluate("dup", "b.rs:9", None).unwrap(),
            SiteOutcome::DuplicateLabel
        );
        // A collision across macro kinds is caught too.
        assert_eq!(
            context.always_check("dup", "c.rs:3", true).unwrap(),
            SiteOutcome::DuplicateLabel
        );
    }

    #[test]
    fn static_site_declarations_do_not_register_or_record_decisions() {
        let mut context = buggify_context(3, BuggifyConfig::default());
        context
            .declare_static_site("never", "src/main.rs:9", BuggifyKind::Reachable)
            .unwrap();
        let diag = context.buggify_diagnostics();
        assert!(!diag.enabled);
        assert_eq!(diag.sites_registered, 0);
        assert_eq!(diag.declared_sites.len(), 1);
        assert_eq!(diag.declared_sites[0].label, "never");
        assert_eq!(diag.declared_sites[0].kind, BuggifyKind::Reachable);
        assert_eq!(context.buggify.to_record(), None);
    }

    #[test]
    fn static_site_declaration_conflict_is_a_duplicate_label_not_a_config_error() {
        let mut context = buggify_context(3, BuggifyConfig::default());
        assert_eq!(
            context
                .declare_static_site("dup", "src/main.rs:3", BuggifyKind::Fault)
                .unwrap(),
            SiteOutcome::Ok
        );
        // Re-declaring the identical site (a second link unit, same literal) is
        // idempotent, not a duplicate.
        assert_eq!(
            context
                .declare_static_site("dup", "src/main.rs:3", BuggifyKind::Fault)
                .unwrap(),
            SiteOutcome::Ok
        );
        assert_eq!(
            context
                .declare_static_site("dup", "src/main.rs:4", BuggifyKind::Fault)
                .unwrap(),
            SiteOutcome::DuplicateLabel
        );
        assert_eq!(
            context
                .declare_static_site("dup", "src/main.rs:3", BuggifyKind::Sometimes)
                .unwrap(),
            SiteOutcome::DuplicateLabel
        );
        // Malformed declarations stay hard errors, distinct from a duplicate.
        assert!(
            context
                .declare_static_site("empty-site", "", BuggifyKind::Reachable)
                .is_err()
        );
        assert_eq!(context.buggify_diagnostics().declared_sites.len(), 1);
    }

    #[test]
    fn buggify_disabled_is_inert_and_records_nothing() {
        let mut context = buggify_context(3, BuggifyConfig::default());
        for _ in 0..100 {
            assert_eq!(
                context.buggify_evaluate("never", "x.rs:1", None).unwrap(),
                SiteOutcome::Ok
            );
        }
        // always! still fires its invariant even with buggify disabled.
        assert_eq!(
            context.always_check("inv", "x.rs:2", false).unwrap(),
            SiteOutcome::AlwaysViolation
        );
        let diag = context.buggify_diagnostics();
        assert!(!diag.enabled);
        assert_eq!(diag.total_firings, 0);
        assert_eq!(context.buggify.to_record(), None);
    }

    #[test]
    fn buggify_fingerprint_requires_enabled_config() {
        // Class-level pairing for SDK buggify value-form point pins: a native
        // `+buggify` compatibility fingerprint without an armed SDK config is a
        // vacuous coverage claim and must fail before any trace can be recorded.
        let directory = tempfile::tempdir().unwrap();
        let trace = directory.path().join("vacuous-buggify.patina");
        let error = match Context::from_config(RuntimeConfig::record(7, &trace, "fp+buggify")) {
            Ok(_) => panic!("+buggify fingerprint without buggify config must fail"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("fingerprint declares +buggify but buggify is not enabled"),
            "{error}"
        );
    }

    #[test]
    fn buggify_knob_is_deterministic_and_in_range() {
        let mut a = buggify_context(9, BUGGIFY_ALL_ACTIVE);
        let mut b = buggify_context(9, BUGGIFY_ALL_ACTIVE);
        let va = a
            .buggify_knob("batch", "k.rs:1", 10, 1, 100)
            .unwrap()
            .unwrap();
        let vb = b
            .buggify_knob("batch", "k.rs:1", 10, 1, 100)
            .unwrap()
            .unwrap();
        assert_eq!(va, vb, "knob is deterministic per seed+label");
        assert!((1..=100).contains(&va), "knob out of range: {va}");
        // Disabled / inactive returns the clamped default.
        let mut off = buggify_context(9, BuggifyConfig::default());
        assert_eq!(
            off.buggify_knob("batch", "k.rs:1", 10, 1, 100)
                .unwrap()
                .unwrap(),
            10
        );
    }

    #[test]
    fn buggify_cutoff_suppresses_firing_after_the_window() {
        let mut context = buggify_context(
            5,
            BuggifyConfig {
                enabled: true,
                fire_permille: 1000,
                activation_permille: 1000,
                cutoff_nanos: 1_000,
                after_setup: false,
            },
        );
        // Before the cutoff (virtual time 0) an always-fire site fires.
        assert_eq!(
            context.buggify_evaluate("c", "c.rs:1", None).unwrap(),
            SiteOutcome::Fire
        );
        // Advance virtual time past the cutoff, then firing is suppressed.
        context.sleep_for(2_000).unwrap();
        assert_eq!(
            context.buggify_evaluate("c", "c.rs:1", None).unwrap(),
            SiteOutcome::Ok
        );
        assert!(context.buggify_diagnostics().cutoff_suppressed >= 1);
    }

    #[test]
    fn buggify_after_setup_gates_firing_and_flags_never_called() {
        let config = BuggifyConfig {
            enabled: true,
            fire_permille: 1000,
            activation_permille: 1000,
            cutoff_nanos: DEFAULT_BUGGIFY_CUTOFF_NANOS,
            after_setup: true,
        };
        // Before setup_complete, an always-fire site stays inert.
        let mut context = buggify_context(2, config);
        assert_eq!(
            context.buggify_evaluate("g", "g.rs:1", None).unwrap(),
            SiteOutcome::Ok,
            "site must be inert before setup_complete"
        );
        // The site is still marked reachable (coverage) even while gated.
        assert!(
            context
                .buggify_diagnostics()
                .sites
                .iter()
                .any(|s| s.reachable && s.site == "g.rs:1")
        );
        // A run that never reaches setup_complete is a declared-but-never-called
        // violation.
        assert!(context.buggify_setup_violation());
        // After setup_complete, firing arms.
        context.lifecycle_setup_complete();
        assert_eq!(
            context.buggify_evaluate("g", "g.rs:1", None).unwrap(),
            SiteOutcome::Fire
        );
        assert!(!context.buggify_setup_violation());
    }

    #[test]
    fn buggify_rng_is_seed_deterministic() {
        let mut a = buggify_context(11, BuggifyConfig::default());
        let mut b = buggify_context(11, BuggifyConfig::default());
        let seq_a: Vec<u64> = (0..8).map(|_| a.buggify_rng()).collect();
        let seq_b: Vec<u64> = (0..8).map(|_| b.buggify_rng()).collect();
        assert_eq!(seq_a, seq_b);
        let mut c = buggify_context(12, BuggifyConfig::default());
        let seq_c: Vec<u64> = (0..8).map(|_| c.buggify_rng()).collect();
        assert_ne!(seq_a, seq_c);
    }

    #[test]
    fn verdicts_are_recorded_queued_and_drained_once() {
        let mut context = buggify_context(11, BuggifyConfig::default());
        let first = context
            .verdict(VerdictKind::Pass, "queue drained", "")
            .unwrap();
        let second = context
            .verdict(VerdictKind::AbortIntent, "checksum", "{\"page\":7}")
            .unwrap();
        assert_eq!((first.seq, second.seq), (0, 1));
        assert_eq!(context.verdicts().len(), 2);
        // The queued lines are exactly the records, and draining is a move: a
        // second drain yields nothing, so no embedder can double-print them.
        let lines = context.take_pending_diagnostics();
        assert_eq!(
            lines,
            vec![first.marker_line(), second.marker_line()],
            "queued diagnostics must be the verdict marker lines in call order"
        );
        assert!(context.take_pending_diagnostics().is_empty());
        assert_eq!(
            lines[0],
            "PATINA_VERDICT seq=0 kind=pass label=queue\\sdrained detail="
        );
        // The reported set survives the drain: draining is a print queue, not the
        // record of what happened.
        assert_eq!(context.verdicts().len(), 2);
    }

    #[test]
    fn always_violation_lowers_to_a_violation_verdict() {
        let mut context = buggify_context(5, BuggifyConfig::default());
        assert_eq!(
            context.always_check("inv", "src/main.rs:9", true).unwrap(),
            SiteOutcome::Ok
        );
        assert!(
            context.verdicts().is_empty(),
            "a satisfied always! must report nothing"
        );
        assert_eq!(
            context.always_check("inv", "src/main.rs:9", false).unwrap(),
            SiteOutcome::AlwaysViolation
        );
        let verdict = context.verdicts().last().expect("violation verdict");
        assert_eq!(verdict.kind, VerdictKind::Violation);
        assert_eq!(verdict.label, "inv");
        assert_eq!(verdict.detail, "src/main.rs:9");
    }

    #[test]
    fn verdict_stream_records_replays_and_refuses_a_divergent_replay() {
        let directory = tempdir().unwrap();
        let trace = directory.path().join("verdicts.patina");

        let mut context = Context::from_config(RuntimeConfig::record(3, &trace, "fp")).unwrap();
        context.entropy_bytes(4).unwrap();
        context
            .verdict(VerdictKind::Pass, "phase-one", "a")
            .unwrap();
        context
            .verdict(VerdictKind::Violation, "two-leaders", "{\"term\":4}")
            .unwrap();
        context.finish().unwrap();

        // The verdicts are trace events, not just diagnostics.
        let bundle = TraceBundle::load(&trace).unwrap();
        let recorded: Vec<_> = bundle
            .resolved_timeline("main")
            .unwrap()
            .into_iter()
            .filter_map(|event| match event.operation {
                Operation::Verdict {
                    verdict_kind,
                    label,
                    ..
                } => Some((verdict_kind, label)),
                _ => None,
            })
            .collect();
        assert_eq!(
            recorded,
            vec![
                (VerdictKind::Pass, "phase-one".to_string()),
                (VerdictKind::Violation, "two-leaders".to_string()),
            ]
        );

        // Replaying the same verdict stream reconciles cleanly.
        let mut replay = Context::from_config(RuntimeConfig::replay(&trace, "fp")).unwrap();
        replay.entropy_bytes(4).unwrap();
        replay.verdict(VerdictKind::Pass, "phase-one", "a").unwrap();
        replay
            .verdict(VerdictKind::Violation, "two-leaders", "{\"term\":4}")
            .unwrap();
        replay.finish().unwrap();

        // A replay whose verdict stream diverges — same labels, different kind —
        // fails closed like any other operation mismatch rather than being
        // reconciled away.
        let mut diverged = Context::from_config(RuntimeConfig::replay(&trace, "fp")).unwrap();
        diverged.entropy_bytes(4).unwrap();
        let error = diverged
            .verdict(VerdictKind::Violation, "phase-one", "a")
            .expect_err("a diverging verdict must be refused");
        let message = error.to_string();
        assert!(
            message.contains("mismatch"),
            "expected an operation mismatch, got: {message}"
        );
    }

    // The custom-op record/replay contract end to end at the runtime layer: the
    // typed entry records a `CustomOp` event carrying the encoded key and result,
    // and a replay returns the recorded value WITHOUT running `perform` — proven
    // by a replay `perform` that would panic the test if it ever ran.
    #[test]
    fn custom_op_records_its_result_and_replays_without_running_perform() {
        let directory = tempdir().unwrap();
        let trace = directory.path().join("custom-op.patina");

        let mut context = Context::from_config(RuntimeConfig::record(3, &trace, "fp")).unwrap();
        let recorded: Vec<String> = context
            .custom_op("s3.get_object", "bucket/key", || {
                vec!["alpha".to_string(), "beta".to_string()]
            })
            .unwrap();
        assert_eq!(recorded, vec!["alpha".to_string(), "beta".to_string()]);
        let count: u64 = context.custom_op("host.pid", &7u32, || 4242u64).unwrap();
        assert_eq!(count, 4242);
        context.finish().unwrap();

        // Both calls are trace events carrying the label and the encoded key.
        let bundle = TraceBundle::load(&trace).unwrap();
        let events: Vec<_> = bundle
            .resolved_timeline("main")
            .unwrap()
            .into_iter()
            .filter_map(|event| match event.operation {
                Operation::CustomOp { label, key } => Some((label, key, event.outcome)),
                _ => None,
            })
            .collect();
        assert_eq!(events.len(), 2, "{events:?}");
        assert_eq!(events[0].0, "s3.get_object");
        assert_eq!(events[0].1, br#""bucket/key""#.to_vec());
        assert_eq!(
            events[0].2,
            Outcome::Bytes(br#"["alpha","beta"]"#.to_vec()),
            "the recorded outcome is the SDK-encoded result"
        );
        assert_eq!(events[1].0, "host.pid");

        // Replay: `perform` must not run, and the recorded values come back typed.
        let mut replay = Context::from_config(RuntimeConfig::replay(&trace, "fp")).unwrap();
        let replayed: Vec<String> = replay
            .custom_op("s3.get_object", "bucket/key", || {
                panic!("replay must not run perform")
            })
            .unwrap();
        assert_eq!(replayed, recorded);
        let replayed_count: u64 = replay
            .custom_op("host.pid", &7u32, || panic!("replay must not run perform"))
            .unwrap();
        assert_eq!(replayed_count, 4242);
        replay.finish().unwrap();
    }

    // Recording is honest, not normative: the same seed with a `perform` that
    // returns something else records the new bytes. Replay of a GIVEN trace is
    // still exact — which is the property that makes the difference visible
    // rather than hidden.
    #[test]
    fn custom_op_recording_reports_what_perform_returned_not_what_a_seed_implies() {
        let directory = tempdir().unwrap();
        let outcome_bytes = |value: &str| {
            let trace = directory.path().join(format!("{value}.patina"));
            let mut context = Context::from_config(RuntimeConfig::record(9, &trace, "fp")).unwrap();
            let _: String = context
                .custom_op("clock.host", &(), || value.to_string())
                .unwrap();
            context.finish().unwrap();
            TraceBundle::load(&trace)
                .unwrap()
                .resolved_timeline("main")
                .unwrap()[0]
                .outcome
                .clone()
        };
        assert_ne!(
            outcome_bytes("first"),
            outcome_bytes("second"),
            "a nondeterministic perform must produce visibly different traces, not a hidden one"
        );
    }

    // A replay may only be answered for the exact question the recording holds:
    // a changed key, and a changed label, each refuse and name the label.
    #[test]
    fn custom_op_replay_refuses_a_changed_key_or_label_naming_the_label() {
        let directory = tempdir().unwrap();
        let trace = directory.path().join("custom-op-key.patina");
        let mut context = Context::from_config(RuntimeConfig::record(3, &trace, "fp")).unwrap();
        let _: u32 = context
            .custom_op("dns.lookup", "example.com", || 1)
            .unwrap();
        context.finish().unwrap();

        // Same label, different key.
        let mut replay = Context::from_config(RuntimeConfig::replay(&trace, "fp")).unwrap();
        let error = replay
            .custom_op::<u32, str>("dns.lookup", "elsewhere.com", || unreachable!())
            .expect_err("a changed key must be refused");
        let message = error.to_string();
        assert!(
            message.contains("dns.lookup") && message.contains("elsewhere.com"),
            "the refusal must name the label and what was asked: {message}"
        );
        assert!(matches!(error, RuntimeError::CustomOp { .. }), "{error:?}");

        // Same key, different label.
        let mut replay = Context::from_config(RuntimeConfig::replay(&trace, "fp")).unwrap();
        let error = replay
            .custom_op::<u32, str>("dns.reverse", "example.com", || unreachable!())
            .expect_err("a changed label must be refused");
        let message = error.to_string();
        assert!(
            message.contains("dns.reverse") && message.contains("dns.lookup"),
            "the refusal must name both labels: {message}"
        );

        // The clean replay still works, so the two refusals above are not a
        // trace that simply cannot be replayed at all.
        let mut replay = Context::from_config(RuntimeConfig::replay(&trace, "fp")).unwrap();
        let value: u32 = replay
            .custom_op("dns.lookup", "example.com", || unreachable!())
            .unwrap();
        assert_eq!(value, 1);
        replay.finish().unwrap();
    }

    // A `perform` that touches an effect Patina DOES model produces a trace that
    // replay could never reproduce (replay skips `perform`). Caught at record
    // time, naming the label and the count, instead of surfacing later as an
    // unexplained operation mismatch.
    #[test]
    fn custom_op_refuses_a_perform_that_performed_modeled_operations() {
        let directory = tempdir().unwrap();
        let trace = directory.path().join("custom-op-inner.patina");
        let mut context = Context::from_config(RuntimeConfig::record(3, &trace, "fp")).unwrap();
        assert_eq!(
            context.custom_op_begin("wrapped.fs", b"k").unwrap(),
            CustomOpMode::Record
        );
        context.entropy_bytes(4).unwrap();
        let error = context
            .custom_op_record(b"result".to_vec())
            .expect_err("a modeled operation inside perform must be refused");
        let message = error.to_string();
        assert!(
            message.contains("wrapped.fs") && message.contains("1 modeled boundary operation"),
            "{message}"
        );
    }

    // The protocol's own invariants: no nesting, no unclosed operation, no
    // fetching a recorded result on a record pass.
    #[test]
    fn custom_op_protocol_misuse_is_refused_rather_than_recorded() {
        let directory = tempdir().unwrap();
        let trace = directory.path().join("custom-op-misuse.patina");
        let mut context = Context::from_config(RuntimeConfig::record(3, &trace, "fp")).unwrap();
        context.custom_op_begin("outer", b"k").unwrap();
        let error = context
            .custom_op_begin("inner", b"k")
            .expect_err("a nested custom op must be refused");
        assert!(
            error.to_string().contains("inner") && error.to_string().contains("outer"),
            "{error}"
        );
        // A record pass has no recorded answer to hand back.
        let error = context
            .custom_op_replay_result()
            .expect_err("a record pass has no recorded result");
        assert!(error.to_string().contains("outer"), "{error}");

        // ... and the still-open operation is refused at finish rather than
        // silently leaving the trace short one event.
        let unclosed = directory.path().join("custom-op-unclosed.patina");
        let mut context = Context::from_config(RuntimeConfig::record(3, &unclosed, "fp")).unwrap();
        context.custom_op_begin("never-closed", b"k").unwrap();
        let error = context.finish().expect_err("an open custom op must refuse");
        assert!(error.to_string().contains("never-closed"), "{error}");

        // Closing with no operation open is equally refused.
        let mut context = Context::from_config(RuntimeConfig::seeded(3)).unwrap();
        assert!(context.custom_op_record(Vec::new()).is_err());
        assert!(context.custom_op_replay_result().is_err());
    }

    // A plain seeded run has no recording to consult, so `perform` runs and its
    // value is returned untouched — the same shape as the record pass, minus the
    // trace. This is what makes a custom op safe to leave in an ordinary run.
    #[test]
    fn custom_op_on_a_seeded_run_performs_and_returns_the_value() {
        let mut context = Context::from_config(RuntimeConfig::seeded(3)).unwrap();
        let mut ran = 0;
        let value: String = context
            .custom_op("host.hostname", &(), || {
                ran += 1;
                "node-a".to_string()
            })
            .unwrap();
        assert_eq!((value.as_str(), ran), ("node-a", 1));
        context.finish().unwrap();
    }

    #[test]
    fn buggify_record_replay_reproduces_decisions_without_re_supplying_flags() {
        let directory = tempdir().unwrap();
        let trace = directory.path().join("buggify.patina");
        let config = BuggifyConfig {
            enabled: true,
            fire_permille: 500,
            activation_permille: 1000,
            cutoff_nanos: DEFAULT_BUGGIFY_CUTOFF_NANOS,
            after_setup: false,
        };

        // Record: interleave a recorded entropy op with buggify evaluations and a
        // fired delay (which records a SleepUntil), then finalize the trace.
        let mut recorded_fires = Vec::new();
        let mut context =
            Context::from_config(RuntimeConfig::record(3, &trace, "fp").with_buggify(config))
                .unwrap();
        context.entropy_bytes(4).unwrap();
        for _ in 0..20 {
            recorded_fires.push(matches!(
                context.buggify_evaluate("s", "r.rs:1", None).unwrap(),
                SiteOutcome::Fire
            ));
            let _ = context.buggify_delay("d", "r.rs:2").unwrap();
        }
        context.finish().unwrap();

        // Replay WITHOUT re-supplying buggify flags: the trace's recorded config
        // is authoritative and the pure-function decisions must reproduce exactly.
        let mut replay_fires = Vec::new();
        let mut replay = Context::from_config(RuntimeConfig::replay(&trace, "fp")).unwrap();
        replay.entropy_bytes(4).unwrap();
        for _ in 0..20 {
            replay_fires.push(matches!(
                replay.buggify_evaluate("s", "r.rs:1", None).unwrap(),
                SiteOutcome::Fire
            ));
            let _ = replay.buggify_delay("d", "r.rs:2").unwrap();
        }
        // No divergence at finalization means every recorded op (entropy +
        // delay-driven SleepUntil) was consumed in the same order.
        replay.finish().unwrap();

        assert_eq!(recorded_fires, replay_fires);
        assert!(
            recorded_fires.iter().any(|fired| *fired),
            "expected some firing"
        );
    }

    /// Drive a fixed multi-task cooperative schedule through a context, returning
    /// the order in which `scheduler_next` selected tasks. Tasks all stay runnable
    /// (yield, never park/complete until the end), so the policy fully controls
    /// the order.
    fn drive_schedule(context: &mut Context, n_workers: usize, rounds: usize) -> Vec<u64> {
        let mut workers = Vec::new();
        for index in 0..n_workers {
            workers.push(context.task_spawn(&format!("w{index}")).unwrap());
        }
        let mut order = Vec::new();
        for _ in 0..rounds {
            let task = context.scheduler_next().unwrap().unwrap();
            order.push(task.0);
            context.task_yield(task).unwrap();
        }
        drop(workers);
        // Drain: complete whatever task each decision selects until none remain.
        while let Some(task) = context.scheduler_next().unwrap() {
            context.task_complete(task).unwrap();
        }
        order
    }

    #[test]
    fn pct_record_replay_reproduces_schedule_and_records_policy() {
        let directory = tempdir().unwrap();
        let trace = directory.path().join("pct.patina");
        let policy = SchedulePolicy {
            pct: Some(PctConfig {
                depth: 3,
                steps: 50,
            }),
            starvation: None,
        };
        let config = RuntimeConfig::record(11, &trace, "fp+pct").with_schedule_policy(policy);
        let mut record = Context::from_config(config).unwrap();
        let recorded = drive_schedule(&mut record, 4, 40);
        record.finish().unwrap();

        // The trace records the policy metadata authoritatively.
        let bundle = patina_dst_trace::TraceBundle::load(&trace).unwrap();
        let recorded_policy = bundle.metadata.schedule_policy.expect("policy recorded");
        assert_eq!(recorded_policy.pct.unwrap().depth, 3);

        // Replay WITHOUT re-supplying the policy reproduces the exact selection
        // order (decisions come from the recorded op-stream).
        let mut replay = Context::from_config(RuntimeConfig::replay(&trace, "fp+pct")).unwrap();
        let replayed = drive_schedule(&mut replay, 4, 40);
        replay.finish().unwrap();
        assert_eq!(recorded, replayed);
        // A depth-3 PCT schedule over four always-runnable workers preempts, so
        // more than one task id appears.
        assert!(
            recorded
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                > 1
        );
    }

    #[test]
    fn reconcile_replay_sud_refuses_a_mismatch_in_both_directions() {
        // Matching states reconcile clean: armed↔armed, and not-armed↔not-armed
        // (the latter covers macOS, non-SUD kernels, and every pre-SUD trace).
        let armed = RuntimeConfig::seeded(0).with_sud(Some(true));
        let unarmed = RuntimeConfig::seeded(0).with_sud(None);
        assert!(reconcile_replay_sud(&armed, Some(true)).is_ok());
        assert!(reconcile_replay_sud(&unarmed, None).is_ok());
        assert!(reconcile_replay_sud(&unarmed, Some(false)).is_ok());

        // RED direction 1: a trace recorded under SUD replayed where SUD did not
        // arm (kernel lacks it / macOS) is refused up front, naming the kernel.
        let err = reconcile_replay_sud(&unarmed, Some(true)).unwrap_err();
        let text = format!("{err}");
        assert!(
            text.contains("recorded under syscall-user-dispatch"),
            "{text}"
        );
        assert!(
            text.contains("rustix_use_libc") || text.contains("lacks SUD"),
            "{text}"
        );

        // RED direction 2: a run that armed SUD replaying a trace recorded WITHOUT
        // it is refused too — the converse mismatch, never a silent divergence.
        let err = reconcile_replay_sud(&armed, None).unwrap_err();
        let text = format!("{err}");
        assert!(text.contains("armed syscall-user-dispatch"), "{text}");
        assert!(text.contains("recorded WITHOUT it"), "{text}");
    }

    #[test]
    fn reconcile_replay_schedule_policy_enforces_the_authoritative_trace_contract() {
        let stored = patina_dst_trace::SchedulePolicyRecord {
            pct: Some(patina_dst_trace::PctPolicyRecord {
                depth: 3,
                steps: 100,
            }),
            starvation: None,
        };
        // A default-policy trace (None) yields no override.
        assert_eq!(
            reconcile_replay_schedule_policy(&RuntimeConfig::seeded(0), None).unwrap(),
            None
        );
        // Flag-free replay adopts the stored policy verbatim.
        let adopted = reconcile_replay_schedule_policy(&RuntimeConfig::seeded(0), Some(&stored))
            .unwrap()
            .expect("stored policy adopted");
        assert_eq!(adopted.pct.unwrap().depth, 3);
        // A conflicting supplied policy fails closed.
        let conflicting = RuntimeConfig::seeded(0).with_schedule_policy(SchedulePolicy {
            pct: Some(PctConfig {
                depth: 9,
                steps: 100,
            }),
            starvation: None,
        });
        assert!(reconcile_replay_schedule_policy(&conflicting, Some(&stored)).is_err());
    }

    #[test]
    fn swarm_masks_a_subset_and_records_candidates_and_selection() {
        let directory = tempdir().unwrap();
        // Enable several fault classes plus buggify, then record under swarm.
        let build = |seed: u64| {
            let trace = directory.path().join(format!("swarm-{seed}.patina"));
            let config = RuntimeConfig::record(seed, &trace, "fp+swarm")
                .with_crash_at(CrashOp::Close, 1)
                .with_fs_error_permille(100)
                .with_fs_short_permille(200)
                .with_net_drop_permille(100)
                .with_sleep_jitter_nanos(1, 2)
                .with_buggify(BuggifyConfig {
                    enabled: true,
                    ..BuggifyConfig::default()
                })
                .with_swarm(true);
            let context = Context::from_config(config).unwrap();
            context.finish().unwrap();
            patina_dst_trace::TraceBundle::load(&trace).unwrap()
        };
        let bundle = build(1);
        let swarm = bundle.metadata.swarm.expect("swarm recorded");
        // All six enabled classes are candidates.
        assert_eq!(
            swarm.candidate_classes,
            vec![
                "crash",
                "fs_error",
                "fs_short",
                "sleep_jitter",
                "net_drop",
                "buggify"
            ]
        );
        // The selected subset is a subset of candidates and reflects the applied
        // (masked) config: exactly the classes that survived masking.
        for class in &swarm.selected_classes {
            assert!(swarm.candidate_classes.contains(class));
        }
        let faults = bundle.metadata.faults.expect("faults recorded");
        assert_eq!(
            faults.crash_at.is_some(),
            swarm.selected_classes.iter().any(|c| c == "crash")
        );
        assert_eq!(
            bundle.metadata.buggify.is_some(),
            swarm.selected_classes.iter().any(|c| c == "buggify")
        );

        // Across seeds the selected subset actually varies (swarm testing).
        let subsets: std::collections::BTreeSet<Vec<String>> = (100..112)
            .map(|seed| build(seed).metadata.swarm.unwrap().selected_classes)
            .collect();
        assert!(
            subsets.len() > 1,
            "swarm subset must vary across seeds: {subsets:?}"
        );
    }

    /// `--swarm` on a run with no fault class enabled is an inert knob: the draw
    /// has nothing to keep or drop, the run explores what a plain run explores,
    /// and the report must SAY so rather than reading like covered swarm
    /// exploration. This is the signature the campaign/sweep `VACUOUS_SWARM`
    /// classes key on, so the wire shape is pinned here.
    #[test]
    fn swarm_with_no_enabled_fault_class_reports_vacuous() {
        let directory = tempdir().unwrap();
        let trace = directory.path().join("swarm-vacuous.patina");
        let config = RuntimeConfig::record(3, &trace, "fp+swarm").with_swarm(true);
        let context = Context::from_config(config).unwrap();
        context.finish().unwrap();
        let bundle = patina_dst_trace::TraceBundle::load(&trace).unwrap();
        let swarm = bundle.metadata.swarm.expect("swarm recorded");
        assert!(swarm.candidate_classes.is_empty());
        assert!(swarm.is_vacuous());
        assert_eq!(
            swarm_report_line(&swarm),
            "PATINA_SWARM_REPORT candidates=0 selected=0 deselected=0 vacuous=1"
        );

        // A live candidate set is NOT vacuous, even when the draw drops all of it:
        // exploring the empty subset of a real candidate set is a legitimate draw.
        let all_dropped = patina_dst_trace::SwarmConfigRecord {
            candidate_classes: vec!["crash".to_string(), "buggify".to_string()],
            selected_classes: Vec::new(),
        };
        assert_eq!(
            swarm_report_line(&all_dropped),
            "PATINA_SWARM_REPORT candidates=2 selected=0 deselected=2 vacuous=0 \
class=crash|0 class=buggify|0"
        );
    }

    /// Every fault knob must survive the trace round trip. A knob the record
    /// does not carry replays as its default — the run reproduces WITHOUT the
    /// fault that was recorded, which is silent inertness wearing a replay's
    /// clothes. Driven off [`FaultKnob::ALL`], so the gate grows with the enum
    /// rather than with a hand-kept sample list.
    #[test]
    fn every_fault_knob_survives_the_trace_record_round_trip() {
        for knob in FaultKnob::ALL {
            if knob.meta().plane != Plane::Fault {
                // The DNS host table has its own record (`DnsConfigRecord`) and
                // its own replay reconciliation; see `reconcile_replay_dns`.
                continue;
            }
            let mut config = RuntimeConfig::seeded(1);
            knob.set_sample(&mut config.faults);
            let record = fault_record(&config);
            assert_ne!(
                record,
                patina_dst_trace::FaultConfigRecord::default(),
                "{knob:?} left no trace in the recorded fault configuration"
            );
            assert_eq!(
                fault_config_from_record(&record),
                config.faults,
                "{knob:?} did not survive the record round trip"
            );
        }
    }

    /// The two halves of "every knob" must describe the same configuration: the
    /// FIELD view below, whose exhaustive struct literals make a new
    /// `*FaultConfig` field a compile error, and the KNOB view, whose exhaustive
    /// `set_sample` match makes a new [`FaultKnob`] one. A field added without a
    /// knob (unreachable from any CLI) or a knob added without a field (carried
    /// to the guest and then dropped) shows up here as a mismatch.
    #[test]
    fn fault_config_fields_and_fault_knobs_describe_the_same_configuration() {
        let mut from_knobs = FaultConfig::default();
        for knob in FaultKnob::ALL {
            knob.set_sample(&mut from_knobs);
        }
        assert_eq!(from_knobs, every_fault_knob_enabled());
    }

    /// Every fault knob at a non-default value, written as EXHAUSTIVE struct
    /// literals on purpose: a field added to any `*FaultConfig` sub-struct is a
    /// compile error right here, which is what drags a new knob through the
    /// swarm-coverage gate below instead of letting it land outside the swarm
    /// table unnoticed. (A `..Default::default()` tail would leave a new field
    /// silently absent — exactly the drift this gate exists to prevent.)
    fn every_fault_knob_enabled() -> FaultConfig {
        FaultConfig {
            fs: FsFaultConfig {
                crash_at: Some(CrashPoint {
                    op: CrashOp::Close,
                    ordinal: 1,
                }),
                torn_granularity: TornGranularity::Byte,
                error_permille: 1,
                short_permille: 1,
                latency_nanos: Some((1, 2)),
            },
            net: NetFaultConfig {
                latency_nanos: 1,
                jitter_nanos: Some((1, 2)),
                drop_permille: 1,
                duplicate_permille: 1,
                connect_refuse_permille: 1,
                reset_permille: 1,
                partitions: BTreeSet::from([
                    ("a".to_string(), "b".to_string()),
                    ("b".to_string(), "a".to_string()),
                ]),
                tcp_buffer_bytes: Some(4096),
            },
            clock: ClockFaultConfig {
                sleep_jitter_nanos: Some((1, 2)),
                epoch_jump_nanos: 1,
            },
            dns: DnsFaultConfig {
                fail_permille: 1,
                latency_nanos: Some((1, 2)),
            },
            entropy: EntropyFaultConfig { fail_permille: 1 },
        }
    }

    #[test]
    fn swarm_class_table_covers_every_current_fault_field() {
        let directory = tempdir().unwrap();
        let trace = directory.path().join("swarm-coverage.patina");
        let mut config = RuntimeConfig::record(9, &trace, "fp+swarm")
            .with_buggify(BuggifyConfig {
                enabled: true,
                ..BuggifyConfig::default()
            })
            .with_swarm(true);
        config.faults = every_fault_knob_enabled();
        let context = Context::from_config(config).unwrap();
        context.finish().unwrap();
        let swarm = patina_dst_trace::TraceBundle::load(&trace)
            .unwrap()
            .metadata
            .swarm
            .expect("swarm recorded");

        // The recorded candidate ORDER, written out by hand on purpose: it is
        // the one thing about `SWARM_CLASSES` that a trace can see, so deriving
        // it from the table would leave a reordered table ungated. That a class
        // EXISTS for every knob is gated separately, off the table, by
        // `swarm_classes_and_knobs_agree`.
        assert_eq!(
            swarm.candidate_classes,
            vec![
                "crash",
                "fs_error",
                "fs_short",
                "fs_latency",
                "dns_fail",
                "dns_latency",
                "sleep_jitter",
                "net_jitter",
                "net_drop",
                "net_latency",
                "net_duplicate",
                "net_connect_refuse",
                "net_reset",
                "net_partition",
                "net_tcp_buffer",
                "entropy_fail",
                "buggify",
                "epoch_jump",
            ]
        );
    }

    /// Each swarm row must be wired to ITS OWN knobs: a config with exactly one
    /// knob set offers exactly that knob's class as the only candidate, and a
    /// deselected class leaves no residue behind. A row copy-pasted onto a
    /// neighbouring field — the likeliest mistake when a domain grows its fourth
    /// knob — shows up here. Driven off [`FaultKnob::ALL`] rather than a sample
    /// list, so a new knob is covered the day it exists.
    #[test]
    fn each_swarm_class_is_wired_to_its_own_fault_knobs() {
        for knob in FaultKnob::ALL {
            // The class that MASKS the knob, which is not always the class the
            // knob declares: `--fs-torn-granularity` declares none and is masked
            // by `crash`, and `--dns-entry` is masked by nothing at all.
            let masking = SWARM_CLASSES
                .iter()
                .find(|class| matches!(class.masks, Masks::Knobs(knobs) if knobs.contains(knob)));
            let mut config = RuntimeConfig::seeded(1).with_swarm(true);
            knob.set_sample(&mut config.faults);
            let record = apply_swarm_mask(&mut config);

            let Some(class) = masking else {
                assert!(
                    record.candidate_classes.is_empty(),
                    "{knob:?} is masked by no class but offered {:?}",
                    record.candidate_classes
                );
                continue;
            };
            assert_eq!(
                record.candidate_classes,
                vec![class.token.to_string()],
                "{} must be the only candidate {knob:?} offers",
                class.token
            );
            if record.selected_classes.is_empty() {
                assert_eq!(
                    config.faults,
                    FaultConfig::default(),
                    "a deselected {} must leave no residue",
                    class.token
                );
            }
        }
    }

    /// The lowest seed for which swarm's `buggify` coin comes up the given way,
    /// so the coherence tests below name a real deselecting/selecting generation
    /// instead of hard-coding a seed that a coin change would silently invert.
    fn seed_where_buggify_is(selected: bool) -> u64 {
        (0..1024)
            .find(|seed| {
                let mut rng = SplitMix64::new(domain_seed(*seed, fault_domain::SWARM_BUGGIFY));
                (rng.next_u64() & 1 == 1) == selected
            })
            .expect("some seed in 0..1024 draws each way")
    }

    /// The bug behind SlateDB feedback item 9. A `--swarm` generation whose seed
    /// deselects `buggify` used to keep `+buggify` in its fingerprint while
    /// disarming the buggify config, which the coherence guard then (correctly)
    /// refused — so a legitimate masked generation aborted. Masking now retracts
    /// the component, and the whole declared state stays truthful.
    #[test]
    fn swarm_deselecting_buggify_retracts_the_fingerprint_component() {
        let directory = tempdir().unwrap();
        let record = |seed: u64| {
            let trace = directory.path().join(format!("swarm-fp-{seed}.patina"));
            let config = RuntimeConfig::record(seed, &trace, "fp+buggify+swarm")
                .with_buggify(BuggifyConfig {
                    enabled: true,
                    fire_permille: 372,
                    ..BuggifyConfig::default()
                })
                .with_swarm(true);
            // RED before the fix: this `build` returned the "+buggify but buggify
            // is not enabled" refusal on a deselecting seed.
            let context = Context::from_config(config).expect("masked run must build");
            context.finish().unwrap();
            patina_dst_trace::TraceBundle::load(&trace).unwrap()
        };

        // Deselected: the component is gone, no buggify config is recorded, and
        // the swarm record still names buggify as a candidate — so the trace says
        // "asked for, dropped here", not "never asked for".
        let dropped = record(seed_where_buggify_is(false));
        assert_eq!(dropped.metadata.fingerprint, "fp+swarm");
        assert_eq!(dropped.metadata.buggify, None);
        let swarm = dropped.metadata.swarm.as_ref().expect("swarm recorded");
        assert!(swarm.was_candidate(FINGERPRINT_BUGGIFY));
        assert!(swarm.deselected(FINGERPRINT_BUGGIFY));
        assert_eq!(swarm.deselected_classes(), vec![FINGERPRINT_BUGGIFY]);
        // The trace's own coherence check agrees (it is what rejects a fingerprint
        // that declares +buggify with no buggify config).
        dropped.validate().expect("masked trace must validate");

        // Selected: nothing changes — the component and the config both stand.
        let kept = record(seed_where_buggify_is(true));
        assert_eq!(kept.metadata.fingerprint, "fp+buggify+swarm");
        assert_eq!(
            kept.metadata
                .buggify
                .as_ref()
                .expect("buggify recorded")
                .fire_permille,
            372
        );
        let swarm = kept.metadata.swarm.as_ref().expect("swarm recorded");
        assert!(!swarm.deselected(FINGERPRINT_BUGGIFY));
        kept.validate().expect("selected trace must validate");
    }

    /// A dropped class leaves NO residue in the configuration: the whole buggify
    /// config resets, so a masked run reports the same numbers a run that never
    /// asked for buggify reports. The requested-but-dropped fact is carried by
    /// `swarm_deselected`, not by leftover permilles — which is what made the
    /// original `enabled=0 fire_permille=372` line read like a broken flag.
    #[test]
    fn swarm_deselection_clears_the_class_config_and_is_reported_distinctly() {
        let requested = || {
            RuntimeConfig::seeded(seed_where_buggify_is(false))
                .with_buggify(BuggifyConfig {
                    enabled: true,
                    fire_permille: 372,
                    activation_permille: 900,
                    ..BuggifyConfig::default()
                })
                .with_swarm(true)
        };
        let mut masked = requested();
        let record = apply_swarm_mask(&mut masked);
        assert!(record.deselected(FINGERPRINT_BUGGIFY));
        assert_eq!(masked.buggify, BuggifyConfig::default());

        // `swarm_deselected` is what separates the two `enabled=0` states.
        let mut context = Context::from_config(requested()).unwrap();
        let diagnostics = context.buggify_diagnostics();
        assert!(!diagnostics.enabled);
        assert!(diagnostics.swarm_deselected);

        let mut never_asked = Context::from_config(RuntimeConfig::seeded(0)).unwrap();
        let diagnostics = never_asked.buggify_diagnostics();
        assert!(!diagnostics.enabled);
        assert!(!diagnostics.swarm_deselected);
    }

    /// `buggify` is the ONLY swarm class whose capability is declared as a
    /// fingerprint component today. Adding another one without registering it in
    /// the swarm class table would resurrect the item-9 incoherence for that
    /// class, so pin the mapping: with every class enabled and every class token
    /// present as a fingerprint component, masking must retract `buggify` (when
    /// dropped) and nothing else, whatever the seed decided.
    #[test]
    fn swarm_class_table_declares_every_fingerprint_component() {
        let classes = [
            "crash",
            "fs_error",
            "fs_short",
            "sleep_jitter",
            "net_jitter",
            "net_drop",
            "net_latency",
            "buggify",
        ];
        for seed in 0..8u64 {
            let mut config = RuntimeConfig::seeded(seed)
                .with_crash_at(CrashOp::Close, 1)
                .with_fs_error_permille(1)
                .with_fs_short_permille(1)
                .with_sleep_jitter_nanos(1, 2)
                .with_net_jitter_nanos(1, 2)
                .with_net_drop_permille(1)
                .with_net_latency_nanos(1)
                .with_buggify(BuggifyConfig {
                    enabled: true,
                    ..BuggifyConfig::default()
                })
                .with_swarm(true);
            config.fingerprint = format!("fp+{}", classes.join("+"));
            let record = apply_swarm_mask(&mut config);
            let expected: Vec<&str> = classes
                .iter()
                .copied()
                .filter(|class| {
                    *class != FINGERPRINT_BUGGIFY || !record.deselected(FINGERPRINT_BUGGIFY)
                })
                .collect();
            assert_eq!(
                config.fingerprint,
                format!("fp+{}", expected.join("+")),
                "seed {seed} retracted the wrong component set"
            );
        }
    }

    #[test]
    fn remove_fingerprint_component_drops_only_whole_components() {
        assert_eq!(
            remove_fingerprint_component("patina-native+buggify+swarm", "buggify"),
            "patina-native+swarm"
        );
        // The base label and every other component keep their order.
        assert_eq!(
            remove_fingerprint_component("base+fsimg:abc+buggify+pct+swarm", "buggify"),
            "base+fsimg:abc+pct+swarm"
        );
        // A component is matched whole, never as a substring of another.
        assert_eq!(
            remove_fingerprint_component("base+buggifyx+swarm", "buggify"),
            "base+buggifyx+swarm"
        );
        // Absent component: unchanged.
        assert_eq!(
            remove_fingerprint_component("base+swarm", "buggify"),
            "base+swarm"
        );
    }

    #[test]
    fn fs_latency_vacuity_is_rate_aware_and_bites_on_an_inert_knob() {
        use patina_dst_driver_api::FsFaultReport;

        // FIRES: a knob that delays every eligible op, over twenty of them,
        // that applied ZERO delays. That is the shape a filesystem path
        // bypassing the Context latency choke point produces — the class this
        // detector exists for — and it must be reported as vacuous.
        assert!(patina_dst_driver_api::range_vacuity_is_diagnosable(
            20,
            (1_000, 1_000)
        ));
        let bypassed = FsFaultReport {
            eligible_ops: 20,
            latency_vacuity_diagnosable: true,
            latency_applied: 0,
            ..FsFaultReport::default()
        };
        assert!(bypassed.is_vacuous());

        // DOES NOT FIRE below the expected-firings floor: four eligible ops are
        // too few to call zero delays anomalous.
        assert!(!patina_dst_driver_api::range_vacuity_is_diagnosable(
            4,
            (1_000, 1_000)
        ));

        // DOES NOT FIRE for a range whose every draw is zero: that knob is inert
        // by construction, not inert on the code path.
        assert!(!patina_dst_driver_api::range_vacuity_is_diagnosable(
            1_000_000,
            (0, 0)
        ));

        // Rate-aware in between: `0..9` delays nine draws in ten, so it takes six
        // eligible ops to expect five delays.
        assert!(!patina_dst_driver_api::range_vacuity_is_diagnosable(
            5,
            (0, 9)
        ));
        assert!(patina_dst_driver_api::range_vacuity_is_diagnosable(
            6,
            (0, 9)
        ));
    }

    /// The report must name WHICH operation kinds absorbed the injected effects.
    /// A bare `errors_injected=7` cannot distinguish a run that failed seven
    /// `open`s from one that failed seven `sync`s, and those are different
    /// coverage: a durability bug reachable only through a failing `sync` stays
    /// untested while the report reads identically. Same for short I/O — shorts
    /// that all landed on reads say nothing about the write path.
    #[test]
    fn fs_fault_report_line_attributes_effects_to_operation_kinds() {
        use patina_dst_driver_api::FsDriver;
        use patina_dst_fs_mem::MemFs;
        use patina_dst_wrapper_fault::FaultFs;

        let readable_write = OpenFlags {
            read: true,
            ..OpenFlags::create_truncate_write()
        };
        let mut inner = MemFs::new();
        let fd = inner.open("/file", readable_write).unwrap();
        inner.write(fd, b"abcdef").unwrap();

        // Every eligible operation fails, so the breakdown is exactly the
        // operations performed, in the report's fixed order rather than the
        // call order.
        let mut fs = FaultFs::new(inner, 1).error_permille(1000);
        assert!(fs.sync(fd).is_err());
        assert!(fs.metadata("/file").is_err());
        assert!(fs.open("/other", readable_write).is_err());
        assert!(fs.read(fd, 4).is_err());
        assert!(fs.read(fd, 4).is_err());
        let report = fs.fault_report().unwrap();
        assert_eq!(report.errors_injected, 5);
        let line = fs_fault_report_line(&report);
        assert!(
            line.contains(" errors_by_op=open:1,read:2,metadata:1,sync:1 "),
            "error breakdown must name the op kinds in the fixed report order:\n{line}"
        );
        assert!(
            line.contains(" shorts_by_op=- "),
            "an unfired class renders as the empty-breakdown sentinel:\n{line}"
        );

        // The short class attributes independently: a truncation counts against
        // the op kind whose result it bound.
        let mut inner = MemFs::new();
        let fd = inner.open("/file", readable_write).unwrap();
        inner.write(fd, b"abcdef").unwrap();
        let mut fs = FaultFs::new(inner, 1).short_permille(1000);
        assert!(fs.write(fd, b"abcdef").unwrap() < 6);
        assert!(fs.read_at(fd, 0, 6).unwrap().len() < 6);
        let report = fs.fault_report().unwrap();
        assert_eq!(report.shorts_applied, 2);
        let line = fs_fault_report_line(&report);
        assert!(
            line.contains(" shorts_by_op=write:1,read_at:1 "),
            "short breakdown must name the op kinds it bound:\n{line}"
        );
        assert!(
            line.contains(" errors_by_op=- "),
            "the error class stayed off and must not borrow the short class's ops:\n{line}"
        );
    }

    /// Every class's coin must come from `domain_seed` with the label the table
    /// declares — not from the root seed, and not from a neighbour's label, which
    /// would make two classes select and deselect together forever. Recomputed
    /// straight from [`SWARM_CLASSES`], so a class added to the table is covered
    /// without touching this test, and a class whose coin is rewired to a
    /// different label fails immediately.
    #[test]
    fn swarm_class_coins_use_the_domain_seed_registry() {
        let seed = 42;
        let mut config = RuntimeConfig::seeded(seed)
            .with_buggify(BuggifyConfig {
                enabled: true,
                ..BuggifyConfig::default()
            })
            .with_swarm(true);
        config.faults = every_fault_knob_enabled();

        let expected: Vec<String> = SWARM_CLASSES
            .iter()
            .filter_map(|class| {
                let mut rng = SplitMix64::new(domain_seed(seed, class.domain));
                (rng.next_u64() & 1 == 1).then(|| class.token.to_string())
            })
            .collect();
        assert!(
            !expected.is_empty() && expected.len() < SWARM_CLASSES.len(),
            "seed {seed} must select SOME classes and drop others for this to prove anything"
        );

        let swarm = apply_swarm_mask(&mut config);
        assert_eq!(swarm.selected_classes, expected);
    }

    #[test]
    fn default_driver_streams_are_domain_separated() {
        let seed = 7;

        let mut context = Context::from_config(RuntimeConfig::seeded(seed)).unwrap();
        let actual_entropy = context.entropy_bytes(24).unwrap();
        context.finish().unwrap();

        let mut expected_entropy = SeededEntropy::new(domain_seed(seed, fault_domain::ENTROPY));
        let mut expected = [0; 24];
        expected_entropy.fill(&mut expected).unwrap();
        assert_eq!(actual_entropy, expected);

        let mut old_aliased_entropy = SeededEntropy::new(seed);
        let mut old = [0; 24];
        old_aliased_entropy.fill(&mut old).unwrap();
        assert_ne!(
            actual_entropy, old,
            "RED-before-GREEN: old runtime entropy used SplitMix64::new(root_seed)"
        );

        fn runtime_drop_pattern(seed: u64) -> Vec<SendDisposition> {
            let mut context =
                Context::from_config(RuntimeConfig::seeded(seed).with_net_drop_permille(500))
                    .unwrap();
            let tx = context.net_bind("tx").unwrap();
            context.net_bind("rx").unwrap();
            let pattern = (0..64)
                .map(|seq| {
                    context
                        .net_send(tx, "rx", &[seq as u8])
                        .unwrap()
                        .disposition
                })
                .collect();
            context.finish().unwrap();
            pattern
        }

        fn sim_drop_pattern(fault_seed: u64) -> Vec<SendDisposition> {
            let mut net = SimNet::builder()
                .fault_seed(fault_seed)
                .drop_permille(500)
                .build()
                .unwrap();
            let tx = net.bind("tx").unwrap();
            net.bind("rx").unwrap();
            (0..64)
                .map(|seq| net.send(tx, "rx", &[seq as u8], 0).unwrap().disposition)
                .collect()
        }

        let runtime_pattern = runtime_drop_pattern(seed);
        assert_eq!(
            runtime_pattern,
            sim_drop_pattern(domain_seed(seed, fault_domain::NET_FAULT))
        );
        assert_ne!(
            runtime_pattern,
            sim_drop_pattern(seed),
            "RED-before-GREEN: old SimNet fault stream used the root seed directly"
        );

        let jittered = {
            let mut context = Context::from_config(
                RuntimeConfig::seeded(seed).with_sleep_jitter_nanos(500, 1_500),
            )
            .unwrap();
            context.sleep_for(1_000).unwrap();
            let elapsed = context.now(ClockKind::Monotonic).unwrap();
            context.finish().unwrap();
            elapsed
        };
        let mut sleep_rng = SplitMix64::new(domain_seed(seed, fault_domain::SLEEP_JITTER));
        let expected_jitter = 500 + (sleep_rng.next_u64() % 1_001);
        assert_eq!(jittered, 1_000 + expected_jitter);
    }

    #[test]
    fn apply_schedule_and_swarm_env_parse_the_control_plane() {
        let vars: BTreeMap<&str, String> = [
            (ENV_SCHED_PCT, "4".to_string()),
            (ENV_SCHED_PCT_STEPS, "123".to_string()),
            (ENV_SCHED_STARVE, "2".to_string()),
            (ENV_SCHED_STARVE_MAX_LEN, "16".to_string()),
            (ENV_SCHED_STARVE_WINDOW, "64".to_string()),
            (ENV_SWARM, "1".to_string()),
        ]
        .into_iter()
        .collect();
        let get = |name: &str| vars.get(name).cloned();
        let config = RuntimeConfig::seeded(0)
            .apply_schedule_env(get)
            .unwrap()
            .apply_swarm_env(get)
            .unwrap();
        let policy = config.schedule_policy();
        assert_eq!(
            policy.pct,
            Some(PctConfig {
                depth: 4,
                steps: 123
            })
        );
        assert_eq!(
            policy.starvation,
            Some(StarvationConfig {
                intervals: 2,
                max_len: 16,
                window: 64
            })
        );
        assert!(config.swarm());

        // A malformed PCT depth fails closed.
        let bad: BTreeMap<&str, String> =
            [(ENV_SCHED_PCT, "abc".to_string())].into_iter().collect();
        assert!(
            RuntimeConfig::seeded(0)
                .apply_schedule_env(|name| bad.get(name).cloned())
                .is_err()
        );
    }

    #[test]
    fn reconcile_replay_buggify_enforces_the_authoritative_trace_contract() {
        let stored = patina_dst_trace::BuggifyConfigRecord {
            fire_permille: 250,
            activation_permille: 250,
            cutoff_nanos: 300_000_000_000,
            after_setup: false,
            active_sites: vec!["s".into()],
            knobs: BTreeMap::new(),
        };
        // A trace without buggify yields no override.
        assert_eq!(
            reconcile_replay_buggify(&RuntimeConfig::seeded(0), None).unwrap(),
            None
        );
        // Flag-free replay adopts the stored config verbatim.
        let adopted = reconcile_replay_buggify(&RuntimeConfig::seeded(0), Some(&stored))
            .unwrap()
            .expect("stored config adopted");
        assert!(adopted.enabled);
        assert_eq!(adopted.fire_permille, 250);
        // Conflicting knobs fail closed.
        let conflicting = RuntimeConfig::seeded(0).with_buggify(BuggifyConfig {
            enabled: true,
            fire_permille: 999,
            ..BuggifyConfig::default()
        });
        assert!(reconcile_replay_buggify(&conflicting, Some(&stored)).is_err());
    }

    #[test]
    fn reconcile_replay_faults_enforces_the_authoritative_trace_contract() {
        use patina_dst_trace::{CrashPointRecord, FaultConfigRecord, FaultCrashOp};

        let stored = FaultConfigRecord {
            crash_at: Some(CrashPointRecord {
                op: FaultCrashOp::Close,
                ordinal: 1,
            }),
            torn_granularity: patina_dst_trace::TornGranularity::Byte,
            fs_error_permille: 111,
            fs_short_permille: 222,
            net_latency_nanos: 500,
            ..FaultConfigRecord::default()
        };

        // A pre-metadata trace (None) yields no override: the operator-supplied
        // configuration is kept, preserving the historical re-supply contract.
        let supplied = RuntimeConfig::seeded(0).with_crash_at(CrashOp::Close, 2);
        assert_eq!(reconcile_replay_faults(&supplied, None).unwrap(), None);

        // Flag-free replay adopts the stored configuration verbatim, so replay is
        // byte-identical without any knobs.
        let faults = reconcile_replay_faults(&RuntimeConfig::seeded(0), Some(&stored))
            .unwrap()
            .expect("stored config adopted");
        assert_eq!(
            faults.fs.crash_at,
            Some(CrashPoint {
                op: CrashOp::Close,
                ordinal: 1
            })
        );
        assert_eq!(faults.fs.torn_granularity, TornGranularity::Byte);
        assert_eq!(faults.fs.error_permille, 111);
        assert_eq!(faults.fs.short_permille, 222);
        assert_eq!(faults.net.latency_nanos, 500);

        // Explicit knobs that MATCH the recording are accepted.
        let matching = RuntimeConfig::seeded(0)
            .with_crash_at(CrashOp::Close, 1)
            .with_fs_torn_granularity(TornGranularity::Byte)
            .with_fs_error_permille(111)
            .with_fs_short_permille(222)
            .with_net_latency_nanos(500);
        reconcile_replay_faults(&matching, Some(&stored))
            .unwrap()
            .expect("matching config adopted");

        // Explicit knobs that DIVERGE fail closed before any driver is built.
        let mismatched = RuntimeConfig::seeded(0).with_crash_at(CrashOp::Close, 2);
        assert!(matches!(
            reconcile_replay_faults(&mismatched, Some(&stored)),
            Err(RuntimeError::Config(_))
        ));
    }

    fn exercise(context: &mut Context) -> Result<Vec<u8>, RuntimeError> {
        let entropy = context.entropy_bytes(12)?;
        context.write_file("/state/value", &entropy)?;
        assert_eq!(context.read_file("/state/value")?, entropy);
        context.sleep_for(250)?;
        assert_eq!(context.now(ClockKind::Monotonic)?, 250);
        Ok(entropy)
    }

    /// Drive the scheduler until `worker` completes, parking any other task that
    /// is scheduled first and yielding the worker `yields` times before it runs
    /// to completion. `yields == 0` models a worker whose whole body runs under a
    /// single selection with no scheduling boundary.
    fn run_worker(context: &mut Context, worker: TaskId, yields: u32) {
        let mut remaining = yields;
        loop {
            let selected = context.scheduler_next().unwrap().unwrap();
            if selected == worker {
                if remaining > 0 {
                    remaining -= 1;
                    context.task_yield(worker).unwrap();
                } else {
                    context.task_complete(worker).unwrap();
                    return;
                }
            } else {
                context.task_park(selected, "wait-for-worker").unwrap();
            }
        }
    }

    #[test]
    fn vacuous_worker_that_never_yields_is_flagged() {
        // RED: a spawned worker that runs from first scheduled to completion with
        // zero scheduling boundaries — like a lost-update race on an
        // atomics-only RwLock fast path — must be reported as vacuous.
        let mut context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
        let _main = context.task_spawn("main").unwrap();
        let worker = context.task_spawn("worker").unwrap();
        run_worker(&mut context, worker, 0);

        let diagnostics = context.schedule_diagnostics();
        assert!(diagnostics.had_concurrency());
        assert_eq!(diagnostics.vacuous, vec![worker]);
        let stat = diagnostics
            .tasks
            .iter()
            .find(|stat| stat.task == worker)
            .expect("worker recorded");
        assert_eq!(stat.boundaries, 0);
        assert!(stat.vacuous);
    }

    #[test]
    fn worker_that_passes_a_boundary_is_not_flagged() {
        // GREEN: a worker that clears the scaffolding floor with real scheduling
        // boundaries — like the `deadlock` mode's interposed mutex loop, which
        // yields on every lock/unlock — is explorable and must NOT be flagged.
        let mut context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
        let _main = context.task_spawn("main").unwrap();
        let worker = context.task_spawn("worker").unwrap();
        run_worker(&mut context, worker, SCAFFOLDING_YIELD_FLOOR as u32 + 1);

        let diagnostics = context.schedule_diagnostics();
        assert!(diagnostics.had_concurrency());
        assert!(
            diagnostics.vacuous.is_empty(),
            "worker cleared the scaffolding floor; must not be vacuous: {diagnostics:?}"
        );
        let stat = diagnostics
            .tasks
            .iter()
            .find(|stat| stat.task == worker)
            .expect("worker recorded");
        assert!(stat.yields > SCAFFOLDING_YIELD_FLOOR);
        assert!(!stat.vacuous);
    }

    #[test]
    fn single_task_run_reports_no_concurrency() {
        // A run with only the initial task has no schedule to explore, so the
        // diagnostic stays silent.
        let mut context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
        let solo = context.task_spawn("main").unwrap();
        let selected = context.scheduler_next().unwrap().unwrap();
        assert_eq!(selected, solo);
        context.task_complete(solo).unwrap();

        let diagnostics = context.schedule_diagnostics();
        assert!(!diagnostics.had_concurrency());
        assert!(diagnostics.vacuous.is_empty());
    }

    #[test]
    fn task_lifetime_and_completion_cause_are_annotated() {
        // A joined worker is reported `Completed` with a positive lifetime (it
        // spans at least its own spawn->complete steps); the initial thread of
        // control, still live at run end, is reported `LiveAtExit`.
        let mut context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
        let main = context.task_spawn("main").unwrap();
        let worker = context.task_spawn("worker").unwrap();
        run_worker(&mut context, worker, 2);

        let diagnostics = context.schedule_diagnostics();
        let worker_stat = diagnostics
            .tasks
            .iter()
            .find(|stat| stat.task == worker)
            .expect("worker recorded");
        assert_eq!(worker_stat.cause, TaskCompletionCause::Completed);
        assert!(
            worker_stat.lifetime > 0,
            "a completed worker spans at least one scheduling step: {worker_stat:?}"
        );

        let main_stat = diagnostics
            .tasks
            .iter()
            .find(|stat| stat.task == main)
            .expect("main recorded");
        assert_eq!(main_stat.cause, TaskCompletionCause::LiveAtExit);
    }

    #[test]
    fn same_seed_repeats_and_different_seed_varies() {
        let mut first = Context::from_config(RuntimeConfig::seeded(7)).unwrap();
        let first_result = exercise(&mut first).unwrap();
        first.finish().unwrap();

        let mut second = Context::from_config(RuntimeConfig::seeded(7)).unwrap();
        let second_result = exercise(&mut second).unwrap();
        second.finish().unwrap();

        let mut different = Context::from_config(RuntimeConfig::seeded(8)).unwrap();
        let different_result = exercise(&mut different).unwrap();
        different.finish().unwrap();

        assert_eq!(first_result, second_result);
        assert_ne!(first_result, different_result);
    }

    #[test]
    fn record_and_replay_cover_all_initial_effects() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("run.patina");
        let mut record =
            Context::from_config(RuntimeConfig::record(99, &path, "fixture-v1")).unwrap();
        let expected = exercise(&mut record).unwrap();
        record.finish().unwrap();

        let mut replay = Context::from_config(RuntimeConfig::replay(&path, "fixture-v1")).unwrap();
        assert_eq!(replay.root_seed(), 99);
        assert_eq!(exercise(&mut replay).unwrap(), expected);
        replay.finish().unwrap();
    }

    #[derive(Clone, Default)]
    struct SharedTransport {
        bytes: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    }

    impl SharedTransport {
        fn stored(&self) -> Vec<u8> {
            self.bytes.lock().unwrap().clone()
        }
    }

    impl TraceTransport for SharedTransport {
        fn read_bundle(&mut self) -> std::io::Result<Vec<u8>> {
            Ok(self.stored())
        }

        fn write_bundle(&mut self, bytes: &[u8]) -> std::io::Result<()> {
            *self.bytes.lock().unwrap() = bytes.to_vec();
            Ok(())
        }
    }

    #[test]
    fn trace_transport_records_and_replays_without_paths() {
        let transport = SharedTransport::default();
        let mut record = RuntimeBuilder::new(RuntimeConfig::record_transport(99, "fixture-v1"))
            .with_default_drivers()
            .with_trace_transport(transport.clone())
            .build()
            .unwrap();
        let expected = exercise(&mut record).unwrap();
        record.finish().unwrap();
        assert!(!transport.stored().is_empty());

        let mut replay = RuntimeBuilder::new(RuntimeConfig::replay_transport_timeline(
            "main",
            "fixture-v1",
        ))
        .with_default_drivers()
        .with_trace_transport(transport.clone())
        .build()
        .unwrap();
        assert_eq!(replay.root_seed(), 99);
        assert_eq!(exercise(&mut replay).unwrap(), expected);
        replay.finish().unwrap();

        let unconsumed = RuntimeBuilder::new(RuntimeConfig::replay_transport_timeline(
            "main",
            "fixture-v1",
        ))
        .with_default_drivers()
        .with_trace_transport(transport)
        .build()
        .unwrap();
        assert!(matches!(
            unconsumed.finish(),
            Err(RuntimeError::Trace(TraceError::UnconsumedEvents { .. }))
        ));
    }

    #[test]
    fn trace_transport_configuration_fails_loudly() {
        assert!(matches!(
            RuntimeBuilder::new(RuntimeConfig::record_transport(1, "fixture-v1"))
                .with_default_drivers()
                .build(),
            Err(RuntimeError::Config(_))
        ));
        assert!(matches!(
            RuntimeBuilder::new(RuntimeConfig::seeded(1))
                .with_default_drivers()
                .with_trace_transport(SharedTransport::default())
                .build(),
            Err(RuntimeError::Config(_))
        ));
    }

    #[test]
    fn replay_rejects_changed_operations_and_unconsumed_events() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("run.patina");
        let mut record =
            Context::from_config(RuntimeConfig::record(1, &path, "fixture-v1")).unwrap();
        record.entropy_bytes(4).unwrap();
        record.finish().unwrap();

        let mut changed = Context::from_config(RuntimeConfig::replay(&path, "fixture-v1")).unwrap();
        assert!(matches!(
            changed.entropy_bytes(5),
            Err(RuntimeError::Trace(TraceError::OperationMismatch { .. }))
        ));

        let untouched = Context::from_config(RuntimeConfig::replay(&path, "fixture-v1")).unwrap();
        assert!(matches!(
            untouched.finish(),
            Err(RuntimeError::Trace(TraceError::UnconsumedEvents { .. }))
        ));
    }

    #[test]
    fn record_mode_rejects_concurrent_and_existing_trace_writers() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("run.patina");
        let first = Context::from_config(RuntimeConfig::record(1, &path, "fixture-v1")).unwrap();
        assert!(matches!(
            Context::from_config(RuntimeConfig::record(1, &path, "fixture-v1")),
            Err(RuntimeError::Io { .. })
        ));
        drop(first);

        Context::from_config(RuntimeConfig::record(1, &path, "fixture-v1"))
            .unwrap()
            .finish()
            .unwrap();
        assert!(matches!(
            Context::from_config(RuntimeConfig::record(1, &path, "fixture-v1")),
            Err(RuntimeError::Config(message)) if message.contains("refusing to overwrite")
        ));
    }

    #[test]
    fn replay_rejects_a_changed_fingerprint() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("run.patina");
        Context::from_config(RuntimeConfig::record(1, &path, "fixture-v1"))
            .unwrap()
            .finish()
            .unwrap();
        assert!(matches!(
            Context::from_config(RuntimeConfig::replay(&path, "fixture-v2")),
            Err(RuntimeError::Trace(TraceError::FingerprintMismatch { .. }))
        ));
    }

    #[test]
    fn record_and_replay_cross_scheduler_network_clock_and_filesystem() {
        fn simulation(context: &mut Context) -> Result<(TaskId, Vec<u8>), RuntimeError> {
            let first = context.task_spawn("first")?;
            context.task_spawn("second")?;
            let selected = context.scheduler_next()?.expect("tasks are runnable");
            context.task_yield(selected)?;

            let left = context.net_bind("left")?;
            let right = context.net_bind("right")?;
            context.net_send(left, "right", b"packet")?;
            let packet = context
                .net_recv(right)?
                .expect("zero-latency packet is ready");
            context.write_file("/state/packet", &packet.bytes)?;
            context.net_close(left)?;
            context.net_close(right)?;
            assert_eq!(first, TaskId(1));
            Ok((selected, context.read_file("/state/packet")?))
        }

        let directory = tempdir().unwrap();
        let path = directory.path().join("simulation.patina");
        let mut record =
            Context::from_config(RuntimeConfig::record(77, &path, "simulation-v1")).unwrap();
        let expected = simulation(&mut record).unwrap();
        record.finish().unwrap();

        let mut replay =
            Context::from_config(RuntimeConfig::replay(&path, "simulation-v1")).unwrap();
        assert_eq!(simulation(&mut replay).unwrap(), expected);
        replay.finish().unwrap();
    }

    #[test]
    fn tcp_operations_record_and_replay_byte_identically() {
        fn simulation(context: &mut Context) -> Result<(String, Vec<u8>, Vec<u8>), RuntimeError> {
            let listener = context.net_tcp_listen("server", 2)?;
            let client = context.net_tcp_connect("client", "server")?;
            let accepted = context
                .net_tcp_accept(listener)?
                .expect("connect queued an accept");
            context.net_tcp_send(client, b"ping")?;
            context.net_tcp_send(accepted.socket, b"pong")?;
            context.net_tcp_shutdown(client, ShutdownHow::Write)?;
            let request = context.net_tcp_recv(accepted.socket, 16)?.unwrap();
            let eof = context.net_tcp_recv(accepted.socket, 16)?.unwrap();
            let reply = context.net_tcp_recv(client, 16)?.unwrap();
            context.net_close(client)?;
            context.net_close(accepted.socket)?;
            context.net_close(listener)?;
            Ok((accepted.peer, request, [eof, reply].concat()))
        }

        let directory = tempdir().unwrap();
        let path = directory.path().join("tcp.patina");
        let mut record = Context::from_config(RuntimeConfig::record(10, &path, "tcp-v1")).unwrap();
        let expected = simulation(&mut record).unwrap();
        record.finish().unwrap();

        let mut replay = Context::from_config(RuntimeConfig::replay(&path, "tcp-v1")).unwrap();
        assert_eq!(simulation(&mut replay).unwrap(), expected);
        replay.finish().unwrap();
    }

    #[test]
    fn tcp_replay_rejects_a_divergent_payload() {
        fn program(context: &mut Context, bytes: &[u8]) -> Result<(), RuntimeError> {
            let listener = context.net_tcp_listen("server", 1)?;
            let client = context.net_tcp_connect("client", "server")?;
            let accepted = context.net_tcp_accept(listener)?.unwrap();
            context.net_tcp_send(client, bytes)?;
            context.net_close(client)?;
            context.net_close(accepted.socket)?;
            context.net_close(listener)
        }

        let directory = tempdir().unwrap();
        let path = directory.path().join("tcp-divergent.patina");
        let mut record = Context::from_config(RuntimeConfig::record(11, &path, "tcp-v1")).unwrap();
        program(&mut record, b"same").unwrap();
        record.finish().unwrap();

        let mut replay = Context::from_config(RuntimeConfig::replay(&path, "tcp-v1")).unwrap();
        assert!(matches!(
            program(&mut replay, b"different"),
            Err(RuntimeError::Trace(TraceError::OperationMismatch { .. }))
        ));
    }

    #[test]
    fn tcp_blocking_pattern_parks_and_wakes_deterministically() {
        fn program(context: &mut Context) -> Result<(TaskId, TaskId, String), RuntimeError> {
            let acceptor_task = context.task_spawn("acceptor")?;
            let connector_task = context.task_spawn("connector")?;
            let selected = context.scheduler_next()?.expect("a task is runnable");
            let listener = context.net_tcp_listen("server", 1)?;
            assert!(context.net_tcp_accept(listener)?.is_none());
            context.task_park(selected, "tcp-accept")?;
            let client = context.net_tcp_connect("client", "server")?;
            context.task_wake(selected)?;
            let accepted = context.net_tcp_accept(listener)?.unwrap();
            context.net_close(client)?;
            context.net_close(accepted.socket)?;
            context.net_close(listener)?;
            Ok((acceptor_task, connector_task, accepted.peer))
        }

        let directory = tempdir().unwrap();
        let path = directory.path().join("tcp-park.patina");
        let mut record = Context::from_config(RuntimeConfig::record(12, &path, "tcp-v1")).unwrap();
        let expected = program(&mut record).unwrap();
        record.finish().unwrap();

        let mut replay = Context::from_config(RuntimeConfig::replay(&path, "tcp-v1")).unwrap();
        assert_eq!(program(&mut replay).unwrap(), expected);
        replay.finish().unwrap();
    }

    #[test]
    fn branch_replays_the_prefix_and_uses_a_new_seed_for_the_suffix() {
        fn two_decisions(context: &mut Context) -> Result<(Vec<u8>, Vec<u8>), RuntimeError> {
            Ok((context.entropy_bytes(8)?, context.entropy_bytes(8)?))
        }

        let directory = tempdir().unwrap();
        let path = directory.path().join("branches.patina");
        let mut record =
            Context::from_config(RuntimeConfig::record(7, &path, "branches-v1")).unwrap();
        let main = two_decisions(&mut record).unwrap();
        record.finish().unwrap();

        let mut branch = Context::from_config(RuntimeConfig::branch(
            &path,
            "main",
            1,
            "branch-99",
            99,
            "branches-v1",
        ))
        .unwrap();
        let branched = two_decisions(&mut branch).unwrap();
        branch.finish().unwrap();
        assert_eq!(branched.0, main.0, "the prefix must replay exactly");
        assert_ne!(branched.1, main.1, "the suffix must use the branch seed");

        let mut replay = Context::from_config(RuntimeConfig::replay_timeline(
            &path,
            "branch-99",
            "branches-v1",
        ))
        .unwrap();
        assert_eq!(two_decisions(&mut replay).unwrap(), branched);
        replay.finish().unwrap();
    }

    #[test]
    fn guest_argv_env_parses_a_json_array_and_fails_closed_on_garbage() {
        // A JSON string array sets the recorded argv, preserving order; an empty
        // array is a valid zero-argument recording distinct from absence.
        fn map(value: &'static str) -> impl Fn(&str) -> Option<String> {
            move |name: &str| (name == ENV_GUEST_ARGV).then(|| value.to_string())
        }
        let config = RuntimeConfig::record(0, "/trace", "fp")
            .apply_guest_argv_env(map(r#"["--tick-millis","50"]"#))
            .unwrap();
        assert_eq!(
            config.guest_argv(),
            Some(["--tick-millis".to_string(), "50".to_string()].as_slice())
        );
        let empty = RuntimeConfig::record(0, "/trace", "fp")
            .apply_guest_argv_env(map("[]"))
            .unwrap();
        assert_eq!(empty.guest_argv(), Some([].as_slice()));

        // Absent variable leaves argv unset (no behavior change).
        let unset = RuntimeConfig::record(0, "/trace", "fp")
            .apply_guest_argv_env(|_| None)
            .unwrap();
        assert_eq!(unset.guest_argv(), None);

        // Malformed JSON is rejected fail-closed rather than silently dropped.
        let error = RuntimeConfig::record(0, "/trace", "fp")
            .apply_guest_argv_env(map("not json"))
            .unwrap_err();
        assert!(matches!(error, RuntimeError::Config(_)), "{error:?}");
    }

    #[test]
    fn guest_env_env_parses_validates_and_reconciles_trace_metadata() {
        fn map(value: &'static str) -> impl Fn(&str) -> Option<String> {
            move |name: &str| (name == ENV_GUEST_ENV).then(|| value.to_string())
        }

        let config = RuntimeConfig::record(0, "/trace", "fp")
            .apply_guest_env_env(map(r#"{"RUST_LOG":"debug","MODE":"test"}"#))
            .unwrap();
        assert_eq!(config.guest_env()["RUST_LOG"], "debug");
        assert_eq!(config.guest_env()["MODE"], "test");

        let empty = RuntimeConfig::record(0, "/trace", "fp")
            .apply_guest_env_env(map("{}"))
            .unwrap();
        assert!(empty.guest_env().is_empty());

        let invalid = RuntimeConfig::record(0, "/trace", "fp")
            .apply_guest_env_env(map(r#"{"":"value"}"#))
            .unwrap_err();
        assert!(matches!(invalid, RuntimeError::Config(_)), "{invalid:?}");

        let stored = BTreeMap::from([("RUST_LOG".to_string(), "debug".to_string())]);
        let adopted = reconcile_replay_guest_env(&RuntimeConfig::seeded(0), Some(&stored))
            .unwrap()
            .unwrap();
        assert_eq!(adopted, stored);
        reconcile_replay_guest_env(
            &RuntimeConfig::seeded(0).with_guest_env(stored.clone()),
            Some(&stored),
        )
        .unwrap();
        let conflict = RuntimeConfig::seeded(0).with_guest_env(BTreeMap::from([(
            "RUST_LOG".to_string(),
            "trace".to_string(),
        )]));
        assert!(reconcile_replay_guest_env(&conflict, Some(&stored)).is_err());
    }

    // Guest-driven env mutation is a deterministic in-process operation, so the
    // context exposes it directly. It must honor POSIX's overwrite flag, hold the
    // same key/value invariant the startup path validates, and — critically —
    // leave the recorded startup map alone: the trace metadata is built from the
    // config, so a guest that rewrites its environment must not rewrite history.
    #[test]
    fn guest_env_mutation_follows_posix_and_leaves_the_recorded_startup_map_alone() {
        let startup = BTreeMap::from([("SEEDED".to_string(), "from-flag".to_string())]);
        let config = RuntimeConfig::seeded(1).with_guest_env(startup.clone());
        let mut context = Context::from_config(config.clone()).unwrap();
        assert_eq!(context.guest_env_var("SEEDED"), Some("from-flag"));

        assert!(context.guest_env_set("ALPHA", "one", true).unwrap());
        assert_eq!(context.guest_env_var("ALPHA"), Some("one"));
        // overwrite=false leaves an existing key alone and reports no change.
        assert!(!context.guest_env_set("ALPHA", "ignored", false).unwrap());
        assert_eq!(context.guest_env_var("ALPHA"), Some("one"));
        assert!(context.guest_env_set("ALPHA", "two", true).unwrap());
        // Rewriting a key to its current value is not a change.
        assert!(!context.guest_env_set("ALPHA", "two", true).unwrap());
        // A guest overwrite of a startup key wins for the rest of the run.
        assert!(context.guest_env_set("SEEDED", "replaced", true).unwrap());
        assert_eq!(
            context.guest_env(),
            &BTreeMap::from([
                ("ALPHA".to_string(), "two".to_string()),
                ("SEEDED".to_string(), "replaced".to_string()),
            ])
        );

        // The startup invariant holds for mutations too, so a set can never
        // install an entry the startup validator would have rejected.
        assert!(context.guest_env_set("", "x", true).is_err());
        assert!(context.guest_env_set("BAD=NAME", "x", true).is_err());
        assert!(context.guest_env_set("NUL\0KEY", "x", true).is_err());
        assert!(context.guest_env_set("OK", "NUL\0VALUE", true).is_err());
        assert!(context.guest_env_remove("BAD=NAME").is_err());

        // Removing an absent key succeeds and reports no change (POSIX).
        assert!(!context.guest_env_remove("NEVER_SET").unwrap());
        assert!(context.guest_env_remove("ALPHA").unwrap());
        assert_eq!(context.guest_env_var("ALPHA"), None);
        assert!(context.guest_env_clear());
        assert!(context.guest_env().is_empty());
        assert!(!context.guest_env_clear());

        // The trace metadata is derived from the config, so none of the above
        // reaches the recorded startup map.
        assert_eq!(guest_env_record(&config), Some(startup));
    }

    #[test]
    fn typed_builder_parameters_are_explicit() {
        let config = RuntimeConfig::seeded(1).with_param("zone", "a").unwrap();
        let context = Context::from_config(config).unwrap();
        assert_eq!(context.param("zone"), Some("a"));
        assert_eq!(context.param("missing"), None);
    }

    #[test]
    fn step_budget_stops_before_an_unrecorded_boundary_operation() {
        let mut context =
            Context::from_config(RuntimeConfig::seeded(1).with_step_budget(2)).unwrap();
        context.entropy_bytes(1).unwrap();
        context.now(ClockKind::Monotonic).unwrap();
        assert_eq!(context.steps(), 2);
        assert!(matches!(
            context.entropy_bytes(1),
            Err(RuntimeError::StepBudgetExceeded { budget: 2 })
        ));
        assert_eq!(context.steps(), 2);
    }

    #[test]
    fn missing_drivers_fail_without_fallback() {
        let mut context = RuntimeBuilder::new(RuntimeConfig::seeded(1))
            .build()
            .unwrap();
        let error = context.entropy_bytes(1).unwrap_err();
        assert!(matches!(
            error,
            RuntimeError::Effect(EffectError {
                code: ErrorCode::MissingDriver,
                ..
            })
        ));
    }

    struct WrongHandleFs;

    impl FsDriver for WrongHandleFs {
        fn open(&mut self, _path: &str, _flags: OpenFlags) -> Result<Fd, EffectError> {
            Ok(Fd(999))
        }

        fn read(&mut self, _fd: Fd, _max_len: usize) -> Result<Vec<u8>, EffectError> {
            unreachable!()
        }

        fn write(&mut self, _fd: Fd, _bytes: &[u8]) -> Result<usize, EffectError> {
            unreachable!()
        }

        fn close(&mut self, _fd: Fd) -> Result<(), EffectError> {
            unreachable!()
        }
    }

    #[test]
    fn fs_dup_records_replays_and_reconciles_handle_identity() {
        fn exercise_dup(context: &mut Context) -> Result<Vec<u8>, RuntimeError> {
            let write = context.fs_open("/value", OpenFlags::create_truncate_write())?;
            context.fs_write(write, b"abcdef")?;
            context.fs_close(write)?;
            let first = context.fs_open("/value", OpenFlags::read_only())?;
            let second = context.fs_dup(first)?;
            assert_eq!(second, Fd(first.0 + 1));
            context.fs_seek(second, 1, SeekWhence::Start)?;
            let bytes = context.fs_read(first, 2)?;
            context.fs_close(first)?;
            context.fs_close(second)?;
            Ok(bytes)
        }

        let directory = tempdir().unwrap();
        let trace = directory.path().join("dup.patina");
        let mut record = Context::from_config(RuntimeConfig::record(11, &trace, "dup-v1")).unwrap();
        assert_eq!(exercise_dup(&mut record).unwrap(), b"bc");
        record.finish().unwrap();

        let mut replay = Context::from_config(RuntimeConfig::replay(&trace, "dup-v1")).unwrap();
        assert_eq!(exercise_dup(&mut replay).unwrap(), b"bc");
        replay.finish().unwrap();

        let mut tampered = TraceBundle::load(&trace).unwrap();
        for event in &mut tampered.timelines[0].decisions {
            if matches!(event.operation, Operation::FsDup { .. }) {
                event.outcome = Outcome::Handle(Fd(999));
                break;
            }
        }
        let tampered_path = directory.path().join("dup-tampered.patina");
        tampered.write_atomic(&tampered_path).unwrap();
        let mut replay =
            Context::from_config(RuntimeConfig::replay(&tampered_path, "dup-v1")).unwrap();
        let error = exercise_dup(&mut replay).unwrap_err();
        assert!(matches!(
            error,
            RuntimeError::Trace(TraceError::OutcomeMismatch { .. })
        ));
    }

    #[test]
    fn captured_host_files_replay_without_host_access_and_fail_on_branch_miss() {
        let directory = tempdir().unwrap();
        let host = directory.path().join("host");
        std::fs::create_dir(&host).unwrap();
        std::fs::write(host.join("value"), b"captured").unwrap();
        let trace = directory.path().join("capture.patina");

        let config = RuntimeConfig::record(3, &trace, "capture-v1");
        let mut record = RuntimeBuilder::new(config)
            .with_captured_filesystem(HostCaptureFs::new("/fixtures", &host).unwrap())
            .build()
            .unwrap();
        let fd = record
            .fs_open("/fixtures/value", OpenFlags::read_only())
            .unwrap();
        assert_eq!(record.fs_read(fd, 32).unwrap(), b"captured");
        record.fs_close(fd).unwrap();
        record.finish().unwrap();

        std::fs::remove_file(host.join("value")).unwrap();
        let config = RuntimeConfig::replay(&trace, "capture-v1");
        let mut replay = RuntimeBuilder::new(config)
            .with_captured_filesystem(HostCaptureFs::new("/fixtures", &host).unwrap())
            .build()
            .unwrap();
        let fd = replay
            .fs_open("/fixtures/value", OpenFlags::read_only())
            .unwrap();
        assert_eq!(replay.fs_read(fd, 32).unwrap(), b"captured");
        replay.fs_close(fd).unwrap();
        replay.finish().unwrap();

        let config = RuntimeConfig::branch(&trace, "main", 1, "capture-miss", 4, "capture-v1");
        let mut branch = RuntimeBuilder::new(config)
            .with_captured_filesystem(HostCaptureFs::new("/fixtures", &host).unwrap())
            .build()
            .unwrap();
        let fd = branch
            .fs_open("/fixtures/value", OpenFlags::read_only())
            .unwrap();
        assert!(matches!(
            branch.fs_read(fd, 32),
            Err(RuntimeError::Effect(EffectError {
                code: ErrorCode::Denied,
                ..
            }))
        ));
    }

    #[test]
    fn crash_filesystem_record_and_replay_restore_the_synced_checkpoint() {
        fn exercise(context: &mut Context) -> Result<Vec<u8>, RuntimeError> {
            let fd = context.fs_open("/state", OpenFlags::create_truncate_write())?;
            context.fs_write(fd, b"stable")?;
            context.fs_sync(fd)?;
            let dir = context.fs_open("/", OpenFlags::read_only())?;
            context.fs_sync(dir)?;
            context.fs_close(dir)?;
            context.fs_write(fd, b"-volatile")?;
            context.fs_crash()?;
            assert!(matches!(
                context.fs_write(fd, b"stale"),
                Err(RuntimeError::Effect(EffectError {
                    code: ErrorCode::InvalidHandle,
                    ..
                }))
            ));
            context.read_file("/state")
        }

        let directory = tempdir().unwrap();
        let trace = directory.path().join("crash.patina");
        let config = RuntimeConfig::record(71, &trace, "crash-v1");
        let mut record = RuntimeBuilder::new(config)
            .with_default_drivers()
            .with_filesystem(CrashFs::default())
            .build()
            .unwrap();
        assert_eq!(exercise(&mut record).unwrap(), b"stable");
        record.finish().unwrap();

        let config = RuntimeConfig::replay(&trace, "crash-v1");
        let mut replay = RuntimeBuilder::new(config)
            .with_default_drivers()
            .with_filesystem(CrashFs::default())
            .build()
            .unwrap();
        assert_eq!(exercise(&mut replay).unwrap(), b"stable");
        replay.finish().unwrap();
    }

    #[test]
    fn crash_torn_writes_record_and_replay_reproduce_the_same_image() {
        fn crash_fs() -> CrashFs {
            CrashFs::builder()
                .seed(9)
                .torn_write_granularity(2)
                .torn_write_probability(0.5)
                .build()
                .unwrap()
        }

        fn exercise(context: &mut Context) -> Result<Vec<u8>, RuntimeError> {
            let fd = context.fs_open("/log", OpenFlags::create_truncate_write())?;
            context.fs_write(fd, b"AAAAAAAA")?;
            context.fs_sync(fd)?;
            let dir = context.fs_open("/", OpenFlags::read_only())?;
            context.fs_sync(dir)?;
            context.fs_close(dir)?;
            context.fs_seek(fd, 0, SeekWhence::Start)?;
            context.fs_write(fd, b"BBBBBBBB")?;
            context.fs_crash()?;
            // The pre-crash handle is stale after the modeled restart.
            assert!(matches!(
                context.fs_write(fd, b"stale"),
                Err(RuntimeError::Effect(EffectError {
                    code: ErrorCode::InvalidHandle,
                    ..
                }))
            ));
            context.read_file("/log")
        }

        let directory = tempdir().unwrap();
        let trace = directory.path().join("torn.patina");
        let config = RuntimeConfig::record(3, &trace, "crash-torn-v1");
        let mut record = RuntimeBuilder::new(config)
            .with_default_drivers()
            .with_filesystem(crash_fs())
            .build()
            .unwrap();
        let recorded = exercise(&mut record).unwrap();
        record.finish().unwrap();

        // The seeded tear is a real per-block mix, not a whole-image outcome.
        assert_eq!(recorded.len(), 8);
        assert!(
            recorded
                .chunks(2)
                .all(|block| block == b"AA" || block == b"BB")
        );
        assert!(recorded.chunks(2).any(|block| block == b"AA"));
        assert!(recorded.chunks(2).any(|block| block == b"BB"));

        let config = RuntimeConfig::replay(&trace, "crash-torn-v1");
        let mut replay = RuntimeBuilder::new(config)
            .with_default_drivers()
            .with_filesystem(crash_fs())
            .build()
            .unwrap();
        assert_eq!(exercise(&mut replay).unwrap(), recorded);
        replay.finish().unwrap();
    }

    // Structural guard for the "parsed fault knob silently ignored because a
    // pre-installed filesystem bypassed the config" gap class: an explicit
    // filesystem MUST NOT coexist with config-driven crash knobs. `build` fails
    // closed instead of dropping them. (The historical bug installed a default
    // CrashFs and let `--fs-torn-granularity byte` be silently ignored.)
    #[test]
    fn explicit_filesystem_with_crash_knobs_fails_closed() {
        // `Context` is not `Debug`, so assert on the Result shape directly.
        // Explicit filesystem + a crash point -> refuse.
        let result = RuntimeBuilder::new(RuntimeConfig::seeded(1).with_crash_at(CrashOp::Write, 1))
            .with_default_drivers()
            .with_filesystem(CrashFs::default())
            .build();
        assert!(matches!(result, Err(RuntimeError::Config(_))));

        // Explicit filesystem + a non-default torn granularity -> refuse, even
        // with no crash point, because the granularity would be dropped.
        let result = RuntimeBuilder::new(
            RuntimeConfig::seeded(1).with_fs_torn_granularity(TornGranularity::Byte),
        )
        .with_default_drivers()
        .with_filesystem(CrashFs::default())
        .build();
        assert!(matches!(result, Err(RuntimeError::Config(_))));

        // An explicit filesystem with NO crash knobs is still fine (tests /
        // embedders that drive `fs_crash` manually).
        assert!(
            RuntimeBuilder::new(RuntimeConfig::seeded(1))
                .with_default_drivers()
                .with_filesystem(CrashFs::default())
                .build()
                .is_ok()
        );

        // Supplying both a base image and an explicit filesystem is ambiguous.
        let result = RuntimeBuilder::new(RuntimeConfig::seeded(1))
            .with_default_drivers()
            .with_filesystem(MemFs::new())
            .with_fs_image(MemFs::new())
            .build();
        assert!(matches!(result, Err(RuntimeError::Config(_))));
    }

    // The single choke point builds the crash filesystem from the fault config:
    // a base image + `--fs-crash-at` + `--fs-torn-granularity byte` yields a
    // sub-block partial tear, while the default (block) granularity reverts the
    // final write wholesale. This is the runtime-level guarantee the shim relies
    // on instead of constructing the CrashFs itself.
    #[test]
    fn fs_image_choke_point_honors_configured_torn_granularity() {
        fn recovered_image(granularity: TornGranularity) -> Vec<u8> {
            let mut config = RuntimeConfig::seeded(1).with_crash_at(CrashOp::Write, 2);
            if granularity == TornGranularity::Byte {
                config = config.with_fs_torn_granularity(TornGranularity::Byte);
            }
            let mut context = RuntimeBuilder::new(config)
                .with_default_drivers()
                .with_fs_image(MemFs::new())
                .build()
                .unwrap();
            // Durable baseline, then one unsynced overwrite (crash fires after
            // this second write), then read the recovered image.
            let fd = context
                .fs_open("/f", OpenFlags::create_truncate_write())
                .unwrap();
            context.fs_write_at(fd, 0, &[b'A'; 16]).unwrap(); // write 1
            context.fs_sync(fd).unwrap();
            let dir = context.fs_open("/", OpenFlags::read_only()).unwrap();
            context.fs_sync(dir).unwrap();
            context.fs_close(dir).unwrap();
            let _ = context.fs_write_at(fd, 0, &[b'B'; 16]); // write 2 -> crash
            context.read_file("/f").unwrap_or_default()
        }

        let block = recovered_image(TornGranularity::Block);
        let byte = recovered_image(TornGranularity::Byte);
        assert_eq!(
            block,
            vec![b'A'; 16],
            "block granularity should revert wholesale"
        );
        assert_ne!(
            byte, block,
            "byte granularity should not match the block revert"
        );
        assert!(
            byte.contains(&b'B') && byte.contains(&b'A'),
            "byte granularity should leave a partial live/durable mix: {byte:?}"
        );
    }

    // Regression for two bugs the shim/WASI paths hit, both via
    // `with_default_drivers` WITHOUT `with_fs_image` (exactly what
    // `Context::from_config` — the WASI `wasi-run` path — does), knob-free:
    //   (a) the choke point used `MemFs::default()` as the base, which is
    //       ROOTLESS (no `/`), so every path op (create_dir/open) failed with
    //       NotFound; it must use `MemFs::new()`.
    //   (b) a bare `MemFs` cannot crash — `crash()` returns `InvalidState`
    //       (errno 13) — so imperative `fs_crash()` callers broke; the base must
    //       be wrapped in a `CrashFs`.
    // This single test exercises both: a rooted directory/file op AND a manual
    // crash with no `--fs-crash-at` configured.
    #[test]
    fn context_from_config_filesystem_is_rooted_and_crashable() {
        let mut context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
        // (a) Rooted: create a directory and a file under `/`, write, sync.
        context.fs_create_directory("/state").unwrap();
        let root = context.fs_open("/", OpenFlags::read_only()).unwrap();
        context.fs_sync(root).unwrap();
        context.fs_close(root).unwrap();
        let fd = context
            .fs_open("/state/value", OpenFlags::create_truncate_write())
            .unwrap();
        context.fs_write_at(fd, 0, b"durable").unwrap();
        context.fs_sync(fd).unwrap();
        let state = context.fs_open("/state", OpenFlags::read_only()).unwrap();
        context.fs_sync(state).unwrap();
        context.fs_close(state).unwrap();
        context.fs_write_at(fd, 0, b"volatile").unwrap(); // unsynced overwrite
        // (b) Crashable: an imperative crash with NO crash_at must succeed and
        // drop the unsynced overwrite back to the durable bytes.
        context
            .fs_crash()
            .expect("imperative fs_crash must succeed");
        assert_eq!(context.read_file("/state/value").unwrap(), b"durable");
    }

    /// Drive the runtime the way the shim does: spawn two tasks, park each with
    /// a virtual-clock deadline, then let `scheduler_next` rescue the deadlock by
    /// advancing time and waking the earliest-due task. Returns the observed wake
    /// order and the virtual time at each wake.
    fn timed_rescue(context: &mut Context) -> Result<Vec<(TaskId, u64)>, RuntimeError> {
        let a = context.task_spawn("a")?;
        let b = context.task_spawn("b")?;
        // Park the first-selected task at 200 and the other at 100 so the wake
        // order is determined by deadline, not by spawn or selection order.
        let first = context.scheduler_next()?.expect("a task is runnable");
        context.task_park_timed(first, "wait", ClockKind::Monotonic, 200)?;
        let second = context.scheduler_next()?.expect("a task is runnable");
        context.task_park_timed(second, "wait", ClockKind::Monotonic, 100)?;
        let mut wakes = Vec::new();
        // Both tasks are parked; each `scheduler_next` now rescues in turn.
        for _ in 0..2 {
            let woken = context.scheduler_next()?.expect("a timer wakes a task");
            wakes.push((woken, context.now(ClockKind::Monotonic)?));
            context.task_complete(woken)?;
        }
        assert!(context.scheduler_next()?.is_none());
        let _ = (a, b);
        Ok(wakes)
    }

    #[test]
    fn deadlock_rescue_advances_time_and_wakes_in_deadline_order() {
        let mut context = Context::from_config(RuntimeConfig::seeded(5)).unwrap();
        let wakes = timed_rescue(&mut context).unwrap();
        // The task parked at 100 wakes first at virtual time 100, then the task
        // parked at 200 wakes at 200 — deadline order, not registration order.
        assert_eq!(wakes.len(), 2);
        assert_eq!(wakes[0].1, 100);
        assert_eq!(wakes[1].1, 200);
        assert_ne!(wakes[0].0, wakes[1].0);
        context.finish().unwrap();
    }

    #[test]
    fn deadlock_rescue_records_and_replays_byte_identically() {
        let directory = tempdir().unwrap();
        let first = directory.path().join("timer-a.patina");
        let second = directory.path().join("timer-b.patina");
        for path in [&first, &second] {
            let mut record =
                Context::from_config(RuntimeConfig::record(9, path, "timer-v1")).unwrap();
            timed_rescue(&mut record).unwrap();
            record.finish().unwrap();
        }
        // Two independent record processes with the same seed are byte-identical.
        assert_eq!(fs::read(&first).unwrap(), fs::read(&second).unwrap());

        // Replay consumes every recorded SleepUntil/TaskWake/SchedulerNext event.
        let mut replay = Context::from_config(RuntimeConfig::replay(&first, "timer-v1")).unwrap();
        timed_rescue(&mut replay).unwrap();
        replay.finish().unwrap();
    }

    /// The calibration busy-wait, reduced to its essence: read the monotonic
    /// clock in a loop until `window` nanoseconds of it have gone by, doing
    /// nothing else. This is the shape `fastant`/`minstant`/`quanta` run in a
    /// pre-`main` constructor to measure the timestamp counter, and the shape
    /// that hangs forever without advance-on-spin. Returns (reads, elapsed).
    fn calibration_spin(context: &mut Context, window: u64) -> Result<(u64, u64), RuntimeError> {
        let start = context.now(ClockKind::Monotonic)?;
        let mut reads = 1u64;
        loop {
            let now = context.now(ClockKind::Monotonic)?;
            reads += 1;
            if now - start > window {
                return Ok((reads, now - start));
            }
        }
    }

    #[test]
    fn advance_on_spin_converges_a_clock_busy_wait_in_tens_of_rescues() {
        // RED before advance-on-spin: this call never returns — virtual time only
        // moved through a recorded `SleepUntil`, and the loop issues none.
        let mut context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
        let (reads, elapsed) = calibration_spin(&mut context, 10_000_000).unwrap();

        // The token schedule pinned exactly (1 µs doubling to the 1 ms ceiling):
        // ten escalating rescues sum to 1_023_000 ns, then nine at the ceiling
        // carry the rest — 19 rescues for a 10 ms window, which is the brief's
        // "tens of rescues, not millions of loop iterations".
        assert_eq!(context.spin.rescues, 19);
        assert_eq!(elapsed, 10_023_000);
        assert_eq!(context.spin.advanced_nanos, 10_023_000);
        // Each rescue costs exactly `SPIN_RESCUE_CLOCK_OPS` reads, and the read
        // that observes the escaped deadline is the one that triggers the last.
        assert_eq!(reads, 19 * SPIN_RESCUE_CLOCK_OPS + 1);
        // Trace-size sanity: the recorded stream is one op per read plus one
        // `SleepUntil` per rescue, three orders of magnitude under the cap.
        assert!(reads + context.spin.rescues < patina_dst_trace::MAX_TIMELINE_EVENTS as u64);
        context.finish().unwrap();
    }

    #[test]
    fn advance_on_spin_leaves_virtual_time_alone_below_the_trigger() {
        // The non-vacuity guard for the constant: one read short of the streak
        // must not move the clock by a nanosecond. This is what keeps every
        // existing recorded artifact byte-identical.
        let mut context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
        for _ in 0..SPIN_RESCUE_CLOCK_OPS {
            assert_eq!(context.now(ClockKind::Monotonic).unwrap(), 0);
        }
        assert_eq!(context.spin.rescues, 0);
        // One more read crosses the streak and rescues.
        assert_eq!(
            context.now(ClockKind::Monotonic).unwrap(),
            SPIN_RESCUE_TOKEN_MIN_NANOS
        );
        assert_eq!(context.spin.rescues, 1);
        context.finish().unwrap();
    }

    #[test]
    fn a_progress_op_ends_the_spin_episode_so_a_working_run_never_rescues() {
        // A guest that reads the clock hard but keeps doing real work: the
        // streak is broken by every genuine effect, so it never accumulates and
        // the clock never moves. An unbounded number of reads, zero rescues.
        let mut context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
        for _ in 0..8 {
            for _ in 0..SPIN_RESCUE_CLOCK_OPS {
                assert_eq!(context.now(ClockKind::Monotonic).unwrap(), 0);
            }
            context.write_file("/work", b"x").unwrap();
        }
        assert_eq!(context.spin.rescues, 0);
        assert_eq!(context.now(ClockKind::Monotonic).unwrap(), 0);
        context.finish().unwrap();
    }

    #[test]
    fn a_guest_sleep_ends_the_spin_episode_so_a_polling_loop_never_rescues() {
        // The other reset arm: virtual time moving for a reason the rescue did
        // not cause. A poll loop that sleeps between reads walks the clock on its
        // own and must never be rescued, however many reads it takes.
        let mut context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
        for _ in 0..4 {
            // One short of the streak, leaving room for `sleep_for`'s own
            // clock read: 1023 reads plus that one is exactly at the trigger,
            // not past it.
            for _ in 0..(SPIN_RESCUE_CLOCK_OPS - 1) {
                context.now(ClockKind::Monotonic).unwrap();
            }
            context.sleep_for(1).unwrap();
        }
        assert_eq!(context.spin.rescues, 0);
        // Exactly the four nanoseconds the guest itself slept.
        assert_eq!(context.now(ClockKind::Monotonic).unwrap(), 4);
        context.finish().unwrap();
    }

    #[test]
    fn advance_on_spin_records_and_replays_byte_identically() {
        let directory = tempdir().unwrap();
        let first = directory.path().join("spin-a.patina");
        let second = directory.path().join("spin-b.patina");
        let mut recorded = Vec::new();
        for path in [&first, &second] {
            let mut record =
                Context::from_config(RuntimeConfig::record(9, path, "spin-v1")).unwrap();
            recorded.push(calibration_spin(&mut record, 100_000).unwrap());
            record.finish().unwrap();
        }
        // Same seed, two independent record runs: identical answers and bytes.
        assert_eq!(recorded[0], recorded[1]);
        assert_eq!(recorded[0].0, 7 * SPIN_RESCUE_CLOCK_OPS + 1);
        assert_eq!(fs::read(&first).unwrap(), fs::read(&second).unwrap());

        // Replay consumes the recorded `SleepUntil`/`ClockNow` stream in order:
        // the rescue re-fires at the same point because the spin state is a pure
        // function of that stream, not of anything the record run measured.
        let mut replay = Context::from_config(RuntimeConfig::replay(&first, "spin-v1")).unwrap();
        assert_eq!(calibration_spin(&mut replay, 100_000).unwrap(), recorded[0]);
        replay.finish().unwrap();
    }

    #[test]
    fn frozen_clock_churn_aborts_a_loop_that_ignores_the_clock() {
        // A loop whose exit condition never depends on the clock value it reads:
        // no amount of advancing frees it, so the backstop must name it rather
        // than rescue it forever.
        let mut context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
        let mut reads = 0u64;
        let error = loop {
            match context.now(ClockKind::Monotonic) {
                Ok(_) => reads += 1,
                Err(error) => break error,
            }
        };
        let RuntimeError::FrozenClockChurn { detail } = error else {
            panic!("expected a frozen-clock-churn abort, got {error:?}");
        };
        // The marker rides the established liveness interface contract, so a
        // campaign consumer classifies it without a new rule, and names the
        // pattern and what the guest was doing.
        assert!(detail.starts_with("PATINA_VIOLATION liveness detail=frozen-clock-churn "));
        assert!(detail.contains(&format!("rescues={SPIN_CHURN_ABORT_RESCUES}")));
        // Ten escalating tokens (1_023_000 ns) plus 246 at the 1 ms ceiling.
        assert!(
            detail.contains("advanced_ns=247023000"),
            "marker was: {detail}"
        );
        assert_eq!(context.spin.rescues, SPIN_CHURN_ABORT_RESCUES);
        // The abort fires only once the spin PERSISTS past the last rescue:
        // a full further streak of reads bought nothing.
        assert_eq!(
            reads,
            (SPIN_CHURN_ABORT_RESCUES + 1) * SPIN_RESCUE_CLOCK_OPS
        );
        // The facts document carries the same finding as the line.
        let finding = &context.run_facts()["runtime_findings"][0];
        assert_eq!(finding["detail"], "frozen-clock-churn");
        assert_eq!(finding["rescues"], SPIN_CHURN_ABORT_RESCUES);
    }

    #[test]
    fn the_liveness_watchdog_fires_first_on_a_spin_that_advance_on_spin_feeds() {
        // Before this slice the watchdog structurally could not fire on a clock
        // spin: its no-progress window is measured in virtual nanoseconds, and
        // virtual time did not move. Now the rescue feeds it, so a budget the
        // rescues walk past trips it — and it trips FIRST, long before the
        // frozen-clock backstop's 256 rescues. One mechanism, cleanly.
        let mut context =
            Context::from_config(RuntimeConfig::seeded(1).with_liveness(LivenessConfig {
                no_progress_budget_nanos: Some(5_000),
                converge_budget_nanos: None,
                heal_after_nanos: None,
            }))
            .unwrap();
        let error = loop {
            if let Err(error) = context.now(ClockKind::Monotonic) {
                break error;
            }
        };
        let RuntimeError::Liveness { kind, detail } = error else {
            panic!("expected the liveness watchdog to fire first, got {error:?}");
        };
        assert_eq!(kind, LivenessKind::NoProgress);
        assert!(detail.starts_with("PATINA_VIOLATION liveness detail=no-progress "));
        // Fired at the third rescue (1+2+4 = 7 µs past a 5 µs budget), so the
        // churn backstop was nowhere near its own trigger.
        assert_eq!(context.spin.rescues, 3);
        assert!(context.spin.rescues < SPIN_CHURN_ABORT_RESCUES);
    }

    #[test]
    fn a_step_budget_abort_under_record_leaves_a_loadable_truncated_trace() {
        // The artifact that would explain a wedge is exactly the one a budget
        // abort used to destroy: `finish` is never reached in the interposed
        // families, so the pre-created trace file stayed empty.
        let directory = tempdir().unwrap();
        let path = directory.path().join("budget.patina");
        let mut context =
            Context::from_config(RuntimeConfig::record(4, &path, "budget-v1").with_step_budget(6))
                .unwrap();
        context.write_file("/a", b"one").unwrap();
        context.write_file("/b", b"two").unwrap();
        let error = context
            .write_file("/c", b"three")
            .expect_err("the budget must stop the run");
        assert!(matches!(
            error,
            RuntimeError::StepBudgetExceeded { budget: 6 }
        ));

        // The trace exists, loads, and carries the operations up to the abort —
        // truncated but structurally valid.
        let bundle = TraceBundle::load(&path).expect("the truncated trace must load");
        let events = &bundle.timelines[0].decisions;
        assert_eq!(
            events.len(),
            6,
            "every op performed before the stop is kept"
        );
        assert!(
            events
                .iter()
                .any(|event| matches!(&event.operation, Operation::FsWrite { .. }))
        );
        // `finish` must not write a second bundle over the flushed one.
        context.finish().unwrap();
        assert_eq!(
            TraceBundle::load(&path).unwrap().timelines,
            bundle.timelines
        );
    }

    #[test]
    fn realtime_deadlines_convert_through_the_clock_epoch() {
        // A clock whose realtime epoch is 1_000ns ahead of monotonic: a realtime
        // deadline of 1_150 must register (and rescue-advance) at monotonic 150.
        let mut context = RuntimeBuilder::new(RuntimeConfig::seeded(1))
            .with_default_drivers()
            .with_clock(VirtualClock::new(1_000))
            .build()
            .unwrap();
        let task = context.task_spawn("sleeper").unwrap();
        let running = context.scheduler_next().unwrap().unwrap();
        assert_eq!(running, task);
        context
            .task_park_timed(task, "sleep", ClockKind::Realtime, 1_150)
            .unwrap();
        let woken = context.scheduler_next().unwrap().unwrap();
        assert_eq!(woken, task);
        assert_eq!(context.now(ClockKind::Monotonic).unwrap(), 150);
        assert_eq!(context.now(ClockKind::Realtime).unwrap(), 1_150);
        context.task_complete(task).unwrap();
        context.finish().unwrap();
    }

    #[test]
    fn an_early_wake_deregisters_the_timer_so_the_rescue_skips_it() {
        let mut context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
        let a = context.task_spawn("a").unwrap();
        let b = context.task_spawn("b").unwrap();
        // `a` parks with an early deadline, then is woken by a "signal" before it
        // fires; only `b`'s later timer should drive a rescue.
        let first = context.scheduler_next().unwrap().unwrap();
        context
            .task_park_timed(first, "wait", ClockKind::Monotonic, 50)
            .unwrap();
        let second = context.scheduler_next().unwrap().unwrap();
        context
            .task_park_timed(second, "wait", ClockKind::Monotonic, 500)
            .unwrap();
        // Signal-wake `first` (deregisters its 50ns timer). It must not be woken
        // again by the rescue, which should advance straight to 500 for `second`.
        context.task_wake(first).unwrap();
        let resumed = context.scheduler_next().unwrap().unwrap();
        assert_eq!(
            resumed, first,
            "the signalled task runs without advancing time"
        );
        assert_eq!(context.now(ClockKind::Monotonic).unwrap(), 0);
        context.task_park(first, "again").unwrap();
        let rescued = context.scheduler_next().unwrap().unwrap();
        assert_eq!(rescued, second);
        assert_eq!(context.now(ClockKind::Monotonic).unwrap(), 500);
        let _ = (a, b);
    }

    #[test]
    fn a_timed_park_with_no_other_runnable_task_rescues_itself() {
        // Single-task program: the sleeper is the only task, so the very next
        // `scheduler_next` deadlocks, the rescue advances time, and it wakes.
        let mut context = Context::from_config(RuntimeConfig::seeded(3)).unwrap();
        let task = context.task_spawn("only").unwrap();
        assert_eq!(context.scheduler_next().unwrap(), Some(task));
        context
            .task_park_timed(task, "sleep", ClockKind::Monotonic, 4_096)
            .unwrap();
        assert_eq!(context.scheduler_next().unwrap(), Some(task));
        assert_eq!(context.now(ClockKind::Monotonic).unwrap(), 4_096);
        assert!(context.take_rescued_timeouts().contains(&task));
        context.task_complete(task).unwrap();
    }

    #[test]
    fn replay_compares_deterministic_driver_outcomes() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("run.patina");
        let mut record =
            Context::from_config(RuntimeConfig::record(1, &path, "fixture-v1")).unwrap();
        record
            .fs_open("/value", OpenFlags::create_truncate_write())
            .unwrap();
        record.finish().unwrap();

        let mut replay = RuntimeBuilder::new(RuntimeConfig::replay(&path, "fixture-v1"))
            .with_filesystem(WrongHandleFs)
            .build()
            .unwrap();
        assert!(matches!(
            replay.fs_open("/value", OpenFlags::create_truncate_write()),
            Err(RuntimeError::Trace(TraceError::OutcomeMismatch { .. }))
        ));
    }

    // -- Liveness watchdog --------------------------------------------------

    #[test]
    fn operation_progress_classification_is_correct() {
        // Pure scheduling/time/wait ops are non-progress; genuine effects are.
        assert!(!operation_is_progress(&Operation::SchedulerNext));
        assert!(!operation_is_progress(&Operation::ClockNow {
            clock: ClockKind::Monotonic
        }));
        assert!(!operation_is_progress(&Operation::SleepUntil {
            clock: ClockKind::Monotonic,
            deadline_nanos: 1
        }));
        assert!(!operation_is_progress(&Operation::TaskParkTimed {
            task: TaskId(1),
            reason: "x".into(),
            deadline_nanos: 1
        }));
        assert!(operation_is_progress(&Operation::FsWrite {
            fd: Fd(1),
            bytes: vec![1]
        }));
        assert!(operation_is_progress(&Operation::TaskComplete {
            task: TaskId(1)
        }));
        assert!(operation_is_progress(&Operation::EntropyFill { len: 4 }));
    }

    #[test]
    fn watchdog_arm_excuses_policy_deferral_windows() {
        // The CRITICAL COUPLING: while the scheduler reports a deliberate
        // deferral, no-progress must NOT accrue toward the budget — a starvation
        // interval or PCT priority deferral is never a liveness violation.
        let mut arm = WatchdogArm {
            kind: LivenessKind::NoProgress,
            arm_time_nanos: 0,
            budget_nanos: 1_000,
            armed: false,
            baseline_nanos: 0,
            stall_ops: 0,
        };
        // Virtual time races far past the budget, but every step is a policy
        // deferral, so the arm never fires and the baseline keeps advancing.
        for now in [500u64, 1_000, 5_000, 50_000, 500_000] {
            assert!(arm.observe(now, false, true).is_none());
        }
        // Once deferral stops, genuine no-progress accrues from the current time
        // and eventually trips the budget.
        assert!(arm.observe(500_500, false, false).is_none()); // stall 1
        assert!(arm.observe(501_000, false, false).is_none()); // stall 2
        assert!(arm.observe(501_400, false, false).is_none()); // stall 3
        // stall 4 and elapsed (501_600-500_000=1_600) > 1_000 -> fire.
        assert!(arm.observe(501_600, false, false).is_some());
    }

    #[test]
    fn watchdog_arm_ignores_a_single_long_but_legitimate_sleep() {
        // One huge no-progress jump (a single legitimate sleep) must not trip the
        // watchdog: only genuine churn (>= LIVENESS_MIN_STALL_OPS non-progress
        // ops) can. A progress op then resets the clock.
        let mut arm = WatchdogArm {
            kind: LivenessKind::NoProgress,
            arm_time_nanos: 0,
            budget_nanos: 1_000,
            armed: false,
            baseline_nanos: 0,
            stall_ops: 0,
        };
        // A single sleep past the budget: only one stall op, below the floor.
        assert!(arm.observe(1_000_000, false, false).is_none());
        // Genuine progress resets.
        assert!(arm.observe(1_000_001, true, false).is_none());
        assert_eq!(arm.stall_ops, 0);
    }

    #[test]
    fn liveness_watchdog_fires_on_virtual_time_no_progress_wedge() {
        // A single-task loop that only advances the virtual clock (sleep) with no
        // genuine effect is a pure-churn wedge: the watchdog fires deterministically
        // rather than letting virtual time march to a step budget silently.
        let mut context =
            Context::from_config(RuntimeConfig::seeded(1).with_liveness(LivenessConfig {
                no_progress_budget_nanos: Some(1_000),
                converge_budget_nanos: None,
                heal_after_nanos: None,
            }))
            .unwrap();
        let mut fired = None;
        for _ in 0..1_000 {
            if let Err(error) = context.sleep_for(500) {
                fired = Some(error);
                break;
            }
        }
        match fired {
            Some(RuntimeError::Liveness { kind, .. }) => {
                assert_eq!(kind, LivenessKind::NoProgress);
            }
            other => panic!("expected a liveness violation, got {other:?}"),
        }
    }

    #[test]
    fn heal_then_converge_only_arms_after_the_fault_window() {
        // The converge arm arms at H (here 5_000 ns) and must not fire before then,
        // even though the guest is already wedged; after H it enforces the
        // convergence budget and fires.
        let mut context =
            Context::from_config(RuntimeConfig::seeded(1).with_liveness(LivenessConfig {
                no_progress_budget_nanos: None,
                converge_budget_nanos: Some(1_000),
                heal_after_nanos: Some(5_000),
            }))
            .unwrap();
        let mut fired_at_iter = None;
        for iteration in 0..1_000 {
            if let Err(RuntimeError::Liveness { kind, .. }) = context.sleep_for(500) {
                assert_eq!(kind, LivenessKind::HealThenConverge);
                fired_at_iter = Some(iteration);
                break;
            }
        }
        // sleep_for advances 500 ns/iteration, so ~10 iterations to reach H=5_000
        // and ~2 more (plus the min-stall floor) before the 1_000 ns budget trips.
        let fired = fired_at_iter.expect("converge watchdog must fire");
        assert!(
            fired >= 10,
            "must not fire before the fault window (H): {fired}"
        );
    }

    #[test]
    fn liveness_watchdog_does_not_fire_on_a_run_that_makes_progress() {
        // A run that keeps doing genuine effects (writes) between sleeps never
        // trips the watchdog: each write resets the no-progress clock.
        let mut context =
            Context::from_config(RuntimeConfig::seeded(1).with_liveness(LivenessConfig {
                no_progress_budget_nanos: Some(1_000),
                converge_budget_nanos: None,
                heal_after_nanos: None,
            }))
            .unwrap();
        for index in 0..50 {
            context
                .write_file(&format!("/f{index}"), b"progress")
                .unwrap();
            context.sleep_for(10_000).unwrap();
        }
        context.finish().unwrap();
    }

    #[test]
    fn liveness_watchdog_is_schedule_invariant_when_no_violation_fires() {
        // The schedule-invariance proof: recording a healthy run with the watchdog
        // enabled produces a byte-identical recorded op stream to recording it
        // without. The watchdog only ADDS a possible report; it never records a
        // boundary op nor perturbs selection. The metadata differs only by the
        // informational (non-fingerprinted) watchdog field.
        let dir = tempdir().unwrap();
        let plain = dir.path().join("plain.patina");
        let watched = dir.path().join("watched.patina");
        let run = |path: &std::path::Path, liveness: LivenessConfig| {
            let mut context = Context::from_config(
                RuntimeConfig::record(7, path, "wd-invariance-v1").with_liveness(liveness),
            )
            .unwrap();
            context.write_file("/f", b"hello").unwrap();
            context.sleep_for(1_000).unwrap();
            let _ = context.read_file("/f").unwrap();
            context.finish().unwrap();
        };
        run(&plain, LivenessConfig::default());
        run(
            &watched,
            LivenessConfig {
                no_progress_budget_nanos: Some(10_000_000_000),
                converge_budget_nanos: Some(10_000_000_000),
                heal_after_nanos: None,
            },
        );
        let a = TraceBundle::load(&plain).unwrap();
        let b = TraceBundle::load(&watched).unwrap();
        assert_eq!(
            a.timelines, b.timelines,
            "the watchdog must not perturb the recorded op stream"
        );
        assert!(a.metadata.watchdog.is_none());
        let record = b.metadata.watchdog.expect("watchdog recorded");
        assert_eq!(record.no_progress_budget_nanos, Some(10_000_000_000));
        assert_eq!(record.converge_budget_nanos, Some(10_000_000_000));
        // Fingerprint is unchanged by the watchdog (schedule-invariant).
        assert_eq!(a.metadata.fingerprint, b.metadata.fingerprint);
    }

    #[test]
    fn watchdog_config_is_recorded_and_replay_ignores_it() {
        // A watchdog trace replays against a build with no watchdog (informational
        // metadata, not reconciled fail-closed) — the op stream is authoritative.
        let dir = tempdir().unwrap();
        let path = dir.path().join("wd.patina");
        {
            let mut context = Context::from_config(
                RuntimeConfig::record(3, &path, "wd-replay-v1").with_liveness(LivenessConfig {
                    no_progress_budget_nanos: Some(1_000_000),
                    converge_budget_nanos: None,
                    heal_after_nanos: None,
                }),
            )
            .unwrap();
            context.write_file("/f", b"data").unwrap();
            context.finish().unwrap();
        }
        // Replay with NO watchdog configured: must succeed (config not reconciled).
        // Re-issue the same recorded op stream (the write).
        let mut replay =
            Context::from_config(RuntimeConfig::replay(&path, "wd-replay-v1")).unwrap();
        replay.write_file("/f", b"data").unwrap();
        replay.finish().unwrap();
    }

    // Report suppression is presentation, not run semantics: two recordings of the
    // same workload — one with every report on, one with every report off — must
    // produce byte-identical traces. That property is what keeps the knobs out of
    // the fingerprint and out of everything replay reconciles, so a quietly
    // recorded trace still replays against a loud one and back.
    #[test]
    fn report_suppression_does_not_reach_a_recorded_byte() {
        let directory = tempdir().unwrap();
        let record = |name: &str, reports: ReportConfig| {
            let trace = directory.path().join(name);
            let config = RuntimeConfig::record(11, &trace, "reports-v1").with_reports(reports);
            let mut context = Context::from_config(config).unwrap();
            context.write_file("/data", b"payload").unwrap();
            assert_eq!(context.read_file("/data").unwrap(), b"payload");
            context.finish().unwrap();
            fs::read(&trace).unwrap()
        };

        let mut silent = ReportConfig::default();
        for report in Report::ALL {
            silent.set(report, false);
        }
        assert_eq!(
            record("loud.patina", ReportConfig::default()),
            record("quiet.patina", silent),
            "a suppression preference must not change a recorded byte"
        );
    }

    #[test]
    fn run_with_context_finalizes_recording_when_the_application_returns_an_error() {
        // The explicit-context `run` path always finalizes: a recorded run whose
        // closure fails still flushes the trace and surfaces the closure error.
        let directory = tempdir().unwrap();
        let trace = directory.path().join("failed-run.patina");
        let context = Context::from_config(RuntimeConfig::record(5, &trace, "fixture-v1")).unwrap();
        let result = run_with_context(context, |_| {
            Err::<(), _>(EffectError::new(ErrorCode::Denied, "application failed").into())
        });
        assert!(matches!(result, Err(RuntimeError::Effect(_))));
        assert!(trace.is_file());
    }
}

/// Source-level convention lints for the end-of-run report knobs.
///
/// The class these pin is "the runtime reads the process environment after the
/// runtime is installed". On the native path that read is routed through the
/// interposed `getenv`, which by finalization sees only the scrubbed
/// deterministic environment with no context in the slot — so it returns NULL
/// and every knob silently reads as absent. Every report knob is therefore
/// resolved once, at configuration time, into [`ReportConfig`].
#[cfg(test)]
mod source_lints {
    use super::{Report, ReportConfig};
    use std::collections::BTreeSet;

    /// The gate behind [`Report`]: a suppression variable declared in this file
    /// but missing from the table would be documented, parsed by nothing, and
    /// inert — the exact failure this whole mechanism exists to remove.
    #[test]
    fn report_table_covers_every_declared_suppression_variable() {
        let source = include_str!("lib.rs");
        let declared: BTreeSet<&str> = source
            .lines()
            .filter_map(|line| {
                let rest = line.trim().strip_prefix("pub const ENV_")?;
                let (name, value) = rest.split_once(": &str = ")?;
                name.ends_with("_REPORT")
                    .then(|| value.trim().trim_end_matches(';').trim_matches('"'))
            })
            .collect();
        let table: BTreeSet<&str> = Report::ALL.iter().map(|report| report.env()).collect();
        assert_eq!(
            declared, table,
            "every declared PATINA_*_REPORT variable needs a Report variant (and vice versa)"
        );
    }

    /// No report knob may be read from the process environment. Assembled at
    /// runtime so this test's own text cannot match itself.
    #[test]
    fn no_report_knob_is_read_from_the_process_environment() {
        let source = include_str!("lib.rs");
        // Whitespace-stripped so the lint survives any rustfmt line breaking.
        let packed: String = source.chars().filter(|c| !c.is_whitespace()).collect();
        for needle in [
            format!("env{}var(ENV_", "::"),
            format!("env{}var_os(ENV_", "::"),
        ] {
            let mut cursor = 0;
            while let Some(offset) = packed[cursor..].find(&needle) {
                let start = cursor + offset + needle.len();
                let end = start + packed[start..].find(')').expect("closing parenthesis");
                assert!(
                    !packed[start..end].ends_with("_REPORT"),
                    "ENV_{} is read from the process environment; resolve it once into \
                     ReportConfig at configuration time instead — a native finalization-time \
                     read returns NULL and silently disables the knob",
                    &packed[start..end],
                );
                cursor = end;
            }
        }
    }

    /// Absent knobs leave every report on; only the documented false-y spellings
    /// suppress; an explicit truthy value re-enables what an ambient `0` had
    /// suppressed (the pin a campaign puts on its children).
    #[test]
    fn report_config_parses_the_documented_spellings() {
        // `ReportConfig` indexes by discriminant while `applied` iterates `ALL`,
        // so a reordered or duplicated row would read one report's setting under
        // another's name. Pin the two orders together.
        for (index, report) in Report::ALL.iter().enumerate() {
            assert_eq!(
                *report as usize, index,
                "Report::ALL must be in variant order"
            );
        }
        assert!(ReportConfig::default().enabled(Report::Schedule));
        for value in ["0", "off", "FALSE", " no "] {
            let config = ReportConfig::default()
                .applied(|name| (name == Report::Schedule.env()).then(|| value.to_string()));
            assert!(!config.enabled(Report::Schedule), "{value:?} must suppress");
            assert!(
                config.enabled(Report::Swarm),
                "{value:?} must not touch a sibling report"
            );
        }
        for value in ["1", "", "yes", "on"] {
            let config = ReportConfig::default()
                .applied(|_| Some("0".to_string()))
                .applied(|name| (name == Report::Sdk.env()).then(|| value.to_string()));
            assert!(config.enabled(Report::Sdk), "{value:?} must re-enable");
            assert!(!config.enabled(Report::Swarm));
        }
    }
}
