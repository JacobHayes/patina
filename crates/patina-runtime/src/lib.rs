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

#![deny(clippy::disallowed_methods)]

use crate::buggify::Buggify;
use crate::custom_op::PendingCustomOp;
use crate::liveness::{CpuTime, LivenessWatchdog, SpinRescue};
use crate::recording::Execution;
use crate::schedule::ScheduleTracker;
use patina_dst_abi::{EffectError, Operation, Outcome, TaskId};
use patina_dst_driver_api::{ClockDriver, EntropyDriver, FsDriver, NetDriver, SchedulerDriver};
use patina_dst_fs_mem::FsSnapshot;
use patina_dst_rng_seeded::SplitMix64;
use patina_dst_trace::{HandoffConsumedState, TraceError};
use std::collections::BTreeMap;
use std::fmt;

mod buggify;
mod builder;
mod config;
mod config_env;
mod custom_op;
mod filesystem;
mod fs_crash;
mod liveness;
mod network;
mod recording;
mod replay;
mod reports;
mod schedule;
mod swarm;
mod time;

pub use config::{
    BuggifyConfig, ClockFaultConfig, CustomOpFaultConfig, DnsFaultConfig, EntropyFaultConfig,
    ExecutionMode, FaultConfig, FsFaultConfig, LivenessConfig, NetFaultConfig, RuntimeConfig,
    validate_hostname,
};

pub use builder::RuntimeBuilder;
pub use recording::TraceTransport;

pub use config_env::trace_fd_from_env;
pub use filesystem::FsTime;
pub use fs_crash::{CrashCounts, CrashOp, CrashPoint};

pub use schedule::{ScheduleDiagnostics, TaskCompletionCause, TaskScheduleStat};

pub use liveness::LivenessKind;

pub use buggify::{
    BuggifyDeclaredSiteReport, BuggifyDiagnostics, BuggifyKind, BuggifySiteReport, SiteOutcome,
    VerdictRecord,
};

pub use custom_op::CustomOpMode;

pub use reports::{
    ENV_CLOCK_FAULT_REPORT, ENV_COVERAGE_REPORT, ENV_CUSTOMOP_FAULT_REPORT, ENV_DEPTH_REPORT,
    ENV_DNS_FAULT_REPORT, ENV_ENTROPY_FAULT_REPORT, ENV_FS_FAULT_REPORT, ENV_LIVENESS_REPORT,
    ENV_NET_FAULT_REPORT, ENV_SCHEDULE_POLICY_REPORT, ENV_SCHEDULE_REPORT, ENV_SDK_REPORT,
    ENV_SWARM_REPORT, Report, ReportConfig,
};

pub use patina_dst_abi::VerdictKind;

pub use patina_dst_fs_crash::TornGranularity;

pub use patina_dst_time_virtual::{DEFAULT_BOOT_ORIGIN_NANOS, DEFAULT_REALTIME_EPOCH_NANOS};

pub use patina_dst_trace::MAX_TRACE_BYTES;

mod fault_knob;

pub use fault_knob::{
    FaultKnob, KnobMeta, Masks, Plane, Plumbing, RepeatableFormat, SWARM_CLASSES, SwarmClass,
};

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

/// Inherited host descriptor carrying an encoded `patina_dst_fs_mem::FsImage`. When
/// set, `native-run` streams a read-only host directory tree into the guest and
/// the shim rebuilds it as the deterministic filesystem instead of an empty one,
/// so a fully interposed guest sees a fixed corpus without touching the host.
/// The image's hash is folded into the run fingerprint, so replay rejects a
/// different corpus. Off when unset.
pub const ENV_FS_IMAGE_FD: &str = "PATINA_FS_IMAGE_FD";

/// Supervisor-owned descriptor the native shim writes a crash-restart handoff to
/// when `--fs-crash-at` fires. Only the native supervisor sets it; ordinary
/// guest code never sees it after the startup scrub.
pub const ENV_HANDOFF_FD: &str = "PATINA_HANDOFF_FD";

/// Hex-encoded 32-byte supervisor key used by the native shim to seal the
/// crash-restart handoff written to [`ENV_HANDOFF_FD`].
pub const ENV_HANDOFF_KEY: &str = "PATINA_HANDOFF_KEY";

/// Supervisor-owned descriptor containing an encoded [`patina_dst_fs_mem::FsSnapshot`]
/// used to seed a fresh native incarnation after a modeled crash.
pub const ENV_RESTART_SNAPSHOT_FD: &str = "PATINA_RESTART_SNAPSHOT_FD";

/// Zero-based process incarnation identifier for native crash-restart runs.
pub const ENV_INCARNATION: &str = "PATINA_INCARNATION";

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

/// Native supervisor reservation marker (`=1`): the initial environment has
/// room for the deterministic map and a disjoint copy of the platform trailer.
/// The shim checks actual capacity before publishing into the initial stack.
/// Unreserved direct launches may only start with an empty guest map.
pub const ENV_INITIAL_STACK: &str = "PATINA_INITIAL_STACK";

/// Extra pointer-sized environment slots the native supervisor reserves for
/// the platform startup trailer. The shim fails closed if the trailer does not
/// fit; this is reservation policy, not a claim about a platform's auxv size.
pub const NATIVE_INITIAL_STACK_TRAILER_SLOTS: usize = 256;

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

/// The guest's initial working directory as an absolute virtual path. Set by
/// native `run --cwd PATH`; recorded into trace metadata and restored on replay
/// so relative-path guests reproduce without re-supplying the flag. Absent means
/// `/`. A relative path, an empty one, a NUL byte, or a `..` component fails
/// closed; the value is canonicalized lexically (`.` and `//` dropped).
pub const ENV_GUEST_CWD: &str = "PATINA_GUEST_CWD";

/// The run's virtual realtime epoch as Unix-time nanoseconds (decimal `u64`):
/// what `ClockKind::Realtime` reads at monotonic zero. Set by `run
/// --realtime-epoch`, which accepts an RFC 3339 UTC timestamp and forwards its
/// nanosecond value here; recorded into trace metadata and restored on replay.
/// Absent means [`DEFAULT_REALTIME_EPOCH_NANOS`]. A malformed value fails closed.
pub const ENV_REALTIME_EPOCH_NANOS: &str = "PATINA_REALTIME_EPOCH_NANOS";

/// The node name the guest's virtual kernel reports (`uname`'s `nodename`,
/// `gethostname`). Set by `run --hostname`; recorded into trace metadata and
/// restored on replay. Absent means `patina_dst_syscalls::IDENTITY_HOSTNAME`.
/// A value [`validate_hostname`] refuses fails closed.
pub const ENV_GUEST_HOSTNAME: &str = "PATINA_GUEST_HOSTNAME";

/// The longest node name the kernel stores, in bytes (`__NEW_UTS_LEN`).
pub const HOSTNAME_MAX_BYTES: usize = 64;

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

/// Seeded guest custom-operation failure probability in per-mille (0..=1000),
/// applied to every custom operation the guest declared fault-eligible. On fire
/// the operation's `perform` closure does not run and the guest is handed the
/// failure it declared. Off (zero) when unset.
pub const ENV_CUSTOM_OP_FAIL_PERMILLE: &str = "PATINA_CUSTOM_OP_FAIL_PERMILLE";

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

/// Enable cooperative-SUT (buggify) fault injection. Its value is the
/// per-evaluation firing probability in per-mille for an active site (0..=1000);
/// an empty value uses the FoundationDB default of 25% (250). Presence of the
/// variable enables buggify; absence disables it (zero behavior change).
pub const ENV_BUGGIFY: &str = "PATINA_BUGGIFY";

/// Per-run site activation probability in per-mille (0..=1000): the fraction of
/// buggify sites made active for the run. Default 25% (250). Inert without
/// [`ENV_BUGGIFY`].
pub const ENV_BUGGIFY_ACTIVATION: &str = "PATINA_BUGGIFY_ACTIVATION_PERMILLE";

/// Elapsed virtual nanoseconds since guest start after which buggify stops firing
/// (the FoundationDB damage-control window). Default 300 virtual seconds. Inert
/// without [`ENV_BUGGIFY`].
pub const ENV_BUGGIFY_CUTOFF: &str = "PATINA_BUGGIFY_CUTOFF_NANOS";

/// Declare that the guest calls `patina_dst::lifecycle::setup_complete()`, gating
/// buggify off until that call. A false-y value (or absence) leaves it off.
/// Inert without [`ENV_BUGGIFY`]. When set and the guest never calls
/// `setup_complete()`, the run fails loudly at finalization.
pub const ENV_BUGGIFY_AFTER_SETUP: &str = "PATINA_BUGGIFY_AFTER_SETUP";

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

/// FoundationDB's default per-evaluation buggify firing probability, in per-mille.
pub const DEFAULT_BUGGIFY_FIRE_PERMILLE: u16 = 250;

/// FoundationDB's default per-run buggify site activation probability, in per-mille.
pub const DEFAULT_BUGGIFY_ACTIVATION_PERMILLE: u16 = 250;

/// Default buggify damage-control cutoff: 300 virtual seconds, in nanoseconds.
pub const DEFAULT_BUGGIFY_CUTOFF_NANOS: u64 = 300_000_000_000;

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
    /// Actual initial monotonic reading, including explicitly installed drivers.
    boot_origin_nanos: u64,
    compute_stop: Option<patina_dst_trace::ComputeStop>,
    root_seed: u64,
    compatibility_fingerprint: String,
    step_budget: Option<u64>,
    steps: u64,
    params: BTreeMap<String, String>,
    guest_env: BTreeMap<String, String>,
    guest_cwd: Option<String>,
    hostname: String,
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
    incarnation: u64,
    require_crash_selector_reached: bool,
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
    /// Seeded custom-operation failure knob, the root of its per-label stream
    /// family, and the streams handed out so far — one per label first seen, so
    /// a label's decisions depend on that label alone. Zero means the knob is
    /// off, and no label ever gets a stream.
    custom_op_fail_permille: u16,
    custom_op_fault_root: u64,
    custom_op_fault_rngs: BTreeMap<String, SplitMix64>,
    /// Custom-op fault accounting for the end-of-run vacuity diagnostic.
    custom_op_report: patina_dst_driver_api::CustomOpFaultReport,
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
    /// Virtual CPU time. See [`CpuTime`].
    cpu: CpuTime,
    /// The earliest monotonic deadline of the embedder's process timers (the
    /// native shim's interval timers, POSIX timers and timer descriptors), set
    /// through [`Context::set_alarm`]. The advance-on-spin rescue never steps
    /// over it, as it never steps over a parked task's deadline.
    alarm: Option<u64>,
    /// The CPU time the embedder's earliest CPU-time timer still needs, as
    /// published through [`Context::set_cpu_alarm`], with the process CPU
    /// time it was published at: the advance-on-spin rescue advances toward
    /// it in whole steps.
    cpu_alarm: Option<(u64, u64)>,
    /// Whether the recording has already been written out by
    /// [`Context::flush_recording`] on a runtime-initiated stop. The trace
    /// transport is an append-only descriptor in the interposed families, so a
    /// second write would corrupt the bundle: this flag keeps it at exactly one.
    recording_flushed: bool,
}

pub struct InjectedFsCrash {
    pub compatibility_fingerprint: String,
    pub from_incarnation: u64,
    pub to_incarnation: u64,
    pub selector: patina_dst_trace::CrashPointRecord,
    pub consumed: HandoffConsumedState,
    pub snapshot: FsSnapshot,
}

impl fmt::Debug for InjectedFsCrash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InjectedFsCrash")
            .field("compatibility_fingerprint", &self.compatibility_fingerprint)
            .field("from_incarnation", &self.from_incarnation)
            .field("to_incarnation", &self.to_incarnation)
            .field("selector", &self.selector)
            .field("consumed", &self.consumed)
            .field("snapshot", &self.snapshot)
            .finish()
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
    /// A configured `--fs-crash-at` boundary fired. This is an internal,
    /// uncatchable runtime control for the native shim/supervisor: the triggering
    /// boundary operation has already succeeded and been recorded, the durable
    /// filesystem image has been recovered, and no value may be returned to guest
    /// code in this incarnation.
    InjectedFsCrash(Box<InjectedFsCrash>),
    /// A run ended without reaching its requested automatic crash boundary.
    CrashSelectorUnreached {
        selector: CrashPoint,
        counts: CrashCounts,
    },
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
    /// Native compute-only starvation: a runtime limit, never a guest verdict.
    ComputeBound {
        task: TaskId,
        steps: u64,
    },
    /// The asynchronous stop could not export its evidence. No heap-owned
    /// diagnostic: an interrupted allocator may be unavailable.
    ComputeStopExport,
    /// Recording was already abandoned; no terminal prefix may be fabricated.
    ComputeStopOverflow,
    /// Terminal metadata disagrees with the strictly replayed scheduler state.
    ComputeStopState,
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(message) => write!(f, "invalid Patina configuration: {message}"),
            Self::Io { action, source } => write!(f, "failed to {action}: {source}"),
            Self::Effect(error) => error.fmt(f),
            Self::Trace(error) => error.fmt(f),
            Self::InjectedFsCrash(control) => write!(
                f,
                "Patina injected filesystem crash at {:?}:{} after {} operations; terminate incarnation {} and restart incarnation {}",
                control.selector.op,
                control.selector.ordinal,
                control.consumed.operations,
                control.from_incarnation,
                control.to_incarnation
            ),
            Self::CrashSelectorUnreached { selector, counts } => write!(
                f,
                "PATINA_FS_CRASH_SELECTOR_UNREACHED requested {:?}:{} but only observed open={} write={} sync={} close={} successful boundary operations",
                selector.op, selector.ordinal, counts.open, counts.write, counts.sync, counts.close
            ),
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
            Self::ComputeStopExport => f.write_str("PATINA_INFRA compute_stop_export_failed"),
            Self::ComputeStopOverflow => {
                f.write_str("PATINA_INFRA compute_stop_export_failed reason=trace-overflow")
            }
            Self::ComputeStopState => {
                f.write_str("PATINA_INFRA compute_stop_invalid_scheduler_state")
            }
            Self::ComputeBound { task, steps } => write!(
                f,
                "PATINA_VIOLATION liveness detail=compute-bound task={} steps={} known_limit=true: no scheduling point within the host-time bound while another managed thread is runnable; host blocking and descheduling are not distinguished from computation; this is a known Patina limit, not a guest bug",
                task.0, steps
            ),
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

    pub fn param(&self, key: &str) -> Option<&str> {
        self.params.get(key).map(String::as_str)
    }

    /// The deterministic guest environment the run starts with (the startup
    /// map, in key order): the array the native shim publishes as `environ`
    /// before the guest's first instruction. From then on the environment is
    /// the guest's own process memory (the shim runs glibc's environment
    /// functions over `environ`), so this is only the starting point; the
    /// trace metadata records it.
    pub const fn guest_env(&self) -> &BTreeMap<String, String> {
        &self.guest_env
    }

    /// The guest's initial working directory as configured (`None` for `/`).
    /// The LIVE working directory is process state the native shim keeps —
    /// `chdir` is guest-driven and unrecorded, like `setenv` — so this is only
    /// the starting point the run was configured with.
    pub fn guest_cwd(&self) -> Option<&str> {
        self.guest_cwd.as_deref()
    }

    /// The node name the guest's virtual kernel reports (`uname`'s
    /// `nodename`, `gethostname`): the run's configured or replayed name,
    /// else `patina_dst_syscalls::IDENTITY_HOSTNAME`.
    pub fn hostname(&self) -> &str {
        &self.hostname
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
}

#[cfg(test)]
mod tests;
