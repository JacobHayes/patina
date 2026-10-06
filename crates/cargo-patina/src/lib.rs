//! Process-level implementation behind the `cargo-patina` binary.
//!
//! Internal crate: the `cargo patina` CLI — verb parsing (`build`, `run`,
//! `test`, `audit`, `replay`, `explore`, `campaign`, `minimize`, `sites`, `trace`), artifact
//! family inference (Cargo package / shim-linked native binary / WASI module),
//! build orchestration, the supervisor protocol that hands the `PATINA_*`
//! control plane to a guest, and result rendering (`--format json`,
//! `--render`). The user-facing contract is `cargo patina <verb> --help` (and
//! `--help --format json` for the machine-readable registry), not this crate's
//! API. See [ARCHITECTURE.md] for how the CLI drives the runtime.
//!
//! [ARCHITECTURE.md]: https://github.com/JacobHayes/patina/blob/main/ARCHITECTURE.md

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

use patina_dst_runtime::{
    ENV_BRANCH_FROM, ENV_BRANCH_ID, ENV_BRANCH_SEED, ENV_FINGERPRINT, ENV_GUEST_HOSTNAME, ENV_MODE,
    ENV_PARAMS_JSON, ENV_PARENT_TIMELINE, ENV_REALTIME_EPOCH_NANOS, ENV_SEED, ENV_STEP_BUDGET,
    ENV_TIMELINE, ENV_TRACE, FaultKnob,
};
use patina_dst_trace::{lock_exclusive, remove_dead_scratch};
use patina_dst_wasi_host::{MountPolicy, ResourceLimits};
use sha2::{Digest, Sha256};

// Additive output-side modules: HTML timeline rendering and the machine-readable
// `--output json` envelope. Both are read-only consumers of trace/runtime
// semantics — they never record, replay, or mutate a trace — so rendering or
// emitting an envelope cannot perturb replay hashes.
mod audit;
mod aux_store;
mod campaign;
mod cli;
mod config;
mod coverage;
#[cfg(unix)]
mod crash_restart;
mod depth;
mod guided;
mod harness;
mod help;
mod minimize;
mod native_build;
mod native_run;
mod output;
mod parse;
mod render;
mod rollup;
mod sdk_report;
mod shim_build;
mod shim_cache;
mod sites;
mod syscalls;
mod trace_cmd;
mod trace_view;
mod values;
mod wasi_exec;

use audit::execute_native_audit;
use harness::{execute_explore, execute_native_harness};
use native_build::{
    GuestInstrumentation, binary_instrumentation, execute_native_build,
    instrumentation_fingerprint, resolve_artifact,
};
use native_run::{TRACE_CHANNEL_UNAVAILABLE, execute_native_run};
use parse::{
    BUGGIFY_ENV_VARS, ParseResult, buggify_env_pairs, current_verb, knob_env_pairs, knob_env_vars,
    locate_positionals, package_integrates_patina, parse, reject_stranded_artifact,
};
use shim_build::{TARGET_DIR_LOCK, lock_target_dir};
use wasi_exec::{execute_wasi_audit, execute_wasi_build, execute_wasi_run};

const PATINA_CFG_FLAGS: &str = "--cfg patina --cfg dst";

/// Crate names whose presence in a package's declared dependencies means the
/// package integrates the Patina deterministic runtime at the library level. This
/// is the routing pivot between the two execution models a `run`/`replay` of a
/// Cargo package can take: a runtime-linked package stays on the cargo-family
/// path (seed/param/budget/branch and record/replay honored by the linked
/// runtime), while a plain package is built shim-linked and run under the native
/// pre-run gate. `patina-dst` (the SDK) re-exports the runtime, so either name
/// counts.
const PATINA_RUNTIME_CRATES: &[&str] = &["patina-dst-runtime", "patina-dst"];
const DEFAULT_NATIVE_FINGERPRINT: &str = "patina-native";
/// The fixed, machine-independent `argv[0]` every native guest sees. `native-run`
/// resolves the guest binary to an absolute host path (tempdir-specific,
/// machine-specific) to exec it, so passing that path through as `argv[0]` would
/// leak a non-portable string into the guest's `std::env::args().next()` — a
/// latent cross-machine determinism surface. The supervisor is the sole exec-er,
/// so it stamps this stable name as `argv[0]` instead; guests read their own
/// arguments from `argv[1..]` (all in-repo guests `.skip(1)`), so nothing that
/// observes real program arguments is affected.
const NATIVE_GUEST_ARGV0: &str = "patina-guest";
// Native supervisor descriptors are inherited at their already-open fd numbers;
// the child discovers them from `PATINA_TRACE_FD` / `PATINA_FS_IMAGE_FD`. Keeping
// the actual numbers avoids a macOS Rust 1.86 fork/exec edge where pre-exec
// relocation onto fixed low fds could still leave those fds closed after exec.
#[cfg(unix)]
const F_GETFD: i32 = 1;
#[cfg(unix)]
const F_SETFD: i32 = 2;
#[cfg(unix)]
const FD_CLOEXEC: i32 = 1;

#[cfg(unix)]
unsafe extern "C" {
    // Declared with the variadic tail it really has: Darwin arm64 reads anonymous
    // varargs from the stack, so a non-variadic declaration passes `arg` in a
    // register the callee never reads and `F_SETFD` writes stack garbage instead.
    fn fcntl(fd: i32, cmd: i32, ...) -> i32;
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Mode {
    Seeded {
        seed: u64,
    },
    Record {
        seed: u64,
        path: PathBuf,
    },
    Replay {
        path: PathBuf,
        timeline: String,
    },
    Branch {
        path: PathBuf,
        parent: String,
        from_sequence: u64,
        branch_seed: u64,
        branch_id: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct WasiInvocation {
    module: ArtifactRef,
    mode: Mode,
    fuel: u64,
    arguments: Vec<String>,
    environment: BTreeMap<String, String>,
    sockets: Vec<WasiSocketConfig>,
    preopens: Vec<WasiPreopenConfig>,
    resource_limits: WasiResourceLimitOverrides,
    /// Maximum boundary operations before the run fails explicitly (`--budget`).
    /// Family-neutral: the same `RuntimeConfig::step_budget` the Cargo family
    /// sets, and distinct from `--fuel`, which bounds wasm execution rather than
    /// recorded boundary operations.
    step_budget: Option<u64>,
    /// The run's virtual realtime epoch in Unix-time nanoseconds
    /// (`--realtime-epoch`), or `None` for the runtime default. Applied to the
    /// in-process runtime on a seeded/`--record` run and recorded into the
    /// trace; `replay` restores it from the trace and carries `None`.
    realtime_epoch_nanos: Option<u64>,
    /// Seed-driven fault-injection knobs applied to the in-process runtime before
    /// `Context::from_config`, so a WASI guest's filesystem and datagram sockets
    /// see the same seeded crash/jitter/drop drivers the native family does.
    /// Recorded into the trace metadata on `--record`; restored from the trace on
    /// `replay`, so a WASI replay is flag-free. `--sleep-jitter-nanos` is carried
    /// here too: the wasip1 host applies it at its single guest-facing sleep entry
    /// (`Preview1Host::sleep_until`, also covering `poll_oneoff` clock timeouts).
    /// `--net-partition` rides the same table: wasip1 has no name resolution, so
    /// the DNS knobs are refused for this family, but the partition set is an
    /// ordinary `FaultConfig` field and applies exactly as it does natively.
    knobs: KnobValues,
    /// Cooperative-SUT (buggify) knobs applied to the in-process runtime through
    /// the same `apply_buggify_env` accessor the native family feeds over its
    /// control plane. `None` unless `--buggify` was passed. Recorded into the
    /// trace metadata on `--record` and restored from the trace on `replay`, so a
    /// WASI buggify replay is flag-free, exactly like the fault knobs.
    buggify: Option<NativeBuggify>,
    /// Liveness-watchdog knobs applied to the in-process runtime through the shared
    /// `apply_liveness_env` accessor. Schedule-invariant, so recorded into the
    /// trace metadata (informational) but never fingerprinted.
    liveness: NativeLiveness,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct WasiPreopenConfig {
    guest_path: String,
    policy: MountPolicy,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct WasiResourceLimitOverrides {
    fuel: Option<u64>,
    max_memory_pages: Option<u32>,
    max_iovecs: Option<usize>,
    max_io_bytes: Option<usize>,
    max_descriptors: Option<usize>,
    max_preopens: Option<usize>,
    max_path_bytes: Option<usize>,
}

impl WasiResourceLimitOverrides {
    fn to_host_limits(&self) -> ResourceLimits {
        let mut limits = ResourceLimits::default();
        if let Some(fuel) = self.fuel {
            limits.fuel = fuel;
        }
        if let Some(max_memory_pages) = self.max_memory_pages {
            limits.max_memory_pages = max_memory_pages;
        }
        if let Some(max_iovecs) = self.max_iovecs {
            limits.max_iovecs = max_iovecs;
        }
        if let Some(max_io_bytes) = self.max_io_bytes {
            limits.max_io_bytes = max_io_bytes;
        }
        if let Some(max_descriptors) = self.max_descriptors {
            limits.max_descriptors = max_descriptors;
        }
        if let Some(max_preopens) = self.max_preopens {
            limits.max_preopens = max_preopens;
        }
        if let Some(max_path_bytes) = self.max_path_bytes {
            limits.max_path_bytes = max_path_bytes;
        }
        limits
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct WasiSocketConfig {
    fd: u32,
    bind: String,
    peer: String,
}

struct NativeAuditInvocation {
    binary: ArtifactRef,
    allow: BTreeSet<String>,
    /// Audit a prebuilt native binary even when it is not shim-linked. Without
    /// it, `execute_native_audit` fails closed on a stock `cargo build` output
    /// (whose imports are unsatisfied libc calls, not the post-interposition
    /// residual). With it, the full audit runs anyway under a loud banner
    /// marking the import findings as pre-interposition.
    raw: bool,
}

/// Default number of candidate seeds tried when reducing a scenario's seed.
const DEFAULT_SEED_BUDGET: u64 = 256;

#[derive(Clone)]
struct Invocation {
    cargo_command: String,
    cargo_args: Vec<OsString>,
    mode: Mode,
    step_budget: Option<u64>,
    /// The run's virtual realtime epoch in Unix-time nanoseconds
    /// (`--realtime-epoch`), forwarded as [`ENV_REALTIME_EPOCH_NANOS`]; `None`
    /// leaves the runtime default. Recorded into the trace on `--record`; the
    /// `replay` verb carries `None` and the trace restores it.
    realtime_epoch_nanos: Option<u64>,
    /// The guest's node name (`--hostname`), forwarded as
    /// [`ENV_GUEST_HOSTNAME`] and observable through `Context::hostname`;
    /// `None` leaves the runtime default. Recorded and restored like the epoch.
    hostname: Option<String>,
    params: BTreeMap<String, String>,
    /// Seed-driven fault-injection knobs forwarded to the guest through the
    /// `PATINA_*` control plane (the same knobs the native and WASI families
    /// accept). Recorded into the trace metadata on `--record`; restored from the
    /// trace on the `replay` verb, so a cargo-family replay is flag-free. Default
    /// (all `None`) leaves faults off.
    knobs: KnobValues,
    /// Cooperative-SUT (buggify) knobs, or `None` when `--buggify` was not
    /// passed. Forwarded over the same `PATINA_BUGGIFY*` control plane the other
    /// families use; the guest's `apply_buggify_env` is family-neutral, so only
    /// the parser ever omitted them.
    buggify: Option<NativeBuggify>,
    /// Working directory the cargo subprocess runs in, or `None` to inherit the
    /// caller's. Set by the cargo-family `replay` verb from its `<pkg>` positional
    /// so a replay can run from anywhere while its fingerprint (which walks the
    /// package's own source tree) still matches the recording.
    working_dir: Option<PathBuf>,
}

struct ExploreInvocation {
    target: ExploreTarget,
    start_seed: u64,
    seed_count: u64,
    wrapped_command: Vec<OsString>,
}

/// What `explore` sweeps across seeds. The Cargo package family re-runs the whole
/// `run`/`test` command per seed (each cargo invocation is cheap next to the
/// build it caches). The native and WASI families instead build the artifact
/// once and run that SAME artifact across every seed, so a source/package is
/// never rebuilt per seed.
enum ExploreTarget {
    Cargo(Invocation),
    Wasi(WasiInvocation),
    Native(NativeRunInvocation),
}

struct NativeHarnessInvocation {
    origin: PathBuf,
    manifest: PathBuf,
    package: Option<String>,
    harness_target: String,
    exact: String,
    seeds: HarnessSeeds,
    release: bool,
    /// Cargo feature selection forwarded verbatim to the harness build
    /// (`--features`, `--all-features`, `--no-default-features`).
    features: HarnessFeatures,
    /// How the native libtest harness is instrumented (see
    /// [`GuestInstrumentation`]). Off by default.
    instrumentation: GuestInstrumentation,
    /// Boundary-operation budget forwarded to each seed's child `run`.
    step_budget: Option<u64>,
    /// The `--realtime-epoch` timestamp, re-emitted verbatim onto each seed's
    /// child `run`.
    realtime_epoch: Option<String>,
    /// The `--hostname` name, re-emitted verbatim onto each seed's child `run`.
    hostname: Option<String>,
    /// Every fault knob this invocation set, re-emitted onto each seed's child
    /// `run` command line by [`knob_flag_pairs`].
    knobs: KnobValues,
    buggify: Option<NativeBuggify>,
    schedule: NativeSchedule,
    liveness: NativeLiveness,
}

/// Cargo feature selection for a native libtest harness build.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct HarnessFeatures {
    features: Option<String>,
    all_features: bool,
    no_default_features: bool,
}

impl HarnessFeatures {
    /// The `cargo rustc` arguments that reproduce this selection.
    fn cargo_args(&self) -> Vec<OsString> {
        let mut args = Vec::new();
        if let Some(features) = &self.features {
            args.push(OsString::from("--features"));
            args.push(OsString::from(features));
        }
        if self.all_features {
            args.push(OsString::from("--all-features"));
        }
        if self.no_default_features {
            args.push(OsString::from("--no-default-features"));
        }
        args
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HarnessSeeds {
    One(u64),
    Range(u64),
}

impl HarnessSeeds {
    fn iter(self) -> Box<dyn Iterator<Item = u64>> {
        match self {
            HarnessSeeds::One(seed) => Box::new(std::iter::once(seed)),
            HarnessSeeds::Range(count) => Box::new(0..count),
        }
    }

    fn label(self) -> String {
        match self {
            HarnessSeeds::One(seed) => format!("seed {seed}"),
            HarnessSeeds::Range(count) => format!("seeds 0..{count}"),
        }
    }

    fn contains(self, seed: u64) -> String {
        match self {
            HarnessSeeds::One(_) => format!("seed {seed}"),
            HarnessSeeds::Range(count) => format!("seed {seed} of 0..{count}"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct NativeBuildInvocation {
    target: NativeBuildTarget,
    output: Option<PathBuf>,
    release: bool,
    /// How the guest is instrumented: not at all (default), with a scheduling
    /// point at every basic block (`--yield-points`), or with edge counters and
    /// an optional sampled scheduling point (`--coverage-points[=N]`). See
    /// [`GuestInstrumentation`]. Off by default; plain native builds are
    /// unchanged.
    instrumentation: GuestInstrumentation,
}

/// What `build` compiles for the native target: a single Rust source linked
/// directly with `rustc`, or a whole Cargo package driven through its own
/// `cargo build`.
#[derive(Clone, Debug, PartialEq, Eq)]
enum NativeBuildTarget {
    Source {
        source: PathBuf,
        edition: String,
        rustc_args: Vec<OsString>,
    },
    Package {
        manifest: PathBuf,
        package: Option<String>,
        bin: Option<String>,
    },
}

/// What `build --target wasi` compiles: a Cargo package for `wasm32-wasip1`.
/// WASI is package-only (a single `.rs` source is native-only).
#[derive(Clone, Debug, PartialEq, Eq)]
struct WasiBuildInvocation {
    manifest: PathBuf,
    package: Option<String>,
    bin: Option<String>,
    release: bool,
    /// When set, the produced `.wasm` is copied here; otherwise its Cargo
    /// artifact path is reported.
    output: Option<PathBuf>,
}

/// A build-on-the-fly request captured at parse time and executed by the shared
/// build pipeline just before a run/audit/replay consumes its product. Carries
/// the user's original source argument (`origin`) so a WASI guest's `argv[0]`
/// and diagnostics name the source rather than a throwaway temp path.
#[derive(Clone, Debug, PartialEq, Eq)]
struct BuildSpec {
    origin: PathBuf,
    kind: BuildSpecKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum BuildSpecKind {
    Native(NativeBuildInvocation),
    Wasi(WasiBuildInvocation),
}

/// A run/audit/replay artifact argument: either an already-built file used
/// directly (build-once-run-many stays first-class), or a source/package built
/// on the fly through the shared build pipeline before use. Resolved to a
/// concrete path — building if needed — at execute time by [`resolve_artifact`].
#[derive(Clone, Debug, PartialEq, Eq)]
enum ArtifactRef {
    Prebuilt(PathBuf),
    Build(Box<BuildSpec>),
}

#[derive(Clone)]
enum NativeRunMode {
    Seeded {
        seed: u64,
    },
    Record {
        seed: u64,
        path: PathBuf,
        fingerprint: String,
    },
    Replay {
        path: PathBuf,
        fingerprint: String,
    },
}

#[derive(Clone)]
struct NativeRunInvocation {
    binary: ArtifactRef,
    mode: NativeRunMode,
    program_args: Vec<OsString>,
    /// Deterministic guest environment values injected by native `run --env`.
    /// Recorded into trace metadata on `--record` and restored by replay.
    environment: BTreeMap<String, String>,
    /// The guest's initial working directory (`run --cwd`), an absolute path in
    /// the deterministic filesystem; `None` is `/`. Recorded into trace
    /// metadata on `--record` and restored by replay like the environment.
    cwd: Option<String>,
    /// Maximum boundary operations before the run fails explicitly (`--budget`),
    /// forwarded over the control plane. Family-neutral: the same
    /// `RuntimeConfig::step_budget` the Cargo and WASI families set.
    step_budget: Option<u64>,
    /// The run's virtual realtime epoch in Unix-time nanoseconds
    /// (`--realtime-epoch`), forwarded as [`ENV_REALTIME_EPOCH_NANOS`]; `None`
    /// leaves the runtime default. Recorded into trace metadata on `--record`
    /// and restored by replay like the working directory.
    realtime_epoch_nanos: Option<u64>,
    /// The guest's node name (`--hostname`), forwarded as
    /// [`ENV_GUEST_HOSTNAME`] for the shim's `uname`/`gethostname`; `None`
    /// leaves the runtime default. Recorded and restored like the epoch.
    hostname: Option<String>,
    /// Fault-injection knobs forwarded to the guest through the `PATINA_*`
    /// control plane. Each is a validated raw value stored verbatim; the runtime
    /// re-parses it identically on record and replay, so a mismatched flag on
    /// replay fails closed like any other operation divergence. The repeatable
    /// knobs (`--dns-entry`, `--net-partition`) ride the same table: they are
    /// semantic configuration, recorded into the trace and restored on replay, so
    /// `replay` refuses a re-supplied set.
    knobs: KnobValues,
    /// Cooperative-SUT (buggify) knobs, or `None` when `--buggify` was not
    /// passed. Presence enables buggify and folds `+buggify` into the run
    /// fingerprint.
    buggify: Option<NativeBuggify>,
    /// Exploration scheduling-policy (PCT / starvation) and swarm knobs. Enabling
    /// a non-default policy or swarm folds `+pct`/`+starve`/`+swarm` into the run
    /// fingerprint.
    schedule: NativeSchedule,
    /// Liveness-watchdog knobs forwarded to the guest through the control plane.
    /// Schedule-invariant: recorded (informational) but NOT fingerprinted.
    liveness: NativeLiveness,
    /// Extra symbols to treat as known-safe in the pre-run audit gate, beyond
    /// the baked shim control-plane vehicle. Mirrors `native-audit --allow`.
    allow: BTreeSet<String>,
    /// How the pre-run gate treats symbols that are neither interposed nor
    /// known-safe.
    allow_unsupported: UnsupportedPolicy,
    /// Host path where `run --coverage-out` writes the native yield-point edge
    /// counter map. The supervisor creates the file and passes its descriptor via
    /// `PATINA_COVERAGE_FD`, so the shim never opens it through the deterministic
    /// filesystem. Native yield-point binaries only.
    coverage_out: Option<PathBuf>,
    /// Host directory to capture read-only into the guest filesystem, mounted at
    /// the guest root `/`. When set, the supervisor (which is not interposed)
    /// walks the tree into a deterministic `FsImage`, streams it to the guest
    /// over an inherited descriptor, and the shim rebuilds it as the
    /// deterministic filesystem. The image hash is folded into the run
    /// fingerprint so replay rejects a different corpus.
    mount: Option<PathBuf>,
    /// `--harness`: the guest is a `patina-dst-harness` binary (usage mode 2). Sets
    /// `PATINA_DEFER_INIT=1` so the packaged constructor captures/scrubs the
    /// control plane and registers finalization but does NOT install the runtime;
    /// `patina_dst_harness::run`/`run_with` installs it explicitly after applying
    /// its configuration overlay. Applies to both record/seeded runs and replay of
    /// a harness binary (replay must defer too, or the constructor would install a
    /// context the harness could not own).
    harness: bool,
}

/// Every fault knob an invocation set, keyed by [`FaultKnob`] and stored as the
/// exact text the operator typed so the runtime re-parses the same protocol
/// string on record and on replay.
///
/// One store for both plumbing shapes: a [`Plumbing::Scalar`] knob holds at most
/// one value, a [`Plumbing::Repeatable`] one holds the whole set in CLI order.
/// Every family's plumbing — the WASI in-process overlay, the native subprocess
/// environment, the cargo subprocess environment and its scrub list, and the
/// native harness's re-emitted `run` command line — iterates
/// [`FaultKnob::ALL`], so a knob added to the registry cannot be forwarded by one
/// family and silently dropped by another. There is no per-knob field, accessor
/// or forwarding row to forget: `knob_table_covers_every_registry_fault_flag`
/// gates the enum against the registry, and everything else follows from it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct KnobValues(BTreeMap<FaultKnob, Vec<String>>);

impl KnobValues {
    /// The raw CLI texts supplied for one knob, empty when it was not set.
    fn get(&self, knob: FaultKnob) -> &[String] {
        self.0.get(&knob).map_or(&[], Vec::as_slice)
    }
}

/// Cooperative-SUT (buggify) knobs for `native-run`, forwarded to the guest as
/// validated raw strings through the `PATINA_BUGGIFY*` control plane. Presence
/// of the enclosing `Option` means `--buggify` was passed (buggify enabled).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct NativeBuggify {
    /// Per-evaluation firing probability in per-mille from `--buggify[=permille]`.
    fire_permille: Option<String>,
    /// Per-run site activation probability from `--buggify-activation-permille`.
    activation_permille: Option<String>,
    /// Damage-control cutoff in virtual nanoseconds from `--buggify-cutoff-nanos`.
    cutoff_nanos: Option<String>,
    /// `--buggify-after-setup`: declare that the guest calls
    /// `setup_complete()`, gating buggify off until it does.
    after_setup: bool,
}

/// Exploration scheduling-policy and swarm knobs for `native-run`, forwarded to
/// the guest as validated raw strings through the `PATINA_SCHED_*`/`PATINA_SWARM`
/// control plane. Each is default-off; enabling a non-default policy or swarm
/// folds a fingerprint component so a policy trace never cross-replays with a
/// plain build.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct NativeSchedule {
    /// PCT bug depth `d` from `--sched-pct[=D]`. `Some("")` = bare `--sched-pct`
    /// (default depth); `Some("N")` = explicit depth. `None` = PCT off.
    pct: Option<String>,
    /// Expected schedule length from `--sched-pct-steps N`. Inert without `pct`.
    pct_steps: Option<String>,
    /// Starvation interval count from `--starve[=N]`. `Some("")` = bare `--starve`
    /// (default count). `None` = starvation off.
    starve: Option<String>,
    /// Maximum starvation-interval length from `--starve-max-len N`. Inert
    /// without `starve`.
    starve_max_len: Option<String>,
    /// Starvation start window from `--starve-window N`. Inert without `starve`.
    starve_window: Option<String>,
    /// `--swarm`: apply a seed-derived subset of the enabled fault classes.
    swarm: bool,
}

/// Liveness-watchdog knobs, forwarded to the guest/runtime as validated raw
/// strings through the `PATINA_LIVENESS_*`/`PATINA_CONVERGE_*`/`PATINA_HEAL_*`
/// control plane. Virtual-time controls default off; the native compute bound
/// defaults to the shim's 10 seconds. Kept SEPARATE from [`NativeSchedule`]
/// because the watchdog is schedule-invariant: enabling it folds NO fingerprint
/// component (it only adds a possible violation report), so a watchdog trace
/// replays against any build.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct NativeLiveness {
    /// Native-only host-time terminal bound; never a schedule input.
    compute_watchdog_ms: Option<String>,
    /// `--liveness-watchdog[=NANOS]`: generic no-progress budget. `Some("")` = bare
    /// (runtime default budget); `Some("N")` = explicit budget. `None` = off.
    watchdog: Option<String>,
    /// `--converge-within[=NANOS]`: heal-then-converge budget. `Some("")` = bare
    /// (runtime default); `Some("N")` = explicit. `None` = off.
    converge: Option<String>,
    /// `--heal-after=NANOS`: explicit override for the converge arm-time. Inert
    /// without `converge`.
    heal_after: Option<String>,
}

impl NativeLiveness {
    fn is_enabled(&self) -> bool {
        self.watchdog.is_some() || self.converge.is_some()
    }
}

/// The escape hatch for `native-run`'s pre-run default-deny gate. By default an
/// unsupported symbol on the blocking/effect surface is a hard error before the
/// guest runs; the operator can downgrade specific symbols (or all) to a loud
/// warning for programs that carry unsupported surface never reached by the
/// scenario under test.
#[derive(Clone, Debug, PartialEq, Eq)]
enum UnsupportedPolicy {
    /// Default: any unsupported symbol is a hard error (fail closed).
    Deny,
    /// `--allow-unsupported-symbols all`: downgrade every unsupported symbol.
    All,
    /// `--allow-unsupported-symbols a,b,c`: downgrade only the listed symbols;
    /// anything else still hard-errors.
    Only(BTreeSet<String>),
}

pub fn entrypoint() -> Result<i32, CliError> {
    let arguments = env::args_os().skip(1).collect::<Vec<_>>();
    // Strip the cross-cutting output/config flags (`--format`, `--render`,
    // `--report`, `--no-config`) once, globally, before any per-verb routing —
    // the same pre-pass shape as `extract_target`. They are patina-level flags,
    // so they never reach the guest (anything after `--` is left in place).
    let (options, arguments) = output::extract(arguments)?;
    let is_json = options.is_json();
    let no_config = options.no_config;
    output::install(options);
    let result = config::layer_arguments(arguments, no_config).and_then(dispatch);
    // Under `--output json` a CLI-side failure becomes a JSON error envelope
    // rather than the bare `cargo-patina: {error}` stderr line, so an agent always
    // parses one machine-readable object.
    match result {
        Err(error) if is_json => {
            output::emit_simple("cli", "error", 2, Some(error.to_string()));
            Ok(2)
        }
        other => other,
    }
}

fn dispatch(arguments: Vec<OsString>) -> Result<i32, CliError> {
    match parse(arguments)? {
        ParseResult::Help(topic) => {
            // `--help --format json` (the output pre-pass already stripped and
            // installed the format) emits the machine-readable registry scoped to
            // the same topic: the compact index for the overview, one verb's full
            // detail for a verb. The human form prints the focused section. Both
            // exit 0.
            if output::options().is_json() {
                print!("{}", help::render_json(topic));
            } else {
                print!("{}", help::render(topic));
            }
            Ok(0)
        }
        ParseResult::Version => {
            println!("cargo-patina {}", env!("CARGO_PKG_VERSION"));
            println!(
                "virtual Linux kernel: {} (pinned: Ubuntu 24.04's GA kernel)",
                patina_dst_syscalls::VIRTUAL_ABI
            );
            Ok(0)
        }
        ParseResult::Run(invocation) => execute(invocation),
        ParseResult::Campaign(invocation) => campaign::execute(invocation),
        ParseResult::Coverage(invocation) => coverage::execute(invocation),
        ParseResult::Sites(invocation) => sites::execute(invocation),
        ParseResult::Syscalls(invocation) => syscalls::execute(invocation),
        ParseResult::Explore(invocation) => execute_explore(invocation),
        ParseResult::WasiBuild(invocation) => execute_wasi_build(invocation),
        ParseResult::WasiAudit(artifact) => execute_wasi_audit(artifact),
        ParseResult::WasiRun(invocation) => execute_wasi_run(invocation),
        ParseResult::NativeAudit(invocation) => execute_native_audit(invocation),
        ParseResult::NativeBuild(invocation) => execute_native_build(invocation),
        ParseResult::NativeRun(invocation) => execute_native_run(invocation),
        ParseResult::NativeHarness(invocation) => execute_native_harness(invocation),
        ParseResult::Minimize(invocation) => minimize::execute(invocation),
        ParseResult::Trace(invocation) => trace_cmd::execute(invocation),
    }
}

fn execute(invocation: Invocation) -> Result<i32, CliError> {
    if !invocation.knobs.get(FaultKnob::FsCrashAt).is_empty() {
        return Err(CliError::usage(
            "cargo-family --fs-crash-at crash-restart is not implemented; refusing rather than running rollback-and-continue semantics",
        ));
    }
    let workspace = workspace_root_in(invocation.working_dir.as_deref(), &invocation.cargo_args)?;

    // The cargo-family `run` (and its cargo-family `replay`, which reuses the
    // `run` command) derives ALL of its determinism — seeding, recording, replay,
    // and the escape surface — from the runtime the guest package LINKS. A package
    // that does not integrate the Patina runtime links no such runtime, so this
    // path would silently degrade to a plain `cargo run`: no pre-run gate, a
    // no-op `--record`, and a fail-open `replay`. Refuse it loudly here — before
    // any guest executes — and point at the native path, which builds the package
    // shim-linked and runs it under the pre-run default-deny gate. `test` is left
    // to Cargo (a plain `cargo test` is a legitimate thing to ask for).
    if invocation.cargo_command == "run"
        && !package_integrates_patina(None, invocation.working_dir.as_deref())
    {
        let where_ = match &invocation.working_dir {
            Some(dir) => format!("the package at {}", dir.display()),
            None => "the current package".to_string(),
        };
        return Err(CliError(format!(
            "refusing to run {where_}: it does not depend on the Patina runtime \
(patina-dst / patina-dst-runtime), so a cargo-family run links no deterministic \
runtime and CANNOT apply the pre-run escape gate, record a trace, or replay — it \
would run the guest as a plain `cargo run`. Run it under the native deterministic \
runtime instead, which builds it shim-linked and applies the pre-run default-deny \
gate:\n  cargo patina run <DIR|Cargo.toml> [--seed N] [--record <PATH>]\nor build it \
and run/audit the artifact (cargo patina build <DIR|Cargo.toml> --output <PATH>)."
        )));
    }

    // Replay/branch read a recorded trace; a missing or unreadable one must fail
    // closed BEFORE the guest runs, never fall through to a plain run (the
    // cargo-family fail-open replay defect). The native replay path validates the
    // trace the same way via `reconcile_replay_argv`.
    if let Mode::Replay { path, .. } | Mode::Branch { path, .. } = &invocation.mode {
        fs::read(path).map_err(|error| {
            CliError(format!(
                "failed to read trace {} for replay: {error}",
                path.display()
            ))
        })?;
    }

    ensure_lockfile(&workspace)?;
    let fingerprint = compatibility_fingerprint(&workspace, &invocation)?;
    let cargo = env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let mut command = Command::new(cargo);
    // The cargo-family `replay` verb runs from anywhere: run cargo in the
    // package's directory so its build and workspace resolution match the
    // recording (whose fingerprint walks that same source tree), without adding a
    // `--manifest-path` to the arguments, which would perturb the fingerprint.
    if let Some(working_dir) = &invocation.working_dir {
        command.current_dir(working_dir);
    }
    command
        .arg(&invocation.cargo_command)
        .args(&invocation.cargo_args)
        .env("RUSTFLAGS", patina_rustflags())
        .env(ENV_FINGERPRINT, fingerprint.clone())
        .env_remove(ENV_MODE)
        .env_remove(ENV_SEED)
        .env_remove(ENV_TRACE)
        .env_remove(ENV_TIMELINE)
        .env_remove(ENV_BRANCH_FROM)
        .env_remove(ENV_BRANCH_SEED)
        .env_remove(ENV_BRANCH_ID)
        .env_remove(ENV_PARENT_TIMELINE)
        .env_remove(ENV_STEP_BUDGET)
        .env_remove(ENV_REALTIME_EPOCH_NANOS)
        .env_remove(ENV_GUEST_HOSTNAME)
        .env_remove(ENV_PARAMS_JSON);
    // Scrub the fault-injection control plane so only the flags this invocation
    // parsed reach the child; an ambient `PATINA_FS_CRASH_AT` (or any sibling) in
    // the caller's environment must never silently perturb a run that requested
    // no faults. Driven by the shared knob table, so a new knob is scrubbed the
    // day it is registered.
    for variable in knob_env_vars() {
        command.env_remove(variable);
    }
    // Forward this run's fault knobs. On a `--record` run the child's runtime
    // captures them into the trace metadata; on the `replay` verb none are set
    // (the trace is authoritative and the runtime restores them), so replay is
    // flag-free.
    for (name, value) in knob_env_pairs(&invocation.knobs)? {
        command.env(name, value);
    }
    // Cooperative-SUT (buggify) knobs ride the same control plane. Scrubbed
    // first, for the same reason the fault knobs are: an ambient PATINA_BUGGIFY
    // must never enable buggify in a run that did not ask for it.
    for variable in BUGGIFY_ENV_VARS {
        command.env_remove(variable);
    }
    if let Some(buggify) = &invocation.buggify {
        for (name, value) in buggify_env_pairs(buggify) {
            command.env(name, value);
        }
    }
    if let Some(budget) = invocation.step_budget {
        command.env(ENV_STEP_BUDGET, budget.to_string());
    }
    if let Some(nanos) = invocation.realtime_epoch_nanos {
        command.env(ENV_REALTIME_EPOCH_NANOS, nanos.to_string());
    }
    if let Some(hostname) = &invocation.hostname {
        command.env(ENV_GUEST_HOSTNAME, hostname);
    }
    if !invocation.params.is_empty() {
        command.env(
            ENV_PARAMS_JSON,
            serde_json::to_string(&invocation.params)
                .map_err(|error| CliError(format!("failed to encode parameters: {error}")))?,
        );
    }

    match &invocation.mode {
        Mode::Seeded { seed } => {
            command
                .env(ENV_MODE, "seeded")
                .env(ENV_SEED, seed.to_string());
        }
        Mode::Record { seed, path } => {
            command
                .env(ENV_MODE, "record")
                .env(ENV_SEED, seed.to_string())
                .env(ENV_TRACE, path);
        }
        Mode::Replay { path, timeline } => {
            command
                .env(ENV_MODE, "replay")
                .env(ENV_TRACE, path)
                .env(ENV_TIMELINE, timeline);
        }
        Mode::Branch {
            path,
            parent,
            from_sequence,
            branch_seed,
            branch_id,
        } => {
            command
                .env(ENV_MODE, "branch")
                .env(ENV_TRACE, path)
                .env(ENV_PARENT_TIMELINE, parent)
                .env(ENV_BRANCH_FROM, from_sequence.to_string())
                .env(ENV_BRANCH_SEED, branch_seed.to_string())
                .env(ENV_BRANCH_ID, branch_id);
        }
    }
    if invocation.cargo_command == "test" {
        command.env("RUST_TEST_THREADS", "1");
    }
    // The structured run-facts channel. A cargo-family guest is not interposed,
    // so it writes the document to a plain path like it writes its trace.
    // Scrubbed first: an ambient value must never redirect a run's facts.
    command.env_remove(patina_dst_runtime::ENV_FACTS);
    command.env_remove(patina_dst_runtime::ENV_FACTS_FD);
    let facts_file = if output::facts_active() {
        Some(tempfile::NamedTempFile::new().map_err(|error| {
            CliError(format!("failed to create the run-facts channel: {error}"))
        })?)
    } else {
        None
    };
    if let Some(file) = &facts_file {
        command.env(patina_dst_runtime::ENV_FACTS, file.path());
    }

    let captured = output::execute_command(&mut command)?;

    // A successful `--record` run MUST have produced the trace. If the guest exited
    // 0 but wrote nothing, its runtime never engaged the recorder — a silent no-op
    // `--record` (exit 0, no file, no error), the worst outcome. Fail closed so the
    // caller cannot mistake it for a recording. (Only on success: a guest that
    // failed legitimately may not have reached the point of writing a trace.)
    if let Mode::Record { path, .. } = &invocation.mode {
        if captured.exit_code == 0 && !path.is_file() {
            return Err(CliError(format!(
                "record run exited 0 but wrote no trace to {}: the guest's runtime did \
not engage the recorder, so `--record` was a silent no-op. Ensure the package \
integrates the Patina runtime, or record under the native runtime: cargo patina run \
<DIR|Cargo.toml> --record <PATH>.",
                path.display()
            )));
        }
    }
    let (trace_path, seed, timeline) = match &invocation.mode {
        Mode::Seeded { seed } => (None, Some(*seed), "main".to_string()),
        Mode::Record { seed, path } => (Some(path.clone()), Some(*seed), "main".to_string()),
        Mode::Replay { path, timeline } => (Some(path.clone()), None, timeline.clone()),
        Mode::Branch {
            path, branch_id, ..
        } => (Some(path.clone()), None, branch_id.clone()),
    };
    let artifact = format!("cargo {}", invocation.cargo_command);
    let facts = read_facts_channel(facts_file.as_ref().map(tempfile::NamedTempFile::path))?;
    output::finalize_run(
        output::RunReport {
            verb: &invocation.cargo_command,
            family: "cargo",
            artifact: &artifact,
            trace_path,
            timeline: &timeline,
            fingerprint: Some(fingerprint),
            seed,
            coverage: None,
            depth: None,
            crash_restart: None,
            facts,
        },
        captured,
    )
}

/// Locate the Cargo workspace root, optionally resolving from `working_dir`
/// (the cargo-family `replay` verb's package directory) rather than the inherited
/// current directory. An explicit `--manifest-path` in `cargo_args` still wins.
fn workspace_root_in(
    working_dir: Option<&Path>,
    cargo_args: &[OsString],
) -> Result<PathBuf, CliError> {
    let cargo = env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let mut command = Command::new(cargo);
    command.args(["locate-project", "--workspace", "--message-format", "plain"]);
    if let Some(working_dir) = working_dir {
        command.current_dir(working_dir);
    }
    if let Some(path) = manifest_path(cargo_args)? {
        command.arg("--manifest-path").arg(path);
    }
    let output = command
        .output()
        .map_err(|error| CliError(format!("failed to locate Cargo workspace: {error}")))?;
    if !output.status.success() {
        return Err(CliError(format!(
            "cargo locate-project failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let manifest = String::from_utf8(output.stdout)
        .map_err(|_| CliError("cargo locate-project returned a non-UTF-8 path".into()))?;
    let manifest = PathBuf::from(manifest.trim());
    manifest.parent().map(Path::to_path_buf).ok_or_else(|| {
        CliError(format!(
            "workspace manifest has no parent: {}",
            manifest.display()
        ))
    })
}

fn manifest_path(arguments: &[OsString]) -> Result<Option<&OsStr>, CliError> {
    let mut index = 0;
    while index < arguments.len() {
        if arguments[index] == "--" {
            break;
        }
        if arguments[index] == "--manifest-path" {
            return arguments
                .get(index + 1)
                .map(|value| Some(value.as_os_str()))
                .ok_or_else(|| CliError::usage("--manifest-path requires a path"));
        }
        if let Some(value) = arguments[index]
            .to_str()
            .and_then(|value| value.strip_prefix("--manifest-path="))
        {
            return Ok(Some(OsStr::new(value)));
        }
        index += 1;
    }
    Ok(None)
}

fn patina_rustflags() -> OsString {
    let mut flags = env::var_os("RUSTFLAGS").unwrap_or_default();
    if !flags.is_empty() {
        flags.push(" ");
    }
    flags.push(PATINA_CFG_FLAGS);
    flags
}

/// Materialize `Cargo.lock` before the fingerprint is computed. The lockfile is
/// a fingerprint input, but a fresh workspace has none until the first build
/// writes one. Recording would then hash the pre-build state, while replay —
/// run after the build materialized the lockfile — hashes a file the recording
/// never saw and aborts with a spurious `FingerprintMismatch`. Generating it up
/// front (only when absent, so an existing lockfile's pins are never disturbed)
/// makes the record- and replay-time fingerprints observe the same lockfile.
fn ensure_lockfile(workspace: &Path) -> Result<(), CliError> {
    if workspace.join("Cargo.lock").exists() {
        return Ok(());
    }
    let cargo = env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let status = Command::new(cargo)
        .arg("generate-lockfile")
        .arg("--manifest-path")
        .arg(workspace.join("Cargo.toml"))
        .status()
        .map_err(|error| CliError(format!("failed to materialize Cargo.lock: {error}")))?;
    if !status.success() {
        return Err(CliError(
            "cargo generate-lockfile failed to materialize Cargo.lock".into(),
        ));
    }
    Ok(())
}

fn compatibility_fingerprint(
    workspace: &Path,
    invocation: &Invocation,
) -> Result<String, CliError> {
    let mut hasher = Sha256::new();
    hash_bytes(&mut hasher, b"patina-fingerprint-v1");
    hash_bytes(&mut hasher, env!("CARGO_PKG_VERSION").as_bytes());

    let rustc = Command::new("rustc")
        .arg("-vV")
        .output()
        .map_err(|error| CliError(format!("failed to query rustc identity: {error}")))?;
    if !rustc.status.success() {
        return Err(CliError(format!(
            "rustc -vV failed: {}",
            String::from_utf8_lossy(&rustc.stderr).trim()
        )));
    }
    hash_bytes(&mut hasher, &rustc.stdout);
    hash_bytes(&mut hasher, invocation.cargo_command.as_bytes());
    hash_os(&mut hasher, &patina_rustflags());
    for argument in &invocation.cargo_args {
        hash_os(&mut hasher, argument);
    }
    for (key, value) in &invocation.params {
        hash_bytes(&mut hasher, key.as_bytes());
        hash_bytes(&mut hasher, value.as_bytes());
    }

    let mut inputs = Vec::new();
    collect_inputs(workspace, workspace, &mut inputs)?;
    inputs.sort();
    for relative in inputs {
        hash_os(&mut hasher, relative.as_os_str());
        let contents = fs::read(workspace.join(&relative)).map_err(|error| {
            CliError(format!(
                "failed to read fingerprint input {}: {error}",
                workspace.join(&relative).display()
            ))
        })?;
        hash_bytes(&mut hasher, &contents);
    }

    Ok(format!("sha256:{}", hex(&hasher.finalize())))
}

fn collect_inputs(
    root: &Path,
    directory: &Path,
    inputs: &mut Vec<PathBuf>,
) -> Result<(), CliError> {
    let entries = fs::read_dir(directory).map_err(|error| {
        CliError(format!(
            "failed to read workspace directory {}: {error}",
            directory.display()
        ))
    })?;
    for entry in entries {
        let entry = entry.map_err(|error| {
            CliError(format!(
                "failed to inspect workspace directory {}: {error}",
                directory.display()
            ))
        })?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|error| CliError(format!("failed to inspect {}: {error}", path.display())))?;
        if file_type.is_dir() {
            if matches!(entry.file_name().to_str(), Some("target" | ".git" | ".jj")) {
                continue;
            }
            collect_inputs(root, &path, inputs)?;
        } else if file_type.is_file() && is_fingerprint_input(&path) {
            let relative = path.strip_prefix(root).map_err(|error| {
                CliError(format!(
                    "failed to make {} relative to {}: {error}",
                    path.display(),
                    root.display()
                ))
            })?;
            inputs.push(relative.to_path_buf());
        }
    }
    Ok(())
}

fn is_fingerprint_input(path: &Path) -> bool {
    path.file_name() == Some(OsStr::new("Cargo.lock"))
        || matches!(
            path.extension().and_then(|value| value.to_str()),
            Some("rs" | "toml")
        )
}

fn hash_bytes(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

#[cfg(unix)]
fn hash_os(hasher: &mut Sha256, value: &OsStr) {
    use std::os::unix::ffi::OsStrExt;
    hash_bytes(hasher, value.as_bytes());
}

#[cfg(windows)]
fn hash_os(hasher: &mut Sha256, value: &OsStr) {
    use std::os::windows::ffi::OsStrExt;
    let bytes = value
        .encode_wide()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    hash_bytes(hasher, &bytes);
}

fn hex(bytes: &[u8]) -> String {
    use fmt::Write;
    bytes.iter().fold(String::new(), |mut output, byte| {
        write!(output, "{byte:02x}").expect("writing to a String cannot fail");
        output
    })
}

/// Read back the structured `patina.runfacts/v1` document the run wrote to its
/// facts channel, or `None` when no channel was installed. A channel that was
/// installed but never written (the guest aborted before finalization) reads as
/// an empty file, which is `None` too — absent means "the run did not get that
/// far", never "zero".
fn read_facts_channel(path: Option<&Path>) -> Result<Option<serde_json::Value>, CliError> {
    let Some(path) = path else {
        return Ok(None);
    };
    let bytes = fs::read(path).map_err(|error| {
        CliError(format!(
            "failed to read the run-facts channel {}: {error}",
            path.display()
        ))
    })?;
    output::parse_facts(&bytes)
}

fn exit_code(status: ExitStatus) -> Result<i32, CliError> {
    status
        .code()
        .ok_or_else(|| CliError("Cargo process terminated by a signal".into()))
}

#[derive(Debug)]
pub struct CliError(String);

impl CliError {
    /// A usage error: the specific message, then the offending verb's synopsis
    /// lines (or the compact top-level list before a verb is resolved) and a
    /// `--help` pointer — never the whole help wall.
    fn usage(message: impl Into<String>) -> Self {
        Self(format!(
            "{}\n\n{}",
            message.into(),
            help::usage_synopsis(current_verb())
        ))
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CliError {}

#[cfg(test)]
mod tests;

#[cfg(all(test, unix))]
use native_run::{NativeChildStatus, native_child_status};
#[cfg(test)]
use patina_dst_trace::create_scratch;
