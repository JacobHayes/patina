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
use std::fs::{self, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use patina_dst_fs_mem::{FsImage, FsImageEntry};
use patina_dst_runtime::{
    Context, ENV_BRANCH_FROM, ENV_BRANCH_ID, ENV_BRANCH_SEED, ENV_BUGGIFY, ENV_BUGGIFY_ACTIVATION,
    ENV_BUGGIFY_AFTER_SETUP, ENV_BUGGIFY_CUTOFF, ENV_CONVERGE_WITHIN, ENV_COVERAGE_FD,
    ENV_DEFER_INIT, ENV_FINGERPRINT, ENV_FS_IMAGE_FD, ENV_GUEST_ARGV, ENV_GUEST_ENV,
    ENV_HEAL_AFTER, ENV_LIVENESS_WATCHDOG, ENV_MODE, ENV_PARAMS_JSON, ENV_PARENT_TIMELINE,
    ENV_SCHED_PCT, ENV_SCHED_PCT_STEPS, ENV_SCHED_STARVE, ENV_SCHED_STARVE_MAX_LEN,
    ENV_SCHED_STARVE_WINDOW, ENV_SEED, ENV_STEP_BUDGET, ENV_SWARM, ENV_TIMELINE, ENV_TRACE,
    ENV_TRACE_FD, FaultKnob, Plumbing, RuntimeConfig,
};
use patina_dst_target::{
    NativeAudit, NativeEscape, TargetError, WASI_PREVIEW1_TARGET, WasiAudit,
    native_binary_has_sud_marker, native_binary_has_tsc_marker, native_binary_is_shim_linked,
    native_deny_trap_armed, native_escape_is_sud_manageable, native_escape_is_tsc_manageable,
    native_host_identity_sites, render_cpu_nondeterminism_note, render_host_identity_note,
    render_inert_weak_imports, render_native_escapes_grouped, render_tsc_managed_note,
    shim_control_plane_symbols,
};
use patina_dst_trace::TraceBundle;
use patina_dst_wasi_host::{
    DEFAULT_WASM_FUEL, MountPolicy, Preview1Host, ResourceLimits, execute_preview1_with_fuel,
};
use sha2::{Digest, Sha256};

// Additive output-side modules: HTML timeline rendering and the machine-readable
// `--output json` envelope. Both are read-only consumers of trace/runtime
// semantics — they never record, replay, or mutate a trace — so rendering or
// emitting an envelope cannot perturb replay hashes.
mod aux_store;
mod campaign;
mod cli;
mod config;
mod coverage;
mod depth;
mod guided;
mod help;
mod minimize;
mod output;
mod render;
mod rollup;
mod sdk_report;
mod sites;
mod trace_cmd;
mod trace_view;
mod values;

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

// The native link recipe is packaged into `cargo patina` so `native-build` can
// reproduce it without the source tree: the POSIX shim C layer and its header
// are embedded, compiled below the user program, and linked against the
// `patina-dst-native-shim` staticlib. The C text is sourced from the shim crate
// itself (its `pub const`s) rather than an `include_str!` across the crate
// boundary, so there is a single copy of the C that cannot drift and both
// crates package cleanly for publish.
const PATINA_POSIX_C: &str = patina_dst_native_shim::POSIX_C_SOURCE;
const PATINA_NATIVE_H: &str = patina_dst_native_shim::NATIVE_HEADER;
/// Build-time deterministic-preemption hook, linked only under `--yield-points`.
const PATINA_YIELD_C: &str = include_str!("../c/patina_yield.c");
/// Weak, inert SanitizerCoverage entry points so an instrumented artifact that
/// links on its own — a dependency's unused `cdylib` — resolves them. Linked only
/// under `--yield-points`, alongside (and overridden by) `PATINA_YIELD_C`.
const PATINA_SANCOV_STUB_C: &str = include_str!("../c/patina_sancov_stub.c");
/// Marker string the `--yield-points` hook embeds; `native-run` looks for it in
/// the binary to fold yield-point scheduling into the compatibility fingerprint.
const PATINA_YIELD_MARKER: &[u8] = b"PATINA_YIELD_POINTS_V1";
/// Fingerprint suffix distinguishing a yield-point binary's schedule policy from
/// a plain one, so their recorded traces never cross-replay.
const PATINA_YIELD_FINGERPRINT_SUFFIX: &str = "+yieldpoints";
const NATIVE_SHIM_STATICLIB: &str = "libpatina_dst_native_shim.a";
/// Subdirectory of the shim's own profile target dir where the content-addressed
/// POSIX/yield helper objects are staged, so their `-Clink-arg` paths stay stable
/// across builds and Cargo's crate fingerprints stay warm.
const NATIVE_SHIM_OBJECTS_DIR: &str = "patina-shim-objects";
/// Cfg name carrying the hash of the shim link inputs a package build injects.
/// Nothing compiles against it; it exists so Cargo's fingerprint of the injected
/// `CARGO_ENCODED_RUSTFLAGS` tracks the shim's *bytes* — see
/// [`shim_link_inputs_hash`].
const SHIM_BUILD_CFG: &str = "patina_shim_build";
const DEFAULT_NATIVE_EDITION: &str = "2024";
const DEFAULT_NATIVE_FINGERPRINT: &str = "patina-native";
static NATIVE_TRACE_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);
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
    yield_points: bool,
    /// Boundary-operation budget forwarded to each seed's child `run`.
    step_budget: Option<u64>,
    /// Every fault knob this invocation set, re-emitted onto each seed's child
    /// `run` command line by [`knob_flag_pairs`].
    knobs: KnobValues,
    buggify: Option<NativeBuggify>,
    schedule: NativeSchedule,
    liveness: NativeLiveness,
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
    /// Instrument the guest with deterministic yield points (LLVM
    /// SanitizerCoverage → `patina_yield_point`) so atomics-only race windows are
    /// schedulable. Off by default; native builds never see it.
    yield_points: bool,
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
    /// Maximum boundary operations before the run fails explicitly (`--budget`),
    /// forwarded over the control plane. Family-neutral: the same
    /// `RuntimeConfig::step_budget` the Cargo and WASI families set.
    step_budget: Option<u64>,
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
/// control plane. Default-off. Deliberately kept SEPARATE from [`NativeSchedule`]
/// because the watchdog is schedule-invariant: enabling it folds NO fingerprint
/// component (it only adds a possible violation report), so a watchdog trace
/// replays against any build.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct NativeLiveness {
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
            Ok(0)
        }
        ParseResult::Run(invocation) => execute(invocation),
        ParseResult::Campaign(invocation) => campaign::execute(invocation),
        ParseResult::Coverage(invocation) => coverage::execute(invocation),
        ParseResult::Sites(invocation) => sites::execute(invocation),
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

enum ParseResult {
    Help(help::Topic),
    Version,
    Run(Invocation),
    Campaign(campaign::CampaignInvocation),
    Coverage(coverage::CoverageInvocation),
    Sites(sites::SitesInvocation),
    Explore(ExploreInvocation),
    WasiBuild(WasiBuildInvocation),
    WasiAudit(ArtifactRef),
    WasiRun(WasiInvocation),
    NativeAudit(NativeAuditInvocation),
    NativeBuild(NativeBuildInvocation),
    NativeRun(NativeRunInvocation),
    NativeHarness(NativeHarnessInvocation),
    Minimize(minimize::MinimizeInvocation),
    Trace(trace_cmd::TraceInvocation),
}

thread_local! {
    /// The verb a usage error should print the synopsis for, set as soon as
    /// routing identifies it. Unset (`None`) before verb resolution, so a
    /// top-level error prints the compact synopsis list. A CLI process parses
    /// once, single-threaded, so a thread-local is ample.
    static CURRENT_VERB: std::cell::RefCell<Option<&'static str>> =
        const { std::cell::RefCell::new(None) };
}

fn set_current_verb(verb: Option<&'static str>) {
    CURRENT_VERB.with(|cell| *cell.borrow_mut() = verb);
}

fn current_verb() -> Option<&'static str> {
    CURRENT_VERB.with(|cell| *cell.borrow())
}

/// Whether `flag`/`short` appears anywhere before a literal `--` separator. After
/// `--` the token belongs to the guest/oracle and is left untouched. The name may
/// be inline (`--flag=...` never applies to these valueless switches, so an exact
/// match is what matters).
fn flag_before_separator(arguments: &[OsString], long: &str, short: &str) -> bool {
    for argument in arguments {
        if argument == "--" {
            return false;
        }
        if argument == long || argument == short {
            return true;
        }
    }
    false
}

/// Whether `-h`/`--help` appears anywhere before a literal `--` separator.
fn help_requested(arguments: &[OsString]) -> bool {
    flag_before_separator(arguments, "--help", "-h")
}

/// Whether `-V`/`--version` appears anywhere before a literal `--` separator.
fn version_requested(arguments: &[OsString]) -> bool {
    flag_before_separator(arguments, "--version", "-V")
}

fn parse(mut arguments: Vec<OsString>) -> Result<ParseResult, CliError> {
    // `cargo patina ...` invokes this binary with a leading `patina` argument.
    if arguments.first().and_then(|value| value.to_str()) == Some("patina") {
        arguments.remove(0);
    }
    if arguments.is_empty() {
        return Err(CliError::usage(
            "missing command (expected run, test, campaign, explore, build, audit, replay, minimize, coverage, sites, or trace)",
        ));
    }
    // The routed verb (if any). Every known verb records itself so a usage error
    // prints that verb's synopsis, and `-h`/`--help` anywhere before `--` returns
    // that verb's focused help instead of being consumed as a positional. Owned so
    // the `arguments.remove(0)` below does not conflict with the borrow.
    let verb = arguments
        .first()
        .and_then(|value| value.to_str())
        .map(str::to_string);
    if let Some(name) = verb.as_deref() {
        if help::verb(name).is_some() {
            arguments.remove(0);
            let topic = help::topic_for(name);
            // Record the canonical verb name (a `'static` from the registry) so
            // later usage errors in the family parser point at the right section.
            if let help::Topic::Verb(canonical) = topic {
                set_current_verb(Some(canonical));
            }
            if help_requested(&arguments) {
                return Ok(ParseResult::Help(topic));
            }
            // `-V`/`--version` is intercepted everywhere before `--`, exactly like
            // `--help`, so every verb honors it (not just the top level and the
            // cargo family).
            if version_requested(&arguments) {
                return Ok(ParseResult::Version);
            }
            return match name {
                "campaign" => campaign::parse(arguments).map(ParseResult::Campaign),
                "coverage" => coverage::parse(arguments).map(ParseResult::Coverage),
                "sites" => sites::parse(arguments).map(ParseResult::Sites),
                "explore" => parse_explore(arguments).map(ParseResult::Explore),
                "build" => parse_build(arguments),
                "audit" => parse_audit(arguments),
                "run" => parse_run(arguments),
                "test" => parse_test(arguments),
                // `replay` is the sole replay entry point for all three families,
                // routed by the same artifact inference as `run`: it restores each
                // family's semantic config (seed, fault knobs, buggify, guest argv)
                // from the trace and exposes no semantic flags.
                "replay" => parse_replay(arguments),
                "minimize" => parse_minimize(arguments).map(ParseResult::Minimize),
                "trace" => parse_trace(arguments).map(ParseResult::Trace),
                _ => unreachable!("verb() gated the known-verb set"),
            };
        }
    }
    match verb.as_deref() {
        Some("-h" | "--help") => Ok(ParseResult::Help(help::Topic::Overview)),
        Some("-V" | "--version") => Ok(ParseResult::Version),
        _ => Err(CliError::usage(format!(
            "unsupported command {:?}; expected run, test, campaign, explore, build, audit, replay, minimize, coverage, sites, or trace",
            arguments[0].to_string_lossy()
        ))),
    }
}

/// A compiled artifact's target family, inferred from its leading magic bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ArtifactFamily {
    /// A WebAssembly module (`\0asm` preamble) → the WASI runner/audit path.
    Wasm,
    /// A native executable (Mach-O or ELF magic) → the native runner/audit path.
    Native,
}

/// Classify a compiled artifact by its leading magic bytes. Pure and
/// filesystem-free so it is unit-testable on byte slices; returns `None` for
/// anything that is neither a WebAssembly module nor a native Mach-O/ELF image
/// (a `Cargo.toml`, a shell script, an empty file, ...).
fn detect_artifact_family(bytes: &[u8]) -> Option<ArtifactFamily> {
    // WebAssembly: the four-byte `\0asm` preamble.
    if bytes.starts_with(b"\0asm") {
        return Some(ArtifactFamily::Wasm);
    }
    // ELF: 0x7F 'E' 'L' 'F'.
    if bytes.starts_with(&[0x7f, b'E', b'L', b'F']) {
        return Some(ArtifactFamily::Native);
    }
    // Mach-O: thin 32/64-bit in either byte order, plus universal ("fat")
    // archives. Each four-byte magic is matched exactly.
    const MACH_O_MAGICS: [[u8; 4]; 6] = [
        [0xfe, 0xed, 0xfa, 0xce], // MH_MAGIC (32-bit)
        [0xce, 0xfa, 0xed, 0xfe], // MH_CIGAM (32-bit, byte-swapped)
        [0xfe, 0xed, 0xfa, 0xcf], // MH_MAGIC_64 (64-bit)
        [0xcf, 0xfa, 0xed, 0xfe], // MH_CIGAM_64 (64-bit, byte-swapped)
        [0xca, 0xfe, 0xba, 0xbe], // FAT_MAGIC (universal)
        [0xbe, 0xba, 0xfe, 0xca], // FAT_CIGAM (universal, byte-swapped)
    ];
    if MACH_O_MAGICS.iter().any(|magic| bytes.starts_with(magic)) {
        return Some(ArtifactFamily::Native);
    }
    None
}

/// Read the leading magic bytes of `path` and classify it with
/// [`detect_artifact_family`]. Only a short prefix is read, so a multi-megabyte
/// native binary is not slurped merely to route it.
fn artifact_family(path: &Path) -> Result<Option<ArtifactFamily>, CliError> {
    use std::io::Read;
    let mut file = fs::File::open(path).map_err(|error| {
        CliError(format!(
            "failed to open artifact {}: {error}",
            path.display()
        ))
    })?;
    let mut prefix = [0u8; 8];
    let read = file.read(&mut prefix).map_err(|error| {
        CliError(format!(
            "failed to read artifact {}: {error}",
            path.display()
        ))
    })?;
    Ok(detect_artifact_family(&prefix[..read]))
}

/// Extract a `--target native|wasi` selector from the leading (pre-`--`) region
/// of an argument list, returning it plus the arguments with the selector
/// removed. A `--target` after a `--` separator is left in place — there it is a
/// rustc/cargo flag, not Patina's family selector.
fn extract_target(arguments: Vec<OsString>) -> Result<(Option<String>, Vec<OsString>), CliError> {
    let (found, rest) = cli::strip(&[cli::flag("run", "--target")], arguments)?;
    let target = cli::single(&found, "--target")?.map(|value| value.to_string_lossy().into_owned());
    Ok((target, rest))
}

/// Map a `--target` value to its artifact family.
fn target_family(target: &str) -> Result<ArtifactFamily, CliError> {
    match target {
        "native" => Ok(ArtifactFamily::Native),
        "wasi" => Ok(ArtifactFamily::Wasm),
        other => Err(CliError::usage(format!(
            "--target must be native or wasi; got {other:?}"
        ))),
    }
}

/// How a run/audit/replay positional argument classifies. The single shared
/// resolution step (unit-tested via [`classify_arg`]) decides between using an
/// already-built artifact directly and building a source/package on the fly.
enum ArgKind {
    /// An existing file with WebAssembly or native Mach-O/ELF magic.
    Artifact(ArtifactFamily),
    /// A single `.rs` source (built native).
    SourceFile(PathBuf),
    /// A directory or `Cargo.toml` (a Cargo package), resolved to its manifest.
    SourcePackage(PathBuf),
    /// A leading flag, or a plain non-source file: neither artifact nor source.
    Other,
}

/// Whether a positional token is unmistakably a filesystem path (so a
/// nonexistent one is a mistake to surface, not a plausible bare Cargo argument):
/// it names a `.wasm`/`.rs`/`Cargo.toml`, or contains a path separator.
fn looks_like_path(raw: &OsStr) -> bool {
    let Some(text) = raw.to_str() else {
        // A non-UTF-8 token is never a bare Cargo argument; treat it as a path.
        return true;
    };
    text.ends_with(".wasm")
        || text.ends_with(".rs")
        || Path::new(text).file_name() == Some(OsStr::new("Cargo.toml"))
        || text.contains('/')
        || text.contains(std::path::MAIN_SEPARATOR)
}

/// Classify a run/audit/replay positional argument. A built artifact is
/// recognized by leading magic bytes (used directly); an existing `.rs`,
/// directory, or `Cargo.toml` is a source/package to build; a bare name that does
/// not exist is `Other` (a plausible Cargo argument, left to the cargo family).
/// A token that clearly names a file path (`.wasm`/`.rs`/`Cargo.toml`, or with a
/// separator) but does not exist is a hard error — fail closed rather than let
/// `run nonexistent.wasm` fall through to a confusing `cargo run` failure.
fn classify_arg(raw: &OsStr) -> Result<ArgKind, CliError> {
    if raw.to_str().is_some_and(|value| value.starts_with('-')) {
        return Ok(ArgKind::Other);
    }
    let path = Path::new(raw);
    if path.is_dir() {
        return Ok(ArgKind::SourcePackage(native_manifest_path(path)));
    }
    if path.is_file() {
        if let Some(family) = artifact_family(path)? {
            return Ok(ArgKind::Artifact(family));
        }
        if path.file_name() == Some(OsStr::new("Cargo.toml")) {
            return Ok(ArgKind::SourcePackage(path.to_path_buf()));
        }
        if path.extension().and_then(OsStr::to_str) == Some("rs") {
            return Ok(ArgKind::SourceFile(path.to_path_buf()));
        }
        // An existing file that is neither an artifact nor a source: not ours.
        return Ok(ArgKind::Other);
    }
    // The token does not exist. If it plainly names a file path, fail closed;
    // otherwise it is a bare name the cargo family may interpret.
    if looks_like_path(raw) {
        return Err(CliError::usage(format!("no such file: {}", path.display())));
    }
    Ok(ArgKind::Other)
}

/// Build spec for a single-source native build on the fly (defaults: current
/// edition, debug, no yield points, no extra rustc args).
fn native_source_spec(source: PathBuf) -> BuildSpec {
    BuildSpec {
        origin: source.clone(),
        kind: BuildSpecKind::Native(NativeBuildInvocation {
            target: NativeBuildTarget::Source {
                source,
                edition: DEFAULT_NATIVE_EDITION.to_string(),
                rustc_args: Vec::new(),
            },
            output: None,
            release: false,
            yield_points: false,
        }),
    }
}

/// Build spec for a native Cargo-package build on the fly. Binary selection is
/// automatic (fails closed on ambiguity, like the `build` verb).
fn native_package_spec(origin: PathBuf, manifest: PathBuf) -> BuildSpec {
    BuildSpec {
        origin,
        kind: BuildSpecKind::Native(NativeBuildInvocation {
            target: NativeBuildTarget::Package {
                manifest,
                package: None,
                bin: None,
            },
            output: None,
            release: false,
            yield_points: false,
        }),
    }
}

/// Build spec for a WASI Cargo-package build on the fly.
fn wasi_package_spec(origin: PathBuf, manifest: PathBuf) -> BuildSpec {
    BuildSpec {
        origin,
        kind: BuildSpecKind::Wasi(WasiBuildInvocation {
            manifest,
            package: None,
            bin: None,
            release: false,
            output: None,
        }),
    }
}

/// Extract source-first `--package NAME`/`-p NAME` and `--bin NAME` from the head
/// of a `run`/`audit` flag list and return them with the remaining flags. When a
/// `run`/`audit` argument is a directory/`Cargo.toml` built on the fly, these
/// select the workspace member and binary exactly as the `build` verb does — the
/// help advertises the form (`audit <Cargo.toml> --package X --bin Y`), so audit
/// and run must honor it rather than reject it. Scanning stops at a `--`
/// separator so a `--package` in the guest/rustc argument section is passed
/// through untouched, and the flags are consumed here (not by the family parser),
/// so a package build and a single-source/prebuilt input get a uniform, precise
/// error via [`apply_package_selection`].
struct SourceFirstSelection {
    package: Option<String>,
    bin: Option<String>,
    /// The flags with `--package`/`--bin` removed, handed to the family parser.
    rest: Vec<OsString>,
}

fn take_package_bin(flags: Vec<OsString>) -> Result<SourceFirstSelection, CliError> {
    let (found, rest) = cli::strip(
        &[cli::flag("run", "--package"), cli::flag("run", "--bin")],
        flags,
    )?;
    Ok(SourceFirstSelection {
        package: cli::single(&found, "--package")?
            .map(|value| value.to_string_lossy().into_owned()),
        bin: cli::single(&found, "--bin")?.map(|value| value.to_string_lossy().into_owned()),
        rest,
    })
}

/// Thread source-first `--package`/`--bin` selection into a build-on-the-fly
/// artifact. Only a Cargo-package build honors them (a workspace member and its
/// binary, exactly as the `build` verb selects them); a single `.rs` source or an
/// already-built artifact has nothing to select, so a stray flag fails closed
/// with a precise message rather than being silently ignored.
fn apply_package_selection(
    artifact: &mut ArtifactRef,
    package: Option<String>,
    bin: Option<String>,
) -> Result<(), CliError> {
    if package.is_none() && bin.is_none() {
        return Ok(());
    }
    match artifact {
        ArtifactRef::Build(spec) => match &mut spec.kind {
            BuildSpecKind::Native(invocation) => match &mut invocation.target {
                NativeBuildTarget::Package {
                    package: pkg,
                    bin: binary,
                    ..
                } => {
                    if package.is_some() {
                        *pkg = package;
                    }
                    if bin.is_some() {
                        *binary = bin;
                    }
                    Ok(())
                }
                NativeBuildTarget::Source { .. } => Err(CliError::usage(
                    "--package and --bin apply to a Cargo-package build, not a single source file",
                )),
            },
            BuildSpecKind::Wasi(invocation) => {
                if package.is_some() {
                    invocation.package = package;
                }
                if bin.is_some() {
                    invocation.bin = bin;
                }
                Ok(())
            }
        },
        ArtifactRef::Prebuilt(_) => Err(CliError::usage(
            "--package and --bin select a member to build; they do not apply to an already-built artifact",
        )),
    }
}

/// Extract a source-first `--release` switch from the head of a `run` flag list,
/// stopping at `--` so a guest/program `--release` after the separator passes
/// through untouched. Mirrors [`take_package_bin`]: the flag is consumed here so
/// the family parser (which rejects unknown options) never sees it. Repeats are
/// idempotent, matching the `build` parser; an inline `--release=VALUE` is
/// rejected because the switch takes no value.
fn take_release(flags: Vec<OsString>) -> Result<(bool, Vec<OsString>), CliError> {
    let (found, rest) = cli::strip(&[cli::flag("run", "--release")], flags)?;
    Ok((found.contains_key("--release"), rest))
}

/// Apply a source-first `--release` to a build-on-the-fly artifact: it selects the
/// release profile for the guest `run` builds itself (default debug). Release is a
/// build profile, so it applies only to a source/package built on the fly; an
/// already-built artifact carries no profile of its own, so `--release` on a
/// prebuilt positional fails closed rather than being silently ignored.
fn apply_release(artifact: &mut ArtifactRef, release: bool) -> Result<(), CliError> {
    if !release {
        return Ok(());
    }
    match artifact {
        ArtifactRef::Build(spec) => {
            match &mut spec.kind {
                BuildSpecKind::Native(invocation) => invocation.release = true,
                BuildSpecKind::Wasi(invocation) => invocation.release = true,
            }
            Ok(())
        }
        ArtifactRef::Prebuilt(_) => Err(CliError::usage(
            "--release selects a build profile for a source/package built on the fly; an already-built artifact has no build profile",
        )),
    }
}

/// Resolve a run/audit/replay positional to an [`ArtifactRef`], honoring
/// `--target` (default native) and building a source/package on the fly. A
/// directory/`Cargo.toml` resolves to a native (or, under `--target wasi`, WASI)
/// build-on-the-fly exactly like a `.rs` source — the SAME path `audit` uses, so
/// a positional naming an existing package is never silently reinterpreted as
/// guest argv. `None` is returned only when the positional is neither an
/// artifact nor a source (a leading flag or a plain file); the caller then falls
/// through to its no-artifact behavior. Whether a runtime-linked package is
/// instead kept on the cargo-family path is a routing decision the `run`/`replay`
/// callers make up front via [`package_integrates_patina`]; this resolver is pure
/// classification.
fn resolve_positional(
    raw: &OsStr,
    target: Option<&str>,
) -> Result<Option<(ArtifactFamily, ArtifactRef)>, CliError> {
    match classify_arg(raw)? {
        ArgKind::Artifact(family) => {
            if let Some(target) = target {
                let requested = target_family(target)?;
                if requested != family {
                    return Err(CliError::usage(format!(
                        "--target {target} does not match {}, an already-built {} artifact",
                        Path::new(raw).display(),
                        family_label(family)
                    )));
                }
            }
            Ok(Some((family, ArtifactRef::Prebuilt(PathBuf::from(raw)))))
        }
        ArgKind::SourceFile(source) => {
            let family = match target {
                Some(target) => target_family(target)?,
                None => ArtifactFamily::Native,
            };
            if family == ArtifactFamily::Wasm {
                return Err(CliError::usage(
                    "build --target wasi compiles a Cargo package; a single .rs source is native-only",
                ));
            }
            Ok(Some((
                family,
                ArtifactRef::Build(Box::new(native_source_spec(source))),
            )))
        }
        ArgKind::SourcePackage(manifest) => match target {
            None => Ok(Some((
                ArtifactFamily::Native,
                ArtifactRef::Build(Box::new(native_package_spec(PathBuf::from(raw), manifest))),
            ))),
            Some(target) => {
                let family = target_family(target)?;
                let spec = match family {
                    ArtifactFamily::Native => native_package_spec(PathBuf::from(raw), manifest),
                    ArtifactFamily::Wasm => wasi_package_spec(PathBuf::from(raw), manifest),
                };
                Ok(Some((family, ArtifactRef::Build(Box::new(spec)))))
            }
        },
        ArgKind::Other => {
            if target.is_some() {
                return Err(CliError::usage(format!(
                    "--target requires a source or package to build; {} is neither a .rs source, a directory, nor a Cargo.toml",
                    Path::new(raw).display()
                )));
            }
            Ok(None)
        }
    }
}

fn family_label(family: ArtifactFamily) -> &'static str {
    match family {
        ArtifactFamily::Wasm => "WebAssembly",
        ArtifactFamily::Native => "native",
    }
}

/// Does the Cargo package integrate the Patina runtime? True iff `cargo metadata
/// --no-deps` reports a declared dependency in [`PATINA_RUNTIME_CRATES`]. This is
/// the routing predicate that keeps a runtime-linked package on the cargo-family
/// path (where the linked runtime provides seeding, recording, replay, and
/// library-level determinism) while a plain package is built shim-linked and run
/// under the native pre-run gate. Any failure to resolve the metadata (no cargo,
/// an unreadable or invalid manifest, ...) answers `false`: a package we cannot
/// prove integrates the runtime is treated as plain — routed to the gated native
/// path or refused loudly — never silently trusted to a no-op cargo-family run.
///
/// `manifest` scopes the query to a positional package path; `cwd` scopes it to a
/// working directory (the cwd-package `run`). At most one is set.
fn package_integrates_patina(manifest: Option<&Path>, cwd: Option<&Path>) -> bool {
    let cargo = env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let mut command = Command::new(&cargo);
    command
        .arg("metadata")
        .arg("--no-deps")
        .arg("--format-version")
        .arg("1")
        .stderr(Stdio::null());
    if let Some(manifest) = manifest {
        command.arg("--manifest-path").arg(manifest);
    }
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    let stdout = match command.output() {
        Ok(output) if output.status.success() => output.stdout,
        _ => return false,
    };
    let metadata: serde_json::Value = match serde_json::from_slice(&stdout) {
        Ok(value) => value,
        Err(_) => return false,
    };
    metadata
        .get("packages")
        .and_then(|value| value.as_array())
        .is_some_and(|packages| {
            packages.iter().any(|package| {
                package
                    .get("dependencies")
                    .and_then(|value| value.as_array())
                    .is_some_and(|deps| {
                        deps.iter().any(|dep| {
                            dep.get("name")
                                .and_then(|value| value.as_str())
                                .is_some_and(|name| PATINA_RUNTIME_CRATES.contains(&name))
                        })
                    })
            })
        })
}

/// The result of scanning a verb's leading region for its positional
/// argument(s) with [`locate_positionals`].
pub(crate) struct PositionalScan {
    /// The located positionals, in encounter order (at most `wanted`).
    pub(crate) positionals: Vec<OsString>,
    /// Every other token, order preserved, with the located positionals removed —
    /// handed to the family parser exactly as the whole tail was handed before.
    pub(crate) rest: Vec<OsString>,
    /// The index (into the scanned slice) of the first UNREGISTERED flag that
    /// halted the scan before `wanted` positionals were found, or `None` when the
    /// scan located everything or reached `--`/end seeing only registered flags.
    pub(crate) stop: Option<usize>,
}

/// Locate up to `wanted` leading positional argument(s) for `verb`, consulting
/// the registry ([`help::flag_arity`]) for flag arity so options may appear in
/// any order around the positional — the `cargo build`/`cargo run` ergonomic.
///
/// The scan walks the pre-`--` region left-to-right: a flag REGISTERED for
/// `verb` is skipped, and its value token too when the registry says the value
/// is `Required` and no inline `=` is present; the first UNREGISTERED
/// flag-looking token stops the scan conservatively — beyond it a token may be
/// the value of an unknown passthrough flag (a forwarded cargo flag like
/// `--manifest-path ./x/Cargo.toml`), and misreading a value as the artifact
/// would corrupt routing. Non-flag tokens are the positionals, collected in
/// order until `wanted` are found. The registry stays authoritative: arity comes
/// only from it, never a second table.
pub(crate) fn locate_positionals(
    verb: &str,
    arguments: &[OsString],
    wanted: usize,
) -> PositionalScan {
    let mut positionals = Vec::new();
    let mut taken = Vec::new();
    let mut stop = None;
    let mut index = 0;
    while index < arguments.len() && positionals.len() < wanted {
        let argument = &arguments[index];
        if argument == "--" {
            break;
        }
        if let Some(text) = argument.to_str() {
            if text.starts_with('-') {
                let name = cli::split_name(text);
                match help::flag_arity(verb, name) {
                    Some(help::Value::Required(..)) if name == text => {
                        // A registered value-taking flag consumes the next token.
                        index += 2;
                        continue;
                    }
                    Some(_) => {
                        // A registered valueless/optional flag, or one with an
                        // inline `=VALUE`: it consumes no separate token.
                        index += 1;
                        continue;
                    }
                    None => {
                        // Unknown flag: stop conservatively.
                        stop = Some(index);
                        break;
                    }
                }
            }
        }
        // A non-flag (or non-UTF-8) token is a positional.
        positionals.push(argument.clone());
        taken.push(index);
        index += 1;
    }
    let rest = arguments
        .iter()
        .enumerate()
        .filter(|(index, _)| !taken.contains(index))
        .map(|(_, argument)| argument.clone())
        .collect();
    PositionalScan {
        positionals,
        rest,
        stop,
    }
}

/// Whether `raw` is an existing file whose magic bytes identify it as a compiled
/// artifact (a `.wasm` module or a native binary). Such a file is NEVER the value
/// of a cargo flag, so an unknown flag standing in front of it is a misuse, not a
/// forwarded flag with a value.
fn existing_compiled_artifact(raw: &OsStr) -> bool {
    let path = Path::new(raw);
    path.is_file() && matches!(artifact_family(path), Ok(Some(_)))
}

/// Whether `raw` names an existing artifact or source/package (a compiled
/// binary, a `.rs` source, a `Cargo.toml`, or a directory) — anything the
/// positional resolver would route to a real family.
fn existing_artifact_or_source(raw: &OsStr) -> bool {
    matches!(
        classify_arg(raw),
        Ok(ArgKind::Artifact(_) | ArgKind::SourceFile(_) | ArgKind::SourcePackage(_))
    )
}

/// Whether `raw` is a path-like token (`.wasm`/`.rs`/`Cargo.toml`, or with a
/// separator) that does not exist — the same shape [`classify_arg`] fails closed
/// on. Behind an unknown flag it is a clearly-named artifact path the user
/// misplaced, not a plausible bare cargo argument.
fn stranded_path_like(raw: &OsStr) -> bool {
    !Path::new(raw).exists()
        && looks_like_path(raw)
        && !raw.to_str().is_some_and(|text| text.starts_with('-'))
}

/// The loud routing error raised when a genuine artifact is stranded behind an
/// unknown flag.
fn stranded_artifact_error(verb: &str, unknown_flag: &OsStr, artifact: &OsStr) -> CliError {
    CliError::usage(format!(
        "unknown option {:?} ahead of artifact {:?}; options and the artifact may appear in any \
order, but an unknown option is only forwarded in the Cargo package family — check the flag name \
(run `cargo patina {verb} --help`)",
        unknown_flag.to_string_lossy(),
        artifact.to_string_lossy(),
    ))
}

/// After [`locate_positionals`] halted on an unregistered flag without locating
/// the artifact, decide the honest outcome — never a silent surprise. `tail`
/// begins at that unknown flag. A genuine artifact/path stranded behind it is a
/// loud routing error (an unknown option only ever forwards in the Cargo family,
/// and every artifact family rejects an unknown flag anyway, so a real artifact
/// after it can only be a misuse); otherwise `Ok(())` lets the caller forward the
/// list to its no-artifact family. The token immediately after an unknown flag is
/// that flag's presumed value (`--manifest-path ./x/Cargo.toml`) and is exempt
/// UNLESS it is a compiled artifact, which is never a flag value.
pub(crate) fn reject_stranded_artifact(verb: &str, tail: &[OsString]) -> Result<(), CliError> {
    let unknown = tail.first().cloned().unwrap_or_default();
    let mut index = 0;
    let mut after_unknown_flag = false;
    while index < tail.len() {
        let argument = &tail[index];
        if argument == "--" {
            break;
        }
        if let Some(text) = argument.to_str() {
            if text.starts_with('-') {
                let name = cli::split_name(text);
                match help::flag_arity(verb, name) {
                    Some(help::Value::Required(..)) if name == text => {
                        index += 2;
                        after_unknown_flag = false;
                        continue;
                    }
                    Some(_) => {
                        index += 1;
                        after_unknown_flag = false;
                        continue;
                    }
                    None => {
                        after_unknown_flag = true;
                        index += 1;
                        continue;
                    }
                }
            }
        }
        if after_unknown_flag {
            // The presumed value of the preceding unknown flag: exempt unless it
            // is a compiled artifact (never a flag value).
            if existing_compiled_artifact(argument) {
                return Err(stranded_artifact_error(verb, &unknown, argument));
            }
            after_unknown_flag = false;
            index += 1;
            continue;
        }
        // A "free" token beyond any flag's value: an existing artifact/source or a
        // path-like nonexistent token here is a misplaced artifact.
        if existing_artifact_or_source(argument) || stranded_path_like(argument) {
            return Err(stranded_artifact_error(verb, &unknown, argument));
        }
        index += 1;
    }
    Ok(())
}

/// Route `run`: source-first with artifacts accepted uniformly. A built
/// artifact runs as-is (family from magic); a `.rs`/dir/`Cargo.toml` with
/// `--target` (or a lone `.rs`) builds on the fly then runs; a dir/`Cargo.toml`
/// with no `--target`, a leading flag, or no artifact is the Cargo package
/// family — the same machinery as `test`.
fn parse_run(arguments: Vec<OsString>) -> Result<ParseResult, CliError> {
    let (target, rest) = extract_target(arguments)?;
    // Options may lead the artifact: locate it registry-arity-aware rather than
    // insisting it be the first token.
    let scan = locate_positionals("run", &rest, 1);
    let Some(first) = scan.positionals.first().cloned() else {
        // No artifact located. If the scan stopped at an unknown flag, refuse
        // loudly when a real artifact is stranded behind it; otherwise the
        // unknown flag is a genuine forwarded cargo flag (`run --manifest-path X`)
        // and the whole list stays the Cargo package family.
        if let Some(stop) = scan.stop {
            reject_stranded_artifact("run", &rest[stop..])?;
        }
        if target.is_some() {
            return Err(CliError::usage(
                "--target requires a source or package to build; `run` with no artifact is the Cargo package family",
            ));
        }
        return parse_cargo("run".to_string(), rest);
    };
    // A directory/`Cargo.toml` positional (no `--target`) that integrates the
    // Patina runtime stays the cargo-family path — the linked runtime owns
    // seeding, recording, replay, and `--param`/`--budget`. A plain package has no
    // such runtime, so it falls through to `resolve_positional`, which builds it
    // shim-linked and runs it under the native pre-run gate exactly like `audit`
    // (and exactly like a prebuilt binary). Either way an existing directory
    // resolves as a source and is NEVER passed through as guest argv.
    if target.is_none() {
        if let ArgKind::SourcePackage(manifest) = classify_arg(&first)? {
            if package_integrates_patina(Some(&manifest), None) {
                return parse_cargo("run".to_string(), rest);
            }
        }
    }
    match resolve_positional(&first, target.as_deref())? {
        Some((ArtifactFamily::Wasm, mut module)) => {
            let selection = take_package_bin(scan.rest)?;
            apply_package_selection(&mut module, selection.package, selection.bin)?;
            let (release, rest) = take_release(selection.rest)?;
            apply_release(&mut module, release)?;
            parse_wasi_run_from(module, rest).map(ParseResult::WasiRun)
        }
        Some((ArtifactFamily::Native, mut binary)) => {
            let selection = take_package_bin(scan.rest)?;
            apply_package_selection(&mut binary, selection.package, selection.bin)?;
            let (release, rest) = take_release(selection.rest)?;
            apply_release(&mut binary, release)?;
            parse_native_run_from(binary, rest).map(ParseResult::NativeRun)
        }
        // Cargo package family: forward the whole argument list (including the
        // positional dir/Cargo.toml, which Cargo interprets) to `parse_cargo`.
        None => parse_cargo("run".to_string(), rest),
    }
}

/// Route `test`: with no source positional this remains the Cargo package
/// family; a directory or `Cargo.toml` positional selects the native libtest
/// harness mode used by point-solution DST tests.
fn parse_test(arguments: Vec<OsString>) -> Result<ParseResult, CliError> {
    let scan = locate_positionals("test", &arguments, 1);
    let Some(first) = scan.positionals.first().cloned() else {
        if let Some(stop) = scan.stop {
            reject_stranded_artifact("test", &arguments[stop..])?;
        }
        return parse_cargo("test".to_string(), arguments);
    };
    match classify_arg(&first)? {
        ArgKind::SourcePackage(manifest) => {
            parse_native_harness_from(PathBuf::from(&first), manifest, scan.rest)
                .map(ParseResult::NativeHarness)
        }
        ArgKind::SourceFile(_) => Err(CliError::usage(
            "test native harness mode requires a Cargo package (directory or Cargo.toml), not a single .rs source",
        )),
        ArgKind::Artifact(_) => Err(CliError::usage(
            "test native harness mode requires a Cargo package (directory or Cargo.toml), not a prebuilt artifact",
        )),
        ArgKind::Other => parse_cargo("test".to_string(), arguments),
    }
}

fn parse_native_harness_from(
    origin: PathBuf,
    manifest: PathBuf,
    arguments: Vec<OsString>,
) -> Result<NativeHarnessInvocation, CliError> {
    if arguments.iter().any(|argument| argument == "--") {
        return Err(CliError::usage(
            "test native harness mode does not accept a `--` tail; it supplies the libtest --exact filter itself",
        ));
    }
    let selection = take_package_bin(arguments)?;
    if selection.bin.is_some() {
        return Err(CliError::usage(
            "--bin does not select a libtest harness; use --harness-target with the Cargo test target name",
        ));
    }
    let args = cli::parse("test", help::Family::Harness, selection.rest)?;
    let seed = args.u64("--seed");
    let seeds = args.u64("--seeds");
    if seed.is_some() && seeds.is_some() {
        return Err(CliError::usage("--seed and --seeds are mutually exclusive"));
    }
    if let Some(count) = seeds {
        if count == 0 || count > 1_000_000 {
            return Err(CliError::usage("--seeds must be between 1 and 1000000"));
        }
    }
    Ok(NativeHarnessInvocation {
        origin,
        manifest,
        package: selection.package,
        harness_target: args.string("--harness-target").ok_or_else(|| {
            CliError::usage("test native harness mode requires --harness-target <NAME>")
        })?,
        exact: args
            .string("--exact")
            .ok_or_else(|| CliError::usage("test native harness mode requires --exact <PATH>"))?,
        seeds: seed
            .map(HarnessSeeds::One)
            .unwrap_or_else(|| HarnessSeeds::Range(seeds.unwrap_or(20))),
        release: args.flag("--release"),
        yield_points: args.flag("--yield-points"),
        step_budget: args.u64("--budget"),
        knobs: knobs_of(&args)?,
        buggify: buggify_of(&args),
        schedule: schedule_of(&args),
        liveness: liveness_of(&args),
    })
}

/// Route `audit`: source-first, artifacts accepted. A native binary (built or
/// built-on-the-fly) goes to the symbol audit; a WASI module lists its imports
/// (and takes no `--allow`, which is native-only). A dir/`Cargo.toml` with no
/// `--target` builds native (audit has no Cargo package family).
fn parse_audit(arguments: Vec<OsString>) -> Result<ParseResult, CliError> {
    let (target, rest) = extract_target(arguments)?;
    // Options may lead the artifact.
    let scan = locate_positionals("audit", &rest, 1);
    let Some(first) = scan.positionals.first().cloned() else {
        // `audit` has no Cargo package family, so a missing artifact is always an
        // error — but name the offending unknown flag (and refuse loudly if a real
        // artifact is stranded behind it) rather than a bare "requires an artifact".
        if let Some(stop) = scan.stop {
            reject_stranded_artifact("audit", &rest[stop..])?;
            return Err(CliError::usage(format!(
                "unsupported option {:?} for `audit`; audit requires an artifact or source path",
                rest[stop].to_string_lossy()
            )));
        }
        return Err(CliError::usage("audit requires an artifact or source path"));
    };
    let (family, mut artifact) = resolve_positional(&first, target.as_deref())?
        .ok_or_else(|| {
            CliError::usage(format!(
                "audit target {} is neither a WebAssembly module, a native binary, nor a source/package to build",
                Path::new(&first).display()
            ))
        })?;
    // Source-first `--package`/`--bin` select the workspace member/binary to build
    // before the audit — the help advertises the form, so it must not be rejected.
    // Consumed here, uniformly for both families, so the family parser sees only
    // its own flags.
    let selection = take_package_bin(scan.rest)?;
    apply_package_selection(&mut artifact, selection.package, selection.bin)?;
    let flags = selection.rest;
    match family {
        ArtifactFamily::Native => {
            parse_native_audit_from(artifact, flags).map(ParseResult::NativeAudit)
        }
        ArtifactFamily::Wasm => {
            cli::parse("audit", help::Family::Wasi, flags)?;
            Ok(ParseResult::WasiAudit(artifact))
        }
    }
}

/// Route `build`: extract `--target` (default `native`) and dispatch to the
/// native or WASI package builder. The rest of the argument vector is handed to
/// the per-target parser unchanged, so each target keeps its exact flag set.
fn parse_build(arguments: Vec<OsString>) -> Result<ParseResult, CliError> {
    let (target, rest) = extract_target(arguments)?;
    match target_family(target.as_deref().unwrap_or("native"))? {
        ArtifactFamily::Native => parse_native_build(rest).map(ParseResult::NativeBuild),
        ArtifactFamily::Wasm => parse_wasi_build(rest).map(ParseResult::WasiBuild),
    }
}

/// Parse `build --target wasi <DIR|Cargo.toml> [--package NAME] [--bin NAME]
/// [--release] [--output PATH]`. WASI is package-only: a single `.rs` source is
/// native-only, and `--yield-points` is meaningless without threads.
fn parse_wasi_build(arguments: Vec<OsString>) -> Result<WasiBuildInvocation, CliError> {
    // The package path may follow options; locate it registry-arity-aware.
    let scan = locate_positionals("build", &arguments, 1);
    let package_path = scan.positionals.into_iter().next().map(PathBuf::from);
    let args = cli::parse("build", help::Family::Wasi, scan.rest)?;
    // Require the package path after the flag scan so an unknown flag is named
    // first (never taken as the path).
    let package_path = package_path.ok_or_else(|| {
        CliError::usage("build --target wasi requires a Cargo package (a directory or Cargo.toml)")
    })?;
    if package_path.extension().and_then(OsStr::to_str) == Some("rs") {
        return Err(CliError::usage(
            "build --target wasi compiles a Cargo package; a single .rs source is native-only",
        ));
    }
    Ok(WasiBuildInvocation {
        manifest: native_manifest_path(&package_path),
        package: args.string("--package"),
        bin: args.string("--bin"),
        release: args.flag("--release"),
        output: args.path("--output"),
    })
}

/// Parse the Cargo package family (`run`/`test` with no diverting artifact): the
/// seed/record machinery, seed-driven fault knobs, and typed `--param`s,
/// forwarding every unrecognized option to Cargo. Replaying a recording — strict
/// or branch-append — is the `replay` verb's job (see [`parse_cargo_replay`]), so
/// `run`/`test` carry no replay/branch/timeline flags.
fn parse_cargo(command: String, arguments: Vec<OsString>) -> Result<ParseResult, CliError> {
    let verb = help::verb(&command).expect("the Cargo family routes only `run` and `test`");
    let (owned, cargo_args) = cli::partition(verb, help::Family::Cargo, arguments);
    let args = cli::parse(&command, help::Family::Cargo, owned)?;
    let seed = args.u64("--seed").unwrap_or(0);
    Ok(ParseResult::Run(Invocation {
        cargo_command: command,
        cargo_args,
        mode: match args.path("--record") {
            Some(path) => Mode::Record { seed, path },
            None => Mode::Seeded { seed },
        },
        step_budget: args.u64("--budget"),
        params: key_values(&args, "--param")?,
        knobs: knobs_of(&args)?,
        buggify: buggify_of(&args),
        working_dir: None,
    }))
}

/// Parse the cargo-family `replay <pkg> <trace>` verb. The `<pkg>` positional
/// (already resolved to its package directory) selects the workspace; the
/// `<trace>` positional replaces the old `--replay`/`--branch` PATH. Two shapes:
///
/// * strict replay — `replay <pkg> <trace> [--timeline ID]` — reproduces a
///   recorded timeline (default `main`);
/// * branch-append — `replay <pkg> <trace> --branch --from N --branch-seed S
///   --branch-id ID [--parent ID]` — replays the parent prefix then records a new
///   branch timeline.
///
/// Cargo selectors (`-p NAME`, `--example NAME`, a `-- ARGS` tail, ...) that are
/// not replay controls are forwarded to Cargo verbatim and folded into the
/// compatibility fingerprint exactly as on the recording, so they must match the
/// recorded run (a mismatch fails closed on the fingerprint). Fault knobs are
/// never accepted here: the trace's recorded fault configuration is authoritative
/// and restored by the runtime, so replay is flag-free.
fn parse_cargo_replay(
    package_dir: PathBuf,
    trace: PathBuf,
    arguments: Vec<OsString>,
) -> Result<ParseResult, CliError> {
    let verb = help::verb("replay").expect("`replay` is registered");
    let (owned, cargo_args) = cli::partition(verb, help::Family::Cargo, arguments);
    let args = cli::parse("replay", help::Family::Cargo, owned)?;
    Ok(ParseResult::Run(Invocation {
        // A recording is produced by `run`; its fingerprint hashes the cargo
        // subcommand, so replaying reproduces the `run` program under the runtime.
        cargo_command: "run".to_string(),
        cargo_args,
        mode: replay_mode(&args, trace)?,
        step_budget: None,
        params: BTreeMap::new(),
        knobs: KnobValues::default(),
        buggify: None,
        working_dir: Some(package_dir),
    }))
}

/// Thin wrapper: treat the leading argument as an already-built module. Used by
/// unit tests; `run` routing calls [`parse_wasi_run_from`] with a resolved ref.
#[cfg(test)]
fn parse_wasi_run(mut arguments: Vec<OsString>) -> Result<WasiInvocation, CliError> {
    if arguments.is_empty() {
        return Err(CliError::usage(
            "run of a WASI module requires a .wasm path",
        ));
    }
    let module = ArtifactRef::Prebuilt(PathBuf::from(arguments.remove(0)));
    parse_wasi_run_from(module, arguments)
}

/// Parse the flags of a WASI `run` given an already-resolved module reference
/// The host-supplied inputs a WASI run/replay shares: fuel, guest argv, guest
/// environment, datagram sockets, preopens, and resource-limit overrides. These
/// are genuine host inputs (not recorded semantic state — except `--arg`, which
/// becomes the recorded guest argv), so both `run` and `replay` accept them and
/// they feed the WASI compatibility fingerprint.
#[derive(Default)]
struct WasiHostInputs {
    fuel: Option<u64>,
    arguments: Vec<String>,
    environment: BTreeMap<String, String>,
    sockets: Vec<WasiSocketConfig>,
    preopens: Vec<WasiPreopenConfig>,
    resource_limits: WasiResourceLimitOverrides,
}

/// Assemble a [`WasiInvocation`] from a parsed mode, the shared host inputs, and
/// the fault knobs. Shared tail of [`parse_wasi_run_from`] and
/// [`parse_wasi_replay`].
fn wasi_invocation_from(
    module: ArtifactRef,
    mode: Mode,
    inputs: WasiHostInputs,
    step_budget: Option<u64>,
    knobs: KnobValues,
    buggify: Option<NativeBuggify>,
    liveness: NativeLiveness,
) -> WasiInvocation {
    WasiInvocation {
        module,
        mode,
        fuel: inputs.fuel.unwrap_or(DEFAULT_WASM_FUEL),
        arguments: inputs.arguments,
        environment: inputs.environment,
        sockets: inputs.sockets,
        preopens: inputs.preopens,
        resource_limits: inputs.resource_limits,
        step_budget,
        knobs,
        buggify,
        liveness,
    }
}

/// Parse the flags of a WASI `run` given an already-resolved module reference
/// (an existing `.wasm` or a build-on-the-fly spec). `run` produces a seeded or
/// `--record` run: replaying a recording is the `replay` verb's job, so the
/// replay/branch/timeline flags live there, not here. The seed-driven fault knobs
/// (including `--sleep-jitter-nanos`, honored at the wasip1 host's sleep entry)
/// and the cooperative-SUT (buggify) knobs are accepted and recorded exactly as
/// on the native family.
fn parse_wasi_run_from(
    module: ArtifactRef,
    arguments: Vec<OsString>,
) -> Result<WasiInvocation, CliError> {
    let args = cli::parse("run", help::Family::Wasi, arguments)?;
    let seed = args.u64("--seed").unwrap_or(0);
    let mode = match args.path("--record") {
        Some(path) => Mode::Record { seed, path },
        None => Mode::Seeded { seed },
    };
    Ok(wasi_invocation_from(
        module,
        mode,
        wasi_host_inputs_of(&args)?,
        args.u64("--budget"),
        knobs_of(&args)?,
        buggify_of(&args),
        liveness_of(&args),
    ))
}

/// Parse the WASI `replay <MODULE.wasm> <TRACE>` verb given an already-resolved
/// module reference and trace path. Flag-free for semantics: the seed and fault
/// knobs are restored from the trace, and `--arg` values (the recorded guest
/// argv) are restored and conflict-checked at execution. Only genuine host inputs
/// stay as flags (`--fuel`/`--env`/`--socket`/`--preopen`/resource limits), plus
/// the timeline selector and branch controls the WASI runtime supports.
fn parse_wasi_replay(
    module: ArtifactRef,
    trace: PathBuf,
    arguments: Vec<OsString>,
) -> Result<WasiInvocation, CliError> {
    let args = cli::parse("replay", help::Family::Wasi, arguments)?;
    Ok(wasi_invocation_from(
        module,
        replay_mode(&args, trace)?,
        wasi_host_inputs_of(&args)?,
        // `replay` registers no --budget: it re-executes a recorded operation
        // stream whose length is already fixed by the trace.
        None,
        KnobValues::default(),
        None,
        NativeLiveness::default(),
    ))
}

fn parse_explore(arguments: Vec<OsString>) -> Result<ExploreInvocation, CliError> {
    let verb = help::verb("explore").expect("`explore` is registered");
    // Everything that is not an explore knob belongs to the wrapped `run`/`test`
    // command, including the verb token itself and anything past `--`.
    let (owned, forwarded) = cli::partition(verb, help::Family::Sole, arguments);
    let args = cli::parse("explore", help::Family::Sole, owned)?;
    // `explore run <artifact|src>` sweeps the native or WASI families; `explore
    // run`/`test` with no diverting artifact stays the Cargo package family. Every
    // family must be in a plain seeded mode — record/replay/branch pin a single
    // run and have nothing to sweep. The recursive `parse` re-points the current
    // verb at the wrapped `run`/`test`; restore `explore` so any later usage error
    // here prints the explore synopsis.
    let wrapped_command = forwarded.clone();
    let parsed = parse(forwarded)?;
    set_current_verb(Some("explore"));
    let (target, mode_seed) = match parsed {
        ParseResult::Run(invocation) => {
            let seed = explore_seed_of(&invocation.mode)?;
            (ExploreTarget::Cargo(invocation), seed)
        }
        ParseResult::WasiRun(invocation) => {
            let seed = explore_seed_of(&invocation.mode)?;
            (ExploreTarget::Wasi(invocation), seed)
        }
        ParseResult::NativeRun(invocation) => {
            let seed = explore_native_seed_of(&invocation.mode)?;
            (ExploreTarget::Native(invocation), seed)
        }
        _ => {
            return Err(CliError::usage(
                "explore requires a `run <artifact|source>`/`test` command",
            ));
        }
    };
    let seed_count = args.u64("--seeds").unwrap_or(100);
    if seed_count == 0 || seed_count > 1_000_000 {
        return Err(CliError::usage("--seeds must be between 1 and 1000000"));
    }
    let start_seed = args.u64("--seed-start").unwrap_or(mode_seed);
    start_seed
        .checked_add(seed_count - 1)
        .ok_or_else(|| CliError::usage("exploration seed range overflows u64"))?;
    Ok(ExploreInvocation {
        target,
        start_seed,
        seed_count,
        wrapped_command,
    })
}

/// The seed of a plain seeded [`Mode`], rejecting record/replay/branch which pin
/// a single run.
fn explore_seed_of(mode: &Mode) -> Result<u64, CliError> {
    match mode {
        Mode::Seeded { seed } => Ok(*seed),
        _ => Err(CliError::usage(
            "explore does not accept record, replay, or branch mode",
        )),
    }
}

/// The seed of a plain seeded [`NativeRunMode`], rejecting record/replay.
fn explore_native_seed_of(mode: &NativeRunMode) -> Result<u64, CliError> {
    match mode {
        NativeRunMode::Seeded { seed } => Ok(*seed),
        _ => Err(CliError::usage(
            "explore does not accept record or replay mode",
        )),
    }
}

/// Thin wrapper: treat the leading argument as an already-built binary. Used by
/// unit tests; `audit` routing calls [`parse_native_audit_from`].
#[cfg(test)]
fn parse_native_audit(mut arguments: Vec<OsString>) -> Result<NativeAuditInvocation, CliError> {
    if arguments.is_empty() {
        return Err(CliError::usage(
            "audit of a native binary requires a binary path",
        ));
    }
    let binary = ArtifactRef::Prebuilt(PathBuf::from(arguments.remove(0)));
    parse_native_audit_from(binary, arguments)
}

/// Parse the flags of a native `audit` given an already-resolved binary
/// reference (an existing binary or a build-on-the-fly spec).
fn parse_native_audit_from(
    binary: ArtifactRef,
    arguments: Vec<OsString>,
) -> Result<NativeAuditInvocation, CliError> {
    let args = cli::parse("audit", help::Family::Native, arguments)?;
    Ok(NativeAuditInvocation {
        binary,
        allow: allow_of(&args),
        raw: args.flag("--raw"),
    })
}

fn split_trailing_args(arguments: &mut Vec<OsString>) -> Vec<OsString> {
    match arguments.iter().position(|argument| argument == "--") {
        Some(index) => {
            let trailing = arguments.split_off(index + 1);
            arguments.pop();
            trailing
        }
        None => Vec::new(),
    }
}

fn parse_native_build(mut arguments: Vec<OsString>) -> Result<NativeBuildInvocation, CliError> {
    let rustc_args = split_trailing_args(&mut arguments);
    // The source/package path may follow options (`build --release ./pkg`), so
    // locate it registry-arity-aware instead of forcing it to lead. A flag-looking
    // token is never taken as the path — the remaining flags (including an unknown
    // one, or a `--release=x` with a stray value) are validated below and produce
    // a usage error naming the flag, not a bogus `--release=x/Cargo.toml`.
    let scan = locate_positionals("build", &arguments, 1);
    let path = scan.positionals.into_iter().next().map(PathBuf::from);
    let args = cli::parse("build", help::Family::Native, scan.rest)?;
    // The path requirement is checked after the flag scan so an unknown flag or a
    // `--release=x` stray value is named first (a usage error about the flag,
    // never a bogus manifest path derived from a flag token).
    let path = path
        .ok_or_else(|| CliError::usage("build requires a Rust source path or a Cargo package"))?;
    let output = args.path("--output");
    let release = args.flag("--release");
    let yield_points = args.flag("--yield-points");

    if is_native_package_path(&path) {
        if let Some(rustc_arg) = rustc_args.first() {
            return Err(CliError::usage(format!(
                "trailing rustc options ({rustc_arg:?}) apply to a single-source build, not package builds"
            )));
        }
        if args.string("--edition").is_some() {
            return Err(CliError::usage(
                "--edition applies to a single-source build; a package's edition comes from its Cargo.toml",
            ));
        }
        Ok(NativeBuildInvocation {
            target: NativeBuildTarget::Package {
                manifest: native_manifest_path(&path),
                package: args.string("--package"),
                bin: args.string("--bin"),
            },
            output,
            release,
            yield_points,
        })
    } else {
        if args.string("--package").is_some() || args.string("--bin").is_some() {
            return Err(CliError::usage(
                "--package and --bin apply to a Cargo-package build, not a single source file",
            ));
        }
        let output = output.ok_or_else(|| CliError::usage("build requires --output <PATH>"))?;
        Ok(NativeBuildInvocation {
            target: NativeBuildTarget::Source {
                source: path,
                edition: args
                    .string("--edition")
                    .unwrap_or_else(|| DEFAULT_NATIVE_EDITION.to_string()),
                rustc_args,
            },
            output: Some(output),
            release,
            yield_points,
        })
    }
}

/// Classify a `native-build` path by shape (no filesystem access, so parsing
/// stays pure): a `.rs` file is a single source, and anything else — a
/// directory or a `Cargo.toml` — is a Cargo package. Existence is checked when
/// the build runs.
fn is_native_package_path(path: &Path) -> bool {
    if path.file_name() == Some(OsStr::new("Cargo.toml")) {
        return true;
    }
    path.extension().and_then(OsStr::to_str) != Some("rs")
}

/// Resolve a package path to its `Cargo.toml`: a manifest path is used as-is, a
/// directory gets `Cargo.toml` appended.
fn native_manifest_path(path: &Path) -> PathBuf {
    if path.file_name() == Some(OsStr::new("Cargo.toml")) {
        path.to_path_buf()
    } else {
        path.join("Cargo.toml")
    }
}

/// The control-plane payload for one repeatable knob's whole value set.
///
/// A repeatable knob carries a SET rather than one value: the control plane
/// takes the whole set as one encoded variable, while a child `run` command line
/// takes the flag once per element. Both shapes hang off the same
/// [`FaultKnob`] table, so neither has to be special-cased at a call site — the
/// bug that was live for `--dns-entry`, which `test`'s native-harness family
/// advertised and never forwarded, so every lookup in a harness run went
/// NXDOMAIN as if no table had been supplied.
fn repeatable_payload(knob: FaultKnob, values: &[String]) -> Result<String, CliError> {
    match knob {
        FaultKnob::DnsEntry => encode_dns_entries(values),
        FaultKnob::NetPartition => encode_net_partitions(values),
        // Every other knob is `Plumbing::Scalar` and carries its one value
        // verbatim; the callers filter on plumbing before asking for a payload,
        // and `every_repeatable_knob_has_an_encoder` proves this arm is dead for
        // every knob the table marks repeatable.
        scalar => Err(CliError(format!(
            "{} is not a repeatable knob",
            scalar.meta().flag
        ))),
    }
}

/// The DNS host table as the JSON object the runtime's control plane carries.
fn encode_dns_entries(values: &[String]) -> Result<String, CliError> {
    let entries: BTreeMap<String, String> = values
        .iter()
        .map(|value| {
            let (name, address) = values::dns_entry("--dns-entry", value).map_err(CliError)?;
            Ok((name.to_string(), address.to_string()))
        })
        .collect::<Result<_, CliError>>()?;
    serde_json::to_string(&entries)
        .map_err(|error| CliError(format!("failed to encode the DNS host table: {error}")))
}

/// The partition set as the JSON array of pairs the control plane carries.
fn encode_net_partitions(values: &[String]) -> Result<String, CliError> {
    let pairs: Vec<(String, String)> = values
        .iter()
        .map(|value| {
            let (left, right) = values::address_pair("--net-partition", value).map_err(CliError)?;
            Ok((left.to_string(), right.to_string()))
        })
        .collect::<Result<_, CliError>>()?;
    serde_json::to_string(&pairs)
        .map_err(|error| CliError(format!("failed to encode the network partitions: {error}")))
}

/// Every fault knob this invocation set, read straight off [`FaultKnob::ALL`].
/// Repeatable values are encoded here as well as forwarded, so a malformed one is
/// reported before anything is built or run.
fn knobs_of(args: &cli::Args) -> Result<KnobValues, CliError> {
    let mut values = BTreeMap::new();
    for knob in FaultKnob::ALL {
        let meta = knob.meta();
        // A knob the registry does not give this family is absent, not an error
        // to read: the DNS knobs are a declared WASI exception, and the exception
        // lives in the registry rather than being restated here.
        if !args.registered(meta.flag) {
            continue;
        }
        let texts: Vec<String> = match meta.plumbing {
            Plumbing::Scalar => args.string(meta.flag).into_iter().collect(),
            Plumbing::Repeatable => args
                .texts(meta.flag)
                .into_iter()
                .map(str::to_string)
                .collect(),
        };
        if texts.is_empty() {
            continue;
        }
        if meta.plumbing == Plumbing::Repeatable {
            repeatable_payload(*knob, &texts)?;
        }
        values.insert(*knob, texts);
    }
    Ok(KnobValues(values))
}

/// The `PATINA_*` control-plane pairs carrying this invocation's knobs to the
/// guest, in [`FaultKnob::ALL`] order, unset knobs omitted so a run that
/// configured none sets nothing. Used by the WASI in-process runtime (via
/// [`RuntimeConfig::apply_fault_env`]) and by the native and cargo subprocesses
/// (as real environment variables), so every family applies the identical
/// protocol the native shim reads.
fn knob_env_pairs(knobs: &KnobValues) -> Result<Vec<(&'static str, String)>, CliError> {
    let mut pairs = Vec::new();
    for knob in FaultKnob::ALL {
        let values = knobs.get(*knob);
        if values.is_empty() {
            continue;
        }
        let meta = knob.meta();
        let payload = match meta.plumbing {
            Plumbing::Scalar => values[0].clone(),
            Plumbing::Repeatable => repeatable_payload(*knob, values)?,
        };
        pairs.push((meta.env, payload));
    }
    Ok(pairs)
}

/// This invocation's knobs as `(flag, value)` pairs — a repeatable flag repeated
/// once per element — for re-emission onto a child `run` command line.
fn knob_flag_pairs(knobs: &KnobValues) -> Vec<(&'static str, &String)> {
    FaultKnob::ALL
        .iter()
        .flat_map(|knob| {
            knobs
                .get(*knob)
                .iter()
                .map(move |value| (knob.meta().flag, value))
        })
        .collect()
}

/// Every `PATINA_*` variable a fault knob can arrive on, for the scrub that keeps
/// an ambient environment from perturbing a run that requested no faults.
fn knob_env_vars() -> impl Iterator<Item = &'static str> {
    FaultKnob::ALL.iter().map(|knob| knob.meta().env)
}

/// The cooperative-SUT (buggify) knobs, or `None` when buggify was not enabled.
/// Any of the four flags enables it — the three detail knobs each imply
/// `--buggify`, as their help says.
fn buggify_of(args: &cli::Args) -> Option<NativeBuggify> {
    let fire = args.text("--buggify");
    let activation = args.string("--buggify-activation-permille");
    let cutoff = args.string("--buggify-cutoff-nanos");
    let after_setup = args.flag("--buggify-after-setup");
    if fire.is_none() && activation.is_none() && cutoff.is_none() && !after_setup {
        return None;
    }
    Some(NativeBuggify {
        // A bare `--buggify` supplies no per-mille; the runtime default applies.
        fire_permille: fire.filter(|value| !value.is_empty()).map(str::to_string),
        activation_permille: activation,
        cutoff_nanos: cutoff,
        after_setup,
    })
}

/// The exploration scheduling knobs. The inert-knob rule (`--sched-pct-steps`
/// without `--sched-pct`, and so on) is declared in the registry and enforced
/// generically by the parser, so it is not repeated here.
fn schedule_of(args: &cli::Args) -> NativeSchedule {
    NativeSchedule {
        pct: args.string("--sched-pct"),
        pct_steps: args.string("--sched-pct-steps"),
        starve: args.string("--starve"),
        starve_max_len: args.string("--starve-max-len"),
        starve_window: args.string("--starve-window"),
        swarm: args.flag("--swarm"),
    }
}

/// The liveness-watchdog knobs.
fn liveness_of(args: &cli::Args) -> NativeLiveness {
    NativeLiveness {
        watchdog: args.string("--liveness-watchdog"),
        converge: args.string("--converge-within"),
        heal_after: args.string("--heal-after"),
    }
}

/// The pre-run gate's allow list.
fn allow_of(args: &cli::Args) -> BTreeSet<String> {
    args.texts("--allow")
        .into_iter()
        .map(str::to_string)
        .collect()
}

/// The unsupported-symbol escape hatch, default-deny.
fn unsupported_policy_of(args: &cli::Args) -> UnsupportedPolicy {
    match args.text("--allow-unsupported-symbols") {
        None => UnsupportedPolicy::Deny,
        Some(value) => {
            match values::unsupported_symbols("--allow-unsupported-symbols", value)
                .expect("validated by the registry grammar")
            {
                None => UnsupportedPolicy::All,
                Some(symbols) => {
                    UnsupportedPolicy::Only(symbols.into_iter().map(str::to_string).collect())
                }
            }
        }
    }
}

/// A repeatable `KEY=VALUE` flag as a map. The grammar already guaranteed a
/// non-empty key; uniqueness is the cross-value rule that remains.
fn key_values(args: &cli::Args, flag: &str) -> Result<BTreeMap<String, String>, CliError> {
    let mut map = BTreeMap::new();
    for entry in args.texts(flag) {
        let (key, value) = entry.split_once('=').expect("KEY=VALUE grammar");
        if map.insert(key.to_string(), value.to_string()).is_some() {
            return Err(CliError::usage(format!(
                "{flag} keys must be non-empty and unique"
            )));
        }
    }
    Ok(map)
}

/// The host-supplied inputs a WASI run/replay shares.
fn wasi_host_inputs_of(args: &cli::Args) -> Result<WasiHostInputs, CliError> {
    let fuel = args.u64("--fuel");
    let mut sockets = Vec::new();
    let mut socket_fds = BTreeSet::new();
    for entry in args.texts("--socket") {
        let (fd, bind, peer) =
            values::socket("--socket", entry).expect("validated by the registry grammar");
        if !socket_fds.insert(fd) {
            return Err(CliError::usage(
                "--socket requires a unique FD above 3 and non-empty addresses",
            ));
        }
        sockets.push(WasiSocketConfig {
            fd,
            bind: bind.to_string(),
            peer: peer.to_string(),
        });
    }
    let preopens = args
        .texts("--preopen")
        .into_iter()
        .map(|entry| {
            let (guest_path, read_only) =
                values::preopen("--preopen", entry).expect("validated by the registry grammar");
            WasiPreopenConfig {
                guest_path: normalize_cli_preopen_path(guest_path),
                policy: if read_only {
                    MountPolicy::ReadOnly
                } else {
                    MountPolicy::ReadWrite
                },
            }
        })
        .collect();
    Ok(WasiHostInputs {
        fuel,
        arguments: args
            .texts("--arg")
            .into_iter()
            .map(str::to_string)
            .collect(),
        environment: key_values(args, "--env")?,
        sockets,
        preopens,
        resource_limits: WasiResourceLimitOverrides {
            fuel,
            max_memory_pages: args.u32("--max-memory-pages"),
            max_iovecs: args.usize("--max-iovecs"),
            max_io_bytes: args.usize("--max-io-bytes"),
            max_descriptors: args.usize("--max-descriptors"),
            max_preopens: args.usize("--max-preopens"),
            max_path_bytes: args.usize("--max-path-bytes"),
        },
    })
}

/// The timeline/branch selection shared by the Cargo package and WASI replay
/// families, which are the two that support branch-append.
fn replay_mode(args: &cli::Args, path: PathBuf) -> Result<Mode, CliError> {
    let timeline = args.string("--timeline");
    let from_sequence = args.u64("--from");
    let branch_seed = args.u64("--branch-seed");
    let branch_id = args.string("--branch-id");
    let parent = args.string("--parent");
    if !args.flag("--branch") {
        if from_sequence.is_some()
            || branch_seed.is_some()
            || branch_id.is_some()
            || parent.is_some()
        {
            return Err(CliError::usage(
                "--from/--branch-seed/--branch-id/--parent require --branch",
            ));
        }
        return Ok(Mode::Replay {
            path,
            timeline: timeline.unwrap_or_else(|| "main".into()),
        });
    }
    if timeline.is_some() {
        return Err(CliError::usage(
            "--timeline selects a timeline to replay and is not valid with --branch",
        ));
    }
    Ok(Mode::Branch {
        path,
        parent: parent.unwrap_or_else(|| "main".into()),
        from_sequence: from_sequence
            .ok_or_else(|| CliError::usage("replay --branch requires --from"))?,
        branch_seed: branch_seed
            .ok_or_else(|| CliError::usage("replay --branch requires --branch-seed"))?,
        branch_id: branch_id
            .ok_or_else(|| CliError::usage("replay --branch requires --branch-id"))?,
    })
}

/// The `--timeline` selector, defaulting to `main`.
fn timeline_or_main(args: &cli::Args) -> String {
    args.string("--timeline")
        .unwrap_or_else(|| "main".to_string())
}

/// Every `PATINA_BUGGIFY*` control-plane variable, for the scrub that keeps an
/// ambient environment from enabling buggify in a run that did not ask for it.
const BUGGIFY_ENV_VARS: &[&str] = &[
    ENV_BUGGIFY,
    ENV_BUGGIFY_ACTIVATION,
    ENV_BUGGIFY_CUTOFF,
    ENV_BUGGIFY_AFTER_SETUP,
];

/// The cooperative-SUT (buggify) control-plane pairs for the in-process WASI
/// runtime, mirroring the env vars the native family forwards to its subprocess.
/// Presence of `PATINA_BUGGIFY` (its value, possibly empty, being the firing
/// per-mille) enables buggify; the optional knobs follow.
fn buggify_env_pairs(buggify: &NativeBuggify) -> Vec<(&'static str, String)> {
    let mut pairs = vec![(
        ENV_BUGGIFY,
        buggify.fire_permille.clone().unwrap_or_default(),
    )];
    if let Some(value) = &buggify.activation_permille {
        pairs.push((ENV_BUGGIFY_ACTIVATION, value.clone()));
    }
    if let Some(value) = &buggify.cutoff_nanos {
        pairs.push((ENV_BUGGIFY_CUTOFF, value.clone()));
    }
    if buggify.after_setup {
        pairs.push((ENV_BUGGIFY_AFTER_SETUP, "1".to_string()));
    }
    pairs
}

/// The exploration scheduling-policy and swarm control-plane pairs. Presence of
/// `PATINA_SCHED_PCT` enables PCT (its value, possibly empty, being the bug
/// depth); `PATINA_SCHED_STARVE` enables starvation; `PATINA_SWARM` enables
/// swarm fault-class selection. Mirrors [`knob_env_pairs`] so the native family
/// forwards them to the subprocess and the WASI/Cargo families to the in-process
/// runtime through the same protocol.
fn schedule_env_pairs(schedule: &NativeSchedule) -> Vec<(&'static str, String)> {
    let mut pairs = Vec::new();
    if let Some(depth) = &schedule.pct {
        pairs.push((ENV_SCHED_PCT, depth.clone()));
        if let Some(steps) = &schedule.pct_steps {
            pairs.push((ENV_SCHED_PCT_STEPS, steps.clone()));
        }
    }
    if let Some(count) = &schedule.starve {
        pairs.push((ENV_SCHED_STARVE, count.clone()));
        if let Some(len) = &schedule.starve_max_len {
            pairs.push((ENV_SCHED_STARVE_MAX_LEN, len.clone()));
        }
        if let Some(window) = &schedule.starve_window {
            pairs.push((ENV_SCHED_STARVE_WINDOW, window.clone()));
        }
    }
    if schedule.swarm {
        pairs.push((ENV_SWARM, "1".to_string()));
    }
    pairs
}

/// The liveness-watchdog control-plane pairs, mirroring [`schedule_env_pairs`] so
/// the native family forwards them to the subprocess and the WASI/Cargo families
/// to the in-process runtime through the same `apply_liveness_env` protocol.
fn liveness_env_pairs(liveness: &NativeLiveness) -> Vec<(&'static str, String)> {
    let mut pairs = Vec::new();
    if let Some(budget) = &liveness.watchdog {
        pairs.push((ENV_LIVENESS_WATCHDOG, budget.clone()));
    }
    if let Some(budget) = &liveness.converge {
        pairs.push((ENV_CONVERGE_WITHIN, budget.clone()));
        if let Some(heal_after) = &liveness.heal_after {
            pairs.push((ENV_HEAL_AFTER, heal_after.clone()));
        }
    }
    pairs
}

/// Thin wrapper: treat the leading argument as an already-built binary. Used by
/// unit tests; `run` routing calls [`parse_native_run_from`] with a resolved ref.
#[cfg(test)]
fn parse_native_run(mut arguments: Vec<OsString>) -> Result<NativeRunInvocation, CliError> {
    // The binary is the first token, ahead of any `--` guest-args separator.
    if arguments.is_empty() || arguments[0] == "--" {
        return Err(CliError::usage(
            "run of a native binary requires a binary path",
        ));
    }
    let binary = ArtifactRef::Prebuilt(PathBuf::from(arguments.remove(0)));
    parse_native_run_from(binary, arguments)
}

/// Parse the flags of a native `run` given an already-resolved binary reference
/// (an existing binary or a build-on-the-fly spec). A trailing `-- ARGS` section
/// is the guest argument vector.
fn parse_native_run_from(
    binary: ArtifactRef,
    mut arguments: Vec<OsString>,
) -> Result<NativeRunInvocation, CliError> {
    let program_args = split_trailing_args(&mut arguments);
    let args = cli::parse("run", help::Family::Native, arguments)?;
    let seed = args.u64("--seed").unwrap_or(0);
    let record = args.path("--record");
    // The label is only ever read back off a recorded trace, and the seeded
    // control plane sets no `PATINA_FINGERPRINT` at all, so `--fingerprint` is
    // registered as dependent on `--record` (see the native run group in
    // `help.rs`): a seeded run carrying one is refused by the generic registry
    // check rather than silently discarding it.
    let fingerprint = args
        .string("--fingerprint")
        .unwrap_or_else(|| DEFAULT_NATIVE_FINGERPRINT.to_string());
    Ok(NativeRunInvocation {
        binary,
        mode: match record {
            Some(path) => NativeRunMode::Record {
                seed,
                path,
                fingerprint,
            },
            None => NativeRunMode::Seeded { seed },
        },
        program_args,
        environment: key_values(&args, "--env")?,
        step_budget: args.u64("--budget"),
        knobs: knobs_of(&args)?,
        buggify: buggify_of(&args),
        schedule: schedule_of(&args),
        liveness: liveness_of(&args),
        allow: allow_of(&args),
        allow_unsupported: unsupported_policy_of(&args),
        coverage_out: args.path("--coverage-out"),
        mount: args.path("--mount"),
        harness: args.flag("--harness"),
    })
}

/// Route `replay <ARTIFACT|SOURCE|PKG> <TRACE>` by the same artifact inference as
/// `run`: a WebAssembly module replays under WASI, a native binary under the
/// native supervisor, and a directory/`Cargo.toml` (no `--target`) under the
/// Cargo package family. Each restores its recorded semantic config from the
/// trace and exposes only that family's genuine host inputs. The two positionals
/// (artifact/source/package, then trace) always lead; per-family flags and any
/// `--` section follow and are handled by the family parser.
fn parse_replay(arguments: Vec<OsString>) -> Result<ParseResult, CliError> {
    // `replay` is source-first like `run`/`audit`: the artifact may be built or a
    // source/package built on the fly (honoring `--target`). A rebuilt binary is
    // judged against the trace by the fail-closed machinery (fingerprint +
    // operation-mismatch), so no special-casing.
    let (target, rest) = extract_target(arguments)?;
    // The two positionals (artifact/source/package, then trace) may be interleaved
    // with options in any order, e.g. `replay --fingerprint f art.wasm trace`.
    // Their relative order is preserved: the first is the origin, the second the
    // trace.
    let scan = locate_positionals("replay", &rest, 2);
    if scan.positionals.len() < 2 {
        if let Some(stop) = scan.stop {
            reject_stranded_artifact("replay", &rest[stop..])?;
        }
        return Err(CliError::usage(if scan.positionals.is_empty() {
            "replay requires an artifact/source/package path and a trace path"
        } else {
            "replay requires a trace path"
        }));
    }
    let origin = scan.positionals[0].clone();
    let trace = PathBuf::from(&scan.positionals[1]);
    let flags = scan.rest;
    // A package that integrates the Patina runtime replays through the cargo
    // family (the linked runtime restores seed/faults/timeline and honors
    // `--branch`/`--timeline`); a plain package rebuilds shim-linked and replays
    // through the native path, where the trace is loaded and fail-closed BEFORE
    // any guest execution.
    if target.is_none() {
        if let ArgKind::SourcePackage(manifest) = classify_arg(&origin)? {
            if package_integrates_patina(Some(&manifest), None) {
                let package_dir = cargo_package_dir(&origin)?;
                return parse_cargo_replay(package_dir, trace, flags);
            }
        }
    }
    match resolve_positional(&origin, target.as_deref())? {
        Some((ArtifactFamily::Wasm, module)) => {
            parse_wasi_replay(module, trace, flags).map(ParseResult::WasiRun)
        }
        Some((ArtifactFamily::Native, binary)) => {
            parse_native_replay(binary, trace, flags).map(ParseResult::NativeRun)
        }
        // Neither an artifact nor a source/package (a leading flag or a plain
        // file): let `cargo_package_dir` produce the precise "neither ..." error.
        None => {
            let package_dir = cargo_package_dir(&origin)?;
            parse_cargo_replay(package_dir, trace, flags)
        }
    }
}

/// Resolve a cargo-family `replay` positional to its package directory. The
/// origin must be a directory or a `Cargo.toml` (the shapes `resolve_positional`
/// classifies as the Cargo package family); anything else is neither an artifact
/// nor a package and is rejected naming the offending path.
fn cargo_package_dir(origin: &OsStr) -> Result<PathBuf, CliError> {
    match classify_arg(origin)? {
        ArgKind::SourcePackage(manifest) => Ok(manifest
            .parent()
            .map(Path::to_path_buf)
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| PathBuf::from("."))),
        _ => Err(CliError::usage(format!(
            "replay target {} is neither a WASI module, a native binary, nor a Cargo package (a directory or Cargo.toml)",
            Path::new(origin).display()
        ))),
    }
}

/// Parse the native `replay <BINARY> <TRACE> [--fingerprint STR] [--mount
/// HOST_DIR] [--allow SYMBOL]... [--allow-unsupported-symbols <all|name,...>]
/// [-- GUEST ARGS]` given an already-resolved binary reference and trace path.
///
/// Native replay restores every semantic input from the trace itself — seed,
/// fault knobs, buggify, guest arguments, and injected guest environment — so it
/// exposes NO semantic flags. The registry declares those refusals (see
/// `REPLAY`'s `refusals`), so each is answered by name rather than as an unknown
/// option, and a knob added to a shared slice is refused the day it is added.
/// The only flags are host/build facts the trace cannot carry: `--fingerprint`,
/// `--mount` (re-supply the host corpus whose hash the fingerprint verifies),
/// `--harness`, and the machine-local pre-run audit surface. An optional trailing
/// `--` section is accepted only for script compatibility and must match the
/// recorded arguments byte-for-byte (enforced downstream by
/// `reconcile_replay_argv`).
fn parse_native_replay(
    binary: ArtifactRef,
    trace: PathBuf,
    mut arguments: Vec<OsString>,
) -> Result<NativeRunInvocation, CliError> {
    let program_args = split_trailing_args(&mut arguments);
    let args = cli::parse("replay", help::Family::Native, arguments)?;
    Ok(NativeRunInvocation {
        binary,
        mode: NativeRunMode::Replay {
            path: trace,
            fingerprint: args
                .string("--fingerprint")
                .unwrap_or_else(|| DEFAULT_NATIVE_FINGERPRINT.to_string()),
        },
        program_args,
        environment: BTreeMap::new(),
        // `replay` registers no --budget: it re-executes a recorded operation
        // stream whose length is already fixed by the trace.
        step_budget: None,
        // Like the fault knobs, the repeatable semantic knobs come from the
        // trace.
        knobs: KnobValues::default(),
        buggify: None,
        // Replay restores the scheduling policy and swarm selection from the
        // trace metadata; the run path reconstructs the fingerprint suffix from
        // the trace (see `native_schedule_from_trace`), so nothing is supplied.
        schedule: NativeSchedule::default(),
        // Liveness is schedule-invariant and informational-only in the trace, so a
        // replay does not re-supply or reconcile it.
        liveness: NativeLiveness::default(),
        allow: allow_of(&args),
        allow_unsupported: unsupported_policy_of(&args),
        coverage_out: args.path("--coverage-out"),
        mount: args.path("--mount"),
        harness: args.flag("--harness"),
    })
}

fn parse_trace(mut arguments: Vec<OsString>) -> Result<trace_cmd::TraceInvocation, CliError> {
    if arguments.is_empty() {
        return Err(CliError::usage(
            "trace requires a subcommand: info, events, stats, or diff",
        ));
    }
    let subcommand = arguments
        .remove(0)
        .into_string()
        .map_err(|_| CliError::usage("trace subcommand must be valid UTF-8"))?;
    match subcommand.as_str() {
        "info" => parse_trace_info(arguments).map(trace_cmd::TraceInvocation::Info),
        "events" => parse_trace_events(arguments).map(trace_cmd::TraceInvocation::Events),
        "stats" => parse_trace_stats(arguments).map(trace_cmd::TraceInvocation::Stats),
        "diff" => parse_trace_diff(arguments).map(trace_cmd::TraceInvocation::Diff),
        other => Err(CliError::usage(format!(
            "unsupported trace subcommand {other:?}; expected info, events, stats, or diff"
        ))),
    }
}

fn parse_trace_info(arguments: Vec<OsString>) -> Result<trace_cmd::TraceInfo, CliError> {
    let scan = locate_positionals("trace", &arguments, 1);
    let args = cli::parse("trace", help::Family::Info, scan.rest)?;
    Ok(trace_cmd::TraceInfo {
        path: scan
            .positionals
            .into_iter()
            .next()
            .map(PathBuf::from)
            .ok_or_else(|| CliError::usage("trace info requires a trace path"))?,
        timeline: timeline_or_main(&args),
    })
}

fn parse_trace_events(arguments: Vec<OsString>) -> Result<trace_cmd::TraceEvents, CliError> {
    let scan = locate_positionals("trace", &arguments, 1);
    let args = cli::parse("trace", help::Family::Events, scan.rest)?;
    let mut filters = trace_cmd::EventFilters {
        first: args.u64("--first"),
        last: args.u64("--last"),
        notable: args.flag("--notable"),
        seq: args
            .text("--seq")
            .map(|value| values::range_of("--seq", value, "..").expect("validated by the grammar")),
        ..trace_cmd::EventFilters::default()
    };
    for value in args.texts("--task") {
        filters.tasks.insert(match value {
            "main" => trace_view::LaneKey::Main,
            id => trace_view::LaneKey::Task(id.parse().expect("validated by the grammar")),
        });
    }
    if let Some(value) = args.text("--kind") {
        let (kinds, categories) = values::kind_list(value).expect("validated by the grammar");
        filters.op_kinds = kinds.into_iter().map(str::to_string).collect();
        filters.categories = categories.into_iter().collect();
    }
    if filters.first.is_some() && filters.last.is_some() {
        return Err(CliError::usage(
            "--first and --last are mutually exclusive for trace events",
        ));
    }
    Ok(trace_cmd::TraceEvents {
        path: scan
            .positionals
            .into_iter()
            .next()
            .map(PathBuf::from)
            .ok_or_else(|| CliError::usage("trace events requires a trace path"))?,
        timeline: timeline_or_main(&args),
        filters,
    })
}

fn parse_trace_stats(arguments: Vec<OsString>) -> Result<trace_cmd::TraceStats, CliError> {
    let scan = locate_positionals("trace", &arguments, 1);
    let args = cli::parse("trace", help::Family::Stats, scan.rest)?;
    Ok(trace_cmd::TraceStats {
        path: scan
            .positionals
            .into_iter()
            .next()
            .map(PathBuf::from)
            .ok_or_else(|| CliError::usage("trace stats requires a trace path"))?,
        timeline: timeline_or_main(&args),
    })
}

fn parse_trace_diff(arguments: Vec<OsString>) -> Result<trace_cmd::TraceDiff, CliError> {
    let scan = locate_positionals("trace", &arguments, 2);
    let args = cli::parse("trace", help::Family::Diff, scan.rest)?;
    if scan.positionals.len() < 2 {
        return Err(CliError::usage(if scan.positionals.is_empty() {
            "trace diff requires two trace paths"
        } else {
            "trace diff requires a second trace path"
        }));
    }
    Ok(trace_cmd::TraceDiff {
        a: PathBuf::from(&scan.positionals[0]),
        b: PathBuf::from(&scan.positionals[1]),
        timeline: timeline_or_main(&args),
        context: args.usize("--context").unwrap_or(3),
    })
}

fn parse_minimize(mut arguments: Vec<OsString>) -> Result<minimize::MinimizeInvocation, CliError> {
    // `--generation` builds its own oracle, so it is the one form that takes no
    // `-- <ORACLE>` tail — and must be routed before the tail is demanded. The
    // name is read through the registry's splitter, so `--generation=14` routes
    // exactly like `--generation 14`.
    if has_minimize_flag(&arguments, "--generation") {
        return parse_minimize_generation(arguments).map(minimize::MinimizeInvocation::Generation);
    }
    let delimiter = arguments
        .iter()
        .position(|argument| argument == "--")
        .ok_or_else(|| CliError::usage("minimize requires `-- <ORACLE> [ARGS]...`"))?;
    let oracle = arguments.split_off(delimiter + 1);
    arguments.pop();
    if oracle.is_empty() {
        return Err(CliError::usage(
            "minimize requires an oracle command after `--`",
        ));
    }
    if has_minimize_flag(&arguments, "--scenario") {
        parse_minimize_scenario(arguments, oracle).map(minimize::MinimizeInvocation::Scenario)
    } else {
        parse_minimize_trace(arguments, oracle).map(minimize::MinimizeInvocation::Trace)
    }
}

/// Whether a `minimize` argument list carries `name`, in either the space or
/// the `=` form.
fn has_minimize_flag(arguments: &[OsString], name: &str) -> bool {
    arguments.iter().any(|argument| {
        argument
            .to_str()
            .is_some_and(|text| cli::split_name(text) == name)
    })
}

fn parse_minimize_trace(
    arguments: Vec<OsString>,
    oracle: Vec<OsString>,
) -> Result<minimize::TraceMinimize, CliError> {
    // The trace path may follow options (`minimize --output out.patina trace`),
    // so locate it registry-arity-aware rather than forcing it to lead.
    let scan = locate_positionals("minimize", &arguments, 1);
    let args = cli::parse("minimize", help::Family::Sole, scan.rest)?;
    let timeline = args.string("--timeline");
    let prune = args.flag("--prune-branches");
    if prune && timeline.is_some() {
        return Err(CliError::usage(
            "--prune-branches operates on the whole branch forest and cannot be combined with --timeline",
        ));
    }
    Ok(minimize::TraceMinimize {
        trace: scan
            .positionals
            .into_iter()
            .next()
            .map(PathBuf::from)
            .ok_or_else(|| CliError::usage("minimize requires a trace path"))?,
        output: args
            .path("--output")
            .ok_or_else(|| CliError::usage("minimize requires --output <PATH>"))?,
        timeline,
        prune,
        oracle,
        jobs: args.usize("--jobs"),
    })
}

fn parse_minimize_generation(
    arguments: Vec<OsString>,
) -> Result<minimize::GenerationMinimize, CliError> {
    if arguments.iter().any(|argument| argument == "--") {
        return Err(CliError::usage(
            "minimize --generation builds its own oracle (--marker) and takes no `-- <ORACLE>`",
        ));
    }
    let args = cli::parse("minimize", help::Family::Generation, arguments)?;
    Ok(minimize::GenerationMinimize {
        out_dir: args
            .path("--out-dir")
            .unwrap_or_else(|| PathBuf::from(campaign::DEFAULT_OUT_DIR)),
        generation: args
            .u64("--generation")
            .ok_or_else(|| CliError::usage("minimize --generation requires <N>"))?,
        marker: args
            .string("--marker")
            .ok_or_else(|| CliError::usage("minimize --generation requires --marker <TEXT>"))?,
        output: args.path("--output"),
        trace_phase: !args.flag("--no-trace-phase"),
        jobs: args.usize("--jobs"),
    })
}

fn parse_minimize_scenario(
    arguments: Vec<OsString>,
    oracle: Vec<OsString>,
) -> Result<minimize::ScenarioMinimize, CliError> {
    let args = cli::parse("minimize", help::Family::Scenario, arguments)?;
    Ok(minimize::ScenarioMinimize {
        seed: args
            .u64("--seed")
            .ok_or_else(|| CliError::usage("minimize --scenario requires --seed <U64>"))?,
        params: key_values(&args, "--param")?,
        seed_budget: args.u64("--seed-budget").unwrap_or(DEFAULT_SEED_BUDGET),
        oracle,
    })
}

fn normalize_cli_preopen_path(path: &str) -> String {
    if !path.starts_with('/') || path.contains('\0') {
        return path.to_owned();
    }
    let mut components = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => return path.to_owned(),
            component => components.push(component),
        }
    }
    if components.is_empty() {
        "/".to_owned()
    } else {
        format!("/{}", components.join("/"))
    }
}

fn execute_wasi_run(invocation: WasiInvocation) -> Result<i32, CliError> {
    let mut invocation = invocation;
    let resolved = resolve_artifact(invocation.module.clone())?;
    let bytes = fs::read(&resolved.path).map_err(|error| {
        CliError(format!(
            "failed to read WebAssembly module {}: {error}",
            resolved.path.display()
        ))
    })?;
    // A replay/branch restores the recorded guest argv from the trace so the run
    // reproduces without the `--arg` values being re-passed. Any `--arg` the
    // operator did supply must match the recording byte-for-byte or the replay is
    // refused up front, naming both — the same authoritative-trace contract the
    // native family enforces. The restored argv is folded into the WASI
    // fingerprint below exactly as it was at record time. A pre-argv trace keeps
    // today's contract: the supplied `--arg` values are used as-is.
    if let Some(trace) = replay_trace_path(&invocation.mode) {
        invocation.arguments = reconcile_wasi_replay_argv(trace, &invocation.arguments)?;
    }
    // Buggify presence folds into the fingerprint exactly as `+buggify` does on
    // the native path, so a buggify trace and a plain trace of the same module are
    // never cross-replayable. On a flag-free replay the operator passes no
    // `--buggify`, so the trace metadata is authoritative — mirror the native
    // `trace_has_buggify` reconciliation so the recomputed fingerprint matches.
    let buggify_enabled = invocation.buggify.is_some()
        || replay_trace_path(&invocation.mode).is_some_and(trace_has_buggify);
    let fingerprint = wasi_compatibility_fingerprint(&bytes, &invocation, buggify_enabled);
    let mut config = match &invocation.mode {
        Mode::Seeded { seed } => RuntimeConfig::seeded(*seed),
        Mode::Record { seed, path } => RuntimeConfig::record(*seed, path.clone(), &fingerprint),
        Mode::Replay { path, timeline } => {
            RuntimeConfig::replay_timeline(path.clone(), timeline.clone(), &fingerprint)
        }
        Mode::Branch {
            path,
            parent,
            from_sequence,
            branch_seed,
            branch_id,
        } => RuntimeConfig::branch(
            path.clone(),
            parent.clone(),
            *from_sequence,
            branch_id.clone(),
            *branch_seed,
            &fingerprint,
        ),
    };
    // On a seeded or `--record` run the operator's fault knobs configure the
    // in-process drivers (and, on record, are captured into the trace metadata
    // via the runtime's record path). On replay/branch the config carries no
    // faults: the runtime restores the trace's authoritative fault configuration
    // during `Context::from_config`, so a flag-free replay rebuilds the same
    // CrashFs/SimNet the recording used.
    if let Some(budget) = invocation.step_budget {
        config = config.with_step_budget(budget);
    }
    if matches!(invocation.mode, Mode::Seeded { .. } | Mode::Record { .. }) {
        let pairs = knob_env_pairs(&invocation.knobs)?;
        config = config
            .apply_fault_env(|name| {
                pairs
                    .iter()
                    .find(|(key, _)| *key == name)
                    .map(|(_, value)| value.clone())
            })
            .map_err(|error| CliError(error.to_string()))?;
        // Cooperative-SUT (buggify) knobs configure the same in-process runtime
        // through the shared `apply_buggify_env` accessor. On `--record` the
        // runtime captures the resulting `BuggifyConfigRecord` into the trace
        // metadata; on replay/branch the config carries no buggify and the runtime
        // restores it from the trace during `Context::from_config`, exactly as the
        // faults above — so a WASI buggify replay is flag-free.
        if let Some(buggify) = &invocation.buggify {
            let pairs = buggify_env_pairs(buggify);
            config = config
                .apply_buggify_env(|name| {
                    pairs
                        .iter()
                        .find(|(key, _)| *key == name)
                        .map(|(_, value)| value.clone())
                })
                .map_err(|error| CliError(error.to_string()))?;
        }
        // Liveness-watchdog knobs configure the same in-process runtime. The
        // watchdog is schedule-invariant, so on `--record` its config is recorded
        // (informational metadata) but not fingerprinted; a WASI guest that wedges
        // into a pure-sleep churn trips a deterministic PATINA_LIVENESS.
        if invocation.liveness.is_enabled() {
            let pairs = liveness_env_pairs(&invocation.liveness);
            config = config
                .apply_liveness_env(|name| {
                    pairs
                        .iter()
                        .find(|(key, _)| *key == name)
                        .map(|(_, value)| value.clone())
                })
                .map_err(|error| CliError(error.to_string()))?;
        }
    }
    // Record the guest argv (the `--arg` values) into the trace metadata so a
    // later `replay` restores them flag-free. Always recorded on `--record`, even
    // when empty, so a zero-argument run reproduces zero arguments rather than
    // inheriting whatever the replay command line supplies.
    if matches!(invocation.mode, Mode::Record { .. }) {
        config = config.with_guest_argv(Some(invocation.arguments.clone()));
    }
    // A WASI guest runs in THIS process, so the report knobs come straight from
    // the supervisor's environment — but through the same table and parser the
    // native and cargo families use, and resolved once for both the runtime's own
    // reports and the depth line this function appends below.
    let reports = patina_dst_runtime::ReportConfig::default().applied(|name| env::var(name).ok());
    config = config.with_reports(reports);
    // The structured run-facts channel. A WASI guest's runtime lives in THIS
    // process, which is not interposed, so the plain path channel is enough — no
    // descriptor hand-off is needed.
    let facts_file = if output::facts_active() {
        Some(tempfile::NamedTempFile::new().map_err(|error| {
            CliError(format!("failed to create the run-facts channel: {error}"))
        })?)
    } else {
        None
    };
    if let Some(file) = &facts_file {
        config = config.with_facts_path(file.path());
    }
    let context = Context::from_config(config).map_err(|error| CliError(error.to_string()))?;
    let host = configured_wasi_host(&invocation, &resolved.display, context)?;
    let mut execution = execute_preview1_with_fuel(&bytes, host, invocation.fuel)
        .map_err(|error| CliError(error.to_string()))?;
    // WASI depth (fuel + hostcall counts) rides the run's own stderr, exactly as
    // the native family's `PATINA_COVERAGE_REPORT` rides the child's — so the
    // human stream, the envelope's `markers`, and a campaign's captured child
    // output all read the same line. Appending happens after the guest and its
    // trace are finalized, so no recorded byte or fingerprint is affected.
    let depth = wasi_depth_report(&execution);
    if reports.enabled(patina_dst_runtime::Report::Depth) {
        execution
            .stderr
            .extend_from_slice(depth.marker_line().as_bytes());
        execution.stderr.push(b'\n');
    }
    let (trace_path, seed, timeline) = match &invocation.mode {
        Mode::Seeded { seed } => (None, Some(*seed), "main".to_string()),
        Mode::Record { seed, path } => (Some(path.clone()), Some(*seed), "main".to_string()),
        Mode::Replay { path, timeline } => (Some(path.clone()), None, timeline.clone()),
        Mode::Branch {
            path, branch_id, ..
        } => (Some(path.clone()), None, branch_id.clone()),
    };
    let artifact = resolved.display.display().to_string();
    let facts = read_facts_channel(facts_file.as_ref().map(tempfile::NamedTempFile::path))?;
    output::finalize_inprocess(
        output::RunReport {
            verb: "run",
            family: "wasi",
            artifact: &artifact,
            trace_path,
            timeline: &timeline,
            fingerprint: Some(fingerprint),
            seed,
            coverage: None,
            depth: Some(depth),
            facts,
        },
        execution.exit_code,
        execution.stdout,
        execution.stderr,
    )
}

/// Build the run envelope's `depth` object from a finished WASI execution. The
/// values come straight from the engine's fuel meter and the host's per-import
/// counters, both deterministic functions of the executed instruction stream.
fn wasi_depth_report(execution: &patina_dst_wasi_host::WasiExecution) -> output::DepthReport {
    output::DepthReport {
        family: "wasi".to_string(),
        fuel_consumed: execution.fuel_consumed,
        hostcalls: execution
            .hostcalls
            .iter()
            .map(|(name, count)| ((*name).to_string(), *count))
            .collect(),
    }
}

/// The trace path a replay/branch mode reads its recorded guest argv from, or
/// `None` for a seeded/record run.
fn replay_trace_path(mode: &Mode) -> Option<&Path> {
    match mode {
        Mode::Replay { path, .. } | Mode::Branch { path, .. } => Some(path),
        Mode::Seeded { .. } | Mode::Record { .. } => None,
    }
}

/// Restore the recorded guest argv from a WASI trace, reconciling it with any
/// `--arg` values the operator also supplied on the replay. The trace is
/// authoritative: with no `--arg` the recorded argv is adopted verbatim; supplied
/// values must match the recording exactly or the replay is refused up front,
/// naming both. A trace recorded before argv capture (`guest_argv` absent) keeps
/// the historical contract — the supplied `--arg` values are used as-is.
fn reconcile_wasi_replay_argv(trace: &Path, supplied: &[String]) -> Result<Vec<String>, CliError> {
    let bundle = TraceBundle::load(trace)
        .map_err(|error| CliError(format!("failed to load trace {}: {error}", trace.display())))?;
    match bundle.metadata.guest_argv {
        Some(recorded) => {
            if !supplied.is_empty() && supplied != recorded.as_slice() {
                return Err(CliError(format!(
                    "replay --arg values {supplied:?} conflict with the trace's recorded guest \
arguments {recorded:?}; the trace is authoritative, so omit --arg (or supply matching values)"
                )));
            }
            Ok(recorded)
        }
        None => Ok(supplied.to_vec()),
    }
}

fn configured_wasi_host(
    invocation: &WasiInvocation,
    argv0: &Path,
    context: Context,
) -> Result<Preview1Host, CliError> {
    let mut host = Preview1Host::new(context)
        .with_resource_limits(invocation.resource_limits.to_host_limits())
        .with_argument(argv0.to_string_lossy().into_owned());
    for preopen in &invocation.preopens {
        host = host
            .with_preopen(&preopen.guest_path, preopen.policy)
            .map_err(|error| CliError(error.to_string()))?;
    }
    for argument in &invocation.arguments {
        host = host.with_argument(argument.clone());
    }
    for (key, value) in &invocation.environment {
        host = host.with_environment(key.clone(), value.clone());
    }
    for socket in &invocation.sockets {
        host = host
            .with_datagram_socket(socket.fd, &socket.bind, socket.peer.clone())
            .map_err(|error| CliError(error.to_string()))?;
    }
    Ok(host)
}

fn wasi_compatibility_fingerprint(
    bytes: &[u8],
    invocation: &WasiInvocation,
    buggify_enabled: bool,
) -> String {
    let mut hasher = Sha256::new();
    hash_bytes(&mut hasher, b"patina-wasi-execution-v1");
    hash_bytes(&mut hasher, env!("CARGO_PKG_VERSION").as_bytes());
    hash_bytes(&mut hasher, bytes);
    // Each section is domain-tagged and count-prefixed so fields cannot
    // migrate between sections (`--arg k --arg v` must not fingerprint like
    // `--env k=v`).
    hash_bytes(&mut hasher, b"wasi-arguments-v1");
    hash_bytes(
        &mut hasher,
        &(invocation.arguments.len() as u64).to_le_bytes(),
    );
    for argument in &invocation.arguments {
        hash_bytes(&mut hasher, argument.as_bytes());
    }
    hash_bytes(&mut hasher, b"wasi-environment-v1");
    hash_bytes(
        &mut hasher,
        &(invocation.environment.len() as u64).to_le_bytes(),
    );
    for (key, value) in &invocation.environment {
        hash_bytes(&mut hasher, key.as_bytes());
        hash_bytes(&mut hasher, value.as_bytes());
    }
    hash_bytes(&mut hasher, b"wasi-sockets-v1");
    hash_bytes(
        &mut hasher,
        &(invocation.sockets.len() as u64).to_le_bytes(),
    );
    for socket in &invocation.sockets {
        hash_bytes(&mut hasher, &socket.fd.to_le_bytes());
        hash_bytes(&mut hasher, socket.bind.as_bytes());
        hash_bytes(&mut hasher, socket.peer.as_bytes());
    }
    hash_wasi_preopens(&mut hasher, &invocation.preopens);
    hash_wasi_limit_overrides(&mut hasher, &invocation.resource_limits);
    // Buggify presence is folded in only when enabled, so a plain (non-buggify)
    // run fingerprints identically to before this component existed — mirroring
    // the native `+buggify` suffix, which is likewise appended only when on. The
    // specific knobs live in the trace metadata and are reconciled by the runtime;
    // the fingerprint carries only the boolean, which is all a flag-free replay
    // can recover from `trace_has_buggify`.
    if buggify_enabled {
        hash_bytes(&mut hasher, b"wasi-buggify-v1");
    }
    format!("sha256:{}", hex(&hasher.finalize()))
}

fn hash_wasi_preopens(hasher: &mut Sha256, preopens: &[WasiPreopenConfig]) {
    if preopens.is_empty() {
        return;
    }
    // Preopens are hashed in configuration order: descriptor numbers are
    // assigned in `with_preopen` call order, so a reordered preopen list is a
    // semantically different guest environment and must change the
    // fingerprint rather than fail later with a boundary-operation mismatch.
    hash_bytes(hasher, b"wasi-preopens-v1");
    hash_bytes(hasher, &(preopens.len() as u64).to_le_bytes());
    for preopen in preopens {
        hash_bytes(hasher, preopen.guest_path.as_bytes());
        hash_bytes(hasher, mount_policy_name(preopen.policy).as_bytes());
    }
}

fn hash_wasi_limit_overrides(hasher: &mut Sha256, limits: &WasiResourceLimitOverrides) {
    if limits == &WasiResourceLimitOverrides::default() {
        return;
    }
    hash_bytes(hasher, b"wasi-resource-limits-v1");
    if let Some(value) = limits.fuel {
        hash_bytes(hasher, b"fuel");
        hash_bytes(hasher, &value.to_le_bytes());
    }
    if let Some(value) = limits.max_memory_pages {
        hash_bytes(hasher, b"max-memory-pages");
        hash_bytes(hasher, &value.to_le_bytes());
    }
    if let Some(value) = limits.max_iovecs {
        hash_bytes(hasher, b"max-iovecs");
        hash_bytes(hasher, &(value as u64).to_le_bytes());
    }
    if let Some(value) = limits.max_io_bytes {
        hash_bytes(hasher, b"max-io-bytes");
        hash_bytes(hasher, &(value as u64).to_le_bytes());
    }
    if let Some(value) = limits.max_descriptors {
        hash_bytes(hasher, b"max-descriptors");
        hash_bytes(hasher, &(value as u64).to_le_bytes());
    }
    if let Some(value) = limits.max_preopens {
        hash_bytes(hasher, b"max-preopens");
        hash_bytes(hasher, &(value as u64).to_le_bytes());
    }
    if let Some(value) = limits.max_path_bytes {
        hash_bytes(hasher, b"max-path-bytes");
        hash_bytes(hasher, &(value as u64).to_le_bytes());
    }
}

fn mount_policy_name(policy: MountPolicy) -> &'static str {
    match policy {
        MountPolicy::ReadOnly => "ro",
        MountPolicy::ReadWrite => "rw",
    }
}

/// The `build --target wasi` verb: build the package and report the module path.
fn execute_wasi_build(invocation: WasiBuildInvocation) -> Result<i32, CliError> {
    let path = run_wasi_build(&invocation, None)?;
    if output::options().is_json() {
        output::emit_build("wasi", &path);
    } else {
        println!("PATINA_WASI_BUILD output={}", path.display());
    }
    Ok(0)
}

/// Build a Cargo package for `wasm32-wasip1` and return the produced `.wasm`.
/// Shared by the `build --target wasi` verb and build-on-the-fly. A `forced`
/// output (or the invocation's `output`) receives a copy of the module.
fn run_wasi_build(
    invocation: &WasiBuildInvocation,
    forced_output: Option<&Path>,
) -> Result<PathBuf, CliError> {
    if !invocation.manifest.is_file() {
        return Err(CliError(format!(
            "no Cargo manifest at {}",
            invocation.manifest.display()
        )));
    }
    let selected = select_native_package_bin(
        &invocation.manifest,
        invocation.package.as_deref(),
        invocation.bin.as_deref(),
    )?;
    let cargo = env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let mut command = Command::new(&cargo);
    command
        .arg("build")
        .arg("--manifest-path")
        .arg(&invocation.manifest)
        .arg("--package")
        .arg(&selected.package)
        .arg("--bin")
        .arg(&selected.bin)
        .arg("--target")
        .arg(WASI_PREVIEW1_TARGET)
        .arg("--message-format=json-render-diagnostics")
        .env("RUSTFLAGS", patina_rustflags())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    if invocation.release {
        command.arg("--release");
    }
    let built = command
        .output()
        .map_err(|error| CliError(format!("failed to run WASI cargo build: {error}")))?;
    if !built.status.success() {
        return Err(CliError(format!(
            "building the WASI package {:?} failed",
            selected.bin
        )));
    }
    let module = native_build_executable(&built.stdout, &selected.bin)?;
    match forced_output.or(invocation.output.as_deref()) {
        Some(destination) => {
            fs::copy(&module, destination).map_err(|error| {
                CliError(format!(
                    "failed to copy built module {} to {}: {error}",
                    module.display(),
                    destination.display()
                ))
            })?;
            Ok(destination.to_path_buf())
        }
        None => Ok(module),
    }
}

fn execute_wasi_audit(artifact: ArtifactRef) -> Result<i32, CliError> {
    let resolved = resolve_artifact(artifact)?;
    let bytes = fs::read(&resolved.path).map_err(|error| {
        CliError(format!(
            "failed to read WebAssembly module {}: {error}",
            resolved.path.display()
        ))
    })?;
    let audit = WasiAudit::audit(&bytes).map_err(|error| CliError(error.to_string()))?;
    let findings: Vec<String> = audit
        .imports
        .iter()
        .map(|import| format!("{}::{}", import.module, import.name))
        .collect();
    if output::options().is_json() {
        output::emit_audit(
            "audit",
            "wasi",
            &resolved.display.display().to_string(),
            findings,
            0,
        );
    } else {
        for finding in &findings {
            println!("{finding}");
        }
    }
    Ok(0)
}

/// A resolved run/audit/replay artifact: the concrete path to consume, a display
/// path (the source argument when built on the fly, so a WASI guest's `argv[0]`
/// and diagnostics name the source rather than a throwaway temp path), and an
/// optional workspace that must outlive its use.
struct ResolvedArtifact {
    path: PathBuf,
    display: PathBuf,
    _workspace: Option<tempfile::TempDir>,
}

/// The single shared resolution step: an already-built artifact is used
/// directly; a source/package is built on the fly through the shared build
/// pipeline (printing a one-line identity note) and its product used.
fn resolve_artifact(artifact: ArtifactRef) -> Result<ResolvedArtifact, CliError> {
    match artifact {
        ArtifactRef::Prebuilt(path) => Ok(ResolvedArtifact {
            display: path.clone(),
            path,
            _workspace: None,
        }),
        ArtifactRef::Build(spec) => build_on_the_fly(*spec),
    }
}

/// Build a source/package on the fly and return its artifact. Prints a one-line
/// identity note (`PATINA_BUILD_ON_RUN`) naming the source, the built artifact,
/// and its content hash, so an implicit rebuild never silently changes what ran.
fn build_on_the_fly(spec: BuildSpec) -> Result<ResolvedArtifact, CliError> {
    let workspace = tempfile::tempdir()
        .map_err(|error| CliError(format!("failed to create build workspace: {error}")))?;
    let (path, target_label) = match spec.kind {
        BuildSpecKind::Native(mut invocation) => {
            invocation.output = Some(workspace.path().join("patina-run-artifact"));
            (run_native_build(invocation)?, "native")
        }
        BuildSpecKind::Wasi(invocation) => {
            let output = workspace.path().join("patina-run-artifact.wasm");
            (run_wasi_build(&invocation, Some(&output))?, "wasi")
        }
    };
    let bytes = fs::read(&path).map_err(|error| {
        CliError(format!(
            "failed to read the built artifact {}: {error}",
            path.display()
        ))
    })?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    // Route this on-the-fly build note to stderr under `--output json` so stdout
    // stays a single clean JSON envelope; human output keeps it on stdout.
    let build_note = format!(
        "PATINA_BUILD_ON_RUN target={target_label} source={} artifact={} sha256={}",
        spec.origin.display(),
        path.display(),
        hex(&hasher.finalize())
    );
    if output::options().is_json() {
        eprintln!("{build_note}");
    } else {
        println!("{build_note}");
    }
    Ok(ResolvedArtifact {
        path,
        display: spec.origin,
        _workspace: Some(workspace),
    })
}

fn shell_quote(value: &OsStr) -> String {
    let text = value.to_string_lossy();
    if !text.is_empty()
        && text.chars().all(|ch| {
            ch.is_ascii_alphanumeric()
                || matches!(ch, '-' | '_' | '.' | '/' | ':' | '=' | '+' | ',')
        })
    {
        return text.into_owned();
    }
    format!("'{}'", text.replace('\'', "'\\''"))
}

fn command_line(prefix: &str, args: &[OsString]) -> String {
    let mut parts = vec![prefix.to_string()];
    parts.extend(args.iter().map(|arg| shell_quote(arg)));
    parts.join(" ")
}

fn command_with_seed(args: &[OsString], seed: u64) -> Vec<OsString> {
    let seed_text = seed.to_string();
    let mut out = Vec::with_capacity(args.len() + 2);
    let mut inserted = false;
    let mut index = 0;
    while index < args.len() {
        if args[index] == "--" {
            if !inserted {
                out.push(OsString::from("--seed"));
                out.push(OsString::from(&seed_text));
            }
            out.extend_from_slice(&args[index..]);
            return out;
        }
        if let Some(text) = args[index].to_str() {
            if text == "--seed" {
                out.push(OsString::from("--seed"));
                out.push(OsString::from(&seed_text));
                inserted = true;
                index += 2;
                continue;
            }
            if text.starts_with("--seed=") {
                out.push(OsString::from("--seed"));
                out.push(OsString::from(&seed_text));
                inserted = true;
                index += 1;
                continue;
            }
        }
        out.push(args[index].clone());
        index += 1;
    }
    if !inserted {
        out.push(OsString::from("--seed"));
        out.push(OsString::from(seed_text));
    }
    out
}

fn exploration_repro(wrapped_command: &[OsString], seed: u64) -> String {
    command_line("cargo patina", &command_with_seed(wrapped_command, seed))
}

struct BuiltNativeHarness {
    guest: PathBuf,
    directory: PathBuf,
    package_name: String,
}

struct NativeHarnessArtifact {
    executable: PathBuf,
    package_id: String,
}

struct HarnessSeedRun {
    exit_code: i32,
    result: String,
    stdout: String,
    stderr: String,
    message: Option<String>,
}

fn execute_native_harness(invocation: NativeHarnessInvocation) -> Result<i32, CliError> {
    let built = build_native_harness(&invocation)?;
    let test_name = format!("{}::{}", invocation.harness_target, invocation.exact);
    for seed in invocation.seeds.iter() {
        let run = run_native_harness_seed(&invocation, &built.guest, seed, None)?;
        if run.exit_code != 0 {
            let trace = built.directory.join(format!("seed-{seed}.patina"));
            let recorded = run_native_harness_seed(&invocation, &built.guest, seed, Some(&trace))?;
            let reproduced = recorded.exit_code == run.exit_code && recorded.exit_code != 0;
            let block = native_harness_failure_block(NativeHarnessFailure {
                invocation: &invocation,
                built: &built,
                test_name: &test_name,
                seed,
                trace: &trace,
                first: &run,
                recorded: &recorded,
                reproduced,
            });
            if !output::options().is_json() {
                eprintln!("{block}");
            }
            let exit = if reproduced { run.exit_code } else { 2 };
            let result = if reproduced {
                recorded.result.as_str()
            } else {
                "error"
            };
            output::emit_simple("test", result, exit, Some(block));
            return Ok(exit);
        }
    }
    let message = format!(
        "patina dst test passed: {test_name} {} package={} guest={}",
        invocation.seeds.label(),
        built.package_name,
        built.guest.display()
    );
    if output::options().is_json() {
        output::emit_simple("test", "ok", 0, Some(message));
    } else {
        println!("PATINA_DST_TEST_PASS {message}");
    }
    Ok(0)
}

fn build_native_harness(
    invocation: &NativeHarnessInvocation,
) -> Result<BuiltNativeHarness, CliError> {
    if !invocation.manifest.is_file() {
        return Err(CliError(format!(
            "no Cargo manifest at {}",
            invocation.manifest.display()
        )));
    }
    let staticlib = build_native_shim(invocation.release)?;
    let host_target = host_target_triple()?;
    let objects_base = staticlib
        .parent()
        .expect("shim staticlib path has a profile directory parent")
        .join(NATIVE_SHIM_OBJECTS_DIR);
    let object = stage_shim_object(&objects_base, &PATINA_POSIX_OBJECT, &host_target)?;
    let yield_object = if invocation.yield_points {
        let yield_note = format!(
            "PATINA_NATIVE_BUILD_YIELD_POINTS instrumentation=llvm-sancov-trace-pc-guard \
scheduler-hook=patina_yield_point fingerprint-suffix={PATINA_YIELD_FINGERPRINT_SUFFIX}"
        );
        if output::options().is_json() {
            eprintln!("{yield_note}");
        } else {
            println!("{yield_note}");
        }
        Some(stage_shim_object(
            &objects_base,
            &PATINA_YIELD_OBJECT,
            &host_target,
        )?)
    } else {
        None
    };
    let sancov_stub = stage_sancov_stub(&objects_base, yield_object.is_some(), &host_target)?;
    let rustflags = native_package_rustflags(
        &object,
        &staticlib,
        yield_object.as_deref(),
        sancov_stub.as_deref(),
        &host_target,
    )?;
    let metadata = cargo_metadata(&invocation.manifest)?;
    let target_dir = metadata
        .get("target_directory")
        .and_then(serde_json::Value::as_str)
        .map(PathBuf::from)
        .ok_or_else(|| CliError("cargo metadata did not report target_directory".into()))?;
    let selected = select_native_harness_target(
        &metadata,
        &invocation.harness_target,
        invocation.package.as_deref(),
    )?;

    let cargo = env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let mut command = Command::new(&cargo);
    command
        .arg("rustc")
        .arg("--manifest-path")
        .arg(&invocation.manifest)
        .arg("--package")
        .arg(&selected.package)
        .arg("--target")
        .arg(&host_target)
        .arg("--message-format=json-render-diagnostics")
        .env_remove("RUSTFLAGS")
        .env("CARGO_ENCODED_RUSTFLAGS", rustflags)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    command.args(selected.kind.select_args(&invocation.harness_target));
    // `cargo rustc` builds a lib/bin target in test mode only under the `test` or
    // `bench` profile, and `--release` is rejected alongside `--profile`. `bench`
    // inherits `release`, so `--release` here means the same codegen settings a
    // `cargo test --release` harness would get, including any `[profile.release]`
    // overrides the package declares.
    command
        .arg("--profile")
        .arg(if invocation.release { "bench" } else { "test" });
    command.arg("--").args(native_package_link_args(
        &object,
        &staticlib,
        yield_object.as_deref(),
    ));
    let built = command.output().map_err(|error| {
        CliError(format!(
            "failed to run cargo rustc for native harness: {error}"
        ))
    })?;
    if !built.status.success() {
        return Err(CliError(format!(
            "building the native libtest harness {:?} failed",
            invocation.harness_target
        )));
    }
    let artifact = native_harness_executable(&built.stdout, &invocation.harness_target)?;
    let package_name = metadata_package_name(&metadata, &artifact.package_id)
        .unwrap_or_else(|| artifact.package_id.clone());
    let directory = target_dir
        .join("patina")
        .join("dst")
        .join(safe_path_segment(&package_name))
        .join(safe_path_segment(&invocation.harness_target))
        .join(safe_path_segment(&invocation.exact));
    fs::create_dir_all(&directory).map_err(|error| {
        CliError(format!(
            "failed to create native harness staging dir {}: {error}",
            directory.display()
        ))
    })?;
    let guest = directory.join("guest");
    fs::copy(&artifact.executable, &guest).map_err(|error| {
        CliError(format!(
            "failed to stage native harness {} at {}: {error}",
            artifact.executable.display(),
            guest.display()
        ))
    })?;
    let permissions = fs::metadata(&artifact.executable)
        .map_err(|error| {
            CliError(format!(
                "failed to read permissions for {}: {error}",
                artifact.executable.display()
            ))
        })?
        .permissions();
    fs::set_permissions(&guest, permissions).map_err(|error| {
        CliError(format!(
            "failed to copy permissions to staged native harness {}: {error}",
            guest.display()
        ))
    })?;
    Ok(BuiltNativeHarness {
        guest,
        directory,
        package_name,
    })
}

fn cargo_metadata(manifest: &Path) -> Result<serde_json::Value, CliError> {
    let cargo = env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let output = Command::new(&cargo)
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .arg("--manifest-path")
        .arg(manifest)
        .output()
        .map_err(|error| CliError(format!("failed to run cargo metadata: {error}")))?;
    if !output.status.success() {
        return Err(CliError(format!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|error| CliError(format!("failed to parse cargo metadata: {error}")))
}

fn metadata_package_name(metadata: &serde_json::Value, package_id: &str) -> Option<String> {
    metadata
        .get("packages")
        .and_then(serde_json::Value::as_array)?
        .iter()
        .find(|package| package.get("id").and_then(serde_json::Value::as_str) == Some(package_id))?
        .get("name")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
}

/// Which `cargo rustc` target-selection flag reaches a libtest harness target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HarnessTargetKind {
    /// The package's own library, built in test mode (`--harness-target <crate>`
    /// naming the crate itself — the common shape).
    Lib,
    /// An integration test under `tests/`.
    Test,
    /// A binary target's inline `#[test]`s.
    Bin,
}

impl HarnessTargetKind {
    fn select_args(self, name: &str) -> Vec<String> {
        match self {
            HarnessTargetKind::Lib => vec!["--lib".to_string()],
            HarnessTargetKind::Test => vec!["--test".to_string(), name.to_string()],
            HarnessTargetKind::Bin => vec!["--bin".to_string(), name.to_string()],
        }
    }
}

/// The package and target kind a `--harness-target` name resolves to.
struct SelectedNativeHarness {
    package: String,
    kind: HarnessTargetKind,
}

/// Resolve `--harness-target` to exactly one package and target *before*
/// building, so the shim link arguments can be scoped to that one unit with
/// `cargo rustc` (see [`native_package_link_args`]). Fails closed on an unknown
/// or ambiguous name, listing what the workspace does offer.
fn select_native_harness_target(
    metadata: &serde_json::Value,
    harness_target: &str,
    package: Option<&str>,
) -> Result<SelectedNativeHarness, CliError> {
    let packages = metadata
        .get("packages")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| CliError("cargo metadata reported no packages".into()))?;
    let mut matches: Vec<SelectedNativeHarness> = Vec::new();
    let mut available = BTreeSet::new();
    for entry in packages {
        let Some(package_name) = entry.get("name").and_then(serde_json::Value::as_str) else {
            continue;
        };
        if package.is_some_and(|wanted| wanted != package_name) {
            continue;
        }
        let targets = entry
            .get("targets")
            .and_then(serde_json::Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default();
        for target in targets {
            let Some(name) = target.get("name").and_then(serde_json::Value::as_str) else {
                continue;
            };
            let kinds: Vec<&str> = target
                .get("kind")
                .and_then(serde_json::Value::as_array)
                .map(|kinds| kinds.iter().filter_map(serde_json::Value::as_str).collect())
                .unwrap_or_default();
            // A `[lib]` reports its declared crate types as its kinds, so a
            // dependency-style `crate-type = ["rlib", "cdylib"]` library is still
            // selected by `--lib`. Build scripts (`custom-build`) and examples
            // carry no libtest harness.
            let kind = if kinds
                .iter()
                .all(|kind| matches!(*kind, "lib" | "rlib" | "dylib" | "cdylib" | "proc-macro"))
                && !kinds.is_empty()
            {
                HarnessTargetKind::Lib
            } else if kinds == ["test"] {
                HarnessTargetKind::Test
            } else if kinds == ["bin"] {
                HarnessTargetKind::Bin
            } else {
                continue;
            };
            available.insert(name.to_string());
            if name == harness_target {
                matches.push(SelectedNativeHarness {
                    package: package_name.to_string(),
                    kind,
                });
            }
        }
    }
    match matches.len() {
        1 => Ok(matches.remove(0)),
        0 => Err(CliError(format!(
            "no libtest harness target named {harness_target:?} in the workspace; available harness targets: {}",
            if available.is_empty() {
                "<none>".to_string()
            } else {
                available.into_iter().collect::<Vec<_>>().join(", ")
            }
        ))),
        _ => Err(CliError(format!(
            "multiple targets named {harness_target:?} were found; select one workspace member with --package"
        ))),
    }
}

fn native_harness_executable(
    stdout: &[u8],
    harness_target: &str,
) -> Result<NativeHarnessArtifact, CliError> {
    let mut matches = Vec::new();
    let mut available = BTreeSet::new();
    for line in stdout.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            continue;
        }
        let Ok(message) = serde_json::from_slice::<serde_json::Value>(line) else {
            continue;
        };
        if message.get("reason").and_then(serde_json::Value::as_str) != Some("compiler-artifact") {
            continue;
        }
        let Some(executable) = message
            .get("executable")
            .and_then(serde_json::Value::as_str)
        else {
            continue;
        };
        let is_test_profile = message
            .get("profile")
            .and_then(|profile| profile.get("test"))
            .and_then(serde_json::Value::as_bool)
            == Some(true);
        if !is_test_profile {
            continue;
        }
        let target_name = message
            .get("target")
            .and_then(|target| target.get("name"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("<unknown>");
        available.insert(target_name.to_string());
        if target_name == harness_target {
            let package_id = message
                .get("package_id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("<unknown-package>")
                .to_string();
            matches.push(NativeHarnessArtifact {
                executable: PathBuf::from(executable),
                package_id,
            });
        }
    }
    match matches.len() {
        1 => Ok(matches.remove(0)),
        0 => Err(CliError(format!(
            "no libtest harness target named {harness_target:?} was reported by cargo test --no-run; available harness targets: {}",
            if available.is_empty() {
                "<none>".to_string()
            } else {
                available.into_iter().collect::<Vec<_>>().join(", ")
            }
        ))),
        _ => Err(CliError(format!(
            "multiple libtest harness targets named {harness_target:?} were reported; select one workspace member with --package"
        ))),
    }
}

fn safe_path_segment(value: &str) -> String {
    let mut segment = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
            segment.push(ch);
        } else {
            segment.push('_');
        }
    }
    if segment.is_empty() {
        "_".to_string()
    } else {
        segment
    }
}

fn run_native_harness_seed(
    invocation: &NativeHarnessInvocation,
    guest: &Path,
    seed: u64,
    record: Option<&Path>,
) -> Result<HarnessSeedRun, CliError> {
    let executable = env::current_exe().map_err(|error| {
        CliError(format!(
            "failed to locate current cargo-patina executable: {error}"
        ))
    })?;
    let mut args = vec![
        OsString::from("run"),
        OsString::from("--format"),
        OsString::from("json"),
    ];
    args.push(guest.as_os_str().to_owned());
    args.push(OsString::from("--seed"));
    args.push(OsString::from(seed.to_string()));
    if let Some(path) = record {
        args.push(OsString::from("--record"));
        args.push(path.as_os_str().to_owned());
    }
    append_native_harness_run_flags(&mut args, invocation);
    args.push(OsString::from("--"));
    args.push(OsString::from("--test-threads=1"));
    args.push(OsString::from("--exact"));
    args.push(OsString::from(&invocation.exact));
    args.push(OsString::from("--nocapture"));
    let output = Command::new(&executable)
        .args(&args)
        .output()
        .map_err(|error| CliError(format!("failed to run native harness seed {seed}: {error}")))?;
    let exit_code = exit_code(output.status)?;
    let stdout_text = String::from_utf8_lossy(&output.stdout).into_owned();
    let child_stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let json_line = stdout_text
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .ok_or_else(|| {
            CliError(format!(
                "native harness seed {seed} produced no JSON envelope\nstderr:\n{child_stderr}"
            ))
        })?;
    let envelope: serde_json::Value = serde_json::from_str(json_line).map_err(|error| {
        CliError(format!(
            "native harness seed {seed} did not produce a valid JSON envelope: {error}\nstdout:\n{stdout_text}\nstderr:\n{child_stderr}"
        ))
    })?;
    let result = envelope
        .get("result")
        .and_then(serde_json::Value::as_str)
        .unwrap_or(if exit_code == 0 { "ok" } else { "failure" })
        .to_string();
    let guest_stdout = envelope
        .get("stdout")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_string();
    let guest_stderr = envelope
        .get("stderr")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let mut stderr = String::new();
    if !child_stderr.is_empty() {
        stderr.push_str(&child_stderr);
        if !child_stderr.ends_with('\n') && !guest_stderr.is_empty() {
            stderr.push('\n');
        }
    }
    stderr.push_str(guest_stderr);
    let message = envelope
        .get("message")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    if stderr.trim().is_empty() {
        if let Some(message) = &message {
            stderr.push_str(message);
        }
    }
    Ok(HarnessSeedRun {
        exit_code,
        result,
        stdout: guest_stdout,
        stderr,
        message,
    })
}

fn append_native_harness_run_flags(args: &mut Vec<OsString>, invocation: &NativeHarnessInvocation) {
    if let Some(budget) = invocation.step_budget {
        args.push(OsString::from("--budget"));
        args.push(OsString::from(budget.to_string()));
    }
    // Every knob the registry defines, from the shared table: a flag the harness
    // parsed but did not re-emit would be silently inert here. That includes the
    // repeatable ones (`--dns-entry`, `--net-partition`), which the harness
    // family registers and which the historical `--dns-entry` bug parsed and
    // then dropped, so every lookup in a harness run went NXDOMAIN as if no
    // table had been supplied.
    for (flag, value) in knob_flag_pairs(&invocation.knobs) {
        args.push(OsString::from(flag));
        args.push(OsString::from(value));
    }
    if let Some(buggify) = &invocation.buggify {
        match &buggify.fire_permille {
            Some(value) => args.push(OsString::from(format!("--buggify={value}"))),
            None => args.push(OsString::from("--buggify")),
        }
        push_optional_arg(
            args,
            "--buggify-activation-permille",
            buggify.activation_permille.as_deref(),
        );
        push_optional_arg(
            args,
            "--buggify-cutoff-nanos",
            buggify.cutoff_nanos.as_deref(),
        );
        if buggify.after_setup {
            args.push(OsString::from("--buggify-after-setup"));
        }
    }
    push_optional_value_flag(args, "--sched-pct", invocation.schedule.pct.as_deref());
    push_optional_arg(
        args,
        "--sched-pct-steps",
        invocation.schedule.pct_steps.as_deref(),
    );
    push_optional_value_flag(args, "--starve", invocation.schedule.starve.as_deref());
    push_optional_arg(
        args,
        "--starve-max-len",
        invocation.schedule.starve_max_len.as_deref(),
    );
    push_optional_arg(
        args,
        "--starve-window",
        invocation.schedule.starve_window.as_deref(),
    );
    if invocation.schedule.swarm {
        args.push(OsString::from("--swarm"));
    }
    push_optional_value_flag(
        args,
        "--liveness-watchdog",
        invocation.liveness.watchdog.as_deref(),
    );
    push_optional_value_flag(
        args,
        "--converge-within",
        invocation.liveness.converge.as_deref(),
    );
    push_optional_arg(
        args,
        "--heal-after",
        invocation.liveness.heal_after.as_deref(),
    );
}

fn push_optional_arg(args: &mut Vec<OsString>, flag: &str, value: Option<&str>) {
    if let Some(value) = value {
        args.push(OsString::from(flag));
        args.push(OsString::from(value));
    }
}

fn push_optional_value_flag(args: &mut Vec<OsString>, flag: &str, value: Option<&str>) {
    if let Some(value) = value {
        if value.is_empty() {
            args.push(OsString::from(flag));
        } else {
            args.push(OsString::from(format!("{flag}={value}")));
        }
    }
}

struct NativeHarnessFailure<'a> {
    invocation: &'a NativeHarnessInvocation,
    built: &'a BuiltNativeHarness,
    test_name: &'a str,
    seed: u64,
    trace: &'a Path,
    first: &'a HarnessSeedRun,
    recorded: &'a HarnessSeedRun,
    reproduced: bool,
}

fn native_harness_failure_block(failure: NativeHarnessFailure<'_>) -> String {
    let repro = native_harness_repro(failure.invocation, failure.seed);
    let replay = format!(
        "cargo patina replay {} {}",
        shell_quote(failure.built.guest.as_os_str()),
        shell_quote(failure.trace.as_os_str())
    );
    let mut block = format!(
        "patina dst test failed: {}\n  {}  exit={}  class={}\n  trace: {}\n  stderr tail:\n{}\n  reproduce:\n    {repro}\n    {replay}",
        failure.test_name,
        failure.invocation.seeds.contains(failure.seed),
        failure.first.exit_code,
        failure.recorded.result,
        failure.trace.display(),
        indent_tail(&failure.recorded.stderr, 20),
    );
    if !failure.reproduced {
        block.push_str(&format!(
            "\n  record-on-failure mismatch: first exit={} recorded exit={}; refusing to call this deterministic",
            failure.first.exit_code, failure.recorded.exit_code
        ));
    }
    if !failure.first.stdout.trim().is_empty() {
        block.push_str("\n  stdout tail:\n");
        block.push_str(&indent_tail(&failure.first.stdout, 10));
    }
    if let Some(message) = &failure.recorded.message {
        if !message.trim().is_empty() && !failure.recorded.stderr.contains(message) {
            block.push_str(&format!("\n  message: {message}"));
        }
    }
    block
}

fn native_harness_repro(invocation: &NativeHarnessInvocation, seed: u64) -> String {
    let mut args = vec![
        OsString::from("test"),
        invocation.origin.as_os_str().to_owned(),
    ];
    if let Some(package) = &invocation.package {
        args.push(OsString::from("--package"));
        args.push(OsString::from(package));
    }
    args.push(OsString::from("--harness-target"));
    args.push(OsString::from(&invocation.harness_target));
    args.push(OsString::from("--exact"));
    args.push(OsString::from(&invocation.exact));
    args.push(OsString::from("--seed"));
    args.push(OsString::from(seed.to_string()));
    if invocation.release {
        args.push(OsString::from("--release"));
    }
    if invocation.yield_points {
        args.push(OsString::from("--yield-points"));
    }
    append_native_harness_run_flags(&mut args, invocation);
    command_line("cargo patina", &args)
}

fn indent_tail(text: &str, max_lines: usize) -> String {
    let lines: Vec<&str> = text.lines().collect();
    if lines.is_empty() {
        return "    (empty)".to_string();
    }
    let start = lines.len().saturating_sub(max_lines);
    lines[start..]
        .iter()
        .map(|line| format!("    {line}"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn execute_explore(exploration: ExploreInvocation) -> Result<i32, CliError> {
    // Explore drives many child runs and reports once, so per-seed run
    // finalization (capture/envelope/render) is suppressed here: each child
    // streams normally and this verb emits a single campaign-level envelope.
    output::suppress_run_finalize();
    let start = exploration.start_seed;
    let count = exploration.seed_count;
    // The native and WASI families build the artifact once, then run that SAME
    // built artifact across every seed — a source/package is never rebuilt per
    // seed. The resolved artifact (and its build workspace) is held for the whole
    // sweep so the built file outlives every run. The Cargo family instead re-runs
    // the whole command per seed (cargo caches the build).
    let prebuilt = match &exploration.target {
        ExploreTarget::Cargo(_) => None,
        ExploreTarget::Wasi(invocation) => Some(resolve_artifact(invocation.module.clone())?),
        ExploreTarget::Native(invocation) => Some(resolve_artifact(invocation.binary.clone())?),
    };
    let seed_at = |offset: u64| {
        start
            .checked_add(offset)
            .expect("exploration range was validated")
    };
    for offset in 0..count {
        let seed = seed_at(offset);
        let exit = match &exploration.target {
            ExploreTarget::Cargo(invocation) => {
                let mut invocation = invocation.clone();
                invocation.mode = Mode::Seeded { seed };
                execute(invocation)?
            }
            ExploreTarget::Wasi(invocation) => {
                let mut invocation = invocation.clone();
                invocation.module = ArtifactRef::Prebuilt(
                    prebuilt
                        .as_ref()
                        .expect("wasi explore resolved")
                        .path
                        .clone(),
                );
                invocation.mode = Mode::Seeded { seed };
                execute_wasi_run(invocation)?
            }
            ExploreTarget::Native(invocation) => {
                let mut invocation = invocation.clone();
                invocation.binary = ArtifactRef::Prebuilt(
                    prebuilt
                        .as_ref()
                        .expect("native explore resolved")
                        .path
                        .clone(),
                );
                invocation.mode = NativeRunMode::Seeded { seed };
                execute_native_run(invocation)?
            }
        };
        if exit != 0 {
            let repro = exploration_repro(&exploration.wrapped_command, seed);
            eprintln!(
                "PATINA_EXPLORE_FAILURE seed={seed} exit={exit} repro={:?}",
                repro
            );
            output::emit_simple(
                "explore",
                "failure",
                exit,
                Some(format!("seed {seed} exited {exit}; repro: {repro}")),
            );
            return Ok(exit);
        }
    }
    if output::options().is_json() {
        output::emit_simple(
            "explore",
            "ok",
            0,
            Some(format!("start={start} seeds={count}")),
        );
    } else {
        println!("PATINA_EXPLORE_COMPLETE start={start} seeds={count}");
    }
    Ok(0)
}

fn execute_native_audit(invocation: NativeAuditInvocation) -> Result<i32, CliError> {
    // A build-on-the-fly artifact is always shim-linked (it comes through the
    // same pipeline `build` uses), so the shim-linked gate only concerns a
    // prebuilt binary the caller handed us.
    let was_prebuilt = matches!(invocation.binary, ArtifactRef::Prebuilt(_));
    let resolved = resolve_artifact(invocation.binary)?;
    let bytes = fs::read(&resolved.path).map_err(|error| {
        CliError(format!(
            "failed to read native binary {}: {error}",
            resolved.path.display()
        ))
    })?;
    // Fail closed on a prebuilt binary that was not built with `cargo patina
    // build`: its import table lists the unsatisfied libc calls the shim would
    // interpose once linked (`open`, `clock_gettime`, `pthread_mutex_*`, ...),
    // not the true post-interposition residual. Auditing it raw reports ~the
    // whole libc surface as "unsupported", the exact opposite of the truth. The
    // audit is only meaningful against a shim-linked artifact, so steer to
    // source-first (which links the shim before auditing) or a Patina-built
    // binary — with `--raw` as the explicit escape hatch.
    let shim_linked = if was_prebuilt {
        native_binary_is_shim_linked(&bytes).map_err(|error| CliError(error.to_string()))?
    } else {
        true
    };
    if !shim_linked && !invocation.raw {
        return Err(CliError(format!(
            "refusing to audit {}: this binary was not built with `cargo patina build`, so its \
             imports are unsatisfied libc calls (open, clock_gettime, pthread_mutex_*, ...) — the \
             surface the shim *interposes* once linked — not the post-interposition residual. The \
             audit would be the opposite of the truth. Audit source-first so the shim is linked \
             first:\n    cargo patina audit ./Cargo.toml --bin <NAME>\nor pass a Patina-built \
             artifact (`cargo patina build ... --output <PATH>`). To list the raw imports of this \
             exact binary anyway, re-run with --raw.",
            resolved.path.display()
        )));
    }
    // `--raw` on a NON-shim-linked binary: run the full audit anyway — the
    // instruction scan and escape categorization stay meaningful — but under a
    // loud banner, because the *import* findings are the pre-interposition libc
    // surface, not the post-interposition residual a shim-linked audit reports.
    if !shim_linked && invocation.raw {
        eprintln!(
            "PATINA_RAW_AUDIT: auditing a NON-shim-linked binary. Import findings reflect \
             unsatisfied libc imports — most are symbols the shim interposes once `cargo patina \
             build` links it in — NOT the post-interposition residual. Audit source-first \
             (`cargo patina audit ./Cargo.toml --bin <NAME>`) for the true residual."
        );
    }
    // Shim-linked (or built on the fly, or --raw): render the real audit — for a
    // shim-linked artifact this is the true post-interposition residual, and it
    // fails closed on any genuine escape.
    //
    // The allow set is the shared `effective_native_allow` (shim control-plane +
    // the operator's `--allow`), the SAME set the pre-run `run` gate audits
    // against, so the static surface `audit` reports equals the surface `run`
    // enforces — closing the reported `_dlsym` disparity.
    //
    // syscall-user-dispatch (SUD-DESIGN.md §7.1): a `direct-syscall` *instruction*
    // finding in a SUD-dispatch-capable binary is not a hard escape — at run time
    // it is trapped and routed by SUD (on a kernel that has it). `audit` is
    // static (no live kernel probe), so it reports BOTH outcomes: runnable under
    // SUD, refused on kernels without it. Any OTHER denial (or the same finding
    // without the SUD marker) still fails closed.
    let effective = effective_native_allow(&invocation.allow);
    // Host-identity reads (`cpuid`) are informational, so they are reported on
    // EVERY outcome of the three-way split below — clean, trap-managed, and
    // refused. Scan for them once here rather than in each arm. The scan can only
    // fail the ways `NativeAudit::audit` fails on the same bytes (parse, format,
    // undecodable architecture), so propagating is fail-closed and changes no
    // message an operator sees.
    let host_identity =
        native_host_identity_sites(&bytes).map_err(|error| CliError(error.to_string()))?;
    let audit = match NativeAudit::audit(&bytes, &effective) {
        Ok(audit) => audit,
        Err(TargetError::UnsupportedNativeImports(denied)) => {
            let sud_marker = native_binary_has_sud_marker(&bytes)
                .map_err(|error| CliError(error.to_string()))?;
            // The timestamp-counter trap is the same shape as the SUD downgrade,
            // one instruction class over: an `rdtsc`/`rdtscp` finding in a
            // trap-capable binary is answered from the virtual clock at run time
            // on x86-64 Linux. `audit` stays static, so it reports both outcomes.
            let tsc_marker = native_binary_has_tsc_marker(&bytes)
                .map_err(|error| CliError(error.to_string()))?;
            let (managed, hard): (Vec<_>, Vec<_>) = denied.iter().cloned().partition(|escape| {
                (sud_marker && native_escape_is_sud_manageable(escape))
                    || (tsc_marker && native_escape_is_tsc_manageable(escape))
            });
            let (sud_instructions, tsc_instructions): (Vec<_>, Vec<_>) = managed
                .into_iter()
                .partition(native_escape_is_sud_manageable);
            if !hard.is_empty() || (sud_instructions.is_empty() && tsc_instructions.is_empty()) {
                // A genuine escape remains (or there was nothing SUD could manage):
                // fail closed and render the provenance-rich audit result.
                emit_native_audit_violation(&resolved.path, &denied, &host_identity);
                emit_host_identity_note(&host_identity);
                return Ok(2);
            }
            // Only trap-manageable instruction findings, and the matching
            // dispatcher is linked: report them as managed (both outcomes) and
            // succeed.
            let sites = sud_instructions.len();
            let tsc_sites = tsc_instructions.len();
            if output::options().is_json() {
                let mut findings: Vec<String> = sud_instructions
                    .iter()
                    .map(|escape| format!("{} (direct-syscall, SUD-managed)", escape.symbol))
                    .collect();
                findings.extend(tsc_instructions.iter().map(|escape| {
                    format!("{} (cpu-nondeterminism, TSC-trap-managed)", escape.symbol)
                }));
                let mut details = native_escape_details(&sud_instructions, Some("SUD-managed"));
                details.extend(native_escape_details(
                    &tsc_instructions,
                    Some("TSC-trap-managed"),
                ));
                details.extend(host_identity_details(&host_identity));
                output::emit_audit_with_details(
                    "audit",
                    "native",
                    &resolved.path.display().to_string(),
                    findings,
                    details,
                    0,
                );
            } else {
                if sites > 0 {
                    println!(
                        "direct-syscall (SUD-managed, {sites} site{}): raw inline syscall instruction(s) \
trapped into the deterministic runtime via syscall-user-dispatch. Runnable on a SUD kernel \
(x86_64 >= 5.11); refused on kernels without it (notably arm64 today) — rebuild with \
`--cfg rustix_use_libc` for those.",
                        if sites == 1 { "" } else { "s" }
                    );
                }
                if tsc_sites > 0 {
                    println!(
                        "cpu-nondeterminism (TSC-trap-managed, {tsc_sites} site{}): inline rdtsc/rdtscp \
answered deterministically from the run's virtual clock via prctl(PR_SET_TSC) on x86-64 Linux; \
refused everywhere else (macOS, arm64) — rebuild the guest without the inline counter read for \
those. Manageable is not runnable: this says the counter reads are answered, not that the guest \
progresses. A guest that calibrates the counter by busy-waiting on clock deltas is carried by the \
runtime's advance-on-spin rescue; one that spins without ever consulting the value stops with a \
named frozen-clock-churn abort.",
                        if tsc_sites == 1 { "" } else { "s" }
                    );
                }
                for escape in sud_instructions.iter().chain(tsc_instructions.iter()) {
                    println!("  {} ({})", escape.symbol, escape.category);
                    for provenance in &escape.provenance {
                        if let Some(site) = provenance.site_label() {
                            println!("    {} [{site}]", provenance.label());
                        } else {
                            println!("    {}", provenance.label());
                        }
                    }
                }
            }
            emit_host_identity_note(&host_identity);
            return Ok(0);
        }
        Err(error) => return Err(CliError(error.to_string())),
    };
    let findings: Vec<String> = audit.imports.iter().map(ToString::to_string).collect();
    if output::options().is_json() {
        output::emit_audit_with_details(
            "audit",
            "native",
            &resolved.path.display().to_string(),
            findings,
            host_identity_details(&host_identity),
            0,
        );
    } else {
        for finding in &findings {
            println!("{finding}");
        }
    }
    // The audit above reports the import-table residual. Deny-trap-armed symbols
    // are absent from it by construction (the shim strong-def drops them off the
    // import table), so add the non-blocking "fails later" note naming any this
    // binary references — visible up front rather than only when a call aborts.
    emit_native_deny_trap_note(&bytes);
    // Same visibility rule for imports the undefined-weak rule cleared: the
    // audit outcome ignores them, but the surface stays named, on stderr in
    // both output modes so the JSON envelope stays schema-stable.
    if let Some(note) = render_inert_weak_imports(&audit.inert_weak_imports) {
        eprintln!("{note}");
    }
    // And for host-identity reads: a clean audit is exactly where their silence
    // used to be total — the binary passes, and nothing said its code paths can
    // vary across hosts.
    emit_host_identity_note(&host_identity);
    Ok(0)
}

/// The disposition label host-identity findings carry in the JSON envelope's
/// `finding_details`, alongside `SUD-managed` / `TSC-trap-managed`. Both halves
/// are the point: *unmanaged* (no trap, no model — unlike the timestamp counter)
/// and *visible* (reported anyway, unlike the silence this replaced).
const HOST_IDENTITY_DISPOSITION: &str = "unmanaged-visible";

fn host_identity_details(sites: &[NativeEscape]) -> Vec<serde_json::Value> {
    native_escape_details(sites, Some(HOST_IDENTITY_DISPOSITION))
}

/// Print the host-identity heading, on stderr in BOTH output modes — the
/// inert-weak-imports rule. The sites are informational and never change the exit
/// code, so keeping them off stdout leaves the human import list and the JSON
/// envelope byte-stable for callers that parse them; JSON consumers get the same
/// sites as `finding_details` rows carrying [`HOST_IDENTITY_DISPOSITION`].
fn emit_host_identity_note(sites: &[NativeEscape]) {
    if let Some(note) = render_host_identity_note(sites) {
        eprintln!("{note}");
    }
}

fn emit_native_audit_violation(
    path: &Path,
    denied: &[NativeEscape],
    host_identity: &[NativeEscape],
) {
    let findings = denied.iter().map(native_escape_summary).collect::<Vec<_>>();
    if output::options().is_json() {
        let mut details = native_escape_details(denied, None);
        // A refusal reports the host-identity sites too: they are not why the
        // binary was refused, and dropping them here would make the class visible
        // on some outcomes and silent on others.
        details.extend(host_identity_details(host_identity));
        output::emit_audit_with_details(
            "audit",
            "native",
            &path.display().to_string(),
            findings,
            details,
            2,
        );
    } else {
        eprintln!("{}", render_native_escapes_grouped(denied));
    }
}

fn native_escape_summary(escape: &NativeEscape) -> String {
    format!("{} ({})", escape.symbol, escape.category)
}

fn push_native_escape_provenance_lines(output: &mut String, escape: &NativeEscape, indent: &str) {
    for provenance in &escape.provenance {
        output.push('\n');
        output.push_str(indent);
        output.push_str(&provenance.label());
        if let Some(site) = provenance.site_label() {
            output.push_str(&format!(" [{site}]"));
        }
    }
}

fn native_escape_details(
    escapes: &[NativeEscape],
    disposition: Option<&str>,
) -> Vec<serde_json::Value> {
    escapes
        .iter()
        .map(|escape| {
            let provenance = escape
                .provenance
                .iter()
                .map(|origin| {
                    serde_json::json!({
                        "object": origin.object.clone(),
                        "crate": origin.crate_name.clone(),
                        "containing_symbol": origin.containing_symbol.clone(),
                        "section": origin.section.clone(),
                    })
                })
                .collect::<Vec<_>>();
            let mut detail = serde_json::json!({
                "symbol": escape.symbol.clone(),
                "category": escape.category,
                "provenance": provenance,
            });
            if let Some(disposition) = disposition {
                detail["disposition"] = serde_json::Value::String(disposition.to_string());
            }
            detail
        })
        .collect()
}

fn link_arg(path: &Path) -> OsString {
    let mut arg = OsString::from("link-arg=");
    arg.push(path);
    arg
}

/// The Patina source workspace root, baked in at compile time. Build-on-the-fly
/// links the `patina-dst-native-shim` staticlib, whose crate lives in this
/// workspace, so the shim build is pinned here rather than to the caller's CWD —
/// letting `build`/`run`/`audit`/`replay` of a source or package succeed from any
/// working directory.
fn patina_source_workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")))
}

/// Build the `patina-dst-native-shim` staticlib and return its path. The shim's
/// Rust boundary is produced by Cargo; the C POSIX layer and header are packaged
/// into this binary and compiled at link time by [`execute_native_build`].
fn build_native_shim(release: bool) -> Result<PathBuf, CliError> {
    // The shim crate lives in the Patina source workspace, so `cargo build -p
    // patina-dst-native-shim` must run THERE, not in the caller's CWD. Pinning it
    // is what lets `build .`/`run <DIR>`/`audit <DIR>` succeed from inside the
    // target package (or any other directory): otherwise cargo resolves `-p
    // patina-dst-native-shim` against the caller's workspace and fails with
    // "package ID specification `patina-dst-native-shim` did not match any
    // packages" — the observed `build .` regression.
    let workspace = patina_source_workspace();
    // Both halves of a native build must come from ONE toolchain. Because the
    // shim build is pinned to the workspace directory above and the guest build
    // is not, the two can resolve different compilers; refuse before compiling
    // anything rather than letting two libstds meet at the guest link.
    check_native_toolchain_agreement(&workspace)?;
    let cargo = env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let mut command = Command::new(&cargo);
    command
        .current_dir(&workspace)
        .arg("build")
        .arg("-p")
        .arg("patina-dst-native-shim");
    if release {
        command.arg("--release");
    }
    let status = command
        .status()
        .map_err(|error| CliError(format!("failed to build patina-dst-native-shim: {error}")))?;
    if !status.success() {
        return Err(CliError(
            "building the patina-dst-native-shim staticlib failed".into(),
        ));
    }
    let target_dir = match env::var_os("CARGO_TARGET_DIR") {
        Some(dir) => PathBuf::from(dir),
        None => workspace.join("target"),
    };
    let profile = if release { "release" } else { "debug" };
    let staticlib = target_dir.join(profile).join(NATIVE_SHIM_STATICLIB);
    if !staticlib.exists() {
        return Err(CliError(format!(
            "expected the shim staticlib at {} after building it",
            staticlib.display()
        )));
    }
    Ok(staticlib)
}

/// A resolved rustc, as `rustc -vV` reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RustcIdentity {
    /// The `rustc -vV` banner line, e.g. `rustc 1.86.0 (05f9846f8 2025-03-31)`.
    banner: String,
    /// The full `-vV` block: release, commit hash, host triple, LLVM version.
    verbose: String,
}

/// Resolve the rustc that compiles code in `directory`.
///
/// The working directory is the input that matters. Under rustup, the `rustc` on
/// `PATH` is a proxy that picks its toolchain from the `rust-toolchain.toml`
/// found by walking up from wherever it runs, and Cargo inherits that: even a
/// toolchain's own `cargo` binary invokes the `PATH` proxy for `rustc`, so the
/// directory a build runs in — not the `cargo` that drives it — decides which
/// compiler compiles the crate. Without rustup, `rustc` is a real binary and
/// every directory resolves the same identity.
fn rustc_identity(rustc: &OsStr, directory: &Path) -> Result<RustcIdentity, CliError> {
    let output = Command::new(rustc)
        .arg("-vV")
        .current_dir(directory)
        .output()
        .map_err(|error| {
            CliError(format!(
                "failed to query the rustc identity in {}: {error}",
                directory.display()
            ))
        })?;
    if !output.status.success() {
        return Err(CliError(format!(
            "rustc -vV failed in {}: {}",
            directory.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let verbose = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let banner = verbose.lines().next().unwrap_or_default().to_owned();
    if banner.is_empty() {
        return Err(CliError(format!(
            "rustc -vV reported no version in {}",
            directory.display()
        )));
    }
    Ok(RustcIdentity { banner, verbose })
}

/// The compiler to probe with, honoring `RUSTC` exactly as the builds do so an
/// explicitly pinned compiler probes as the single identity it is.
///
/// The two probes run in two different directories, so the value must name the
/// same program from both. A bare name is left alone (the OS resolves it against
/// `PATH`, which does not depend on the working directory); a relative path with
/// a directory component would resolve against each probe's own directory, so it
/// is anchored to `from` first.
fn anchored_rustc(rustc: Option<OsString>, from: &Path) -> OsString {
    let Some(rustc) = rustc else {
        return OsString::from("rustc");
    };
    let path = Path::new(&rustc);
    let has_directory = path
        .parent()
        .is_some_and(|parent| !parent.as_os_str().is_empty());
    if path.is_relative() && has_directory {
        from.join(path).into_os_string()
    } else {
        rustc
    }
}

/// Refuse a native build whose shim staticlib and guest program would be
/// compiled by two different toolchains.
///
/// [`build_native_shim`] pins the shim's Cargo build to the Patina source
/// workspace so `-p patina-dst-native-shim` always resolves; the guest build runs
/// in the caller's working directory. When those two directories resolve
/// different toolchains — a tree carrying its own `rust-toolchain.toml`, with the
/// `cargo-patina` binary invoked directly rather than as `cargo patina` — two
/// Rust standard libraries meet at the guest link. That is a `duplicate symbol:
/// rust_eh_personality` link error on Linux and, worse, a silent success on
/// macOS: the guest links and runs carrying two libstds. Name it before either
/// happens.
fn check_native_toolchain_agreement(workspace: &Path) -> Result<(), CliError> {
    if !workspace.is_dir() {
        // No workspace to build the shim in; let `build_native_shim` report that
        // in its own terms rather than shadowing it with a probe failure.
        return Ok(());
    }
    let guest_dir = env::current_dir()
        .map_err(|error| CliError(format!("failed to read the working directory: {error}")))?;
    let rustc = anchored_rustc(env::var_os("RUSTC"), &guest_dir);
    let shim = rustc_identity(&rustc, workspace)?;
    let guest = rustc_identity(&rustc, &guest_dir)?;
    if shim == guest {
        return Ok(());
    }
    Err(CliError(toolchain_mismatch_message(
        &shim, workspace, &guest, &guest_dir,
    )))
}

/// The refusal text for a shim/guest toolchain split: name both toolchains, the
/// directory each resolved in, and the two ways to pin one toolchain for both.
fn toolchain_mismatch_message(
    shim: &RustcIdentity,
    shim_dir: &Path,
    guest: &RustcIdentity,
    guest_dir: &Path,
) -> String {
    let mut message = String::from(
        "refusing to build: the Patina shim staticlib and the guest program would be compiled by \
two different rustc toolchains, so two Rust standard libraries would meet at the guest link \
(`duplicate symbol: rust_eh_personality` on Linux; on macOS the link silently succeeds and the \
guest carries both).\n",
    );
    message.push_str(&format!(
        "  shim toolchain:  {} (resolved in {})\n  guest toolchain: {} (resolved in {})\n",
        shim.banner,
        shim_dir.display(),
        guest.banner,
        guest_dir.display()
    ));
    if shim.banner == guest.banner {
        // Same release, different compiler: show the full identities so the
        // difference (commit hash, host triple, LLVM version) is visible.
        message.push_str(&format!(
            "the two report the same version but are not the same compiler:\n  shim:\n{}\n  \
guest:\n{}\n",
            indent_lines(&shim.verbose, "    "),
            indent_lines(&guest.verbose, "    ")
        ));
    }
    message.push_str(
        "the shim always builds in the Patina source workspace, while the guest builds in the \
working directory, and rustup's `rustc` proxy picks its toolchain from the rust-toolchain file \
above whichever directory it runs in. Pin one toolchain for both: invoke through rustup as `cargo \
patina ...` (the cargo proxy exports RUSTUP_TOOLCHAIN for the whole build), or set RUSTUP_TOOLCHAIN \
yourself before invoking the cargo-patina binary directly.",
    );
    message
}

/// Prefix every line of `text` with `indent`.
fn indent_lines(text: &str, indent: &str) -> String {
    text.lines()
        .map(|line| format!("{indent}{line}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The `build` (native) verb: build and report the artifact path.
fn execute_native_build(invocation: NativeBuildInvocation) -> Result<i32, CliError> {
    let path = run_native_build(invocation)?;
    if output::options().is_json() {
        output::emit_build("native", &path);
    } else {
        println!("PATINA_NATIVE_BUILD output={}", path.display());
    }
    Ok(0)
}

/// Run the native build pipeline and return the produced artifact path. Shared
/// by the `build` verb and build-on-the-fly (`run`/`audit`/`replay` of a
/// source): both go through exactly this code.
fn run_native_build(invocation: NativeBuildInvocation) -> Result<PathBuf, CliError> {
    let staticlib = build_native_shim(invocation.release)?;
    let host_target = host_target_triple()?;

    // Stage the embedded POSIX shim layer at a stable content-addressed path in
    // the shim's own profile target dir (beside the staticlib), compiled below
    // the user program with the flags the deterministic linked target requires.
    // The object lives in the persistent target dir — not a per-invocation
    // tempdir — so its `-Clink-arg` path is byte-identical across builds and
    // Cargo's crate fingerprints stay warm; it outlives every child cargo/rustc.
    let objects_base = staticlib
        .parent()
        .expect("shim staticlib path has a profile directory parent")
        .join(NATIVE_SHIM_OBJECTS_DIR);
    let object = stage_shim_object(&objects_base, &PATINA_POSIX_OBJECT, &host_target)?;
    // The yield-point hook object is compiled and linked only under
    // `--yield-points`; a plain build never references SanitizerCoverage symbols.
    let yield_object = if invocation.yield_points {
        // Surface the instrumentation prominently: this binary is not a plain
        // build — it carries LLVM SanitizerCoverage yield points wired to the
        // deterministic scheduler, and `native-run` will schedule it under a
        // distinct (denser) policy recorded in its fingerprint.
        let yield_note = format!(
            "PATINA_NATIVE_BUILD_YIELD_POINTS instrumentation=llvm-sancov-trace-pc-guard \
scheduler-hook=patina_yield_point fingerprint-suffix={PATINA_YIELD_FINGERPRINT_SUFFIX}"
        );
        if output::options().is_json() {
            eprintln!("{yield_note}");
        } else {
            println!("{yield_note}");
        }
        Some(stage_shim_object(
            &objects_base,
            &PATINA_YIELD_OBJECT,
            &host_target,
        )?)
    } else {
        None
    };

    match invocation.target {
        NativeBuildTarget::Source {
            source,
            edition,
            rustc_args,
        } => build_native_source(
            &source,
            invocation
                .output
                .as_deref()
                .expect("single-source native-build requires --output"),
            &edition,
            invocation.release,
            &object,
            &staticlib,
            yield_object.as_deref(),
            &rustc_args,
        ),
        NativeBuildTarget::Package {
            manifest,
            package,
            bin,
        } => build_native_package(
            &manifest,
            package.as_deref(),
            bin.as_deref(),
            invocation.output.as_deref(),
            invocation.release,
            &host_target,
            &object,
            &staticlib,
            yield_object.as_deref(),
        ),
    }
}

/// A shim helper object compiled below the guest and linked into every native
/// build. Both variants are content-addressed by [`stage_shim_object`]: the POSIX
/// layer always, the `--yield-points` hook only under that flag.
struct ShimObject {
    /// Final object file name, e.g. `patina_posix.o`.
    object_name: &'static str,
    /// C translation-unit file name written into the compile sandbox.
    source_name: &'static str,
    /// Embedded C source compiled into the object.
    source: &'static str,
    /// Header staged beside the source and reached through `-I`, if any.
    header: Option<(&'static str, &'static str)>,
    /// `cc` flags, excluding `-c`/`-I`/the input path/`-o` (added by the stager).
    cc_flags: &'static [&'static str],
    /// What the object is, for staging/compilation diagnostics.
    what: &'static str,
}

/// The embedded POSIX shim C layer, compiled below the user program with the
/// flags the deterministic linked target requires.
const PATINA_POSIX_OBJECT: ShimObject = ShimObject {
    object_name: "patina_posix.o",
    source_name: "patina_posix.c",
    source: PATINA_POSIX_C,
    header: Some(("patina_native.h", PATINA_NATIVE_H)),
    cc_flags: &[
        "-std=c11",
        "-D_POSIX_C_SOURCE=200809L",
        "-fno-stack-protector",
        "-Wall",
        "-Wextra",
        "-Werror",
    ],
    what: "the Patina POSIX shim layer",
};

/// The `--yield-points` hook object. Compiled without the SanitizerCoverage flags
/// themselves, so the hook (and thus `patina_yield_point` it calls) is never
/// itself instrumented and cannot recurse.
const PATINA_YIELD_OBJECT: ShimObject = ShimObject {
    object_name: "patina_yield.o",
    source_name: "patina_yield.c",
    source: PATINA_YIELD_C,
    header: None,
    cc_flags: &[
        "-std=c11",
        "-fno-stack-protector",
        "-Wall",
        "-Wextra",
        "-Werror",
    ],
    what: "the Patina yield-point hook",
};

/// The weak SanitizerCoverage stubs. Unlike every other shim object this one is
/// injected whole-graph rather than scoped to the guest's final link, because the
/// instrumentation it answers for is whole-graph too — so it must be
/// position-independent: the artifacts that need it are shared libraries, and a
/// non-PIC object referencing anything by absolute address is refused outright by
/// GNU `ld`/`lld` inside a shared-object link. macOS `cc` compiles PIC by
/// default, so the flag is a no-op there.
const PATINA_SANCOV_STUB_OBJECT: ShimObject = ShimObject {
    object_name: "patina_sancov_stub.o",
    source_name: "patina_sancov_stub.c",
    source: PATINA_SANCOV_STUB_C,
    header: None,
    cc_flags: &[
        "-std=c11",
        "-fno-stack-protector",
        "-fPIC",
        "-Wall",
        "-Wextra",
        "-Werror",
    ],
    what: "the Patina SanitizerCoverage stubs",
};

/// Hash the inputs that determine a shim object's bytes: the compiler identity
/// and its `--version` banner, the target triple, the object name, the exact cc
/// flags, and the embedded C header/source. The staged path changes only when one
/// of these does, so a rebuild of the same Patina against the same toolchain
/// reuses the object and the `-Clink-arg` path stays stable.
fn shim_object_hash(cc: &OsStr, object: &ShimObject, target: &str) -> Result<String, CliError> {
    let version = Command::new(cc)
        .arg("--version")
        .output()
        .map_err(|error| CliError(format!("failed to query C compiler {cc:?}: {error}")))?;
    if !version.status.success() {
        return Err(CliError(format!("C compiler {cc:?} --version failed")));
    }
    let mut hasher = Sha256::new();
    hash_os(&mut hasher, cc);
    hash_bytes(&mut hasher, &version.stdout);
    hash_bytes(&mut hasher, target.as_bytes());
    hash_bytes(&mut hasher, object.object_name.as_bytes());
    for flag in object.cc_flags {
        hash_bytes(&mut hasher, flag.as_bytes());
    }
    if let Some((header_name, header_source)) = object.header {
        hash_bytes(&mut hasher, header_name.as_bytes());
        hash_bytes(&mut hasher, header_source.as_bytes());
    }
    hash_bytes(&mut hasher, object.source.as_bytes());
    Ok(hex(&hasher.finalize()))
}

/// Compile `object` to a stable, content-addressed path under `base` and return
/// it, reusing an already-staged object without recompiling. Staging is
/// race-safe: the object is compiled in a private sandbox to a unique temp file
/// in the destination dir, then atomically renamed into place — concurrent
/// invocations produce byte-identical content, so a late writer only re-stamps
/// the same object. The staged object lives in the persistent target dir with no
/// RAII cleanup; the cache is bounded because the hash changes only when Patina's
/// embedded C, the cc flags, the target, or the compiler itself changes.
fn stage_shim_object(base: &Path, object: &ShimObject, target: &str) -> Result<PathBuf, CliError> {
    let cc = env::var_os("CC").unwrap_or_else(|| OsString::from("cc"));
    let hash = shim_object_hash(&cc, object, target)?;
    let dir = base.join(hash);
    let staged = dir.join(object.object_name);
    if staged.exists() {
        return Ok(staged);
    }
    fs::create_dir_all(&dir).map_err(|error| {
        CliError(format!(
            "failed to create the shim object cache {}: {error}",
            dir.display()
        ))
    })?;
    let sandbox = tempfile::tempdir().map_err(|error| {
        CliError(format!(
            "failed to create the shim compile sandbox: {error}"
        ))
    })?;
    let mut command = Command::new(&cc);
    command.args(object.cc_flags);
    if let Some((header_name, header_source)) = object.header {
        fs::write(sandbox.path().join(header_name), header_source)
            .map_err(|error| CliError(format!("failed to stage {}: {error}", object.what)))?;
        command.arg("-I").arg(sandbox.path());
    }
    let source_path = sandbox.path().join(object.source_name);
    fs::write(&source_path, object.source)
        .map_err(|error| CliError(format!("failed to stage {}: {error}", object.what)))?;
    let temp_object = tempfile::Builder::new()
        .prefix(object.object_name)
        .suffix(".tmp")
        .tempfile_in(&dir)
        .map_err(|error| CliError(format!("failed to stage {}: {error}", object.what)))?
        .into_temp_path();
    command
        .arg("-c")
        .arg(&source_path)
        .arg("-o")
        .arg(&temp_object);
    let cc_status = command
        .status()
        .map_err(|error| CliError(format!("failed to run C compiler {cc:?}: {error}")))?;
    if !cc_status.success() {
        return Err(CliError(format!("compiling {} failed", object.what)));
    }
    temp_object.persist(&staged).map_err(|error| {
        CliError(format!(
            "failed to stage {} at {}: {error}",
            object.what,
            staged.display()
        ))
    })?;
    Ok(staged)
}

/// The rustc flags that turn on LLVM SanitizerCoverage trace-pc-guard
/// instrumentation at basic-block granularity (level 3 reaches loop backedges),
/// so `__sanitizer_cov_trace_pc_guard` — routed to `patina_yield_point` by the
/// linked hook — fires inside hot loops, not only at function entry. `-Cpasses`
/// and `-Cllvm-args` are stable rustc codegen flags, so this needs no nightly
/// toolchain and no `RUSTC_BOOTSTRAP`. The only version coupling is to LLVM's
/// internal pass name (`sancov-module`) and coverage cl::opts, which are stable
/// across the LLVM releases rustc ships but are not a rustc stability guarantee.
fn sancov_rustc_flags() -> [&'static str; 8] {
    [
        "-C",
        "passes=sancov-module",
        "-C",
        "llvm-args=-sanitizer-coverage-level=3",
        "-C",
        "llvm-args=-sanitizer-coverage-trace-pc-guard",
        "-C",
        "llvm-args=-sanitizer-coverage-pc-table",
    ]
}

/// Add the platform-specific shim link arguments a native binary needs to
/// `configure`. On Linux the shim interposes thread creation with a plain strong
/// `pthread_create` def and reaches the real glibc creator through its host-alias
/// table (`dlsym(RTLD_NEXT, ...)`), so no link-time wrap is needed — and none is
/// used: gcc ships its own `__wrap_pthread_create` in libgcc's x86 split-stack
/// support, so `-Wl,--wrap=pthread_create` would `multiple definition`-clash at
/// link. macOS uses `pthread_create_suspended_np`. The shim objects also land
/// after the toolchain's own `-lc`, and glibc's `atexit` lives in
/// `libc_nonshared.a` (reached through the `libc.so` linker script); GNU ld scans
/// archives in a single pass, so libc must be scanned again after the shim
/// objects introduce their references.
fn push_platform_link_args(mut configure: impl FnMut(&str)) {
    #[cfg(target_os = "linux")]
    {
        // Wrap `dlsym` so the shim's host-alias table can reach the real glibc
        // resolver through `__real_dlsym` while guest/std references to `dlsym`
        // still bind to the shim's `__wrap_dlsym` interposer (which resolves only
        // its deterministic entropy routing table — never a host symbol). This is
        // the Linux half of the host-alias doctrine: `dlsym(RTLD_NEXT, ...)`
        // resolves the trace-fd I/O, baton-semaphore, and host-thread-creation
        // vehicles at runtime, so `__read`/`__write`/`sem_*`/`pthread_create` no
        // longer appear in the guest import table.
        configure("link-arg=-Wl,--wrap=dlsym");
        configure("link-arg=-lc");
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = &mut configure;
    }
}

/// Compile a single Rust source, injecting cfg(patina)/cfg(dst) and linking the
/// POSIX object and shim staticlib below it. Built native for the host, so the
/// host OS selects the link recipe.
#[allow(clippy::too_many_arguments)]
fn build_native_source(
    source: &Path,
    output: &Path,
    edition: &str,
    release: bool,
    object: &Path,
    staticlib: &Path,
    yield_object: Option<&Path>,
    rustc_args: &[OsString],
) -> Result<PathBuf, CliError> {
    let rustc = env::var_os("RUSTC").unwrap_or_else(|| OsString::from("rustc"));
    let mut command = Command::new(&rustc);
    command
        .arg("--edition")
        .arg(edition)
        // `patina_shim` marks a shim-linked build: the `patina` crate's SDK
        // resolves its buggify FFI only under this cfg, so a plain/WASI/`run`
        // build (which also sets `patina`/`dst`) never references the shim
        // symbols and never fails to link.
        .args(["--cfg", "patina", "--cfg", "dst", "--cfg", "patina_shim"])
        .arg("-C")
        .arg(link_arg(object))
        .arg("-C")
        .arg(link_arg(staticlib));
    if let Some(yield_object) = yield_object {
        // SanitizerCoverage is driven entirely through stable `-C` codegen flags
        // (no `RUSTC_BOOTSTRAP`); the hook object below resolves the emitted
        // callbacks.
        command
            .args(sancov_rustc_flags())
            .arg("-C")
            .arg(link_arg(yield_object));
    }
    push_platform_link_args(|arg| {
        command.arg("-C").arg(arg);
    });
    if release {
        // Match cargo's `release` profile so a single-source guest behaves
        // identically to a package guest under `--release`: optimize, and compile
        // out `debug_assert!`/overflow checks (which turns those free failure
        // oracles into no-ops — see the debug-vs-release note). These are stable
        // `-C` codegen flags, so no nightly/`RUSTC_BOOTSTRAP`, and they compose
        // with the sancov yield-point flags above. Emitted before `rustc_args` so
        // an explicit trailing `-C opt-level=…` from the user still wins (rustc
        // takes the last value for a repeated `-C` option).
        command.args([
            "-C",
            "opt-level=3",
            "-C",
            "debug-assertions=off",
            "-C",
            "overflow-checks=off",
        ]);
    }
    command.arg(source).arg("-o").arg(output).args(rustc_args);
    let status = command
        .status()
        .map_err(|error| CliError(format!("failed to run rustc {rustc:?}: {error}")))?;
    if !status.success() {
        return Err(CliError("linking the native Patina program failed".into()));
    }
    Ok(output.to_path_buf())
}

/// Drive a Cargo package's own build under Patina control, as `cargo rustc` so
/// the two injections land at their correct scopes. The cfg flags travel in
/// `CARGO_ENCODED_RUSTFLAGS` and reach every crate compiled from source, which
/// `cfg(patina)`-gated dependency code needs; the shim's link arguments travel
/// as `cargo rustc`'s trailing arguments and reach only the selected binary's
/// final link, never an intermediate dependency artifact
/// ([`native_package_link_args`] has the failure this prevents). The explicit
/// host `--target` additionally keeps the cfgs off build scripts and proc
/// macros, which Cargo compiles for the host without these flags.
#[allow(clippy::too_many_arguments)]
fn build_native_package(
    manifest: &Path,
    package: Option<&str>,
    bin: Option<&str>,
    output: Option<&Path>,
    release: bool,
    host_target: &str,
    object: &Path,
    staticlib: &Path,
    yield_object: Option<&Path>,
) -> Result<PathBuf, CliError> {
    if !manifest.is_file() {
        return Err(CliError(format!(
            "no Cargo manifest at {}",
            manifest.display()
        )));
    }
    let selected = select_native_package_bin(manifest, package, bin)?;
    let objects_base = staticlib
        .parent()
        .expect("shim staticlib path has a profile directory parent")
        .join(NATIVE_SHIM_OBJECTS_DIR);
    let sancov_stub = stage_sancov_stub(&objects_base, yield_object.is_some(), host_target)?;
    let rustflags = native_package_rustflags(
        object,
        staticlib,
        yield_object,
        sancov_stub.as_deref(),
        host_target,
    )?;

    let cargo = env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let mut command = Command::new(&cargo);
    command
        .arg("rustc")
        .arg("--manifest-path")
        .arg(manifest)
        .arg("--package")
        .arg(&selected.package)
        .arg("--bin")
        .arg(&selected.bin)
        .arg("--target")
        .arg(host_target)
        .arg("--message-format=json-render-diagnostics")
        .env_remove("RUSTFLAGS")
        .env("CARGO_ENCODED_RUSTFLAGS", rustflags)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    // The SanitizerCoverage flags carried in the encoded rustflags are stable
    // `-C` codegen options, so no `RUSTC_BOOTSTRAP` is needed. They apply to every
    // crate Cargo compiles from source in this invocation (guest + its
    // path/registry deps); the precompiled std is untouched, so only guest code
    // gains yield points.
    if release {
        command.arg("--release");
    }
    command
        .arg("--")
        .args(native_package_link_args(object, staticlib, yield_object));
    let built = command
        .output()
        .map_err(|error| CliError(format!("failed to run cargo rustc: {error}")))?;
    if !built.status.success() {
        return Err(CliError(format!(
            "building the native Patina package {:?} failed",
            selected.bin
        )));
    }
    let executable = native_build_executable(&built.stdout, &selected.bin)?;
    let final_path = if let Some(destination) = output {
        fs::copy(&executable, destination).map_err(|error| {
            CliError(format!(
                "failed to copy built binary {} to {}: {error}",
                executable.display(),
                destination.display()
            ))
        })?;
        destination.to_path_buf()
    } else {
        executable
    };
    Ok(final_path)
}

/// The package and binary a package `native-build` resolves to.
struct SelectedNativeBin {
    package: String,
    bin: String,
}

/// Resolve which package and which binary target `native-build` should compile,
/// failing closed on ambiguity rather than guessing. `cargo metadata` enumerates
/// the workspace members and their targets without touching the network for a
/// path-only graph.
fn select_native_package_bin(
    manifest: &Path,
    package: Option<&str>,
    bin: Option<&str>,
) -> Result<SelectedNativeBin, CliError> {
    let cargo = env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let output = Command::new(&cargo)
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .arg("--manifest-path")
        .arg(manifest)
        .output()
        .map_err(|error| CliError(format!("failed to run cargo metadata: {error}")))?;
    if !output.status.success() {
        return Err(CliError(format!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let metadata: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| CliError(format!("failed to parse cargo metadata: {error}")))?;
    let packages = metadata
        .get("packages")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| CliError("cargo metadata reported no packages".into()))?;

    let selected = if let Some(name) = package {
        packages
            .iter()
            .find(|entry| entry.get("name").and_then(serde_json::Value::as_str) == Some(name))
            .ok_or_else(|| {
                CliError(format!(
                    "package {name:?} is not a member of {}",
                    manifest.display()
                ))
            })?
    } else {
        // With no --package, select the package defined by exactly this manifest
        // so a member of a larger workspace resolves unambiguously.
        let wanted = fs::canonicalize(manifest).unwrap_or_else(|_| manifest.to_path_buf());
        let mut matches = packages.iter().filter(|entry| {
            entry
                .get("manifest_path")
                .and_then(serde_json::Value::as_str)
                .map(|path| fs::canonicalize(path).unwrap_or_else(|_| PathBuf::from(path)))
                == Some(wanted.clone())
        });
        matches.next().ok_or_else(|| {
            CliError(format!(
                "{} defines no package (a virtual workspace); select a member with --package",
                manifest.display()
            ))
        })?
    };

    let package_name = selected
        .get("name")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| CliError("cargo metadata package has no name".into()))?
        .to_string();
    let mut binaries = selected
        .get("targets")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter(|target| {
            target
                .get("kind")
                .and_then(serde_json::Value::as_array)
                .into_iter()
                .flatten()
                .any(|kind| kind.as_str() == Some("bin"))
        })
        .filter_map(|target| {
            target
                .get("name")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .collect::<Vec<_>>();
    binaries.sort();

    let chosen = if let Some(name) = bin {
        if !binaries.iter().any(|candidate| candidate == name) {
            return Err(CliError(format!(
                "package {package_name:?} has no binary target {name:?}; available: {}",
                binaries.join(", ")
            )));
        }
        name.to_string()
    } else {
        match binaries.as_slice() {
            [single] => single.clone(),
            [] => {
                return Err(CliError(format!(
                    "package {package_name:?} has no binary targets to build"
                )));
            }
            multiple => {
                return Err(CliError(format!(
                    "package {package_name:?} has multiple binary targets ({}); select one with --bin",
                    multiple.join(", ")
                )));
            }
        }
    };
    Ok(SelectedNativeBin {
        package: package_name,
        bin: chosen,
    })
}

/// Locate the executable Cargo emitted for `bin` from its JSON build output.
fn native_build_executable(stdout: &[u8], bin: &str) -> Result<PathBuf, CliError> {
    for line in stdout.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            continue;
        }
        let Ok(message) = serde_json::from_slice::<serde_json::Value>(line) else {
            continue;
        };
        if message.get("reason").and_then(serde_json::Value::as_str) != Some("compiler-artifact") {
            continue;
        }
        let Some(executable) = message
            .get("executable")
            .and_then(serde_json::Value::as_str)
        else {
            continue;
        };
        let is_target_bin = message.get("target").is_some_and(|target| {
            target.get("name").and_then(serde_json::Value::as_str) == Some(bin)
        });
        if is_target_bin {
            return Ok(PathBuf::from(executable));
        }
    }
    Err(CliError(format!(
        "cargo build did not report an executable artifact for binary {bin:?}"
    )))
}

/// Query rustc for the host target triple so the package build isolates its
/// link arguments to host artifacts.
fn host_target_triple() -> Result<String, CliError> {
    let output = Command::new("rustc")
        .arg("-vV")
        .output()
        .map_err(|error| CliError(format!("failed to query rustc host target: {error}")))?;
    if !output.status.success() {
        return Err(CliError(format!(
            "rustc -vV failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .map(str::to_owned)
        .ok_or_else(|| CliError("rustc -vV did not report a host target triple".into()))
}

/// Build the `CARGO_ENCODED_RUSTFLAGS` value for a package build: the
/// cfg(patina)/cfg(dst) family, the shim-build marker that keys the injected
/// link inputs' bytes, plus, under `--yield-points`, the SanitizerCoverage
/// codegen flags. Encoded with the `0x1f` unit separator so values containing
/// spaces survive intact. Any pre-existing `RUSTFLAGS` are preserved ahead of
/// the injected flags, matching how `cargo patina run` layers its cfgs onto the
/// user's flags.
///
/// Everything here is deliberately whole-graph: Cargo forwards `RUSTFLAGS` to
/// every crate it compiles from source in the invocation, which is exactly what
/// `cfg(patina)`-gated guest/dependency code and yield-point instrumentation
/// need. The shim's *link* arguments must not be whole-graph and live in
/// [`native_package_link_args`] instead — with one exception, `sancov_stub`,
/// which is a link argument precisely because the instrumentation above is
/// whole-graph (see [`PATINA_SANCOV_STUB_OBJECT`]). The link-input paths taken
/// here are consumed only by [`shim_link_inputs_hash`]; the link arguments
/// themselves never enter this string.
fn native_package_rustflags(
    object: &Path,
    staticlib: &Path,
    yield_object: Option<&Path>,
    sancov_stub: Option<&Path>,
    target: &str,
) -> Result<OsString, CliError> {
    let mut tokens: Vec<OsString> = Vec::new();
    if let Some(existing) = env::var_os("RUSTFLAGS") {
        for part in existing.to_string_lossy().split_whitespace() {
            tokens.push(OsString::from(part));
        }
    }
    tokens.push(OsString::from("--cfg"));
    tokens.push(OsString::from("patina"));
    tokens.push(OsString::from("--cfg"));
    tokens.push(OsString::from("dst"));
    // Shim-linked build marker; see `compile_single_source` for why the SDK's
    // buggify FFI is gated on `patina_shim` rather than `patina`.
    tokens.push(OsString::from("--cfg"));
    tokens.push(OsString::from("patina_shim"));
    // rustix's DEFAULT Linux backend emits raw inline syscall instructions —
    // invisible to the import audit and refused by the instruction scan. On
    // targets WITHOUT syscall-user-dispatch (aarch64 Linux today; macOS uses
    // libc anyway so the cfg is inert), flip rustix to its libc backend with
    // its own escape hatch so those effects surface as interposable imports.
    // On a SUD-capable target (x86_64 Linux) we DROP the injection: the shim
    // arms SUD and traps the raw syscalls into the deterministic runtime, so
    // the workaround is unnecessary — and keeping it would be a permanent dual
    // path (SUD-DESIGN.md §9). No-cruft: a single conditional, no dead config.
    if !target_has_sud(target) {
        tokens.push(OsString::from("--cfg"));
        tokens.push(OsString::from("rustix_use_libc"));
    }
    if let Some(sancov_stub) = sancov_stub {
        for flag in sancov_rustc_flags() {
            tokens.push(OsString::from(flag));
        }
        tokens.push(OsString::from("-C"));
        tokens.push(link_arg(sancov_stub));
    }
    // Key the flag string to the *bytes* of the link inputs injected by
    // `native_package_link_args`. Cargo fingerprints this string, never the
    // files it points at, so a rebuilt shim staticlib — which always lands at
    // the same canonical `<target>/<profile>/libpatina_dst_native_shim.a` —
    // used to leave the string identical: Cargo called the guest fresh, skipped
    // the link, and `build` handed back a binary still linked against the
    // PREVIOUS shim. The helper objects dodge that by being content-addressed
    // by path (`stage_shim_object`); the staticlib cannot be, so its content
    // travels in the flags instead. See `shim_link_inputs_hash` for why a cfg
    // carries it.
    tokens.push(OsString::from("--cfg"));
    let mut marker = OsString::from(SHIM_BUILD_CFG);
    marker.push("=\"");
    marker.push(shim_link_inputs_hash(object, staticlib, yield_object)?);
    marker.push("\"");
    tokens.push(marker);
    let mut encoded = OsString::new();
    for (index, token) in tokens.iter().enumerate() {
        if index > 0 {
            encoded.push("\u{1f}");
        }
        encoded.push(token);
    }
    Ok(encoded)
}

/// Hash the contents of every shim link input a package build injects, in a
/// fixed order, so the value changes exactly when one of those files' bytes
/// changes.
///
/// The value rides in `--cfg patina_shim_build="<hash>"` rather than in a link
/// argument, for two reasons. It must not perturb the guest: `-C metadata=`
/// would also invalidate Cargo's fingerprint, but it feeds rustc's symbol
/// hashes, so an unchanged program would compile to different bytes. And it
/// must not cost disk: content-addressing the staticlib by path (a hashed copy
/// or hardlink, the way the small C objects are staged) would strand another
/// copy of a tens-of-megabytes archive in the target dir on every shim rebuild,
/// unboundedly over a shim-development session. A cfg no code reads
/// changes nothing about the compiled output and stores nothing — it only moves
/// Cargo's fingerprint, which is the whole point. Identical shim bytes give an
/// identical value, so an unchanged rebuild still hits the cache warm.
fn shim_link_inputs_hash(
    object: &Path,
    staticlib: &Path,
    yield_object: Option<&Path>,
) -> Result<String, CliError> {
    let mut hasher = Sha256::new();
    for input in [Some(object), Some(staticlib), yield_object]
        .into_iter()
        .flatten()
    {
        hash_file_contents(&mut hasher, input)?;
    }
    Ok(hex(&hasher.finalize()))
}

/// Fold `path`'s bytes and length into `hasher`, streamed so the multi-megabyte
/// shim staticlib is never held in memory.
fn hash_file_contents(hasher: &mut Sha256, path: &Path) -> Result<(), CliError> {
    use io::Read;

    let mut file = fs::File::open(path).map_err(|error| {
        CliError(format!(
            "failed to open the shim link input {}: {error}",
            path.display()
        ))
    })?;
    let mut buffer = vec![0u8; 64 * 1024];
    let mut length: u64 = 0;
    loop {
        let read = file.read(&mut buffer).map_err(|error| {
            CliError(format!(
                "failed to read the shim link input {}: {error}",
                path.display()
            ))
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        length += read as u64;
    }
    hasher.update(length.to_le_bytes());
    Ok(())
}

/// Stage [`PATINA_SANCOV_STUB_OBJECT`] when the build is instrumented. The stubs
/// exist only to answer the instrumentation, so a build without `--yield-points`
/// stages nothing and no Patina object reaches a dependency's link at all.
fn stage_sancov_stub(
    base: &Path,
    yield_points: bool,
    target: &str,
) -> Result<Option<PathBuf>, CliError> {
    if !yield_points {
        return Ok(None);
    }
    stage_shim_object(base, &PATINA_SANCOV_STUB_OBJECT, target).map(Some)
}

/// The shim's link arguments for a package build, as the trailing arguments of
/// `cargo rustc -- <args>`.
///
/// These must NOT travel in `RUSTFLAGS`. rustc forwards `-C link-arg` to the
/// system linker for every crate-type it actually links, so a whole-graph
/// injection reaches more than the guest binary: an `rlib` compile has no link
/// step and ignores them, but a dependency whose `[lib]` declares
/// `crate-type = ["rlib", "cdylib"]` (crc-fast 1.10.0, from the SlateDB
/// dogfooding feedback) runs a real `cdylib` link and receives the shim objects
/// and staticlib too. That link then fails on Linux — `duplicate symbol:
/// rust_eh_personality`, defined by both the sysroot libstd rlib and the copy of
/// std bundled inside `libpatina_dst_native_shim.a`, for any cdylib whose code
/// has landing pads — while producing nothing anyone loads. There is no avoiding
/// that build: Cargo produces every crate type a path dependency declares,
/// measured identically with `--target <host>`, without `--target`, and under a
/// plain `cargo build`. The dependency's link has to succeed, so the shim has to
/// stay off it.
///
/// `cargo rustc` passes its trailing arguments to the final compiler invocation
/// for the one selected target only, which is the scope the shim link line needs:
/// the guest binary (or libtest harness) and nothing else. Interposition is
/// unaffected — the shim's strong symbol definitions still land in that final
/// link exactly as before. See
/// `docs/bugs/shim-link-args-reach-dependency-cdylibs.md`.
fn native_package_link_args(
    object: &Path,
    staticlib: &Path,
    yield_object: Option<&Path>,
) -> Vec<OsString> {
    let mut args: Vec<OsString> = vec![
        OsString::from("-C"),
        link_arg(object),
        OsString::from("-C"),
        link_arg(staticlib),
    ];
    if let Some(yield_object) = yield_object {
        args.push(OsString::from("-C"));
        args.push(link_arg(yield_object));
    }
    push_platform_link_args(|arg| {
        args.push(OsString::from("-C"));
        args.push(OsString::from(arg));
    });
    args
}

#[cfg(unix)]
/// Does `policy` downgrade the denied import `escape` from a hard error to a
/// warning? Matches the raw import name and its underscore-stripped alias so an
/// operator can pass either `_os_unfair_lock_lock` or `os_unfair_lock_lock`.
fn policy_downgrades(policy: &UnsupportedPolicy, escape: &NativeEscape) -> bool {
    match policy {
        UnsupportedPolicy::Deny => false,
        UnsupportedPolicy::All => true,
        UnsupportedPolicy::Only(symbols) => {
            symbols.contains(&escape.symbol)
                || symbols.contains(escape.symbol.trim_start_matches('_'))
        }
    }
}

/// Pre-run default-deny gate for `native-run`. Audits the guest binary against
/// the baked shim control-plane vehicle plus any operator `--allow`, then
/// applies the `--allow-unsupported-symbols` policy. Returns the symbols that
/// were downgraded to warnings (empty when the binary audits clean), or a hard
/// error listing the symbols that remain unsupported.
/// Whether `binary` was built with `--yield-points`, detected by the hook's
/// embedded marker. This classification is load-bearing: it selects the
/// `+yieldpoints` compatibility-fingerprint suffix, so a false negative silently
/// records under — or cross-replays against — the wrong schedule policy. A read
/// failure is therefore NOT treated as "not instrumented" (a silent fail-open
/// that, under memory pressure, let an ENOMEM whole-file read misclassify an
/// instrumented binary as plain and bypass the fingerprint gate); it fails
/// closed with the underlying error. The scan streams the image in a bounded
/// window rather than allocating the whole (large, instrumented) binary, so the
/// detection itself never adds the memory pressure it must survive; a marker
/// straddling a chunk boundary is caught by carrying the trailing overlap.
fn binary_has_yield_points(binary: &Path) -> Result<bool, CliError> {
    use std::io::Read;

    let mut file = fs::File::open(binary).map_err(|error| {
        CliError(format!(
            "failed to open {} to detect yield-point instrumentation: {error}",
            binary.display()
        ))
    })?;
    let marker = PATINA_YIELD_MARKER;
    let overlap = marker.len() - 1;
    let mut window: Vec<u8> = Vec::with_capacity(overlap + 64 * 1024);
    let mut chunk = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut chunk).map_err(|error| {
            CliError(format!(
                "failed to read {} to detect yield-point instrumentation: {error}",
                binary.display()
            ))
        })?;
        if read == 0 {
            return Ok(false);
        }
        window.extend_from_slice(&chunk[..read]);
        if window.windows(marker.len()).any(|w| w == marker) {
            return Ok(true);
        }
        // Retain only the trailing `overlap` bytes so a marker split across the
        // next chunk boundary is still found without unbounded growth.
        if window.len() > overlap {
            window.drain(..window.len() - overlap);
        }
    }
}

/// Append the yield-point policy suffix to a base fingerprint when the binary is
/// yield-instrumented, leaving a plain binary's fingerprint untouched.
fn yield_point_fingerprint(base: &str, yield_points: bool) -> String {
    if yield_points {
        format!("{base}{PATINA_YIELD_FINGERPRINT_SUFFIX}")
    } else {
        base.to_string()
    }
}

/// The compatibility fingerprint for a native run: the base fingerprint, then
/// the yield-point policy suffix, the mounted-corpus suffix, and the
/// cooperative-SUT (buggify) suffix. Folding the filesystem image hash in means
/// a trace recorded against one corpus fails closed on replay against a
/// different one, exactly like a schedule-policy mismatch. The `+buggify`
/// suffix means a buggify trace never cross-replays with a non-buggify build,
/// even though the per-site knobs live in (reconciled) metadata.
///
/// `+buggify` is a *request* here; it is the one component the guest may retract.
/// A `--swarm` generation whose seed deselects the buggify class strips it again
/// inside the runtime, so the fingerprint recorded into the trace describes the
/// run that happened. A flag-free replay of such a trace reconstructs the
/// component set from the metadata ([`trace_has_buggify`],
/// [`native_policy_from_trace`]) and therefore recomputes the same string.
fn native_run_fingerprint(
    base: &str,
    yield_points: bool,
    image_hash: Option<&str>,
    buggify: bool,
    policy: &SchedulePolicyFingerprint,
) -> String {
    let mut fingerprint = yield_point_fingerprint(base, yield_points);
    if let Some(hash) = image_hash {
        fingerprint.push_str("+fsimg:");
        fingerprint.push_str(hash);
    }
    if buggify {
        fingerprint.push('+');
        fingerprint.push_str(patina_dst_runtime::FINGERPRINT_BUGGIFY);
    }
    // Exploration-policy suffixes, in a fixed order so the fingerprint is stable.
    // Each folds only when active, so a plain run fingerprints exactly as before
    // these components existed — mirroring the conditional `+buggify` suffix.
    if policy.pct {
        fingerprint.push_str("+pct");
    }
    if policy.starvation {
        fingerprint.push_str("+starve");
    }
    if policy.swarm {
        fingerprint.push_str("+swarm");
    }
    fingerprint
}

/// The exploration-policy fingerprint components of a native run. On a fresh run
/// these come from the CLI flags; on replay they are reconstructed from the trace
/// metadata (see [`native_policy_from_trace`]), so replay is self-contained and a
/// policy trace never cross-replays with a plain build.
#[derive(Clone, Copy, Debug, Default)]
struct SchedulePolicyFingerprint {
    pct: bool,
    starvation: bool,
    swarm: bool,
}

impl SchedulePolicyFingerprint {
    fn from_schedule(schedule: &NativeSchedule) -> Self {
        Self {
            pct: schedule.pct.is_some(),
            starvation: schedule.starve.is_some(),
            swarm: schedule.swarm,
        }
    }
}

/// Whether a recorded trace carries buggify metadata. Used at replay so the
/// `+buggify` fingerprint component is reconstructed from the trace itself,
/// keeping replay self-contained (the operator need not re-pass `--buggify`).
/// A read/parse failure reports `false`; the runtime surfaces any genuine error.
fn trace_has_buggify(path: &Path) -> bool {
    patina_dst_trace::TraceBundle::load(path)
        .map(|bundle| bundle.metadata.buggify.is_some())
        .unwrap_or(false)
}

/// Reconstruct the exploration-policy fingerprint components from a recorded
/// trace's metadata, so a flag-free replay recomputes the same fingerprint the
/// record run folded (`+pct`/`+starve`/`+swarm`) and a cross-policy replay fails
/// closed. A read/parse failure reports the inert default; the runtime surfaces
/// any genuine error.
fn native_policy_from_trace(path: &Path) -> SchedulePolicyFingerprint {
    patina_dst_trace::TraceBundle::load(path)
        .map(|bundle| SchedulePolicyFingerprint {
            pct: bundle
                .metadata
                .schedule_policy
                .as_ref()
                .is_some_and(|policy| policy.pct.is_some()),
            starvation: bundle
                .metadata
                .schedule_policy
                .as_ref()
                .is_some_and(|policy| policy.starvation.is_some()),
            swarm: bundle.metadata.swarm.is_some(),
        })
        .unwrap_or_default()
}

/// An encoded filesystem image held open in a temporary file, ready to be
/// duplicated onto the guest's inherited image descriptor, plus its content
/// hash for the run fingerprint.
struct FsImageCapture {
    file: fs::File,
    hash: String,
}

/// Capture `host_dir` into a deterministic [`FsImage`], encode it, and write the
/// bytes to a rewound anonymous temporary file the child reads over its
/// inherited image descriptor. The supervisor runs uninterposed, so reading the
/// host tree here is sound; the guest only ever sees the rebuilt image.
fn build_fs_image_file(host_dir: &Path) -> Result<FsImageCapture, CliError> {
    use std::io::{Seek, SeekFrom, Write};

    let root = fs::canonicalize(host_dir).map_err(|error| {
        CliError(format!(
            "failed to resolve --mount directory {}: {error}",
            host_dir.display()
        ))
    })?;
    if !root.is_dir() {
        return Err(CliError(format!(
            "--mount target is not a directory: {}",
            root.display()
        )));
    }
    let mut entries = Vec::new();
    collect_fs_entries(&root, "", &mut entries)?;
    let image = FsImage::new(entries);
    let bytes = image.encode();

    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let hash = hasher
        .finalize()
        .iter()
        .take(8)
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();

    let mut file = tempfile::tempfile().map_err(|error| {
        CliError(format!(
            "failed to create filesystem image scratch file: {error}"
        ))
    })?;
    file.write_all(&bytes)
        .map_err(|error| CliError(format!("failed to write filesystem image: {error}")))?;
    file.seek(SeekFrom::Start(0))
        .map_err(|error| CliError(format!("failed to rewind filesystem image: {error}")))?;
    Ok(FsImageCapture { file, hash })
}

/// Recursively collect `host_dir`'s contents as [`FsImageEntry`] values, mapping
/// the mount root to the guest root `/`. Symlinks are captured verbatim (their
/// target string, never followed), directories are recorded and descended, and
/// regular files carry their bytes. `FsImage::new` sorts the result, so the host
/// `readdir` order never leaks into the deterministic image.
fn collect_fs_entries(
    host_dir: &Path,
    guest_prefix: &str,
    entries: &mut Vec<FsImageEntry>,
) -> Result<(), CliError> {
    let listing = fs::read_dir(host_dir).map_err(|error| {
        CliError(format!(
            "failed to read --mount directory {}: {error}",
            host_dir.display()
        ))
    })?;
    for entry in listing {
        let entry = entry.map_err(|error| {
            CliError(format!(
                "failed to read entry under {}: {error}",
                host_dir.display()
            ))
        })?;
        let host_path = entry.path();
        let name = entry.file_name().into_string().map_err(|_| {
            CliError(format!(
                "--mount directory contains a non-UTF-8 name under {}",
                host_dir.display()
            ))
        })?;
        let guest_path = format!("{guest_prefix}/{name}");
        // Classify without following symlinks so a symlink stays a symlink in
        // the image, matching how a default recursive file-walk lstat's and skips it.
        let metadata = fs::symlink_metadata(&host_path).map_err(|error| {
            CliError(format!("failed to stat {}: {error}", host_path.display()))
        })?;
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            let target = fs::read_link(&host_path)
                .map_err(|error| {
                    CliError(format!(
                        "failed to read symlink {}: {error}",
                        host_path.display()
                    ))
                })?
                .into_os_string()
                .into_string()
                .map_err(|_| {
                    CliError(format!(
                        "symlink {} has a non-UTF-8 target",
                        host_path.display()
                    ))
                })?;
            entries.push(FsImageEntry::Symlink {
                path: guest_path,
                target,
            });
        } else if file_type.is_dir() {
            entries.push(FsImageEntry::Directory {
                path: guest_path.clone(),
            });
            collect_fs_entries(&host_path, &guest_path, entries)?;
        } else if file_type.is_file() {
            let contents = fs::read(&host_path).map_err(|error| {
                CliError(format!("failed to read {}: {error}", host_path.display()))
            })?;
            entries.push(FsImageEntry::File {
                path: guest_path,
                contents,
            });
        }
        // Anything else (sockets, devices, fifos) is skipped: a search corpus
        // has none, and the in-memory filesystem cannot model them.
    }
    Ok(())
}

/// Whether the running kernel supports syscall-user-dispatch, probed the same
/// way the shim's C layer probes it: `prctl(PR_SET_SYSCALL_USER_DISPATCH,
/// PR_SYS_DISPATCH_OFF, 0, 0, 0)` returns 0 on a SUD kernel and `-EINVAL` where
/// the feature is absent (arm64 <= 6.18, pre-5.11 x86). Runs in the supervisor
/// process, the same kernel the guest will run on. Non-Linux always returns
/// `false` (SUD is Linux-only), so the audit downgrade never fires off-Linux.
#[cfg(target_os = "linux")]
fn kernel_supports_sud() -> bool {
    // prctl SUD op numbers; 6.8 UAPI headers may predate the constants, so pin
    // the values the design verified against the v6.8 kernel source.
    const PR_SET_SYSCALL_USER_DISPATCH: std::ffi::c_int = 59;
    const PR_SYS_DISPATCH_OFF: std::ffi::c_ulong = 0;
    unsafe extern "C" {
        fn prctl(option: std::ffi::c_int, ...) -> std::ffi::c_int;
    }
    // SAFETY: the OFF form with all-zero args is a pure feature probe — it turns
    // dispatch off (a no-op when it was never on) and mutates no process state.
    let rc = unsafe {
        prctl(
            PR_SET_SYSCALL_USER_DISPATCH,
            PR_SYS_DISPATCH_OFF,
            0usize,
            0usize,
            0usize,
        )
    };
    rc == 0
}

#[cfg(not(target_os = "linux"))]
fn kernel_supports_sud() -> bool {
    false
}

/// Whether this platform can arm the shim's timestamp-counter trap, probed the
/// same way the shim's C layer probes it: `prctl(PR_GET_TSC, &mode)` returns 0
/// where `PR_SET_TSC` exists and `-EINVAL` where it does not. `PR_SET_TSC` is an
/// x86 facility, so the probe is compiled only for x86-64 Linux and every other
/// platform returns `false` — the rdtsc audit downgrade never fires off it.
/// Runs in the supervisor process, on the same kernel the guest will run on.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn platform_supports_tsc_trap() -> bool {
    const PR_GET_TSC: std::ffi::c_int = 25;
    unsafe extern "C" {
        fn prctl(option: std::ffi::c_int, ...) -> std::ffi::c_int;
    }
    let mut mode: std::ffi::c_int = 0;
    // SAFETY: PR_GET_TSC only reads the current per-thread setting into `mode`.
    let rc = unsafe {
        prctl(
            PR_GET_TSC,
            &mut mode as *mut std::ffi::c_int,
            0usize,
            0usize,
            0usize,
        )
    };
    rc == 0
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn platform_supports_tsc_trap() -> bool {
    false
}

/// The effective symbol allow set the native gate audits against: the shim's own
/// control-plane vehicle (auto-allowed on every `cargo patina build` binary —
/// `dlsym` on both platforms) plus the operator's explicit `--allow` symbols.
///
/// Constructed in exactly ONE place and called by BOTH the standalone `audit`
/// (`execute_native_audit`) and the pre-run `run` gate (`native_prerun_gate`), so
/// the static surface `audit` reports and the static surface `run` enforces can
/// never drift: a symbol one tolerates, the other tolerates too. This closes the
/// reported disparity where `audit` reported `_dlsym (dynamic-loading)` as denied
/// while `run` silently permitted it as the shim control-plane vehicle.
fn effective_native_allow(user_allow: &BTreeSet<String>) -> BTreeSet<String> {
    let mut allow = shim_control_plane_symbols();
    allow.extend(user_allow.iter().cloned());
    allow
}

/// Emit the non-blocking "fails later" note for the deny-trap-armed symbols a
/// shim-linked binary references. These symbols pass the import audit and the
/// pre-run gate (the shim strong-def drops them off the import table), but a call
/// aborts the run deterministically — a guarantee the import-table audit is blind
/// to by construction. Surfacing it up front at `audit` and `run` makes the
/// "fails later" contract visible before the guest is launched. Informational
/// only: stderr, never touches the exit code, and stays off stdout so a `--format
/// json` envelope is unaffected. A read/parse hiccup here must never fail the
/// caller's real operation, so it is swallowed (the note is best-effort).
fn emit_native_deny_trap_note(bytes: &[u8]) {
    let armed = match native_deny_trap_armed(bytes) {
        Ok(armed) if !armed.is_empty() => armed,
        _ => return,
    };
    let list = armed
        .iter()
        .map(|trap| format!("{} ({})", trap.symbol, trap.class))
        .collect::<Vec<_>>()
        .join(", ");
    eprintln!(
        "note: {} linked symbol(s) are deny-trap armed under patina (a call aborts \
deterministically): {list}",
        armed.len()
    );
}

/// Whether a *build* target has kernel syscall-user-dispatch, so a shim-linked
/// guest's raw inline syscalls are trapped at runtime rather than needing the
/// `--cfg rustix_use_libc` interposition workaround. x86_64 Linux has SUD since
/// 5.11; arm64 Linux does not yet (it needs the generic-entry kernels), so it
/// keeps the workaround. macOS never reaches here for rustix (it uses libc), so
/// its classification is moot. This is a build-time target decision (which cfg
/// to inject), distinct from the run-time [`kernel_supports_sud`] probe (whether
/// THIS kernel can trap). SUD-DESIGN.md §9.
fn target_has_sud(target: &str) -> bool {
    target.starts_with("x86_64") && target.contains("linux")
}

fn native_prerun_gate(
    binary: &Path,
    allow: &BTreeSet<String>,
    policy: &UnsupportedPolicy,
) -> Result<Vec<NativeEscape>, CliError> {
    let bytes = fs::read(binary).map_err(|error| {
        CliError(format!(
            "failed to read native program {} for the pre-run audit: {error}",
            binary.display()
        ))
    })?;
    let effective = effective_native_allow(allow);
    let denied = match NativeAudit::audit(&bytes, &effective) {
        Ok(_) => {
            // Clean import audit: the run proceeds. Surface the "fails later"
            // deny-trap note once, up front, before the guest is launched.
            emit_native_deny_trap_note(&bytes);
            return Ok(Vec::new());
        }
        Err(TargetError::UnsupportedNativeImports(denied)) => denied,
        // A binary we cannot even parse/format-check must never run.
        Err(other) => {
            return Err(CliError(format!(
                "refusing to run {}: {other}",
                binary.display()
            )));
        }
    };

    // syscall-user-dispatch downgrade (SUD-DESIGN.md §7.1): a `direct-syscall`
    // *instruction* finding is trapped into the deterministic runtime at run time
    // — not an escape — iff BOTH (a) the binary carries the shim's SUD dispatch
    // marker and (b) the live kernel probe says SUD is available. Both conditions
    // together: an old-shim binary (no marker) or a no-SUD kernel keeps today's
    // refusal. cpu-nondeterminism findings are never SUD-manageable (register
    // reads SUD cannot trap), so they never enter this split.
    let sud_ok = native_binary_has_sud_marker(&bytes).unwrap_or(false) && kernel_supports_sud();
    // The timestamp-counter trap downgrade, on the same two conditions: the
    // binary carries the trap dispatcher AND this platform can arm PR_SET_TSC.
    // Only rdtsc/rdtscp enter this split — rdrand/rdseed/CNTVCT share the
    // category but no mechanism traps them, so they stay in `remaining`.
    let tsc_ok =
        native_binary_has_tsc_marker(&bytes).unwrap_or(false) && platform_supports_tsc_trap();
    let (sud_instructions, rest): (Vec<_>, Vec<_>) = denied
        .into_iter()
        .partition(native_escape_is_sud_manageable);
    let (tsc_instructions, rest): (Vec<_>, Vec<_>) =
        rest.into_iter().partition(native_escape_is_tsc_manageable);
    let mut sud_managed = Vec::new();
    let mut remaining = rest;
    if tsc_ok {
        if let Some(note) =
            render_tsc_managed_note(&tsc_instructions, &binary.display().to_string())
        {
            eprintln!("{note}");
        }
    } else {
        // Not trappable here: fold back so the counter reads are blocked (with
        // the cpu-nondeterminism note below naming why), or force-runnable via
        // the operator's --allow-unsupported-symbols hatch.
        remaining.extend(tsc_instructions);
    }
    if sud_ok {
        sud_managed = sud_instructions;
    } else {
        // Not downgradable here: fold back so these raw-syscall sites are blocked
        // (with a SUD-specific hint below) — or force-runnable via the operator's
        // --allow-unsupported-symbols hatch, exactly as before SUD.
        remaining.extend(sud_instructions);
    }

    if !sud_managed.is_empty() {
        eprintln!(
            "patina: {} direct-syscall instruction site(s) in {} are SUD-managed: trapped into the \
deterministic runtime via syscall-user-dispatch (kernel SUD present, shim dispatcher linked). \
These are contained, not escapes — the run stays deterministic.",
            sud_managed.len(),
            binary.display()
        );
    }

    let (downgraded, blocked): (Vec<_>, Vec<_>) = remaining
        .into_iter()
        .partition(|escape| policy_downgrades(policy, escape));

    if !blocked.is_empty() {
        let has_raw_syscall = blocked.iter().any(native_escape_is_sud_manageable);
        let mut message = format!(
            "refusing to run {}: {} symbol(s) on the blocking/time/scheduling/effect surface are \
neither interposed by the deterministic runtime nor known-safe (default-deny). Interpose them, or \
pass --allow-unsupported-symbols <all|name,name,...> to run anyway with a warning:",
            binary.display(),
            blocked.len()
        );
        for escape in &blocked {
            message.push_str(&format!("\n  {}", native_escape_summary(escape)));
            push_native_escape_provenance_lines(&mut message, escape, "    ");
        }
        if has_raw_syscall {
            // Raw inline syscall instructions present but not SUD-manageable here:
            // either this kernel lacks syscall-user-dispatch (notably arm64, which
            // needs the generic-entry kernels) or the shim linked carries no SUD
            // dispatcher. Point at the two real fixes.
            message.push_str(
                "\nnote: the direct-syscall instruction site(s) above are raw inline syscalls. This \
kernel lacks syscall-user-dispatch (arm64 needs the generic-entry kernels; x86_64 has it since \
5.11), so they cannot be trapped here. Rebuild with `--cfg rustix_use_libc` (rustix's libc \
backend emits interposable imports instead), or run on an x86_64 SUD kernel where the shim traps \
them.",
            );
        }
        if let Some(note) = render_cpu_nondeterminism_note(&blocked) {
            // Instruction-class findings have no symbol name, so `--allow` can
            // never clear one; and only the timestamp counter is trappable at
            // all. Say both, rather than leaving the operator to infer them.
            message.push('\n');
            message.push_str(&note);
        }
        if blocked
            .iter()
            .any(|escape| escape.category == "macos-framework")
        {
            // CoreFoundation/Security framework calls: name the determinism problem
            // and the explicit allow path with its qualified-determinism caveat.
            message.push_str(
                "\nnote: the macos-framework symbol(s) above are macOS CoreFoundation/Security \
framework calls that the deterministic runtime does not interpose. The common dormant \
native-trust-root surface (rustls-native-certs: SecTrustSettingsCopy*, SecCertificateCopyData, the \
CF* helpers, kCFAllocator*) is now deny-trap interposed — a binary that merely LINKS it runs, and a \
genuine call aborts deterministically, so it never reaches this refusal. A macos-framework symbol \
reaching HERE is one the shim does not deny-trap (a non-enumerated framework symbol, or a prebuilt \
non-shim binary): the Security-framework subset reads the host keychain and system trust store — \
mutable host state that varies by machine and over time — so a run that reaches it is NOT \
reproducible. Compile the framework path out, or pass --allow-unsupported-symbols \
<all|name,name,...> to run anyway with a warning; determinism is then only qualified — the trust \
store the guest reads is whatever the host holds at run time.",
            );
        }
        if blocked
            .iter()
            .any(|escape| escape.category == "host-introspection")
        {
            // Mach/BSD/IOKit host-state reads: name the determinism problem and
            // the interpose-or-refuse posture (these must never be allowlisted).
            message.push_str(
                "\nnote: the host-introspection symbol(s) above read host CPU/memory/hardware/process \
state — nondeterministic across hosts and runs; interpose-or-refuse, never allowlist. The dormant \
hardware-inventory surface (sysinfo: host_statistics64/host_processor_info, the IOKit registry \
walk, mach_host_self, proc_*, vm_deallocate) is now deny-trap interposed — a binary that merely \
LINKS it runs, and a genuine call aborts deterministically. A host-introspection symbol reaching \
HERE is a live-path member a normal startup actually reaches (sysctl/sysctlbyname, getrusage, \
task_info) that stays refused pending a deterministic interposer, or a prebuilt non-shim binary. A \
run that reaches one is not reproducible, so it is refused; pass --allow-unsupported-symbols \
<all|name,name,...> to run anyway with a warning, but determinism is then only qualified.",
            );
        }
        return Err(CliError(message));
    }

    if !downgraded.is_empty() {
        eprintln!(
            "patina: WARNING: running {} with {} UNSUPPORTED symbol(s) downgraded from error by \
--allow-unsupported-symbols:",
            binary.display(),
            downgraded.len()
        );
        for escape in &downgraded {
            eprintln!("patina:   {}", native_escape_summary(escape));
            for provenance in &escape.provenance {
                eprintln!("patina:     {}", provenance.label());
            }
        }
        eprintln!(
            "patina: these host symbols are NOT interposed by the deterministic runtime; if the \
guest reaches them at run time it can block, read host time, or otherwise escape the scheduler. \
This run's determinism is NOT guaranteed and any \"deterministic\" claim on it is qualified."
        );
    }

    // The run proceeds (clean, or with downgraded symbols). Surface the "fails
    // later" deny-trap note once, up front, before the guest is launched.
    emit_native_deny_trap_note(&bytes);
    Ok(downgraded)
}

struct NativeTraceSink {
    final_path: PathBuf,
    temp_path: PathBuf,
    file: Option<fs::File>,
}

impl NativeTraceSink {
    fn create(final_path: &Path) -> Result<Self, CliError> {
        if final_path.exists() && TraceBundle::load(final_path).is_err() {
            fs::remove_file(final_path).map_err(|error| {
                CliError(format!(
                    "failed to remove incomplete existing trace {} before recording: {error}",
                    final_path.display()
                ))
            })?;
        }
        if let Some(parent) = final_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent).map_err(|error| {
                CliError(format!(
                    "failed to create trace directory {}: {error}",
                    parent.display()
                ))
            })?;
        }
        let temp_path = native_trace_temp_path(final_path);
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
            .map_err(|error| {
                CliError(format!(
                    "failed to create temporary trace {}: {error}",
                    temp_path.display()
                ))
            })?;
        Ok(Self {
            final_path: final_path.to_path_buf(),
            temp_path,
            file: Some(file),
        })
    }

    #[cfg(unix)]
    fn raw_fd(&self) -> std::os::unix::io::RawFd {
        use std::os::unix::io::AsRawFd;

        self.file
            .as_ref()
            .expect("trace sink is live until commit")
            .as_raw_fd()
    }

    fn commit(mut self) -> Result<PathBuf, String> {
        drop(self.file.take());
        if let Err(error) = TraceBundle::load(&self.temp_path) {
            let _ = fs::remove_file(&self.temp_path);
            return Err(error.to_string());
        }
        fs::rename(&self.temp_path, &self.final_path).map_err(|error| {
            let _ = fs::remove_file(&self.temp_path);
            format!(
                "failed to atomically rename temporary trace {} to {}: {error}",
                self.temp_path.display(),
                self.final_path.display()
            )
        })?;
        Ok(self.final_path.clone())
    }
}

impl Drop for NativeTraceSink {
    fn drop(&mut self) {
        if self.file.is_some() {
            let _ = fs::remove_file(&self.temp_path);
        }
    }
}

fn native_trace_temp_path(path: &Path) -> PathBuf {
    let counter = NATIVE_TRACE_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut name = OsString::from(".");
    name.push(path.file_name().unwrap_or_else(|| OsStr::new("trace")));
    name.push(format!(".tmp.{}.{}", std::process::id(), counter));
    path.with_file_name(name)
}

fn remove_native_trace_scratch(trace_path: &Path) {
    let Some(parent) = trace_path.parent() else {
        return;
    };
    let Some(file_name) = trace_path.file_name() else {
        return;
    };
    let mut prefix = OsString::from(".");
    prefix.push(file_name);
    prefix.push(".tmp.");
    let Ok(entries) = fs::read_dir(parent) else {
        return;
    };
    let prefix = prefix.to_string_lossy().into_owned();
    for entry in entries.flatten() {
        if entry.file_name().to_string_lossy().starts_with(&prefix) {
            let _ = fs::remove_file(entry.path());
        }
    }
}

/// Record the downgraded-symbol caveat next to a recorded trace so a later
/// reader of the artifact sees that the run was not an unconditional
/// determinism claim.
fn write_unsupported_sidecar(trace: &Path, downgraded: &[NativeEscape]) -> Result<(), CliError> {
    if downgraded.is_empty() {
        return Ok(());
    }
    let sidecar = {
        let mut name = trace.as_os_str().to_owned();
        name.push(".unsupported-symbols");
        PathBuf::from(name)
    };
    let mut contents = String::from(
        "# This trace was recorded with --allow-unsupported-symbols. The symbols\n\
# below are NOT interposed by the deterministic runtime; the run's determinism\n\
# is qualified. Symbol (category), followed by provenance when recoverable:\n",
    );
    for escape in downgraded {
        contents.push_str(&format!("{}\n", native_escape_summary(escape)));
        push_native_escape_provenance_lines(&mut contents, escape, "  ");
    }
    fs::write(&sidecar, contents).map_err(|error| {
        CliError(format!(
            "failed to write unsupported-symbols sidecar {}: {error}",
            sidecar.display()
        ))
    })
}

/// Encode the guest program arguments (`argv[1..]`) as the JSON string array the
/// runtime records into the trace metadata. Recording requires UTF-8 arguments
/// (the trace bundle is UTF-8 JSON); a non-UTF-8 argument fails closed here,
/// before the guest runs, rather than corrupting the trace.
fn encode_guest_argv(program_args: &[OsString]) -> Result<String, CliError> {
    let mut argv = Vec::with_capacity(program_args.len());
    for argument in program_args {
        let text = argument.to_str().ok_or_else(|| {
            CliError(format!(
                "cannot record the guest argument {argument:?}: --record requires UTF-8 guest \
arguments so they round-trip through the trace metadata"
            ))
        })?;
        argv.push(text.to_owned());
    }
    serde_json::to_string(&argv)
        .map_err(|error| CliError(format!("failed to encode guest arguments: {error}")))
}

/// Reconcile the guest arguments for a replay against the trace's recorded argv.
///
/// The trace records the `argv[1..]` it ran with, so a bare replay (no `--`
/// section) reproduces them and the operator need not re-pass the arguments —
/// fixing the incident where a divergent default argv caused a confusing mid-run
/// operation mismatch. If a `--` section IS supplied it must match the recording
/// byte-for-byte, otherwise the replay is refused UPFRONT naming both the
/// recorded and the passed arguments (a parse-time error, never a mid-run
/// divergence). A trace recorded before argv capture carries no recorded argv, so
/// the arguments are taken from the command line exactly as before — no new error
/// for old traces.
fn reconcile_replay_argv(trace: &Path, passed: &[OsString]) -> Result<Vec<OsString>, CliError> {
    let bundle = TraceBundle::load(trace).map_err(|error| {
        CliError(format!(
            "failed to read trace {} for guest-argument restoration: {error}",
            trace.display()
        ))
    })?;
    let Some(recorded) = bundle.metadata.guest_argv else {
        // Pre-argv trace: honor the historical contract (arguments from the
        // command line, and their absence behaves exactly as today).
        return Ok(passed.to_vec());
    };
    let recorded_os: Vec<OsString> = recorded.iter().map(OsString::from).collect();
    if passed.is_empty() || passed == recorded_os.as_slice() {
        Ok(recorded_os)
    } else {
        Err(CliError(format!(
            "replay guest-argument mismatch for {}: the trace recorded {recorded:?}, but the \
command line passed {passed:?} after `--`. Omit the `--` section to replay the recorded arguments, \
or pass them byte-for-byte identically.",
            trace.display()
        )))
    }
}

#[cfg(unix)]
struct InheritedFdGuard {
    saved: Vec<(i32, i32)>,
}

#[cfg(unix)]
impl InheritedFdGuard {
    fn clear_cloexec(fds: &[i32]) -> Result<Self, CliError> {
        let mut saved = Vec::with_capacity(fds.len());
        for &fd in fds {
            // SAFETY: `fd` is an open descriptor owned by the supervisor.
            let flags = unsafe { fcntl(fd, F_GETFD, 0) };
            if flags < 0 {
                return Err(CliError(format!(
                    "failed to inspect inherited descriptor {fd}: {}",
                    io::Error::last_os_error()
                )));
            }
            saved.push((fd, flags));
            if flags & FD_CLOEXEC != 0 {
                // SAFETY: `F_SETFD` only updates descriptor flags on this fd.
                if unsafe { fcntl(fd, F_SETFD, flags & !FD_CLOEXEC) } < 0 {
                    return Err(CliError(format!(
                        "failed to make descriptor {fd} inheritable: {}",
                        io::Error::last_os_error()
                    )));
                }
                let cleared = unsafe { fcntl(fd, F_GETFD, 0) };
                if cleared < 0 || cleared & FD_CLOEXEC != 0 {
                    return Err(CliError(format!(
                        "failed to clear close-on-exec for descriptor {fd}: {}",
                        if cleared < 0 {
                            io::Error::last_os_error().to_string()
                        } else {
                            format!("descriptor flags are still {cleared}")
                        }
                    )));
                }
            }
        }
        Ok(Self { saved })
    }

    fn restore(mut self) -> Result<(), CliError> {
        for (fd, flags) in self.saved.drain(..) {
            // SAFETY: Restore the exact descriptor flags saved before spawn.
            if unsafe { fcntl(fd, F_SETFD, flags) } < 0 {
                return Err(CliError(format!(
                    "failed to restore descriptor {fd} flags: {}",
                    io::Error::last_os_error()
                )));
            }
        }
        Ok(())
    }
}

#[cfg(unix)]
impl Drop for InheritedFdGuard {
    fn drop(&mut self) {
        for (fd, flags) in self.saved.drain(..) {
            // Best-effort cleanup for early returns. Callers use `restore()` on
            // the normal path so restore errors can be reported explicitly.
            let _ = unsafe { fcntl(fd, F_SETFD, flags) };
        }
    }
}

#[cfg(unix)]
fn spawn_native_child(
    command: &mut Command,
    binary: &Path,
    inherited_fds: &[i32],
) -> Result<(std::process::Child, InheritedFdGuard), CliError> {
    // Return the guard to the caller instead of restoring immediately: the
    // descriptor-inheritance contract is simple and conservative if the fds stay
    // inheritable for the whole child lifetime, and this supervisor process does
    // not spawn unrelated children while waiting for the guest.
    let guard = InheritedFdGuard::clear_cloexec(inherited_fds)?;
    let child = command.spawn().map_err(|error| {
        CliError(format!(
            "failed to run native program {}: {error}",
            binary.display()
        ))
    })?;
    Ok((child, guard))
}

#[cfg(unix)]
fn native_child_status(status: ExitStatus) -> (i32, Option<i32>) {
    use std::os::unix::process::ExitStatusExt;

    if let Some(code) = status.code() {
        (code, None)
    } else if let Some(signal) = status.signal() {
        (128 + signal, Some(signal))
    } else {
        (2, None)
    }
}

#[cfg(unix)]
fn append_native_infra_marker(
    captured: &mut output::Captured,
    signal: Option<i32>,
    trace_error: Option<(&Path, &str)>,
) {
    if signal.is_none() && trace_error.is_none() {
        return;
    }
    let mut line = String::from("PATINA_INFRA native_run");
    if let Some(signal) = signal {
        line.push_str(&format!(" signal={signal}"));
    }
    if let Some((path, reason)) = trace_error {
        line.push_str(&format!(
            " trace=incomplete trace_path={:?} reason={:?}",
            path.display().to_string(),
            reason
        ));
    }
    line.push('\n');
    if captured.captured {
        captured.stderr.extend_from_slice(line.as_bytes());
    } else {
        eprint!("{line}");
    }
}

#[cfg(unix)]
fn execute_native_run(invocation: NativeRunInvocation) -> Result<i32, CliError> {
    use std::os::unix::io::AsRawFd;
    use std::os::unix::process::CommandExt;

    // Source-first: an artifact runs as-is; a source/package is built on the fly
    // first (`resolved` holds the build workspace alive for the whole run). For
    // replay, the rebuilt binary is judged against the trace by the fingerprint
    // and operation-mismatch machinery below — no special-casing.
    let resolved = resolve_artifact(invocation.binary.clone())?;
    let binary = fs::canonicalize(&resolved.path).map_err(|error| {
        CliError(format!(
            "failed to resolve native program {}: {error}",
            resolved.path.display()
        ))
    })?;

    // Pre-run default-deny gate. Before the guest executes, enumerate every
    // externally-resolved symbol it can reach and hard-error, listing names, if
    // any on the blocking/time/scheduling/effect surface is neither interposed
    // nor known-safe. This is what makes a missed interposer (the class the
    // macOS dispatch-semaphore Parker escape belonged to) structurally
    // impossible to run silently: an unmodeled blocking symbol is an import the
    // shim does not define, so it surfaces here as a denial rather than blocking
    // a host thread outside the scheduler. `--allow-unsupported-symbols`
    // downgrades matching denials to a loud warning for programs that carry
    // unsupported surface the scenario never reaches.
    let downgraded = native_prerun_gate(&binary, &invocation.allow, &invocation.allow_unsupported)?;

    // A binary built with `--yield-points` schedules under a different (denser)
    // policy, so its recorded traces must not cross-replay with a plain binary.
    // Detect the linked hook's marker and fold it into the compatibility
    // fingerprint; the same binary is inspected on record and replay, so the
    // suffix is applied consistently and a policy mismatch is rejected.
    let yield_points = binary_has_yield_points(&binary)?;
    if invocation.coverage_out.is_some() && !yield_points {
        return Err(CliError::usage(
            "--coverage-out requires a native binary built with `cargo patina build --yield-points`; coverage rides the yield-point SanitizerCoverage hook",
        ));
    }

    // Starvation intervals reorder real thread execution adversarially. A guest
    // whose synchronization is INTERPOSED (mutex/condvar/futex) is always safe —
    // every wait is a scheduling boundary the aging guarantee can act on. But a
    // guest with an *invisible atomic spinlock* (e.g. std's queue `RwLock`/`Parker`
    // fast path) held across an interposed boundary can wedge: the adversarial
    // deferral schedules the spinner while the lock holder is starved, and the
    // spinner's atomics-only loop offers no boundary for aging to force the holder
    // — the exact cooperative-scheduling limitation the vacuous-schedule warning
    // flags. `--yield-points` closes it (loop backedges become boundaries), so
    // starvation there is always liveness-safe. Warn loudly when starvation is
    // enabled on a non-instrumented binary rather than risk a silent hang.
    if invocation.schedule.starve.is_some() && !yield_points {
        eprintln!(
            "PATINA WARNING: starvation intervals (--starve) are enabled on a binary that was NOT \
built with `--yield-points`. Starvation is liveness-safe for guests whose synchronization is \
interposed (mutex/condvar/futex), but a guest with an invisible atomic spinlock (e.g. std's queue \
RwLock/Parker fast path) held across a boundary can WEDGE under adversarial deferral — the same \
atomics-only window the vacuous-schedule diagnostic flags as unreachable. Rebuild with \
`cargo patina build --yield-points` to make those windows schedulable so starvation stays \
liveness-safe."
        );
    }

    // Capture the mounted host directory into a deterministic filesystem image.
    // The supervisor is not interposed, so it may read the host tree freely; the
    // encoded image travels to the guest over an inherited descriptor and the
    // shim rebuilds it, so the fully interposed guest never touches the host
    // filesystem. The image hash folds into the fingerprint below so a replay
    // against a different corpus is rejected exactly like any incompatibility.
    let image_file = match &invocation.mount {
        Some(host_dir) => Some(build_fs_image_file(host_dir)?),
        None => None,
    };
    let image_hash = image_file.as_ref().map(|image| image.hash.clone());
    let coverage_file = match &invocation.coverage_out {
        Some(path) => Some(fs::File::create(path).map_err(|error| {
            CliError(format!(
                "failed to create coverage map {}: {error}",
                path.display()
            ))
        })?),
        None => None,
    };
    // The structured run-facts channel. A native guest is FULLY interposed, so
    // the document cannot travel over a path — it rides an inherited host
    // descriptor the shim writes through its private host aliases, exactly like
    // the trace bundle and the coverage map.
    let facts_file = if output::facts_active() {
        Some(tempfile::tempfile().map_err(|error| {
            CliError(format!("failed to create the run-facts channel: {error}"))
        })?)
    } else {
        None
    };

    // Restore the guest arguments for a replay from the trace's recorded argv, so
    // a bare replay reproduces them without the `--` section being re-passed; a
    // mismatched `--` section is refused upfront (see `reconcile_replay_argv`).
    // For seeded/record runs the arguments are the ones supplied on the command
    // line, unchanged.
    let program_args = match &invocation.mode {
        NativeRunMode::Replay { path, .. } => {
            reconcile_replay_argv(path, &invocation.program_args)?
        }
        NativeRunMode::Seeded { .. } | NativeRunMode::Record { .. } => {
            invocation.program_args.clone()
        }
    };

    let mut command = Command::new(&binary);
    // Stamp a fixed, machine-independent `argv[0]`: the guest is exec'd from an
    // absolute host path, but that path must not leak into the guest's
    // `std::env::args()` as a non-portable string. The guest's own arguments live
    // in `argv[1..]`.
    command
        .args(&program_args)
        .arg0(NATIVE_GUEST_ARGV0)
        .env_clear();
    // A `patina-dst-harness` binary (usage mode 2) defers runtime installation to
    // its `run`/`run_with` call: tell the packaged constructor to capture/scrub the
    // control plane and register finalization but NOT install the runtime. Applies
    // uniformly to seeded/record and replay so the harness owns installation on
    // every path. An interposed effect before the harness installs fails closed.
    if invocation.harness {
        command.env(ENV_DEFER_INIT, "1");
    }
    if let Some(image) = &image_file {
        command.env(ENV_FS_IMAGE_FD, image.file.as_raw_fd().to_string());
    }
    if let Some(file) = &coverage_file {
        command.env(ENV_COVERAGE_FD, file.as_raw_fd().to_string());
    }
    if let Some(file) = &facts_file {
        command.env(
            patina_dst_runtime::ENV_FACTS_FD,
            file.as_raw_fd().to_string(),
        );
    }
    // The guest's environment is cleared above, so every end-of-run report knob
    // the operator set has to be forwarded explicitly or it never reaches the
    // guest at all. Driven by `Report::ALL` rather than a hand-kept list, so a
    // report added to the runtime is silenceable on native the day it exists —
    // only `PATINA_COVERAGE_REPORT` used to be carried, which is why every other
    // knob read as inert on this family.
    for report in patina_dst_runtime::Report::ALL {
        if let Some(value) = env::var_os(report.env()) {
            command.env(report.env(), value);
        }
    }
    if !invocation.environment.is_empty() {
        let encoded = serde_json::to_string(&invocation.environment).map_err(|error| {
            CliError(format!(
                "failed to encode native guest environment: {error}"
            ))
        })?;
        command.env(ENV_GUEST_ENV, encoded);
    }
    // The boundary-operation budget is a supervisor-side bound, not recorded run
    // semantics, so it is supplied per invocation on every family alike.
    if let Some(budget) = invocation.step_budget {
        command.env(ENV_STEP_BUDGET, budget.to_string());
    }
    // Forward whatever fault knobs the operator supplied to the guest, scrubbing
    // every knob's variable first so an ambient value cannot leak into a run that
    // set none. On record and seeded runs these configure the faults and are
    // recorded into the trace metadata. Native replay does not accept semantic
    // re-supply; the trace's recorded configuration is authoritative and restored
    // by the runtime.
    for variable in knob_env_vars() {
        command.env_remove(variable);
    }
    for (name, value) in knob_env_pairs(&invocation.knobs)? {
        command.env(name, value);
    }
    // Forward the cooperative-SUT (buggify) knobs. Presence of `PATINA_BUGGIFY`
    // enables buggify; its value (if any) is the firing per-mille. Like the fault
    // knobs, these are recorded into trace metadata and restored from the trace on
    // native replay, rather than re-supplied as semantic flags.
    if let Some(buggify) = &invocation.buggify {
        command.env(ENV_BUGGIFY, buggify.fire_permille.as_deref().unwrap_or(""));
        if let Some(value) = &buggify.activation_permille {
            command.env(ENV_BUGGIFY_ACTIVATION, value);
        }
        if let Some(value) = &buggify.cutoff_nanos {
            command.env(ENV_BUGGIFY_CUTOFF, value);
        }
        if buggify.after_setup {
            command.env(ENV_BUGGIFY_AFTER_SETUP, "1");
        }
    }
    // Forward the exploration scheduling-policy (PCT / starvation) and swarm
    // knobs through the same control plane. Recorded into the trace metadata and
    // restored from the trace on native replay; the fingerprint suffix rejects a
    // cross-policy replay.
    for (name, value) in schedule_env_pairs(&invocation.schedule) {
        command.env(name, value);
    }
    // Forward the liveness-watchdog knobs through the same control plane. The
    // watchdog is schedule-invariant: recorded (informational) but not
    // fingerprinted, so a watchdog trace replays against any build.
    for (name, value) in liveness_env_pairs(&invocation.liveness) {
        command.env(name, value);
    }

    // Hold the trace transport file open until the child exits so the inherited
    // descriptor named by `PATINA_TRACE_FD` remains valid. Record mode writes to
    // a sibling temporary file first; the supervisor validates and renames it to
    // the requested path only after the guest reaches trace finalization.
    let mut replay_trace_file: Option<fs::File> = None;
    let trace_sink = match &invocation.mode {
        NativeRunMode::Seeded { seed } => {
            command
                .env(ENV_MODE, "seeded")
                .env(ENV_SEED, seed.to_string());
            None
        }
        NativeRunMode::Record {
            seed,
            path,
            fingerprint,
        } => {
            let sink = NativeTraceSink::create(path)?;
            command
                .env(ENV_MODE, "record")
                .env(ENV_SEED, seed.to_string())
                .env(
                    ENV_FINGERPRINT,
                    native_run_fingerprint(
                        fingerprint,
                        yield_points,
                        image_hash.as_deref(),
                        invocation.buggify.is_some(),
                        &SchedulePolicyFingerprint::from_schedule(&invocation.schedule),
                    ),
                )
                .env(ENV_TRACE_FD, sink.raw_fd().to_string())
                // Record the guest arguments into the trace metadata so a later
                // `replay` restores them without the `--` section being
                // re-passed. Always forwarded (even when empty) so a
                // zero-argument run records `[]` — distinct from an old trace's
                // absent field, so replaying it reproduces zero arguments rather
                // than inheriting whatever the command line supplies.
                .env(ENV_GUEST_ARGV, encode_guest_argv(&program_args)?);
            Some(sink)
        }
        NativeRunMode::Replay { path, fingerprint } => {
            let file = fs::File::open(path).map_err(|error| {
                CliError(format!("failed to open trace {}: {error}", path.display()))
            })?;
            // Reconstruct the `+buggify` and `+pct`/`+starve`/`+swarm` fingerprint
            // components from the trace so replay is self-contained; a policy
            // trace replayed against a plain build still fails closed on the
            // fingerprint.
            let buggify = invocation.buggify.is_some() || trace_has_buggify(path);
            let policy = native_policy_from_trace(path);
            command
                .env(ENV_MODE, "replay")
                .env(
                    ENV_FINGERPRINT,
                    native_run_fingerprint(
                        fingerprint,
                        yield_points,
                        image_hash.as_deref(),
                        buggify,
                        &policy,
                    ),
                )
                .env(ENV_TRACE_FD, file.as_raw_fd().to_string());
            replay_trace_file = Some(file);
            None
        }
    };

    // The shim reads inherited host descriptors named by `PATINA_TRACE_FD` and
    // `PATINA_FS_IMAGE_FD`. Make only those already-open descriptors inheritable
    // for the child, then restore the supervisor's close-on-exec state after the
    // child exits.
    let mut inherited_fds: Vec<std::os::unix::io::RawFd> = Vec::new();
    if let Some(sink) = &trace_sink {
        inherited_fds.push(sink.raw_fd());
    }
    if let Some(file) = &replay_trace_file {
        inherited_fds.push(file.as_raw_fd());
    }
    if let Some(image) = &image_file {
        inherited_fds.push(image.file.as_raw_fd());
    }
    if let Some(file) = &coverage_file {
        inherited_fds.push(file.as_raw_fd());
    }
    if let Some(file) = &facts_file {
        inherited_fds.push(file.as_raw_fd());
    }

    // Starvation stall backstop (diagnostic, NOT a liveness guarantee; armed only
    // when starvation is enabled, so it has zero effect on any other mode). The
    // scheduler's aging bounds starvation for interposed synchronization, but a
    // guest spinning inside a std-internal atomic critical section — which is NOT
    // yield-point instrumented, so cooperative scheduling has no edge to preempt
    // it while the lock holder is starved — can livelock. A hung generation
    // silently eats a sweep slot, so the supervisor (uninterposed, real
    // wall-clock) converts an already-hung run into a LOUD named fatal with a
    // distinct nonzero exit so sweeps classify STARVATION_STALL instead of
    // hanging. The threshold is deliberately generous (default 60 real seconds,
    // `PATINA_STARVATION_STALL_SECS` override) so it is unreachable on any healthy
    // run; it never touches the recorded operation stream of a run that completes.
    // The kill-able wait loop mirrors `output::execute_command`'s capture
    // semantics (piped when the JSON envelope / render wants guest output,
    // inherited otherwise) so `--starve` composes with `--format json`.
    let mut captured = if invocation.schedule.starve.is_some() {
        let stall_secs: u64 = std::env::var("PATINA_STARVATION_STALL_SECS")
            .ok()
            .and_then(|value| value.trim().parse().ok())
            .filter(|value| *value > 0)
            .unwrap_or(60);
        let capture = output::capture_active();
        if capture {
            command.stdout(Stdio::piped()).stderr(Stdio::piped());
        }
        let (mut child, inherited_guard) =
            spawn_native_child(&mut command, &binary, &inherited_fds)?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(stall_secs);
        loop {
            match child.try_wait() {
                Ok(Some(_status)) => break,
                Ok(None) => {
                    if std::time::Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        eprintln!(
                            "patina: starvation stall — no scheduler progress in {stall_secs}s under \
--starve; the guest is likely spinning inside an uninstrumented atomic critical section (std is not \
yield-point instrumented, so cooperative scheduling cannot preempt a spinner while the lock holder \
is starved). This is the documented starvation limitation, not a liveness guarantee — see \
IMPLEMENTATION.md \"Slice 7: exploration tier\". Killed with a nonzero exit."
                        );
                        inherited_guard.restore()?;
                        drop(trace_sink);
                        drop(replay_trace_file);
                        drop(image_file);
                        drop(coverage_file);
                        drop(facts_file);
                        return Ok(STARVATION_STALL_EXIT);
                    }
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                Err(error) => {
                    return Err(CliError(format!(
                        "failed while waiting on native program {}: {error}",
                        binary.display()
                    )));
                }
            }
        }
        let output = child.wait_with_output().map_err(|error| {
            CliError(format!(
                "failed while waiting on native program {}: {error}",
                binary.display()
            ))
        })?;
        inherited_guard.restore()?;
        let (exit_code, signal) = native_child_status(output.status);
        output::Captured {
            exit_code,
            stdout: output.stdout,
            stderr: output.stderr,
            captured: capture,
            signal,
        }
    } else if output::capture_active() {
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
        let (child, inherited_guard) = spawn_native_child(&mut command, &binary, &inherited_fds)?;
        let output = child.wait_with_output().map_err(|error| {
            CliError(format!(
                "failed while waiting on native program {}: {error}",
                binary.display()
            ))
        })?;
        inherited_guard.restore()?;
        let (exit_code, signal) = native_child_status(output.status);
        output::Captured {
            exit_code,
            stdout: output.stdout,
            stderr: output.stderr,
            captured: true,
            signal,
        }
    } else {
        let (mut child, inherited_guard) =
            spawn_native_child(&mut command, &binary, &inherited_fds)?;
        let status = child.wait().map_err(|error| {
            CliError(format!(
                "failed while waiting on native program {}: {error}",
                binary.display()
            ))
        })?;
        inherited_guard.restore()?;
        let (exit_code, signal) = native_child_status(status);
        output::Captured {
            exit_code,
            stdout: Vec::new(),
            stderr: Vec::new(),
            captured: false,
            signal,
        }
    };
    drop(replay_trace_file);
    let mut committed_record_trace = None;
    let mut trace_finalization_error: Option<(PathBuf, String)> = None;
    if let Some(sink) = trace_sink {
        match sink.commit() {
            Ok(path) => {
                if let Err(error) = write_unsupported_sidecar(&path, &downgraded) {
                    let _ = fs::remove_file(&path);
                    return Err(error);
                }
                committed_record_trace = Some(path);
            }
            Err(reason) => {
                let path = match &invocation.mode {
                    NativeRunMode::Record { path, .. } => path.clone(),
                    NativeRunMode::Seeded { .. } | NativeRunMode::Replay { .. } => PathBuf::new(),
                };
                if captured.exit_code == 0 {
                    captured.exit_code = 2;
                }
                trace_finalization_error = Some((path, reason));
            }
        }
    }
    let native_signal = captured.signal;
    append_native_infra_marker(
        &mut captured,
        native_signal,
        trace_finalization_error
            .as_ref()
            .map(|(path, reason)| (path.as_path(), reason.as_str())),
    );
    drop(image_file);
    drop(coverage_file);
    // Read the facts document back off the inherited descriptor. The child wrote
    // through the same open file description, so the offset is at the end —
    // rewind before reading.
    let facts = match facts_file {
        Some(mut file) => {
            use std::io::{Read, Seek};
            file.rewind().map_err(|error| {
                CliError(format!("failed to rewind the run-facts channel: {error}"))
            })?;
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes).map_err(|error| {
                CliError(format!("failed to read the run-facts channel: {error}"))
            })?;
            output::parse_facts(&bytes)?
        }
        None => None,
    };
    let coverage = if let Some(path) = &invocation.coverage_out {
        let len = fs::metadata(path)
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        if captured.exit_code == 0 || len > 0 {
            Some(coverage::coverage_summary_from_map(path)?)
        } else {
            None
        }
    } else {
        None
    };
    let (trace_path, seed) = match &invocation.mode {
        NativeRunMode::Seeded { seed } => (None, Some(*seed)),
        NativeRunMode::Record { seed, .. } => (committed_record_trace.clone(), Some(*seed)),
        NativeRunMode::Replay { path, .. } => (Some(path.clone()), None),
    };
    let fingerprint = match &invocation.mode {
        NativeRunMode::Seeded { .. } => None,
        NativeRunMode::Record { fingerprint, .. } | NativeRunMode::Replay { fingerprint, .. } => {
            Some(fingerprint.clone())
        }
    };
    let artifact = resolved.display.display().to_string();
    let exit = output::finalize_run(
        output::RunReport {
            verb: "run",
            family: "native",
            artifact: &artifact,
            trace_path,
            timeline: "main",
            fingerprint,
            seed,
            coverage: coverage.clone(),
            depth: None,
            facts,
        },
        captured,
    )?;
    if let Some(coverage) = coverage {
        if !output::options().is_json() {
            if let Some(path) = coverage.map_path {
                eprintln!(
                    "PATINA_COVERAGE map={} edges={}/{} covered_permille={}",
                    path.display(),
                    coverage.edges_covered,
                    coverage.edges_total,
                    coverage.covered_permille,
                );
            }
        }
    }
    Ok(exit)
}

/// Distinct exit code the supervisor returns when the starvation stall backstop
/// kills a hung `--starve` run, so a sweep can classify `STARVATION_STALL` rather
/// than treat the run as an ordinary crash.
const STARVATION_STALL_EXIT: i32 = 111;

#[cfg(not(unix))]
fn execute_native_run(_invocation: NativeRunInvocation) -> Result<i32, CliError> {
    Err(CliError(
        "native-run requires a Unix host for the PATINA_TRACE_FD supervisor channel".into(),
    ))
}

fn execute(invocation: Invocation) -> Result<i32, CliError> {
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
mod tests {
    use super::*;

    #[test]
    fn a_relative_rustc_probes_as_one_program_from_both_directories() {
        let from = Path::new("/work/guest");
        // A bare name is PATH-resolved, which does not vary by directory.
        assert_eq!(anchored_rustc(None, from), OsString::from("rustc"));
        assert_eq!(
            anchored_rustc(Some("rustc".into()), from),
            OsString::from("rustc")
        );
        // An absolute path already names one program.
        assert_eq!(
            anchored_rustc(Some("/opt/rust/bin/rustc".into()), from),
            OsString::from("/opt/rust/bin/rustc")
        );
        // A relative path with a directory component would otherwise resolve
        // against each probe's own working directory — two different programs,
        // reported as a toolchain split that does not exist.
        assert_eq!(
            anchored_rustc(Some("./tools/rustc".into()), from),
            OsString::from("/work/guest/./tools/rustc")
        );
        assert_eq!(
            anchored_rustc(Some("tools/rustc".into()), from),
            OsString::from("/work/guest/tools/rustc")
        );
    }

    #[test]
    fn a_same_version_toolchain_split_still_names_the_difference() {
        // Two compilers can print the same banner and still be different builds
        // (a rebuilt nightly, a vendored rustc). The banner alone would then read
        // as a contradiction — "these two identical toolchains disagree" — so the
        // refusal falls back to the full `-vV` blocks.
        let shim = RustcIdentity {
            banner: "rustc 1.90.0 (aaaaaaaaa 2026-01-01)".into(),
            verbose: "rustc 1.90.0 (aaaaaaaaa 2026-01-01)\ncommit-hash: aaaaaaaaa\nLLVM version: \
                      20.1.0"
                .into(),
        };
        let guest = RustcIdentity {
            banner: shim.banner.clone(),
            verbose: "rustc 1.90.0 (aaaaaaaaa 2026-01-01)\ncommit-hash: bbbbbbbbb\nLLVM version: \
                      21.1.0"
                .into(),
        };
        assert_ne!(shim, guest);
        let message = toolchain_mismatch_message(
            &shim,
            Path::new("/patina"),
            &guest,
            Path::new("/work/guest"),
        );
        assert!(message.contains("refusing to build"), "{message}");
        assert!(
            message.contains("/patina") && message.contains("/work/guest"),
            "{message}"
        );
        assert!(
            message.contains("commit-hash: aaaaaaaaa")
                && message.contains("commit-hash: bbbbbbbbb"),
            "the same-banner case must show the full identities:\n{message}"
        );
        assert!(message.contains("RUSTUP_TOOLCHAIN"), "{message}");

        // Differing banners are self-explanatory; no full dump.
        let other = RustcIdentity {
            banner: "rustc 1.86.0 (05f9846f8 2025-03-31)".into(),
            verbose: "rustc 1.86.0 (05f9846f8 2025-03-31)\ncommit-hash: 05f9846f8".into(),
        };
        let message =
            toolchain_mismatch_message(&shim, Path::new("/patina"), &other, Path::new("/g"));
        assert!(message.contains("rustc 1.86.0"), "{message}");
        assert!(
            !message.contains("commit-hash: 05f9846f8"),
            "differing banners need no full dump:\n{message}"
        );
    }

    #[test]
    fn rustix_use_libc_is_dropped_only_on_sud_capable_targets() {
        // x86_64 Linux has kernel SUD, so the raw-syscall workaround is dropped
        // (SUD traps the raw syscalls); every other target keeps it. Guards the
        // no-cruft retirement against silently re-widening or over-dropping.
        assert!(target_has_sud("x86_64-unknown-linux-gnu"));
        assert!(target_has_sud("x86_64-unknown-linux-musl"));
        assert!(!target_has_sud("aarch64-unknown-linux-gnu")); // no SUD yet
        assert!(!target_has_sud("aarch64-apple-darwin")); // rustix uses libc
        assert!(!target_has_sud("x86_64-apple-darwin"));

        // The injected flags reflect it: present for aarch64-linux, absent for
        // x86_64-linux.
        let directory = tempfile::tempdir().unwrap();
        let obj = directory.path().join("o.o");
        let lib = directory.path().join("l.a");
        fs::write(&obj, b"object").unwrap();
        fs::write(&lib, b"staticlib").unwrap();
        let x86 =
            native_package_rustflags(&obj, &lib, None, None, "x86_64-unknown-linux-gnu").unwrap();
        let arm =
            native_package_rustflags(&obj, &lib, None, None, "aarch64-unknown-linux-gnu").unwrap();
        assert!(!x86.to_string_lossy().contains("rustix_use_libc"));
        assert!(arm.to_string_lossy().contains("rustix_use_libc"));
    }

    // The scoping split behind
    // `docs/bugs/shim-link-args-reach-dependency-cdylibs.md`: the whole-graph
    // `RUSTFLAGS` carry cfgs and instrumentation, and the shim's link arguments
    // live in the `cargo rustc --` set that reaches one unit's final link. The
    // single deliberate exception is the weak SanitizerCoverage stub, which is
    // whole-graph because the instrumentation it answers for is. Any OTHER
    // link-arg leaking back into the rustflags side restores the
    // dependency-cdylib failure, so pin the boundary directly. (Real files:
    // the shim-build marker streams the link inputs' bytes.)
    #[test]
    fn shim_link_args_never_travel_in_whole_graph_rustflags() {
        let directory = tempfile::tempdir().unwrap();
        let object = directory.path().join("patina_posix.o");
        let staticlib = directory.path().join("libpatina_dst_native_shim.a");
        let yield_object = directory.path().join("patina_yield.o");
        let sancov_stub = directory.path().join("patina_sancov_stub.o");
        for path in [&object, &staticlib, &yield_object, &sancov_stub] {
            fs::write(path, b"bytes").unwrap();
        }

        for stub in [None, Some(sancov_stub.as_path())] {
            let rustflags = native_package_rustflags(
                &object,
                &staticlib,
                None,
                stub,
                "x86_64-unknown-linux-gnu",
            )
            .unwrap();
            let rustflags = rustflags.to_string_lossy().into_owned();
            assert!(rustflags.contains("patina_shim"));
            // Yield-point instrumentation is codegen, not linking: it must stay
            // whole-graph so dependency code gains yield points too.
            assert_eq!(
                rustflags.contains("sanitizer-coverage-trace-pc-guard"),
                stub.is_some()
            );
            let link_args: Vec<&str> = rustflags
                .split('\u{1f}')
                .filter(|token| token.starts_with("link-arg="))
                .collect();
            match stub {
                None => assert!(
                    link_args.is_empty(),
                    "an uninstrumented build injects nothing whole-graph, got: {link_args:?}"
                ),
                Some(_) => assert_eq!(
                    link_args,
                    vec![format!("link-arg={}", sancov_stub.display()).as_str()]
                ),
            }
        }

        let args = native_package_link_args(&object, &staticlib, Some(&yield_object));
        let rendered: Vec<String> = args
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert!(rendered.iter().any(|arg| arg.ends_with("patina_posix.o")));
        assert!(
            rendered
                .iter()
                .any(|arg| arg.ends_with("libpatina_dst_native_shim.a"))
        );
        assert!(rendered.iter().any(|arg| arg.ends_with("patina_yield.o")));
        for arg in &rendered {
            assert!(
                arg == "-C" || arg.starts_with("link-arg="),
                "the scoped set is link arguments only, got: {arg}"
            );
        }
        assert!(
            native_package_link_args(&object, &staticlib, None)
                .iter()
                .all(|arg| !arg.to_string_lossy().ends_with("patina_yield.o"))
        );
    }

    // The injected flag string must key the shim link inputs' CONTENT, because
    // Cargo fingerprints that string and nothing else: same bytes must give the
    // same string (so an unchanged rebuild stays a cache hit), and changed bytes
    // must give a different one (so a rebuilt shim forces the guest to relink
    // instead of silently reusing a binary linked against the previous archive).
    // The staticlib is the input that needs this — it has one canonical path,
    // unlike the helper objects, which are content-addressed by path.
    #[test]
    fn shim_link_input_bytes_key_the_injected_flags() {
        let directory = tempfile::tempdir().unwrap();
        let object = directory.path().join("patina_posix.o");
        let staticlib = directory.path().join("libpatina_dst_native_shim.a");
        fs::write(&object, b"object bytes").unwrap();
        fs::write(&staticlib, b"shim bytes").unwrap();
        let target = "aarch64-apple-darwin";

        let first = native_package_rustflags(&object, &staticlib, None, None, target).unwrap();
        let repeat = native_package_rustflags(&object, &staticlib, None, None, target).unwrap();
        assert_eq!(first, repeat, "unchanged inputs must give identical flags");

        // Same path, different bytes: the pre-fix flag string was byte-identical
        // here, which is exactly how a stale guest survived a shim change.
        fs::write(&staticlib, b"rebuilt shim bytes").unwrap();
        let rebuilt = native_package_rustflags(&object, &staticlib, None, None, target).unwrap();
        assert_ne!(
            first, rebuilt,
            "a rebuilt staticlib at the same path must change the injected flags"
        );

        // Same length, different content: a size/mtime-shaped key would miss it.
        fs::write(&staticlib, b"shim bytez").unwrap();
        let flipped = native_package_rustflags(&object, &staticlib, None, None, target).unwrap();
        assert_ne!(first, flipped, "a same-length edit must change the flags");
    }

    fn strings(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    fn invocation(values: &[&str]) -> Invocation {
        match parse(strings(values)).unwrap() {
            ParseResult::Run(value) => value,
            _ => panic!("expected invocation"),
        }
    }

    // `run`/`audit`/`build` infer their target from artifact magic bytes at the
    // routing layer (covered by the e2e suite with real artifacts and by
    // `detects_artifact_family_from_magic` below). These helpers exercise the
    // per-target parsers directly, so the first element is a readable label the
    // helper drops before parsing.
    fn wasi_invocation(values: &[&str]) -> WasiInvocation {
        parse_wasi_run(strings(&values[1..])).unwrap()
    }

    fn native_run(values: &[&str]) -> NativeRunInvocation {
        parse_native_run(strings(&values[1..])).unwrap()
    }

    #[test]
    fn native_run_parses_fault_knobs() {
        let parsed = native_run(&[
            "native-run",
            "bin",
            "--fs-crash-at",
            "close:1",
            "--fs-torn-granularity",
            "byte",
            "--sleep-jitter-nanos",
            "500..1500",
            "--net-jitter-nanos",
            "0..1000",
            "--net-drop-permille",
            "250",
        ]);
        assert_eq!(parsed.knobs.get(FaultKnob::FsCrashAt), ["close:1"]);
        assert_eq!(parsed.knobs.get(FaultKnob::FsTornGranularity), ["byte"]);
        assert_eq!(parsed.knobs.get(FaultKnob::SleepJitterNanos), ["500..1500"]);
        assert_eq!(parsed.knobs.get(FaultKnob::NetJitterNanos), ["0..1000"]);
        assert_eq!(parsed.knobs.get(FaultKnob::NetDropPermille), ["250"]);
    }

    #[test]
    fn native_run_defaults_leave_fault_knobs_off() {
        let parsed = native_run(&["native-run", "bin"]);
        assert_eq!(parsed.knobs, KnobValues::default());
    }

    #[test]
    fn native_run_buggify_value_form_enables_and_carries_permille() {
        // Point pin for the `--buggify=N` native parser/plumbing path; class-level
        // pairing: runtime/trace `+buggify` metadata-coherence fail-closed guard.
        let parsed = native_run(&[
            "native-run",
            "bin",
            "--buggify=372",
            "--buggify-activation-permille=330",
            "--buggify-cutoff-nanos=12345",
            "--buggify-after-setup",
        ]);
        let buggify = parsed.buggify.expect("--buggify must enable SDK buggify");
        assert_eq!(buggify.fire_permille.as_deref(), Some("372"));
        assert_eq!(buggify.activation_permille.as_deref(), Some("330"));
        assert_eq!(buggify.cutoff_nanos.as_deref(), Some("12345"));
        assert!(buggify.after_setup);
        let env = buggify_env_pairs(&buggify);
        assert!(
            env.iter()
                .any(|(name, value)| *name == ENV_BUGGIFY && value == "372")
        );
        assert!(
            env.iter()
                .any(|(name, value)| *name == ENV_BUGGIFY_ACTIVATION && value == "330")
        );
    }

    #[test]
    fn strips_cargo_plugin_name_and_forwards_unknown_arguments() {
        let parsed = invocation(&[
            "patina",
            "run",
            "--seed",
            "42",
            "--budget",
            "100",
            "--param",
            "zone=a",
            "--release",
            "--example=demo",
        ]);
        assert_eq!(parsed.cargo_command, "run");
        assert_eq!(parsed.mode, Mode::Seeded { seed: 42 });
        assert_eq!(parsed.step_budget, Some(100));
        assert_eq!(parsed.params.get("zone").map(String::as_str), Some("a"));
        assert_eq!(parsed.cargo_args, strings(&["--release", "--example=demo"]));
    }

    #[test]
    fn does_not_consume_program_arguments_after_separator() {
        let parsed = invocation(&["run", "--seed=1", "--", "--seed", "application"]);
        assert_eq!(parsed.mode, Mode::Seeded { seed: 1 });
        assert_eq!(parsed.cargo_args, strings(&["--", "--seed", "application"]));
    }

    #[test]
    fn parses_record_and_replay_and_rejects_conflicts() {
        assert_eq!(
            invocation(&["test", "--record", "run.patina"]).mode,
            Mode::Record {
                seed: 0,
                path: "run.patina".into()
            }
        );
        // Replaying a Cargo-family recording is the `replay` verb's job. The `.`
        // package positional routes to the Cargo family (the crate directory the
        // test runs in) and the trace positional replaces the old `--replay` PATH.
        let replayed = invocation(&["replay", ".", "run.patina"]);
        assert_eq!(
            replayed.mode,
            Mode::Replay {
                path: "run.patina".into(),
                timeline: "main".into(),
            }
        );
        // A recording is produced by `run`, so replay reproduces the `run`
        // program under the runtime; its package directory is threaded through.
        assert_eq!(replayed.cargo_command, "run");
        assert!(replayed.working_dir.is_some());
        assert_eq!(
            invocation(&[
                "replay",
                ".",
                "run.patina",
                "--branch",
                "--from",
                "4",
                "--branch-seed",
                "99",
                "--branch-id",
                "branch-99",
                "--parent",
                "main",
            ])
            .mode,
            Mode::Branch {
                path: "run.patina".into(),
                parent: "main".into(),
                from_sequence: 4,
                branch_seed: 99,
                branch_id: "branch-99".into(),
            }
        );
        // `--timeline` selects a timeline to replay and cannot combine with the
        // branch controls; branch controls without `--branch` are also rejected.
        assert!(
            parse(strings(&[
                "replay",
                ".",
                "run.patina",
                "--branch",
                "--from",
                "1",
                "--branch-seed",
                "2",
                "--branch-id",
                "b",
                "--timeline",
                "x",
            ]))
            .is_err()
        );
        assert!(parse(strings(&["replay", ".", "run.patina", "--from", "1"])).is_err());
        // `run`/`test` no longer parse the replay/branch flags: an unknown flag is
        // forwarded to Cargo, leaving the Patina mode plainly seeded.
        assert_eq!(
            invocation(&["test", "--seed", "1"]).mode,
            Mode::Seeded { seed: 1 }
        );
    }

    #[test]
    fn parses_bounded_seed_exploration() {
        match parse(strings(&[
            "explore",
            "test",
            "--seeds=3",
            "--seed-start",
            "5",
            "--release",
        ]))
        .unwrap()
        {
            ParseResult::Explore(exploration) => {
                assert_eq!(exploration.start_seed, 5);
                assert_eq!(exploration.seed_count, 3);
                match exploration.target {
                    ExploreTarget::Cargo(invocation) => {
                        assert_eq!(invocation.cargo_command, "test");
                        assert_eq!(invocation.cargo_args, strings(&["--release"]));
                    }
                    _ => panic!("expected a Cargo explore target"),
                }
            }
            _ => panic!("expected exploration"),
        }
        assert!(parse(strings(&["explore", "test", "--seeds", "0"])).is_err());
        assert!(parse(strings(&["explore", "test", "--record", "run.patina"])).is_err());
    }

    #[test]
    fn cargo_family_parses_fault_knobs_and_explore_run_wasi() {
        // The Cargo family accepts the seed-driven fault knobs on run/test.
        let parsed = invocation(&[
            "run",
            "--fs-crash-at",
            "close:2",
            "--net-drop-permille",
            "300",
            "--",
            "app-arg",
        ]);
        assert_eq!(parsed.knobs.get(FaultKnob::FsCrashAt), ["close:2"]);
        assert_eq!(parsed.knobs.get(FaultKnob::NetDropPermille), ["300"]);
        // The `--` tail is forwarded to Cargo, unaffected by fault parsing.
        assert_eq!(parsed.cargo_args, strings(&["--", "app-arg"]));

        // `explore run <MODULE.wasm>` sweeps the WASI family (build once, run the
        // same artifact across seeds). The module is recognized by magic bytes at
        // execution; here a real `.wasm` file exercises the routing.
        let directory = tempfile::tempdir().unwrap();
        let module = directory.path().join("m.wasm");
        std::fs::write(&module, b"\0asm\x01\0\0\0").unwrap();
        match parse(strings(&[
            "explore",
            "run",
            module.to_str().unwrap(),
            "--seeds",
            "4",
            "--seed-start",
            "2",
        ]))
        .unwrap()
        {
            ParseResult::Explore(exploration) => {
                assert_eq!(exploration.start_seed, 2);
                assert_eq!(exploration.seed_count, 4);
                assert!(matches!(exploration.target, ExploreTarget::Wasi(_)));
            }
            _ => panic!("expected a WASI exploration"),
        }
    }

    fn trace_invocation(values: &[&str]) -> minimize::TraceMinimize {
        match parse(strings(values)).unwrap() {
            ParseResult::Minimize(minimize::MinimizeInvocation::Trace(invocation)) => invocation,
            _ => panic!("expected trace minimization"),
        }
    }

    fn scenario_invocation(values: &[&str]) -> minimize::ScenarioMinimize {
        match parse(strings(values)).unwrap() {
            ParseResult::Minimize(minimize::MinimizeInvocation::Scenario(invocation)) => invocation,
            _ => panic!("expected scenario minimization"),
        }
    }

    #[test]
    fn parses_trace_minimization_with_an_external_oracle() {
        let invocation = trace_invocation(&[
            "minimize",
            "failure.patina",
            "--output",
            "small.patina",
            "--timeline",
            "failure",
            "--",
            "./oracle",
            "--exact",
        ]);
        assert_eq!(invocation.trace, PathBuf::from("failure.patina"));
        assert_eq!(invocation.output, PathBuf::from("small.patina"));
        assert_eq!(invocation.timeline.as_deref(), Some("failure"));
        assert!(!invocation.prune);
        assert_eq!(invocation.oracle, strings(&["./oracle", "--exact"]));
        assert!(parse(strings(&["minimize", "failure.patina"])).is_err());
    }

    #[test]
    fn parses_branch_pruning_and_rejects_timeline_combo() {
        let invocation = trace_invocation(&[
            "minimize",
            "failure.patina",
            "--output",
            "small.patina",
            "--prune-branches",
            "--",
            "./oracle",
        ]);
        assert!(invocation.prune);
        assert_eq!(invocation.timeline, None);
        // --prune-branches and --timeline are mutually exclusive.
        assert!(
            parse(strings(&[
                "minimize",
                "failure.patina",
                "--output",
                "small.patina",
                "--prune-branches",
                "--timeline",
                "leaf",
                "--",
                "./oracle",
            ]))
            .is_err()
        );
    }

    #[test]
    fn parses_scenario_minimization_with_seed_and_params() {
        let invocation = scenario_invocation(&[
            "minimize",
            "--scenario",
            "--seed",
            "12",
            "--param",
            "zone=a",
            "--seed-budget",
            "16",
            "--",
            "./oracle",
            "--flag",
        ]);
        assert_eq!(invocation.seed, 12);
        assert_eq!(invocation.seed_budget, 16);
        assert_eq!(invocation.params.get("zone").map(String::as_str), Some("a"));
        assert_eq!(invocation.oracle, strings(&["./oracle", "--flag"]));
        // --scenario requires a seed and an oracle after `--`.
        assert!(parse(strings(&["minimize", "--scenario", "--", "./oracle"])).is_err());
        assert!(parse(strings(&["minimize", "--scenario", "--seed", "1"])).is_err());
        // trace-only options are rejected in scenario mode.
        assert!(
            parse(strings(&[
                "minimize",
                "--scenario",
                "--seed",
                "1",
                "--timeline",
                "leaf",
                "--",
                "./oracle",
            ]))
            .is_err()
        );
    }

    #[test]
    fn detects_artifact_family_from_magic() {
        // WebAssembly preamble.
        assert_eq!(
            detect_artifact_family(b"\0asm\x01\0\0\0"),
            Some(ArtifactFamily::Wasm)
        );
        // ELF.
        assert_eq!(
            detect_artifact_family(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]),
            Some(ArtifactFamily::Native)
        );
        // Mach-O thin (both byte orders) and universal ("fat").
        for magic in [
            [0xfe, 0xed, 0xfa, 0xce],
            [0xce, 0xfa, 0xed, 0xfe],
            [0xfe, 0xed, 0xfa, 0xcf],
            [0xcf, 0xfa, 0xed, 0xfe],
            [0xca, 0xfe, 0xba, 0xbe],
            [0xbe, 0xba, 0xfe, 0xca],
        ] {
            assert_eq!(
                detect_artifact_family(&magic),
                Some(ArtifactFamily::Native),
                "Mach-O magic {magic:02x?} should classify as native"
            );
        }
        // Unrecognized: a Cargo.toml, a too-short buffer, an empty buffer.
        assert_eq!(detect_artifact_family(b"[package]\nname = \"x\"\n"), None);
        assert_eq!(detect_artifact_family(b"\0as"), None);
        assert_eq!(detect_artifact_family(b""), None);
    }

    #[test]
    fn extracts_target_selector() {
        let (target, rest) =
            extract_target(strings(&["src.rs", "--target", "wasi", "--release"])).unwrap();
        assert_eq!(target.as_deref(), Some("wasi"));
        assert_eq!(rest, strings(&["src.rs", "--release"]));

        let (target, rest) = extract_target(strings(&["pkg", "--target=native"])).unwrap();
        assert_eq!(target.as_deref(), Some("native"));
        assert_eq!(rest, strings(&["pkg"]));

        // A `--target` past `--` is a rustc/cargo flag, left in place.
        let (target, rest) = extract_target(strings(&["src.rs", "--", "--target", "x86"])).unwrap();
        assert_eq!(target, None);
        assert_eq!(rest, strings(&["src.rs", "--", "--target", "x86"]));

        assert_eq!(target_family("native").unwrap(), ArtifactFamily::Native);
        assert_eq!(target_family("wasi").unwrap(), ArtifactFamily::Wasm);
        assert!(target_family("riscv").is_err());
    }

    #[test]
    fn classifies_and_resolves_positional_arguments() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();

        // A native (ELF) magic file is a built artifact.
        let elf = root.join("bin");
        fs::write(&elf, [0x7f, b'E', b'L', b'F', 2, 1, 1, 0]).unwrap();
        assert!(matches!(
            classify_arg(elf.as_os_str()).unwrap(),
            ArgKind::Artifact(ArtifactFamily::Native)
        ));
        // A WebAssembly magic file is a built artifact.
        let wasm = root.join("mod.wasm");
        fs::write(&wasm, b"\0asm\x01\0\0\0").unwrap();
        assert!(matches!(
            classify_arg(wasm.as_os_str()).unwrap(),
            ArgKind::Artifact(ArtifactFamily::Wasm)
        ));
        // A `.rs` source, a package directory, and a Cargo.toml are sources.
        let source = root.join("main.rs");
        fs::write(&source, "fn main() {}").unwrap();
        assert!(matches!(
            classify_arg(source.as_os_str()).unwrap(),
            ArgKind::SourceFile(_)
        ));
        let pkg = root.join("pkg");
        fs::create_dir(&pkg).unwrap();
        fs::write(pkg.join("Cargo.toml"), "[package]").unwrap();
        match classify_arg(pkg.as_os_str()).unwrap() {
            ArgKind::SourcePackage(manifest) => assert_eq!(manifest, pkg.join("Cargo.toml")),
            _ => panic!("expected a source package"),
        }
        assert!(matches!(
            classify_arg(pkg.join("Cargo.toml").as_os_str()).unwrap(),
            ArgKind::SourcePackage(_)
        ));
        // A leading flag and a plain non-source file are neither.
        assert!(matches!(
            classify_arg(OsStr::new("--seed")).unwrap(),
            ArgKind::Other
        ));
        let plain = root.join("notes.txt");
        fs::write(&plain, "hello").unwrap();
        assert!(matches!(
            classify_arg(plain.as_os_str()).unwrap(),
            ArgKind::Other
        ));

        // Resolution: a lone `.rs` builds native; `--target wasi` on a `.rs`
        // errors (native-only); a prebuilt artifact with a mismatched --target
        // errors.
        let (family, artifact) = resolve_positional(source.as_os_str(), None)
            .unwrap()
            .unwrap();
        assert_eq!(family, ArtifactFamily::Native);
        assert!(matches!(artifact, ArtifactRef::Build(_)));
        assert!(resolve_positional(source.as_os_str(), Some("wasi")).is_err());
        assert!(resolve_positional(wasm.as_os_str(), Some("native")).is_err());

        // A package directory resolves to a native build-on-the-fly with no
        // `--target` — the SAME path `audit` uses, so an existing directory is
        // never reinterpreted as guest argv. (Keeping a runtime-linked package on
        // the cargo family is a `run`/`replay` routing decision made upstream via
        // `package_integrates_patina`, not by this pure resolver.) `--target wasi`
        // selects the WASI package build.
        let (family, artifact) = resolve_positional(pkg.as_os_str(), None).unwrap().unwrap();
        assert_eq!(family, ArtifactFamily::Native);
        assert!(matches!(artifact, ArtifactRef::Build(_)));
        let (family, _) = resolve_positional(pkg.as_os_str(), Some("wasi"))
            .unwrap()
            .unwrap();
        assert_eq!(family, ArtifactFamily::Wasm);
        // A leading flag resolves to nothing (the caller's no-artifact path).
        assert!(
            resolve_positional(OsStr::new("--seed"), None)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn parses_build_wasi_target_and_native_audit() {
        // `build --target wasi <package>` resolves a manifest-scoped package
        // build; a `.rs` source, `--yield-points`, and an unknown target rejected.
        match parse_build(strings(&["pkg", "--target", "wasi", "--release"])).unwrap() {
            ParseResult::WasiBuild(invocation) => {
                assert_eq!(invocation.manifest, PathBuf::from("pkg/Cargo.toml"));
                assert!(invocation.release);
                assert_eq!(invocation.package, None);
                assert_eq!(invocation.bin, None);
                assert_eq!(invocation.output, None);
            }
            _ => panic!("expected a WASI build"),
        }
        assert!(parse_build(strings(&["probe.rs", "--target", "wasi"])).is_err());
        assert!(parse_build(strings(&["pkg", "--target", "wasi", "--yield-points"])).is_err());
        assert!(parse_build(strings(&["pkg", "--target", "riscv"])).is_err());

        // Native audit parsing (routing to it by artifact magic is covered by e2e).
        let audit = parse_native_audit(strings(&[
            "probe",
            "--allow",
            "write",
            "--allow",
            "clock_gettime",
        ]))
        .unwrap();
        assert_eq!(audit.binary, ArtifactRef::Prebuilt(PathBuf::from("probe")));
        assert!(audit.allow.contains("write"));
        assert!(audit.allow.contains("clock_gettime"));
    }

    #[test]
    fn source_first_package_selection_threads_into_the_build_spec() {
        // `--package`/`--bin` are extracted from the head (before any `--`) and the
        // rest is passed through; a `--package` in the guest section is untouched.
        let selection = take_package_bin(strings(&[
            "--package",
            "member",
            "--seed",
            "1",
            "--bin",
            "app",
            "--",
            "--package",
            "guest",
        ]))
        .unwrap();
        assert_eq!(selection.package.as_deref(), Some("member"));
        assert_eq!(selection.bin.as_deref(), Some("app"));
        assert_eq!(
            selection.rest,
            strings(&["--seed", "1", "--", "--package", "guest"])
        );

        // Applied to a native package build spec, they select the member/binary.
        let mut artifact = ArtifactRef::Build(Box::new(native_package_spec(
            PathBuf::from("ws"),
            PathBuf::from("ws/Cargo.toml"),
        )));
        apply_package_selection(&mut artifact, Some("member".into()), Some("app".into())).unwrap();
        match &artifact {
            ArtifactRef::Build(spec) => match &spec.kind {
                BuildSpecKind::Native(inv) => match &inv.target {
                    NativeBuildTarget::Package { package, bin, .. } => {
                        assert_eq!(package.as_deref(), Some("member"));
                        assert_eq!(bin.as_deref(), Some("app"));
                    }
                    _ => panic!("expected a package target"),
                },
                _ => panic!("expected a native build"),
            },
            _ => panic!("expected a build spec"),
        }

        // A prebuilt artifact or a single `.rs` source has nothing to select, so a
        // stray selection fails closed rather than being silently ignored; an empty
        // selection is a no-op on any artifact.
        let mut prebuilt = ArtifactRef::Prebuilt(PathBuf::from("bin"));
        assert!(apply_package_selection(&mut prebuilt, Some("x".into()), None).is_err());
        assert!(apply_package_selection(&mut prebuilt, None, None).is_ok());
        let mut source = ArtifactRef::Build(Box::new(native_source_spec(PathBuf::from("main.rs"))));
        assert!(apply_package_selection(&mut source, None, Some("x".into())).is_err());
    }

    #[test]
    fn source_first_release_threads_into_the_build_spec() {
        // `--release` is extracted from the head (before any `--`); the rest passes
        // through, and a `--release` in the guest section stays untouched.
        let (release, rest) =
            take_release(strings(&["--release", "--seed", "1", "--", "--release"])).unwrap();
        assert!(release);
        assert_eq!(rest, strings(&["--seed", "1", "--", "--release"]));

        // Absent, it defaults off; an inline value is rejected (valueless switch).
        let (release, rest) = take_release(strings(&["--seed", "1"])).unwrap();
        assert!(!release);
        assert_eq!(rest, strings(&["--seed", "1"]));
        assert!(take_release(strings(&["--release=yes"])).is_err());

        // Applied to a native source/package build, it flips the release profile;
        // a WASI package build spec flips too.
        for mut artifact in [
            ArtifactRef::Build(Box::new(native_source_spec(PathBuf::from("main.rs")))),
            ArtifactRef::Build(Box::new(native_package_spec(
                PathBuf::from("ws"),
                PathBuf::from("ws/Cargo.toml"),
            ))),
            ArtifactRef::Build(Box::new(wasi_package_spec(
                PathBuf::from("ws"),
                PathBuf::from("ws/Cargo.toml"),
            ))),
        ] {
            apply_release(&mut artifact, true).unwrap();
            let released = match &artifact {
                ArtifactRef::Build(spec) => match &spec.kind {
                    BuildSpecKind::Native(inv) => inv.release,
                    BuildSpecKind::Wasi(inv) => inv.release,
                },
                _ => panic!("expected a build spec"),
            };
            assert!(
                released,
                "release profile did not thread into the build spec"
            );
        }

        // An already-built artifact carries no build profile, so `--release` on a
        // prebuilt positional fails closed rather than being silently ignored; a
        // false (absent) release is a no-op on any artifact.
        let mut prebuilt = ArtifactRef::Prebuilt(PathBuf::from("bin"));
        assert!(apply_release(&mut prebuilt, true).is_err());
        assert!(apply_release(&mut prebuilt, false).is_ok());
    }

    #[test]
    fn parses_wasi_run_record_and_branch_modes() {
        let invocation = parse_wasi_run(strings(&[
            "module.wasm",
            "--seed",
            "7",
            "--record",
            "run.patina",
            "--arg",
            "one",
            "--env",
            "MODE=test",
            "--socket",
            "4=node-a->node-b",
            "--socket",
            "5=node-b->node-a",
            "--preopen",
            "/data:ro",
            "--max-memory-pages",
            "128",
            "--max-descriptors",
            "32",
            "--max-preopens",
            "4",
            "--max-path-bytes",
            "512",
            "--max-io-bytes",
            "4096",
            "--max-iovecs",
            "16",
        ]))
        .unwrap();
        assert_eq!(
            invocation.module,
            ArtifactRef::Prebuilt(PathBuf::from("module.wasm"))
        );
        assert_eq!(invocation.fuel, DEFAULT_WASM_FUEL);
        assert_eq!(invocation.arguments, ["one"]);
        assert_eq!(invocation.environment["MODE"], "test");
        assert_eq!(invocation.sockets.len(), 2);
        assert_eq!(invocation.sockets[0].fd, 4);
        assert_eq!(invocation.preopens.len(), 1);
        assert_eq!(invocation.preopens[0].guest_path, "/data");
        assert_eq!(invocation.preopens[0].policy, MountPolicy::ReadOnly);
        assert_eq!(invocation.resource_limits.max_memory_pages, Some(128));
        assert_eq!(invocation.resource_limits.max_descriptors, Some(32));
        assert_eq!(invocation.resource_limits.max_preopens, Some(4));
        assert_eq!(invocation.resource_limits.max_path_bytes, Some(512));
        assert_eq!(invocation.resource_limits.max_io_bytes, Some(4096));
        assert_eq!(invocation.resource_limits.max_iovecs, Some(16));
        assert_eq!(
            invocation.mode,
            Mode::Record {
                seed: 7,
                path: "run.patina".into()
            }
        );

        // Replaying and branching a WASI trace is the `replay` verb's job now:
        // the trace is a positional and the flags are semantic-free.
        let module = ArtifactRef::Prebuilt(PathBuf::from("module.wasm"));
        let branched = parse_wasi_replay(
            module.clone(),
            "run.patina".into(),
            strings(&[
                "--branch",
                "--from",
                "3",
                "--branch-seed",
                "8",
                "--branch-id",
                "wasi-branch",
            ]),
        )
        .unwrap();
        assert_eq!(
            branched.mode,
            Mode::Branch {
                path: "run.patina".into(),
                parent: "main".into(),
                from_sequence: 3,
                branch_seed: 8,
                branch_id: "wasi-branch".into(),
            }
        );

        // Strict replay of a named timeline, and the recorded host inputs
        // (`--socket`) still re-supplied as genuine host state.
        let replayed = parse_wasi_replay(
            module,
            "run.patina".into(),
            strings(&["--timeline", "wasi-branch", "--socket", "4=node-a->node-b"]),
        )
        .unwrap();
        assert_eq!(
            replayed.mode,
            Mode::Replay {
                path: "run.patina".into(),
                timeline: "wasi-branch".into(),
            }
        );
        assert_eq!(replayed.sockets.len(), 1);
        // A semantic flag on WASI replay is refused: the trace is authoritative.
        assert!(
            parse_wasi_replay(
                ArtifactRef::Prebuilt(PathBuf::from("module.wasm")),
                "run.patina".into(),
                strings(&["--fs-crash-at", "close:1"]),
            )
            .is_err()
        );
    }

    #[test]
    fn parses_wasi_preopen_policy_forms_and_limits() {
        let invocation = wasi_invocation(&[
            "wasi-run",
            "module.wasm",
            "--fuel",
            "99",
            "--preopen",
            "/default",
            "--preopen",
            "/readonly:ro",
            "--preopen",
            "/readwrite:rw",
            "--max-memory-pages",
            "2",
            "--max-descriptors",
            "3",
            "--max-preopens",
            "4",
            "--max-path-bytes",
            "5",
            "--max-io-bytes",
            "6",
            "--max-iovecs",
            "7",
        ]);
        assert_eq!(invocation.fuel, 99);
        assert_eq!(invocation.resource_limits.fuel, Some(99));
        assert_eq!(invocation.preopens.len(), 3);
        assert_eq!(invocation.preopens[0].guest_path, "/default");
        assert_eq!(invocation.preopens[0].policy, MountPolicy::ReadWrite);
        assert_eq!(invocation.preopens[1].guest_path, "/readonly");
        assert_eq!(invocation.preopens[1].policy, MountPolicy::ReadOnly);
        assert_eq!(invocation.preopens[2].guest_path, "/readwrite");
        assert_eq!(invocation.preopens[2].policy, MountPolicy::ReadWrite);
        assert_eq!(invocation.resource_limits.max_memory_pages, Some(2));
        assert_eq!(invocation.resource_limits.max_descriptors, Some(3));
        assert_eq!(invocation.resource_limits.max_preopens, Some(4));
        assert_eq!(invocation.resource_limits.max_path_bytes, Some(5));
        assert_eq!(invocation.resource_limits.max_io_bytes, Some(6));
        assert_eq!(invocation.resource_limits.max_iovecs, Some(7));
    }

    #[test]
    fn rejects_missing_and_duplicate_wasi_option_values() {
        // Value-GRAMMAR rejection is covered generically by
        // `registry_value_grammars_match_the_parsers`; what stays here are the
        // non-grammar shapes: a required-value flag with no value at all, and a
        // repeated non-repeatable flag.
        assert!(parse_wasi_run(strings(&["module.wasm", "--preopen"])).is_err());
        assert!(
            parse_wasi_run(strings(&[
                "module.wasm",
                "--max-iovecs",
                "1",
                "--max-iovecs",
                "2",
            ]))
            .is_err()
        );
    }

    #[test]
    fn wasi_host_configuration_errors_are_cli_errors() {
        let invalid = wasi_invocation(&["wasi-run", "module.wasm", "--preopen", "relative"]);
        let error = configured_wasi_host(
            &invalid,
            Path::new("module.wasm"),
            Context::from_config(RuntimeConfig::seeded(0)).unwrap(),
        )
        .err()
        .unwrap()
        .to_string();
        assert!(error.contains("invalid WASI preopen"));

        let overlapping = wasi_invocation(&[
            "wasi-run",
            "module.wasm",
            "--preopen",
            "/data",
            "--preopen",
            "/data/inner",
        ]);
        let error = configured_wasi_host(
            &overlapping,
            Path::new("module.wasm"),
            Context::from_config(RuntimeConfig::seeded(0)).unwrap(),
        )
        .err()
        .unwrap()
        .to_string();
        assert!(error.contains("overlaps the configured mount"));

        let too_many = wasi_invocation(&[
            "wasi-run",
            "module.wasm",
            "--max-preopens",
            "1",
            "--preopen",
            "/first",
            "--preopen",
            "/second",
        ]);
        let error = configured_wasi_host(
            &too_many,
            Path::new("module.wasm"),
            Context::from_config(RuntimeConfig::seeded(0)).unwrap(),
        )
        .err()
        .unwrap()
        .to_string();
        assert!(error.contains("configured limit of 1"));
    }

    #[test]
    fn wasi_fingerprint_separates_arguments_from_environment() {
        let module = b"module";
        let arguments = wasi_invocation(&["wasi-run", "module.wasm", "--arg", "k", "--arg", "v"]);
        let environment = wasi_invocation(&["wasi-run", "module.wasm", "--env", "k=v"]);
        assert_ne!(
            wasi_compatibility_fingerprint(module, &arguments, false),
            wasi_compatibility_fingerprint(module, &environment, false)
        );
    }

    #[test]
    fn wasi_fingerprint_covers_preopens_and_resource_limits() {
        let module = b"module";
        let ordered = wasi_invocation(&[
            "wasi-run",
            "module.wasm",
            "--preopen",
            "/beta:ro",
            "--preopen",
            "/alpha:rw",
            "--max-io-bytes",
            "64",
        ]);
        let reordered = wasi_invocation(&[
            "wasi-run",
            "module.wasm",
            "--preopen",
            "/alpha:rw",
            "--preopen",
            "/beta:ro",
            "--max-io-bytes",
            "64",
        ]);
        // Reordering preopens changes descriptor assignment, so it must
        // change the fingerprint.
        assert_ne!(
            wasi_compatibility_fingerprint(module, &ordered, false),
            wasi_compatibility_fingerprint(module, &reordered, false)
        );

        let changed_preopen = wasi_invocation(&[
            "wasi-run",
            "module.wasm",
            "--preopen",
            "/alpha:ro",
            "--preopen",
            "/beta:ro",
            "--max-io-bytes",
            "64",
        ]);
        assert_ne!(
            wasi_compatibility_fingerprint(module, &ordered, false),
            wasi_compatibility_fingerprint(module, &changed_preopen, false)
        );

        let changed_limit = wasi_invocation(&[
            "wasi-run",
            "module.wasm",
            "--preopen",
            "/beta:ro",
            "--preopen",
            "/alpha:rw",
            "--max-io-bytes",
            "65",
        ]);
        assert_ne!(
            wasi_compatibility_fingerprint(module, &ordered, false),
            wasi_compatibility_fingerprint(module, &changed_limit, false)
        );
    }

    fn native_build_invocation(values: &[&str]) -> NativeBuildInvocation {
        // The first element is a readable label; `build` routing lives in
        // `parse_build`, exercised separately.
        parse_native_build(strings(&values[1..])).unwrap()
    }

    #[test]
    fn parses_native_build_with_output_edition_and_forwarded_rustc_args() {
        let invocation = native_build_invocation(&[
            "native-build",
            "probe.rs",
            "--output",
            "probe",
            "--edition",
            "2021",
            "--release",
            "--",
            "-C",
            "opt-level=2",
        ]);
        assert_eq!(invocation.output.as_deref(), Some(Path::new("probe")));
        assert!(invocation.release);
        match invocation.target {
            NativeBuildTarget::Source {
                source,
                edition,
                rustc_args,
            } => {
                assert_eq!(source, PathBuf::from("probe.rs"));
                assert_eq!(edition, "2021");
                assert_eq!(rustc_args, strings(&["-C", "opt-level=2"]));
            }
            NativeBuildTarget::Package { .. } => panic!("expected a single-source target"),
        }
        // The default edition applies and --output is required.
        let invocation =
            native_build_invocation(&["native-build", "probe.rs", "--output", "probe", "--"]);
        assert!(!invocation.release);
        match invocation.target {
            NativeBuildTarget::Source {
                edition,
                rustc_args,
                ..
            } => {
                assert_eq!(edition, DEFAULT_NATIVE_EDITION);
                assert!(rustc_args.is_empty());
            }
            NativeBuildTarget::Package { .. } => panic!("expected a single-source target"),
        }
        assert!(parse_native_build(strings(&["probe.rs"])).is_err());
        assert!(parse_native_build(strings(&["--output", "probe"])).is_err());
        // Package-only options are rejected for a single source.
        assert!(
            parse_native_build(strings(&["probe.rs", "--output", "probe", "--bin", "x"])).is_err()
        );
    }

    #[test]
    fn yield_points_flag_and_fingerprint_suffix() {
        // Off by default on both target shapes.
        assert!(
            !native_build_invocation(&["native-build", "probe.rs", "--output", "p"]).yield_points
        );
        assert!(!native_build_invocation(&["native-build", "pkg", "--output", "p"]).yield_points);
        // `--yield-points` sets it on a single source and on a package.
        assert!(
            native_build_invocation(&[
                "native-build",
                "probe.rs",
                "--output",
                "p",
                "--yield-points",
            ])
            .yield_points
        );
        assert!(
            native_build_invocation(&["native-build", "pkg", "--output", "p", "--yield-points"])
                .yield_points
        );
        // The fingerprint gains the policy suffix only for a yield-point binary,
        // so a plain binary's traces stay compatible and cross-config replay is
        // rejected.
        assert_eq!(
            yield_point_fingerprint(DEFAULT_NATIVE_FINGERPRINT, false),
            DEFAULT_NATIVE_FINGERPRINT
        );
        assert_eq!(
            yield_point_fingerprint(DEFAULT_NATIVE_FINGERPRINT, true),
            format!("{DEFAULT_NATIVE_FINGERPRINT}{PATINA_YIELD_FINGERPRINT_SUFFIX}")
        );
    }

    // The yield-point classification is load-bearing for the compatibility
    // fingerprint, so its detector must (a) find the marker even when it straddles
    // the streaming chunk boundary, (b) report a clean absence as `Ok(false)`, and
    // (c) FAIL CLOSED on an unreadable image rather than silently reporting "not
    // instrumented" — the fail-open that let a memory-pressure read failure
    // misclassify an instrumented binary as plain and bypass the fingerprint gate.
    #[test]
    fn yield_point_detection_streams_and_fails_closed() {
        let dir = tempfile::tempdir().unwrap();

        // Absent marker -> Ok(false).
        let plain = dir.path().join("plain.bin");
        fs::write(&plain, vec![0u8; 200_000]).unwrap();
        assert_eq!(binary_has_yield_points(&plain).ok(), Some(false));

        // Marker present, and deliberately positioned to straddle the 64 KiB
        // streaming boundary so the trailing-overlap carry is exercised.
        let boundary = 64 * 1024 - (PATINA_YIELD_MARKER.len() / 2);
        let mut image = vec![0u8; 200_000];
        image[boundary..boundary + PATINA_YIELD_MARKER.len()].copy_from_slice(PATINA_YIELD_MARKER);
        let instrumented = dir.path().join("instrumented.bin");
        fs::write(&instrumented, &image).unwrap();
        assert_eq!(binary_has_yield_points(&instrumented).ok(), Some(true));

        // An unreadable image is a hard error, never a silent `false`.
        let missing = dir.path().join("does-not-exist.bin");
        let error = binary_has_yield_points(&missing).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("detect yield-point instrumentation"),
            "read failure must fail closed with a named error, got: {error}"
        );
    }

    #[test]
    fn parses_native_build_for_cargo_packages() {
        // A directory and an explicit Cargo.toml both resolve to a manifest path.
        let invocation = native_build_invocation(&[
            "native-build",
            "pkg",
            "--package",
            "demo",
            "--bin",
            "app",
            "--output",
            "out",
            "--release",
        ]);
        assert_eq!(invocation.output.as_deref(), Some(Path::new("out")));
        assert!(invocation.release);
        match invocation.target {
            NativeBuildTarget::Package {
                manifest,
                package,
                bin,
            } => {
                assert_eq!(manifest, PathBuf::from("pkg/Cargo.toml"));
                assert_eq!(package.as_deref(), Some("demo"));
                assert_eq!(bin.as_deref(), Some("app"));
            }
            NativeBuildTarget::Source { .. } => panic!("expected a package target"),
        }

        // --output is optional for packages; a Cargo.toml path is used as-is.
        let invocation = native_build_invocation(&["native-build", "pkg/Cargo.toml"]);
        assert!(invocation.output.is_none());
        match invocation.target {
            NativeBuildTarget::Package {
                manifest,
                package,
                bin,
            } => {
                assert_eq!(manifest, PathBuf::from("pkg/Cargo.toml"));
                assert_eq!(package, None);
                assert_eq!(bin, None);
            }
            NativeBuildTarget::Source { .. } => panic!("expected a package target"),
        }

        // Single-source options are rejected for a package.
        assert!(parse_native_build(strings(&["pkg", "--edition", "2021"])).is_err());
        assert!(parse_native_build(strings(&["pkg", "--", "-C", "opt-level=2"])).is_err());
    }

    #[test]
    fn parses_native_run_modes_and_rejects_conflicts() {
        let seeded = native_run(&[
            "native-run",
            "probe",
            "--seed",
            "9",
            "--env",
            "RUST_LOG=debug",
            "--",
            "one",
        ]);
        assert_eq!(seeded.binary, ArtifactRef::Prebuilt(PathBuf::from("probe")));
        assert!(matches!(seeded.mode, NativeRunMode::Seeded { seed: 9 }));
        assert_eq!(seeded.program_args, strings(&["one"]));
        assert_eq!(seeded.environment["RUST_LOG"], "debug");
        assert!(parse_native_run(strings(&["probe", "--env", ""])).is_err());

        let covered = native_run(&[
            "native-run",
            "probe",
            "--seed",
            "9",
            "--coverage-out",
            "run.covmap",
        ]);
        assert_eq!(covered.coverage_out, Some(PathBuf::from("run.covmap")));

        let recorded = native_run(&[
            "native-run",
            "probe",
            "--record",
            "run.patina",
            "--seed",
            "5",
            "--fingerprint",
            "native-v1",
        ]);
        match recorded.mode {
            NativeRunMode::Record {
                seed,
                path,
                fingerprint,
            } => {
                assert_eq!(seed, 5);
                assert_eq!(path, PathBuf::from("run.patina"));
                assert_eq!(fingerprint, "native-v1");
            }
            _ => panic!("expected record mode"),
        }
        // `run <BINARY>` has no `--replay` flag: replay is the sole domain of the
        // `replay` subcommand, so the native runner rejects it as an unknown option.
        assert!(parse_native_run(strings(&["probe", "--replay", "run.patina"])).is_err());
        assert!(parse_native_run(Vec::new()).is_err());

        // `replay <bin> <trace>` parses into replay mode, restoring seed/faults/
        // buggify/argv from the trace and defaulting the fingerprint. `replay` is
        // source-first, so the binary is classified by magic: use a real file
        // carrying native (ELF) magic as the prebuilt artifact.
        let directory = tempfile::tempdir().unwrap();
        let probe = directory.path().join("probe");
        fs::write(&probe, [0x7f, b'E', b'L', b'F', 2, 1, 1, 0]).unwrap();
        let probe = probe.to_str().unwrap();
        match parse(strings(&["replay", probe, "run.patina"])).unwrap() {
            ParseResult::NativeRun(invocation) => {
                assert_eq!(
                    invocation.binary,
                    ArtifactRef::Prebuilt(PathBuf::from(probe))
                );
                match invocation.mode {
                    NativeRunMode::Replay { path, fingerprint } => {
                        assert_eq!(path, PathBuf::from("run.patina"));
                        assert_eq!(fingerprint, DEFAULT_NATIVE_FINGERPRINT);
                    }
                    _ => panic!("expected replay mode"),
                }
            }
            _ => panic!("expected native-run invocation from replay"),
        }
        // `replay` accepts host/build inputs the trace cannot carry ...
        assert!(
            parse(strings(&[
                "replay",
                probe,
                "run.patina",
                "--fingerprint",
                "fp"
            ]))
            .is_ok()
        );
        assert!(
            parse(strings(&[
                "replay",
                probe,
                "run.patina",
                "--mount",
                "corpus"
            ]))
            .is_ok()
        );
        match parse(strings(&[
            "replay",
            probe,
            "run.patina",
            "--coverage-out",
            "replay.covmap",
        ]))
        .unwrap()
        {
            ParseResult::NativeRun(invocation) => {
                assert_eq!(
                    invocation.coverage_out,
                    Some(PathBuf::from("replay.covmap"))
                );
            }
            _ => panic!("expected native replay invocation"),
        }
        // ... but rejects semantic knobs (the trace is authoritative) and a
        // missing trace path.
        assert!(
            parse(strings(&[
                "replay",
                probe,
                "run.patina",
                "--net-latency-nanos",
                "5"
            ]))
            .is_err()
        );
        assert!(parse(strings(&["replay", probe, "run.patina", "--seed", "1"])).is_err());
        assert!(
            parse(strings(&[
                "replay",
                probe,
                "run.patina",
                "--env",
                "RUST_LOG=trace"
            ]))
            .is_err()
        );
        assert!(parse(strings(&["replay", probe])).is_err());
    }

    #[test]
    fn parses_manifest_path_for_fingerprinting() {
        assert_eq!(
            manifest_path(&strings(&["--manifest-path", "nested/Cargo.toml"]))
                .unwrap()
                .unwrap(),
            OsStr::new("nested/Cargo.toml")
        );
    }

    fn is_help(values: &[&str]) -> bool {
        matches!(parse(strings(values)), Ok(ParseResult::Help(_)))
    }

    #[test]
    fn help_is_intercepted_for_every_verb_and_position() {
        // `-h`/`--help` in the first flag position of every verb and subcommand
        // routes to Help — never consumed as a positional, never an error.
        for verb in [
            "run", "test", "build", "audit", "replay", "explore", "campaign", "minimize",
            "coverage", "sites", "trace",
        ] {
            assert!(is_help(&[verb, "--help"]), "{verb} --help");
            assert!(is_help(&[verb, "-h"]), "{verb} -h");
        }
        // Explore/trace subcommands.
        assert!(is_help(&["explore", "run", "--help"]));
        assert!(is_help(&["explore", "test", "--help"]));
        assert!(is_help(&["trace", "info", "--help"]));
        assert!(is_help(&["trace", "events", "--help"]));
        // After a positional (the old bug: `--help` swallowed as an artifact/trace
        // path or an unsupported option).
        assert!(is_help(&["run", "./bin", "--help"]));
        assert!(is_help(&["campaign", "artifact", "--help"]));
        assert!(is_help(&["replay", "a.wasm", "trace", "--help"]));
        assert!(is_help(&["audit", "artifact", "--help"]));
        assert!(is_help(&["build", "src.rs", "--help"]));
        assert!(is_help(&["minimize", "trace.patina", "--help"]));
        assert!(is_help(&["explore", "run", "artifact", "--help"]));
        assert!(is_help(&["trace", "events", "trace.patina", "--help"]));
        // Top-level.
        assert!(is_help(&["--help"]));
        assert!(is_help(&["-h"]));
        assert!(is_help(&["patina", "--help"]));
    }

    #[test]
    fn help_after_double_dash_belongs_to_the_guest() {
        // A `--help` after the `--` separator is the guest's/oracle's, never
        // intercepted as Patina help.
        assert!(!is_help(&["run", "mod.wasm", "--", "--help"]));
        assert!(!is_help(&["campaign", "artifact", "--", "--help"]));
        assert!(!is_help(&["test", "--", "--help"]));
    }

    #[test]
    fn parses_trace_subcommands_and_events_filters() {
        match parse(strings(&[
            "trace",
            "info",
            "--timeline",
            "b1",
            "run.patina",
        ]))
        .unwrap()
        {
            ParseResult::Trace(trace_cmd::TraceInvocation::Info(info)) => {
                assert_eq!(info.path, PathBuf::from("run.patina"));
                assert_eq!(info.timeline, "b1");
            }
            _ => panic!("expected trace info"),
        }

        match parse(strings(&[
            "trace",
            "events",
            "--kind",
            "fs_write,network",
            "--task",
            "main",
            "--task=2",
            "--seq",
            "2..5",
            "--first",
            "3",
            "run.patina",
        ]))
        .unwrap()
        {
            ParseResult::Trace(trace_cmd::TraceInvocation::Events(events)) => {
                assert_eq!(events.path, PathBuf::from("run.patina"));
                assert_eq!(events.timeline, "main");
                assert!(events.filters.op_kinds.contains("fs_write"));
                assert!(
                    events
                        .filters
                        .categories
                        .contains(&trace_view::Category::Net)
                );
                assert!(events.filters.tasks.contains(&trace_view::LaneKey::Main));
                assert!(events.filters.tasks.contains(&trace_view::LaneKey::Task(2)));
                assert_eq!(events.filters.seq, Some((2, 5)));
                assert_eq!(events.filters.first, Some(3));
            }
            _ => panic!("expected trace events"),
        }

        assert!(
            parse_error(&["trace", "events", "--kind", "nope", "run.patina"])
                .contains("unknown --kind token")
        );
        assert!(
            parse_error(&[
                "trace",
                "events",
                "--first",
                "1",
                "--last",
                "1",
                "run.patina",
            ])
            .contains("mutually exclusive")
        );
        match parse(strings(&["trace", "stats", "run.patina", "--timeline=b2"])).unwrap() {
            ParseResult::Trace(trace_cmd::TraceInvocation::Stats(stats)) => {
                assert_eq!(stats.path, PathBuf::from("run.patina"));
                assert_eq!(stats.timeline, "b2");
            }
            _ => panic!("expected trace stats"),
        }

        match parse(strings(&[
            "trace",
            "diff",
            "a.patina",
            "--context",
            "0",
            "b.patina",
            "--timeline",
            "main",
        ]))
        .unwrap()
        {
            ParseResult::Trace(trace_cmd::TraceInvocation::Diff(diff)) => {
                assert_eq!(diff.a, PathBuf::from("a.patina"));
                assert_eq!(diff.b, PathBuf::from("b.patina"));
                assert_eq!(diff.context, 0);
                assert_eq!(diff.timeline, "main");
            }
            _ => panic!("expected trace diff"),
        }

        assert!(
            parse_error(&["trace", "info", "--kind", "fs_write", "run.patina"])
                .contains("does not accept --kind")
        );
        assert!(
            parse_error(&["trace", "stats", "--first", "1", "run.patina"])
                .contains("does not accept --first")
        );
        assert!(parse_error(&["trace", "diff", "a.patina"]).contains("second trace"));
    }

    /// Parse the index payload (`--help --format json`, overview topic).
    fn index_json() -> serde_json::Value {
        serde_json::from_str(&help::render_json(help::Topic::Overview))
            .expect("index help JSON parses")
    }

    /// Parse a verb's scoped payload (`<verb> --help --format json`).
    fn verb_json(name: &'static str) -> serde_json::Value {
        serde_json::from_str(&help::render_json(help::Topic::Verb(name)))
            .expect("verb help JSON parses")
    }

    #[test]
    fn json_index_lists_every_verb_without_flag_groups() {
        let json = index_json();
        assert_eq!(json["schema"], help::HELP_SCHEMA);
        // The env protocol and global flags live in the index.
        assert!(json["environment"].is_array(), "index carries environment");
        assert!(
            json["global_flags"]["flags"].is_array(),
            "index carries global flags"
        );
        // A machine-readable pointer to per-verb detail, with a substitutable
        // {verb} template.
        let template = json["verb_detail"]["command_template"]
            .as_str()
            .expect("verb_detail.command_template is a string");
        assert!(
            template.contains("{verb}") && template.contains("--format json"),
            "command_template should be a substitutable per-verb command: {template}"
        );
        // Every registered verb appears with a summary + forms but NO flag_groups
        // (the index is a directory, not a flag dump).
        let verbs = json["verbs"].as_object().expect("verbs object");
        assert_eq!(
            verbs.len(),
            help::VERBS.len(),
            "index verb count matches the registry"
        );
        for verb in help::VERBS {
            let entry = &verbs[verb.name];
            assert_eq!(
                entry["summary"], verb.summary,
                "index summary for {}",
                verb.name
            );
            assert!(
                entry["forms"].is_array(),
                "index carries {} forms",
                verb.name
            );
            assert!(
                entry.get("flag_groups").is_none(),
                "index must NOT carry flag_groups for {}",
                verb.name
            );
        }
    }

    #[test]
    fn json_verb_scope_carries_only_that_verbs_detail() {
        // Class-shaped: walk the registry. Each verb's scoped payload names that
        // verb, carries its own flag_groups and global flags, and leaks neither
        // the environment block nor any other verb's entry.
        for verb in help::VERBS {
            let json = verb_json(verb.name);
            assert_eq!(json["schema"], help::HELP_SCHEMA, "{} schema", verb.name);
            assert_eq!(json["verb"]["name"], verb.name, "verb name");
            assert_eq!(json["verb"]["summary"], verb.summary, "verb summary");
            assert!(
                json["verb"]["flag_groups"].is_array(),
                "{} carries flag_groups",
                verb.name
            );
            assert_eq!(
                json["verb"]["flag_groups"].as_array().unwrap().len(),
                verb.groups.len(),
                "{} flag_groups count matches the registry",
                verb.name
            );
            assert!(
                json["global_flags"]["flags"].is_array(),
                "{} carries global flags",
                verb.name
            );
            // Scoping: no top-level `verbs` map and no environment block.
            assert!(
                json.get("verbs").is_none(),
                "{} scoped payload must not carry the verbs index",
                verb.name
            );
            assert!(
                json.get("environment").is_none(),
                "{} scoped payload must not carry the environment block",
                verb.name
            );
            // The verb's own flags are present; a DIFFERENT verb's unique flag is
            // not. `run`'s `--mount` (re-supplying a host corpus) is unique to
            // run/replay, so it never appears in, say, `build`'s payload.
            // Deliberately NOT `--harness`: `campaign` forwards that one to its
            // child runs and registers it too, so it would not be a probe of
            // leakage.
            let names = flag_names(&json["verb"]["flag_groups"]);
            if verb.name != "run" && verb.name != "replay" {
                assert!(
                    !names.contains("--mount"),
                    "{}'s payload leaked run's unique --mount flag",
                    verb.name
                );
            }
        }
        // Positive: run's payload does contain its unique flag.
        let run = verb_json("run");
        assert!(
            flag_names(&run["verb"]["flag_groups"]).contains("--mount"),
            "run's payload should contain its own --mount flag"
        );
    }

    #[test]
    fn json_flag_omits_default_valued_fields() {
        // `--release` (build) is a valueless, non-repeatable switch with no short
        // form: only name/value_kind/doc survive; the default-valued keys are gone.
        let build = verb_json("build");
        let release = find_flag(&build["verb"]["flag_groups"], "--release")
            .expect("build registers --release");
        assert_eq!(release["value_kind"], "none");
        for absent in [
            "short",
            "placeholder",
            "value_grammar",
            "choices",
            "repeatable",
        ] {
            assert!(
                release.get(absent).is_none(),
                "--release should omit default-valued `{absent}`, got {release}"
            );
        }
        // `--output` (build) has a short form and a required value: those keys are
        // present, but `repeatable` (false) is still omitted.
        let output =
            find_flag(&build["verb"]["flag_groups"], "--output").expect("build registers --output");
        assert_eq!(output["short"], "-o");
        assert_eq!(output["value_kind"], "required");
        assert_eq!(output["placeholder"], "PATH");
        assert!(
            output.get("repeatable").is_none(),
            "non-repeatable --output should omit `repeatable`"
        );
        // A repeatable flag emits `repeatable: true`; a `--param` is repeatable.
        let run = verb_json("run");
        let param =
            find_flag(&run["verb"]["flag_groups"], "--param").expect("run registers --param");
        assert_eq!(param["repeatable"], true);
        // An enum-valued flag emits its choices; `--format` (global) is native|json.
        let format = find_flag(&run["global_flags"], "--format").expect("global --format");
        assert_eq!(format["value_grammar"], "enum");
        assert!(
            format["choices"].as_array().is_some(),
            "an enum flag lists its choices"
        );
    }

    /// The set of flag `name`s across an array of `{title, flags}` groups (or a
    /// single such group object).
    fn flag_names(groups_or_group: &serde_json::Value) -> BTreeSet<String> {
        let mut names = BTreeSet::new();
        collect_flags(groups_or_group, &mut |flag| {
            if let Some(name) = flag["name"].as_str() {
                names.insert(name.to_string());
            }
        });
        names
    }

    /// The first flag object named `name` across an array of groups or a single
    /// `{title, flags}` group.
    fn find_flag(groups_or_group: &serde_json::Value, name: &str) -> Option<serde_json::Value> {
        let mut found = None;
        collect_flags(groups_or_group, &mut |flag| {
            if found.is_none() && flag["name"].as_str() == Some(name) {
                found = Some(flag.clone());
            }
        });
        found
    }

    /// Invoke `visit` on every flag object inside an array of `{title, flags}`
    /// groups or a single such group.
    fn collect_flags(
        groups_or_group: &serde_json::Value,
        visit: &mut dyn FnMut(&serde_json::Value),
    ) {
        let groups: Vec<&serde_json::Value> = match groups_or_group {
            serde_json::Value::Array(groups) => groups.iter().collect(),
            single => vec![single],
        };
        for group in groups {
            if let Some(flags) = group["flags"].as_array() {
                for flag in flags {
                    visit(flag);
                }
            }
        }
    }

    // ---- Value-grammar drift gate (registry Kind <-> real parsers) ----

    /// Valid and invalid sample values for a registry value grammar. Every valid
    /// sample must parse through the real verb parser that owns the flag; every
    /// invalid sample must be rejected (a usage error, never a panic or silent
    /// acceptance). The samples are the intersection-safe set for every flag of a
    /// kind: a valid `PositiveU64` stays small so it also satisfies `--seeds`'
    /// tighter `1..=1000000` bound, and a valid `U64` never triggers `--seed-start`
    /// overflow (its driver pins `--seeds 1`). A `Path`/`Str` grammar accepts any
    /// string, so it has no invalid samples.
    fn kind_samples(kind: help::Kind) -> (Vec<&'static str>, Vec<&'static str>) {
        use help::Kind;
        match kind {
            Kind::U64 => (
                vec!["0", "1", "42", "18446744073709551615"],
                vec!["-1", "abc", "", "1.5", "99999999999999999999999"],
            ),
            Kind::U32 => (
                vec!["0", "1", "4294967295"],
                vec!["-1", "abc", "", "4294967296"],
            ),
            Kind::Usize => (vec!["0", "1", "65536"], vec!["-1", "abc", ""]),
            Kind::PositiveU64 => (vec!["1", "5", "100"], vec!["0", "-1", "abc", ""]),
            Kind::Permille => (
                vec!["0", "1", "250", "1000"],
                vec!["1001", "2000", "-1", "abc", ""],
            ),
            Kind::NanosRange => (
                vec!["0..0", "0..1000", "5..10", "0..18446744073709551615"],
                vec!["0:1000", "abc", "", "10..5", "0..", "..5", "5", "0..abc"],
            ),
            Kind::U64Range => (
                vec!["0..0", "0..1000", "5..10", "0..18446744073709551615"],
                vec!["0:1000", "abc", "", "10..5", "0..", "..5", "5", "0..abc"],
            ),
            Kind::OpKindList => (
                vec!["fs_write", "network", "fs_write,net_send", "clock,entropy"],
                vec!["unknown_op", "", "fs_write,", ",network", "NETWORK"],
            ),
            Kind::TaskSelector => (vec!["main", "0", "1", "42"], vec!["-1", "abc", ""]),
            Kind::CrashSpec => (
                vec![
                    "open", "write", "sync", "close", "open:1", "write:3", "close:10",
                ],
                vec!["read", "", "open:0", "open:abc", "open:", ":3", "OPEN"],
            ),
            Kind::KeyValue => (
                vec!["k=v", "key=", "a=b=c", "x=1"],
                vec!["=v", "novalue", "", "= "],
            ),
            Kind::DnsEntry => (
                vec!["db.internal=10.0.0.5", "a=0.0.0.0", "x=255.255.255.255"],
                vec![
                    "=10.0.0.5",
                    "db.internal",
                    "db.internal=",
                    "db.internal=10.0.0",
                    "db.internal=10.0.0.256",
                    "db.internal=example.com",
                    "",
                ],
            ),
            Kind::AddressPair => (
                vec!["a,b", "10.0.0.1:80,10.0.0.2:80", "left, right"],
                vec!["a", "a,", ",b", "a,b,c", "", "a,a", " , "],
            ),
            Kind::Socket => (
                vec!["4=a->b", "5=x->y", "100=addr1->addr2"],
                vec!["3=a->b", "4=a->", "4=->b", "foo=a->b", "4=ab", "", "0=a->b"],
            ),
            Kind::Preopen => (
                vec!["/data", "/data:ro", "/data:rw", "rel", "/a/b"],
                vec!["", "/data:xx", ":ro"],
            ),
            Kind::UnsupportedSymbols => (
                vec!["all", "memcpy", "a,b", "foo , bar"],
                vec!["", ",", " , "],
            ),
            Kind::Enum(choices) => (choices.to_vec(), vec!["bogus", ""]),
            Kind::Symbol => (vec!["memcpy", "foo_bar", "x"], vec![""]),
            Kind::Path => (vec!["/tmp/x", "out.html", "x"], vec![""]),
            Kind::Str => (vec!["x", "hello", ""], vec![]),
        }
    }

    // Family-parser drivers. Each feeds an argument list to the real per-family
    // parser exactly as routing would, with a leading binary/module label where
    // the parser strips one, so a sample exercises the true value validation.

    /// The syntactic form a flag drive renders — the registry's arity decides
    /// which forms must parse, so the generic tests exercise every form of every
    /// flag rather than a hand-picked sample.
    #[derive(Clone, Copy)]
    enum FlagForm<'a> {
        /// `--flag=VALUE` — valid for required- and optional-value flags alike.
        Inline,
        /// `--flag VALUE` — a required-value flag consumes the next token; an
        /// optional-value flag must NOT (the sample lands as a stray positional).
        Spaced,
        /// `-x VALUE` — the registry short, space form.
        Short(&'a str),
        /// `--flag=A --flag=B` — rejected (`set_once`) unless registry-repeatable.
        Repeated(&'a str),
    }

    /// Drive `args` through the real parser of `verb`'s `family`, supplying the
    /// context that family's routing would already have consumed: the
    /// positionals it takes, and the companion flags a successful parse needs
    /// (a native harness needs a target and a test filter; a branch replay needs
    /// its whole quorum).
    ///
    /// This is the ONLY hand-written table left in the walk, and it is keyed by
    /// family rather than by flag — twenty entries that change when a family
    /// is added, not sixty that change when a flag is. Which flags to drive
    /// comes from the registry ([`help::Verb::family_flags`]), so a new flag is
    /// exercised in every family that accepts it without touching this file.
    fn drive_family(
        verb: &str,
        family: help::Family,
        flag: &str,
        args: &[&str],
    ) -> Result<(), CliError> {
        // A companion the parse needs but the flag under test does not supply.
        let unless = |name: &'static str, tokens: &[&'static str]| -> Vec<String> {
            if flag == name {
                Vec::new()
            } else {
                tokens.iter().map(|t| t.to_string()).collect()
            }
        };
        // The branch quorum is all-or-nothing and conflicts with `--timeline`, so
        // it is supplied only when the flag under test is part of it.
        let quorum = |names: &[&'static str]| -> Vec<String> {
            if !names.contains(&flag) && flag != "--parent" {
                return Vec::new();
            }
            names
                .iter()
                .filter(|name| **name != flag)
                .map(|name| match *name {
                    "--branch" => "--branch".to_string(),
                    "--from" => "--from=0".to_string(),
                    "--branch-seed" => "--branch-seed=1".to_string(),
                    other => format!("{other}=b"),
                })
                .collect()
        };
        let with = |prefix: Vec<String>, suffix: &[&str]| -> Vec<OsString> {
            prefix
                .iter()
                .map(String::as_str)
                .chain(args.iter().copied())
                .chain(suffix.iter().copied())
                .map(OsString::from)
                .collect()
        };
        let none: Vec<String> = Vec::new();
        let prebuilt = |name: &str| ArtifactRef::Prebuilt(PathBuf::from(name));
        let trace = || PathBuf::from("t.patina");
        match (verb, family) {
            ("run" | "test", help::Family::Cargo) => {
                parse_cargo(verb.to_string(), with(none, &[])).map(|_| ())
            }
            ("run", help::Family::Wasi) => {
                parse_wasi_run_from(prebuilt("m.wasm"), with(none, &[])).map(|_| ())
            }
            ("run", help::Family::Native) => {
                parse_native_run_from(prebuilt("bin"), with(none, &[])).map(|_| ())
            }
            ("test", help::Family::Harness) => {
                let mut prefix = unless("--harness-target", &["--harness-target=harness"]);
                prefix.extend(unless("--exact", &["--exact=module::test"]));
                parse_native_harness_from(
                    PathBuf::from("."),
                    PathBuf::from("Cargo.toml"),
                    with(prefix, &[]),
                )
                .map(|_| ())
            }
            ("build", help::Family::Native) => {
                // A single-source build needs an output; a package build is what
                // `--package`/`--bin` select.
                let prefix = if matches!(flag, "--package" | "--bin") {
                    vec!["sub/Cargo.toml".to_string()]
                } else {
                    let mut prefix = vec!["x.rs".to_string()];
                    prefix.extend(unless("--output", &["--output=/tmp/o"]));
                    prefix
                };
                parse_native_build(with(prefix, &[])).map(|_| ())
            }
            ("build", help::Family::Wasi) => {
                parse_wasi_build(with(vec!["sub/Cargo.toml".to_string()], &[])).map(|_| ())
            }
            ("audit", help::Family::Native) => {
                parse_native_audit_from(prebuilt("bin"), with(none, &[])).map(|_| ())
            }
            ("audit", help::Family::Wasi) => {
                cli::parse("audit", family, with(none, &[])).map(|_| ())
            }
            ("replay", help::Family::Cargo) => parse_cargo_replay(
                PathBuf::from("."),
                trace(),
                with(
                    quorum(&["--branch", "--from", "--branch-seed", "--branch-id"]),
                    &[],
                ),
            )
            .map(|_| ()),
            ("replay", help::Family::Wasi) => parse_wasi_replay(
                prebuilt("m.wasm"),
                trace(),
                with(
                    quorum(&["--branch", "--from", "--branch-seed", "--branch-id"]),
                    &[],
                ),
            )
            .map(|_| ()),
            ("replay", help::Family::Native) => {
                parse_native_replay(prebuilt("bin"), trace(), with(none, &[])).map(|_| ())
            }
            // `--seed-start` pins `--seeds 1` so a max-u64 start never overflows
            // the swept range.
            ("explore", _) => {
                parse_explore(with(unless("--seeds", &["--seeds=1"]), &["test"])).map(|_| ())
            }
            // A continuation takes no artifact; every other campaign flag needs
            // one. `--spec` reads its file while parsing, so the driver makes
            // whatever path the sample names a readable empty spec — otherwise
            // the drive would fail for a reason that is not the grammar's.
            ("campaign", _) => {
                let prefix = if matches!(flag, "--extend" | "--resume") {
                    none
                } else {
                    vec!["art.wasm".to_string()]
                };
                let mut argv = with(prefix, &[]);
                if flag == "--spec" {
                    // `--spec` reads its file while parsing, so a non-empty
                    // sampled path is redirected to a real empty spec in a temp
                    // dir. What is under test is the grammar, not the
                    // filesystem — and nothing is written into the source tree.
                    // An EMPTY value is left alone: it is the invalid sample and
                    // must still be rejected.
                    let dir = tempfile::tempdir().expect("tempdir");
                    let real = dir.path().join("spec.json");
                    std::fs::write(&real, b"{}").expect("write spec");
                    let real = real.display().to_string();
                    let mut after_spec = false;
                    for token in &mut argv {
                        let text = token.to_string_lossy().into_owned();
                        match text.strip_prefix("--spec=") {
                            Some(value) if !value.is_empty() => {
                                *token = OsString::from(format!("--spec={real}"));
                            }
                            _ if after_spec && !text.is_empty() => {
                                *token = OsString::from(&real);
                            }
                            _ => {}
                        }
                        after_spec = text == "--spec";
                    }
                    return campaign::parse(argv).map(|_| ());
                }
                campaign::parse(argv).map(|_| ())
            }
            ("coverage", _) => coverage::parse(with(
                vec!["guest".to_string(), "run.covmap".to_string()],
                &[],
            ))
            .map(|_| ()),
            ("sites", _) => sites::parse(with(none, &[])).map(|_| ()),
            ("minimize", help::Family::Sole) => {
                let mut prefix = vec!["t.patina".to_string()];
                prefix.extend(unless("--output", &["--output=/tmp/o"]));
                parse_minimize(with(prefix, &["--", "oracle"])).map(|_| ())
            }
            ("minimize", help::Family::Generation) => {
                let mut prefix = unless("--generation", &["--generation=1"]);
                prefix.extend(unless("--marker", &["--marker=boom"]));
                parse_minimize(with(prefix, &[])).map(|_| ())
            }
            ("minimize", help::Family::Scenario) => {
                let mut prefix = vec!["--scenario".to_string()];
                prefix.extend(unless("--seed", &["--seed=0"]));
                parse_minimize(with(prefix, &["--", "oracle"])).map(|_| ())
            }
            ("trace", help::Family::Diff) => parse_trace(with(
                vec![
                    "diff".to_string(),
                    "a.patina".to_string(),
                    "b.patina".to_string(),
                ],
                &[],
            ))
            .map(|_| ()),
            ("trace", subcommand) => parse_trace(with(
                vec![subcommand.tag().to_string(), "t.patina".to_string()],
                &[],
            ))
            .map(|_| ()),
            (verb, family) => panic!("no driver for `{verb}` family {family:?}"),
        }
    }

    /// Parse a single flag with `value`, rendered in `form`, through the family
    /// parser under test, prefixing whatever the registry says the flag is inert
    /// without.
    fn drive_flag(
        verb: &str,
        family: help::Family,
        flag: &'static help::Flag,
        value: &str,
        form: FlagForm<'_>,
    ) -> Result<(), CliError> {
        let rendered: Vec<String> = match form {
            FlagForm::Inline => vec![format!("{}={value}", flag.name)],
            FlagForm::Spaced => vec![flag.name.to_string(), value.to_string()],
            FlagForm::Short(short) => vec![short.to_string(), value.to_string()],
            FlagForm::Repeated(second) => vec![
                format!("{}={value}", flag.name),
                format!("{}={second}", flag.name),
            ],
        };
        // A dependent knob is refused without its parent, so supply the parent in
        // whichever form it takes: an optional-value switch is armed bare, while a
        // required-value parent (`--fingerprint` needs `--record PATH`) needs a
        // sample of its own kind, taken from the registry rather than hardcoded.
        let parent = flag.requires.map(|name| {
            let parent = help::verb(verb)
                .expect("registered verb")
                .family_flags(family)
                .find(|candidate| candidate.name == name)
                .unwrap_or_else(|| {
                    panic!(
                        "`{verb}` flag `{}` requires unregistered `{name}`",
                        flag.name
                    )
                });
            match parent.value.grammar() {
                Some(kind) => format!(
                    "{name}={}",
                    kind_samples(kind).0.first().expect("a valid sample")
                ),
                None => name.to_string(),
            }
        });
        let mut tokens: Vec<&str> = parent.iter().map(String::as_str).collect();
        tokens.extend(rendered.iter().map(String::as_str));
        drive_family(verb, family, flag.name, &tokens)
    }

    /// A verb may not redeclare a global flag. The global output/config switches
    /// are stripped by a pre-pass BEFORE any verb routing, so a verb that
    /// registers the same name can never be reached — and if the two declare
    /// different arities, the pre-pass also eats the following token.
    ///
    /// This is a shipped bug pinned as a class: `campaign --report` was
    /// documented and unreachable, because the global `--report OUT.html`
    /// consumed both it and whatever came next.
    /// A Cargo-family replay refuses a semantic knob by name instead of handing
    /// it to Cargo: the trace is authoritative, and silently forwarding
    /// `--fs-crash-at` would surface as a confusing cargo error rather than the
    /// reason the knob is not accepted.
    #[test]
    fn cargo_replay_refuses_semantic_knobs_rather_than_forwarding_them() {
        for flag in ["--fs-crash-at", "--seed", "--buggify", "--sched-pct"] {
            let argv = vec![
                OsString::from(flag),
                OsString::from("close"),
                OsString::from("--example"),
                OsString::from("demo"),
            ];
            let Err(error) =
                parse_cargo_replay(PathBuf::from("."), PathBuf::from("t.patina"), argv)
            else {
                panic!("{flag} should be refused, not forwarded to Cargo");
            };
            let message = error.to_string();
            assert!(
                message.contains(flag) && message.contains("trace is authoritative"),
                "{flag}: {message}"
            );
        }
    }

    /// The Cargo family forwards every unrecognized token verbatim, in place,
    /// including one that is not valid UTF-8 — such a token can never be a
    /// Patina flag, and dropping or re-encoding it would corrupt a legitimate
    /// cargo argument (a path under a non-UTF-8 locale). The `--` section is
    /// the guest's and is passed through whole, so a `--seed` after it stays a
    /// guest argument.
    #[cfg(unix)]
    #[test]
    fn cargo_passthrough_preserves_order_and_non_utf8_tokens() {
        use std::os::unix::ffi::OsStringExt;
        let raw = OsString::from_vec(vec![b'-', b'-', b'p', b'=', 0xff, 0xfe]);
        let forwarded = [
            OsString::from("--manifest-path"),
            OsString::from("./x/Cargo.toml"),
            raw.clone(),
            OsString::from("--example"),
            OsString::from("demo"),
            OsString::from("--"),
            OsString::from("--seed=99"),
        ];
        let mut argv = vec![
            OsString::from("--manifest-path"),
            OsString::from("./x/Cargo.toml"),
        ];
        argv.push(OsString::from("--seed=7"));
        argv.extend(forwarded[2..].iter().cloned());

        let ParseResult::Run(invocation) = parse_cargo("run".to_string(), argv).unwrap() else {
            panic!("expected a Cargo-family run");
        };
        assert_eq!(invocation.mode, Mode::Seeded { seed: 7 });
        assert_eq!(
            invocation.cargo_args,
            forwarded.to_vec(),
            "forwarded tokens keep their order and bytes; only the Patina flag is taken"
        );
    }

    #[test]
    fn no_verb_redeclares_a_global_flag() {
        let globals: BTreeSet<&str> = help::GLOBAL_OUTPUT
            .iter()
            .chain(help::HELP_FLAGS.iter())
            .flat_map(|flag| [Some(flag.name), flag.short])
            .flatten()
            .collect();
        for verb in help::VERBS {
            for flag in verb.groups.iter().flat_map(|group| group.flags.iter()) {
                for name in [Some(flag.name), flag.short].into_iter().flatten() {
                    assert!(
                        !globals.contains(name),
                        "verb `{}` registers `{name}`, which the global pre-pass strips before \
                         routing — the verb's flag is unreachable",
                        verb.name
                    );
                }
            }
        }
    }

    /// Every family a group claims is one the verb declares, and every family a
    /// verb declares owns at least one flag. Without this a typo in a group's
    /// `families` would silently drop flags from a parser (they would simply
    /// stop being accepted) rather than failing loudly.
    #[test]
    fn registry_families_are_declared_and_populated() {
        for verb in help::VERBS {
            let declared: BTreeSet<help::Family> =
                verb.families.iter().map(|spec| spec.family).collect();
            for group in verb.groups {
                for family in group
                    .families
                    .iter()
                    .chain(group.flags.iter().filter_map(|f| f.families).flatten())
                {
                    assert!(
                        declared.contains(family),
                        "verb `{}` group {:?} claims undeclared family {family:?}",
                        verb.name,
                        group.title
                    );
                }
            }
            for spec in verb.families {
                assert!(
                    verb.family_flags(spec.family).next().is_some(),
                    "verb `{}` declares family {:?} but no flag reaches it",
                    verb.name,
                    spec.family
                );
            }
        }
    }

    #[test]
    fn every_report_knob_is_documented_in_the_environment_registry() {
        // Same drift gate as the fault knobs, for the report suppressors: the
        // registry is what `--help` and the JSON index publish, so a report the
        // runtime can silence but the registry never names is a working knob
        // nobody can discover — and an undocumented knob is the first step back
        // toward one family carrying it and the rest dropping it.
        let documented: String = help::ENVIRONMENT
            .iter()
            .map(|entry| entry.name)
            .collect::<Vec<_>>()
            .join(" ");
        for report in patina_dst_runtime::Report::ALL {
            assert!(
                documented.contains(report.env()),
                "{} has no row in the help environment registry",
                report.env()
            );
        }
    }

    #[test]
    fn knob_table_covers_every_registry_fault_flag() {
        // The drift gate behind `FaultKnob`: every knob the registry declares has
        // a variant, so every family's plumbing carries it. Without this, a knob
        // can be parsed by one family and silently dropped on the way to the
        // guest — the silent-inertness class, which looks exactly like a clean
        // run. Compared in ORDER, not as a set: `FaultKnob::ALL` order is what
        // the control plane and the re-emitted command line follow, and the
        // registry is where that order is decided.
        let table: Vec<&str> = FaultKnob::ALL.iter().map(|knob| knob.meta().flag).collect();
        let registry: Vec<&str> = help::fault_flag_names().collect();
        assert_eq!(
            registry, table,
            "every registry fault flag needs a FaultKnob variant, in registry order (and vice versa)"
        );
    }

    /// The error arm in `repeatable_payload` must be dead: every knob the table
    /// marks repeatable has an encoder, and every knob it marks scalar is
    /// filtered out before one is asked for. A knob switched to
    /// `Plumbing::Repeatable` without an encoder fails here rather than at the
    /// first invocation that sets it.
    #[test]
    fn every_repeatable_knob_has_an_encoder() {
        let mut repeatable = 0;
        for knob in FaultKnob::ALL {
            let sample = vec![knob_sample(*knob).to_string()];
            match knob.meta().plumbing {
                Plumbing::Repeatable => {
                    repeatable += 1;
                    repeatable_payload(*knob, &sample)
                        .unwrap_or_else(|error| panic!("{knob:?} has no encoder: {error}"));
                }
                Plumbing::Scalar => assert!(
                    repeatable_payload(*knob, &sample).is_err(),
                    "{knob:?} is scalar but answered to a repeatable payload"
                ),
            }
        }
        assert!(repeatable > 0, "no repeatable knobs left to prove anything");
    }

    /// A sample value of the right grammar for each knob, so the family and
    /// round-trip gates below can drive every knob off `FaultKnob::ALL` instead
    /// of a hand-kept list that a new knob can be left out of.
    fn knob_sample(knob: FaultKnob) -> &'static str {
        match knob {
            FaultKnob::FsCrashAt => "write:2",
            FaultKnob::FsTornGranularity => "byte",
            FaultKnob::NetLatencyNanos | FaultKnob::EpochJumpNanos => "500",
            FaultKnob::NetTcpBufferBytes => "4096",
            FaultKnob::NetPartition => "a,b",
            FaultKnob::DnsEntry => "svc=10.0.0.9",
            FaultKnob::FsLatencyNanos
            | FaultKnob::SleepJitterNanos
            | FaultKnob::NetJitterNanos
            | FaultKnob::DnsLatencyNanos => "10..20",
            FaultKnob::FsErrorPermille
            | FaultKnob::FsShortPermille
            | FaultKnob::NetDropPermille
            | FaultKnob::NetDuplicatePermille
            | FaultKnob::NetConnectRefusePermille
            | FaultKnob::NetResetPermille
            | FaultKnob::DnsFailPermille
            | FaultKnob::EntropyFailPermille => "100",
        }
    }

    #[test]
    fn every_fault_knob_reaches_every_family_and_is_refused_by_replay() {
        // Each knob, set to a valid value, must survive parsing into the same
        // control-plane variable for the Cargo, WASI and native families, and must
        // be REFUSED by `replay` — which derives its refusal list from the same
        // registry slice, so a new knob is refused the day it is registered.
        for knob in FaultKnob::ALL {
            let meta = knob.meta();
            let flag = meta.flag;
            let value = knob_sample(*knob);
            // A repeatable knob's variable carries the ENCODED set, not the raw
            // text, so the expected payload comes from the same encoder the
            // forwarding path uses.
            let expected = match meta.plumbing {
                Plumbing::Scalar => value.to_string(),
                Plumbing::Repeatable => repeatable_payload(*knob, &[value.to_string()])
                    .expect("every repeatable knob encodes its sample"),
            };
            for (verb, family) in [
                ("run", help::Family::Cargo),
                ("run", help::Family::Wasi),
                ("run", help::Family::Native),
                ("test", help::Family::Cargo),
                ("test", help::Family::Harness),
            ] {
                // wasip1 has no name-resolution surface at all, so the DNS knobs
                // are a DECLARED family exception: the WASI parser must refuse
                // them rather than accept a knob that could never fire. The
                // registry narrows them, so this asks the registry rather than
                // hard-coding which flags are excepted.
                if !help::verb(verb)
                    .expect("registered verb")
                    .family_flags(family)
                    .any(|registered| registered.name == flag)
                {
                    assert!(
                        cli::parse(verb, family, strings(&[flag, value])).is_err(),
                        "{verb} {family:?} must refuse the unregistered {flag}"
                    );
                    continue;
                }
                let args = cli::parse(verb, family, strings(&[flag, value]))
                    .unwrap_or_else(|error| panic!("{verb} {family:?} rejected {flag}: {error}"));
                let pairs = knob_env_pairs(&knobs_of(&args).expect("knob parse")).expect("encode");
                assert!(
                    pairs.contains(&(meta.env, expected.clone())),
                    "{verb} {family:?} did not carry {flag} to {}: {pairs:?}",
                    meta.env
                );
            }
            for family in [
                help::Family::Cargo,
                help::Family::Wasi,
                help::Family::Native,
            ] {
                let message = match cli::parse("replay", family, strings(&[flag, value])) {
                    Err(error) => error.to_string(),
                    Ok(_) => panic!("replay accepted a re-supplied {flag}"),
                };
                assert!(
                    message.contains(flag) && message.contains("the trace is authoritative"),
                    "replay refusal for {flag} should explain itself: {message}"
                );
            }
        }
    }

    #[test]
    fn the_native_harness_re_emits_every_fault_knob_it_parsed() {
        // Native harness mode runs each seed as a child `run`, so a knob it
        // parsed but did not re-emit is silently inert — the shape the
        // hand-maintained forwarding list had for the Wave B fs knobs, and the
        // shape the historical `--dns-entry` bug had (advertised by the harness
        // family, never forwarded to its child `run`). Every registered knob,
        // repeatable ones included, must survive the round trip.
        let mut tokens: Vec<OsString> = Vec::new();
        for knob in FaultKnob::ALL {
            tokens.push(OsString::from(knob.meta().flag));
            tokens.push(OsString::from(knob_sample(*knob)));
        }

        let args = cli::parse("test", help::Family::Harness, tokens).expect("harness parse");
        let invocation = NativeHarnessInvocation {
            origin: PathBuf::new(),
            manifest: PathBuf::new(),
            package: None,
            harness_target: "t".into(),
            exact: "m::t".into(),
            seeds: HarnessSeeds::One(0),
            release: false,
            yield_points: false,
            step_budget: Some(9),
            knobs: knobs_of(&args).expect("harness knob parse"),
            buggify: None,
            schedule: NativeSchedule::default(),
            liveness: NativeLiveness::default(),
        };
        let mut emitted: Vec<OsString> = Vec::new();
        append_native_harness_run_flags(&mut emitted, &invocation);
        for knob in FaultKnob::ALL {
            let flag = knob.meta().flag;
            let value = knob_sample(*knob);
            let at = emitted
                .iter()
                .position(|token| token == flag)
                .unwrap_or_else(|| {
                    panic!("native harness dropped {flag} on the way to its child run")
                });
            assert_eq!(
                emitted.get(at + 1).map(OsString::as_os_str),
                Some(OsStr::new(value)),
                "native harness re-emitted {flag} without its value"
            );
        }
        assert!(emitted.iter().any(|token| token == "--budget"));
    }

    #[test]
    fn wasi_run_forwards_every_registered_fault_knob() {
        // WASI's `run` has no child process to re-emit onto — it applies fault
        // knobs to the in-process runtime through `knob_env_pairs` — but the same
        // silent-drop class applies: a knob the registry gives the WASI family
        // that `parse_wasi_run`/`knob_env_pairs` fails to carry through to the
        // control-plane pairs would leave that family's faults inert with nothing
        // to notice, the shape the historical `--net-partition` bug had for WASI.
        // Driven off `FaultKnob::ALL` and the registry's own family list (never a
        // hand-kept one), so a future knob is covered the day it is registered,
        // and the DNS knobs (which WASI's parser refuses outright) are skipped
        // because the registry says so, not because this test hard-codes it.
        let registered: Vec<FaultKnob> = FaultKnob::ALL
            .iter()
            .copied()
            .filter(|knob| {
                help::verb("run")
                    .expect("registered verb")
                    .family_flags(help::Family::Wasi)
                    .any(|flag| flag.name == knob.meta().flag)
            })
            .collect();
        assert!(
            !registered.is_empty(),
            "no fault knobs registered for the WASI family — the filter is wrong"
        );
        let mut tokens: Vec<OsString> = vec![OsString::from("guest.wasm")];
        for knob in &registered {
            tokens.push(OsString::from(knob.meta().flag));
            tokens.push(OsString::from(knob_sample(*knob)));
        }
        let invocation = parse_wasi_run(tokens).expect("wasi run parse");
        let pairs = knob_env_pairs(&invocation.knobs).expect("encode");
        for knob in &registered {
            let meta = knob.meta();
            let expected = match meta.plumbing {
                Plumbing::Scalar => knob_sample(*knob).to_string(),
                Plumbing::Repeatable => {
                    repeatable_payload(*knob, &[knob_sample(*knob).to_string()])
                        .expect("every repeatable knob encodes its sample")
                }
            };
            assert!(
                pairs.contains(&(meta.env, expected.clone())),
                "WASI run dropped {} on the way to {}: {pairs:?}",
                meta.flag,
                meta.env
            );
        }
    }

    #[test]
    fn registry_value_grammars_match_the_parsers() {
        // The generic drift gate: every registered value-bearing flag's declared
        // `help::Kind` is exercised against the REAL parser that consumes it, in
        // both directions. Valid samples of the kind must parse; invalid samples
        // must be rejected. A parser that tightens or loosens a value grammar
        // without updating the registry kind (or a kind that does not match parser
        // reality) fails here — the general form of the `--sleep-jitter-nanos
        // 0:N` vs `0..N` regression, for every flag at once.

        // Global output options are parsed once, before routing, by output::extract.
        // Both value forms must work here too (the uniform-value-syntax rule).
        for flag in help::GLOBAL_OUTPUT {
            let Some(kind) = flag.value.grammar() else {
                continue;
            };
            let (valid, invalid) = kind_samples(kind);
            for sample in valid {
                for args in [
                    vec![format!("{}={sample}", flag.name)],
                    vec![flag.name.to_string(), sample.to_string()],
                ] {
                    let args: Vec<&str> = args.iter().map(String::as_str).collect();
                    output::extract(strings(&args)).unwrap_or_else(|error| {
                        panic!(
                            "global `{}` rejected valid {sample:?} as {args:?}: {error}",
                            flag.name
                        )
                    });
                }
            }
            for sample in invalid {
                let arg = format!("{}={sample}", flag.name);
                assert!(
                    output::extract(strings(&[&arg])).is_err(),
                    "global `{}` accepted invalid {sample:?}",
                    flag.name
                );
            }
        }

        // Every per-verb flag, driven through its owning family parser, in every
        // registry-implied form: inline `=` always; the space form must parse for
        // required-value flags and must NOT consume the token for optional-value
        // flags (the sample lands as a stray positional and the parse fails); a
        // declared short takes the space form.
        for verb in help::VERBS {
            for spec in verb.families {
                let mut seen: BTreeSet<&str> = BTreeSet::new();
                for flag in verb.family_flags(spec.family) {
                    let Some(kind) = flag.value.grammar() else {
                        continue;
                    };
                    if !seen.insert(flag.name) {
                        continue;
                    }
                    let (valid, invalid) = kind_samples(kind);
                    for sample in &valid {
                        let drive = |form: FlagForm<'_>| {
                            drive_flag(verb.name, spec.family, flag, sample, form)
                        };
                        drive(FlagForm::Inline).unwrap_or_else(|error| {
                            panic!(
                                "verb `{}` flag `{}` ({kind:?}) rejected VALID sample {sample:?}: \
                             {error}",
                                verb.name, flag.name
                            )
                        });
                        match flag.value {
                            help::Value::Required(..) => {
                                drive(FlagForm::Spaced).unwrap_or_else(|error| {
                                    panic!(
                                        "verb `{}` flag `{}` rejected the space form of valid \
                                     {sample:?}: {error}",
                                        verb.name, flag.name
                                    )
                                });
                                if let Some(short) = flag.short {
                                    drive(FlagForm::Short(short)).unwrap_or_else(|error| {
                                    panic!(
                                        "verb `{}` flag `{}` rejected short `{short}` with valid \
                                         {sample:?}: {error}",
                                        verb.name, flag.name
                                    )
                                });
                                }
                            }
                            help::Value::Optional(..) => {
                                assert!(
                                    drive(FlagForm::Spaced).is_err(),
                                    "verb `{}` optional-value flag `{}` CONSUMED the space-form \
                                 token {sample:?} (optional values are `=`-only)",
                                    verb.name,
                                    flag.name
                                );
                            }
                            help::Value::None => unreachable!("grammar() returned Some"),
                        }
                    }
                    for sample in &invalid {
                        for form in [FlagForm::Inline, FlagForm::Spaced] {
                            // The space form only reaches the value validator on
                            // required-value flags.
                            if matches!(form, FlagForm::Spaced)
                                && !matches!(flag.value, help::Value::Required(..))
                            {
                                continue;
                            }
                            let outcome = drive_flag(verb.name, spec.family, flag, sample, form);
                            assert!(
                                outcome.is_err(),
                                "verb `{}` family {:?} flag `{}` ({kind:?}) ACCEPTED invalid \
                             sample {sample:?}",
                                verb.name,
                                spec.family,
                                flag.name
                            );
                        }
                    }
                }
            }
        }
    }

    /// The registry's `repeatable` field must match the parsers: a repeatable
    /// value flag accepts two occurrences; a non-repeatable one rejects them
    /// (`set_once`'s "provided more than once"). Scope is value-bearing flags —
    /// a repeated bare switch is idempotent and harmless by construction.
    #[test]
    fn registry_repeatable_flags_match_the_parsers() {
        for flag in help::GLOBAL_OUTPUT {
            let Some(kind) = flag.value.grammar() else {
                continue;
            };
            let (valid, _) = kind_samples(kind);
            let first = valid[0];
            let second = valid.get(1).copied().unwrap_or(first);
            let args = [
                format!("{}={first}", flag.name),
                format!("{}={second}", flag.name),
            ];
            let args: Vec<&str> = args.iter().map(String::as_str).collect();
            let outcome = output::extract(strings(&args)).map(|_| ());
            assert_eq!(
                outcome.is_ok(),
                flag.repeatable,
                "global `{}` repeat behavior does not match registry repeatable={}: {outcome:?}",
                flag.name,
                flag.repeatable
            );
        }
        for verb in help::VERBS {
            for spec in verb.families {
                let mut seen: BTreeSet<&str> = BTreeSet::new();
                for flag in verb.family_flags(spec.family) {
                    let Some(kind) = flag.value.grammar() else {
                        continue;
                    };
                    if !seen.insert(flag.name) {
                        continue;
                    }
                    let (valid, _) = kind_samples(kind);
                    let first = valid[0];
                    let second = valid.get(1).copied().unwrap_or(first);
                    let outcome = drive_flag(
                        verb.name,
                        spec.family,
                        flag,
                        first,
                        FlagForm::Repeated(second),
                    );
                    assert_eq!(
                        outcome.is_ok(),
                        flag.repeatable,
                        "verb `{}` family {:?} flag `{}` repeat behavior does not match \
                         registry repeatable={}: {outcome:?}",
                        verb.name,
                        spec.family,
                        flag.name,
                        flag.repeatable
                    );
                }
            }
        }
    }

    // ---- Phase 2: renames, uniform value syntax, fail-closed positionals ----

    #[test]
    fn explore_seed_start_replaces_start() {
        // The new spelling sets the range start.
        match parse(strings(&["explore", "test", "--seed-start=5"])).unwrap() {
            ParseResult::Explore(exploration) => assert_eq!(exploration.start_seed, 5),
            _ => panic!("expected exploration"),
        }
        // The old `--start` is no longer an explore flag; it forwards to the
        // wrapped command, so the range start falls back to the default (0).
        match parse(strings(&["explore", "test", "--start", "5"])).unwrap() {
            ParseResult::Explore(exploration) => assert_eq!(exploration.start_seed, 0),
            _ => panic!("expected exploration"),
        }
    }

    #[test]
    fn inline_arg_passes_a_literal_help_token() {
        // `--arg=--help` delivers a literal `--help` to the WASI guest argv; the
        // inline form is the only way, since a bare `--help` before `--` is
        // intercepted as Patina help (see `help_is_intercepted_for_every_verb`).
        let inv = parse_wasi_run(strings(&["m.wasm", "--arg=--help", "--arg", "tail"])).unwrap();
        assert_eq!(
            inv.arguments,
            vec!["--help".to_string(), "tail".to_string()]
        );
    }

    #[test]
    fn nonexistent_pathlike_positional_fails_closed() {
        // A token that clearly names a file path but does not exist is a hard
        // error, not a silent cargo-family fallthrough.
        assert!(classify_arg(OsStr::new("nonexistent.wasm")).is_err());
        assert!(classify_arg(OsStr::new("missing.rs")).is_err());
        assert!(classify_arg(OsStr::new("sub/dir/thing")).is_err());
        assert!(classify_arg(OsStr::new("no/such/Cargo.toml")).is_err());
        // A bare name (no extension, no separator) stays a cargo argument.
        assert!(matches!(
            classify_arg(OsStr::new("mycrate")).unwrap(),
            ArgKind::Other
        ));
        // Routed through the verbs.
        assert!(parse(strings(&["run", "nope.wasm"])).is_err());
        assert!(parse(strings(&["audit", "nope.wasm"])).is_err());
        assert!(parse(strings(&["replay", "nope.wasm", "trace"])).is_err());
    }

    #[test]
    fn version_intercepted_across_verbs_before_separator() {
        for verb in [
            "run", "test", "build", "audit", "replay", "explore", "campaign", "minimize",
            "coverage", "sites", "trace",
        ] {
            assert!(
                matches!(
                    parse(strings(&[verb, "--version"])),
                    Ok(ParseResult::Version)
                ),
                "{verb} --version"
            );
            assert!(
                matches!(parse(strings(&[verb, "-V"])), Ok(ParseResult::Version)),
                "{verb} -V"
            );
        }
        assert!(matches!(
            parse(strings(&["--version"])),
            Ok(ParseResult::Version)
        ));
        // After `--` it belongs to the guest and is not intercepted.
        assert!(!matches!(
            parse(strings(&["run", "mycrate", "--", "--version"])),
            Ok(ParseResult::Version)
        ));
    }

    // ---- Options may precede the artifact (cargo-run/cargo-build ergonomics) ----

    /// A real WASI module on disk (recognized by its `\0asm` magic at routing).
    fn wasm_fixture(dir: &tempfile::TempDir, name: &str) -> PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, b"\0asm\x01\0\0\0").unwrap();
        path
    }

    /// A real native binary on disk (recognized by its ELF magic at routing).
    fn native_fixture(dir: &tempfile::TempDir, name: &str) -> PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, [0x7f, b'E', b'L', b'F', 2, 1, 1, 0]).unwrap();
        path
    }

    fn native_seed(mode: &NativeRunMode) -> Option<u64> {
        match mode {
            NativeRunMode::Seeded { seed } | NativeRunMode::Record { seed, .. } => Some(*seed),
            NativeRunMode::Replay { .. } => None,
        }
    }

    /// The message of a top-level `parse` that must fail (`ParseResult` is not
    /// `Debug`, so `unwrap_err` cannot be used directly).
    fn parse_error(values: &[&str]) -> String {
        match parse(strings(values)) {
            Err(error) => error.to_string(),
            Ok(_) => panic!("expected a usage error for {values:?}"),
        }
    }

    #[test]
    fn run_locates_a_wasi_artifact_around_options() {
        let dir = tempfile::tempdir().unwrap();
        let module = wasm_fixture(&dir, "m.wasm");
        let m = module.to_str().unwrap();
        let wasi = |values: &[&str]| match parse(strings(values)).unwrap() {
            ParseResult::WasiRun(inv) => inv,
            _ => panic!("expected a WASI run"),
        };
        // Baseline: the artifact leads.
        let base = wasi(&["run", m, "--seed", "5", "--fuel", "128"]);
        // Every ordering with the same registered flags parses identically.
        assert_eq!(base, wasi(&["run", "--seed", "5", "--fuel", "128", m])); // both after
        assert_eq!(base, wasi(&["run", "--seed=5", "--fuel=128", m])); // equals form
        assert_eq!(base, wasi(&["run", "--seed", "5", m, "--fuel", "128"])); // interleaved
        // After a valueless registered switch the module + mode + fuel are unchanged
        // (only the buggify field differs).
        let switched = wasi(&[
            "run",
            "--buggify-after-setup",
            "--fuel",
            "128",
            "--seed",
            "5",
            m,
        ]);
        assert_eq!(switched.module, base.module);
        assert_eq!(switched.mode, base.mode);
        assert_eq!(switched.fuel, base.fuel);
    }

    #[test]
    fn run_locates_a_native_artifact_around_options() {
        let dir = tempfile::tempdir().unwrap();
        let binary = native_fixture(&dir, "app");
        let b = binary.to_str().unwrap();
        let native = |values: &[&str]| match parse(strings(values)).unwrap() {
            ParseResult::NativeRun(inv) => inv,
            _ => panic!("expected a native run"),
        };
        // `--fingerprint` labels a recording, so it rides with `--record` (a seeded
        // run refuses it; see
        // `fingerprint_on_a_seeded_native_run_is_refused_not_ignored`).
        let base = native(&[
            "run",
            b,
            "--seed",
            "5",
            "--record",
            "t.patina",
            "--fingerprint",
            "fp",
        ]);
        for spelling in [
            &[
                "run",
                "--seed",
                "5",
                "--record",
                "t.patina",
                "--fingerprint",
                "fp",
                b,
            ][..],
            &[
                "run",
                "--seed=5",
                "--record=t.patina",
                "--fingerprint=fp",
                b,
            ][..],
            &[
                "run",
                "--fingerprint",
                "fp",
                b,
                "--seed",
                "5",
                "--record",
                "t.patina",
            ][..],
        ] {
            let got = native(spelling);
            assert_eq!(got.binary, base.binary);
            assert_eq!(native_seed(&got.mode), native_seed(&base.mode));
        }
        // Interleaved artifact between semantic flags, record mode.
        match native(&["run", "--seed", "5", b, "--record", "t.patina"]).mode {
            NativeRunMode::Record { seed, path, .. } => {
                assert_eq!(seed, 5);
                assert_eq!(path, PathBuf::from("t.patina"));
            }
            _ => panic!("expected record mode"),
        }
    }

    /// `--fingerprint` is only ever read back off a recorded trace: the seeded
    /// native path sets no `PATINA_FINGERPRINT` at all, so a label supplied there
    /// could never be compared against anything. It is refused instead of quietly
    /// discarded, so "I pinned this run to a build" cannot be believed of a run
    /// that pinned nothing.
    #[test]
    fn fingerprint_on_a_seeded_native_run_is_refused_not_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let binary = native_fixture(&dir, "app");
        let b = binary.to_str().unwrap();
        let Err(error) = parse(strings(&["run", b, "--seed", "5", "--fingerprint", "fp"])) else {
            panic!("a seeded run must refuse a fingerprint it cannot record");
        };
        let text = format!("{error}");
        assert!(text.contains("--record"), "{text}");

        // With a recording the same label is accepted and carried into the trace.
        match parse(strings(&[
            "run",
            b,
            "--seed",
            "5",
            "--record",
            "t.patina",
            "--fingerprint",
            "fp",
        ]))
        .unwrap()
        {
            ParseResult::NativeRun(inv) => match inv.mode {
                NativeRunMode::Record { fingerprint, .. } => assert_eq!(fingerprint, "fp"),
                _ => panic!("expected record mode"),
            },
            _ => panic!("expected a native run"),
        }

        // A seeded run without the flag is untouched.
        assert!(matches!(
            parse(strings(&["run", b, "--seed", "5"])).unwrap(),
            ParseResult::NativeRun(NativeRunInvocation {
                mode: NativeRunMode::Seeded { seed: 5 },
                ..
            })
        ));
    }

    #[test]
    fn audit_locates_a_native_artifact_around_options() {
        let dir = tempfile::tempdir().unwrap();
        let binary = native_fixture(&dir, "app");
        let b = binary.to_str().unwrap();
        let audit = |values: &[&str]| match parse(strings(values)).unwrap() {
            ParseResult::NativeAudit(inv) => inv,
            _ => panic!("expected a native audit"),
        };
        let base = audit(&["audit", b, "--allow", "foo"]);
        for spelling in [
            &["audit", "--allow", "foo", b][..], // `audit --allow foo ./bin`
            &["audit", "--allow=foo", b][..],
        ] {
            let got = audit(spelling);
            assert_eq!(got.binary, base.binary);
            assert_eq!(got.allow, base.allow);
            assert_eq!(got.raw, base.raw);
        }
    }

    #[test]
    fn replay_locates_two_positionals_around_options_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let binary = native_fixture(&dir, "app");
        let b = binary.to_str().unwrap();
        // A flag leads the two positionals; their order (binary then trace) holds.
        match parse(strings(&["replay", "--fingerprint", "f", b, "run.patina"])).unwrap() {
            ParseResult::NativeRun(inv) => {
                assert_eq!(inv.binary, ArtifactRef::Prebuilt(PathBuf::from(b)));
                match inv.mode {
                    NativeRunMode::Replay { path, fingerprint } => {
                        assert_eq!(path, PathBuf::from("run.patina"));
                        assert_eq!(fingerprint, "f");
                    }
                    _ => panic!("expected replay mode"),
                }
            }
            _ => panic!("expected a native run from replay"),
        }
        // Interleaved keeps binary-then-trace order.
        match parse(strings(&["replay", b, "--fingerprint", "f", "run.patina"])).unwrap() {
            ParseResult::NativeRun(inv) => {
                assert_eq!(inv.binary, ArtifactRef::Prebuilt(PathBuf::from(b)));
                assert!(matches!(inv.mode, NativeRunMode::Replay { .. }));
            }
            _ => panic!("expected a native run"),
        }
    }

    #[test]
    fn conservative_stop_keeps_unknown_flag_runs_in_the_cargo_family() {
        // `--bin` is registered (source-first selection), so its value `server` is
        // skipped by the scan: no artifact, Cargo family.
        assert!(matches!(
            parse(strings(&["run", "--bin", "server"])).unwrap(),
            ParseResult::Run(_)
        ));
        assert!(matches!(
            parse(strings(&["run", "--seed", "5", "--bin", "server"])).unwrap(),
            ParseResult::Run(_)
        ));
        // An UNKNOWN flag stops the scan; `thing.wasm` after it is path-like but does
        // NOT exist, so it is presumed the unknown flag's value (never an artifact)
        // and the run stays the Cargo family.
        assert!(matches!(
            parse(strings(&[
                "run",
                "--seed",
                "5",
                "--some-unknown",
                "thing.wasm"
            ]))
            .unwrap(),
            ParseResult::Run(_)
        ));
        // A forwarded cargo flag with a (nonexistent) manifest value, no artifact
        // token present: the whole list forwards to Cargo.
        assert!(matches!(
            parse(strings(&["run", "--manifest-path", "./x/Cargo.toml"])).unwrap(),
            ParseResult::Run(_)
        ));
        // `--release` is not a `run` flag; with no artifact it is a forwarded cargo
        // flag (like `cargo run --release`), and the run stays the Cargo family.
        match parse(strings(&["run", "--release", "--seed", "5"])).unwrap() {
            ParseResult::Run(inv) => {
                assert_eq!(inv.mode, Mode::Seeded { seed: 5 });
                assert!(inv.cargo_args.iter().any(|a| a == "--release"));
            }
            _ => panic!("expected a Cargo-family run"),
        }
    }

    #[test]
    fn run_fails_closed_on_a_nonexistent_artifact_after_leading_options() {
        // The motivating fix: `--seed 5` is registered and skipped, so the scan
        // reaches `nonexistent.wasm` — a path-like token that does not exist — and
        // fails closed rather than falling through to a confusing `cargo run`.
        let err = parse_error(&["run", "--seed", "5", "nonexistent.wasm"]);
        assert!(err.contains("no such file"), "{err}");
    }

    #[test]
    fn run_rejects_a_real_artifact_stranded_behind_an_unknown_flag() {
        let dir = tempfile::tempdir().unwrap();
        let module = wasm_fixture(&dir, "app.wasm");
        let m = module.to_str().unwrap();
        // `--frob` is unknown and `app.wasm` is a real compiled artifact (never a
        // flag value): a loud routing error naming both, never a silent Cargo
        // fallthrough.
        let message = parse_error(&["run", "--frob", m]);
        assert!(message.contains("--frob"), "{message}");
        assert!(message.contains(m), "{message}");
    }

    #[test]
    fn artifact_scan_never_crosses_the_double_dash_separator() {
        // Everything after `--` is the guest/cargo tail; an artifact-looking token
        // there is never scanned as the artifact, so no fail-closed "no such file".
        match parse(strings(&["run", "--seed", "5", "--", "nonexistent.wasm"])).unwrap() {
            ParseResult::Run(inv) => {
                assert_eq!(inv.cargo_args, strings(&["--", "nonexistent.wasm"]));
            }
            _ => panic!("expected a Cargo-family run"),
        }
    }

    /// The message of a `build` parse that must fail (parse_build's `Ok` variant
    /// is not `Debug`, so `unwrap_err` cannot be used directly).
    fn build_error(values: &[&str]) -> String {
        match parse_build(strings(values)) {
            Err(error) => error.to_string(),
            Ok(_) => panic!("expected a build usage error for {values:?}"),
        }
    }

    #[test]
    fn build_locates_the_path_after_options_and_names_bad_flags() {
        // `build --release <pkg>`: the path follows the flag, like `cargo build`.
        match parse_build(strings(&["--release", "pkg"])).unwrap() {
            ParseResult::NativeBuild(inv) => {
                assert!(inv.release);
                assert!(matches!(inv.target, NativeBuildTarget::Package { .. }));
            }
            _ => panic!("expected a native build"),
        }
        // A stray value on the valueless `--release` is a usage error naming the
        // flag, never a bogus `--release=x/Cargo.toml` manifest path.
        let err = build_error(&["--release=x"]);
        assert!(err.contains("--release"), "{err}");
        assert!(err.contains("'x'"), "{err}");
        // An unknown flag is a usage error naming it (not a manifest-path failure).
        assert!(build_error(&["--nonsense"]).contains("--nonsense"));
    }

    #[test]
    fn minimize_locates_the_trace_after_options() {
        // `minimize --output out.patina trace.patina -- oracle`: the trace follows
        // the option, like the other verbs (previously the option was mistaken for
        // the trace path).
        match parse(strings(&[
            "minimize",
            "--output",
            "out.patina",
            "trace.patina",
            "--",
            "oracle",
        ]))
        .unwrap()
        {
            ParseResult::Minimize(minimize::MinimizeInvocation::Trace(trace)) => {
                assert_eq!(trace.trace, PathBuf::from("trace.patina"));
                assert_eq!(trace.output, PathBuf::from("out.patina"));
                assert_eq!(trace.oracle, strings(&["oracle"]));
            }
            _ => panic!("expected a trace minimization"),
        }
    }
}
