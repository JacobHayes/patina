//! CLI environment-variable registry.

use super::*;

/// The `PATINA_*` environment protocol and honored tool variables.
pub const ENVIRONMENT: &[EnvVar] = &[
    EnvVar {
        name: "PATINA_<FLAG>",
        scope: "user",
        doc: "Default for any CLI flag except --help/--version: PATINA_ plus the long name in upper snake case (--seed → PATINA_SEED, --seed-start → PATINA_SEED_START), shown as [env: …] beside each flag. A typed flag wins, then a non-empty variable, then the built-in default; an empty variable is unset. A switch reads 0/false/no/off/n/f as off and anything else as on. A variable defaults its flag only where that flag is accepted, and campaign and minimize children never inherit one: their flags are explicit.",
    },
    EnvVar {
        name: "PATINA_RT_*",
        scope: "protocol",
        doc: "The runtime's supervisor↔guest control plane, below. Set only by the supervisor: an inherited PATINA_RT_* is removed from every Cargo-family child, and a native guest starts from an empty environment.",
    },
    EnvVar {
        name: "PATINA_RT_SEED",
        scope: "user",
        doc: "The seed the runtime reads; a scenario-minimize oracle receives its candidate seed here. To seed a cargo-patina invocation use --seed (or PATINA_SEED).",
    },
    EnvVar {
        name: patina_dst_runtime::Report::ENV_NAMES,
        scope: "user",
        doc: "End-of-run diagnostics, all on by default; a false-y value (0/off/false/no) silences one, on every family. Presentation only: suppressing a report changes no recorded byte, so a quiet run and a loud one replay against each other. The structured run facts a campaign classifies do not depend on them.",
    },
    EnvVar {
        name: "PATINA_RT_PARAMS_JSON",
        scope: "user",
        doc: "Typed --param values as a JSON object (the scenario-minimize oracle protocol).",
    },
    EnvVar {
        name: "PATINA_CLI",
        scope: "user",
        doc: "Absolute path to the cargo-patina a `#[patina_dst::test]` launches under plain `cargo test` (default: cargo-patina on PATH).",
    },
    EnvVar {
        name: "PATINA_RT_MODE",
        scope: "protocol",
        doc: "Run mode (seeded/record/replay/branch); set by the supervisor for the guest.",
    },
    EnvVar {
        name: "PATINA_RT_TRACE",
        scope: "protocol",
        doc: "On-disk trace path for record/replay.",
    },
    EnvVar {
        name: "PATINA_RT_TRACE_FD",
        scope: "protocol",
        doc: "Inherited already-open trace descriptor (native), so a fully interposed guest never recurses into the deterministic FS while finalizing its trace.",
    },
    EnvVar {
        name: "PATINA_RT_COVERAGE_FD",
        scope: "protocol",
        doc: "Native coverage dump descriptor for --coverage-out.",
    },
    EnvVar {
        name: "PATINA_RT_FACTS",
        scope: "protocol",
        doc: "Path the runtime writes its patina.runfacts/v1 document to (cargo family). Set by --format json; the CLI folds the document into the envelope's fault_reports/runtime_findings.",
    },
    EnvVar {
        name: "PATINA_RT_FACTS_FD",
        scope: "protocol",
        doc: "Inherited descriptor carrying the same patina.runfacts/v1 document on the native family, so a fully interposed guest never writes it through the deterministic FS.",
    },
    EnvVar {
        name: "PATINA_RT_FS_IMAGE_FD",
        scope: "protocol",
        doc: "Inherited descriptor streaming the --mount host-directory image to the guest.",
    },
    EnvVar {
        name: "PATINA_RT_DEFER_INIT",
        scope: "protocol",
        doc: "Set for a patina-dst-harness binary (recognised by its embedded marker): defer runtime installation so the harness owns configure-then-run.",
    },
    EnvVar {
        name: "PATINA_RT_STEP_BUDGET",
        scope: "protocol",
        doc: "Maximum boundary operations (mirrors --budget).",
    },
    EnvVar {
        name: "PATINA_RT_FINGERPRINT",
        scope: "protocol",
        doc: "Compatibility fingerprint checked on replay.",
    },
    EnvVar {
        name: "PATINA_RT_EXPECTED_SUPERVISOR_SHA256",
        scope: "protocol",
        doc: "Digest of the cargo-patina that launched this one (campaign and reduction children); a cargo-patina of another build refuses before running anything.",
    },
    EnvVar {
        name: "PATINA_RT_TIMELINE / PATINA_RT_PARENT_TIMELINE / PATINA_RT_BRANCH_FROM / PATINA_RT_BRANCH_SEED / PATINA_RT_BRANCH_ID",
        scope: "protocol",
        doc: "Timeline and branch-append controls (mirror the replay --timeline/--branch flags).",
    },
    EnvVar {
        name: "PATINA_RT_GUEST_ARGV",
        scope: "protocol",
        doc: "Recorded guest argv restored on replay.",
    },
    EnvVar {
        name: "PATINA_RT_GUEST_ENV_JSON",
        scope: "protocol",
        doc: "Recorded native guest environment map from run --env, restored on replay.",
    },
    EnvVar {
        name: "PATINA_RT_GUEST_CWD",
        scope: "protocol",
        doc: "Recorded native guest initial working directory from run --cwd, restored on replay.",
    },
    EnvVar {
        name: "PATINA_RT_REALTIME_EPOCH_NANOS",
        scope: "protocol",
        doc: "Virtual realtime epoch in Unix-time nanoseconds (mirrors --realtime-epoch); recorded and restored on replay.",
    },
    EnvVar {
        name: "PATINA_RT_GUEST_HOSTNAME",
        scope: "protocol",
        doc: "Node name the guest's virtual kernel reports (mirrors --hostname); recorded and restored on replay.",
    },
    EnvVar {
        name: "PATINA_RT_GUEST_CPUS",
        scope: "protocol",
        doc: "The guest's virtual CPU count (mirrors native --cpus, default 4); recorded, supplied by replay from the trace, and refused when it disagrees.",
    },
    EnvVar {
        name: "PATINA_RT_MACHINE_CRASH_PERMILLE / PATINA_RT_PROCESS_CRASH_PERMILLE / PATINA_RT_FS_ERROR_PERMILLE / PATINA_RT_FS_ERROR_AT / PATINA_RT_FS_SHORT_PERMILLE",
        scope: "protocol",
        doc: "Crash, filesystem error, targeted error, and short-I/O fault knobs (mirror --machine-crash-permille, --process-crash-permille and the --fs-* flags).",
    },
    EnvVar {
        name: "PATINA_RT_SLEEP_JITTER_NANOS / PATINA_RT_NET_JITTER_NANOS / PATINA_RT_NET_DROP_PERMILLE / PATINA_RT_NET_LATENCY_NANOS",
        scope: "protocol",
        doc: "Seed-driven timing/network fault knobs (mirror the --*-nanos/--net-* flags).",
    },
    EnvVar {
        name: "PATINA_RT_ENTROPY_FAIL_PERMILLE",
        scope: "protocol",
        doc: "Seeded guest entropy-request failure knob (mirrors --entropy-fail-permille).",
    },
    EnvVar {
        name: "PATINA_RT_EPOCH_JUMP_NANOS",
        scope: "protocol",
        doc: "Seeded realtime-epoch jump knob (mirrors --epoch-jump-nanos).",
    },
    EnvVar {
        name: "PATINA_RT_CUSTOM_OP_FAIL_PERMILLE",
        scope: "protocol",
        doc: "Seeded guest custom-operation failure knob (mirrors --custom-op-fail-permille).",
    },
    EnvVar {
        name: "PATINA_RT_BUGGIFY / PATINA_RT_BUGGIFY_ACTIVATION_PERMILLE / PATINA_RT_BUGGIFY_CUTOFF_NANOS / PATINA_RT_BUGGIFY_AFTER_SETUP",
        scope: "protocol",
        doc: "Cooperative-SUT (buggify) knobs (mirror the --buggify* flags).",
    },
    EnvVar {
        name: "PATINA_RT_SCHED_PCT / PATINA_RT_SCHED_PCT_STEPS / PATINA_RT_SCHED_YIELD_STRIDE",
        scope: "protocol",
        doc: "Native scheduling exploration knobs (mirror --sched-pct/--yield-stride).",
    },
    EnvVar {
        name: "PATINA_RT_SWARM",
        scope: "protocol",
        doc: "Seed-derived swarm fault-class selection (mirrors --swarm).",
    },
    EnvVar {
        name: "PATINA_RT_LIVENESS_WATCHDOG_NANOS / PATINA_RT_CONVERGE_WITHIN_NANOS / PATINA_RT_HEAL_AFTER_NANOS",
        scope: "protocol",
        doc: "Liveness watchdog / convergence budgets (mirror --liveness-watchdog/--converge-within/--heal-after).",
    },
    EnvVar {
        name: "PATINA_RT_COMPUTE_WATCHDOG_MS",
        scope: "protocol",
        doc: "Native compute-only starvation stop: host milliseconds without boundary progress while another managed task is runnable or in a timed park (default 10000; 1..=86400000; mirrors --compute-watchdog-ms). Replay follows the recorded terminal boundary, not this timeout. This is a known runtime limit, not a guest bug.",
    },
    EnvVar {
        name: "CARGO / RUSTC / CC",
        scope: "tool",
        doc: "Override the cargo, rustc, and C compiler binaries (default cargo/rustc/cc).",
    },
    EnvVar {
        name: "RUSTFLAGS / CARGO_TARGET_DIR",
        scope: "tool",
        doc: "Honored as usual; Patina augments RUSTFLAGS via CARGO_ENCODED_RUSTFLAGS for package builds and uses CARGO_TARGET_DIR as the base for its namespaced shim staging.",
    },
    EnvVar {
        name: "PATINA_SHIM_TARGET_DIR",
        scope: "tool",
        doc: "The base for Patina's namespaced shim staging in place of CARGO_TARGET_DIR, which still holds the guest's own build: guests built in separate target dirs share one shim build.",
    },
];
