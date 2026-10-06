//! CLI environment-variable registry.

use super::*;

/// The `PATINA_*` environment protocol and honored tool variables.
pub const ENVIRONMENT: &[EnvVar] = &[
    EnvVar {
        name: "PATINA_SEED",
        scope: "user",
        doc: "Deterministic root seed (mirrors --seed; a scenario-minimize oracle receives its candidate seed here).",
    },
    EnvVar {
        name: "PATINA_<DEFAULT_KEY>",
        scope: "user",
        doc: "CLI default override for `.patina/config.toml` keys (for example PATINA_SEED, PATINA_GENERATIONS): explicit flags still win; campaign scrubs run-default env names from child runs.",
    },
    EnvVar {
        name: "PATINA_SCHEDULE_REPORT / PATINA_SCHEDULE_POLICY_REPORT / PATINA_SWARM_REPORT / PATINA_LIVENESS_REPORT / PATINA_SDK_REPORT / PATINA_FS_FAULT_REPORT / PATINA_DNS_FAULT_REPORT / PATINA_NET_FAULT_REPORT / PATINA_ENTROPY_FAULT_REPORT / PATINA_CLOCK_FAULT_REPORT / PATINA_CUSTOMOP_FAULT_REPORT / PATINA_COVERAGE_REPORT / PATINA_DEPTH_REPORT",
        scope: "user",
        doc: "End-of-run diagnostics, all on by default; a false-y value (0/off/false/no) silences one, on every family. Presentation only: suppressing a report changes no recorded byte, so a quiet run and a loud one replay against each other. A campaign pins them all on, since for a campaign they are classifier inputs rather than cosmetics.",
    },
    EnvVar {
        name: "PATINA_PARAMS_JSON",
        scope: "user",
        doc: "Typed --param values as a JSON object (the scenario-minimize oracle protocol).",
    },
    EnvVar {
        name: "PATINA_MINIMIZE_TRACE",
        scope: "user",
        doc: "Path to the candidate trace a trace-minimize oracle must judge; a non-zero exit means the failure is still present.",
    },
    EnvVar {
        name: "PATINA_MODE",
        scope: "protocol",
        doc: "Run mode (seeded/record/replay/branch); set by the supervisor for the guest.",
    },
    EnvVar {
        name: "PATINA_TRACE",
        scope: "protocol",
        doc: "On-disk trace path for record/replay.",
    },
    EnvVar {
        name: "PATINA_TRACE_FD",
        scope: "protocol",
        doc: "Inherited already-open trace descriptor (native), so a fully interposed guest never recurses into the deterministic FS while finalizing its trace.",
    },
    EnvVar {
        name: "PATINA_COVERAGE_FD",
        scope: "protocol",
        doc: "Native coverage dump descriptor for --coverage-out.",
    },
    EnvVar {
        name: "PATINA_FACTS",
        scope: "protocol",
        doc: "Path the runtime writes its patina.runfacts/v1 document to (cargo/WASI families). Set by --format json; the CLI folds the document into the envelope's fault_reports/runtime_findings.",
    },
    EnvVar {
        name: "PATINA_FACTS_FD",
        scope: "protocol",
        doc: "Inherited descriptor carrying the same patina.runfacts/v1 document on the native family, so a fully interposed guest never writes it through the deterministic FS.",
    },
    EnvVar {
        name: "PATINA_FS_IMAGE_FD",
        scope: "protocol",
        doc: "Inherited descriptor streaming the --mount host-directory image to the guest.",
    },
    EnvVar {
        name: "PATINA_DEFER_INIT",
        scope: "protocol",
        doc: "Set by --harness: defer runtime installation so the harness owns configure-then-run.",
    },
    EnvVar {
        name: "PATINA_STEP_BUDGET",
        scope: "protocol",
        doc: "Maximum boundary operations (mirrors --budget).",
    },
    EnvVar {
        name: "PATINA_FINGERPRINT",
        scope: "protocol",
        doc: "Compatibility fingerprint checked on replay.",
    },
    EnvVar {
        name: "PATINA_TIMELINE / PATINA_PARENT_TIMELINE / PATINA_BRANCH_FROM / PATINA_BRANCH_SEED / PATINA_BRANCH_ID",
        scope: "protocol",
        doc: "Timeline and branch-append controls (mirror the replay --timeline/--branch flags).",
    },
    EnvVar {
        name: "PATINA_GUEST_ARGV",
        scope: "protocol",
        doc: "Recorded guest argv restored on replay.",
    },
    EnvVar {
        name: "PATINA_GUEST_ENV_JSON",
        scope: "protocol",
        doc: "Recorded native guest environment map from run --env, restored on replay.",
    },
    EnvVar {
        name: "PATINA_GUEST_CWD",
        scope: "protocol",
        doc: "Recorded native guest initial working directory from run --cwd, restored on replay.",
    },
    EnvVar {
        name: "PATINA_REALTIME_EPOCH_NANOS",
        scope: "protocol",
        doc: "Virtual realtime epoch in Unix-time nanoseconds (mirrors --realtime-epoch); recorded and restored on replay.",
    },
    EnvVar {
        name: "PATINA_GUEST_HOSTNAME",
        scope: "protocol",
        doc: "Node name the guest's virtual kernel reports (mirrors --hostname); recorded and restored on replay.",
    },
    EnvVar {
        name: "PATINA_FS_CRASH_AT / PATINA_FS_TORN_GRANULARITY / PATINA_FS_ERROR_PERMILLE / PATINA_FS_SHORT_PERMILLE",
        scope: "protocol",
        doc: "Filesystem crash, error, and short-I/O fault knobs (mirror the --fs-* flags).",
    },
    EnvVar {
        name: "PATINA_SLEEP_JITTER_NANOS / PATINA_NET_JITTER_NANOS / PATINA_NET_DROP_PERMILLE / PATINA_NET_LATENCY_NANOS",
        scope: "protocol",
        doc: "Seed-driven timing/network fault knobs (mirror the --*-nanos/--net-* flags).",
    },
    EnvVar {
        name: "PATINA_ENTROPY_FAIL_PERMILLE",
        scope: "protocol",
        doc: "Seeded guest entropy-request failure knob (mirrors --entropy-fail-permille).",
    },
    EnvVar {
        name: "PATINA_EPOCH_JUMP_NANOS",
        scope: "protocol",
        doc: "Seeded realtime-epoch jump knob (mirrors --epoch-jump-nanos).",
    },
    EnvVar {
        name: "PATINA_CUSTOM_OP_FAIL_PERMILLE",
        scope: "protocol",
        doc: "Seeded guest custom-operation failure knob (mirrors --custom-op-fail-permille).",
    },
    EnvVar {
        name: "PATINA_BUGGIFY / PATINA_BUGGIFY_ACTIVATION_PERMILLE / PATINA_BUGGIFY_CUTOFF_NANOS / PATINA_BUGGIFY_AFTER_SETUP",
        scope: "protocol",
        doc: "Cooperative-SUT (buggify) knobs (mirror the --buggify* flags).",
    },
    EnvVar {
        name: "PATINA_SCHED_PCT / PATINA_SCHED_PCT_STEPS / PATINA_SCHED_STARVE / PATINA_SCHED_STARVE_MAX_LEN / PATINA_SCHED_STARVE_WINDOW",
        scope: "protocol",
        doc: "Native scheduling exploration knobs (mirror --sched-pct/--starve*). A wedged run is killed by the starvation stall backstop (exit 111).",
    },
    EnvVar {
        name: "PATINA_SWARM",
        scope: "protocol",
        doc: "Seed-derived swarm fault-class selection (mirrors --swarm).",
    },
    EnvVar {
        name: "PATINA_LIVENESS_WATCHDOG_NANOS / PATINA_CONVERGE_WITHIN_NANOS / PATINA_HEAL_AFTER_NANOS",
        scope: "protocol",
        doc: "Liveness watchdog / convergence budgets (mirror --liveness-watchdog/--converge-within/--heal-after).",
    },
    EnvVar {
        name: "PATINA_COMPUTE_WATCHDOG_MS",
        scope: "protocol",
        doc: "Native compute-only starvation stop: host milliseconds without boundary progress while another managed task is runnable (default 10000; 1..=86400000). Forwarded by native run/replay; --compute-watchdog-ms takes precedence. Replay follows the recorded terminal boundary, not this timeout. This is a known runtime limit, not a guest bug.",
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
];
