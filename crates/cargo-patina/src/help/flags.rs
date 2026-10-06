//! Shared CLI flag groups.

use super::*;

// ===========================================================================
// Shared flag groups
// ===========================================================================

/// Output options, parsed once globally (before routing) and honored by every
/// verb. Documented in the overview and appended to each verb section.
pub const GLOBAL_OUTPUT: &[Flag] = &[
    f(
        "--format",
        None,
        Value::Required("human|json", Kind::Enum(&["human", "json"])),
        "Result format (default human). `json` prints one machine-readable result envelope (schema patina.result/v1) on stdout; `coverage --format json` prints patina.coverage/v1, and `trace events --format json` is the streaming exception and prints patina.trace.events/v1 JSON Lines. `--help --format json` prints this registry as JSON.",
        false,
    ),
    f(
        "--render",
        None,
        Value::Required("OUT.html", Kind::Path),
        "For a run/replay with a trace, write a self-contained HTML timeline to OUT.html.",
        false,
    ),
    f(
        "--report",
        None,
        Value::Required("OUT.html", Kind::Path),
        "Like --render but only when the run fails; the HTML leads with a failure summary.",
        false,
    ),
    f(
        "--no-config",
        None,
        Value::None,
        "Ignore .patina/config.toml for this invocation (PATINA_* environment defaults still apply).",
        false,
    ),
];

pub const HELP_FLAGS: &[Flag] = &[
    f(
        "--help",
        Some("-h"),
        Value::None,
        "Print help (accepted anywhere before `--`).",
        false,
    ),
    f(
        "--version",
        Some("-V"),
        Value::None,
        "Print version and the pinned virtual Linux kernel.",
        false,
    ),
];

pub(super) const TARGET_FLAG: Flag = f(
    "--target",
    None,
    Value::Required("native|wasi", Kind::Enum(&["native", "wasi"])),
    "Select the family for a source/package argument (default native); stripped before routing.",
    false,
);

pub(super) const SOURCE_SELECT: &[Flag] = &[
    f(
        "--package",
        Some("-p"),
        Value::Required("NAME", Kind::Str),
        "Select a workspace member to build on the fly.",
        false,
    ),
    f(
        "--bin",
        None,
        Value::Required("NAME", Kind::Str),
        "Select the binary when the package defines more than one.",
        false,
    ),
    TARGET_FLAG,
];

pub(super) const FAULT_FLAGS: &[Flag] = &[
    f(
        "--fs-crash-at",
        None,
        Value::Required("SPEC", Kind::CrashSpec),
        "Native only: after the Nth successful fs boundary op, terminate the process and restart once from the recovered filesystem; records and replays across both incarnations: open|write|sync|close[:N] (bare = :1).",
        false,
    ),
    f(
        "--fs-torn-granularity",
        None,
        Value::Required("block|byte", Kind::Enum(&["block", "byte"])),
        "Torn-write granularity for --fs-crash-at: block (default) or byte.",
        false,
    ),
    f(
        "--fs-error-permille",
        None,
        Value::Required("N", Kind::Permille),
        "Fail eligible fs ops at N per-mille with a seeded errno (EIO/ENOSPC/EINTR per op).",
        false,
    ),
    f(
        "--fs-short-permille",
        None,
        Value::Required("N", Kind::Permille),
        "Truncate fs reads/writes at N per-mille (short I/O, ≥1 byte).",
        false,
    ),
    f(
        "--fs-latency-nanos",
        None,
        Value::Required("MIN..MAX", Kind::NanosRange),
        "Add seeded latency drawn from [MIN, MAX] to every fault-eligible fs op, before it runs.",
        false,
    ),
    f(
        "--sleep-jitter-nanos",
        None,
        Value::Required("MIN..MAX", Kind::NanosRange),
        "Add seeded latency drawn from [MIN, MAX] to every guest sleep.",
        false,
    ),
    f(
        "--net-jitter-nanos",
        None,
        Value::Required("MIN..MAX", Kind::NanosRange),
        "Add seeded per-datagram delivery jitter drawn from [MIN, MAX].",
        false,
    ),
    f(
        "--net-drop-permille",
        None,
        Value::Required("N", Kind::Permille),
        "Drop datagrams at N per-mille (0..=1000).",
        false,
    ),
    f(
        "--net-latency-nanos",
        None,
        Value::Required("N", Kind::U64),
        "Base per-datagram/segment delivery latency in nanoseconds.",
        false,
    ),
    f(
        "--net-duplicate-permille",
        None,
        Value::Required("N", Kind::Permille),
        "Deliver datagrams twice at N per-mille (each copy draws its own jitter).",
        false,
    ),
    f(
        "--net-connect-refuse-permille",
        None,
        Value::Required("N", Kind::Permille),
        "Refuse otherwise-establishable TCP connections at N per-mille.",
        false,
    ),
    f(
        "--net-reset-permille",
        None,
        Value::Required("N", Kind::Permille),
        "Reset an established TCP stream at N per-mille per data operation (both directions).",
        false,
    ),
    f(
        "--net-partition",
        None,
        Value::Required("A,B", Kind::AddressPair),
        "Partition two virtual addresses from each other, both directions (repeatable).",
        true,
    ),
    f(
        "--net-tcp-buffer-bytes",
        None,
        Value::Required("N", Kind::Usize),
        "Virtual TCP receive-buffer size; smaller values make would-block/partial sends reachable.",
        false,
    ),
    f(
        "--entropy-fail-permille",
        None,
        Value::Required("N", Kind::Permille),
        "Fail guest entropy requests at N per-mille with a seeded named error instead of bytes.",
        false,
    ),
    f(
        "--epoch-jump-nanos",
        None,
        Value::Required("HI", Kind::U64),
        "Jump each realtime-epoch read by a seeded signed offset in [-HI, HI] nanoseconds (saturating at 0).",
        false,
    ),
    f(
        "--custom-op-fail-permille",
        None,
        Value::Required("N", Kind::Permille),
        "Fail guest custom operations that declared a failure shape at N per-mille, handing back that failure instead of running the operation.",
        false,
    ),
];

/// The DNS domain: the host table (semantic configuration, like `--param`) and
/// its two seeded fault knobs.
///
/// A slice of its own rather than rows in [`FAULT_FLAGS`], because wasip1 has no
/// name-resolution surface at all — no `getaddrinfo`, no `sock_addr_resolve` — so
/// the WASI parser must refuse these loudly instead of accepting knobs that could
/// never fire. That family exception is declared once, by the owning GROUP in
/// each verb, which is also the only place that can name families the verb
/// actually has.
/// The host table itself, split out because `campaign` takes it WITHOUT the fault
/// knobs: a campaign draws `--dns-fail-permille`/`--dns-latency-nanos` per
/// generation from the generation hash, so accepting them from the operator too
/// would be two authorities over one knob.
const DNS_ENTRY_FLAG: Flag = f(
    "--dns-entry",
    None,
    Value::Required("NAME=ADDR", Kind::DnsEntry),
    "Define NAME to resolve to IPv4 ADDR (repeatable). Undefined names are NXDOMAIN.",
    true,
);

pub(super) const DNS_ENTRY_FLAGS: &[Flag] = &[DNS_ENTRY_FLAG];

pub(super) const DNS_FLAGS: &[Flag] = &[
    DNS_ENTRY_FLAG,
    f(
        "--dns-fail-permille",
        None,
        Value::Required("N", Kind::Permille),
        "Fail resolutions of DEFINED names at N per-mille (seeded NXDOMAIN or timeout).",
        false,
    ),
    f(
        "--dns-latency-nanos",
        None,
        Value::Required("MIN..MAX", Kind::NanosRange),
        "Add seeded latency drawn from [MIN, MAX] to every resolution of a defined name.",
        false,
    ),
];

pub(super) const WASI_HOST_FLAGS: &[Flag] = &[
    f(
        "--fuel",
        None,
        Value::Required("N", Kind::U64),
        "Maximum wasm fuel (execution budget).",
        false,
    ),
    f(
        "--arg",
        None,
        Value::Required("VALUE", Kind::Str),
        "Append a guest argv entry (recorded and restored on replay).",
        true,
    ),
    f(
        "--env",
        None,
        Value::Required("K=V", Kind::KeyValue),
        "Set a guest environment variable.",
        true,
    ),
    f(
        "--socket",
        None,
        Value::Required("FD=BIND->PEER", Kind::Socket),
        "Configure a datagram socket at a unique FD above 3.",
        true,
    ),
    f(
        "--preopen",
        None,
        Value::Required("GUEST[:ro|:rw]", Kind::Preopen),
        "Preopen an absolute guest path (default rw; first explicit preopen replaces the implicit rw `/`).",
        true,
    ),
    f(
        "--max-memory-pages",
        None,
        Value::Required("N", Kind::U32),
        "Maximum guest memory pages (64 KiB each).",
        false,
    ),
    f(
        "--max-descriptors",
        None,
        Value::Required("N", Kind::Usize),
        "Maximum open WASI descriptors.",
        false,
    ),
    f(
        "--max-preopens",
        None,
        Value::Required("N", Kind::Usize),
        "Maximum configured preopened directories.",
        false,
    ),
    f(
        "--max-path-bytes",
        None,
        Value::Required("N", Kind::Usize),
        "Maximum bytes in a single guest path.",
        false,
    ),
    f(
        "--max-io-bytes",
        None,
        Value::Required("N", Kind::Usize),
        "Maximum bytes in one WASI I/O operation.",
        false,
    ),
    f(
        "--max-iovecs",
        None,
        Value::Required("N", Kind::Usize),
        "Maximum iovec entries in one WASI operation.",
        false,
    ),
];

pub(super) const BUGGIFY_FLAGS: &[Flag] = &[
    f(
        "--buggify",
        None,
        Value::Optional("PERMILLE", Kind::Permille),
        "Enable cooperative-SUT (buggify) fault injection; PERMILLE is the per-evaluation firing probability (default 250 = 25%).",
        false,
    ),
    f(
        "--buggify-activation-permille",
        None,
        Value::Required("N", Kind::Permille),
        "Fraction of buggify sites made active this run (default 250). Implies --buggify.",
        false,
    ),
    f(
        "--buggify-cutoff-nanos",
        None,
        Value::Required("N", Kind::U64),
        "Elapsed virtual nanoseconds since guest start after which buggify stops firing (default 300000000000). Implies --buggify.",
        false,
    ),
    f(
        "--buggify-after-setup",
        None,
        Value::None,
        "Buggify stays inert until the guest calls patina_dst::lifecycle::setup_complete(). Implies --buggify.",
        false,
    ),
];

pub(super) const COMPUTE_WATCHDOG_FLAG: Flag = f(
    "--compute-watchdog-ms",
    None,
    Value::Required("MS", Kind::WatchdogMillis),
    "Native call-free starvation bound in host milliseconds (1..=86400000; default 10000). Overrides PATINA_COMPUTE_WATCHDOG_MS; replay follows the recorded stop, not host time.",
    false,
);

pub(super) const LIVENESS_FLAGS_OPTIONAL: &[Flag] = &[
    f(
        "--liveness-watchdog",
        None,
        Value::Optional("NANOS", Kind::U64),
        "Arm a no-progress watchdog over virtual time (bare = runtime default budget).",
        false,
    ),
    f(
        "--converge-within",
        None,
        Value::Optional("NANOS", Kind::U64),
        "Require convergence within NANOS of the last injected fault (bare = default).",
        false,
    ),
    needs(
        f(
            "--heal-after",
            None,
            Value::Required("NANOS", Kind::U64),
            "Fault-free convergence arm-time in elapsed virtual nanoseconds since guest start; requires --converge-within.",
            false,
        ),
        "--converge-within",
    ),
];

pub(super) const NATIVE_SCHEDULE_FLAGS: &[Flag] = &[
    f(
        "--sched-pct",
        None,
        Value::Optional("N", Kind::PositiveU64),
        "PCT priority-scheduling exploration; N is the bug depth (>= 1).",
        false,
    ),
    needs(
        f(
            "--sched-pct-steps",
            None,
            Value::Required("N", Kind::PositiveU64),
            "Decision-space span the d-1 PCT change points are spread over (>= 1, default 2000). Requires --sched-pct.",
            false,
        ),
        "--sched-pct",
    ),
    f(
        "--starve",
        None,
        Value::Optional("N", Kind::PositiveU64),
        "Starvation exploration; N is the interval count (>= 1).",
        false,
    ),
    needs(
        f(
            "--starve-max-len",
            None,
            Value::Required("N", Kind::PositiveU64),
            "Maximum starvation run length (>= 1). Requires --starve.",
            false,
        ),
        "--starve",
    ),
    needs(
        f(
            "--starve-window",
            None,
            Value::Required("N", Kind::PositiveU64),
            "Starvation window (>= 1). Requires --starve.",
            false,
        ),
        "--starve",
    ),
    f(
        "--swarm",
        None,
        Value::None,
        "Seed-derived swarm selection of a fault-class subset.",
        false,
    ),
];

pub(super) const REPLAY_TIMELINE_FLAGS: &[Flag] = &[
    f(
        "--timeline",
        None,
        Value::Required("ID", Kind::Str),
        "Replay a named timeline (default main).",
        false,
    ),
    f(
        "--branch",
        None,
        Value::None,
        "Replay the parent prefix then append a new branch timeline.",
        false,
    ),
    f(
        "--from",
        None,
        Value::Required("N", Kind::U64),
        "Branch point sequence number. Requires --branch.",
        false,
    ),
    f(
        "--branch-seed",
        None,
        Value::Required("S", Kind::U64),
        "Seed for the appended branch. Requires --branch.",
        false,
    ),
    f(
        "--branch-id",
        None,
        Value::Required("ID", Kind::Str),
        "Id for the appended branch timeline. Requires --branch.",
        false,
    ),
    f(
        "--parent",
        None,
        Value::Required("ID", Kind::Str),
        "Parent timeline to branch from (default main). Requires --branch.",
        false,
    ),
];
