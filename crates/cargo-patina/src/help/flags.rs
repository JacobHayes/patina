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
        "Result format (default human). `json` prints one machine-readable result envelope (schema patina.result/v2) on stdout; `coverage --format json` prints patina.coverage/v1, `test --format json` prints patina.test/v1, and `trace events --format json` is the streaming exception and prints patina.trace.events/v1 JSON Lines. `--help --format json` prints this registry as JSON. Add --progress for progress lines on stderr while it runs.",
        false,
    ),
    f(
        "--progress",
        None,
        Value::None,
        "Under --format json, also stream progress on stderr as JSON Lines (schema patina.progress/v1) while `run`, `campaign` or `test` works: one object per event with `event` and `elapsed_secs`, e.g. a campaign's `generation` events with `done`, `target`, `failures` and `novel_signatures`. stdout still carries the one result. Human output shows its own progress either way.",
        false,
    ),
    f(
        "--render",
        None,
        Value::Required("OUT.html", Kind::Path),
        "Write a self-contained HTML timeline of a run or replay to OUT.html; a failed run's page leads with a failure summary.",
        false,
    ),
    f(
        "--verbose",
        Some("-v"),
        Value::None,
        "Also print Patina's own detail on stderr: the end-of-run reports of every plane, the pre-run notes and build lines. Without it a run prints the guest's output, a warning for a requested fault that never landed, and one result line; --format json carries the reports as `reports`.",
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
];

use patina_dst_runtime::{FaultKnob, Plumbing};

#[derive(Clone, Copy)]
enum KnobGroup {
    Fault,
    Dns,
}

// Every new runtime knob must declare its CLI grammar, prose and group here.
const fn knob_flag(knob: FaultKnob) -> (Flag, KnobGroup) {
    let (value, doc, group) = match knob {
        FaultKnob::MachineCrashPermille => (
            Value::Required("N", Kind::Permille),
            "Native only: take the machine down at N per-mille after each successful op a peer or the disk sees (fs write, sync, close, rename, unlink, ..., net send, TCP connect/accept/close). Only what the disk holds survives; the run restarts once from that image. Drawn before --process-crash-permille; records and replays across both incarnations.",
            KnobGroup::Fault,
        ),
        FaultKnob::ProcessCrashPermille => (
            Value::Required("N", Kind::Permille),
            "Native only: kill the process at N per-mille at each such op the machine survived. The page cache survives, so every completed write is kept; the run restarts once.",
            KnobGroup::Fault,
        ),
        FaultKnob::FsErrorPermille => (
            Value::Required("N", Kind::Permille),
            "Fail eligible fs ops at N per-mille with a seeded errno (EIO/ENOSPC/EINTR per op).",
            KnobGroup::Fault,
        ),
        FaultKnob::FsErrorAt => (
            Value::Required("KIND:N[:ERRNO]", Kind::FsErrorTarget),
            "Fail the Nth fault-eligible fs op of KIND (as the fs fault report names it: sync, sync_all, write, read_at, ...) with ERRNO (EIO, the default; ENOSPC, EINTR or ENOMEM where the op can fail so: ENOMEM is a procfs open or first read, the only error one has), whatever the seed (repeatable). A target that never landed makes the fs fault report vacuous.",
            KnobGroup::Fault,
        ),
        FaultKnob::FsShortPermille => (
            Value::Required("N", Kind::Permille),
            "Truncate fs reads/writes at N per-mille (short I/O, ≥1 byte).",
            KnobGroup::Fault,
        ),
        FaultKnob::FsLatencyNanos => (
            Value::Required("MIN..MAX", Kind::NanosRange),
            "Add seeded latency drawn from [MIN, MAX] to every fault-eligible fs op, before it runs.",
            KnobGroup::Fault,
        ),
        FaultKnob::SleepJitterNanos => (
            Value::Required("MIN..MAX", Kind::NanosRange),
            "Add seeded latency drawn from [MIN, MAX] to every guest sleep.",
            KnobGroup::Fault,
        ),
        FaultKnob::NetJitterNanos => (
            Value::Required("MIN..MAX", Kind::NanosRange),
            "Add seeded per-datagram delivery jitter drawn from [MIN, MAX].",
            KnobGroup::Fault,
        ),
        FaultKnob::NetDropPermille => (
            Value::Required("N", Kind::Permille),
            "Drop datagrams at N per-mille (0..=1000).",
            KnobGroup::Fault,
        ),
        FaultKnob::NetLatencyNanos => (
            Value::Required("N", Kind::U64),
            "Base per-datagram/segment delivery latency in nanoseconds.",
            KnobGroup::Fault,
        ),
        FaultKnob::NetDuplicatePermille => (
            Value::Required("N", Kind::Permille),
            "Deliver datagrams twice at N per-mille (each copy draws its own jitter).",
            KnobGroup::Fault,
        ),
        FaultKnob::NetConnectRefusePermille => (
            Value::Required("N", Kind::Permille),
            "Refuse otherwise-establishable TCP connections at N per-mille.",
            KnobGroup::Fault,
        ),
        FaultKnob::NetResetPermille => (
            Value::Required("N", Kind::Permille),
            "Reset an established TCP stream at N per-mille per data operation (both directions).",
            KnobGroup::Fault,
        ),
        FaultKnob::NetPartition => (
            Value::Required("A,B", Kind::AddressPair),
            "Partition two virtual addresses from each other, both directions (repeatable).",
            KnobGroup::Fault,
        ),
        FaultKnob::NetTcpBufferBytes => (
            Value::Required("N", Kind::Usize),
            "Virtual TCP receive-buffer size; smaller values make would-block/partial sends reachable.",
            KnobGroup::Fault,
        ),
        FaultKnob::EntropyFailPermille => (
            Value::Required("N", Kind::Permille),
            "Fail at N per-mille the entropy requests a real pool can fail: GRND_NONBLOCK reads before the pool is known ready answer EAGAIN.",
            KnobGroup::Fault,
        ),
        FaultKnob::EpochJumpNanos => (
            Value::Required("HI", Kind::U64),
            "Jump each realtime-epoch read by a seeded signed offset in [-HI, HI] nanoseconds (saturating at 0).",
            KnobGroup::Fault,
        ),
        FaultKnob::DnsEntry => (
            Value::Required("NAME=ADDR", Kind::DnsEntry),
            "Define NAME to resolve to IPv4 ADDR (repeatable). Undefined names are NXDOMAIN.",
            KnobGroup::Dns,
        ),
        FaultKnob::DnsFailPermille => (
            Value::Required("N", Kind::Permille),
            "Fail resolutions of DEFINED names at N per-mille (seeded NXDOMAIN or timeout).",
            KnobGroup::Dns,
        ),
        FaultKnob::DnsLatencyNanos => (
            Value::Required("MIN..MAX", Kind::NanosRange),
            "Add seeded latency drawn from [MIN, MAX] to every resolution of a defined name.",
            KnobGroup::Dns,
        ),
    };
    (
        f(
            knob.meta().flag,
            None,
            value,
            doc,
            matches!(knob.meta().plumbing, Plumbing::Repeatable(_)),
        ),
        group,
    )
}
const fn knob_count(group: KnobGroup) -> usize {
    let mut count = 0;
    let mut i = 0;
    while i < FaultKnob::ALL.len() {
        if knob_flag(FaultKnob::ALL[i]).1 as usize == group as usize {
            count += 1;
        }
        i += 1;
    }
    count
}
const fn knob_flags<const N: usize>(group: KnobGroup) -> [Flag; N] {
    let mut rows = [knob_flag(FaultKnob::ALL[0]).0; N];
    let mut index = 0;
    let mut i = 0;
    while i < FaultKnob::ALL.len() {
        let (flag, owner) = knob_flag(FaultKnob::ALL[i]);
        if owner as usize == group as usize {
            rows[index] = flag;
            index += 1;
        }
        i += 1;
    }
    assert!(index == N);
    rows
}
pub(super) const FAULT_FLAGS: &[Flag] =
    &knob_flags::<{ knob_count(KnobGroup::Fault) }>(KnobGroup::Fault);
// Campaign takes the semantic table alone.
pub(super) const DNS_FLAGS: &[Flag] = &knob_flags::<{ knob_count(KnobGroup::Dns) }>(KnobGroup::Dns);
pub(super) const DNS_ENTRY_FLAGS: &[Flag] = &[knob_flag(FaultKnob::DnsEntry).0];

pub(super) const BUGGIFY_FLAGS: &[Flag] = &[
    f(
        "--buggify",
        None,
        Value::None,
        "Enable cooperative-SUT (buggify) fault injection.",
        false,
    ),
    f(
        "--buggify-fire-permille",
        None,
        Value::Required("N", Kind::Permille),
        "Per-evaluation firing probability of an active buggify site (default 250 = 25%). Implies --buggify.",
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
    "Host milliseconds a native guest may run without a call that reaches the runtime before the run stops as a timeout (1..=86400000; default 10000); replay follows the recorded stop, not host time.",
    false,
);

pub(super) const LIVENESS_FLAGS: &[Flag] = &[
    f(
        "--liveness-watchdog",
        None,
        Value::Required("NANOS", Kind::PositiveU64),
        "Arm a no-progress watchdog: the run is a liveness failure when NANOS virtual nanoseconds pass without progress (600000000000 = 10 minutes is a generous budget).",
        false,
    ),
    f(
        "--converge-within",
        None,
        Value::Required("NANOS", Kind::PositiveU64),
        "Require convergence within NANOS virtual nanoseconds of the last injected fault (300000000000 = 5 minutes is a generous budget).",
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
        Value::Required("DEPTH", Kind::PositiveU64),
        "PCT priority-scheduling exploration at bug depth DEPTH (>= 1; 3 finds most ordering bugs of up to three steps).",
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
    SWARM_FLAG,
    f(
        "--yield-stride",
        None,
        Value::Required("N", Kind::U32),
        "On an --instrument build, a scheduling point every N edges a thread executes (default 0: none; 1 = every edge).",
        false,
    ),
];

pub(super) const SWARM_FLAG: Flag = f(
    "--swarm",
    None,
    Value::None,
    "Seed-derived swarm selection of a fault-class subset.",
    false,
);

pub(super) const ALLOW_FLAG: Flag = f(
    "--allow",
    None,
    Value::Required("SYMBOL|all", Kind::Symbol),
    "Let the pre-run gate admit SYMBOL, which the guest links but does not reach in a way that matters (repeatable). An instruction-class finding (`instruction@.text+OFF`, an address that moves on every relink) also matches by the containing symbol its provenance names, and is admitted with a warning that qualifies the run. `all` admits every unsupported symbol that way.",
    true,
);

pub(super) const PARAM_FLAG: Flag = f(
    "--param",
    None,
    Value::Required("K=V", Kind::KeyValue),
    "A run parameter the guest reads through `patina_dst::param(K)`. Recorded and restored on replay.",
    true,
);

pub(super) const CPUS_FLAG: Flag = f(
    "--cpus",
    None,
    Value::Required("N", Kind::Cpus),
    "The number of CPUs the guest's virtual machine has (default 4, at most 1024): its affinity mask, getcpu, sysconf(_SC_NPROCESSORS_*) and macOS's hw.ncpu agree, so a runtime sizing its pool from the CPU count starts that many workers; tasks still run one at a time. Recorded and restored on replay.",
    false,
);

pub(super) const ALLOW_RANDOMIZED_LAYOUT_FLAG: Flag = f(
    "--allow-randomized-address-layout",
    None,
    Value::None,
    "Run the native guest with the host's address-space randomization when the host forbids turning it off (Docker's default seccomp profile does): addresses are then not a function of the seed, and the run's determinism is qualified on stderr, in the result envelope and in the trace, and its replay keeps the host's randomization.",
    false,
);
