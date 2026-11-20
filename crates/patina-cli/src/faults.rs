//! The fault plan of a run: presets (`--faults NAME`), single settings (`--fault KEY=VALUE`,
//! `[faults]` in `patina.toml`) and `--crash`, resolved against the seed into the runtime's,
//! the wire's and the SDK's configurations.
//!
//! A value may be a range `A..B`: the run's value is drawn from the seed, uniformly in the
//! range, by a draw keyed by the setting's name (`plan_draw`). Adding, removing or changing
//! one setting therefore never moves another's value, nor any other decision of the run.
//! `swarm=1` turns each configured class off with probability one half, by the same kind of
//! draw. The resolved values are the plan (`Plan::resolved`), written to `run.json` and to
//! `result.json`'s `faults.plan`: the seed and the configuration are the whole run.

use crate::cli::Res;
use proto::faults::{FClass, CRASH_MACHINE, CRASH_PROCESS};
use serde_json::{json, Value};

/// Incarnations a run may start when `max-incarnations` is not given.
pub const MAX_INCARNATIONS_DEFAULT: u64 = 4;
/// `restart-gap-ms` when not given: 1 s to 61 s.
pub const RESTART_GAP_DEFAULT: (u64, u64) = (1_000_000_000, 61_000_000_000);
/// `down-ms` when not given: 1 s to 5 s. Short beside `crash-gap-ms`, so that with several
/// nodes the seed's kills seldom leave every node down at once.
pub const DOWN_DEFAULT: (u64, u64) = (1_000_000_000, 5_000_000_000);
/// `crash-gap-ms` when not given: 5 s to 60 s.
pub const CRASH_GAP_DEFAULT: (u64, u64) = (5_000_000_000, 60_000_000_000);
/// `pause-ms` when pauses are on and it is not given.
const PAUSE_MS_DEFAULT: &str = "100..15000";

/// The fault plan of a run.
#[derive(Clone, Debug)]
pub struct Plan {
    pub faults: proto::faults::FaultCfg,
    /// `faults-in-recovery=0`: no faults other than crashes after the first crash.
    pub faults_in_recovery: bool,
    /// `max-incarnations=N`: crashes stop once the run has started N incarnations.
    pub max_incarnations: u64,
    /// `restart-gap-ms=A..B`: virtual time from a crash to the restart, drawn per restart in
    /// [A, B) ns (A when A = B).
    pub restart_gap_ns: (u64, u64),
    /// With nodes: `crash-gap-ms` and `down-ms` (ns), and the nodes the seed kills
    /// (`--crash process[@NODE,...]`; bit `k` for node `k`).
    pub crash_gap_ns: (u64, u64),
    pub down_ns: (u64, u64),
    pub node_crash: u64,
    /// What the seed's kills of those nodes do (`proto::node::CRASH_NODE_*`).
    pub node_crash_kind: u64,
    /// `net-*` keys.
    pub net: proto::wire::NetCfg,
    /// `--buggify`, `buggify-permille=N`, `point:LABEL=N` (`proto::sdk`).
    pub sdk: proto::sdk::SdkCfg,
    /// Compute points: the run's mean gap in events (`compute-gap`; 0: no compute switches).
    pub compute_gap: u64,
    /// Whether the switch budget applies (`proto::compute::budget`): only to a gap drawn by
    /// default; a plan that names `compute-gap` gets that gap for the whole run.
    pub compute_budget: bool,
    /// Load-time points: the longest walk of a switch past its site, in instructions
    /// (`compute-walk`; 0: switches are taken at their sites).
    pub compute_walk: u64,
    /// With nodes: each node's disk and memory settings (`NodeTab::faults`; the driver's are
    /// in `faults`, entry 0 unused).
    pub node_faults: [proto::faults::FaultCfg; proto::node::MAX_NODES],
    /// `pause-gap-ms` and `pause-ms` (ns; gap (0, 0): no pauses): a node's own, resolved with
    /// its seed, and each node's (`node_pause`, entry 0 unused: the driver is never paused).
    pub pause_gap_ns: (u64, u64),
    pub pause_ns: (u64, u64),
    pub node_pause: [[u64; 4]; proto::node::MAX_NODES],
    /// `clock-skew-ms` (ns; max 0: none): a node's own, and each node's (entry 0 unused: the
    /// driver's clock is the run's virtual time).
    pub skew_ns: (u64, u64),
    pub node_skew: [(u64, u64); proto::node::MAX_NODES],
    /// The resolved settings, in key order, as `result.json` and `run.json` show them: a
    /// number, a string, or `"off"` for a class `swarm` turned off.
    pub resolved: Vec<(String, Value)>,
}

/// How a key's value is read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Val {
    /// 0 to 1000; may be a range; a class `swarm` may turn off.
    Permille,
    /// A count; may be a range; a class `swarm` may turn off.
    Count,
    /// A count; may be a range; a parameter of another class.
    Param,
    /// A size in bytes; a range `A..B` (A at least 1) draws log-uniformly, since sizes span
    /// orders of magnitude; a class `swarm` may turn off.
    Size,
    /// The key's own grammar, like `Own`, for a parameter of another class: never swarmed.
    Spread,
    /// 0 or 1.
    Flag,
    /// The key's own grammar (`A..B` milliseconds are the per-event spread, not a plan
    /// range); a class `swarm` may turn off.
    Own,
    /// A position (the N-th call): may be a range, which searches positions across seeds;
    /// never swarmed.
    At,
    /// `compute-gap`, `compute-walk`: `A..B` draws log-uniformly, not uniformly; never
    /// swarmed.
    Gap,
    /// A window `START+LENGTH[:PORT]` in milliseconds, START and LENGTH each a number or a
    /// range resolved like any other (LENGTH by the draw of `KEY:length`); a class `swarm`
    /// may turn off.
    Window,
    /// A word or a list of words, as given: never drawn, never swarmed.
    Word,
}

/// One fault setting.
pub struct Key {
    pub name: &'static str,
    pub value: &'static str,
    pub help: &'static str,
    val: Val,
}

const fn key(name: &'static str, value: &'static str, val: Val, help: &'static str) -> Key {
    Key {
        name,
        value,
        help,
        val,
    }
}

/// Every `--fault` key. `--help` and the guide print this table.
pub const KEYS: &[Key] = &[
    key(
        "fs-error-permille",
        "P",
        Val::Permille,
        "fail a call on a /work file or path with an errno Linux returns for it",
    ),
    key(
        "fs-short-permille",
        "P",
        Val::Permille,
        "shorten a read or write (/work files, pipes, unix sockets)",
    ),
    key(
        "fs-delay-permille",
        "P",
        Val::Permille,
        "delay a call in virtual time, up to fs-delay-max-ms",
    ),
    key(
        "fs-delay-max-ms",
        "N",
        Val::Param,
        "longest fs delay [default: 10]",
    ),
    key(
        "fsync-error-permille",
        "P",
        Val::Permille,
        "fail the write-back of a sync call (fsync, fdatasync, msync, syncfs, sync_file_range, an O_SYNC write): its unsynced data never becomes durable; the error is reported as Linux reports it, once to each open file description, an unseen one also to a later opener",
    ),
    key(
        "enospc-after-bytes",
        "N",
        Val::Count,
        "ENOSPC once N bytes have been written to /work",
    ),
    key(
        "fs-eintr",
        "0|1",
        Val::Flag,
        "fs errors on calls that can wait may also be EINTR",
    ),
    key(
        "mem-error-permille",
        "P",
        Val::Permille,
        "mmap, brk, mremap answer ENOMEM; thread creation EAGAIN",
    ),
    key(
        "mem-limit-mb",
        "N",
        Val::Count,
        "a process's private writable memory past N MiB: mmap, brk, mremap answer ENOMEM",
    ),
    key(
        "path-swap-permille",
        "P",
        Val::Permille,
        "between a process's check of a /work path and its use, make it a symlink, rename another entry into its place, or rename it away (opt-in: models a concurrent process)",
    ),
    key(
        "net-delay-ms",
        "A..B",
        Val::Own,
        "each TCP delivery and each datagram is delayed by a draw in A..B ms [default: 0.01..0.05]",
    ),
    key(
        "net-chunk-max",
        "N",
        Val::Size,
        "TCP deliveries are split into pieces of at most N bytes (a range A..B draws log-uniformly per seed)",
    ),
    key(
        "net-chunk-gap-us",
        "A..B",
        Val::Spread,
        "the pieces of a split delivery follow each other by a draw in A..B microseconds [default: each piece is delayed as a delivery is, by net-delay-ms]",
    ),
    key(
        "net-reset-permille",
        "P",
        Val::Permille,
        "reset a TCP connection, drawn for each piece of data a guest sends on it (so a long-lived connection meets one)",
    ),
    key(
        "net-connect-refuse-permille",
        "P",
        Val::Permille,
        "refuse a TCP connect",
    ),
    key(
        "net-connect-timeout-permille",
        "P",
        Val::Permille,
        "time out a TCP connect",
    ),
    key(
        "net-blackout",
        "START+LENGTH[:PORT]",
        Val::Window,
        "for LENGTH ms of virtual time from START ms, hold TCP deliveries, lose datagrams and leave keepalive probes unanswered on every link the link faults act on, loopback included (from or to PORT); START and LENGTH are each a number or a range A..B drawn per seed",
    ),
    key(
        "net-syn-retries",
        "N",
        Val::Param,
        "a TCP connect that gets no answer (across a cut link, or net-connect-timeout) retries its SYN N times, after 1, 3, 7, 15, ... s, and fails ETIMEDOUT after the last (in a run with nodes a socket's TCP_SYNCNT, when set, is its own) [default: 6, ETIMEDOUT at 127 s]",
    ),
    key(
        "net-give-up-ms",
        "N",
        Val::Param,
        "a TCP direction whose data a cut link has held for N ms resets its sender, who sees ETIMEDOUT (in a run with nodes a socket's TCP_USER_TIMEOUT, when set, is its own limit); keepalive (SO_KEEPALIVE) has its own budget [default: 924600]",
    ),
    key(
        "net-links",
        "nodes|driver|all",
        Val::Word,
        "in a run with nodes, the links the net- faults and partitions act on: between two nodes other than the driver; also the driver's; also every node's loopback (partitions never cut loopback) [default: nodes]",
    ),
    key(
        "partition-gap-ms",
        "A..B",
        Val::Own,
        "in a run with nodes, seed-drawn partitions: virtual time from the start of the run (or setup-complete), then from each partition's end, to the next one's start, a draw in A..B ms each time",
    ),
    key(
        "partition-ms",
        "A..B",
        Val::Spread,
        "how long each partition lasts: a draw in A..B ms [default: 1000..30000]",
    ),
    key(
        "partition-shape",
        "SHAPE[,SHAPE]",
        Val::Word,
        "the shapes partitions are drawn from: split (two sides, both ways), isolate (one node from the rest), oneway (two sides, one direction), bridge (two sides, one node still reaches both) [default: all four]",
    ),
    key(
        "pause-gap-ms",
        "A..B",
        Val::Own,
        "in a run with nodes, seed-drawn pauses of each node (all its threads stop; its links hold): virtual time from the run's start (or setup-complete), then from each pause's end, to the node's next pause, a draw in A..B ms each time; each node's own (@NODE scopes it)",
    ),
    key(
        "pause-ms",
        "A..B",
        Val::Spread,
        "how long each pause lasts: a draw in A..B ms [default: 100..15000]",
    ),
    key(
        "clock-skew-ms",
        "A..B",
        Val::Own,
        "in a run with nodes, each boot of a node draws its realtime clock's offset: A..B ms, ahead or behind (monotonic clocks have none); each node's own (@NODE scopes it)",
    ),
    key(
        "net-drop-permille",
        "P",
        Val::Permille,
        "lose a datagram (UDP)",
    ),
    key(
        "net-dup-permille",
        "P",
        Val::Permille,
        "deliver a datagram twice, the copy with its own delay",
    ),
    key(
        "net-reorder-permille",
        "P",
        Val::Permille,
        "hold a datagram back past the delay range, so later ones overtake it",
    ),
    key(
        "net-halfclose-delay-ms",
        "A..B",
        Val::Own,
        "delay each delivered FIN by a draw in A..B ms",
    ),
    key(
        "buggify-permille",
        "P",
        Val::Permille,
        "SDK fault points fire at this rate (with --buggify)",
    ),
    key(
        "point:LABEL",
        "P",
        Val::Permille,
        "the SDK fault point LABEL fires at this rate (with --buggify)",
    ),
    key(
        "swarm",
        "0|1",
        Val::Flag,
        "turn each configured class off with probability 1/2, per seed",
    ),
    key(
        "faults-after-setup",
        "0|1",
        Val::Flag,
        "no fault until the guest's SDK marks setup-complete",
    ),
    key(
        "faults-in-recovery",
        "0|1",
        Val::Flag,
        "after a crash, the other faults stay on (1) or go off for the rest of the run (0) [default: 1]",
    ),
    key(
        "restart-gap-ms",
        "A..B",
        Val::Spread,
        "virtual time from a crash to the restart: a draw in A..B ms for each restart [default: 1000..61000]",
    ),
    key(
        "max-incarnations",
        "N",
        Val::Param,
        "at most N incarnations: no crash in the N-th, so a run restarts at most N-1 times (with nodes: each node's boots, as its own max-incarnations) [default: 4]",
    ),
    key(
        "crash-gap-ms",
        "A..B",
        Val::Spread,
        "with nodes and --crash process: virtual time from a node's start to the seed's kill of its processes, a draw in A..B ms for each boot [default: 5000..60000]",
    ),
    key(
        "down-ms",
        "A..B",
        Val::Spread,
        "with nodes: virtual time a node stays down before its restart, a draw in A..B ms for each restart [default: 1000..5000]",
    ),
    key(
        "compute-gap",
        "G|A..B",
        Val::Gap,
        "rebuilt code (compute points): mean events between switches, drawn log-uniformly per seed from A..B; 0 turns switches off [default: 64..65536]",
    ),
    key(
        "compute-walk",
        "W|A..B",
        Val::Gap,
        "--preempt points: 2 switches in W (in 4 when W is below 4) are taken 1..W instructions (uniform) past their point, single-stepped, the rest at it; W drawn log-uniformly per seed from A..B; 0 takes every switch at its point [default: 4..512]",
    ),
    key(
        "fs-error-at",
        "CLASS:N",
        Val::At,
        "fail exactly the N-th call of CLASS (open, read, write, sync, ...)",
    ),
    key(
        "fsync-error-at",
        "N",
        Val::At,
        "fail exactly the N-th sync call (as fsync-error-permille)",
    ),
    key(
        "mem-error-at",
        "N",
        Val::At,
        "fail exactly the N-th memory request",
    ),
    key(
        "path-swap-at",
        "N",
        Val::At,
        "swap the path at exactly the N-th use of a checked /work path",
    ),
];

/// `--faults NAME`: rare-fault rates, each a range the seed resolves. `net-reset-permille` is
/// drawn for each send, so its preset rate is high enough that a connection carrying a few
/// dozen sends (a keep-alive client's) meets a reset in a good share of seeds.
pub const PRESETS: &[(&str, &[(&str, &str)])] = &[
    (
        "disk",
        &[
            ("fs-error-permille", "0..5"),
            ("fs-short-permille", "0..20"),
            ("fsync-error-permille", "0..3"),
            ("fs-delay-permille", "0..20"),
        ],
    ),
    (
        "net",
        &[
            ("net-delay-ms", "0..50"),
            ("net-chunk-max", "1..65536"),
            ("net-chunk-gap-us", "1..10"),
            ("net-reset-permille", "5..50"),
            ("net-connect-refuse-permille", "0..10"),
            ("net-drop-permille", "0..50"),
            ("net-dup-permille", "0..20"),
            ("net-reorder-permille", "0..50"),
        ],
    ),
    (
        "all",
        &[
            ("fs-error-permille", "0..5"),
            ("fs-short-permille", "0..20"),
            ("fsync-error-permille", "0..3"),
            ("fs-delay-permille", "0..20"),
            ("net-delay-ms", "0..50"),
            ("net-chunk-max", "1..65536"),
            ("net-chunk-gap-us", "1..10"),
            ("net-reset-permille", "5..50"),
            ("net-connect-refuse-permille", "0..10"),
            ("net-drop-permille", "0..50"),
            ("net-dup-permille", "0..20"),
            ("net-reorder-permille", "0..50"),
            ("mem-error-permille", "0..2"),
        ],
    ),
    // Only in a run with nodes (`resolve` refuses it without): the link faults here, the
    // partitions, pauses, clock skew and machine crashes in `NODE_PRESETS` and
    // `MACHINE_PRESETS` (the crashes: `cluster_crash`).
    (
        "cluster",
        &[
            ("net-delay-ms", "0..50"),
            ("net-chunk-max", "1..65536"),
            ("net-chunk-gap-us", "1..10"),
            ("net-reset-permille", "5..50"),
            ("net-connect-refuse-permille", "0..10"),
            ("net-drop-permille", "0..50"),
            ("net-dup-permille", "0..20"),
            ("net-reorder-permille", "0..50"),
        ],
    ),
];

/// What `--faults net` (and `all`, which includes it) adds in a run with at least two nodes
/// the link faults act on: seed-drawn partitions. Without them a preset sets none of these,
/// so a one-machine run's plan is what it was.
pub const NODE_PRESETS: &[(&str, &[(&str, &str)])] = &[
    (
        "net",
        &[
            ("partition-gap-ms", "5000..60000"),
            ("partition-ms", "500..20000"),
        ],
    ),
    (
        "all",
        &[
            ("partition-gap-ms", "5000..60000"),
            ("partition-ms", "500..20000"),
        ],
    ),
    (
        "cluster",
        &[
            ("partition-gap-ms", "5000..60000"),
            ("partition-ms", "500..20000"),
        ],
    ),
];

/// What `--faults cluster` and `all` add in a run with nodes (one or more): each node's
/// pauses and clock skew (node keys: each node draws its own), and for `cluster` the time
/// between the seed's machine crashes of every node (`cluster_crash`).
pub const MACHINE_PRESETS: &[(&str, &[(&str, &str)])] = &[
    (
        "all",
        &[
            ("pause-gap-ms", "10000..120000"),
            ("pause-ms", "100..15000"),
            ("clock-skew-ms", "0..2000"),
        ],
    ),
    (
        "cluster",
        &[
            ("pause-gap-ms", "10000..120000"),
            ("pause-ms", "100..15000"),
            ("clock-skew-ms", "0..2000"),
            ("crash-gap-ms", "30000..300000"),
        ],
    ),
];

/// `--crash` a run with nodes has when it names none and `cluster` is among its presets:
/// every node's machine crashes at drawn times (`crash-gap-ms`).
pub const CLUSTER_CRASH: &str = "machine";

/// Whether presets `p` (as given: `NAME,...[@NODE,...]`) name `cluster`.
pub fn names_cluster(p: &[String]) -> bool {
    p.iter()
        .any(|p| split_scope(p).0.split(',').any(|n| n == "cluster"))
}
/// `partition-ms` when partitions are on and it is not given.
const PARTITION_MS_DEFAULT: &str = "1000..30000";

/// The crash rate `--crash KIND` takes when none is given (per mille, at each crash point).
pub const CRASH_DEFAULT_PERMILLE: u64 = 3;
/// `fs-delay-max-ms` when not given.
const DELAY_MAX_MS_DEFAULT: u64 = 10;

/// The words a renamed key is refused with (no alias: a plan means one thing).
fn renamed(k: &str) -> Option<String> {
    (k == "net-partition").then(|| {
        "--fault net-partition: renamed net-blackout (a partition is now a cut between nodes, \
         partition-gap-ms)"
            .to_string()
    })
}

fn find(k: &str) -> Option<&'static Key> {
    let name = if k.starts_with("point:") {
        "point:LABEL"
    } else {
        k
    };
    KEYS.iter().find(|x| x.name == name)
}

/// The draw that resolves the setting `name`: its own stream, keyed by the name only. A
/// renamed key keeps drawing under its old name (`net-blackout` was `net-partition`), so a
/// rename moves no draw.
pub fn plan_draw(seed: u64, name: &str) -> u64 {
    let old;
    let name = if name.contains("net-blackout") {
        old = name.replace("net-blackout", "net-partition");
        old.as_str()
    } else {
        name
    };
    proto::draw(
        seed,
        proto::Stream::FaultPlan,
        proto::rec::hash_bytes(0x706c_616e, name.as_bytes()),
    )
}

fn num(k: &str, v: &str) -> Res<u64> {
    v.parse()
        .map_err(|_| format!("--fault {k}: not a number: {v}"))
}

/// A number or a range `A..B`, resolved: the value, and whether it was drawn.
fn resolve_num(seed: u64, k: &str, v: &str, max: u64) -> Res<u64> {
    let (a, b) = match v.split_once("..") {
        Some((a, b)) => (num(k, a)?, num(k, b)?),
        None => {
            let x = num(k, v)?;
            (x, x)
        }
    };
    if a > b {
        return Err(format!("--fault {k}={v}: A is larger than B"));
    }
    if b > max {
        return Err(format!("--fault {k}: at most {max}"));
    }
    Ok(a + plan_draw(seed, k) % (b - a + 1))
}

/// `compute-gap=G|A..B` (the run's mean gap) and `compute-walk=W|A..B` (its longest walk): a
/// range drawn log-uniformly by the key's own plan draw (`proto::compute::mean_gap`). `0`
/// turns compute switches, or walks, off.
fn resolve_gap(seed: u64, k: &str, v: &str) -> Res<u64> {
    let max = match k {
        "compute-walk" => proto::compute::WALK_MAX,
        _ => proto::compute::GAP_MAX,
    };
    let (a, b) = match v.split_once("..") {
        Some((a, b)) => (num(k, a)?, num(k, b)?),
        None => {
            let x = num(k, v)?;
            (x, x)
        }
    };
    if a > b {
        return Err(format!("--fault {k}={v}: A is larger than B"));
    }
    if b > max {
        return Err(format!("--fault {k}: at most {max}"));
    }
    if a == 0 && b != 0 {
        return Err(format!(
            "--fault {k}={v}: a range starts at 1 (0 alone turns it off)"
        ));
    }
    Ok(proto::compute::mean_gap(plan_draw(seed, k), a, b))
}

/// A size or a range `A..B` of sizes, resolved: a range draws log-uniformly
/// (`proto::pmu::log_uniform`) by the key's own plan draw.
fn resolve_size(seed: u64, k: &str, v: &str) -> Res<u64> {
    let (a, b) = match v.split_once("..") {
        Some((a, b)) => (num(k, a)?, num(k, b)?),
        None => return num(k, v),
    };
    if a > b {
        return Err(format!("--fault {k}={v}: A is larger than B"));
    }
    if a == 0 || b > u64::MAX / 4 {
        return Err(format!(
            "--fault {k}={v}: a range is from 1 to {}",
            u64::MAX / 4
        ));
    }
    Ok(proto::pmu::log_uniform(plan_draw(seed, k), a, b))
}

/// `START+LENGTH[:PORT]`, each of START and LENGTH resolved like a number (LENGTH by the
/// draw of `KEY:length`, so the two move independently): `S+L[:PORT]` in milliseconds.
fn resolve_window(seed: u64, k: &str, v: &str) -> Res<String> {
    let (w, port) = match v.split_once(':') {
        Some((w, p)) => (w, Some(p)),
        None => (v, None),
    };
    let (start, len) = w
        .split_once('+')
        .ok_or_else(|| format!("--fault {k}={v}: expected START+LENGTH[:PORT] (milliseconds)"))?;
    let start = resolve_num(seed, k, start, u64::MAX / 4_000_000)?;
    let len = resolve_num(seed, &format!("{k}:length"), len, u64::MAX / 4_000_000)?;
    Ok(match port {
        Some(p) => format!("{start}+{len}:{p}"),
        None => format!("{start}+{len}"),
    })
}

/// A position key's value (`N`, or `CLASS:N` for `fs-error-at`) with `N` resolved like any
/// other number: a range searches positions across seeds.
fn resolve_at(seed: u64, k: &str, v: &str) -> Res<String> {
    Ok(match v.split_once(':') {
        Some((class, n)) => format!("{class}:{}", resolve_num(seed, k, n, u64::MAX / 2)?),
        // `apply` names what is missing.
        None if k == "fs-error-at" => v.to_string(),
        None => resolve_num(seed, k, v, u64::MAX / 2)?.to_string(),
    })
}

/// The links the net- faults act on, by `net-links`'s word.
fn links(v: &str) -> Res<u64> {
    use proto::wire::{LINKS_ALL, LINKS_DRIVER, LINKS_NODES};
    match v {
        "nodes" => Ok(LINKS_NODES),
        "driver" => Ok(LINKS_DRIVER),
        "all" => Ok(LINKS_ALL),
        _ => Err(format!(
            "--fault net-links={v}: expected nodes, driver or all"
        )),
    }
}

/// The nodes the link faults act on (`net-links`, the last one given): partitions need two.
fn faultable_nodes(nodes: usize, settings: &[String]) -> Res<usize> {
    let scope = match settings
        .iter()
        .rev()
        .filter_map(|kv| kv.split_once('='))
        .find(|(k, _)| *k == "net-links")
    {
        Some((_, v)) => links(v)?,
        None => proto::wire::LINKS_NODES,
    };
    Ok(if nodes == 0 {
        0
    } else {
        nodes + (scope >= proto::wire::LINKS_DRIVER) as usize
    })
}

/// A key each node has its own value of (DESIGN 2.4): the disk and memory keys. In a run with
/// nodes the run's value applies to every node but the driver, and `@NODE,...` scopes it.
pub fn node_scoped(k: &str) -> bool {
    k.starts_with("fs-")
        || k.starts_with("fsync-")
        || k.starts_with("mem-")
        || k.starts_with("path-swap-")
        || k == "enospc-after-bytes"
        || node_only(k)
}

/// A node's own key that only a node has (the driver is never paused): refused in a run
/// without nodes, and for the driver.
pub fn node_only(k: &str) -> bool {
    k.starts_with("pause-") || k.starts_with("clock-")
}

/// `SETTING@NODE,...`: the setting and the nodes it names (`None`: no scope). A setting's
/// scope follows its value (`KEY=VALUE@NODE`): an `@` in the key (`point:LABEL`) is the key's.
pub fn split_scope(s: &str) -> (&str, Option<&str>) {
    let from = s.find('=').map_or(0, |i| i + 1);
    match s[from..].rfind('@') {
        Some(j) => (&s[..from + j], Some(&s[from + j + 1..])),
        None => (s, None),
    }
}

/// Copy the node-scoped settings of `src` into `dst` (the rest of `dst` stays).
pub fn set_node_keys(dst: &mut proto::faults::FaultCfg, src: &proto::faults::FaultCfg) {
    dst.fs_error_permille = src.fs_error_permille;
    (dst.fs_error_at_class, dst.fs_error_at_n) = (src.fs_error_at_class, src.fs_error_at_n);
    dst.fs_eintr = src.fs_eintr;
    dst.short_permille = src.short_permille;
    dst.fsync_error_permille = src.fsync_error_permille;
    dst.fsync_error_at = src.fsync_error_at;
    dst.enospc_after_bytes = src.enospc_after_bytes;
    (dst.delay_permille, dst.delay_max_ns) = (src.delay_permille, src.delay_max_ns);
    (dst.mem_error_permille, dst.mem_error_at) = (src.mem_error_permille, src.mem_error_at);
    dst.mem_limit_bytes = src.mem_limit_bytes;
    (dst.path_swap_permille, dst.path_swap_at) = (src.path_swap_permille, src.path_swap_at);
    dst.any |= src.any;
}

/// The keys of preset `p` in a run with `faultable` nodes the link faults act on: its own,
/// its partition keys (`NODE_PRESETS`) when there are two such nodes, and its machine keys
/// (`MACHINE_PRESETS`) when there is one. `cluster` without nodes is refused.
pub fn preset_keys(p: &str, faultable: usize) -> Res<Vec<(&'static str, &'static str)>> {
    let (_, kv) = PRESETS.iter().find(|x| x.0 == p).ok_or_else(|| {
        let names: Vec<&str> = PRESETS.iter().map(|x| x.0).collect();
        format!("--faults: unknown preset {p} ({})", names.join(", "))
    })?;
    if p == "cluster" && faultable == 0 {
        return Err("--faults cluster: only in a run with nodes".into());
    }
    let mut out: Vec<(&str, &str)> = kv.to_vec();
    if faultable >= 2 {
        for (_, kv) in NODE_PRESETS.iter().filter(|x| x.0 == p) {
            out.extend(kv.iter().copied());
        }
    }
    if faultable >= 1 {
        for (_, kv) in MACHINE_PRESETS.iter().filter(|x| x.0 == p) {
            out.extend(kv.iter().copied());
        }
    }
    Ok(out)
}

/// A preset expanded into its settings, as `resolve` would apply them for this run: `minimize`
/// replaces a preset with them (settings given beside it win).
pub fn preset_settings(p: &str, nodes: usize, settings: &[String]) -> Res<Vec<(String, String)>> {
    let f = faultable_nodes(nodes, settings)?;
    Ok(preset_keys(p, f)?
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect())
}

/// Resolve presets, settings (later ones replace earlier ones of the same key, settings
/// replace presets) and `--crash` against `seed`. `nodes` is the run's nodes besides the
/// driver (0: a run without nodes).
pub fn resolve(
    seed: u64,
    presets: &[String],
    settings: &[String],
    crash: Option<&str>,
    nodes: usize,
) -> Res<Plan> {
    let mut given: Vec<(String, String)> = vec![];
    fn set(given: &mut Vec<(String, String)>, k: &str, v: &str) {
        match given.iter_mut().find(|e| e.0 == k) {
            Some(e) => e.1 = v.to_string(),
            None => given.push((k.to_string(), v.to_string())),
        }
    }
    let mut named = vec![];
    for kv in settings {
        let (k, v) = kv
            .split_once('=')
            .ok_or_else(|| format!("--fault {kv}: expected KEY=VALUE"))?;
        if let Some(e) = renamed(k) {
            return Err(e);
        }
        if find(k).is_none() {
            return Err(format!("--fault: unknown key {k}"));
        }
        named.push((k, v));
    }
    let faultable = faultable_nodes(nodes, settings)?;
    for p in presets.iter().flat_map(|p| p.split(',')) {
        for (k, v) in preset_keys(p, faultable)? {
            set(&mut given, k, v);
        }
    }
    for (k, v) in named {
        set(&mut given, k, v);
    }
    let parts = given.iter().any(|e| e.0 == "partition-gap-ms");
    if parts && faultable < 2 {
        return Err(format!(
            "--fault partition-gap-ms: partitions need two nodes the link faults act on ({})",
            if nodes == 0 {
                "the run has no nodes".to_string()
            } else {
                format!("the run has {nodes}; net-links=driver adds the driver")
            }
        ));
    }
    if nodes == 0 {
        if let Some(e) = given.iter().find(|e| {
            e.0.starts_with("partition-")
                || matches!(e.0.as_str(), "net-links" | "crash-gap-ms" | "down-ms")
        }) {
            return Err(format!("--fault {}: only in a run with nodes", e.0));
        }
    }
    if parts && !given.iter().any(|e| e.0 == "partition-ms") {
        set(&mut given, "partition-ms", PARTITION_MS_DEFAULT);
    }
    if given.iter().any(|e| e.0 == "pause-gap-ms") && !given.iter().any(|e| e.0 == "pause-ms") {
        set(&mut given, "pause-ms", PAUSE_MS_DEFAULT);
    }
    given.sort();
    let swarm = match given.iter().position(|e| e.0 == "swarm") {
        Some(i) => num("swarm", &given.remove(i).1)? != 0,
        None => false,
    };
    // The default is not part of the plan: a run that does not name the key resolves it the
    // same way every time, and a stock program's plan reads as before.
    let (lo, hi) = proto::compute::GAP_DEFAULT;
    let (wlo, whi) = proto::compute::WALK_DEFAULT;
    let mut plan = Plan {
        faults: Default::default(),
        faults_in_recovery: true,
        max_incarnations: MAX_INCARNATIONS_DEFAULT,
        restart_gap_ns: RESTART_GAP_DEFAULT,
        crash_gap_ns: CRASH_GAP_DEFAULT,
        down_ns: DOWN_DEFAULT,
        node_crash: 0,
        node_crash_kind: 0,
        net: Default::default(),
        sdk: Default::default(),
        compute_gap: resolve_gap(seed, "compute-gap", &format!("{lo}..{hi}"))?,
        compute_budget: true,
        compute_walk: resolve_gap(seed, "compute-walk", &format!("{wlo}..{whi}"))?,
        node_faults: Default::default(),
        pause_gap_ns: (0, 0),
        pause_ns: (0, 0),
        node_pause: Default::default(),
        skew_ns: (0, 0),
        node_skew: Default::default(),
        resolved: vec![],
    };
    if swarm {
        plan.resolved.push(("swarm".into(), json!(1)));
    }
    let mut delay_max_given = false;
    for (k, v) in &given {
        let info = find(k).unwrap();
        let value: Value = match info.val {
            Val::Permille => json!(resolve_num(seed, k, v, 1000)?),
            Val::Count | Val::Param => json!(resolve_num(seed, k, v, u64::MAX / 2)?),
            Val::Flag => json!((num(k, v)? != 0) as u64),
            Val::Size => json!(resolve_size(seed, k, v)?),
            Val::Own | Val::Spread | Val::Word => json!(v),
            Val::Window => json!(resolve_window(seed, k, v)?),
            Val::At => json!(resolve_at(seed, k, v)?),
            Val::Gap => {
                let g = resolve_gap(seed, k, v)?;
                match k.as_str() {
                    "compute-walk" => plan.compute_walk = g,
                    _ => (plan.compute_gap, plan.compute_budget) = (g, false),
                }
                plan.resolved.push((k.clone(), json!(g)));
                continue;
            }
        };
        let class = matches!(
            info.val,
            Val::Permille | Val::Count | Val::Own | Val::Size | Val::Window
        );
        if swarm && class && plan_draw(seed, &format!("swarm:{k}")) & 1 == 1 {
            plan.resolved.push((k.clone(), json!("off")));
            continue;
        }
        let s = match &value {
            Value::String(s) => s.clone(),
            x => x.to_string(),
        };
        apply(&mut plan, k, &s)?;
        delay_max_given |= k == "fs-delay-max-ms";
        plan.resolved.push((k.clone(), value));
    }
    if !delay_max_given && plan.faults.delay_permille != 0 {
        plan.faults.delay_max_ns = DELAY_MAX_MS_DEFAULT * 1_000_000;
    }
    if let Some(c) = crash {
        let s = crash_plan(seed, &mut plan.faults, c)?;
        plan.resolved.push(("crash".into(), json!(s)));
    }
    let shapes = plan.net.part_shapes;
    if parts
        && shapes != 0
        && !proto::node::SHAPES
            .iter()
            .any(|s| shapes & (1 << s.0) != 0 && proto::node::shape_min_nodes(s.0) <= faultable)
    {
        return Err(format!(
            "--fault partition-shape: no shape it names fits {faultable} nodes the link faults act \
             on (bridge needs 3)"
        ));
    }
    Ok(plan)
}

impl Plan {
    /// The resolved plan as a JSON object.
    pub fn json(&self) -> Value {
        Value::Object(self.resolved.iter().cloned().collect())
    }
}

/// Apply one resolved `KEY=VALUE`.
fn apply(o: &mut Plan, k: &str, v: &str) -> Res<()> {
    let n = |v: &str| num(k, v);
    let f = &mut o.faults;
    match k {
        "fs-error-permille" => f.fs_error_permille = n(v)?,
        "fs-error-at" => {
            let (c, n_) = v
                .split_once(':')
                .ok_or_else(|| format!("--fault fs-error-at={v}: expected CLASS:N"))?;
            let class = FClass::from_name(c).ok_or_else(|| {
                let names: Vec<&str> = FClass::ALL.iter().map(|c| c.name()).collect();
                format!(
                    "--fault fs-error-at: unknown class {c} ({})",
                    names.join(", ")
                )
            })?;
            f.fs_error_at_class = class as u64 + 1;
            f.fs_error_at_n = n(n_)?;
            if f.fs_error_at_n == 0 {
                return Err("--fault fs-error-at: N counts from 1".into());
            }
        }
        "fs-eintr" => f.fs_eintr = n(v)?,
        "fs-short-permille" => f.short_permille = n(v)?,
        "fsync-error-permille" => f.fsync_error_permille = n(v)?,
        "fsync-error-at" => f.fsync_error_at = n(v)?,
        "enospc-after-bytes" => f.enospc_after_bytes = n(v)?,
        "fs-delay-permille" => f.delay_permille = n(v)?,
        "fs-delay-max-ms" => f.delay_max_ns = n(v)? * 1_000_000,
        "mem-error-permille" => f.mem_error_permille = n(v)?,
        "mem-error-at" => f.mem_error_at = n(v)?,
        "path-swap-permille" => f.path_swap_permille = n(v)?,
        "path-swap-at" => f.path_swap_at = n(v)?,
        "mem-limit-mb" => {
            // A limit, not a draw: it holds whether or not other faults are active.
            f.mem_limit_bytes = n(v)?.saturating_mul(1 << 20);
            return Ok(());
        }
        "faults-in-recovery" => {
            o.faults_in_recovery = n(v)? != 0;
            return Ok(());
        }
        "restart-gap-ms" => {
            o.restart_gap_ns = ms_range(k, v)?;
            return Ok(());
        }
        "crash-gap-ms" => {
            o.crash_gap_ns = ms_range(k, v)?;
            return Ok(());
        }
        "down-ms" => {
            o.down_ns = ms_range(k, v)?;
            if o.down_ns.1 == 0 {
                return Err(format!("--fault {k}={v}: B is at least 1"));
            }
            return Ok(());
        }
        "max-incarnations" => {
            o.max_incarnations = n(v)?;
            if o.max_incarnations == 0 {
                return Err("--fault max-incarnations: at least 1".into());
            }
            return Ok(());
        }
        // The `setup-complete` mark lowers it to its own sequence number.
        "faults-after-setup" => {
            f.fault_after_seq = if n(v)? != 0 { u64::MAX } else { 0 };
            return Ok(());
        }
        "buggify-permille" => {
            o.sdk.fire_permille = n(v)?;
            return Ok(());
        }
        _ if k.starts_with("point:") => return point(&mut o.sdk, &k["point:".len()..], n(v)?),
        "partition-gap-ms" => {
            (o.net.part_gap_min_ns, o.net.part_gap_max_ns) = ms_range(k, v)?;
            if o.net.part_gap_min_ns == 0 {
                return Err(format!("--fault {k}={v}: A is at least 1"));
            }
            if o.net.part_shapes == 0 {
                o.net.part_shapes = proto::node::SHAPES.iter().fold(0, |b, s| b | 1 << s.0);
            }
            return Ok(());
        }
        "clock-skew-ms" => {
            o.skew_ns = ms_range(k, v)?;
            if o.skew_ns.1 > proto::node::CLOCK_STEP_MAX_NS {
                return Err(format!("--fault {k}={v}: at most a year"));
            }
            return Ok(());
        }
        "pause-gap-ms" => {
            o.pause_gap_ns = ms_range(k, v)?;
            if o.pause_gap_ns.0 == 0 {
                return Err(format!("--fault {k}={v}: A is at least 1"));
            }
            return Ok(());
        }
        "pause-ms" => {
            o.pause_ns = ms_range(k, v)?;
            if o.pause_ns.0 == 0 {
                return Err(format!("--fault {k}={v}: A is at least 1"));
            }
            return Ok(());
        }
        "partition-ms" => {
            (o.net.part_min_ns, o.net.part_max_ns) = ms_range(k, v)?;
            if o.net.part_min_ns == 0 {
                return Err(format!("--fault {k}={v}: A is at least 1"));
            }
            return Ok(());
        }
        "partition-shape" => {
            let mut bits = 0;
            for w in v.split(',') {
                let s = proto::node::SHAPES
                    .iter()
                    .find(|s| s.1 == w)
                    .ok_or_else(|| {
                        format!("--fault {k}: unknown shape {w} (split, isolate, oneway, bridge)")
                    })?;
                bits |= 1 << s.0;
            }
            o.net.part_shapes = bits;
            return Ok(());
        }
        _ if k.starts_with("net-") => return net_fault(&mut o.net, k, v),
        _ => return Err(format!("--fault: unknown key {k}")),
    }
    o.faults.any = 1;
    Ok(())
}

/// `point:LABEL=PERMILLE`: the SDK fault point LABEL is active and fires at this rate
/// (0: never). It acts only with `--buggify`.
fn point(c: &mut proto::sdk::SdkCfg, label: &str, p: u64) -> Res<()> {
    if label.is_empty() || label.len() > proto::sdk::LABEL_MAX {
        return Err(format!("--fault point:{label}: a label is 1 to 255 bytes"));
    }
    let h = proto::sdk::label_hash(label.as_bytes());
    let n = c.npoints as usize;
    if let Some(e) = c.points[..n].iter_mut().find(|e| e[0] == h) {
        e[1] = p;
    } else if n < proto::sdk::MAX_POINTS {
        c.points[n] = [h, p];
        c.npoints += 1;
    } else {
        return Err(format!(
            "--fault point: at most {} points",
            proto::sdk::MAX_POINTS
        ));
    }
    Ok(())
}

/// `A..B` (milliseconds) as nanoseconds.
fn ms_range(k: &str, v: &str) -> Res<(u64, u64)> {
    span(k, v, 1_000_000, "milliseconds")
}

/// `A..B` in units of `ns` nanoseconds, as nanoseconds.
fn span(k: &str, v: &str, ns: u64, unit: &str) -> Res<(u64, u64)> {
    let (a, b) = v
        .split_once("..")
        .ok_or_else(|| format!("--fault {k}={v}: expected A..B ({unit})"))?;
    let (a, b) = (num(k, a)?, num(k, b)?);
    if a > b {
        return Err(format!("--fault {k}={v}: A is larger than B"));
    }
    match (a.checked_mul(ns), b.checked_mul(ns)) {
        (Some(a), Some(b)) => Ok((a, b)),
        _ => Err(format!("--fault {k}={v}: too large")),
    }
}

/// One `net-*` key, resolved. They act on the supervisor's wire only, so they do not switch
/// on the runtime's per-call fault work.
fn net_fault(c: &mut proto::wire::NetCfg, k: &str, v: &str) -> Res<()> {
    let n = |v: &str| num(k, v);
    match k {
        "net-delay-ms" => {
            (c.delay_min_ns, c.delay_max_ns) = ms_range(k, v)?;
            c.delay_set = 1;
        }
        "net-chunk-max" => {
            c.chunk_max = n(v)?;
            if c.chunk_max == 0 {
                return Err("--fault net-chunk-max: at least 1".into());
            }
        }
        "net-reset-permille" => c.reset_permille = n(v)?,
        "net-connect-refuse-permille" => c.refuse_permille = n(v)?,
        "net-connect-timeout-permille" => c.timeout_permille = n(v)?,
        "net-blackout" => {
            let (range, port) = match v.split_once(':') {
                Some((r, p)) => (r, n(p)?),
                None => (v, 0),
            };
            if port > 65535 {
                return Err(format!("--fault net-blackout: port {port} out of range"));
            }
            let (start, len) = range
                .split_once('+')
                .ok_or_else(|| format!("--fault {k}={v}: expected START+LENGTH"))?;
            c.blackout_from_ns = n(start)? * 1_000_000;
            c.blackout_to_ns = c.blackout_from_ns + n(len)? * 1_000_000;
            c.blackout_port = port;
            c.blackout_set = 1;
        }
        "net-syn-retries" => {
            c.syn_retries = n(v)?;
            if c.syn_retries == 0 || c.syn_retries > proto::wire::SYN_RETRIES_MAX {
                return Err(format!(
                    "--fault {k}: 1 to {} (the kernel's least is 1)",
                    proto::wire::SYN_RETRIES_MAX
                ));
            }
            c.syn_retries_set = 1;
        }
        "net-give-up-ms" => {
            c.give_up_ns = n(v)?.saturating_mul(1_000_000);
            if c.give_up_ns == 0 {
                return Err(format!("--fault {k}: at least 1"));
            }
            c.give_up_set = 1;
        }
        "net-links" => c.links = links(v)?,
        "net-chunk-gap-us" => {
            (c.chunk_gap_min_ns, c.chunk_gap_max_ns) = span(k, v, 1000, "microseconds")?;
            c.chunk_gap_set = 1;
        }
        "net-halfclose-delay-ms" => {
            (c.halfclose_min_ns, c.halfclose_max_ns) = ms_range(k, v)?;
            c.halfclose_set = 1;
        }
        "net-drop-permille" => c.drop_permille = n(v)?,
        "net-dup-permille" => c.dup_permille = n(v)?,
        "net-reorder-permille" => c.reorder_permille = n(v)?,
        _ => return Err(format!("--fault: unknown key {k}")),
    }
    Ok(())
}

/// `--crash machine|process[:PERMILLE] | machine-at:N | process-at:N`, where PERMILLE and N
/// may be a range `A..B`. N is a crash point's ordinal in the first incarnation. Returns the
/// resolved form.
pub fn crash_plan(seed: u64, f: &mut proto::faults::FaultCfg, s: &str) -> Res<String> {
    let (k, v) = s.split_once(':').unwrap_or((s, ""));
    let (kind, at) = match k {
        "machine" => (CRASH_MACHINE, false),
        "process" => (CRASH_PROCESS, false),
        "machine-at" => (CRASH_MACHINE, true),
        "process-at" => (CRASH_PROCESS, true),
        _ => {
            return Err(format!(
                "--crash: unknown kind {k} (machine, process, machine-at:N, process-at:N)"
            ))
        }
    };
    f.crash_kind = kind;
    if at {
        if v.is_empty() {
            return Err(format!("--crash {s}: expected {k}:N (or A..B)"));
        }
        let n = resolve_num(seed, "crash-at", v, u64::MAX / 2)
            .map_err(|e| e.replace("--fault crash-at", &format!("--crash {k}")))?;
        f.crash_at = n.max(1);
        f.crash_permille = 0;
        return Ok(format!("{k}:{}", f.crash_at));
    }
    f.crash_permille = if v.is_empty() {
        CRASH_DEFAULT_PERMILLE
    } else {
        resolve_num(seed, "crash", v, 1000).map_err(|e| e.replace("--fault crash", "--crash"))?
    };
    f.crash_at = 0;
    Ok(format!("{k}:{}", f.crash_permille))
}

/// The presets and keys, for `patina run --help`.
pub fn help_text() -> String {
    let mut s = String::from(
        "\nfault presets (--faults NAME[,NAME]; each range is resolved from the seed):\n",
    );
    for (name, kv) in PRESETS {
        let v: Vec<String> = kv.iter().map(|(k, v)| format!("{k}={v}")).collect();
        s.push_str(&format!("  {name:<6} {}\n", v.join(" ")));
    }
    s.push_str("\nfault keys (--fault KEY=VALUE, or [faults] in patina.toml; P and N may be a range A..B):\n");
    for k in KEYS {
        let lhs = format!("{}={}", k.name, k.value);
        s.push_str(&format!("  {lhs:<34} {}\n", k.help));
    }
    s
}

/// The same tables as JSON.
pub fn help_json() -> Value {
    json!({
        "presets": PRESETS.iter().map(|(n, kv)| json!({
            "name": n,
            "settings": kv.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
        "keys": KEYS.iter().map(|k| json!({"name": k.name, "value": k.value, "help": k.help})).collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    fn val(p: &Plan, k: &str) -> Value {
        p.json()[k].clone()
    }

    #[test]
    fn ranges_resolve_from_the_seed_and_only_from_it() {
        let disk = v(&["disk"]);
        let a = resolve(1, &disk, &[], None, 0).unwrap();
        let b = resolve(1, &disk, &[], None, 0).unwrap();
        assert_eq!(a.json(), b.json());
        let rates: std::collections::BTreeSet<u64> = (0..64)
            .map(|s| {
                let p = resolve(s, &disk, &[], None, 0).unwrap();
                val(&p, "fs-short-permille").as_u64().unwrap()
            })
            .collect();
        assert!(
            rates.len() > 1 && rates.iter().all(|r| *r <= 20),
            "{rates:?}"
        );
    }

    #[test]
    fn one_setting_never_moves_another() {
        let disk = v(&["disk"]);
        for s in 0..32 {
            let a = resolve(s, &disk, &[], Some("machine:0..5"), 0).unwrap();
            let b = resolve(
                s,
                &disk,
                &v(&[
                    "net-chunk-max=1..4",
                    "net-chunk-gap-us=1..10",
                    "mem-limit-mb=10..20",
                ]),
                Some("machine:0..5"),
                0,
            )
            .unwrap();
            for (k, x) in &a.resolved {
                assert_eq!(&val(&b, k), x, "seed {s} key {k}");
            }
            let mut bf = b.faults;
            bf.mem_limit_bytes = 0;
            assert_eq!(a.faults, bf, "seed {s}");
        }
    }

    #[test]
    fn settings_replace_presets_and_unknowns_are_named() {
        let p = resolve(3, &v(&["disk"]), &v(&["fs-error-permille=7"]), None, 0).unwrap();
        assert_eq!(p.faults.fs_error_permille, 7);
        assert!(resolve(0, &v(&["dsk"]), &[], None, 0)
            .unwrap_err()
            .contains("dsk"));
        assert!(resolve(0, &[], &v(&["nope=1"]), None, 0)
            .unwrap_err()
            .contains("nope"));
        assert!(resolve(0, &[], &v(&["fs-error-permille=5..2"]), None, 0).is_err());
        assert!(resolve(0, &[], &v(&["fs-error-permille=0..1001"]), None, 0).is_err());
        let c = resolve(0, &[], &[], Some("machine"), 0).unwrap();
        assert_eq!(c.faults.crash_permille, CRASH_DEFAULT_PERMILLE);
    }

    #[test]
    fn positions_may_be_ranges() {
        let at = v(&[
            "fsync-error-at=1..100",
            "fs-error-at=write:5..9",
            "mem-error-at=3",
        ]);
        let mut seen = std::collections::BTreeSet::new();
        for s in 0..64 {
            let p = resolve(s, &[], &at, Some("machine-at:10..20"), 0).unwrap();
            let q = resolve(s, &[], &at, Some("machine-at:10..20"), 0).unwrap();
            assert_eq!(p.json(), q.json());
            let f = p.faults;
            assert!(
                (1..=100).contains(&f.fsync_error_at),
                "{}",
                f.fsync_error_at
            );
            assert!((5..=9).contains(&f.fs_error_at_n), "{}", f.fs_error_at_n);
            assert!((10..=20).contains(&f.crash_at), "{}", f.crash_at);
            assert_eq!(f.mem_error_at, 3);
            assert_eq!(
                val(&p, "fs-error-at"),
                json!(format!("write:{}", f.fs_error_at_n))
            );
            seen.insert(f.fsync_error_at);
        }
        assert!(seen.len() > 1, "{seen:?}");
        assert!(resolve(0, &[], &v(&["fsync-error-at=9..2"]), None, 0).is_err());
        assert!(resolve(0, &[], &[], Some("machine-at:x"), 0).is_err());
    }

    #[test]
    fn compute_gap_is_drawn_per_seed_and_never_swarmed() {
        let mut seen = std::collections::BTreeSet::new();
        for s in 0..64 {
            let d = resolve(s, &[], &[], None, 0).unwrap();
            let (lo, hi) = proto::compute::GAP_DEFAULT;
            assert!((lo..=hi).contains(&d.compute_gap), "{}", d.compute_gap);
            assert!(d.resolved.is_empty() && d.compute_budget);
            seen.insert(d.compute_gap);
            let p = resolve(s, &[], &v(&["compute-gap=8", "swarm=1"]), None, 0).unwrap();
            assert_eq!((p.compute_gap, val(&p, "compute-gap")), (8, json!(8)));
            assert!(!p.compute_budget);
            let r = resolve(s, &[], &v(&["compute-gap=100..200"]), None, 0).unwrap();
            assert!((100..=200).contains(&r.compute_gap));
            assert_eq!(val(&r, "compute-gap"), json!(r.compute_gap));
        }
        assert!(seen.len() > 8, "{seen:?}");
        assert_eq!(
            resolve(0, &[], &v(&["compute-gap=0"]), None, 0)
                .unwrap()
                .compute_gap,
            0
        );
        for bad in ["compute-gap=0..8", "compute-gap=9..8", "compute-gap=x"] {
            assert!(resolve(0, &[], &v(&[bad]), None, 0).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_size_range_draws_log_uniformly_and_a_size_stays_put() {
        let mut small = 0;
        let mut seen = std::collections::BTreeSet::new();
        for s in 0..256 {
            let p = resolve(s, &v(&["net"]), &[], None, 0).unwrap();
            let c = p.net.chunk_max;
            assert!(
                (1..=65536).contains(&c) && val(&p, "net-chunk-max") == json!(c),
                "{c}"
            );
            small += (c <= 16) as u32;
            seen.insert(c);
            let one = resolve(s, &[], &v(&["net-chunk-max=7"]), None, 0).unwrap();
            assert_eq!(one.net.chunk_max, 7);
        }
        // Log-uniform: about a quarter of seeds at 16 bytes or less (uniform: one in 4096).
        assert!(
            (32..=100).contains(&small) && seen.len() > 64,
            "{small} {}",
            seen.len()
        );
        assert!(resolve(0, &[], &v(&["net-chunk-max=0..8"]), None, 0).is_err());
        let g = resolve(0, &[], &v(&["net-chunk-gap-us=1..10"]), None, 0).unwrap();
        assert_eq!(
            (
                g.net.chunk_gap_set,
                g.net.chunk_gap_min_ns,
                g.net.chunk_gap_max_ns
            ),
            (1, 1000, 10_000)
        );
        assert!(resolve(0, &[], &v(&["net-chunk-gap-us=5"]), None, 0).is_err());
    }

    #[test]
    fn partitions_come_with_two_nodes_and_never_without() {
        let net = v(&["net"]);
        // Without nodes, and with one node the faults act on, `net` is what it always was.
        for nodes in [0, 1] {
            for s in 0..8 {
                let p = resolve(s, &net, &[], None, nodes).unwrap();
                let q = resolve(s, &net, &[], None, 0).unwrap();
                assert_eq!(p.json(), q.json());
                assert_eq!(p.net, q.net);
            }
        }
        let p = resolve(5, &net, &[], None, 2).unwrap();
        assert!(p.net.part_gap_max_ns >= p.net.part_gap_min_ns && p.net.part_gap_min_ns > 0);
        assert!(p.net.part_shapes != 0 && p.net.part_min_ns > 0);
        // One node and the driver's links: two nodes to cut between.
        let d = resolve(5, &net, &v(&["net-links=driver"]), None, 1).unwrap();
        assert!(d.net.part_gap_max_ns > 0);
        assert!(resolve(0, &[], &v(&["partition-gap-ms=1..2"]), None, 1).is_err());
        assert!(resolve(0, &[], &v(&["partition-gap-ms=1..2"]), None, 0).is_err());
        assert!(resolve(0, &[], &v(&["net-links=driver"]), None, 0).is_err());
        let one = resolve(
            0,
            &[],
            &v(&["partition-gap-ms=10..20", "partition-shape=oneway,bridge"]),
            None,
            3,
        )
        .unwrap();
        assert_eq!(one.net.part_gap_min_ns, 10_000_000);
        assert_eq!(
            one.net.part_shapes,
            1 << proto::node::SHAPE_ONEWAY | 1 << proto::node::SHAPE_BRIDGE
        );
        // The default length.
        assert_eq!(one.net.part_min_ns, 1_000_000_000);
        assert!(resolve(0, &[], &v(&["partition-shape=ring"]), None, 3).is_err());
        let e = resolve(0, &[], &v(&["net-partition=1+2"]), None, 0).unwrap_err();
        assert!(e.contains("net-blackout"), "{e}");
    }

    #[test]
    fn a_node_is_down_briefly_by_default() {
        let p = resolve(3, &[], &[], Some("process"), 3).unwrap();
        let s = 1_000_000_000;
        assert!(p.down_ns.0 >= s && p.down_ns.1 <= 5 * s, "{:?}", p.down_ns);
        assert!(p.down_ns.1 <= p.crash_gap_ns.0, "{:?}", p.down_ns);
        // The restart gap of a run without nodes is its own.
        let one = resolve(3, &[], &[], Some("machine"), 0).unwrap();
        assert_eq!(one.restart_gap_ns, (s, 61 * s));
    }

    #[test]
    fn a_scope_follows_the_value() {
        assert_eq!(
            split_scope("fs-error-permille=5@a,b"),
            ("fs-error-permille=5", Some("a,b"))
        );
        assert_eq!(split_scope("disk@a"), ("disk", Some("a")));
        assert_eq!(split_scope("point:db@retry=5"), ("point:db@retry=5", None));
        assert_eq!(
            split_scope("fs-error-permille=5"),
            ("fs-error-permille=5", None)
        );
    }

    #[test]
    fn swarm_turns_classes_off_per_seed() {
        let all = v(&["all"]);
        let offs: std::collections::BTreeSet<usize> = (0..32)
            .map(|s| {
                let p = resolve(s, &all, &v(&["swarm=1"]), None, 0).unwrap();
                p.resolved.iter().filter(|e| e.1 == json!("off")).count()
            })
            .collect();
        assert!(offs.len() > 2, "{offs:?}");
    }
}
