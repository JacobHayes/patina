//! The fault plan of a run: classes (`--faults CLASS`, `[faults] faults`) and single settings
//! (`--fault KEY=VALUE`, `[faults] KEY`), resolved against the seed into the runtime's, the
//! wire's and the SDK's configurations. A class turns on its keys (`CLASSES`); `buggify`,
//! `crash` and `kill` turn on what has no key of its own (every fault point; a crash's kind).
//!
//! A value may be a range `A..B`: the run's value is drawn from the seed, uniformly in the
//! range, by a draw keyed by the setting's name (`plan_draw`). Adding, removing or changing
//! one setting therefore never moves another's value, nor any other decision of the run.
//! The resolved values are the plan (`Plan::resolved`), written to `run.json` and to
//! `result.json`'s `faults.plan`: the seed and the configuration are the whole run.

use crate::cli::Res;
use proto::faults::{FClass, CRASH_MACHINE, CRASH_PROCESS};
use serde_json::{json, Value};

/// Incarnations a run may start when `max-incarnations` is not given.
pub const MAX_INCARNATIONS_DEFAULT: u64 = 4;
/// `crash-permille` of the `crash` and `kill` classes at crash points when no crash key is given.
pub const CRASH_DEFAULT_PERMILLE: u64 = 3;
/// `down-ms` on one machine when not given: 1 s to 61 s.
pub const RESTART_GAP_DEFAULT: (u64, u64) = (1_000_000_000, 61_000_000_000);
/// `down-ms` with nodes when not given: 1 s to 5 s. Short beside `crash-gap-ms`, so that with several
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
    /// `max-incarnations=N`: crashes stop once the run has started N incarnations.
    pub max_incarnations: u64,
    /// `down-ms=A..B` on one machine: virtual time from a crash to the restart, drawn per
    /// restart in [A, B) ns (A when A = B).
    pub restart_gap_ns: (u64, u64),
    /// With nodes: `crash-gap-ms` and `down-ms` (ns), and the nodes the seed kills
    /// (`--faults kill[@NODE,...]`; bit `k` for node `k`).
    pub crash_gap_ns: (u64, u64),
    pub down_ns: (u64, u64),
    pub node_crash: u64,
    /// What the seed's kills of those nodes do (`proto::node::CRASH_NODE_*`).
    pub node_crash_kind: u64,
    /// `net-*` keys.
    pub net: proto::wire::NetCfg,
    /// The `buggify` class, `buggify:LABEL=N` (`proto::sdk`).
    pub sdk: proto::sdk::SdkCfg,
    /// The crash kind the `crash` or `kill` class, or a crash key, names (`CRASH_*`; 0: none).
    /// Set in `faults` too when the crash comes at crash points (`Ctx::crash_points`).
    pub crash_class: u64,
    /// Compute points: the run's mean gap in events (`compute-gap`; 0: no compute switches).
    pub compute_gap: u64,
    /// Whether the switch budget applies (`proto::compute::budget`): only to a gap drawn by
    /// default, and not in a process whose rebuilt code said hello; a plan that names
    /// `compute-gap` gets that gap for the whole run.
    pub compute_budget: bool,
    /// Load-time points: the longest walk of a switch past its site, in instructions
    /// (`Config::compute_walk`; 0: switches are taken at their sites).
    pub compute_walk: u64,
    /// With nodes: each node's disk, memory and crash-point settings (`NodeTab::faults`; the
    /// driver's are in `faults`, entry 0 unused), and its fault points (`NodeTab::sdk`).
    pub node_faults: [proto::faults::FaultCfg; proto::node::MAX_NODES],
    pub node_sdk: [proto::sdk::SdkCfg; proto::node::MAX_NODES],
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
    /// number or a string.
    pub resolved: Vec<(String, Value)>,
}

/// How a key's value is read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Val {
    /// 0 to 1000; may be a range.
    Permille,
    /// A count; may be a range.
    Count,
    /// A count; may be a range; a parameter of another class.
    Param,
    /// A size in bytes; a range `A..B` (A at least 1) draws log-uniformly, since sizes span
    /// orders of magnitude.
    Size,
    /// The key's own grammar, like `Own`, for a parameter of another class.
    Spread,
    /// The key's own grammar (`A..B` milliseconds are the per-event spread, not a plan
    /// range).
    Own,
    /// A position (the N-th call): may be a range, which searches positions across seeds.
    At,
    /// `compute-gap`: `A..B` draws log-uniformly, not uniformly.
    Gap,
    /// A window `START+LENGTH[:PORT]` in milliseconds, START and LENGTH each a number or a
    /// range resolved like any other (LENGTH by the draw of `KEY:length`).
    Window,
    /// A word, as given: never drawn.
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
        "delay a call in virtual time, by up to 10 ms",
    ),
    key(
        "fsync-error-permille",
        "P",
        Val::Permille,
        "fail the write-back of a sync call (fsync, fdatasync, msync, syncfs, sync_file_range, an O_SYNC write): its unsynced data never becomes durable; the error is reported as Linux reports it, once to each open file description, an unseen one also to a later opener",
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
        "net-links",
        "nodes|driver|all",
        Val::Word,
        "in a run with nodes, the links the net- faults and partitions act on: between two nodes other than the driver; also the driver's; also every node's loopback (partitions never cut loopback) [default: nodes]",
    ),
    key(
        "partition-gap-ms",
        "A..B",
        Val::Own,
        "in a run with nodes, seed-drawn partitions: virtual time from the start of the run, then from each partition's end, to the next one's start, a draw in A..B ms each time",
    ),
    key(
        "partition-ms",
        "A..B",
        Val::Spread,
        "how long each partition lasts: a draw in A..B ms [default: 1000..30000]",
    ),
    key(
        "pause-gap-ms",
        "A..B",
        Val::Own,
        "in a run with nodes, seed-drawn pauses of each node (all its threads stop; its links hold): virtual time from the run's start, then from each pause's end, to the node's next pause, a draw in A..B ms each time; each node's own (@NODE scopes it)",
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
        "buggify:LABEL",
        "P",
        Val::Permille,
        "the SDK fault point LABEL fires at this rate (alone: only the points named fire)",
    ),
    key(
        "crash-permille",
        "P",
        Val::Permille,
        "crash at each crash point (after each change to /work, before each sync) at this rate (implies crash; with kill, a kill) [default with the class: 3]",
    ),
    key(
        "crash-at",
        "N",
        Val::At,
        "crash at exactly the N-th crash point of the first incarnation (implies crash; with kill, a kill)",
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
        "with nodes: virtual time from a node's start to the seed's crash (or kill) of it, a draw in A..B ms for each boot (implies crash) [default: 5000..60000]",
    ),
    key(
        "down-ms",
        "A..B",
        Val::Spread,
        "virtual time from a crash to the restart, a draw in A..B ms for each restart [default: 1000..61000; with nodes, each node's, 1000..5000]",
    ),
    key(
        "compute-gap",
        "G|A..B",
        Val::Gap,
        "load-time and rebuilt compute points: mean events between switches, drawn log-uniformly per seed from A..B; 0 turns switches off [default: half the seeds 1..16, half 16..65536, load-time points held to a switch budget]",
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
];

/// The fault classes (`--faults CLASS`): each turns on its keys, every value a range the seed
/// resolves. `buggify`, `crash` and `kill` have none of their own: they turn on every fault
/// point, and a crash of their kind (`CRASH_DEFAULT_PERMILLE` at each crash point on one
/// machine, at drawn times with nodes). `net-reset-permille` is drawn for each send, so its
/// rate is high enough that a connection carrying a few dozen sends (a keep-alive client's)
/// meets a reset in a good share of seeds. `partition`, `pause` and `clock` act on nodes.
pub const CLASSES: &[(&str, &[(&str, &str)])] = &[
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
            ("net-reset-permille", "5..50"),
            ("net-connect-refuse-permille", "0..10"),
            ("net-drop-permille", "0..50"),
            ("net-dup-permille", "0..20"),
            ("net-reorder-permille", "0..50"),
        ],
    ),
    ("mem", &[("mem-error-permille", "0..2")]),
    ("buggify", &[]),
    ("crash", &[]),
    ("kill", &[]),
    (
        "partition",
        &[
            ("partition-gap-ms", "5000..60000"),
            ("partition-ms", "500..20000"),
        ],
    ),
    (
        "pause",
        &[
            ("pause-gap-ms", "10000..120000"),
            ("pause-ms", "100..15000"),
        ],
    ),
    ("clock", &[("clock-skew-ms", "0..2000")]),
];

/// `all`: every class that applies to the run but `crash` and `kill`, which a program must be
/// written to survive (it restarts on what its disk kept).
pub const ALL: &[&str] = &[
    "disk",
    "net",
    "mem",
    "buggify",
    "partition",
    "pause",
    "clock",
];

/// The classes that act on nodes only, and that `all` leaves out of a run without them (or,
/// `partition`, without two nodes the link faults act on).
pub fn needs_nodes(class: &str) -> bool {
    matches!(class, "partition" | "pause" | "clock")
}

/// The classes that are each node's (`@NODE` scopes them); `net` and `partition` are the
/// links', the run's.
pub fn node_class(class: &str) -> bool {
    !matches!(class, "net" | "partition")
}

/// The keys of class `c`.
pub fn class_keys(c: &str) -> Res<&'static [(&'static str, &'static str)]> {
    CLASSES
        .iter()
        .find(|x| x.0 == c)
        .map(|x| x.1)
        .ok_or_else(|| {
            let names: Vec<&str> = CLASSES.iter().map(|x| x.0).chain(["all"]).collect();
            format!("--faults: unknown class {c} ({})", names.join(", "))
        })
}

/// The classes a list names (`NAME,...` without its scope), `all` expanded for a run with
/// `nodes` nodes of which `faultable` the link faults act on: a class that needs nodes is
/// left out of `all` when it has nothing to act on, and refused when named. Each class once.
pub fn classes(list: &str, nodes: usize, faultable: usize) -> Res<Vec<&'static str>> {
    let mut out: Vec<&'static str> = vec![];
    for name in list.split(',').map(str::trim).filter(|n| !n.is_empty()) {
        let names: Vec<&'static str> = if name == "all" {
            ALL.iter()
                .copied()
                .filter(|c| !needs_nodes(c) || nodes > 0)
                .filter(|c| *c != "partition" || faultable >= 2)
                .collect()
        } else {
            let k = CLASSES
                .iter()
                .find(|x| x.0 == name)
                .map(|x| x.0)
                .ok_or_else(|| class_keys(name).unwrap_err())?;
            if needs_nodes(k) && nodes == 0 {
                return Err(format!("--faults {k}: only in a run with nodes"));
            }
            if k == "partition" && faultable < 2 {
                return Err(format!(
                    "--faults partition: partitions need two nodes the link faults act on (the run has {nodes}; net-links=driver adds the driver)"
                ));
            }
            vec![k]
        };
        for c in names {
            if !out.contains(&c) {
                out.push(c);
            }
        }
    }
    if out.contains(&"crash") && out.contains(&"kill") {
        return Err("--faults crash,kill: a machine crashes or its processes are killed, not both (one of them)".into());
    }
    Ok(out)
}

/// `partition-ms` when partitions are on and it is not given.
const PARTITION_MS_DEFAULT: &str = "1000..30000";

/// The longest `fs-delay-permille` delay.
const DELAY_MAX_NS: u64 = 10_000_000;
/// The time between the pieces of a split delivery (`net-chunk-max`): 1 to 10 µs.
const CHUNK_GAP_NS: (u64, u64) = (1_000, 10_000);

fn find(k: &str) -> Option<&'static Key> {
    let name = if k.starts_with("buggify:") {
        "buggify:LABEL"
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

/// The longest walk past a switch point, `W` or `A..B` drawn as `resolve_gap` draws (the test
/// input `PATINA_TEST_COMPUTE_WALK`, `Config::compute_walk`).
pub fn walk(seed: u64, v: &str) -> Res<u64> {
    resolve_gap(seed, "compute-walk", v)
}

/// `compute-gap=G|A..B` (the run's mean gap) and the longest walk (`walk`): a range drawn
/// log-uniformly by the key's own plan draw (`proto::compute::mean_gap`). `0` turns compute
/// switches, or walks, off.
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
/// (`proto::draw::log_uniform`) by the key's own plan draw.
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
    Ok(proto::draw::log_uniform(plan_draw(seed, k), a, b))
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
pub fn faultable_nodes(nodes: usize, settings: &[String]) -> Res<usize> {
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

/// A key each node has its own value of: the disk, memory, crash-point, fault-point, pause
/// and clock keys. In a run with nodes the run's value applies to every node but the driver,
/// and `@NODE,...` scopes it.
pub fn node_scoped(k: &str) -> bool {
    k.starts_with("fs-")
        || k.starts_with("fsync-")
        || k.starts_with("mem-")
        || k.starts_with("path-swap-")
        || k.starts_with("buggify:")
        || matches!(k, "crash-permille" | "crash-at")
        || node_only(k)
}

/// A node's own key that only a node has (the driver is never paused): refused in a run
/// without nodes, and for the driver.
pub fn node_only(k: &str) -> bool {
    k.starts_with("pause-") || k.starts_with("clock-")
}

/// `SETTING@NODE,...`: the setting and the nodes it names (`None`: no scope). A setting's
/// scope follows its value (`KEY=VALUE@NODE`): an `@` in the key (`buggify:LABEL`) is the key's.
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
    dst.short_permille = src.short_permille;
    dst.fsync_error_permille = src.fsync_error_permille;
    dst.fsync_error_at = src.fsync_error_at;
    (dst.delay_permille, dst.delay_max_ns) = (src.delay_permille, src.delay_max_ns);
    (dst.mem_error_permille, dst.mem_error_at) = (src.mem_error_permille, src.mem_error_at);
    dst.mem_limit_bytes = src.mem_limit_bytes;
    dst.path_swap_permille = src.path_swap_permille;
    (dst.crash_kind, dst.crash_permille, dst.crash_at) =
        (src.crash_kind, src.crash_permille, src.crash_at);
    dst.any |= src.any;
}

/// A class's settings, as `resolve` applies them (settings given beside it win): `minimize`
/// replaces a class with them.
pub fn class_settings(c: &str) -> Res<Vec<(String, String)>> {
    Ok(class_keys(c)?
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect())
}

/// Where a crash comes when the `crash` or `kill` class names no crash key: at crash points
/// (`CRASH_DEFAULT_PERMILLE`; one machine, or nodes some of which name a crash key), or at
/// drawn times (nodes: `crash-gap-ms`, set by the caller).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrashAt {
    Points,
    Times,
}

/// Resolve classes (as `classes` expands them) and settings (later ones replace earlier ones
/// of the same key, settings replace a class's) against `seed`. `nodes` is the run's nodes
/// besides the driver (0: a run without nodes, or a node's own settings).
pub fn resolve(
    seed: u64,
    classes: &[&str],
    settings: &[String],
    nodes: usize,
    crash_at: CrashAt,
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
        if find(k).is_none() {
            return Err(format!("--fault: unknown key {k}"));
        }
        named.push((k, v));
    }
    for c in classes {
        for (k, v) in class_keys(c)? {
            set(&mut given, k, v);
        }
    }
    for (k, v) in named {
        set(&mut given, k, v);
    }
    let faultable = faultable_nodes(nodes, settings)?;
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
            e.0.starts_with("partition-") || matches!(e.0.as_str(), "net-links" | "crash-gap-ms")
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
    // A crash: of the kind its class names (a crash key alone: the machine's), where a crash
    // key says, or by default.
    let has = |given: &[(String, String)], k: &str| given.iter().any(|e| e.0 == k);
    let (rate, at) = (has(&given, "crash-permille"), has(&given, "crash-at"));
    if rate && at {
        return Err(
            "--fault crash-permille and crash-at: one or the other (at a rate, or at one point)"
                .into(),
        );
    }
    let crash_class = if classes.contains(&"kill") {
        CRASH_PROCESS
    } else if classes.contains(&"crash") || rate || at {
        CRASH_MACHINE
    } else {
        proto::faults::CRASH_NONE
    };
    if crash_class != proto::faults::CRASH_NONE && crash_at == CrashAt::Points && !rate && !at {
        set(
            &mut given,
            "crash-permille",
            &CRASH_DEFAULT_PERMILLE.to_string(),
        );
    }
    given.sort();
    // The default is not part of the plan: a run that does not name the key resolves it the
    // same way every time, and a stock program's plan reads as before.
    let (wlo, whi) = proto::compute::WALK_DEFAULT;
    let mut plan = Plan {
        faults: Default::default(),
        max_incarnations: MAX_INCARNATIONS_DEFAULT,
        restart_gap_ns: RESTART_GAP_DEFAULT,
        crash_gap_ns: CRASH_GAP_DEFAULT,
        down_ns: DOWN_DEFAULT,
        node_crash: 0,
        node_crash_kind: 0,
        net: Default::default(),
        sdk: proto::sdk::SdkCfg {
            seed,
            ..Default::default()
        },
        crash_class,
        compute_gap: proto::compute::default_gap(plan_draw(seed, "compute-gap")),
        compute_budget: true,
        compute_walk: resolve_gap(seed, "compute-walk", &format!("{wlo}..{whi}"))?,
        node_faults: Default::default(),
        node_sdk: Default::default(),
        pause_gap_ns: (0, 0),
        pause_ns: (0, 0),
        node_pause: Default::default(),
        skew_ns: (0, 0),
        node_skew: Default::default(),
        resolved: vec![],
    };
    for (k, v) in &given {
        let info = find(k).unwrap();
        let value: Value = match info.val {
            Val::Permille => json!(resolve_num(seed, k, v, 1000)?),
            Val::Count | Val::Param => json!(resolve_num(seed, k, v, u64::MAX / 2)?),
            Val::Size => json!(resolve_size(seed, k, v)?),
            Val::Own | Val::Spread | Val::Word => json!(v),
            Val::Window => json!(resolve_window(seed, k, v)?),
            Val::At => json!(resolve_at(seed, k, v)?),
            Val::Gap => {
                let g = resolve_gap(seed, k, v)?;
                (plan.compute_gap, plan.compute_budget) = (g, false);
                plan.resolved.push((k.clone(), json!(g)));
                continue;
            }
        };
        let s = match &value {
            Value::String(s) => s.clone(),
            x => x.to_string(),
        };
        apply(&mut plan, k, &s)?;
        plan.resolved.push((k.clone(), value));
    }
    if plan.faults.delay_permille != 0 {
        plan.faults.delay_max_ns = DELAY_MAX_NS;
    }
    // The pieces of a split delivery follow each other closely, as a sender's segments do.
    if plan.net.chunk_max != 0 {
        (plan.net.chunk_gap_min_ns, plan.net.chunk_gap_max_ns) = CHUNK_GAP_NS;
        plan.net.chunk_gap_set = 1;
    }
    if crash_class != proto::faults::CRASH_NONE {
        let kind = if crash_class == CRASH_PROCESS {
            "process"
        } else {
            "machine"
        };
        plan.resolved.push(("crash".into(), json!(kind)));
        if crash_at == CrashAt::Points || rate || at {
            plan.faults.crash_kind = crash_class;
        }
    }
    // Every fault point (the class), or only the points named.
    if classes.contains(&"buggify") {
        plan.sdk.buggify = proto::sdk::BUGGIFY_ALL;
        plan.resolved.push(("buggify".into(), json!("all")));
    } else if plan.sdk.npoints != 0 {
        plan.sdk.buggify = proto::sdk::BUGGIFY_NAMED;
    }
    Ok(plan)
}

/// Whether a plan injects anything: a setting or class beyond the limits and timings that
/// shape a run without faults (`compute-*`, `max-incarnations`, `down-ms`, `net-links`,
/// `mem-limit-mb`, `crash-gap-ms`).
pub fn injects(p: &Plan) -> bool {
    p.resolved.iter().any(|(k, _)| {
        let k = k.split('@').next().unwrap_or(k);
        !(k.starts_with("compute-")
            || matches!(
                k,
                "max-incarnations" | "down-ms" | "net-links" | "mem-limit-mb" | "crash-gap-ms"
            ))
    })
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
        "fs-short-permille" => f.short_permille = n(v)?,
        "fsync-error-permille" => f.fsync_error_permille = n(v)?,
        "fsync-error-at" => f.fsync_error_at = n(v)?,
        "fs-delay-permille" => f.delay_permille = n(v)?,
        "mem-error-permille" => f.mem_error_permille = n(v)?,
        "mem-error-at" => f.mem_error_at = n(v)?,
        "path-swap-permille" => f.path_swap_permille = n(v)?,
        "mem-limit-mb" => {
            // A limit, not a draw: it holds whether or not other faults are active.
            f.mem_limit_bytes = n(v)?.saturating_mul(1 << 20);
            return Ok(());
        }
        "crash-gap-ms" => {
            o.crash_gap_ns = ms_range(k, v)?;
            return Ok(());
        }
        "down-ms" => {
            // One machine's restart, or each node's: the run has one or the other.
            o.down_ns = ms_range(k, v)?;
            o.restart_gap_ns = o.down_ns;
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
        // The kind is the class's (`resolve`).
        "crash-permille" => {
            f.crash_permille = n(v)?;
            return Ok(());
        }
        "crash-at" => {
            f.crash_at = n(v)?.max(1);
            return Ok(());
        }
        _ if k.starts_with("buggify:") => return point(&mut o.sdk, &k["buggify:".len()..], n(v)?),
        "partition-gap-ms" => {
            (o.net.part_gap_min_ns, o.net.part_gap_max_ns) = ms_range(k, v)?;
            if o.net.part_gap_min_ns == 0 {
                return Err(format!("--fault {k}={v}: A is at least 1"));
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
        _ if k.starts_with("net-") => return net_fault(&mut o.net, k, v),
        _ => return Err(format!("--fault: unknown key {k}")),
    }
    o.faults.any = 1;
    Ok(())
}

/// `buggify:LABEL=PERMILLE`: the SDK fault point LABEL is active and fires at this rate
/// (0: never). Without the `buggify` class only the points named fire.
fn point(c: &mut proto::sdk::SdkCfg, label: &str, p: u64) -> Res<()> {
    if label.is_empty() || label.len() > proto::sdk::LABEL_MAX {
        return Err(format!(
            "--fault buggify:{label}: a label is 1 to 255 bytes"
        ));
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
        "net-links" => c.links = links(v)?,
        "net-drop-permille" => c.drop_permille = n(v)?,
        "net-dup-permille" => c.dup_permille = n(v)?,
        "net-reorder-permille" => c.reorder_permille = n(v)?,
        _ => return Err(format!("--fault: unknown key {k}")),
    }
    Ok(())
}

/// The classes and keys, for `--fault help`.
pub fn help_text() -> String {
    let mut s = String::from(
        "fault classes (--faults CLASS[,CLASS][@NODE,...]; each range is resolved from the seed):\n",
    );
    for (name, kv) in CLASSES {
        let v: Vec<String> = kv.iter().map(|(k, v)| format!("{k}={v}")).collect();
        let v = match *name {
            "buggify" => "every SDK fault point (buggify:LABEL=P sets one)".to_string(),
            "crash" => format!("machine crashes: crash-permille={CRASH_DEFAULT_PERMILLE} at crash points; with nodes at drawn times (crash-gap-ms)"),
            "kill" => "process kills, the disk kept: as crash".to_string(),
            "net" => format!("{} (no partitions: that is the partition class)", v.join(" ")),
            _ => v.join(" "),
        };
        s.push_str(&format!("  {name:<9} {v}\n"));
    }
    s.push_str(&format!(
        "  {:<9} {}\n",
        "all",
        "every class above that applies to the run, never crash or kill (name them: all,crash)"
    ));
    s.push_str("\nfault keys (--fault KEY=VALUE[@NODE,...], or [faults] in patina.toml; P and N may be a range A..B):\n");
    for k in KEYS {
        let lhs = format!("{}={}", k.name, k.value);
        s.push_str(&format!("  {lhs:<34} {}\n", k.help));
    }
    s
}

/// The same tables as JSON.
pub fn help_json() -> Value {
    json!({
        "classes": CLASSES.iter().map(|(n, kv)| json!({
            "name": n,
            "settings": kv.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
        "all": ALL,
        "keys": KEYS.iter().map(|k| json!({"name": k.name, "value": k.value, "help": k.help})).collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use CrashAt::{Points, Times};

    fn v(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    fn val(p: &Plan, k: &str) -> Value {
        p.json()[k].clone()
    }

    #[test]
    fn ranges_resolve_from_the_seed_and_only_from_it() {
        let disk = ["disk"];
        let a = resolve(1, &disk, &[], 0, Points).unwrap();
        let b = resolve(1, &disk, &[], 0, Points).unwrap();
        assert_eq!(a.json(), b.json());
        let rates: std::collections::BTreeSet<u64> = (0..64)
            .map(|s| {
                let p = resolve(s, &disk, &[], 0, Points).unwrap();
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
        let disk = ["disk"];
        for s in 0..32 {
            let a = resolve(s, &disk, &v(&["crash-permille=0..5"]), 0, Points).unwrap();
            let b = resolve(
                s,
                &disk,
                &v(&[
                    "crash-permille=0..5",
                    "net-chunk-max=1..4",
                    "mem-limit-mb=10..20",
                ]),
                0,
                Points,
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
        let p = resolve(3, &["disk"], &v(&["fs-error-permille=7"]), 0, Points).unwrap();
        assert_eq!(p.faults.fs_error_permille, 7);
        assert!(resolve(0, &["dsk"], &[], 0, Points)
            .unwrap_err()
            .contains("dsk"));
        assert!(resolve(0, &[], &v(&["nope=1"]), 0, Points)
            .unwrap_err()
            .contains("nope"));
        assert!(resolve(0, &[], &v(&["fs-error-permille=5..2"]), 0, Points).is_err());
        assert!(resolve(0, &[], &v(&["fs-error-permille=0..1001"]), 0, Points).is_err());
        let c = resolve(0, &["crash"], &[], 0, Points).unwrap();
        assert_eq!(c.faults.crash_permille, CRASH_DEFAULT_PERMILLE);
        assert_eq!(c.faults.crash_kind, CRASH_MACHINE);
        let k = resolve(0, &["kill"], &v(&["crash-at=4"]), 0, Points).unwrap();
        assert_eq!(
            (
                k.faults.crash_kind,
                k.faults.crash_at,
                k.faults.crash_permille
            ),
            (CRASH_PROCESS, 4, 0)
        );
        // A crash key alone crashes the machine; both keys, or a crash and a kill, are refused.
        let m = resolve(0, &[], &v(&["crash-permille=9"]), 0, Points).unwrap();
        assert_eq!(
            (m.faults.crash_kind, m.faults.crash_permille),
            (CRASH_MACHINE, 9)
        );
        assert!(resolve(0, &[], &v(&["crash-permille=9", "crash-at=2"]), 0, Points).is_err());
        assert!(classes("crash,kill", 0, 0).is_err());
        // At drawn times (nodes), the class says only what a crash is.
        let t = resolve(0, &["crash"], &[], 0, Times).unwrap();
        assert_eq!((t.crash_class, t.faults.crash_kind), (CRASH_MACHINE, 0));
    }

    #[test]
    fn positions_may_be_ranges() {
        let at = v(&[
            "fsync-error-at=1..100",
            "fs-error-at=write:5..9",
            "mem-error-at=3",
            "crash-at=10..20",
        ]);
        let mut seen = std::collections::BTreeSet::new();
        for s in 0..64 {
            let p = resolve(s, &[], &at, 0, Points).unwrap();
            let q = resolve(s, &[], &at, 0, Points).unwrap();
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
        assert!(resolve(0, &[], &v(&["fsync-error-at=9..2"]), 0, Points).is_err());
        assert!(resolve(0, &[], &v(&["crash-at=x"]), 0, Points).is_err());
    }

    #[test]
    fn compute_gap_is_drawn_per_seed() {
        let mut seen = std::collections::BTreeSet::new();
        for s in 0..64 {
            let d = resolve(s, &[], &[], 0, Points).unwrap();
            let (lo, hi) = (proto::compute::GAP_SMALL.0, proto::compute::GAP_LARGE.1);
            assert!((lo..=hi).contains(&d.compute_gap), "{}", d.compute_gap);
            assert!(d.resolved.is_empty() && d.compute_budget);
            seen.insert(d.compute_gap);
            let p = resolve(s, &[], &v(&["compute-gap=8"]), 0, Points).unwrap();
            assert_eq!((p.compute_gap, val(&p, "compute-gap")), (8, json!(8)));
            assert!(!p.compute_budget);
            let r = resolve(s, &[], &v(&["compute-gap=100..200"]), 0, Points).unwrap();
            assert!((100..=200).contains(&r.compute_gap));
            assert_eq!(val(&r, "compute-gap"), json!(r.compute_gap));
        }
        assert!(seen.len() > 8, "{seen:?}");
        assert_eq!(
            resolve(0, &[], &v(&["compute-gap=0"]), 0, Points)
                .unwrap()
                .compute_gap,
            0
        );
        for bad in ["compute-gap=0..8", "compute-gap=9..8", "compute-gap=x"] {
            assert!(resolve(0, &[], &v(&[bad]), 0, Points).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_size_range_draws_log_uniformly_and_a_size_stays_put() {
        let mut small = 0;
        let mut seen = std::collections::BTreeSet::new();
        for s in 0..256 {
            let p = resolve(s, &["net"], &[], 0, Points).unwrap();
            let c = p.net.chunk_max;
            assert!(
                (1..=65536).contains(&c) && val(&p, "net-chunk-max") == json!(c),
                "{c}"
            );
            small += (c <= 16) as u32;
            seen.insert(c);
            let one = resolve(s, &[], &v(&["net-chunk-max=7"]), 0, Points).unwrap();
            assert_eq!(one.net.chunk_max, 7);
        }
        // Log-uniform: about a quarter of seeds at 16 bytes or less (uniform: one in 4096).
        assert!(
            (32..=100).contains(&small) && seen.len() > 64,
            "{small} {}",
            seen.len()
        );
        assert!(resolve(0, &[], &v(&["net-chunk-max=0..8"]), 0, Points).is_err());
        // The pieces of a split delivery follow each other by 1 to 10 µs.
        let g = resolve(0, &[], &v(&["net-chunk-max=8"]), 0, Points).unwrap();
        assert_eq!(
            (
                g.net.chunk_gap_set,
                g.net.chunk_gap_min_ns,
                g.net.chunk_gap_max_ns
            ),
            (1, 1000, 10_000)
        );
        assert_eq!(
            resolve(0, &[], &[], 0, Points).unwrap().net.chunk_gap_set,
            0
        );
    }

    #[test]
    fn partitions_come_with_their_class_and_two_nodes() {
        let net = ["net"];
        // `net` is the links' faults alone, whatever the nodes.
        for nodes in [0, 1, 2] {
            for s in 0..8 {
                let p = resolve(s, &net, &[], nodes, Points).unwrap();
                let q = resolve(s, &net, &[], 0, Points).unwrap();
                assert_eq!(p.json(), q.json());
                assert_eq!(p.net, q.net);
            }
        }
        let p = resolve(5, &["partition"], &[], 2, Points).unwrap();
        assert!(p.net.part_gap_max_ns >= p.net.part_gap_min_ns && p.net.part_gap_min_ns > 0);
        assert!(p.net.part_min_ns > 0);
        // `all` leaves out what has nothing to act on; naming it is refused.
        assert_eq!(
            classes("all", 0, 0).unwrap(),
            ["disk", "net", "mem", "buggify"]
        );
        assert!(classes("all", 1, 1).unwrap().contains(&"pause"));
        assert!(!classes("all", 1, 1).unwrap().contains(&"partition"));
        assert!(classes("all", 2, 2).unwrap().contains(&"partition"));
        assert!(classes("partition", 1, 1).is_err());
        assert!(classes("pause", 0, 0).is_err());
        assert!(classes("cluster", 2, 2).is_err());
        // One node and the driver's links: two nodes to cut between.
        let d = resolve(5, &["partition"], &v(&["net-links=driver"]), 1, Points).unwrap();
        assert!(d.net.part_gap_max_ns > 0);
        assert!(resolve(0, &[], &v(&["partition-gap-ms=1..2"]), 1, Points).is_err());
        assert!(resolve(0, &[], &v(&["partition-gap-ms=1..2"]), 0, Points).is_err());
        assert!(resolve(0, &[], &v(&["net-links=driver"]), 0, Points).is_err());
        let one = resolve(0, &[], &v(&["partition-gap-ms=10..20"]), 3, Points).unwrap();
        assert_eq!(one.net.part_gap_min_ns, 10_000_000);
        // The default length.
        assert_eq!(one.net.part_min_ns, 1_000_000_000);
    }

    #[test]
    fn a_node_is_down_briefly_by_default() {
        let p = resolve(3, &["kill"], &[], 3, Times).unwrap();
        let s = 1_000_000_000;
        assert!(p.down_ns.0 >= s && p.down_ns.1 <= 5 * s, "{:?}", p.down_ns);
        assert!(p.down_ns.1 <= p.crash_gap_ns.0, "{:?}", p.down_ns);
        // The restart gap of a run without nodes is its own.
        let one = resolve(3, &["crash"], &[], 0, Points).unwrap();
        assert_eq!(one.restart_gap_ns, (s, 61 * s));
    }

    #[test]
    fn a_scope_follows_the_value() {
        assert_eq!(
            split_scope("fs-error-permille=5@a,b"),
            ("fs-error-permille=5", Some("a,b"))
        );
        assert_eq!(split_scope("disk@a"), ("disk", Some("a")));
        assert_eq!(
            split_scope("buggify:db@retry=5"),
            ("buggify:db@retry=5", None)
        );
        assert_eq!(
            split_scope("fs-error-permille=5"),
            ("fs-error-permille=5", None)
        );
    }
}
