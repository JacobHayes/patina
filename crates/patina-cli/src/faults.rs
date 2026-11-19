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

/// The fault plan of a run.
#[derive(Clone, Debug)]
pub struct Plan {
    pub faults: proto::faults::FaultCfg,
    /// `faults-in-recovery=0`: no faults other than crashes after the first crash.
    pub faults_in_recovery: bool,
    /// `max-incarnations=N`: crashes stop once the run has started N incarnations.
    pub max_incarnations: u64,
    /// `net-*` keys.
    pub net: proto::wire::NetCfg,
    /// `--buggify`, `buggify-permille=N`, `point:LABEL=N` (`proto::sdk`).
    pub sdk: proto::sdk::SdkCfg,
    /// Compute points: the run's mean gap in events (`compute-gap`; 0: no compute switches).
    pub compute_gap: u64,
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
    /// `compute-gap`: `A..B` draws log-uniformly, not uniformly; never swarmed.
    Gap,
    /// A window `START+LENGTH[:PORT]` in milliseconds, START and LENGTH each a number or a
    /// range resolved like any other (LENGTH by the draw of `KEY:length`); a class `swarm`
    /// may turn off.
    Window,
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
        "fail an fsync: reported once, the unsynced data never becomes durable",
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
        "net-partition",
        "START+LENGTH[:PORT]",
        Val::Window,
        "for LENGTH ms of virtual time from START ms, hold TCP deliveries and lose datagrams (from or to PORT); START and LENGTH are each a number or a range A..B drawn per seed",
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
        "max-incarnations",
        "N",
        Val::Param,
        "at most N incarnations: no crash in the N-th, so a run restarts at most N-1 times [default: 4]",
    ),
    key(
        "compute-gap",
        "G|A..B",
        Val::Gap,
        "rebuilt code (compute points): mean events between switches, drawn log-uniformly per seed from A..B; 0 turns switches off [default: 64..65536]",
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
        "fail exactly the N-th fsync",
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
];

/// The crash rate `--crash KIND` takes when none is given (per mille, at each crash point).
pub const CRASH_DEFAULT_PERMILLE: u64 = 3;
/// `fs-delay-max-ms` when not given.
const DELAY_MAX_MS_DEFAULT: u64 = 10;

fn find(k: &str) -> Option<&'static Key> {
    let name = if k.starts_with("point:") {
        "point:LABEL"
    } else {
        k
    };
    KEYS.iter().find(|x| x.name == name)
}

/// The draw that resolves the setting `name`: its own stream, keyed by the name only.
pub fn plan_draw(seed: u64, name: &str) -> u64 {
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

/// `compute-gap=G|A..B`: the run's mean gap, a range drawn log-uniformly by the key's own
/// plan draw (`proto::compute::mean_gap`). `0` turns compute switches off.
fn resolve_gap(seed: u64, k: &str, v: &str) -> Res<u64> {
    let max = proto::compute::GAP_MAX;
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
            "--fault {k}={v}: a range starts at 1 (0 alone turns switches off)"
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

/// Resolve presets, settings (later ones replace earlier ones of the same key, settings
/// replace presets) and `--crash` against `seed`.
pub fn resolve(
    seed: u64,
    presets: &[String],
    settings: &[String],
    crash: Option<&str>,
) -> Res<Plan> {
    let mut given: Vec<(String, String)> = vec![];
    let mut set = |k: &str, v: &str| match given.iter_mut().find(|e| e.0 == k) {
        Some(e) => e.1 = v.to_string(),
        None => given.push((k.to_string(), v.to_string())),
    };
    for p in presets.iter().flat_map(|p| p.split(',')) {
        let (_, kv) = PRESETS.iter().find(|x| x.0 == p).ok_or_else(|| {
            let names: Vec<&str> = PRESETS.iter().map(|x| x.0).collect();
            format!("--faults: unknown preset {p} ({})", names.join(", "))
        })?;
        for (k, v) in kv.iter() {
            set(k, v);
        }
    }
    for kv in settings {
        let (k, v) = kv
            .split_once('=')
            .ok_or_else(|| format!("--fault {kv}: expected KEY=VALUE"))?;
        if find(k).is_none() {
            return Err(format!("--fault: unknown key {k}"));
        }
        set(k, v);
    }
    given.sort();
    let swarm = match given.iter().position(|e| e.0 == "swarm") {
        Some(i) => num("swarm", &given.remove(i).1)? != 0,
        None => false,
    };
    // The default is not part of the plan: a run that does not name the key resolves it the
    // same way every time, and a stock program's plan reads as before.
    let (lo, hi) = proto::compute::GAP_DEFAULT;
    let mut plan = Plan {
        faults: Default::default(),
        faults_in_recovery: true,
        max_incarnations: MAX_INCARNATIONS_DEFAULT,
        net: Default::default(),
        sdk: Default::default(),
        compute_gap: resolve_gap(seed, "compute-gap", &format!("{lo}..{hi}"))?,
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
            Val::Own | Val::Spread => json!(v),
            Val::Window => json!(resolve_window(seed, k, v)?),
            Val::At => json!(resolve_at(seed, k, v)?),
            Val::Gap => {
                plan.compute_gap = resolve_gap(seed, k, v)?;
                plan.resolved.push((k.clone(), json!(plan.compute_gap)));
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
        "net-partition" => {
            let (range, port) = match v.split_once(':') {
                Some((r, p)) => (r, n(p)?),
                None => (v, 0),
            };
            if port > 65535 {
                return Err(format!("--fault net-partition: port {port} out of range"));
            }
            let (start, len) = range
                .split_once('+')
                .ok_or_else(|| format!("--fault {k}={v}: expected START+LENGTH"))?;
            c.partition_from_ns = n(start)? * 1_000_000;
            c.partition_to_ns = c.partition_from_ns + n(len)? * 1_000_000;
            c.partition_port = port;
            c.partition_set = 1;
        }
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
fn crash_plan(seed: u64, f: &mut proto::faults::FaultCfg, s: &str) -> Res<String> {
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
        let a = resolve(1, &disk, &[], None).unwrap();
        let b = resolve(1, &disk, &[], None).unwrap();
        assert_eq!(a.json(), b.json());
        let rates: std::collections::BTreeSet<u64> = (0..64)
            .map(|s| {
                let p = resolve(s, &disk, &[], None).unwrap();
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
            let a = resolve(s, &disk, &[], Some("machine:0..5")).unwrap();
            let b = resolve(
                s,
                &disk,
                &v(&[
                    "net-chunk-max=1..4",
                    "net-chunk-gap-us=1..10",
                    "mem-limit-mb=10..20",
                ]),
                Some("machine:0..5"),
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
        let p = resolve(3, &v(&["disk"]), &v(&["fs-error-permille=7"]), None).unwrap();
        assert_eq!(p.faults.fs_error_permille, 7);
        assert!(resolve(0, &v(&["dsk"]), &[], None)
            .unwrap_err()
            .contains("dsk"));
        assert!(resolve(0, &[], &v(&["nope=1"]), None)
            .unwrap_err()
            .contains("nope"));
        assert!(resolve(0, &[], &v(&["fs-error-permille=5..2"]), None).is_err());
        assert!(resolve(0, &[], &v(&["fs-error-permille=0..1001"]), None).is_err());
        let c = resolve(0, &[], &[], Some("machine")).unwrap();
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
            let p = resolve(s, &[], &at, Some("machine-at:10..20")).unwrap();
            let q = resolve(s, &[], &at, Some("machine-at:10..20")).unwrap();
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
        assert!(resolve(0, &[], &v(&["fsync-error-at=9..2"]), None).is_err());
        assert!(resolve(0, &[], &[], Some("machine-at:x")).is_err());
    }

    #[test]
    fn compute_gap_is_drawn_per_seed_and_never_swarmed() {
        let mut seen = std::collections::BTreeSet::new();
        for s in 0..64 {
            let d = resolve(s, &[], &[], None).unwrap();
            let (lo, hi) = proto::compute::GAP_DEFAULT;
            assert!((lo..=hi).contains(&d.compute_gap), "{}", d.compute_gap);
            assert!(d.resolved.is_empty());
            seen.insert(d.compute_gap);
            let p = resolve(s, &[], &v(&["compute-gap=8", "swarm=1"]), None).unwrap();
            assert_eq!((p.compute_gap, val(&p, "compute-gap")), (8, json!(8)));
            let r = resolve(s, &[], &v(&["compute-gap=100..200"]), None).unwrap();
            assert!((100..=200).contains(&r.compute_gap));
            assert_eq!(val(&r, "compute-gap"), json!(r.compute_gap));
        }
        assert!(seen.len() > 8, "{seen:?}");
        assert_eq!(
            resolve(0, &[], &v(&["compute-gap=0"]), None)
                .unwrap()
                .compute_gap,
            0
        );
        for bad in ["compute-gap=0..8", "compute-gap=9..8", "compute-gap=x"] {
            assert!(resolve(0, &[], &v(&[bad]), None).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_size_range_draws_log_uniformly_and_a_size_stays_put() {
        let mut small = 0;
        let mut seen = std::collections::BTreeSet::new();
        for s in 0..256 {
            let p = resolve(s, &v(&["net"]), &[], None).unwrap();
            let c = p.net.chunk_max;
            assert!(
                (1..=65536).contains(&c) && val(&p, "net-chunk-max") == json!(c),
                "{c}"
            );
            small += (c <= 16) as u32;
            seen.insert(c);
            let one = resolve(s, &[], &v(&["net-chunk-max=7"]), None).unwrap();
            assert_eq!(one.net.chunk_max, 7);
        }
        // Log-uniform: about a quarter of seeds at 16 bytes or less (uniform: one in 4096).
        assert!(
            (32..=100).contains(&small) && seen.len() > 64,
            "{small} {}",
            seen.len()
        );
        assert!(resolve(0, &[], &v(&["net-chunk-max=0..8"]), None).is_err());
        let g = resolve(0, &[], &v(&["net-chunk-gap-us=1..10"]), None).unwrap();
        assert_eq!(
            (
                g.net.chunk_gap_set,
                g.net.chunk_gap_min_ns,
                g.net.chunk_gap_max_ns
            ),
            (1, 1000, 10_000)
        );
        assert!(resolve(0, &[], &v(&["net-chunk-gap-us=5"]), None).is_err());
    }

    #[test]
    fn swarm_turns_classes_off_per_seed() {
        let all = v(&["all"]);
        let offs: std::collections::BTreeSet<usize> = (0..32)
            .map(|s| {
                let p = resolve(s, &all, &v(&["swarm=1"]), None).unwrap();
                p.resolved.iter().filter(|e| e.1 == json!("off")).count()
            })
            .collect();
        assert!(offs.len() > 2, "{offs:?}");
    }
}
