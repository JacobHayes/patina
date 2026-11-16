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

/// The fault plan of a run.
#[derive(Clone, Debug)]
pub struct Plan {
    pub faults: proto::faults::FaultCfg,
    /// `faults-in-recovery = false`: no faults other than crashes after the first crash.
    pub faults_in_recovery: bool,
    /// `net-*` keys.
    pub net: proto::wire::NetCfg,
    /// `--buggify`, `buggify-permille=N`, `point:LABEL=N` (`proto::sdk`).
    pub sdk: proto::sdk::SdkCfg,
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
    /// 0 or 1.
    Flag,
    /// The key's own grammar (`A..B` milliseconds are the per-event spread, not a plan
    /// range); a class `swarm` may turn off.
    Own,
    /// An exact position, for regression tests: never a range, never swarmed.
    Exact,
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
        "net-delay-ms",
        "A..B",
        Val::Own,
        "each TCP delivery is delayed by a draw in A..B ms",
    ),
    key(
        "net-chunk-max",
        "N",
        Val::Count,
        "TCP deliveries are split into pieces of at most N bytes",
    ),
    key(
        "net-reset-permille",
        "P",
        Val::Permille,
        "reset a TCP connection, drawn for each piece of data a guest sends on it",
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
        "A..B[:PORT]",
        Val::Own,
        "hold TCP deliveries (to PORT) from A to B ms of virtual time",
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
        "fs-error-at",
        "CLASS:N",
        Val::Exact,
        "fail exactly the N-th call of CLASS (open, read, write, sync, ...)",
    ),
    key(
        "fsync-error-at",
        "N",
        Val::Exact,
        "fail exactly the N-th fsync",
    ),
    key(
        "mem-error-at",
        "N",
        Val::Exact,
        "fail exactly the N-th memory request",
    ),
];

/// `--faults NAME`: rare-fault rates, each a range the seed resolves.
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
            ("net-reset-permille", "0..5"),
            ("net-connect-refuse-permille", "0..10"),
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
            ("net-reset-permille", "0..5"),
            ("net-connect-refuse-permille", "0..10"),
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

/// Resolve presets, settings (later ones replace earlier ones of the same key, settings
/// replace presets) and `--crash` against `seed`.
pub fn resolve(
    seed: u64,
    presets: &[String],
    settings: &[String],
    crash: Option<&str>,
    faults_in_recovery: bool,
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
    let mut plan = Plan {
        faults: Default::default(),
        faults_in_recovery,
        net: Default::default(),
        sdk: Default::default(),
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
            Val::Own | Val::Exact => json!(v),
        };
        let class = matches!(info.val, Val::Permille | Val::Count | Val::Own);
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
        "mem-limit-mb" => {
            // A limit, not a draw: it holds whether or not other faults are active.
            f.mem_limit_bytes = n(v)?.saturating_mul(1 << 20);
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
    let (a, b) = v
        .split_once("..")
        .ok_or_else(|| format!("--fault {k}={v}: expected A..B (milliseconds)"))?;
    let (a, b) = (num(k, a)?, num(k, b)?);
    if a > b {
        return Err(format!("--fault {k}={v}: A is larger than B"));
    }
    Ok((a * 1_000_000, b * 1_000_000))
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
            (c.partition_from_ns, c.partition_to_ns) = ms_range(k, range)?;
            c.partition_port = port;
            c.partition_set = 1;
        }
        "net-halfclose-delay-ms" => {
            (c.halfclose_min_ns, c.halfclose_max_ns) = ms_range(k, v)?;
            c.halfclose_set = 1;
        }
        _ => return Err(format!("--fault: unknown key {k}")),
    }
    Ok(())
}

/// `--crash machine|process[:PERMILLE or A..B] | machine-at:SEQ | process-at:SEQ`. Returns
/// the resolved form.
fn crash_plan(seed: u64, f: &mut proto::faults::FaultCfg, s: &str) -> Res<String> {
    let (k, v) = s.split_once(':').unwrap_or((s, ""));
    let (kind, at) = match k {
        "machine" => (CRASH_MACHINE, false),
        "process" => (CRASH_PROCESS, false),
        "machine-at" => (CRASH_MACHINE, true),
        "process-at" => (CRASH_PROCESS, true),
        _ => {
            return Err(format!(
                "--crash: unknown kind {k} (machine, process, machine-at:SEQ, process-at:SEQ)"
            ))
        }
    };
    f.crash_kind = kind;
    if at {
        let n: u64 = v
            .parse()
            .map_err(|_| format!("--crash {s}: expected {k}:SEQ"))?;
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
        let a = resolve(1, &disk, &[], None, true).unwrap();
        let b = resolve(1, &disk, &[], None, true).unwrap();
        assert_eq!(a.json(), b.json());
        let rates: std::collections::BTreeSet<u64> = (0..64)
            .map(|s| {
                let p = resolve(s, &disk, &[], None, true).unwrap();
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
            let a = resolve(s, &disk, &[], Some("machine:0..5"), true).unwrap();
            let b = resolve(
                s,
                &disk,
                &v(&["net-chunk-max=1..4", "mem-limit-mb=10..20"]),
                Some("machine:0..5"),
                true,
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
        let p = resolve(3, &v(&["disk"]), &v(&["fs-error-permille=7"]), None, true).unwrap();
        assert_eq!(p.faults.fs_error_permille, 7);
        assert!(resolve(0, &v(&["dsk"]), &[], None, true)
            .unwrap_err()
            .contains("dsk"));
        assert!(resolve(0, &[], &v(&["nope=1"]), None, true)
            .unwrap_err()
            .contains("nope"));
        assert!(resolve(0, &[], &v(&["fs-error-permille=5..2"]), None, true).is_err());
        assert!(resolve(0, &[], &v(&["fs-error-permille=0..1001"]), None, true).is_err());
        let c = resolve(0, &[], &[], Some("machine"), true).unwrap();
        assert_eq!(c.faults.crash_permille, CRASH_DEFAULT_PERMILLE);
    }

    #[test]
    fn swarm_turns_classes_off_per_seed() {
        let all = v(&["all"]);
        let offs: std::collections::BTreeSet<usize> = (0..32)
            .map(|s| {
                let p = resolve(s, &all, &v(&["swarm=1"]), None, true).unwrap();
                p.resolved.iter().filter(|e| e.1 == json!("off")).count()
            })
            .collect();
        assert!(offs.len() > 2, "{offs:?}");
    }
}
