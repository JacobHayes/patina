//! Options shared by `run` and `verify`.

use crate::durability::materialise::Model;
use proto::faults::{FClass, FaultCfg, CRASH_MACHINE, CRASH_PROCESS};
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct Opts {
    pub out: Option<PathBuf>,
    pub seed: u64,
    pub guest: Option<PathBuf>,
    pub root: Option<PathBuf>,
    pub cpu: Option<usize>,
    /// `--ncpu N`: the CPU count the guest is told it has (affinity, `/sys`, `/proc`);
    /// default 24, whatever the host has (`launch::DEFAULT_NCPU`).
    pub ncpu: Option<u64>,
    pub env: Vec<String>,
    pub preempt_permille: u64,
    pub vtime_limit_s: u64,
    pub stall_ms: u64,
    pub tmpfs_bytes: u64,
    pub no_personality: bool,
    pub runs: usize,
    pub vary: Vec<String>,
    pub cmd: Vec<String>,
    /// `--fault` and `--crash`.
    pub faults: FaultCfg,
    pub faults_in_recovery: bool,
    /// `--fault net-*`.
    pub net: proto::wire::NetCfg,
    pub fs_model: Model,
    pub max_incarnations: u64,
    /// `--pmu` and its policy flags (each implies `--pmu`).
    pub pmu: bool,
    pub pmu_slice: (u64, u64),
    pub pmu_short_permille: u64,
    pub pmu_short_max: u64,
    pub pmu_charge_ps: u64,
    pub pmu_margin: u64,
    /// `--buggify`, `--fault buggify-permille=N`, `--fault point:LABEL=N` (`proto::sdk`).
    pub sdk: proto::sdk::SdkCfg,
}

pub type Res<T> = Result<T, String>;

fn num<T: std::str::FromStr>(flag: &str, v: Option<&String>) -> Res<T> {
    let v = v.ok_or_else(|| format!("{flag} needs a value"))?;
    v.parse().map_err(|_| format!("{flag}: not a number: {v}"))
}

pub fn parse(args: &[String]) -> Res<Opts> {
    let mut o = Opts {
        out: None,
        seed: 0,
        guest: None,
        root: None,
        cpu: None,
        ncpu: None,
        env: vec![],
        preempt_permille: 100,
        vtime_limit_s: 3600,
        stall_ms: 10_000,
        tmpfs_bytes: 256 << 20,
        no_personality: false,
        runs: 1,
        vary: vec![],
        cmd: vec![],
        faults: FaultCfg::default(),
        faults_in_recovery: true,
        net: proto::wire::NetCfg::default(),
        fs_model: Model::Ext4Ordered,
        max_incarnations: 4,
        pmu: false,
        pmu_slice: (proto::pmu::SLICE_MIN_DEFAULT, proto::pmu::SLICE_MAX_DEFAULT),
        pmu_short_permille: proto::pmu::SHORT_PERMILLE_DEFAULT,
        pmu_short_max: proto::pmu::SHORT_MAX_DEFAULT,
        pmu_charge_ps: proto::pmu::CHARGE_PS_DEFAULT,
        pmu_margin: proto::pmu::MARGIN_DEFAULT,
        sdk: proto::sdk::SdkCfg::default(),
    };
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--" => {
                o.cmd = it.cloned().collect();
                break;
            }
            "--out" => o.out = Some(PathBuf::from(it.next().ok_or("--out needs a value")?)),
            "--seed" => o.seed = num(a, it.next())?,
            "--guest" => o.guest = Some(PathBuf::from(it.next().ok_or("--guest needs a value")?)),
            "--root" => o.root = Some(PathBuf::from(it.next().ok_or("--root needs a value")?)),
            "--cpu" => o.cpu = Some(num(a, it.next())?),
            "--ncpu" => o.ncpu = Some(num(a, it.next())?),
            "--env" => o.env.push(it.next().ok_or("--env needs K=V")?.clone()),
            "--preempt-permille" => o.preempt_permille = num(a, it.next())?,
            "--vtime-limit-s" => o.vtime_limit_s = num(a, it.next())?,
            "--stall-ms" => o.stall_ms = num(a, it.next())?,
            "--tmpfs-bytes" => o.tmpfs_bytes = num(a, it.next())?,
            "--no-personality" => o.no_personality = true,
            "--runs" => o.runs = num(a, it.next())?,
            "--vary" => {
                let v = it.next().ok_or("--vary needs a list")?;
                for k in v.split(',') {
                    match k {
                        "cpu" | "aslr" | "sandbox" | "load" | "repeat" | "parallel" | "env"
                        | "time" => o.vary.push(k.to_string()),
                        _ => return Err(format!("--vary: unknown variant {k}")),
                    }
                }
            }
            "--fault" => fault(&mut o, it.next().ok_or("--fault needs KEY=VALUE")?)?,
            "--crash" => crash(&mut o.faults, it.next().ok_or("--crash needs KIND:VALUE")?)?,
            "--fs-model" => {
                let v = it.next().ok_or("--fs-model needs a value")?;
                o.fs_model = Model::parse(v).ok_or_else(|| {
                    format!("--fs-model: unknown model {v} (ext4-ordered, posix-strict)")
                })?;
            }
            "--max-incarnations" => {
                o.max_incarnations = num(a, it.next())?;
                if o.max_incarnations == 0 {
                    return Err("--max-incarnations is at least 1".into());
                }
            }
            // Counter preemption: off unless asked for.
            "--buggify" => o.sdk.buggify = 1,
            "--pmu" => o.pmu = true,
            "--pmu-slice" => {
                let v = it.next().ok_or("--pmu-slice needs MIN..MAX")?;
                let (lo, hi) = v.split_once("..").ok_or("--pmu-slice needs MIN..MAX")?;
                let lo: u64 = lo
                    .parse()
                    .map_err(|_| format!("--pmu-slice: not a number: {lo}"))?;
                let hi: u64 = hi
                    .parse()
                    .map_err(|_| format!("--pmu-slice: not a number: {hi}"))?;
                o.pmu_slice = (lo, hi);
                o.pmu = true;
            }
            "--pmu-short-permille" => {
                o.pmu_short_permille = num(a, it.next())?;
                o.pmu = true;
            }
            "--pmu-short-max" => {
                o.pmu_short_max = num(a, it.next())?;
                o.pmu = true;
            }
            "--pmu-charge-ps" => {
                o.pmu_charge_ps = num(a, it.next())?;
                o.pmu = true;
            }
            "--pmu-margin" => {
                o.pmu_margin = num(a, it.next())?;
                o.pmu = true;
            }
            _ => return Err(format!("unknown option {a}")),
        }
    }
    if o.cmd.is_empty() {
        return Err("missing -- /guest/prog args...".into());
    }
    if o.preempt_permille > 1000 {
        return Err("--preempt-permille is at most 1000".into());
    }
    if o.pmu_short_permille > 1000 || o.pmu_short_max == 0 || o.pmu_short_max > 0xffff_ffff {
        return Err("--pmu-short-permille is at most 1000, --pmu-short-max at least 1".into());
    }
    let (lo, hi) = o.pmu_slice;
    if lo == 0 || lo > hi || o.pmu_margin < 64 {
        return Err("--pmu-slice needs 1 <= MIN <= MAX; --pmu-margin at least 64".into());
    }
    if o.pmu_short_max > o.pmu_margin + proto::pmu::HOP_EXTRA {
        return Err(
            "--pmu-short-max is at most --pmu-margin + 1024 (short slices are hopped)".into(),
        );
    }
    Ok(o)
}

fn permille(k: &str, v: &str) -> Res<u64> {
    let p: u64 = v
        .parse()
        .map_err(|_| format!("--fault {k}: not a number: {v}"))?;
    if p > 1000 {
        return Err(format!("--fault {k}: at most 1000"));
    }
    Ok(p)
}

/// One `--fault KEY=VALUE`; unknown keys are an error.
fn fault(o: &mut Opts, kv: &str) -> Res<()> {
    let (k, v) = kv
        .split_once('=')
        .ok_or_else(|| format!("--fault {kv}: expected KEY=VALUE"))?;
    let n = |v: &str| -> Res<u64> {
        v.parse()
            .map_err(|_| format!("--fault {k}: not a number: {v}"))
    };
    let f = &mut o.faults;
    match k {
        "fs-error-permille" => f.fs_error_permille = permille(k, v)?,
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
        "fs-eintr" => f.fs_eintr = (n(v)? != 0) as u64,
        "short-permille" => f.short_permille = permille(k, v)?,
        "fsync-error-permille" => f.fsync_error_permille = permille(k, v)?,
        "fsync-error-at" => f.fsync_error_at = n(v)?,
        "enospc-after-bytes" => f.enospc_after_bytes = n(v)?,
        "delay-permille" => f.delay_permille = permille(k, v)?,
        "delay-max-ms" => f.delay_max_ns = n(v)? * 1_000_000,
        "mem-error-permille" => f.mem_error_permille = permille(k, v)?,
        "mem-error-at" => f.mem_error_at = n(v)?,
        "fault-after-seq" => f.fault_after_seq = n(v)?,
        // The `setup-complete` mark lowers it to its own sequence number.
        "faults-after-setup" => f.fault_after_seq = if n(v)? != 0 { u64::MAX } else { 0 },
        "faults-in-recovery" => o.faults_in_recovery = n(v)? != 0,
        "buggify-permille" => {
            o.sdk.fire_permille = permille(k, v)?;
            return Ok(());
        }
        _ if k.starts_with("point:") => return point(&mut o.sdk, &k["point:".len()..], v),
        _ if k.starts_with("net-") => return net_fault(&mut o.net, k, v),
        _ => return Err(format!("--fault: unknown key {k}")),
    }
    if !matches!(
        k,
        "fault-after-seq" | "faults-after-setup" | "faults-in-recovery"
    ) {
        o.faults.any = 1;
    }
    Ok(())
}

/// `--fault point:LABEL=PERMILLE`: the SDK fault point LABEL is active and fires at this rate
/// (0: never). It acts only with `--buggify`.
fn point(c: &mut proto::sdk::SdkCfg, label: &str, v: &str) -> Res<()> {
    if label.is_empty() || label.len() > proto::sdk::LABEL_MAX {
        return Err(format!("--fault point:{label}: a label is 1 to 255 bytes"));
    }
    let p = permille(&format!("point:{label}"), v)?;
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
    let p = |x: &str| -> Res<u64> {
        x.parse()
            .map_err(|_| format!("--fault {k}: not a number: {x}"))
    };
    let (a, b) = (p(a)?, p(b)?);
    if a > b {
        return Err(format!("--fault {k}={v}: A is larger than B"));
    }
    Ok((a * 1_000_000, b * 1_000_000))
}

/// One `--fault net-*` key. They act on the supervisor's
/// wire only, so they do not switch on the runtime's per-call fault work.
fn net_fault(c: &mut proto::wire::NetCfg, k: &str, v: &str) -> Res<()> {
    let n = |v: &str| -> Res<u64> {
        v.parse()
            .map_err(|_| format!("--fault {k}: not a number: {v}"))
    };
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
        "net-reset-permille" => c.reset_permille = permille(k, v)?,
        "net-connect-refuse-permille" => c.refuse_permille = permille(k, v)?,
        "net-connect-timeout-permille" => c.timeout_permille = permille(k, v)?,
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

/// `--crash machine:P | process:P | machine-at:SEQ | process-at:SEQ`.
fn crash(f: &mut FaultCfg, s: &str) -> Res<()> {
    let (k, v) = s
        .split_once(':')
        .ok_or_else(|| format!("--crash {s}: expected KIND:VALUE"))?;
    let n: u64 = v
        .parse()
        .map_err(|_| format!("--crash {s}: not a number: {v}"))?;
    let (kind, at) = match k {
        "machine" => (CRASH_MACHINE, false),
        "process" => (CRASH_PROCESS, false),
        "machine-at" => (CRASH_MACHINE, true),
        "process-at" => (CRASH_PROCESS, true),
        _ => {
            return Err(format!(
                "--crash: unknown kind {k} (machine, process, machine-at, process-at)"
            ))
        }
    };
    f.crash_kind = kind;
    if at {
        f.crash_at = n.max(1);
        f.crash_permille = 0;
    } else {
        if n > 1000 {
            return Err("--crash: the rate is per mille, at most 1000".into());
        }
        f.crash_permille = n;
        f.crash_at = 0;
    }
    Ok(())
}
