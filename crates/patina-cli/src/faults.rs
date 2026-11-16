//! Fault settings: `--fault KEY=VALUE`, `--crash KIND:VALUE` and the same keys in
//! `[faults]` of `patina.toml`, parsed into the runtime's and the wire's configurations.

use crate::cli::Res;
use proto::faults::{FClass, FaultCfg, CRASH_MACHINE, CRASH_PROCESS};

/// The fault plan of a run.
#[derive(Clone, Debug, Default)]
pub struct Plan {
    pub faults: FaultCfg,
    /// `faults-in-recovery=0`: no faults other than crashes after the first crash.
    pub faults_in_recovery: bool,
    /// `net-*` keys.
    pub net: proto::wire::NetCfg,
    /// `--buggify`, `buggify-permille=N`, `point:LABEL=N` (`proto::sdk`).
    pub sdk: proto::sdk::SdkCfg,
}

impl Plan {
    pub fn new() -> Plan {
        Plan {
            faults_in_recovery: true,
            ..Plan::default()
        }
    }
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

/// One `KEY=VALUE`; unknown keys are an error naming the key.
pub fn fault(o: &mut Plan, kv: &str) -> Res<()> {
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

/// `point:LABEL=PERMILLE`: the SDK fault point LABEL is active and fires at this rate
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

/// One `net-*` key. They act on the supervisor's wire only, so they do not switch on the
/// runtime's per-call fault work.
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

/// `machine:P | process:P | machine-at:SEQ | process-at:SEQ`.
pub fn crash(f: &mut FaultCfg, s: &str) -> Res<()> {
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
