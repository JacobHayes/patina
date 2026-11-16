//! `patina log dump|diff|ops`: read a boundary log, compare two, list file operations; and
//! the record-by-record comparison of two run directories that replay and verify use.

use crate::cli::{Args, Res};
use crate::durability::check::incarnations;
use proto::ctl::Op;
use proto::rec::{Rec, REC_SIZE};
use proto::table::{name, Class};
use proto::RecKind;
use std::path::Path;
use std::process::ExitCode;

pub fn load(path: &str) -> Res<Vec<Rec>> {
    let b = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    if b.len() % REC_SIZE != 0 {
        return Err(format!(
            "{path}: length {} is not a multiple of {REC_SIZE}",
            b.len()
        ));
    }
    Ok(b.as_chunks::<REC_SIZE>()
        .0
        .iter()
        .map(|c| Rec::from_bytes(c))
        .collect())
}

pub fn describe(r: &Rec) -> String {
    let kind = RecKind::from_u8(r.kind);
    let what = match kind {
        Some(RecKind::Trap) => format!("{} [{}]", name(r.nr as u64), Class::code_name(r.class)),
        Some(RecKind::SupDecision) => Op::from_u32(r.nr)
            .map(|o| o.name().to_string())
            .unwrap_or_else(|| format!("op{}", r.nr)),
        Some(RecKind::InsnEmulation) => match r.nr {
            0x0f31 => "rdtsc".to_string(),
            0x0f01f9 => "rdtscp".to_string(),
            0x0fc706 => "rdrand".to_string(),
            0x0fc707 => "rdseed".to_string(),
            0xf30fc707 => "rdpid".to_string(),
            n => format!("{n:#x}"),
        },
        Some(RecKind::Preempt) => match r.nr {
            1 => "counter".to_string(),
            2 => "spin point".to_string(),
            proto::compute::PREEMPT_NR => match r.args[2] {
                proto::compute::REASON_DEADLINE => "compute deadline".to_string(),
                _ => "compute switch".to_string(),
            },
            n => format!("{n:#x}"),
        },
        Some(RecKind::Name) => {
            let (b, n, cut) = r.name_bytes();
            let s = String::from_utf8_lossy(&b[..n]);
            format!("{}{s}", if cut { "..." } else { "" })
        }
        _ => format!("{:#x}", r.nr),
    };
    format!(
        "seq={} {} slot={} t={} {} args=[{:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:#x}] ret={} out={:016x} in={:016x}",
        r.seq,
        kind.map(|k| k.name()).unwrap_or("?"),
        r.slot,
        r.vclock_ns,
        what,
        r.args[0],
        r.args[1],
        r.args[2],
        r.args[3],
        r.args[4],
        r.args[5],
        r.ret,
        r.out_hash,
        r.in_hash
    )
}

/// Index and both versions of the first differing record, if any.
pub fn first_difference(a: &[Rec], b: &[Rec]) -> Option<(usize, Option<Rec>, Option<Rec>)> {
    let n = a.len().max(b.len());
    (0..n)
        .find(|&i| a.get(i) != b.get(i))
        .map(|i| (i, a.get(i).copied(), b.get(i).copied()))
}

pub fn print_difference(pa: &str, pb: &str) -> Res<bool> {
    let (a, b) = (load(pa)?, load(pb)?);
    match first_difference(&a, &b) {
        None => {
            println!("identical: {} records", a.len());
            Ok(false)
        }
        Some((i, x, y)) => {
            println!(
                "first difference at record {i} (of {} and {}):",
                a.len(),
                b.len()
            );
            let show = |r: Option<Rec>| {
                r.map(|r| describe(&r))
                    .unwrap_or_else(|| "(end of log)".into())
            };
            println!("  A: {}", show(x));
            println!("  B: {}", show(y));
            Ok(true)
        }
    }
}

/// The first difference between the boundary logs of two run directories, incarnation by
/// incarnation, decoded; `None` when every log is equal.
pub fn first_run_difference(a: &Path, b: &Path) -> Res<Option<String>> {
    let (ia, ib) = (incarnations(a), incarnations(b));
    for k in 0..ia.len().max(ib.len()) {
        let (Some(da), Some(db)) = (ia.get(k), ib.get(k)) else {
            return Ok(Some(format!(
                "incarnation counts differ: {} and {}",
                ia.len(),
                ib.len()
            )));
        };
        let pa = da.join("boundary.log").display().to_string();
        let pb = db.join("boundary.log").display().to_string();
        let (x, y) = (load(&pa)?, load(&pb)?);
        if let Some((i, ra, rb)) = first_difference(&x, &y) {
            let show = |r: Option<Rec>| {
                r.map(|r| describe(&r))
                    .unwrap_or_else(|| "(end of log)".into())
            };
            return Ok(Some(format!(
                "inc-{k} record {i}: recorded {}; replayed {}",
                show(ra),
                show(rb)
            )));
        }
    }
    Ok(None)
}

pub fn main(args: &Args) -> Res<ExitCode> {
    let p = &args.positional;
    let arg = |i: usize, usage: &str| -> Res<&str> {
        p.get(i)
            .map(|s| s.as_str())
            .ok_or_else(|| usage.to_string())
    };
    match p.first().map(|s| s.as_str()) {
        Some("dump") => {
            let path = arg(1, "log dump LOG [--from SEQ] [--to SEQ]")?;
            let from = args.num::<u64>("--from")?.unwrap_or(0);
            let to = args.num::<u64>("--to")?.unwrap_or(u64::MAX);
            for r in load(path)?.iter().filter(|r| r.seq >= from && r.seq <= to) {
                println!("{}", describe(r));
            }
            Ok(ExitCode::SUCCESS)
        }
        Some("diff") => {
            let (a, b) = (arg(1, "log diff LOG LOG")?, arg(2, "log diff LOG LOG")?);
            Ok(if print_difference(a, b)? {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            })
        }
        Some("ops") => {
            let dir = Path::new(arg(1, "log ops INCDIR | log ops --check RUNDIR")?);
            if args.has("--check") {
                crate::durability::check::check(dir)?;
            } else {
                crate::durability::log::dump(dir)?;
            }
            Ok(ExitCode::SUCCESS)
        }
        _ => {
            Err("log dump LOG | log diff LOG LOG | log ops INCDIR | log ops --check RUNDIR".into())
        }
    }
}
