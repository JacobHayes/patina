//! `patina log dump` and `patina log diff`.

use crate::cli::Res;
use proto::ctl::Op;
use proto::rec::{Rec, REC_SIZE};
use proto::table::{name, Class};
use proto::RecKind;
use std::process::ExitCode;

fn load(path: &str) -> Res<Vec<Rec>> {
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

pub fn main(args: &[String]) -> Res<ExitCode> {
    match args.first().map(|s| s.as_str()) {
        Some("dump") => {
            let path = args.get(1).ok_or("log dump FILE")?;
            let (mut from, mut to) = (0u64, u64::MAX);
            let mut it = args[2..].iter();
            while let Some(a) = it.next() {
                let v: u64 = it
                    .next()
                    .and_then(|v| v.parse().ok())
                    .ok_or(format!("{a} needs a number"))?;
                match a.as_str() {
                    "--from" => from = v,
                    "--to" => to = v,
                    _ => return Err(format!("unknown option {a}")),
                }
            }
            for r in load(path)?.iter().filter(|r| r.seq >= from && r.seq <= to) {
                println!("{}", describe(r));
            }
            Ok(ExitCode::SUCCESS)
        }
        Some("diff") => {
            let (a, b) = (
                args.get(1).ok_or("log diff A B")?,
                args.get(2).ok_or("log diff A B")?,
            );
            Ok(if print_difference(a, b)? {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            })
        }
        _ => Err("log dump FILE | log diff A B".into()),
    }
}
