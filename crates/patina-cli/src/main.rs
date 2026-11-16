//! `patina`: launcher, supervisor (hidden `__sup`), log tools and the table printer.

mod cli;
mod durability;
mod insn;
mod launch;
mod launcher;
mod logtool;
mod outcome;
mod sup;
mod sys;
mod table;
mod verify;

use std::process::ExitCode;

fn usage() -> ExitCode {
    eprintln!(
        "usage:\n  patina run --out RUN [--seed N] [--guest DIR] [--root DIR] [--cpu N] [--env K=V]... \
         [--preempt-permille P] [--vtime-limit-s S] [--stall-ms MS] [--tmpfs-bytes N] [--no-personality] -- /guest/prog args...\n  \
         patina verify (run options) --runs N [--vary cpu,load,aslr,sandbox]\n  \
         patina log dump RUN/inc-0/boundary.log [--from SEQ --to SEQ]\n  \
         patina log diff A/boundary.log B/boundary.log\n  \
         patina table\n  \
         patina oplog check RUN | patina oplog dump RUN/inc-K\n  \
         patina crash-states RUN --at SEQ --count N [--inc K] [--seed N] [--fs-model M] [--out DIR]"
    );
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = args.first() else {
        return usage();
    };
    let rest = &args[1..];
    let r = match cmd.as_str() {
        "run" => cli::parse(rest).and_then(|o| launch::run(&o)),
        "verify" => cli::parse(rest).and_then(|o| verify::verify(&o)),
        "log" => logtool::main(rest),
        "table" => {
            table::print();
            Ok(ExitCode::SUCCESS)
        }
        "__sup" => sup::main(rest),
        "oplog" => oplog_cmd(rest),
        "crash-states" => crash_states(rest),
        "insn-scan" => insn::main(rest),
        _ => return usage(),
    };
    match r {
        Ok(c) => c,
        Err(e) => {
            eprintln!("patina: {e}");
            ExitCode::from(2)
        }
    }
}

fn oplog_cmd(args: &[String]) -> Result<ExitCode, String> {
    let (Some(sub), Some(p)) = (args.first(), args.get(1)) else {
        return Ok(usage());
    };
    let p = std::path::Path::new(p);
    match sub.as_str() {
        "check" => durability::check::check(p).map(|_| ExitCode::SUCCESS),
        "dump" => durability::log::dump(p).map(|_| ExitCode::SUCCESS),
        _ => Ok(usage()),
    }
}

/// `patina crash-states RUN --at SEQ --count N`: N post-crash trees for one crash point (the
/// log prefix up to SEQ of incarnation K), one per `Torn` key: different legal states.
fn crash_states(args: &[String]) -> Result<ExitCode, String> {
    use durability::materialise::{materialise, Model};
    let run = std::path::PathBuf::from(args.first().ok_or("crash-states needs RUN")?);
    let (mut at, mut count, mut inc, mut seed, mut model, mut out) =
        (u64::MAX, 10u64, 0u64, 0u64, Model::Ext4Ordered, None);
    let mut it = args[1..].iter();
    while let Some(a) = it.next() {
        let v = it.next().ok_or_else(|| format!("{a} needs a value"))?;
        let n = || {
            v.parse::<u64>()
                .map_err(|_| format!("{a}: not a number: {v}"))
        };
        match a.as_str() {
            "--at" => at = n()?,
            "--count" => count = n()?,
            "--inc" => inc = n()?,
            "--seed" => seed = n()?,
            "--fs-model" => model = Model::parse(v).ok_or_else(|| format!("unknown model {v}"))?,
            "--out" => out = Some(std::path::PathBuf::from(v)),
            _ => return Err(format!("crash-states: unknown option {a}")),
        }
    }
    let t0 = std::time::Instant::now();
    let log = durability::log::OpLog::load(&run.join(format!("inc-{inc}")))?;
    if std::env::var_os("PATINA_TIMING").is_some() {
        eprintln!(
            "patina-timing load records={} us={}",
            log.ops.len(),
            t0.elapsed().as_micros()
        );
    }
    let mut distinct = std::collections::BTreeSet::new();
    for key in 0..count {
        let t = materialise(&log, at, seed, key, model, &[])?;
        let d = t.digest();
        println!("variant {key}: {d} {} paths", t.nodes.len());
        if let Some(o) = &out {
            let dir = o.join(format!("variant-{key}"));
            t.write_dir(&dir)
                .map_err(|e| format!("{}: {e}", dir.display()))?;
        }
        distinct.insert(d);
    }
    println!(
        "{} distinct trees of {count} ({}, prefix seq <= {at})",
        distinct.len(),
        model.name()
    );
    Ok(ExitCode::SUCCESS)
}
