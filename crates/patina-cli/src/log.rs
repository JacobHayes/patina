//! `patina log dump|diff|ops|tree|events`: read a boundary log, compare two, list file
//! operations, write out an incarnation's final work tree, export a run as JSON lines
//! (`crate::events`); and
//! the record-by-record comparison of two run directories that replay and verify use.

use crate::cli::{Args, Res};
use crate::durability::check::incarnations;
use proto::ctl::Op;
use proto::rec::{
    Rec, REC_SIZE, STR_ARGV, STR_ARGV_CUT, STR_BYTES, STR_CUT, STR_LABEL, STR_MORE, STR_PATH,
    STR_PATH2, STR_RESOLVED, STR_RESOLVED2, STR_TEXT, STR_WHICH,
};
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

/// Records `[from, from + n)` of the log at `path` (fewer at its end).
fn load_range(path: &Path, from: u64, n: u64) -> Res<Vec<Rec>> {
    use std::io::{Read, Seek, SeekFrom};
    let err = |e: std::io::Error| format!("{}: {e}", path.display());
    let mut f = std::fs::File::open(path).map_err(err)?;
    f.seek(SeekFrom::Start(from * REC_SIZE as u64))
        .map_err(err)?;
    let mut b = vec![];
    f.take(n * REC_SIZE as u64)
        .read_to_end(&mut b)
        .map_err(err)?;
    Ok(b.as_chunks::<REC_SIZE>()
        .0
        .iter()
        .map(|c| Rec::from_bytes(c))
        .collect())
}

/// A boundary log a sweep cut to its first and last records (`boundary.cut` beside it):
/// `boundary.log` holds the first `head` records, `boundary.tail` the records from `tail_from`
/// to the end, `records` in all.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Cut {
    pub records: u64,
    pub head: u64,
    pub tail_from: u64,
}

/// Cut the boundary log of the incarnation `inc` to its first and last `keep` bytes.
pub fn cut(inc: &Path, keep: u64) -> Res<()> {
    use std::io::{Read, Seek, SeekFrom};
    let log = inc.join("boundary.log");
    let err = |e: std::io::Error| format!("{}: {e}", log.display());
    let len = std::fs::metadata(&log).map_err(err)?.len();
    let n = len / REC_SIZE as u64;
    let k = keep / REC_SIZE as u64;
    if n <= 2 * k {
        return Ok(());
    }
    let c = Cut {
        records: n,
        head: k,
        tail_from: n - k,
    };
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&log)
        .map_err(err)?;
    f.seek(SeekFrom::Start(c.tail_from * REC_SIZE as u64))
        .map_err(err)?;
    let mut tail = vec![];
    f.read_to_end(&mut tail).map_err(err)?;
    std::fs::write(inc.join("boundary.tail"), &tail).map_err(err)?;
    f.set_len(c.head * REC_SIZE as u64).map_err(err)?;
    // Last: a log is read as cut only once it is.
    crate::result::write_json(
        &inc.join("boundary.cut"),
        &serde_json::to_value(&c).unwrap(),
    )
}

/// The name of an emulated instruction (an `InsnEmulation` record's `nr`).
pub fn insn_name(nr: u32) -> String {
    match nr {
        0x0f31 => "rdtsc".to_string(),
        0x0f01f9 => "rdtscp".to_string(),
        0x0fc706 => "rdrand".to_string(),
        0x0fc707 => "rdseed".to_string(),
        0xf30fc707 => "rdpid".to_string(),
        // arm64: `mrs` with the target register cleared.
        0xd53be040 => "mrs cntvct_el0".to_string(),
        0xd53be0c0 => "mrs cntvctss_el0".to_string(),
        0xd53be000 => "mrs cntfrq_el0".to_string(),
        0xd53b2400 => "mrs rndr".to_string(),
        0xd53b2420 => "mrs rndrrs".to_string(),
        // arm64 pause points: the original word.
        0xd503203f => "yield".to_string(),
        0xd503205f => "wfe".to_string(),
        0xd503207f => "wfi".to_string(),
        0xd5033fdf => "isb".to_string(),
        n => format!("{n:#x}"),
    }
}

pub fn describe(r: &Rec) -> String {
    let kind = RecKind::from_u8(r.kind);
    let what = match kind {
        Some(RecKind::Trap) => format!("{} [{}]", name(r.nr as u64), Class::code_name(r.class)),
        Some(RecKind::SupDecision) => Op::from_u32(r.nr)
            .map(|o| o.name().to_string())
            .unwrap_or_else(|| format!("op{}", r.nr)),
        Some(RecKind::InsnEmulation) => insn_name(r.nr),
        Some(RecKind::Preempt) => match r.nr {
            1 => "counter".to_string(),
            2 => "spin point".to_string(),
            proto::compute::PREEMPT_NR => match r.args[2] {
                proto::compute::REASON_DEADLINE => "compute deadline".to_string(),
                proto::compute::REASON_REFILL => "compute refill".to_string(),
                _ => "compute switch".to_string(),
            },
            n => format!("{n:#x}"),
        },
        Some(RecKind::Name) => {
            let (b, n, cut) = r.name_bytes();
            let s = String::from_utf8_lossy(&b[..n]);
            format!("{}{s}", if cut { "..." } else { "" })
        }
        Some(RecKind::Str) => {
            let b = r.str_bytes();
            let more = r.class & STR_MORE != 0;
            // This record's part of the string, escaped on one line (a later record does not
            // know where the string ends: its zero padding is left out). `log events` joins
            // the parts.
            let k = if more {
                b.iter().rposition(|&c| c != 0).map_or(0, |i| i + 1)
            } else {
                (r.nr as usize).min(STR_BYTES)
            };
            format!(
                "{} of {}{}{} \"{}\"",
                str_which(r.class & STR_WHICH),
                r.nr,
                if more { " (more)" } else { "" },
                if r.class & STR_CUT != 0 { " (cut)" } else { "" },
                b[..k].escape_ascii()
            )
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

/// The name of a string (`Str` record) kind.
pub fn str_which(w: u8) -> &'static str {
    match w {
        STR_LABEL => "label",
        STR_TEXT => "text",
        STR_PATH => "path",
        STR_PATH2 => "path2",
        STR_RESOLVED => "resolved",
        STR_RESOLVED2 => "resolved2",
        STR_ARGV => "argv",
        STR_ARGV_CUT => "argv-cut",
        _ => "string",
    }
}

/// A string read back from its `Str` records: `start` at its first record, `push` the ones
/// after it until it is whole.
#[derive(Debug, PartialEq, Eq)]
pub struct Str {
    pub which: u8,
    pub pid: i64,
    pub bytes: Vec<u8>,
    /// Longer than the bytes kept.
    pub cut: bool,
    len: usize,
}

impl Str {
    pub fn start(r: &Rec) -> Option<Str> {
        if r.kind != RecKind::Str as u8 || r.class & STR_MORE != 0 {
            return None;
        }
        let mut s = Str {
            which: r.class & STR_WHICH,
            pid: r.ret,
            bytes: vec![],
            cut: r.class & STR_CUT != 0,
            len: r.nr as usize,
        };
        s.take(r);
        Some(s)
    }

    fn take(&mut self, r: &Rec) {
        let k = (self.len - self.bytes.len()).min(STR_BYTES);
        self.bytes.extend_from_slice(&r.str_bytes()[..k]);
    }

    /// All of its records read (not so when a log was cut in the middle of one).
    pub fn whole(&self) -> bool {
        self.bytes.len() == self.len
    }

    /// Whether `r` is this string's next record; if so its bytes are taken.
    pub fn push(&mut self, r: &Rec) -> bool {
        let next = !self.whole()
            && r.kind == RecKind::Str as u8
            && r.class & STR_MORE != 0
            && r.class & STR_WHICH == self.which
            && r.nr as usize == self.len
            && r.ret == self.pid;
        if next {
            self.take(r);
        }
        next
    }
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
        let show = |r: Option<Rec>| {
            r.map(|r| describe(&r))
                .unwrap_or_else(|| "(end of log)".into())
        };
        // A cut log (a sweep's kept run) is compared where it was kept: its first and last
        // records and its length; the digest, compared after, covers the records between.
        if let Ok(c) = crate::result::read_json(&da.join("boundary.cut")) {
            let c: Cut = serde_json::from_value(c).map_err(|e| format!("{}: {e}", da.display()))?;
            let pb = Path::new(&pb);
            let len = std::fs::metadata(pb).map(|m| m.len()).unwrap_or(0) / REC_SIZE as u64;
            if len != c.records {
                return Ok(Some(format!(
                    "inc-{k}: the recorded log has {} records, the replayed {len}",
                    c.records
                )));
            }
            let parts = [
                (load(&pa)?, load_range(pb, 0, c.head)?, 0),
                (
                    load(&da.join("boundary.tail").display().to_string())?,
                    load_range(pb, c.tail_from, c.records - c.tail_from)?,
                    c.tail_from as usize,
                ),
            ];
            for (x, y, at) in parts {
                if let Some((i, ra, rb)) = first_difference(&x, &y) {
                    return Ok(Some(format!(
                        "inc-{k} record {}: recorded {}; replayed {}",
                        at + i,
                        show(ra),
                        show(rb)
                    )));
                }
            }
            continue;
        }
        let (x, y) = (load(&pa)?, load(&pb)?);
        if let Some((i, ra, rb)) = first_difference(&x, &y) {
            return Ok(Some(format!(
                "inc-{k} record {i}: recorded {}; replayed {}",
                show(ra),
                show(rb)
            )));
        }
    }
    Ok(None)
}

/// `log tree INCDIR DIR`: write the work tree the incarnation ended with (`INCDIR/live.tree`)
/// into `DIR`, which must not exist or be empty: names, kinds, modes, contents, symlinks, hard
/// links and user xattrs, as `Tree::write_dir` does.
fn tree(inc: &Path, dir: &Path) -> Res<()> {
    let live = inc.join("live.tree");
    if !live.is_file() {
        return Err(format!(
            "{}: no such file: an incarnation's final tree is kept only with its run's logs; a sweep prunes the logs of ok runs unless given --keep all",
            live.display()
        ));
    }
    let t = crate::durability::tree::Tree::read_archive(&live)?;
    let err = |e: std::io::Error| format!("{}: {e}", dir.display());
    match std::fs::read_dir(dir) {
        Ok(mut rd) => {
            if rd.next().is_some() {
                return Err(format!("{}: exists and is not empty", dir.display()));
            }
            t.fill(dir, 0o700).map_err(err)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => t.write_dir(dir).map_err(err),
        Err(e) => Err(err(e)),
    }
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
        Some("tree") => {
            let usage = "log tree INCDIR DIR";
            tree(Path::new(arg(1, usage)?), Path::new(arg(2, usage)?))?;
            Ok(ExitCode::SUCCESS)
        }
        Some("events") => {
            let run = Path::new(arg(1, "log events RUNDIR [--types T,T] [--from SEQ] [--to SEQ]")?);
            let sel = crate::events::Select::parse(
                args.last("--types"),
                args.num::<u64>("--from")?.unwrap_or(0),
                args.num::<u64>("--to")?.unwrap_or(u64::MAX),
            )?;
            match crate::events::export(run, &sel, std::io::stdout().lock()) {
                // A reader that stopped early (`| head`) is not an error.
                Err(e) if e.contains("Broken pipe") => Ok(ExitCode::SUCCESS),
                r => r.map(|()| ExitCode::SUCCESS),
            }
        }
        _ => Err(
            "log dump LOG | log diff LOG LOG | log ops INCDIR | log ops --check RUNDIR | log tree INCDIR DIR | log events RUNDIR"
                .into(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A string of any length comes back whole from its records, which follow one another
    /// with the same process; a record of another string ends it.
    #[test]
    fn strings_round_trip() {
        for n in [0usize, 1, 63, 64, 65, 255, 4096] {
            let s: Vec<u8> = (0..n).map(|i| (i * 7 % 256) as u8).collect();
            let recs: Vec<Rec> = Rec::strs(9, 5, 2, 42, STR_LABEL, &s, n == 255).collect();
            assert_eq!(recs.len(), n.div_ceil(STR_BYTES).max(1));
            let mut got = Str::start(&recs[0]).unwrap();
            for r in &recs[1..] {
                assert!(got.push(r));
                assert!(Str::start(r).is_none());
            }
            assert!(got.whole());
            assert_eq!((got.bytes, got.pid, got.cut), (s, 42, n == 255));
        }
        let a: Vec<Rec> = Rec::strs(1, 0, 0, 7, STR_LABEL, &[1; 100], false).collect();
        let b: Vec<Rec> = Rec::strs(1, 0, 0, 7, STR_TEXT, &[2; 100], false).collect();
        let mut s = Str::start(&a[0]).unwrap();
        assert!(!s.push(&b[0]) && !s.push(&b[1]) && !s.whole());
    }
}
