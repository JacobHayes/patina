//! `patina log ops --check RUN`: for every incarnation, replaying the complete operation log onto
//! its base must give exactly the live tree the supervisor exported (`live.tree`): names,
//! kinds, modes, owners, link structure (inode numbers), contents, extended attributes.
//! A difference means the tracker missed a way of changing a file. There is no exception:
//! stores through shared mappings are logged however their process ends, by its runtime or,
//! for a `SIGKILL`, the end of the run or a crash, by the supervisor (`sup::maps`).

use super::log::OpLog;
use super::materialise::replay;
use super::tree::{diff, Tree};
use std::path::{Path, PathBuf};

pub fn incarnations(run: &Path) -> Vec<PathBuf> {
    let mut v = vec![];
    for k in 0.. {
        let d = run.join(format!("inc-{k}"));
        if !d.is_dir() {
            break;
        }
        v.push(d);
    }
    v
}

/// Check one incarnation directory. Ok(summary) or Err(first difference).
pub fn check_inc(dir: &Path) -> Result<String, String> {
    let log = OpLog::load(dir)?;
    let live = Tree::read_archive(&dir.join("live.tree"))?;
    let replayed = replay(&log)?.to_tree();
    if let Some(d) = diff(&replayed, &live, true) {
        return Err(format!(
            "{}: replay differs from the live tree: {d} (first tree: replay)",
            dir.display()
        ));
    }
    let (m, b) = log.bytes();
    Ok(format!(
        "{}: ok ({} records, {} + {} bytes, {} paths)",
        dir.display(),
        log.ops.len(),
        m,
        b,
        live.nodes.len()
    ))
}

pub fn check(run: &Path) -> Result<(), String> {
    let incs = incarnations(run);
    if incs.is_empty() {
        return Err(format!("{}: no incarnations", run.display()));
    }
    let mut bad = 0;
    for d in incs {
        match check_inc(&d) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                println!("FAIL {e}");
                bad += 1;
            }
        }
    }
    if bad > 0 {
        return Err(format!("log ops --check: {bad} incarnation(s) differ"));
    }
    Ok(())
}
