//! The supervisor's part of crash and restart:
//!
//! - `copy_in`: the next incarnation's `/in` into `/work` in sorted path order, keeping hard
//!   links, symlinks, FIFOs, modes and user xattrs (inode numbers then follow that order).
//! - `write_base`: the initial `/work` as base records (`seq` 0, durable) at the head of the
//!   operation log, so the log alone determines every post-crash tree.
//! - `crash_verdict`: `Op::CrashPoint` ends the incarnation; the caller kills every guest
//!   process (`finish` kills the whole PID namespace, which holds for any number of
//!   processes) and then exports the live tree.
//! - `export`: the live `/work` as a tree archive on descriptor 3006, at every finish, after
//!   the guests are dead.

use crate::durability::tree::{Kind, Tree};
use crate::outcome::Verdict;
use proto::ctl::Ctl;
use proto::faults::{CRASH_MACHINE, CRASH_PROCESS};
use proto::layout::*;
use proto::oplog::{OpKind, OpRec};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::Ordering::Relaxed;

pub fn copy_in(src: &Path, dst: &Path) -> Result<(), String> {
    let t = Tree::from_dir(src).map_err(|e| format!("reading {}: {e}", src.display()))?;
    t.fill(dst, 0)
        .map_err(|e| format!("writing {}: {e}", dst.display()))
}

fn pwrite_all(fd: i32, mut off: u64, b: &[u8]) -> Result<(), String> {
    let mut done = 0;
    while done < b.len() {
        let r = unsafe {
            libc::pwrite(
                fd,
                b[done..].as_ptr() as *const _,
                b.len() - done,
                off as i64,
            )
        };
        if r <= 0 {
            return Err(format!(
                "operation log write: {}",
                std::io::Error::last_os_error()
            ));
        }
        done += r as usize;
        off += r as u64;
    }
    Ok(())
}

struct Writer<'a> {
    ctl: &'a Ctl,
}

impl Writer<'_> {
    fn rec(&self, kind: OpKind, ino: u64, a: [u64; 6], data: &[u8]) -> Result<(), String> {
        let doff = self.ctl.opdata_len.load(Relaxed);
        pwrite_all(FD_OPLOG_DATA, doff, data)?;
        self.ctl.opdata_len.store(doff + data.len() as u64, Relaxed);
        let r = OpRec {
            seq: 0,
            vclock_ns: self.ctl.vclock_ns.load(Relaxed),
            kind: kind as u32,
            pid: 0,
            ino,
            a,
            data_off: doff,
            data_len: data.len() as u64,
        };
        let off = self.ctl.oplog_len.load(Relaxed);
        pwrite_all(FD_OPLOG_META, off, r.as_bytes())?;
        self.ctl
            .oplog_len
            .store(off + r.as_bytes().len() as u64, Relaxed);
        Ok(())
    }
}

fn fmt_bits(k: Kind) -> u64 {
    match k {
        Kind::Dir => 0o040000,
        Kind::File => 0o100000,
        Kind::Symlink => 0o120000,
        Kind::Fifo => 0o010000,
        Kind::Socket => 0o140000,
        Kind::Other => 0,
    }
}

/// Base records for the tree now in `/work`. Returns the number of records.
pub fn write_base(ctl: &Ctl, work: &Path) -> Result<usize, String> {
    let t = Tree::from_dir(work).map_err(|e| format!("reading {}: {e}", work.display()))?;
    let w = Writer { ctl };
    let root = t.nodes.get(&b""[..]).ok_or("no root")?;
    let owner = (root.uid, root.gid);
    w.rec(
        OpKind::Root,
        root.ino,
        [root.mode as u64, root.uid as u64, root.gid as u64, 1, 0, 0],
        &[],
    )?;
    let mut n = 1;
    let mut seen: BTreeMap<u64, ()> = BTreeMap::new();
    for (p, node) in &t.nodes {
        if p.is_empty() {
            continue;
        }
        let (parent_path, name) = match p.iter().rposition(|&c| c == b'/') {
            Some(i) => (&p[..i], &p[i + 1..]),
            None => (&b""[..], &p[..]),
        };
        let parent = t.nodes[parent_path].ino;
        if node.kind != Kind::Dir && seen.insert(node.ino, ()).is_some() {
            w.rec(OpKind::Link, node.ino, [parent, 0, 0, 1, 0, 0], name)?;
            n += 1;
            continue;
        }
        match node.kind {
            Kind::Dir => w.rec(
                OpKind::Mkdir,
                node.ino,
                [parent, node.mode as u64, 0, 1, 0, 0],
                name,
            )?,
            Kind::Symlink => {
                let d = [name, &node.data.to_vec()[..]].concat();
                w.rec(
                    OpKind::Symlink,
                    node.ino,
                    [parent, name.len() as u64, 0, 1, 0, 0],
                    &d,
                )?
            }
            k => w.rec(
                OpKind::Create,
                node.ino,
                [parent, node.mode as u64, fmt_bits(k), 1, 0, 0],
                name,
            )?,
        }
        n += 1;
        if node.kind == Kind::File && !node.data.is_empty() {
            // Sparse: only the extents holding non-zero bytes are logged.
            let ex = crate::durability::materialise::sparse_encode(&node.data);
            w.rec(
                OpKind::Write,
                node.ino,
                [0, node.data.len(), 1, proto::oplog::WRITE_SPARSE, 0, 0],
                &ex,
            )?;
            n += 1;
        }
        if node.kind != Kind::Symlink && (node.uid, node.gid) != owner {
            w.rec(
                OpKind::SetAttr,
                node.ino,
                [node.mode as u64, node.uid as u64, node.gid as u64, 1, 0, 0],
                &[],
            )?;
            n += 1;
        }
        for (k, v) in &node.xattrs {
            w.rec(
                OpKind::XattrSet,
                node.ino,
                [k.len() as u64, 1, 0, 0, 0, 0],
                &[&k[..], &v[..]].concat(),
            )?;
            n += 1;
        }
    }
    Ok(n)
}

pub fn crash_name(kind: u64) -> &'static str {
    match kind {
        CRASH_MACHINE => "machine",
        CRASH_PROCESS => "process",
        _ => "unknown",
    }
}

/// The verdict for `Op::CrashPoint [kind, seq, k]`: class `crash`, detail
/// `KIND SEQ VCLOCK_NS SUBPOINT`.
pub fn crash_verdict(a: [u64; 6], vclock_ns: u64) -> Verdict {
    Verdict::new(
        "crash",
        format!("{} {} {} {}", crash_name(a[0]), a[1], vclock_ns, a[2]),
    )
}

/// Export the live `/work` to descriptor 3006 (absent when the launcher passed none).
pub fn export(work: &Path) {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(FD_EXPORT, &mut st) } != 0 {
        return;
    }
    let bytes = match Tree::from_dir(work) {
        Ok(t) => t.encode(),
        Err(e) => format!("export failed: {e}").into_bytes(),
    };
    let _ = pwrite_all(FD_EXPORT, 0, &bytes);
}
