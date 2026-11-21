//! The supervisor's part of crash and restart:
//!
//! - `copy_in`: the next incarnation's `/in` into `/work` in sorted path order, keeping hard
//!   links, symlinks, FIFOs, modes and user xattrs (inode numbers then follow that order).
//! - `write_base`: the initial `/work` as base records (`seq` 0, durable) at the head of the
//!   operation log, so the log alone determines every post-crash tree.
//! - `crash_verdict`: `Op::CrashPoint` ends the incarnation; the caller logs every process's
//!   shared mappings (`maps`) and the `Crash` record (`append_crash`), then kills every guest
//!   process (`finish` kills the whole PID namespace, which holds for any number of
//!   processes) and then exports the live tree.
//! - `export`: the live `/work` as a tree archive on descriptor 3006, at every finish, after
//!   the guests are dead, with the virtual modification times the guest saw (`live_tree`).
//! - `seed_times`: at a restart, the times the tree it starts from carries (`Tree::times`,
//!   passed on by `carry_times`) go into the virtual time table, so a file keeps the time it
//!   had.

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

/// Node `node`'s work tree `work` with the virtual modification time of each inode the guest
/// changed (the virtual time table's).
pub fn live_tree(ctl: &Ctl, node: usize, work: &Path) -> Result<Tree, String> {
    let mut t = Tree::from_dir(work).map_err(|e| format!("live tree export: {e}"))?;
    let v = unsafe { proto::vfs::Vfs::at(ctl as *const Ctl as *mut u8) };
    let epoch = FILE_EPOCH_S * 1_000_000_000;
    for n in t.nodes.values_mut() {
        if let Some(Ok(i)) = v.vt_find(proto::vfs::work_key(node as u64, n.ino)) {
            n.mtime = Some(v.vt[i].mtime).filter(|&m| m != epoch);
        }
    }
    Ok(t)
}

/// A restart of node `node` (0: the driver) on the tree now in `work`: the table forgets the
/// inodes of the node's earlier work tree, and each path of `times` (what `Tree::times` wrote
/// for that tree) gets its time as all four of its inode's times (the tree carries only the
/// modification time). Before any guest of the node runs.
pub fn seed_times(ctl: &Ctl, node: usize, work: &Path, times: &[u8]) -> Result<(), String> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    let v = unsafe { proto::vfs::Vfs::at(ctl as *const Ctl as *mut u8) };
    let mine = |k: u64| k >> 48 == (node as u64) << 8 | proto::vfs::VT_WORK;
    super::vtgc::retain(v, |e| !mine(e.key));
    for (p, t) in crate::durability::tree::decode_times(times)? {
        let f = if p.is_empty() {
            work.to_path_buf()
        } else {
            work.join(std::ffi::OsStr::from_bytes(&p))
        };
        // A path a work tree cannot hold as a file (a socket's) is not there.
        let Ok(m) = std::fs::symlink_metadata(&f) else {
            continue;
        };
        let key = proto::vfs::work_key(node as u64, m.ino());
        let Some(slot) = v.vt_find(key) else {
            return Err("the virtual time table is full".into());
        };
        if let Err(i) = slot {
            if v.vt_used as usize >= proto::vfs::VT_CAP / 2 {
                return Err(format!(
                    "more than {} files with times to carry in the work tree",
                    proto::vfs::VT_CAP / 2
                ));
            }
            v.vt_used += 1;
            v.vt[i] = proto::vfs::VtEntry {
                key,
                atime: t,
                mtime: t,
                ctime: t,
                btime: t,
                gone_dev: 0,
            };
        }
    }
    Ok(())
}

/// The times of the tree a crash left go to the next incarnation's supervisor after the
/// System V shared memory a process crash carries, in the same descriptor (`FD_SHM`): the
/// launcher appends them and their length (`carry_times`), the supervisor splits them off
/// (`carried`).
pub fn carry_times(fd: i32, times: &[u8]) -> Result<(), String> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return Err(format!(
            "carried state: {}",
            std::io::Error::last_os_error()
        ));
    }
    let b = [times, &(times.len() as u64).to_le_bytes()].concat();
    pwrite_all(fd, st.st_size as u64, &b)
}

/// What the carried state holds: the shared memory, and the times (`carry_times`; empty in a
/// first incarnation, which no crash came before).
pub fn carried(b: &[u8], restart: bool) -> Result<(&[u8], &[u8]), String> {
    if !restart {
        return Ok((b, &[]));
    }
    let n = b
        .len()
        .checked_sub(8)
        .ok_or("carried state without its times")?;
    let t = u64::from_le_bytes(b[n..].try_into().unwrap()) as usize;
    let s = n
        .checked_sub(t)
        .ok_or("carried times longer than the state")?;
    Ok((&b[..s], &b[s..n]))
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

/// Append one operation record (with its bytes) at the end of the log, as the runtime does
/// (`rt::oplog::put_rec`), and keep its inode's window in the shadow store (`shadows`): `seq`
/// and `pid` say where in the run it belongs (0, 0 for the base); `node` is the node whose
/// work tree it is about.
#[allow(clippy::too_many_arguments)]
pub fn append(
    ctl: &Ctl,
    node: usize,
    kind: OpKind,
    ino: u64,
    a: [u64; 6],
    data: &[u8],
    seq: u64,
    pid: u32,
) -> Result<(), String> {
    put(
        ctl,
        proto::oplog::tag_kind(kind as u32, node),
        ino,
        a,
        data,
        seq,
        pid,
    )?;
    super::shadows::apply(ctl, proto::oplog::node_key(ino, node), kind, &a, data)
}

fn put(
    ctl: &Ctl,
    kind: u32,
    ino: u64,
    a: [u64; 6],
    data: &[u8],
    seq: u64,
    pid: u32,
) -> Result<(), String> {
    let doff = ctl.opdata_len.load(Relaxed);
    pwrite_all(FD_OPLOG_DATA, doff, data)?;
    ctl.opdata_len.store(doff + data.len() as u64, Relaxed);
    let r = OpRec {
        seq,
        vclock_ns: ctl.vclock_ns.load(Relaxed),
        kind,
        pid,
        ino,
        a,
        data_off: doff,
        data_len: data.len() as u64,
    };
    let off = ctl.oplog_len.load(Relaxed);
    pwrite_all(FD_OPLOG_META, off, r.as_bytes())?;
    ctl.oplog_len
        .store(off + r.as_bytes().len() as u64, Relaxed);
    Ok(())
}

/// The `Crash` record that ends the log of a crashed incarnation (`kind`: `CRASH_*`), after
/// the shared mappings of every process were logged (`maps`).
pub fn append_crash(ctl: &Ctl, node: usize, kind: u64, seq: u64, pid: u32) -> Result<(), String> {
    append(
        ctl,
        node,
        OpKind::Crash,
        0,
        [kind, 0, 0, 0, 0, 0],
        &[],
        seq,
        pid,
    )
}

struct Writer<'a> {
    ctl: &'a Ctl,
    node: usize,
}

impl Writer<'_> {
    fn rec(&self, kind: OpKind, ino: u64, a: [u64; 6], data: &[u8]) -> Result<(), String> {
        append(self.ctl, self.node, kind, ino, a, data, 0, 0)
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

/// Base records for the tree now in node `node`'s work tree `work`. Returns the number of
/// records.
pub fn write_base(ctl: &Ctl, node: usize, work: &Path) -> Result<usize, String> {
    let t = Tree::from_dir(work).map_err(|e| format!("reading {}: {e}", work.display()))?;
    let w = Writer { ctl, node };
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

/// Node `node`'s live work tree `work` as a record of the log (`KIND_LIVE_TREE`), after the
/// guests are dead: the launcher makes it the node's `live.tree`.
pub fn export_node(ctl: &Ctl, node: usize, work: &Path) -> Result<Tree, String> {
    let tree = live_tree(ctl, node, work)?;
    let bytes = tree.encode();
    let kind = proto::oplog::tag_kind(proto::oplog::KIND_LIVE_TREE, node);
    let len = |c: &Ctl| c.oplog_len.load(Relaxed) + c.opdata_len.load(Relaxed);
    let before = len(ctl);
    let r = put(ctl, kind, 0, [0; 6], &bytes, ctl.seq.load(Relaxed), 0);
    // The archive is the check's input, not the guest's output: exempt from `[run] log-limit`.
    ctl.log_exempt.fetch_add(len(ctl) - before, Relaxed);
    r.map(|()| tree)
}

/// The log of node `node`'s disk so far: its records in the shared log from `at` (bytes of
/// `oplog.meta`, where the disk's base records begin), plain.
pub fn disk_log(ctl: &Ctl, node: usize, at: u64) -> Result<crate::durability::log::OpLog, String> {
    use proto::oplog::{kind_node, KIND_LIVE_TREE, KIND_MASK, OPREC_SIZE};
    let read = |fd: i32, off: u64, len: usize| -> Result<Vec<u8>, String> {
        let mut b = vec![0u8; len];
        let mut done = 0;
        while done < len {
            let r = unsafe {
                libc::pread(
                    fd,
                    b[done..].as_mut_ptr() as *mut _,
                    len - done,
                    (off + done as u64) as i64,
                )
            };
            if r <= 0 {
                return Err(format!(
                    "operation log read: {}",
                    std::io::Error::last_os_error()
                ));
            }
            done += r as usize;
        }
        Ok(b)
    };
    let end = ctl.oplog_len.load(Relaxed);
    let meta = read(FD_OPLOG_META, at, end.saturating_sub(at) as usize)?;
    let mut ops = vec![];
    for (i, c) in meta.as_chunks::<OPREC_SIZE>().0.iter().enumerate() {
        let r = OpRec::from_bytes(c);
        if kind_node(r.kind) != node || r.kind & KIND_MASK == KIND_LIVE_TREE {
            continue;
        }
        let data = read(FD_OPLOG_DATA, r.data_off, r.data_len as usize)?;
        let plain = OpRec {
            kind: r.kind & KIND_MASK,
            ..r
        };
        ops.push(crate::durability::log::Op::from_rec(i, &plain, data)?);
    }
    Ok(crate::durability::log::OpLog { ops })
}

/// Export the live `/work` to descriptor 3006 (absent when the launcher passed none).
pub fn export(ctl: &Ctl, work: &Path) {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(FD_EXPORT, &mut st) } != 0 {
        return;
    }
    let bytes = match live_tree(ctl, 0, work) {
        Ok(t) => t.encode(),
        Err(e) => format!("export failed: {e}").into_bytes(),
    };
    let _ = pwrite_all(FD_EXPORT, 0, &bytes);
}
