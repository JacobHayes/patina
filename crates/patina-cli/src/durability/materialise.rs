//! Post-crash trees: a pure function of
//! (operation log prefix, seed, model). The base image is part of the log: the supervisor
//! records the initial `/work` (incarnation 0's `--work`, or the previous incarnation's
//! post-crash tree) as base records with `seq` 0, which are durable by definition. So the
//! function needs no filesystem and is tested without a sandbox.
//!
//! `Fs` is the inode-level replay both models and the self-check share: names are keyed by
//! (parent inode, name), data by inode, exactly as the records carry them.

use super::content::Content;
use super::log::{Op, OpLog};
use super::tree::{Kind, Node, Tree};
use proto::oplog::{OpKind, WRITE_SPARSE};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Model {
    Ext4Ordered,
    PosixStrict,
}

impl Model {
    pub fn parse(s: &str) -> Option<Model> {
        match s {
            "ext4-ordered" => Some(Model::Ext4Ordered),
            "posix-strict" => Some(Model::PosixStrict),
            _ => None,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Model::Ext4Ordered => "ext4-ordered",
            Model::PosixStrict => "posix-strict",
        }
    }
}

pub use super::content::BLOCK;

#[derive(Clone, Debug)]
pub struct Inode {
    pub kind: Kind,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub xattrs: BTreeMap<Vec<u8>, Vec<u8>>,
    /// File contents (length = size) or symlink target.
    pub data: Content,
}

/// An inode-level file system image.
#[derive(Clone, Debug, Default)]
pub struct Fs {
    pub root: u64,
    pub inodes: BTreeMap<u64, Inode>,
    pub dirs: BTreeMap<u64, BTreeMap<Vec<u8>, u64>>,
    /// Owner of the root (default owner of created inodes).
    pub owner: (u32, u32),
    /// With `track`: every inode whose entry in `inodes` or `dirs` changed since the set was
    /// last taken (the ext4 model's commit copies only these).
    pub track: bool,
    pub changed: BTreeSet<u64>,
}

/// Decode a `WRITE_SPARSE` record's extents.
pub fn sparse_extents(data: &[u8]) -> Result<Vec<(u64, &[u8])>, String> {
    let mut out = vec![];
    let mut p = 0usize;
    while p < data.len() {
        if p + 16 > data.len() {
            return Err("sparse write record: truncated extent header".into());
        }
        let off = u64::from_le_bytes(data[p..p + 8].try_into().unwrap());
        let n = u64::from_le_bytes(data[p + 8..p + 16].try_into().unwrap()) as usize;
        p += 16;
        if p + n > data.len() {
            return Err("sparse write record: truncated extent".into());
        }
        out.push((off, &data[p..p + n]));
        p += n;
    }
    Ok(out)
}

/// Encode extents for a `WRITE_SPARSE` record.
pub fn sparse_encode(c: &Content) -> Vec<u8> {
    let mut o = vec![];
    for (off, b) in c.extents() {
        o.extend_from_slice(&off.to_le_bytes());
        o.extend_from_slice(&(b.len() as u64).to_le_bytes());
        o.extend_from_slice(&b);
    }
    o
}

pub type R = Result<(), String>;

const RENAME_EXCHANGE: u64 = 2;
const FALLOC_KEEP_SIZE: u64 = 1;
const FALLOC_PUNCH_HOLE: u64 = 2;
const FALLOC_ZERO_RANGE: u64 = 0x10;

impl Fs {
    fn mark(&mut self, ino: u64) {
        if self.track {
            self.changed.insert(ino);
        }
    }

    fn dir(&mut self, d: u64) -> Result<&mut BTreeMap<Vec<u8>, u64>, String> {
        if self.track {
            self.changed.insert(d);
        }
        self.dirs
            .get_mut(&d)
            .ok_or_else(|| format!("directory inode {d} unknown"))
    }

    fn inode_mut(&mut self, ino: u64) -> Option<&mut Inode> {
        self.mark(ino);
        self.inodes.get_mut(&ino)
    }

    fn new_inode(&mut self, ino: u64, kind: Kind, mode: u32, data: Vec<u8>) {
        let (uid, gid) = self.owner;
        self.mark(ino);
        self.inodes.insert(
            ino,
            Inode {
                kind,
                mode: mode & 0o7777,
                uid,
                gid,
                xattrs: BTreeMap::new(),
                data: Content::from_slice(&data),
            },
        );
        if kind == Kind::Dir {
            self.dirs.insert(ino, BTreeMap::new());
        }
    }

    fn add_name(&mut self, parent: u64, name: &[u8], ino: u64) -> R {
        let d = self.dir(parent)?;
        if d.contains_key(name) {
            return Err(format!(
                "name {:?} exists in {parent}",
                String::from_utf8_lossy(name)
            ));
        }
        d.insert(name.to_vec(), ino);
        Ok(())
    }

    pub fn has(&self, ino: u64) -> bool {
        self.inodes.contains_key(&ino)
    }

    pub fn size(&self, ino: u64) -> u64 {
        self.inodes.get(&ino).map(|i| i.data.len()).unwrap_or(0)
    }

    /// Write bytes at an offset (extending with zeros).
    pub fn write(&mut self, ino: u64, off: u64, bytes: &[u8]) -> R {
        let i = self
            .inode_mut(ino)
            .ok_or_else(|| format!("write to unknown inode {ino}"))?;
        i.data.write(off, bytes);
        Ok(())
    }

    /// `ino[lo..hi] = src[lo..hi]`, within the current size (blocks are shared).
    pub fn copy_from(&mut self, ino: u64, src: &Content, lo: u64, hi: u64) -> R {
        let i = self
            .inode_mut(ino)
            .ok_or_else(|| format!("write to unknown inode {ino}"))?;
        i.data.copy_from(src, lo, hi);
        Ok(())
    }

    pub fn resize(&mut self, ino: u64, size: u64) -> R {
        let i = self
            .inode_mut(ino)
            .ok_or_else(|| format!("truncate of unknown inode {ino}"))?;
        i.data.resize(size);
        Ok(())
    }

    pub fn zero(&mut self, ino: u64, off: u64, len: u64) -> R {
        let i = self
            .inode_mut(ino)
            .ok_or_else(|| format!("unknown inode {ino}"))?;
        i.data.zero(off, off.saturating_add(len));
        Ok(())
    }

    /// Would `apply(op)` fail? Exactly the conditions `apply` checks, evaluated before it
    /// changes anything; `None` for the records where `apply` could fail after a partial
    /// change (an inode that is its own parent or rename target: never seen in a real log),
    /// for which the caller must apply to a copy.
    pub fn would_fail(&self, op: &Op) -> Option<bool> {
        let a = op.a;
        let ino = op.ino;
        let dir = |d: u64| self.dirs.get(&d);
        let named = |d: u64, n: &[u8]| self.dirs.get(&d).is_some_and(|m| m.contains_key(n));
        Some(match op.kind {
            OpKind::Root => false,
            OpKind::Create => {
                if a[0] != 0 && a[0] == ino {
                    return None;
                }
                a[0] != 0 && (dir(a[0]).is_none() || named(a[0], &op.data))
            }
            OpKind::Mkdir => {
                if a[0] == ino {
                    return None;
                }
                dir(a[0]).is_none() || named(a[0], &op.data)
            }
            OpKind::Symlink => {
                if a[0] == ino {
                    return None;
                }
                let (name, _) = op.split(a[1]);
                dir(a[0]).is_none() || named(a[0], name)
            }
            OpKind::Link => !self.has(ino) || dir(a[0]).is_none() || named(a[0], &op.data),
            OpKind::Unlink | OpKind::Rmdir => {
                if a[0] == ino {
                    return None;
                }
                match dir(a[0]).and_then(|d| d.get(&op.data)) {
                    Some(&i) if i == ino => {
                        op.kind == OpKind::Rmdir
                            && self.dirs.get(&ino).is_some_and(|c| !c.is_empty())
                    }
                    _ => true,
                }
            }
            OpKind::Rename => {
                let (old, new) = op.split(a[4]);
                let (op_, np) = (a[0], a[1]);
                let Some(src) = dir(op_).and_then(|d| d.get(old)).copied() else {
                    return Some(true);
                };
                if src != ino {
                    return Some(true);
                }
                let Some(nd) = dir(np) else { return Some(true) };
                let dst = nd.get(new).copied();
                if a[3] & RENAME_EXCHANGE != 0 {
                    dst.is_none()
                } else if dst == Some(src) {
                    false
                } else if let Some(r) = dst {
                    if r == op_ || r == np {
                        return None;
                    }
                    self.dirs.get(&r).is_some_and(|c| !c.is_empty())
                } else {
                    false
                }
            }
            OpKind::Write | OpKind::MmapDirty => {
                if op.kind == OpKind::Write && a[3] & WRITE_SPARSE != 0 {
                    !self.has(ino) || sparse_extents(&op.data).is_err()
                } else {
                    op.data.len() as u64 != a[1] || !self.has(ino)
                }
            }
            OpKind::Truncate => !self.has(ino),
            OpKind::Fallocate => {
                let (mode, off, len) = (a[0], a[1], a[2]);
                (mode & (FALLOC_PUNCH_HOLE | FALLOC_ZERO_RANGE) != 0 && !self.has(ino))
                    || (mode & (FALLOC_KEEP_SIZE | FALLOC_PUNCH_HOLE) == 0
                        && self.size(ino) < off + len
                        && !self.has(ino))
                    || mode & !(FALLOC_KEEP_SIZE | FALLOC_PUNCH_HOLE | FALLOC_ZERO_RANGE) != 0
            }
            OpKind::SetAttr | OpKind::XattrSet | OpKind::XattrRemove => !self.has(ino),
            OpKind::MmapShared
            | OpKind::Fsync
            | OpKind::FsyncDir
            | OpKind::FsyncFail
            | OpKind::Sync
            | OpKind::Close
            | OpKind::Crash => false,
        })
    }

    /// Apply one record (the full, live semantics: every effect happens).
    pub fn apply(&mut self, op: &Op) -> R {
        let a = op.a;
        let ino = op.ino;
        match op.kind {
            OpKind::Root => {
                self.root = ino;
                self.owner = (a[1] as u32, a[2] as u32);
                self.new_inode(ino, Kind::Dir, a[0] as u32, vec![]);
            }
            OpKind::Create => {
                if a[0] != 0 {
                    self.dir(a[0])?;
                }
                self.new_inode(ino, Kind::from_mode(a[2] as u32), a[1] as u32, vec![]);
                if a[0] != 0 {
                    self.add_name(a[0], &op.data, ino)?;
                }
            }
            OpKind::Mkdir => {
                self.dir(a[0])?;
                self.new_inode(ino, Kind::Dir, a[1] as u32, vec![]);
                self.add_name(a[0], &op.data, ino)?;
            }
            OpKind::Symlink => {
                self.dir(a[0])?;
                let (name, target) = op.split(a[1]);
                self.new_inode(ino, Kind::Symlink, 0o777, target.to_vec());
                self.add_name(a[0], name, ino)?;
            }
            OpKind::Link => {
                if !self.has(ino) {
                    return Err(format!("link to unknown inode {ino}"));
                }
                self.add_name(a[0], &op.data, ino)?;
            }
            OpKind::Unlink | OpKind::Rmdir => {
                let d = self.dir(a[0])?;
                match d.get(&op.data) {
                    Some(&i) if i == ino => {}
                    _ => {
                        return Err(format!(
                            "unlink: {:?} in {} is not inode {ino}",
                            String::from_utf8_lossy(&op.data),
                            a[0]
                        ))
                    }
                }
                if op.kind == OpKind::Rmdir {
                    if self.dirs.get(&ino).is_some_and(|c| !c.is_empty()) {
                        return Err(format!("rmdir of non-empty directory {ino}"));
                    }
                    self.mark(ino);
                    self.dirs.remove(&ino);
                }
                self.dir(a[0])?.remove(&op.data);
            }
            OpKind::Rename => {
                let (old, new) = op.split(a[4]);
                let (op_, np) = (a[0], a[1]);
                let src = *self
                    .dir(op_)?
                    .get(old)
                    .ok_or_else(|| format!("rename: no {:?}", String::from_utf8_lossy(old)))?;
                if src != ino {
                    return Err(format!(
                        "rename: {:?} is inode {src}, record says {ino}",
                        String::from_utf8_lossy(old)
                    ));
                }
                let dst = self.dir(np)?.get(new).copied();
                if a[3] & RENAME_EXCHANGE != 0 {
                    let dst = dst.ok_or("rename exchange: no target")?;
                    self.dir(op_)?.insert(old.to_vec(), dst);
                    self.dir(np)?.insert(new.to_vec(), src);
                } else if dst == Some(src) {
                    // Two names of one inode: POSIX says nothing happens.
                } else {
                    if let Some(r) = dst {
                        if self.dirs.get(&r).is_some_and(|c| !c.is_empty()) {
                            return Err("rename over a non-empty directory".into());
                        }
                        if self.inodes.get(&r).is_some_and(|i| i.kind == Kind::Dir) {
                            self.mark(r);
                            self.dirs.remove(&r);
                        }
                    }
                    self.dir(op_)?.remove(old);
                    self.dir(np)?.insert(new.to_vec(), src);
                }
            }
            OpKind::Write if a[3] & WRITE_SPARSE != 0 => {
                // A base record of a sparse file: `[off, off + len)` is the extents over
                // zeros.
                let ex = sparse_extents(&op.data)?;
                if !self.has(ino) {
                    return Err(format!("write to unknown inode {ino}"));
                }
                let end = a[0] + a[1];
                if self.size(ino) < end {
                    self.resize(ino, end)?;
                }
                self.zero(ino, a[0], a[1])?;
                for (o, b) in ex {
                    self.write(ino, a[0] + o, b)?;
                }
            }
            OpKind::Write | OpKind::MmapDirty => {
                if op.data.len() as u64 != a[1] {
                    return Err(format!(
                        "write record holds {} bytes, says {}",
                        op.data.len(),
                        a[1]
                    ));
                }
                self.write(ino, a[0], &op.data)?;
            }
            OpKind::Truncate => self.resize(ino, a[0])?,
            OpKind::Fallocate => {
                let (mode, off, len) = (a[0], a[1], a[2]);
                if mode & (FALLOC_PUNCH_HOLE | FALLOC_ZERO_RANGE) != 0 {
                    self.zero(ino, off, len)?;
                }
                if mode & (FALLOC_KEEP_SIZE | FALLOC_PUNCH_HOLE) == 0 && self.size(ino) < off + len
                {
                    self.resize(ino, off + len)?;
                }
                if mode & !(FALLOC_KEEP_SIZE | FALLOC_PUNCH_HOLE | FALLOC_ZERO_RANGE) != 0 {
                    return Err(format!("fallocate mode {mode:#x} not modelled"));
                }
            }
            OpKind::SetAttr => {
                let i = self
                    .inode_mut(ino)
                    .ok_or_else(|| format!("setattr of unknown inode {ino}"))?;
                if a[3] == 1 {
                    i.mode = a[0] as u32 & 0o7777;
                    i.uid = a[1] as u32;
                    i.gid = a[2] as u32;
                }
            }
            OpKind::XattrSet => {
                let (k, v) = op.split(a[0]);
                let i = self
                    .inode_mut(ino)
                    .ok_or_else(|| format!("xattr of unknown inode {ino}"))?;
                i.xattrs.insert(k.to_vec(), v.to_vec());
            }
            OpKind::XattrRemove => {
                let i = self
                    .inode_mut(ino)
                    .ok_or_else(|| format!("xattr of unknown inode {ino}"))?;
                i.xattrs.remove(&op.data);
            }
            OpKind::MmapShared
            | OpKind::Fsync
            | OpKind::FsyncDir
            | OpKind::FsyncFail
            | OpKind::Sync
            | OpKind::Close
            | OpKind::Crash => {}
        }
        Ok(())
    }

    /// The tree reachable from the root (unlinked inodes have no name and do not appear).
    pub fn to_tree(&self) -> Tree {
        let mut t = Tree::default();
        let mut stack = vec![(Vec::new(), self.root)];
        while let Some((path, ino)) = stack.pop() {
            let Some(i) = self.inodes.get(&ino) else {
                continue;
            };
            t.nodes.insert(
                path.clone(),
                Node {
                    kind: i.kind,
                    mode: i.mode,
                    uid: i.uid,
                    gid: i.gid,
                    ino,
                    data: i.data.clone(),
                    xattrs: i.xattrs.clone(),
                },
            );
            if let Some(d) = self.dirs.get(&ino) {
                for (name, &c) in d {
                    let p = if path.is_empty() {
                        name.clone()
                    } else {
                        [&path[..], b"/", name].concat()
                    };
                    stack.push((p, c));
                }
            }
        }
        t
    }
}

/// Replay the whole log: the live tree the incarnation should have ended with.
pub fn replay(log: &OpLog) -> Result<Fs, String> {
    let mut fs = Fs::default();
    for (i, op) in log.ops.iter().enumerate() {
        fs.apply(op)
            .map_err(|e| format!("record {i} ({} seq {}): {e}", op.kind.name(), op.seq))?;
    }
    Ok(fs)
}

/// The post-crash tree for the log prefix `seq <= upto` under `model`. `key` separates
/// crash points and variants (the crash materialiser).
pub fn materialise(
    log: &OpLog,
    upto: u64,
    seed: u64,
    key: u64,
    model: Model,
) -> Result<Tree, String> {
    let owned;
    let prefix = if log.ops.iter().all(|o| o.seq <= upto) {
        log
    } else {
        owned = log.upto(upto);
        &owned
    };
    match model {
        Model::Ext4Ordered => super::model_ext4::materialise(prefix, seed, key),
        Model::PosixStrict => super::model_posix::materialise(prefix, seed, key),
    }
}

/// The crash's virtual time: the `Crash` record's, or the last record's.
pub fn crash_time(ops: &[Op]) -> u64 {
    ops.iter()
        .rev()
        .find(|o| o.kind == OpKind::Crash)
        .or(ops.last())
        .map(|o| o.vclock_ns)
        .unwrap_or(0)
}

/// A draw for the materialiser: `draw(seed, Torn, mix(key, a, b))`.
pub fn torn(seed: u64, key: u64, a: u64, b: u64) -> u64 {
    use proto::draw::mix64;
    proto::draw(
        seed,
        proto::Stream::Torn,
        mix64(key ^ mix64(a.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ b.rotate_left(29))),
    )
}
