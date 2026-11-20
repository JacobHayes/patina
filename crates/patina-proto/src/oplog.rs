//! The operation log: fixed-size records in descriptor
//! 3002 (`oplog.meta`), variable data (names, written bytes) in 3003 (`oplog.data`).
//! Appended by the runtime after each successful mutating call on `/work`, while it holds
//! the turn; the supervisor writes the base records (the initial tree) before the first
//! guest starts. Inode numbers are the tmpfs numbers of the incarnation that wrote them.
//!
//! Fields of `OpRec::a` per kind (data = the record's bytes in `oplog.data`):
//!
//! | Kind | `ino` | `a` | data |
//! |---|---|---|---|
//! | `Root` | root inode | [mode, uid, gid] | |
//! | `Create` | new inode | [parent, mode, S_IFMT kind, base] | name |
//! | `Mkdir` | new inode | [parent, mode, 0, base] | name |
//! | `Symlink` | new inode | [parent, name length, 0, base] | name ++ target |
//! | `Link` | inode | [parent, 0, 0, base] | name |
//! | `Unlink`, `Rmdir` | inode | [parent, links left] | name |
//! | `Rename` | moved inode | [old parent, new parent, replaced inode or 0, flags, old name length] | old name ++ new name |
//! | `Write` | inode | [offset, length, base, `WRITE_SPARSE`] | bytes, or with `WRITE_SPARSE` (base records only) extents: u64 offset, u64 length, bytes; the rest of `[offset, offset + length)` is zeros |
//! | `Truncate` | inode | [size] | |
//! | `Fallocate` | inode | [mode, offset, length] | |
//! | `SetAttr` | inode | [mode, uid, gid, 1 if mode/owner known] | |
//! | `XattrSet` | inode | [name length, base] | name ++ value |
//! | `XattrRemove` | inode | [] | name |
//! | `MmapShared` | inode | [file offset, length] | |
//! | `MmapDirty` | inode | [offset, length] | bytes |
//! | `Fsync` | inode | [`FSYNC_*` flags] | |
//! | `FsyncDir` | inode | [] | |
//! | `FsyncFail` | inode, or 0 for `sync` | [] | |
//! | `Sync` | 0 | [] | |
//! | `Close` | inode | [] | |
//! | `Crash` | 0 | [`CRASH_*` kind] | |

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpKind {
    Root = 1,
    Create = 2,
    Mkdir = 3,
    Symlink = 4,
    Link = 5,
    Unlink = 6,
    Rmdir = 7,
    Rename = 8,
    Write = 9,
    Truncate = 10,
    Fallocate = 11,
    SetAttr = 12,
    XattrSet = 13,
    XattrRemove = 14,
    MmapShared = 15,
    MmapDirty = 16,
    Fsync = 17,
    FsyncDir = 18,
    FsyncFail = 19,
    Sync = 20,
    Close = 21,
    Crash = 22,
}

impl OpKind {
    pub const ALL: [OpKind; 22] = [
        OpKind::Root,
        OpKind::Create,
        OpKind::Mkdir,
        OpKind::Symlink,
        OpKind::Link,
        OpKind::Unlink,
        OpKind::Rmdir,
        OpKind::Rename,
        OpKind::Write,
        OpKind::Truncate,
        OpKind::Fallocate,
        OpKind::SetAttr,
        OpKind::XattrSet,
        OpKind::XattrRemove,
        OpKind::MmapShared,
        OpKind::MmapDirty,
        OpKind::Fsync,
        OpKind::FsyncDir,
        OpKind::FsyncFail,
        OpKind::Sync,
        OpKind::Close,
        OpKind::Crash,
    ];
    pub fn from_u32(v: u32) -> Option<OpKind> {
        OpKind::ALL.iter().copied().find(|k| *k as u32 == v)
    }
    pub fn name(self) -> &'static str {
        match self {
            OpKind::Root => "Root",
            OpKind::Create => "Create",
            OpKind::Mkdir => "Mkdir",
            OpKind::Symlink => "Symlink",
            OpKind::Link => "Link",
            OpKind::Unlink => "Unlink",
            OpKind::Rmdir => "Rmdir",
            OpKind::Rename => "Rename",
            OpKind::Write => "Write",
            OpKind::Truncate => "Truncate",
            OpKind::Fallocate => "Fallocate",
            OpKind::SetAttr => "SetAttr",
            OpKind::XattrSet => "XattrSet",
            OpKind::XattrRemove => "XattrRemove",
            OpKind::MmapShared => "MmapShared",
            OpKind::MmapDirty => "MmapDirty",
            OpKind::Fsync => "Fsync",
            OpKind::FsyncDir => "FsyncDir",
            OpKind::FsyncFail => "FsyncFail",
            OpKind::Sync => "Sync",
            OpKind::Close => "Close",
            OpKind::Crash => "Crash",
        }
    }
}

/// `Write` `a[3]`: the data is a list of extents (the supervisor's base records, so that a
/// sparse file such as a 64 MiB preallocated journal costs its written bytes only).
pub const WRITE_SPARSE: u64 = 1;

/// `Fsync` flags.
pub const FSYNC_DATA_ONLY: u64 = 1;
/// Writeback without a journal commit (`sync_file_range`, an `fsync` that reported an
/// earlier writeback error).
pub const FSYNC_NO_COMMIT: u64 = 2;
/// `msync(MS_SYNC)`.
pub const FSYNC_MSYNC: u64 = 4;

/// `OpRec::kind` of a run with nodes: the low 16 bits are the `OpKind`, the next 8 the node
/// whose work tree the record is about (0: the driver's, so a run without nodes has plain
/// kinds). The launcher splits such a log into one log per node (`launcher::disks`), whose
/// kinds are plain again; nothing else reads a tagged log.
pub const KIND_MASK: u32 = 0xffff;
pub const KIND_NODE_SHIFT: u32 = 16;

pub fn tag_kind(kind: u32, node: usize) -> u32 {
    kind | ((node as u32 & 0xff) << KIND_NODE_SHIFT)
}

/// The raw kind of a record of a tagged log holding its node's live work tree, as a tree
/// archive (the supervisor's, at the end of the run): the launcher makes it that node's
/// `live.tree`. Not an `OpKind`.
pub const KIND_LIVE_TREE: u32 = KIND_MASK;

/// The node of a tagged kind (`tag_kind`).
pub fn kind_node(kind: u32) -> usize {
    ((kind >> KIND_NODE_SHIFT) & 0xff) as usize
}

/// The key of a node's inode in the tables shared by every node (`Shadows`, `Dur::errgen`):
/// its inode number with the node in the top byte (node 0's keys are its inode numbers).
/// Work inode numbers are tmpfs's, far below 2^56.
pub fn node_key(ino: u64, node: usize) -> u64 {
    ino ^ ((node as u64) << 56)
}

/// One operation record.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OpRec {
    pub seq: u64,
    pub vclock_ns: u64,
    pub kind: u32,
    /// Writer's pid (0 for base records).
    pub pid: u32,
    pub ino: u64,
    pub a: [u64; 6],
    /// Offset and length of this record's bytes in `oplog.data`.
    pub data_off: u64,
    pub data_len: u64,
}

pub const OPREC_SIZE: usize = core::mem::size_of::<OpRec>();
const _: () = assert!(OPREC_SIZE == 96);

impl OpRec {
    pub fn as_bytes(&self) -> &[u8; OPREC_SIZE] {
        // SAFETY: repr(C), all fields integers, size asserted (no padding).
        unsafe { &*(self as *const OpRec as *const [u8; OPREC_SIZE]) }
    }
    pub fn from_bytes(b: &[u8]) -> OpRec {
        assert!(b.len() >= OPREC_SIZE);
        // SAFETY: any bit pattern is a valid OpRec.
        unsafe { core::ptr::read_unaligned(b.as_ptr() as *const OpRec) }
    }
}

/// Shared mappings of `/work` files a process tracks (`MAP_SHARED`, opened for writing).
pub const MAX_SHARED_MAPS: usize = 128;

/// One tracked shared mapping, in the runtime's memory: the mapped range and the file.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SharedMap {
    pub addr: u64,
    pub len: u64,
    pub ino: u64,
    /// File offset of `addr`.
    pub off: u64,
    /// The runtime's hidden duplicate of the mapped file's descriptor.
    pub fd: i64,
}

/// A process's tracked shared mappings. The runtime keeps one at the address it publishes in
/// `Ctl::maps_table` (the same in every process); the supervisor reads a process's table with
/// `process_vm_readv` when the process ends without its runtime (a `SIGKILL`, teardown, a
/// crash, a `sync`) and logs what its mappings hold that the log does not (`sup::maps`).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SharedMaps {
    pub m: [SharedMap; MAX_SHARED_MAPS],
    pub n: usize,
}

pub const SHARED_MAPS_SIZE: usize = core::mem::size_of::<SharedMaps>();

/// Shared durability state after the virtual-time region: the write-back error sequences
/// (ARCHITECTURE.md, "The fsync-error model") and the shadow store's table.
///
/// Each inode has an error sequence, as Linux keeps one per file mapping (`errseq_t`): its
/// value is the failures injected on the inode plus those of its whole disk (`wide`) since the
/// inode was made, and it is *seen* when its current value was reported to some open file description. A description
/// samples the sequence when it is opened: the current value if seen, else 0, so an error
/// nobody has seen is reported to a later opener too. A call that reports compares the
/// description's sample with the value, returns the error when they differ, and advances the
/// sample and marks the value seen. Each node's disk has one such sequence for `syncfs` (`sb`:
/// every failure on the node). Descriptions are named by keys the runtime gives at open
/// (`node << 56 | n`, from `next_desc`); a description that reported keeps its samples in
/// `descs`, which every descriptor of it (a duplicate, a fork's copy, a mapping) reads.
pub const ERRGEN_CAP: usize = 4096;
/// Descriptions that reported an error at once (`Dur::descs`).
pub const DESC_CAP: usize = 4096;

#[repr(C)]
pub struct Dur {
    /// Open addressing by inode key (`node_key`): `[key, failures, seen, base]`, where `seen`
    /// is the value of the inode's sequence last reported and `base` the node's `wide` when the
    /// inode was made; key 0 is empty.
    pub errgen: [[u64; 4]; ERRGEN_CAP],
    /// Failures of a whole disk (an injected `syncfs` failure), per node: they count in every
    /// inode's sequence of that node.
    pub wide: [u64; crate::node::MAX_NODES],
    /// The disk's sequence per node, `[value, seen]`: every failure on the node's disk.
    pub sb: [[u64; 2]; crate::node::MAX_NODES],
    /// Description key → `[key, file sample, disk sample]`, one entry per slot (direct-mapped:
    /// a description whose slot another takes falls back to its descriptors' own samples, and
    /// may report an error once more).
    pub descs: [[u64; 3]; DESC_CAP],
    /// The last description key given (`new_desc`).
    pub next_desc: u64,
    pub shadows: Shadows,
}

/// Work files with a shadow at once (`Shadows`): one store each, at descriptor
/// `layout::FD_SHADOWS + k`.
pub const SHADOW_SLOTS: usize = 64;

/// The shadow store's table. Slot `k`'s store is a memfd the supervisor makes at each
/// incarnation's start, inherited by every guest at the hidden descriptor
/// `layout::FD_SHADOWS + k`; it holds what the operation log holds of the work inode `ino[k]`,
/// at the file's own offsets (sparse: a hole, or a read past its end, is zeros and holds no
/// memory). One memfd per slot, not windows of one: `RLIMIT_FSIZE` bounds the offsets a write
/// may reach, and the work file itself is bounded by it, so a store at the file's offsets
/// always fits.
///
/// Invariant: for every work inode with a slot, its store holds the result of replaying the
/// incarnation's operation log for that inode. Every content record appended for a slotted
/// inode, by the runtime or the supervisor, updates the store from the record's own bytes
/// (`effect`); a slot is made at the first tracked mapping of an inode no slot names (no
/// mapping of it exists, so the file holds what the log holds) and filled from the file;
/// it is freed when no process maps the inode (the supervisor's reclaim, from each live
/// process's `/proc/PID/maps`). So a mapping's page that differs from the store differs from
/// the log, whichever process changed it and however (`MmapDirty`).
///
/// Slot numbers reach neither the program nor a log: which slot a file gets changes no record.
#[repr(C)]
pub struct Shadows {
    /// The inode of each slot (0: free).
    pub ino: [u64; SHADOW_SLOTS],
    /// Bytes each slot's store holds (its allocated blocks), as last seen.
    pub bytes: [u64; SHADOW_SLOTS],
    /// Slots in use.
    pub used: u64,
    /// Set by a runtime that dropped a tracked mapping or started an image while slots are in
    /// use: the supervisor frees the slots of inodes no process maps before the next request
    /// it serves.
    pub reclaim: u64,
    /// The most bytes the stores held at once, for `result.json`.
    pub peak: u64,
}

impl Shadows {
    pub fn slot_of(&self, ino: u64) -> Option<usize> {
        if self.used == 0 || ino == 0 {
            return None;
        }
        self.ino.iter().position(|&i| i == ino)
    }
    pub fn free_slot(&self) -> Option<usize> {
        self.ino.iter().position(|&i| i == 0)
    }
    /// Slot `k`'s store now holds `n` bytes.
    pub fn held(&mut self, k: usize, n: u64) {
        self.bytes[k] = n;
        self.peak = self.peak.max(self.bytes.iter().sum());
    }
}

/// What a record does to the contents of its inode, and so to the inode's window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    /// Nothing.
    None,
    /// `[off, off + len)` holds the record's bytes (`Write`, `MmapDirty`).
    Data { off: u64, len: u64 },
    /// `[off, off + len)` reads as zeros (`Truncate` from the new size on; a punched or
    /// zeroed range).
    Zero { off: u64, len: u64 },
    /// A new inode with this number (`Create`, `Mkdir`, `Symlink`): any earlier inode with the
    /// number is dead, and its slot goes.
    New,
}

pub const FALLOC_PUNCH_HOLE: u64 = 2;
pub const FALLOC_ZERO_RANGE: u64 = 0x10;

/// The record's effect on its inode's contents, as the materialiser applies it
/// (`durability::materialise`). A sparse `Write` is a base record, written before any guest
/// runs and so before any slot exists.
pub fn effect(kind: OpKind, a: &[u64; 6]) -> Effect {
    match kind {
        OpKind::Write if a[3] & WRITE_SPARSE != 0 => Effect::None,
        OpKind::Write | OpKind::MmapDirty => Effect::Data {
            off: a[0],
            len: a[1],
        },
        OpKind::Truncate => Effect::Zero {
            off: a[0],
            len: u64::MAX - a[0],
        },
        OpKind::Fallocate if a[0] & (FALLOC_PUNCH_HOLE | FALLOC_ZERO_RANGE) != 0 => Effect::Zero {
            off: a[1],
            len: a[2],
        },
        OpKind::Create | OpKind::Mkdir | OpKind::Symlink => Effect::New,
        _ => Effect::None,
    }
}

pub const DUR_OFFSET: usize = (crate::vfs::VFS_OFFSET + crate::vfs::VFS_SIZE + 0xFFF) & !0xFFF;
pub const DUR_SIZE: usize = core::mem::size_of::<Dur>();

impl Dur {
    /// # Safety
    /// `ctl_base` must point at a full control region of `CTL_SIZE` bytes.
    pub unsafe fn at<'a>(ctl_base: *mut u8) -> &'a mut Dur {
        &mut *(ctl_base.add(DUR_OFFSET) as *mut Dur)
    }
    fn slot(&self, key: u64) -> Option<usize> {
        let mut i = (crate::draw::mix64(key) as usize) % ERRGEN_CAP;
        for _ in 0..ERRGEN_CAP {
            if self.errgen[i][0] == key || self.errgen[i][0] == 0 {
                return Some(i);
            }
            i = (i + 1) % ERRGEN_CAP;
        }
        None
    }
    fn entry(&self, key: u64) -> [u64; 4] {
        match self.slot(key) {
            Some(i) if self.errgen[i][0] == key => self.errgen[i],
            _ => [key, 0, 0, 0],
        }
    }
    fn node_of(key: u64) -> usize {
        ((key >> 56) as usize).min(crate::node::MAX_NODES - 1)
    }
    /// The current value of the error sequence of inode `key` (`node_key`).
    pub fn seq(&self, key: u64) -> u64 {
        let [_, n, _, base] = self.entry(key);
        n + self.wide[Self::node_of(key)] - base
    }
    /// What a description opened now on inode `key` samples: the value if it was seen, else 0.
    pub fn sample(&self, key: u64) -> u64 {
        let [_, _, seen, _] = self.entry(key);
        let v = self.seq(key);
        if seen == v {
            v
        } else {
            0
        }
    }
    /// A write-back failure of inode `key`; None when the table is full.
    pub fn fail(&mut self, key: u64) -> Option<()> {
        let i = self.slot(key)?;
        self.errgen[i][0] = key;
        self.errgen[i][1] += 1;
        self.sb[Self::node_of(key)][0] += 1;
        Some(())
    }
    /// A write-back failure of node `node`'s whole disk (`syncfs`).
    pub fn fail_wide(&mut self, node: usize) {
        let n = node.min(crate::node::MAX_NODES - 1);
        self.wide[n] += 1;
        self.sb[n][0] += 1;
    }
    /// Inode `key` was made (a file, directory or symlink, maybe at a number a deleted inode
    /// had): it starts with no error. None when the table is full.
    pub fn new_inode(&mut self, key: u64) -> Option<()> {
        let w = self.wide[Self::node_of(key)];
        if w == 0 && self.entry(key) == [key, 0, 0, 0] {
            return Some(()); // nothing to forget, nothing to start from
        }
        let i = self.slot(key)?;
        self.errgen[i] = [key, 0, 0, w];
        Some(())
    }
    /// The value of inode `key`'s sequence was reported: it is seen. None when the table is full.
    pub fn mark_seen(&mut self, key: u64) -> Option<()> {
        let v = self.seq(key);
        if self.entry(key)[2] == v {
            return Some(());
        }
        let i = self.slot(key)?;
        self.errgen[i][0] = key;
        self.errgen[i][2] = v;
        Some(())
    }
    /// The disk sequence of `node`: its value, and what an opener samples.
    pub fn sb_seq(&self, node: usize) -> u64 {
        self.sb[node.min(crate::node::MAX_NODES - 1)][0]
    }
    pub fn sb_sample(&self, node: usize) -> u64 {
        let [v, seen] = self.sb[node.min(crate::node::MAX_NODES - 1)];
        if seen == v {
            v
        } else {
            0
        }
    }
    pub fn sb_mark_seen(&mut self, node: usize) {
        let n = node.min(crate::node::MAX_NODES - 1);
        self.sb[n][1] = self.sb[n][0];
    }
    /// A new description key for a descriptor opened on node `node`.
    pub fn new_desc(&mut self, node: usize) -> u64 {
        self.next_desc += 1;
        (self.next_desc & ((1 << 56) - 1)) | ((node.min(crate::node::MAX_NODES - 1) as u64) << 56)
    }
    fn desc_slot(key: u64) -> usize {
        (crate::draw::mix64(key) as usize) % DESC_CAP
    }
    /// The samples description `key` advanced to when it last reported (`[file, disk]`;
    /// zeros if it never did, or its slot was taken since).
    pub fn desc(&self, key: u64) -> [u64; 2] {
        let e = self.descs[Self::desc_slot(key)];
        if key != 0 && e[0] == key {
            [e[1], e[2]]
        } else {
            [0, 0]
        }
    }
    /// Description `key` reported: its samples are now `s`.
    pub fn set_desc(&mut self, key: u64, s: [u64; 2]) {
        self.descs[Self::desc_slot(key)] = [key, s[0], s[1]];
    }
    /// Node `node`'s disk is gone (a machine crash, its processes dead): its inodes' sequences,
    /// its disk sequence and its descriptions' samples read 0 again, so its next disk starts
    /// with none. The keys stay, holding their place in the probe chains.
    pub fn forget_node(&mut self, node: usize) {
        if node == 0 || node >= crate::node::MAX_NODES {
            return;
        }
        self.wide[node] = 0;
        self.sb[node] = [0, 0];
        for e in self.errgen.iter_mut() {
            if e[0] != 0 && e[0] >> 56 == node as u64 {
                e[1] = 0;
                e[2] = 0;
                e[3] = 0;
            }
        }
        for e in self.descs.iter_mut() {
            if e[0] != 0 && e[0] >> 56 == node as u64 {
                e[1] = 0;
                e[2] = 0;
            }
        }
    }
}
