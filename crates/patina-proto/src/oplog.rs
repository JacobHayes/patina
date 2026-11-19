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

/// One tracked shared mapping, in the runtime's memory: the mapped range, the file and the
/// shadow (the runtime's copy of what the log holds for the range).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SharedMap {
    pub addr: u64,
    pub len: u64,
    pub ino: u64,
    /// File offset of `addr`.
    pub off: u64,
    pub shadow: u64,
    pub shadow_len: u64,
    /// The runtime's hidden duplicate of the mapped file's descriptor.
    pub fd: i64,
}

/// A process's tracked shared mappings. The runtime keeps one at the address it publishes in
/// `Ctl::maps_table` (the same in every process); the supervisor reads a process's table with
/// `process_vm_readv` when the process ends without its runtime (a `SIGKILL`, teardown, a
/// crash) and logs what its mappings hold that the log does not (`sup::maps`).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SharedMaps {
    pub m: [SharedMap; MAX_SHARED_MAPS],
    pub n: usize,
}

pub const SHARED_MAPS_SIZE: usize = core::mem::size_of::<SharedMaps>();

/// Shared durability state after the virtual-time region: the writeback error generation
/// of each inode (failed fsync is reported once per descriptor generation).
pub const ERRGEN_CAP: usize = 4096;

#[repr(C)]
pub struct Dur {
    /// Open addressing by inode number: `(ino, generation)`; ino 0 is empty.
    pub errgen: [[u64; 2]; ERRGEN_CAP],
    /// Generation of the "any inode" error reported by `sync`/`syncfs`.
    pub sync_gen: u64,
}

pub const DUR_OFFSET: usize = (crate::vfs::VFS_OFFSET + crate::vfs::VFS_SIZE + 0xFFF) & !0xFFF;
pub const DUR_SIZE: usize = core::mem::size_of::<Dur>();

impl Dur {
    /// # Safety
    /// `ctl_base` must point at a full control region of `CTL_SIZE` bytes.
    pub unsafe fn at<'a>(ctl_base: *mut u8) -> &'a mut Dur {
        &mut *(ctl_base.add(DUR_OFFSET) as *mut Dur)
    }
    fn slot(&self, ino: u64) -> Option<usize> {
        let mut i = (crate::draw::mix64(ino) as usize) % ERRGEN_CAP;
        for _ in 0..ERRGEN_CAP {
            if self.errgen[i][0] == ino || self.errgen[i][0] == 0 {
                return Some(i);
            }
            i = (i + 1) % ERRGEN_CAP;
        }
        None
    }
    pub fn gen(&self, ino: u64) -> u64 {
        match self.slot(ino) {
            Some(i) if self.errgen[i][0] == ino => self.errgen[i][1],
            _ => 0,
        }
    }
    /// Bump the generation of `ino`; returns the new one (None when the table is full).
    pub fn bump(&mut self, ino: u64) -> Option<u64> {
        let i = self.slot(ino)?;
        self.errgen[i][0] = ino;
        self.errgen[i][1] += 1;
        Some(self.errgen[i][1])
    }
}
