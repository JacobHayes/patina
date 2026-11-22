//! Fault injection and crash configuration, shared by the launcher (which
//! writes it), the runtime (which decides faults and crash points before each call) and the
//! supervisor. Lives in the control region header (`Ctl::faults`).
//!
//! Every decision is a stateless draw keyed by the trap's `seq` and a sub-key, so turning a
//! fault kind on never shifts another stream's draws.

use crate::nr;
use core::sync::atomic::{AtomicU64, Ordering::Relaxed};

/// Classes of faultable calls. The order is the index of the per-class counter.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FClass {
    Open = 0,
    Read = 1,
    Write = 2,
    Sync = 3,
    Rename = 4,
    Unlink = 5,
    Mkdir = 6,
    Truncate = 7,
    Link = 8,
    Fallocate = 9,
    Close = 10,
    Mem = 11,
}

pub const NCLASS: usize = 12;

impl FClass {
    pub const ALL: [FClass; NCLASS] = [
        FClass::Open,
        FClass::Read,
        FClass::Write,
        FClass::Sync,
        FClass::Rename,
        FClass::Unlink,
        FClass::Mkdir,
        FClass::Truncate,
        FClass::Link,
        FClass::Fallocate,
        FClass::Close,
        FClass::Mem,
    ];
    pub fn name(self) -> &'static str {
        match self {
            FClass::Open => "open",
            FClass::Read => "read",
            FClass::Write => "write",
            FClass::Sync => "sync",
            FClass::Rename => "rename",
            FClass::Unlink => "unlink",
            FClass::Mkdir => "mkdir",
            FClass::Truncate => "truncate",
            FClass::Link => "link",
            FClass::Fallocate => "fallocate",
            FClass::Close => "close",
            FClass::Mem => "mem",
        }
    }
    pub fn from_name(s: &str) -> Option<FClass> {
        FClass::ALL.iter().copied().find(|c| c.name() == s)
    }
    pub fn from_u8(v: u8) -> Option<FClass> {
        FClass::ALL.get(v as usize).copied()
    }
}

/// What a faultable call acts on, as the runtime classifies it before deciding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Obj {
    /// A regular file under `/work`.
    File,
    /// A directory under `/work`, or a path under `/work` named by a call (open, rename,
    /// unlink, mkdir, link, truncate by name).
    Path,
    /// A pipe or FIFO.
    Pipe,
    /// A unix socket. (TCP sockets are the wire's: the runtime does not fault them.)
    Unix,
    /// Memory: mappings, the break, thread and process creation.
    Mem,
}

impl Obj {
    pub fn name(self) -> &'static str {
        match self {
            Obj::File => "file",
            Obj::Path => "path",
            Obj::Pipe => "pipe",
            Obj::Unix => "unix",
            Obj::Mem => "memory",
        }
    }
}

const EIO: i32 = 5;
const ENOMEM: i32 = 12;
const ENFILE: i32 = 23;
const EMFILE: i32 = 24;
const ENOSPC: i32 = 28;
const EDQUOT: i32 = 122;

/// The errnos an injected error may take: only what Linux can return for this call on this
/// object. The injector draws from this table and from nothing else; an empty slice means
/// the call is never failed with an error (pipes and unix sockets get short transfers and
/// delays only; `close` fails only on a regular file, after closing it). Network faults draw no errno
/// here: TCP's act on the wire (a reset answers `ECONNRESET`, a refused connect
/// `ECONNREFUSED`), and a datagram fault loses, duplicates or holds the datagram, so a UDP
/// call never fails from a fault (`ECONNREFUSED` on a connected UDP socket is a port nobody
/// holds, as Linux reports it).
pub fn errnos(obj: Obj, c: FClass, creating: bool) -> &'static [i32] {
    match (obj, c) {
        (Obj::Mem, FClass::Mem) => &[ENOMEM],
        (Obj::Mem, _) | (_, FClass::Mem) => &[],
        (Obj::Pipe | Obj::Unix, _) => &[],
        (_, FClass::Open) if creating => &[EIO, ENOSPC, EMFILE, ENFILE],
        (_, FClass::Open) => &[EIO, EMFILE, ENFILE],
        (Obj::File, FClass::Read) => &[EIO],
        (Obj::File, FClass::Write) => &[EIO, ENOSPC, EDQUOT],
        (Obj::File, FClass::Close) => &[EIO],
        (Obj::File | Obj::Path, FClass::Sync) => &[EIO],
        // read and write on a directory answer EISDIR before any I/O; close has no flush.
        (Obj::Path, FClass::Read | FClass::Write | FClass::Close) => &[],
        (_, FClass::Rename | FClass::Mkdir | FClass::Link | FClass::Fallocate) => &[EIO, ENOSPC],
        (_, FClass::Unlink | FClass::Truncate) => &[EIO],
    }
}

/// May the count of this read or write be shortened? Regular files, pipes and unix sockets.
pub fn short_ok(obj: Obj) -> bool {
    matches!(obj, Obj::File | Obj::Pipe | Obj::Unix)
}

/// The class of a syscall number, if it is faultable at all. Which target (path or
/// descriptor) is eligible is decided by the runtime (`/work`, pipes, sockets).
pub fn class_of(nr: u64) -> Option<FClass> {
    Some(match nr {
        nr::OPEN | nr::CREAT | nr::OPENAT | nr::OPENAT2 => FClass::Open,
        nr::READ | nr::PREAD64 | nr::READV | nr::PREADV | nr::PREADV2 => FClass::Read,
        nr::WRITE
        | nr::PWRITE64
        | nr::WRITEV
        | nr::PWRITEV
        | nr::PWRITEV2
        | nr::COPY_FILE_RANGE
        | nr::SENDFILE => FClass::Write,
        nr::FSYNC | nr::FDATASYNC | nr::SYNC_FILE_RANGE | nr::MSYNC | nr::SYNC | nr::SYNCFS => {
            FClass::Sync
        }
        nr::RENAME | nr::RENAMEAT | nr::RENAMEAT2 => FClass::Rename,
        nr::UNLINK | nr::UNLINKAT | nr::RMDIR => FClass::Unlink,
        nr::MKDIR | nr::MKDIRAT | nr::MKNOD | nr::MKNODAT => FClass::Mkdir,
        nr::TRUNCATE | nr::FTRUNCATE => FClass::Truncate,
        nr::LINK | nr::LINKAT | nr::SYMLINK | nr::SYMLINKAT => FClass::Link,
        nr::FALLOCATE => FClass::Fallocate,
        nr::CLOSE => FClass::Close,
        nr::MMAP | nr::BRK | nr::MREMAP | nr::CLONE | nr::FORK | nr::VFORK => FClass::Mem,
        _ => return None,
    })
}

/// Crash kinds (`--crash`).
pub const CRASH_NONE: u64 = 0;
pub const CRASH_MACHINE: u64 = 1;
pub const CRASH_PROCESS: u64 = 2;

/// Sub-keys of `draw(Stream::FaultFs, seq * 16 + sub)`.
pub const SUB_DELAY_FIRE: u64 = 1;
pub const SUB_DELAY_LEN: u64 = 2;
pub const SUB_ERR_FIRE: u64 = 3;
pub const SUB_ERR_PICK: u64 = 4;
pub const SUB_SHORT_FIRE: u64 = 5;
pub const SUB_SHORT_LEN: u64 = 6;
pub const SUB_FSYNC_FIRE: u64 = 7;
pub const SUB_MEM_FIRE: u64 = 8;
pub const SUB_SWAP_FIRE: u64 = 9;
/// The swap's mutation, symlink target and whether it is put back (`swap_how`).
pub const SUB_SWAP_HOW: u64 = 10;
/// The component swapped, and the sibling a rename or a symlink takes.
pub const SUB_SWAP_PICK: u64 = 11;
pub const SUB_SWAP_SIBLING: u64 = 12;
/// `fs-error` at the sync an `O_SYNC`/`O_DSYNC` write makes (the write drew `SUB_ERR_FIRE`).
pub const SUB_WSYNC_ERR_FIRE: u64 = 13;

/// Injected-fault kinds (`Rec::args[0]` of an `Injected` boundary record).
pub const INJ_ERROR: u64 = 1;
pub const INJ_SHORT: u64 = 2;
pub const INJ_DELAY: u64 = 3;
pub const INJ_FSYNC_EIO: u64 = 5;
/// The class that failed a sync (`args[3]` of an `INJ_FSYNC_EIO` record).
pub const SYNC_BY_FSYNC_ERROR: u64 = 0;
pub const SYNC_BY_FS_ERROR: u64 = 1;
/// An earlier failed writeback reported again to a descriptor that had not seen it.
pub const INJ_FSYNC_REPORT: u64 = 6;
/// `mem-limit-mb`: a growth of anonymous memory past the limit (value: the bytes asked for).
pub const INJ_MEM_LIMIT: u64 = 7;
/// `path-swap`: a path the process checked was changed before it used it. args: [kind,
/// `swap_how` code, 0, the guest's first argument, the checking call's number, its seq];
/// two `Name` records follow: the swapped path, then the target (`swap_how`).
pub const INJ_PATH_SWAP: u64 = 8;

/// The runtime's fault classes whose eligible calls are counted (`FaultCtl::eligible`): a
/// call is eligible for a class when that class could act on it, whatever its rate.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    FsError = 0,
    FsShort = 1,
    FsDelay = 2,
    FsyncError = 3,
    MemError = 4,
    MemLimit = 5,
    PathSwap = 6,
}

pub const NKIND: usize = 7;
/// The plan's class name of each `Kind` (`result.json` `faults.counts`).
pub const KIND_NAMES: [&str; NKIND] = [
    "fs-error",
    "fs-short",
    "fs-delay",
    "fsync-error",
    "mem-error",
    "mem-limit",
    "path-swap",
];

/// Written by the launcher, read-only afterwards (except the counters below it).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct FaultCfg {
    /// 1 when any fault key is set (the runtime skips all fault work otherwise).
    pub any: u64,
    pub fs_error_permille: u64,
    /// `fs-error-at=CLASS:N`: class index + 1 (0: off) and N.
    pub fs_error_at_class: u64,
    pub fs_error_at_n: u64,
    /// `fs-short-permille`.
    pub short_permille: u64,
    pub fsync_error_permille: u64,
    /// 0: off.
    pub fsync_error_at: u64,
    /// `fs-delay-permille`; the longest delay (10 ms).
    pub delay_permille: u64,
    pub delay_max_ns: u64,
    pub mem_error_permille: u64,
    pub mem_error_at: u64,
    /// No fault before this sequence number: a run that declares a setup (`[run] setup`) starts
    /// with the maximum, lowered where the setup ends (the setup command's exit 0, or the
    /// program's `setup-complete` mark).
    pub fault_after_seq: u64,
    /// No fault from this sequence number on: where the faults end (a `faults-done` mark, or
    /// the main command's end in a run with `--finally`; 0: not yet).
    pub fault_until_seq: u64,
    /// 1: the run declares that the program marks `setup-complete` (`[run] setup = "mark"`);
    /// 0: a `setup-complete` mark ends the run (`ctl::LIFE_SETUP_UNDECLARED`).
    pub setup_mark: u64,
    /// `CRASH_*`.
    pub crash_kind: u64,
    /// Per-mille rate at each crash point (when `crash_at` is 0).
    pub crash_permille: u64,
    /// `machine-at:N` / `process-at:N`: crash at the N-th crash point of the first boot
    /// (0: off).
    pub crash_at: u64,
    /// 1 when this boot may crash (not the last permitted one; `-at` only until it fired).
    pub crash_enabled: u64,
    /// Boot number (also `PATINA_BOOT`).
    pub boot: u64,
    /// `mem-limit-mb` in bytes (0: off): anonymous memory growth past it answers `ENOMEM`.
    pub mem_limit_bytes: u64,
    /// `path-swap-permille` (0: off).
    pub path_swap_permille: u64,
}

impl FaultCfg {
    /// Faults may act at sequence number `seq`: after setup and before `faults-done`.
    pub fn in_window(&self, seq: u64) -> bool {
        seq >= self.fault_after_seq && (self.fault_until_seq == 0 || seq < self.fault_until_seq)
    }
    pub fn faults_active(&self) -> bool {
        self.any != 0
    }
    pub fn path_swap(&self) -> bool {
        self.path_swap_permille != 0
    }
}

/// Fault state in the control region: configuration, the per-class call counters, counts.
#[repr(C)]
pub struct FaultCtl {
    pub cfg: FaultCfg,
    /// Eligible calls seen per class (`fs-error-at`, `mem-error-at` count these).
    pub counters: [AtomicU64; NCLASS],
    /// Sync-class calls on eligible targets (`fsync-error-at`).
    pub sync_calls: AtomicU64,
    pub injected: AtomicU64,
    /// Crash points passed in this boot (whether or not one fired); after a crash, the
    /// ordinal of the point that fired.
    pub crash_points: AtomicU64,
    /// Eligible calls per `Kind`, counted while faults are active.
    pub eligible: [AtomicU64; NKIND],
}

impl FaultCtl {
    /// Count one eligible call for `k`.
    pub fn eligible(&self, k: Kind) {
        let e = &self.eligible[k as usize];
        e.store(e.load(Relaxed) + 1, Relaxed);
    }
    /// Increment and return the new count of `c`.
    pub fn count(&self, c: FClass) -> u64 {
        let v = self.counters[c as usize].load(Relaxed) + 1;
        self.counters[c as usize].store(v, Relaxed);
        v
    }
}
