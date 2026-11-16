//! Fault injection and crash configuration, shared by the launcher (which
//! writes it), the runtime (which decides faults and crash points before each call) and the
//! supervisor. Lives in the control region header (`Ctl::faults`).
//!
//! Every decision is a stateless draw keyed by the trap's `seq` and a sub-key, so turning a
//! fault kind on never shifts another stream's draws.

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
    /// Errnos an injected error of this class is drawn from. `EINTR` is
    /// appended by the runtime only when `fs-eintr=1`.
    pub fn errnos(self) -> &'static [i32] {
        const EIO: i32 = 5;
        match self {
            FClass::Open => &[EIO, 28, 24, 12], // EIO ENOSPC EMFILE ENOMEM
            FClass::Read => &[EIO],
            FClass::Write => &[EIO, 28],
            FClass::Sync => &[EIO],
            FClass::Rename | FClass::Unlink | FClass::Mkdir | FClass::Link => &[EIO, 28],
            FClass::Truncate | FClass::Fallocate => &[EIO, 28],
            FClass::Close => &[EIO],
            FClass::Mem => &[12],
        }
    }
    /// Can `EINTR` be drawn (with `fs-eintr=1`)? Only for calls that can wait in Linux.
    pub fn eintr_ok(self) -> bool {
        matches!(self, FClass::Open | FClass::Read | FClass::Write)
    }
}

/// The class of a syscall number, if it is faultable at all. Which target (path or
/// descriptor) is eligible is decided by the runtime (`/work`, pipes, sockets).
pub fn class_of(nr: u64) -> Option<FClass> {
    Some(match nr {
        2 | 85 | 257 | 437 => FClass::Open,
        0 | 17 | 19 | 295 | 327 => FClass::Read,
        1 | 18 | 20 | 296 | 328 | 326 | 40 => FClass::Write,
        74 | 75 | 277 | 26 | 162 | 306 => FClass::Sync,
        82 | 264 | 316 => FClass::Rename,
        87 | 263 | 84 => FClass::Unlink,
        83 | 258 | 133 | 259 => FClass::Mkdir,
        76 | 77 => FClass::Truncate,
        86 | 265 | 88 | 266 => FClass::Link,
        285 => FClass::Fallocate,
        3 => FClass::Close,
        9 | 12 | 25 | 56 | 57 | 58 => FClass::Mem,
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

/// Injected-fault kinds (`Rec::args[0]` of an `Injected` boundary record).
pub const INJ_ERROR: u64 = 1;
pub const INJ_SHORT: u64 = 2;
pub const INJ_DELAY: u64 = 3;
pub const INJ_ENOSPC: u64 = 4;
pub const INJ_FSYNC_EIO: u64 = 5;
/// An earlier failed writeback reported again to a descriptor that had not seen it.
pub const INJ_FSYNC_REPORT: u64 = 6;

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
    pub fs_eintr: u64,
    pub short_permille: u64,
    pub fsync_error_permille: u64,
    /// 0: off.
    pub fsync_error_at: u64,
    /// 0: off.
    pub enospc_after_bytes: u64,
    pub delay_permille: u64,
    pub delay_max_ns: u64,
    pub mem_error_permille: u64,
    pub mem_error_at: u64,
    pub fault_after_seq: u64,
    /// `CRASH_*`.
    pub crash_kind: u64,
    /// Per-mille rate at each crash point (when `crash_at` is 0).
    pub crash_permille: u64,
    /// `machine-at:SEQ` / `process-at:SEQ`: crash at the first crash point at or after SEQ (0: off).
    pub crash_at: u64,
    /// 1 when this incarnation may crash (not the last permitted one; `-at` only until it fired).
    pub crash_enabled: u64,
    /// Incarnation number (also `PATINA_INCARNATION`).
    pub incarnation: u64,
    /// `faults-in-recovery=0`: no faults other than crashes after the first crash.
    pub faults_off: u64,
    pub reserved: [u64; 4],
}

impl FaultCfg {
    pub fn faults_active(&self) -> bool {
        self.any != 0 && self.faults_off == 0
    }
}

/// Fault state in the control region: configuration, the per-class call counters, bytes
/// written to `/work` (for `enospc-after-bytes`), counts.
#[repr(C)]
pub struct FaultCtl {
    pub cfg: FaultCfg,
    /// Eligible calls seen per class (`fs-error-at`, `mem-error-at` count these).
    pub counters: [AtomicU64; NCLASS],
    /// Sync-class calls on eligible targets (`fsync-error-at`).
    pub sync_calls: AtomicU64,
    pub work_bytes: AtomicU64,
    pub injected: AtomicU64,
    /// Crash points passed (whether or not one fired).
    pub crash_points: AtomicU64,
}

impl FaultCtl {
    /// Increment and return the new count of `c`.
    pub fn count(&self, c: FClass) -> u64 {
        let v = self.counters[c as usize].load(Relaxed) + 1;
        self.counters[c as usize].store(v, Relaxed);
        v
    }
}
