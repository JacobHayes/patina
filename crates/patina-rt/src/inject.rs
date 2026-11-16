//! Fault decisions made before a call, and crash points.
//!
//! `before(call, class)` is called by the dispatcher for every faultable row (by
//! `proto::faults::class_of`) when fault injection is configured. Every draw is
//! `draw(seed, FaultFs, seq * 16 + sub)` keyed by the trap's own `seq`, so a decision never
//! depends on how many other draws were made, and a fault kind that is off draws nothing
//! that another kind could see. An error means the call is not made (except `close`, which
//! closes and then reports `EIO`, as Linux does); a short transfer is made with a smaller
//! count; a delay parks the thread in virtual time and then the call is made.

use crate::path::{self, PathBuf};
use crate::raw::*;
use crate::state::{ctl, proc, thread};
use crate::sys::fs::{fstat_raw, AT_FDCWD};
use crate::trap::Call;
use core::sync::atomic::Ordering::Relaxed;
use proto::ctl::Op;
use proto::faults::*;
use proto::{draw, Stream};

pub enum Decision {
    Proceed,
    /// Return -errno without making the call.
    Error(i64),
    /// Make the call with this count.
    Shorten(u64),
    /// Park this many virtual nanoseconds, then decide again (phase 2).
    #[allow(dead_code)]
    Delay(u64),
    /// Return this value without making the call (`brk` fails by returning the old break).
    Ret(i64),
    /// `enospc-after-bytes`: `None` = no room left (ENOSPC), `Some(n)` = write the n that fit.
    Enospc(Option<u64>),
}

fn d(sub: u64) -> u64 {
    let ts = thread();
    draw(
        ctl().config.seed,
        Stream::FaultFs,
        ts.seq.wrapping_mul(16).wrapping_add(sub),
    )
}

fn permille(p: u64, sub: u64) -> bool {
    p != 0 && d(sub) % 1000 < p
}

const S_IFMT: u64 = 0o170000;
const S_IFIFO: u64 = 0o010000;
const S_IFSOCK: u64 = 0o140000;
const S_IFREG: u64 = 0o100000;

/// A descriptor whose calls may be faulted: a `/work` object, a pipe or a socket.
fn fd_target(fd: u64) -> Option<(bool, u64)> {
    let st = fstat_raw(fd as i32 as i64)?;
    let fmt = st[3] & S_IFMT;
    if path::is_work(st[0]) {
        return Some((true, st[1]));
    }
    (fmt == S_IFIFO || fmt == S_IFSOCK).then_some((false, 0))
}

/// Does `(dirfd, path)` name something under `/work`? Lexical, after normalisation; a
/// relative path is judged by the directory it is relative to.
pub fn path_on_work(dirfd: i64, p: u64) -> bool {
    if p == 0 {
        return false;
    }
    let s = unsafe { crate::loader::cstr(p as *const u8) };
    let mut norm = PathBuf::new();
    if path::absolute(dirfd, s, &mut norm) {
        let b = norm.as_bytes();
        return b == b"/work" || b.starts_with(b"/work/");
    }
    if dirfd == AT_FDCWD {
        let mut buf = [0u8; 256];
        let r = unsafe { sc2(79, buf.as_mut_ptr() as u64, buf.len() as u64) };
        if r <= 0 {
            return false;
        }
        let c = &buf[..(r as usize).saturating_sub(1)];
        return c == b"/work" || c.starts_with(b"/work/");
    }
    fstat_raw(dirfd).is_some_and(|st| path::is_work(st[0]))
}

/// Is this call's target eligible for faults? (The sync class is decided by its handler.)
fn eligible(call: &dyn Call, c: FClass) -> bool {
    let a = |i: usize| call.arg(i);
    let fd = |i: usize| a(i) as i32 as i64;
    match call.nr() {
        // open family
        2 | 85 => path_on_work(AT_FDCWD, a(0)),
        257 | 437 => path_on_work(fd(0), a(1)),
        // read/write family on descriptors; copy_file_range and sendfile by their target
        0 | 17 | 19 | 295 | 327 | 1 | 18 | 20 | 296 | 328 | 77 | 285 | 3 => {
            fd_target(a(0)).is_some()
        }
        326 => fd_target(a(2)).is_some_and(|t| t.0),
        40 => fd_target(a(0)).is_some_and(|t| t.0),
        // names
        82 | 87 | 84 | 83 | 133 | 76 => path_on_work(AT_FDCWD, a(0)),
        86 => path_on_work(AT_FDCWD, a(1)),
        88 => path_on_work(AT_FDCWD, a(1)),
        264 | 316 | 265 => path_on_work(fd(0), a(1)) || path_on_work(fd(2), a(3)),
        263 | 258 | 259 => path_on_work(fd(0), a(1)),
        266 => path_on_work(fd(1), a(2)),
        // memory: anonymous or /work mappings, growth of brk and mremap, thread or process creation
        9 => {
            const MAP_ANON: u64 = 0x20;
            const MAP_FIXED_ANY: u64 = 0x10 | 0x10_0000;
            a(3) & MAP_FIXED_ANY == 0
                && (a(3) & MAP_ANON != 0 || fd_target(a(4)).is_some_and(|t| t.0))
        }
        12 => a(0) > proc().brk_cur,
        25 => a(2) > a(1),
        56..=58 => true,
        _ => {
            let _ = c;
            false
        }
    }
}

/// Write an `Injected` boundary record for the current trap.
pub fn note(nr: u64, kind: u64, class: u64, value: u64, a0: u64) {
    let ts = thread();
    let c = ctl();
    let rec = proto::Rec {
        seq: ts.seq,
        vclock_ns: c.vclock_ns.load(Relaxed),
        slot: ts.slot as u16,
        kind: proto::RecKind::Injected as u8,
        class: 0,
        nr: nr as u32,
        args: [kind, class, value, a0, 0, 0],
        ret: 0,
        out_hash: 0,
        in_hash: 0,
    };
    crate::log::append(&rec);
    let f = &c.faults;
    f.injected.store(f.injected.load(Relaxed) + 1, Relaxed);
    c.stats
        .faults_injected
        .store(c.stats.faults_injected.load(Relaxed) + 1, Relaxed);
}

fn after_start() -> bool {
    thread().seq >= ctl().faults.cfg.fault_after_seq
}

/// Phase 1: the delay, if one is drawn. Phase 2 (`decide`): error or short transfer.
fn delay(c: FClass) -> Option<u64> {
    let cfg = &ctl().faults.cfg;
    if c == FClass::Mem || cfg.delay_permille == 0 || !permille(cfg.delay_permille, SUB_DELAY_FIRE)
    {
        return None;
    }
    Some(d(SUB_DELAY_LEN) % (cfg.delay_max_ns + 1))
}

fn decide(call: &dyn Call, c: FClass) -> Decision {
    let f = &ctl().faults;
    let cfg = &f.cfg;
    let nr = call.nr();
    if c == FClass::Sync {
        return Decision::Proceed; // the sync handler decides (failed-fsync semantics)
    }
    let n = f.count(c);
    if c == FClass::Mem {
        let fire = (cfg.mem_error_at != 0 && cfg.mem_error_at == n)
            || permille(cfg.mem_error_permille, SUB_MEM_FIRE);
        if !fire {
            return Decision::Proceed;
        }
        let errno = match nr {
            56 if call.arg(0) & 0x10000 != 0 => e::EAGAIN, // CLONE_THREAD
            12 => return Decision::Ret(proc().brk_cur as i64),
            _ => e::ENOMEM,
        };
        return Decision::Error(errno);
    }
    let at = cfg.fs_error_at_class != 0
        && cfg.fs_error_at_class == c as u64 + 1
        && cfg.fs_error_at_n == n;
    // `close` reports EIO only for regular files: Linux's close of a directory, pipe
    // or socket has no flush step and cannot fail that way (Rust's std asserts on it for
    // directories, which turned an illegal fault into a guest panic in the fjall sweeps).
    let close_ok = c != FClass::Close || is_reg(call.arg(0));
    if close_ok && (at || permille(cfg.fs_error_permille, SUB_ERR_FIRE)) {
        let base = c.errnos();
        let eintr = cfg.fs_eintr != 0 && c.eintr_ok();
        let k = base.len() as u64 + eintr as u64;
        let i = (d(SUB_ERR_PICK) % k) as usize;
        let errno = if i < base.len() {
            base[i] as i64
        } else {
            e::EINTR
        };
        return Decision::Error(errno);
    }
    if c == FClass::Write
        && cfg.enospc_after_bytes != 0
        && fd_target(write_fd(call)).is_some_and(|t| t.0)
    {
        let used = f.work_bytes.load(Relaxed);
        let left = cfg.enospc_after_bytes.saturating_sub(used);
        if left == 0 {
            return Decision::Enospc(None);
        }
        if matches!(nr, 1 | 18) && call.arg(2) > left {
            return Decision::Enospc(Some(left));
        }
    }
    if matches!(nr, 0 | 17 | 1 | 18)
        && call.arg(2) >= 2
        && permille(cfg.short_permille, SUB_SHORT_FIRE)
    {
        let n = call.arg(2);
        return Decision::Shorten(1 + d(SUB_SHORT_LEN) % (n - 1));
    }
    Decision::Proceed
}

fn write_fd(call: &dyn Call) -> u64 {
    match call.nr() {
        326 => call.arg(2),
        _ => call.arg(0),
    }
}

/// What the dispatcher does with a faultable call. `Some(r)`: return `r` without the call.
/// `Err(errno)` in `post`: make the call, then report this errno if it succeeded (`close`).
pub struct Gate {
    pub ret: Option<i64>,
    pub post: Option<i64>,
}

pub fn before(call: &mut dyn Call, c: FClass) -> Gate {
    let none = Gate {
        ret: None,
        post: None,
    };
    if !ctl().faults.cfg.faults_active() || !after_start() || !eligible(call, c) {
        return none;
    }
    let nr = call.nr();
    if let Some(ns) = delay(c) {
        note(nr, INJ_DELAY, c as u64, ns, call.arg(0));
        let deadline = ctl().vclock_ns.load(Relaxed) + ns;
        crate::sup::call_sup(Op::Sleep, [deadline, 0, 0, 0, 0, 0]);
    }
    match decide(call, c) {
        Decision::Proceed | Decision::Delay(_) => none,
        Decision::Ret(v) => {
            note(nr, INJ_ERROR, c as u64, e::ENOMEM as u64, call.arg(0));
            Gate {
                ret: Some(v),
                post: None,
            }
        }
        Decision::Enospc(None) => {
            note(nr, INJ_ENOSPC, c as u64, 0, call.arg(0));
            Gate {
                ret: Some(-28),
                post: None,
            }
        }
        Decision::Enospc(Some(n)) => {
            note(nr, INJ_ENOSPC, c as u64, n, call.arg(0));
            call.set_arg(2, n);
            none
        }
        Decision::Error(errno) => {
            note(nr, INJ_ERROR, c as u64, errno as u64, call.arg(0));
            if c == FClass::Close {
                Gate {
                    ret: None,
                    post: Some(-errno),
                }
            } else {
                Gate {
                    ret: Some(-errno),
                    post: None,
                }
            }
        }
        Decision::Shorten(n) => {
            note(nr, INJ_SHORT, c as u64, n, call.arg(0));
            call.set_arg(2, n);
            none
        }
    }
}

/// The sync handler's question: does this sync-class call on an eligible target fail?
/// Counts the call for `fsync-error-at` and `fs-error-at=sync:N`.
pub fn sync_fails() -> bool {
    let f = &ctl().faults;
    let cfg = &f.cfg;
    if !cfg.faults_active() || !after_start() {
        return false;
    }
    let n = f.sync_calls.load(Relaxed) + 1;
    f.sync_calls.store(n, Relaxed);
    let cn = f.count(FClass::Sync);
    (cfg.fsync_error_at != 0 && cfg.fsync_error_at == n)
        || (cfg.fs_error_at_class == FClass::Sync as u64 + 1 && cfg.fs_error_at_n == cn)
        || permille(cfg.fsync_error_permille, SUB_FSYNC_FIRE)
        || permille(cfg.fs_error_permille, SUB_ERR_FIRE)
}

/// Is `[fd]` a regular file? (`close` errors are drawn only for regular files)
pub fn is_reg(fd: u64) -> bool {
    fstat_raw(fd as i32 as i64).is_some_and(|st| st[3] & S_IFMT == S_IFREG)
}

// ---- crash points ----

struct CrashSub {
    seq: u64,
    sub: u64,
}

static SUB: path::Global<CrashSub> = path::Global::new(CrashSub { seq: 0, sub: 0 });

/// A crash point: the tracker's state changed (a record was appended) or a sync-class call is
/// about to be made. Draws `draw(Crash, seq * 16 + k)` (k counts the points of this trap) and,
/// when it fires, appends the `Crash` record and hands the crash to the supervisor, which
/// kills every guest process. Never returns in that case.
pub fn crash_point() {
    let c = ctl();
    let f = &c.faults;
    let cfg = &f.cfg;
    if cfg.crash_kind == CRASH_NONE || cfg.crash_enabled == 0 {
        return;
    }
    let ts = thread();
    if ts.seq < cfg.fault_after_seq {
        return;
    }
    let s = SUB.get();
    if s.seq != ts.seq {
        s.seq = ts.seq;
        s.sub = 0;
    }
    let k = s.sub;
    s.sub += 1;
    f.crash_points
        .store(f.crash_points.load(Relaxed) + 1, Relaxed);
    let fire = if cfg.crash_at != 0 {
        ts.seq >= cfg.crash_at
    } else {
        cfg.crash_permille != 0
            && draw(
                c.config.seed,
                Stream::Crash,
                ts.seq.wrapping_mul(16).wrapping_add(k),
            ) % 1000
                < cfg.crash_permille
    };
    if !fire {
        return;
    }
    crate::oplog::append_crash(cfg.crash_kind);
    crate::sup::call_sup(Op::CrashPoint, [cfg.crash_kind, ts.seq, k, 0, 0, 0]);
    crate::sup::hang()
}
