//! Fault decisions made before a call, and crash points.
//!
//! `before(call, class)` is called by the dispatcher for every faultable row (by
//! `proto::faults::class_of`) when fault injection is configured. It first classifies the
//! call's object (`Obj`: a `/work` file or path, a pipe, a unix socket, memory; TCP sockets
//! are the wire's and other objects are never faulted), then counts the call as eligible
//! for each class that could act on it, then decides. Every draw is
//! `draw(seed, FaultFs, seq * 16 + sub)` keyed by the trap's own `seq`, so a decision never
//! depends on how many other draws were made, and a fault kind that is off draws nothing
//! that another kind could see. An injected errno comes only from
//! `proto::faults::errnos(obj, class)`, what Linux can return for that call on that object.
//! An error means the call is not made (except `close`, which closes and then reports
//! `EIO`, as Linux does); a short transfer is made with a smaller count; a delay parks the
//! thread in virtual time and then the call is made. Each injected fault is an `Injected`
//! boundary record followed by a `Name` record naming its object.

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
    /// Return this value without making the call (`brk` fails by returning the old break).
    Ret(i64),
    /// `enospc-after-bytes`: `None` = no room left (ENOSPC), `Some(n)` = write the n that fit.
    Enospc(Option<u64>),
}

pub fn d(sub: u64) -> u64 {
    let ts = thread();
    draw(
        ctl().config.seed,
        Stream::FaultFs,
        ts.seq.wrapping_mul(16).wrapping_add(sub),
    )
}

pub fn permille(p: u64, sub: u64) -> bool {
    p != 0 && d(sub) % 1000 < p
}

const S_IFMT: u64 = 0o170000;
const S_IFIFO: u64 = 0o010000;
const S_IFSOCK: u64 = 0o140000;
const S_IFREG: u64 = 0o100000;

/// How the object of an injected fault is named in its `Name` record.
#[derive(Clone, Copy)]
pub enum Who {
    /// A descriptor: its `/work` path, or its object type.
    Fd(i64, Obj),
    /// A path argument, relative to a directory descriptor.
    At(i64, u64),
    /// No path: the object type alone.
    Kind(Obj),
}

/// The object of a descriptor whose calls may be faulted: a `/work` file or directory, a
/// pipe, a unix socket. TCP sockets (the wire's) and everything else: `None`.
fn fd_obj(fd: u64) -> Option<Obj> {
    let fd = fd as i32 as i64;
    let st = fstat_raw(fd)?;
    let fmt = st.mode() as u64 & S_IFMT;
    if path::is_work(st.dev()) {
        return Some(if fmt == S_IFREG { Obj::File } else { Obj::Path });
    }
    match fmt {
        S_IFIFO => Some(Obj::Pipe),
        S_IFSOCK if crate::sys::inet::wire_idx(fd).is_none() => Some(Obj::Unix),
        _ => None,
    }
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
        return crate::state::on_work(norm.as_bytes());
    }
    if dirfd == AT_FDCWD {
        let mut buf = [0u8; 256];
        let r = unsafe { sc2(nr::GETCWD, buf.as_mut_ptr() as u64, buf.len() as u64) };
        if r <= 0 {
            return false;
        }
        let c = &buf[..(r as usize).saturating_sub(1)];
        return crate::state::on_work(c);
    }
    fstat_raw(dirfd).is_some_and(|st| path::is_work(st.dev()))
}

/// The call's object, if it is eligible for faults, and how to name it. (The sync class
/// is decided by its handler.)
fn target(call: &dyn Call) -> Option<(Obj, Who)> {
    let a = |i: usize| call.arg(i);
    let fd = |i: usize| a(i) as i32 as i64;
    let on = |dirfd: i64, p: u64| path_on_work(dirfd, p).then_some((Obj::Path, Who::At(dirfd, p)));
    let by_fd = |i: usize| fd_obj(a(i)).map(|o| (o, Who::Fd(fd(i), o)));
    match call.nr() {
        // open family
        nr::OPEN | nr::CREAT => on(AT_FDCWD, a(0)),
        nr::OPENAT | nr::OPENAT2 => on(fd(0), a(1)),
        // read/write family on descriptors; copy_file_range and sendfile by their target
        nr::READ
        | nr::PREAD64
        | nr::READV
        | nr::PREADV
        | nr::PREADV2
        | nr::WRITE
        | nr::PWRITE64
        | nr::WRITEV
        | nr::PWRITEV
        | nr::PWRITEV2
        | nr::FTRUNCATE
        | nr::FALLOCATE
        | nr::CLOSE => by_fd(0),
        nr::COPY_FILE_RANGE => by_fd(2).filter(|t| t.0 == Obj::File),
        nr::SENDFILE => by_fd(0).filter(|t| t.0 == Obj::File),
        // names
        nr::RENAME | nr::UNLINK | nr::RMDIR | nr::MKDIR | nr::MKNOD | nr::TRUNCATE => {
            on(AT_FDCWD, a(0))
        }
        nr::LINK | nr::SYMLINK => on(AT_FDCWD, a(1)),
        nr::RENAMEAT | nr::RENAMEAT2 | nr::LINKAT => on(fd(0), a(1)).or_else(|| on(fd(2), a(3))),
        nr::UNLINKAT | nr::MKDIRAT | nr::MKNODAT => on(fd(0), a(1)),
        nr::SYMLINKAT => on(fd(1), a(2)),
        // memory: anonymous or /work mappings, growth of brk and mremap, thread or process creation
        nr::MMAP => {
            const MAP_ANON: u64 = 0x20;
            const MAP_FIXED_ANY: u64 = 0x10 | 0x10_0000;
            (a(3) & MAP_FIXED_ANY == 0 && (a(3) & MAP_ANON != 0 || fd_obj(a(4)) == Some(Obj::File)))
                .then_some((Obj::Mem, Who::Kind(Obj::Mem)))
        }
        nr::BRK => (a(0) > proc().brk_cur).then_some((Obj::Mem, Who::Kind(Obj::Mem))),
        nr::MREMAP => (a(2) > a(1)).then_some((Obj::Mem, Who::Kind(Obj::Mem))),
        nr::CLONE | nr::FORK | nr::VFORK => Some((Obj::Mem, Who::Kind(Obj::Mem))),
        _ => None,
    }
}

/// Write an `Injected` boundary record for the current trap, and a `Name` record naming
/// its object.
pub fn note(nr: u64, kind: u64, class: u64, value: u64, a0: u64, who: Who) {
    let ts = thread();
    let c = ctl();
    let vclock_ns = c.vclock_ns.load(Relaxed);
    let rec = proto::Rec {
        seq: ts.seq,
        vclock_ns,
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
    let mut buf = PathBuf::new();
    let name: &[u8] = match who {
        Who::Fd(fd, o @ (Obj::File | Obj::Path)) => {
            if path::full(fd, b"", &mut buf) {
                buf.as_bytes()
            } else {
                o.name().as_bytes()
            }
        }
        Who::At(dirfd, p) => {
            let s = unsafe { crate::loader::cstr(p as *const u8) };
            if path::full(dirfd, s, &mut buf) {
                buf.as_bytes()
            } else {
                s
            }
        }
        Who::Fd(_, o) | Who::Kind(o) => o.name().as_bytes(),
    };
    crate::log::append(&proto::Rec::name(
        ts.seq,
        vclock_ns,
        ts.slot as u16,
        ts.pid as i64,
        name,
    ));
    count_injected();
}

/// Count one injected fault.
pub fn count_injected() {
    let c = ctl();
    let f = crate::state::faults();
    f.injected.store(f.injected.load(Relaxed) + 1, Relaxed);
    c.stats
        .faults_injected
        .store(c.stats.faults_injected.load(Relaxed) + 1, Relaxed);
}

/// Faults are active and the run is past `faults-after-setup`.
pub fn active() -> bool {
    crate::state::faults().cfg.faults_active() && after_start()
}

fn after_start() -> bool {
    thread().seq >= ctl().faults.cfg.fault_after_seq
}

/// Phase 1: the delay, if one is drawn. Phase 2 (`decide`): error or short transfer.
fn delay(obj: Obj) -> Option<u64> {
    let f = crate::state::faults();
    let cfg = &f.cfg;
    if obj == Obj::Mem {
        return None;
    }
    f.eligible(Kind::FsDelay);
    if !permille(cfg.delay_permille, SUB_DELAY_FIRE) {
        return None;
    }
    Some(d(SUB_DELAY_LEN) % (cfg.delay_max_ns + 1))
}

fn decide(call: &dyn Call, c: FClass, obj: Obj) -> Decision {
    let f = crate::state::faults();
    let cfg = &f.cfg;
    let nr = call.nr();
    if c == FClass::Sync {
        return Decision::Proceed; // the sync handler decides (failed-fsync semantics)
    }
    let n = f.count(c);
    if c == FClass::Mem {
        f.eligible(Kind::MemError);
        let fire = (cfg.mem_error_at != 0 && cfg.mem_error_at == n)
            || permille(cfg.mem_error_permille, SUB_MEM_FIRE);
        if !fire {
            return Decision::Proceed;
        }
        let errno = match nr {
            nr::CLONE if call.arg(0) & 0x10000 != 0 => e::EAGAIN, // CLONE_THREAD
            nr::BRK => return Decision::Ret(proc().brk_cur as i64),
            _ => e::ENOMEM,
        };
        return Decision::Error(errno);
    }
    const O_CREAT: u64 = 0o100;
    let creating = match nr {
        nr::OPEN => call.arg(1) & O_CREAT != 0,
        nr::OPENAT => call.arg(2) & O_CREAT != 0,
        nr::CREAT => true,
        _ => false,
    };
    let base = errnos(obj, c, creating);
    let eintr = cfg.fs_eintr != 0 && eintr_ok(obj, c);
    let k = base.len() as u64 + eintr as u64;
    if k != 0 {
        f.eligible(Kind::FsError);
        let at = cfg.fs_error_at_class != 0
            && cfg.fs_error_at_class == c as u64 + 1
            && cfg.fs_error_at_n == n;
        if at || permille(cfg.fs_error_permille, SUB_ERR_FIRE) {
            let i = (d(SUB_ERR_PICK) % k) as usize;
            let errno = if i < base.len() {
                base[i] as i64
            } else {
                e::EINTR
            };
            return Decision::Error(errno);
        }
    }
    if c == FClass::Write && obj == Obj::File {
        f.eligible(Kind::Enospc);
        if cfg.enospc_after_bytes != 0 {
            let used = f.work_bytes.load(Relaxed);
            let left = cfg.enospc_after_bytes.saturating_sub(used);
            if left == 0 {
                return Decision::Enospc(None);
            }
            if matches!(nr, nr::WRITE | nr::PWRITE64) && call.arg(2) > left {
                return Decision::Enospc(Some(left));
            }
        }
    }
    if matches!(nr, nr::READ | nr::PREAD64 | nr::WRITE | nr::PWRITE64)
        && call.arg(2) >= 2
        && short_ok(obj)
    {
        f.eligible(Kind::FsShort);
        if permille(cfg.short_permille, SUB_SHORT_FIRE) {
            let n = call.arg(2);
            return Decision::Shorten(1 + d(SUB_SHORT_LEN) % (n - 1));
        }
    }
    Decision::Proceed
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
    if !crate::state::faults().cfg.faults_active() || !after_start() {
        return none;
    }
    let Some((obj, who)) = target(call) else {
        return none;
    };
    let nr = call.nr();
    // The record names the guest's own first argument, not a path the runtime resolved.
    let a0 = call.guest_args()[0];
    if let Some(ns) = delay(obj) {
        note(nr, INJ_DELAY, c as u64, ns, a0, who);
        let deadline = ctl().vclock_ns.load(Relaxed) + ns;
        crate::sup::call_sup(Op::Sleep, [deadline, 0, 0, 0, 0, 0]);
        // Other threads ran: an iovec or msghdr the call names may now point elsewhere.
        if !crate::guest::still_clear() {
            return Gate {
                ret: Some(-e::EFAULT),
                post: None,
            };
        }
    }
    match decide(call, c, obj) {
        Decision::Proceed => none,
        Decision::Ret(v) => {
            note(nr, INJ_ERROR, c as u64, e::ENOMEM as u64, a0, who);
            Gate {
                ret: Some(v),
                post: None,
            }
        }
        Decision::Enospc(None) => {
            note(nr, INJ_ENOSPC, c as u64, 0, a0, who);
            Gate {
                ret: Some(-28),
                post: None,
            }
        }
        Decision::Enospc(Some(n)) => {
            note(nr, INJ_ENOSPC, c as u64, n, a0, who);
            call.set_arg(2, n);
            none
        }
        Decision::Error(errno) => {
            note(nr, INJ_ERROR, c as u64, errno as u64, a0, who);
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
            note(nr, INJ_SHORT, c as u64, n, a0, who);
            call.set_arg(2, n);
            none
        }
    }
}

/// The sync handler's question: does this sync-class call on an eligible target fail, and by
/// which class (`SYNC_BY_FSYNC_ERROR` or `SYNC_BY_FS_ERROR`)? Counts the call for
/// `fsync-error-at` and `fs-error-at=sync:N`, and as eligible for both classes.
pub fn sync_fails() -> Option<u64> {
    let f = crate::state::faults();
    let cfg = &f.cfg;
    if !cfg.faults_active() || !after_start() {
        return None;
    }
    let n = f.sync_calls.load(Relaxed) + 1;
    f.sync_calls.store(n, Relaxed);
    let cn = f.count(FClass::Sync);
    f.eligible(Kind::FsyncError);
    f.eligible(Kind::FsError);
    if (cfg.fsync_error_at != 0 && cfg.fsync_error_at == n)
        || permille(cfg.fsync_error_permille, SUB_FSYNC_FIRE)
    {
        Some(SYNC_BY_FSYNC_ERROR)
    } else if (cfg.fs_error_at_class == FClass::Sync as u64 + 1 && cfg.fs_error_at_n == cn)
        || permille(cfg.fs_error_permille, SUB_ERR_FIRE)
    {
        Some(SYNC_BY_FS_ERROR)
    } else {
        None
    }
}

/// `mem-limit-mb`: may this process's anonymous memory grow by `grow` bytes? It is the
/// kernel's own count of the process's private writable memory (`/proc/self/statm` data,
/// what `RLIMIT_DATA` limits), a function of the calls made, since the runtime places every
/// mapping. Past the limit the call answers `ENOMEM` and an `Injected` record names it.
/// Holds from the start, whatever `faults-after-setup` says: it is a limit, not a draw.
pub fn mem_limit_refuses(nr: u64, grow: u64) -> bool {
    let f = crate::state::faults();
    let limit = f.cfg.mem_limit_bytes;
    if limit == 0 || grow == 0 {
        return false;
    }
    f.eligible(Kind::MemLimit);
    let used = statm_data_bytes();
    if used.saturating_add(grow) <= limit {
        return false;
    }
    note(
        nr,
        INJ_MEM_LIMIT,
        FClass::Mem as u64,
        grow,
        used,
        Who::Kind(Obj::Mem),
    );
    true
}

/// The `data` field of `/proc/self/statm`, in bytes.
fn statm_data_bytes() -> u64 {
    let fd = unsafe {
        sc4(
            nr::OPENAT,
            AT_FDCWD as u64,
            c"/proc/self/statm".as_ptr() as u64,
            0o2000000,
            0,
        )
    };
    if fd < 0 {
        crate::sup::host_error(fd, nr::OPENAT, proto::ctl::HE_SYSCALL);
    }
    let mut b = [0u8; 128];
    let n = unsafe { sc3(nr::READ, fd as u64, b.as_mut_ptr() as u64, b.len() as u64) };
    unsafe { sc1(nr::CLOSE, fd as u64) };
    if n <= 0 {
        crate::sup::host_error(n, 0, proto::ctl::HE_SYSCALL);
    }
    // size resident shared text lib data dt
    let field = b[..n as usize].split(|&c| c == b' ').nth(5).unwrap_or(b"0");
    let pages = field
        .iter()
        .take_while(|c| c.is_ascii_digit())
        .fold(0u64, |v, &c| v * 10 + (c - b'0') as u64);
    pages * 4096
}

// ---- crash points ----

struct CrashSub {
    seq: u64,
    sub: u64,
}

static SUB: path::Global<CrashSub> = path::Global::new(CrashSub { seq: 0, sub: 0 });

/// A crash point: the tracker's state changed (a record was appended) or a sync-class call is
/// about to be made. Counts the point (`crash_points`: its ordinal in this incarnation), then
/// either fires at the `crash_at`-th point or draws `draw(Crash, seq * 16 + k)` (k counts the
/// points of this trap). When it fires it appends the `Crash` record and hands the crash to
/// the supervisor, which kills every guest process. Never returns in that case. A point that
/// does not fire changes nothing but the count, so a run's prefix is the same whatever the
/// crash setting.
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
    let n = f.crash_points.load(Relaxed) + 1;
    f.crash_points.store(n, Relaxed);
    let fire = if cfg.crash_at != 0 {
        n == cfg.crash_at
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
    // The supervisor logs what every process's shared mappings hold, then the `Crash` record.
    crate::sup::call_sup(Op::CrashPoint, [cfg.crash_kind, ts.seq, k, 0, 0, 0]);
    crate::sup::hang()
}
