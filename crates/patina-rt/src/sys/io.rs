//! Blocking I/O: every call that can wait on a descriptor is a non-blocking attempt
//! plus a park in the supervisor.
//!
//! - `Waiter::run` is the one loop every blocking-capable handler uses: make the attempt;
//!   if it would block, honour `O_NONBLOCK` (the guest gets `EAGAIN`), else `Park` until the
//!   I/O generation moves or the virtual deadline passes, and attempt again.
//! - `bump()` moves the I/O generation after any call that can change readiness. It is a
//!   store in the control region; if threads are parked on I/O, the calling thread also
//!   yields at the end of its call so they re-attempt (a scheduling point, drawn by seed).
//! - `write_all` continues partial counts on blocking descriptors.
//! - The non-blocking forms are `RWF_NOWAIT`, `MSG_DONTWAIT`, zero timeouts,
//!   `LOCK_NB`/`F_SETLK`, `SPLICE_F_NONBLOCK`. Where the kernel offers none
//!   (`connect`; eventfd writes and FIFOs opened by path refuse `RWF_NOWAIT`), the
//!   description is made non-blocking for the one call (see `toggled`).

use super::fs::fstat_raw;
use super::*;
use core::sync::atomic::AtomicBool;
use proto::ctl::{Op, NO_DEADLINE, PARK_IN, PARK_OPEN, PARK_OUT};

pub const RWF_NOWAIT: u64 = 8;
pub const O_NONBLOCK: u64 = 0o4000;
const F_GETFL: u64 = 3;
const F_SETFL: u64 = 4;
pub const POLLIN: u16 = 1;
pub const POLLERR: u16 = 8;
pub const POLLHUP: u16 = 0x10;
const NS: u64 = 1_000_000_000;

/// What kind of object a descriptor is, decided by `fstat` at the call.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    /// Regular files, directories, devices: cannot wait; passed.
    Plain,
    /// Pipes and FIFOs.
    Pipe,
    Sock,
    /// Anonymous inodes: eventfd, timerfd (an eventfd here), epoll.
    Anon,
}

pub fn kind_of(fd: i64) -> Option<Kind> {
    let st = fstat_raw(fd)?;
    Some(match st.mode() & 0o170000 {
        0o010000 => Kind::Pipe,
        0o140000 => Kind::Sock,
        0 => Kind::Anon,
        _ => Kind::Plain,
    })
}

pub fn can_block(k: Option<Kind>) -> bool {
    matches!(k, Some(Kind::Pipe | Kind::Sock | Kind::Anon))
}

// ---- the generation ----

static NOTIFY: AtomicBool = AtomicBool::new(false);

/// A call that can change readiness completed.
pub fn bump() {
    let io = &ctl().io;
    io.gen.store(io.gen.load(Relaxed) + 1, Relaxed);
    if io.waiters.load(Relaxed) != 0 {
        NOTIFY.store(true, Relaxed);
    }
}

/// Should this thread yield at the end of its call so that I/O waiters re-attempt?
pub fn take_notify() -> bool {
    NOTIFY.swap(false, Relaxed)
}

fn inc(c: &core::sync::atomic::AtomicU64) {
    c.store(c.load(Relaxed) + 1, Relaxed);
}

pub fn nonblocking(fd: i64) -> bool {
    let fl = unsafe { sc2(nr::FCNTL, fd as u64, F_GETFL) };
    fl >= 0 && fl as u64 & O_NONBLOCK != 0
}

pub fn set_nonblock(fd: i64, on: bool) -> i64 {
    let fl = unsafe { sc2(nr::FCNTL, fd as u64, F_GETFL) };
    if fl < 0 {
        return fl;
    }
    let nfl = if on {
        fl as u64 | O_NONBLOCK
    } else {
        fl as u64 & !O_NONBLOCK
    };
    unsafe { sc3(nr::FCNTL, fd as u64, F_SETFL, nfl) }
}

/// One `pollfd` with a zero timeout: the ready events (0 if none).
pub fn poll1(fd: i64, events: u16) -> u16 {
    let mut p: [u32; 2] = [fd as u32, events as u32];
    let ts = [0u64; 2];
    let r = unsafe {
        sc6(
            nr::PPOLL,
            p.as_mut_ptr() as u64,
            1,
            ts.as_ptr() as u64,
            0,
            8,
            0,
        )
    };
    if r <= 0 {
        0
    } else {
        (p[1] >> 16) as u16
    }
}

// ---- deadlines ----

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Deadline {
    None,
    At(u64),
    /// The socket's SO_RCVTIMEO / SO_SNDTIMEO, read at the first would-block.
    RcvTimeo,
    SndTimeo,
}

fn sock_timeo(fd: i64, opt: u64) -> Option<u64> {
    let mut tv = [0i64; 2];
    let mut len: u32 = 16;
    let r = unsafe {
        sc6(
            nr::GETSOCKOPT,
            fd as u64,
            1,
            opt,
            tv.as_mut_ptr() as u64,
            &mut len as *mut u32 as u64,
            0,
        )
    };
    if r != 0 || (tv[0] == 0 && tv[1] == 0) || tv[0] < 0 {
        return None;
    }
    Some(super::time::now().saturating_add(tv[0] as u64 * NS + tv[1] as u64 * 1000))
}

impl Deadline {
    fn resolve(&mut self, fd: i64) -> Option<u64> {
        match *self {
            Deadline::None => None,
            Deadline::At(t) => Some(t),
            Deadline::RcvTimeo | Deadline::SndTimeo => {
                let opt = if *self == Deadline::RcvTimeo { 20 } else { 21 };
                let d = sock_timeo(fd, opt);
                *self = d.map(Deadline::At).unwrap_or(Deadline::None);
                d
            }
        }
    }
    /// A relative timeout in nanoseconds from now.
    pub fn after(ns: u64) -> Deadline {
        Deadline::At(super::time::now().saturating_add(ns))
    }
}

// ---- the attempt loop ----

pub enum Got {
    /// The attempt completed with this result (success or an error other than would-block).
    Done(i64),
    /// The virtual deadline passed.
    TimedOut,
    /// A signal woke the thread (signals decides about restarting).
    Interrupted,
    /// It would block, and the descriptor (or the call) is non-blocking.
    WouldBlock,
}

pub struct Waiter {
    pub fd: i64,
    pub dir: u64,
    pub nr: u64,
    pub nfds: u64,
    pub deadline: Deadline,
    /// Some(true): the guest asked for a non-blocking call; Some(false): known blocking;
    /// None: look at the descriptors' O_NONBLOCK at the first would-block.
    pub nonblock: Option<bool>,
    /// Descriptors whose O_NONBLOCK makes the call non-blocking (-1: none).
    pub nb_fds: [i64; 2],
    pub parked: bool,
}

impl Waiter {
    pub fn new(fd: i64, dir: u64, nr: u64) -> Waiter {
        Waiter {
            fd,
            dir,
            nr,
            nfds: 1,
            deadline: Deadline::None,
            nonblock: None,
            nb_fds: [fd, -1],
            parked: false,
        }
    }

    fn is_nonblock(&mut self) -> bool {
        if self.nonblock.is_none() {
            self.nonblock = Some(self.nb_fds.iter().any(|&f| f >= 0 && nonblocking(f)));
        }
        self.nonblock == Some(true)
    }

    /// Attempt until done. `f` makes one non-blocking attempt and returns None when it
    /// would have waited.
    pub fn run(&mut self, mut f: impl FnMut() -> Option<i64>) -> Got {
        let io = &ctl().io;
        let mut again = false;
        loop {
            let gen = io.gen.load(Relaxed);
            let r = f();
            if again {
                inc(&io.reattempts);
                if r.is_none() {
                    inc(&io.spurious);
                }
            }
            if let Some(r) = r {
                return Got::Done(r);
            }
            if self.is_nonblock() {
                return Got::WouldBlock;
            }
            let dl = self.deadline.resolve(self.fd);
            if dl.is_some_and(|d| super::time::now() >= d) {
                return Got::TimedOut;
            }
            NOTIFY.store(false, Relaxed); // the request itself tells the supervisor
            let w = crate::sup::call_sup(
                Op::Park,
                [
                    gen,
                    dl.unwrap_or(NO_DEADLINE),
                    self.fd as u64,
                    self.dir,
                    self.nr,
                    self.nfds,
                ],
            )
            .ret;
            if w == -EINTR {
                return Got::Interrupted;
            }
            self.parked = true;
            again = true;
            if !crate::guest::still_clear() {
                return Got::Done(-e::EFAULT);
            }
        }
    }

    /// Count a completed call (spurious re-attempt rate: re-attempts / blocking calls done).
    pub fn finish(&self, r: i64) -> i64 {
        if r >= 0 && self.nonblock != Some(true) {
            let io = &ctl().io;
            inc(&io.blocking_done);
            if self.parked {
                inc(&io.blocking_parked);
            }
        }
        r
    }
}

pub const EINTR: i64 = 4;
pub const EOPNOTSUPP: i64 = 95;

/// Map the end of an attempt loop to a return value (`timeout` for a passed deadline).
pub fn result(g: Got, timeout: i64) -> i64 {
    match g {
        Got::Done(r) => r,
        Got::TimedOut => timeout,
        Got::Interrupted => -EINTR,
        Got::WouldBlock => -e::EAGAIN,
    }
}

pub fn eagain(r: i64) -> Option<i64> {
    if r == -e::EAGAIN {
        None
    } else {
        Some(r)
    }
}

// ---- iovec cursors (partial transfers) ----

pub const WIN: usize = 64;

/// A position in a guest iovec array.
pub struct IovCursor {
    iov: u64,
    cnt: u64,
    seg: u64,
    off: u64,
}

impl IovCursor {
    pub fn new(iov: u64, cnt: u64) -> IovCursor {
        IovCursor {
            iov,
            cnt: cnt.min(1024),
            seg: 0,
            off: 0,
        }
    }
    /// Entry `i`. The array is the runtime's own (`rw` builds one for `read` and `write`) or
    /// the program's, read as guest memory: one it unmapped meanwhile reads as empty. A
    /// program's array is never in the runtime's region (`guest::names_runtime`).
    fn at(&self, i: u64) -> [u64; 2] {
        let p = self.iov + i * 16;
        if crate::guest::in_region(p, 16) {
            unsafe { *(p as *const [u64; 2]) }
        } else {
            crate::guest::get::<[u64; 2]>(p).unwrap_or([0, 0])
        }
    }
    /// Skip `n` transferred bytes.
    pub fn advance(&mut self, mut n: u64) {
        while self.seg < self.cnt {
            let [_, len] = self.at(self.seg);
            let left = len - self.off;
            if n < left {
                self.off += n;
                return;
            }
            n -= left;
            self.seg += 1;
            self.off = 0;
        }
    }
    /// Nothing left (zero-length segments at the end count as done).
    pub fn done(&self) -> bool {
        (self.seg..self.cnt).all(|i| self.at(i)[1] - if i == self.seg { self.off } else { 0 } == 0)
    }
    /// The remainder as an iovec array of at most `WIN` entries.
    pub fn window(&self, out: &mut [[u64; 2]; WIN]) -> u64 {
        let mut n = 0;
        let mut i = self.seg;
        while i < self.cnt && n < WIN {
            let [b, l] = self.at(i);
            let o = if i == self.seg { self.off } else { 0 };
            out[n] = [b + o, l - o];
            n += 1;
            i += 1;
        }
        n as u64
    }
}

/// Blocking write semantics over non-blocking attempts: `f(iov, cnt)` makes one attempt on
/// the remainder. Partial counts are continued after parks; returns the total, or the
/// error / would-block / timeout / EINTR if nothing was written.
pub fn write_all(w: &mut Waiter, iov: u64, cnt: u64, mut f: impl FnMut(u64, u64) -> i64) -> i64 {
    let mut cur = IovCursor::new(iov, cnt);
    let mut win = [[0u64; 2]; WIN];
    let mut total = 0i64;
    let mut first = true;
    loop {
        // The first attempt passes the guest's own array, so a write of at most 4096 bytes
        // to a pipe is one kernel call (atomic) however it is split into segments.
        let (p, n) = if first {
            (iov, cnt)
        } else {
            (win.as_ptr() as u64, cur.window(&mut win))
        };
        first = false;
        let g = w.run(|| eagain(f(p, n)));
        match g {
            Got::Done(r) if r > 0 => {
                total += r;
                bump();
                cur.advance(r as u64);
                if cur.done() {
                    return total;
                }
            }
            Got::Done(r) => return if total > 0 { total } else { r },
            g => {
                return if total > 0 {
                    total
                } else {
                    result(g, -e::EAGAIN)
                }
            }
        }
    }
}

// ---- read and write on descriptors that can block ----

/// Some objects refuse RWF_NOWAIT (EOPNOTSUPP): eventfd writes, and FIFOs opened by path
/// (only `pipe()` sets the kernel's FMODE_NOWAIT on them). For those the description is
/// made non-blocking for the duration of the plain readv/writev only. No other guest
/// thread, in any process, runs meanwhile, so nobody can observe the flag.
fn toggled(fd: i64, nr: u64, iov: u64, cnt: u64) -> i64 {
    let fl = unsafe { sc2(nr::FCNTL, fd as u64, F_GETFL) };
    if fl < 0 {
        return fl;
    }
    if fl as u64 & O_NONBLOCK == 0 {
        unsafe { sc3(nr::FCNTL, fd as u64, F_SETFL, fl as u64 | O_NONBLOCK) };
    }
    let r = unsafe { sc3(nr, fd as u64, iov, cnt) };
    if fl as u64 & O_NONBLOCK == 0 {
        unsafe { sc3(nr::FCNTL, fd as u64, F_SETFL, fl as u64) };
    }
    r
}

/// read, readv, preadv2(offset -1) on a pipe, socket or anonymous object.
pub fn read_iov(nr: u64, fd: i64, kind: Kind, iov: u64, cnt: u64, flags: u64) -> i64 {
    let mut w = Waiter::new(fd, PARK_IN, nr);
    if kind == Kind::Sock {
        w.deadline = Deadline::RcvTimeo;
    }
    if flags & RWF_NOWAIT != 0 {
        w.nonblock = Some(true);
    }
    let g = w.run(|| {
        if kind == Kind::Anon {
            if let Some(r) = super::timerfd::canceled(fd) {
                return Some(r);
            }
        }
        let mut r = unsafe {
            sc6(
                nr::PREADV2,
                fd as u64,
                iov,
                cnt,
                u64::MAX,
                u64::MAX,
                flags | RWF_NOWAIT,
            )
        };
        if r == -EOPNOTSUPP && flags & !RWF_NOWAIT == 0 {
            r = toggled(fd, nr::READV, iov, cnt);
        }
        eagain(r)
    });
    let r = result(g, -e::EAGAIN);
    if r > 0 {
        bump();
    }
    w.finish(r)
}

/// write, writev, pwritev2(offset -1) on a pipe, socket or anonymous object.
pub fn write_iov(nr: u64, fd: i64, kind: Kind, iov: u64, cnt: u64, flags: u64) -> i64 {
    if kind == Kind::Anon && (super::timerfd::is_timerfd(fd) || super::signalfd::is_signalfd(fd)) {
        return -e::EINVAL;
    }
    let mut w = Waiter::new(fd, PARK_OUT, nr);
    if kind == Kind::Sock {
        w.deadline = Deadline::SndTimeo;
    }
    if flags & RWF_NOWAIT != 0 {
        w.nonblock = Some(true);
    }
    let r = write_all(&mut w, iov, cnt, |p, n| {
        let r = unsafe {
            sc6(
                nr::PWRITEV2,
                fd as u64,
                p,
                n,
                u64::MAX,
                u64::MAX,
                flags | RWF_NOWAIT,
            )
        };
        if r == -EOPNOTSUPP && flags & !RWF_NOWAIT == 0 {
            toggled(fd, nr::WRITEV, p, n)
        } else {
            r
        }
    });
    w.finish(r)
}

/// The read/write family on a descriptor that can block (`kind` from `kind_of`).
pub fn rw(call: &mut dyn Call, kind: Kind) -> i64 {
    set_class(call, Class::Attempt);
    let a = args(call);
    let fd = a[0] as i32 as i64;
    let one = [a[1], a[2]];
    let p1 = one.as_ptr() as u64;
    match call.nr() {
        nr::READ => read_iov(nr::READ, fd, kind, p1, 1, 0),
        nr::WRITE => write_iov(nr::WRITE, fd, kind, p1, 1, 0),
        nr::READV => read_iov(nr::READV, fd, kind, a[1], a[2], 0),
        nr::WRITEV => write_iov(nr::WRITEV, fd, kind, a[1], a[2], 0),
        nr::PREADV2 if a[3] as i64 == -1 => read_iov(nr::PREADV2, fd, kind, a[1], a[2], a[5]),
        nr::PWRITEV2 if a[3] as i64 == -1 => write_iov(nr::PWRITEV2, fd, kind, a[1], a[2], a[5]),
        // An explicit offset on a pipe or socket: the kernel answers ESPIPE without waiting.
        _ => {
            set_class(call, Class::Pass);
            raw(call)
        }
    }
}

// ---- FIFO open ----

const O_ACCMODE: u64 = 3;
const O_CREAT: u64 = 0o100;
const O_EXCL: u64 = 0o200;
const O_PATH: u64 = 0o10000000;
use proto::abi::open::O_NOFOLLOW;

/// `open`/`openat` of a FIFO without O_NONBLOCK would wait in the kernel for the other
/// side. Returns None when the call is not that case. A writer opens non-blocking and
/// parks while that answers ENXIO (no reader); a reader opens non-blocking and parks
/// until the FIFO is readable or has seen a writer come and go (the kernel exposes no
/// count of writers to wait on). The new description's O_NONBLOCK, set
/// by the runtime before the guest has seen it, is then cleared.
pub fn fifo_open(nr: u64, a: &[u64; 6], dirfd: i64, pi: usize, flags: u64) -> Option<i64> {
    if !(nr == nr::OPEN || nr == nr::OPENAT)
        || flags & (O_NONBLOCK | O_PATH) != 0
        || flags & O_ACCMODE == 2
    {
        return None;
    }
    if flags & (O_CREAT | O_EXCL) == O_CREAT | O_EXCL {
        return None;
    }
    let nofollow = if flags & O_NOFOLLOW != 0 { 0x100 } else { 0 };
    let st = super::fs::fstatat_raw(dirfd, a[pi], nofollow)?;
    if st.mode() & 0o170000 != 0o010000 {
        return None;
    }
    let mut b = *a;
    let fi = if nr == nr::OPEN { 1 } else { 2 };
    b[fi] = flags | O_NONBLOCK;
    let open = || unsafe { sc6(nr, b[0], b[1], b[2], b[3], b[4], b[5]) };
    let mut w = Waiter::new(-1, PARK_OPEN, nr);
    w.nonblock = Some(false);
    let r = if flags & O_ACCMODE == 1 {
        let g = w.run(|| {
            let r = open();
            if r == -e::ENXIO {
                None
            } else {
                Some(r)
            }
        });
        result(g, -e::EAGAIN)
    } else {
        let r = open();
        if r < 0 {
            return Some(r);
        }
        bump(); // a writer parked on ENXIO can go on
        w.fd = r;
        let g = w.run(|| {
            if poll1(r, POLLIN) & (POLLIN | POLLHUP) != 0 {
                Some(r)
            } else {
                None
            }
        });
        match g {
            Got::Done(_) => r,
            g => {
                unsafe { sc1(nr::CLOSE, r as u64) };
                result(g, -e::EAGAIN)
            }
        }
    };
    if r >= 0 {
        set_nonblock(r, false);
        bump();
    }
    Some(w.finish(r))
}

// ---- splice, tee, vmsplice ----

const SPLICE_F_NONBLOCK: u64 = 2;

/// splice/tee between pipes or a pipe and a regular file: SPLICE_F_NONBLOCK attempts and
/// parks. A socket or anonymous object on either side answers EINVAL.
pub fn splice(call: &mut dyn Call) -> i64 {
    let mut a = args(call);
    let nr = call.nr();
    let (fi, fdi, fdo) = match nr {
        nr::SPLICE => (5, a[0], a[2]),
        nr::TEE => (3, a[0], a[1]),
        _ => (3, a[0], u64::MAX), // vmsplice(fd, iov, n, flags)
    };
    let mut nb = [-1i64; 2];
    for (i, fd) in [fdi, fdo].into_iter().enumerate() {
        if fd == u64::MAX {
            continue;
        }
        match kind_of(fd as i32 as i64) {
            Some(Kind::Sock | Kind::Anon) => {
                let c = ctl();
                c.note_denied(nr);
                return -e::EINVAL;
            }
            Some(Kind::Pipe) => nb[i] = fd as i32 as i64,
            _ => {}
        }
    }
    let guest_nb = a[fi] & SPLICE_F_NONBLOCK != 0;
    a[fi] |= SPLICE_F_NONBLOCK;
    let mut w = Waiter::new(fdi as i32 as i64, PARK_IN, nr);
    w.nb_fds = nb;
    if guest_nb {
        w.nonblock = Some(true);
    }
    let g = w.run(|| eagain(unsafe { sc6(nr, a[0], a[1], a[2], a[3], a[4], a[5]) }));
    let r = result(g, -e::EAGAIN);
    if r > 0 {
        bump();
    }
    w.finish(r)
}
