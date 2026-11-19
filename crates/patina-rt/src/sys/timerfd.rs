//! timerfd: the guest's descriptor is an eventfd created by the runtime
//! (non-semaphore mode, so `read` returns and resets an 8-byte count exactly as a timerfd
//! does). The supervisor holds a duplicate, keeps the timer in its virtual-time event queue
//! and writes the expiry count at expiry. settime/gettime are answered from supervisor
//! state. The supervisor hands out each timer's key at creation (every eventfd has the same
//! inode, so the file cannot name its timer); `fork` copies the keys with the memory.

use super::io;
use super::*;
use core::cell::UnsafeCell;
use proto::ctl::{Op, TFD_ARM, TFD_CREATE, TFD_FIND, TFD_RELEASE};
use proto::layout::FD_HIDDEN_MIN;

const NS: u64 = 1_000_000_000;
const N: usize = FD_HIDDEN_MIN as usize;
const TFD_TIMER_ABSTIME: u64 = 1;
const TFD_TIMER_CANCEL_ON_SET: u64 = 2;
const TFD_NONBLOCK: u64 = 0o4000;
const TFD_CLOEXEC: u64 = 0o2000000;

/// Per-process: the timer key (0: not a timerfd) and clock of each descriptor.
struct Marks {
    key: [u64; N],
    clock: [u8; N],
}
struct G(UnsafeCell<Marks>);
unsafe impl Sync for G {}
static MARKS: G = G(UnsafeCell::new(Marks {
    key: [0; N],
    clock: [0; N],
}));

fn marks() -> &'static mut Marks {
    unsafe { &mut *MARKS.0.get() }
}

fn idx(fd: i64) -> Option<usize> {
    (0..N as i64).contains(&fd).then_some(fd as usize)
}

pub fn is_timerfd(fd: i64) -> bool {
    idx(fd).is_some_and(|i| marks().key[i] != 0)
}

/// `dst` became a duplicate of `src` (dup, dup2, dup3, F_DUPFD).
pub fn copy(src: i64, dst: i64) {
    if crate::state::in_vfork_child() {
        return; // the marks are the parent's
    }
    let (Some(s), Some(d)) = (idx(src), idx(dst)) else {
        return;
    };
    let m = marks();
    if m.key[d] != 0 && m.key[d] != m.key[s] {
        closed(dst);
    }
    m.key[d] = m.key[s];
    m.clock[d] = m.clock[s];
}

/// `fd` was closed: when no other descriptor of this process names the timer, the
/// supervisor drops it (a closed timerfd never fires again). The supervisor counts holders
/// per process, so copies inherited by `fork` keep the timer alive.
pub fn closed(fd: i64) {
    if crate::state::in_vfork_child() {
        return; // the marks are the parent's; its descriptors stay open
    }
    let Some(i) = idx(fd) else { return };
    let m = marks();
    let key = m.key[i];
    if key == 0 {
        return;
    }
    m.key[i] = 0;
    if !m.key.contains(&key) {
        crate::sup::call_sup(Op::TimerFdSet, [TFD_RELEASE, key, 0, 0, 0, 0]);
    }
}

fn create(clock: u64, flags: u64) -> i64 {
    match clock {
        0 | 1 | 7 => {}
        8 | 9 => return -e::EPERM,
        _ => return -e::EINVAL,
    }
    if flags & !(TFD_NONBLOCK | TFD_CLOEXEC) != 0 {
        return -e::EINVAL;
    }
    let fd = unsafe { sc2(nr::EVENTFD2, 0, flags) }; // EFD_NONBLOCK/EFD_CLOEXEC have the same values
    if fd < 0 {
        return fd;
    }
    let key = crate::sup::call_sup(Op::TimerFdSet, [TFD_CREATE, 0, fd as u64, clock, 0, 0]).ret;
    if key < 0 {
        unsafe { sc1(nr::CLOSE, fd as u64) };
        return key;
    }
    let key = key as u64;
    let Some(i) = idx(fd) else { return fd };
    marks().key[i] = key;
    marks().clock[i] = clock as u8;
    fd
}

fn key_of(fd: i64) -> Result<(u64, u64), i64> {
    match idx(fd).map(|i| (marks().key[i], marks().clock[i] as u64)) {
        Some((k, c)) if k != 0 => Ok((k, c)),
        _ => {
            let ok = unsafe { sc2(nr::FCNTL, fd as u64, 1) };
            Err(if ok < 0 { -e::EBADF } else { -e::EINVAL })
        }
    }
}

/// Current setting as an itimerspec: [interval s, ns, value s, ns].
fn current(key: u64) -> [u64; 4] {
    let next = crate::sup::call_sup(Op::TimerFdGet, [key, 0, 0, 0, 0, 0]).ret as u64;
    let ival = crate::sup::call_sup(Op::TimerFdGet, [key, 1, 0, 0, 0, 0]).ret as u64;
    let left = if next == 0 {
        0
    } else {
        next.saturating_sub(super::time::now()).max(1)
    };
    [ival / NS, ival % NS, left / NS, left % NS]
}

fn settime(fd: i64, flags: u64, new: u64, old: u64) -> i64 {
    let (key, clock) = match key_of(fd) {
        Ok(k) => k,
        Err(e) => return e,
    };
    if flags & !(TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET) != 0 {
        return -e::EINVAL;
    }
    let v = match get::<[i64; 4]>(new) {
        Ok(v) => v,
        Err(e) => return e,
    };
    for k in [0, 2] {
        if v[k] < 0 || !(0..NS as i64).contains(&v[k + 1]) {
            return -e::EINVAL;
        }
    }
    if old != 0 {
        if let Err(e) = put(old, current(key)) {
            return e;
        }
    }
    // Setting the timer resets the expiry count, as the kernel does.
    let mut c = 0u64;
    let iov = [&mut c as *mut u64 as u64, 8];
    let r = unsafe {
        sc6(
            nr::PREADV2,
            fd as u64,
            iov.as_ptr() as u64,
            1,
            u64::MAX,
            u64::MAX,
            io::RWF_NOWAIT,
        )
    };
    if r > 0 {
        io::bump();
    }
    let interval = v[0] as u64 * NS + v[1] as u64;
    let value = v[2] as u64 * NS + v[3] as u64;
    let first = if value == 0 {
        0
    } else if flags & TFD_TIMER_ABSTIME != 0 {
        let t = if clock == 0 {
            super::time::realtime_to_vclock(value)
        } else {
            value
        };
        t.max(1)
    } else {
        super::time::now().saturating_add(value)
    };
    crate::sup::call_sup(Op::TimerFdSet, [TFD_ARM, key, first, interval, 0, 0]).ret
}

fn gettime(fd: i64, cur: u64) -> i64 {
    match key_of(fd) {
        Ok((key, _)) => put(cur, current(key)).map(|_| 0).unwrap_or_else(|e| e),
        Err(e) => e,
    }
}

pub fn handle(call: &mut dyn Call) -> i64 {
    let a = args(call);
    match call.nr() {
        nr::TIMERFD_CREATE => create(a[0], a[1]),
        nr::TIMERFD_SETTIME => settime(a[0] as i32 as i64, a[1], a[2], a[3]),
        _ => gettime(a[0] as i32 as i64, a[1]),
    }
}

/// (New image) `fd`, an eventfd the previous image left open, is a timerfd when the
/// supervisor has a timer of this process on the same file.
pub fn found(fd: i64) {
    let Some(i) = idx(fd) else { return };
    let key = crate::sup::call_sup(Op::TimerFdSet, [TFD_FIND, 0, fd as u64, 0, 0, 0]).ret;
    if key == -e::ENOENT {
        return;
    }
    if key < 0 {
        // The supervisor's kcmp failed: which timer this is cannot be told.
        crate::sup::host_error(key, nr::KCMP, proto::ctl::HE_SYSCALL);
    }
    let clock = crate::sup::call_sup(Op::TimerFdGet, [key as u64, 2, 0, 0, 0, 0]).ret;
    marks().key[i] = key as u64;
    marks().clock[i] = clock as u8;
}
