//! signalfd: the guest's descriptor is an eventfd made by the runtime, used only as a
//! readiness flag; signals stay in the supervisor's pending sets. Before every poll, select and
//! epoll attempt (and after a read of one) `sync` makes each signalfd of the process readable
//! exactly while a signal of its mask is pending for the calling thread (its own or its
//! process's, as the kernel's `signalfd_poll` looks at the caller), with a fresh write of the
//! eventfd when a signal of the mask became pending since the last look (the edge an
//! edge-triggered epoll reports). A read dequeues through the supervisor (`SigWait` with a
//! passed deadline) and answers `signalfd_siginfo` records; a blocking read parks on the I/O
//! generation, which the supervisor moves when a signal of a mask the process holds becomes
//! pending (`Op::SigFd` tells it the union of the masks).
//!
//! The mask is per process: `signalfd(fd, mask)` on an existing descriptor changes it for the
//! descriptors of this process that name the same file, not for another process holding it.
//! `fork` copies the marks with the memory; `execve` carries the marks of descriptors that
//! stay open in the slot's siginfo words (`before_exec`, `after_exec`).

use super::io::{self, Got, Waiter};
use super::*;
use core::cell::UnsafeCell;
use proto::ctl::{Op, PARK_IN};
use proto::layout::FD_HIDDEN_MIN;

const N: usize = FD_HIDDEN_MIN as usize;
const SFD_NONBLOCK: u64 = 0o4000;
const SFD_CLOEXEC: u64 = 0o2000000;
/// SIGKILL and SIGSTOP are never read through a signalfd.
const UNBLOCKABLE: u64 = super::sig::UNBLOCKABLE;
/// `struct signalfd_siginfo`.
const SSI: usize = 128;
/// siginfo word 0 while marks are carried across `execve` (a signal number is at most 64).
const EXEC_MAGIC: u64 = 0x5346_445f_4558_4543;
const EXEC_MAX: usize = 7;

/// Per-process: the mask of each signalfd descriptor (0: not one), the file it names (its
/// virtual inode), and the signals of the mask last made visible by `sync`.
struct Marks {
    mask: [u64; N],
    key: [u64; N],
    seen: [u64; N],
    count: usize,
    /// The union last sent to the supervisor (`Op::SigFd`).
    sent: u64,
}
struct G(UnsafeCell<Marks>);
unsafe impl Sync for G {}
static MARKS: G = G(UnsafeCell::new(Marks {
    mask: [0; N],
    key: [0; N],
    seen: [0; N],
    count: 0,
    sent: 0,
}));

fn marks() -> &'static mut Marks {
    unsafe { &mut *MARKS.0.get() }
}

fn idx(fd: i64) -> Option<usize> {
    (0..N as i64).contains(&fd).then_some(fd as usize)
}

pub fn is_signalfd(fd: i64) -> bool {
    idx(fd).is_some_and(|i| marks().mask[i] != 0)
}

fn set(i: usize, mask: u64, key: u64) {
    let m = marks();
    match (m.mask[i] != 0, mask != 0) {
        (false, true) => m.count += 1,
        (true, false) => m.count -= 1,
        _ => {}
    }
    m.mask[i] = mask;
    m.key[i] = key;
    m.seen[i] = 0;
}

/// Tell the supervisor the union of the masks when it changed.
fn publish() {
    let m = marks();
    let u = m.mask.iter().fold(0, |a, &x| a | x) & !(1 << 63);
    if u != m.sent {
        m.sent = u;
        crate::sup::call_sup(Op::SigFd, [u, 0, 0, 0, 0, 0]);
    }
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
    if m.mask[s] == 0 && m.mask[d] == 0 {
        return;
    }
    let (mask, key) = (m.mask[s], m.key[s]);
    set(d, mask, key);
    publish();
}

/// `fd` was closed.
pub fn closed(fd: i64) {
    if crate::state::in_vfork_child() {
        return;
    }
    if let Some(i) = idx(fd) {
        if marks().mask[i] != 0 {
            set(i, 0, 0);
            publish();
        }
    }
}

/// signalfd(fd, mask, size) and signalfd4(fd, mask, size, flags).
pub fn create(call: &mut dyn Call) -> i64 {
    let a = args(call);
    let fd = a[0] as i32 as i64;
    let flags = if call.nr() == nr::SIGNALFD4 { a[3] } else { 0 };
    if a[2] != 8 || flags & !(SFD_NONBLOCK | SFD_CLOEXEC) != 0 {
        return -e::EINVAL;
    }
    let mask = match get::<u64>(a[1]) {
        Ok(v) => v & !UNBLOCKABLE,
        Err(e) => return e,
    };
    // An empty mask is a signalfd that never becomes readable; the mark needs a bit.
    let stored = if mask == 0 { 1 << 63 } else { mask };
    if fd != -1 {
        let ok = unsafe { sc2(nr::FCNTL, fd as u64, 1) };
        if ok < 0 {
            return -e::EBADF;
        }
        if !is_signalfd(fd) {
            return -e::EINVAL;
        }
        let key = marks().key[fd as usize];
        for i in 0..N {
            if marks().mask[i] != 0 && marks().key[i] == key {
                set(i, stored, key);
            }
        }
        publish();
        sync();
        return fd;
    }
    // EFD_NONBLOCK and EFD_CLOEXEC have the same values.
    let fd = unsafe { sc2(nr::EVENTFD2, 0, flags) };
    if fd < 0 {
        return fd;
    }
    let Some(i) = idx(fd) else {
        unsafe { sc1(nr::CLOSE, fd as u64) };
        return -24; // EMFILE: never, the lowest free number is below the hidden ones
    };
    let key = crate::vino::of_fd(fd).unwrap_or(fd as u64);
    if !crate::state::in_vfork_child() {
        set(i, stored, key);
        publish();
    }
    sync();
    fd
}

/// The signals of the descriptor's mask (the empty-mask marker dropped).
fn mask_of(i: usize) -> u64 {
    marks().mask[i] & !(1 << 63)
}

/// Make each signalfd of the process readable exactly while a signal of its mask is pending
/// for the calling thread; a signal that became pending since the last look writes the
/// eventfd again (an edge).
pub fn sync() {
    let m = marks();
    if m.count == 0 {
        return;
    }
    let ts = crate::state::thread();
    let pend = unsafe { &*ctl().slot(ts.slot as usize) }
        .sigpend
        .load(Relaxed);
    for i in 0..N {
        if m.mask[i] == 0 {
            continue;
        }
        let want = pend & mask_of(i);
        let fd = i as u64;
        if want == 0 {
            let mut c = 0u64;
            let iov = [&mut c as *mut u64 as u64, 8];
            unsafe {
                sc6(
                    nr::PREADV2,
                    fd,
                    iov.as_ptr() as u64,
                    1,
                    u64::MAX,
                    u64::MAX,
                    io::RWF_NOWAIT,
                )
            };
        } else if want & !m.seen[i] != 0 || io::poll1(i as i64, io::POLLIN) == 0 {
            let one = 1u64;
            unsafe { sc3(nr::WRITE, fd, &one as *const u64 as u64, 8) };
        }
        m.seen[i] = want;
    }
}

/// One `signalfd_siginfo` from a kernel `siginfo_t` (the kernel's `signalfd_copyinfo`).
fn ssi(info: &[u64; 16]) -> [u8; SSI] {
    let b: [u8; 128] = unsafe { core::mem::transmute(*info) };
    let i32_at = |o: usize| i32::from_ne_bytes(b[o..o + 4].try_into().unwrap());
    let u64_at = |o: usize| u64::from_ne_bytes(b[o..o + 8].try_into().unwrap());
    let mut o = [0u8; SSI];
    let put32 =
        |o: &mut [u8; SSI], at: usize, v: i32| o[at..at + 4].copy_from_slice(&v.to_ne_bytes());
    let (signo, errno, code) = (i32_at(0), i32_at(4), i32_at(8));
    put32(&mut o, 0, signo);
    put32(&mut o, 4, errno);
    put32(&mut o, 8, code);
    let put64 =
        |o: &mut [u8; SSI], at: usize, v: u64| o[at..at + 8].copy_from_slice(&v.to_ne_bytes());
    const SIGCHLD: i32 = 17;
    const SI_KERNEL: i32 = 0x80;
    const SI_TIMER: i32 = -2;
    const SI_SIGIO: i32 = -5;
    let fault = matches!(signo, 4 | 5 | 7 | 8 | 11);
    if code > 0 && code < SI_KERNEL && signo == SIGCHLD {
        put32(&mut o, 12, i32_at(16)); // ssi_pid
        put32(&mut o, 16, i32_at(20)); // ssi_uid
        put32(&mut o, 40, i32_at(24)); // ssi_status
        put64(&mut o, 56, u64_at(32)); // ssi_utime
        put64(&mut o, 64, u64_at(40)); // ssi_stime
    } else if code > 0 && code < SI_KERNEL && fault {
        put64(&mut o, 72, u64_at(16)); // ssi_addr
    } else if (code > 0 && code < SI_KERNEL && signo == 29) || code == SI_SIGIO {
        put32(&mut o, 28, u64_at(16) as i32); // ssi_band
        put32(&mut o, 20, i32_at(24)); // ssi_fd
    } else if code == SI_TIMER {
        put32(&mut o, 24, i32_at(16)); // ssi_tid
        put32(&mut o, 32, i32_at(20)); // ssi_overrun
        put64(&mut o, 48, u64_at(24)); // ssi_ptr
        put32(&mut o, 44, i32_at(24)); // ssi_int
    } else if code < 0 {
        put32(&mut o, 12, i32_at(16));
        put32(&mut o, 16, i32_at(20));
        put64(&mut o, 48, u64_at(24));
        put32(&mut o, 44, i32_at(24));
    } else {
        put32(&mut o, 12, i32_at(16));
        put32(&mut o, 16, i32_at(20));
    }
    o
}

/// Dequeue one signal of `mask` for the calling thread, its record in `out`.
fn take(mask: u64, out: &mut [u8; SSI]) -> bool {
    let r = crate::sup::call_sup(Op::SigWait, [mask, 0, 0, 0, 0, 0]).ret;
    if r <= 0 {
        return false;
    }
    let ts = crate::state::thread();
    let info = unsafe { core::ptr::read_volatile(&(*ctl().slot(ts.slot as usize)).siginfo) };
    *out = ssi(&info);
    true
}

/// Copy `rec` into the guest's iovec array at byte `off`.
fn scatter(iov: u64, cnt: u64, mut off: u64, rec: &[u8]) -> Result<(), i64> {
    let mut done = 0usize;
    for k in 0..cnt {
        let [base, len] = get::<[u64; 2]>(iov + k * 16)?;
        if off >= len {
            off -= len;
            continue;
        }
        let n = ((len - off) as usize).min(rec.len() - done);
        crate::guest::write(base + off, &rec[done..done + n])?;
        done += n;
        off = 0;
        if done == rec.len() {
            break;
        }
    }
    Ok(())
}

/// read, readv, preadv2(offset -1) on a signalfd: as many records as fit, the first waited
/// for unless the descriptor (or RWF_NOWAIT) is non-blocking.
pub fn read(call: &mut dyn Call, fd: i64) -> i64 {
    let a = args(call);
    let one = [a[1], a[2]];
    let (iov, cnt, flags) = match call.nr() {
        nr::READ => (one.as_ptr() as u64, 1, 0),
        nr::PREADV2 => (a[1], a[2], a[5]),
        _ => (a[1], a[2], 0),
    };
    if cnt > 1024 {
        return -e::EINVAL;
    }
    let mut total = 0u64;
    for k in 0..cnt {
        match get::<[u64; 2]>(iov + k * 16) {
            Ok([_, len]) => total = total.saturating_add(len),
            Err(e) => return e,
        }
    }
    if total < SSI as u64 {
        return -e::EINVAL;
    }
    let Some(i) = idx(fd) else { return -e::EINVAL };
    let mask = mask_of(i);
    let mut w = Waiter::new(fd, PARK_IN, call.nr());
    if flags & io::RWF_NOWAIT != 0 {
        w.nonblock = Some(true);
    }
    let mut rec = [0u8; SSI];
    let g = w.run(|| take(mask, &mut rec).then_some(0));
    let r = match g {
        Got::Done(_) => {
            let mut n = 0u64;
            loop {
                if let Err(e) = scatter(iov, cnt, n * SSI as u64, &rec) {
                    break if n == 0 { e } else { (n * SSI as u64) as i64 };
                }
                n += 1;
                if (n + 1) * SSI as u64 > total || !take(mask, &mut rec) {
                    break (n * SSI as u64) as i64;
                }
            }
        }
        g => io::result(g, -e::EAGAIN),
    };
    sync();
    w.finish(r)
}

/// `execve`: the marks of descriptors that stay open go to the new image in the slot's
/// siginfo words (nothing else writes them before the new image reads them); more than
/// `EXEC_MAX` such descriptors end the run.
pub fn before_exec() -> Result<(), ()> {
    let ts = crate::state::thread();
    let mut w = [0u64; 16];
    let mut n = 0;
    for i in 0..N {
        let mask = marks().mask[i];
        if mask == 0 {
            continue;
        }
        let fl = unsafe { sc2(nr::FCNTL, i as u64, 1) };
        if fl < 0 || fl & 1 != 0 {
            if !crate::state::in_vfork_child() {
                set(i, 0, 0);
            }
            continue;
        }
        if n == EXEC_MAX {
            return Err(());
        }
        w[2 + 2 * n] = i as u64;
        w[3 + 2 * n] = mask;
        n += 1;
    }
    if n > 0 {
        w[0] = EXEC_MAGIC;
        w[1] = n as u64;
    }
    if !crate::state::in_vfork_child() {
        publish();
    } else {
        // The child's own union (the supervisor copied the parent's at the vfork).
        let u = (0..n).fold(0, |a, k| a | w[3 + 2 * k]) & !(1 << 63);
        if u != marks().sent {
            crate::sup::call_sup(Op::SigFd, [u, 0, 0, 0, 0, 0]);
        }
    }
    unsafe { core::ptr::write_volatile(&mut (*ctl().slot(ts.slot as usize)).siginfo, w) };
    Ok(())
}

/// (New image) The marks `before_exec` carried.
pub fn after_exec() {
    let ts = crate::state::thread();
    let s = unsafe { &mut *ctl().slot(ts.slot as usize) };
    let w = unsafe { core::ptr::read_volatile(&s.siginfo) };
    if w[0] != EXEC_MAGIC {
        return;
    }
    unsafe { core::ptr::write_volatile(&mut s.siginfo[0], 0) };
    let mut u = 0;
    for k in 0..(w[1] as usize).min(EXEC_MAX) {
        let (fd, mask) = (w[2 + 2 * k] as i64, w[3 + 2 * k]);
        if let Some(i) = idx(fd) {
            let key = crate::vino::of_fd(fd).unwrap_or(fd as u64);
            set(i, mask, key);
            u |= mask & !(1 << 63);
        }
    }
    marks().sent = u;
}
