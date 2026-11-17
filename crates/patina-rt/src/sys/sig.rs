//! Signals: virtual dispositions, masks, the alternate stack, sending, waiting,
//! interval timers, and the trap-exit delivery loop. The kernel-level mask and handlers
//! stay the runtime's; guest handlers are entered only through frames built
//! by `crate::sigframe` at a trap exit of the receiving thread.
//!
//! State: dispositions are per process in runtime memory (`Proc::sigact`); the supervisor
//! is told the kind of a disposition (default, ignore, handler) when it changes, because it
//! decides whether a sent signal is discarded and whether it interrupts a park. The mask is
//! per thread (`ThreadState::vmask`, mirrored into the slot for the supervisor). Pending
//! sets and queues are supervisor state; the slot's `sigpend` word lets the runtime test
//! "anything deliverable?" at every trap exit without a round trip.

use super::*;
use crate::sigframe;
use crate::state::{ctl, thread, ThreadState};
use crate::trap::{reg::*, TrapFrame};
use proto::ctl::{Op, NO_DEADLINE, REP_DELIVER_MASK, SIGK_DEFAULT, SIGK_HANDLER, SIGK_IGNORE};

pub const SIGILL: u64 = 4;
pub const SIGTRAP: u64 = 5;
pub const SIGBUS: u64 = 7;
pub const SIGFPE: u64 = 8;
pub const SIGKILL: u64 = 9;
pub const SIGSEGV: u64 = 11;
pub const SIGPIPE: u64 = 13;
pub const SIGSTOP: u64 = 19;
pub const SIGTSTP: u64 = 20;
pub const SIGTTIN: u64 = 21;
pub const SIGTTOU: u64 = 22;
pub const SIGXFSZ: u64 = 25;
pub const SIGSYS: u64 = 31;

pub const SA_NOCLDSTOP: u64 = 1;
pub const SA_NOCLDWAIT: u64 = 2;
pub const SA_SIGINFO: u64 = 4;
pub const SA_ONSTACK: u64 = 0x0800_0000;
pub const SA_RESTART: u64 = 0x1000_0000;
pub const SA_NODEFER: u64 = 0x4000_0000;
pub const SA_RESETHAND: u64 = 0x8000_0000;
pub const SA_RESTORER: u64 = 0x0400_0000;
/// Flags the kernel keeps (`UAPI_SA_FLAGS` on x86_64); others read back as 0.
const SA_KNOWN: u64 = SA_NOCLDSTOP
    | SA_NOCLDWAIT
    | SA_SIGINFO
    | SA_ONSTACK
    | SA_RESTART
    | SA_NODEFER
    | SA_RESETHAND
    | SA_RESTORER;

pub const SIG_DFL: u64 = 0;
pub const SIG_IGN: u64 = 1;

pub const SS_ONSTACK: u64 = 1;
pub const SS_DISABLE: u64 = 2;
pub const SS_AUTODISARM: u64 = 1 << 31;
const MINSIGSTKSZ: u64 = 2048;

pub const SI_USER: i32 = 0;
pub const SI_TKILL: i32 = -6;

pub const fn bit(sig: u64) -> u64 {
    1 << (sig - 1)
}
pub const UNBLOCKABLE: u64 = bit(SIGKILL) | bit(SIGSTOP);

/// The kernel's internal restart codes. A handler returns one of these when its call was
/// interrupted by a signal; the trap exit turns it into `EINTR` or a restart.
pub const ERESTARTSYS: i64 = 512;
pub const ERESTARTNOINTR: i64 = 513;
pub const ERESTARTNOHAND: i64 = 514;
pub const ERESTART_RESTARTBLOCK: i64 = 516;

/// Restart blocks (`ThreadState::restart[0]`).
pub const RB_NONE: u64 = 0;
/// [_, deadline, rem pointer]
pub const RB_SLEEP: u64 = 1;
/// [_, uaddr, val, deadline, bitset]
pub const RB_FUTEX: u64 = 2;

/// Default action of a signal.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Default {
    Terminate,
    Ignore,
    Stop,
}

pub fn default_action(sig: u64) -> Default {
    if proto::ctl::sig_default_ignored(sig) {
        Default::Ignore
    } else {
        match sig {
            SIGSTOP | SIGTSTP | SIGTTIN | SIGTTOU => Default::Stop,
            _ => Default::Terminate,
        }
    }
}

/// The kind of a disposition, as the supervisor needs it.
fn kind(sig: u64, handler: u64) -> u64 {
    match handler {
        SIG_IGN => SIGK_IGNORE,
        SIG_DFL if default_action(sig) == Default::Ignore => SIGK_IGNORE,
        SIG_DFL => SIGK_DEFAULT,
        _ => SIGK_HANDLER,
    }
}

fn slot_of(ts: &ThreadState) -> &'static proto::Slot {
    unsafe { &*ctl().slot(ts.slot as usize) }
}

/// Set the thread's virtual mask (SIGKILL and SIGSTOP cannot be blocked).
pub fn set_vmask(ts: &mut ThreadState, m: u64) {
    ts.vmask = m & !UNBLOCKABLE;
    slot_of(ts).vmask.store(ts.vmask, Relaxed);
}

/// Change a disposition; tell the supervisor when its kind changed.
pub fn set_action(sig: u64, act: [u64; 4]) {
    let t = crate::state::sigact();
    let old = kind(sig, t[sig as usize][0]);
    let old_reap = sig == SIGCHLD && autoreap(&t[sig as usize]);
    t[sig as usize] = act;
    let new = kind(sig, act[0]);
    if sig == SIGCHLD {
        // Auto-reaping (SIGCHLD ignored, or SA_NOCLDWAIT) is the kernel's: the real
        // disposition mirrors it, with no handler, and SIGCHLD stays blocked for real.
        let reap = autoreap(&act);
        let real: [u64; 4] = [
            if act[0] == SIG_IGN { SIG_IGN } else { SIG_DFL },
            SA_RESTORER | (act[1] & SA_NOCLDWAIT),
            crate::entry::restorer(),
            0,
        ];
        unsafe { sc4(nr::RT_SIGACTION, SIGCHLD, real.as_ptr() as u64, 0, 8) };
        if old != new || old_reap != reap {
            crate::sup::call_sup(Op::SigAction, [sig, new, reap as u64, 0, 0, 0]);
        }
        return;
    }
    if old != new {
        crate::sup::call_sup(Op::SigAction, [sig, new, 0, 0, 0, 0]);
    }
}

pub const SIGCHLD: u64 = 17;

fn autoreap(act: &[u64; 4]) -> bool {
    act[0] == SIG_IGN
        || (act[0] != SIG_DFL && act[1] & SA_NOCLDWAIT != 0)
        || (act[0] == SIG_DFL && act[1] & SA_NOCLDWAIT != 0)
}

fn sigaction(call: &mut dyn Call) -> i64 {
    let [sig, act, oact, size, ..] = args(call);
    if size != 8 || sig == 0 || sig > 64 {
        return -e::EINVAL;
    }
    if act != 0 && (sig == SIGKILL || sig == SIGSTOP) {
        return -e::EINVAL;
    }
    let old = crate::state::sigact()[sig as usize];
    let new = if act != 0 {
        match get::<[u64; 4]>(act) {
            Ok(mut v) => {
                v[1] &= SA_KNOWN;
                v[3] &= !UNBLOCKABLE;
                Some(v)
            }
            Err(e) => return e,
        }
    } else {
        None
    };
    if oact != 0 {
        if let Err(e) = put(oact, old) {
            return e;
        }
    }
    if let Some(v) = new {
        set_action(sig, v);
    }
    0
}

fn sigprocmask(call: &mut dyn Call) -> i64 {
    let [how, set, oset, size, ..] = args(call);
    if size != 8 {
        return -e::EINVAL;
    }
    let ts = call.thread();
    let old = ts.vmask;
    if set != 0 {
        let s = match get::<u64>(set) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let m = match how {
            0 => old | s,
            1 => old & !s,
            2 => s,
            _ => return -e::EINVAL,
        };
        set_vmask(ts, m);
    }
    if oset != 0 {
        if let Err(e) = put(oset, old) {
            set_vmask(ts, old);
            return e;
        }
    }
    0
}

/// `__on_sig_stack`: is `sp` inside the virtual alternate stack?
fn in_altstack(valt: &[u64; 3], sp: u64) -> bool {
    sp > valt[0] && sp - valt[0] <= valt[2]
}

/// `on_sig_stack`: as above, except that an `SS_AUTODISARM` stack never counts.
pub fn on_sig_stack(valt: &[u64; 3], sp: u64) -> bool {
    valt[1] & SS_AUTODISARM == 0 && in_altstack(valt, sp)
}

/// `sas_ss_flags`.
pub fn sas_ss_flags(valt: &[u64; 3], sp: u64) -> u64 {
    if valt[2] == 0 {
        SS_DISABLE
    } else if on_sig_stack(valt, sp) {
        SS_ONSTACK
    } else {
        0
    }
}

/// `do_sigaltstack`'s set half: validate and store `[sp, flags, size]`.
pub fn set_altstack(ts: &mut ThreadState, v: [u64; 3], sp: u64) -> i64 {
    if on_sig_stack(&ts.valt, sp) {
        return -e::EPERM;
    }
    let flags = v[1] & 0xffff_ffff;
    let mode = flags & !SS_AUTODISARM;
    if mode != SS_DISABLE && mode != SS_ONSTACK && mode != 0 {
        return -e::EINVAL;
    }
    if mode == SS_DISABLE {
        ts.valt = [0, flags, 0];
    } else {
        if v[2] < MINSIGSTKSZ {
            return -e::ENOMEM;
        }
        ts.valt = [v[0], flags, v[2]];
    }
    0
}

fn sigaltstack(call: &mut dyn Call) -> i64 {
    let [ss, oss, ..] = args(call);
    let sp = match call.frame() {
        Some(f) => f.gregs[RSP],
        None => return i64::MIN,
    };
    let ts = call.thread();
    let old = [
        ts.valt[0],
        sas_ss_flags(&ts.valt, sp) | (ts.valt[1] & SS_AUTODISARM),
        ts.valt[2],
    ];
    if ss != 0 {
        let v = match get::<[u64; 3]>(ss) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let r = set_altstack(ts, v, sp);
        if r != 0 {
            return r;
        }
    }
    if oss != 0 {
        if let Err(e) = put(oss, old) {
            return e;
        }
    }
    0
}

/// A kernel `siginfo_t` as 16 words.
pub type SigInfo = [u64; 16];

pub fn siginfo(sig: u64, code: i32, pid: i32, uid: u32) -> SigInfo {
    let mut i = [0u64; 16];
    i[0] = sig; // si_signo, si_errno = 0
    i[1] = code as u32 as u64;
    i[2] = pid as u32 as u64 | (uid as u64) << 32;
    i
}

fn uid() -> u32 {
    unsafe { sc0(nr::GETUID) as u32 }
}

/// A `SigSend` with `info` in the caller's slot.
fn send(mode: u64, pid: i64, tid: i64, sig: u64, info: &SigInfo) -> i64 {
    let ts = thread();
    unsafe { core::ptr::write_volatile(&mut (*ctl().slot(ts.slot as usize)).siginfo, *info) };
    crate::sup::call_sup(Op::SigSend, [mode, pid as u64, tid as u64, sig, 0, 0]).ret
}

/// A signal the kernel raises for the calling thread itself (`SIGPIPE` on `EPIPE` from a
/// wire socket): thread-directed, as `send_sig` does.
pub fn raise_thread(sig: u64) {
    let ts = thread();
    let info = siginfo(sig, SI_USER, ts.pid, uid());
    send(
        proto::ctl::SIGSEND_TGKILL,
        ts.pid as i64,
        ts.tid as i64,
        sig,
        &info,
    );
}

fn kill(call: &mut dyn Call) -> i64 {
    let [pid, sig, ..] = args(call);
    let (pid, sig) = (pid as i32 as i64, sig as i32 as i64);
    if !(0..=64).contains(&sig) {
        return -e::EINVAL;
    }
    let own = call.thread().pid as i64;
    let info = siginfo(sig as u64, SI_USER, own as i32, uid());
    // Other processes, groups and kill(-1) are resolved by the supervisor from its
    // process table (groups read back from the kernel).
    match pid {
        p if p > 0 => send(proto::ctl::SIGSEND_PROC, p, 0, sig as u64, &info),
        0 => {
            let pgid = unsafe { sc1(nr::GETPGID, 0) };
            send(proto::ctl::SIGSEND_PGRP, pgid, 0, sig as u64, &info)
        }
        -1 => send(proto::ctl::SIGSEND_ALL, 0, 0, sig as u64, &info),
        p => send(proto::ctl::SIGSEND_PGRP, -p, 0, sig as u64, &info),
    }
}

/// `tgkill(tgid, tid, sig)`, or `tkill(tid, sig)` when `tgid` is None.
fn tgkill(call: &mut dyn Call, tgid: Option<i64>, tid: i64, sig: i64) -> i64 {
    if tid <= 0 || tgid.is_some_and(|g| g <= 0) || !(0..=64).contains(&sig) {
        return -e::EINVAL;
    }
    let own = call.thread().pid;
    let info = siginfo(sig as u64, SI_TKILL, own, uid());
    match tgid {
        None => send(proto::ctl::SIGSEND_TKILL, 0, tid, sig as u64, &info),
        Some(g) => send(proto::ctl::SIGSEND_TGKILL, g, tid, sig as u64, &info),
    }
}

/// `rt_sigqueueinfo` / `rt_tgsigqueueinfo`: the guest's own siginfo, as the kernel takes it.
fn sigqueue(call: &mut dyn Call, tgid: i64, tid: i64, sig: i64, uinfo: u64) -> i64 {
    if !(1..=64).contains(&sig) {
        return -e::EINVAL;
    }
    if tid != 0 && (tid <= 0 || tgid <= 0) {
        return -e::EINVAL;
    }
    let mut info = match get::<SigInfo>(uinfo) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let code = info[1] as u32 as i32;
    let own = call.thread().pid as i64;
    if (code >= 0 || code == SI_TKILL) && tgid != own {
        return -e::EPERM;
    }
    info[0] = (info[0] & !0xffff_ffff) | sig as u64;
    if tid == 0 {
        send(proto::ctl::SIGSEND_PROC, tgid, 0, sig as u64, &info)
    } else {
        send(proto::ctl::SIGSEND_TGKILL, tgid, tid, sig as u64, &info)
    }
}

fn sigpending(call: &mut dyn Call) -> i64 {
    let [set, size, ..] = args(call);
    if size > 8 {
        return -e::EINVAL;
    }
    let ts = call.thread();
    let p = slot_of(ts).sigpend.load(Relaxed) & ts.vmask;
    let b = p.to_le_bytes();
    crate::guest::write(set, &b[..size as usize])
        .err()
        .unwrap_or(0)
}

fn sigtimedwait(call: &mut dyn Call) -> i64 {
    let [uset, uinfo, uts, size, ..] = args(call);
    if size != 8 {
        return -e::EINVAL;
    }
    let set = match get::<u64>(uset) {
        Ok(v) => v & !UNBLOCKABLE,
        Err(e) => return e,
    };
    let deadline = if uts == 0 {
        NO_DEADLINE
    } else {
        match super::time::read_timespec(uts) {
            Ok(ns) => super::time::now().saturating_add(ns),
            Err(e) => return e,
        }
    };
    let ts = call.thread();
    let r = crate::sup::call_sup(Op::SigWait, [set, deadline, 0, 0, 0, 0]).ret;
    if r > 0 {
        if uinfo != 0 {
            let info =
                unsafe { core::ptr::read_volatile(&(*ctl().slot(ts.slot as usize)).siginfo) };
            if let Err(e) = put(uinfo, info) {
                return e;
            }
        }
        r
    } else if r == 0 {
        -e::EAGAIN
    } else {
        -e::EINTR
    }
}

/// `rt_sigsuspend` and `pause`: park until a signal is deliverable; the handler's frame
/// saves the old mask (`has_saved`).
fn suspend(call: &mut dyn Call, new: Option<u64>) -> i64 {
    let ts = call.thread();
    if let Some(m) = new {
        ts.saved_mask = ts.vmask;
        ts.has_saved = 1;
        set_vmask(ts, m);
    }
    if slot_of(ts).sigpend.load(Relaxed) & !ts.vmask == 0 {
        crate::sup::call_sup(Op::SigSuspend, [0; 6]);
    }
    -ERESTARTNOHAND
}

const NS: u64 = 1_000_000_000;

/// `ITIMER_REAL`: returns the old [value ns, interval ns].
fn timer_set(value: u64, interval: u64, query: bool) -> [u64; 2] {
    let ts = thread();
    crate::sup::call_sup(Op::TimerSet, [0, value, interval, query as u64, 0, 0]);
    let w = unsafe { core::ptr::read_volatile(&(*ctl().slot(ts.slot as usize)).siginfo) };
    [w[0], w[1]]
}

fn timeval(ns: u64) -> [u64; 2] {
    [ns / NS, (ns % NS) / 1000]
}

fn read_itimerval(p: u64) -> Result<[u64; 2], i64> {
    let [is, ius, vs, vus] = get::<[i64; 4]>(p)?;
    let ok = |s: i64, us: i64| s >= 0 && (0..1_000_000).contains(&us);
    if !ok(is, ius) || !ok(vs, vus) {
        return Err(-e::EINVAL);
    }
    Ok([
        vs as u64 * NS + vus as u64 * 1000,
        is as u64 * NS + ius as u64 * 1000,
    ])
}

fn itimer(call: &mut dyn Call) -> i64 {
    let nr = call.nr();
    let which = call.arg(0) as i32;
    match which {
        0 => {}
        1 | 2 => {
            stop_here(call);
        }
        _ => return -e::EINVAL,
    }
    let (newp, oldp) = if nr == nr::SETITIMER {
        (call.arg(1), call.arg(2))
    } else {
        (0, call.arg(1))
    };
    let old = if nr == nr::SETITIMER {
        let new = if newp == 0 {
            [0, 0]
        } else {
            match read_itimerval(newp) {
                Ok(v) => v,
                Err(e) => return e,
            }
        };
        timer_set(new[0], new[1], false)
    } else {
        timer_set(0, 0, true)
    };
    if oldp != 0 {
        let [iv, ius] = timeval(old[1]);
        let [vs, vus] = timeval(old[0]);
        if let Err(e) = put(oldp, [iv, ius, vs, vus]) {
            return e;
        }
    }
    0
}

fn alarm(secs: u64) -> i64 {
    let secs = secs as u32 as u64;
    let old = timer_set(secs * NS, 0, false)[0];
    let (s, rem) = (old / NS, old % NS);
    // The kernel rounds: half a second or more counts as one, and a pending timer is never 0.
    (if rem >= NS / 2 || (s == 0 && rem != 0) {
        s + 1
    } else {
        s
    }) as i64
}

/// A sleep interrupted by a signal: write the remaining time and set the restart block.
pub fn sleep_interrupted(deadline: u64, rem: u64, absolute: bool) -> i64 {
    if absolute {
        return -ERESTARTNOHAND;
    }
    let left = deadline.saturating_sub(super::time::now());
    if rem != 0 {
        let _ = put(rem, [left / NS, left % NS]);
    }
    thread().restart = [RB_SLEEP, deadline, rem, 0, 0];
    -ERESTART_RESTARTBLOCK
}

/// A futex wait interrupted by a signal.
pub fn futex_interrupted(uaddr: u64, val: u64, deadline: u64, bitset: u64) -> i64 {
    if deadline == NO_DEADLINE {
        return -ERESTARTSYS;
    }
    thread().restart = [RB_FUTEX, uaddr, val, deadline, bitset];
    -ERESTART_RESTARTBLOCK
}

/// `restart_syscall`: continue what a signal without a handler interrupted.
fn restart_syscall(call: &mut dyn Call) -> i64 {
    let rb = call.thread().restart;
    call.thread().restart = [RB_NONE; 5];
    match rb[0] {
        RB_SLEEP => {
            let r = crate::sup::call_sup(Op::Sleep, [rb[1], 0, 0, 0, 0, 0]).ret;
            if r == -e::EINTR {
                sleep_interrupted(rb[1], rb[2], false)
            } else {
                r
            }
        }
        RB_FUTEX => {
            let cur = match crate::guest::get::<u32>(rb[1]) {
                Ok(v) => v,
                Err(r) => return r,
            };
            if cur != rb[2] as u32 {
                return -e::EAGAIN;
            }
            if rb[3] <= super::time::now() {
                return -e::ETIMEDOUT;
            }
            let r = crate::sup::call_sup(
                Op::FutexWait,
                [super::mem::futex_key(rb[1]), rb[2], rb[3], rb[4], 0, 0],
            )
            .ret;
            if r == -e::EINTR {
                futex_interrupted(rb[1], rb[2], rb[3], rb[4])
            } else {
                r
            }
        }
        _ => -e::EINTR,
    }
}

pub fn handle(call: &mut dyn Call) -> Action {
    let a = args(call);
    let r = match call.nr() {
        nr::RT_SIGACTION => sigaction(call),
        nr::RT_SIGPROCMASK => sigprocmask(call),
        nr::SIGALTSTACK => sigaltstack(call),
        nr::RT_SIGRETURN => match call.frame() {
            Some(f) => sigframe::sigreturn(f, thread()),
            None => return Action::NeedsFrame,
        },
        nr::KILL => kill(call),
        nr::TKILL => tgkill(call, None, a[0] as i32 as i64, a[1] as i32 as i64),
        nr::TGKILL => tgkill(
            call,
            Some(a[0] as i32 as i64),
            a[1] as i32 as i64,
            a[2] as i32 as i64,
        ),
        nr::RT_SIGQUEUEINFO => sigqueue(call, a[0] as i32 as i64, 0, a[1] as i32 as i64, a[2]),
        nr::RT_TGSIGQUEUEINFO => sigqueue(
            call,
            a[0] as i32 as i64,
            a[1] as i32 as i64,
            a[2] as i32 as i64,
            a[3],
        ),
        nr::RT_SIGPENDING => sigpending(call),
        nr::RT_SIGTIMEDWAIT => sigtimedwait(call),
        nr::RT_SIGSUSPEND => {
            if a[1] != 8 {
                -e::EINVAL
            } else {
                match get::<u64>(a[0]) {
                    Ok(m) => suspend(call, Some(m)),
                    Err(e) => e,
                }
            }
        }
        nr::PAUSE => suspend(call, None),
        nr::ALARM => alarm(a[0]),
        nr::GETITIMER | nr::SETITIMER => itimer(call),
        nr::RESTART_SYSCALL => restart_syscall(call),
        _ => return stop_here(call),
    };
    if r == i64::MIN {
        return Action::NeedsFrame;
    }
    Action::Return(r)
}

/// Is `r` one of the internal restart codes?
fn is_restart(r: i64) -> bool {
    matches!(
        -r,
        ERESTARTSYS | ERESTARTNOINTR | ERESTARTNOHAND | ERESTART_RESTARTBLOCK
    )
}

/// The kernel's restart class of a call that parks in the supervisor and was woken by a
/// signal. Those parks (blocking I/O's blocking I/O, waits) answer plain `EINTR`; this gives the code
/// the kernel would have returned instead. `poll`/`select` restart with their full timeout
/// when no handler runs (the kernel uses a restart block with the remaining time); the epoll
/// waits are never restarted (`signal(7)`).
fn restart_class(nr: u64) -> Option<i64> {
    match nr {
        // read, write, pread64, pwrite64, readv, writev, connect, accept, sendto, recvfrom,
        // sendmsg, recvmsg, wait4, fcntl (F_SETLKW), flock, accept4, preadv, pwritev,
        // recvmmsg, sendmmsg, waitid, preadv2, pwritev2, open/openat (FIFO)
        nr::READ
        | nr::WRITE
        | nr::PREAD64
        | nr::PWRITE64
        | nr::READV
        | nr::WRITEV
        | nr::CONNECT
        | nr::ACCEPT
        | nr::SENDTO
        | nr::RECVFROM
        | nr::SENDMSG
        | nr::RECVMSG
        | nr::WAIT4
        | nr::FCNTL
        | nr::FLOCK
        | nr::ACCEPT4
        | nr::PREADV
        | nr::PWRITEV
        | nr::RECVMMSG
        | nr::SENDMMSG
        | nr::WAITID
        | nr::PREADV2
        | nr::PWRITEV2
        | nr::OPEN
        | nr::OPENAT => Some(ERESTARTSYS),
        // poll, select, pselect6, ppoll
        nr::POLL | nr::SELECT | nr::PSELECT6 | nr::PPOLL => Some(ERESTARTNOHAND),
        _ => None,
    }
}

/// A handler is about to run: an interrupted call returns `EINTR` or restarts (`SA_RESTART`).
fn resolve_for_handler(frame: &mut TrapFrame, nr: u64, flags: u64) {
    let r = frame.gregs[RAX] as i64;
    if !is_restart(r) {
        return;
    }
    let restart = match -r {
        ERESTARTNOINTR => true,
        ERESTARTSYS => flags & SA_RESTART != 0,
        _ => false,
    };
    if restart {
        frame.gregs[RAX] = nr;
        frame.gregs[RIP] -= 2;
    } else {
        frame.gregs[RAX] = (-e::EINTR) as u64;
    }
}

/// No handler ran: an interrupted call restarts (through `restart_syscall` when it has a
/// restart block).
fn resolve_without_handler(frame: &mut TrapFrame, nr: u64) {
    let r = frame.gregs[RAX] as i64;
    if !is_restart(r) {
        return;
    }
    frame.gregs[RAX] = if -r == ERESTART_RESTARTBLOCK {
        nr::RESTART_SYSCALL
    } else {
        nr
    };
    frame.gregs[RIP] -= 2;
}

/// End the process as killed by `sig` (default action "terminate").
pub fn die(sig: u64) -> ! {
    crate::sup::call_sup_noreply(Op::ProcExit, [128 + sig, sig, 0, 0, 0, 0]);
    unsafe {
        sc1(nr::EXIT_GROUP, 128 + sig);
    }
    crate::sup::hang()
}

/// Act on one dequeued signal. Returns true if a handler frame was built.
pub fn act_on(
    frame: &mut TrapFrame,
    ts: &mut ThreadState,
    sig: u64,
    info: &SigInfo,
    nr: Option<u64>,
    fault: bool,
) -> bool {
    let act = crate::state::sigact()[sig as usize];
    match act[0] {
        SIG_IGN => false,
        SIG_DFL => match default_action(sig) {
            Default::Ignore => false,
            Default::Stop => crate::sup::stop(nr.unwrap_or(0), sig),
            Default::Terminate => die(sig),
        },
        _ => {
            if let Some(nr) = nr {
                resolve_for_handler(frame, nr, act[1]);
            }
            sigframe::deliver(frame, ts, sig, info, act, fault);
            true
        }
    }
}

/// The trap exit: deliver every deliverable signal (each new frame nests on the previous
/// one, as the kernel's exit-to-user loop does), then resolve an interrupted call that
/// ran no handler. `nr` is the syscall that trapped (None for faults, emulated
/// instructions and `rt_sigreturn`).
pub fn trap_exit(frame: &mut TrapFrame, nr: Option<u64>) {
    let ts = thread();
    let nr = nr.filter(|&n| n != nr::RT_SIGRETURN);
    if let Some(code) = nr.and_then(restart_class) {
        if frame.gregs[RAX] as i64 == -e::EINTR {
            frame.gregs[RAX] = (-code) as u64;
        }
    }
    let mut handled = false;
    loop {
        let slot = slot_of(ts);
        if slot.sigpend.load(Relaxed) & !ts.vmask == 0 {
            break;
        }
        let rep = crate::sup::call_sup(Op::SigTake, [ts.vmask, 0, 0, 0, 0, 0]);
        let sig = rep.flags & REP_DELIVER_MASK;
        if sig == 0 {
            break;
        }
        let info = unsafe { core::ptr::read_volatile(&slot.siginfo) };
        handled |= act_on(frame, ts, sig, &info, nr, false);
    }
    if !handled {
        if let Some(nr) = nr {
            resolve_without_handler(frame, nr);
        }
        if ts.has_saved != 0 {
            ts.has_saved = 0;
            set_vmask(ts, ts.saved_mask);
        }
    }
}
