//! Scheduling calls, threads and futexes: answered by the runtime and the supervisor.

use super::*;
use crate::state::config;
use crate::sys::thread;
use proto::ctl::{Op, Slot, MAX_THREADS, NO_DEADLINE, SLOT_LIVE};

const FUTEX_WAIT: u64 = 0;
const FUTEX_WAKE: u64 = 1;
const FUTEX_REQUEUE: u64 = 3;
const FUTEX_CMP_REQUEUE: u64 = 4;
const FUTEX_WAKE_OP: u64 = 5;
const FUTEX_LOCK_PI: u64 = 6;
const FUTEX_UNLOCK_PI: u64 = 7;
const FUTEX_TRYLOCK_PI: u64 = 8;
const FUTEX_WAIT_BITSET: u64 = 9;
const FUTEX_WAKE_BITSET: u64 = 10;
const FUTEX_WAIT_REQUEUE_PI: u64 = 11;
const FUTEX_CMP_REQUEUE_PI: u64 = 12;
const FUTEX_LOCK_PI2: u64 = 13;
const FUTEX_CMD_MASK: u64 = 0x7f;
const FUTEX_CLOCK_REALTIME: u64 = 256;
/// `CLONE_NEWNS`, `CLONE_NEWCGROUP`, `CLONE_NEWUTS`, `CLONE_NEWIPC`, `CLONE_NEWUSER`,
/// `CLONE_NEWPID`, `CLONE_NEWNET`.
const CLONE_NEW_ANY: u64 =
    0x0002_0000 | 0x0200_0000 | 0x0400_0000 | 0x0800_0000 | 0x1000_0000 | 0x2000_0000 | 0x4000_0000;

/// Read a futex word (the caller holds the turn, so nothing can change it meanwhile).
fn word(addr: u64) -> Result<u32, i64> {
    if addr == 0 {
        return Err(-e::EFAULT);
    }
    if addr & 3 != 0 {
        return Err(-e::EINVAL);
    }
    crate::guest::get::<u32>(addr)
}

/// Count argument of a wake (an `int` in the kernel; negative means none).
fn count(v: u64) -> u64 {
    let n = v as u32 as i32;
    if n < 0 {
        0
    } else {
        n as u64
    }
}

fn futex(call: &mut dyn Call) -> i64 {
    let [uaddr, op, val, timeout, uaddr2, val3] = args(call);
    let cmd = op & FUTEX_CMD_MASK;
    let realtime = op & FUTEX_CLOCK_REALTIME != 0;
    match cmd {
        FUTEX_WAIT | FUTEX_WAIT_BITSET => {
            let bitset = if cmd == FUTEX_WAIT {
                u32::MAX
            } else {
                val3 as u32
            };
            if bitset == 0 {
                return -e::EINVAL;
            }
            let deadline = if timeout == 0 {
                NO_DEADLINE
            } else {
                let ns = match super::time::read_timespec(timeout) {
                    Ok(ns) => ns,
                    Err(e) => return e,
                };
                if cmd == FUTEX_WAIT {
                    super::time::now().saturating_add(ns) // relative
                } else if realtime {
                    super::time::realtime_to_vclock(ns) // absolute CLOCK_REALTIME
                } else {
                    ns // absolute CLOCK_MONOTONIC
                }
            };
            let cur = match word(uaddr) {
                Ok(v) => v,
                Err(e) => return e,
            };
            if cur != val as u32 {
                return -e::EAGAIN;
            }
            if deadline <= super::time::now() {
                return -e::ETIMEDOUT;
            }
            let key = super::mem::futex_key(uaddr);
            let r = crate::sup::call_sup(
                Op::FutexWait,
                [key, val as u32 as u64, deadline, bitset as u64, 0, 0],
            )
            .ret;
            if r == -e::EINTR {
                return super::sig::futex_interrupted(
                    uaddr,
                    val as u32 as u64,
                    deadline,
                    bitset as u64,
                );
            }
            r
        }
        FUTEX_WAKE | FUTEX_WAKE_BITSET => {
            let bitset = if cmd == FUTEX_WAKE {
                u32::MAX
            } else {
                val3 as u32
            };
            if bitset == 0 {
                return -e::EINVAL;
            }
            if uaddr == 0 {
                return -e::EFAULT;
            }
            crate::sup::call_sup(
                Op::FutexWake,
                [
                    super::mem::futex_key(uaddr),
                    count(val),
                    bitset as u64,
                    0,
                    0,
                    0,
                ],
            )
            .ret
        }
        FUTEX_REQUEUE | FUTEX_CMP_REQUEUE => {
            if uaddr == 0 || uaddr2 == 0 {
                return -e::EFAULT;
            }
            if cmd == FUTEX_CMP_REQUEUE {
                match word(uaddr) {
                    Ok(v) if v != val3 as u32 => return -e::EAGAIN,
                    Ok(_) => {}
                    Err(e) => return e,
                }
            }
            // The requeue count travels in the timeout argument.
            let cmp = (cmd == FUTEX_CMP_REQUEUE) as u64;
            crate::sup::call_sup(
                Op::FutexRequeue,
                [
                    super::mem::futex_key(uaddr),
                    super::mem::futex_key(uaddr2),
                    count(val),
                    count(timeout),
                    cmp,
                    0,
                ],
            )
            .ret
        }
        FUTEX_WAKE_OP => wake_op(uaddr, count(val), uaddr2, count(timeout), val3 as u32),
        FUTEX_LOCK_PI
        | FUTEX_UNLOCK_PI
        | FUTEX_TRYLOCK_PI
        | FUTEX_WAIT_REQUEUE_PI
        | FUTEX_CMP_REQUEUE_PI
        | FUTEX_LOCK_PI2 => {
            let c = ctl();
            c.note_denied(call.nr());
            c.stats
                .refusals
                .store(c.stats.refusals.load(Relaxed) + 1, Relaxed);
            set_class(call, Class::Deny(38));
            -e::ENOSYS
        }
        _ => -e::ENOSYS,
    }
}

/// `FUTEX_WAKE_OP`: change the word at `uaddr2` (under the turn, so atomically), wake
/// `n` on `uaddr` and, if the old value passes the comparison, `n2` on `uaddr2`.
fn wake_op(uaddr: u64, n: u64, uaddr2: u64, n2: u64, enc: u32) -> i64 {
    if uaddr == 0 {
        return -e::EFAULT;
    }
    let old = match word(uaddr2) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let sext12 = |v: u32| ((v << 20) as i32) >> 20;
    let op = (enc >> 28) & 0xf;
    let cmp = (enc >> 24) & 0xf;
    let mut oparg = sext12((enc >> 12) & 0xfff);
    let cmparg = sext12(enc & 0xfff);
    if op & 8 != 0 {
        if !(0..=31).contains(&oparg) {
            return -e::EINVAL;
        }
        oparg = 1 << oparg;
    }
    let oa = oparg as u32;
    let new = match op & 7 {
        0 => oa,
        1 => old.wrapping_add(oa),
        2 => old | oa,
        3 => old & !oa,
        4 => old ^ oa,
        _ => return -e::ENOSYS,
    };
    let o = old as i32;
    let pass = match cmp {
        0 => o == cmparg,
        1 => o != cmparg,
        2 => o < cmparg,
        3 => o <= cmparg,
        4 => o > cmparg,
        5 => o >= cmparg,
        _ => return -e::ENOSYS,
    };
    if let Err(r) = crate::guest::put(uaddr2, new) {
        return r;
    }
    let n2 = if pass { n2 } else { 0 };
    crate::sup::call_sup(
        Op::FutexWake,
        [
            super::mem::futex_key(uaddr),
            n,
            u32::MAX as u64,
            super::mem::futex_key(uaddr2),
            n2,
            0,
        ],
    )
    .ret
}

// ---- scheduling attributes ----
//
// The supervisor schedules every thread alike; what a program sets is kept in its slot
// (`Slot::sched`) and read back, and what the kernel refuses an unprivileged process
// (`RLIMIT_NICE` and `RLIMIT_RTPRIO` are 0) is refused: a lower nice value, a real-time or
// deadline policy, leaving `SCHED_IDLE`, clearing `SCHED_RESET_ON_FORK`.

const SCHED_OTHER: u64 = 0;
const SCHED_FIFO: u64 = 1;
const SCHED_RR: u64 = 2;
const SCHED_BATCH: u64 = 3;
const SCHED_IDLE: u64 = 5;
const SCHED_DEADLINE: u64 = 6;
const SCHED_RESET_ON_FORK: u64 = 0x4000_0000;
const PRIO_PROCESS: u64 = 0;
const PRIO_PGRP: u64 = 1;
const PRIO_USER: u64 = 2;
/// `sched_attr.sched_flags`.
const FLAG_RESET_ON_FORK: u64 = 0x01;
const FLAG_KEEP_POLICY: u64 = 0x08;
const FLAG_KEEP_PARAMS: u64 = 0x10;
const FLAG_UTIL_CLAMP: u64 = 0x60;
/// `SCHED_FLAG_ALL | SCHED_FLAG_SUGOV`: the flags the kernel knows.
const FLAGS_KNOWN: u64 = 0x7f | 0x1000_0000;
/// `struct sched_attr`: the first version's size, and the current one's.
const ATTR_VER0: u64 = 48;
const ATTR_SIZE: u64 = 56;
/// `Slot::sched`: the reset-on-fork bit.
const RESET: u64 = 1 << 16;

#[derive(Clone, Copy, PartialEq, Eq)]
struct Attr {
    nice: i64,
    policy: u64,
    reset: bool,
}

impl Attr {
    fn of(s: &Slot) -> Attr {
        let w = s.sched.load(Relaxed);
        Attr {
            nice: (w as u8 as i8) as i64,
            policy: (w >> 8) & 0xff,
            reset: w & RESET != 0,
        }
    }
    fn store(self, s: &Slot) {
        let w = (self.nice as i8 as u8 as u64) | (self.policy << 8);
        s.sched
            .store(w | if self.reset { RESET } else { 0 }, Relaxed);
    }
}

/// What a new thread or process starts with: its creator's attributes, reset-on-fork
/// cleared (nothing else is reset: no real-time policy or negative nice can be set).
pub fn inherited() -> u64 {
    own_slot().sched.load(Relaxed) & !RESET
}

fn own_slot() -> &'static Slot {
    unsafe { &*ctl().slot(crate::state::thread().slot as usize) }
}

fn slots() -> impl Iterator<Item = &'static Slot> {
    (0..MAX_THREADS)
        .map(|i| unsafe { &*ctl().slot(i) })
        .filter(|s| s.state.load(Acquire) == SLOT_LIVE)
}

/// The live thread `tid` (0: the caller), as `find_task_by_vpid`.
fn target(tid: u64) -> Option<&'static Slot> {
    if tid == 0 {
        return Some(own_slot());
    }
    slots().find(|s| s.tid.load(Relaxed) as u32 as u64 == tid)
}

/// The threads `getpriority` and `setpriority` act on.
fn prio_targets(which: u64, who: u64) -> Result<impl Iterator<Item = &'static Slot>, i64> {
    let who = who as u32 as u64;
    let pgrp = match which {
        PRIO_PROCESS | PRIO_USER => 0,
        PRIO_PGRP if who == 0 => (unsafe { sc1(nr::GETPGID, 0) }) as u64,
        PRIO_PGRP => who,
        _ => return Err(-e::EINVAL),
    };
    // Every task of the run has the sandbox's one uid.
    let uid = unsafe { sc0(nr::GETUID) } as u64;
    let own = own_slot() as *const Slot;
    Ok(slots().filter(move |s| match which {
        PRIO_PROCESS if who == 0 => core::ptr::eq(*s, own),
        PRIO_PROCESS => s.tid.load(Relaxed) as u32 as u64 == who,
        PRIO_PGRP => (unsafe { sc1(nr::GETPGID, s.pid.load(Relaxed) as u64) }) as u64 == pgrp,
        _ => who == 0 || who == uid,
    }))
}

fn getpriority(which: u64, who: u64) -> i64 {
    match prio_targets(which, who) {
        // The kernel's encoding: 20 - nice, the highest of the targets.
        Ok(t) => t.map(|s| 20 - Attr::of(s).nice).max().unwrap_or(-e::ESRCH),
        Err(r) => r,
    }
}

fn setpriority(which: u64, who: u64, nice: u64) -> i64 {
    let nice = (nice as u32 as i32 as i64).clamp(-20, 19);
    let t = match prio_targets(which, who) {
        Ok(t) => t,
        Err(r) => return r,
    };
    // As `set_one_prio`: each target in turn; a refusal is the answer unless a later
    // target succeeds after it.
    let mut r = -e::ESRCH;
    for s in t {
        let mut a = Attr::of(s);
        if nice < a.nice {
            r = -e::EACCES;
            continue;
        }
        a.nice = nice;
        a.store(s);
        if r == -e::ESRCH {
            r = 0;
        }
    }
    r
}

/// What `__sched_setscheduler` decides for an unprivileged caller, in its order, and the
/// store. `policy` None keeps the thread's policy and reset-on-fork (`sched_setparam`,
/// `SCHED_FLAG_KEEP_POLICY`).
struct Req {
    policy: Option<u64>,
    reset: bool,
    prio: u64,
    nice: i64,
    flags: u64,
    /// The deadline parameters are valid (`__checkparam_dl`).
    dl_ok: bool,
}

fn set_attr(s: &Slot, r: Req) -> i64 {
    let old = Attr::of(s);
    let (policy, reset) = match r.policy {
        Some(p) => (p, r.reset),
        None => (old.policy, old.reset),
    };
    match policy {
        SCHED_OTHER | SCHED_BATCH | SCHED_IDLE | SCHED_FIFO | SCHED_RR | SCHED_DEADLINE => {}
        _ => return -e::EINVAL,
    }
    if r.flags & !FLAGS_KNOWN != 0 {
        return -e::EINVAL;
    }
    let rt = matches!(policy, SCHED_FIFO | SCHED_RR);
    if r.prio > 99 || rt != (r.prio != 0) || (policy == SCHED_DEADLINE && !r.dl_ok) {
        return -e::EINVAL;
    }
    if rt
        || policy == SCHED_DEADLINE
        || r.nice < old.nice
        || (old.policy == SCHED_IDLE && policy != SCHED_IDLE)
        || (old.reset && !reset)
    {
        return -e::EPERM;
    }
    // Utilisation clamping answers as on a kernel built without it.
    if r.flags & FLAG_UTIL_CLAMP != 0 {
        return -e::EOPNOTSUPP;
    }
    Attr {
        nice: r.nice,
        policy,
        reset,
    }
    .store(s);
    0
}

fn setscheduler(pid: u64, policy: Option<u64>, param: u64) -> i64 {
    if param == 0 || (pid as i32) < 0 {
        return -e::EINVAL;
    }
    let prio = match crate::guest::get::<i32>(param) {
        Ok(p) => p as u32 as u64,
        Err(r) => return r,
    };
    let Some(s) = target(pid as u32 as u64) else {
        return -e::ESRCH;
    };
    let nice = Attr::of(s).nice;
    let req = |policy: Option<u64>, reset: bool| Req {
        policy,
        reset,
        prio,
        nice,
        flags: 0,
        dl_ok: false,
    };
    match policy {
        Some(p) if (p as i32) < 0 => -e::EINVAL,
        Some(p) => set_attr(
            s,
            req(Some(p & !SCHED_RESET_ON_FORK), p & SCHED_RESET_ON_FORK != 0),
        ),
        None => set_attr(s, req(None, false)),
    }
}

fn setattr(pid: u64, uattr: u64, flags: u64) -> i64 {
    if uattr == 0 || (pid as i32) < 0 || flags != 0 {
        return -e::EINVAL;
    }
    let size = match crate::guest::get::<u32>(uattr) {
        Ok(0) => ATTR_VER0,
        Ok(v) => v as u64,
        Err(r) => return r,
    };
    let mut b = [0u8; ATTR_SIZE as usize];
    let big = !(ATTR_VER0..=4096).contains(&size) || {
        let n = size.min(ATTR_SIZE) as usize;
        if let Err(r) = crate::guest::read(uattr, &mut b[..n]) {
            return r;
        }
        // Bytes past the structure this kernel knows must be zero.
        (ATTR_SIZE..size).any(|o| crate::guest::get::<u8>(uattr + o) != Ok(0))
    };
    if big {
        // The kernel writes the size it knows back.
        return match put(uattr, ATTR_SIZE as u32) {
            Ok(()) => -e::E2BIG,
            Err(r) => r,
        };
    }
    let u32_at = |o: usize| u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]) as u64;
    let u64_at = |o: usize| u32_at(o) | (u32_at(o + 4) << 32);
    let policy = u32_at(4);
    let aflags = u64_at(8);
    let nice = (u32_at(16) as u32 as i32 as i64).clamp(-20, 19);
    let prio = u32_at(20);
    let (runtime, deadline, period) = (u64_at(24), u64_at(32), u64_at(40));
    if aflags & FLAG_UTIL_CLAMP != 0 && size < ATTR_SIZE {
        return -e::EINVAL;
    }
    if (policy as u32 as i32) < 0 {
        return -e::EINVAL;
    }
    let Some(s) = target(pid as u32 as u64) else {
        return -e::ESRCH;
    };
    let keep_params = aflags & FLAG_KEEP_PARAMS != 0;
    set_attr(
        s,
        Req {
            policy: (aflags & FLAG_KEEP_POLICY == 0).then_some(policy),
            reset: aflags & FLAG_RESET_ON_FORK != 0,
            prio: if keep_params { 0 } else { prio },
            nice: if keep_params { Attr::of(s).nice } else { nice },
            flags: aflags,
            // `__checkparam_dl`, without its bounds on the period (all refused anyway).
            dl_ok: deadline != 0
                && runtime >= 1 << 10
                && runtime <= deadline
                && (period == 0 || period >= deadline),
        },
    )
}

fn getattr(pid: u64, uattr: u64, usize: u64, flags: u64) -> i64 {
    if uattr == 0 || (pid as i32) < 0 || !(ATTR_VER0..=4096).contains(&usize) || flags != 0 {
        return -e::EINVAL;
    }
    let Some(s) = target(pid as u32 as u64) else {
        return -e::ESRCH;
    };
    let a = Attr::of(s);
    let n = usize.min(ATTR_SIZE);
    let mut b = [0u8; ATTR_SIZE as usize];
    b[0..4].copy_from_slice(&(n as u32).to_le_bytes());
    b[4..8].copy_from_slice(&(a.policy as u32).to_le_bytes());
    let f = if a.reset { FLAG_RESET_ON_FORK } else { 0 };
    b[8..16].copy_from_slice(&f.to_le_bytes());
    b[16..20].copy_from_slice(&(a.nice as i32).to_le_bytes());
    crate::guest::write(uattr, &b[..n as usize])
        .err()
        .unwrap_or(0)
}

fn scheduling(call: &mut dyn Call) -> i64 {
    let [a0, a1, a2, a3, ..] = args(call);
    match call.nr() {
        nr::GETPRIORITY => getpriority(a0, a1),
        nr::SETPRIORITY => setpriority(a0, a1, a2),
        nr::SCHED_GETSCHEDULER => {
            if (a0 as i32) < 0 {
                return -e::EINVAL;
            }
            match target(a0 as u32 as u64) {
                Some(s) => {
                    let a = Attr::of(s);
                    (a.policy | if a.reset { SCHED_RESET_ON_FORK } else { 0 }) as i64
                }
                None => -e::ESRCH,
            }
        }
        nr::SCHED_GETPARAM => {
            if a1 == 0 || (a0 as i32) < 0 {
                return -e::EINVAL;
            }
            match target(a0 as u32 as u64) {
                // No real-time policy can be set: the static priority is 0.
                Some(_) => put(a1, 0i32).err().unwrap_or(0),
                None => -e::ESRCH,
            }
        }
        nr::SCHED_SETSCHEDULER => setscheduler(a0, Some(a1), a2),
        nr::SCHED_SETPARAM => setscheduler(a0, None, a1),
        nr::SCHED_SETATTR => setattr(a0, a1, a2),
        _ => getattr(a0, a1, a2, a3),
    }
}

pub fn handle(call: &mut dyn Call) -> Action {
    let r = match call.nr() {
        nr::SCHED_YIELD => {
            crate::sup::call_sup(Op::Yield, [0; 6]);
            0
        }
        nr::SCHED_GETAFFINITY => {
            let (len, mask) = (call.arg(1), call.arg(2));
            if len < 8 || len % 8 != 0 {
                -e::EINVAL
            } else if mask == 0 {
                -e::EFAULT
            } else {
                let n = config().cpu_count.clamp(1, 64);
                let bits = if n == 64 { u64::MAX } else { (1u64 << n) - 1 };
                match put(mask, bits) {
                    Ok(()) => 8,
                    Err(r) => r,
                }
            }
        }
        nr::SCHED_SETAFFINITY => 0,
        nr::GETCPU => {
            let one = |p: u64| if p != 0 { put(p, 0u32) } else { Ok(()) };
            one(call.arg(0))
                .and_then(|()| one(call.arg(1)))
                .err()
                .unwrap_or(0)
        }
        nr::FUTEX => futex(call),
        nr::GETPRIORITY
        | nr::SETPRIORITY
        | nr::SCHED_GETSCHEDULER
        | nr::SCHED_SETSCHEDULER
        | nr::SCHED_GETPARAM
        | nr::SCHED_SETPARAM
        | nr::SCHED_GETATTR
        | nr::SCHED_SETATTR => scheduling(call),
        nr::CLONE => {
            let [mut flags, stack, ptid, ctid, tls] = crate::arch::clone_args(args(call));
            // New namespaces belong to the sandbox, not the guest: EPERM, as `unshare` answers
            // (`CLONE_NEWTIME` is not among them: in `clone` that bit is the exit signal's).
            if flags & CLONE_NEW_ANY != 0 {
                let c = ctl();
                c.note_denied(call.nr());
                c.stats
                    .refusals
                    .store(c.stats.refusals.load(Relaxed) + 1, Relaxed);
                set_class(call, Class::Deny(e::EPERM as i32));
                return Action::Return(-e::EPERM);
            }
            // The kernel ignores a parent-tid pointer it cannot write; one into the runtime's
            // region reads as such (the kernel must not store the tid there).
            if flags & thread::CLONE_PARENT_SETTID != 0 && crate::guest::in_region(ptid, 4) {
                flags &= !thread::CLONE_PARENT_SETTID;
            }
            // Threads here; fork (no CLONE_VM) and vfork (CLONE_VM|CLONE_VFORK): processes.
            if flags & thread::CLONE_VM == 0 || flags & super::proc::CLONE_VFORK != 0 {
                return super::proc::clone_process(call, flags, stack, ptid, ctid, tls);
            }
            let accepted = thread::THREAD_FLAGS
                | thread::CLONE_SETTLS
                | thread::CLONE_PARENT_SETTID
                | thread::CLONE_CHILD_CLEARTID
                | thread::CLONE_CHILD_SETTID
                | thread::CLONE_DETACHED;
            if flags & thread::THREAD_FLAGS != thread::THREAD_FLAGS
                || flags & !accepted != 0
                || super::proc::in_vfork()
            {
                return stop_here(call);
            }
            let r = thread::clone_vm(call, flags, stack, ptid, ctid, tls);
            if r == i64::MIN {
                return Action::NeedsFrame;
            }
            r
        }
        nr::EXIT => thread::exit(call),
        _ => return stop_here(call),
    };
    Action::Return(r)
}
