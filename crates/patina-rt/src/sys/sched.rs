//! Scheduling calls, threads and futexes: answered by the runtime and the supervisor.

use super::*;
use crate::state::config;
use crate::sys::thread;
use proto::ctl::{Op, NO_DEADLINE};

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
        nr::CLONE => {
            let [flags, stack, ptid, ctid, tls, _] = args(call);
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
