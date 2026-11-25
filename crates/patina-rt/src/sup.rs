//! The request protocol: the only way the turn moves.

use crate::raw::*;
use crate::state::{ctl, thread};
use core::sync::atomic::Ordering::*;
use proto::ctl::{
    futex_bloom_mask, Op, Reply, Request, FAST_BASE, FAST_SOLO, IPC_READY, IPC_SLEEP, IPC_SPIN,
    YIELD_OTHER,
};

unsafe fn post(op: Op, args: [u64; 6], go_init: u32) -> *mut proto::Slot {
    let ts = thread();
    let c = ctl();
    let slot = c.slot(ts.slot as usize);
    core::ptr::write_volatile(
        &mut (*slot).req,
        Request {
            op: op as u32,
            _pad: 0,
            args,
        },
    );
    (*slot).go.store(go_init, Relaxed);
    c.pending_slot.store(ts.slot, Relaxed);
    if c.sup_word.swap(IPC_READY, AcqRel) == IPC_SLEEP {
        futex_wake(&c.sup_word as *const _ as *const u32, 1);
    }
    slot
}

/// In-process fast path for self-picking `Op::Yield` (solo or multi-thread when the seeded pick
/// selects the current thread) and zero-waiter `Op::FutexWake` (verified via `Ctl::futex_bloom`).
/// Produces the exact same `RecKind::SupDecision` record, counters, and `SchedView` as the
/// supervisor without waking or context-switching to it.
#[inline]
fn try_fast_sup(op: Op, args: [u64; 6]) -> Option<Reply> {
    let c = ctl();
    let fast = c.sup_fast.load(Relaxed);
    if fast & FAST_BASE == 0 || c.config.debug != 0 {
        return None;
    }
    let seq = c.seq.load(Relaxed) + 1;
    match op {
        Op::Yield => {
            if fast & FAST_SOLO != 0 {
                // Only eligible runnable thread: both Pick and PickOther choose `idx`.
            } else if args[0] != YIELD_OTHER {
                let eligible = c.view.runnable.load(Relaxed);
                let pos = c.runnable_pos.load(Relaxed);
                if eligible <= 1 || pos >= eligible {
                    return None;
                }
                if proto::draw(c.config.seed, proto::Stream::Sched, seq) % eligible != pos {
                    return None;
                }
            } else {
                return None;
            }
        }
        Op::FutexWake => {
            let b = c.futex_bloom.load(Relaxed);
            if b != 0 {
                let m0 = futex_bloom_mask(args[0]);
                if b & m0 == m0 {
                    return None;
                }
                if args[3] != 0 {
                    let m3 = futex_bloom_mask(args[3]);
                    if b & m3 == m3 {
                        return None;
                    }
                }
            }
        }
        _ => return None,
    }
    let now = c.vclock_ns.load(Relaxed);
    if now > proto::layout::VCLOCK_BOOT_NS + c.config.vtime_limit_ns
        || now >= c.next_deadline_ns.load(Relaxed)
    {
        return None;
    }
    if c.io.waiters.load(Relaxed) != 0 && c.io.gen.load(Relaxed) != c.io_synced_gen.load(Relaxed) {
        return None;
    }
    let base = crate::state::ctl_base();
    let shadows_reclaim = unsafe {
        (*(base.add(proto::oplog::DUR_OFFSET) as *const proto::oplog::Dur))
            .shadows
            .reclaim
    };
    if shadows_reclaim != 0 {
        return None;
    }
    let wt = unsafe { proto::wire::WireTab::at(base) };
    if wt.dirty_n != 0 || wt.scan_all != 0 {
        return None;
    }
    if crate::log::over_limit() {
        return None;
    }
    if (seq & 1023) == 0 {
        outside_check();
    }
    c.seq.store(seq, Relaxed);
    let s = &c.stats.decisions;
    s.store(s.load(Relaxed) + 1, Relaxed);
    let idx = thread().slot as usize;
    let rec = proto::rec::Rec {
        seq,
        vclock_ns: now,
        slot: idx as u16,
        kind: proto::RecKind::SupDecision as u8,
        class: 0,
        nr: op as u32,
        args,
        ret: idx as i64,
        out_hash: 0,
        in_hash: 0,
    };
    crate::log::append(&rec);
    c.view.seq.store(seq, Relaxed);
    Some(Reply { ret: 0, flags: 0 })
}

/// Give the turn to the supervisor with a request; return when it gives the turn back.
/// Every blocking/lifecycle request (and periodically for hot non-blocking ops) checks for
/// real signals from outside.
pub fn call_sup(op: Op, args: [u64; 6]) -> Reply {
    if let Some(rep) = try_fast_sup(op, args) {
        return rep;
    }
    let check = crate::state::config().debug != 0
        || (ctl().seq.load(Relaxed) & 63) == 0
        || matches!(
            op,
            Op::Hello
                | Op::Sleep
                | Op::FutexWait
                | Op::Park
                | Op::WaitPark
                | Op::SigWait
                | Op::SigSuspend
                | Op::VforkStart
                | Op::ProcExit
                | Op::ThreadExit
                | Op::Exec
                | Op::Forked
                | Op::Machine
        );
    if check {
        outside_check();
    }
    call_sup_raw(op, args)
}

/// Real signals pending for this task other than SIGCHLD: every asynchronous signal is held
/// blocked in the kernel, so anything pending was sent from outside the sandbox.
/// The call is made from runtime text and does not trap.
pub fn outside_check() {
    const SIGCHLD_BIT: u64 = 1 << (17 - 1);
    let mut set: u64 = 0;
    let r = unsafe { sc2(nr::RT_SIGPENDING, &mut set as *mut u64 as u64, 8) };
    let mut set = set & !SIGCHLD_BIT;
    if crate::state::config().debug != 0 {
        set = debugger_signals(set);
    }
    if r == 0 && set != 0 {
        let sig = set.trailing_zeros() as u64 + 1;
        host_error(sig as i64, 0, proto::ctl::HE_OUTSIDE_SIGNAL);
    }
}

/// A debug session's rules for signals from outside (`Config::debug`), which the user's
/// debugger sends: the `SIGSTOP` of its attach and a `SIGCONT` after it are its own business,
/// and a `SIGINT` (its interrupt, Ctrl-C) is taken from the queue and becomes a `SIGTRAP` this
/// thread sends itself, which the debugger's helper stops on and does not pass on (a
/// `SIGSTOP` would outlive a detach and stop the process for good). The run sees neither.
/// Returns the rest of `set`.
fn debugger_signals(set: u64) -> u64 {
    const SIGINT: u64 = 2;
    const SIGSTOP: u64 = 19;
    const SIGCONT: u64 = 18;
    const SIGTRAP: u64 = 5;
    let bit = |s: u64| 1u64 << (s - 1);
    let take = set & (bit(SIGINT) | bit(SIGCONT));
    if take != 0 {
        let zero = [0u64; 2];
        let mut info = [0u64; 16];
        let ts = thread();
        unsafe {
            while sc4(
                nr::RT_SIGTIMEDWAIT,
                &take as *const u64 as u64,
                info.as_mut_ptr() as u64,
                zero.as_ptr() as u64,
                8,
            ) > 0
            {}
            if take & bit(SIGINT) != 0 {
                sc3(nr::TGKILL, ts.pid as u64, ts.tid as u64, SIGTRAP);
            }
        }
    }
    set & !bit(SIGINT) & !bit(SIGSTOP) & !bit(SIGCONT)
}

fn call_sup_raw(op: Op, args: [u64; 6]) -> Reply {
    let t0 = crate::profile::now_ns();
    // Only spin on the guest CPU when this request will likely return the turn to the same
    // thread. Blocking ops (or Yield with another runnable thread) yield the guest CPU right
    // away so the next guest thread runs without contention.
    let may_switch = matches!(
        op,
        Op::FutexWait
            | Op::Sleep
            | Op::Park
            | Op::WaitPark
            | Op::SigWait
            | Op::SigSuspend
            | Op::VforkStart
    ) || (op == Op::Yield && ctl().view.runnable.load(Relaxed) > 1);
    let spin_iters = if may_switch {
        0
    } else {
        ctl().ipc_spin.load(Relaxed)
    };
    let go_init = if spin_iters > 0 { IPC_SPIN } else { IPC_SLEEP };
    let rep = unsafe {
        let slot = post(op, args, go_init);
        let mut state = (*slot).go.load(Acquire);
        if state == IPC_SPIN {
            for _ in 0..spin_iters {
                core::hint::spin_loop();
                state = (*slot).go.load(Acquire);
                if state != IPC_SPIN {
                    break;
                }
            }
        }
        while state != IPC_READY {
            if state == IPC_SLEEP
                || (*slot)
                    .go
                    .compare_exchange(IPC_SPIN, IPC_SLEEP, AcqRel, Acquire)
                    .is_ok()
            {
                futex_wait(&(*slot).go as *const _ as *const u32, IPC_SLEEP);
            }
            state = (*slot).go.load(Acquire);
        }
        core::ptr::read_volatile(&(*slot).rep)
    };
    crate::profile::record_sup_ipc(crate::profile::now_ns().saturating_sub(t0));
    rep
}

/// Send a request the supervisor never answers (exit); the caller exits right after.
pub fn call_sup_noreply(op: Op, args: [u64; 6]) {
    unsafe {
        post(op, args, IPC_SLEEP);
    }
}

/// End the run as `unsupported`, naming the call. Never returns: the supervisor kills the sandbox.
pub fn stop(nr: u64, a0: u64) -> ! {
    ctl().stop_nr.store(nr, Relaxed);
    call_sup_raw(Op::Stop, [nr, a0, 0, 0, 0, 0]);
    hang()
}

/// End the run as `infra`. A call of the runtime's own that failed for want of a descriptor
/// is the program's use of descriptors reaching the process's limit: a named limit.
pub fn host_error(errno: i64, nr: u64, code: u64) -> ! {
    const EMFILE: i64 = 24;
    if errno == -EMFILE && (code == proto::ctl::HE_SYSCALL || code == proto::ctl::HE_RUNTIME_ASSERT)
    {
        capacity(proto::ctl::LIMIT_DESCRIPTORS, 4096);
    }
    call_sup_raw(Op::HostError, [errno as u64, nr, code, 0, 0, 0]);
    hang()
}

/// The first image cannot run (`exec::resolve` failed with `r`): the run ends `error`.
pub fn exec_failed(r: i64, why: proto::exec::Why, depth: usize) -> ! {
    call_sup_raw(
        Op::HostError,
        [
            (-r) as u64,
            why as u64,
            proto::ctl::HE_EXEC,
            depth as u64,
            0,
            0,
        ],
    );
    hang()
}

/// End the run `unsupported`, stop `capacity`: the table `limit` (`proto::ctl::LIMIT_*`)
/// holds `cap` entries the program still uses.
pub fn capacity(limit: u64, cap: u64) -> ! {
    call_sup_raw(
        Op::HostError,
        [limit, cap, proto::ctl::HE_CAPACITY, 0, 0, 0],
    );
    hang()
}

/// End the run `log-limit`: the append that would pass `Config::log_limit` is not made.
pub fn log_limit() -> ! {
    call_sup_raw(Op::HostError, [0, 0, proto::ctl::HE_LOG_LIMIT, 0, 0, 0]);
    hang()
}

/// A write to a file of the run directory failed (`r` its result): a full host filesystem
/// ends the run `disk-full`, a file size limit is a host limit, anything else a host error.
pub fn log_write_failed(r: i64, nr: u64) -> ! {
    let code = match -r {
        e::ENOSPC | e::EDQUOT => proto::ctl::HE_DISK_FULL,
        e::EFBIG => proto::ctl::HE_HOST_LIMIT,
        _ => proto::ctl::HE_SYSCALL,
    };
    host_error(r, nr, code)
}

/// End the run `unsupported`, stop `signal-context`: a signal frame would hold the context
/// record `magic`, which the runtime does not build (`proto::ctl::HE_SIGNAL_CONTEXT`).
#[allow(dead_code)]
pub fn signal_context(magic: u32) -> ! {
    call_sup_raw(
        Op::HostError,
        [magic as u64, 0, proto::ctl::HE_SIGNAL_CONTEXT, 0, 0, 0],
    );
    hang()
}

/// End the run: program code reached into the runtime (`proto::ctl::HE_CONTAINMENT`).
pub fn containment(kind: u64, addr: u64, rip: u64, store: bool) -> ! {
    call_sup_raw(
        Op::HostError,
        [kind, addr, proto::ctl::HE_CONTAINMENT, rip, store as u64, 0],
    );
    hang()
}

pub fn hang() -> ! {
    loop {
        unsafe {
            sc1(nr::EXIT_GROUP, 125);
        }
    }
}
