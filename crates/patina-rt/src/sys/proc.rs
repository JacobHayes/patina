//! Process identity, exit, limits; and fork, vfork, wait, process groups.
//!
//! fork: the parent holds the turn, picks the child's slot (lowest free) and writes it into
//! its own memory, makes the real fork, and announces the child (`Forked`). The child, a copy
//! of the runtime in the middle of the same trap, takes that slot, forgets the parent's other
//! threads, sleeps on the slot until the supervisor gives it the turn, says `Hello` and
//! returns 0 from the trap.
//!
//! vfork: the thread trampoline (`thread::copy_frame`) with `CLONE_VM|CLONE_VFORK`. The parent
//! sends `VforkStart` (the supervisor parks it but it keeps the turn), clears its `go` word and
//! makes the real clone, blocking in the kernel; the child holds the turn from its first
//! instruction. The kernel releases the parent when the child execs or exits; the parent then
//! sleeps on `go` like any thread without the turn, and the supervisor makes it runnable only
//! at the child's post-exec `Hello` or exit barrier. The child shares the parent's memory, so
//! it writes no per-process runtime table (`ThreadState::vfork`).

use super::thread::{CLONE_CHILD_CLEARTID, CLONE_CHILD_SETTID, CLONE_PARENT_SETTID, CLONE_VM};
use super::*;
use crate::state::{ctl, proc, thread, ThreadState};
use proto::ctl::{
    Op, FORKED_PROCESS, HELLO_FORK, MAX_THREADS, SLOT_FREE, SLOT_RESERVED, WAIT_PARK, WAIT_REAPED,
};

pub const CLONE_VFORK: u64 = 0x4000;
const CSIGNAL: u64 = 0xff;
const SIGCHLD: u64 = 17;
const WNOHANG: u64 = 1;
const WNOWAIT: u64 = 0x0100_0000;

/// Is the calling thread a vfork child?
pub fn in_vfork() -> bool {
    crate::state::in_vfork_child()
}

/// `clone` without `CLONE_VM` (fork) or with `CLONE_VM|CLONE_VFORK` (vfork), `fork`, `vfork`.
pub fn clone_process(
    call: &mut dyn Call,
    flags: u64,
    stack: u64,
    ptid: u64,
    ctid: u64,
    _tls: u64,
) -> Action {
    let sig = flags & CSIGNAL;
    let tids = CLONE_PARENT_SETTID | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID;
    let rest = flags & !CSIGNAL & !tids;
    // A fork or vfork child that is not reported by SIGCHLD (or 0) is not supported;
    // so is fork/vfork from a vfork child (it would share its parent's memory).
    if (sig != SIGCHLD && sig != 0) || in_vfork() {
        return stop_here(call);
    }
    let r = if rest == 0 {
        fork(call, flags, stack, ptid, ctid)
    } else if rest == CLONE_VM | CLONE_VFORK {
        vfork(call, flags, stack, ptid, ctid)
    } else {
        return stop_here(call);
    };
    if r == i64::MIN {
        return Action::NeedsFrame;
    }
    Action::Return(r)
}

fn reserve(slot: usize, vmask: u64) {
    let s = unsafe { &*ctl().slot(slot) };
    s.go.store(0, SeqCst);
    s.tid.store(0, Relaxed);
    s.pid.store(0, Relaxed);
    s.vmask.store(vmask, Relaxed);
    s.sigpend.store(0, Relaxed);
    s.state.store(SLOT_RESERVED, SeqCst);
}

fn release(slot: usize) {
    let s = unsafe { &*ctl().slot(slot) };
    s.state.store(SLOT_FREE, SeqCst);
}

fn fork(call: &mut dyn Call, flags: u64, stack: u64, ptid: u64, ctid: u64) -> i64 {
    let vmask = call.thread().vmask;
    if call.frame().is_none() {
        return i64::MIN;
    }
    super::thread::reclaim();
    let Some(slot) = super::thread::take_slot() else {
        return -e::EAGAIN;
    };
    reserve(slot, vmask);
    proc().fork_slot = slot as u64;
    let kflags = flags & (CSIGNAL | CLONE_PARENT_SETTID);
    let r = unsafe { sc6(nr::CLONE, kflags, 0, ptid, 0, 0, 0) };
    if r < 0 {
        release(slot);
        host_check(call, r);
        return r;
    }
    if r == 0 {
        return fork_child(call, flags, stack, ctid);
    }
    crate::sup::call_sup(
        Op::Forked,
        [
            slot as u64,
            r as u64,
            r as u64,
            FORKED_PROCESS,
            flags & CSIGNAL,
            0,
        ],
    );
    r
}

/// The child of a fork, still inside the parent's trap (in its own copy of everything).
fn fork_child(call: &mut dyn Call, flags: u64, stack: u64, ctid: u64) -> i64 {
    let slot = proc().fork_slot as usize;
    if stack != 0 {
        if let Some(f) = call.frame() {
            f.set_sp(stack);
        }
    }
    let ts = thread();
    ts.slot = slot as u32;
    ts.tid = unsafe { sc0(nr::GETTID) } as i32;
    ts.pid = unsafe { sc0(nr::GETPID) } as i32;
    ts.ktid = 1;
    unsafe { sc1(nr::SET_TID_ADDRESS, &ts.ktid as *const u32 as u64) };
    ts.clear_tid = if flags & CLONE_CHILD_CLEARTID != 0 {
        ctid
    } else {
        0
    };
    ts.child_settid = if flags & CLONE_CHILD_SETTID != 0 {
        ctid
    } else {
        0
    };
    // Only this thread exists in the child: the other threads' alternate stacks are
    // copies nobody runs on, free for reuse.
    let p = proc();
    let own = ts as *mut ThreadState as u64;
    let mut others = [0u64; MAX_THREADS];
    let mut nothers = 0;
    for i in 0..MAX_THREADS {
        let a = p.alt_of_slot[i];
        p.alt_of_slot[i] = 0;
        if a != 0 && a != own {
            super::thread::free_altstack(a);
            others[nothers] = a;
            nothers += 1;
        }
    }
    p.alt_of_slot[slot] = own;
    p.asid = slot as u64;
    let s = unsafe { &*ctl().slot(slot) };
    while s.go.load(Acquire) == 0 {
        unsafe { futex_wait(&s.go as *const _ as *const u32, 0) };
    }
    // Holding the turn from here on.
    crate::sup::call_sup(
        Op::Hello,
        [ts.pid as u64, ts.tid as u64, HELLO_FORK, 0, 0, 0],
    );
    if ts.child_settid != 0 {
        // As the kernel: a pointer it cannot write is ignored (and never runtime memory).
        let _ = crate::guest::put(ts.child_settid, ts.tid);
    }
    // The inherited counters count the parent's threads: replace them.
    crate::pmu::fork_child(ts, &others[..nothers]);
    // The child's own boundary event for the return of the call.
    crate::entry::charge(ts);
    0
}

fn vfork(call: &mut dyn Call, flags: u64, stack: u64, ptid: u64, ctid: u64) -> i64 {
    let (vmask, valt, own_slot) = {
        let ts = call.thread();
        (ts.vmask, ts.valt, ts.slot)
    };
    let Some(frame) = call.frame() else {
        return i64::MIN;
    };
    let uc = frame as *mut crate::arch::Frame as u64;
    super::thread::reclaim();
    let Some(slot) = super::thread::take_slot() else {
        return -e::EAGAIN;
    };
    let alt = super::thread::alloc_altstack();
    unsafe {
        let mut t = ThreadState::new(slot as u32, 0, 0, vmask);
        t.vfork = 1;
        t.valt = valt; // CLONE_VM|CLONE_VFORK keeps the alternate stack
        t.vf_sigact = proc().sigact;
        t.clear_tid = if flags & CLONE_CHILD_CLEARTID != 0 {
            ctid
        } else {
            0
        };
        t.child_settid = if flags & CLONE_CHILD_SETTID != 0 {
            ctid
        } else {
            0
        };
        *(alt as *mut ThreadState) = t;
    }
    let (uc2, start) = super::thread::copy_frame(uc, alt, stack);
    reserve(slot, vmask);
    // Parks this thread in the supervisor (it is "in vfork"); the reply keeps the turn here.
    crate::sup::call_sup(Op::VforkStart, [slot as u64, 0, 0, 0, 0, 0]);
    let me = unsafe { &*ctl().slot(own_slot as usize) };
    me.go.store(0, SeqCst);
    let kflags = CLONE_VM | CLONE_VFORK | (flags & (CSIGNAL | CLONE_PARENT_SETTID));
    let r = crate::arch::clone_vm(kflags, start, ptid, 0, 0, uc2);
    if r < 0 {
        // The child never ran: this thread still holds the turn.
        release(slot);
        super::thread::free_altstack(alt);
        crate::sup::call_sup(Op::VforkStart, [slot as u64, 1, 0, 0, 0, 0]);
        host_check(call, r);
        return r;
    }
    // The kernel let this thread go: the child has exec'd or exited. Nothing may be touched
    // until the supervisor gives the turn back (other threads of this process may run).
    while me.go.load(Acquire) == 0 {
        unsafe { futex_wait(&me.go as *const _ as *const u32, 0) };
    }
    // The child no longer uses this address space: its alternate stack is free.
    super::thread::free_altstack(alt);
    r
}

/// First code of a vfork child after `thread::thread_start` (own alternate stack installed).
/// It holds the turn already.
pub fn vfork_child_start(uc2: u64) -> ! {
    let ts = thread();
    ts.pid = unsafe { sc0(nr::GETPID) } as i32;
    crate::sup::call_sup(
        Op::Hello,
        [
            ts.pid as u64,
            ts.tid as u64,
            proto::ctl::HELLO_VFORK,
            0,
            0,
            0,
        ],
    );
    if ts.child_settid != 0 {
        // As the kernel: a pointer it cannot write is ignored (and never runtime memory).
        let _ = crate::guest::put(ts.child_settid, ts.tid);
    }
    crate::compute::exit(ts);
    crate::arch::sigreturn_to(uc2)
}

/// Status word to report for a reaped child: the supervisor's record of a virtual signal death.
fn reaped(pid: i64, really: bool, real: i32) -> i32 {
    let v = crate::sup::call_sup(
        Op::WaitPark,
        [
            WAIT_REAPED,
            pid as u64,
            really as u64,
            real as u32 as u64,
            0,
            0,
        ],
    )
    .ret;
    if v >= 0 {
        v as i32
    } else {
        real
    }
}

fn wait4(call: &mut dyn Call) -> i64 {
    let [pid, ustatus, options, urusage, ..] = args(call);
    loop {
        let mut st: i32 = 0;
        let r = unsafe {
            sc4(
                nr::WAIT4,
                pid,
                &mut st as *mut i32 as u64,
                options | WNOHANG,
                0,
            )
        };
        if r > 0 {
            let st = reaped(r, true, st);
            if ustatus != 0 {
                if let Err(e) = put(ustatus, st) {
                    return e;
                }
            }
            if urusage != 0 {
                if let Err(e) = put(urusage, [0u64; 18]) {
                    return e;
                }
            }
            return r;
        }
        if r < 0 || options & WNOHANG != 0 {
            return r;
        }
        let rep = crate::sup::call_sup(Op::WaitPark, [WAIT_PARK, 0, 0, 0, 0, 0]).ret;
        if rep < 0 {
            return rep;
        }
    }
}

fn waitid(call: &mut dyn Call) -> i64 {
    let [idtype, id, infop, options, urusage, ..] = args(call);
    loop {
        let mut info = [0u64; 16];
        let r = unsafe {
            sc6(
                nr::WAITID,
                idtype,
                id,
                info.as_mut_ptr() as u64,
                options | WNOHANG,
                0,
                0,
            )
        };
        if r < 0 {
            return r;
        }
        let cpid = info[2] as u32 as i32;
        if cpid != 0 || options & WNOHANG != 0 {
            if cpid != 0 {
                const CLD_EXITED: u64 = 1;
                const CLD_KILLED: u64 = 2;
                let code = info[1] as u32 as u64;
                let status = info[3] as u32 as i32;
                if code == CLD_EXITED || code == CLD_KILLED {
                    let real = if code == CLD_EXITED {
                        (status & 0xff) << 8
                    } else {
                        status & 0x7f
                    };
                    let w = reaped(cpid as i64, options & WNOWAIT == 0, real);
                    if w & 0x7f != 0 {
                        info[1] = CLD_KILLED;
                        info[3] = (w & 0x7f) as u64;
                    } else {
                        info[1] = CLD_EXITED;
                        info[3] = ((w >> 8) & 0xff) as u64;
                    }
                }
                info[4] = 0; // si_utime
                info[5] = 0; // si_stime
            }
            if infop != 0 {
                if let Err(e) = put(infop, info) {
                    return e;
                }
            }
            if urusage != 0 {
                if let Err(e) = put(urusage, [0u64; 18]) {
                    return e;
                }
            }
            return 0;
        }
        let rep = crate::sup::call_sup(Op::WaitPark, [WAIT_PARK, 0, 0, 0, 0, 0]).ret;
        if rep < 0 {
            return rep;
        }
    }
}

const RLIM_INFINITY: u64 = u64::MAX;
const RLIMIT_STACK: u64 = 3;
const RLIMIT_NOFILE: u64 = 7;
const RLIM_NLIMITS: u64 = 16;

fn rlimit(res: u64) -> Result<[u64; 2], i64> {
    match res {
        RLIMIT_STACK => Ok([8 << 20, RLIM_INFINITY]),
        RLIMIT_NOFILE => Ok([1024, 2048]),
        r if r < RLIM_NLIMITS => Ok([RLIM_INFINITY, RLIM_INFINITY]),
        _ => Err(-e::EINVAL),
    }
}

fn exit(call: &mut dyn Call, row: &'static proto::Row) -> ! {
    let a = args(call);
    let status = a[0] & 0xff;
    crate::oplog::on_exit();
    crate::log::trap(row, call, 0);
    crate::sup::call_sup_noreply(Op::ProcExit, [status, 0, 0, 0, 0, 0]);
    unsafe {
        sc1(nr::EXIT_GROUP, status);
    }
    crate::sup::hang()
}

pub fn handle(call: &mut dyn Call) -> Action {
    let nr = call.nr();
    let r = match nr {
        nr::GETPID
        | nr::GETPPID
        | nr::GETTID
        | nr::GETUID
        | nr::GETEUID
        | nr::GETGID
        | nr::GETEGID => raw(call),
        // The UTS namespace starts as a copy of the host's: its NIS domain name reads as
        // a fixed "(none)" (the sandbox cannot set it: bwrap's user namespace is nested, so the
        // UTS namespace is not the sandbox's to change).
        nr::UNAME => {
            let r = raw(call);
            if r == 0 {
                let p = call.arg(0) + 5 * 65;
                let v = b"(none)\0";
                unsafe { core::ptr::write_bytes(p as *mut u8, 0, 65) };
                unsafe { core::ptr::copy_nonoverlapping(v.as_ptr(), p as *mut u8, v.len()) };
            }
            r
        }
        // Process groups and sessions: the kernel's.
        nr::SETPGID | nr::GETPGRP | nr::SETSID | nr::GETPGID | nr::GETSID => raw(call),
        nr::FORK => return clone_process(call, SIGCHLD, 0, 0, 0, 0),
        nr::VFORK => return clone_process(call, CLONE_VM | CLONE_VFORK | SIGCHLD, 0, 0, 0, 0),
        nr::EXECVE | nr::EXECVEAT => return crate::exec::execve(call),
        nr::WAIT4 => wait4(call),
        nr::WAITID => waitid(call),
        nr::EXIT_GROUP => exit(call, proto::row(nr as u32)),
        nr::SET_TID_ADDRESS => {
            let a0 = call.arg(0);
            let ts = call.thread();
            ts.clear_tid = a0;
            ts.tid as i64
        }
        nr::SET_ROBUST_LIST => {
            if call.arg(1) != 24 {
                -e::EINVAL
            } else {
                let (h, l) = (call.arg(0), call.arg(1));
                call.thread().robust = [h, l];
                0
            }
        }
        nr::PRLIMIT64 => {
            let [pid, res, _new, old, ..] = args(call);
            let own = call.thread().pid as u64;
            if pid != 0 && pid != own {
                crate::sys::stop_here(call);
            }
            match rlimit(res) {
                Ok(v) => {
                    if old != 0 {
                        put(old, v).map(|_| 0).unwrap_or_else(|e| e)
                    } else {
                        0
                    }
                }
                Err(e) => e,
            }
        }
        nr::GETRLIMIT => rlimit(call.arg(0))
            .and_then(|v| put(call.arg(1), v))
            .map(|_| 0)
            .unwrap_or_else(|e| e),
        nr::SETRLIMIT => rlimit(call.arg(0)).map(|_| 0).unwrap_or_else(|e| e),
        nr::ARCH_PRCTL => match call.arg(0) {
            0x1001..=0x1004 => raw(call),
            _ => {
                set_class(call, Class::Virt);
                -e::EINVAL
            }
        },
        nr::PRCTL => match call.arg(0) {
            15 | 16 | 3 | 0x5356_4d41 => raw(call),
            // instruction channels: the timestamp-counter mode is virtual (the real one stays SIGSEGV).
            25 => {
                set_class(call, Class::Virt);
                match put::<u32>(call.arg(1), crate::insn::tsc::virtual_mode()) {
                    Ok(()) => 0,
                    Err(e) => e,
                }
            }
            26 => {
                set_class(call, Class::Virt);
                match crate::insn::tsc::set_virtual_mode(call.arg(1)) {
                    true => 0,
                    false => -e::EINVAL,
                }
            }
            // PR_SET_PDEATHSIG, PR_GET_PDEATHSIG: virtual.
            1 => {
                let sig = call.arg(1);
                set_class(call, Class::Virt);
                if sig > 64 {
                    -e::EINVAL
                } else {
                    crate::sup::call_sup(
                        Op::SigAction,
                        [0, proto::ctl::SIGACT_PDEATHSIG, sig, 0, 0, 0],
                    )
                    .ret
                }
            }
            2 => {
                set_class(call, Class::Virt);
                let v = crate::sup::call_sup(
                    Op::SigAction,
                    [0, proto::ctl::SIGACT_PDEATHSIG + 1, 0, 0, 0, 0],
                )
                .ret;
                put(call.arg(1), v as i32).map(|_| 0).unwrap_or_else(|e| e)
            }
            // PR_SET_CHILD_SUBREAPER: orphans always go to the supervisor (PID 1).
            36 => {
                set_class(call, Class::Virt);
                -e::EINVAL
            }
            // Any other option: refused (EINVAL, as for an unknown option).
            o => refuse_request(call, b"prctl", o, false, -e::EINVAL),
        },
        _ => return stop_here(call),
    };
    Action::Return(r)
}
