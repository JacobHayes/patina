//! Threads: creation by the frame-copy trampoline, exit with the emulated
//! clear-tid, and reclamation of slots and alternate stacks.
//!
//! Creation. The parent holds the turn. It reclaims what earlier threads of this
//! process left behind, takes the lowest free slot, prepares the child's runtime
//! state at the base of a new alternate stack, copies its own trap frame to the top
//! of that stack (patching `rax`, `rsp`, the FP-state pointer and `uc_stack`), and
//! makes the real `clone` with the guest's flags, a start stack inside the new
//! alternate stack, and the kernel's clear-tid pointed at the child's runtime tid
//! word. The child installs its alternate stack, sleeps on its slot until the
//! supervisor gives it the turn, says `Hello`, performs the guest's
//! `CLONE_CHILD_SETTID` store, and `rt_sigreturn`s into guest code. The parent tells
//! the supervisor with `Forked` and returns the tid.
//!
//! Exit. The runtime stores 0 to the guest's clear-tid word and the supervisor
//! wakes one waiter on it (both as part of `ThreadExit`), then the real `exit`
//! runs without a reply. The slot and the alternate stack are reused only after the
//! kernel has cleared the runtime tid word, which the next `clone` in this process
//! waits for on a real futex.

use super::*;
use crate::state::{ctl, proc, thread, ThreadState};
use crate::trap::TrapFrame;
use core::arch::global_asm;
use proto::ctl::{Op, MAX_THREADS, SLOT_EXITING, SLOT_FREE, SLOT_RESERVED};
use proto::layout::ALT_SIZE;

pub const CLONE_VM: u64 = 0x100;
pub const CLONE_FS: u64 = 0x200;
pub const CLONE_FILES: u64 = 0x400;
pub const CLONE_SIGHAND: u64 = 0x800;
pub const CLONE_THREAD: u64 = 0x10000;
pub const CLONE_SYSVSEM: u64 = 0x40000;
pub const CLONE_SETTLS: u64 = 0x80000;
pub const CLONE_PARENT_SETTID: u64 = 0x100000;
pub const CLONE_CHILD_CLEARTID: u64 = 0x200000;
pub const CLONE_CHILD_SETTID: u64 = 0x1000000;
/// Ignored by the kernel for threads (musl's `pthread_create` passes it).
pub const CLONE_DETACHED: u64 = 0x400000;

/// The flag set of a thread (glibc, Rust std, Go, musl all pass exactly this, plus tid/TLS flags).
pub const THREAD_FLAGS: u64 =
    CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM;

global_asm!(
    // patina_clone_vm(flags, stack, ptid, ctid, tls, uc2): the real clone, through the syscall
    // stub. The child starts on `stack` (inside its own alternate stack), where the stub's `ret`
    // finds `patina_clone_child` and then `uc2`; it calls thread_start(uc2) and never returns
    // here or touches the parent's stacks. The parent returns from the stub to the caller.
    ".globl patina_clone_vm",
    "patina_clone_vm:",
    "  lea rax, [rip + patina_clone_child]",
    "  mov [rsi - 16], rax",
    "  mov [rsi - 8], r9",
    "  sub rsi, 16",
    "  mov r10, rcx",
    "  mov eax, 56",
    "  jmp patina_syscall",
    "patina_clone_child:",
    "  pop rdi",
    "  and rsp, -16",
    "  call {start}",
    "  ud2",
    // patina_sigreturn_to(uc): rt_sigreturn with the frame at `uc`.
    ".globl patina_sigreturn_to",
    "patina_sigreturn_to:",
    "  mov rsp, rdi",
    "  mov eax, 15",
    "  jmp patina_syscall",
    start = sym thread_start,
);

extern "C" {
    fn patina_clone_vm(flags: u64, stack: u64, ptid: u64, ctid: u64, tls: u64, uc2: u64) -> i64;
    fn patina_sigreturn_to(uc: u64) -> !;
}

/// Enter guest code with the frame at `uc` (`rt_sigreturn`).
pub fn sigreturn_to(uc: u64) -> ! {
    unsafe { patina_sigreturn_to(uc) }
}

/// An alternate stack for a new thread: a reclaimed one, or a fresh mapping.
pub fn alloc_altstack() -> u64 {
    let p = proc();
    if p.nalt_free > 0 {
        p.nalt_free -= 1;
        return p.alt_free[p.nalt_free];
    }
    crate::state::new_alt_stack()
}

/// Return slots (and their alternate stacks) of threads of this process that have
/// exited. Waits on each runtime tid word until the kernel has cleared it: then the
/// task is gone and nothing runs on that stack any more.
pub fn reclaim() {
    let c = ctl();
    let p = proc();
    let own = thread() as *mut ThreadState as u64;
    for i in 0..MAX_THREADS {
        let alt = p.alt_of_slot[i];
        if alt == 0 || alt == own {
            continue;
        }
        let s = unsafe { &*c.slot(i) };
        if s.state.load(Acquire) != SLOT_EXITING {
            continue;
        }
        let w = unsafe { &(*(alt as *const ThreadState)).ktid } as *const u32;
        loop {
            let v = unsafe { core::ptr::read_volatile(w) };
            if v == 0 {
                break;
            }
            unsafe { futex_wait(w, v) };
        }
        p.alt_of_slot[i] = 0;
        p.alt_free[p.nalt_free] = alt;
        p.nalt_free += 1;
        s.state.store(SLOT_FREE, Release);
    }
}

/// Lowest free slot (slots are a function of history: creations are serialised under the turn).
pub fn take_slot() -> Option<usize> {
    let c = ctl();
    (0..MAX_THREADS).find(|&i| unsafe { (*c.slot(i)).state.load(Acquire) } == SLOT_FREE)
}

/// Copy the trap frame at `uc` to the top of the alternate stack `alt` (from the restorer
/// slot below the ucontext to the top), patching `rax = 0`, the FP-state pointer, `uc_stack`
/// and, if `stack` is not 0, `rsp`. Returns (the copy, the stack the child starts on).
pub fn copy_frame(uc: u64, alt: u64, stack: u64) -> (u64, u64) {
    let top = alt + ALT_SIZE;
    let own_top = (uc & !(ALT_SIZE - 1)) + ALT_SIZE;
    let lo = uc - 8;
    let delta = top - own_top;
    unsafe {
        core::ptr::copy_nonoverlapping(
            lo as *const u8,
            (lo + delta) as *mut u8,
            (own_top - lo) as usize,
        )
    };
    let uc2 = unsafe { &mut *((uc + delta) as *mut TrapFrame) };
    if uc2.fpstate != 0 {
        uc2.fpstate += delta;
    }
    uc2.ss_sp = alt;
    uc2.ss_flags = 0;
    uc2.ss_size = ALT_SIZE;
    uc2.gregs[crate::trap::reg::RAX] = 0;
    if stack != 0 {
        uc2.gregs[crate::trap::reg::RSP] = stack;
    }
    let start = (lo + delta - 512) & !15;
    (uc + delta, start)
}

/// The real clone on the trampoline: the child starts in `thread_start(uc2)` on `start`.
pub fn raw_clone_vm(flags: u64, start: u64, ptid: u64, ctid: u64, tls: u64, uc2: u64) -> i64 {
    unsafe { patina_clone_vm(flags, start, ptid, ctid, tls, uc2) }
}

/// `clone` with `CLONE_VM`: the trampoline. Returns the child's tid or -errno.
pub fn clone_vm(
    call: &mut dyn Call,
    flags: u64,
    stack: u64,
    ptid: u64,
    ctid: u64,
    tls: u64,
) -> i64 {
    let (parent_vmask, pid) = {
        let ts = call.thread();
        (ts.vmask, ts.pid)
    };
    let Some(frame) = call.frame() else {
        return i64::MIN;
    };
    let uc = frame as *mut TrapFrame as u64;
    reclaim();
    let Some(slot) = take_slot() else {
        return -e::EAGAIN;
    };
    let alt = alloc_altstack();
    // Child runtime state at the base of its alternate stack.
    unsafe {
        let mut t = ThreadState::new(slot as u32, 0, pid, parent_vmask);
        // a new thread starts with no alternate stack (SS_DISABLE) and nothing pending
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
    let (uc2, start) = copy_frame(uc, alt, stack);
    let c = ctl();
    let s = unsafe { &*c.slot(slot) };
    s.go.store(0, SeqCst);
    s.tid.store(0, Relaxed);
    s.pid.store(pid, Relaxed);
    // The child inherits the virtual mask; its pending word is set by the supervisor at `Forked`.
    s.vmask.store(parent_vmask, Relaxed);
    s.sigpend.store(0, Relaxed);
    s.state.store(SLOT_RESERVED, SeqCst);
    let kflags = (flags & !(CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID)) | CLONE_CHILD_CLEARTID;
    let ktid = unsafe { &(*(alt as *const ThreadState)).ktid } as *const u32 as u64;
    let r = unsafe { patina_clone_vm(kflags, start, ptid, ktid, tls, uc2) };
    if r < 0 {
        s.state.store(SLOT_FREE, SeqCst);
        free_altstack(alt);
        host_check(call, r);
        return r;
    }
    proc().alt_of_slot[slot] = alt;
    crate::sup::call_sup(
        Op::Forked,
        [
            slot as u64,
            r as u64,
            pid as u64,
            proto::ctl::FORKED_THREAD,
            0,
            0,
        ],
    );
    r
}

/// Return an alternate stack nobody runs on any more to the free list.
pub fn free_altstack(alt: u64) {
    let p = proc();
    p.alt_free[p.nalt_free] = alt;
    p.nalt_free += 1;
}

/// First code of a new thread, on its own alternate stack. Must not trap and must
/// not touch shared runtime state until it holds the turn.
extern "C" fn thread_start(uc2: *mut TrapFrame) -> ! {
    let alt = (uc2 as u64) & !(ALT_SIZE - 1);
    unsafe {
        // CLONE_VM without CLONE_VFORK cleared the kernel's alternate stack in the child.
        let st: [u64; 3] = [alt, 0, ALT_SIZE];
        if sc2(nr::SIGALTSTACK, st.as_ptr() as u64, 0) != 0 {
            sc1(nr::EXIT_GROUP, 126);
        }
    }
    let ts = thread();
    ts.tid = unsafe { sc0(nr::GETTID) } as i32;
    if ts.vfork != 0 {
        // A vfork child: the parent handed it the turn with the clone.
        crate::sys::proc::vfork_child_start(uc2 as u64);
    }
    let s = unsafe { &*ctl().slot(ts.slot as usize) };
    while s.go.load(Acquire) == 0 {
        unsafe { futex_wait(&s.go as *const _ as *const u32, 0) };
    }
    // Holding the turn from here on.
    crate::sup::call_sup(
        Op::Hello,
        [
            ts.pid as u64,
            ts.tid as u64,
            proto::ctl::HELLO_THREAD,
            0,
            0,
            0,
        ],
    );
    if ts.child_settid != 0 {
        // As the kernel: a pointer it cannot write is ignored (and never runtime memory).
        let _ = crate::guest::put(ts.child_settid, ts.tid);
    }
    crate::pmu::open(ts);
    crate::pmu::exit(ts, unsafe { (*uc2).gregs[crate::trap::reg::RIP] }, 0);
    unsafe { patina_sigreturn_to(uc2 as u64) }
}

/// `exit`: end this thread. The guest's stack may already be unmapped (glibc frees a
/// detached thread's stack before calling exit): only the alternate stack is used.
pub fn exit(call: &mut dyn Call) -> ! {
    let a = args(call);
    let status = a[0] & 0xff;
    crate::oplog::on_exit();
    let row = proto::row(nr::EXIT as u32);
    crate::log::trap(row, nr::EXIT, &a, 0);
    let ts = thread();
    let clear = ts.clear_tid;
    if clear != 0 {
        // As the kernel: a pointer it cannot write is ignored (and never runtime memory).
        let _ = crate::guest::put(clear, 0u32);
    }
    crate::pmu::close(ts);
    crate::sup::call_sup_noreply(Op::ThreadExit, [status, clear, 0, 0, 0, 0]);
    loop {
        unsafe { sc1(nr::EXIT, status) };
    }
}
