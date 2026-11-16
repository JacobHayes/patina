//! Process entry, the trap entry (`trap`, the SIGSYS handler), the fault
//! entry (timestamp-counter emulation, guest faults), and the seccomp filter.

use crate::raw::*;
use crate::state::*;
use crate::trap::{reg::*, Action, TrapCall, TrapFrame};
use core::arch::global_asm;
use core::sync::atomic::Ordering::*;
use proto::ctl::Op;
use proto::layout::*;
use proto::{draw, Stream};

global_asm!(
    ".section .text.entry,\"ax\"",
    ".globl _start",
    "_start:",
    "  mov rdi, rsp",
    "  and rsp, -16",
    "  call {start}",
    "  ud2",
    ".text",
    ".globl patina_restorer",
    "patina_restorer:",
    "  mov eax, 15",
    "  syscall",
    "  ud2",
    // switch_stack(top, ksp, f): run f(ksp) on a new stack
    ".globl patina_switch_stack",
    "patina_switch_stack:",
    "  mov rsp, rdi",
    "  mov rdi, rsi",
    "  call rdx",
    "  ud2",
    // enter_guest(sp, entry): clean registers, jump
    ".globl patina_enter_guest",
    "patina_enter_guest:",
    "  mov rsp, rdi",
    "  mov rax, rsi",
    "  xor ebx, ebx", "xor ecx, ecx", "xor edx, edx", "xor esi, esi", "xor edi, edi", "xor ebp, ebp",
    "  xor r8d, r8d", "xor r9d, r9d", "xor r10d, r10d", "xor r11d, r11d",
    "  xor r12d, r12d", "xor r13d, r13d", "xor r14d, r14d", "xor r15d, r15d",
    "  jmp rax",
    start = sym rt_start,
);

extern "C" {
    fn patina_restorer();
    fn patina_switch_stack(top: u64, ksp: u64, f: extern "C" fn(u64) -> !) -> !;
    pub fn patina_enter_guest(sp: u64, entry: u64) -> !;
}

use crate::fault::on_fault;
use crate::sys::sig::{
    bit, SA_NODEFER, SA_ONSTACK, SA_RESTORER, SA_SIGINFO, SIGBUS, SIGFPE, SIGILL, SIGPIPE, SIGSEGV,
    SIGSYS, SIGTRAP, SIGXFSZ,
};

/// Signals that are never in a guest thread's kernel mask: SIGSYS and the fault signals,
/// which have the runtime's handlers, and SIGPIPE and SIGXFSZ, whose real disposition is
/// "ignore" (a blocked signal is never discarded as ignored, so they must stay unblocked).
pub const OPEN_SIGNALS: u64 = bit(SIGSYS)
    | bit(SIGSEGV)
    | bit(SIGILL)
    | bit(SIGBUS)
    | bit(SIGFPE)
    | bit(SIGTRAP)
    | bit(SIGPIPE)
    | bit(SIGXFSZ);

/// The real mask of every guest thread, constant: checked at every trap exit.
/// (The kernel never keeps SIGKILL and SIGSTOP in a mask.)
pub const REAL_MASK: u64 = !OPEN_SIGNALS & !crate::sys::sig::UNBLOCKABLE;

/// The invariant that the kernel-level mask never changes.
pub fn check_real_mask(frame: &TrapFrame) {
    if frame.sigmask != REAL_MASK {
        crate::sup::host_error(frame.sigmask as i64, 0, proto::ctl::HE_REAL_MASK);
    }
}

/// The runtime's signal restorer (for real `rt_sigaction` calls made by handlers).
pub fn restorer() -> u64 {
    patina_restorer as *const () as u64
}

extern "C" fn rt_start(ksp: u64) -> ! {
    // Map the first alternate stack and continue on it, so that thread state
    // is found by masking the stack pointer from here on.
    let alt = new_alt_stack();
    unsafe { patina_switch_stack(alt + ALT_SIZE - 64, ksp, rt_main) }
}

extern "C" fn rt_main(ksp: u64) -> ! {
    let ts = thread();
    *ts = ThreadState::new(
        u32::MAX,
        unsafe { sc0(nr::GETTID) } as i32,
        unsafe { sc0(nr::GETPID) } as i32,
        0,
    );
    // The kernel clears the runtime's tid word when this task is gone (thread reclamation).
    unsafe { sc1(nr::SET_TID_ADDRESS, &ts.ktid as *const u32 as u64) };
    unsafe {
        let r = sc6(
            nr::MMAP,
            CTL_ADDR,
            proto::ctl::CTL_SIZE as u64,
            PROT_READ | PROT_WRITE,
            MAP_SHARED | MAP_FIXED_NOREPLACE,
            FD_CTL as u64,
            0,
        );
        if r as u64 != CTL_ADDR {
            crate::fatal(b"cannot map control region (descriptor 3000)");
        }
    }
    if !ctl().check() {
        crate::fatal(b"control region magic or layout mismatch");
    }
    install_handlers();
    // rdtsc/rdtscp fault from here on (inherited by fork and execve); the fault
    // entry answers them from virtual time. Checked, and set if it did not survive.
    crate::insn::tsc::ensure_faulting();
    install_filter();
    hello();
    crate::pmu::open(thread());
    let k = crate::loader::KernelStart::parse(ksp);
    crate::loader::start(&k)
}

fn install_handlers() {
    let alt = thread() as *mut ThreadState as u64;
    unsafe {
        let st: [u64; 3] = [alt, 0, ALT_SIZE];
        if sc2(nr::SIGALTSTACK, st.as_ptr() as u64, 0) != 0 {
            crate::fatal(b"sigaltstack");
        }
        let flags = SA_SIGINFO | SA_ONSTACK | SA_NODEFER | SA_RESTORER;
        let sys: [u64; 4] = [
            on_sigsys as *const () as u64,
            flags,
            patina_restorer as *const () as u64,
            0,
        ];
        if sc4(nr::RT_SIGACTION, SIGSYS, sys.as_ptr() as u64, 0, 8) != 0 {
            crate::fatal(b"sigaction SIGSYS");
        }
        for s in [SIGSEGV, SIGILL, SIGBUS, SIGFPE, SIGTRAP] {
            // With counter preemption, SIGTRAP enters through the overflow stub, which
            // passes every other SIGTRAP on to the fault entry.
            let h = if s == SIGTRAP && config().pmu & proto::ctl::PMU_ON != 0 {
                crate::pmu::sigtrap_entry()
            } else {
                on_fault as *const () as u64
            };
            let f: [u64; 4] = [h, flags, patina_restorer as *const () as u64, 0];
            if sc4(nr::RT_SIGACTION, s, f.as_ptr() as u64, 0, 8) != 0 {
                crate::fatal(b"sigaction fault");
            }
        }
        // SIGPIPE and SIGXFSZ: ignored for real; the runtime raises the virtual signal.
        for s in [SIGPIPE, SIGXFSZ] {
            let ign: [u64; 4] = [1, SA_RESTORER, patina_restorer as *const () as u64, 0];
            if sc4(nr::RT_SIGACTION, s, ign.as_ptr() as u64, 0, 8) != 0 {
                crate::fatal(b"sigaction ignore");
            }
        }
        // Block every other signal at the kernel level; the guest's mask is virtual.
        let mask: u64 = REAL_MASK;
        sc4(nr::RT_SIGPROCMASK, 2, &mask as *const u64 as u64, 0, 8);
    }
}

#[repr(C)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}
#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

/// Trap every syscall whose instruction pointer is outside the runtime's text.
/// Installed once per process tree: the filter is inherited by fork and kept across execve.
fn install_filter() {
    const PR_SET_NO_NEW_PRIVS: u64 = 38;
    const PR_SET_SECCOMP: u64 = 22;
    const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
    let f = [
        SockFilter {
            code: 0x20,
            jt: 0,
            jf: 0,
            k: 4,
        }, // ld arch
        SockFilter {
            code: 0x15,
            jt: 0,
            jf: 6,
            k: AUDIT_ARCH_X86_64,
        },
        SockFilter {
            code: 0x20,
            jt: 0,
            jf: 0,
            k: 12,
        }, // ld ip high word
        SockFilter {
            code: 0x15,
            jt: 0,
            jf: 3,
            k: RT_IP_HI32,
        },
        SockFilter {
            code: 0x20,
            jt: 0,
            jf: 0,
            k: 8,
        }, // ld ip low word
        SockFilter {
            code: 0x35,
            jt: 1,
            jf: 0,
            k: RT_IP_LO_END,
        }, // jge end -> trap
        SockFilter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x7fff_0000,
        }, // allow
        SockFilter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x0003_0000,
        }, // trap
        SockFilter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x8000_0000,
        }, // kill process
    ];
    let prog = SockFprog {
        len: f.len() as u16,
        filter: f.as_ptr(),
    };
    unsafe {
        if ctl()
            .filter_installed
            .load(core::sync::atomic::Ordering::Acquire)
            != 0
        {
            return; // already filtered (re-entry after execve; see Ctl::filter_installed)
        }
        if sc2(nr::PRCTL, PR_SET_NO_NEW_PRIVS, 1) != 0 {
            crate::fatal(b"no_new_privs");
        }
        if sc3(
            nr::PRCTL,
            PR_SET_SECCOMP,
            2,
            &prog as *const SockFprog as u64,
        ) != 0
        {
            crate::fatal(b"seccomp");
        }
        ctl()
            .filter_installed
            .store(1, core::sync::atomic::Ordering::Release);
    }
}

/// Find this task's slot (reserved by the supervisor) and announce it.
fn hello() {
    let ts = thread();
    let c = ctl();
    let mut found = None;
    for i in 0..proto::ctl::MAX_THREADS {
        let s = unsafe { &*c.slot(i) };
        let st = s.state.load(Acquire);
        if (st == proto::ctl::SLOT_LIVE || st == proto::ctl::SLOT_RESERVED)
            && s.tid.load(Relaxed) == ts.tid
        {
            found = Some(i);
            break;
        }
    }
    if found.is_none() {
        for i in 0..proto::ctl::MAX_THREADS {
            let s = unsafe { &*c.slot(i) };
            if s.state.load(Acquire) == proto::ctl::SLOT_RESERVED && s.tid.load(Relaxed) == 0 {
                s.tid.store(ts.tid, Relaxed);
                s.pid.store(ts.pid, Relaxed);
                found = Some(i);
                break;
            }
        }
    }
    let Some(i) = found else {
        crate::fatal(b"no slot reserved for this task")
    };
    ts.slot = i as u32;
    let p = proc();
    p.asid = i as u64;
    p.alt_of_slot[i] = ts as *mut ThreadState as u64;
    // A new image keeps the thread's virtual mask (in its slot) and the ignored
    // dispositions (the supervisor's record, in the reply) across execve.
    ts.vmask = unsafe { &*c.slot(i) }.vmask.load(Relaxed);
    let ign = crate::sup::call_sup(
        Op::Hello,
        [
            ts.pid as u64,
            ts.tid as u64,
            proto::ctl::HELLO_IMAGE,
            0,
            0,
            0,
        ],
    )
    .ret as u64;
    for s in 1..65u64 {
        if ign & (1 << (s - 1)) != 0 {
            p.sigact[s as usize] = [crate::sys::sig::SIG_IGN, 0, 0, 0];
        }
    }
    crate::exec::rescan_marks();
}

/// Charge a boundary event: next seq, virtual time.
pub fn charge(ts: &mut ThreadState) {
    let c = ctl();
    ts.seq = c.seq.load(Relaxed) + 1;
    c.seq.store(ts.seq, Relaxed);
    let t = c.vclock_ns.load(Relaxed) + c.config.trap_charge_ns;
    c.vclock_ns.store(t, Relaxed);
    c.stats
        .traps
        .store(c.stats.traps.load(Relaxed) + 1, Relaxed);
    ts.traps += 1;
}

/// After an event: preemption draw, timer deadline.
pub fn maybe_yield(ts: &ThreadState) {
    let c = ctl();
    let cfg = &c.config;
    let fire = draw(cfg.seed, Stream::Preempt, ts.seq) % 1000 < cfg.preempt_permille;
    // `take_notify`: this call moved the I/O generation while threads were parked on I/O.
    if crate::sys::io::take_notify() | fire
        || c.vclock_ns.load(Relaxed) >= c.next_deadline_ns.load(Relaxed)
    {
        crate::sup::call_sup(Op::Yield, [0; 6]);
    }
}

/// The trap entry: SIGSYS for every guest syscall.
pub extern "C" fn on_sigsys(_sig: i32, _info: *mut u8, uc: *mut TrapFrame) {
    let ts = thread();
    let frame = unsafe { &mut *uc };
    if crate::pmu::is_race(frame.gregs[RIP]) {
        // Delivered on top of the overflow signal: that handler re-executes the call.
        crate::pmu::sigsys_race(ts);
        return;
    }
    crate::pmu::enter(ts, Some(frame));
    charge(ts);
    if ts.traps & 1023 == 0 {
        crate::sup::outside_check();
    }
    let mut call = TrapCall::new(frame, ts);
    let nr = call.nr;
    let args = call.args;
    let row = proto::row(if nr > u32::MAX as u64 {
        u32::MAX
    } else {
        nr as u32
    });
    call.ts.eff_class = row.class.code();
    match crate::sys::dispatch(&mut call, row) {
        Action::Return(r) => {
            crate::log::trap(row, nr, &args, r);
            call.frame.gregs[RAX] = r as u64;
            maybe_yield(call.ts);
            crate::sys::sig::trap_exit(call.frame, Some(nr));
        }
        Action::Restart => {
            // Re-execute the same syscall instruction after the handler returns.
            call.frame.gregs[RAX] = nr;
            call.frame.gregs[RIP] -= 2;
            crate::sys::sig::trap_exit(call.frame, None);
        }
        Action::NoReturn => crate::sup::hang(),
        Action::NeedsFrame => crate::sup::host_error(0, nr, proto::ctl::HE_RUNTIME_ASSERT),
    }
    check_real_mask(frame_of(uc));
    crate::pmu::exit(thread(), frame_of(uc).gregs[RIP], 0);
}

fn frame_of<'a>(uc: *mut TrapFrame) -> &'a TrapFrame {
    unsafe { &*uc }
}
