//! Process entry, the trap entry (`trap`, the SIGSYS handler), the fault
//! entry (timestamp-counter emulation, guest faults), and the seccomp filter.

use crate::arch::Frame;
use crate::raw::*;
use crate::state::*;
use crate::trap::{Action, TrapCall};
use core::sync::atomic::Ordering::*;
use proto::ctl::Op;
use proto::layout::*;
use proto::{draw, Stream};

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
pub fn check_real_mask(frame: &Frame) {
    if frame.sigmask != REAL_MASK {
        crate::sup::host_error(frame.sigmask as i64, 0, proto::ctl::HE_REAL_MASK);
    }
}

/// The runtime's signal restorer (for real `rt_sigaction` calls made by handlers).
pub fn restorer() -> u64 {
    crate::arch::restorer()
}

/// The first Rust code of an image, on the start-up stack (`arch`'s `_start`).
pub extern "C" fn rt_start(ksp: u64) -> ! {
    crate::arch::process_init();
    // Map the first alternate stack and continue on it, so that thread state
    // is found by masking the stack pointer from here on.
    let alt = new_alt_stack();
    crate::arch::switch_stack(alt + ALT_SIZE - 64, ksp, rt_main)
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
    map_shared();
    if !ctl().check() {
        crate::fatal(proto::ctl::Setup::CtlCheck, 0);
    }
    install_handlers();
    // rdtsc/rdtscp fault from here on (inherited by fork and execve); the fault
    // entry answers them from virtual time. Checked, and set if it did not survive.
    crate::insn::tsc::ensure_faulting();
    // The slot first: it says which node this process belongs to, and so whether the filter
    // is installed already (no system call is made while finding it).
    claim_slot();
    install_filter();
    hello();
    crate::pmu::open(thread());
    let k = crate::loader::KernelStart::parse(ksp);
    // The host facts the instruction rule depends on, before any image is scanned.
    crate::arch::insn::init(k.aux(16), k.aux(26)); // AT_HWCAP, AT_HWCAP2
    crate::loader::start(&k)
}

fn install_handlers() {
    let alt = thread() as *mut ThreadState as u64;
    unsafe {
        let st: [u64; 3] = [alt, 0, ALT_SIZE];
        if sc2(nr::SIGALTSTACK, st.as_ptr() as u64, 0) != 0 {
            crate::fatal(proto::ctl::Setup::SigAltStack, 0);
        }
        let flags =
            SA_SIGINFO | SA_ONSTACK | SA_NODEFER | SA_RESTORER | crate::arch::SA_ARCH_RUNTIME;
        // arm64 with counter preemption: SIGTRAP waits while a handler runs, so that the
        // overflow signal never interrupts runtime code (`arch/aarch64/pmu.rs`).
        let held: u64 = if cfg!(target_arch = "aarch64") && config().pmu & proto::ctl::PMU_ON != 0 {
            bit(SIGTRAP)
        } else {
            0
        };
        let sys: [u64; 4] = [on_sigsys as *const () as u64, flags, restorer(), held];
        if sc4(nr::RT_SIGACTION, SIGSYS, sys.as_ptr() as u64, 0, 8) != 0 {
            crate::fatal(proto::ctl::Setup::SigactionSys, 0);
        }
        for s in [SIGSEGV, SIGILL, SIGBUS, SIGFPE, SIGTRAP] {
            // With counter preemption, SIGTRAP enters through the overflow stub, which
            // passes every other SIGTRAP on to the fault entry.
            let h = if s == SIGTRAP && config().pmu & proto::ctl::PMU_ON != 0 {
                crate::pmu::sigtrap_entry()
            } else {
                on_fault as *const () as u64
            };
            let f: [u64; 4] = [h, flags, restorer(), held];
            if sc4(nr::RT_SIGACTION, s, f.as_ptr() as u64, 0, 8) != 0 {
                crate::fatal(proto::ctl::Setup::SigactionFault, 0);
            }
        }
        // SIGPIPE and SIGXFSZ: ignored for real; the runtime raises the virtual signal.
        for s in [SIGPIPE, SIGXFSZ] {
            let ign: [u64; 4] = [1, SA_RESTORER, restorer(), 0];
            if sc4(nr::RT_SIGACTION, s, ign.as_ptr() as u64, 0, 8) != 0 {
                crate::fatal(proto::ctl::Setup::SigactionIgnore, 0);
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

/// Trap every syscall but the runtime's own, made by its one system-call instruction
/// (`raw::stub_ip`; the same address in every image, the runtime being linked at a fixed base).
/// Installed once per process tree: the filter is inherited by fork and kept across execve.
fn install_filter() {
    const PR_SET_NO_NEW_PRIVS: u64 = 38;
    const PR_SET_SECCOMP: u64 = 22;
    let ip = crate::raw::stub_ip();
    let ins = |code: u16, jt: u8, jf: u8, k: u32| SockFilter { code, jt, jf, k };
    let f = [
        ins(0x20, 0, 0, 4),                       // ld arch
        ins(0x15, 0, 6, crate::arch::AUDIT_ARCH), // jne -> kill
        ins(0x20, 0, 0, 12),                      // ld ip high word
        ins(0x15, 0, 2, (ip >> 32) as u32),       // jne -> trap
        ins(0x20, 0, 0, 8),                       // ld ip low word
        ins(0x15, 1, 0, ip as u32),               // jeq -> allow
        ins(0x06, 0, 0, 0x0003_0000),             // trap
        ins(0x06, 0, 0, 0x7fff_0000),             // allow
        ins(0x06, 0, 0, 0x8000_0000),             // kill process
    ];
    let prog = SockFprog {
        len: f.len() as u16,
        filter: f.as_ptr(),
    };
    unsafe {
        let bit = 1u64 << proc().node;
        if ctl()
            .filter_installed
            .load(core::sync::atomic::Ordering::Acquire)
            & bit
            != 0
        {
            return; // already filtered (re-entry after execve; see Ctl::filter_installed)
        }
        if sc2(nr::PRCTL, PR_SET_NO_NEW_PRIVS, 1) != 0 {
            crate::fatal(proto::ctl::Setup::NoNewPrivs, 0);
        }
        if sc3(
            nr::PRCTL,
            PR_SET_SECCOMP,
            2,
            &prog as *const SockFprog as u64,
        ) != 0
        {
            crate::fatal(proto::ctl::Setup::Seccomp, 0);
        }
        let f = &ctl().filter_installed;
        f.store(
            f.load(core::sync::atomic::Ordering::Relaxed) | bit,
            core::sync::atomic::Ordering::Release,
        );
    }
}

/// Find this task's slot (reserved by the supervisor) and its node.
fn claim_slot() {
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
        crate::fatal(proto::ctl::Setup::NoSlot, 0)
    };
    ts.slot = i as u32;
    proc().node = unsafe { &*c.slot(i) }.node.load(Relaxed) as usize;
}

/// Announce this task's slot.
fn hello() {
    let ts = thread();
    let c = ctl();
    let i = ts.slot as usize;
    let p = proc();
    p.asid = i as u64;
    p.alt_of_slot[i] = ts as *mut ThreadState as u64;
    // A new image keeps the thread's virtual mask (in its slot) and the ignored
    // dispositions (the supervisor's record, in the reply) across execve.
    ts.vmask = unsafe { &*c.slot(i) }.vmask.load(Relaxed);
    crate::oplog::publish_maps();
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
    crate::sys::signalfd::after_exec();
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
pub extern "C" fn on_sigsys(_sig: i32, _info: *mut u8, uc: *mut Frame) {
    let ts = thread();
    let frame = unsafe { &mut *uc };
    if crate::pmu::is_race(frame.pc()) {
        // Delivered on top of the overflow signal: that handler re-executes the call.
        crate::pmu::sigsys_race(ts);
        return;
    }
    let pc = frame.pc();
    // The instruction's own address: a program mapping may end where the region starts.
    let insn = pc.wrapping_sub(crate::arch::SYSCALL_LEN);
    if crate::fault::in_runtime(insn) {
        // A system-call instruction in the runtime's text other than the stub's. On a program
        // stack: program code jumped there. On a runtime stack: a runtime defect.
        if crate::fault::in_runtime(frame.sp()) {
            crate::sup::host_error(0, pc, proto::ctl::HE_RUNTIME_ASSERT);
        }
        crate::sup::containment(proto::ctl::CONTAIN_SYSCALL, insn, insn, false);
    }
    crate::pmu::enter(ts, Some(frame));
    crate::spin::enter(ts, Some(frame), true);
    crate::compute::enter(ts);
    if frame.nr() == proto::sdk::SYSCALL
        && frame.args()[0] == proto::sdk::OP_COMPUTE_POINT
        && crate::compute::active()
    {
        // Its events are already charged: no trap charge, no trap record (`compute::point`).
        crate::compute::point(ts, frame, frame.pc(), false);
        frame.set_ret(0);
        crate::sys::sig::trap_exit(frame, None);
        check_real_mask(frame_of(uc));
        crate::compute::exit(thread());
        crate::pmu::exit(thread(), frame_of(uc).pc(), 0);
        return;
    }
    charge(ts);
    if ts.traps & 1023 == 0 {
        crate::sup::outside_check();
    }
    // The call's path buffers live as long as its record is not yet written.
    let mut paths = crate::resolve::Paths::new();
    let mut call = TrapCall::new(frame, ts, &mut paths);
    let nr = call.nr;
    let row = proto::row(if nr > u32::MAX as u64 {
        u32::MAX
    } else {
        nr as u32
    });
    call.ts.eff_class = row.class.code();
    match crate::sys::dispatch(&mut call, row) {
        Action::Return(r) => {
            crate::log::trap(row, &call, r);
            call.frame.set_ret(r);
            maybe_yield(call.ts);
            let arg0 = crate::trap::Call::guest_args(&call)[0];
            crate::sys::sig::trap_exit(call.frame, Some((nr, arg0)));
        }
        Action::Restart => {
            // Re-execute the same system call instruction after the handler returns.
            call.frame.rewind(nr);
            crate::sys::sig::trap_exit(call.frame, None);
        }
        Action::NoReturn => crate::sup::hang(),
        Action::NeedsFrame => crate::sup::host_error(0, nr, proto::ctl::HE_RUNTIME_ASSERT),
    }
    check_real_mask(frame_of(uc));
    crate::compute::exit(thread());
    crate::pmu::exit(thread(), frame_of(uc).pc(), 0);
}

fn frame_of<'a>(uc: *mut Frame) -> &'a Frame {
    unsafe { &*uc }
}
