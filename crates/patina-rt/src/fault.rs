//! Synchronous faults: real SIGSEGV, SIGILL, SIGBUS, SIGFPE and SIGTRAP arrive at
//! `on_fault` on the runtime's alternate stack. In order: runtime code running on a program
//! stack (program code jumped into the runtime) ends the run (`HE_CONTAINMENT`); a fault in a
//! guest copy (`guest.rs`) returns `EFAULT` from it; any other fault in runtime code is a
//! runtime defect (`infra`); then the chain of instruction emulators; a program access to the
//! runtime's region ends the run (`HE_CONTAINMENT`); then the guest's virtual disposition: a
//! handler gets a frame built by `arch::deliver` with the kernel's siginfo, the default
//! action terminates.

use crate::arch::Frame;
use crate::entry::charge;
use crate::state::thread;
use crate::sys::sig::{self, SigInfo, SIG_DFL, SIG_IGN};
use proto::layout::*;

/// An instruction emulator: returns true when it handled the fault (and advanced `pc`).
pub type Emulator = fn(&mut Frame, i32, &SigInfo) -> bool;

/// The emulators, tried in order: the timestamp counter (SIGSEGV under `PR_SET_TSC`), then
/// patched sites (SIGILL at a `ud2` the runtime wrote).
static EMULATORS: &[Emulator] = &[
    crate::insn::tsc::try_emulate,
    crate::insn::emulate::try_emulate,
];

pub fn in_runtime(a: u64) -> bool {
    (RT_BASE..RT_REGION_END).contains(&a)
}

/// The fault entry.
pub extern "C" fn on_fault(sig: i32, info: *mut SigInfo, uc: *mut Frame) {
    let frame = unsafe { &mut *uc };
    let pc = frame.pc();
    if sig as u64 == sig::SIGTRAP && crate::spin::on_sigtrap(unsafe { &*info }, frame) {
        return;
    }
    if in_runtime(pc) && !in_runtime(frame.sp()) {
        // Runtime code on a program stack: program code jumped into the runtime's text; at the
        // syscall stub's stop, after making a call through its instruction (`raw.rs`).
        let kind = if pc == crate::raw::stub_escape() {
            proto::ctl::CONTAIN_STUB
        } else {
            proto::ctl::CONTAIN_EXEC
        };
        crate::sup::containment(kind, pc, pc, false);
    }
    if in_runtime(pc) {
        // A guest pointer the runtime was copying through: the copy returns EFAULT.
        if matches!(sig as u64, sig::SIGSEGV | sig::SIGBUS) {
            if let Some(to) = crate::guest::fixup(pc) {
                frame.set_pc(to);
                return;
            }
        }
        if crate::pmu::is_race(pc) {
            // Delivered on top of the overflow signal: the instruction faults again.
            crate::pmu::note_race();
            return;
        }
        crate::sup::host_error(sig as i64, pc, proto::ctl::HE_GUEST_FAULT_IN_RUNTIME);
    }
    crate::pmu::enter(thread(), Some(frame));
    crate::spin::enter(thread(), Some(frame));
    crate::compute::enter(thread());
    let info: SigInfo = unsafe { core::ptr::read(info) };
    for emu in EMULATORS {
        if emu(frame, sig, &info) {
            sig::trap_exit(frame, None);
            crate::entry::check_real_mask(frame);
            crate::compute::exit(thread());
            crate::pmu::exit(thread(), frame.pc(), 0);
            return;
        }
    }
    let sig = sig as u64;
    let addr = info[2];
    if matches!(sig, sig::SIGSEGV | sig::SIGBUS) && in_runtime(addr) {
        // Program code loaded or stored at an address of the runtime's region.
        let store = frame.fault_is_store();
        crate::sup::containment(proto::ctl::CONTAIN_ACCESS, addr, pc, store);
    }
    let ts = thread();
    charge(ts);
    crate::log::fault(sig, &info, pc);
    // The kernel's force_sig: a blocked or ignored fault signal is unblocked and its
    // disposition reset to the default, so the process dies of it.
    let blocked = ts.vmask & sig::bit(sig) != 0;
    let act = crate::state::sigact()[sig as usize];
    if blocked || act[0] == SIG_IGN {
        sig::set_action(sig, [SIG_DFL, act[1], act[2], act[3]]);
        if blocked {
            sig::set_vmask(ts, ts.vmask & !sig::bit(sig));
        }
    }
    if crate::state::sigact()[sig as usize][0] == SIG_DFL {
        sig::die(sig);
    }
    sig::act_on(frame, ts, sig, &info, None, true);
    sig::trap_exit(frame, None);
    crate::entry::check_real_mask(frame);
    crate::compute::exit(thread());
    crate::pmu::exit(thread(), frame.pc(), 0);
}
