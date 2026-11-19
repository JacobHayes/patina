//! Instruction channels: the ways guest code can read something that varies from run to
//! run without a system call.
//!
//! - `tsc`: the counter (`rdtsc`/`rdtscp`; on arm64 `mrs` of `CNTVCT_EL0`, `CNTVCTSS_EL0`,
//!   `CNTFRQ_EL0`) faults under `PR_SET_TSC` and is answered from virtual time (complete:
//!   every occurrence faults, wherever the code came from).
//! - `scan` + `patch`: sites in executable file mappings (`rdrand`/`rdseed`; `RNDR`/`RNDRRS`;
//!   the pause hints) are found when the mapping appears (loader, `mmap`, `mprotect`) and
//!   overwritten with an undefined instruction (a read-only file's mapping is scanned once per
//!   run: its verdicts are kept for the run's other processes, `scan`); `emulate` answers the
//!   SIGILL. Only addresses in the side table are emulated: any other undefined instruction is
//!   the guest's own and goes to its SIGILL disposition. Code that is not a scanned file
//!   mapping (anonymous memory made executable) is counted, not scanned.
//!
//! What differs by architecture (the rule, the emulators, the record codes) is
//! `crate::arch::insn`; the mappings, the side table and the write are here.
//!
//! Counters live in the control region (`proto::ctl::InsnCtl`) and become the outcome fields
//! `patched_sites`, `emulated` and `unscanned_exec_mappings`.

pub mod patch;
pub mod scan;

pub use crate::arch::insn::{emulate, tsc};

use crate::arch::Frame;
use crate::state::ctl;
use core::sync::atomic::{AtomicU64, Ordering::Relaxed};

/// The verdict code of a candidate the rule refused (inside another instruction, skipped by
/// the sweep, data in text); the others are the site kinds (`proto::insn::SiteKind`).
pub const REJECTED: u8 = 0xff;

/// Add to a counter (only the thread holding the turn writes).
pub fn bump(c: &AtomicU64, n: u64) {
    c.store(c.load(Relaxed) + n, Relaxed);
}

pub fn count_emulated(i: usize) {
    bump(&ctl().insn.emulated[i], 1);
}

/// A patched pause hint at `pc` (`len` bytes, record code `code`): a scheduling point. The
/// runtime charges virtual time, records it, and yields to the supervisor as `sched_yield`
/// does. Under one-thread-at-a-time scheduling a thread that executes a pause hint is waiting
/// for another thread, so handing over loses nothing.
pub fn pause_point(frame: &mut Frame, pc: u64, len: u64, code: u32) -> bool {
    let ts = crate::state::thread();
    let c = ctl();
    ts.seq = c.seq.load(Relaxed) + 1;
    c.seq.store(ts.seq, Relaxed);
    let t = c.vclock_ns.load(Relaxed) + c.config.spin_charge_ns;
    c.vclock_ns.store(t, Relaxed);
    bump(&c.sched.pause_points, 1);
    frame.set_pc(pc + len);
    crate::log::insn(code, pc, 0);
    crate::sup::call_sup(proto::ctl::Op::Yield, [0; 6]);
    true
}
