//! Instruction channels: the ways guest code can read something that varies from run to
//! run without a system call.
//!
//! - `tsc`: `rdtsc`/`rdtscp` fault under `PR_SET_TSC` and are answered from virtual time
//!   (complete: every occurrence faults, wherever the code came from).
//! - `scan` + `patch`: `rdrand`/`rdseed` sites in executable file mappings are found when the
//!   mapping appears (loader, `mmap`, `mprotect`) and overwritten with `ud2`; `emulate` answers
//!   the SIGILL from the seeded entropy stream. Only addresses in the side table are emulated:
//!   any other `ud2` is the guest's own and goes to its SIGILL disposition. Code that is not a
//!   scanned file mapping (anonymous memory made executable) is counted, not scanned.
//!
//! Counters live in the control region (`proto::ctl::InsnCtl`) and become the outcome fields
//! `patched_sites`, `emulated` and `unscanned_exec_mappings`.

pub mod emulate;
pub mod patch;
pub mod scan;
pub mod tsc;

use crate::state::ctl;
use core::sync::atomic::{AtomicU64, Ordering::Relaxed};

/// Add to a counter (only the thread holding the turn writes).
pub fn bump(c: &AtomicU64, n: u64) {
    c.store(c.load(Relaxed) + n, Relaxed);
}

pub fn count_emulated(i: usize) {
    bump(&ctl().insn.emulated[i], 1);
}
