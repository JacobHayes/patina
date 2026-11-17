//! Spin probes are not ported to arm64. A probe from the supervisor finds nothing here, which
//! the guest cannot see (as on x86_64 when a probe finds no fixed point); a SIGTRAP that is not
//! a probe goes on to the fault entry.

use crate::arch::Frame;
use crate::state::ThreadState;
use crate::sys::sig::SigInfo;

/// Per-thread probe state: none.
pub struct Spin;

impl Spin {
    pub const fn new() -> Spin {
        Spin
    }
}

#[inline(always)]
pub fn enter(_ts: &mut ThreadState, _frame: Option<&mut Frame>) {}

/// True for a probe from the supervisor (`tgkill` from PID 1): handled by doing nothing.
pub fn on_sigtrap(info: &SigInfo, _frame: &mut Frame) -> bool {
    const SI_TKILL: i32 = -6;
    (info[1] & 0xffff_ffff) as i32 == SI_TKILL && (info[2] & 0xffff_ffff) as i32 == 1
}
