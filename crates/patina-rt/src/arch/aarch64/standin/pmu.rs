//! Branch-counter preemption is not ported to arm64: the launcher refuses `--preempt branches`
//! there, and a run that asks for it anyway ends `arm64-unported`. Without it every entry
//! point here does nothing, as on x86_64 with counters off.

use crate::arch::Frame;
use crate::state::{config, ThreadState};

/// Per-thread counter state: none.
pub struct Pmu;

impl Pmu {
    pub const fn new() -> Pmu {
        Pmu
    }
}

fn refuse_if_on() {
    if config().pmu & proto::ctl::PMU_ON != 0 {
        crate::sup::unported(proto::ctl::UNPORTED_COUNTERS);
    }
}

pub fn sigtrap_entry() -> u64 {
    crate::sup::unported(proto::ctl::UNPORTED_COUNTERS)
}

pub fn open(_ts: &mut ThreadState) {
    refuse_if_on();
}

#[allow(dead_code)]
pub fn close(_ts: &mut ThreadState) {}

#[allow(dead_code)]
pub fn fork_child(_ts: &mut ThreadState, _others: &[u64]) {}

#[inline(always)]
pub fn enter(_ts: &mut ThreadState, _frame: Option<&mut Frame>) {}

#[inline(always)]
pub fn exit(_ts: &mut ThreadState, _pc: u64, _tail: u64) {}

pub fn sigsys_race(_ts: &mut ThreadState) {}

#[inline(always)]
pub fn is_race(_pc: u64) -> bool {
    false
}

pub fn note_race() {}
