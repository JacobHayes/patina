//! Branch-counter preemption on arm64: none. No arm64 CPU's branch counting is checked exact,
//! so the launcher refuses `--preempt branches` before any run (`launcher::pmu`), and every
//! entry point here does nothing, as on x86_64 with counters off. A configuration that asks
//! for counters anyway ends the run at setup (`Setup::Counters`), never runs without them.

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
        crate::fatal(proto::ctl::Setup::Counters, 0);
    }
}

pub fn sigtrap_entry() -> u64 {
    crate::fatal(proto::ctl::Setup::Counters, 0)
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
