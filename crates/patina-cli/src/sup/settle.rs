//! `patina ctl settle` (`Op::Lifecycle` `LIFE_SETTLE`, from main): the end of the seed's faults
//! and the wait for the system to recover. The first call stops every fault from its sequence
//! number on (`FaultCfg::fault_until_seq`, which also stops the count of crash points), ends the
//! seed's partition and pauses in force, and boots at once every machine the seed took down
//! (its restart, scheduled by its policy, moves to now). The seed's actions and the script's are
//! separate books: a cut, a pause or a down machine of the script's stays, and a machine the
//! script took down is not waited for. The call is answered `-EAGAIN` until every other machine
//! is ready, and the runtime asks again 100 ms of virtual time later; past the call's limit the
//! run ends `liveness`, stop `settle`, naming the machine. Once answered 0, a call is a no-op.

use super::{Next, Sup, Verdict};
use std::sync::atomic::Ordering::Relaxed;

/// The verdict class of a run whose machines were not ready within `settle`'s limit
/// (`outcome::classify`: `liveness`, stop `settle`).
pub const SETTLE: &str = "settle";

impl Sup {
    /// `LIFE_SETTLE` [_, _, limit ns]; `seq` is the call's decision record.
    pub(super) fn settle_call(&mut self, seq: u64, limit_ns: u64) -> Next {
        if self.phases.settled {
            return Next::Continue(0);
        }
        let ph = &self.ctl.phases;
        if ph.settle_seq.load(Relaxed) == 0 {
            ph.settle_seq.store(seq, Relaxed);
            ph.settle_ns.store(self.now(), Relaxed);
            let f = &self.ctl.faults.cfg;
            if f.fault_until_seq == 0 {
                let at = std::ptr::addr_of!(f.fault_until_seq) as *mut u64;
                unsafe { std::ptr::write_volatile(at, seq) };
            }
            self.seed_stop();
        }
        let Some((k, why)) = (1..self.machine_count()).find_map(|k| Some((k, self.unready(k)?)))
        else {
            self.phases.settled = true;
            return Next::Continue(0);
        };
        let waited = self.now() - self.ctl.phases.settle_ns.load(Relaxed);
        if waited < limit_ns {
            return Next::Continue(-(libc::EAGAIN as i64));
        }
        let d = format!(
            "{} s after the faults stopped, machine {} was not ready: {why}",
            waited / 1_000_000_000,
            self.machine_name(k)
        );
        self.machines_stop();
        self.finish(Verdict::new(SETTLE, d))
    }

    /// The seed's faults end: its partition and pauses in force end, and every machine it took
    /// down whose restart its policy scheduled is queued to start now. A machine the script took
    /// down, or one its policy or `max-boots` leaves down, stays down.
    pub(super) fn seed_stop(&mut self) {
        self.partitions_done();
        self.pauses_done();
        for k in 1..self.machine_count() {
            if !self.machine_is_up(k) && self.machines_start_queued(k) {
                self.machine_start_now(k);
            }
        }
    }

    /// Why `settle` still waits for machine `k` (None: it does not). A machine that is down
    /// with no start to come (the script took it down, or its policy leaves it down) is not
    /// waited for. Ready means started and not paused.
    fn unready(&self, k: usize) -> Option<&'static str> {
        if self.machine_is_up(k) {
            self.paused(k).then_some("paused by the script")
        } else {
            self.machines_start_queued(k)
                .then_some("it has not started again")
        }
    }
}
