//! The SDK channel's requests: a failed `always` ends the run as `violation`, and `settle`
//! (`Op::Settle`). Everything else the SDK asks is answered by the runtime under the turn
//! (`patina-rt/src/sys/sdk.rs`) from the seed, into the site table the launcher reads after the
//! run (`launch::sdk_sites`).

use super::{Next, Sup, Verdict};
use proto::ctl::Op;
use proto::sdk::SdkTab;

impl Sup {
    /// The runtime wrote the violation into the table and the trap's record into the log.
    pub(super) fn sdk_violation(&mut self, idx: usize, a: [u64; 6]) -> ! {
        self.decide(Op::SdkViolation as u32, idx, a, 0);
        let t = unsafe { SdkTab::at(self.ctl as *const _ as *mut u8) };
        let msg = String::from_utf8_lossy(t.violation()).into_owned();
        self.finish(Verdict::new("violation", msg))
    }

    /// `patina ctl settle` (`Op::Settle` [the call's sequence number, limit ns]), from main
    /// only (`settle::settle_call`).
    pub(super) fn settle_req(&mut self, idx: usize, a: [u64; 6]) -> Next {
        let seq = self.decide(Op::Settle as u32, idx, a, 0);
        match self.machine_of(idx) {
            0 => self.settle_call(seq, a[1]),
            _ => Next::Continue(-(libc::EPERM as i64)),
        }
    }
}
