//! The SDK channel's requests: a failed `always` ends the run as `violation`, and the lifecycle
//! marks (`Op::Lifecycle`). Everything else the SDK asks is answered by the runtime under the
//! turn (`patina-rt/src/sys/sdk.rs`) from the seed, into the site table the launcher reads
//! after the run (`launch::sdk_sites`).

use super::{Next, Sup, Verdict};
use proto::ctl::{Op, LIFE_FAULTS_DONE, LIFE_RESTART};
use proto::sdk::SdkTab;

/// The verdict class of a pass that ended at `setup-complete` to be run again held until setup
/// (`launch::run_one`); never a run's outcome.
pub const SETUP_RESTART: &str = "setup-restart";

impl Sup {
    /// The runtime wrote the violation into the table and the trap's record into the log.
    pub(super) fn sdk_violation(&mut self, idx: usize, a: [u64; 6]) -> ! {
        self.decide(Op::SdkViolation as u32, idx, a, 0);
        let t = unsafe { SdkTab::at(self.ctl as *const _ as *mut u8) };
        let msg = String::from_utf8_lossy(t.violation()).into_owned();
        self.finish(Verdict::new("violation", msg))
    }

    /// A lifecycle mark (`Op::Lifecycle`): the end of a pass at `setup-complete`, or
    /// `faults-done`, after which the seed's partition and pauses in force end and no fault of
    /// the supervisor's acts (`faults_on`; the runtime set `fault_until_seq`).
    pub(super) fn lifecycle(&mut self, idx: usize, a: [u64; 6]) -> Next {
        self.decide(Op::Lifecycle as u32, idx, a, 0);
        match a[0] {
            LIFE_RESTART => self.finish(Verdict::new(SETUP_RESTART, String::new())),
            LIFE_FAULTS_DONE => {
                self.partitions_done();
                self.pauses_done();
                Next::Continue(0)
            }
            _ => Next::Continue(-(libc::EINVAL as i64)),
        }
    }
}
