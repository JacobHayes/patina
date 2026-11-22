//! The SDK channel's requests: a failed `always` ends the run as `violation`, and the lifecycle
//! marks (`Op::Lifecycle`). Everything else the SDK asks is answered by the runtime under the
//! turn (`patina-rt/src/sys/sdk.rs`) from the seed, into the site table the launcher reads
//! after the run (`launch::sdk_sites`).

use super::{Next, Sup, Verdict};
use proto::ctl::{Op, LIFE_FAULTS_DONE, LIFE_SETTLE, LIFE_SETUP_UNDECLARED};
use proto::sdk::SdkTab;

/// The verdict class of a run whose program marked `setup-complete` without the run declaring
/// it (`outcome::classify`: `error`, stop `setup-mark`).
pub const SETUP_MARK: &str = "setup-mark";

impl Sup {
    /// The runtime wrote the violation into the table and the trap's record into the log.
    pub(super) fn sdk_violation(&mut self, idx: usize, a: [u64; 6]) -> ! {
        self.decide(Op::SdkViolation as u32, idx, a, 0);
        let t = unsafe { SdkTab::at(self.ctl as *const _ as *mut u8) };
        let msg = String::from_utf8_lossy(t.violation()).into_owned();
        self.finish(Verdict::new("violation", msg))
    }

    /// A lifecycle mark (`Op::Lifecycle`): an undeclared `setup-complete`, which ends the run,
    /// or `faults-done`, after which the seed's partition and pauses in force end and no fault
    /// of the supervisor's acts (`faults_on`; the runtime set `fault_until_seq`); or
    /// `settle` (`settle::settle_call`).
    pub(super) fn lifecycle(&mut self, idx: usize, a: [u64; 6]) -> Next {
        let seq = self.decide(Op::Lifecycle as u32, idx, a, 0);
        match a[0] {
            LIFE_SETUP_UNDECLARED => {
                let d = if self.phases.setup.is_some() {
                    "the program marked setup-complete, but the run's setup is a command (--setup): \
                     a program that marks the end of its own setup declares `setup = \"mark\"` instead"
                } else {
                    "the program marked setup-complete, which the run does not declare: add \
                     `setup = \"mark\"` under [run] in patina.toml (or pass --setup mark)"
                };
                self.finish(Verdict::new(SETUP_MARK, d))
            }
            LIFE_FAULTS_DONE => {
                self.partitions_done();
                self.pauses_done();
                Next::Continue(0)
            }
            LIFE_SETTLE if self.machine_of(idx) == 0 => self.settle_call(seq, a[2]),
            LIFE_SETTLE => Next::Continue(-(libc::EPERM as i64)),
            _ => Next::Continue(-(libc::EINVAL as i64)),
        }
    }
}
