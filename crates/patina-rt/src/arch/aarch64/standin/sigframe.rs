//! Signal delivery to a program's handler and `rt_sigreturn` are not ported to arm64: a run
//! that reaches either ends `arm64-unported`. Signals whose disposition needs no frame (the
//! default action, ignore) work as on x86_64.

use crate::arch::Frame;
use crate::state::ThreadState;
use crate::sys::sig::SigInfo;

pub fn deliver(
    _frame: &mut Frame,
    _ts: &mut ThreadState,
    _sig: u64,
    _info: &SigInfo,
    _act: [u64; 4],
    _fault: bool,
) {
    crate::sup::unported(proto::ctl::UNPORTED_SIGNALS)
}

pub fn sigreturn(_frame: &mut Frame, _ts: &mut ThreadState) -> i64 {
    crate::sup::unported(proto::ctl::UNPORTED_SIGNALS)
}
