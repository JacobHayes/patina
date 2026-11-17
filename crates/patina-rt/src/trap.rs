//! The interface that keeps capture swappable: handlers see a
//! `Call` and return an `Action`, never how the call arrived. Only the trap
//! entry exists in the skeleton; it provides a frame.

use crate::arch::Frame;
use crate::state::ThreadState;

// `frame()`, `Restart`, `NoReturn` and `NeedsFrame`: the interface of handlers that need the
// machine context (signals, clone, execve).
#[allow(dead_code)]
pub trait Call {
    fn nr(&self) -> u64;
    fn arg(&self, i: usize) -> u64;
    fn thread(&mut self) -> &mut ThreadState;
    fn frame(&mut self) -> Option<&mut Frame>;
    /// Replace argument `i` for the handler (a resolved path in a runtime buffer, a
    /// shortened transfer). `guest_args` keeps the arguments as the guest passed them.
    fn set_arg(&mut self, i: usize, v: u64);
    /// The arguments as the guest passed them, before any `set_arg`: what the boundary record
    /// and the supervisor are told (never a runtime address).
    fn guest_args(&self) -> [u64; 6];
}

#[allow(dead_code)]
pub enum Action {
    Return(i64),
    Restart,
    NoReturn,
    NeedsFrame,
}

/// A call that arrived by SIGSYS.
pub struct TrapCall<'a> {
    pub frame: &'a mut Frame,
    pub ts: &'a mut ThreadState,
    pub nr: u64,
    pub args: [u64; 6],
    guest: [u64; 6],
}

impl<'a> TrapCall<'a> {
    pub fn new(frame: &'a mut Frame, ts: &'a mut ThreadState) -> TrapCall<'a> {
        let args = frame.args();
        let nr = frame.nr();
        TrapCall {
            frame,
            ts,
            nr,
            args,
            guest: args,
        }
    }
}

impl Call for TrapCall<'_> {
    fn nr(&self) -> u64 {
        self.nr
    }
    fn arg(&self, i: usize) -> u64 {
        self.args[i]
    }
    fn thread(&mut self) -> &mut ThreadState {
        self.ts
    }
    fn frame(&mut self) -> Option<&mut Frame> {
        Some(self.frame)
    }
    fn set_arg(&mut self, i: usize, v: u64) {
        self.args[i] = v;
    }
    fn guest_args(&self) -> [u64; 6] {
        self.guest
    }
}

/// The six arguments of a call.
pub fn args(call: &dyn Call) -> [u64; 6] {
    [
        call.arg(0),
        call.arg(1),
        call.arg(2),
        call.arg(3),
        call.arg(4),
        call.arg(5),
    ]
}
