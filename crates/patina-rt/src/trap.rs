//! The interface that keeps capture swappable: handlers see a
//! `Call` and return an `Action`, never how the call arrived. Only the trap
//! entry exists in the skeleton; it provides a frame.

use crate::state::ThreadState;

/// x86_64 kernel `ucontext` as delivered on the alternate stack.
#[repr(C)]
pub struct TrapFrame {
    pub uc_flags: u64,
    pub uc_link: u64,
    pub ss_sp: u64,
    pub ss_flags: u32,
    pub _pad: u32,
    pub ss_size: u64,
    /// r8 r9 r10 r11 r12 r13 r14 r15 rdi rsi rbp rbx rdx rax rcx rsp rip eflags csgsfs err trapno oldmask cr2
    pub gregs: [u64; 23],
    pub fpstate: u64,
    pub reserved: [u64; 8],
    pub sigmask: u64,
}

#[allow(dead_code)]
pub mod reg {
    pub const R8: usize = 0;
    pub const R9: usize = 1;
    pub const R10: usize = 2;
    pub const RDI: usize = 8;
    pub const RSI: usize = 9;
    pub const RBP: usize = 10;
    pub const RBX: usize = 11;
    pub const RDX: usize = 12;
    pub const RAX: usize = 13;
    pub const RCX: usize = 14;
    pub const RSP: usize = 15;
    pub const RIP: usize = 16;
    pub const EFL: usize = 17;
    pub const CSGSFS: usize = 18;
    pub const ERR: usize = 19;
    pub const TRAPNO: usize = 20;
    pub const OLDMASK: usize = 21;
    pub const CR2: usize = 22;
}

// `frame()`, `Restart`, `NoReturn` and `NeedsFrame`: the interface of handlers that need the
// machine context (signals, clone, execve).
#[allow(dead_code)]
pub trait Call {
    fn nr(&self) -> u64;
    fn arg(&self, i: usize) -> u64;
    fn thread(&mut self) -> &mut ThreadState;
    fn frame(&mut self) -> Option<&mut TrapFrame>;
    /// Replace argument `i` for the handler (a shortened transfer). The boundary
    /// record keeps the arguments as the guest passed them.
    fn set_arg(&mut self, i: usize, v: u64);
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
    pub frame: &'a mut TrapFrame,
    pub ts: &'a mut ThreadState,
    pub nr: u64,
    pub args: [u64; 6],
}

impl<'a> TrapCall<'a> {
    pub fn new(frame: &'a mut TrapFrame, ts: &'a mut ThreadState) -> TrapCall<'a> {
        use reg::*;
        let g = &frame.gregs;
        let args = [g[RDI], g[RSI], g[RDX], g[R10], g[R8], g[R9]];
        let nr = g[RAX];
        TrapCall {
            frame,
            ts,
            nr,
            args,
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
    fn frame(&mut self) -> Option<&mut TrapFrame> {
        Some(self.frame)
    }
    fn set_arg(&mut self, i: usize, v: u64) {
        self.args[i] = v;
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
