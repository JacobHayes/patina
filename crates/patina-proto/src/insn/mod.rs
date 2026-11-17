//! Instruction sites: the rule that decides which instructions of program code are patched,
//! per architecture. Shared so that `patina __insn-scan` runs the very code the runtime runs
//! (the false-positive audit compares it with a disassembler).

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "aarch64")]
pub use aarch64::*;

/// The x86-64 length decoder and rule; also compiled elsewhere: the counter-preemption
/// classifier (`crate::pmu`) is built on its decoder.
pub mod x86_64;
#[cfg(target_arch = "x86_64")]
pub use x86_64::*;
