//! What differs by instruction set: the trap frame and its accessors, the one system-call
//! instruction (the stub and `sc6`), process entry and the jumps between stacks, per-image
//! setup, the seccomp program's architecture, and the guest copy with its fault fix-up.
//!
//! One of `x86_64` or `aarch64` is compiled, chosen by `target_arch`; both export the same
//! names and the compiler checks each build. Portable code names no register, instruction or
//! frame offset: it goes through `Frame`'s accessors.

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "aarch64")]
pub use aarch64::*;

#[cfg(target_arch = "x86_64")]
mod x86_64;
#[cfg(target_arch = "x86_64")]
pub use x86_64::*;
