//! The syscall-conformance harness library (docs/arcs/syscall-conformance.md §4).
//!
//! * [`vehicle`] — how a call reaches the kernel: libc symbol, `syscall(2)`, or
//!   inline-asm `syscall` (x86_64 Linux).
//! * [`observe`] — typed JSONL events and the per-field normalization tags.
//! * [`calls`] — the probe-facing API: one method per row, each recording its
//!   event with the right normalizations, plus `check` for semantic properties.
//! * [`probe`] — argv parsing and the `probe_main!` entry macro.
//! * [`signals`] — the signal-family probes' shared handler state.
//! * [`expect`] — the harness half used by the `conform` binary: normalizer,
//!   expectation files with their blessing header, `divergences.toml`, the
//!   differ (undeclared and stale divergences both fail), the host gate, and
//!   the planted-failure selftest.
//!
//! Probes are Linux programs (the rows are Linux ABI). The `expect` half is
//! plain Rust and builds everywhere so `run.sh --selftest` and the differ do not
//! depend on the probes compiling.

#[cfg(target_os = "linux")]
pub mod calls;
pub mod expect;
pub mod observe;
#[cfg(target_os = "linux")]
pub mod probe;
#[cfg(target_os = "linux")]
pub mod signals;
#[cfg(target_os = "linux")]
pub mod vehicle;

#[cfg(not(target_os = "linux"))]
pub mod vehicle {
    /// The errno vocabulary is Linux-only; off Linux the differ never sees a
    /// live errno, so any name is a pass-through.
    pub fn errno_name(code: i32) -> String {
        format!("E#{code}")
    }
}

#[cfg(not(target_os = "linux"))]
#[macro_export]
macro_rules! probe_main {
    ($id:literal, $body:path) => {
        fn main() {
            eprintln!(
                "{}: syscall-conformance probes are Linux-only (this is {} {})",
                $id,
                std::env::consts::OS,
                std::env::consts::ARCH
            );
            std::process::exit(4);
        }
    };
}

#[cfg(target_os = "linux")]
mod associations;

#[cfg(all(test, target_os = "linux"))]
mod registry_gate;
