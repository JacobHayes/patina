//! Linux syscall conformance scenarios, with the host kernel as the live
//! oracle (docs/arcs/syscall-conformance.md).
//!
//! A scenario is a plain function over a [`probe::Probe`]: it issues calls
//! through one of three vehicles (`libc`, `syscall`, `raw`), asserts the
//! properties it pins with `check`, and writes one typed event per observed
//! call (see [`observe`]). Every scenario is built into ONE probe binary
//! (`conformance-probe <scenario> --vehicle V --dir D`). The
//! `crates/cargo-patina/tests/native_conformance.rs` tests run it natively and
//! under `cargo patina` in the same test and [`compare::judge`] the streams:
//! exact by default, differing only where the scenario declares a
//! [`catalog::Gap`].
//!
//! * [`catalog`] — every scenario with the rows it covers, what it needs from
//!   the host, and its gaps; the coverage exclusions.
//! * [`probe`] — the scenario-facing call API; [`vehicle`] — the three doors.
//! * [`compare`] — normalization and the live comparison; [`leak`] — the
//!   strace escape filter; [`host`] — applicability detection; [`coverage`] —
//!   registry entries no scenario or exclusion accounts for.
//!
//! The scenarios and the probe API are the Linux syscall ABI and build only
//! there; the comparison and the leak filter are plain Rust.

pub mod compare;
pub mod leak;
pub mod observe;

#[cfg(target_os = "linux")]
pub mod catalog;
#[cfg(target_os = "linux")]
pub mod coverage;
#[cfg(target_os = "linux")]
pub mod host;
#[cfg(target_os = "linux")]
pub mod owned;
#[cfg(target_os = "linux")]
pub mod probe;
#[cfg(target_os = "linux")]
pub mod record;
#[cfg(target_os = "linux")]
mod scenarios;
#[cfg(target_os = "linux")]
pub mod signals;
#[cfg(target_os = "linux")]
pub mod vehicle;
