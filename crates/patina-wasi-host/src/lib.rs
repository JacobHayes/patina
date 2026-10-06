//! Deterministic WASI Preview 1 host functions and Wasmi guest-memory bridges.
//!
//! Internal crate: the host side of `cargo patina run` for `wasm32-wasip1`
//! guests. It implements the audited WASI Preview 1 import surface — plus the
//! `patina_sdk` module the `patina-dst` macros bridge to — against the same
//! deterministic runtime the native shim drives. The allowlisted surface covers
//! process inputs, clocks, entropy, virtual files, polling, configured
//! datagrams, stdio, and exit. Every other import is rejected before
//! instantiation, so an unmodeled effect is a loud refusal rather than a host
//! escape. Adopters use the CLI; see [ARCHITECTURE.md] for the WASI host design.
//!
//! [ARCHITECTURE.md]: https://github.com/JacobHayes/patina/blob/main/ARCHITECTURE.md

use patina_dst_runtime::RuntimeError;
use patina_dst_target::TargetError;
use std::fmt;
use wasmi::Error as WasmiError;

mod abi;
mod execute;
mod fs;
mod host;
mod imports;
mod limits;
mod memory;
mod preview1;
mod sdk;
mod static_sites;

pub use execute::{WasiExecution, execute_preview1, execute_preview1_with_fuel};
pub use host::{Preview1Host, WasiClock};
pub use limits::{DEFAULT_WASM_FUEL, MountPolicy, ResourceLimits};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WasiExit {
    pub code: u32,
}

#[derive(Debug)]
pub enum WasiRunError {
    Target(TargetError),
    Engine(WasmiError),
    /// The guest itself trapped: `_start` returned an error that is not a WASI
    /// `proc_exit` status. That is an outcome OF the guest (an `always!`
    /// violation, an `unreachable`, a memory-cap trap), structurally different
    /// from an [`WasiRunError::Engine`] failure to build or link the module,
    /// which is a problem WITH the module or the host. Callers that report run
    /// results keep the distinction: a trap gets a run envelope, a link failure
    /// does not.
    GuestTrap(WasmiError),
    Host(WasiHostError),
    /// Depth accounting (fuel / hostcall counters) did not produce data for a
    /// run that executed. Reported rather than papered over so "no depth data"
    /// can never be read as "zero depth".
    Depth(String),
    RunWithOutput {
        run: Box<WasiRunError>,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    },
    RunAndFinalize {
        run: Box<WasiRunError>,
        finalize: Box<WasiRunError>,
    },
}

impl WasiRunError {
    /// The guest's own trap and whatever it had written, when this error IS a
    /// guest trap -- looking through the [`WasiRunError::RunWithOutput`] wrapper
    /// so a caller never has to re-match the nesting. Returns the trap's rendered
    /// message plus the stdout/stderr bytes the guest produced before it (both
    /// empty when the guest wrote nothing).
    ///
    /// Every other failure is handed back unchanged in `Err`: an audit refusal, an
    /// engine/link error, or a host finalization error is not something the guest
    /// did, and must not be reported as a guest outcome.
    pub fn guest_trap(self) -> Result<(String, Vec<u8>, Vec<u8>), Self> {
        match self {
            Self::GuestTrap(_) => {
                let message = self.to_string();
                Ok((message, Vec::new(), Vec::new()))
            }
            Self::RunWithOutput {
                run,
                stdout,
                stderr,
            } if matches!(*run, Self::GuestTrap(_)) => Ok((run.to_string(), stdout, stderr)),
            other => Err(other),
        }
    }
}

impl fmt::Display for WasiRunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Target(error) => error.fmt(f),
            Self::Engine(error) => error.fmt(f),
            Self::GuestTrap(error) => error.fmt(f),
            Self::Host(error) => error.fmt(f),
            Self::Depth(message) => f.write_str(message),
            Self::RunWithOutput {
                run,
                stdout,
                stderr,
            } => {
                write!(f, "{run}")?;
                if !stdout.is_empty() {
                    write!(f, "; stdout: {}", String::from_utf8_lossy(stdout))?;
                }
                if !stderr.is_empty() {
                    write!(f, "; stderr: {}", String::from_utf8_lossy(stderr))?;
                }
                Ok(())
            }
            Self::RunAndFinalize { run, finalize } => {
                write!(
                    f,
                    "WASI execution failed ({run}) and finalization failed ({finalize})"
                )
            }
        }
    }
}

impl std::error::Error for WasiRunError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Target(error) => Some(error),
            Self::Engine(error) => Some(error),
            Self::GuestTrap(error) => Some(error),
            Self::Host(error) => Some(error),
            Self::Depth(_) => None,
            Self::RunWithOutput { run, .. } => Some(run),
            Self::RunAndFinalize { run, .. } => Some(run),
        }
    }
}

#[derive(Debug)]
pub enum WasiHostError {
    Runtime(RuntimeError),
    DeniedFd(u32),
    NotCapable(u32),
    DescriptorInUse(u32),
    DescriptorExhausted,
    OutputSizeOverflow,
    InvalidInput,
    Loop,
    /// A mutation targeted a read-only preopened mount.
    ReadOnly,
    /// A guest-supplied path exceeded the configured maximum length.
    PathTooLong,
    /// A configured preopen overlaps an existing one (nested or duplicate).
    PreopenOverlap {
        existing: String,
        requested: String,
    },
    /// More preopens were configured than the resource limit allows.
    TooManyPreopens(usize),
    /// A configured preopen path was not a valid absolute path.
    InvalidPreopen(String),
    /// `--buggify-after-setup` was declared but the guest never called
    /// `patina_dst::lifecycle::setup_complete()` — a harness bug, not a silent
    /// no-fault run. Mirrors the native shim's `PATINA_BUGGIFY_SETUP_NEVER_CALLED`.
    BuggifySetupNeverCalled,
}

/// The stderr marker line for the `--buggify-after-setup` gate violation, shared
/// by the [`WasiHostError`] display and the host-side stderr emission so the
/// campaign classifier sees the same token the native shim emits.
const BUGGIFY_SETUP_NEVER_CALLED_MARKER: &str = "PATINA_BUGGIFY_SETUP_NEVER_CALLED --buggify-after-setup was declared but the guest never \
called patina_dst::lifecycle::setup_complete()";

impl fmt::Display for WasiHostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Runtime(error) => error.fmt(f),
            Self::DeniedFd(fd) => write!(f, "WASI fd {fd} is not an allowed deterministic stream"),
            Self::NotCapable(fd) => write!(f, "WASI fd {fd} lacks the required capability"),
            Self::DescriptorInUse(fd) => write!(f, "WASI fd {fd} is already configured"),
            Self::DescriptorExhausted => f.write_str("WASI descriptor table exhausted"),
            Self::OutputSizeOverflow => f.write_str("WASI output size overflowed"),
            Self::InvalidInput => f.write_str("invalid WASI argument"),
            Self::Loop => f.write_str("WASI symlink resolution stopped at a symbolic link"),
            Self::ReadOnly => f.write_str("WASI mutation denied on a read-only preopened mount"),
            Self::PathTooLong => f.write_str("WASI path exceeds the configured maximum length"),
            Self::PreopenOverlap {
                existing,
                requested,
            } => write!(
                f,
                "WASI preopen {requested:?} overlaps the configured mount {existing:?}"
            ),
            Self::TooManyPreopens(limit) => {
                write!(f, "WASI preopens exceed the configured limit of {limit}")
            }
            Self::InvalidPreopen(message) => write!(f, "invalid WASI preopen: {message}"),
            Self::BuggifySetupNeverCalled => f.write_str(BUGGIFY_SETUP_NEVER_CALLED_MARKER),
        }
    }
}

impl std::error::Error for WasiHostError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Runtime(error) => Some(error),
            _ => None,
        }
    }
}

impl From<RuntimeError> for WasiHostError {
    fn from(value: RuntimeError) -> Self {
        Self::Runtime(value)
    }
}

#[cfg(test)]
mod tests;
