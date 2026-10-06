//! Guest resource ceilings and Wasmi store limits.

use wasmi::{StoreLimits, StoreLimitsBuilder};

const MAX_WASI_IOVECS: usize = 1_024;

const MAX_WASI_IO_BYTES: usize = 16 * 1024 * 1024;

/// Size of one WebAssembly linear-memory page.
const WASM_PAGE_BYTES: usize = 64 * 1024;

/// Generous default guest linear-memory cap: 4096 pages (256 MiB).
const DEFAULT_MAX_MEMORY_PAGES: u32 = 4_096;

/// Default ceiling on simultaneously open descriptors (preopens included).
const DEFAULT_MAX_DESCRIPTORS: usize = 1_024;

/// Default ceiling on configured preopened directories.
const DEFAULT_MAX_PREOPENS: usize = 64;

/// Default ceiling on a single guest-supplied path in bytes.
const DEFAULT_MAX_PATH_BYTES: usize = 4_096;

pub const DEFAULT_WASM_FUEL: u64 = 10_000_000;

/// Access policy applied to a preopened directory and everything under it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MountPolicy {
    /// Reads and metadata are allowed; every mutation is denied.
    ReadOnly,
    /// Full read/write access.
    ReadWrite,
}

/// Deterministic, fail-closed resource ceilings for one guest execution.
///
/// Every limit is enforced as a typed deterministic error or trap, never a
/// silent fallthrough. Defaults are generous but bounded, not unlimited.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResourceLimits {
    /// Wasmi fuel budget for the whole run (also caps CPU work).
    pub fuel: u64,
    /// Maximum guest linear-memory size in 64 KiB pages. Growth past this is a
    /// deterministic trap.
    pub max_memory_pages: u32,
    /// Maximum iovec entries accepted by a single scatter/gather call.
    pub max_iovecs: usize,
    /// Maximum bytes moved by a single read/write/path operation.
    pub max_io_bytes: usize,
    /// Maximum simultaneously open descriptors, preopens included.
    pub max_descriptors: usize,
    /// Maximum configured preopened directories.
    pub max_preopens: usize,
    /// Maximum length in bytes of a single guest-supplied path.
    pub max_path_bytes: usize,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            fuel: DEFAULT_WASM_FUEL,
            max_memory_pages: DEFAULT_MAX_MEMORY_PAGES,
            max_iovecs: MAX_WASI_IOVECS,
            max_io_bytes: MAX_WASI_IO_BYTES,
            max_descriptors: DEFAULT_MAX_DESCRIPTORS,
            max_preopens: DEFAULT_MAX_PREOPENS,
            max_path_bytes: DEFAULT_MAX_PATH_BYTES,
        }
    }
}

pub(super) fn build_store_limits(max_memory_pages: u32) -> StoreLimits {
    let bytes = (max_memory_pages as usize).saturating_mul(WASM_PAGE_BYTES);
    StoreLimitsBuilder::new()
        .memory_size(bytes)
        .trap_on_grow_failure(true)
        .build()
}
