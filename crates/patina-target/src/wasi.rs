//! WASI import metadata and fail-closed import auditing.

use crate::TargetError;
use wasmparser::{Parser, Payload};

pub const WASI_PREVIEW1_TARGET: &str = "wasm32-wasip1";
pub const WASI_PREVIEW1_MODULE: &str = "wasi_snapshot_preview1";

/// Preview 1 imports implemented by the deterministic host adapter.
pub const SUPPORTED_PREVIEW1_IMPORTS: &[&str] = &[
    "args_get",
    "args_sizes_get",
    "clock_res_get",
    "clock_time_get",
    "environ_get",
    "environ_sizes_get",
    "fd_advise",
    "fd_allocate",
    "fd_close",
    "fd_datasync",
    "fd_fdstat_get",
    "fd_fdstat_set_flags",
    "fd_fdstat_set_rights",
    "fd_filestat_get",
    "fd_filestat_set_size",
    "fd_filestat_set_times",
    "fd_pread",
    "fd_prestat_dir_name",
    "fd_prestat_get",
    "fd_pwrite",
    "fd_read",
    "fd_readdir",
    "fd_renumber",
    "fd_seek",
    "fd_sync",
    "fd_tell",
    "fd_write",
    "path_create_directory",
    "path_filestat_get",
    "path_filestat_set_times",
    "path_link",
    "path_open",
    "path_readlink",
    "path_remove_directory",
    "path_rename",
    "path_symlink",
    "path_unlink_file",
    "poll_oneoff",
    "proc_exit",
    "proc_raise",
    "random_get",
    "sched_yield",
    "sock_accept",
    "sock_recv",
    "sock_send",
    "sock_shutdown",
];

/// The cooperative-SUT SDK import module a patina-built wasm guest links
/// against (the wasm mirror of the native shim's C ABI).
pub const PATINA_SDK_MODULE: &str = "patina_sdk";

/// SDK imports implemented by the deterministic WASI host. Allowlisted
/// UNCONDITIONALLY (not gated on `--buggify`): the import surface is a
/// link-time fact of a patina-built module, while whether buggify fires is a
/// run-time decision — sites are inert when disabled, mirroring native. The
/// security posture of the audit is unchanged: this module's effect surface is
/// a strict subset of what preview1 already grants (`rng` is the same seeded
/// entropy as `random_get`; every other function only mutates sandboxed SDK
/// state — site registries, assertion counters, lifecycle marks — with no
/// host effect). A module built without `cfg(patina)` carries none of these
/// imports.
pub const SUPPORTED_PATINA_SDK_IMPORTS: &[&str] = &[
    "buggify",
    "buggify_delay",
    "buggify_knob",
    "always",
    "sometimes",
    "reachable",
    "is_simulated",
    "rng",
    "lifecycle_setup_complete",
    "lifecycle_event",
    // The verdict ABI. Its effect surface is a structured record in the host's
    // own run state plus a diagnostic line — strictly less than `fd_write`
    // already grants.
    "verdict",
    // The custom-op ABI. These grant the guest NO new reach: the real effect a
    // custom op wraps is performed by the guest's own code, through whatever
    // imports it already has (and audited as such). These three only move opaque
    // bytes between the guest and the host's recorded trace.
    "custom_op_begin",
    "custom_op_replay_result",
    "custom_op_record",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WasmImport {
    pub module: String,
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WasiAudit {
    pub imports: Vec<WasmImport>,
}

impl WasiAudit {
    pub fn audit(bytes: &[u8]) -> Result<Self, TargetError> {
        let mut imports = Vec::new();
        for payload in Parser::new(0).parse_all(bytes) {
            if let Payload::ImportSection(reader) = payload.map_err(TargetError::Parse)? {
                for group in reader {
                    for import in group.map_err(TargetError::Parse)? {
                        let (_, import) = import.map_err(TargetError::Parse)?;
                        imports.push(WasmImport {
                            module: import.module.into(),
                            name: import.name.into(),
                        });
                    }
                }
            }
        }
        fn import_is_supported(import: &WasmImport) -> bool {
            match import.module.as_str() {
                WASI_PREVIEW1_MODULE => SUPPORTED_PREVIEW1_IMPORTS.contains(&import.name.as_str()),
                PATINA_SDK_MODULE => SUPPORTED_PATINA_SDK_IMPORTS.contains(&import.name.as_str()),
                _ => false,
            }
        }
        let unsupported = imports
            .iter()
            .filter(|import| !import_is_supported(import))
            .cloned()
            .collect::<Vec<_>>();
        if !unsupported.is_empty() {
            return Err(TargetError::UnsupportedImports(unsupported));
        }
        Ok(Self { imports })
    }
}

#[cfg(test)]
mod tests;
