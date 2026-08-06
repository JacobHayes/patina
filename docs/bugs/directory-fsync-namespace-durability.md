# Directory fsync namespace durability

Status: fixed.

## Field symptom

Under the native shim, opening a directory read-only (`open(dir, O_RDONLY)` or
`File::open(parent_dir)`) returned `EISDIR`. Guests could not run the standard
namespace durability protocol:

1. write a temporary file;
2. `fsync` the file data;
3. rename/link/unlink in the parent directory;
4. open the parent directory and `fsync` that fd.

SlateDB's local object store had to skip the parent-directory sync, so crash
results around newly published files were uninterpretable: a crash model that
makes renames durable immediately cannot distinguish a correct LSM commit
protocol from a missing-directory-fsync bug.

## Fix

- `MemFs` now supports read-only directory descriptors. `fd_metadata` reports a
  directory, `sync` accepts the descriptor, and ordinary data I/O remains
  fail-closed (`read` returns `IsDirectory`; writes fail because the descriptor is
  not writable). Write-capable directory opens still fail with `IsDirectory`.
- `CrashFs` treats `sync` on a directory fd as `sync_directory(path)`: pending
  creates, links, unlinks, symlinks, and rename sides governed by that directory
  become crash-durable. The default crash model now loses un-fsynced namespace
  changes, matching the conservative unsynced-data behavior.
- The native shim routes read-only `open`/`openat(..., O_DIRECTORY)` directory
  descriptors through the deterministic filesystem, so `fstat` and `fsync` work
  on the same fd. `fdopendir`/`unlinkat` keep using the Patina-issued directory
  mapping. Linux SUD directory fds mirror the same fsync behavior.
- The WASI host now backs opened directory descriptors with deterministic fs
  handles, so `fd_sync`/`fd_datasync` on a directory fd hit the same barrier.

## Evidence

Focused regression coverage:

- `patina-dst-fs-mem::read_only_directory_open_supports_fstat_fsync_and_close_only`
- `patina-dst-fs-crash::directory_fd_sync_commits_namespace_operations`
- `patina-dst-wasi-host::directory_fd_sync_commits_namespace_durability`
- `cargo-patina::native_directory_fsync_guards_namespace_durability_and_replays`

The native e2e is the planted detector: without the parent-directory fsync,
`--fs-crash-at close:1` loses the renamed file; with the parent-directory fsync,
`--fs-crash-at sync:2` keeps it, and a dir-fsync-bearing trace replays
byte-identically.
