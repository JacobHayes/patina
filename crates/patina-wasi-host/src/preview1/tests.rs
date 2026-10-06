//! Tests for WASI Preview 1 import registration.

use super::*;
use crate::tests::{create_write_open, read_open, read_stdout_u64s, seeded_context, seeded_memfs};
use crate::{MountPolicy, execute_preview1};
use patina_dst_runtime::{Context, RuntimeConfig};
use tempfile::tempdir;

#[test]
fn wasm_engine_exercises_symlink_readlink_and_set_times_imports() {
    let module = wat::parse_str(
        r#"(module
                (import "wasi_snapshot_preview1" "path_open"
                    (func $path_open (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
                (import "wasi_snapshot_preview1" "fd_filestat_set_times"
                    (func $fd_filestat_set_times (param i32 i64 i64 i32) (result i32)))
                (import "wasi_snapshot_preview1" "path_symlink"
                    (func $path_symlink (param i32 i32 i32 i32 i32) (result i32)))
                (import "wasi_snapshot_preview1" "path_readlink"
                    (func $path_readlink (param i32 i32 i32 i32 i32 i32) (result i32)))
                (memory (export "memory") 1)
                (data (i32.const 32) "target")
                (data (i32.const 48) "link")
                (func (export "_start")
                    i32.const 3 i32.const 0 i32.const 32 i32.const 6 i32.const 1
                    i64.const 66 i64.const 0 i32.const 0 i32.const 100
                    call $path_open
                    if unreachable end
                    i32.const 100
                    i32.load
                    i64.const 11
                    i64.const 22
                    i32.const 5
                    call $fd_filestat_set_times
                    if unreachable end
                    i32.const 32 i32.const 6 i32.const 3 i32.const 48 i32.const 4
                    call $path_symlink
                    if unreachable end
                    i32.const 3 i32.const 48 i32.const 4 i32.const 80 i32.const 4 i32.const 120
                    call $path_readlink
                    if unreachable end
                    i32.const 120
                    i32.load
                    i32.const 4
                    i32.ne
                    if unreachable end))"#,
    )
    .unwrap();
    let context = Context::from_config(RuntimeConfig::seeded(11)).unwrap();
    assert_eq!(
        execute_preview1(&module, Preview1Host::new(context))
            .unwrap()
            .exit_code,
        0
    );
}

#[test]
fn wasm_engine_exercises_fdstat_set_flags_and_renumber_imports() {
    let module = wat::parse_str(
        r#"(module
                (import "wasi_snapshot_preview1" "path_open"
                    (func $path_open (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
                (import "wasi_snapshot_preview1" "fd_fdstat_set_flags"
                    (func $fd_fdstat_set_flags (param i32 i32) (result i32)))
                (import "wasi_snapshot_preview1" "fd_fdstat_get"
                    (func $fd_fdstat_get (param i32 i32) (result i32)))
                (import "wasi_snapshot_preview1" "fd_renumber"
                    (func $fd_renumber (param i32 i32) (result i32)))
                (import "wasi_snapshot_preview1" "fd_write"
                    (func $fd_write (param i32 i32 i32 i32) (result i32)))
                (memory (export "memory") 1)
                (data (i32.const 0) "\40\00\00\00\01\00\00\00")
                (data (i32.const 32) "wat")
                (data (i32.const 64) "A")
                (func (export "_start")
                    i32.const 3
                    i32.const 0
                    i32.const 32
                    i32.const 3
                    i32.const 1
                    i64.const 66
                    i64.const 0
                    i32.const 0
                    i32.const 100
                    call $path_open
                    if unreachable end
                    i32.const 100
                    i32.load
                    i32.const 1
                    call $fd_fdstat_set_flags
                    if unreachable end
                    i32.const 100
                    i32.load
                    i32.const 104
                    call $fd_fdstat_get
                    if unreachable end
                    i32.const 106
                    i32.load16_u
                    i32.const 1
                    i32.ne
                    if unreachable end
                    i32.const 100
                    i32.load
                    i32.const 8
                    call $fd_renumber
                    if unreachable end
                    i32.const 8
                    i32.const 0
                    i32.const 1
                    i32.const 120
                    call $fd_write
                    if unreachable end))"#,
    )
    .unwrap();
    let context = Context::from_config(RuntimeConfig::seeded(8)).unwrap();
    assert_eq!(
        execute_preview1(&module, Preview1Host::new(context))
            .unwrap()
            .exit_code,
        0
    );
}

#[test]
fn wasm_engine_executes_audited_preview1_and_replays_host_effects() {
    let module = wat::parse_str(
        r#"(module
                (import "wasi_snapshot_preview1" "args_sizes_get"
                    (func $args_sizes_get (param i32 i32) (result i32)))
                (import "wasi_snapshot_preview1" "args_get"
                    (func $args_get (param i32 i32) (result i32)))
                (import "wasi_snapshot_preview1" "environ_sizes_get"
                    (func $environ_sizes_get (param i32 i32) (result i32)))
                (import "wasi_snapshot_preview1" "environ_get"
                    (func $environ_get (param i32 i32) (result i32)))
                (import "wasi_snapshot_preview1" "random_get"
                    (func $random_get (param i32 i32) (result i32)))
                (import "wasi_snapshot_preview1" "clock_res_get"
                    (func $clock_res_get (param i32 i32) (result i32)))
                (import "wasi_snapshot_preview1" "clock_time_get"
                    (func $clock_time_get (param i32 i64 i32) (result i32)))
                (import "wasi_snapshot_preview1" "fd_write"
                    (func $fd_write (param i32 i32 i32 i32) (result i32)))
                (import "wasi_snapshot_preview1" "proc_exit"
                    (func $proc_exit (param i32)))
                (memory (export "memory") 1)
                (data (i32.const 0) "\10\00\00\00\05\00\00\00")
                (data (i32.const 16) "hello")
                (func (export "_start")
                    i32.const 200
                    i32.const 204
                    call $args_sizes_get
                    drop
                    i32.const 208
                    i32.const 300
                    call $args_get
                    drop
                    i32.const 220
                    i32.const 224
                    call $environ_sizes_get
                    drop
                    i32.const 228
                    i32.const 400
                    call $environ_get
                    drop
                    i32.const 1
                    i32.const 500
                    call $clock_res_get
                    drop
                    i32.const 1
                    i64.const 1
                    i32.const 508
                    call $clock_time_get
                    drop
                    i32.const 100
                    i32.const 4
                    call $random_get
                    drop
                    i32.const 1
                    i32.const 0
                    i32.const 1
                    i32.const 8
                    call $fd_write
                    drop
                    i32.const 0
                    call $proc_exit))"#,
    )
    .unwrap();
    let directory = tempdir().unwrap();
    let trace = directory.path().join("engine.patina");
    let context = Context::from_config(RuntimeConfig::record(42, &trace, "engine-v1")).unwrap();
    let recorded = execute_preview1(
        &module,
        Preview1Host::new(context)
            .with_argument("probe.wasm")
            .with_environment("MODE", "record"),
    )
    .unwrap();
    assert_eq!(recorded.exit_code, 0);
    assert_eq!(recorded.stdout, b"hello");

    let context = Context::from_config(RuntimeConfig::replay(&trace, "engine-v1")).unwrap();
    let replayed = execute_preview1(
        &module,
        Preview1Host::new(context)
            .with_argument("probe.wasm")
            .with_environment("MODE", "record"),
    )
    .unwrap();
    assert_eq!(replayed, recorded);
}

#[test]
fn wasi_stat_and_readdir_report_hard_link_identity() {
    let module = wat::parse_str(
        r#"(module
                (import "wasi_snapshot_preview1" "path_filestat_get"
                    (func $path_filestat_get (param i32 i32 i32 i32 i32) (result i32)))
                (import "wasi_snapshot_preview1" "path_unlink_file"
                    (func $path_unlink_file (param i32 i32 i32) (result i32)))
                (import "wasi_snapshot_preview1" "fd_readdir"
                    (func $fd_readdir (param i32 i32 i32 i64 i32) (result i32)))
                (import "wasi_snapshot_preview1" "fd_write"
                    (func $fd_write (param i32 i32 i32 i32) (result i32)))
                (memory (export "memory") 1)
                (data (i32.const 32) "a")
                (data (i32.const 48) "b")
                (func $write8 (param $ptr i32)
                    i32.const 0 local.get $ptr i32.store
                    i32.const 4 i32.const 8 i32.store
                    i32.const 1 i32.const 0 i32.const 1 i32.const 24
                    call $fd_write
                    if unreachable end)
                (func (export "_start")
                    i32.const 3 i32.const 0 i32.const 32 i32.const 1 i32.const 100
                    call $path_filestat_get
                    if unreachable end
                    i32.const 108 call $write8
                    i32.const 124 call $write8
                    i32.const 3 i32.const 0 i32.const 48 i32.const 1 i32.const 200
                    call $path_filestat_get
                    if unreachable end
                    i32.const 208 call $write8
                    i32.const 224 call $write8
                    i32.const 3 i32.const 32 i32.const 1
                    call $path_unlink_file
                    if unreachable end
                    i32.const 3 i32.const 0 i32.const 48 i32.const 1 i32.const 400
                    call $path_filestat_get
                    if unreachable end
                    i32.const 408 call $write8
                    i32.const 424 call $write8
                    i32.const 3 i32.const 500 i32.const 128 i64.const 0 i32.const 700
                    call $fd_readdir
                    if unreachable end
                    i32.const 508 call $write8))"#,
    )
    .unwrap();
    let context = seeded_context(14, &[("/a", b"data")]);
    let mut host = Preview1Host::new(context);
    host.path_link(3, b"a", 3, b"b").unwrap();
    let output = execute_preview1(&module, host).unwrap();
    assert_eq!(output.exit_code, 0);
    let values = read_stdout_u64s(&output.stdout);
    assert_eq!(values.len(), 7);
    let [
        a_ino,
        a_nlink,
        b_ino,
        b_nlink,
        survivor_ino,
        survivor_nlink,
        dirent_ino,
    ] = values.try_into().unwrap();
    assert_eq!(a_ino, b_ino);
    assert_eq!(a_nlink, 2);
    assert_eq!(b_nlink, 2);
    assert_eq!(survivor_ino, b_ino);
    assert_eq!(survivor_nlink, 1);
    assert_eq!(dirent_ino, survivor_ino);
}

#[test]
fn read_only_mount_denies_inline_namespace_calls() {
    // path_create_directory and path_unlink_file run inside the linker and
    // must also honor the read-only mount (EROFS = 69).
    let module = wat::parse_str(
        r#"(module
                (import "wasi_snapshot_preview1" "path_create_directory"
                    (func $mkdir (param i32 i32 i32) (result i32)))
                (import "wasi_snapshot_preview1" "path_unlink_file"
                    (func $unlink (param i32 i32 i32) (result i32)))
                (memory (export "memory") 1)
                (data (i32.const 0) "dir")
                (data (i32.const 16) "file")
                (func (export "_start")
                    (if (i32.ne (call $mkdir (i32.const 3) (i32.const 0) (i32.const 3))
                                (i32.const 69)) (then unreachable))
                    (if (i32.ne (call $unlink (i32.const 3) (i32.const 16) (i32.const 4))
                                (i32.const 69)) (then unreachable))))"#,
    )
    .unwrap();
    let context = Context::from_config(RuntimeConfig::seeded(7)).unwrap();
    let host = Preview1Host::new(context)
        .with_preopen("/ro", MountPolicy::ReadOnly)
        .unwrap();
    assert_eq!(execute_preview1(&module, host).unwrap().exit_code, 0);
}

#[test]
fn multiple_preopens_appear_through_fd_prestat() {
    let module = wat::parse_str(
        r#"(module
                (import "wasi_snapshot_preview1" "fd_prestat_get"
                    (func $prestat (param i32 i32) (result i32)))
                (memory (export "memory") 1)
                (func (export "_start")
                    (if (i32.ne (call $prestat (i32.const 3) (i32.const 0)) (i32.const 0))
                        (then unreachable))
                    (if (i32.ne (call $prestat (i32.const 4) (i32.const 0)) (i32.const 0))
                        (then unreachable))
                    (if (i32.ne (call $prestat (i32.const 5) (i32.const 0)) (i32.const 8))
                        (then unreachable))))"#,
    )
    .unwrap();
    let context = Context::from_config(RuntimeConfig::seeded(6)).unwrap();
    let host = Preview1Host::new(context)
        .with_preopen("/alpha", MountPolicy::ReadWrite)
        .unwrap()
        .with_preopen("/beta", MountPolicy::ReadOnly)
        .unwrap();
    assert_eq!(execute_preview1(&module, host).unwrap().exit_code, 0);
}

#[test]
fn preopen_policy_reads_and_denials_record_and_replay() {
    fn exercise(host: &mut Preview1Host) -> Result<Vec<u8>, WasiHostError> {
        let fd = host.path_open(3, b"seed", read_open())?;
        let bytes = host.fd_read(fd, 16)?;
        host.fd_close(fd)?;
        // A denied write leaves no boundary operation in the trace.
        assert!(matches!(
            host.path_open(3, b"seed", create_write_open()),
            Err(WasiHostError::ReadOnly)
        ));
        let out = host.path_open(4, b"out", create_write_open())?;
        host.fd_write(out, &[b"z"])?;
        host.fd_close(out)?;
        Ok(bytes)
    }

    fn host_for(context: Context) -> Preview1Host {
        Preview1Host::new(context)
            .with_preopen("/ro", MountPolicy::ReadOnly)
            .unwrap()
            .with_preopen("/rw", MountPolicy::ReadWrite)
            .unwrap()
    }

    let directory = tempdir().unwrap();
    let trace = directory.path().join("preopen.patina");
    let record_context =
        patina_dst_runtime::RuntimeBuilder::new(RuntimeConfig::record(9, &trace, "preopen-v1"))
            .with_default_drivers()
            .with_filesystem(seeded_memfs(&[("/ro/seed", b"data")]))
            .build()
            .unwrap();
    let mut record = host_for(record_context);
    let expected = exercise(&mut record).unwrap();
    record.finish().unwrap();

    let replay_context =
        patina_dst_runtime::RuntimeBuilder::new(RuntimeConfig::replay(&trace, "preopen-v1"))
            .with_default_drivers()
            .with_filesystem(seeded_memfs(&[("/ro/seed", b"data")]))
            .build()
            .unwrap();
    let mut replay = host_for(replay_context);
    assert_eq!(exercise(&mut replay).unwrap(), expected);
    replay.finish().unwrap();
}
