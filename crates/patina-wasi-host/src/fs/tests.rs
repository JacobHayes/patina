//! Tests for virtual filesystem descriptors, paths, metadata, and mount capabilities.

use super::*;
use crate::ResourceLimits;
use crate::tests::{create_write_open, directory_open, read_open, seeded_context};
use patina_dst_abi::{ClockKind, Operation};
use patina_dst_runtime::{Context, RuntimeConfig};
use tempfile::tempdir;

#[test]
fn positioned_io_allocation_and_advice_preserve_the_cursor() {
    let context = Context::from_config(RuntimeConfig::seeded(3)).unwrap();
    let mut host = Preview1Host::new(context);
    let rights =
        WASI_RIGHT_FD_READ | WASI_RIGHT_FD_WRITE | WASI_RIGHT_FD_ADVISE | WASI_RIGHT_FD_ALLOCATE;
    let fd = host
        .path_open(
            3,
            b"value",
            WasiPathOpen {
                oflags: WASI_OFLAG_CREATE,
                rights,
                inheriting: 0,
                fdflags: 0,
                follow_symlink: false,
            },
        )
        .unwrap();
    assert_eq!(host.fd_write(fd, &[b"abc"]).unwrap(), 3);
    host.fd_advise(fd).unwrap();
    host.fd_allocate(fd, 8, 2).unwrap();
    assert_eq!(host.fd_metadata(fd).unwrap().0.len, 10);
    assert_eq!(host.fd_seek(fd, 0, SeekWhence::Current).unwrap(), 3);
    assert_eq!(host.fd_pwrite(fd, &[b"X"], 1).unwrap(), 1);
    assert_eq!(host.fd_seek(fd, 0, SeekWhence::Current).unwrap(), 3);
    assert_eq!(host.fd_pread(fd, 3, 0).unwrap(), b"aXc");
    assert_eq!(host.fd_seek(fd, 0, SeekWhence::Current).unwrap(), 3);
    host.fd_close(fd).unwrap();
    host.finish().unwrap();
}

#[test]
fn fdstat_set_flags_controls_append_for_cursor_writes() {
    let context = Context::from_config(RuntimeConfig::seeded(4)).unwrap();
    let mut host = Preview1Host::new(context);
    let rights = WASI_RIGHT_FD_READ | WASI_RIGHT_FD_WRITE;
    let fd = host
        .path_open(
            3,
            b"value",
            WasiPathOpen {
                oflags: WASI_OFLAG_CREATE,
                rights,
                inheriting: 0,
                fdflags: 0,
                follow_symlink: false,
            },
        )
        .unwrap();
    assert_eq!(host.fd_write(fd, &[b"abc"]).unwrap(), 3);
    assert_eq!(host.fd_seek(fd, 0, SeekWhence::Start).unwrap(), 0);
    host.fd_fdstat_set_flags(fd, WASI_FDFLAG_APPEND).unwrap();
    assert!(matches!(
        host.descriptors.get(&fd),
        Some(WasiDescriptor::File { flags, .. }) if *flags == WASI_FDFLAG_APPEND
    ));
    assert_eq!(host.fd_write(fd, &[b"Z"]).unwrap(), 1);
    assert_eq!(host.fd_seek(fd, 0, SeekWhence::Current).unwrap(), 4);
    assert_eq!(host.fd_pwrite(fd, &[b"X"], 1).unwrap(), 1);
    assert_eq!(host.fd_seek(fd, 0, SeekWhence::Current).unwrap(), 4);
    assert_eq!(host.fd_pread(fd, 4, 0).unwrap(), b"aXcZ");
    assert!(matches!(
        host.fd_fdstat_set_flags(fd, WASI_FDFLAGS_ALL | 0x20),
        Err(WasiHostError::Runtime(RuntimeError::Effect(error)))
            if error.code == ErrorCode::InvalidInput
    ));
    assert!(matches!(
        host.fd_fdstat_set_flags(99, 0),
        Err(WasiHostError::DeniedFd(99))
    ));
    host.fd_close(fd).unwrap();
    host.finish().unwrap();
}

#[test]
fn fdstat_set_rights_only_narrows_file_capabilities() {
    let context = Context::from_config(RuntimeConfig::seeded(5)).unwrap();
    let mut host = Preview1Host::new(context);
    let fd = host
        .path_open(
            3,
            b"rights",
            WasiPathOpen {
                oflags: WASI_OFLAG_CREATE,
                rights: WASI_RIGHT_FD_READ | WASI_RIGHT_FD_WRITE,
                inheriting: 0,
                fdflags: 0,
                follow_symlink: false,
            },
        )
        .unwrap();
    assert_eq!(host.fd_write(fd, &[b"abc"]).unwrap(), 3);
    assert_eq!(host.fd_seek(fd, 0, SeekWhence::Start).unwrap(), 0);
    host.fd_fdstat_set_rights(fd, WASI_RIGHT_FD_READ, 0)
        .unwrap();
    assert!(matches!(
        host.fd_write(fd, &[b"x"]),
        Err(WasiHostError::NotCapable(closed)) if closed == fd
    ));
    assert_eq!(host.fd_read(fd, 3).unwrap(), b"abc");
    assert!(matches!(
        host.fd_fdstat_set_rights(fd, WASI_RIGHT_FD_READ | WASI_RIGHT_FD_WRITE, 0),
        Err(WasiHostError::NotCapable(closed)) if closed == fd
    ));
    assert!(matches!(
        host.fd_fdstat_set_rights(fd, WASI_RIGHT_FD_READ, WASI_RIGHT_FD_READ),
        Err(WasiHostError::NotCapable(closed)) if closed == fd
    ));
    assert!(matches!(
        host.fd_fdstat_set_rights(99, 0, 0),
        Err(WasiHostError::DeniedFd(99))
    ));
    host.fd_close(fd).unwrap();
    host.finish().unwrap();
}

#[test]
fn fd_renumber_moves_descriptors_and_closes_the_target() {
    let context = Context::from_config(RuntimeConfig::seeded(6)).unwrap();
    let mut host = Preview1Host::new(context);
    let rights = WASI_RIGHT_FD_READ | WASI_RIGHT_FD_WRITE;
    let from = host
        .path_open(
            3,
            b"from",
            WasiPathOpen {
                oflags: WASI_OFLAG_CREATE,
                rights,
                inheriting: 0,
                fdflags: 0,
                follow_symlink: false,
            },
        )
        .unwrap();
    let to = host
        .path_open(
            3,
            b"to",
            WasiPathOpen {
                oflags: WASI_OFLAG_CREATE,
                rights,
                inheriting: 0,
                fdflags: 0,
                follow_symlink: false,
            },
        )
        .unwrap();
    let target_handle = match host.descriptors.get(&to) {
        Some(WasiDescriptor::File { handle, .. }) => *handle,
        _ => unreachable!("path_open creates file descriptors"),
    };
    host.fd_renumber(from, to).unwrap();
    assert!(!host.descriptors.contains_key(&from));
    assert!(matches!(
        host.descriptors.get(&to),
        Some(WasiDescriptor::File { path, .. }) if path == "/from"
    ));
    assert!(matches!(
        host.context.fs_write(target_handle, b"x"),
        Err(RuntimeError::Effect(error)) if error.code == ErrorCode::InvalidHandle
    ));
    assert_eq!(host.fd_write(to, &[b"ok"]).unwrap(), 2);
    host.fd_renumber(to, to).unwrap();
    assert!(matches!(
        host.fd_renumber(99, to),
        Err(WasiHostError::DeniedFd(99))
    ));
    assert!(matches!(
        host.fd_renumber(3, to),
        Err(WasiHostError::DeniedFd(3))
    ));
    host.fd_close(to).unwrap();
    host.finish().unwrap();
}

#[test]
fn filestat_set_times_supports_explicit_and_now_values() {
    let context = Context::from_config(RuntimeConfig::seeded(9)).unwrap();
    let mut host = Preview1Host::new(context);
    let rights = WASI_RIGHT_FD_READ | WASI_RIGHT_FD_WRITE;
    let fd = host
        .path_open(
            3,
            b"times",
            WasiPathOpen {
                oflags: WASI_OFLAG_CREATE,
                rights,
                inheriting: 0,
                fdflags: 0,
                follow_symlink: false,
            },
        )
        .unwrap();
    host.fd_filestat_set_times(fd, Some(11), Some(22)).unwrap();
    assert_eq!(host.fd_metadata(fd).unwrap().0.atime_nanos, 11);
    assert_eq!(host.fd_metadata(fd).unwrap().0.mtime_nanos, 22);
    // A realtime deadline 77ns past the current reading: NOW resolves to it.
    let wake = host.clock_time_get(WasiClock::Realtime).unwrap() + 77;
    host.sleep_until(WasiClock::Realtime, wake).unwrap();
    let (atime, mtime) = host
        .filestat_set_times_values(0, 0, WASI_FSTFLAG_ATIM_NOW | WASI_FSTFLAG_MTIM_NOW)
        .unwrap();
    assert_eq!((atime, mtime), (Some(wake), Some(wake)));
    host.fd_filestat_set_times(fd, atime, mtime).unwrap();
    assert_eq!(
        host.fd_metadata(fd).unwrap().0.atime_nanos,
        i128::from(wake)
    );
    assert!(matches!(
        host.filestat_set_times_values(1, 2, WASI_FSTFLAG_ATIM | WASI_FSTFLAG_ATIM_NOW),
        Err(WasiHostError::InvalidInput)
    ));
    host.path_filestat_set_times(3, b"times", false, Some(33), None)
        .unwrap();
    assert_eq!(host.fd_metadata(fd).unwrap().0.atime_nanos, 33);
    host.fd_close(fd).unwrap();
    host.finish().unwrap();

    let directory = tempdir().unwrap();
    let trace = directory.path().join("set-times-now.patina");
    let context =
        Context::from_config(RuntimeConfig::record(9, &trace, "set-times-now-v1")).unwrap();
    let mut record = Preview1Host::new(context);
    let values = record
        .filestat_set_times_values(0, 0, WASI_FSTFLAG_ATIM_NOW | WASI_FSTFLAG_MTIM_NOW)
        .unwrap();
    assert_eq!(values.0, values.1);
    record.finish().unwrap();
    let bundle = patina_dst_trace::TraceBundle::load(&trace).unwrap();
    let clock_now_count = bundle.timelines[0]
        .decisions
        .iter()
        .filter(|event| {
            matches!(
                event.operation,
                Operation::ClockNow {
                    clock: ClockKind::Realtime
                }
            )
        })
        .count();
    assert_eq!(clock_now_count, 1);
}

#[test]
fn links_symlinks_and_terminal_follow_are_deterministic() {
    let context = Context::from_config(RuntimeConfig::seeded(10)).unwrap();
    let mut host = Preview1Host::new(context);
    let rights = WASI_RIGHT_FD_READ | WASI_RIGHT_FD_WRITE;
    let fd = host
        .path_open(
            3,
            b"target",
            WasiPathOpen {
                oflags: WASI_OFLAG_CREATE,
                rights,
                inheriting: 0,
                fdflags: 0,
                follow_symlink: false,
            },
        )
        .unwrap();
    assert_eq!(host.fd_write(fd, &[b"abc"]).unwrap(), 3);
    host.fd_close(fd).unwrap();
    host.path_link(3, b"target", 3, b"linked").unwrap();
    let linked = host
        .path_open(
            3,
            b"linked",
            WasiPathOpen {
                oflags: 0,
                rights: WASI_RIGHT_FD_READ,
                inheriting: 0,
                fdflags: 0,
                follow_symlink: false,
            },
        )
        .unwrap();
    assert_eq!(host.fd_read(linked, 3).unwrap(), b"abc");
    host.fd_close(linked).unwrap();
    host.path_symlink(b"target", 3, b"link").unwrap();
    assert_eq!(host.path_readlink(3, b"link").unwrap(), "target");
    assert!(matches!(
        host.path_open(
            3,
            b"link",
            WasiPathOpen {
                oflags: 0,
                rights: WASI_RIGHT_FD_READ,
                inheriting: 0,
                fdflags: 0,
                follow_symlink: false
            }
        ),
        Err(WasiHostError::Loop)
    ));
    let followed = host
        .path_open(
            3,
            b"link",
            WasiPathOpen {
                oflags: 0,
                rights: WASI_RIGHT_FD_READ,
                inheriting: 0,
                fdflags: 0,
                follow_symlink: true,
            },
        )
        .unwrap();
    assert_eq!(host.fd_read(followed, 3).unwrap(), b"abc");
    host.fd_close(followed).unwrap();
    host.path_symlink(b"link", 3, b"link2").unwrap();
    assert!(matches!(
        host.path_open(
            3,
            b"link2",
            WasiPathOpen {
                oflags: 0,
                rights: WASI_RIGHT_FD_READ,
                inheriting: 0,
                fdflags: 0,
                follow_symlink: true
            }
        ),
        Err(WasiHostError::Loop)
    ));
    host.path_symlink(b"target", 3, b"mid").unwrap();
    assert!(matches!(
        host.path_readlink(3, b"mid/x"),
        Err(WasiHostError::Runtime(RuntimeError::Effect(error)))
            if error.code == ErrorCode::Denied
    ));
    host.finish().unwrap();
}

#[test]
fn new_filesystem_operations_record_and_replay() {
    fn exercise_new_ops(host: &mut Preview1Host) -> Result<Vec<u8>, WasiHostError> {
        let rights = WASI_RIGHT_FD_READ | WASI_RIGHT_FD_WRITE;
        let fd = host.path_open(
            3,
            b"a",
            WasiPathOpen {
                oflags: WASI_OFLAG_CREATE,
                rights,
                inheriting: 0,
                fdflags: 0,
                follow_symlink: false,
            },
        )?;
        host.fd_write(fd, &[b"abc"])?;
        host.fd_filestat_set_times(fd, Some(1), Some(2))?;
        host.fd_close(fd)?;
        host.path_link(3, b"a", 3, b"b")?;
        host.path_symlink(b"b", 3, b"l")?;
        let fd = host.path_open(
            3,
            b"l",
            WasiPathOpen {
                oflags: 0,
                rights: WASI_RIGHT_FD_READ,
                inheriting: 0,
                fdflags: 0,
                follow_symlink: true,
            },
        )?;
        let bytes = host.fd_read(fd, 3)?;
        host.fd_close(fd)?;
        Ok(bytes)
    }

    let directory = tempdir().unwrap();
    let trace = directory.path().join("new-fs.patina");
    let context = Context::from_config(RuntimeConfig::record(43, &trace, "new-fs-v1")).unwrap();
    let mut record = Preview1Host::new(context);
    let expected = exercise_new_ops(&mut record).unwrap();
    record.finish().unwrap();

    let context = Context::from_config(RuntimeConfig::replay(&trace, "new-fs-v1")).unwrap();
    let mut replay = Preview1Host::new(context);
    assert_eq!(exercise_new_ops(&mut replay).unwrap(), expected);
    replay.finish().unwrap();
}

#[test]
fn directory_fd_sync_commits_namespace_durability() {
    let context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
    let mut host = Preview1Host::new(context);
    let tmp = host.path_open(3, b"ns.tmp", create_write_open()).unwrap();
    host.fd_write(tmp, &[b"stable"]).unwrap();
    host.fd_sync(tmp).unwrap();
    host.fd_close(tmp).unwrap();
    host.context.fs_rename("/ns.tmp", "/final").unwrap();

    let root = host.path_open(3, b".", directory_open()).unwrap();
    host.fd_sync(root).unwrap();
    host.fd_close(root).unwrap();
    host.context.fs_crash().unwrap();

    let final_fd = host.path_open(3, b"final", read_open()).unwrap();
    assert_eq!(host.fd_read(final_fd, 16).unwrap(), b"stable");
}

#[test]
fn read_only_preopen_denies_mutations_but_allows_reads() {
    let context = seeded_context(1, &[("/ro/seed", b"data"), ("/ro/old", b"x")]);
    // fd 3 = /ro (read-only), fd 4 = /rw (read-write).
    let mut host = Preview1Host::new(context)
        .with_preopen("/ro", MountPolicy::ReadOnly)
        .unwrap()
        .with_preopen("/rw", MountPolicy::ReadWrite)
        .unwrap();

    // Reads and metadata are allowed.
    let fd = host.path_open(3, b"seed", read_open()).unwrap();
    assert_eq!(host.fd_read(fd, 16).unwrap(), b"data");
    host.fd_close(fd).unwrap();

    // Every mutation kind is denied with EROFS, regardless of requested rights.
    assert!(matches!(
        host.path_open(3, b"created", create_write_open()),
        Err(WasiHostError::ReadOnly)
    ));
    assert!(matches!(
        host.path_open(3, b"seed", create_write_open()),
        Err(WasiHostError::ReadOnly)
    ));
    assert!(matches!(
        host.path_filestat_set_times(3, b"seed", true, Some(1), Some(2)),
        Err(WasiHostError::ReadOnly)
    ));
    assert!(matches!(
        host.path_symlink(b"seed", 3, b"link"),
        Err(WasiHostError::ReadOnly)
    ));
    assert!(matches!(
        host.path_link(3, b"seed", 3, b"hardlink"),
        Err(WasiHostError::ReadOnly)
    ));

    // The sibling read-write mount is unaffected.
    let out = host.path_open(4, b"out", create_write_open()).unwrap();
    assert_eq!(host.fd_write(out, &[b"ok"]).unwrap(), 2);
    host.fd_close(out).unwrap();
    host.finish().unwrap();
}

#[test]
fn path_link_denies_read_only_source_alias_bypass() {
    let context = seeded_context(
        12,
        &[
            ("/ro/secret", b"secret"),
            ("/rw/source", b"data"),
            ("/rw/.keep", b""),
        ],
    );
    let mut host = Preview1Host::new(context)
        .with_preopen("/ro", MountPolicy::ReadOnly)
        .unwrap()
        .with_preopen("/rw", MountPolicy::ReadWrite)
        .unwrap();

    assert!(matches!(
        host.path_link(3, b"secret", 4, b"alias"),
        Err(WasiHostError::ReadOnly)
    ));
    let secret = host.path_open(3, b"secret", read_open()).unwrap();
    assert_eq!(host.fd_read(secret, 16).unwrap(), b"secret");
    host.fd_close(secret).unwrap();
    assert!(matches!(
        host.path_open(4, b"alias", read_open()),
        Err(WasiHostError::Runtime(RuntimeError::Effect(error)))
            if error.code == ErrorCode::NotFound
    ));

    host.path_link(4, b"source", 4, b"source-link").unwrap();
    let linked = host.path_open(4, b"source-link", read_open()).unwrap();
    assert_eq!(host.fd_read(linked, 16).unwrap(), b"data");
    host.fd_close(linked).unwrap();
    host.finish().unwrap();
}

#[test]
fn fd_filestat_set_size_denies_read_only_mount_even_with_write_right() {
    let context = seeded_context(13, &[("/ro/seed", b"data")]);
    let mut host = Preview1Host::new(context);
    let fd = host
        .path_open(
            3,
            b"ro/seed",
            WasiPathOpen {
                oflags: 0,
                rights: WASI_RIGHT_FD_READ | WASI_RIGHT_FD_WRITE,
                inheriting: 0,
                fdflags: 0,
                follow_symlink: true,
            },
        )
        .unwrap();
    host.mounts.clear();
    host.mounts.insert("/ro".to_owned(), MountPolicy::ReadOnly);

    assert!(matches!(
        host.fd_filestat_set_size(fd, 99),
        Err(WasiHostError::ReadOnly)
    ));
    assert_eq!(host.fd_metadata(fd).unwrap().0.len, 4);
    host.fd_close(fd).unwrap();
    host.finish().unwrap();
}

#[test]
fn descriptor_and_path_length_limits_are_enforced() {
    let context = seeded_context(3, &[("/a", b"1"), ("/b", b"2"), ("/c", b"3")]);
    let mut host = Preview1Host::new(context).with_resource_limits(ResourceLimits {
        max_descriptors: 3,
        ..ResourceLimits::default()
    });
    // The root preopen occupies one slot, so two opens fit and the third fails.
    let _a = host.path_open(3, b"a", read_open()).unwrap();
    let _b = host.path_open(3, b"b", read_open()).unwrap();
    assert!(matches!(
        host.path_open(3, b"c", read_open()),
        Err(WasiHostError::DescriptorExhausted)
    ));

    let mut host = Preview1Host::new(seeded_context(4, &[])).with_resource_limits(ResourceLimits {
        max_path_bytes: 4,
        ..ResourceLimits::default()
    });
    assert!(matches!(
        host.path_open(3, b"toolong", read_open()),
        Err(WasiHostError::PathTooLong)
    ));

    let over = Preview1Host::new(seeded_context(4, &[]))
        .with_resource_limits(ResourceLimits {
            max_preopens: 1,
            ..ResourceLimits::default()
        })
        .with_preopen("/first", MountPolicy::ReadWrite)
        .unwrap()
        .with_preopen("/second", MountPolicy::ReadWrite);
    assert!(matches!(over, Err(WasiHostError::TooManyPreopens(1))));
}
