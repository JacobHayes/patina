//! Tests for filesystem effects, timestamps, file helpers, and crash injection.

use crate::builder::RuntimeBuilder;
use crate::config::RuntimeConfig;
use crate::filesystem::FsTime;
use crate::{Context, DEFAULT_BOOT_ORIGIN_NANOS, DEFAULT_REALTIME_EPOCH_NANOS, RuntimeError};
use patina_dst_abi::{
    ClockKind, EffectError, ErrorCode, Fd, FsClock, OpenFlags, Operation, Outcome, SeekWhence,
};
use patina_dst_driver_api::FsDriver;

use patina_dst_fs_host::HostCaptureFs;
use patina_dst_fs_mem::MemFs;
use patina_dst_time_virtual::VirtualClock;
use patina_dst_trace::{TraceBundle, TraceError};
use patina_dst_wrapper_fault::FaultFs;

use tempfile::tempdir;

#[test]
fn filesystem_attribute_latency_repeats_and_replays() {
    // Class pairing: strict boundary replay and the post-latency clock sampler.
    fn exercise(ctx: &mut Context) {
        ctx.fs_create_directory("/d", 0o755).unwrap();
        let fd = ctx
            .fs_open("/d/f", OpenFlags::create_truncate_write())
            .unwrap();
        ctx.fs_write(fd, b"hello").unwrap();
        ctx.fs_set_len(fd, 2).unwrap();
        ctx.fs_set_times_spec(fd, FsTime::Now, FsTime::Now).unwrap();
        let m = ctx.fs_fd_metadata(fd).unwrap();
        assert_eq!(m.atime_nanos, m.ctime_nanos);
        assert_eq!(m.mtime_nanos, m.ctime_nanos);
        ctx.fs_set_times_by_path_spec("/d/f", FsTime::Omit, FsTime::Now)
            .unwrap();
        ctx.fs_make_fifo("/d/p", 0o600).unwrap();
        let ino = ctx.fs_metadata("/d/p").unwrap().ino;
        ctx.fs_retain_inode(ino).unwrap();
        ctx.fs_remove_file("/d/p").unwrap();
        ctx.fs_set_inode_times_spec(ino, FsTime::Now, FsTime::Now)
            .unwrap();
        let m = ctx.fs_inode_metadata(ino).unwrap();
        assert_eq!(m.atime_nanos, m.ctime_nanos);
        ctx.fs_release_inode(ino).unwrap();
        ctx.fs_close(fd).unwrap();
    }
    let directory = tempdir().unwrap();
    let a = directory.path().join("a.patina");
    let b = directory.path().join("b.patina");
    for path in [&a, &b] {
        let mut ctx = Context::from_config(
            RuntimeConfig::record(7, path, "attrs").with_fs_latency_nanos(10, 10),
        )
        .unwrap();
        exercise(&mut ctx);
        ctx.finish().unwrap();
    }
    assert_eq!(std::fs::read(&a).unwrap(), std::fs::read(&b).unwrap());
    let mut ctx = Context::from_config(RuntimeConfig::replay(&a, "attrs")).unwrap();
    exercise(&mut ctx);
    ctx.finish().unwrap();
}

/// The unrecorded cursor, metadata and path queries leave no trace op: a run
/// that asks them records the same trace as one that does not, and that
/// trace replays a run that asks them.
#[test]
fn unrecorded_filesystem_queries_leave_no_trace_op() {
    fn exercise(ctx: &mut Context, ask: bool) {
        let fd = ctx
            .fs_open("/f", OpenFlags::create_truncate_write())
            .unwrap();
        ctx.fs_write(fd, b"hello").unwrap();
        if ask {
            assert_eq!(ctx.fs_cursor_unrecorded(fd).unwrap(), 5);
            let by_fd = ctx.fs_fd_metadata_unrecorded(fd).unwrap();
            assert_eq!(by_fd.len, 5);
            let by_path = ctx.fs_metadata_unrecorded("/f").unwrap();
            assert_eq!(by_path.ino, by_fd.ino);
            assert_eq!(ctx.fs_fd_path_unrecorded(fd).unwrap(), "/f");
        }
        ctx.fs_close(fd).unwrap();
    }
    let directory = tempdir().unwrap();
    let asked = directory.path().join("asked.patina");
    let quiet = directory.path().join("quiet.patina");
    for (path, ask) in [(&asked, true), (&quiet, false)] {
        let mut ctx = Context::from_config(RuntimeConfig::record(7, path, "queries")).unwrap();
        exercise(&mut ctx, ask);
        ctx.finish().unwrap();
    }
    assert_eq!(
        std::fs::read(&asked).unwrap(),
        std::fs::read(&quiet).unwrap()
    );
    let mut ctx = Context::from_config(RuntimeConfig::replay(&quiet, "queries")).unwrap();
    exercise(&mut ctx, true);
    ctx.finish().unwrap();
}

/// The unrecorded metadata queries are never faulted: under a fault knob
/// that fails every eligible operation they answer what the filesystem
/// holds, and they draw nothing from the fault stream.
#[test]
fn unrecorded_filesystem_queries_are_never_faulted() {
    let mut inner = MemFs::new();
    let fd = inner
        .open(FsClock::EPOCH, "/f", OpenFlags::create_truncate_write())
        .unwrap();
    let expected = inner.fd_metadata(fd).unwrap();
    let mut ctx = RuntimeBuilder::new(RuntimeConfig::seeded(1))
        .with_filesystem(FaultFs::new(inner, 3).error_permille(1000))
        .build()
        .unwrap();
    assert_eq!(ctx.fs_fd_metadata_unrecorded(fd).unwrap(), expected);
    assert_eq!(ctx.fs_metadata_unrecorded("/f").unwrap(), expected);
    assert_eq!(ctx.fs_fault_report().unwrap().eligible_ops, 0);
    // The recorded read is a guest operation, and the knob fails it.
    assert!(ctx.fs_fd_metadata(fd).is_err());
    assert_eq!(ctx.fs_fault_report().unwrap().eligible_ops, 1);
}

#[test]
fn filesystem_without_a_clock_refuses_instead_of_stamping_epoch() {
    let mut ctx = RuntimeBuilder::new(RuntimeConfig::seeded(1))
        .with_filesystem(MemFs::new())
        .build()
        .unwrap();
    let error = ctx
        .fs_open("/f", OpenFlags::create_truncate_write())
        .unwrap_err();
    assert!(error.to_string().contains("no clock driver"));
}

#[test]
fn filesystem_mutations_sample_after_latency() {
    // Class pairing: the clocked filesystem choke point and trace replay.
    let mut context =
        Context::from_config(RuntimeConfig::seeded(1).with_fs_latency_nanos(10, 10)).unwrap();
    context.fs_create_directory("/d", 0o755).unwrap();
    // Realtime stamps: epoch + boot origin + the modeled latency.
    assert_eq!(
        context.fs_metadata("/d").unwrap().btime_nanos,
        i128::from(DEFAULT_REALTIME_EPOCH_NANOS + DEFAULT_BOOT_ORIGIN_NANOS + 10)
    );
    let fd = context
        .fs_open("/d/f", OpenFlags::create_truncate_write())
        .unwrap();
    context.fs_set_len(fd, 2).unwrap();
    let now = context.now(ClockKind::Realtime).unwrap();
    assert_eq!(
        context.fs_fd_metadata(fd).unwrap().mtime_nanos,
        i128::from(now)
    );
    context.fs_set_times(fd, Some(1), Some(2)).unwrap();
    let now = context.now(ClockKind::Realtime).unwrap();
    assert_eq!(
        context.fs_fd_metadata(fd).unwrap().ctime_nanos,
        i128::from(now)
    );
}

pub(crate) struct WrongHandleFs;

impl FsDriver for WrongHandleFs {
    fn open(&mut self, _clock: FsClock, _path: &str, _flags: OpenFlags) -> Result<Fd, EffectError> {
        Ok(Fd(999))
    }

    fn read(&mut self, _clock: FsClock, _fd: Fd, _max_len: usize) -> Result<Vec<u8>, EffectError> {
        unreachable!()
    }

    fn write(&mut self, _clock: FsClock, _fd: Fd, _bytes: &[u8]) -> Result<usize, EffectError> {
        unreachable!()
    }

    fn close(&mut self, _fd: Fd) -> Result<(), EffectError> {
        unreachable!()
    }
}

#[test]
fn fs_dup_records_replays_and_reconciles_handle_identity() {
    fn exercise_dup(context: &mut Context) -> Result<Vec<u8>, RuntimeError> {
        let write = context.fs_open("/value", OpenFlags::create_truncate_write())?;
        context.fs_write(write, b"abcdef")?;
        context.fs_close(write)?;
        let first = context.fs_open("/value", OpenFlags::read_only())?;
        let second = context.fs_dup(first)?;
        assert_eq!(second, Fd(first.0 + 1));
        context.fs_seek(second, 1, SeekWhence::Start)?;
        let bytes = context.fs_read(first, 2)?;
        context.fs_close(first)?;
        context.fs_close(second)?;
        Ok(bytes)
    }

    let directory = tempdir().unwrap();
    let trace = directory.path().join("dup.patina");
    let mut record = Context::from_config(RuntimeConfig::record(11, &trace, "dup-v1")).unwrap();
    assert_eq!(exercise_dup(&mut record).unwrap(), b"bc");
    record.finish().unwrap();

    let mut replay = Context::from_config(RuntimeConfig::replay(&trace, "dup-v1")).unwrap();
    assert_eq!(exercise_dup(&mut replay).unwrap(), b"bc");
    replay.finish().unwrap();

    let mut tampered = TraceBundle::load(&trace).unwrap();
    for event in &mut tampered.timelines[0].decisions {
        if matches!(event.operation, Operation::FsDup { .. }) {
            event.outcome = Outcome::Handle(Fd(999));
            break;
        }
    }
    let tampered_path = directory.path().join("dup-tampered.patina");
    tampered.write_atomic(&tampered_path).unwrap();
    let mut replay = Context::from_config(RuntimeConfig::replay(&tampered_path, "dup-v1")).unwrap();
    let error = exercise_dup(&mut replay).unwrap_err();
    assert!(matches!(
        error,
        RuntimeError::Trace(TraceError::OutcomeMismatch { .. })
    ));
}

#[test]
fn captured_host_files_replay_without_host_access_and_fail_on_branch_miss() {
    let directory = tempdir().unwrap();
    let host = directory.path().join("host");
    std::fs::create_dir(&host).unwrap();
    std::fs::write(host.join("value"), b"captured").unwrap();
    let trace = directory.path().join("capture.patina");

    let config = RuntimeConfig::record(3, &trace, "capture-v1");
    let mut record = RuntimeBuilder::new(config)
        .with_clock(VirtualClock::new(0))
        .with_captured_filesystem(HostCaptureFs::new("/fixtures", &host).unwrap())
        .build()
        .unwrap();
    let fd = record
        .fs_open("/fixtures/value", OpenFlags::read_only())
        .unwrap();
    assert_eq!(record.fs_read(fd, 32).unwrap(), b"captured");
    record.fs_close(fd).unwrap();
    record.finish().unwrap();

    std::fs::remove_file(host.join("value")).unwrap();
    let config = RuntimeConfig::replay(&trace, "capture-v1");
    let mut replay = RuntimeBuilder::new(config)
        .with_clock(VirtualClock::new(0))
        .with_captured_filesystem(HostCaptureFs::new("/fixtures", &host).unwrap())
        .build()
        .unwrap();
    let fd = replay
        .fs_open("/fixtures/value", OpenFlags::read_only())
        .unwrap();
    assert_eq!(replay.fs_read(fd, 32).unwrap(), b"captured");
    replay.fs_close(fd).unwrap();
    replay.finish().unwrap();

    let config = RuntimeConfig::branch(&trace, "main", 1, "capture-miss", 4, "capture-v1");
    let mut branch = RuntimeBuilder::new(config)
        .with_clock(VirtualClock::new(0))
        .with_captured_filesystem(HostCaptureFs::new("/fixtures", &host).unwrap())
        .build()
        .unwrap();
    let fd = branch
        .fs_open("/fixtures/value", OpenFlags::read_only())
        .unwrap();
    assert!(matches!(
        branch.fs_read(fd, 32),
        Err(RuntimeError::Effect(EffectError {
            code: ErrorCode::Denied,
            ..
        }))
    ));
}
