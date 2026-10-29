//! Tests for the public crash filesystem and shared fixtures.

use crate::CrashFs;
use patina_dst_abi::{CrashKind, Fd, FsClock, OpenFlags};
use patina_dst_driver_api::FsDriver;
use patina_dst_fs_mem::MemFs;

pub(super) fn write_only() -> OpenFlags {
    OpenFlags {
        read: false,
        write: true,
        create: false,
        truncate: false,
        append: false,
        exclusive: false,
        path_only: false,
        mode: patina_dst_abi::CREATE_MODE_UNUSED,
    }
}

pub(super) fn append_write() -> OpenFlags {
    OpenFlags {
        append: true,
        ..write_only()
    }
}

pub(super) fn write(fs: &mut CrashFs, path: &str, bytes: &[u8]) -> Fd {
    let fd = fs
        .open(FsClock::EPOCH, path, OpenFlags::create_truncate_write())
        .unwrap();
    fs.write(FsClock::EPOCH, fd, bytes).unwrap();
    fd
}

/// The snapshot a machine crash exports is the recovered image: synced bytes
/// kept, unsynced ones reverted, and hard links still one node. A process
/// crash exports the live image, unsynced bytes included.
#[test]
fn crash_and_snapshot_exports_the_image_the_crash_kind_leaves() {
    let mut base = MemFs::new().with_file("/a", b"stable").unwrap();
    base.link(FsClock::EPOCH, "/a", "/b").unwrap();
    let mut fs = CrashFs::new(base);
    let fd = write(&mut fs, "/state", b"stable");
    fs.sync(fd).unwrap();
    fs.write(FsClock::EPOCH, fd, b"-volatile").unwrap();
    let linked = fs.open(FsClock::EPOCH, "/a", write_only()).unwrap();
    fs.write(FsClock::EPOCH, linked, b"volatile").unwrap();

    let process = fs
        .crash_and_snapshot(FsClock::EPOCH, CrashKind::Process)
        .unwrap()
        .into_memfs();
    assert_eq!(process.contents("/state").unwrap(), b"stable-volatile");
    assert_eq!(process.contents("/b").unwrap(), b"volatile");

    let mut imported = fs
        .crash_and_snapshot(FsClock::EPOCH, CrashKind::Machine)
        .unwrap()
        .into_memfs();
    assert_eq!(imported.contents("/state").unwrap(), b"stable");
    let a = imported.metadata("/a").unwrap();
    let b = imported.metadata("/b").unwrap();
    assert_eq!((a.ino, a.nlink), (b.ino, 2));
    assert_eq!(imported.contents("/a").unwrap(), b"stable");
    assert_eq!(imported.contents("/b").unwrap(), b"stable");
}

/// An uncommitted rename of a committed file still held open: a machine
/// crash brings the old name back and keeps no name for the dead process's
/// descriptor, while an in-place crash, whose process lives on, keeps the
/// open file reachable under the name it holds.
#[test]
fn a_held_unsynced_rename_recovers_in_place_and_for_a_restart() {
    let build = || {
        let mut fs = CrashFs::new(MemFs::new());
        let fd = write(&mut fs, "/t", b"stable");
        fs.sync(fd).unwrap();
        fs.rename(FsClock::EPOCH, "/t", "/final").unwrap();
        (fs, fd)
    };
    let (mut fs, _held) = build();
    let image = fs
        .crash_and_snapshot(FsClock::EPOCH, CrashKind::Machine)
        .unwrap()
        .into_memfs();
    assert_eq!(image.contents("/t").unwrap(), b"stable");
    assert!(image.contents("/final").is_err());
    let (mut fs, held) = build();
    fs.crash(FsClock::EPOCH).unwrap();
    assert!(fs.fd_metadata(held).is_ok());
    assert!(fs.contents("/final").is_ok());
}

/// A filesystem holding an empty `/d`, seeded.
pub(super) fn with_dir() -> CrashFs {
    let mut base = MemFs::new();
    base.create_directory(FsClock::EPOCH, "/d", 0o777).unwrap();
    CrashFs::builder().filesystem(base).seed(7).build().unwrap()
}

/// The virtual clock `seconds` past the epoch.
pub(super) fn at_seconds(seconds: u64) -> FsClock {
    FsClock::at(seconds * 1_000_000_000)
}
