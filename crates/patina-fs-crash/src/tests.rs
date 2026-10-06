//! Tests for the public crash filesystem and shared fixtures.

use crate::CrashFs;
use patina_dst_abi::{ErrorCode, Fd, FsClock, OpenFlags};
use patina_dst_driver_api::FsDriver;
use patina_dst_fs_mem::{FsSnapshot, MemFs};

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

#[test]
fn crash_and_snapshot_exports_recovered_image_without_handles() {
    let mut fs = CrashFs::default();
    let fd = fs
        .open(FsClock::EPOCH, "/state", OpenFlags::create_truncate_write())
        .unwrap();
    fs.write(FsClock::EPOCH, fd, b"stable").unwrap();
    fs.sync(fd).unwrap();
    fs.sync_directory("/").unwrap();
    fs.write(FsClock::EPOCH, fd, b"-volatile").unwrap();

    let snapshot = fs.crash_and_snapshot().unwrap();
    let encoded = snapshot.encode().unwrap();
    assert_eq!(
        FsSnapshot::decode(&encoded).unwrap().encode().unwrap(),
        encoded
    );
    let mut imported = snapshot.into_memfs();
    assert_eq!(imported.contents("/state").unwrap(), b"stable");
    assert_eq!(
        imported.read(FsClock::EPOCH, fd, 1).unwrap_err().code,
        ErrorCode::InvalidHandle
    );
    assert_eq!(
        imported
            .open(FsClock::EPOCH, "/state", OpenFlags::read_only())
            .unwrap(),
        Fd(3)
    );
}

#[test]
fn crash_and_snapshot_preserves_hard_link_inode_identity() {
    let mut base = MemFs::new().with_file("/a", b"stable").unwrap();
    base.link(FsClock::EPOCH, "/a", "/b").unwrap();
    let mut fs = CrashFs::new(base);
    let fd = fs.open(FsClock::EPOCH, "/a", write_only()).unwrap();
    fs.write(FsClock::EPOCH, fd, b"volatile").unwrap();

    let snapshot = fs.crash_and_snapshot().unwrap();
    let mut imported = snapshot.into_memfs();
    let a = imported.metadata("/a").unwrap();
    let b = imported.metadata("/b").unwrap();
    assert_eq!(a.ino, b.ino);
    assert_eq!(a.nlink, 2);
    assert_eq!(b.nlink, 2);
    assert_eq!(imported.contents("/a").unwrap(), b"stable");
    assert_eq!(imported.contents("/b").unwrap(), b"stable");
}

#[test]
fn builder_rejects_invalid_configuration() {
    assert_eq!(
        CrashFs::builder()
            .torn_write_granularity(0)
            .build()
            .unwrap_err()
            .code,
        ErrorCode::InvalidInput
    );
    assert_eq!(
        CrashFs::builder()
            .torn_write_probability(1.5)
            .build()
            .unwrap_err()
            .code,
        ErrorCode::InvalidInput
    );
    assert_eq!(
        CrashFs::builder()
            .directory_loss_probability(-0.1)
            .build()
            .unwrap_err()
            .code,
        ErrorCode::InvalidInput
    );
    assert!(
        CrashFs::builder()
            .torn_write_probability(f64::NAN)
            .build()
            .is_err()
    );
}

#[test]
fn checkpoint_persists_namespace_operations() {
    let mut fs = CrashFs::default();
    let fd = write(&mut fs, "/before", b"value");
    fs.close(fd).unwrap();
    fs.checkpoint();
    // A committed rename after the checkpoint survives; unsynced content
    // written afterwards does not.
    fs.rename(FsClock::EPOCH, "/before", "/after").unwrap();
    fs.checkpoint();
    fs.crash().unwrap();
    assert_eq!(fs.contents("/after").unwrap(), b"value");
    assert_eq!(
        fs.metadata("/before").unwrap_err().code,
        ErrorCode::NotFound
    );
}

pub(super) fn lossy() -> CrashFs {
    let mut base = MemFs::new();
    base.create_directory(FsClock::EPOCH, "/d", 0o777).unwrap();
    CrashFs::builder()
        .filesystem(base)
        .seed(7)
        .model_directory_durability(true)
        .directory_loss_probability(1.0)
        .build()
        .unwrap()
}
