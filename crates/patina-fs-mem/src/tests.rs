//! Tests for filesystem construction and shared operations.

use crate::MemFs;
use patina_dst_abi::{ErrorCode, FsClock, FsEntryKind, OpenFlags, SeekWhence, XattrTarget};
use patina_dst_driver_api::{DriverResult, FsDriver};

/// RED before node-identity resolution: `*at` resolution replayed the name a
/// descriptor was opened under, so a renamed directory detached its
/// descriptor and a symlink planted at the vacated name captured every later
/// resolution through it.
/// A plain `O_WRONLY`: write access with no creation, truncation, or append.
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

#[test]
fn new_seeds_root_and_tmp_directories() {
    let mut fs = MemFs::new();
    assert_eq!(fs.metadata("/").unwrap().kind, FsEntryKind::Directory);
    assert_eq!(fs.metadata("/tmp").unwrap().kind, FsEntryKind::Directory);
}

#[test]
fn directories_metadata_seek_append_and_remove_are_deterministic() {
    let mut fs = MemFs::new();
    fs.create_directory(FsClock::EPOCH, "/state", 0o777)
        .unwrap();
    assert_eq!(fs.metadata("/state").unwrap().kind, FsEntryKind::Directory);
    let fd = fs
        .open(
            FsClock::EPOCH,
            "/state/value",
            OpenFlags {
                read: true,
                write: true,
                create: true,
                truncate: false,
                append: false,
                exclusive: true,
                path_only: false,
                mode: patina_dst_abi::DEFAULT_FILE_CREATE_MODE,
            },
        )
        .unwrap();
    fs.write(FsClock::EPOCH, fd, b"patina").unwrap();
    assert_eq!(fs.seek(fd, -3, SeekWhence::End).unwrap(), 3);
    assert_eq!(fs.read(FsClock::EPOCH, fd, 3).unwrap(), b"ina");
    assert_eq!(fs.fd_metadata(fd).unwrap().len, 6);
    fs.close(fd).unwrap();

    let append = fs
        .open(
            FsClock::EPOCH,
            "/state/value",
            OpenFlags {
                read: false,
                write: true,
                create: false,
                truncate: false,
                append: true,
                exclusive: false,
                path_only: false,
                mode: patina_dst_abi::CREATE_MODE_UNUSED,
            },
        )
        .unwrap();
    fs.write(FsClock::EPOCH, append, b"!").unwrap();
    fs.close(append).unwrap();
    assert_eq!(fs.contents("/state/value").unwrap(), b"patina!");
    fs.remove_file(FsClock::EPOCH, "/state/value").unwrap();
    assert_eq!(
        fs.metadata("/state/value").unwrap_err().code,
        ErrorCode::NotFound
    );
}

// ---- The timestamp model: the kernel's rules on the clock each operation
// is handed. Each test is the class detector for one rule; every assertion
// below was RED against the two-timestamp filesystem (ctime/btime absent,
// reads and writes stamping nothing).

pub(super) fn read_write() -> OpenFlags {
    OpenFlags {
        read: true,
        write: true,
        create: false,
        truncate: false,
        append: false,
        exclusive: false,
        path_only: false,
        mode: patina_dst_abi::CREATE_MODE_UNUSED,
    }
}

pub(super) fn times(fs: &mut MemFs, path: &str) -> (i128, i128, i128, i128) {
    let metadata = fs.metadata(path).unwrap();
    (
        metadata.atime_nanos,
        metadata.mtime_nanos,
        metadata.ctime_nanos,
        metadata.btime_nanos,
    )
}

pub(super) fn create(fs: &mut MemFs, path: &str, mode: u32) {
    let fd = fs
        .open(
            FsClock::EPOCH,
            path,
            OpenFlags {
                mode,
                ..OpenFlags::create_truncate_write()
            },
        )
        .unwrap();
    fs.close(fd).unwrap();
}

pub(super) fn xattr_value(fs: &mut MemFs, path: &str, name: &str) -> DriverResult<Vec<u8>> {
    fs.get_xattr(&XattrTarget::Path(path.into()), name)
}
