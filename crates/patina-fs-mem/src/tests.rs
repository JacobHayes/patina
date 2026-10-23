//! Tests for filesystem construction and shared operations.

use crate::MemFs;
use patina_dst_abi::{ErrorCode, FsClock, FsEntryKind, OpenFlags, SeekWhence, XattrTarget};
use patina_dst_driver_api::{DriverResult, FsDriver};

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
fn files_are_written_read_seeked_appended_truncated_and_removed() {
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
    assert_eq!(fs.write(FsClock::EPOCH, fd, b"patina").unwrap(), 6);
    assert_eq!(fs.seek(fd, -3, SeekWhence::End).unwrap(), 3);
    assert_eq!(fs.read(FsClock::EPOCH, fd, 3).unwrap(), b"ina");
    assert_eq!(fs.fd_metadata(fd).unwrap().len, 6);
    fs.close(fd).unwrap();

    // A path with empty and `.` components names the same file; a short
    // read stops at the end and a read there is empty.
    let read_fd = fs
        .open(FsClock::EPOCH, "/state//./value", OpenFlags::read_only())
        .unwrap();
    assert_eq!(fs.read(FsClock::EPOCH, read_fd, 3).unwrap(), b"pat");
    assert_eq!(fs.read(FsClock::EPOCH, read_fd, 99).unwrap(), b"ina");
    assert!(fs.read(FsClock::EPOCH, read_fd, 1).unwrap().is_empty());
    fs.close(read_fd).unwrap();

    let append = fs
        .open(
            FsClock::EPOCH,
            "/state/value",
            OpenFlags {
                append: true,
                ..write_only()
            },
        )
        .unwrap();
    fs.write(FsClock::EPOCH, append, b"!").unwrap();
    fs.close(append).unwrap();
    assert_eq!(fs.contents("/state/value").unwrap(), b"patina!");

    let truncate_fd = fs
        .open(
            FsClock::EPOCH,
            "/state/value",
            OpenFlags::create_truncate_write(),
        )
        .unwrap();
    fs.close(truncate_fd).unwrap();
    assert!(fs.contents("/state/value").unwrap().is_empty());
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
