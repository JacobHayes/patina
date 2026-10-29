//! Tests for filesystem construction and shared operations.

use crate::MemFs;
use patina_dst_abi::{FsClock, OpenFlags, XattrTarget};
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
