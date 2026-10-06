//! Tests for guest-facing filesystem operations through fsdriver.

use crate::MemFs;
use crate::tests::write_only;
use patina_dst_abi::{ErrorCode, FsClock, FsDirectoryEntry, FsEntryKind, OpenFlags, SeekWhence};
use patina_dst_driver_api::FsDriver;

#[test]
fn opening_a_fifo_enforces_its_mode_and_then_defers_to_the_pipe_boundary() {
    let mut fs = MemFs::new();
    fs.make_fifo(FsClock::EPOCH, "/tmp/pipe", 0o666).unwrap();
    // Permitted: the driver has nothing to hand back, because the bytes are
    // not filesystem state — but it says so with `InvalidInput`, never with
    // a permission or existence error.
    assert_eq!(
        fs.open(FsClock::EPOCH, "/tmp/pipe", OpenFlags::read_only())
            .unwrap_err()
            .code,
        ErrorCode::InvalidInput
    );
    assert_eq!(
        fs.open(FsClock::EPOCH, "/tmp/pipe", write_only())
            .unwrap_err()
            .code,
        ErrorCode::InvalidInput
    );

    // Denied: the permission decision belongs to the ONE enforcement point,
    // and it has to stay distinguishable from "not found".
    fs.set_mode(FsClock::EPOCH, "/tmp/pipe", 0o000).unwrap();
    assert_eq!(
        fs.open(FsClock::EPOCH, "/tmp/pipe", OpenFlags::read_only())
            .unwrap_err()
            .code,
        ErrorCode::Denied,
        "a 0o000 FIFO must not be openable for reading"
    );
    assert_eq!(
        fs.open(FsClock::EPOCH, "/tmp/pipe", write_only())
            .unwrap_err()
            .code,
        ErrorCode::Denied
    );
    fs.set_mode(FsClock::EPOCH, "/tmp/pipe", 0o400).unwrap();
    assert_eq!(
        fs.open(FsClock::EPOCH, "/tmp/pipe", OpenFlags::read_only())
            .unwrap_err()
            .code,
        ErrorCode::InvalidInput
    );
    assert_eq!(
        fs.open(FsClock::EPOCH, "/tmp/pipe", write_only())
            .unwrap_err()
            .code,
        ErrorCode::Denied,
        "a read-only FIFO must not be openable for writing"
    );
    // An unsearchable parent hides it exactly as it hides a file.
    fs.create_directory(FsClock::EPOCH, "/tmp/gate", 0o777)
        .unwrap();
    fs.make_fifo(FsClock::EPOCH, "/tmp/gate/pipe", 0o666)
        .unwrap();
    fs.set_mode(FsClock::EPOCH, "/tmp/gate", 0o000).unwrap();
    assert_eq!(
        fs.metadata("/tmp/gate/pipe").unwrap_err().code,
        ErrorCode::Denied
    );
}

#[test]
fn read_only_directory_open_supports_fstat_fsync_and_close_only() {
    let mut fs = MemFs::new();
    fs.create_directory(FsClock::EPOCH, "/state", 0o777)
        .unwrap();
    let fd = fs
        .open(FsClock::EPOCH, "/state", OpenFlags::read_only())
        .unwrap();
    assert_eq!(fs.fd_metadata(fd).unwrap().kind, FsEntryKind::Directory);
    fs.sync(fd).unwrap();
    assert_eq!(
        fs.read(FsClock::EPOCH, fd, 1).unwrap_err().code,
        ErrorCode::IsDirectory
    );
    assert_eq!(
        fs.write(FsClock::EPOCH, fd, b"x").unwrap_err().code,
        ErrorCode::NotWritable
    );
    assert_eq!(
        fs.seek(fd, 0, SeekWhence::Start).unwrap_err().code,
        ErrorCode::InvalidInput
    );
    fs.close(fd).unwrap();

    let write_dir = OpenFlags {
        read: true,
        write: true,
        create: false,
        truncate: false,
        append: false,
        exclusive: false,
        path_only: false,
        mode: patina_dst_abi::CREATE_MODE_UNUSED,
    };
    assert_eq!(
        fs.open(FsClock::EPOCH, "/state", write_dir)
            .unwrap_err()
            .code,
        ErrorCode::IsDirectory
    );
}

/// RED before `O_PATH` was in the driver's flag vocabulary: every directory
/// open was the same open — it charged `x` on the directory and handed back
/// a readable handle, so a `cap-std` component walk paid for a capability it
/// never asked for while a real read of the directory paid nothing extra,
/// and the `r` a listing costs was charged at `read_directory` where a
/// `chmod` after the open could still reach it.
/// RED mutations: charge `READ` on the path-only branch (the `0o111` open
/// below fails), or drop the `readable` check in `read_directory_fd` (the
/// path-only descriptor lists).
#[test]
fn a_path_only_open_names_a_location_and_a_plain_one_opens_the_entry() {
    let mut fs = MemFs::new();
    fs.create_directory(FsClock::EPOCH, "/d", 0o777).unwrap();
    let fd = fs
        .open(
            FsClock::EPOCH,
            "/d/file",
            OpenFlags::create_truncate_write(),
        )
        .unwrap();
    fs.close(fd).unwrap();

    // A plain `O_RDONLY|O_DIRECTORY` open opens the directory for reading
    // and can iterate it: `.` (the directory), `..` (its parent), then the
    // children, each naming its inode.
    let readable = fs
        .open(FsClock::EPOCH, "/d", OpenFlags::read_only())
        .unwrap();
    let [dir, root, file] = ["/d", "/", "/d/file"].map(|path| fs.metadata(path).unwrap().ino);
    let entry = |name: &str, kind, ino| FsDirectoryEntry {
        name: name.into(),
        kind,
        ino,
    };
    assert_eq!(
        fs.read_directory_fd(FsClock::EPOCH, readable).unwrap(),
        [
            entry(".", FsEntryKind::Directory, dir),
            entry("..", FsEntryKind::Directory, root),
            entry("file", FsEntryKind::File, file),
        ]
    );

    // An `O_PATH` open opens nothing: it resolves and answers `fstat`, and
    // every operation that touches the entry is refused.
    let location = fs
        .open(FsClock::EPOCH, "/d", OpenFlags::path_only())
        .unwrap();
    assert_eq!(
        fs.fd_metadata(location).unwrap().kind,
        FsEntryKind::Directory
    );
    assert_eq!(fs.fd_path(location).unwrap(), "/d");
    assert_eq!(
        fs.read_directory_fd(FsClock::EPOCH, location)
            .unwrap_err()
            .code,
        ErrorCode::NotReadable
    );
    assert_eq!(
        fs.sync(location).unwrap_err().code,
        ErrorCode::InvalidHandle
    );
    assert_eq!(
        fs.set_fd_mode(FsClock::EPOCH, location, 0o700)
            .unwrap_err()
            .code,
        ErrorCode::InvalidHandle
    );

    // Search-only bits: a plain open pays `r` and is refused, a path-only
    // open pays nothing on the entry and succeeds — which is exactly how a
    // capability guest walks a directory it may traverse but not list.
    fs.set_mode(FsClock::EPOCH, "/d", 0o111).unwrap();
    assert_eq!(
        fs.open(FsClock::EPOCH, "/d", OpenFlags::read_only())
            .unwrap_err()
            .code,
        ErrorCode::Denied
    );
    let walked = fs
        .open(FsClock::EPOCH, "/d", OpenFlags::path_only())
        .unwrap();
    assert_eq!(fs.fd_path(walked).unwrap(), "/d");

    // The access was charged at open, so the `chmod` cannot reach back into
    // a descriptor already holding the directory — while the FUSED path form
    // (`opendir`+`readdir` in one call) charges its own `r` and is refused.
    assert_eq!(
        fs.read_directory_fd(FsClock::EPOCH, readable)
            .unwrap()
            .len(),
        3
    );
    assert_eq!(
        fs.read_directory(FsClock::EPOCH, "/d").unwrap_err().code,
        ErrorCode::Denied
    );
    fs.close(readable).unwrap();
    fs.close(location).unwrap();
    fs.close(walked).unwrap();
}

/// `O_PATH` is not a directory-only spelling: the kernel gives a path-only
/// descriptor for any kind, charging nothing on the entry.
#[test]
fn a_path_only_open_of_a_file_or_fifo_reads_nothing_and_needs_no_permission() {
    let mut fs = MemFs::new();
    let fd = fs
        .open(
            FsClock::EPOCH,
            "/tmp/locked",
            OpenFlags {
                mode: 0o000,
                ..OpenFlags::create_truncate_write()
            },
        )
        .unwrap();
    fs.write(FsClock::EPOCH, fd, b"hidden").unwrap();
    fs.close(fd).unwrap();
    assert_eq!(
        fs.open(FsClock::EPOCH, "/tmp/locked", OpenFlags::read_only())
            .unwrap_err()
            .code,
        ErrorCode::Denied
    );

    let location = fs
        .open(FsClock::EPOCH, "/tmp/locked", OpenFlags::path_only())
        .unwrap();
    let metadata = fs.fd_metadata(location).unwrap();
    assert_eq!(metadata.kind, FsEntryKind::File);
    assert_eq!(metadata.len, 6);
    assert_eq!(metadata.mode, 0o000);
    assert_eq!(
        fs.read(FsClock::EPOCH, location, 8).unwrap_err().code,
        ErrorCode::NotReadable
    );
    assert_eq!(
        fs.write(FsClock::EPOCH, location, b"x").unwrap_err().code,
        ErrorCode::NotWritable
    );
    assert_eq!(
        fs.seek(location, 0, SeekWhence::End).unwrap_err().code,
        ErrorCode::InvalidInput
    );
    fs.close(location).unwrap();

    fs.make_fifo(FsClock::EPOCH, "/tmp/pipe", 0o000).unwrap();
    let fifo = fs
        .open(FsClock::EPOCH, "/tmp/pipe", OpenFlags::path_only())
        .unwrap();
    assert_eq!(fs.fd_metadata(fifo).unwrap().kind, FsEntryKind::Fifo);
    fs.close(fifo).unwrap();
    // A path-only open carries no access mode: asking for both is asking for
    // two different descriptors at once.
    assert_eq!(
        fs.open(
            FsClock::EPOCH,
            "/tmp/pipe",
            OpenFlags {
                read: true,
                ..OpenFlags::path_only()
            }
        )
        .unwrap_err()
        .code,
        ErrorCode::InvalidInput
    );
}

#[test]
fn access_modes_and_unsafe_paths_are_rejected() {
    let mut fs = MemFs::new().with_file("/value", b"x").unwrap();
    let read_fd = fs
        .open(FsClock::EPOCH, "/value", OpenFlags::read_only())
        .unwrap();
    assert_eq!(
        fs.write(FsClock::EPOCH, read_fd, b"no").unwrap_err().code,
        ErrorCode::NotWritable
    );
    assert_eq!(
        fs.open(FsClock::EPOCH, "../host", OpenFlags::read_only())
            .unwrap_err()
            .code,
        ErrorCode::InvalidInput
    );
    assert_eq!(
        fs.open(FsClock::EPOCH, "/safe/../host", OpenFlags::read_only())
            .unwrap_err()
            .code,
        ErrorCode::InvalidInput
    );
}
