//! Tests for open descriptions, descriptor allocation and inode reference lifetime.

use crate::MemFs;
use patina_dst_abi::{ErrorCode, Fd, FsClock, FsEntryKind, OpenFlags, SeekWhence};
use patina_dst_driver_api::FsDriver;

#[test]
fn a_descriptor_follows_its_node_through_a_rename() {
    let mut fs = MemFs::new();
    fs.create_directory(FsClock::EPOCH, "/pinned", 0o777)
        .unwrap();
    let fd = fs
        .open(
            FsClock::EPOCH,
            "/pinned/file",
            OpenFlags::create_truncate_write(),
        )
        .unwrap();
    fs.close(fd).unwrap();

    let dir = fs
        .open(FsClock::EPOCH, "/pinned", OpenFlags::read_only())
        .unwrap();
    assert_eq!(fs.fd_path(dir).unwrap(), "/pinned");

    fs.rename(FsClock::EPOCH, "/pinned", "/moved").unwrap();
    assert_eq!(
        fs.fd_path(dir).unwrap(),
        "/moved",
        "the descriptor names an inode, so it moved with the directory"
    );

    // Planting a symlink at the vacated name must not recapture it.
    fs.symlink(FsClock::EPOCH, "/elsewhere", "/pinned").unwrap();
    assert_eq!(fs.fd_path(dir).unwrap(), "/moved");

    // An ancestor rename moves it too.
    fs.create_directory(FsClock::EPOCH, "/outer", 0o777)
        .unwrap();
    fs.rename(FsClock::EPOCH, "/moved", "/outer/inner").unwrap();
    assert_eq!(fs.fd_path(dir).unwrap(), "/outer/inner");
    fs.rename(FsClock::EPOCH, "/outer", "/renamed-outer")
        .unwrap();
    assert_eq!(fs.fd_path(dir).unwrap(), "/renamed-outer/inner");
}

/// `dup` numbers deterministically and shares the description's cursor;
/// the description outlives every handle but its last, and an unknown or
/// closed handle is `InvalidHandle`.
#[test]
fn dup_shares_the_description_until_its_last_handle_closes() {
    let mut fs = MemFs::new().with_file("/value", b"abcdef").unwrap();
    let first = fs
        .open(FsClock::EPOCH, "/value", OpenFlags::read_only())
        .unwrap();
    let second = fs.dup(first).unwrap();
    assert_eq!(second, Fd(first.0 + 1));
    assert_eq!(fs.read(FsClock::EPOCH, first, 3).unwrap(), b"abc");
    assert_eq!(fs.read(FsClock::EPOCH, second, 3).unwrap(), b"def");
    fs.seek(second, 1, SeekWhence::Start).unwrap();
    assert_eq!(fs.read(FsClock::EPOCH, first, 2).unwrap(), b"bc");

    fs.close(first).unwrap();
    assert_eq!(fs.read(FsClock::EPOCH, second, 1).unwrap(), b"d");
    fs.close(second).unwrap();
    assert_eq!(
        fs.read(FsClock::EPOCH, second, 1).unwrap_err().code,
        ErrorCode::InvalidHandle
    );
    assert_eq!(fs.dup(Fd(99)).unwrap_err().code, ErrorCode::InvalidHandle);
}

/// RED before inode lifetime: `remove_file` refused an open file outright
/// (`InvalidState`, "cannot remove open virtual file"), because a
/// description was keyed by PATH and unlinking the name would have left it
/// pointing at nothing. A kernel refuses no such thing — it drops the name
/// and keeps the node alive for every descriptor that still holds it.
/// RED mutation: free the node in `drop_name` instead of
/// `release_if_unreferenced`, and every read below fails.
#[test]
fn an_unlinked_file_stays_alive_behind_its_descriptors() {
    let mut fs = MemFs::new().with_file("/value", b"abc").unwrap();
    let first = fs
        .open(FsClock::EPOCH, "/value", OpenFlags::read_only())
        .unwrap();
    let second = fs.dup(first).unwrap();
    let before = fs.fd_metadata(first).unwrap();
    fs.close(first).unwrap();

    fs.remove_file(FsClock::EPOCH, "/value").unwrap();
    assert_eq!(fs.metadata("/value").unwrap_err().code, ErrorCode::NotFound);

    // The NAME is gone; the NODE is not. Reads, `fstat` and `fchmod` all
    // reach it through the descriptor, and the link count reads 0 exactly
    // as it does on a real unlinked-but-open file.
    assert_eq!(fs.read(FsClock::EPOCH, second, 8).unwrap(), b"abc");
    let after = fs.fd_metadata(second).unwrap();
    assert_eq!(after.ino, before.ino);
    assert_eq!(after.nlink, 0);
    assert_eq!(after.len, 3);
    fs.set_fd_mode(FsClock::EPOCH, second, 0o600).unwrap();
    assert_eq!(fs.fd_metadata(second).unwrap().mode, 0o600);
    // With no name left there is nothing to answer `fd_path` with.
    assert_eq!(fs.fd_path(second).unwrap_err().code, ErrorCode::NotFound);

    // The last reference of either kind is what frees it.
    let ino = after.ino;
    fs.close(second).unwrap();
    assert_eq!(
        fs.inode_metadata(ino).unwrap_err().code,
        ErrorCode::NotFound
    );
    // And a fresh entry never inherits a released node's identity.
    let fd = fs
        .open(FsClock::EPOCH, "/value", OpenFlags::create_truncate_write())
        .unwrap();
    assert_ne!(fs.fd_metadata(fd).unwrap().ino, ino);

    // A node with a name left over is released by the NAME, not by the
    // descriptor: unlinking one hard link while the other is open is an
    // ordinary link-count decrement.
    fs.link(FsClock::EPOCH, "/value", "/alias").unwrap();
    fs.remove_file(FsClock::EPOCH, "/alias").unwrap();
    assert_eq!(fs.fd_metadata(fd).unwrap().nlink, 1);
}

/// A FIFO endpoint is the descriptor the filesystem hands back no handle
/// for, so its reference is taken explicitly. `inode_metadata` reads the
/// LIVE node by inode, as `fstat` on the endpoint does: a `chmod` or a
/// rename after the open is visible, and the reference keeps the node
/// answerable after the last name is unlinked.
#[test]
fn an_unlinked_fifo_answers_through_the_reference_its_endpoint_holds() {
    let mut fs = MemFs::new();
    fs.make_fifo(FsClock::EPOCH, "/tmp/pipe", 0o644).unwrap();
    let ino = fs.metadata("/tmp/pipe").unwrap().ino;
    fs.retain_inode(ino).unwrap();
    fs.set_mode(FsClock::EPOCH, "/tmp/pipe", 0o640).unwrap();
    assert_eq!(fs.inode_metadata(ino).unwrap().mode, 0o640);
    fs.rename(FsClock::EPOCH, "/tmp/pipe", "/tmp/moved")
        .unwrap();
    assert_eq!(fs.inode_metadata(ino).unwrap().ino, ino);

    fs.remove_file(FsClock::EPOCH, "/tmp/moved").unwrap();
    assert_eq!(
        fs.metadata("/tmp/moved").unwrap_err().code,
        ErrorCode::NotFound
    );
    let live = fs.inode_metadata(ino).unwrap();
    assert_eq!(live.kind, FsEntryKind::Fifo);
    assert_eq!(live.nlink, 0);
    assert_eq!(live.mode, 0o640);

    fs.release_inode(ino).unwrap();
    assert_eq!(
        fs.inode_metadata(ino).unwrap_err().code,
        ErrorCode::NotFound
    );
    // A release with nothing to release is a bug in the caller, not a no-op.
    assert_eq!(fs.release_inode(ino).unwrap_err().code, ErrorCode::NotFound);
}
