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

#[test]
fn missing_and_closed_handles_fail_explicitly() {
    let mut fs = MemFs::new();
    let missing = fs
        .open(FsClock::EPOCH, "/missing", OpenFlags::read_only())
        .unwrap_err();
    assert_eq!(missing.code, ErrorCode::NotFound);

    let fd = fs
        .open(FsClock::EPOCH, "/value", OpenFlags::create_truncate_write())
        .unwrap();
    fs.close(fd).unwrap();
    let closed = fs.write(FsClock::EPOCH, fd, b"no").unwrap_err();
    assert_eq!(closed.code, ErrorCode::InvalidHandle);
}

#[test]
fn dup_shares_cursor_and_is_deterministically_numbered() {
    let mut fs = MemFs::new();
    let write = fs
        .open(FsClock::EPOCH, "/value", OpenFlags::create_truncate_write())
        .unwrap();
    fs.write(FsClock::EPOCH, write, b"abcdef").unwrap();
    fs.close(write).unwrap();

    let first = fs
        .open(FsClock::EPOCH, "/value", OpenFlags::read_only())
        .unwrap();
    let second = fs.dup(first).unwrap();
    assert_eq!(second, Fd(first.0 + 1));
    assert_eq!(fs.read(FsClock::EPOCH, first, 3).unwrap(), b"abc");
    assert_eq!(fs.read(FsClock::EPOCH, second, 3).unwrap(), b"def");
    fs.seek(second, 1, SeekWhence::Start).unwrap();
    assert_eq!(fs.read(FsClock::EPOCH, first, 2).unwrap(), b"bc");
}

#[test]
fn close_of_one_duplicate_keeps_the_description() {
    let mut fs = MemFs::new().with_file("/value", b"abc").unwrap();
    let first = fs
        .open(FsClock::EPOCH, "/value", OpenFlags::read_only())
        .unwrap();
    let second = fs.dup(first).unwrap();
    fs.close(first).unwrap();
    assert_eq!(fs.read(FsClock::EPOCH, second, 1).unwrap(), b"a");
    fs.close(second).unwrap();
    let error = fs.read(FsClock::EPOCH, second, 1).unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidHandle);
    assert_eq!(
        error.message,
        format!("virtual file handle {} is not open", second.0)
    );
}

#[test]
fn dup_of_unknown_fd_is_invalid_handle() {
    let mut fs = MemFs::new();
    let error = fs.dup(Fd(99)).unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidHandle);
    assert_eq!(error.message, "virtual file handle 99 is not open");
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
}

/// A node with a name left over is released by the NAME, not by the
/// descriptor: unlinking one hard link while the other is open is an
/// ordinary link-count decrement.
#[test]
fn a_hard_link_is_removable_while_another_of_its_names_is_open() {
    let mut fs = MemFs::new().with_file("/a", b"abc").unwrap();
    fs.link(FsClock::EPOCH, "/a", "/b").unwrap();
    let fd = fs
        .open(FsClock::EPOCH, "/a", OpenFlags::read_only())
        .unwrap();
    fs.remove_file(FsClock::EPOCH, "/b").unwrap();
    assert_eq!(fs.fd_metadata(fd).unwrap().nlink, 1);
    fs.remove_file(FsClock::EPOCH, "/a").unwrap();
    assert_eq!(fs.fd_metadata(fd).unwrap().nlink, 0);
    assert_eq!(fs.read(FsClock::EPOCH, fd, 8).unwrap(), b"abc");
    fs.close(fd).unwrap();
}

/// A FIFO endpoint is the descriptor the filesystem hands back no handle
/// for, so its reference is taken explicitly — and it is what keeps the node
/// answerable after the last name is unlinked. RED before inode lifetime:
/// `inode_metadata` searched the NAME tables, so the unlinked FIFO answered
/// `NotFound` and the shim fell back to a copy taken at open time.
#[test]
fn an_unlinked_fifo_answers_through_the_reference_its_endpoint_holds() {
    let mut fs = MemFs::new();
    fs.make_fifo(FsClock::EPOCH, "/tmp/pipe", 0o640).unwrap();
    let ino = fs.metadata("/tmp/pipe").unwrap().ino;
    fs.retain_inode(ino).unwrap();

    fs.remove_file(FsClock::EPOCH, "/tmp/pipe").unwrap();
    assert_eq!(
        fs.metadata("/tmp/pipe").unwrap_err().code,
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
