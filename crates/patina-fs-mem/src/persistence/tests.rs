//! Tests for persistent state inspection, restoration and descriptor adoption.

use crate::tests::{times, xattr_value};
use crate::{FsSnapshot, MemFs};
use patina_dst_abi::{ErrorCode, FsClock, FsEntryKind, FsNode, OpenFlags, XattrTarget};
use patina_dst_driver_api::FsDriver;

#[test]
fn persistent_snapshot_drops_descriptions() {
    let mut fs = MemFs::new().with_file("/value", b"abc").unwrap();
    let first = fs
        .open(FsClock::EPOCH, "/value", OpenFlags::read_only())
        .unwrap();
    let second = fs.dup(first).unwrap();
    let mut snapshot = fs.persistent_snapshot();
    assert_eq!(
        snapshot.read(FsClock::EPOCH, first, 1).unwrap_err().code,
        ErrorCode::InvalidHandle
    );
    assert_eq!(
        snapshot.read(FsClock::EPOCH, second, 1).unwrap_err().code,
        ErrorCode::InvalidHandle
    );
}

#[test]
fn a_crash_model_restores_all_four_times_verbatim() {
    let mut fs = MemFs::new();
    fs.create_directory(FsClock::at(10), "/d", 0o755).unwrap();
    fs.restore_times("/d", 1, 2, 3, 4).unwrap();
    assert_eq!(times(&mut fs, "/d"), (1, 2, 3, 4));
    fs.restore_mode("/d", 0o700).unwrap();
    assert_eq!(
        times(&mut fs, "/d"),
        (1, 2, 3, 4),
        "a restore stamps nothing"
    );
    assert_eq!(fs.metadata("/d").unwrap().mode, 0o700);
    assert_eq!(
        fs.restore_times("/missing", 1, 2, 3, 4).unwrap_err().code,
        ErrorCode::NotFound
    );
}

/// A restart snapshot carries every node kind with its mode, identity,
/// links and attributes, and re-encodes to the same bytes. A hard-linked
/// FIFO is one node with two names, or the shim would key two pipe
/// channels off what used to be one pipe.
#[test]
fn nodes_modes_links_and_attributes_survive_a_restart_snapshot() {
    let mut fs = MemFs::new();
    fs.create_directory(FsClock::EPOCH, "/d", 0o755).unwrap();
    let fd = fs
        .open(
            FsClock::EPOCH,
            "/d/file",
            OpenFlags::create_truncate_write(),
        )
        .unwrap();
    fs.close(fd).unwrap();
    fs.set_mode(FsClock::EPOCH, "/d/file", 0o600).unwrap();
    fs.set_mode(FsClock::EPOCH, "/d", 0o700).unwrap();
    fs.make_fifo(FsClock::EPOCH, "/tmp/pipe", 0o666).unwrap();
    fs.set_mode(FsClock::EPOCH, "/tmp/pipe", 0o640).unwrap();
    fs.link(FsClock::EPOCH, "/tmp/pipe", "/tmp/alias").unwrap();
    fs.symlink(FsClock::EPOCH, "t", "/l").unwrap();
    fs.link(FsClock::EPOCH, "/l", "/l2").unwrap();
    fs.make_node(FsClock::EPOCH, "/s", FsNode::Socket, 0o600)
        .unwrap();
    fs.set_xattr(
        FsClock::EPOCH,
        &XattrTarget::Path("/d".into()),
        "user.k",
        b"v",
        0,
    )
    .unwrap();
    let pipe = fs.metadata("/tmp/pipe").unwrap();

    let encoded = fs.export_snapshot().encode().unwrap();
    let mut restored = FsSnapshot::decode(&encoded).unwrap().into_memfs();
    assert_eq!(restored.metadata("/d/file").unwrap().mode, 0o600);
    assert_eq!(restored.metadata("/d").unwrap().mode, 0o700);
    for name in ["/tmp/pipe", "/tmp/alias"] {
        let after = restored.metadata(name).unwrap();
        assert_eq!(
            (after.kind, after.mode, after.ino, after.nlink),
            (FsEntryKind::Fifo, 0o640, pipe.ino, 2),
            "{name}"
        );
    }
    assert_eq!(restored.metadata("/l2").unwrap().nlink, 2);
    assert_eq!(
        restored.metadata("/l").unwrap().ino,
        restored.metadata("/l2").unwrap().ino
    );
    assert_eq!(restored.metadata("/s").unwrap().kind, FsEntryKind::Socket);
    assert_eq!(xattr_value(&mut restored, "/d", "user.k").unwrap(), b"v");
    assert_eq!(restored.export_snapshot().encode().unwrap(), encoded);
}
