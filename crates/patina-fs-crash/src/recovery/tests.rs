//! Tests for crash reconstruction and surviving source-inode selection.

use crate::CrashFs;
use crate::tests::{append_write, lossy, write};
use patina_dst_abi::{
    ErrorCode, FsClock, FsDirectoryEntry, FsEntryKind, FsNode, OpenFlags, SeekWhence, XattrTarget,
};
use patina_dst_driver_api::FsDriver;
use patina_dst_fs_mem::MemFs;

/// A crash keeps synced data and loses unsynced data, and never touches
/// the descriptor table: real storage cannot invalidate a caller's fd, so
/// every pre-crash descriptor still names its file (an `InvalidHandle` here
/// would surface as an impossible `EBADF`), an append descriptor appends at
/// the rebuilt end, and a fresh open never reuses a live number.
#[test]
fn a_crash_keeps_synced_data_loses_unsynced_and_leaves_descriptors_usable() {
    let initial = MemFs::new().with_file("/log", b"stable").unwrap();
    let mut fs = CrashFs::new(initial);
    let durable = write(&mut fs, "/keep", b"durable");
    fs.sync(durable).unwrap();
    // Only the namespace entry is durable: the bytes are discarded,
    // leaving an empty file.
    let volatile = write(&mut fs, "/lose", b"volatile");
    fs.sync_directory("/").unwrap();
    let append = fs.open(FsClock::EPOCH, "/log", append_write()).unwrap();
    fs.write(FsClock::EPOCH, append, b"-volatile").unwrap();
    fs.crash().unwrap();
    assert_eq!(fs.crash_count(), 1);

    assert_eq!(fs.contents("/keep").unwrap(), b"durable");
    assert!(fs.contents("/lose").unwrap().is_empty());
    assert_eq!(fs.contents("/log").unwrap(), b"stable");

    fs.fd_metadata(durable).expect("fd_metadata after crash");
    fs.sync(durable).expect("sync after crash");
    fs.seek(durable, 0, SeekWhence::Start).unwrap();
    assert_eq!(fs.write(FsClock::EPOCH, durable, b"D").unwrap(), 1);
    assert_eq!(fs.contents("/keep").unwrap(), b"Durable");
    fs.seek(volatile, 0, SeekWhence::Start).unwrap();
    assert_eq!(fs.write(FsClock::EPOCH, volatile, b"x").unwrap(), 1);
    assert_eq!(fs.contents("/lose").unwrap(), b"x");
    fs.write(FsClock::EPOCH, append, b"-after").unwrap();
    assert_eq!(fs.contents("/log").unwrap(), b"stable-after");

    let reopened = fs
        .open(FsClock::EPOCH, "/keep", OpenFlags::read_only())
        .unwrap();
    assert!(![durable, volatile, append].contains(&reopened));
    assert_eq!(fs.read(FsClock::EPOCH, reopened, 16).unwrap(), b"Durable");
    fs.close(durable).expect("close after crash");
}

/// Every node kind comes back from a crash once its parent is fsynced: a
/// file and a directory with their modes, a FIFO as a FIFO (listed as one)
/// with its mode, hard-linked FIFOs and symlinks as one node each, a socket,
/// a whiteout, and a file's attributes.
#[test]
fn every_node_kind_comes_back_from_a_crash_with_its_mode_links_and_attributes() {
    let mut fs = lossy();
    let fd = fs
        .open(
            FsClock::EPOCH,
            "/d/file",
            OpenFlags {
                mode: 0o604,
                ..OpenFlags::create_truncate_write()
            },
        )
        .unwrap();
    fs.write(FsClock::EPOCH, fd, b"bytes").unwrap();
    fs.sync(fd).unwrap();
    fs.close(fd).unwrap();
    fs.create_directory(FsClock::EPOCH, "/d/sub", 0o700)
        .unwrap();
    fs.make_fifo(FsClock::EPOCH, "/d/pipe", 0o666).unwrap();
    fs.set_mode(FsClock::EPOCH, "/d/pipe", 0o640).unwrap();
    fs.link(FsClock::EPOCH, "/d/pipe", "/d/pipe2").unwrap();
    fs.symlink(FsClock::EPOCH, "/target", "/d/l").unwrap();
    fs.link(FsClock::EPOCH, "/d/l", "/d/l2").unwrap();
    fs.make_node(FsClock::EPOCH, "/d/s", FsNode::Socket, 0o600)
        .unwrap();
    fs.make_node(FsClock::EPOCH, "/d/w", FsNode::Whiteout, 0)
        .unwrap();
    fs.sync_directory("/d").unwrap();
    fs.sync_directory("/d/sub").unwrap();
    fs.set_xattr(
        FsClock::EPOCH,
        &XattrTarget::Path("/d/file".into()),
        "user.k",
        b"v",
        0,
    )
    .unwrap();

    fs.crash().unwrap();
    assert_eq!(fs.contents("/d/file").unwrap(), b"bytes");
    assert_eq!(fs.metadata("/d/file").unwrap().mode, 0o604);
    assert_eq!(fs.metadata("/d/sub").unwrap().mode, 0o700);
    assert_eq!(fs.metadata("/d").unwrap().mode, 0o777);
    let pipe = fs.metadata("/d/pipe").unwrap();
    let pipe2 = fs.metadata("/d/pipe2").unwrap();
    assert_eq!(
        (pipe.kind, pipe.mode, pipe.nlink),
        (FsEntryKind::Fifo, 0o640, 2)
    );
    assert_eq!((pipe2.kind, pipe2.ino), (FsEntryKind::Fifo, pipe.ino));
    let listed = fs.read_directory(FsClock::EPOCH, "/d").unwrap();
    assert!(listed.contains(&FsDirectoryEntry {
        name: "pipe".into(),
        kind: FsEntryKind::Fifo,
        ino: pipe.ino,
    }));
    let (first, second) = (fs.metadata("/d/l").unwrap(), fs.metadata("/d/l2").unwrap());
    assert_eq!(
        (first.kind, first.ino, first.nlink),
        (FsEntryKind::Symlink, second.ino, 2)
    );
    assert_eq!(fs.read_link(FsClock::EPOCH, "/d/l2").unwrap(), "/target");
    assert_eq!(fs.metadata("/d/s").unwrap().kind, FsEntryKind::Socket);
    let whiteout = fs.metadata("/d/w").unwrap();
    assert_eq!((whiteout.kind, whiteout.mode), (FsEntryKind::CharDevice, 0));
    assert_eq!(
        fs.get_xattr(&XattrTarget::Path("/d/file".into()), "user.k")
            .unwrap(),
        b"v"
    );
}

/// A directory clamped so tightly that the reconstruction walk could not
/// see inside it still comes back with every child intact: permission bits
/// are written from the leaves up, after the namespace is rebuilt.
#[test]
fn a_restrictive_directory_mode_survives_without_hiding_its_children() {
    let mut base = MemFs::new();
    base.create_directory(FsClock::EPOCH, "/d", 0o777).unwrap();
    let mut fs = CrashFs::builder().filesystem(base).build().unwrap();
    fs.create_directory(FsClock::EPOCH, "/d/vault", 0o777)
        .unwrap();
    let fd = fs
        .open(
            FsClock::EPOCH,
            "/d/vault/secret",
            OpenFlags::create_truncate_write(),
        )
        .unwrap();
    fs.write(FsClock::EPOCH, fd, b"inner").unwrap();
    fs.sync(fd).unwrap();
    fs.close(fd).unwrap();
    fs.sync_directory("/d").unwrap();
    fs.sync_directory("/d/vault").unwrap();
    fs.set_mode(FsClock::EPOCH, "/d/vault", 0o000).unwrap();

    fs.crash().unwrap();
    assert_eq!(fs.metadata("/d/vault").unwrap().mode, 0o000);
    // The child is there; only the mode keeps the guest out of it, which is
    // an `EACCES` and never a `NotFound`.
    assert_eq!(
        fs.metadata("/d/vault/secret").unwrap_err().code,
        ErrorCode::Denied
    );
    fs.set_mode(FsClock::EPOCH, "/d/vault", 0o755).unwrap();
    assert_eq!(fs.contents("/d/vault/secret").unwrap(), b"inner");
}

#[test]
fn crash_restores_newly_synced_times_and_symlink_times() {
    // Class pairing: inode metadata durability across actual reconstruction.
    let mut fs = CrashFs::default();
    let fd = fs
        .open(
            FsClock::at(10),
            "/attrs",
            OpenFlags::create_truncate_write(),
        )
        .unwrap();
    fs.write(FsClock::at(20), fd, b"stable").unwrap();
    fs.set_times(FsClock::at(30), fd, Some(1), Some(2)).unwrap();
    fs.symlink(FsClock::at(40), "attrs", "/link").unwrap();
    fs.set_times_by_path(FsClock::at(50), "/link", Some(3), Some(4))
        .unwrap();
    fs.sync(fd).unwrap();
    fs.sync_directory("/").unwrap();
    let durable = fs.fd_metadata(fd).unwrap();
    let link = fs.metadata("/link").unwrap();
    fs.set_times(FsClock::at(60), fd, Some(5), Some(6)).unwrap();
    fs.close(fd).unwrap();
    let mut restored = fs.crash_and_snapshot().unwrap().into_memfs();
    let actual = restored.metadata("/attrs").unwrap();
    assert_eq!(
        (
            actual.atime_nanos,
            actual.mtime_nanos,
            actual.ctime_nanos,
            actual.btime_nanos
        ),
        (
            durable.atime_nanos,
            durable.mtime_nanos,
            durable.ctime_nanos,
            durable.btime_nanos
        )
    );
    let actual = restored.metadata("/link").unwrap();
    assert_eq!(
        (
            actual.atime_nanos,
            actual.mtime_nanos,
            actual.ctime_nanos,
            actual.btime_nanos
        ),
        (
            link.atime_nanos,
            link.mtime_nanos,
            link.ctime_nanos,
            link.btime_nanos
        )
    );
    // Checkpointed symlinks must also retain their nonzero timestamps.
    let mut fs = CrashFs::new(restored);
    fs.crash().unwrap();
    let actual = fs.metadata("/link").unwrap();
    assert_eq!(actual.btime_nanos, 40);
    assert_eq!(actual.ctime_nanos, 50);
}

/// A file whose creation did not survive still comes back as a NAME for the
/// descriptor that is open on it — with its data rolled all the way back.
#[test]
fn a_crash_lost_create_keeps_its_open_descriptor_and_loses_its_data() {
    let mut fs = CrashFs::builder()
        .model_directory_durability(true)
        .directory_loss_probability(1.0)
        .build()
        .unwrap();
    let fd = write(&mut fs, "/fresh", b"never-durable");
    fs.crash().unwrap();

    assert_eq!(
        fs.contents("/fresh").unwrap(),
        b"",
        "a lost create keeps no data"
    );
    let metadata = fs.fd_metadata(fd).expect("the fd stays valid");
    assert_eq!(metadata.len, 0);
    // And it is still writable, so the guest recovers by rewriting.
    assert_eq!(fs.write(FsClock::EPOCH, fd, b"again").unwrap(), 5);
}

/// A descriptor on an entry whose last NAME is gone crosses a crash like any
/// other: a crash reaches the disk, not the process's descriptor table. The
/// journal enumerates names and this node has none, so it is re-bound to a
/// fresh anonymous node carrying what the descriptor last held — and never
/// to a number the rebuilt image gave some unrelated entry.
///
/// RED before inode lifetime: `remove_file` refused an open file outright,
/// so this state was unreachable; with descriptions still keyed by path, the
/// adopted description would have named an entry the rebuilt image does not
/// have.
#[test]
fn a_descriptor_on_an_unlinked_entry_survives_a_crash_without_capturing_another_node() {
    // Directory durability off, so the unlink itself is not the variable
    // under test: this is about what a descriptor on a NAMELESS node means.
    let mut fs = CrashFs::builder()
        .model_directory_durability(false)
        .build()
        .unwrap();
    let kept = write(&mut fs, "/kept", b"durable");
    fs.sync(kept).unwrap();
    let doomed = write(&mut fs, "/doomed", b"anonymous");
    fs.sync(doomed).unwrap();
    fs.checkpoint();
    fs.remove_file(FsClock::EPOCH, "/doomed").unwrap();
    let anonymous_ino = fs.fd_metadata(doomed).unwrap().ino;
    let kept_ino = fs.fd_metadata(kept).unwrap().ino;
    assert_ne!(anonymous_ino, kept_ino);

    fs.crash().unwrap();

    // The named entry comes back at its name; the anonymous one comes back
    // only behind its descriptor, and the two are still different nodes.
    assert_eq!(fs.contents("/kept").unwrap(), b"durable");
    assert_eq!(
        fs.metadata("/doomed").unwrap_err().code,
        ErrorCode::NotFound,
        "an unlinked name is not resurrected by its descriptor"
    );
    let after = fs.fd_metadata(doomed).expect("the descriptor stays valid");
    assert_eq!(after.nlink, 0, "still no name");
    assert_ne!(
        after.ino,
        fs.fd_metadata(kept).unwrap().ino,
        "the anonymous descriptor must not capture another entry's node"
    );
    assert_eq!(after.len, 9, "and still holds what it last wrote");
    // The descriptor is write-only (it was minted by `File::create`), and it
    // still is: a crash cannot change what a descriptor was opened for.
    assert_eq!(fs.write(FsClock::EPOCH, doomed, b"!").unwrap(), 1);
    assert_eq!(fs.fd_metadata(doomed).unwrap().len, 10);
}

fn set_xattr(fs: &mut impl FsDriver, path: &str, value: &[u8]) {
    fs.set_xattr(
        FsClock::EPOCH,
        &XattrTarget::Path(path.into()),
        "user.v",
        value,
        0,
    )
    .unwrap();
}

fn xattr(fs: &mut CrashFs, path: &str) -> Vec<u8> {
    fs.get_xattr(&XattrTarget::Path(path.into()), "user.v")
        .unwrap()
}

/// A journal name reused before its directory is fsynced again: the first
/// journal's creation is durable, its unlink and the second creation are
/// not, so the crash leaves the first journal at the name.
#[test]
fn a_lost_creation_leaves_the_node_a_lost_removal_kept() {
    let mut fs = CrashFs::default();
    let first = write(&mut fs, "/journal", b"first");
    fs.sync(first).unwrap();
    fs.sync_directory("/").unwrap();
    fs.close(first).unwrap();
    fs.remove_file(FsClock::EPOCH, "/journal").unwrap();
    let second = write(&mut fs, "/journal", b"second");
    fs.sync(second).unwrap();
    fs.close(second).unwrap();

    fs.crash().unwrap();

    assert_eq!(fs.contents("/journal").unwrap(), b"first");
}

/// A directory removed durably, recreated, and removed again without the
/// parent fsynced: the lost last removal leaves the recreated directory, with
/// its own mode and attributes, not the first one's that shared its name.
#[test]
fn a_recreated_directory_comes_back_with_its_own_metadata() {
    let mut base = MemFs::new();
    base.create_directory(FsClock::EPOCH, "/d", 0o700).unwrap();
    set_xattr(&mut base, "/d", b"old");
    let mut fs = CrashFs::new(base);
    fs.remove_directory(FsClock::EPOCH, "/d").unwrap();
    fs.sync_directory("/").unwrap();
    fs.create_directory(FsClock::EPOCH, "/d", 0o750).unwrap();
    set_xattr(&mut fs, "/d", b"new");
    fs.sync_directory("/").unwrap();
    fs.sync_directory("/d").unwrap();
    fs.remove_directory(FsClock::EPOCH, "/d").unwrap();

    fs.crash().unwrap();

    assert_eq!(fs.metadata("/d").unwrap().mode, 0o750);
    assert_eq!(xattr(&mut fs, "/d"), b"new");
}

/// A lost unlink of one hard link restores the name onto the node its other
/// link still holds, and that node's fsynced metadata wins over what the
/// unlinked name carried when it went.
#[test]
fn a_restored_hard_link_keeps_its_nodes_fsynced_metadata() {
    let mut fs = CrashFs::default();
    let z = write(&mut fs, "/z", b"Z");
    fs.sync(z).unwrap();
    fs.close(z).unwrap();
    set_xattr(&mut fs, "/z", b"old");
    fs.link(FsClock::EPOCH, "/z", "/a").unwrap();
    fs.sync_directory("/").unwrap();
    fs.remove_file(FsClock::EPOCH, "/z").unwrap();
    set_xattr(&mut fs, "/a", b"new");
    let a = fs
        .open(FsClock::EPOCH, "/a", OpenFlags::read_only())
        .unwrap();
    fs.sync(a).unwrap();
    fs.close(a).unwrap();

    fs.crash().unwrap();

    assert_eq!(
        fs.metadata("/z").unwrap().ino,
        fs.metadata("/a").unwrap().ino
    );
    assert_eq!(xattr(&mut fs, "/a"), b"new");
    assert_eq!(xattr(&mut fs, "/z"), b"new");
}

/// A lost unlink of one hard link restores the name onto a node whose
/// timestamps were changed through the other link and never fsynced: the
/// node's durable timestamps come back, whichever name restores them.
#[test]
fn a_restored_hard_link_rolls_its_nodes_timestamps_back() {
    let mut fs = CrashFs::new(MemFs::new().with_file("/a", b"A").unwrap());
    fs.set_times_by_path(FsClock::EPOCH, "/a", None, Some(10))
        .unwrap();
    fs.checkpoint();
    fs.link(FsClock::EPOCH, "/a", "/z").unwrap();
    fs.sync_directory("/").unwrap();
    fs.remove_file(FsClock::EPOCH, "/z").unwrap();
    fs.set_times_by_path(FsClock::EPOCH, "/a", None, Some(99))
        .unwrap();

    fs.crash().unwrap();

    assert_eq!(
        fs.metadata("/z").unwrap().ino,
        fs.metadata("/a").unwrap().ino
    );
    assert_eq!(fs.metadata("/a").unwrap().mtime_nanos, 10);
}

/// A baseline file whose mode and attributes changed and were fsynced, then
/// was unlinked without its parent fsynced: it comes back with them, not
/// with the baseline's.
#[test]
fn a_restored_baseline_file_keeps_the_metadata_it_was_removed_with() {
    let mut base = MemFs::new().with_file("/f", b"F").unwrap();
    base.set_mode(FsClock::EPOCH, "/f", 0o600).unwrap();
    set_xattr(&mut base, "/f", b"old");
    let mut fs = CrashFs::new(base);
    fs.set_mode(FsClock::EPOCH, "/f", 0o640).unwrap();
    set_xattr(&mut fs, "/f", b"new");
    let fd = fs
        .open(FsClock::EPOCH, "/f", OpenFlags::read_only())
        .unwrap();
    fs.sync(fd).unwrap();
    fs.close(fd).unwrap();
    fs.remove_file(FsClock::EPOCH, "/f").unwrap();

    fs.crash().unwrap();

    assert_eq!(fs.metadata("/f").unwrap().mode, 0o640);
    assert_eq!(xattr(&mut fs, "/f"), b"new");
}

/// A baseline file renamed, its mode and attributes changed and fsynced,
/// then unlinked under its new name, all without the parent fsynced: the
/// lost rename brings back the old name, and it carries the node's
/// metadata from when the node was removed, though the name it was removed
/// under does not survive.
#[test]
fn a_node_brought_back_under_another_name_keeps_its_removal_metadata() {
    let mut base = MemFs::new().with_file("/a", b"A").unwrap();
    base.set_mode(FsClock::EPOCH, "/a", 0o600).unwrap();
    set_xattr(&mut base, "/a", b"old");
    let mut fs = CrashFs::new(base);
    fs.rename(FsClock::EPOCH, "/a", "/b").unwrap();
    fs.set_mode(FsClock::EPOCH, "/b", 0o640).unwrap();
    set_xattr(&mut fs, "/b", b"new");
    let fd = fs
        .open(FsClock::EPOCH, "/b", OpenFlags::read_only())
        .unwrap();
    fs.sync(fd).unwrap();
    fs.close(fd).unwrap();
    fs.remove_file(FsClock::EPOCH, "/b").unwrap();

    fs.crash().unwrap();

    assert_eq!(fs.metadata("/b").unwrap_err().code, ErrorCode::NotFound);
    assert_eq!(fs.metadata("/a").unwrap().mode, 0o640);
    assert_eq!(xattr(&mut fs, "/a"), b"new");
}
