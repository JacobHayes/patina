//! Tests for crash reconstruction and surviving source-inode selection.

use crate::CrashFs;
use crate::tests::{append_write, lossy, write};
use patina_dst_abi::{ErrorCode, FsClock, FsEntryKind, FsNode, OpenFlags, SeekWhence, XattrTarget};
use patina_dst_driver_api::FsDriver;
use patina_dst_fs_mem::MemFs;

#[test]
fn crash_discards_unsynchronized_data_but_not_open_handles() {
    let mut fs = CrashFs::default();
    let fd = write(&mut fs, "/volatile", b"lost");
    // Fsync the parent directory to make only the namespace entry durable;
    // the unsynced bytes are still discarded, leaving an empty file.
    fs.sync_directory("/").unwrap();
    fs.crash().unwrap();
    assert_eq!(fs.crash_count(), 1);
    assert!(fs.contents("/volatile").unwrap().is_empty());
    // The DATA is gone; the descriptor is not. A write through it lands on
    // the rebuilt file rather than reporting the guest's own fd invalid.
    // The cursor is process state and survives with the fd, so the write
    // lands where the guest left off (past the rolled-back bytes).
    fs.seek(fd, 0, SeekWhence::Start).unwrap();
    assert_eq!(fs.write(FsClock::EPOCH, fd, b"stale").unwrap(), 5);
    assert_eq!(fs.contents("/volatile").unwrap(), b"stale");
}

#[test]
fn append_handle_survives_crash_and_appends_at_rebuilt_eof() {
    let initial = MemFs::new().with_file("/log", b"stable").unwrap();
    let mut fs = CrashFs::new(initial);
    let fd = fs.open(FsClock::EPOCH, "/log", append_write()).unwrap();

    fs.write(FsClock::EPOCH, fd, b"-volatile").unwrap();
    fs.crash().unwrap();
    assert_eq!(fs.contents("/log").unwrap(), b"stable");

    fs.write(FsClock::EPOCH, fd, b"-after").unwrap();
    assert_eq!(fs.contents("/log").unwrap(), b"stable-after");
}

#[test]
fn a_crash_keeps_synced_data_loses_unsynced_and_leaves_handles_usable() {
    let mut fs = CrashFs::default();
    let durable = write(&mut fs, "/keep", b"durable");
    fs.sync(durable).unwrap();
    fs.sync_directory("/").unwrap();
    let volatile = write(&mut fs, "/lose", b"volatile");
    fs.sync_directory("/").unwrap();
    fs.crash().unwrap();

    assert_eq!(fs.contents("/keep").unwrap(), b"durable");
    assert!(fs.contents("/lose").unwrap().is_empty());

    // Handles from before the crash still name their files. A crash rolls
    // back bytes; it cannot invalidate the guest's descriptor table, and
    // reporting `InvalidHandle` here would surface as an impossible `EBADF`.
    fs.seek(durable, 0, SeekWhence::Start).unwrap();
    assert_eq!(fs.write(FsClock::EPOCH, durable, b"D").unwrap(), 1);
    assert_eq!(fs.contents("/keep").unwrap(), b"Durable");
    fs.seek(volatile, 0, SeekWhence::Start).unwrap();
    assert_eq!(fs.write(FsClock::EPOCH, volatile, b"x").unwrap(), 1);
    assert_eq!(fs.contents("/lose").unwrap(), b"x");

    // A fresh open gets its own descriptor number and sees the live bytes.
    let reopened = fs
        .open(FsClock::EPOCH, "/keep", OpenFlags::read_only())
        .unwrap();
    assert_ne!(reopened, durable);
    assert_eq!(fs.read(FsClock::EPOCH, reopened, 16).unwrap(), b"Durable");
}

// --- Finding 2: symlinks are modeled, not silently dropped on crash. ---

#[test]
fn symlink_and_read_link_work_through_crashfs_before_and_after_crash() {
    let mut base = MemFs::new();
    base.create_directory(FsClock::EPOCH, "/d", 0o777).unwrap();
    let mut fs = CrashFs::builder().filesystem(base).build().unwrap();
    fs.symlink(FsClock::EPOCH, "/target", "/d/link").unwrap();
    assert_eq!(fs.read_link(FsClock::EPOCH, "/d/link").unwrap(), "/target");
    assert_eq!(fs.metadata("/d/link").unwrap().kind, FsEntryKind::Symlink);

    // Fsyncing the parent directory makes the symlink and its verbatim target
    // survive the crash rather than being silently dropped.
    fs.sync_directory("/d").unwrap();
    fs.crash().unwrap();
    assert_eq!(fs.read_link(FsClock::EPOCH, "/d/link").unwrap(), "/target");
    assert_eq!(fs.metadata("/d/link").unwrap().kind, FsEntryKind::Symlink);
}

// --- Named pipes: the NAME is durable namespace state, the bytes are not. ---

#[test]
fn fifo_name_and_mode_survive_a_crash_once_the_parent_is_fsynced() {
    let mut base = MemFs::new();
    base.create_directory(FsClock::EPOCH, "/d", 0o777).unwrap();
    let mut fs = CrashFs::builder().filesystem(base).build().unwrap();
    fs.make_fifo(FsClock::EPOCH, "/d/pipe", 0o666).unwrap();
    assert_eq!(fs.metadata("/d/pipe").unwrap().kind, FsEntryKind::Fifo);
    fs.set_mode(FsClock::EPOCH, "/d/pipe", 0o640).unwrap();

    // Fsyncing the parent commits the name; reconstruction must rebuild it
    // as a FIFO with the mode it had, not as a regular file.
    fs.sync_directory("/d").unwrap();
    fs.crash().unwrap();
    let metadata = fs.metadata("/d/pipe").unwrap();
    assert_eq!(metadata.kind, FsEntryKind::Fifo);
    assert_eq!(metadata.mode, 0o640);
    // And it is still listed as a FIFO by its parent.
    assert_eq!(
        fs.read_directory(FsClock::EPOCH, "/d").unwrap(),
        vec![patina_dst_abi::FsDirectoryEntry {
            name: "pipe".into(),
            kind: FsEntryKind::Fifo,
            ino: metadata.ino,
        }]
    );
}

/// A mode is durable metadata like a symlink's target. RED before crash
/// reconstruction restored permission bits: the rebuilt image created every
/// file at `0o644` and every directory at `0o755`, so a `chmod` — or a
/// creation mode a real crash has no way to undo — silently reverted.
#[test]
fn modes_survive_a_crash_for_every_kind_that_owns_one() {
    let mut base = MemFs::new();
    base.create_directory(FsClock::EPOCH, "/d", 0o755).unwrap();
    let mut fs = CrashFs::builder().filesystem(base).build().unwrap();
    let fd = fs
        .open(
            FsClock::EPOCH,
            "/d/file",
            OpenFlags {
                path_only: false,
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
    fs.make_fifo(FsClock::EPOCH, "/d/pipe", 0o640).unwrap();
    fs.sync_directory("/d").unwrap();
    fs.sync_directory("/d/sub").unwrap();

    fs.crash().unwrap();
    assert_eq!(fs.metadata("/d/file").unwrap().mode, 0o604);
    assert_eq!(fs.metadata("/d/sub").unwrap().mode, 0o700);
    assert_eq!(fs.metadata("/d/pipe").unwrap().mode, 0o640);
    assert_eq!(fs.metadata("/d").unwrap().mode, 0o755);
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

/// Two names for one FIFO are one node, and a crash must not split them
/// into two pipes. The file path already grouped by inode; the FIFO path
/// now does too.
#[test]
fn hard_linked_fifos_come_back_from_a_crash_as_one_node() {
    let mut base = MemFs::new();
    base.create_directory(FsClock::EPOCH, "/d", 0o777).unwrap();
    let mut fs = CrashFs::builder().filesystem(base).build().unwrap();
    fs.make_fifo(FsClock::EPOCH, "/d/pipe", 0o666).unwrap();
    fs.link(FsClock::EPOCH, "/d/pipe", "/d/alias").unwrap();
    fs.sync_directory("/d").unwrap();

    fs.crash().unwrap();
    let first = fs.metadata("/d/pipe").unwrap();
    let second = fs.metadata("/d/alias").unwrap();
    assert_eq!(first.kind, FsEntryKind::Fifo);
    assert_eq!(second.kind, FsEntryKind::Fifo);
    assert_eq!(first.ino, second.ino);
    assert_eq!(first.nlink, 2);
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

#[test]
fn hard_link_names_and_durable_timestamps_survive_crash() {
    let mut fs = CrashFs::default();
    let fd = write(&mut fs, "/a", b"data");
    fs.close(fd).unwrap();
    fs.link(FsClock::EPOCH, "/a", "/b").unwrap();
    assert_eq!(fs.contents("/b").unwrap(), b"data");
    fs.set_times_by_path(FsClock::EPOCH, "/a", Some(111), Some(222))
        .unwrap();
    fs.checkpoint();
    fs.crash().unwrap();

    // Both names keep their content and durable timestamps across the crash.
    assert_eq!(fs.contents("/a").unwrap(), b"data");
    assert_eq!(fs.contents("/b").unwrap(), b"data");
    let metadata = fs.metadata("/a").unwrap();
    assert_eq!((metadata.atime_nanos, metadata.mtime_nanos), (111, 222));
}

/// A crash must never hand the guest `EBADF` for a descriptor it is still
/// holding: real storage cannot invalidate a caller's fd, so a guest is
/// right not to tolerate one, and a simulator that produces one is testing
/// against an impossible world.
#[test]
fn descriptors_opened_before_a_crash_stay_usable_after_it() {
    let mut fs = CrashFs::default();
    let fd = write(&mut fs, "/a", b"durable");
    fs.sync(fd).unwrap();
    fs.checkpoint();
    // A second, unsynced write is what the crash rolls back.
    fs.write(FsClock::EPOCH, fd, b"-lost").unwrap();
    fs.crash().unwrap();

    // Every operation on the pre-crash fd resolves; none reports
    // `InvalidHandle` (which the POSIX boundary renders as `EBADF`).
    fs.fd_metadata(fd).expect("fd_metadata after crash");
    fs.seek(fd, 0, SeekWhence::Start).expect("seek after crash");
    fs.sync(fd).expect("sync after crash");
    fs.close(fd).expect("close after crash");
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

/// A post-crash `open` must not reuse a descriptor number the guest still
/// believes is live: aliasing two files onto one fd is a corruption the
/// guest can neither see nor defend against.
#[test]
fn a_post_crash_open_never_reuses_a_live_descriptor_number() {
    let mut fs = CrashFs::default();
    let held = write(&mut fs, "/a", b"data");
    fs.sync(held).unwrap();
    fs.checkpoint();
    fs.crash().unwrap();

    let fresh = fs
        .open(FsClock::EPOCH, "/a", OpenFlags::create_truncate_write())
        .unwrap();
    assert_ne!(fresh, held);
}

#[test]
fn linked_symlinks_and_special_nodes_come_back_as_one_node_each() {
    let mut fs = lossy();
    fs.symlink(FsClock::EPOCH, "t", "/d/l").unwrap();
    fs.link(FsClock::EPOCH, "/d/l", "/d/l2").unwrap();
    fs.make_node(FsClock::EPOCH, "/d/s", FsNode::Socket, 0o600)
        .unwrap();
    fs.make_node(FsClock::EPOCH, "/d/w", FsNode::Whiteout, 0)
        .unwrap();
    fs.sync_directory("/d").unwrap();
    fs.crash().unwrap();
    let (first, second) = (fs.metadata("/d/l").unwrap(), fs.metadata("/d/l2").unwrap());
    assert_eq!(first.ino, second.ino);
    assert_eq!(first.nlink, 2);
    assert_eq!(fs.read_link(FsClock::EPOCH, "/d/l2").unwrap(), "t");
    assert_eq!(fs.metadata("/d/s").unwrap().kind, FsEntryKind::Socket);
    let whiteout = fs.metadata("/d/w").unwrap();
    assert_eq!((whiteout.kind, whiteout.mode), (FsEntryKind::CharDevice, 0));
}

#[test]
fn attributes_survive_a_crash_with_their_node() {
    let mut fs = lossy();
    let fd = write(&mut fs, "/d/f", b"x");
    fs.close(fd).unwrap();
    fs.sync_directory("/d").unwrap();
    fs.set_xattr(
        FsClock::EPOCH,
        &XattrTarget::Path("/d/f".into()),
        "user.k",
        b"v",
        0,
    )
    .unwrap();
    fs.crash().unwrap();
    assert_eq!(
        fs.get_xattr(&XattrTarget::Path("/d/f".into()), "user.k")
            .unwrap(),
        b"v"
    );
}
