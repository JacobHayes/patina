//! Tests for the journal: what commits the running transaction, and what a
//! crash between commits leaves.

use crate::CrashFs;
use crate::tests::{at_seconds, with_dir, write, write_only};
use patina_dst_abi::{ErrorCode, FsClock, FsEntryKind, OpenFlags};
use patina_dst_driver_api::FsDriver;
use patina_dst_fs_mem::MemFs;
use std::collections::BTreeSet;

fn bytes_at(fs: &mut CrashFs, path: &str) -> Option<Vec<u8>> {
    fs.contents(path).ok()
}

/// A file opened, written and closed at `clock`, never fsynced.
fn create_at(fs: &mut CrashFs, clock: FsClock, path: &str, bytes: &[u8]) {
    let fd = fs
        .open(clock, path, OpenFlags::create_truncate_write())
        .unwrap();
    fs.write(clock, fd, bytes).unwrap();
    fs.close(fd).unwrap();
}

/// `fsync` of a new file commits the whole running transaction: its own
/// directory entry, with no directory fsync, and every other change on the
/// volume since the last commit. The other file's bytes were never written
/// back, so it comes back empty.
///
/// RED before the journal model: the entry was lost unless `/d` was fsynced.
#[test]
fn a_file_fsync_commits_its_directory_entry_and_every_other_change() {
    let mut fs = with_dir();
    create_at(&mut fs, FsClock::EPOCH, "/d/other", b"never written back");
    fs.create_directory(FsClock::EPOCH, "/d/sub", 0o755)
        .unwrap();
    let fd = write(&mut fs, "/d/new", b"bytes");
    fs.sync(fd).unwrap();
    fs.close(fd).unwrap();

    fs.crash(FsClock::EPOCH).unwrap();

    assert_eq!(bytes_at(&mut fs, "/d/new").unwrap(), b"bytes");
    assert_eq!(bytes_at(&mut fs, "/d/other").unwrap(), b"");
    assert_eq!(fs.metadata("/d/sub").unwrap().kind, FsEntryKind::Directory);
}

/// A creation nothing fsynced is lost by a crash before the transaction's
/// first periodic commit, and kept once five virtual seconds have passed,
/// whether the commit falls due at a later operation or at the crash itself.
/// The create-without-a-directory-fsync bug class stays reachable.
#[test]
fn a_creation_is_lost_before_the_periodic_commit_and_kept_after_it() {
    let crash_at = |seconds: u64, touch_at: Option<u64>| {
        let mut fs = with_dir();
        create_at(&mut fs, at_seconds(1), "/d/f", b"data");
        if let Some(touch) = touch_at {
            fs.read_directory(at_seconds(touch), "/d").unwrap();
        }
        fs.crash(at_seconds(seconds)).unwrap();
        fs.metadata("/d/f").map(|metadata| metadata.len)
    };
    assert_eq!(crash_at(5, None).unwrap_err().code, ErrorCode::NotFound);
    assert_eq!(crash_at(6, None).unwrap(), 0);
    assert_eq!(crash_at(6, Some(6)).unwrap(), 0);
}

/// `fsync` of an inode with no change in the running transaction commits
/// nothing; a directory's own fsync commits once an entry in it changed.
#[test]
fn only_an_fsync_of_a_changed_inode_commits() {
    let mut fs = CrashFs::new(MemFs::new().with_file("/clean", b"c").unwrap());
    create_at(&mut fs, FsClock::EPOCH, "/new", b"n");
    let clean = fs
        .open(FsClock::EPOCH, "/clean", OpenFlags::read_only())
        .unwrap();
    fs.sync(clean).unwrap();
    fs.crash(FsClock::EPOCH).unwrap();
    assert_eq!(bytes_at(&mut fs, "/new"), None);

    create_at(&mut fs, FsClock::EPOCH, "/new", b"n");
    let root = fs
        .open(FsClock::EPOCH, "/", OpenFlags::read_only())
        .unwrap();
    fs.sync(root).unwrap();
    fs.crash(FsClock::EPOCH).unwrap();
    assert_eq!(bytes_at(&mut fs, "/new").unwrap(), b"");
}

/// Delayed allocation: a file comes back at the size the last commit
/// recorded. An append within the block the committed size ends in needs no
/// allocation, so its size is recorded at once and the commit carries it
/// whether or not the bytes reached the block (here they did not: zeros);
/// past that block, only what was written back counts.
#[test]
fn a_file_comes_back_at_the_size_the_last_commit_recorded() {
    let mut fs = CrashFs::default();
    let fd = write(&mut fs, "/log", b"abc");
    fs.sync(fd).unwrap();
    fs.write(at_seconds(1), fd, &[b'd'; 8192]).unwrap();
    fs.crash(at_seconds(10)).unwrap();
    let mut expected = b"abc".to_vec();
    expected.resize(4096, 0);
    assert_eq!(bytes_at(&mut fs, "/log").unwrap(), expected);
}

/// A periodic commit records a fresh file empty, and a later `fsync`
/// allocates its blocks and records its size, so it commits again.
#[test]
fn an_fsync_after_a_periodic_commit_commits_the_data() {
    let mut fs = CrashFs::default();
    let fd = write(&mut fs, "/f", b"data");
    fs.read_directory(at_seconds(10), "/").unwrap();
    fs.sync(fd).unwrap();
    fs.crash(at_seconds(10)).unwrap();
    assert_eq!(bytes_at(&mut fs, "/f").unwrap(), b"data");
}

/// `auto_da_alloc`: a rename over an existing name writes the source's data
/// back, so the commit that carries the rename carries the bytes. A rename
/// onto a fresh name does not, and the commit leaves a zero-length file —
/// the classic ext4 replace-without-fsync result.
#[test]
fn a_rename_over_an_existing_name_carries_the_written_data() {
    let renamed = |replace: bool| {
        let mut fs = CrashFs::new(MemFs::new().with_file("/config", b"old").unwrap());
        create_at(&mut fs, at_seconds(1), "/config.tmp", b"new");
        let to = if replace { "/config" } else { "/fresh" };
        fs.rename(at_seconds(1), "/config.tmp", to).unwrap();
        fs.crash(at_seconds(10)).unwrap();
        bytes_at(&mut fs, to).unwrap()
    };
    assert_eq!(renamed(true), b"new");
    assert_eq!(renamed(false), b"");
}

/// `auto_da_alloc`: closing a file truncated to zero writes its data back;
/// while it is still open, a commit records it empty.
#[test]
fn closing_a_file_truncated_to_zero_writes_its_data_back() {
    let rewritten = |close: bool| {
        let mut fs = CrashFs::new(MemFs::new().with_file("/state", b"old").unwrap());
        let fd = fs
            .open(at_seconds(1), "/state", OpenFlags::create_truncate_write())
            .unwrap();
        fs.write(at_seconds(1), fd, b"new").unwrap();
        if close {
            fs.close(fd).unwrap();
        }
        fs.crash(at_seconds(10)).unwrap();
        bytes_at(&mut fs, "/state").unwrap()
    };
    assert_eq!(rewritten(true), b"new");
    assert_eq!(rewritten(false), b"");
}

/// The rename-over-a-committed-file pattern, crashed before and after the
/// commit that carries the rename, under every tear decision: the crash
/// leaves the old state or the new one whole, never both names nor neither.
///
/// RED before the journal model: with rename atomicity off a crash could
/// leave the entry duplicated or lost — a state no ext4 crash produces.
#[test]
fn a_rename_is_all_or_nothing_at_every_crash_point() {
    let mut states = BTreeSet::new();
    for seed in 0..16 {
        for crash_at in [2, 10] {
            let mut fs = CrashFs::builder()
                .filesystem(MemFs::new().with_file("/db", b"old").unwrap())
                .torn_write_probability(0.5)
                .seed(seed)
                .build()
                .unwrap();
            let fd = write(&mut fs, "/db.tmp", b"new");
            fs.sync(fd).unwrap();
            fs.close(fd).unwrap();
            fs.rename(at_seconds(1), "/db.tmp", "/db").unwrap();
            fs.crash(at_seconds(crash_at)).unwrap();
            states.insert((bytes_at(&mut fs, "/db"), bytes_at(&mut fs, "/db.tmp")));
        }
    }
    let old = (Some(b"old".to_vec()), Some(b"new".to_vec()));
    let new = (Some(b"new".to_vec()), None);
    assert_eq!(states, BTreeSet::from([old, new]));
}

/// An exchange and a whiteout rename are one metadata change each: the
/// crash leaves them done or undone, and both names agree.
#[test]
fn an_exchange_and_a_whiteout_rename_are_all_or_nothing() {
    let base = || {
        MemFs::new()
            .with_file("/a", b"A")
            .unwrap()
            .with_file("/b", b"B")
            .unwrap()
    };
    for commit in [false, true] {
        let mut fs = CrashFs::new(base());
        fs.exchange(at_seconds(1), "/a", "/b").unwrap();
        let crash = if commit { 10 } else { 1 };
        fs.crash(at_seconds(crash)).unwrap();
        let (a, b) = (bytes_at(&mut fs, "/a"), bytes_at(&mut fs, "/b"));
        let expected = if commit { (b"B", b"A") } else { (b"A", b"B") };
        assert_eq!(
            (a.unwrap(), b.unwrap()),
            (expected.0.to_vec(), expected.1.to_vec())
        );

        let mut fs = CrashFs::new(base());
        fs.rename_whiteout(at_seconds(1), "/a", "/c").unwrap();
        fs.crash(at_seconds(crash)).unwrap();
        let a = fs.metadata("/a").unwrap().kind;
        let c = bytes_at(&mut fs, "/c");
        if commit {
            assert_eq!((a, c), (FsEntryKind::CharDevice, Some(b"A".to_vec())));
        } else {
            assert_eq!((a, c), (FsEntryKind::File, None));
        }
    }
}

/// A committed rename of a directory over an empty one moves the whole
/// subtree, and nothing of the replaced directory remains; an uncommitted
/// one leaves both as the last commit had them.
#[test]
fn a_directory_rename_moves_its_subtree_with_the_commit() {
    for commit in [false, true] {
        let mut fs = with_dir();
        fs.create_directory(FsClock::EPOCH, "/d/src", 0o755)
            .unwrap();
        fs.create_directory(FsClock::EPOCH, "/d/dst", 0o755)
            .unwrap();
        let fd = write(&mut fs, "/d/src/child", b"c");
        fs.sync(fd).unwrap();
        fs.close(fd).unwrap();
        fs.rename(at_seconds(1), "/d/src", "/d/dst").unwrap();
        fs.crash(at_seconds(if commit { 10 } else { 1 })).unwrap();
        let moved = bytes_at(&mut fs, "/d/dst/child");
        let stayed = bytes_at(&mut fs, "/d/src/child");
        if commit {
            assert_eq!((moved, stayed), (Some(b"c".to_vec()), None));
        } else {
            assert_eq!((moved, stayed), (None, Some(b"c".to_vec())));
        }
    }
}

/// A removal rolls back with the transaction that held it, and a name
/// reused since the last commit holds the node the commit recorded there.
#[test]
fn a_crash_leaves_the_node_the_last_commit_recorded_at_a_name() {
    let mut fs = CrashFs::default();
    let first = write(&mut fs, "/journal", b"first");
    fs.sync(first).unwrap();
    fs.close(first).unwrap();
    fs.remove_file(at_seconds(1), "/journal").unwrap();
    create_at(&mut fs, at_seconds(1), "/journal", b"second");

    fs.crash(at_seconds(1)).unwrap();

    assert_eq!(bytes_at(&mut fs, "/journal").unwrap(), b"first");
}

/// `auto_da_alloc` flushes only delayed allocations: a rename over an
/// existing name leaves an in-place overwrite of the source's committed
/// blocks unsynced, so it can still come back old.
#[test]
fn a_rename_over_a_name_leaves_in_place_overwrites_unsynced() {
    let mut fs = CrashFs::new(
        MemFs::new()
            .with_file("/src", b"old!")
            .unwrap()
            .with_file("/dst", b"dst")
            .unwrap(),
    );
    let fd = fs.open(at_seconds(1), "/src", write_only()).unwrap();
    fs.write(at_seconds(1), fd, b"new!").unwrap();
    fs.rename(at_seconds(1), "/src", "/dst").unwrap();
    fs.crash(at_seconds(10)).unwrap();
    assert_eq!(bytes_at(&mut fs, "/dst").unwrap(), b"old!");
}

/// An anonymous file is not on the journal: syncing one commits nothing.
#[test]
fn syncing_an_anonymous_file_commits_nothing() {
    let mut fs = CrashFs::default();
    create_at(&mut fs, FsClock::EPOCH, "/named", b"n");
    let anonymous = fs
        .create_anonymous(FsClock::EPOCH, "memfd", 0o600, 0, 0)
        .unwrap();
    fs.set_len(FsClock::EPOCH, anonymous, 10).unwrap();
    fs.sync(anonymous).unwrap();
    fs.crash(FsClock::EPOCH).unwrap();
    assert_eq!(bytes_at(&mut fs, "/named"), None);
}
