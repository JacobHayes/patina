//! Tests for namespace journaling, directory durability, and survivor paths.

use crate::CrashFs;
use crate::tests::{lossy, write, write_only};
use patina_dst_abi::{ErrorCode, FsClock, FsEntryKind, OpenFlags};
use patina_dst_driver_api::FsDriver;
use patina_dst_fs_mem::MemFs;
use std::collections::BTreeSet;

#[test]
fn crash_prunes_children_whose_parent_chain_was_lost() {
    let mut fs = CrashFs::builder()
        .model_directory_durability(true)
        .directory_loss_probability(1.0)
        .build()
        .unwrap();
    fs.create_directory(FsClock::EPOCH, "/parent", 0o777)
        .unwrap();
    fs.create_directory(FsClock::EPOCH, "/parent/child", 0o777)
        .unwrap();
    let fd = write(&mut fs, "/parent/child/file", b"data");
    fs.close(fd).unwrap();
    fs.symlink(FsClock::EPOCH, "file", "/parent/child/link")
        .unwrap();
    fs.sync_directory("/parent").unwrap();
    fs.sync_directory("/parent/child").unwrap();

    fs.crash().unwrap();
    assert_eq!(
        fs.metadata("/parent").unwrap_err().code,
        ErrorCode::NotFound
    );
    assert_eq!(
        fs.metadata("/parent/child").unwrap_err().code,
        ErrorCode::NotFound
    );
    assert_eq!(
        fs.metadata("/parent/child/file").unwrap_err().code,
        ErrorCode::NotFound
    );
    assert_eq!(
        fs.metadata("/parent/child/link").unwrap_err().code,
        ErrorCode::NotFound
    );
}

/// An entry of any kind created since the parent's last fsync is lost by a
/// crash with certain loss, however its own bytes were synced; an fsync of
/// the parent, through a directory descriptor as well as by path, commits
/// it. Only a directory can be fsynced as one.
#[test]
fn a_new_entry_is_lost_without_a_parent_fsync_and_kept_with_one() {
    let mut base = MemFs::new();
    base.create_directory(FsClock::EPOCH, "/d", 0o777).unwrap();
    let populate = |fs: &mut CrashFs| {
        let fd = write(fs, "/d/f", b"x");
        fs.sync(fd).unwrap();
        fs.close(fd).unwrap();
        fs.make_fifo(FsClock::EPOCH, "/d/pipe", 0o666).unwrap();
        fs.symlink(FsClock::EPOCH, "/target", "/d/link").unwrap();
    };

    let mut fs = CrashFs::new(base.clone());
    populate(&mut fs);
    fs.crash().unwrap();
    assert_eq!(fs.metadata("/d").unwrap().kind, FsEntryKind::Directory);
    for name in ["/d/f", "/d/pipe", "/d/link"] {
        assert_eq!(
            fs.metadata(name).unwrap_err().code,
            ErrorCode::NotFound,
            "{name}"
        );
    }

    let mut fs = CrashFs::new(base);
    populate(&mut fs);
    let dir = fs
        .open(FsClock::EPOCH, "/d", OpenFlags::read_only())
        .unwrap();
    fs.sync(dir).unwrap();
    fs.close(dir).unwrap();
    fs.crash().unwrap();
    assert_eq!(fs.contents("/d/f").unwrap(), b"x");
    assert_eq!(fs.metadata("/d/pipe").unwrap().kind, FsEntryKind::Fifo);
    assert_eq!(fs.read_link(FsClock::EPOCH, "/d/link").unwrap(), "/target");

    assert_eq!(
        fs.sync_directory("/d/f").unwrap_err().code,
        ErrorCode::NotDirectory
    );
    assert_eq!(
        fs.sync_directory("/missing").unwrap_err().code,
        ErrorCode::NotFound
    );
}

fn rename_two_sided(atomic: bool, sync_dest: bool, sync_source: bool, seed: u64) -> (bool, bool) {
    let mut base = MemFs::new();
    base.create_directory(FsClock::EPOCH, "/src", 0o777)
        .unwrap();
    base.create_directory(FsClock::EPOCH, "/dst", 0o777)
        .unwrap();
    let mut fs = CrashFs::builder()
        .filesystem(base)
        .seed(seed)
        .model_rename_atomicity(atomic)
        .model_directory_durability(true)
        .directory_loss_probability(0.5)
        .build()
        .unwrap();
    let fd = write(&mut fs, "/src/a", b"data");
    fs.close(fd).unwrap();
    fs.checkpoint();
    fs.rename(FsClock::EPOCH, "/src/a", "/dst/b").unwrap();
    if sync_dest {
        fs.sync_directory("/dst").unwrap();
    }
    if sync_source {
        fs.sync_directory("/src").unwrap();
    }
    fs.crash().unwrap();
    (fs.metadata("/src/a").is_ok(), fs.metadata("/dst/b").is_ok())
}

/// A rename's durability is governed by both parent directories. With both
/// fsynced it is fully durable. An atomic rename is otherwise one
/// all-or-nothing decision; a non-atomic one is two: fsyncing only the
/// destination keeps the new name but can leave the old one (duplicated),
/// fsyncing only the source drops the old name but can lose the new one,
/// and fsyncing neither can do either.
#[test]
fn rename_durability_follows_both_parent_directories() {
    let (mut duplicated, mut lost, mut torn) = (false, false, false);
    for seed in 0..64 {
        for atomic in [true, false] {
            assert_eq!(
                rename_two_sided(atomic, true, true, seed),
                (false, true),
                "both parents fsynced, atomic={atomic}, seed {seed}"
            );
        }
        for (sync_dest, sync_source) in [(true, false), (false, true), (false, false)] {
            let (from, to) = rename_two_sided(true, sync_dest, sync_source, seed);
            assert!(
                from != to,
                "atomic rename torn at seed {seed}: from={from} to={to}"
            );
        }
        let (from, to) = rename_two_sided(false, true, false, seed);
        assert!(to, "destination link should be durable at seed {seed}");
        duplicated |= from;
        let (from, to) = rename_two_sided(false, false, true, seed);
        assert!(!from, "source unlink should be durable at seed {seed}");
        lost |= !to;
        torn |= matches!(
            rename_two_sided(false, false, false, seed),
            (true, true) | (false, false)
        );
    }
    assert!(
        duplicated,
        "only-destination fsync never left the unlink side losable"
    );
    assert!(lost, "only-source fsync never left the link side losable");
    assert!(
        torn,
        "non-atomic rename never exposed a torn intermediate state"
    );
}

#[test]
fn an_exchange_is_all_or_nothing_across_a_crash() {
    for commit in [false, true] {
        let mut fs = lossy();
        let fd = write(&mut fs, "/d/a", b"A");
        fs.close(fd).unwrap();
        fs.create_directory(FsClock::EPOCH, "/d/b", 0o755).unwrap();
        fs.sync_all().unwrap();
        fs.exchange(FsClock::EPOCH, "/d/a", "/d/b").unwrap();
        if commit {
            fs.sync_directory("/d").unwrap();
        }
        fs.crash().unwrap();
        let (a, b) = (fs.metadata("/d/a").unwrap(), fs.metadata("/d/b").unwrap());
        if commit {
            assert_eq!(
                (a.kind, b.kind),
                (FsEntryKind::Directory, FsEntryKind::File)
            );
            assert_eq!(fs.contents("/d/b").unwrap(), b"A");
        } else {
            assert_eq!(
                (a.kind, b.kind),
                (FsEntryKind::File, FsEntryKind::Directory)
            );
            assert_eq!(fs.contents("/d/a").unwrap(), b"A");
        }
    }
}

/// A lost rename over an existing entry brings the replaced entry back,
/// not the live node that had been moved over it, for a directory over an
/// empty directory and a file over a file.
#[test]
fn a_lost_rename_brings_back_the_entry_it_replaced() {
    let mut fs = lossy();
    fs.create_directory(FsClock::EPOCH, "/d/a", 0o700).unwrap();
    fs.create_directory(FsClock::EPOCH, "/d/b", 0o755).unwrap();
    for (path, bytes) in [("/d/f", b"F"), ("/d/g", b"G")] {
        let fd = write(&mut fs, path, bytes);
        fs.close(fd).unwrap();
    }
    fs.sync_all().unwrap();
    fs.rename(FsClock::EPOCH, "/d/a", "/d/b").unwrap();
    fs.rename(FsClock::EPOCH, "/d/f", "/d/g").unwrap();
    fs.crash().unwrap();
    assert_eq!(fs.metadata("/d/a").unwrap().mode, 0o700);
    assert_eq!(fs.metadata("/d/b").unwrap().mode, 0o755);
    assert_eq!(fs.contents("/d/f").unwrap(), b"F");
    assert_eq!(fs.contents("/d/g").unwrap(), b"G");
}

/// A crash model where every uncommitted namespace change is a coin flip,
/// so a run over many seeds reaches every combination of survived and
/// lost changes.
fn coin_flips(seed: u64) -> CrashFs {
    let mut base = MemFs::new();
    base.create_directory(FsClock::EPOCH, "/d", 0o777).unwrap();
    CrashFs::builder()
        .filesystem(base)
        .seed(seed)
        .model_directory_durability(true)
        .directory_loss_probability(0.5)
        .build()
        .unwrap()
}

/// Every state `observe` reads after `run` and a crash, over enough seeds
/// to decide each of a handful of changes both ways.
fn crash_states<T: Ord>(
    run: impl Fn(&mut CrashFs),
    observe: impl Fn(&mut CrashFs) -> T,
) -> BTreeSet<T> {
    (0..64)
        .map(|seed| {
            let mut fs = coin_flips(seed);
            run(&mut fs);
            fs.crash().unwrap();
            observe(&mut fs)
        })
        .collect()
}

fn bytes_at(fs: &mut CrashFs, path: &str) -> Option<Vec<u8>> {
    fs.contents(path).ok()
}

/// Overwrite `path`'s bytes in place and `fsync` them.
fn write_and_fsync(fs: &mut CrashFs, path: &str, bytes: &[u8]) {
    let fd = fs.open(FsClock::EPOCH, path, write_only()).unwrap();
    fs.write(FsClock::EPOCH, fd, bytes).unwrap();
    fs.sync(fd).unwrap();
    fs.close(fd).unwrap();
}

fn seed_file(fs: &mut CrashFs, path: &str, bytes: &[u8]) {
    let fd = write(fs, path, bytes);
    fs.close(fd).unwrap();
}

/// `fsync` makes a node's bytes durable whatever later happens to its
/// name: a rename of the file, of its directory, or an exchange, survived
/// or lost, leaves the fsynced bytes at whichever name the node has.
#[test]
fn fsynced_bytes_survive_a_later_rename_either_way() {
    let file = crash_states(
        |fs| {
            seed_file(fs, "/d/f", b"old");
            fs.sync_all().unwrap();
            write_and_fsync(fs, "/d/f", b"new");
            fs.rename(FsClock::EPOCH, "/d/f", "/d/g").unwrap();
        },
        |fs| (bytes_at(fs, "/d/f"), bytes_at(fs, "/d/g")),
    );
    assert_eq!(
        file,
        BTreeSet::from([(Some(b"new".to_vec()), None), (None, Some(b"new".to_vec()))])
    );
    let parent = crash_states(
        |fs| {
            fs.create_directory(FsClock::EPOCH, "/d/a", 0o755).unwrap();
            seed_file(fs, "/d/a/f", b"old");
            fs.sync_all().unwrap();
            write_and_fsync(fs, "/d/a/f", b"new");
            fs.rename(FsClock::EPOCH, "/d/a", "/d/b").unwrap();
        },
        |fs| (bytes_at(fs, "/d/a/f"), bytes_at(fs, "/d/b/f")),
    );
    assert_eq!(
        parent,
        BTreeSet::from([(Some(b"new".to_vec()), None), (None, Some(b"new".to_vec()))])
    );
    let exchange = crash_states(
        |fs| {
            seed_file(fs, "/d/f", b"old");
            seed_file(fs, "/d/g", b"G");
            fs.sync_all().unwrap();
            write_and_fsync(fs, "/d/f", b"new");
            fs.exchange(FsClock::EPOCH, "/d/f", "/d/g").unwrap();
        },
        |fs| (bytes_at(fs, "/d/f"), bytes_at(fs, "/d/g")),
    );
    assert_eq!(
        exchange,
        BTreeSet::from([
            (Some(b"new".to_vec()), Some(b"G".to_vec())),
            (Some(b"G".to_vec()), Some(b"new".to_vec())),
        ])
    );
}

/// A rename onto an empty directory needs the replaced node empty, and a
/// durable rename frees that node: a lost removal of its former child
/// cannot put the child back beneath the directory that moved in.
#[test]
fn a_durable_rename_over_a_directory_leaves_none_of_its_children() {
    for child_is_directory in [false, true] {
        let states = crash_states(
            |fs| {
                fs.create_directory(FsClock::EPOCH, "/d/a", 0o700).unwrap();
                fs.create_directory(FsClock::EPOCH, "/d/b", 0o750).unwrap();
                if child_is_directory {
                    fs.create_directory(FsClock::EPOCH, "/d/b/c", 0o755)
                        .unwrap();
                } else {
                    seed_file(fs, "/d/b/c", b"C");
                }
                fs.sync_all().unwrap();
                if child_is_directory {
                    fs.remove_directory(FsClock::EPOCH, "/d/b/c").unwrap();
                } else {
                    fs.remove_file(FsClock::EPOCH, "/d/b/c").unwrap();
                }
                fs.rename(FsClock::EPOCH, "/d/a", "/d/b").unwrap();
            },
            |fs| {
                let mode = |fs: &mut CrashFs, path: &str| fs.metadata(path).ok().map(|m| m.mode);
                (
                    mode(fs, "/d/a"),
                    mode(fs, "/d/b"),
                    fs.metadata("/d/b/c").is_ok(),
                )
            },
        );
        assert_eq!(
            states,
            BTreeSet::from([
                // Both lost.
                (Some(0o700), Some(0o750), true),
                // The removal survived, the rename lost.
                (Some(0o700), Some(0o750), false),
                // The rename survived, whatever the removal did.
                (None, Some(0o700), false),
            ]),
            "child is a directory: {child_is_directory}"
        );
    }
}

/// `RENAME_WHITEOUT` is one change: the name moves and the whiteout takes
/// its old place together, or neither happens.
#[test]
fn a_whiteout_rename_is_all_or_nothing_across_a_crash() {
    let states = crash_states(
        |fs| {
            seed_file(fs, "/d/f", b"F");
            fs.sync_all().unwrap();
            fs.rename_whiteout(FsClock::EPOCH, "/d/f", "/d/g").unwrap();
        },
        |fs| {
            let kind = |fs: &mut CrashFs, path: &str| {
                fs.metadata(path).ok().map(|m| format!("{:?}", m.kind))
            };
            (kind(fs, "/d/f"), bytes_at(fs, "/d/g"))
        },
    );
    assert_eq!(
        states,
        BTreeSet::from([
            (Some("File".to_owned()), None),
            (Some("CharDevice".to_owned()), Some(b"F".to_vec())),
        ])
    );
}

/// Create, fsync and remove `path`: a temp file's whole life.
fn create_and_remove(fs: &mut CrashFs, path: &str, bytes: &[u8]) {
    let fd = write(fs, path, bytes);
    fs.sync(fd).unwrap();
    fs.close(fd).unwrap();
    fs.remove_file(FsClock::EPOCH, path).unwrap();
}

/// A lost removal leaves the name holding the node it took away, so a file
/// created and removed since the last durability point comes back exactly
/// when its creation survived and its removal did not, with the bytes it
/// fsynced. Nothing else brings it back, and no outcome fails the crash.
#[test]
fn a_removed_file_comes_back_only_where_its_creation_survived() {
    let states = crash_states(
        |fs| create_and_remove(fs, "/d/f", b"F"),
        |fs| bytes_at(fs, "/d/f"),
    );
    assert_eq!(states, BTreeSet::from([None, Some(b"F".to_vec())]));
}

/// `remove_dir_all` of a directory holding a file, as a dropped temp
/// directory does. With nothing committed every change is lost and nothing
/// comes back. With both creations committed, each name comes back exactly
/// when its own removal was lost, and a directory that comes back keeps the
/// mode it was made with.
#[test]
fn a_removed_directory_with_a_file_comes_back_only_where_its_creations_survived() {
    let temp_dir = |fs: &mut CrashFs, commit: bool| {
        fs.create_directory(FsClock::EPOCH, "/d/s", 0o750).unwrap();
        let fd = write(fs, "/d/s/f", b"F");
        fs.sync(fd).unwrap();
        fs.close(fd).unwrap();
        if commit {
            fs.sync_directory("/d").unwrap();
            fs.sync_directory("/d/s").unwrap();
        }
        fs.remove_file(FsClock::EPOCH, "/d/s/f").unwrap();
        fs.remove_directory(FsClock::EPOCH, "/d/s").unwrap();
    };
    let observe = |fs: &mut CrashFs| {
        let mode = fs.metadata("/d/s").ok().map(|metadata| metadata.mode);
        (mode, bytes_at(fs, "/d/s/f"))
    };

    let mut fs = lossy();
    temp_dir(&mut fs, false);
    fs.crash().unwrap();
    assert_eq!(observe(&mut fs), (None, None));

    let states = crash_states(|fs| temp_dir(fs, true), observe);
    assert_eq!(
        states,
        BTreeSet::from([
            (None, None),
            (Some(0o750), None),
            (Some(0o750), Some(b"F".to_vec())),
        ])
    );
}
