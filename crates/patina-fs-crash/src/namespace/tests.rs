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

fn rename_outcome(atomic: bool, seed: u64) -> (bool, bool) {
    let mut fs = CrashFs::builder()
        .seed(seed)
        .model_rename_atomicity(atomic)
        .model_directory_durability(true)
        .directory_loss_probability(0.5)
        .build()
        .unwrap();
    let fd = write(&mut fs, "/a", b"data");
    fs.close(fd).unwrap();
    fs.checkpoint();
    fs.rename(FsClock::EPOCH, "/a", "/b").unwrap();
    fs.crash().unwrap();
    let from = fs.metadata("/a").is_ok();
    let to = fs.metadata("/b").is_ok();
    (from, to)
}

#[test]
fn atomic_rename_is_all_or_nothing_across_a_crash() {
    for seed in 0..64 {
        let (from, to) = rename_outcome(true, seed);
        assert!(
            from != to,
            "atomic rename left both or neither name at seed {seed}: from={from} to={to}"
        );
    }
}

#[test]
fn non_atomic_rename_can_duplicate_or_lose_the_entry() {
    // The two-step rename can leave a state atomic rename never produces:
    // both names present (duplicate) or neither (lost).
    let observed_non_atomic =
        (0..64).any(|seed| matches!(rename_outcome(false, seed), (true, true) | (false, false)));
    assert!(
        observed_non_atomic,
        "non-atomic rename never exposed a torn intermediate state"
    );
}

#[test]
fn directory_fd_sync_commits_namespace_operations() {
    let mut base = MemFs::new();
    base.create_directory(FsClock::EPOCH, "/d", 0o777).unwrap();
    let mut fs = CrashFs::builder()
        .filesystem(base)
        .model_directory_durability(true)
        .directory_loss_probability(1.0)
        .build()
        .unwrap();
    let fd = write(&mut fs, "/d/f", b"x");
    fs.sync(fd).unwrap();
    fs.close(fd).unwrap();
    let dir = fs
        .open(FsClock::EPOCH, "/d", OpenFlags::read_only())
        .unwrap();
    assert_eq!(fs.fd_metadata(dir).unwrap().kind, FsEntryKind::Directory);
    fs.sync(dir).unwrap();
    fs.close(dir).unwrap();
    fs.crash().unwrap();
    assert_eq!(fs.contents("/d/f").unwrap(), b"x");
}

#[test]
fn directory_entry_loss_requires_a_directory_fsync() {
    let mut base = MemFs::new();
    base.create_directory(FsClock::EPOCH, "/d", 0o777).unwrap();

    // Without a directory fsync the created entry can be lost on crash.
    let mut fs = CrashFs::builder()
        .filesystem(base.clone())
        .model_directory_durability(true)
        .directory_loss_probability(1.0)
        .build()
        .unwrap();
    let fd = write(&mut fs, "/d/f", b"x");
    fs.sync(fd).unwrap();
    fs.close(fd).unwrap();
    fs.crash().unwrap();
    assert_eq!(fs.metadata("/d").unwrap().kind, FsEntryKind::Directory);
    assert_eq!(fs.metadata("/d/f").unwrap_err().code, ErrorCode::NotFound);

    // Fsyncing the parent directory commits the entry so it survives.
    let mut fs = CrashFs::builder()
        .filesystem(base)
        .model_directory_durability(true)
        .directory_loss_probability(1.0)
        .build()
        .unwrap();
    let fd = write(&mut fs, "/d/f", b"x");
    fs.sync(fd).unwrap();
    fs.close(fd).unwrap();
    fs.sync_directory("/d").unwrap();
    fs.crash().unwrap();
    assert_eq!(fs.contents("/d/f").unwrap(), b"x");
}

#[test]
fn sync_directory_rejects_non_directories() {
    let mut fs = CrashFs::default();
    let fd = write(&mut fs, "/file", b"x");
    fs.close(fd).unwrap();
    assert_eq!(
        fs.sync_directory("/file").unwrap_err().code,
        ErrorCode::NotDirectory
    );
    assert_eq!(
        fs.sync_directory("/missing").unwrap_err().code,
        ErrorCode::NotFound
    );
}

#[test]
fn an_unsynced_fifo_creation_is_lost_like_any_other_name() {
    let mut base = MemFs::new();
    base.create_directory(FsClock::EPOCH, "/d", 0o777).unwrap();
    let mut fs = CrashFs::builder()
        .filesystem(base)
        .seed(7)
        .model_directory_durability(true)
        .directory_loss_probability(1.0)
        .build()
        .unwrap();
    fs.make_fifo(FsClock::EPOCH, "/d/pipe", 0o666).unwrap();
    fs.crash().unwrap();
    assert_eq!(
        fs.metadata("/d/pipe").unwrap_err().code,
        ErrorCode::NotFound,
        "an uncommitted FIFO creation is namespace state a crash can lose"
    );
}

fn symlink_after_crash(sync_dir: bool, probability: f64, seed: u64) -> Option<String> {
    let mut base = MemFs::new();
    base.create_directory(FsClock::EPOCH, "/d", 0o777).unwrap();
    let mut fs = CrashFs::builder()
        .filesystem(base)
        .seed(seed)
        .model_directory_durability(true)
        .directory_loss_probability(probability)
        .build()
        .unwrap();
    fs.symlink(FsClock::EPOCH, "/target", "/d/link").unwrap();
    if sync_dir {
        fs.sync_directory("/d").unwrap();
    }
    fs.crash().unwrap();
    fs.read_link(FsClock::EPOCH, "/d/link").ok()
}

#[test]
fn symlink_survives_crash_when_parent_directory_is_fsynced() {
    // Even with certain loss configured, an fsynced directory commits the
    // symlink so it survives.
    assert_eq!(
        symlink_after_crash(true, 1.0, 7),
        Some("/target".to_owned())
    );
}

#[test]
fn symlink_is_lost_without_directory_fsync() {
    // Without the directory fsync and certain loss, the symlink is dropped
    // by the seeded policy (deterministically), not silently.
    assert_eq!(symlink_after_crash(false, 1.0, 7), None);
}

#[test]
fn symlink_loss_is_deterministic_per_seed_and_varies() {
    for seed in 0..8 {
        assert_eq!(
            symlink_after_crash(false, 0.5, seed),
            symlink_after_crash(false, 0.5, seed)
        );
    }
    let outcomes: Vec<bool> = (0..32)
        .map(|seed| symlink_after_crash(false, 0.5, seed).is_some())
        .collect();
    assert!(
        outcomes.iter().any(|kept| *kept) && outcomes.iter().any(|kept| !*kept),
        "seeded symlink loss never varied across seeds"
    );
}

// --- Finding 8: rename durability is governed by both parent directories. ---

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

#[test]
fn non_atomic_rename_only_dest_fsync_leaves_unlink_side_losable() {
    // Fsyncing only the destination parent makes the new link durable, but
    // the source unlink is still subject to loss, so the old name can
    // survive (duplicated) for some seeds. The new name is always present.
    let mut saw_duplicate = false;
    for seed in 0..64 {
        let (from, to) = rename_two_sided(false, true, false, seed);
        assert!(to, "destination link should be durable at seed {seed}");
        saw_duplicate |= from;
    }
    assert!(
        saw_duplicate,
        "only-destination fsync never left the unlink side losable"
    );
}

#[test]
fn non_atomic_rename_only_source_fsync_leaves_link_side_losable() {
    // Fsyncing only the source parent makes the unlink durable, but the new
    // link is still subject to loss, so the destination can be missing
    // (data lost) for some seeds. The old name is always gone.
    let mut saw_lost = false;
    for seed in 0..64 {
        let (from, to) = rename_two_sided(false, false, true, seed);
        assert!(!from, "source unlink should be durable at seed {seed}");
        saw_lost |= !to;
    }
    assert!(
        saw_lost,
        "only-source fsync never left the link side losable"
    );
}

#[test]
fn rename_with_both_parents_fsynced_is_fully_durable() {
    for atomic in [true, false] {
        for seed in 0..64 {
            assert_eq!(
                rename_two_sided(atomic, true, true, seed),
                (false, true),
                "both-parent fsync should fully commit the rename (atomic={atomic})"
            );
        }
    }
}

#[test]
fn atomic_rename_stays_all_or_nothing_under_partial_dir_sync() {
    // Atomic rename is never torn: partial directory sync leaves it subject
    // to a single all-or-nothing decision, never both or neither name.
    for (sync_dest, sync_source) in [(true, false), (false, true), (false, false)] {
        for seed in 0..64 {
            let (from, to) = rename_two_sided(true, sync_dest, sync_source, seed);
            assert!(
                from != to,
                "atomic rename produced a torn state at seed {seed}: from={from} to={to}"
            );
        }
    }
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

#[test]
fn a_directory_replacing_an_empty_one_is_undone_by_a_lost_rename() {
    let mut fs = lossy();
    fs.create_directory(FsClock::EPOCH, "/d/a", 0o700).unwrap();
    fs.create_directory(FsClock::EPOCH, "/d/b", 0o755).unwrap();
    fs.sync_all().unwrap();
    fs.rename(FsClock::EPOCH, "/d/a", "/d/b").unwrap();
    fs.crash().unwrap();
    assert_eq!(fs.metadata("/d/a").unwrap().mode, 0o700);
    assert_eq!(fs.metadata("/d/b").unwrap().mode, 0o755);
}

/// RED before: a name a lost rename brought back was rebuilt from the LIVE
/// node at that name — the file that had been moved over it.
#[test]
fn a_lost_rename_over_a_file_brings_the_replaced_file_back() {
    let mut fs = lossy();
    for (path, bytes) in [("/d/a", b"A"), ("/d/b", b"B")] {
        let fd = write(&mut fs, path, bytes);
        fs.close(fd).unwrap();
    }
    fs.sync_all().unwrap();
    fs.rename(FsClock::EPOCH, "/d/a", "/d/b").unwrap();
    fs.crash().unwrap();
    assert_eq!(fs.contents("/d/a").unwrap(), b"A");
    assert_eq!(fs.contents("/d/b").unwrap(), b"B");
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
