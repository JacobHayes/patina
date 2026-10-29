//! Tests for seeded crash decisions and in-place block tearing.

use std::collections::BTreeSet;

use crate::CrashFs;
use crate::tests::{write, write_only};
use patina_dst_abi::{Fd, FsAllocateMode, FsClock, OpenFlags, SeekWhence};
use patina_dst_driver_api::FsDriver;

fn torn_after_crash(seed: u64) -> Vec<u8> {
    let mut fs = CrashFs::builder()
        .seed(seed)
        .torn_write_granularity(2)
        .torn_write_probability(0.5)
        .build()
        .unwrap();
    let fd = write(&mut fs, "/f", b"AAAAAAAA");
    fs.close(fd).unwrap();
    fs.checkpoint();
    let fd = fs.open(FsClock::EPOCH, "/f", write_only()).unwrap();
    fs.write(FsClock::EPOCH, fd, b"BBBBBBBB").unwrap();
    fs.crash(FsClock::EPOCH).unwrap();
    fs.contents("/f").unwrap()
}

#[test]
fn only_an_in_place_overwrite_tears_and_never_materializes_a_hole() {
    // A 1 TiB file: 4 KiB of `a` at 0, a reservation at 1 GiB, 4 KiB of
    // `z` just below the end, all committed. One step changes it, and the
    // crash keeps every block it can (probability 0); each row expects
    // `st_blocks`, `SEEK_DATA` from 4096 and the first byte. Only the
    // overwrite of a committed block reaches the disk: a write into a hole
    // was never allocated, and a punch or a reservation is an extent change
    // the commit did not record. A hole never becomes data and nothing is
    // materialized: a merge over the hole would not finish.
    const TIB: u64 = 1 << 40;
    const GIB: u64 = 1 << 30;
    type Change = fn(&mut CrashFs, Fd);
    type Expected = (u64, u64, u8);
    let committed = (3 * 8, TIB - 4096, b'a');
    let rows: &[(&str, Change, Expected)] = &[
        (
            "an overwrite of a committed block",
            |fs, fd| {
                fs.write_at(FsClock::EPOCH, fd, 0, b"n").unwrap();
            },
            (3 * 8, TIB - 4096, b'n'),
        ),
        (
            "a write into a hole far out",
            |fs, fd| {
                fs.write_at(FsClock::EPOCH, fd, 512 * GIB, b"new").unwrap();
            },
            committed,
        ),
        (
            "a punched data block",
            |fs, fd| {
                fs.allocate(FsClock::EPOCH, fd, 0, 4096, FsAllocateMode::PunchHole, true)
                    .unwrap();
            },
            committed,
        ),
        (
            "a reservation",
            |fs, fd| {
                fs.allocate(
                    FsClock::EPOCH,
                    fd,
                    2 * GIB,
                    8192,
                    FsAllocateMode::Reserve,
                    true,
                )
                .unwrap();
            },
            committed,
        ),
    ];
    for (name, change, expected) in rows {
        {
            let mut fs = CrashFs::builder()
                .torn_write_probability(0.0)
                .build()
                .unwrap();
            let fd = write(&mut fs, "/f", &[b'a'; 4096]);
            fs.write_at(FsClock::EPOCH, fd, TIB - 4096, &[b'z'; 4096])
                .unwrap();
            fs.allocate(FsClock::EPOCH, fd, GIB, 4096, FsAllocateMode::Reserve, true)
                .unwrap();
            fs.checkpoint();
            change(&mut fs, fd);
            fs.crash(FsClock::EPOCH).unwrap();
            let metadata = fs.fd_metadata(fd).unwrap();
            let data = fs.seek(fd, 4096, SeekWhence::Data).unwrap();
            let reader = fs
                .open(FsClock::EPOCH, "/f", OpenFlags::read_only())
                .unwrap();
            let first = fs.read_at(FsClock::EPOCH, reader, 0, 1).unwrap()[0];
            assert_eq!(metadata.len, TIB, "{name}");
            assert_eq!((metadata.blocks, data, first), *expected, "{name}");
            assert_eq!(
                fs.read_at(FsClock::EPOCH, reader, TIB - 2, 8).unwrap(),
                b"zz"
            );
        }
    }
}

#[test]
fn a_block_tear_mixes_durable_and_live_blocks_and_varies_across_seeds() {
    let baseline = torn_after_crash(0);
    let mut varied = false;
    for seed in 0..64 {
        let torn = torn_after_crash(seed);
        assert_eq!(torn.len(), 8);
        assert!(torn.chunks(2).all(|block| block == b"AA" || block == b"BB"));
        varied |= torn != baseline;
    }
    assert!(varied, "torn writes never varied across seeds");
}

/// The SQLite/Turso torn log tail: a fresh log fsynced once (no directory
/// fsync), then rewritten in place and appended to without one. Across
/// seeds the crash leaves the committed length with each rewritten block
/// old or new on its own, and never the unwritten-back append.
///
/// RED before the journal model: the log's entry was lost unless its
/// directory was fsynced, so no tear ever reached it.
#[test]
fn a_torn_tail_reaches_a_fresh_file_whose_directory_was_never_fsynced() {
    let mut images = BTreeSet::new();
    for seed in 0..64 {
        let mut fs = CrashFs::builder()
            .seed(seed)
            .torn_write_granularity(2)
            .torn_write_probability(0.5)
            .build()
            .unwrap();
        let fd = write(&mut fs, "/wal", b"AAAA");
        fs.sync(fd).unwrap();
        fs.write_at(FsClock::EPOCH, fd, 0, b"BBBBCC").unwrap();
        fs.crash(FsClock::EPOCH).unwrap();
        images.insert(fs.contents("/wal").unwrap());
    }
    let expected: BTreeSet<Vec<u8>> = [b"AAAA", b"BBAA", b"AABB", b"BBBB"]
        .iter()
        .map(|image| image.to_vec())
        .collect();
    assert_eq!(images, expected);
}

/// A block truncated or punched away since the last commit was freed, not
/// overwritten in place: whatever is written there again, its committed
/// bytes come back whole. The block a truncation's end falls in stays
/// allocated, so it tears like any other.
#[test]
fn a_block_freed_since_the_commit_comes_back_whole() {
    const BLOCK: usize = 4096;
    let punch = |fs: &mut CrashFs, fd: Fd| {
        let mode = FsAllocateMode::PunchHole;
        fs.allocate(FsClock::EPOCH, fd, BLOCK as u64, BLOCK as u64, mode, true)
            .unwrap();
    };
    let truncate = |fs: &mut CrashFs, fd: Fd| {
        fs.set_len(FsClock::EPOCH, fd, BLOCK as u64 + 1).unwrap();
    };
    type Free = fn(&mut CrashFs, Fd);
    let frees: [(&str, Free, std::ops::Range<usize>); 2] =
        [("punch", punch, 1..2), ("truncate", truncate, 2..3)];
    for (name, free, freed) in frees {
        let mut kept = BTreeSet::new();
        for seed in 0..16 {
            let mut fs = CrashFs::builder()
                .seed(seed)
                .torn_write_probability(0.5)
                .build()
                .unwrap();
            let fd = write(&mut fs, "/f", &[b'A'; 3 * BLOCK]);
            fs.sync(fd).unwrap();
            free(&mut fs, fd);
            fs.write_at(FsClock::EPOCH, fd, 0, &[b'B'; 3 * BLOCK])
                .unwrap();
            fs.crash(FsClock::EPOCH).unwrap();
            let image = fs.contents("/f").unwrap();
            let blocks: Vec<u8> = image.chunks(BLOCK).map(|block| block[0]).collect();
            assert!(
                blocks[freed.clone()].iter().all(|byte| *byte == b'A'),
                "{name} seed {seed}: {blocks:?}"
            );
            kept.insert(blocks[0]);
        }
        assert_eq!(kept, BTreeSet::from(*b"AB"), "{name}");
    }
}
