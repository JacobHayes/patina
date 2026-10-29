//! Tests for seeded crash decisions and block torn-write merging.

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
    fs.crash().unwrap();
    fs.contents("/f").unwrap()
}

#[test]
fn a_crash_merges_a_sparse_file_block_by_block_without_its_holes() {
    // A 1 TiB file: 4 KiB of `a` at 0, a reservation at 1 GiB, 4 KiB of
    // `z` just below the end, all durable. After the checkpoint one step
    // changes it and the crash keeps (probability 0) or reverts
    // (probability 1) every modified block; each row expects `st_blocks`,
    // `SEEK_DATA` from 4096 and the first byte. A hole never becomes data
    // and nothing is materialized: a merge over the hole would not finish.
    const TIB: u64 = 1 << 40;
    const GIB: u64 = 1 << 30;
    type Change = fn(&mut CrashFs, Fd);
    type Expected = (u64, u64, u8);
    let rows: &[(&str, Change, Expected, Expected)] = &[
        (
            "a write into a hole far out",
            |fs, fd| {
                fs.write_at(FsClock::EPOCH, fd, 512 * GIB, b"new").unwrap();
            },
            (4 * 8, 512 * GIB, b'a'),
            (3 * 8, TIB - 4096, b'a'),
        ),
        (
            "a punched data block (its bytes changed)",
            |fs, fd| {
                fs.allocate(FsClock::EPOCH, fd, 0, 4096, FsAllocateMode::PunchHole, true)
                    .unwrap();
            },
            (2 * 8, TIB - 4096, 0),
            (3 * 8, TIB - 4096, b'a'),
        ),
        (
            "a reservation alone (metadata, no bytes changed)",
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
            (5 * 8, TIB - 4096, b'a'),
            (5 * 8, TIB - 4096, b'a'),
        ),
    ];
    for (name, change, kept, reverted) in rows {
        for (probability, expected) in [(0.0, kept), (1.0, reverted)] {
            let mut fs = CrashFs::builder()
                .torn_write_probability(probability)
                .build()
                .unwrap();
            let fd = write(&mut fs, "/f", &[b'a'; 4096]);
            fs.write_at(FsClock::EPOCH, fd, TIB - 4096, &[b'z'; 4096])
                .unwrap();
            fs.allocate(FsClock::EPOCH, fd, GIB, 4096, FsAllocateMode::Reserve, true)
                .unwrap();
            fs.checkpoint();
            change(&mut fs, fd);
            fs.crash().unwrap();
            let metadata = fs.fd_metadata(fd).unwrap();
            let data = fs.seek(fd, 4096, SeekWhence::Data).unwrap();
            let reader = fs
                .open(FsClock::EPOCH, "/f", OpenFlags::read_only())
                .unwrap();
            let first = fs.read_at(FsClock::EPOCH, reader, 0, 1).unwrap()[0];
            assert_eq!(metadata.len, TIB, "{name}");
            assert_eq!(
                (metadata.blocks, data, first),
                *expected,
                "{name} at probability {probability}"
            );
            assert_eq!(
                fs.read_at(FsClock::EPOCH, reader, TIB - 2, 8).unwrap(),
                b"zz"
            );
        }
    }
}

/// A seeded tear over a multi-block file: 12388 durable bytes, then
/// unsynced writes across blocks, into a hole past the end, and last
/// inside the first write.
fn golden_tear(seed: u64) -> Vec<u8> {
    let clock = FsClock::EPOCH;
    let mut fs = CrashFs::builder()
        .seed(seed)
        .torn_write_granularity(512)
        .torn_write_probability(0.5)
        .build()
        .unwrap();
    let durable: Vec<u8> = (0..12_388u32).map(|i| b'a' + (i % 26) as u8).collect();
    let fd = write(&mut fs, "/f", &durable);
    fs.checkpoint();
    fs.write_at(clock, fd, 1000, &[b'B'; 6000]).unwrap();
    fs.write_at(clock, fd, 20_000, b"CCCCCCCCCC").unwrap();
    fs.write_at(clock, fd, 3000, &[b'D'; 700]).unwrap();
    fs.crash().unwrap();
    fs.contents("/f").unwrap()
}

#[test]
fn a_seeded_tear_is_the_dense_models_byte_for_byte() {
    // Digests (FNV-1a 64) of the dense byte-vector merge's result on main
    // before the block map, per seed: the block-map merge visits fewer
    // blocks but draws the same decisions in the same order, so each
    // seed's torn image is unchanged.
    fn fnv(bytes: &[u8]) -> u64 {
        bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
            (hash ^ u64::from(*byte)).wrapping_mul(0x0100_0000_01b3)
        })
    }
    let rows: &[(u64, usize, u64)] = &[
        (0, 20010, 0xdead_e3b0_8f80_ced7),
        (1, 20010, 0x12ff_b786_e153_1d57),
        (2, 12388, 0x59d8_b2a7_56dd_9995),
        (3, 12388, 0xbc4f_c4ab_01cc_c1ad),
        (4, 20010, 0xa4a2_83cf_a23b_01c3),
        (5, 12388, 0x6c67_df6c_1454_70c5),
    ];
    for &(seed, len, digest) in rows {
        let torn = golden_tear(seed);
        assert_eq!((torn.len(), fnv(&torn)), (len, digest), "seed {seed}");
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

/// An append's blocks persist or revert each on its own, the file's length
/// following its last persisted block: across seeds, a two-block append to a
/// durable empty file recovers as nothing, either block alone, or both.
#[test]
fn an_unsynced_append_recovers_any_subset_of_its_blocks() {
    let mut images = std::collections::BTreeSet::new();
    for seed in 0..64 {
        let mut fs = CrashFs::builder()
            .seed(seed)
            .torn_write_granularity(2)
            .torn_write_probability(0.5)
            .build()
            .unwrap();
        let fd = write(&mut fs, "/f", b"");
        fs.sync(fd).unwrap();
        fs.close(fd).unwrap();
        fs.checkpoint();
        let fd = fs.open(FsClock::EPOCH, "/f", write_only()).unwrap();
        fs.write(FsClock::EPOCH, fd, b"BBCC").unwrap();
        fs.crash().unwrap();
        images.insert(fs.contents("/f").unwrap());
    }
    let expected: std::collections::BTreeSet<Vec<u8>> = [&b""[..], b"BB", b"\0\0CC", b"BBCC"]
        .iter()
        .map(|image| image.to_vec())
        .collect();
    assert_eq!(images, expected);
}
