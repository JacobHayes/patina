//! Tests for seeded crash decisions and block or byte torn-write merging.

use crate::tests::{append_write, write, write_only};
use crate::{CrashFs, TornGranularity};
use patina_dst_abi::{Fd, FsAllocateMode, FsClock, OpenFlags, SeekWhence};
use patina_dst_driver_api::FsDriver;
use patina_dst_fs_mem::MemFs;

#[test]
fn byte_torn_append_uses_actual_eof_region_after_intervening_writes() {
    let initial = MemFs::new().with_file("/log", b"stable").unwrap();
    let mut fs = CrashFs::builder()
        .filesystem(initial)
        .torn_granularity(TornGranularity::Byte)
        .torn_write_granularity(4096)
        .torn_write_probability(1.0)
        .build()
        .unwrap();
    let append = fs.open(FsClock::EPOCH, "/log", append_write()).unwrap();

    let regular = fs.open(FsClock::EPOCH, "/log", write_only()).unwrap();
    fs.seek(regular, 0, SeekWhence::End).unwrap();
    fs.write(FsClock::EPOCH, regular, b"-intervening").unwrap();
    fs.sync(regular).unwrap();
    fs.close(regular).unwrap();

    fs.write(FsClock::EPOCH, append, b"-tail").unwrap();
    fs.crash().unwrap();
    let after = fs.contents("/log").unwrap();
    let full = b"stable-intervening-tail";
    assert_eq!(after.len(), full.len());
    assert!(after.starts_with(b"stable-intervening-"));
    assert_ne!(after, full);
}

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
/// inside the first write (the region a byte-granularity tear cuts).
fn golden_tear(seed: u64, granularity: TornGranularity) -> Vec<u8> {
    let clock = FsClock::EPOCH;
    let mut fs = CrashFs::builder()
        .seed(seed)
        .torn_write_granularity(512)
        .torn_write_probability(0.5)
        .torn_granularity(granularity)
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
    use TornGranularity::{Block, Byte};
    let rows: &[(TornGranularity, u64, usize, u64)] = &[
        (Block, 0, 20010, 0xdead_e3b0_8f80_ced7),
        (Block, 1, 20010, 0x12ff_b786_e153_1d57),
        (Block, 2, 12388, 0x59d8_b2a7_56dd_9995),
        (Block, 3, 12388, 0xbc4f_c4ab_01cc_c1ad),
        (Block, 4, 20010, 0xa4a2_83cf_a23b_01c3),
        (Block, 5, 12388, 0x6c67_df6c_1454_70c5),
        (Byte, 0, 12388, 0x0311_5781_b715_dd03),
        (Byte, 1, 12388, 0xff19_cb6e_d9c3_1637),
        (Byte, 2, 20010, 0xd8cd_022a_ee65_9837),
        (Byte, 3, 12388, 0xd0c0_21f7_52e2_f51c),
        (Byte, 4, 20010, 0x508d_63a5_332e_0fab),
        (Byte, 5, 20010, 0xd617_6246_f07e_e754),
    ];
    for &(granularity, seed, len, digest) in rows {
        let torn = golden_tear(seed, granularity);
        assert_eq!(
            (torn.len(), fnv(&torn)),
            (len, digest),
            "{granularity:?} seed {seed}"
        );
    }
}

#[test]
fn torn_writes_are_deterministic_per_seed_and_vary_across_seeds() {
    // The same seed reproduces the same tear exactly.
    for seed in 0..8 {
        assert_eq!(torn_after_crash(seed), torn_after_crash(seed));
    }
    // Every result is a per-block mix of the durable and live bytes.
    for seed in 0..8 {
        let torn = torn_after_crash(seed);
        assert_eq!(torn.len(), 8);
        assert!(torn.chunks(2).all(|block| block == b"AA" || block == b"BB"));
    }
    // Some seeds tear differently from seed 0.
    let baseline = torn_after_crash(0);
    assert!(
        (0..64).any(|seed| torn_after_crash(seed) != baseline),
        "torn writes never varied across seeds"
    );
}

#[test]
fn torn_write_probability_extremes_are_decision_free() {
    // Probability 0 keeps every modified block; probability 1 reverts them.
    let mut kept = CrashFs::builder()
        .torn_write_probability(0.0)
        .torn_write_granularity(2)
        .build()
        .unwrap();
    let fd = write(&mut kept, "/f", b"AAAA");
    kept.close(fd).unwrap();
    kept.checkpoint();
    let fd = kept.open(FsClock::EPOCH, "/f", write_only()).unwrap();
    kept.write(FsClock::EPOCH, fd, b"BBBB").unwrap();
    kept.crash().unwrap();
    assert_eq!(kept.contents("/f").unwrap(), b"BBBB");

    let mut reverted = CrashFs::builder()
        .torn_write_probability(1.0)
        .torn_write_granularity(2)
        .build()
        .unwrap();
    let fd = write(&mut reverted, "/f", b"AAAA");
    reverted.close(fd).unwrap();
    reverted.checkpoint();
    let fd = reverted.open(FsClock::EPOCH, "/f", write_only()).unwrap();
    reverted.write(FsClock::EPOCH, fd, b"BBBB").unwrap();
    reverted.crash().unwrap();
    assert_eq!(reverted.contents("/f").unwrap(), b"AAAA");
}

fn byte_torn_final_write(seed: u64) -> Vec<u8> {
    // Durable "AAAA...", then a single unsynced overwrite with "BBBB..."
    // that a byte-granularity crash may tear part-way through.
    let mut fs = CrashFs::builder()
        .seed(seed)
        .torn_granularity(TornGranularity::Byte)
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
fn byte_granularity_tears_the_final_write_into_a_partial_image() {
    // The load-bearing property for the sub-block crash campaign: the final
    // unsynced write survives PARTIALLY, so the reconstructed image differs
    // from BOTH the durable baseline and the fully-applied write -- the torn
    // page a whole-block model can never produce.
    for seed in 0..32 {
        let torn = byte_torn_final_write(seed);
        assert_eq!(torn.len(), 8);
        assert_ne!(
            torn, b"AAAAAAAA",
            "seed {seed} reverted wholesale (durable)"
        );
        assert_ne!(torn, b"BBBBBBBB", "seed {seed} applied wholesale (live)");
        // The surviving prefix is live bytes, the reverted suffix is durable.
        let cut = torn.iter().take_while(|&&byte| byte == b'B').count();
        assert!(
            (1..8).contains(&cut),
            "seed {seed} cut {cut} is not a strict interior split: {torn:?}"
        );
        assert!(
            torn[cut..].iter().all(|&byte| byte == b'A'),
            "seed {seed} suffix is not the durable image: {torn:?}"
        );
    }
}

#[test]
fn byte_torn_final_write_is_deterministic_per_seed_and_varies() {
    for seed in 0..8 {
        assert_eq!(byte_torn_final_write(seed), byte_torn_final_write(seed));
    }
    let baseline = byte_torn_final_write(0);
    assert!(
        (0..64).any(|seed| byte_torn_final_write(seed) != baseline),
        "byte-granularity tear geometry never varied across seeds"
    );
}

#[test]
fn block_granularity_leaves_the_final_write_whole() {
    // The default whole-block policy is unchanged: with certain tearing the
    // single unsynced overwrite reverts entirely to the durable image, never
    // a partial mix. This is the behavior every pre-existing trace relies on.
    for seed in 0..32 {
        let mut fs = CrashFs::builder()
            .seed(seed)
            .torn_granularity(TornGranularity::Block)
            .build()
            .unwrap();
        let fd = write(&mut fs, "/f", b"AAAAAAAA");
        fs.close(fd).unwrap();
        fs.checkpoint();
        let fd = fs.open(FsClock::EPOCH, "/f", write_only()).unwrap();
        fs.write(FsClock::EPOCH, fd, b"BBBBBBBB").unwrap();
        fs.crash().unwrap();
        assert_eq!(
            fs.contents("/f").unwrap(),
            b"AAAAAAAA",
            "whole-block tear produced a non-durable image at seed {seed}"
        );
    }
}

#[test]
fn byte_granularity_tears_only_the_final_write_not_earlier_ones() {
    // An earlier unsynced write to a different page reverts wholesale, while
    // the final write's page tears partially -- the "clean prefix plus one
    // torn final page" geometry the sub-block crash hunt needs.
    let mut fs = CrashFs::builder()
        .seed(11)
        .torn_write_granularity(4)
        .torn_granularity(TornGranularity::Byte)
        .build()
        .unwrap();
    // Durable baseline: two 4-byte pages of zeros.
    let fd = fs
        .open(FsClock::EPOCH, "/db", OpenFlags::create_truncate_write())
        .unwrap();
    fs.set_len(FsClock::EPOCH, fd, 8).unwrap();
    fs.sync(fd).unwrap();
    fs.sync_directory("/").unwrap();
    // First (earlier) write to page 0, then the final write to page 1.
    fs.write_at(FsClock::EPOCH, fd, 0, b"XXXX").unwrap();
    fs.write_at(FsClock::EPOCH, fd, 4, b"YYYY").unwrap();
    fs.crash().unwrap();
    let after = fs.contents("/db").unwrap();
    assert_eq!(after.len(), 8);
    // Page 0 (the earlier write) reverted wholesale to durable zeros.
    assert_eq!(
        &after[0..4],
        &[0, 0, 0, 0],
        "earlier write did not revert wholesale"
    );
    // Page 1 (the final write) tore partially: at least one live 'Y' survived
    // and at least one durable zero remains.
    assert!(
        after[4..8].contains(&b'Y'),
        "final write left no surviving prefix: {after:?}"
    );
    assert!(
        after[4..8].contains(&0),
        "final write applied wholesale instead of tearing: {after:?}"
    );
}
