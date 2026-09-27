//! A sparse file costs what it has written, not its length: the heap a 100 GiB
//! file with a few KiB written holds, and one written in scattered blocks
//! across 1 TiB, measured by a counting allocator (this test binary's own;
//! its tests take turns, so each counts only itself).

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use patina_dst_abi::{FsAllocateMode, FsClock, OpenFlags};
use patina_dst_driver_api::FsDriver;
use patina_dst_fs_mem::MemFs;

struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);

// SAFETY: every call forwards to the system allocator unchanged; the counter
// only observes sizes.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        LIVE.fetch_add(layout.size(), Ordering::Relaxed);
        // SAFETY: forwarded under the caller's contract.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        // SAFETY: forwarded under the caller's contract.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

const GIB: u64 = 1 << 30;

/// One test at a time: the counter is the whole process's.
static TURN: Mutex<()> = Mutex::new(());

#[test]
fn a_100_gib_sparse_file_with_a_few_kib_written_costs_a_few_kib() {
    let _turn = TURN.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut fs = MemFs::new();
    let flags = OpenFlags {
        read: true,
        write: true,
        create: true,
        truncate: false,
        append: false,
        exclusive: true,
        path_only: false,
        mode: 0o644,
    };
    let fd = fs.open(FsClock::EPOCH, "/tmp/sparse", flags).unwrap();
    let before = LIVE.load(Ordering::Relaxed);
    let clock = FsClock::EPOCH;
    // Every way a file reaches 100 GiB without writing it: an extending
    // truncate, a write far past the end, a reservation past the end.
    fs.set_len(clock, fd, 50 * GIB).unwrap();
    fs.write_at(clock, fd, 100 * GIB - 3000, &[7; 3000])
        .unwrap();
    fs.write_at(clock, fd, 0, &[1; 1000]).unwrap();
    fs.allocate(
        clock,
        fd,
        100 * GIB,
        64 * GIB,
        FsAllocateMode::Reserve,
        true,
    )
    .unwrap();
    fs.allocate(clock, fd, 10 * GIB, GIB, FsAllocateMode::PunchHole, true)
        .unwrap();
    let held = LIVE.load(Ordering::Relaxed) - before;
    let metadata = fs.fd_metadata(fd).unwrap();
    assert_eq!(metadata.len, 100 * GIB);
    // Two written blocks and 64 GiB reserved past the end.
    assert_eq!(metadata.blocks, (2 + 16 * 1024 * 1024) * 8);
    assert!(held < 16 * 1024, "the file holds {held} bytes of heap");
    // A copy (what a crash model's durability point takes) and a restart
    // snapshot cost the written blocks too.
    let image = fs.persistent_snapshot();
    let encoded = image.export_snapshot().encode().unwrap();
    assert!(
        encoded.len() < 16 * 1024,
        "the snapshot is {} bytes",
        encoded.len()
    );
    assert!(LIVE.load(Ordering::Relaxed) - before < 64 * 1024);
}

#[test]
fn scattered_blocks_across_a_1_tib_span_cost_their_bytes_and_a_little_index() {
    // 20000 4 KiB writes at seeded block offsets spread over 1 TiB, most of
    // them alone in their 2 MiB of the file: the heap beyond the blocks'
    // own bytes stays within 128 bytes a block, and a copy (a crash model's
    // durability point) costs a reference per leaf, not a slot per block.
    let _turn = TURN.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    const WRITES: u64 = 20_000;
    let span = (1u64 << 40) / 4096;
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let offsets: Vec<u64> = (0..WRITES)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state % span * 4096
        })
        .collect();
    let mut fs = MemFs::new();
    let flags = OpenFlags {
        read: true,
        write: true,
        create: true,
        truncate: false,
        append: false,
        exclusive: true,
        path_only: false,
        mode: 0o644,
    };
    let fd = fs.open(FsClock::EPOCH, "/tmp/scatter", flags).unwrap();
    let page = [7u8; 4096];
    let before = LIVE.load(Ordering::Relaxed);
    for offset in &offsets {
        fs.write_at(FsClock::EPOCH, fd, *offset, &page).unwrap();
    }
    let held = LIVE.load(Ordering::Relaxed) - before;
    let blocks = fs.fd_metadata(fd).unwrap().blocks / 8;
    let index = held as u64 - blocks * (4096 + 16);
    assert!(
        index < blocks * 128,
        "{blocks} blocks hold {index} bytes of index"
    );
    let copied = LIVE.load(Ordering::Relaxed);
    let image = fs.persistent_snapshot();
    let copy = LIVE.load(Ordering::Relaxed) - copied;
    assert!(copy < index as usize / 2, "a copy costs {copy} bytes");
    drop(image);
}

#[test]
fn dense_leaves_punched_to_one_block_each_give_their_room_back() {
    // 200 stretches of 2 MiB (one index leaf each), every block written with
    // one byte, then each punched down to its first block: a survivor holds
    // its byte and a little index, not the slots its dense stretch needed.
    let _turn = TURN.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    const LEAVES: u64 = 200;
    const PER_LEAF: u64 = 512;
    const BLOCK: u64 = 4096;
    let clock = FsClock::EPOCH;
    let mut fs = MemFs::new();
    let flags = OpenFlags {
        read: true,
        write: true,
        create: true,
        truncate: false,
        append: false,
        exclusive: true,
        path_only: false,
        mode: 0o644,
    };
    let fd = fs.open(clock, "/tmp/punched", flags).unwrap();
    let before = LIVE.load(Ordering::Relaxed);
    for block in 0..LEAVES * PER_LEAF {
        fs.write_at(clock, fd, block * BLOCK, &[1]).unwrap();
    }
    for leaf in 0..LEAVES {
        let start = (leaf * PER_LEAF + 1) * BLOCK;
        fs.allocate(
            clock,
            fd,
            start,
            (PER_LEAF - 1) * BLOCK,
            FsAllocateMode::PunchHole,
            true,
        )
        .unwrap();
    }
    let held = LIVE.load(Ordering::Relaxed) - before;
    let blocks = fs.fd_metadata(fd).unwrap().blocks / 8;
    assert_eq!(blocks, LEAVES);
    assert!(
        (held as u64) < blocks * 256,
        "{blocks} surviving blocks hold {held} bytes of heap"
    );
}
