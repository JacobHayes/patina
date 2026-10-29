//! A sparse file costs what it has written, not its length: the heap a 100 GiB
//! file with a few KiB written holds, measured by a counting allocator (this
//! test binary's own, so it counts only this test).

use std::alloc::{GlobalAlloc, Layout, System};
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

#[test]
fn a_100_gib_sparse_file_with_a_few_kib_written_costs_a_few_kib() {
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
