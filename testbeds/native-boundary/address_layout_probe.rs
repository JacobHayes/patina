//! Prints where the guest's memory lives — its code, the main and a worker
//! thread's stacks, a thread-local, small and large heap blocks, an anonymous
//! mapping — plus an order that only the addresses decide. Then it churns:
//! boundary operations the runtime records, beside guest allocations that
//! live and die, and prints the heap blocks and mappings it gets after. Under
//! Patina every line is a function of the seed: identical across seeded runs,
//! recordings and replay.
//!
//! `deep-stack` (Linux) first raises the soft stack limit to 16 MiB and
//! recurses through 11 MiB of main stack, past the 8 MiB a process starts
//! with, then reports the same layout. `no-churn` reports the first layout
//! and stops, for a run that only needs some output the layout decides.

use std::collections::BTreeMap;
use std::ffi::c_void;
use std::hash::{DefaultHasher, Hash, Hasher};

unsafe extern "C" {
    fn mmap(addr: *mut c_void, len: usize, prot: i32, flags: i32, fd: i32, off: i64)
    -> *mut c_void;
}

const PROT_READ: i32 = 1;
const PROT_WRITE: i32 = 2;
const MAP_PRIVATE: i32 = 2;
#[cfg(target_os = "linux")]
const MAP_ANONYMOUS: i32 = 0x20;
#[cfg(target_os = "macos")]
const MAP_ANONYMOUS: i32 = 0x1000;

thread_local! {
    static LOCAL: u64 = const { 7 };
}

/// Raise the soft stack limit to 16 MiB, then use 11 MiB of the main stack.
#[cfg(target_os = "linux")]
fn deep_stack() {
    unsafe extern "C" {
        fn getrlimit(resource: i32, limit: *mut [u64; 2]) -> i32;
        fn setrlimit(resource: i32, limit: *const [u64; 2]) -> i32;
    }
    const RLIMIT_STACK: i32 = 3;
    const FRAME: usize = 64 << 10;

    #[inline(never)]
    fn descend(depth: usize) {
        let mut frame = [0u8; FRAME];
        std::hint::black_box(&mut frame);
        if depth > 0 {
            descend(depth - 1);
        }
    }

    let mut limit = [0u64; 2];
    // SAFETY: `limit` is a writable `struct rlimit`.
    assert_eq!(unsafe { getrlimit(RLIMIT_STACK, &mut limit) }, 0, "getrlimit");
    limit[0] = 16 << 20;
    // SAFETY: `limit` is a valid `struct rlimit`.
    assert_eq!(unsafe { setrlimit(RLIMIT_STACK, &limit) }, 0, "setrlimit");
    descend((11 << 20) / FRAME);
}

#[inline(never)]
fn stack_address() -> usize {
    let marker = 0u64;
    std::hint::black_box(&marker) as *const u64 as usize
}

fn main() {
    #[cfg(target_os = "linux")]
    if std::env::args().nth(1).as_deref() == Some("deep-stack") {
        deep_stack();
    }
    let mut regions: Vec<(&str, usize)> = vec![
        ("code", main as fn() as usize),
        ("stack", stack_address()),
        (
            "thread-stack",
            std::thread::spawn(stack_address).join().unwrap(),
        ),
        ("tls", LOCAL.with(|value| value as *const u64 as usize)),
    ];

    // Small blocks come from the allocator's arena; the large one is past
    // every allocator's mmap threshold, so it is a mapping of its own.
    let small: Vec<Box<[u8; 48]>> = (0..8).map(|_| Box::new([0; 48])).collect();
    regions.push(("heap", small[0].as_ptr() as usize));
    let large = vec![0u8; 4 << 20];
    regions.push(("heap-large", large.as_ptr() as usize));
    regions.push(("mmap", map(1 << 16)));

    for (name, address) in &regions {
        println!("{name}={address:#x}");
    }

    // Pointer-keyed ordering: the small blocks sorted by a hash of their
    // addresses. Their allocation order is fixed, so only the addresses can
    // change this line.
    let ordered: BTreeMap<u64, usize> = small
        .iter()
        .enumerate()
        .map(|(index, block)| {
            let mut hasher = DefaultHasher::new();
            (block.as_ptr() as usize).hash(&mut hasher);
            (hasher.finish(), index)
        })
        .collect();
    let order: Vec<String> = ordered.values().map(usize::to_string).collect();
    println!("pointer-order={}", order.join(","));
    if std::env::args().nth(1).as_deref() == Some("no-churn") {
        return;
    }

    churn();
    // Blocks of each size class an allocator keeps, one past the C
    // library's initial mmap threshold, and mappings of a few sizes.
    let sizes = [16, 40, 100, 250, 600, 1500, 4000, 10_000, 40_000, 200 << 10];
    let blocks: Vec<Vec<u8>> = sizes.iter().map(|size| vec![1u8; *size]).collect();
    for (size, block) in sizes.iter().zip(&blocks) {
        println!("after-churn-heap-{size}={:#x}", block.as_ptr() as usize);
    }
    for pages in [1, 16, 256] {
        println!("after-churn-mmap-{pages}={:#x}", map(pages << 12));
    }
}

/// A file written and read back, over and over, each round beside guest
/// allocations of varying sizes, some kept and most dropped: a recording's
/// trace grows with every round, and a replay holds every round's events.
fn churn() {
    let path = "address-layout-churn";
    let mut kept = Vec::new();
    for round in 0..1500usize {
        let bytes = vec![round as u8; 1 + round % 700];
        std::fs::write(path, &bytes).expect("write");
        assert_eq!(std::fs::read(path).expect("read"), bytes);
        if round % 7 == 0 {
            kept.push(vec![0u8; 1 + round % 3000]);
        }
        if round % 500 == 499 {
            println!("during-churn-mmap-{round}={:#x}", map(1 << 16));
            println!("during-churn-heap-{round}={:#x}", kept[kept.len() - 1].as_ptr() as usize);
        }
    }
    std::fs::remove_file(path).expect("remove");
    std::hint::black_box(kept);
}

/// An anonymous private mapping of `len` bytes with no address hint.
fn map(len: usize) -> usize {
    // SAFETY: an anonymous private mapping with no address hint.
    let mapping = unsafe {
        mmap(
            std::ptr::null_mut(),
            len,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(mapping as isize, -1, "mmap failed");
    mapping as usize
}
