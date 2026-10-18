//! Prints where the guest's memory lives — its code, the main and a worker
//! thread's stacks, a thread-local, small and large heap blocks, an anonymous
//! mapping — plus an order that only the addresses decide. Under Patina every
//! line is a function of the seed: identical across seeded runs and replay.
//!
//! `deep-stack` (Linux) first raises the soft stack limit to 16 MiB and
//! recurses through 11 MiB of main stack, past the 8 MiB a process starts
//! with, then reports the same layout.

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
    // SAFETY: an anonymous private mapping with no address hint.
    let mapping = unsafe {
        mmap(
            std::ptr::null_mut(),
            1 << 16,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(mapping as isize, -1, "mmap failed");
    regions.push(("mmap", mapping as usize));

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
}
