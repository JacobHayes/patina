// An allocator that makes system calls of its own on every allocation, as a
// per-CPU arena allocator does (jemalloc, mimalloc, tcmalloc), shared by the
// package's binaries. It is both the program's `#[global_allocator]` and its
// C `malloc` family (a heap of its own, which never reuses a block), so the C
// library and the runtime's C-level allocations reach it in the middle of
// calls of the runtime's own: a new thread's TLS while the runtime creates
// the host thread (holding its state), a directory stream as `opendir` makes
// it. Every allocation asks which CPU it runs on through `syscall(SYS_getcpu)`
// (a held libc door) and, where its binary has one, the raw `getcpu`
// instruction (`crate::raw_cpu`: a trapped call). While a directory is listed
// it also reads its rusage and affinity (`getrusage`, `sched_getaffinity`:
// held libc doors that read the runtime's state, which a thread's creation
// holds, so they are asked only then) and makes a `getrusage` that fails,
// whose errno it reads. [`main`] spawns and joins threads and lists a
// directory; the C entry points' calls that answered are tallied (the C
// library and the runtime are their only callers), and the CPUs every call
// saw.
use std::alloc::{GlobalAlloc, Layout};
use std::cell::{Cell, UnsafeCell};
use std::ffi::{c_int, c_long, c_void};
use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

/// Set once `main` runs: the C library allocates long before the runtime
/// starts, and the allocator asks nothing until then.
static ARMED: AtomicBool = AtomicBool::new(false);
/// Set while `main` lists a directory: allocations also read the runtime's
/// state then.
static LISTING: AtomicBool = AtomicBool::new(false);
/// C allocations whose CPU reads answered, and whose state reads did; the
/// bitmask of CPUs every allocation saw.
static C_ASKED: AtomicU64 = AtomicU64::new(0);
static C_READ_STATE: AtomicU64 = AtomicU64::new(0);
static SEEN: AtomicU64 = AtomicU64::new(0);

thread_local! {
    /// The allocator's own calls on this thread: one the runtime answers by
    /// allocating is not asked about again.
    static ASKING: Cell<bool> = const { Cell::new(false) };
}

/// The calls an allocation makes (`from_c`: through a C entry point),
/// leaving errno as it found it. A call that answers wrongly stops the
/// program.
fn ask(from_c: bool) {
    if !ARMED.load(Ordering::Relaxed) || ASKING.with(|asking| asking.replace(true)) {
        return;
    }
    let errno = unsafe { *__errno_location() };
    let mut door: u32 = u32::MAX;
    let via_libc = unsafe { syscall(SYS_GETCPU, &mut door as *mut u32, 0usize, 0usize) };
    let raw = crate::raw_cpu().unwrap_or(i64::from(door));
    if via_libc != 0 || raw != i64::from(door) {
        unsafe { abort() };
    }
    if door < 64 {
        SEEN.fetch_or(1 << door, Ordering::Relaxed);
    }
    if from_c {
        C_ASKED.fetch_add(1, Ordering::Relaxed);
    }
    if LISTING.load(Ordering::Relaxed) {
        let mut usage = [0u64; 18];
        let rusage = unsafe { getrusage(RUSAGE_SELF, usage.as_mut_ptr().cast()) };
        let mut set = [0u64; 16];
        let affinity = unsafe { sched_getaffinity(0, size_of_val(&set), set.as_mut_ptr().cast()) };
        let refused = unsafe { getrusage(-5, usage.as_mut_ptr().cast()) };
        let refused_errno = unsafe { *__errno_location() };
        if rusage != 0 || affinity != 0 || set[0] == 0 || refused != -1 || refused_errno != EINVAL {
            unsafe { abort() };
        }
        if from_c {
            C_READ_STATE.fetch_add(1, Ordering::Relaxed);
        }
    }
    unsafe { *__errno_location() = errno };
    ASKING.with(|asking| asking.set(false));
}

/// The allocator's memory: blocks are carved from it in order and never
/// reused, so each is zeroed; a block's size is the word before it.
const HEAP_BYTES: usize = 64 << 20;
#[repr(C, align(4096))]
struct Heap(UnsafeCell<[u8; HEAP_BYTES]>);
// SAFETY: every block is carved once, by one atomic step, for one caller.
unsafe impl Sync for Heap {}
static HEAP: Heap = Heap(UnsafeCell::new([0; HEAP_BYTES]));
/// The offset no block has been carved from.
static NEXT: AtomicUsize = AtomicUsize::new(0);

/// A fresh block of `size` bytes at `align`, after asking (`from_c`: for a
/// C entry point); null when the heap is spent.
fn carve(size: usize, align: usize, from_c: bool) -> *mut u8 {
    ask(from_c);
    let base = HEAP.0.get() as usize;
    let align = align.max(16);
    let mut start = NEXT.load(Ordering::Relaxed);
    loop {
        let block = (base + start + 16).next_multiple_of(align);
        let end = block + size - base;
        if end > HEAP_BYTES {
            return null_mut();
        }
        match NEXT.compare_exchange_weak(start, end, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => {
                unsafe { ((block - 8) as *mut usize).write(size) };
                return block as *mut u8;
            }
            Err(now) => start = now,
        }
    }
}

/// The size `block` was carved with.
unsafe fn carved(block: *mut c_void) -> usize {
    unsafe { ((block as usize - 8) as *const usize).read() }
}

struct PerCpu;

unsafe impl GlobalAlloc for PerCpu {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        carve(layout.size(), layout.align(), false)
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

#[global_allocator]
static GLOBAL: PerCpu = PerCpu;

// The C allocator's entry points: the C library's, and the runtime's C-level
// allocations, come from the same heap.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn malloc(size: usize) -> *mut c_void {
    carve(size, 16, true).cast()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn calloc(count: usize, size: usize) -> *mut c_void {
    match count.checked_mul(size) {
        Some(bytes) => carve(bytes, 16, true).cast(),
        None => null_mut(),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn realloc(ptr: *mut c_void, size: usize) -> *mut c_void {
    let grown = carve(size, 16, true);
    if !ptr.is_null() && !grown.is_null() {
        unsafe { std::ptr::copy_nonoverlapping(ptr.cast(), grown, carved(ptr).min(size)) };
    }
    grown.cast()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn posix_memalign(out: *mut *mut c_void, align: usize, size: usize) -> c_int {
    let block = carve(size, align, true);
    if block.is_null() {
        return ENOMEM;
    }
    unsafe { out.write(block.cast()) };
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn aligned_alloc(align: usize, size: usize) -> *mut c_void {
    carve(size, align, true).cast()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memalign(align: usize, size: usize) -> *mut c_void {
    carve(size, align, true).cast()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn malloc_usable_size(ptr: *mut c_void) -> usize {
    if ptr.is_null() {
        0
    } else {
        unsafe { carved(ptr) }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn free(_ptr: *mut c_void) {}

/// Spawn and join threads, list a directory, and report the tallies.
pub fn main() {
    ARMED.store(true, Ordering::Relaxed);
    let threads: Vec<_> = (0..6)
        .map(|n| std::thread::spawn(move || vec![n; 64 + n].len()))
        .collect();
    let total: usize = threads.into_iter().map(|t| t.join().unwrap()).sum();
    LISTING.store(true, Ordering::Relaxed);
    let entries = std::fs::read_dir("/").unwrap().count();
    LISTING.store(false, Ordering::Relaxed);
    println!(
        "NATIVE_SYSCALL_ALLOC_RESULT total={total} asked={} cpus_seen={} read_state={} listed={}",
        u64::from(C_ASKED.load(Ordering::Relaxed) > 0),
        SEEN.load(Ordering::Relaxed).count_ones(),
        u64::from(C_READ_STATE.load(Ordering::Relaxed) > 0),
        u64::from(entries > 0),
    );
}

#[cfg(target_arch = "x86_64")]
const SYS_GETCPU: c_long = 309;
#[cfg(target_arch = "aarch64")]
const SYS_GETCPU: c_long = 168;
const RUSAGE_SELF: c_int = 0;
const ENOMEM: c_int = 12;
const EINVAL: c_int = 22;

unsafe extern "C" {
    fn syscall(number: c_long, ...) -> c_long;
    fn getrusage(who: c_int, usage: *mut c_void) -> c_int;
    fn sched_getaffinity(pid: c_int, size: usize, set: *mut c_void) -> c_int;
    fn abort() -> !;
    fn __errno_location() -> *mut c_int;
}
