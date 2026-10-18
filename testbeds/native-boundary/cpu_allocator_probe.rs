// A global allocator that asks which CPU it runs on, as a per-CPU arena
// allocator (jemalloc, mimalloc, tcmalloc) does on every allocation. The
// runtime allocates through it while it holds its own state (spawning a
// thread, say), so each CPU read must answer without the runtime's lock. Each
// allocation reads the CPU (Linux: glibc's `sched_getcpu`; macOS: `sysctl
// hw.ncpu`) and the online count, and the reads are tallied; threads are
// spawned and joined so the runtime allocates under its lock. The allocator
// starts asking in a constructor that runs before Patina's startup
// constructor, so its first read lands in that startup's own allocations
// (capturing the control plane), before the runtime exists.
use std::alloc::{GlobalAlloc, Layout, System};
use std::ffi::{c_int, c_long};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

struct PerCpu;

/// Set by [`arm`]: until then the allocator reads nothing.
static ARMED: AtomicBool = AtomicBool::new(false);

extern "C" fn arm() {
    ARMED.store(true, Ordering::Relaxed);
}

// Before Patina's startup constructor (`.init_array.00101`).
#[cfg(target_os = "linux")]
#[used]
#[unsafe(link_section = ".init_array.00099")]
static ARM: extern "C" fn() = arm;
#[cfg(target_os = "macos")]
#[used]
#[unsafe(link_section = "__DATA,__mod_init_func,mod_init_funcs")]
static ARM: extern "C" fn() = arm;

/// Allocations that read the CPU, and the bitmask of CPUs they saw.
static READS: AtomicU64 = AtomicU64::new(0);
static SEEN: AtomicU64 = AtomicU64::new(0);
/// The largest online count an allocation read.
static ONLINE: AtomicU32 = AtomicU32::new(0);

unsafe impl GlobalAlloc for PerCpu {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if !ARMED.load(Ordering::Relaxed) {
            return unsafe { System.alloc(layout) };
        }
        let cpu = platform::cpu();
        if cpu < 64 {
            SEEN.fetch_or(1 << cpu, Ordering::Relaxed);
        }
        let online = unsafe { sysconf(SC_NPROCESSORS_ONLN) };
        ONLINE.fetch_max(online as u32, Ordering::Relaxed);
        READS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: PerCpu = PerCpu;

fn main() {
    let threads: Vec<_> = (0..6)
        .map(|n| std::thread::spawn(move || vec![n; 64 + n].len()))
        .collect();
    let total: usize = threads.into_iter().map(|t| t.join().unwrap()).sum();
    println!(
        "NATIVE_CPU_ALLOC_RESULT total={total} read={} cpus_seen={} online={}",
        u64::from(READS.load(Ordering::Relaxed) > 0),
        SEEN.load(Ordering::Relaxed).count_ones(),
        ONLINE.load(Ordering::Relaxed)
    );
}

#[cfg(target_os = "linux")]
mod platform {
    use super::*;

    /// The CPU through glibc's `sched_getcpu`.
    pub fn cpu() -> u32 {
        let cpu = unsafe { sched_getcpu() };
        if cpu < 0 {
            std::process::abort();
        }
        cpu as u32
    }

    unsafe extern "C" {
        fn sched_getcpu() -> c_int;
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use super::*;
    use std::ffi::c_void;

    /// macOS has no per-thread CPU query; the sysctl count stands in for it.
    pub fn cpu() -> u32 {
        let mut value: c_int = -1;
        let mut len = std::mem::size_of::<c_int>();
        let r = unsafe {
            sysctlbyname(
                c"hw.ncpu".as_ptr(),
                &mut value as *mut c_int as *mut c_void,
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if r != 0 || value < 1 {
            std::process::abort();
        }
        0
    }

    unsafe extern "C" {
        fn sysctlbyname(
            name: *const std::ffi::c_char,
            oldp: *mut c_void,
            oldlenp: *mut usize,
            newp: *mut c_void,
            newlen: usize,
        ) -> c_int;
    }
}

#[cfg(target_os = "linux")]
const SC_NPROCESSORS_ONLN: c_int = 84;
#[cfg(target_os = "macos")]
const SC_NPROCESSORS_ONLN: c_int = 58;

unsafe extern "C" {
    fn sysconf(name: c_int) -> c_long;
}
