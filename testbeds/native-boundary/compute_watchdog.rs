//! Calls are deliberately absent from the compute regions. The protocol uses
//! atomics/condvars, never host sleeps or timing to arrange task states.
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};

// Class detector for off-baton finalization: the stopped thread may own the
// guest allocator. A watchdog that clones/serializes via Vec or formats via
// String then deadlocks instead of exporting a trace.
struct LockedAllocator;
static ALLOCATOR_HELD: AtomicBool = AtomicBool::new(false);
unsafe impl std::alloc::GlobalAlloc for LockedAllocator {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        while ALLOCATOR_HELD.load(Ordering::Acquire) {
            std::hint::spin_loop();
        }
        unsafe { std::alloc::System.alloc(layout) }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: std::alloc::Layout) {
        while ALLOCATOR_HELD.load(Ordering::Acquire) {
            std::hint::spin_loop();
        }
        unsafe { std::alloc::System.dealloc(pointer, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: LockedAllocator = LockedAllocator;

unsafe extern "C" {
    fn signal(sig: i32, handler: extern "C" fn(i32)) -> usize;
    fn raise(sig: i32) -> i32;
    fn printf(format: *const std::ffi::c_char, ...) -> i32;
    fn patina_custom_op_begin(
        label: *const u8,
        label_len: usize,
        key: *const u8,
        key_len: usize,
        fault_eligible: i32,
        out_len: *mut usize,
    ) -> i32;
    fn patina_custom_op_record(result: *const u8, result_len: usize) -> i32;
    fn patina_custom_op_replay_result(out: *mut u8, out_cap: usize) -> isize;
}

static PROBE_HANDLER: AtomicBool = AtomicBool::new(true);
static HANDLER_SEEN: AtomicBool = AtomicBool::new(false);
static ALLOCATING_HANDLER: AtomicBool = AtomicBool::new(false);
extern "C" fn hostile_abort_handler(_: i32) {
    if PROBE_HANDLER.swap(false, Ordering::SeqCst) {
        HANDLER_SEEN.store(true, Ordering::SeqCst);
        return;
    }
    if ALLOCATING_HANDLER.load(Ordering::Acquire) {
        let layout = std::alloc::Layout::new::<u64>();
        // Intentionally hostile/non-signal-safe: entering this allocator while
        // the spinning task owns it deadlocks. A private stop must not enter it.
        std::hint::black_box(unsafe { std::alloc::alloc(layout) });
    }
    loop {
        std::hint::spin_loop();
    }
}
fn install_hostile_abort_handler(allocating: bool) {
    ALLOCATING_HANDLER.store(allocating, Ordering::Release);
    assert_ne!(unsafe { signal(6, hostile_abort_handler) }, usize::MAX);
    // Non-vacuity: registration must actually deliver before the fatal phase.
    assert_eq!(unsafe { raise(6) }, 0);
    assert!(HANDLER_SEEN.load(Ordering::SeqCst));
}

fn custom_op(perform: impl FnOnce() -> Vec<u8>) {
    let label = b"watchdog.perform";
    let mut length = 0;
    match unsafe {
        patina_custom_op_begin(
            label.as_ptr(),
            label.len(),
            std::ptr::null(),
            0,
            0,
            &mut length,
        )
    } {
        0 => {
            let result = perform();
            assert_eq!(
                unsafe { patina_custom_op_record(result.as_ptr(), result.len()) },
                0
            );
        }
        1 => {
            let mut result = vec![0; length];
            assert_eq!(
                unsafe { patina_custom_op_replay_result(result.as_mut_ptr(), result.len()) },
                length as isize
            );
        }
        other => panic!("custom-op begin refused: {other}"),
    }
}

fn compute() {
    let mut value = 1u64;
    for _ in 0..200_000_000 {
        value = std::hint::black_box(value.wrapping_mul(6364136223846793005).wrapping_add(1));
    }
    assert_ne!(value, 1);
}

/// Spin, call-free, with the stack pointer at the top of a 2 KiB stack just
/// above an inaccessible page (a runtime's small thread stack): the
/// watchdog's program-counter sample must not need room on it.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn spin_on_a_small_stack() -> ! {
    unsafe extern "C" {
        fn mmap(
            address: *mut u8,
            length: usize,
            protection: i32,
            flags: i32,
            fd: i32,
            offset: i64,
        ) -> *mut u8;
        fn mprotect(address: *mut u8, length: usize, protection: i32) -> i32;
    }
    // PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS.
    let base = unsafe { mmap(std::ptr::null_mut(), 8192, 3, 0x22, -1, 0) };
    assert_ne!(base as isize, -1);
    assert_eq!(unsafe { mprotect(base, 4096, 0) }, 0);
    let top = unsafe { base.add(4096 + 2048) };
    unsafe {
        std::arch::asm!(
            "mov rsp, {top}",
            "2:",
            "pause",
            "jmp 2b",
            top = in(reg) top,
            options(noreturn)
        )
    }
}

fn main() {
    let mode = std::env::args().nth(1).unwrap();
    match mode.as_str() {
        "starved" | "allocator-held" | "custom-spin" | "handler-loop" | "handler-alloc"
        | "overflow-held" | "payload-held" | "sync-buffer" => {
            if mode == "handler-loop" || mode == "handler-alloc" {
                install_hostile_abort_handler(mode == "handler-alloc");
            }
            if mode == "overflow-held" {
                // 200 MiB of bytes becomes >256 MiB of base64: abandon the
                // real recorder budget, in modest chunks to bound peak memory.
                // Before a runnable peer exists, and before holding the allocator.
                for _ in 0..25 {
                    custom_op(|| vec![255; 8 * 1024 * 1024]);
                }
            }
            if mode == "payload-held" {
                // Exercise byte-field serialization too, including buffer and
                // base64 padding boundaries, not just scalar scheduler events.
                custom_op(|| (0..4097).map(|n| (n % 256) as u8).collect());
            }
            let started = Arc::new(AtomicBool::new(false));
            let done = Arc::new(AtomicBool::new(false));
            let worker = {
                let started = Arc::clone(&started);
                let done = Arc::clone(&done);
                std::thread::spawn(move || {
                    while !started.load(Ordering::Acquire) {
                        std::thread::yield_now();
                    }
                    done.store(true, Ordering::Release);
                })
            };
            eprint!("COMPUTE_PARTIAL_STDERR");
            let perform = || {
                ALLOCATOR_HELD.store(
                    matches!(
                        mode.as_str(),
                        "allocator-held" | "handler-alloc" | "overflow-held" | "payload-held"
                    ),
                    Ordering::Release,
                );
                started.store(true, Ordering::Release);
                while !done.load(Ordering::Acquire) {
                    std::hint::spin_loop();
                }
                ALLOCATOR_HELD.store(false, Ordering::Release);
                Vec::new()
            };
            if mode == "sync-buffer" {
                // No newline/flush: only a synchronous refusal may salvage this
                // C stream. Replay reaches the custom-op admission guard.
                assert!(unsafe { printf(c"WATCHDOG_BUFFERED_C_STDOUT".as_ptr()) } > 0);
            }
            if mode == "custom-spin" || mode == "sync-buffer" {
                custom_op(perform);
            } else {
                perform();
            }
            worker.join().unwrap();
        }
        "worker-starved" => {
            let started = Arc::new(AtomicBool::new(false));
            let done = Arc::new(AtomicBool::new(false));
            let worker = {
                let started = Arc::clone(&started);
                let done = Arc::clone(&done);
                std::thread::spawn(move || {
                    started.store(true, Ordering::Release);
                    while !done.load(Ordering::Acquire) {
                        std::hint::spin_loop();
                    }
                })
            };
            while !started.load(Ordering::Acquire) {
                std::thread::yield_now();
            }
            done.store(true, Ordering::Release);
            worker.join().unwrap();
        }
        "finite" => {
            let done = Arc::new(AtomicBool::new(false));
            let worker = {
                let done = Arc::clone(&done);
                std::thread::spawn(move || {
                    while !done.load(Ordering::Acquire) {
                        std::thread::yield_now();
                    }
                })
            };
            // The peer remains runnable throughout this call-free finite region.
            compute();
            done.store(true, Ordering::Release);
            worker.join().unwrap();
        }
        "single" => {
            // Arm the real observer before testing its lone-task exemption.
            std::thread::spawn(|| {}).join().unwrap();
            compute();
        }
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        "small-stack" => {
            // A runnable peer the spin starves.
            let _peer = std::thread::spawn(|| {
                loop {
                    std::thread::yield_now();
                }
            });
            std::thread::yield_now();
            spin_on_a_small_stack();
        }
        "parked" => {
            let state = Arc::new((Mutex::new((false, false)), Condvar::new()));
            let worker = {
                let state = Arc::clone(&state);
                std::thread::spawn(move || {
                    let (lock, cond) = &*state;
                    let mut guard = lock.lock().unwrap();
                    guard.0 = true;
                    cond.notify_one();
                    while !guard.1 {
                        guard = cond.wait(guard).unwrap();
                    }
                })
            };
            let (lock, cond) = &*state;
            let mut guard = lock.lock().unwrap();
            while !guard.0 {
                guard = cond.wait(guard).unwrap();
            }
            // Holding the lock proves the worker released it into cond.wait.
            drop(guard);
            compute();
            lock.lock().unwrap().1 = true;
            cond.notify_one();
            worker.join().unwrap();
        }
        _ => panic!(
            "expected starved, worker-starved, allocator-held, custom-spin, handler-loop, handler-alloc, overflow-held, payload-held, sync-buffer, finite, single, or parked"
        ),
    }
    println!("COMPUTE_RESULT completed=true");
}
