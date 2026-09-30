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

fn compute() {
    let mut value = 1u64;
    for _ in 0..200_000_000 {
        value = std::hint::black_box(value.wrapping_mul(6364136223846793005).wrapping_add(1));
    }
    assert_ne!(value, 1);
}

fn main() {
    let mode = std::env::args().nth(1).unwrap();
    match mode.as_str() {
        "starved" | "allocator-held" => {
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
            ALLOCATOR_HELD.store(mode == "allocator-held", Ordering::Release);
            started.store(true, Ordering::Release);
            while !done.load(Ordering::Acquire) {
                std::hint::spin_loop();
            }
            ALLOCATOR_HELD.store(false, Ordering::Release);
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
        "single" => compute(),
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
        _ => panic!("expected starved, worker-starved, allocator-held, finite, single, or parked"),
    }
    println!("COMPUTE_RESULT completed=true");
}
