// os_unfair_lock (parking_lot_core's Darwin word lock) is interposed: the bare
// u32 word — with NO init call — routes through the deterministic scheduler and
// the shared mutex table, which lazily registers it on first use. Three threads
// contend on ONE os_unfair_lock guarding a shared vector across a scheduling
// point, so the others park on it; the acquisition order is chosen by
// DetScheduler and is byte-identical per seed. trylock acquires an unheld lock
// and reports contention on a held one.
use std::cell::UnsafeCell;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[repr(C)]
struct Shared {
    word: UnsafeCell<u32>,
    order: UnsafeCell<Vec<u32>>,
}
unsafe impl Sync for Shared {}

unsafe extern "C" {
    fn os_unfair_lock_lock(lock: *mut u32);
    fn os_unfair_lock_trylock(lock: *mut u32) -> bool;
    fn os_unfair_lock_unlock(lock: *mut u32);
}

fn main() {
    let shared = Arc::new(Shared {
        word: UnsafeCell::new(0),
        order: UnsafeCell::new(Vec::new()),
    });
    unsafe {
        let word = shared.word.get();
        assert!(
            os_unfair_lock_trylock(word),
            "trylock of an unheld lock must acquire"
        );
        assert!(
            !os_unfair_lock_trylock(word),
            "trylock of a held lock must fail"
        );
        os_unfair_lock_unlock(word);
    }
    let mut handles = Vec::new();
    for id in 0..3u32 {
        let shared = Arc::clone(&shared);
        handles.push(thread::spawn(move || {
            for _ in 0..3 {
                unsafe {
                    let word = shared.word.get();
                    os_unfair_lock_lock(word);
                    // Guarded by the lock, so serialized under the scheduler.
                    (*shared.order.get()).push(id);
                    thread::sleep(Duration::from_nanos(1));
                    os_unfair_lock_unlock(word);
                }
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    unsafe {
        println!("OS_UNFAIR_LOCK_RESULT order={:?}", *shared.order.get());
    }
}
