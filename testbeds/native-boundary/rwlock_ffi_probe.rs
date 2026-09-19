use std::cell::UnsafeCell;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

// std's own RwLock never lowers to pthread_rwlock_* on the supported
// toolchains, so exercise the shim's deterministic pthread_rwlock interposers
// directly through FFI. Three writer threads each hold the write lock across a
// scheduling point, so the others park on it; the acquisition order is chosen by
// DetScheduler (writer-preferring, FIFO), byte-identical per seed.
#[repr(C, align(16))]
struct RawRwLock(UnsafeCell<[u8; 200]>);
unsafe impl Sync for RawRwLock {}

unsafe extern "C" {
    fn pthread_rwlock_init(lock: *mut u8, attr: *const u8) -> i32;
    fn pthread_rwlock_wrlock(lock: *mut u8) -> i32;
    fn pthread_rwlock_unlock(lock: *mut u8) -> i32;
}

static LOCK: RawRwLock = RawRwLock(UnsafeCell::new([0u8; 200]));

fn main() {
    unsafe {
        assert_eq!(
            pthread_rwlock_init(LOCK.0.get() as *mut u8, std::ptr::null()),
            0
        );
    }
    let log = Arc::new(Mutex::new(Vec::<u32>::new()));
    let mut handles = Vec::new();
    for id in 0..3u32 {
        let log = Arc::clone(&log);
        handles.push(thread::spawn(move || {
            for _ in 0..3 {
                unsafe {
                    assert_eq!(pthread_rwlock_wrlock(LOCK.0.get() as *mut u8), 0);
                }
                log.lock().unwrap().push(id);
                thread::sleep(Duration::from_nanos(1));
                unsafe {
                    assert_eq!(pthread_rwlock_unlock(LOCK.0.get() as *mut u8), 0);
                }
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    println!("NATIVE_RWLOCK_FFI_RESULT order={:?}", *log.lock().unwrap());
}
