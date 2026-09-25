// A default (normal) pthread mutex relocked by its owner before the process
// has created a thread: glibc's relock never returns, so the only process
// state is a self-deadlock. Under patina the run must end as the scheduler's
// named deadlock (the main task parked on the mutex), never as a shim fault
// about a task the scheduler does not know.
#[repr(C, align(8))]
struct Mutex([u8; 40]);

unsafe extern "C" {
    fn pthread_mutex_init(mutex: *mut Mutex, attr: *const u8) -> i32;
    fn pthread_mutex_lock(mutex: *mut Mutex) -> i32;
}

fn main() {
    let mutex: &'static mut Mutex = Box::leak(Box::new(Mutex([0; 40])));
    unsafe {
        assert_eq!(pthread_mutex_init(mutex, std::ptr::null()), 0);
        assert_eq!(pthread_mutex_lock(mutex), 0);
        println!("MUTEX_RELOCK_LOCKED");
        pthread_mutex_lock(mutex);
    }
    println!("MUTEX_RELOCK_RETURNED");
}
