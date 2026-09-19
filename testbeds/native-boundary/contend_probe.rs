// The main thread holds a std::sync::Mutex ACROSS a boundary op (a virtual-clock
// sleep) while a worker contends for the same lock. If the mutex were a real
// kernel lock, the worker would block in the kernel while parked with the baton
// and deadlock. Because the mutex is virtual (routed through the deterministic
// scheduler), it completes deterministically and no update is lost: final is
// always 111 (10 + 100 + 1). No explicit Patina init/shutdown: the packaged
// startup path installs and finalizes the runtime.
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

fn main() {
    let state = Arc::new((Mutex::new(0u64), Condvar::new()));
    let worker_state = Arc::clone(&state);
    let worker = thread::spawn(move || {
        let (lock, condvar) = &*worker_state;
        let mut guard = lock.lock().unwrap();
        *guard += 1;
        condvar.notify_all();
        *guard
    });

    {
        let (lock, _) = &*state;
        let mut guard = lock.lock().unwrap();
        *guard += 10;
        thread::sleep(Duration::from_millis(5));
        *guard += 100;
    }

    let worker_result = worker.join().unwrap();
    let (lock, _) = &*state;
    let final_value = *lock.lock().unwrap();
    println!("NATIVE_CONTEND_RESULT worker={worker_result} final={final_value}");
}
