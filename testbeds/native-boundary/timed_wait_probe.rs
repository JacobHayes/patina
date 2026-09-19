use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

fn main() {
    let signal_delay = Duration::from_millis(25);
    let signal_deadline = Duration::from_millis(100);
    let signalled = Arc::new((Mutex::new(false), Condvar::new()));
    let worker_signalled = Arc::clone(&signalled);
    let signal_started = Instant::now();
    let worker = thread::spawn(move || {
        thread::sleep(signal_delay);
        let (lock, condvar) = &*worker_signalled;
        let mut guard = lock.lock().unwrap();
        *guard = true;
        condvar.notify_one();
    });

    let (lock, condvar) = &*signalled;
    let mut guard = lock.lock().unwrap();
    let mut timed_out = false;
    while !*guard {
        let (next_guard, result) = condvar.wait_timeout(guard, signal_deadline).unwrap();
        guard = next_guard;
        if result.timed_out() {
            timed_out = true;
            break;
        }
    }
    let signal_elapsed = signal_started.elapsed();
    if timed_out || !*guard {
        eprintln!("signalled condvar wait timed out unexpectedly");
        std::process::exit(10);
    }
    if signal_elapsed != signal_delay {
        eprintln!(
            "signalled condvar elapsed {:?}, expected {:?}",
            signal_elapsed, signal_delay
        );
        std::process::exit(11);
    }
    drop(guard);
    worker.join().unwrap();

    let timeout = Duration::from_millis(100);
    let timeout_pair = (Mutex::new(false), Condvar::new());
    let (lock, condvar) = &timeout_pair;
    let guard = lock.lock().unwrap();
    let timeout_started = Instant::now();
    let (_guard, result) = condvar.wait_timeout(guard, timeout).unwrap();
    let timeout_elapsed = timeout_started.elapsed();
    if !result.timed_out() {
        eprintln!("unsignalled condvar wait did not time out");
        std::process::exit(12);
    }
    if timeout_elapsed != timeout {
        eprintln!(
            "timeout condvar elapsed {:?}, expected {:?}",
            timeout_elapsed, timeout
        );
        std::process::exit(13);
    }

    println!(
        "NATIVE_TIMED_WAIT_RESULT signalled_elapsed_ns={} timeout_elapsed_ns={}",
        signal_elapsed.as_nanos(),
        timeout_elapsed.as_nanos()
    );
}
