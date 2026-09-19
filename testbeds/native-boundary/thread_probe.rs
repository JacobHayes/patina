// Ordinary Rust threads, Mutex, and Condvar executed under Patina's
// deterministic scheduler through the interposed pthread layer. Three workers
// each increment a shared counter under the mutex and append their id to a
// shared log; the final count is schedule-invariant but the acquisition order
// is interleaving-sensitive, so it is stable per seed and varies across seeds.
use std::sync::{Arc, Condvar, Mutex};
use std::thread;

struct Shared {
    counter: u64,
    order: Vec<u8>,
    done: u32,
}

fn main() {
    let workers: u8 = 3;
    let iterations: u64 = 4;
    let shared = Arc::new((
        Mutex::new(Shared {
            counter: 0,
            order: Vec::new(),
            done: 0,
        }),
        Condvar::new(),
    ));
    let mut handles = Vec::new();
    for id in 0..workers {
        let shared = Arc::clone(&shared);
        handles.push(thread::spawn(move || {
            let (lock, cond) = &*shared;
            for _ in 0..iterations {
                let mut guard = lock.lock().unwrap();
                guard.counter += 1;
                guard.order.push(id);
            }
            let mut guard = lock.lock().unwrap();
            guard.done += 1;
            cond.notify_all();
        }));
    }
    {
        let (lock, cond) = &*shared;
        let mut guard = lock.lock().unwrap();
        while guard.done < u32::from(workers) {
            guard = cond.wait(guard).unwrap();
        }
    }
    for handle in handles {
        handle.join().unwrap();
    }
    let (lock, _cond) = &*shared;
    let guard = lock.lock().unwrap();
    let counter = guard.counter;
    let order: String = guard.order.iter().map(|id| char::from(b'0' + id)).collect();
    drop(guard);
    println!("NATIVE_THREAD_RESULT counter={counter} order={order}");
}
