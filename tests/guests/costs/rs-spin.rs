// Spin-wait patterns in Rust std.
//   rs-spin spin [ITERS]    a hand-written spin lock (AtomicBool, spin_loop hint, never
//                           yields: the `spin` crate's shape) held across a system call
//   rs-spin mutex [ITERS]   std::sync::Mutex (bounded spin, then futex) around the same call
// Two threads, ITERS (default 2000) rounds each; exit 0 if the counter is right.
use std::hint::spin_loop;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::*};
use std::sync::{Arc, Mutex};

static LOCK: AtomicBool = AtomicBool::new(false);
static COUNT: AtomicU64 = AtomicU64::new(0);

fn call() -> u64 {
    std::process::id() as u64 // getpid: a system call
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).cloned().unwrap_or_default();
    let iters: u64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(2000);
    let m = Arc::new(Mutex::new(0u64));
    let hs: Vec<_> = (0..2)
        .map(|_| {
            let mode = mode.clone();
            let m = m.clone();
            std::thread::spawn(move || {
                for _ in 0..iters {
                    match mode.as_str() {
                        "spin" => {
                            while LOCK.compare_exchange_weak(false, true, Acquire, Relaxed).is_err() {
                                while LOCK.load(Relaxed) {
                                    spin_loop();
                                }
                            }
                            let c = COUNT.load(Relaxed);
                            COUNT.store(c + (call() > 0) as u64, Relaxed);
                            LOCK.store(false, Release);
                        }
                        "mutex" => {
                            let mut g = m.lock().unwrap();
                            *g += (call() > 0) as u64;
                        }
                        _ => std::process::exit(2),
                    }
                }
            })
        })
        .collect();
    for h in hs {
        h.join().unwrap();
    }
    let total = if mode == "spin" { COUNT.load(Relaxed) } else { *m.lock().unwrap() };
    println!("{} counter={}", mode, total);
    std::process::exit(if total == 2 * iters { 0 } else { 1 });
}
