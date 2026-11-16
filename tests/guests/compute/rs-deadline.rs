// A deadline inside code that makes no system call: a thread sleeps 50 ms, then sets a flag;
// the main thread computes until it sees the flag, then prints how long it ran (`Instant`,
// virtual time under Patina) and exits 0 if that is 50 to 60 ms, else 1. Without compute
// points nothing switches back to the sleeper while the main thread computes.
use patina_dst as _;
use std::hint::black_box;
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::time::{Duration, Instant};

static DONE: AtomicBool = AtomicBool::new(false);

fn main() {
    let t0 = Instant::now();
    std::thread::spawn(|| {
        std::thread::sleep(Duration::from_millis(50));
        DONE.store(true, Relaxed);
    });
    let (mut x, mut rounds) = (1u64, 0u64);
    while !DONE.load(Relaxed) {
        for i in 0..64 {
            x = black_box(x.wrapping_mul(6364136223846793005).wrapping_add(i));
        }
        rounds += 1;
    }
    let ms = t0.elapsed().as_secs_f64() * 1e3;
    println!("deadline after {ms:.3} ms, {rounds} rounds (x={})", x & 0xff);
    std::process::exit(if (50.0..=60.0).contains(&ms) { 0 } else { 1 });
}
