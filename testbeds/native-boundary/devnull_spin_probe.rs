//! A thread that writes to /dev/null until a sleeping peer wakes and stops
//! it: the writes are its only calls, so they must yield and move the clock.
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

fn main() {
    let stop = Arc::new(AtomicBool::new(false));
    let peer = {
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(5));
            stop.store(true, Ordering::SeqCst);
        })
    };
    let mut null = OpenOptions::new()
        .write(true)
        .open("/dev/null")
        .expect("open /dev/null");
    while !stop.load(Ordering::SeqCst) {
        null.write_all(b"x").expect("write /dev/null");
    }
    peer.join().expect("join the sleeper");
    println!("NATIVE_DEVNULL_SPIN stopped=true");
}
