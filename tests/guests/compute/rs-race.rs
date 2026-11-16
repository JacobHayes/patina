// An atomics check-then-act with no system call in the window (the prototype's rs-race).
// Two threads start together at a barrier; each checks the balance with an atomic load, then
// withdraws with an atomic subtract. Each step is atomic; the pair is not. Exit 1 and
// "DOUBLE-SPEND" if both withdrew.
use patina_dst as _;
use std::sync::atomic::{AtomicI64, Ordering::SeqCst};
use std::sync::{Arc, Barrier};
use std::thread;

static BALANCE: AtomicI64 = AtomicI64::new(100);
static WITHDRAWN: AtomicI64 = AtomicI64::new(0);

fn withdraw(start: Arc<Barrier>) {
    start.wait();
    if BALANCE.load(SeqCst) >= 100 {
        BALANCE.fetch_sub(100, SeqCst);
        WITHDRAWN.fetch_add(100, SeqCst);
    }
}

fn main() {
    let start = Arc::new(Barrier::new(2));
    let t: Vec<_> = (0..2)
        .map(|_| {
            let s = start.clone();
            thread::spawn(move || withdraw(s))
        })
        .collect();
    for h in t {
        h.join().unwrap();
    }
    let w = WITHDRAWN.load(SeqCst);
    let verdict = if w > 100 { "DOUBLE-SPEND" } else { "ok" };
    println!("balance={} withdrawn={w} {verdict}", BALANCE.load(SeqCst));
    std::process::exit((w > 100) as i32);
}
