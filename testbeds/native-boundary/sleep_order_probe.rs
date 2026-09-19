use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

struct State {
    order: Vec<char>,
    a_elapsed_ns: Option<u128>,
    work: u64,
}

fn main() {
    let state = Arc::new(Mutex::new(State {
        order: Vec::new(),
        a_elapsed_ns: None,
        work: 0,
    }));

    let a_state = Arc::clone(&state);
    let thread_a = thread::spawn(move || {
        let started = Instant::now();
        thread::sleep(Duration::from_millis(100));
        let elapsed = started.elapsed();
        if elapsed != Duration::from_millis(100) {
            eprintln!("thread A elapsed {:?}, expected 100ms", elapsed);
            std::process::exit(20);
        }
        println!("NATIVE_SLEEP_ORDER_A elapsed_ns={}", elapsed.as_nanos());
        let mut guard = a_state.lock().unwrap();
        guard.a_elapsed_ns = Some(elapsed.as_nanos());
        guard.order.push('A');
    });

    let b_state = Arc::clone(&state);
    let thread_b = thread::spawn(move || {
        for value in 0..100u64 {
            let mut guard = b_state.lock().unwrap();
            guard.work += value;
        }
        let work = b_state.lock().unwrap().work;
        println!("NATIVE_SLEEP_ORDER_B done work={work}");
        let mut guard = b_state.lock().unwrap();
        guard.order.push('B');
    });

    thread_a.join().unwrap();
    thread_b.join().unwrap();

    let guard = state.lock().unwrap();
    let order: String = guard.order.iter().collect();
    let a_elapsed_ns = guard.a_elapsed_ns.unwrap();
    println!(
        "NATIVE_SLEEP_ORDER_RESULT order={order} a_elapsed_ns={a_elapsed_ns} work={}",
        guard.work
    );
}
