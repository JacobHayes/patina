//! Run three jobs on threads and print their results, which must come back in job order.
use std::sync::mpsc;
use std::thread;

/// Run every job on its own thread and return the results in job order.
fn run_all(jobs: Vec<fn() -> u64>) -> Vec<u64> {
    let (sender, receiver) = mpsc::channel();
    for job in jobs {
        let sender = sender.clone();
        thread::spawn(move || sender.send(job()).unwrap());
    }
    drop(sender);
    receiver.iter().collect() // BUG: this is the order the jobs finished in
}

/// The fix: join the threads in job order.
fn run_all_fixed(jobs: Vec<fn() -> u64>) -> Vec<u64> {
    let workers: Vec<_> = jobs.into_iter().map(thread::spawn).collect();
    workers.into_iter().map(|w| w.join().unwrap()).collect()
}

fn main() {
    let jobs: Vec<fn() -> u64> = vec![|| 1, || 2, || 3];
    let results = match std::env::args().nth(1).as_deref() {
        Some("fixed") => run_all_fixed(jobs),
        _ => run_all(jobs),
    };
    assert_eq!(results, [1, 2, 3], "results out of job order");
    println!("results: {results:?}");
}
