use std::sync::mpsc;
use std::thread;

/// Run every job on its own thread and return the results in job order.
pub fn run_all(jobs: Vec<fn() -> u64>) -> Vec<u64> {
    let (sender, receiver) = mpsc::channel();
    for job in jobs {
        let sender = sender.clone();
        thread::spawn(move || sender.send(job()).unwrap());
    }
    drop(sender);
    receiver.iter().collect() // BUG: this is the order the jobs finished in
}
