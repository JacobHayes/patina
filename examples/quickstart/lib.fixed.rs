use std::thread;

/// Run every job on its own thread and return the results in job order.
pub fn run_all(jobs: Vec<fn() -> u64>) -> Vec<u64> {
    let workers: Vec<_> = jobs.into_iter().map(thread::spawn).collect();
    workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect()
}
