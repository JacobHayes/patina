// The rewriter's differential guest in Rust: threads over channels, Mutex, RwLock and atomics,
// a HashMap reported in key order, and a sort. Prints the same lines on every run.
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex, RwLock};
use std::thread;

fn main() {
    let counter = Arc::new(AtomicU64::new(0));
    let locked = Arc::new(Mutex::new(0u64));
    let table = Arc::new(RwLock::new(HashMap::new()));
    let (tx, rx) = mpsc::channel();
    let hs: Vec<_> = (0..4u64)
        .map(|t| {
            let (counter, locked, table, tx) = (counter.clone(), locked.clone(), table.clone(), tx.clone());
            thread::spawn(move || {
                for i in 0..20000u64 {
                    counter.fetch_add(i % 5, Ordering::SeqCst);
                    *locked.lock().unwrap() += t;
                    if i % 1000 == 0 {
                        table.write().unwrap().insert(t * 100000 + i, i * i);
                        tx.send(i + t).unwrap();
                    }
                }
            })
        })
        .collect();
    drop(tx);
    let sent: u64 = rx.iter().sum();
    for h in hs {
        h.join().unwrap();
    }
    let ordered: BTreeMap<_, _> = table.read().unwrap().iter().map(|(k, v)| (*k, *v)).collect();
    let mut v: Vec<u64> = (0..50000u64).map(|i| (i * 7919) % 10007).collect();
    v.sort_unstable();
    let s: String = ordered.iter().take(3).map(|(k, v)| format!("{k}={v} ")).collect();
    println!("counter {} locked {} sent {sent}", counter.load(Ordering::SeqCst), locked.lock().unwrap());
    println!("table {} {s}v {}..{}", ordered.len(), v[0], v[v.len() - 1]);
}
