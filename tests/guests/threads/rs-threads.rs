// Rust std threads: Mutex, Condvar, mpsc, thread::sleep, park_timeout, Instant
// arithmetic and a thread pool of 16. Exit 1 with an INVARIANT line if a check fails.
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

fn check(ok: bool, what: &str) -> bool {
    if !ok {
        eprintln!("INVARIANT {what}");
    }
    ok
}

fn main() {
    let mut ok = true;

    // Mutex counter.
    let c = Arc::new(Mutex::new(0u64));
    let hs: Vec<_> = (0..8)
        .map(|_| {
            let c = c.clone();
            thread::spawn(move || {
                for i in 0..1000 {
                    *c.lock().unwrap() += 1;
                    if i % 100 == 0 {
                        thread::yield_now();
                    }
                }
            })
        })
        .collect();
    for h in hs {
        h.join().unwrap();
    }
    let n = *c.lock().unwrap();
    println!("mutex {n}");
    ok &= check(n == 8000, "mutex counter");

    // Condvar ping-pong.
    let pair = Arc::new((Mutex::new((0u32, Vec::<u8>::new())), Condvar::new()));
    let hs: Vec<_> = (0..2u32)
        .map(|me| {
            let pair = pair.clone();
            thread::spawn(move || {
                let (m, cv) = &*pair;
                for _ in 0..100 {
                    let mut g = m.lock().unwrap();
                    while g.0 != me {
                        g = cv.wait(g).unwrap();
                    }
                    g.1.push(b'a' + me as u8);
                    g.0 = 1 - me;
                    cv.notify_all();
                }
            })
        })
        .collect();
    for h in hs {
        h.join().unwrap();
    }
    let trace = pair.0.lock().unwrap().1.clone();
    let alt = trace.iter().enumerate().all(|(i, &b)| b == b'a' + (i % 2) as u8);
    println!("condvar {} alternating {alt}", trace.len());
    ok &= check(trace.len() == 200 && alt, "condvar ping-pong");

    // mpsc.
    let (tx, rx) = mpsc::channel();
    let hs: Vec<_> = (0..4u64)
        .map(|p| {
            let tx = tx.clone();
            thread::spawn(move || {
                for i in 0..250u64 {
                    tx.send(p * 1000 + i).unwrap();
                }
            })
        })
        .collect();
    drop(tx);
    let mut sum = 0u64;
    let mut count = 0;
    for v in rx {
        sum += v;
        count += 1;
    }
    for h in hs {
        h.join().unwrap();
    }
    let want: u64 = (0..4u64).map(|p| (0..250u64).map(|i| p * 1000 + i).sum::<u64>()).sum();
    println!("mpsc {count} {sum}");
    ok &= check(count == 1000 && sum == want, "mpsc");

    // sleep and Instant arithmetic.
    let t0 = Instant::now();
    thread::sleep(Duration::from_millis(1500));
    let slept = t0.elapsed();
    println!("sleep {}", slept.as_nanos());
    ok &= check(slept >= Duration::from_millis(1500) && slept < Duration::from_millis(1501), "sleep");
    let later = t0 + Duration::from_secs(3);
    ok &= check(later.duration_since(t0) == Duration::from_secs(3) && later > Instant::now(), "instant arithmetic");

    // park_timeout: nobody unparks, so it times out. A token left by an earlier unpark
    // (std's mpsc parks and unparks threads) makes it return early, as documented: loop.
    let t1 = Instant::now();
    let mut parks = 0;
    while t1.elapsed() < Duration::from_millis(700) {
        thread::park_timeout(Duration::from_millis(700) - t1.elapsed());
        parks += 1;
    }
    let parked = t1.elapsed();
    ok &= check(parks <= 2, "park_timeout returned early more than once");
    println!("park_timeout {}", parked.as_nanos());
    ok &= check(parked >= Duration::from_millis(700) && parked < Duration::from_millis(701), "park_timeout");

    // unpark wakes a parked thread.
    let h = thread::spawn(|| {
        let t = Instant::now();
        thread::park_timeout(Duration::from_secs(60));
        t.elapsed()
    });
    thread::sleep(Duration::from_millis(10));
    h.thread().unpark();
    let waited = h.join().unwrap();
    println!("unpark after {}", waited.as_nanos());
    ok &= check(waited < Duration::from_secs(60), "unpark");

    // Thread pool of 16.
    let (jtx, jrx) = mpsc::channel::<u64>();
    let jrx = Arc::new(Mutex::new(jrx));
    let (rtx, rrx) = mpsc::channel::<(usize, u64)>();
    let workers: Vec<_> = (0..16)
        .map(|w| {
            let jrx = jrx.clone();
            let rtx = rtx.clone();
            thread::spawn(move || loop {
                let job = jrx.lock().unwrap().recv();
                match job {
                    Ok(j) => rtx.send((w, j * j)).unwrap(),
                    Err(_) => break,
                }
            })
        })
        .collect();
    drop(rtx);
    for j in 0..2000u64 {
        jtx.send(j).unwrap();
    }
    drop(jtx);
    let mut total = 0u64;
    let mut per_worker = [0u32; 16];
    for (w, v) in rrx {
        total += v;
        per_worker[w] += 1;
    }
    for w in workers {
        w.join().unwrap();
    }
    let want: u64 = (0..2000u64).map(|j| j * j).sum();
    println!("pool {total} jobs per worker {per_worker:?}");
    ok &= check(total == want, "thread pool");

    std::process::exit(if ok { 0 } else { 1 });
}
