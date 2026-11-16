//! W1 rust-threads-files: 8 threads produce records under a mutex; a condvar-driven
//! flusher appends them to `log`, fsyncs it, then acknowledges them in `acks` (fsynced).
//! Every third batch it also replaces `state` (a snapshot) by write-to-temp + rename and
//! acknowledges the snapshot number. A checker runs at the start of every incarnation
//! after the first (the tree under /work/w1 exists) and verifies that every acknowledged
//! record and snapshot survived.
//!
//! Usage: rust-threads-files MODE   (MODE: correct | a | b)
//!   a: the planted bug "acknowledge without fsync": the log append is not fsynced.
//!   b: the planted bug "rename without sync": the new snapshot's data and the directory
//!      are not fsynced before the snapshot is acknowledged.
//! Invariants print `INVARIANT <name>` on stderr and exit 1.
//! The flusher waits with a 30 s `Condvar::wait_timeout`, and after the workers finish
//! the main thread waits 30 s on a condvar nobody signals: both run in virtual time.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

const ROOT: &str = "/work/w1";
const THREADS: u64 = 8;
const PER_THREAD: u64 = 12;
const SNAP_BODY: usize = 6000;

fn invariant(name: &str, why: String) -> ! {
    eprintln!("{why}");
    eprintln!("INVARIANT {name}");
    std::process::exit(1);
}

fn h(x: u64) -> u64 {
    let mut z = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

fn fsync_path(p: &Path) {
    File::open(p).and_then(|f| f.sync_all()).unwrap_or_else(|e| panic!("fsync {p:?}: {e}"));
}

/// '\n'-terminated lines of a file; a NUL inside a line (zeros left by a crash after an
/// append whose data never reached disk) cuts off everything before it.
fn lines(p: &Path) -> Vec<String> {
    let mut b = vec![];
    File::open(p).and_then(|mut f| f.read_to_end(&mut b)).unwrap_or_else(|e| panic!("read {p:?}: {e}"));
    let end = b.iter().rposition(|&c| c == b'\n').map(|i| i + 1).unwrap_or(0);
    b[..end]
        .split(|&c| c == b'\n')
        .filter_map(|l| {
            let l = match l.iter().rposition(|&c| c == 0) {
                Some(i) => &l[i + 1..],
                None => l,
            };
            (!l.is_empty()).then(|| String::from_utf8_lossy(l).into_owned())
        })
        .collect()
}

fn record_line(t: u64, seq: u64) -> String {
    format!("R {t} {seq} {:016x}\n", h(seq ^ (t << 56)))
}

fn snapshot_bytes(s: u64) -> Vec<u8> {
    let mut v = format!("SNAP {s} {:016x}\n", h(s)).into_bytes();
    while v.len() < SNAP_BODY {
        v.extend_from_slice(format!("{:016x}", h(s + v.len() as u64)).as_bytes());
    }
    v.truncate(SNAP_BODY);
    v.push(b'\n');
    v
}

fn check(root: &Path) -> (u64, u64) {
    // records present in the log
    let mut have = std::collections::BTreeSet::new();
    for l in lines(&root.join("log")) {
        let f: Vec<&str> = l.split(' ').collect();
        let ok = f.len() == 4 && f[0] == "R";
        let parsed = if ok { (f[1].parse::<u64>().ok(), f[2].parse::<u64>().ok()) } else { (None, None) };
        match parsed {
            (Some(t), Some(seq)) if record_line(t, seq) == format!("{l}\n") => {
                have.insert(seq);
            }
            _ => invariant("log-record-corrupt", format!("bad log line {l:?}")),
        }
    }
    let (mut acked, mut snap_acked, mut max_seq) = (0u64, 0u64, 0u64);
    for l in lines(&root.join("acks")) {
        let mut f = l.split(' ');
        match (f.next(), f.next().and_then(|x| x.parse::<u64>().ok())) {
            (Some("R"), Some(seq)) => {
                acked += 1;
                max_seq = max_seq.max(seq);
                if !have.contains(&seq) {
                    invariant("acked-record-lost", format!("record {seq} acknowledged, not in the log"));
                }
            }
            (Some("S"), Some(s)) => snap_acked = snap_acked.max(s),
            _ => invariant("ack-line-corrupt", format!("bad ack line {l:?}")),
        }
    }
    let mut st = vec![];
    File::open(root.join("state")).and_then(|mut f| f.read_to_end(&mut st)).unwrap_or_else(|e| {
        invariant("snapshot-missing", format!("state: {e}"))
    });
    let s = std::str::from_utf8(&st)
        .ok()
        .and_then(|t| t.split(' ').nth(1))
        .and_then(|x| x.parse::<u64>().ok())
        .filter(|&s| snapshot_bytes(s) == st);
    match s {
        None => invariant("snapshot-corrupt", format!("state holds {} bytes, not a whole snapshot", st.len())),
        Some(s) if s < snap_acked => invariant("snapshot-lost", format!("state is snapshot {s}, {snap_acked} was acknowledged")),
        Some(s) => {
            println!("check: {} records in log, {acked} acknowledged, snapshot {s} (acknowledged {snap_acked})", have.len());
            (max_seq, s)
        }
    }
}

fn setup(root: &Path) {
    let _ = fs::remove_dir_all(root);
    fs::create_dir_all(root).unwrap();
    fsync_path(root.parent().unwrap());
    File::create(root.join("log")).unwrap().sync_all().unwrap();
    let mut s = File::create(root.join("state")).unwrap();
    s.write_all(&snapshot_bytes(0)).unwrap();
    s.sync_all().unwrap();
    fsync_path(root);
    // `acks` existing means the setup is durable
    File::create(root.join("acks")).unwrap().sync_all().unwrap();
    fsync_path(root);
}

struct Shared {
    pending: Vec<(u64, u64)>, // (thread, seq)
    durable_upto: u64,        // every seq below this is acknowledged
    next_seq: u64,
    workers_done: u64,
}

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "correct".into());
    let (fsync_log, sync_snapshot) = match mode.as_str() {
        "correct" => (true, true),
        "a" => (false, true),
        "b" => (true, false),
        _ => panic!("mode: correct | a | b"),
    };
    let root = Path::new(ROOT);
    let (seq0, mut snap) = if root.join("acks").exists() {
        let (m, s) = check(root);
        (m + 1, s)
    } else {
        setup(root);
        (0, 0)
    };
    let round: u64 = std::env::var("PATINA_INCARNATION").ok().and_then(|s| s.parse().ok()).unwrap_or(0);
    let seq0 = seq0.max(round * 1_000_000);
    let sh = Arc::new((Mutex::new(Shared { pending: vec![], durable_upto: seq0, next_seq: seq0, workers_done: 0 }), Condvar::new(), Condvar::new()));
    // flusher
    let fsh = sh.clone();
    let flusher = std::thread::spawn(move || {
        let (m, work, durable) = &*fsh;
        let mut log = OpenOptions::new().append(true).open(Path::new(ROOT).join("log")).unwrap();
        let mut acks = OpenOptions::new().append(true).open(Path::new(ROOT).join("acks")).unwrap();
        let mut batches = 0u64;
        let mut timeouts = 0u64;
        loop {
            let mut g = m.lock().unwrap();
            while g.pending.is_empty() && g.workers_done < THREADS {
                let (g2, r) = work.wait_timeout(g, Duration::from_secs(30)).unwrap();
                g = g2;
                if r.timed_out() {
                    timeouts += 1;
                }
            }
            if g.pending.is_empty() {
                return timeouts;
            }
            let batch = std::mem::take(&mut g.pending);
            drop(g);
            let mut buf = String::new();
            let mut ackb = String::new();
            let mut top = 0;
            for &(t, seq) in &batch {
                buf.push_str(&record_line(t, seq));
                ackb.push_str(&format!("R {seq}\n"));
                top = top.max(seq);
            }
            log.write_all(buf.as_bytes()).unwrap();
            if fsync_log {
                log.sync_all().unwrap();
            }
            acks.write_all(ackb.as_bytes()).unwrap();
            acks.sync_all().unwrap();
            batches += 1;
            if batches % 3 == 0 {
                snap += 1;
                let dir = Path::new(ROOT);
                let mut f = OpenOptions::new().write(true).create(true).truncate(true).mode(0o644).open(dir.join("state.tmp")).unwrap();
                f.write_all(&snapshot_bytes(snap)).unwrap();
                if sync_snapshot {
                    f.sync_all().unwrap();
                }
                drop(f);
                fs::rename(dir.join("state.tmp"), dir.join("state")).unwrap();
                if sync_snapshot {
                    fsync_path(dir);
                }
                acks.write_all(format!("S {snap}\n").as_bytes()).unwrap();
                acks.sync_all().unwrap();
            }
            let mut g = m.lock().unwrap();
            // the batch is acknowledged: every seq below `top + 1` that was taken is in it
            g.durable_upto = g.durable_upto.max(top + 1);
            durable.notify_all();
        }
    });
    let mut workers = vec![];
    for t in 0..THREADS {
        let wsh = sh.clone();
        workers.push(std::thread::spawn(move || {
            let (m, work, durable) = &*wsh;
            for _ in 0..PER_THREAD {
                let mut g = m.lock().unwrap();
                let seq = g.next_seq;
                g.next_seq += 1;
                g.pending.push((t, seq));
                work.notify_one();
                while g.durable_upto <= seq {
                    g = durable.wait(g).unwrap();
                }
            }
            let mut g = m.lock().unwrap();
            g.workers_done += 1;
            work.notify_one();
        }));
    }
    for w in workers {
        w.join().unwrap();
    }
    // A 30 s timeout that nobody cuts short: it must fire in virtual time.
    let idle = (Mutex::new(()), Condvar::new());
    let t0 = Instant::now();
    let mut g = idle.0.lock().unwrap();
    loop {
        let (g2, r) = idle.1.wait_timeout(g, Duration::from_secs(30)).unwrap();
        g = g2;
        if r.timed_out() {
            break;
        }
    }
    drop(g);
    let waited = t0.elapsed();
    let timeouts = flusher.join().unwrap();
    println!(
        "round {round} mode {mode}: {} records acknowledged, idle wait {} ms, flusher timeouts {timeouts}",
        THREADS * PER_THREAD,
        waited.as_millis()
    );
    if waited < Duration::from_secs(30) {
        invariant("timeout-early", format!("30 s wait returned after {waited:?}"));
    }
}
