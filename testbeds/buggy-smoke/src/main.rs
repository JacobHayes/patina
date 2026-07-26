//! buggy-smoke: a deliberately-buggy canary for Patina.
//!
//! The inverse of the other testbeds. Where they are correct programs we expect
//! Patina to keep GREEN, this one plants six real, reachable bugs that native
//! testing almost always misses on fast hardware but that Patina's deterministic
//! scheduler, virtual clock, SimNet, CrashFs, and seeded entropy should surface
//! quickly. If Patina ever stops finding these, Patina regressed.
//!
//! Contract for every bug mode:
//!   * a tripped assertion prints exactly `BUG_CAUGHT bug=<name> detail=<short>` and exits 1;
//!   * a clean scenario prints `CLEAN bug=<name>` and exits 0.
//!
//! Each planted flaw is marked with a `// BUG:` comment naming the flaw and the
//! Patina capability expected to catch it. 100% std-pure: no Patina imports, no
//! cfg(patina), no external crates.

use std::collections::hash_map::RandomState;
use std::env;
use std::fs::{self, File};
use std::hash::{BuildHasher, Hasher};
use std::io::{self, Write};
use std::net::UdpSocket;
use std::process;
use std::sync::mpsc;
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant};

/// One preformatted line per bug for `--list`: name, flaw, catching capability.
const CATALOG: &[&str] = &[
    "lost-update: two threads do a read-then-write increment with no atomic upgrade, losing updates [caught by: deterministic scheduler]",
    "deadlock: a rare reverse transfer takes two mutexes in the opposite order, an AB/BA inversion [caught by: deterministic scheduler + deadlock detection]",
    "no-fsync: a write-ahead commit never fsyncs, so a crash can lose records it reported durable [caught by: CrashFs crash injection]",
    "tight-deadline: a worker's completion is asserted within ~2x of its own sleep budget [caught by: virtual clock + latency injection]",
    "udp-order: a receiver assumes loopback UDP is FIFO and lossless and rejects any gap [caught by: SimNet reorder/drop]",
    "unlucky-byte: a 0x00-reserved sentinel makes a legitimate zero byte silently drop state [caught by: seeded entropy sweep]",
];

/// A finished scenario: either clean or a caught bug with a short detail.
enum Outcome {
    Clean,
    Caught(String),
}

/// Parsed CLI. Defaults make native runs behave as the README claims.
struct Args {
    bug: Option<String>,
    seed: Option<u64>,
    iters: Option<u64>,
    stress: bool,
    verify_db: Option<String>,
    list: bool,
}

fn main() {
    let args = match parse_args(env::args().skip(1)) {
        Ok(args) => args,
        Err(message) => {
            eprintln!("buggy-smoke: {message}");
            eprintln!("usage: buggy-smoke --bug <name> [--seed N] [--iters N] [--stress] | --list");
            flush_and_exit(2);
        }
    };

    if args.list {
        for line in CATALOG {
            println!("{line}");
        }
        flush_and_exit(0);
    }

    // `--verify-db` is the reopen-and-check half of the no-fsync protocol; it is
    // what the crash-injection phase runs after a simulated crash.
    if let Some(path) = args.verify_db {
        report("no-fsync", verify_db(&path, args.iters.unwrap_or(64)));
    }

    let bug = args.bug.unwrap_or_else(|| {
        eprintln!("buggy-smoke: --bug <name> is required (see --list)");
        flush_and_exit(2);
    });

    let outcome = match bug.as_str() {
        "lost-update" => lost_update(args.iters.unwrap_or(2_000), args.stress),
        "deadlock" => deadlock(args.iters.unwrap_or(64)),
        "no-fsync" => no_fsync(args.iters.unwrap_or(64)),
        "tight-deadline" => tight_deadline(args.iters.unwrap_or(10)),
        "udp-order" => udp_order(args.iters.unwrap_or(64)),
        "unlucky-byte" => unlucky_byte(args.seed),
        other => {
            eprintln!("buggy-smoke: unknown bug {other:?} (see --list)");
            flush_and_exit(2);
        }
    };
    report(&bug, outcome);
}

/// Print the contract line for `outcome` and exit with the matching code.
fn report(name: &str, outcome: Outcome) -> ! {
    match outcome {
        Outcome::Clean => {
            println!("CLEAN bug={name}");
            flush_and_exit(0);
        }
        Outcome::Caught(detail) => {
            println!("BUG_CAUGHT bug={name} detail={detail}");
            flush_and_exit(1);
        }
    }
}

fn flush_and_exit(code: i32) -> ! {
    // process::exit does not flush; stdout is block-buffered under a pipe.
    let _ = io::stdout().flush();
    process::exit(code);
}

// --- Bug 1: lost-update -----------------------------------------------------

/// Threads (2, or 8 under `--stress`) each increment a shared counter `iters`
/// times using a read lock to load and a separate write lock to store.
fn lost_update(iters: u64, stress: bool) -> Outcome {
    let threads: u64 = if stress { 8 } else { 2 };
    let cell = Arc::new(RwLock::new(0u64));
    let handles: Vec<_> = (0..threads)
        .map(|_| {
            let cell = Arc::clone(&cell);
            thread::spawn(move || {
                for _ in 0..iters {
                    // BUG: read-modify-write with no atomic upgrade. The read
                    // guard drops before the write guard is taken, so two threads
                    // can observe the same `current` and one increment is lost.
                    // Natively the window is tiny and low `iters` usually survives
                    // on fast hardware; Patina's scheduler drives the dropping
                    // interleaving on every seed, and `--stress` widens it enough
                    // to lose updates natively too.
                    let current = *cell.read().unwrap();
                    let next = current + 1;
                    *cell.write().unwrap() = next;
                }
            })
        })
        .collect();
    for handle in handles {
        handle.join().unwrap();
    }
    let observed = *cell.read().unwrap();
    let expected = threads * iters;
    if observed == expected {
        Outcome::Clean
    } else {
        Outcome::Caught(format!("lost={} expected={expected}", expected - observed))
    }
}

// --- Bug 2: deadlock --------------------------------------------------------

/// Two threads move a unit between two mutex-guarded accounts. Thread A always
/// locks a->b; thread B does too EXCEPT for one "rebalance" iteration that locks
/// b->a. A generous wall-clock watchdog bounds the run.
fn deadlock(iters: u64) -> Outcome {
    let account_a = Arc::new(Mutex::new(1_000_000u64));
    let account_b = Arc::new(Mutex::new(1_000_000u64));
    let (done_tx, done_rx) = mpsc::channel();

    let transfer = |from: &Mutex<u64>, to: &Mutex<u64>| {
        let mut from = from.lock().unwrap();
        let mut to = to.lock().unwrap();
        if *from > 0 {
            *from -= 1;
            *to += 1;
        }
    };

    let (a1, b1, tx1) = (
        Arc::clone(&account_a),
        Arc::clone(&account_b),
        done_tx.clone(),
    );
    let worker_a = thread::spawn(move || {
        for _ in 0..iters {
            transfer(&a1, &b1);
        }
        let _ = tx1.send(());
    });

    let (a2, b2, tx2) = (Arc::clone(&account_a), Arc::clone(&account_b), done_tx);
    let worker_b = thread::spawn(move || {
        for i in 0..iters {
            if i == iters / 2 {
                // BUG: the rebalance path locks b->a while the common path locks
                // a->b, an AB/BA inversion. It deadlocks only if worker A holds
                // `a` and is waiting for `b` at this instant -- a window native
                // scheduling almost never hits, but Patina's scheduler can align
                // the threads and its deadlock detector reports the cycle.
                transfer(&b2, &a2);
            } else {
                transfer(&a2, &b2);
            }
        }
        let _ = tx2.send(());
    });

    // Watchdog: both workers must signal completion within the budget.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut finished = 0;
    while finished < 2 {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match done_rx.recv_timeout(remaining) {
            Ok(()) => finished += 1,
            Err(_) => {
                // Deadlocked: the workers are unjoinable, so detach and report.
                drop(worker_a);
                drop(worker_b);
                return Outcome::Caught("watchdog-timeout".to_string());
            }
        }
    }
    worker_a.join().unwrap();
    worker_b.join().unwrap();
    Outcome::Clean
}

// --- Bug 3: no-fsync --------------------------------------------------------

/// 4-byte marker terminating a fully-written record frame.
const COMMIT_MARKER: [u8; 4] = [0xCA, 0xFE, 0xBA, 0xBE];
/// Fixed payload length per record; content is derived from the sequence.
const RECORD_PAYLOAD: usize = 16;

/// Append `count` framed records, each followed by a commit marker, then declare
/// success -- WITHOUT fsync. Verifies inline so the native (no-crash) run passes.
fn no_fsync(count: u64) -> Outcome {
    let dir = env::temp_dir().join(format!("buggy-smoke-wal-{}", process::id()));
    let _ = fs::create_dir_all(&dir);
    let path = dir.join("commit.log");
    let path_str = path.to_string_lossy().into_owned();
    // Announce the DB path (on stderr, so the single stdout contract line is
    // untouched) so the crash-injection phase and the checker can find it.
    eprintln!("db-path={path_str}");

    {
        let mut file = match File::create(&path) {
            Ok(file) => file,
            Err(error) => return Outcome::Caught(format!("create-failed={error}")),
        };
        for seq in 0..count {
            let mut frame = Vec::with_capacity(12 + RECORD_PAYLOAD + 4);
            frame.extend_from_slice(&seq.to_le_bytes());
            frame.extend_from_slice(&(RECORD_PAYLOAD as u32).to_le_bytes());
            frame.extend_from_slice(&[seq as u8; RECORD_PAYLOAD]);
            frame.extend_from_slice(&COMMIT_MARKER);
            if let Err(error) = file.write_all(&frame) {
                return Outcome::Caught(format!("write-failed={error}"));
            }
            // BUG: no file.sync_all() here, and none before returning success.
            // The OS may not have flushed these records to stable storage, so a
            // crash can lose records this protocol has reported durable. CrashFs,
            // which respects fsync boundaries and injects torn writes, exposes
            // it; the checker is `--verify-db` after the crash.
        }
    }

    // Native path: no crash, so the reopened file is a clean, complete prefix.
    verify_db(&path_str, count)
}

/// Reopen the WAL and check it holds a contiguous, uncorrupted prefix of exactly
/// `expected` committed records. Used inline (native) and by `--verify-db`.
fn verify_db(path: &str, expected: u64) -> Outcome {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) => return Outcome::Caught(format!("reopen-failed={error}")),
    };
    let mut offset = 0usize;
    let mut committed = 0u64;
    while offset < bytes.len() {
        if offset + 12 > bytes.len() {
            break; // Torn header at the very end: an uncommitted append, fine.
        }
        let seq = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
        let len = u32::from_le_bytes(bytes[offset + 8..offset + 12].try_into().unwrap()) as usize;
        let end = offset + 12 + len + 4;
        if end > bytes.len() {
            break; // Torn record tail: an uncommitted crash-during-append, fine.
        }
        if bytes[offset + 12 + len..end] != COMMIT_MARKER {
            return Outcome::Caught(format!("torn-marker-at-seq={seq}"));
        }
        if seq != committed {
            return Outcome::Caught(format!("seq-gap-expected={committed}-got={seq}"));
        }
        committed += 1;
        offset = end;
    }
    if committed < expected {
        Outcome::Caught(format!(
            "lost-durable-records committed={committed} expected={expected}"
        ))
    } else {
        Outcome::Clean
    }
}

// --- Bug 4: tight-deadline --------------------------------------------------

/// A worker does `steps` paced chunks of work; the main thread asserts it
/// finishes within ~2x the nominal budget.
fn tight_deadline(steps: u64) -> Outcome {
    let step = Duration::from_millis(5);
    let budget = step * (steps as u32) * 2; // ~2x headroom over nominal work.

    let worker = thread::spawn(move || {
        let start = Instant::now();
        for _ in 0..steps {
            thread::sleep(step);
        }
        start.elapsed()
    });
    let elapsed = worker.join().unwrap();

    // BUG: correctness depends on a wall-clock timing assumption -- that each
    // paced step costs ~`step` so the total stays under `budget`. Under Patina
    // sleeps advance virtual time; injected latency on the clock/scheduler pushes
    // the virtual elapsed past `budget` and trips this.
    if elapsed <= budget {
        Outcome::Clean
    } else {
        Outcome::Caught(format!(
            "elapsed-ms={} budget-ms={}",
            elapsed.as_millis(),
            budget.as_millis()
        ))
    }
}

// --- Bug 5: udp-order -------------------------------------------------------

/// A sender fires `count` numbered datagrams over loopback UDP to a receiver
/// that asserts strictly-contiguous sequence numbers.
fn udp_order(count: u64) -> Outcome {
    let receiver = match UdpSocket::bind("127.0.0.1:0") {
        Ok(socket) => socket,
        Err(error) => return Outcome::Caught(format!("bind-failed={error}")),
    };
    if let Err(error) = receiver.set_read_timeout(Some(Duration::from_secs(2))) {
        return Outcome::Caught(format!("timeout-setup-failed={error}"));
    }
    let port = match receiver.local_addr() {
        Ok(addr) => addr.port(),
        Err(error) => return Outcome::Caught(format!("addr-failed={error}")),
    };

    let sender = thread::spawn(move || {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("sender bind");
        for seq in 0..count as u32 {
            socket
                .send_to(&seq.to_le_bytes(), ("127.0.0.1", port))
                .expect("send datagram");
        }
    });

    let mut buf = [0u8; 4];
    let mut previous: i64 = -1;
    for _ in 0..count {
        match receiver.recv_from(&mut buf) {
            Ok((4, _)) => {
                let seq = u32::from_le_bytes(buf) as i64;
                // BUG: assumes loopback UDP is FIFO and lossless, so the next
                // datagram must be exactly previous+1. SimNet's reorder and drop
                // decisions break both assumptions and trip this at once.
                if seq != previous + 1 {
                    let _ = sender.join();
                    return Outcome::Caught(format!(
                        "out-of-order got={seq} want={}",
                        previous + 1
                    ));
                }
                previous = seq;
            }
            _ => {
                let _ = sender.join();
                return Outcome::Caught(format!("drop-or-timeout after-seq={previous}"));
            }
        }
    }
    let _ = sender.join();
    Outcome::Clean
}

// --- Bug 6: unlucky-byte ----------------------------------------------------

/// Draw 16 random bytes, fold them to one byte, and use it as a nonzero
/// "generation tag". A tag of 0 is (wrongly) assumed impossible.
fn unlucky_byte(seed: Option<u64>) -> Outcome {
    let bytes = sample_bytes(seed);
    let derived = bytes.iter().fold(0u8, |acc, &byte| acc ^ byte);

    const SLOTS: usize = 255;
    let mut table = [0u8; SLOTS];
    let tag = derived;
    // BUG: convention is that tag 0 means "unset", so real tags run 1..=255 and
    // store at `tag - 1`. But a folded byte is legitimately 0 for 1/256 of draws;
    // on that draw the write is skipped and the slot the writer believes it
    // filled stays empty. Patina's seeded-entropy sweep finds the unlucky seed
    // fast because the draw is deterministic per seed.
    if tag != 0 {
        table[(tag - 1) as usize] = tag;
    }

    let stored = table.iter().filter(|&&value| value != 0).count();
    if stored == 1 {
        Outcome::Clean
    } else {
        Outcome::Caught(format!("derived=0x{derived:02x} stored={stored}"))
    }
}

/// 16 random bytes. With `--seed`, a deterministic SplitMix64 stream (native
/// reproducibility). Without, the standard library's OS entropy via RandomState
/// -- the source Patina's seeded-entropy driver interposes, so a Patina seed
/// sweep (no app `--seed`) varies these bytes deterministically.
fn sample_bytes(seed: Option<u64>) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    match seed {
        Some(seed) => {
            let mut state = seed;
            bytes[0..8].copy_from_slice(&splitmix64(&mut state).to_le_bytes());
            bytes[8..16].copy_from_slice(&splitmix64(&mut state).to_le_bytes());
        }
        None => {
            bytes[0..8].copy_from_slice(&os_entropy_word().to_le_bytes());
            bytes[8..16].copy_from_slice(&os_entropy_word().to_le_bytes());
        }
    }
    bytes
}

/// One 64-bit word of OS entropy. Each RandomState draws fresh SipHash keys from
/// the OS RNG (getrandom / CommonCrypto), which Patina interposes; hashing a
/// fixed message surfaces those keys as an effectively-uniform word.
fn os_entropy_word() -> u64 {
    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u8(0);
    hasher.finish()
}

fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

// --- CLI parsing ------------------------------------------------------------

fn parse_args(mut args: impl Iterator<Item = String>) -> Result<Args, String> {
    let mut parsed = Args {
        bug: None,
        seed: None,
        iters: None,
        stress: false,
        verify_db: None,
        list: false,
    };
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--list" => parsed.list = true,
            "--stress" => parsed.stress = true,
            "--bug" => parsed.bug = Some(value(&mut args, "--bug")?),
            "--seed" => parsed.seed = Some(parse_u64(&value(&mut args, "--seed")?, "--seed")?),
            "--iters" => parsed.iters = Some(parse_u64(&value(&mut args, "--iters")?, "--iters")?),
            "--verify-db" => parsed.verify_db = Some(value(&mut args, "--verify-db")?),
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    Ok(parsed)
}

fn value(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    args.next()
        .ok_or_else(|| format!("{flag} requires a value"))
}

fn parse_u64(text: &str, flag: &str) -> Result<u64, String> {
    text.parse()
        .map_err(|_| format!("{flag} must be an unsigned integer"))
}
