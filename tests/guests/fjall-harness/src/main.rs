//! Crash-recovery harness for fjall, an ordinary binary run under `patina run`.
//!
//! Incarnation 0 (no `ROOT/db` yet): create the db, commit batches that insert
//! key i into two keyspaces atomically, and every few batches call
//! `db.persist(SyncAll)` and then append the acknowledged high-water mark to an
//! fsynced ack file. Background flush/compaction is forced via a tiny memtable.
//!
//! Recovery (ROOT/db exists, i.e. after a crash and restart): reopen and check
//!  1. every acked key is present in both keyspaces with the right value
//!  2. both keyspaces hold the same key set (cross-keyspace batch atomicity)
//!  3. the key set is a prefix 0..n (no holes)
//!  4. a second reopen gives the same contents (recovery is stable)
//!
//! - Parameters come from the environment: `FJ_N` (default 300), `FJ_WORKERS`
//!   (default 1), `FJ_PERSIST` (`buffer` = planted bug: acknowledge without fsync),
//!   `FJ_LOG` (`1`: fjall's log at info and progress every 50 batches; `2`: every batch),
//!   `FJ_VAL_SHIFT` (default 0; shifts the sequence of value lengths, and so the journal's layout),
//!   `FJ_ROOT` (default `/work/fjtest`; the native check points it at a copied tree),
//!   `FJ_WIPE_PARTIAL=1` (a workaround for finding F1: wipe a db without a `version`
//!   marker and start over).
//! - Invariants are `patina_dst::always!`, and failures found without a condition (an open
//!   or iteration error) `patina_dst::unreachable!`: under Patina either ends the run
//!   `violation` with `label: detail`. Run natively (on a kept post-crash tree) the SDK is inert, so a
//!   failure prints `INVARIANT label: detail` to stderr and exits 1.
//! - Two fault points, `persist-now` (persist and acknowledge early) and `manual-flush`
//!   (rotate keyspace a's memtable), are `patina_dst::buggify!`: they fire only under
//!   `patina run --faults buggify`.
//! - An open that fails with an error that was not an injected I/O error violates
//!   `open-after-crash` when recovering after a crash, `reopen-failed` in the checks after
//!   writing; an iteration error violates `iterate-failed`.
//! - "Injected" errors (UNJUDGED, exit 0) are the errnos Patina's fault injection returns
//!   (EIO, ENOSPC, EDQUOT, EMFILE, ENFILE, ENOMEM, EINTR); an injected error opening or
//!   reading the ack file is UNJUDGED too, and so is one creating the root or wiping a
//!   partial database.

use fjall::{Database, Keyspace, KeyspaceCreateOptions, PersistMode};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

fn param(name: &str) -> Option<String> {
    std::env::var(format!("FJ_{}", name.to_uppercase())).ok()
}

/// An invariant: `check!(cond, "label")` or `check!(cond, "label", "fmt", args..)`.
macro_rules! check {
    ($cond:expr, $label:expr) => {
        check!($cond, $label, "")
    };
    ($cond:expr, $label:expr, $($detail:tt)+) => {{
        let ok: bool = $cond;
        patina_dst::always!(ok, $label, $($detail)+);
        if !ok {
            // natively the SDK is inert: report and stop like any failed check
            eprintln!("INVARIANT {}: {}", $label, format_args!($($detail)+));
            std::process::exit(1);
        }
    }};
}

/// A failure found without a condition to check: `fail!("label", "fmt", args..)`. An
/// `unreachable!` under Patina, so a sweep in which no run fails this way does not list it.
macro_rules! fail {
    ($label:expr, $($detail:tt)+) => {{
        patina_dst::unreachable!($label, $($detail)+);
        eprintln!("INVARIANT {}: {}", $label, format_args!($($detail)+));
        std::process::exit(1);
    }};
}

struct StderrLog;
impl log::Log for StderrLog {
    fn enabled(&self, m: &log::Metadata) -> bool {
        m.level() <= log::Level::Info
    }
    fn log(&self, r: &log::Record) {
        if self.enabled(r.metadata()) {
            eprintln!("LOG {} {}: {}", r.level(), r.target(), r.args());
        }
    }
    fn flush(&self) {}
}
static LOGGER: StderrLog = StderrLog;

fn val(i: u64) -> Vec<u8> {
    // value length varies with i so blocks/tables vary; FJ_VAL_SHIFT moves the sequence of
    // lengths, so the journal's layout (where its 4 KiB block boundaries fall) changes
    static SHIFT: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    let shift = *SHIFT.get_or_init(|| param("val_shift").and_then(|s| s.parse().ok()).unwrap_or(0));
    let len = 16 + (i.wrapping_add(shift).wrapping_mul(2654435761) % 600) as usize;
    let mut v = Vec::with_capacity(len);
    while v.len() < len {
        v.extend_from_slice(&i.to_be_bytes());
    }
    v.truncate(len);
    v
}

fn key(i: u64) -> [u8; 8] {
    i.to_be_bytes()
}

fn fsync_dir(p: &Path) {
    if let Err(e) = File::open(p).and_then(|f| f.sync_all()) {
        eprintln!("UNJUDGED fsync dir {p:?}: {e}");
        std::process::exit(0);
    }
}

/// Errnos Patina's fault injection can return on a `/work` file or path (EIO, ENOSPC,
/// EDQUOT, EMFILE, ENFILE, ENOMEM): an operation that fails
/// with one of these cannot be judged.
fn is_injected_io(d: &str) -> bool {
    ["code: 5,", "code: 28,", "code: 122,", "code: 24,", "code: 23,", "code: 12,", "code: 4,"]
        .iter()
        .any(|c| d.contains(c))
}

fn unjudged(what: &str, e: std::io::Error) -> ! {
    eprintln!("UNJUDGED {what} hit injected I/O error: {e}");
    std::process::exit(0);
}

/// An open that fails with a non-injected error violates `open-after-crash` when
/// recovering a database a crash left (`recovering`), else `reopen-failed`.
fn open(root: &Path, recovering: bool) -> (Database, Keyspace, Keyspace) {
    match try_open(root) {
        Ok(x) => x,
        Err(e) => {
            let d = format!("{e:?}");
            if is_injected_io(&d) {
                // an injected I/O error: this run cannot be judged
                eprintln!("UNJUDGED open hit injected I/O error: {d}");
                std::process::exit(0);
            }
            if recovering {
                fail!("open-after-crash", "open db: {d}");
            }
            fail!("reopen-failed", "open db: {d}");
        }
    }
}

fn try_open(root: &Path) -> fjall::Result<(Database, Keyspace, Keyspace)> {
    let db = Database::builder(root.join("db"))
        .worker_threads(param("workers").and_then(|s| s.parse().ok()).unwrap_or(1))
        .open()?;
    let opts = || KeyspaceCreateOptions::default().max_memtable_size(16 * 1024);
    let a = db.keyspace("a", opts)?;
    let b = db.keyspace("b", opts)?;
    Ok((db, a, b))
}

fn read_acked(root: &Path) -> Option<u64> {
    let mut s = String::new();
    match File::open(root.join("acks")) {
        Ok(mut f) => {
            if let Err(e) = f.read_to_string(&mut s) {
                unjudged("read acks", e);
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => unjudged("open acks", e),
    }
    // only '\n'-terminated lines count: a torn last line was never acknowledged
    let complete = match s.rfind('\n') {
        Some(i) => &s[..i],
        None => "",
    };
    complete
        .split('\n')
        .filter(|l| !l.is_empty())
        // a line of NULs is an append whose size a later journal commit
        // recorded but whose data never reached disk: not acknowledged.
        .filter(|l| !l.bytes().all(|b| b == 0))
        .map(|l| {
            l.parse::<u64>()
                .unwrap_or_else(|e| panic!("ack line {l:?} must parse ({e}); file bytes {:?}", s.as_bytes()))
        })
        .max()
}

fn snapshot(ks: &Keyspace) -> Vec<(u64, Vec<u8>)> {
    let mut out = Vec::new();
    for kv in ks.iter() {
        let (k, v) = match kv.into_inner() {
            Ok(x) => x,
            Err(e) => {
                let d = format!("{e:?}");
                if is_injected_io(&d) {
                    eprintln!("UNJUDGED iterate hit injected I/O error: {d}");
                    std::process::exit(0);
                }
                fail!("iterate-failed", "iter: {d}");
            }
        };
        let k = u64::from_be_bytes(k.as_ref().try_into().expect("8-byte key"));
        out.push((k, v.to_vec()));
    }
    out
}

fn check(root: &Path, recovering: bool) -> usize {
    let acked = read_acked(root);
    let (db, a, b) = open(root, recovering);
    let sa = snapshot(&a);
    let sb = snapshot(&b);
    drop((a, b));
    drop(db);
    eprintln!("recovery: acked_high={acked:?} a_len={} b_len={}", sa.len(), sb.len());
    let keys_a: Vec<u64> = sa.iter().map(|(k, _)| *k).collect();
    let keys_b: Vec<u64> = sb.iter().map(|(k, _)| *k).collect();
    if keys_a != keys_b {
        eprintln!("A keys {keys_a:?}\nB keys {keys_b:?}");
    }
    check!(keys_a == keys_b, "batch-atomic-across-keyspaces", "a has {} keys, b has {}", keys_a.len(), keys_b.len());
    let prefix = keys_a.iter().enumerate().all(|(n, k)| *k == n as u64);
    if !prefix {
        eprintln!("A keys not a prefix: {keys_a:?}");
    }
    check!(prefix, "recovered-keys-are-prefix");
    let vals_ok = sa.iter().chain(sb.iter()).all(|(k, v)| *v == val(*k));
    check!(vals_ok, "recovered-values-correct");
    if let Some(h) = acked {
        let durable = keys_a.len() as u64 > h && keys_b.len() as u64 > h;
        if !durable {
            eprintln!("LOST ACKED: acked through {h}, a has {} b has {}", keys_a.len(), keys_b.len());
        }
        check!(durable, "acked-writes-survive", "acked through {h}, a has {} b has {}", keys_a.len(), keys_b.len());
    }
    // recovery must be stable: reopen again and compare
    let (db2, a2, b2) = open(root, false);
    let sa2 = snapshot(&a2);
    let sb2 = snapshot(&b2);
    check!(sa2 == sa && sb2 == sb, "reopen-is-stable");
    drop((a2, b2));
    drop(db2);
    sa.len()
}

fn workload(root: &Path, start: u64, n: u64) -> Result<(), String> {
    let (db, a, b) = try_open(root).map_err(|e| format!("open: {e:?}"))?;
    // ack file: create + fsync it and its dir before anything counts as acked
    let mut acks = OpenOptions::new().create(true).append(true).open(root.join("acks")).map_err(|e| format!("open acks: {e}"))?;
    // terminate any torn line a crash left behind
    acks.write_all(b"\n").map_err(|e| format!("ack sep: {e}"))?;
    acks.sync_all().map_err(|e| format!("sync acks: {e}"))?;
    File::open(root).and_then(|d| d.sync_all()).map_err(|e| format!("fsync root: {e}"))?;
    let log = param("log");
    for i in start..start + n {
        if log.is_some() && (i % 50 == 0 || log.as_deref() == Some("2")) {
            eprintln!("PROGRESS batch {i}");
        }
        let mut batch = db.batch();
        batch.insert(&a, key(i), val(i));
        batch.insert(&b, key(i), val(i));
        batch.commit().map_err(|e| format!("commit {i}: {e:?}"))?;
        if i % 7 == 6 || patina_dst::buggify!("persist-now") {
            // planted-bug control: FJ_PERSIST=buffer acks without fsync
            let mode = if param("persist").as_deref() == Some("buffer") { PersistMode::Buffer } else { PersistMode::SyncAll };
            if log.as_deref() == Some("2") {
                eprintln!("PERSIST {i}");
            }
            db.persist(mode).map_err(|e| format!("persist {i}: {e:?}"))?;
            acks.write_all(format!("{i}\n").as_bytes()).map_err(|e| format!("write ack: {e}"))?;
            acks.sync_all().map_err(|e| format!("sync ack: {e}"))?;
        }
        if log.as_deref() == Some("2") {
            eprintln!("COMMITTED {i}");
        }
        if patina_dst::buggify!("manual-flush") {
            if log.as_deref() == Some("2") {
                eprintln!("ROTATE {i}");
            }
            a.rotate_memtable().map_err(|e| format!("rotate: {e:?}"))?;
        }
    }
    db.persist(PersistMode::SyncAll).map_err(|e| format!("final persist: {e:?}"))?;
    acks.write_all(format!("{}\n", start + n - 1).as_bytes()).map_err(|e| format!("write ack: {e}"))?;
    acks.sync_all().map_err(|e| format!("sync ack: {e}"))?;
    drop((a, b));
    drop(db);
    Ok(())
}

/// After an error, keep making crash points so a machine crash is likely to land
/// while the failed state is still in the page cache.
fn crash_soon(root: &Path) {
    for k in 0..400u32 {
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(root.join("scratch")) {
            let _ = f.write_all(&k.to_le_bytes());
            let _ = f.sync_all();
        }
    }
}

fn run_workload(root: &Path, start: u64, n: u64) -> bool {
    match workload(root, start, n) {
        Ok(()) => true,
        Err(e) => {
            eprintln!("WORKLOAD-ERROR {e}");
            crash_soon(root);
            false
        }
    }
}

fn main() {
    if param("log").is_some() {
        log::set_logger(&LOGGER).expect("logger");
        log::set_max_level(log::LevelFilter::Info);
    }
    let root_s = param("root").unwrap_or_else(|| "/work/fjtest".into());
    let root = PathBuf::from(&root_s);
    let root = root.as_path();
    let n: u64 = param("n").and_then(|s| s.parse().ok()).unwrap_or(300);
    let recovering = root.join("db").try_exists().expect("stat db");
    let version_ok = std::fs::read(root.join("db/version")).map(|v| v.len() >= 4).unwrap_or(false);
    if recovering && !version_ok && param("wipe_partial").as_deref() == Some("1") {
        // KNOWN fjall finding (F1): a crash inside the first Database::open leaves a db
        // dir without `version` that can never be reopened (EEXIST on 0.jnl).
        // Embedder workaround so the sweep keeps exploring: wipe and start over.
        eprintln!("KNOWN: partial create (no version marker); wiping db");
        if let Err(e) = std::fs::remove_dir_all(root.join("db")) {
            unjudged("wipe db", e);
        }
        std::fs::remove_file(root.join("acks")).ok();
        fsync_dir(root);
        if run_workload(root, 0, 100) {
            let have = check(root, false);
            check!(have == 100, "fresh-after-wipe-complete", "{have} keys");
        }
        println!("wiped and rebuilt 0");
    } else if recovering {
        let have = check(root, true);
        // keep going on the recovered db, then check again
        if !run_workload(root, have as u64, 50) {
            return;
        }
        let have2 = check(root, false);
        check!(have2 == have + 50, "post-recovery-writes-land", "{have} then {have2} keys");
        println!("recovered {have} then {have2}");
    } else {
        if let Err(e) = std::fs::create_dir_all(root) {
            unjudged("mkdir root", e);
        }
        fsync_dir(root.parent().unwrap_or(Path::new("/")));
        if !run_workload(root, 0, n) {
            return;
        }
        let have = check(root, false);
        check!(have as u64 == n, "clean-run-complete", "{have} of {n} keys");
        println!("clean run: {have} keys");
    }
}
