//! Crash-recovery harness for fjall, ported from the Patina trial
//! (`trial-fjall/harness/src/main.rs`) to run as an ordinary binary under `patina`.
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
//! Port (W9):
//! - parameters come from the environment: `FJ_N` (default 300), `FJ_WORKERS`
//!   (default 1), `FJ_PERSIST` (`buffer` = planted bug: acknowledge without fsync),
//!   `FJ_LOG` (`1`: fjall's log at info and progress every 50 batches; `2`: every batch),
//!   `FJ_ROOT` (default `/work/fjtest`; the native check points it at a copied tree),
//!   `FJ_WIPE_PARTIAL=1` (the trial's workaround for finding F1: wipe a db without a
//!   `version` marker and start over), `FJ_BUGGIFY=1` (enable the two buggify sites).
//! - `always!(c, name)` prints `INVARIANT name` to stderr and exits 1.
//! - `sometimes!` is gone (it only fed coverage reports).
//! - `buggify!(site)`: when `FJ_BUGGIFY=1`, each site is active for the run with
//!   probability 250/1000 and an active site fires with probability 250/1000 per
//!   evaluation (the trial tool's defaults). The draws come from `getrandom`, which is
//!   the tool's seeded entropy stream under `patina`.
//! - An open that fails with an error that was not an injected I/O error reports
//!   `INVARIANT open-after-crash` when recovering after a crash, `INVARIANT reopen-failed`
//!   in the checks after writing; an iteration error reports `INVARIANT iterate-failed`
//!   (the trial panicked in all three).
//! - The trial's `fsync_dir("/tmp")` and `fsync_dir("/")` fsync the parent of the root.
//! - "Injected" errors (UNJUDGED, exit 0) also include EMFILE and ENOMEM, which this tool
//!   draws for `open`; an injected error opening or reading the ack file is UNJUDGED too
//!   (the trial panicked there); so is one while wiping a partial database.

use fjall::{Database, Keyspace, KeyspaceCreateOptions, PersistMode};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

fn param(name: &str) -> Option<String> {
    std::env::var(format!("FJ_{}", name.to_uppercase())).ok()
}

fn always(cond: bool, name: &str) {
    if !cond {
        eprintln!("INVARIANT {name}");
        std::process::exit(1);
    }
}

fn rand_u64() -> u64 {
    let mut b = [0u8; 8];
    let mut got = 0;
    while got < 8 {
        let r = unsafe { libc::getrandom(b[got..].as_mut_ptr().cast(), 8 - got, 0) };
        if r > 0 {
            got += r as usize;
        } else if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            panic!("getrandom: {}", std::io::Error::last_os_error());
        }
    }
    u64::from_le_bytes(b)
}

/// Buggify sites: activation is decided once per run per site, then each evaluation
/// of an active site fires with probability 250/1000.
fn buggify(site: &str) -> bool {
    use std::collections::HashMap;
    use std::sync::Mutex;
    static ACTIVE: Mutex<Option<HashMap<String, bool>>> = Mutex::new(None);
    if param("buggify").as_deref() != Some("1") {
        return false;
    }
    let active = {
        let mut g = ACTIVE.lock().unwrap();
        let m = g.get_or_insert_with(HashMap::new);
        *m.entry(site.to_string()).or_insert_with(|| rand_u64() % 1000 < 250)
    };
    active && rand_u64() % 1000 < 250
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
    // value length varies with i so blocks/tables vary
    let len = 16 + (i.wrapping_mul(2654435761) % 600) as usize;
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

/// Errnos the fault injector can return (EIO, ENOSPC, EINTR as in the trial, plus EMFILE
/// and ENOMEM, which this tool also draws for `open`): an open that fails with one of
/// these cannot be judged.
fn is_injected_io(d: &str) -> bool {
    ["code: 5,", "code: 28,", "code: 4,", "code: 24,", "code: 12,"].iter().any(|c| d.contains(c))
}

fn unjudged(what: &str, e: std::io::Error) -> ! {
    eprintln!("UNJUDGED {what} hit injected I/O error: {e}");
    std::process::exit(0);
}

/// `invariant`: what an open that fails with a non-injected error violates
/// (`open-after-crash` when recovering a database a crash left, else `reopen-failed`).
fn open(root: &Path, invariant: &str) -> (Database, Keyspace, Keyspace) {
    match try_open(root) {
        Ok(x) => x,
        Err(e) => {
            let d = format!("{e:?}");
            if is_injected_io(&d) {
                // an injected I/O error: this run cannot be judged
                eprintln!("UNJUDGED open hit injected I/O error: {d}");
                std::process::exit(0);
            }
            eprintln!("open db: {d}");
            always(false, invariant);
            unreachable!()
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
                eprintln!("iter: {d}");
                always(false, "iterate-failed");
                unreachable!()
            }
        };
        let k = u64::from_be_bytes(k.as_ref().try_into().expect("8-byte key"));
        out.push((k, v.to_vec()));
    }
    out
}

fn check(root: &Path, recovering: bool) -> usize {
    let acked = read_acked(root);
    let inv = if recovering { "open-after-crash" } else { "reopen-failed" };
    let (db, a, b) = open(root, inv);
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
    always(keys_a == keys_b, "batch-atomic-across-keyspaces");
    let prefix = keys_a.iter().enumerate().all(|(n, k)| *k == n as u64);
    if !prefix {
        eprintln!("A keys not a prefix: {keys_a:?}");
    }
    always(prefix, "recovered-keys-are-prefix");
    let vals_ok = sa.iter().chain(sb.iter()).all(|(k, v)| *v == val(*k));
    always(vals_ok, "recovered-values-correct");
    if let Some(h) = acked {
        let durable = keys_a.len() as u64 > h && keys_b.len() as u64 > h;
        if !durable {
            eprintln!("LOST ACKED: acked through {h}, a has {} b has {}", keys_a.len(), keys_b.len());
        }
        always(durable, "acked-writes-survive");
    }
    // recovery must be stable: reopen again and compare
    let (db2, a2, b2) = open(root, "reopen-failed");
    let sa2 = snapshot(&a2);
    let sb2 = snapshot(&b2);
    always(sa2 == sa && sb2 == sb, "reopen-is-stable");
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
        if i % 7 == 6 || buggify("persist-now") {
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
        if buggify("manual-flush") {
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
            always(have == 100, "fresh-after-wipe-complete");
        }
        println!("wiped and rebuilt 0");
    } else if recovering {
        let have = check(root, true);
        // keep going on the recovered db, then check again
        if !run_workload(root, have as u64, 50) {
            return;
        }
        let have2 = check(root, false);
        always(have2 == have + 50, "post-recovery-writes-land");
        println!("recovered {have} then {have2}");
    } else {
        std::fs::create_dir_all(root).expect("mkdir root");
        fsync_dir(root.parent().unwrap_or(Path::new("/")));
        if !run_workload(root, 0, n) {
            return;
        }
        let have = check(root, false);
        always(have as u64 == n, "clean-run-complete");
        println!("clean run: {have} keys");
    }
}
