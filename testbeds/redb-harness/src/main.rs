//! Deterministic redb workload/oracle for the Patina durability testbed.
//!
//! This is a std-pure + redb binary. Its only cooperative-SUT touch point is a
//! single `patina::lifecycle::setup_complete()` call marking the setup/workload
//! boundary; that macro is a no-op outside a Patina build, so `run-native.sh`
//! builds and behaves exactly as a plain std+redb binary (no `cfg(patina)` in
//! this file). The buggify fault sites themselves live in the vendored redb fork
//! (`../redb-fork`), not here. The Patina phase runs this same binary under
//! `cargo patina` with the crash-injecting filesystem and `--buggify` to hunt
//! durability bugs. Everything the test decides -- the op sequence, the durable-
//! state model, every invariant -- lives inside this process and reports through
//! the process exit code and one machine-parseable RESULT line. Shell scripts
//! only orchestrate and compare those lines.
//!
//! ## Determinism contract
//!
//! Given the same `--seed`, `--ops`, and `--db` layout the op sequence and the
//! committed-state hash are byte-identical run to run: the PRNG is an inline
//! splitmix64, all model containers are ordered (`BTreeMap`/`BTreeSet`), and
//! nothing consults the wall clock or hashes thread timing. The concurrent
//! reader threads never feed the RESULT hash; they only assert an MVCC
//! invariant, so their number and interleaving cannot change the output line.
//!
//! ## RESULT line
//!
//! ```text
//! RESULT seed=<u64> committed=<u64> state=<hex16>
//! ```
//!
//! `committed` counts durable commits (persisted in a meta table so a fresh
//! reopen recovers it); `state` is a 64-bit FNV-1a digest of the durable data
//! tables, printed as 16 lowercase hex chars. The digest excludes the meta
//! table so a commit that changes only the counter still hashes stably.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use redb::{
    Database, ReadTransaction, ReadableDatabase, ReadableTable, ReadableTableMetadata,
    TableDefinition,
};

/// Fallible result carrying a thread-safe boxed error, so worker-thread failures
/// can cross the `JoinHandle` boundary unchanged.
type Fallible<T> = Result<T, Box<dyn Error + Send + Sync>>;

/// The data tables under test. Keys are ordered `u64` (clean ranges), values are
/// opaque byte strings of mixed size. Multiple tables exercise redb's
/// multi-tree commit path in one transaction.
const DATA_TABLE_NAMES: [&str; 4] = ["records", "secondary_index", "blobs", "journal"];
const DATA_TABLES: [TableDefinition<u64, &[u8]>; 4] = [
    TableDefinition::new(DATA_TABLE_NAMES[0]),
    TableDefinition::new(DATA_TABLE_NAMES[1]),
    TableDefinition::new(DATA_TABLE_NAMES[2]),
    TableDefinition::new(DATA_TABLE_NAMES[3]),
];

/// Meta table: durable bookkeeping that is deliberately excluded from the state
/// digest. Key 0 holds the running commit count so `verify` can recover
/// `committed` from a cold reopen.
const META_TABLE: TableDefinition<u64, u64> = TableDefinition::new("__harness_meta");
const META_COMMIT_COUNT_KEY: u64 = 0;

/// Bounded keyspace so updates and deletes frequently hit existing keys instead
/// of only ever appending fresh ones.
const KEYSPACE: u64 = 4096;

/// Key band reserved for the savepoint-rollback exercise so its throwaway
/// writes never collide with the modeled keyspace.
const SAVEPOINT_SCRATCH_BASE: u64 = 1_000_000;

/// Largest value the workload emits (64 KiB), well under redb's limits.
const MAX_VALUE_LEN: usize = 64 * 1024;

// --- Inline splitmix64: a tiny, allocation-free, fully specified PRNG so the
// workload needs no `rand` dependency and reproduces bit-for-bit. ---

struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Value in `[0, n)`; `n` is small here so modulo bias is negligible and,
    /// crucially, identical across runs.
    fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }
}

// --- FNV-1a 64: canonical, order-fixed digest shared by the model and the DB
// so "model == database contents" is a real, checkable equality. ---

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

fn fnv_bytes(mut hash: u64, bytes: &[u8]) -> u64 {
    for &byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

fn fnv_u64(hash: u64, value: u64) -> u64 {
    fnv_bytes(hash, &value.to_le_bytes())
}

/// The in-memory model of what MUST be durable: one ordered map per data table,
/// index-aligned with `DATA_TABLES`.
type Model = Vec<BTreeMap<u64, Vec<u8>>>;

fn empty_model() -> Model {
    (0..DATA_TABLES.len()).map(|_| BTreeMap::new()).collect()
}

/// Digest the model's committed contents. Framing is domain-tagged per table
/// (name, length, then each key/value) so contents cannot migrate between
/// tables without changing the hash.
fn hash_model(model: &Model) -> u64 {
    let mut hash = FNV_OFFSET;
    for (index, table) in model.iter().enumerate() {
        hash = fnv_bytes(hash, DATA_TABLE_NAMES[index].as_bytes());
        hash = fnv_u64(hash, table.len() as u64);
        for (key, value) in table {
            hash = fnv_u64(hash, *key);
            hash = fnv_u64(hash, value.len() as u64);
            hash = fnv_bytes(hash, value);
        }
    }
    hash
}

/// Digest the database's committed contents through a read snapshot, using the
/// exact framing of [`hash_model`]. Any divergence between this and the model
/// is a correctness failure.
fn hash_db(txn: &ReadTransaction) -> Fallible<u64> {
    let mut hash = FNV_OFFSET;
    for (index, definition) in DATA_TABLES.iter().enumerate() {
        let table = txn.open_table(*definition)?;
        hash = fnv_bytes(hash, DATA_TABLE_NAMES[index].as_bytes());
        hash = fnv_u64(hash, table.len()?);
        for entry in table.range(0u64..)? {
            let (key, value) = entry?;
            hash = fnv_u64(hash, key.value());
            let bytes = value.value();
            hash = fnv_u64(hash, bytes.len() as u64);
            hash = fnv_bytes(hash, bytes);
        }
    }
    Ok(hash)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RunMode {
    Write,
    Verify,
    Full,
    Crash,
}

struct Options {
    seed: u64,
    ops: u64,
    db: PathBuf,
    mode: RunMode,
    threads: usize,
}

fn parse_options() -> Result<Options, String> {
    let mut seed = None;
    let mut ops = None;
    let mut db = None;
    let mut mode = None;
    let mut threads = 2usize;

    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        let mut value = || args.next().ok_or_else(|| format!("{flag} requires a value"));
        match flag.as_str() {
            "--seed" => seed = Some(value()?.parse().map_err(|_| "--seed must be a u64")?),
            "--ops" => ops = Some(value()?.parse().map_err(|_| "--ops must be a u64")?),
            "--db" => db = Some(PathBuf::from(value()?)),
            "--mode" => {
                mode = Some(match value()?.as_str() {
                    "write" => RunMode::Write,
                    "verify" => RunMode::Verify,
                    "full" => RunMode::Full,
                    "crash" => RunMode::Crash,
                    other => return Err(format!("unknown --mode {other:?}")),
                });
            }
            "--threads" => {
                let parsed: usize = value()?.parse().map_err(|_| "--threads must be a usize")?;
                if parsed == 0 {
                    return Err("--threads must be at least 1".into());
                }
                threads = parsed;
            }
            other => return Err(format!("unknown argument {other:?}")),
        }
    }

    Ok(Options {
        seed: seed.ok_or("--seed is required")?,
        ops: ops.ok_or("--ops is required")?,
        db: db.ok_or("--db is required")?,
        mode: mode.ok_or("--mode is required")?,
        threads,
    })
}

fn main() {
    let options = match parse_options() {
        Ok(options) => options,
        Err(message) => {
            eprintln!("error: {message}");
            eprintln!(
                "usage: redb-harness --seed <u64> --ops <n> --db <path> \
                 --mode <write|verify|full|crash> [--threads <n>]"
            );
            std::process::exit(2);
        }
    };

    // Crash mode owns its own reporting: it always prints a CRASH line (the
    // recovered state is data, not a pass/fail) and exits with a code that
    // classifies the durability outcome, so it never routes through the
    // Ok/Err RESULT-line path below.
    if options.mode == RunMode::Crash {
        let report = run_crash(&options);
        println!("{}", report.line(options.seed));
        std::process::exit(report.exit_code());
    }

    let outcome = match options.mode {
        RunMode::Write => run_write(&options).map(|summary| summary.result_line(options.seed)),
        RunMode::Verify => run_verify(&options.db).map(|summary| summary.result_line(options.seed)),
        RunMode::Full => run_full(&options).map(|summary| summary.result_line(options.seed)),
        RunMode::Crash => unreachable!("crash mode is handled above"),
    };

    match outcome {
        Ok(line) => println!("{line}"),
        Err(error) => {
            eprintln!(
                "FAIL seed={} mode={}: {error}",
                options.seed,
                mode_name(options.mode)
            );
            std::process::exit(1);
        }
    }
}

fn mode_name(mode: RunMode) -> &'static str {
    match mode {
        RunMode::Write => "write",
        RunMode::Verify => "verify",
        RunMode::Full => "full",
        RunMode::Crash => "crash",
    }
}

/// The observable result of a run: everything the RESULT line reports.
struct Summary {
    committed: u64,
    state: u64,
}

impl Summary {
    fn result_line(&self, seed: u64) -> String {
        format!(
            "RESULT seed={seed} committed={} state={:016x}",
            self.committed, self.state
        )
    }
}

/// Derive the commit interval from the seed so different seeds batch ops
/// differently (4..=16 ops per commit), while a fixed seed is stable.
fn commit_interval(seed: u64) -> u64 {
    4 + (seed % 13)
}

/// Build one workload value: mostly small (1..=256 B), occasionally large (up
/// to 64 KiB), filled from a deterministic byte stream.
fn generate_value(rng: &mut SplitMix64) -> Vec<u8> {
    let large = rng.below(8) == 0;
    let len = if large {
        1 + (rng.next_u64() as usize % MAX_VALUE_LEN)
    } else {
        1 + (rng.next_u64() as usize % 256)
    };
    let mut value = vec![0u8; len];
    let mut lane = rng.next_u64();
    for chunk in value.chunks_mut(8) {
        lane = lane
            .wrapping_mul(0x5851_F42D_4C95_7F2D)
            .wrapping_add(0x1405_7B7E_F767_814F);
        let bytes = lane.to_le_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }
    value
}

/// Run the seeded write workload against `db`, keeping the durable model in
/// step and (when `threads > 1`) running concurrent snapshot readers that
/// assert the MVCC no-torn-read invariant. Returns the durable summary.
fn run_write(options: &Options) -> Fallible<Summary> {
    let database = Arc::new(Database::create(&options.db)?);
    let mut rng = SplitMix64::new(options.seed);
    let interval = commit_interval(options.seed);

    let mut model = empty_model();
    let mut committed: u64 = 0;

    // Set of every hash a committed snapshot may legitimately expose. Readers
    // assert their observation is a member; a hash is published *before* its
    // commit so the set is always a superset of what is observable, making a
    // reader-side false positive impossible.
    let published: Arc<Mutex<BTreeSet<u64>>> = Arc::new(Mutex::new(BTreeSet::new()));

    // Baseline commit: materialize every table (so all read snapshots find
    // them) and record the empty state.
    publish(&published, hash_model(&model));
    {
        let write = database.begin_write()?;
        for definition in DATA_TABLES.iter() {
            write.open_table(*definition)?;
        }
        write_commit_count(&write, committed + 1)?;
        write.commit()?;
        committed += 1;
    }

    // Exercise savepoint/restore before readers start: a throwaway mutation is
    // rolled back to the baseline, and the database must hash back to the
    // committed model. This runs while single-threaded so it cannot race.
    savepoint_exercise(&database, &model)?;

    // Setup (create + baseline + savepoint) is done. Under a Patina buggify run
    // with --buggify-after-setup, cooperative faults in redb's commit/recovery
    // paths stay inert until here, so DB creation is fault-free and the workload
    // commits below are what get perturbed. A no-op outside a Patina build.
    patina::lifecycle::setup_complete();

    // Spawn snapshot readers: one writer plus `threads - 1` readers.
    let done = Arc::new(AtomicBool::new(false));
    let mut readers = Vec::new();
    for _ in 1..options.threads {
        let database = Arc::clone(&database);
        let published = Arc::clone(&published);
        let done = Arc::clone(&done);
        readers.push(thread::spawn(move || {
            reader_loop(&database, &published, &done)
        }));
    }

    // Main writer loop: batches of `interval` ops per transaction.
    let mut applied: u64 = 0;
    while applied < options.ops {
        let group_end = (applied + interval).min(options.ops);
        let write = database.begin_write()?;
        {
            let mut tables = DATA_TABLES
                .iter()
                .map(|definition| write.open_table(*definition))
                .collect::<Result<Vec<_>, _>>()?;
            while applied < group_end {
                apply_op(&mut rng, &mut tables, &mut model)?;
                applied += 1;
            }
        }
        let next_count = committed + 1;
        write_commit_count(&write, next_count)?;
        // Publish before commit so the state is visible to readers only after
        // it is already a member of the set.
        publish(&published, hash_model(&model));
        write.commit()?;
        committed = next_count;
    }

    // Stop readers and surface the first invariant violation, if any.
    done.store(true, Ordering::Release);
    for reader in readers {
        reader.join().map_err(|_| "reader thread panicked")??;
    }

    let state = hash_model(&model);
    // Cross-check the model against the freshly-committed database in-process.
    let read = database.begin_read()?;
    let db_state = hash_db(&read)?;
    if db_state != state {
        return Err(format!(
            "write-model hash {state:016x} != in-process db hash {db_state:016x}"
        )
        .into());
    }

    Ok(Summary { committed, state })
}

/// Apply a single seeded operation to both the open tables and the model.
/// Range reads additionally cross-check redb's read-your-writes view against
/// the model inside the live transaction.
fn apply_op(
    rng: &mut SplitMix64,
    tables: &mut [redb::Table<u64, &'static [u8]>],
    model: &mut Model,
) -> Fallible<()> {
    let table_index = (rng.next_u64() as usize) % tables.len();
    let key = rng.below(KEYSPACE);
    match rng.below(10) {
        0..=5 => {
            let value = generate_value(rng);
            tables[table_index].insert(key, value.as_slice())?;
            model[table_index].insert(key, value);
        }
        6..=7 => {
            tables[table_index].remove(key)?;
            model[table_index].remove(&key);
        }
        _ => {
            let span = 1 + rng.below(64);
            let hi = key.saturating_add(span);
            let mut db_hash = FNV_OFFSET;
            for entry in tables[table_index].range(key..hi)? {
                let (entry_key, entry_value) = entry?;
                db_hash = fnv_u64(db_hash, entry_key.value());
                db_hash = fnv_bytes(db_hash, entry_value.value());
            }
            let mut model_hash = FNV_OFFSET;
            for (entry_key, entry_value) in model[table_index].range(key..hi) {
                model_hash = fnv_u64(model_hash, *entry_key);
                model_hash = fnv_bytes(model_hash, entry_value);
            }
            if db_hash != model_hash {
                return Err(format!(
                    "range read [{key}, {hi}) on {} diverged from the model",
                    DATA_TABLE_NAMES[table_index]
                )
                .into());
            }
        }
    }
    Ok(())
}

/// Persist the running commit counter into the meta table (excluded from the
/// state digest) so a cold `verify` can recover `committed`.
fn write_commit_count(write: &redb::WriteTransaction, count: u64) -> Fallible<()> {
    let mut meta = write.open_table(META_TABLE)?;
    meta.insert(META_COMMIT_COUNT_KEY, count)?;
    Ok(())
}

fn publish(published: &Mutex<BTreeSet<u64>>, hash: u64) {
    published
        .lock()
        .expect("published-state lock is never poisoned by a panicking holder")
        .insert(hash);
}

/// Take an ephemeral savepoint, apply throwaway writes, restore, commit, and
/// assert the database hashes back to the committed model -- exercising redb's
/// savepoint/restore path with a checkable invariant.
fn savepoint_exercise(database: &Database, model: &Model) -> Fallible<()> {
    let expected = hash_model(model);
    let mut write = database.begin_write()?;
    let savepoint = write.ephemeral_savepoint()?;
    {
        let mut table = write.open_table(DATA_TABLES[0])?;
        for offset in 0..5u64 {
            table.insert(SAVEPOINT_SCRATCH_BASE + offset, [0xABu8; 32].as_slice())?;
        }
    }
    write.restore_savepoint(&savepoint)?;
    drop(savepoint);
    write.commit()?;

    let read = database.begin_read()?;
    let restored = hash_db(&read)?;
    if restored != expected {
        return Err(format!(
            "savepoint restore left db hash {restored:016x}, expected committed {expected:016x}"
        )
        .into());
    }
    Ok(())
}

/// A snapshot reader: repeatedly opens read transactions and asserts each
/// observed committed state is one the writer published. A hash outside the
/// published set is a torn/uncommitted observation -- a reportable MVCC bug.
/// Returns the number of complete snapshots read.
fn reader_loop(
    database: &Database,
    published: &Mutex<BTreeSet<u64>>,
    done: &AtomicBool,
) -> Fallible<u64> {
    let mut snapshots = 0u64;
    loop {
        let finishing = done.load(Ordering::Acquire);
        let read = database.begin_read()?;
        let observed = hash_db(&read)?;
        {
            let set = published
                .lock()
                .expect("published-state lock is never poisoned by a panicking holder");
            if !set.contains(&observed) {
                return Err(
                    format!("reader observed uncommitted/torn state hash {observed:016x}").into(),
                );
            }
        }
        snapshots += 1;
        // Take one final snapshot after `done` so the last committed state is
        // always checked, then stop.
        if finishing {
            return Ok(snapshots);
        }
    }
}

/// Reopen the database cold, run redb's integrity check, walk every table, and
/// recompute the committed state hash. Fails on any integrity or read error.
fn run_verify(path: &Path) -> Fallible<Summary> {
    let mut database = Database::open(path)?;
    // `Ok(true)` clean, `Ok(false)` failed-but-repaired, `Err` unrepairable.
    // On a native (crash-free) run we require a clean check; the Patina crash
    // phase will relax this to accept a documented repair.
    if !database.check_integrity()? {
        return Err("integrity check reported the database was not clean (repaired)".into());
    }

    let read = database.begin_read()?;
    let state = hash_db(&read)?;
    let committed = read
        .open_table(META_TABLE)?
        .get(META_COMMIT_COUNT_KEY)?
        .map(|guard| guard.value())
        .ok_or("meta table is missing the commit count")?;

    Ok(Summary { committed, state })
}

/// Write, drop the database handle, then verify in-process, asserting the write
/// and verify hashes (and commit counts) agree.
fn run_full(options: &Options) -> Fallible<Summary> {
    let write_summary = run_write(options)?;
    let verify_summary = run_verify(&options.db)?;
    if write_summary.state != verify_summary.state {
        return Err(format!(
            "full-mode mismatch: write state {:016x} != verify state {:016x}",
            write_summary.state, verify_summary.state
        )
        .into());
    }
    if write_summary.committed != verify_summary.committed {
        return Err(format!(
            "full-mode mismatch: write committed {} != verify committed {}",
            write_summary.committed, verify_summary.committed
        )
        .into());
    }
    Ok(verify_summary)
}

// --- Crash mode: the durability oracle under injected crashes -------------
//
// Native `full` mode asserts write == verify because no crash occurs. Under
// Patina's `--fs-crash-at`, the crash drops unsynced data and invalidates
// redb's open file handles, so the write workload stops with a redb I/O error
// partway through, and reopening the same in-memory image exposes whatever redb
// made durable. This mode runs the write workload and the cold reopen in ONE
// process (the in-memory crash filesystem does not survive a process exit),
// then judges the recovered state against the committed-PREFIX oracle:
//
//   * Every commit whose `commit()` RETURNED before the crash was fsynced
//     (Durability::Immediate), so the recovered commit count must be >= that
//     last acknowledged count -- losing one is a real durability bug.
//   * The recovered (count, state) must be exactly one legitimately published
//     committed prefix -- a state that was never a real prefix is torn,
//     reordered, or phantom, also a real bug.
//   * redb may instead panic or return Err while opening a sufficiently damaged
//     image; those are robustness outcomes, distinguished and reported, not
//     conflated with a lost commit.

/// Why the write workload stopped. A redb-origin error is the injected crash
/// (its handles went stale); a harness-invariant violation is a genuine
/// pre-crash correctness bug that must never be silently reclassified.
enum WriteStop {
    Crashed,
    Invariant(String),
}

/// The recovered-state classification a crash run reports.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum CrashOutcome {
    /// The configured crash never fired; the workload completed and the reopen
    /// reproduced the full write state (native runs always land here).
    NoCrash,
    /// Reopen succeeded and exposed a legitimate committed prefix that kept
    /// every acknowledged commit -- durability held.
    Holds,
    /// Reopen succeeded but lost a commit redb had acknowledged durable.
    LostCommit,
    /// Reopen succeeded but exposed a state that was never a published prefix.
    TornState,
    /// `Database::open` (or the integrity check) returned `Err` on the image.
    OpenErr,
    /// `Database::open` panicked on the image (redb's internal recovery assert).
    OpenPanic,
}

impl CrashOutcome {
    fn label(self) -> &'static str {
        match self {
            CrashOutcome::NoCrash => "NO_CRASH",
            CrashOutcome::Holds => "HOLDS",
            CrashOutcome::LostCommit => "LOST_COMMIT",
            CrashOutcome::TornState => "TORN_STATE",
            CrashOutcome::OpenErr => "OPEN_ERR",
            CrashOutcome::OpenPanic => "OPEN_PANIC",
        }
    }
}

/// Everything a crash run reports on its single CRASH line.
struct CrashReport {
    outcome: CrashOutcome,
    crashed: bool,
    ack: u64,
    recovered: Option<u64>,
    state: Option<u64>,
    integrity: &'static str,
    detail: String,
}

impl CrashReport {
    fn line(&self, seed: u64) -> String {
        let recovered = self
            .recovered
            .map_or_else(|| "-".to_string(), |value| value.to_string());
        let state = self
            .state
            .map_or_else(|| "-".to_string(), |value| format!("{value:016x}"));
        format!(
            "CRASH seed={seed} crashed={} ack={} recovered={recovered} state={state} \
             integrity={} outcome={} detail={}",
            u8::from(self.crashed),
            self.ack,
            self.integrity,
            self.outcome.label(),
            self.detail
        )
    }

    /// Exit code partitions outcomes for scripts: 0 = durability held or no
    /// crash; 3 = a real redb durability bug (the jackpot -- run-patina.sh must
    /// fail on it); 4 = redb refused to open; 5 = redb panicked; 1 = a
    /// pre-crash harness-invariant violation.
    fn exit_code(&self) -> i32 {
        match self.outcome {
            CrashOutcome::NoCrash | CrashOutcome::Holds => 0,
            CrashOutcome::LostCommit | CrashOutcome::TornState => 3,
            CrashOutcome::OpenErr => 4,
            CrashOutcome::OpenPanic => 5,
        }
    }
}

/// Run the seeded write workload single-threaded, recording the ordered set of
/// legitimately-committed prefixes, then reopen the (possibly crashed) image
/// cold and classify the recovered state. `--threads` is ignored here: MVCC
/// readers would themselves fault on the crash and muddy the durability signal
/// (they are exercised separately, crash-free).
fn run_crash(options: &Options) -> CrashReport {
    // Every (commit_count -> committed model hash) redb could legitimately
    // expose after recovery. Published just before each commit, mirroring
    // `run_write`, so an in-flight commit's target is included. Seed the
    // pre-baseline empty prefix (committed 0) up front so that even a crash
    // injected *inside* `Database::create` -- before the workload can record
    // anything -- still recognizes redb recovering to an empty database as the
    // legitimate committed-0 prefix rather than a torn state.
    let mut published: BTreeMap<u64, u64> = BTreeMap::new();
    published.insert(0, hash_model(&empty_model()));
    // The last commit whose `commit()` RETURNED -- fsynced and acknowledged.
    let mut ack: u64 = 0;

    let stop = drive_crash_workload(options, &mut published, &mut ack);
    if let Some(WriteStop::Invariant(message)) = &stop {
        // A correctness violation observed BEFORE any crash is a real bug, not a
        // durability outcome; surface it like any harness failure.
        eprintln!("FAIL seed={} mode=crash: {message}", options.seed);
        std::process::exit(1);
    }
    let crashed = matches!(stop, Some(WriteStop::Crashed));

    // Reopen cold. `Database::open` can panic on a damaged image before
    // `check_integrity` runs, so guard it with `catch_unwind` and a silenced
    // hook to keep the sweep output to one line per run.
    let previous_hook = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));
    let opened = panic::catch_unwind(AssertUnwindSafe(|| reopen_and_read(&options.db)));
    panic::set_hook(previous_hook);

    match opened {
        Err(_) => CrashReport {
            outcome: CrashOutcome::OpenPanic,
            crashed,
            ack,
            recovered: None,
            state: None,
            integrity: "panic",
            detail: "Database::open panicked on the crashed image".to_string(),
        },
        Ok(Err(error)) => CrashReport {
            outcome: CrashOutcome::OpenErr,
            crashed,
            ack,
            recovered: None,
            state: None,
            integrity: "error",
            detail: sanitize(&error.to_string()),
        },
        Ok(Ok(recovery)) => classify_recovery(recovery, crashed, ack, &published),
    }
}

/// The successful outcome of a cold reopen: integrity verdict plus the recovered
/// commit count and state hash.
struct Recovery {
    integrity: &'static str,
    committed: u64,
    state: u64,
}

/// Reopen the database cold and read back the recovered committed count and
/// state hash. Unlike native `verify`, a repaired (`Ok(false)`) integrity check
/// is a legitimate post-crash result and is reported, not rejected.
///
/// The read is deliberately LENIENT about missing tables: a crash injected
/// before the baseline commit became durable leaves redb with a valid but
/// table-less database (`committed = 0`, empty state). That is durability
/// holding when nothing was acknowledged, not a read failure -- so an absent
/// harness table hashes as empty and an absent meta table reads as `0`, exactly
/// mirroring the pre-baseline model. A genuine `Database::open` refusal still
/// propagates as `Err` (→ `OPEN_ERR`), and a non-absent read error still fails.
fn reopen_and_read(path: &Path) -> Fallible<Recovery> {
    let mut database = Database::open(path)?;
    let integrity = if database.check_integrity()? {
        "clean"
    } else {
        "repaired"
    };
    let read = database.begin_read()?;
    let state = hash_db_lenient(&read)?;
    let committed = match read.open_table(META_TABLE) {
        Ok(meta) => meta
            .get(META_COMMIT_COUNT_KEY)?
            .map(|guard| guard.value())
            .unwrap_or(0),
        Err(redb::TableError::TableDoesNotExist(_)) => 0,
        Err(other) => return Err(other.into()),
    };
    Ok(Recovery {
        integrity,
        committed,
        state,
    })
}

/// Digest the database like [`hash_db`], but treat a table that does not exist
/// as an empty table (matching [`hash_model`]'s framing for an empty map). This
/// is what makes a pre-baseline crashed image hash equal to the empty model.
fn hash_db_lenient(txn: &ReadTransaction) -> Fallible<u64> {
    let mut hash = FNV_OFFSET;
    for (index, definition) in DATA_TABLES.iter().enumerate() {
        hash = fnv_bytes(hash, DATA_TABLE_NAMES[index].as_bytes());
        match txn.open_table(*definition) {
            Ok(table) => {
                hash = fnv_u64(hash, table.len()?);
                for entry in table.range(0u64..)? {
                    let (key, value) = entry?;
                    hash = fnv_u64(hash, key.value());
                    let bytes = value.value();
                    hash = fnv_u64(hash, bytes.len() as u64);
                    hash = fnv_bytes(hash, bytes);
                }
            }
            Err(redb::TableError::TableDoesNotExist(_)) => {
                hash = fnv_u64(hash, 0);
            }
            Err(other) => return Err(other.into()),
        }
    }
    Ok(hash)
}

/// Apply the committed-prefix durability oracle to a successful reopen.
fn classify_recovery(
    recovery: Recovery,
    crashed: bool,
    ack: u64,
    published: &BTreeMap<u64, u64>,
) -> CrashReport {
    let Recovery {
        integrity,
        committed,
        state,
    } = recovery;
    let is_published_prefix = published.get(&committed) == Some(&state);
    let outcome = if !is_published_prefix {
        // A recovered state that was never a legitimate committed prefix: torn,
        // reordered, or phantom data.
        CrashOutcome::TornState
    } else if committed < ack {
        // redb lost a commit it had acknowledged durable.
        CrashOutcome::LostCommit
    } else if !crashed && committed == ack {
        CrashOutcome::NoCrash
    } else {
        CrashOutcome::Holds
    };
    let detail = format!("prefix={} ack={ack}", u8::from(is_published_prefix));
    CrashReport {
        outcome,
        crashed,
        ack,
        recovered: Some(committed),
        state: Some(state),
        integrity,
        detail,
    }
}

/// Replace whitespace runs in an error string so it stays a single
/// space-delimited field on the CRASH line.
fn sanitize(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join("_")
}

/// Drive the seeded write workload single-threaded, publishing every committed
/// prefix and advancing `ack` on each returned commit. Returns `None` if the
/// workload completed with no crash, or the reason it stopped.
fn drive_crash_workload(
    options: &Options,
    published: &mut BTreeMap<u64, u64>,
    ack: &mut u64,
) -> Option<WriteStop> {
    let result = (|| -> Result<(), WriteStop> {
        let database = Database::create(&options.db).map_err(crashed)?;
        let mut rng = SplitMix64::new(options.seed);
        let interval = commit_interval(options.seed);
        let mut model = empty_model();
        let mut committed: u64 = 0;

        // Baseline commit: materialize the tables and record the empty prefix.
        // (The committed-0 pre-baseline prefix is pre-seeded by the caller.)
        published.insert(committed + 1, hash_model(&model));
        {
            let write = database.begin_write().map_err(crashed)?;
            for definition in DATA_TABLES.iter() {
                write.open_table(*definition).map_err(crashed)?;
            }
            write_commit_count(&write, committed + 1).map_err(|_| WriteStop::Crashed)?;
            write.commit().map_err(crashed)?;
            committed += 1;
            *ack = committed;
        }

        // Savepoint/restore, crash-catching: a fault here is the injected crash,
        // not a savepoint bug (savepoint correctness is covered by native full).
        savepoint_exercise(&database, &model).map_err(|_| WriteStop::Crashed)?;

        // Setup done: gate cooperative (buggify) faults to the workload commits
        // below under --buggify-after-setup. No-op outside a Patina build.
        patina::lifecycle::setup_complete();

        let mut applied: u64 = 0;
        while applied < options.ops {
            let group_end = (applied + interval).min(options.ops);
            let write = database.begin_write().map_err(crashed)?;
            {
                let mut tables = DATA_TABLES
                    .iter()
                    .map(|definition| write.open_table(*definition))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(crashed)?;
                while applied < group_end {
                    apply_op_crash(&mut rng, &mut tables, &mut model)?;
                    applied += 1;
                }
            }
            let next_count = committed + 1;
            write_commit_count(&write, next_count).map_err(|_| WriteStop::Crashed)?;
            // Publish before commit so a recovered in-flight state is a member.
            published.insert(next_count, hash_model(&model));
            write.commit().map_err(crashed)?;
            committed = next_count;
            *ack = committed;
        }
        Ok(())
    })();
    result.err()
}

/// Any redb-origin error is the injected crash: its handle went stale.
fn crashed<E>(_error: E) -> WriteStop {
    WriteStop::Crashed
}

/// Crash-aware [`apply_op`]: redb errors become `Crashed` (the injected crash
/// invalidated the handle) while a model divergence becomes `Invariant` (a real
/// read-your-writes bug that must not be hidden by the crash reclassification).
fn apply_op_crash(
    rng: &mut SplitMix64,
    tables: &mut [redb::Table<u64, &'static [u8]>],
    model: &mut Model,
) -> Result<(), WriteStop> {
    let table_index = (rng.next_u64() as usize) % tables.len();
    let key = rng.below(KEYSPACE);
    match rng.below(10) {
        0..=5 => {
            let value = generate_value(rng);
            tables[table_index]
                .insert(key, value.as_slice())
                .map_err(crashed)?;
            model[table_index].insert(key, value);
        }
        6..=7 => {
            tables[table_index].remove(key).map_err(crashed)?;
            model[table_index].remove(&key);
        }
        _ => {
            let span = 1 + rng.below(64);
            let hi = key.saturating_add(span);
            let mut db_hash = FNV_OFFSET;
            for entry in tables[table_index].range(key..hi).map_err(crashed)? {
                let (entry_key, entry_value) = entry.map_err(crashed)?;
                db_hash = fnv_u64(db_hash, entry_key.value());
                db_hash = fnv_bytes(db_hash, entry_value.value());
            }
            let mut model_hash = FNV_OFFSET;
            for (entry_key, entry_value) in model[table_index].range(key..hi) {
                model_hash = fnv_u64(model_hash, *entry_key);
                model_hash = fnv_bytes(model_hash, entry_value);
            }
            if db_hash != model_hash {
                return Err(WriteStop::Invariant(format!(
                    "range read [{key}, {hi}) on {} diverged from the model",
                    DATA_TABLE_NAMES[table_index]
                )));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Positive control for the durability oracle: prove `classify_recovery`
    // actually fires LOST_COMMIT and TORN_STATE, so the campaign's "zero
    // durability violations across N runs" is a real negative, not a detector
    // that can never trip. A published prefix set with three acknowledged
    // commits (0=empty, 1=stateA, 2=stateB) stands in for a real run.
    fn published() -> BTreeMap<u64, u64> {
        let mut map = BTreeMap::new();
        map.insert(0, 0xE0);
        map.insert(1, 0xA1);
        map.insert(2, 0xB2);
        map
    }

    fn recovery(committed: u64, state: u64) -> Recovery {
        Recovery {
            integrity: "clean",
            committed,
            state,
        }
    }

    #[test]
    fn oracle_accepts_a_committed_prefix_that_keeps_every_ack() {
        // Crash acked commit 2; redb recovers exactly commit 2 -> HOLDS.
        let report = classify_recovery(recovery(2, 0xB2), true, 2, &published());
        assert_eq!(report.outcome, CrashOutcome::Holds);
        // Crash acked commit 2; redb recovers an OLDER valid prefix (1) that is
        // still >= a LOWER ack (1) -> HOLDS (a legitimate shorter prefix).
        let report = classify_recovery(recovery(1, 0xA1), true, 1, &published());
        assert_eq!(report.outcome, CrashOutcome::Holds);
    }

    #[test]
    fn oracle_flags_a_lost_acknowledged_commit() {
        // ack=2 but redb only recovered commit 1 (a real, valid prefix) -- an
        // acknowledged durable commit was lost. LOST_COMMIT, exit code 3.
        let report = classify_recovery(recovery(1, 0xA1), true, 2, &published());
        assert_eq!(report.outcome, CrashOutcome::LostCommit);
        assert_eq!(report.exit_code(), 3);
    }

    #[test]
    fn oracle_flags_a_state_that_was_never_a_published_prefix() {
        // redb reports committed=2 but with a state hash that is NOT the
        // published commit-2 state: torn, reordered, or phantom. TORN_STATE.
        let report = classify_recovery(recovery(2, 0xDEAD), true, 2, &published());
        assert_eq!(report.outcome, CrashOutcome::TornState);
        assert_eq!(report.exit_code(), 3);
        // A right count with a right-but-mismatched-count state also tears:
        // commit-1's state reported under count 2.
        let report = classify_recovery(recovery(2, 0xA1), true, 2, &published());
        assert_eq!(report.outcome, CrashOutcome::TornState);
    }

    #[test]
    fn oracle_reports_no_crash_when_nothing_fired() {
        // The crash never fired and redb kept the full acked state.
        let report = classify_recovery(recovery(2, 0xB2), false, 2, &published());
        assert_eq!(report.outcome, CrashOutcome::NoCrash);
        assert_eq!(report.exit_code(), 0);
    }
}
