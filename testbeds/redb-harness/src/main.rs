//! Deterministic redb workload/oracle for the Patina durability testbed.
//!
//! This is a std-pure + redb binary: no Patina imports, no `cfg(patina)`. The
//! LATER Patina phase runs this same binary, unchanged, under `cargo patina`
//! with the crash-injecting filesystem to hunt durability bugs. Everything the
//! test decides -- the op sequence, the durable-state model, every invariant --
//! lives inside this process and reports through the process exit code and one
//! machine-parseable RESULT line. Shell scripts only orchestrate and compare
//! those lines.
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
                 --mode <write|verify|full> [--threads <n>]"
            );
            std::process::exit(2);
        }
    };

    let outcome = match options.mode {
        RunMode::Write => run_write(&options).map(|summary| summary.result_line(options.seed)),
        RunMode::Verify => run_verify(&options.db).map(|summary| summary.result_line(options.seed)),
        RunMode::Full => run_full(&options).map(|summary| summary.result_line(options.seed)),
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
