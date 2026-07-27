//! Model-based (stateful) property mode for the redb harness.
//!
//! This dogfoods `patina-proptest`'s in-house model-based testing layer against
//! the real redb fork. The reference model is a `BTreeMap` mirror of a single
//! redb table with transaction semantics (a working overlay that `Commit`
//! promotes and `Abort` discards); the system under test is a redb database on
//! the in-memory backend, driven by the same abstract commands. After every
//! command the SUT is checked against the model, both per-command (reads compare
//! to the model) and as a whole-table invariant.
//!
//! Command generation rides on `patina_proptest::runner()`, whose ChaCha RNG is
//! seeded from `patina::rng()`. Under `cargo patina native-run` that means the
//! entire command stream — and therefore the printed digest — is a pure function
//! of the Patina run seed: same seed reproduces it byte-for-byte, a different
//! seed changes it. redb is correct, so the property holds; the value here is a
//! seed-deterministic stateful harness that will carry the upcoming
//! crash-geometry hunt.

use std::cell::Cell;
use std::collections::BTreeMap;

use patina_proptest::prelude::*;
use patina_proptest::state::{execute, StateMachine};
use redb::{Database, ReadableTable, TableDefinition, WriteTransaction};

/// The single table under test.
const TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("kv");

/// Small keyspace so inserts, removes, and range reads frequently overlap.
const KEYSPACE: u64 = 8;

/// An abstract operation against the store, including transaction boundaries.
#[derive(Clone, Debug)]
enum Op {
    Insert(u64, u8),
    Remove(u64),
    Get(u64),
    /// A half-open key range `[lo, hi)`.
    Range(u64, u64),
    Commit,
    Abort,
}

impl Op {
    /// A stable per-command tag folded into the run digest.
    fn digest(&self, mut hash: u64) -> u64 {
        let fold = |hash: u64, byte: u64| (hash ^ byte).wrapping_mul(0x0000_0100_0000_01b3);
        match self {
            Op::Insert(k, v) => hash = fold(fold(fold(hash, 1), *k), u64::from(*v)),
            Op::Remove(k) => hash = fold(fold(hash, 2), *k),
            Op::Get(k) => hash = fold(fold(hash, 3), *k),
            Op::Range(lo, hi) => hash = fold(fold(fold(hash, 4), *lo), *hi),
            Op::Commit => hash = fold(hash, 5),
            Op::Abort => hash = fold(hash, 6),
        }
        hash
    }
}

/// The value stored for a `u8`, a short byte string of a size that varies with
/// the value so the framing exercises differing lengths.
fn value_bytes(v: u8) -> Vec<u8> {
    vec![v; 1 + (v & 3) as usize]
}

/// The reference model: a committed snapshot plus the working overlay a live
/// write transaction sees (read-your-writes until commit/abort).
struct Model {
    committed: BTreeMap<u64, Vec<u8>>,
    working: BTreeMap<u64, Vec<u8>>,
}

/// The system under test: a redb database with one always-open write
/// transaction. `Commit`/`Abort` close it and begin the next.
///
/// Field order is load-bearing: `Database::drop` blocks until every live
/// transaction has finished, so `txn` must be declared before `db` to drop
/// (and abort) first — the reverse order deadlocks the database drop against
/// its own still-open transaction.
struct System {
    txn: Option<WriteTransaction>,
    db: Database,
}

impl System {
    fn txn(&self) -> &WriteTransaction {
        self.txn
            .as_ref()
            .expect("a write transaction is always open")
    }

    /// Snapshot the whole table through the live transaction.
    fn scan(&self) -> Result<BTreeMap<u64, Vec<u8>>, String> {
        let table = self.txn().open_table(TABLE).map_err(err)?;
        let mut got = BTreeMap::new();
        for entry in table.range(0u64..).map_err(err)? {
            let (key, value) = entry.map_err(err)?;
            got.insert(key.value(), value.value().to_vec());
        }
        Ok(got)
    }
}

fn err<E: std::fmt::Display>(error: E) -> String {
    error.to_string()
}

/// The stateful contract binding the redb SUT to the `BTreeMap` model.
struct RedbKv;

impl StateMachine for RedbKv {
    type Command = Op;
    type Model = Model;
    type System = System;

    fn init_model() -> Self::Model {
        Model {
            committed: BTreeMap::new(),
            working: BTreeMap::new(),
        }
    }

    fn init_system() -> Self::System {
        let db = Database::builder()
            .create_with_backend(redb::backends::InMemoryBackend::new())
            .expect("in-memory redb database");
        let txn = db.begin_write().expect("initial write transaction");
        System { db, txn: Some(txn) }
    }

    fn command_strategy() -> BoxedStrategy<Self::Command> {
        // Weighted so data operations dominate transaction boundaries, giving
        // deeper working overlays before each commit/abort.
        prop_oneof![
            4 => (0u64..KEYSPACE, any::<u8>()).prop_map(|(k, v)| Op::Insert(k, v)),
            2 => (0u64..KEYSPACE).prop_map(Op::Remove),
            2 => (0u64..KEYSPACE).prop_map(Op::Get),
            2 => (0u64..KEYSPACE, 0u64..KEYSPACE)
                .prop_map(|(a, b)| Op::Range(a.min(b), a.max(b) + 1)),
            1 => Just(Op::Commit),
            1 => Just(Op::Abort),
        ]
        .boxed()
    }

    fn next(model: &mut Self::Model, command: &Self::Command) {
        match command {
            Op::Insert(k, v) => {
                model.working.insert(*k, value_bytes(*v));
            }
            Op::Remove(k) => {
                model.working.remove(k);
            }
            Op::Commit => model.committed = model.working.clone(),
            Op::Abort => model.working = model.committed.clone(),
            Op::Get(_) | Op::Range(_, _) => {}
        }
    }

    fn apply(
        system: &mut Self::System,
        model: &Self::Model,
        command: &Self::Command,
    ) -> Result<(), String> {
        match command {
            Op::Insert(k, v) => {
                let bytes = value_bytes(*v);
                let mut table = system.txn().open_table(TABLE).map_err(err)?;
                table.insert(*k, bytes.as_slice()).map_err(err)?;
            }
            Op::Remove(k) => {
                let mut table = system.txn().open_table(TABLE).map_err(err)?;
                table.remove(*k).map_err(err)?;
            }
            Op::Get(k) => {
                let table = system.txn().open_table(TABLE).map_err(err)?;
                let got = table.get(*k).map_err(err)?.map(|g| g.value().to_vec());
                let expected = model.working.get(k).cloned();
                if got != expected {
                    return Err(format!("get({k}) sut={got:?} model={expected:?}"));
                }
            }
            Op::Range(lo, hi) => {
                let table = system.txn().open_table(TABLE).map_err(err)?;
                let mut got = Vec::new();
                for entry in table.range(*lo..*hi).map_err(err)? {
                    let (key, value) = entry.map_err(err)?;
                    got.push((key.value(), value.value().to_vec()));
                }
                let expected: Vec<(u64, Vec<u8>)> = model
                    .working
                    .range(*lo..*hi)
                    .map(|(k, v)| (*k, v.clone()))
                    .collect();
                if got != expected {
                    return Err(format!(
                        "range([{lo}, {hi})) sut={got:?} model={expected:?}"
                    ));
                }
            }
            Op::Commit => {
                let txn = system.txn.take().expect("open transaction to commit");
                txn.commit().map_err(err)?;
                system.txn = Some(system.db.begin_write().map_err(err)?);
            }
            Op::Abort => {
                let txn = system.txn.take().expect("open transaction to abort");
                txn.abort().map_err(err)?;
                system.txn = Some(system.db.begin_write().map_err(err)?);
            }
        }
        Ok(())
    }

    fn check_invariants(system: &Self::System, model: &Self::Model) -> Result<(), String> {
        let got = system.scan()?;
        if got == model.working {
            Ok(())
        } else {
            Err(format!(
                "table diverged from model working set: sut has {} keys, model has {}",
                got.len(),
                model.working.len()
            ))
        }
    }
}

/// Run the stateful property against redb and print the seed-deterministic
/// digest line. Returns the process exit code (0 on success; a model/SUT
/// divergence panics with the minimal command sequence, aborting nonzero).
pub fn run_stateful() -> i32 {
    let mut config = patina_proptest::config();
    // A bounded but non-trivial campaign: enough cases and command depth to
    // exercise the commit/abort overlay without a slow in-guest run.
    config.cases = 96;
    let mut runner = patina_proptest::runner_with_config(config);

    let digest = Cell::new(0xcbf2_9ce4_8422_2325_u64);
    let cases = Cell::new(0u64);
    let commands = Cell::new(0u64);

    let strategy = proptest::collection::vec(RedbKv::command_strategy(), 0..=24);
    let outcome = runner.run(&strategy, |sequence| {
        let executed = execute::<RedbKv>(&sequence).map_err(|failure| {
            TestCaseError::fail(format!(
                "{} (minimal: {:?})",
                failure.message, failure.commands
            ))
        })?;
        let mut hash = digest.get();
        for op in &executed {
            hash = op.digest(hash);
        }
        digest.set(hash);
        cases.set(cases.get() + 1);
        commands.set(commands.get() + executed.len() as u64);
        Ok(())
    });

    if let Err(error) = outcome {
        // redb is correct, so this is unexpected: surface it loudly and fail.
        eprintln!("STATEFUL_FAIL {error}");
        return 1;
    }

    println!(
        "STATEFUL_RESULT cases={} commands={} digest={:016x}",
        cases.get(),
        commands.get(),
        digest.get()
    );
    0
}
