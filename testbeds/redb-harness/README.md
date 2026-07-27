# redb durability testbed

A deterministic workload/oracle for [redb](https://crates.io/crates/redb)
`=4.1.0`, built to be run first natively (this change) and later, unchanged,
under [Patina](../../ARCHITECTURE.md) with the crash-injecting filesystem
(`crates/patina-fs-crash`) to hunt durability bugs.

The harness is a standalone Cargo package with its own empty `[workspace]`
table, so it is **not** part of the root Patina workspace and `cargo` here never
touches `crates/` or the root manifest. Its only dependency is `redb` itself: the
PRNG is an inline splitmix64 and the state digest is a hand-rolled FNV-1a, so the
code under test is redb and redb alone.

## The one-line Patina swap

Every invariant and assertion lives **inside** the binary, which exits non-zero
on any violation. Shell scripts only orchestrate runs and compare the RESULT
lines. The whole design turns on this: the native and Patina phases run the
*same binary with the same program args*, and only the runner changes.

```sh
# native (run-native.sh)
RUNNER=(cargo run --release --)

# Patina (run-patina.sh, an untested sketch)
RUNNER=(cargo patina native-run "$built_bin")
```

## CLI

```
redb-harness --seed <u64> --ops <n> --db <path> --mode <write|verify|full> [--threads <n>]
```

- `--seed` seeds the workload PRNG; identical seeds produce identical op
  sequences and identical RESULT lines.
- `--ops` is the number of workload operations before the final commit.
- `--db` is the database file path.
- `--mode`:
  - `write` — run the seeded workload, committing every K ops (K derived from
    the seed), and print the RESULT line for the durable state.
  - `verify` — reopen the db cold, run redb's integrity check, walk every table,
    recompute the state hash, and print the RESULT line. Exits non-zero on any
    integrity failure or unreadable table.
  - `full` — `write`, drop the `Database` handle, then `verify` in-process, and
    assert the write hash equals the verify hash.
- `--threads` (default 2) — one writer plus `threads - 1` concurrent snapshot
  readers (see the MVCC invariant below).

## RESULT line contract

Machine-parseable, one per successful run, on stdout:

```
RESULT seed=<u64> committed=<u64> state=<hex16>
```

- `committed` — number of durable commits. It is persisted inside the database
  (a dedicated `__harness_meta` table, key 0) so a cold `verify` recovers the
  same value a fresh reopen would never otherwise know.
- `state` — a 64-bit FNV-1a digest of the durable **data** tables, as 16
  lowercase hex chars. The digest is framed per table (name, entry count, then
  each key with its value length and bytes) so contents cannot silently migrate
  between tables. The `__harness_meta` table is **excluded** from the digest, so
  a commit that changes only the counter still hashes stably.

Any failure prints `FAIL seed=<s> mode=<m>: <reason>` to stderr and exits 1
(bad arguments exit 2). Scripts treat a missing RESULT line / non-zero exit as a
failure.

## Workload

The seeded op stream runs against four named data tables
(`records`, `secondary_index`, `blobs`, `journal`), keyed by `u64` over a bounded
keyspace (so updates and deletes frequently hit existing keys), with a mix of:

- inserts and updates (overwrites),
- deletes,
- ranged reads that are **cross-checked against the model** inside the live
  transaction (a redb read-your-writes divergence fails the run),
- mixed value sizes from 1 B up to 64 KiB (occasional large values),
- explicit commits every K ops, with the commit count persisted each commit,
- a **savepoint/restore** exercise: an ephemeral savepoint is taken, throwaway
  writes are applied to a reserved key band, the savepoint is restored, the
  transaction is committed, and the database must hash back to the committed
  model (a savepoint-restore bug fails the run).

## Invariants enforced inside the binary

1. **Model equivalence.** An in-memory `BTreeMap` model tracks exactly what must
   be durable after each commit. `write` recomputes the database hash in-process
   and asserts it equals the model hash; `full` asserts write hash == cold
   verify hash.
2. **Read-your-writes.** Every ranged read inside a write transaction matches
   the model's view of that same range.
3. **Savepoint restore.** Restoring an ephemeral savepoint returns the database
   to the exact committed state.
4. **Integrity.** `verify` runs redb's `check_integrity`; on a native
   (crash-free) run it must report clean.
5. **MVCC snapshot isolation (concurrent).** While the single writer commits,
   `threads - 1` reader threads repeatedly open read transactions, hash the
   snapshot, and assert the observed hash is one the writer *published*. A hash
   is published before its commit, so the published set is always a superset of
   the observable states; a reader observing anything outside it is a torn or
   uncommitted read and fails the run. The published set covers committed data
   only, so reader count and timing never affect the RESULT line.

## Determinism

Same seed → identical op sequence and identical RESULT line, run to run and
regardless of `--threads`:

- the PRNG is a fully specified inline splitmix64;
- all model containers are ordered (`BTreeMap` / `BTreeSet`) — no `HashMap`
  iteration order;
- nothing reads the wall clock or folds thread timing into the state;
- the reader threads only *assert*; they never feed the RESULT hash.

## Running natively

```sh
./run-native.sh
```

It builds the release binary and checks: `full` mode is deterministic across
fresh databases; a cold `verify` reproduces the `write` RESULT line; thread
count does not change the RESULT; and a 5-seed sweep is per-seed reproducible
and cross-seed distinct.

## Patina-phase plan (crash testing)

`run-patina.sh` is an **untested sketch** of the next phase. The design:

- **Same binary, same args.** `cargo patina native-build` compiles this package
  under `cfg(patina)`/`cfg(dst)` with the native shim linked, and
  `cargo patina native-run` executes it with std::fs routed through the
  deterministic, crash-injecting filesystem and std::thread through the
  deterministic scheduler.
- **Crash points.** The Patina seed selects crash points *between and inside*
  redb commits, plus torn-write and directory-durability decisions in `CrashFs`
  (see `crates/patina-fs-crash`). redb's fsync/rename/`set_len` calls become the
  fault boundaries.
- **Reopen invariant (prefix consistency).** After an injected crash, reopening
  the database must expose a committed state that is a **prefix** of the writer's
  commit history — redb must never surface a partial, torn, or reordered commit.
  The harness already computes a per-commit hash for every committed state; the
  crash phase will have `verify` assert the recovered hash is one of those
  published commit hashes rather than requiring strict equality with the final
  write hash (which native `full` mode uses because no crash occurs).

### What the crash phase still needs (honest gaps)

- **Persisting the published commit hashes across the crash boundary.** Today
  the per-commit hash set lives in memory during `write` and is dropped
  afterward; native `full` mode instead asserts strict write == verify equality.
  Under crash injection the final model may be ahead of what is durable, so the
  crash phase must hand `verify` the ordered list of legitimate commit-prefix
  hashes (e.g. via a side file the harness writes, or by re-deriving them from
  the seed in the same process before the injected crash).
- **`check_integrity` after a crash.** `Ok(false)` (failed-but-repaired) is a
  legitimate post-crash outcome, not the clean `Ok(true)` native requires; the
  crash phase must decide which repairs are acceptable and which indicate a bug.
- **Open-time panics on a damaged file.** redb 4.1.0 can hit an internal
  `assert!` inside `Database::open` (page-manager recovery,
  `assertion failed: !self.needs_recovery`) on a sufficiently corrupted image —
  *before* `check_integrity` can even be called. It is a panic, not an `Err`, so
  the harness cannot catch it as a normal error; the `panic = "unwind"` profile
  keeps it a clean non-zero exit (101). The crash phase must treat such a panic
  (or an abort) as a reportable oracle failure, and reopen through
  `Database::open` inside the fault harness rather than assuming a `Result`.

## redb 4.1.0 syscall-level behavior the Patina shim must model

The Patina filesystem shim must faithfully model how redb 4.1.0 actually touches
the file for the crash injection to be meaningful. Verified against the pinned
source in the crates.io registry cache (redb-4.1.0,
`src/tree_store/page_store/file_backend/optimized.rs`), redb's `StorageBackend`
is offset-addressed with these five operations — `len`, `read(offset, out)`,
`write(offset, data)`, `set_len(len)`, `sync_data()` — over a `std::fs::File`,
so the shim must model, at minimum:

- **`fsync` semantics** — redb's `sync_data()` calls `File::sync_data`
  (`fdatasync`, i.e. data + the metadata needed to read it back, **not** a full
  `fsync`/`sync_all`). The crash model's fsync boundary must map to redb's commit
  points, and torn writes must apply to blocks not yet synced.
- **positional reads/writes** — the backend uses `read_exact_at` /
  `write_all_at` (and drops to raw `libc::pread` / `libc::pwrite` in its
  offset-loop helpers), *not* `seek`+`read`/`write`, so the shim must model
  offset-addressed I/O with no shared file cursor.
- **`set_len` / file growth** — redb grows the file with `File::set_len` as the
  database expands; the crash model must treat a grown-but-unsynced region as
  losable.
- **advisory file locking** — on open redb takes a whole-file advisory lock via
  std's `File::try_lock` / `try_lock_shared` and releases it with `unlock()` on
  drop; a contended lock surfaces as `DatabaseError::DatabaseAlreadyOpen`
  (platforms without lock support set an internal `lock_supported = false`). The
  shim must model advisory lock acquisition, release, and rejection-when-held.
- **two-phase commit / durability** — redb's default `Durability::Immediate`
  fsyncs on commit; `Durability::None` does not. Optional two-phase commit
  (`set_two_phase_commit`) changes the fsync ordering. The shim's ordering model
  must match whichever durability the harness selects (this harness uses the
  default `Immediate`).
- **no mmap** — redb 4.x uses buffered file I/O with its own page cache, not a
  memory-mapped file, so the shim does **not** need to model `mmap`/`msync`
  page-fault write-back.

These are the concrete points where the crash filesystem's decisions must line
up with real redb behavior; a mismatch would produce either false-positive
"bugs" or missed real ones.

## Cooperative-SUT (buggify) campaign

`buggify-sweep.sh` runs a Patina cooperative-SUT campaign: the harness is built
against the vendored `../redb-fork` (redb 4.1.0 with `patina::{buggify!,
buggify_delay!, sometimes!, reachable!, always!}` sites in its commit/recovery
paths — byte-for-byte upstream except for those clearly-marked sites), and run
with `--buggify` combined with the crash filesystem. Each generation derives its
seed, workload, crash geometry, and per-gen buggify activation/fire probabilities
from `SHA-256("redb-buggify-$G")`, so any generation is re-runnable by number.

The harness's single cooperative touch point is one
`patina::lifecycle::setup_complete()` call marking the setup/workload boundary
(a no-op outside a Patina build, so `run-native.sh` is unchanged). Crash-free
generations additionally pass `--buggify-after-setup` so DB creation is
fault-free and cooperative faults fire only from the first workload commit.

Classification reuses the shared `../buggify-campaign.sh` layer (the
`ALWAYS_VIOLATION` and `SOMETIMES_UNMET` classes, the `PATINA_SDK_REPORT` parser,
and the cross-generation `campaign-state.json` coverage accumulator) plus redb's
own durability oracle (a lost/torn acknowledged commit is a `SAFETY_BUG`). The
campaign writes to a fresh `out-buggify/` directory and exits nonzero on any
failure class, including a `sometimes!` site reached but never satisfied.

```sh
./buggify-sweep.sh              # 350 generations into out-buggify/
./buggify-sweep.sh 1 50         # a range
./buggify-sweep.sh --selftest   # the shared campaign-layer selftest
./buggify-sweep.sh --dry-run 1 8
```
