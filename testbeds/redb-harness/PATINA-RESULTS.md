# redb under Patina — results

Rung 3 of the Patina-on-testbeds campaign, and its first real database. This
records what happens when the **unmodified** redb `=4.1.0` embedded ACID KV
store is built and run under Patina's deterministic native runtime with the
crash-injecting filesystem, and what it proves about redb's durability and about
Patina.

- **Host:** macOS 26.5.2, arm64. Date: 2026-07-26. rustc 1.96.0.
- **Guest:** the std-pure `redb-harness` (unchanged source; the LATER-phase
  `crash` mode added this rung is still std-pure) linked against redb 4.1.0. The
  workload PRNG is an inline splitmix64 and the digest a hand-rolled FNV-1a, so
  the code under test is redb and redb alone.
- **The one-line swap holds:** the SAME binary and SAME program args as
  `run-native.sh`, only `$RUNNER` changes to `cargo patina native-run`.

## Headline: durability HOLDS — 346 injected crashes, zero committed-op loss

The crash campaign's a/b/c tabulation (the point of this rung), across **346
injected-crash runs** (write/sync/close ordinals × fault seeds × workload seeds):

| Class | Meaning | Count |
| --- | --- | --- |
| **(a) durability HOLDS** | redb reopened to a committed **prefix** that kept every acknowledged commit | **265** (214 `HOLDS` + 51 `NO_CRASH`) |
| **(b) REAL redb durability bug** | redb lost or tore an **acknowledged** commit | **0** |
| **(c) redb panics instead of `Err`** | `Database::open` panics on the crashed image | **0 observed** — redb fail-closed with `Err` (`OPEN_ERR`, 81) on too-early images instead |

**No case (b): the jackpot was not hit.** Across every crash point exercised,
redb never surfaced a partial, torn, reordered, or lost commit — every commit it
acknowledged durable (`Durability::Immediate` → fsync-on-commit) survived. There
was nothing to minimize.

**No case (c) either, and that is itself a finding.** redb 4.1.0's README-noted
open-time panic (`assertion failed: !self.needs_recovery`) was **not
reproduced**. Under Patina's default crash model — whole-block torn writes
(4 KiB granularity, revert-to-durable) — a crashed image is always either a
crash-consistent committed prefix (redb opens it, `HOLDS`) or too-torn-to-parse
(redb returns `Err`, `OPEN_ERR`), never the sub-block Frankenstein image the
panic assert needs. So that model tests redb's **prefix recovery** thoroughly
but cannot, on its own, manufacture the panic.

### Sub-block torn-write campaign (the follow-up, now run)

The follow-up the paragraph above called for — a sub-block torn-write
granularity knob — is now built (`--fs-torn-granularity byte`, Patina task #17).
Under it the single most recent unsynced page survives *partially*: a seeded
prefix of the write persists and the suffix reverts, so the affected 4 KiB page
carries a header and body that disagree — exactly the torn-page image the
open-time assert is meant to guard against. `crash-sweep.sh` now sweeps both
granularities.

**Result: still no panic, and that is the sharper finding.** Across **432
additional injected crashes** under byte granularity (write ordinals 1–40 dense
+ the coarse 1–300 grid, sync/close ordinals, fault seeds 0–3), redb reproduced
**zero** `OPEN_PANIC` and **zero** durability violation. Byte-granularity tearing
yields the *same* outcome distribution as whole-block: a torn page is either
inside an uncommitted region redb discards (`HOLDS`), or — for the very first
writes (`write:1`, `write:2`, `sync:1`, the file header / first commit) — is
rejected with a clean `Err` (`OPEN_ERR`, "I/O error: invalid data"), *the same
ordinals and the same error* as whole-block revert. redb 4.1.0's **per-page
checksums detect a partially-written page and reject it exactly as they handle a
cleanly-reverted one**, so sub-block tearing does not widen the failure surface.
The known open-time assert did not reproduce even with the torn-page geometry it
was written for — redb behaving *better* than the README feared (clean `Err`,
not panic) is the honest result, now confirmed against the harder crash model.

The sub-block model is proven non-vacuous by
`patina-fs-crash` unit tests (`byte_granularity_tears_the_final_write_into_a_partial_image`,
`byte_granularity_tears_only_the_final_write_not_earlier_ones`, over positional
`write_at` pages — redb's exact I/O shape) and the runtime round-trip test
`byte_granularity_crash_records_a_torn_image_and_replays_self_contained`: each
shows a reconstructed image that differs from *both* the durable baseline and the
fully-applied write. The tear engages; redb's checksums close the door.

The oracle is **not vacuous**: `classify_recovery` provably fires `LOST_COMMIT`
and `TORN_STATE` (harness unit tests `oracle_flags_a_lost_acknowledged_commit`,
`oracle_flags_a_state_that_was_never_a_published_prefix`), and a genuine
`TORN_STATE` was witnessed during development (before a harness fix), so the
zero is a real negative, not a detector that cannot trip.

## Clean runs: redb is byte-identical native vs Patina

The clean `full` battery (write, drop the handle, cold `verify` in-process,
assert write hash == verify hash) is byte-identical to native across 5 seeds —
redb produces the **same durable state** on a real disk and inside Patina's
in-memory crash filesystem:

| seed | RESULT (identical native & Patina) |
| --- | --- |
| 1 | `RESULT seed=1 committed=61 state=41250e23b2059559` |
| 2 | `RESULT seed=2 committed=51 state=705ad4f2b6592e7a` |
| 3 | `RESULT seed=3 committed=44 state=db7eb79096814064` |
| 4 | `RESULT seed=4 committed=39 state=174a0c474d446736` |
| 5 | `RESULT seed=5 committed=35 state=8df40f2a5be3d6f6` |

`full --seed 42 --ops 200` → `state=5922e7fe1df1faa9 committed=30`, native ==
Patina. `./run-patina.sh` runs this battery + replay + a bounded crash sweep and
exits nonzero on any regression (**green**).

```sh
cargo patina native-build testbeds/redb-harness \
  --output testbeds/redb-harness/target/patina/redb-harness --release
cargo patina native-run testbeds/redb-harness/target/patina/redb-harness \
  --seed 1 -- --seed 42 --ops 200 --db /db/redb.redb --mode full --threads 1
```

The db lives at an **absolute path in the writable in-memory guest filesystem**
(`/db/redb.redb`) — NOT via `--mount` (that lands read-only). `CrashFs::default`
is the writable driver, so redb creates and grows the file inside the crash
model.

## The rung's gating work: positional I/O and advisory-lock interposition

redb 4.1.0's file backend does **all** its reads and writes through positional
`pread`/`pwrite` (`read_exact_at`/`write_all_at`, dropping to `libc::pread`/
`libc::pwrite`), never `seek`+`read`/`write`, and takes a whole-file advisory
lock via `File::try_lock` → `flock` on open. The pre-run default-deny audit
correctly flagged all three as **uninterposed**:

```
_flock (unknown-import)   _pread (filesystem)   _pwrite (filesystem)
```

**Allow-listing these would be unsound**, not a convenience: they are reached on
redb's core path, not linked-but-unreachable. Proof — allow-listing them and
running gives `FAIL … I/O error: Bad file descriptor (os error 9)`, because
redb's *virtual* fds (3, 4, …) hit the *real* libc `pread`/`pwrite`, which know
nothing of the guest fd table. And even without that crash, uninterposed
positional I/O would bypass `CrashFs` entirely and make the whole crash campaign
**silently vacuous** (false negatives). So they had to be interposed.

They are interposed as **atomic positional operations at the driver level**, not
a caller-side `seek`+`read` emulation. The driver services `pread`/`pwrite` as
one `FsReadAt`/`FsWriteAt` operation that saves/seeks/reads-or-writes/restores
the cursor **within a single driver call** — atomic w.r.t. the deterministic
scheduler, so it is cursor-independent even when redb's threads share the fd.
A seek+read emulation would be unsound under preemption (a scheduler switch
between the internal seek and read mispositions a concurrent reader), which is
exactly the MVCC step of this rung under a `--yield-points` build — it would
fabricate torn reads and hand back FALSE redb bugs. `write_at` counts toward the
`--fs-crash-at write:N` ordinal and is crash-losable exactly like a cursor write
(unit test `positional_write_is_crash_losable_exactly_like_a_cursor_write`);
`read_at` fires no crash.

`flock` is a **single-process** advisory-lock stub returning success (the guest
is one process, so redb's lock can never be contended). Its deliberate
double-open divergence and the sound per-inode follow-up are documented in
`ESCAPE-CLASSES.md`.

**After interposition the pre-run gate passes clean, zero `--allow`.** `pread`/
`pwrite`/`flock` drop off the import table (shim-defined); the only remaining
flagged imports are the shim's own control-plane vehicle (`semaphore_*`,
`pthread_create_suspended_np`, `read$NOCANCEL`/`write$NOCANCEL`, …), which
`native-run` auto-allows exactly as in the ripgrep rung — no run here needs an
allow-list.

## The crash oracle: committed-prefix durability (`--mode crash`)

Native `full` asserts write == verify because no crash occurs. Under
`--fs-crash-at`, the crash drops unsynced data and invalidates redb's open
handles, so the write workload stops with a redb I/O error partway through, and
reopening the SAME in-memory image exposes whatever redb made durable. Because
the in-memory crash filesystem does not survive a process exit, **write and the
cold reopen run in one process** (`--mode crash`). The oracle:

- Every commit whose `commit()` **returned** before the crash was fsynced
  (`Durability::Immediate`), so the recovered commit count must be **≥** that
  last acknowledged count — losing one is `LOST_COMMIT`.
- The recovered `(count, state)` must be exactly one **published committed
  prefix** — a state that was never a real prefix is `TORN_STATE`.
- `Database::open` can panic before `check_integrity`; it is wrapped in
  `catch_unwind` so a panic is `OPEN_PANIC` (a clean classified line), not a raw
  exit 101. A plain `Err` on open is `OPEN_ERR`.

Each run prints one machine-parseable line and exits with a code that partitions
the outcomes:

```
CRASH seed=<s> crashed=<0|1> ack=<n> recovered=<n|-> state=<hex16|-> integrity=<clean|repaired|error|panic> outcome=<...> detail=<...>
```

| outcome | exit | meaning |
| --- | --- | --- |
| `NO_CRASH` | 0 | ordinal past the run; full state recovered |
| `HOLDS` | 0 | committed prefix kept every acknowledged commit |
| `LOST_COMMIT` | 3 | an acknowledged commit was lost — **redb bug** |
| `TORN_STATE` | 3 | recovered a state that was never a prefix — **redb bug** |
| `OPEN_ERR` | 4 | redb returned `Err` opening the crashed image |
| `OPEN_PANIC` | 5 | redb panicked opening the crashed image |

Example durability HOLDS (crash mid-run, prefix recovered):

```sh
cargo patina native-run …/redb-harness --seed 0 --fs-crash-at write:34 -- \
  --seed 42 --ops 400 --db /db/redb.redb --mode crash --threads 1
# CRASH seed=42 crashed=1 ack=3 recovered=3 state=87b4039500207969 integrity=clean outcome=HOLDS detail=prefix=1 ack=3
```

### The full sweep (`crash-sweep.sh`, tabulated)

`./crash-sweep.sh` sweeps `write`/`sync`/`close` ordinals × fault seeds and
tabulates; it exits nonzero on any `LOST_COMMIT`/`TORN_STATE`. Three sweeps make
up the 346-run campaign:

| Sweep | Runs | HOLDS | NO_CRASH | OPEN_ERR | LOST_COMMIT | TORN_STATE | OPEN_PANIC |
| --- | --- | --- | --- | --- | --- | --- | --- |
| main (write 14, sync 10, close 6 × fseed 0–2, workload 42, ops 400) | 90 | 66 | 18 | 6 | 0 | 0 | 0 |
| panic hunt (write:1–6, sync:1–2, close:1 × fseed 0–24, ops 200) | 200 | 100 | 25 | 75 | 0 | 0 | 0 |
| cross-workload (write/sync/close × fseed 0–1 × workload 7/100/999/12345) | 56 | 48 | 8 | 0 | 0 | 0 | 0 |
| **total** | **346** | **214** | **51** | **81** | **0** | **0** | **0** |

Reading the outcomes:

- **`HOLDS`** — a crash landed between/inside commits; redb reopened to the exact
  committed prefix at the last acknowledged commit. E.g. `sync:26` → `ack=19
  recovered=19`, `sync:50` → `ack=43 recovered=43`.
- **`NO_CRASH`** — all `close:N` runs: redb holds the db file open for the whole
  run and closes only on teardown, *after* every commit is durable, so a
  close-crash drops nothing. A legitimate, expected data point, not a miss.
- **`OPEN_ERR`** — the earliest write/sync ordinals (`write:1`, `sync:1`): the
  crash tore redb's file header before the baseline commit was durable
  (`ack=0`), so `Database::open` returns `Err` (`invalid data` / EIO). Nothing
  acknowledged was lost — redb fail-closed correctly.

## Determinism

- **Crash runs:** `write:34 seed 0`, 3 repeats → byte-identical
  (`HOLDS … state=87b4039500207969 … ack=3`).
- **Clean full:** 5 seeds × 3 repeats each byte-identical, cross-seed distinct
  (table above) — the seed genuinely drives the workload (non-vacuous).
- **Replay (strict):** a recorded crash trace replays byte-identically when the
  fault knob is **re-supplied** (it is a run input, like the seed, which replay
  takes from the trace):

  ```sh
  cargo patina native-run …/redb-harness --record c.trace --fs-crash-at write:34 --seed 0 -- \
    --seed 42 --ops 400 --db /db/redb.redb --mode crash --threads 1   # HOLDS … 87b4039500207969
  cargo patina native-run …/redb-harness --replay c.trace --fs-crash-at write:34 -- \
    --seed 42 --ops 400 --db /db/redb.redb --mode crash --threads 1   # identical, exit 0
  ```

  Replaying **without** re-supplying `--fs-crash-at` diverges (the recorded
  `FsCrash` op has no counterpart) and fails closed — replay is genuinely
  strict, not a no-op.

## MVCC under preemption (the payoff of the atomic driver choice)

redb's `Database` shares **one** file backend across the writer and the
`threads-1` concurrent snapshot readers, so the readers issue concurrent
positional reads on the shared fd. Under a `--yield-points` build (basic-block
preemption), a scheduler switch **inside** a read is near-certain — which is
precisely why positional I/O had to be atomic at the driver level. It is: the
MVCC no-torn-read invariant **held** under 4-thread preemption across 5 fault
seeds, every run exit 0 with an identical RESULT (readers only assert; they
never feed the hash):

```
# --yield-points --threads 4, --seed 7 --ops 80, fault seeds 0..4
RESULT seed=7 committed=9 state=14684e776883bb83   (identical, all 5 seeds, exit 0)
PATINA_SCHEDULE_REPORT tasks_spawned=4 max_concurrent=4 total_boundaries≈11.87M vacuous_threads=0
```

The concurrency is **genuinely non-vacuous** — contrast buggy-smoke's
atomics-only vacuous canary. Even the **plain** (non-instrumented) threaded build
reports real interleaving (`tasks_spawned=4 max_concurrent=4
total_boundaries=19031 vacuous_threads=0`), because redb's MVCC readers do real
interposed positional I/O and block on real boundaries; `--yield-points` adds
~625× finer preemption (11.87M vs 19K boundaries) on top. At `--ops 200` the
same run gives `state=31c4330393531607`, ~38M boundaries, `vacuous_threads=0`.

## Performance (fsync-heavy real-database cost model)

Median of 5 (warm, first discarded), release, `full --ops 1000 --threads 1`.

| | native | Patina | ratio |
| --- | --- | --- | --- |
| `full --ops 1000` | 1174.7 ms | 191.5 ms | **0.16×** |

Patina is **~6× faster** — and this is informative, not an overhead claim. redb
uses `Durability::Immediate`, so native does a real `F_FULLFSYNC` on every commit
(macOS full-barrier fsync is very slow), while Patina's fsync is an in-memory
no-op against a virtual durability model. So on fsync-bound real-database work
Patina replaces real disk barriers with an in-memory crash model **and** adds
deterministic crash injection, for less wall time than native. This extends the
campaign cost model: buggy-smoke's FS-heavy point was 0.2×, ripgrep's
CPU/fs-bound battery was 3.0×; a fsync-heavy database lands at ~0.16×.

**Trace cost is the flip side.** Every positional page read/write is recorded
with its byte payload, so traces are large: **~28 MiB** for `full --ops 1000`
(a full write+verify), vs **~346 KiB** for a `crash --ops 400` run that stops
early. So the per-test storage cost of a fsync-heavy database under record scales
with pages touched, not wall time.

## Patina changes made by this rung

All additive; the greenlit interposition is the atomic positional-I/O driver
path (frozen `patina_sched_yield` / `patina_shutdown→finish()` / `init_from_env`
fs-image hook / `isatty` untouched).

- **`patina-abi`**: `Operation::FsReadAt` / `FsWriteAt` (positional, offset in
  the trace). Encoding is `#[serde(tag="kind", rename_all="snake_case")]` — tags
  are variant **names**, not declaration-order discriminants, so the additions
  are order-independent and cannot renumber existing traces. Pin tests
  `operation_variant_tags_are_pinned_by_name_not_declaration_order` and
  `positional_io_offset_survives_round_trip` make any drift break loudly.
- **`patina-driver-api`**: default `FsDriver::read_at` / `write_at` composing
  `seek`/`read`|`write`/`seek` **atomically within one driver call** (so
  MemFs/CrashFs need no changes and CrashFs journaling of positional writes is
  automatic via the default `write_at`→`self.write` path) + `checked_offset`.
- **`patina-runtime`**: `fs_read_at` / `fs_write_at` mirroring `fs_read`/
  `fs_write`; `fs_write_at` calls `maybe_inject_crash(CrashOp::Write)`.
- **`patina-native-shim`**: Rust `patina_pread` / `patina_pwrite` exports; C
  `pread` / `pwrite` (→ the runtime positional ops) and single-process `flock`
  (→ success) in `patina_posix.c`, + header decls.
- **`patina-fs-crash`**: `positional_write_is_crash_losable_exactly_like_a_cursor_write`
  (the load-bearing test for the campaign).
- **`crates/patina-target/ESCAPE-CLASSES.md`**: *Positional file I/O* and
  *Advisory file lock* rows (the latter documents the double-open divergence and
  the per-inode follow-up).
- **`testbeds/redb-harness/`**: `--mode crash` (committed-prefix oracle,
  `catch_unwind` panic classification, outcome exit codes) + 4 oracle
  positive-control unit tests; real `run-patina.sh`; `crash-sweep.sh`; this file.

Gates green: `patina-abi`/`patina-driver-api`/`patina-fs-crash`/`patina-runtime`
unit tests (incl. the 3 new), `cargo-patina` incl. `end_to_end`,
`scripts/validate-native-shim.sh` (exit 0), and the redb native battery
(`run-native.sh`) before and after.

## Reproducing

```sh
cd /Users/jacobhayes/src/github.com/JacobHayes/patina
cargo build --release -p cargo-patina                 # embeds the shim C
./testbeds/redb-harness/run-native.sh                 # native baseline (deterministic + self-consistent)
./testbeds/redb-harness/run-patina.sh                 # clean + replay + bounded crash sweep (exits nonzero on regression)
./testbeds/redb-harness/crash-sweep.sh                # the full a/b/c crash tabulation
```
