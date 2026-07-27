# redb commit-slot torn-write geometry & the byte-granularity gap

## Question

The 350-generation buggify dogfood campaign (`buggify-sweep.sh`, evidence in
`out-buggify/`) reached the recovery oracle

```rust
// testbeds/redb-fork/src/tree_store/page_store/header.rs:342
let corrupted = checksum != xxh3_checksum(&data[..SLOT_CHECKSUM_OFFSET]);
patina::sometimes!(corrupted, "redb-recovery-torn-slot-checksum-rejected");
```

**214 times but never satisfied it** (`out-buggify/campaign-state.json`:
`reached:true, sometimes_satisfied:false`). No injected crash ever produced a
commit slot whose stored checksum disagreed with its recomputed checksum while
its version byte still parsed. Was the site unreachable under redb's two-slot
commit geometry, or satisfiable and merely missed?

**Answer: satisfiable.** The site never fired because of a Patina tooling gap,
not redb's design: under `run`, `--fs-torn-granularity byte` is silently
a no-op. With byte granularity actually applied, the site fires deterministically
(`--seed 1 --fs-crash-at write:7 --fs-torn-granularity byte`, below).

## What has to be true for the oracle to fire

`TransactionHeader::from_bytes` runs the version check *before* the
`sometimes!`. So a torn slot only reaches the site if:

1. the slot's **version byte** (offset 0 of the 128-byte slot) still reads
   `FILE_FORMAT_VERSION3`; and
2. the checksum over `data[0..112)` disagrees with the stored checksum at
   `[112..128)`.

That is, the slot must be *partially* written: a mix of new and old bytes where
the version survives but the body/checksum are inconsistent. A slot that is
wholly the new image (valid new checksum) or wholly the old image (valid old
checksum) never fires.

## redb's commit write/sync sequence (the write-index map)

The super-header is a single 320-byte region at file offset 0:

```
[0..9)    magic            [9] god byte (bit0 primary, bit1 recovery, bit2 two-phase)
[64..192)  commit slot 0    (version @64, roots, txn id, slot checksum @176..192)
[192..320) commit slot 1    (same layout, slot checksum @304..320)
```

`PagedCachedFile::write(0, DB_HEADER_SIZE, ..)` caches the whole super-header as
one 320-byte page-0 buffer; the file write happens at `flush()`
(`flush_write_buffer` issues one `write_all_at(offset, buffer)` = pwrite per
dirty page, then `sync_data`). `commit_inner` (default `Durability::Immediate`,
single-phase) does:

```
write_header(secondary-slot updated, god byte NOT yet flipped)   -> page-0 buffer
swap_primary_slot(); two_phase_commit = false
write_header(god byte flipped, new primary slot)                 -> page-0 buffer (overwrites)
flush()   ->  pwrite page 0, pwrite data pages..., sync_data
```

Instrumented `write:N` map for the fixed panel workload (`--seed 7 --ops 30
--mode crash`), one `write` per pwrite:

| write:N | offset | len  | what |
|--------:|-------:|-----:|------|
| 1..6    | 0      | 320  | `Database::create` / setup commits, each followed by its own `sync` |
| **7**   | **0**  | **320** | **first data commit: super-header (god 0x07→0x02, slot0 gains roots)** |
| 8,9,10  | 4096.. | 4096 | that commit's btree data pages |
| 7's sync| —      | —    | `sync #7` |
| 11      | 0      | 320  | next commit's super-header |
| 12      | 12288  | 4096 | its data page |
| ...     |        |      | |

Key facts:
- The super-header is always its **own** pwrite at offset 0 — never coalesced
  with data pages.
- Within a commit's flush the header pwrite comes **first**, data pages after,
  so at the trailing `sync` the header is *not* the last write.
- `--fs-crash-at write:N` crashes immediately after the Nth pwrite, making that
  pwrite the CrashFs `last_write` — the only write eligible for a sub-block
  (byte-granularity) tear. So a crash at the offset-0 write ordinal (e.g. 7) is
  exactly what can tear a commit slot.

At `write:7` the live super-header (god `0x02`, slot0 = new roots) differs from
the durable baseline (god `0x07`, slot0 empty) in the god byte and across
slot0's body. A byte-granularity tear cutting inside slot0's differing bytes
`[65,192)` yields a torn slot0 whose version byte (offset 64 = `0x03`, unchanged
in both images) survives — precisely the oracle's trigger. Recovery then reads
`recovery_required`, finds the primary (slot0) checksum-corrupted, and
`pick_primary_for_repair` swaps to the intact secondary: **durability holds**,
which is the healthy behavior the oracle exists to witness.

## Root cause: `--fs-torn-granularity byte` is dropped under `run`

`CrashFs` supports two tear policies (`TornGranularity::Block` default,
`TornGranularity::Byte`). Only `Byte` produces the sub-block "clean prefix + one
torn final page" image; `Block` reverts a modified block wholesale (entirely
durable *or* entirely live), which **can never** yield an inconsistent slot.
`patina-fs-crash`'s own unit tests prove the two differ
(`byte_granularity_tears_the_final_write_into_a_partial_image`).

The flag is parsed by `cargo-patina`, forwarded as `PATINA_FS_TORN_GRANULARITY`,
captured by the shim control plane, and read into
`RuntimeConfig.faults.torn_granularity` by `apply_fault_env`. **But it is then
discarded**, because the shim installs the crash filesystem itself and ignores
the config:

```rust
// crates/patina-native-shim/src/lib.rs  (init_from_env)
let mut builder = RuntimeBuilder::new(config)
    .with_default_drivers()
    .with_filesystem(fs_image_filesystem()?);   // <-- always a DEFAULT-policy CrashFs
```

`fs_image_filesystem()` builds `CrashFs::default()` / `CrashFs::new(image)`,
both of which use the **default** `CrashPolicy` (Block granularity, **seed 0**).
Because `with_filesystem` sets `self.filesystem = Some(..)`, the
`RuntimeBuilder::finish` block that *would* honor the config —

```rust
// crates/patina-runtime/src/lib.rs (finish)
if self.filesystem.is_none() {                       // <-- SKIPPED: already Some
    self.filesystem = Some(if crash_at.is_some() {
        CrashFs::builder().seed(root_seed)
            .torn_granularity(self.config.faults.torn_granularity) // never runs
            ...
```

— is guarded by `self.filesystem.is_none()` and never runs. Net effect under
`run`: the crash filesystem is **always** whole-block, seed 0.
`--fs-torn-granularity byte` and the per-generation `--seed` (for crash
decisions) are both inert. Every byte-granularity generation in the 350-gen
campaign actually ran as block granularity, so the torn-slot oracle was
**unsatisfiable by construction**.

## Evidence

Reproducible on the **pristine** tree (byte granularity a no-op ⇒ byte panel is
byte-identical to the block panel):

```
$ testbeds/redb-harness/geometry-sweep.sh "1 2 3 4"
=== geometry sweep verdict: VACUOUS_BYTE_GRANULARITY ===
    torn-slot fires: byte=0 block=0 (of 160 runs each)
    -> --fs-torn-granularity byte is a NO-OP under run
```

(`geometry-sweep.sh --selftest` proves the classifier's four verdicts bite on
canned input.)

## Proof of satisfiability (with the shim honoring the knob)

Applying the fix below so the shim builds the crash filesystem with the
configured `seed` + `torn_granularity`, the oracle fires — deterministically and
byte-identically across runs:

```
# seed=1  write:7  byte   -> site s1 (SATISFIED), byte-identical on re-run
run1: CRASH ... outcome=HOLDS :: redb-recovery-torn-slot-checksum-rejected|sometimes|...|s1|...
run2: CRASH ... outcome=HOLDS :: redb-recovery-torn-slot-checksum-rejected|sometimes|...|s1|...
# same params, --fs-torn-granularity block -> site s0 (NOT satisfied)
block: CRASH ... outcome=HOLDS :: redb-recovery-torn-slot-checksum-rejected|sometimes|...|s0|...
```

Across patina seeds 1..12 at `write:7`, the site fires for seeds 1, 2, 6, 8, 11,
12 (~50%) — the ~half of byte cuts that land inside slot0's differing bytes. All
firing runs recover to `HOLDS` (torn primary slot checksum-rejected, recovery
falls back to the secondary): **no silent corruption, no redb durability bug.**

Reproducer command (requires the fix applied):

```
target/release/cargo-patina patina run \
  testbeds/redb-harness/target/patina/redb-geometry \
  --seed 1 --fs-crash-at write:7 --fs-torn-granularity byte \
  -- --seed 7 --ops 30 --db /db/redb.redb --mode crash --threads 1
```

## Fix (implemented — structural, not a patch)

The gap class is "a parsed fault knob is silently ignored because a pre-installed
filesystem bypassed the fault config." The fix removes the class rather than the
instance, by making **`RuntimeBuilder::build` the single choke point** that
constructs the crash filesystem from `config.faults`:

- `RuntimeBuilder::with_fs_image(MemFs)` (new) — callers supply only the durable
  base image (empty, or the `--mount` corpus). The shim now uses this instead of
  `with_filesystem(CrashFs::default())`, so it can no longer hand in a
  filesystem that bypasses the config.
- `build` wraps that base image in a `CrashFs` seeded with `root_seed` and the
  configured `torn_granularity` when `--fs-crash-at` is set (else uses the base
  image directly; an un-crashed `CrashFs` is observationally identical to its
  inner `MemFs`, so behavior is preserved).
- **Fail-loud guard:** if an explicit `with_filesystem`/`with_captured_filesystem`
  coexists with crash-consistency knobs (`crash_at`, or a non-default
  `torn_granularity`), or with a base image, `build` returns
  `RuntimeError::Config` instead of proceeding. So the class cannot recur
  silently through any path — it is either impossible (the shim path) or loud
  (an explicit filesystem).
- `patina_init_crash(seed)` now seeds its `CrashFs` from the argument (it
  previously pinned seed 0 — the same silent-drop class, one level down).

Touched crates: `patina-native-shim` and `patina-runtime` (pre-approved for this
scope). No `patina-target` change; no classifier weakened; no fingerprint change.

### Replay semantics (fail-closed for pre-fix traces)

On replay the trace's recorded fault config is authoritative and is adopted into
`config.faults` before the choke point builds the `CrashFs`, so a byte trace now
replays as byte. A trace **recorded before this fix** recorded
`torn_granularity=byte` in its metadata but actually ran as *block*; replaying it
post-fix rebuilds a *byte* `CrashFs`, whose crash image differs, so the first
post-crash read diverges from the recorded outcome and replay **fails closed
loudly** via the existing op-mismatch path — it does not silently pass. The
existing `native_replay_fault_knob_conflict_names_the_conflict` e2e still passes.
Also note: the per-`--seed` crash-decision stream is now live (it was pinned to
seed 0), which changes crash images for `--fs-crash-at` runs across the board
(non-crash results are unchanged — the seed-7 raft `applied_hash` is invariant).

### Regression tests

- `patina-runtime`: `explicit_filesystem_with_crash_knobs_fails_closed` (the
  guard bites) and `fs_image_choke_point_honors_configured_torn_granularity`
  (byte vs block differ through the choke point).
- `cargo-patina` e2e: `native_fs_torn_granularity_byte_reaches_the_guest` (byte
  != block guest-visible image — **fails on pre-fix code**) and
  `native_fs_crash_image_is_seed_live_and_deterministic` (seed liveness +
  determinism).
- `geometry-sweep.sh` is the redb-specific witness: it flips from
  `VACUOUS_BYTE_GRANULARITY` (exit 2) pre-fix to `TORN_SLOT_SATISFIED` (exit 0)
  post-fix, and independently guards against a `SAFETY_BUG` regression.

### Earlier byte-granularity conclusions predate this fix

Any prior campaign that relied on `--fs-torn-granularity byte` under `run`
ran as *block* and its sub-block conclusions are therefore vacuous — in
particular the earlier ~432-run sub-block torn-write campaign. **Recommend** (do
not auto-execute) re-validating those campaigns now that byte tearing is live.
The redb buggify dogfood is refreshed in `out-buggify-v2/` (see below); the
historical pre-fix record stays in `out-buggify/`.

## Files

- `geometry-sweep.sh` — byte-vs-block gap detector + torn-slot witness, with a
  pure-classifier `--selftest`. Outputs to `out-geometry/` (git-ignored).
- Investigation used temporary stderr probes in `redb-fork`, `patina-fs-crash`,
  `patina-runtime`, and a temporary shim fix in `patina-native-shim`; **all were
  reverted** — those crates are back to pristine. No committed change touches
  `patina-runtime`, `patina-fs-crash`, `patina-native-shim`, or `patina-target`.
```
