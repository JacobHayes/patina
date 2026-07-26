# buggy-smoke

A deliberately-buggy **canary** for Patina. Every other testbed is a correct
program we expect Patina to keep GREEN; this one is the inverse. It plants six
real, reachable bugs that native testing almost always misses on fast hardware
but that Patina's deterministic scheduler, virtual clock, SimNet, CrashFs, and
seeded entropy should surface quickly and reproducibly.

If Patina ever stops finding these bugs, **Patina regressed** — that is the whole
point of keeping this testbed.

The binary is 100% std-pure: no Patina imports, no `cfg(patina)`, no external
crates. The only difference between a native and a Patina run is the runner
command; the binary args are byte-for-byte identical.

## CLI

```
buggy-smoke --bug <name> [--seed <u64>] [--iters <n>] [--stress]
buggy-smoke --verify-db <path> [--iters <n>]   # no-fsync crash-checker
buggy-smoke --list
```

Every bug mode runs a self-contained scenario with an internal correctness
assertion and prints exactly one contract line:

- clean scenario → `CLEAN bug=<name>` and exit `0`;
- tripped assertion → `BUG_CAUGHT bug=<name> detail=<short>` and exit `1`.

Each planted flaw is marked with a `// BUG:` comment in `src/main.rs` naming the
flaw and the Patina capability expected to catch it.

## The six bugs

| Bug | The flaw (`// BUG:` in code) | Why native testing usually misses it | Patina capability that should catch it | Expected `BUG_CAUGHT` signature |
| --- | --- | --- | --- | --- |
| `lost-update` | Read-modify-write on a shared counter with no atomic upgrade: a read lock loads, then a *separate* write lock stores, so two threads can lose an increment. | The read→write window is tiny; on fast hardware low `iters` usually completes without a collision. | **Deterministic scheduler** — drives the dropping interleaving on the seeds that schedule it. | `detail=lost=<n> expected=<m>` |
| `deadlock` | A rare "rebalance" iteration takes two mutexes in the opposite order (b→a) from the common path (a→b) — an AB/BA lock-order inversion. | The inversion only deadlocks if thread A holds `a` and waits for `b` at that exact instant; native scheduling almost never aligns them. | **Deterministic scheduler** (lock-order interleaving) + DetScheduler deadlock detection; a wall-clock watchdog is the backstop. | `detail=watchdog-timeout` |
| `no-fsync` | A write-ahead commit appends a record and a commit marker but never `fsync`s before reporting the record durable. | Without a crash the OS flushes everything on close, so the reopened file is always a complete, consistent prefix. | **CrashFs** — respects `fsync` boundaries and injects torn writes; `--verify-db` is the post-crash prefix-consistency checker. | `detail=lost-durable-records committed=<k> expected=<n>` or `detail=torn-marker-at-seq=<s>` |
| `tight-deadline` | A worker's completion is asserted within only ~2x of its own `thread::sleep` pacing budget. | Real sleeps land well under the 2x budget on an unloaded machine. | **Virtual clock + latency injection** — injected clock/scheduler latency pushes virtual-elapsed past the budget. | `detail=elapsed-ms=<e> budget-ms=<b>` |
| `udp-order` | A receiver asserts strictly-contiguous sequence numbers, assuming loopback UDP is FIFO and lossless. | Loopback UDP is effectively FIFO and lossless for a small burst, so every datagram arrives in order. | **SimNet** — datagram reorder and drop decisions break both assumptions. | `detail=out-of-order got=<g> want=<w>` or `detail=drop-or-timeout after-seq=<s>` |
| `unlucky-byte` | 16 random bytes are folded to one byte used as a "generation tag"; tag `0` is treated as an "unset" sentinel, so a legitimate `0x00` fold silently drops state (an off-by-one on the `tag-1` boundary). | The fold is `0x00` for only 1 in 256 draws, so a single native run almost always survives. | **Seeded entropy** — a Patina seed sweep varies the draw deterministically and finds the unlucky one fast. | `detail=derived=0x00 stored=0` |

## Native behavior (baseline)

`./run-native.sh` pins down and asserts the native outcomes:

- **must be CLEAN natively:** `no-fsync`, `tight-deadline`, `udp-order`, and
  `deadlock` (the bug is latent without Patina fault/schedule injection);
- **either outcome tolerated (recorded):** `lost-update` and `unlucky-byte` are
  racy / probabilistic — a native run may legitimately trip or not.

It also proves the bugs are **real and reachable** natively (non-vacuity):

- `lost-update --stress` (8 threads, high `iters`) trips reliably;
- an `unlucky-byte` seed sweep finds an unlucky draw within a bounded budget
  (first hit is seed `15`);
- the `no-fsync` crash-checker (`--verify-db`) is shown to reject a truncated DB,
  so the crash-phase oracle is not vacuous.

```sh
./run-native.sh
# dry-run the Patina invocation shape (still native semantics):
RUNNER='cargo patina run --release --' ./run-native.sh
```

`--seed` makes `unlucky-byte` deterministic (its own SplitMix64 stream). The
other modes depend on real threads / loopback / wall-clock time and are **not**
seed-deterministic natively; determinism arrives only under Patina.

## Patina phase

`run-patina.sh` is an **UNTESTED SKETCH** of the later Patina phase (seed sweeps
via `cargo patina explore`, crash injection for `no-fsync`, trace minimization).
The swap is exactly the runner — the binary and its args do not change.

Confidence that the *current* Patina CLI can trigger each bug against a std-pure
binary varies, and the sketch says so per-bug:

- **High:** `lost-update`, `deadlock` (scheduler), `unlucky-byte` (seeded entropy)
  map cleanly onto `explore`.
- **Low / uncertain:** `no-fsync` (CrashFs), `tight-deadline` (clock latency), and
  `udp-order` (SimNet reorder/drop) need per-driver fault/latency topology that a
  std-pure binary cannot request through the current native CLI. Triggering them
  likely needs new CLI knobs or an explicit-`Context` harness (which would break
  the no-imports rule). These are the honest risks to resolve in the Patina phase.
