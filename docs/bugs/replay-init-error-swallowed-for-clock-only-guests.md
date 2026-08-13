# Replay init errors are swallowed for clock-only guests

Status: fixed 2026-08-13. Found the same day by the advance-on-spin builder
(disclosed, not fixed there — it predates that slice and is orthogonal to it).

## Field symptom

A native `replay` whose runtime initialization fails — e.g. a `--fingerprint`
mismatch — manifests as an **infinite spin at 100% CPU** instead of the loud
`trace fingerprint mismatch` abort, but only for a guest whose sole boundary
operations are clock reads.

## Mechanism

`patina_clock_now`'s bootstrap window answers a fixed `0` without calling
`ensure_runtime`, so a guest that only ever reads the clock never reaches the
path that raises the stored init error. Any other first operation (a sleep, an
fs op, a scheduling point) calls `ensure_runtime` and aborts loudly with the
real error. The failure is therefore shaped exactly like the calibration
guests the advance-on-spin slice unwedged: pure clock-read loops.

## Why it matters now

Before advance-on-spin, clock-only guests hung under patina either way, so the
swallowed error was indistinguishable from the general wedge. Now that such
guests otherwise run to completion, a swallowed init error is a genuine
fail-closed hole: the one guest shape that cannot see the refusal is the one
shape that will actually run long enough to matter.

## Reproduction sketch

Record a trace of a clock-polling guest, replay it with a different
`--fingerprint`: expected = immediate named abort; observed = spin. (The
advance-on-spin builder separated this from their own slice with a `sample` of
the spinning process plus a control guest containing one `sleep`, which aborts
correctly.)

## Fix shape / class pairing

Point fix: the bootstrap clock window must consult the stored init-error state
(or call `ensure_runtime`) before answering. Class-level pairing per the
maintenance rule: a detector that every interposed entry point raises a stored
init error on its first call — enumerate the bootstrap-window entry points and
red/green each, so the next bootstrap-window addition cannot reintroduce the
swallow.

## A second swallow, found by the detector

Building the class detector turned up a second path with the same shape, one
layer out from the bootstrap window: `patina_stdio_write` captures guest output
into a shim-local buffer with no context installed, and `patina_shutdown` with no
context returns quietly. So a guest whose only boundary effect is a `println!`
did not spin — it exited **0 with its output silently dropped** and the refusal
unreported. Demonstrated on both the parent revision and the bootstrap-window fix
before being closed here (a `println!`-only guest, mismatched `--fingerprint`
replay: `exit=0`, empty stdout, empty stderr).

That path is fixed the same way, and is now a leg of the detector. It also means
the class is stated more precisely than "the bootstrap window": **any interposed
entry point that can answer without reaching `ensure_runtime`**. A full audit of
the remaining ~100 C-ABI entry points against that statement was not attempted
here — most reach the runtime through a helper, and confirming each needs call-
graph work rather than a text scan. That audit is the natural follow-up.

## Resolution

The fix is structural rather than per-entry-point. `SHIM_BOOTSTRAP` is cleared
only by a *successful* `install`, so a failed initialization leaves the window
open for the rest of the process; every path behind it reached that state
through one predicate, `in_shim_bootstrap`. That predicate now consults the
stored init error and aborts with the runtime's own diagnostic, which covers the
paths that exist and the ones not yet written. Supporting changes:
`record_init_error` became the single writer of the stored message and publishes
a lock-free `INIT_FAILED` flag for it; `abort_with_init_error` no longer
allocates (it writes the same bytes in pieces) because it is now reachable from
the allocator's own init path; a re-entrancy latch and the reordered
`in_shim_critical() || in_shim_bootstrap()` test in the `os_unfair_lock`
interposers keep shim-internal reentrancy from being the call that aborts.

`patina_stdio_write` takes the same check directly (it is outside the window).

Evidence:

- Class detector: `native_replay_init_error_reaches_every_bootstrap_window_entry_point`
  (`crates/cargo-patina/tests/end_to_end.rs`) drives one guest per answering
  entry point through a fingerprint-mismatched replay, under a deadline so the
  field symptom fails the test instead of hanging it. RED before the fix, naming
  all five swallowing entry points at once (`clock`, `cpu-time`, `read-link` and
  the macOS `unfair-lock` arm exited 0; `clock-until` was still spinning at the
  deadline — observed at 100% CPU for 22 minutes when an earlier run leaked it),
  with only the `sleep` control aborting correctly. GREEN after. The `stdout` leg
  was added later, RED against the bootstrap-window fix and GREEN after.
- Enumeration gate: `bootstrap_window_lints` in `crates/patina-native-shim/src/lib.rs`
  pins the window's source call sites to a named list and forbids any second
  reader of `SHIM_BOOTSTRAP`, so a new bootstrap-window path has to be enumerated
  (and given a leg above) rather than appearing silently.
- Reentrancy guard: `native_replay_init_error_aborts_under_a_custom_global_allocator`
  drives the existing custom-`#[global_allocator]` fixture — whose init takes an
  interposed `os_unfair_lock` — through the same mismatched replay under a
  deadline. It is what would hang if the re-entrancy latch or the spinlock-first
  ordering were dropped. It also shows the fix's reach: that guest used to exit 0
  silently (it is a `println!`-only guest) and now aborts.
- No regression on healthy runs: with only `crates/patina-native-shim/src/lib.rs`
  swapped between the parent revision and this one, a guest exercising clock,
  CPU-time accounting, `read_link`, locks, fs, entropy and threads produced
  byte-identical stdout, byte-identical replay stdout, and byte-identical trace
  bytes at two seeds.
