# Replay init errors are swallowed for clock-only guests

Status: open. Found 2026-08-13 by the advance-on-spin builder (disclosed, not
fixed — it predates that slice and is orthogonal to it).

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
