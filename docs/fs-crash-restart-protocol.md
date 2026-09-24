# Filesystem crash-restart protocol

This note pins the crash-restart protocol surface for `--fs-crash-at`. Native runs use it for seeded runs, `--record`, and `replay`; WASI and cargo-family `--fs-crash-at` refuse by name.

## Trace contract

The trace records incarnation state explicitly:

- every operation has an operation `sequence`, a global logical `order`, and an `incarnation` id;
- every timeline has lifecycle markers in the same `order` namespace;
- structural validation rejects duplicate orders, operations outside an active incarnation, mismatched operation/lifecycle incarnation ids, restarts without a preceding crash, digest mismatches between `Crash` and `Restart`, and unended lifecycles.

The crash-restart shape is:

```text
Start(0)
<successful triggering operation in incarnation 0>
Crash(0, snapshot_digest)
Restart(0 -> 1, snapshot_digest)
Start(1)
...
End(1)
```

Operation `sequence` numbers run contiguously across both incarnations (incarnation 1's first operation follows incarnation 0's last); `order` also gives each lifecycle marker a slot, so it skips the `Crash`, `Restart` and `Start(1)` slots between the incarnations.

## Handoff contract

`IncarnationHandoff/v1` is the supervisor-owned binary envelope around the recovered `FsSnapshot` bytes. It contains:

- compatibility fingerprint;
- from/to incarnation ids;
- crash selector (`op`, 1-based ordinal);
- consumed trace state (operation count and lifecycle order);
- the bounded canonical `FsSnapshot` payload;
- a domain-separated SHA-256 snapshot digest;
- a domain-separated keyed SHA-256 seal.

The current seal is deliberately exposed as a `seal` / `open` API with a `HandoffSealKey`. It is an integrity check for supervisor-controlled bytes, not an HMAC claim and not a guest-authentication boundary. `open` validates magic, version, declared length, exact trailing bytes, seal, snapshot digest, metadata invariants, and nested `FsSnapshot::decode` before returning a verified handoff.

## Native supervision

The runtime turns a reached selector into an internal uncatchable termination control after the selected successful boundary operation. The shim seals the handoff and terminates with `_exit`; the supervisor validates the handoff and starts exactly one fresh incarnation with the snapshot as its base image and clean descriptor state. Both incarnations get the same configuration and seed; a run has one crash selector, and incarnation 0 is the one it fires in, so every later incarnation starts with the selector already consumed. An armed selector that is never reached is a named runtime error (`PATINA_FS_CRASH_SELECTOR_UNREACHED`), and a corrupt handoff is a named supervisor error (`PATINA_FS_CRASH_INVALID_HANDOFF`). When swarm deselects the crash class the selector is not armed, and the run is an ordinary single-incarnation run.

## Record and replay

Each incarnation records and replays a linear trace of its own operations, stamped with its incarnation; the supervisor assembles and takes apart the lifecycle (`CrashRestartSegments` in `crates/patina-trace/src/crash_restart.rs`).

- **Record.** Each incarnation records into its own trace channel. The crash writes incarnation 0's recording (ending with the triggering operation) before the process exits. After incarnation 1 finishes, the supervisor joins the two into one trace with the lifecycle above, the handoff's snapshot digest on the `Crash` and `Restart` markers, and the incarnations' metadata, which must agree except for the buggify sites and knobs each reached (merged). A run whose selector never fires records its one linear trace unchanged.
- **Replay.** The selector comes from the trace's recorded fault configuration. The supervisor splits the trace at its crash and replays incarnation 0 against its own segment with a handoff channel. The crash must come after exactly the recorded number of operations, and the recovered filesystem the replay derives must have the recorded snapshot digest; otherwise replay fails with `PATINA_FS_CRASH_REPLAY_DIVERGENCE` before incarnation 1 starts, keeping incarnation 0's output and reporting `crash_restart.terminal_outcome.kind = "replay_diverged"` in the result envelope. Incarnation 1 then replays its own segment from the re-derived snapshot. The snapshot bytes are never stored in the trace: the recorded digest is what the replay is checked against.

A replay that crashes although the recorded run never did, and a trace with a crash lifecycle but no recorded selector, are refused by name. A crash-restart trace holds exactly one timeline: branches of one are not modeled, and taking such a trace apart refuses it.

## Remaining boundary

WASI `--fs-crash-at` and cargo-family `--fs-crash-at` refuse by name, and native `--fs-crash-at` refuses `--starve`.
