# Filesystem crash-restart protocol

This note pins the Phase 2 protocol surface for turning `--fs-crash-at` into a crash boundary in later runtime work. It does not claim the supervisor relaunch path is wired yet.

## Trace contract

Trace format v5 records incarnation state explicitly:

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

Non-crash v1-v4 traces migrate to v5 by adding a linear `Start(0)` / `End(0)` lifecycle and putting existing operations in incarnation 0. Legacy v1-v4 traces that contain `Operation::FsCrash` fail closed with `LegacyCrashSemantics`, because those recordings used the old rollback-and-continue hybrid semantics.

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

## Not wired yet

The runtime still needs a later phase to terminate the current guest incarnation, export the handoff from the crash filesystem, launch a fresh process/runtime incarnation with clean descriptor state, and replay/record the lifecycle markers through the supervisor. Until that phase lands, existing CLI crash behavior is intentionally not widened in this protocol-only change.
