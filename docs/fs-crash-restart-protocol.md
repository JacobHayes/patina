# Filesystem crash-restart protocol

This note pins the crash-restart protocol surface for `--fs-crash-at`. Native seeded runs use this path today; native record/replay lifecycle assembly, WASI restart, and cargo-family restart still refuse by name rather than falling back to rollback-and-continue.

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

## Wired surface and remaining boundary

For native seeded runs, the runtime turns a reached selector into an internal uncatchable termination control after the selected successful boundary operation. The shim seals the handoff and terminates with `_exit`; the supervisor validates the handoff and starts exactly one fresh incarnation with the snapshot as its base image, clean descriptor state, and the crash selector removed. A selector that is never reached and a corrupt handoff are named nonzero errors.

Record/replay assembly of the v5 lifecycle markers is not wired in this slice. Native `--record`/`replay` with `--fs-crash-at`, WASI `--fs-crash-at`, and cargo-family `--fs-crash-at` refuse explicitly instead of running the old in-process rollback-and-continue model.
