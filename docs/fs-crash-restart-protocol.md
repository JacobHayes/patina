# Filesystem crash-restart protocol

This note pins the crash-restart protocol surface for `--fs-crash-at`. Native runs use it for seeded runs, `--record`, and `replay`; cargo-family `--fs-crash-at` refuses by name.

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

`IncarnationHandoff` (layout version 2) is the supervisor-owned binary envelope around the recovered `FsSnapshot` bytes. It contains:

- compatibility fingerprint;
- from/to incarnation ids;
- crash selector (`op`, 1-based ordinal);
- consumed trace state (operation count and lifecycle order);
- the realtime the crashed incarnation's clock had reached;
- the bounded canonical `FsSnapshot` payload;
- a domain-separated SHA-256 snapshot digest;
- a domain-separated keyed SHA-256 seal.

The current seal is deliberately exposed as a `seal` / `open` API with a `HandoffSealKey`. It is an integrity check for supervisor-controlled bytes, not an HMAC claim and not a guest-authentication boundary. `open` validates magic, version (a handoff of another layout version is refused by its version), declared length, exact trailing bytes, seal, snapshot digest, metadata invariants, and nested `FsSnapshot::decode` before returning a verified handoff.

## Native supervision

The runtime turns a reached selector into an internal uncatchable termination control after the selected successful boundary operation. The shim seals the handoff and terminates with `_exit`; the supervisor validates the handoff and starts exactly one fresh incarnation with the snapshot as its base image, clean descriptor state, and the handoff's realtime (`PATINA_RESTART_REALTIME_NANOS`). Both incarnations get the same configuration and run seed; a run has one crash selector, and incarnation 0 is the one it fires in, so every later incarnation starts with the selector already consumed. When swarm deselects the crash class the selector is not armed, and the run is an ordinary single-incarnation run.

### Each incarnation is a fresh boot

The crash models power loss, so a restarted incarnation boots as a rebooted machine would:

- **Seeded streams.** Every stream of an incarnation derives from its stream root, `incarnation_seed(run_seed, incarnation)` in `patina-rng-seeded`: the run seed itself for incarnation 0, and the run seed keyed by the incarnation number for a restart. Incarnation 1 therefore draws its own entropy, `AT_RANDOM` bytes, scheduler choices, buggify firings, delays and `patina_dst::rng()` values, and its own filesystem, network, DNS, clock, entropy and custom-op fault decisions, while each remains a pure function of the run seed. The handoff carries no seed: the trace records the run seed and stamps every operation with its incarnation, so a replay re-derives each incarnation's streams from those alone.
- **Per-run decisions.** Swarm deselection, buggify site activation and buggify knob values are picks for the run, drawn from the run seed, and are the same in every incarnation: both incarnations run one fault configuration, and the joined trace's metadata must agree on it.
- **Realtime carries forward.** The handoff records the realtime the crashed incarnation's clock had reached, which is at or after every unperturbed realtime read and every timestamp that clock stamped. The restarted incarnation's realtime starts there plus a seeded downtime, uniform over one second to one minute and drawn from its own stream root, so realtime never runs backwards across a restart. `--epoch-jump-nanos` perturbs individual reads around the clock in either incarnation and does not move it.
- **Monotonic time is per boot.** The restarted incarnation's monotonic clock starts again at the run's boot origin, as `CLOCK_MONOTONIC` and `CLOCK_BOOTTIME` do after a real reboot.

The downtime is not a knob: a restart's realtime is a derived value, and replay re-derives it from the replayed handoff and the run seed. The trace layout is unchanged, since the realtime comes from replaying incarnation 0, which the replay checks against the recorded operation count and snapshot digest.

An armed selector that is never reached is a named runtime error (`PATINA_FS_CRASH_SELECTOR_UNREACHED`, refusal class `fs_crash_unreached`, campaign class `VACUOUS_CRASH` over a guest that otherwise exited cleanly), and a corrupt handoff is a named supervisor error (`PATINA_FS_CRASH_INVALID_HANDOFF`).

### Crash reports

Incarnation 0 reports its crash on a supervisor-owned pipe (`PATINA_CRASH_REPORT_FD`) as framed `CrashReport` records, and the supervisor decides from these reports alone whether a crash was attempted, never from an exit status the guest could also produce. A pipe write is subject to neither a file size limit nor `SIGXFSZ`.

- `Attempting` goes out as soon as the runtime selects the crash point, before the snapshot export and before any recording I/O.
- `HandedOver` follows once the sealed handoff is written in full.
- `Failed(reason)` follows when recovery, the snapshot export or the handoff fails. The shim then aborts; when the pipe cannot take the report it names the failure on stderr instead.

### A crash that fails

A reached selector whose crash cannot be carried out is an infra refusal, never an errno handed to the guest. `Attempting` followed by `Failed`, `Attempting` with no outcome (the incarnation died carrying the crash out), and bytes that are not whole reports all count as a failed crash. The supervisor:

- names the refusal (`PATINA_INFRA fs_crash_failed`, refusal class `fs_crash_failed`, campaign class `INFRA`);
- reports `crash_restart.attempted = true`, `reached = false` and `terminal_outcome.kind = "crash_failed"`;
- keeps a recorded run's trace, which incarnation 0 writes as it would for a crash that succeeds.

The trace records the guest's operations, not the outcome of the crash. A replay reaches the same refusal when the failure follows from the run itself, such as a snapshot over the export limit. A failure caused by a host condition, such as a handoff write under a file size limit, recurs only under the same condition. Replayed without it, the crash succeeds where the recording's did not, and the replay reports `replay_diverged`.

## Record and replay

Each incarnation records and replays a linear trace of its own operations, stamped with its incarnation; the supervisor assembles and takes apart the lifecycle (`CrashRestartSegments` in `crates/patina-trace/src/crash_restart.rs`).

- **Record.** Each incarnation records into its own trace channel. The crash writes incarnation 0's recording (ending with the triggering operation) before the process exits. After incarnation 1 finishes, the supervisor joins the two into one trace with the lifecycle above, the handoff's snapshot digest on the `Crash` and `Restart` markers, and the incarnations' metadata, which must agree except for the buggify sites and knobs each reached (merged). A run whose selector never fires records its one linear trace unchanged.
- **Replay.** The selector comes from the trace's recorded fault configuration. The supervisor splits the trace at its crash and replays incarnation 0 against its own segment with a handoff channel. The crash must come after exactly the recorded number of operations, and the recovered filesystem the replay derives must have the recorded snapshot digest; otherwise replay fails with `PATINA_FS_CRASH_REPLAY_DIVERGENCE` before incarnation 1 starts, keeping incarnation 0's output and reporting `crash_restart.terminal_outcome.kind = "replay_diverged"` in the result envelope. Incarnation 1 then replays its own segment from the re-derived snapshot. The snapshot bytes are never stored in the trace: the recorded digest is what the replay is checked against.

A replay that crashes although the recorded run never did, and a trace with a crash lifecycle but no recorded selector, are refused by name. A crash-restart trace holds exactly one timeline: branches of one are not modeled, and taking such a trace apart refuses it.

## Remaining boundary

Cargo-family `--fs-crash-at` refuses by name, and native `--fs-crash-at` refuses `--starve`.
