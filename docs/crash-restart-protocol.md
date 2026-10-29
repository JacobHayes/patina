# Crash-restart protocol

This note pins the crash-restart protocol surface for `--machine-crash-permille` and `--process-crash-permille`. Native runs use it for seeded runs, `--record`, and `replay`. The cargo family refuses both by name.

## Where a crash lands

A crash point is a completed operation whose effect already left the process, so the restarted process must cope with it. Each operation has one effect class (`EffectClass` in `patina-abi`, an exhaustive match, so a new operation needs an explicit decision): `emit` (seen by a peer: sends, a TCP connect, accept or close), `persist` (a change to storage: data, metadata, namespace or durability, including a creating or truncating open), `observe` (reads), `local` (process bookkeeping) and `schedule` (time and scheduling). Emit and persist operations are crash points. An operation that failed is not, and neither is a poll that found nothing to take (an empty accept or receive). The liveness watchdog derives its no-progress set from the same class: schedule operations, and empty polls, are not progress.

Two independent rates decide the crash. At each crash point, `--machine-crash-permille N` takes the machine down with N per-mille odds; where it does not, `--process-crash-permille M` kills the process with M per-mille odds. Both draws come from the run's crash-point stream (`fault_domain::CRASH_POINT`), and a rate of zero draws nothing, so a run with one rate set draws exactly as if the other did not exist. The first hit crashes. A run crashes at most once, always in incarnation 0. A restarted incarnation takes no crash, and swarm masks the `crash` class by clearing both rates. Nothing else draws from the crash-point stream, so where the crash lands, and its kind, depend only on the seed, the rates and the guest's sequence of crash points. Campaigns draw the two rates independently per generation from the `crash` plane; `exclude_knobs` can drop either. The check sits at the runtime's one settle path for recorded operations (`Context::reconcile`), so no syscall family needs code of its own to be crashable.

A live run with a crash rate is refused unless a supervisor will boot the next incarnation. The native shim declares one (`with_crash_supervisor`) when it is handed a handoff channel.

## What a crash takes down

The kind of the crash decides what the restarted incarnation finds on disk:

- **`process`**: the process dies and the kernel lives on. The page cache survives, so every completed write is visible after the restart, synced or not, and so is a store through a shared mapping that no write-back has written yet. Only process state is lost: descriptors, anonymous files, and bytes in flight through a pipe.
- **`machine`**: the machine goes down, and the crash filesystem's ext4 model (`data=ordered`, delayed allocation, `auto_da_alloc`, `commit=5`) decides what reached the disk. Metadata (names, link counts, sizes, extents, times, modes, attributes) rolls back to the last journal commit, atomically: a rename is never half done. A commit happens at an `fsync` of an inode with a change since the last one (its new name included, so a file's own `fsync` makes its directory entry durable), at `sync` or `syncfs`, and five virtual seconds after the running transaction's first change; a crash before any of these loses a new name. File data reaches the disk at writeback (`fsync`, `sync`, a rename over an existing name, the close of a file truncated to zero), so a file comes back as the prefix the last commit recorded, never padded with zeros. A block the last commit already held that was overwritten in place since keeps its old or new bytes on its own seeded coin. No descriptor keeps a name alive, because the process that held it is gone.

## Trace contract

The trace records incarnation state explicitly:

- every operation has an operation `sequence`, a global logical `order`, and an `incarnation` id;
- every timeline has lifecycle markers in the same `order` namespace;
- structural validation rejects duplicate orders, operations outside an active incarnation, mismatched operation and lifecycle incarnation ids, restarts without a preceding crash, digest mismatches between `Crash` and `Restart`, and unended lifecycles.

The crash-restart shape is:

```text
Start(0)
...
<the crash point in incarnation 0>
Crash(0, crash_kind, snapshot_digest)
Restart(0 -> 1, snapshot_digest)
Start(1)
...
End(1)
```

The crash follows incarnation 0's last decision, whatever operation that is. The trace has no selector and no ordinal; the crash's position is the segment boundary itself. Operation `sequence` numbers run contiguously across both incarnations, so incarnation 1's first operation follows incarnation 0's last. `order` also gives each lifecycle marker a slot, so it skips the `Crash`, `Restart` and `Start(1)` slots between the incarnations. The recorded fault configuration carries both rates (`machine_crash_permille`, `process_crash_permille`), and the `Crash` marker carries the kind of the crash that landed (`crash_kind`).

## Handoff contract

`IncarnationHandoff` (layout version 3) is the supervisor-owned binary envelope around the `FsSnapshot` bytes the crash leaves. It contains:

- the compatibility fingerprint;
- the from and to incarnation ids;
- the crash kind;
- the consumed trace state (operation count and lifecycle order);
- the realtime the crashed incarnation's clock had reached;
- the bounded canonical `FsSnapshot` payload;
- a domain-separated SHA-256 snapshot digest;
- a domain-separated keyed SHA-256 seal.

The seal is deliberately exposed as a `seal` / `open` API with a `HandoffSealKey`. It is an integrity check for bytes the supervisor controls; it is neither an HMAC nor a guest-authentication boundary. Before `open` returns a verified handoff, it validates the magic, the version (a handoff of another layout version is refused by its version), the declared length, that no bytes trail, the seal, the snapshot digest, the metadata invariants, and the nested `FsSnapshot::decode`.

## Native supervision

The supervisor runs a seeded or record run whenever either crash rate is above zero, and runs a replay whenever its trace records a crash. In either case it launches incarnation 0 with a handoff channel, a crash-report pipe and a seal key derived from the run seed. A replay's incarnation 0 is also told the recorded crash's kind (`PATINA_RT_REPLAY_CRASH_KIND`), since a replay never draws.

When the crash lands, the runtime turns it into an internal termination control the guest cannot catch. The control follows the operation that completed at the crash point. The shim seals the handoff and terminates with `_exit`. The supervisor validates the handoff, including that its kind is one the run could take (a kind whose rate is live, or a replay's recorded kind), then starts exactly one fresh incarnation. That incarnation gets the snapshot as its base image, clean descriptor state, and the handoff's realtime (`PATINA_RT_RESTART_REALTIME_NANOS`).

Both incarnations get the same configuration and run seed. A run whose rate never hits is an ordinary single-incarnation run that the supervisor watched, reported as `crash_restart.terminal_outcome.kind = "exited_without_crash"`.

### Each incarnation is a fresh boot

A restarted incarnation boots as a fresh process would, on a machine that may itself have rebooted:

- **Seeded streams.** Every stream of an incarnation derives from its stream root, `incarnation_seed(run_seed, incarnation)` in `patina-rng-seeded`. That is the run seed itself for incarnation 0, and the run seed keyed by the incarnation number for a restart. Incarnation 1 therefore draws its own entropy, `AT_RANDOM` bytes, scheduler choices, buggify firings, delays and `patina_dst::rng()` values. It also draws its own filesystem, network, DNS, clock, entropy and custom-op fault decisions, each still a pure function of the run seed. The handoff carries no seed: the trace records the run seed and stamps every operation with its incarnation, so a replay re-derives each incarnation's streams from those alone.
- **Per-run decisions.** Swarm deselection, buggify site activation and buggify knob values are picks for the run, drawn from the run seed. They are the same in every incarnation: both incarnations run one fault configuration, and the joined trace's metadata must agree on it.
- **Realtime carries forward.** The handoff records the realtime the crashed incarnation's clock had reached. That value is at or after every unperturbed realtime read and every timestamp that clock stamped. The restarted incarnation's realtime starts there plus a seeded downtime, uniform over one second to one minute and drawn from its own stream root, so realtime never runs backwards across a restart. `--epoch-jump-nanos` perturbs individual reads around the clock in either incarnation and does not move it.
- **Monotonic time is per boot.** The restarted incarnation's monotonic clock starts again at the run's boot origin, as `CLOCK_MONOTONIC` and `CLOCK_BOOTTIME` do after a real reboot.

The downtime is not a knob: a restart's realtime is a derived value, and replay re-derives it from the replayed handoff and the run seed.

A corrupt handoff is a named supervisor error (`PATINA_CRASH_INVALID_HANDOFF`).

### Crash reports

Incarnation 0 reports its crash on a supervisor-owned pipe (`PATINA_RT_CRASH_REPORT_FD`) as framed `CrashReport` records. The supervisor decides whether a crash was attempted from these reports alone, never from an exit status the guest could also produce. A pipe write is subject to neither a file size limit nor `SIGXFSZ`.

- `Attempting` goes out as soon as the crash lands, before the snapshot export and before any recording I/O.
- `HandedOver` follows once the sealed handoff is written in full.
- `Failed(reason)` follows when recovery, the snapshot export or the handoff fails. The shim then aborts. When the pipe cannot take the report, the shim names the failure on stderr instead.

### A crash that fails

A crash that lands but cannot be carried out is an infra refusal, never an errno handed to the guest. Three cases count as a failed crash:

- `Attempting` followed by `Failed`;
- `Attempting` with no outcome, because the incarnation died carrying the crash out;
- bytes on the pipe that are not whole reports.

The supervisor then:

- names the refusal (`PATINA_INFRA crash_failed`, refusal class `crash_failed`, campaign class `INFRA`);
- reports `crash_restart.attempted = true`, `reached = false` and `terminal_outcome.kind = "crash_failed"`;
- keeps a recorded run's trace, which incarnation 0 writes just as it would for a crash that succeeds.

The kept trace records the guest's operations up to the crash point, and no crash. A replay therefore takes it for a run whose rate never hit: it runs past the operation the crash followed and fails as a replay divergence instead of reproducing the refusal. A failed crash is patina's own limit, never a finding about the guest, so this replay is a diagnostic of the operations that led up to it.

## Record and replay

Each incarnation records and replays a linear trace of its own operations, stamped with its incarnation. The supervisor assembles and takes apart the lifecycle (`CrashRestartSegments` in `crates/patina-trace/src/crash_restart.rs`).

- **Record.** Each incarnation records into its own trace channel. The crash writes incarnation 0's recording, which ends with the crash point, before the process exits. After incarnation 1 finishes, the supervisor joins the two recordings into one trace. The joined trace has the lifecycle above and carries the handoff's snapshot digest on the `Crash` and `Restart` markers. The incarnations' metadata must agree except for the buggify sites and knobs each reached, which are merged. A run whose rate never hits records its one linear trace unchanged.
- **Replay.** A replay never draws a crash. The supervisor splits the trace at its crash, and incarnation 0 replays its own segment and crashes after its last decision. The replay must consume exactly the recorded number of operations, and the filesystem it derives must have the recorded snapshot digest. Otherwise the replay fails with `PATINA_CRASH_REPLAY_DIVERGENCE` before incarnation 1 starts; it keeps incarnation 0's output and reports `crash_restart.terminal_outcome.kind = "replay_diverged"` in the result envelope. If both checks pass, incarnation 1 replays its own segment from the re-derived snapshot. The snapshot bytes are never stored in the trace; the replay is checked against the recorded digest. A trace with no crash replays as one incarnation.

A crash-restart trace holds exactly one timeline. Branching such a trace is not modeled, and taking a branched one apart refuses it.

## Minimizing a crash-restart trace

`minimize` reduces each incarnation separately: the crashed one first, then the restarted one. It never deletes the decision the crash follows. Because a crash is attached to the segment boundary, a deletion elsewhere leaves the crash on the same operation. A replay of a candidate therefore rebuilds incarnation 0's image by replaying its shortened segment and crashes where the recording did. After every deletion the candidate is taken apart and joined again, which renumbers both incarnations.

## Remaining boundary

The cargo family refuses both crash rates by name, and native crash restart refuses `--starve`. A failed crash's trace does not replay to its refusal (see above).
