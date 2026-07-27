# raft under Patina — results

Rung 4 of the Patina-on-testbeds campaign, and the hardest: **[tikv `raft`
0.7.0](https://crates.io/crates/raft) as a 3-node cluster in one process** —
three node threads, real loopback UDP between them, and file-backed raft logs,
all folded into a single deterministic schedule. This is the first guest to
exercise Patina's `std::thread` scheduler **plus** SimNet UDP **plus** the
in-memory filesystem together.

- **Host:** macOS 26.5.2, arm64. Date: 2026-07-26. rustc 1.96.0.
- **Guest:** the std-pure `raft-harness` (unchanged source — no Patina imports,
  no `cfg(patina)`) linked against `raft = "=0.7.0"` (prost-codec). The client
  driver, the file-backed `Storage`, and the UDP transport are the harness's;
  the consensus logic under test is tikv raft and tikv raft alone.
- **The one-line swap holds:** the SAME binary and SAME program args as
  `run-native.sh`, only `$RUNNER` changes to `cargo patina run`. Fault
  topology (reorder, drop, crash) is 100% Patina experiment-plane knobs and the
  seed; there is no fault code in the harness.

## Headline: SAFETY HOLDS — zero invariant violations across every run

Across the entire campaign — clean runs, UDP reorder, packet-drop sweeps to 50%
loss, and a filesystem-crash sweep — raft **never** violated a safety invariant.
Not once did two nodes claim leadership in the same term, not once did applied
logs diverge on their common prefix, not once did an applied index regress. The
only failures observed are **liveness** timeouts under extreme packet loss
(raft stops making progress but stays correct), which is exactly raft's
guarantee. **No jackpot** (no raft bug) and **no Patina unsoundness** surfaced —
the honest, and desired, result for a mature consensus library under a sound
deterministic runtime.

The invariant checks are **not vacuous**: 8 harness unit tests (`cargo test`)
prove each check bites — `divergent_logs_fail_invariants`,
`two_leaders_in_a_term_are_flagged`, `committed_count_requires_all_alive_nodes`,
`applied_hash_reflects_content`, and the torn-record decoder tests — and the
`committed < proposals` failure path is demonstrably reachable (it fires under
500‰ loss, below).

## Reproduce

```sh
# From the repo root. Builds cargo-patina + the harness under Patina, then runs
# the full self-checking regression (clean determinism, replay, reorder, drop
# sweep, fs-crash sweep). Exits nonzero on ANY regression; RAFT_VIOLATION fails.
./testbeds/raft-harness/run-patina.sh
```

Single commands (from repo root, after `cargo build --release -p cargo-patina`
and `cargo patina build testbeds/raft-harness --output <BIN> --release`):

```sh
PATINA=target/release/cargo-patina
BIN=testbeds/raft-harness/target/patina/raft-harness

# Clean deterministic run (world seed 1; harness seed 7 fixes the workload):
$PATINA patina run $BIN --seed 1 -- \
  --seed 7 --proposals 20 --base-port 4001 --data-dir /raft --timeout-secs 60

# UDP delivery reorder:
$PATINA patina run $BIN --seed 1 --net-jitter-nanos 1000000..80000000 -- \
  --seed 7 --proposals 20 --base-port 4001 --data-dir /raft --timeout-secs 60

# 30% packet loss (raft retransmits and converges):
$PATINA patina run $BIN --seed 1 --net-drop-permille 300 -- \
  --seed 7 --proposals 20 --base-port 4001 --data-dir /raft --timeout-secs 90

# Record + strict replay (replay restores the seed and guest arguments from the trace):
$PATINA patina run $BIN --record r.trace -- --seed 7 --proposals 20 --base-port 4001 --data-dir /raft
$PATINA patina replay $BIN r.trace
```

Every command runs under the **default-deny audit gate with no `--allow`** — the
determinism claim below is unqualified.

The guest `--data-dir` is an absolute path (`/raft`) in the writable in-memory
guest filesystem; each of the three nodes gets `/raft/node{1,2,3}/`. No `--mount`
(that mounts read-only).

## Audit: passes the default-deny gate with no allowance

The `run` pre-run gate (default-deny on the blocking/time/scheduling
surface) accepts the harness with **no `--allow` of any kind**. The remaining
symbols `audit` lists (`_semaphore_{create,wait,signal}`, `_thread_resume`,
`_pthread_create_suspended_np`, `_pthread_mach_thread_np`, `_mach_task_self_`,
`_read$NOCANCEL`, `_write$NOCANCEL`) are the shim's own control-plane / execution-
baton vehicle and are already known-safe on the shim allow list.

The one symbol that used to trip the gate — `_pthread_atfork` — is now
**interposed by the shim** as a no-op strong definition
(`crates/patina-native-shim/c/patina_posix.c`), so it binds internally and drops
off the import table entirely. `pthread_atfork` only *registers* handlers to run
at `fork()`; the whole fork/exec process class is a runtime non-goal the audit
denies, so a registered handler could never run and the no-op is sound. This is
confirmed empirically: with the interposer, the run is **byte-identical** (same
`applied_hash`, same schedule report `total_boundaries=1052`) to the earlier
allowance-qualified run — the interposer changed nothing about execution, it only
removed the qualification. Taxonomy row: `ESCAPE-CLASSES.md` → **Host-state
registration**. Rung 4's determinism claim is therefore **unqualified**, like
rungs 1–3.

## Determinism: seed → the entire world, byte-for-byte

Three threads + UDP + fs collapse into one reproducible schedule. For each of 5
world seeds, 3 repeats are **byte-identical** in RAFT_RESULT, the
`PATINA_SCHEDULE_REPORT`, and the recorded trace hash; a recorded run replays
byte-identically:

| world seed | RAFT_RESULT (identical across 3 repeats) | trace sha256 |
| ---: | --- | --- |
| 1 | `committed=20 terms=1 restarts=0 applied_hash=bbb54b74…caf4` | `6f37e9bd2c…` |
| 2 | `committed=20 terms=1 restarts=0 applied_hash=bbb54b74…caf4` | `6ddd80cade…` |
| 3 | `committed=20 terms=1 restarts=0 applied_hash=bbb54b74…caf4` | `fab0a32fd5…` |
| 4 | `committed=20 terms=1 restarts=0 applied_hash=bbb54b74…caf4` | `5accd5ab27…` |
| 5 | `committed=20 terms=1 restarts=0 applied_hash=bbb54b74…caf4` | `a75f919e39…` |

(The `RAFT_RESULT` line gained a `restarts=N` field with the crash-recovery
supervisor — see §Crash-recovery. The consensus outcome is unchanged:
`applied_hash` is still `bbb54b74…` on every clean seed. The trace sha256s
differ from earlier revisions because the supervisor adds per-iteration
bookkeeping on the *driver* thread; that shifts trace bytes but not the
replicated log, and each seed is still byte-identical across its 3 repeats.)

The scheduler genuinely **explores different interleavings per seed** — the 5
trace hashes are all distinct and the boundary counts differ per seed
(`total_boundaries` 1607–1706 at 50 proposals) — yet all converge to the same
replicated log. **That identical `applied_hash` across seeds is the correct
consensus property, not vacuity:** on a clean network the client proposes ids
0..N in order and every interleaving agrees on that committed log. The
`applied_hash` *does* move with content (`proposals=5/10/20/30` →
`5a82f5dd…/cb26a2fd…/bbb54b74…/c15b7f31…`) and *does* fan out once the network
reorders acceptance timing (see reorder, below). Every schedule report shows
`vacuous_threads=0` — Patina's preemption detector confirms no node thread ran a
vacuous (no-observable-effect) schedule.

## Fault campaign

Fixed workload: 20 proposals, world-seed sweep 1..5, harness seed 7. "Safety" =
the three invariants (≤1 leader/term, log matching, no applied regress).

### (a) UDP delivery reorder — `--net-jitter-nanos`

All seeds converge (`committed=20/20`), zero safety violations. Because reorder
shifts *when* the leader accepts each client proposal relative to elections, the
agreed commit order — and thus `applied_hash` — now **varies per seed** (e.g.
`32acc5ff…`, `6749dd67…`, `d11974bb…`, `ba83193d…`), while log matching across
nodes still holds. Reorder perturbs the schedule; raft stays correct.

### (b) Packet drop — `--net-drop-permille`, sweep 100 / 300 / 500

| loss | outcome (5 seeds) | safety violations |
| ---: | --- | ---: |
| **100‰** | all 5 converge `20/20`, `terms=1` (stable leader through 10% loss) | **0** |
| **300‰** | all 5 converge `20/20`; seed 4 churns to `terms=7` (dropped heartbeats force re-elections) then still commits every proposal | **0** |
| **500‰** | 4/5 **honestly time out** (`committed=8..17/20`, `terms` climb to 21–48 as votes/heartbeats are lost); seed 5 still finishes `20/20` | **0** |

At 50% loss raft cannot keep a leader alive long enough to replicate, so it
sacrifices **liveness** — a `RAFT_FAILURE` timeout, exit 1 — while never
sacrificing **safety**. Both the convergence and the honest-timeout outcomes are
reportable and correct; only an invariant violation would be a finding, and
there were none. Runs are deterministic under drop (seed 4 @ 300‰ is identical
across 3 repeats) and replay byte-identically.

**No livelock.** The virtual clock advances via the tick-loop `sleep`, so even a
run that spins its recv-poll loop under heavy loss reaches the virtual deadline
rather than hanging: a full 90-second *virtual* timeout completes in **48 ms of
wall time**.

### (c) Filesystem crash — `--fs-crash-at` (and the honest limit)

`--fs-crash-at` is **process-global**: all three nodes share one CrashFs, so a
fault on any node's persist path affects the whole process. Across a 51-run
sweep (write/sync/close ordinals × 3 seeds):

| outcome | count | meaning |
| --- | ---: | --- |
| clean `20/20`, exit 0 | 25 | crash landed on already-synced / harmless bytes; committed state survived |
| **fail-closed abort**, exit 2 | 26 | fault hit a live persist → `RAFT_ABORT node N storage failure: Bad file descriptor`; the node stops rather than voting with lost state |
| **safety violations** | **0** | — |

The abort is **correct** ("a node that cannot persist must not keep voting") and
**deterministic** (`write:10` aborts on all 3 repeats). This is the **fail-stop**
half of the story: with no recovery configured, a storage fault ends the run
closed. The mechanics changed slightly with the recovery work — a node no longer
calls `process::exit` itself; it propagates the I/O error to the supervisor,
which, absent `--recover-storage-faults`, prints the same `RAFT_ABORT` and exits
2. The **recovery** half — the node dies, restarts, reopens `FileStorage` on the
crash-surviving image, rejoins, and catches up **under Patina** — is now
implemented and swept; see **§Crash-recovery** below. The zero here is no longer
an "untested recovery" caveat; it is the fail-stop leg of a two-leg story.

### (d) Schedule exploration — `--yield-points` (BLOCKED, reported)

The `--yield-points` build **crashes deterministically** on this harness across
all 5 seeds with a shim-fatal error:

```
patina native shim fatal: invalid_handle: scheduler task 2 does not exist
```

The non-yield build is unaffected. This is the first testbed to drive
`--yield-points` with more than one guest thread (the harness spawns 4 scheduler
tasks: driver + 3 nodes), and the fault fires immediately — likely during task
spawn/registration under the yield-point hook. This is a
deterministic-preemption bug, **reported to the coordinator (task #13)**, not
worked around. Schedule exploration via plain seed sweeps (a/b above) stands in
for it this round.

## Crash-recovery: a downed node reincarnates, rejoins, and catches up

The fs-crash sweep above proved **fail-stop**. This section proves the other
leg: a node that dies — whether from a deliberate kill or a real injected
storage crash — is **restarted in-process**, reopens `FileStorage` on its SAME
data dir, rebinds its UDP port, rejoins the cluster, and **catches up the
entries it missed**, with every safety invariant holding **across the restart**.
Zero safety violations across the whole recovery sweep; every recovery run is
deterministic and replays byte-identically.

### The supervisor (harness-side, still 100% std-pure)

Each node is owned by a `Supervisor` running on the driver thread. A node stops
either cooperatively (a shutdown flag) or by a storage failure it now
**propagates** to the supervisor via a shared slot instead of aborting the
process. The supervisor then either fails the run closed (`RAFT_ABORT`, exit 2,
the default fail-stop) or, when recovery is enabled, waits a seeded delay,
joins the dead thread (freeing its UDP port), resets its observation slot, and
spawns a **fresh** thread that calls `FileStorage::open` on the surviving image.
Everything is driven by new std-only flags — no Patina imports, no `cfg`:

- `--kill-plan ID:AT[,ID:AT...]` — deterministically kill node `ID` the moment
  the committed count first reaches `AT`, then restart it. Anchoring to the
  committed count (not wall time) makes the kill point reproducible and
  sweepable.
- `--restart-after-ticks N` — virtual-time delay before the reincarnation spawns.
- `--recover-storage-faults` — also restart a node that dies from an injected
  storage crash (the fs-crash composition), instead of failing closed.
- `--propose-window K` — cap client proposals in flight so the committed count
  advances one step at a time; a kill anchored to `committed==N` then lands at a
  precise, intermediate point and the reincarnation must **replicate** the
  entries it missed rather than re-applying an already-complete batch. (Default
  0 = the original pipelined workload; the clean sweeps above are unchanged.)

### Why the invariants still hold across a restart

- **No applied-index regress.** A reincarnation re-applies its recovered log
  from index 0 into a *fresh* in-thread applied history. The regress check is
  scoped to one thread's lifetime, so legitimate re-application never trips it;
  the cross-node log-matching check compares the reincarnation's re-applied
  prefix against the survivors and would bite the instant that prefix disagreed.
  The harness resets the node's shared observation on restart so the driver
  never compares a stale pre-crash log against the survivors.
- **No two leaders in a term.** raft loads its fsync'd `HardState` (term + vote)
  from `FileStorage` on reopen, so a reincarnation cannot re-vote in a term it
  already voted in. The leadership log is accumulated across incarnations; a
  double-leader would surface regardless of restarts.
- **Convergence.** The driver only declares victory when every proposal is
  applied on **every alive node including the reincarnation**, with no restart
  pending. A node that fails to rejoin before the (virtual) deadline is a
  **liveness** timeout (exit 1, `RAFT_FAILURE`) — reportable, and *distinct*
  from a safety violation.

### What "one node's storage crashed" means under a shared CrashFs

`--fs-crash-at` is process-global: all three nodes share one CrashFs. The honest
reading — and what the model delivers — is this: nodes hold **no** long-lived
filesystem handles between persists (`write_atomic` opens, writes, fsyncs, and
closes within one call; the only long-lived fds are UDP sockets). A crash
invalidates every *open* handle, so it lands on whichever node is **mid-persist**
at the injected ordinal — that node's in-flight write returns `EBADF`, it dies,
and it restarts. The other nodes, holding no fs handles at that instant, are
unaffected and keep serving from the **crash-surviving image** that is now the
durable state for everyone. So "one node's storage crashed" is faithful: exactly
the node whose persist was interrupted loses its in-flight write and must recover
from what survived. (A rare interleaving can catch two nodes mid-persist at once;
both restart, and if that momentarily drops quorum it is a liveness event, never
a safety one. None occurred in the sweep.)

### Tabulation (world-seed sweep, harness seed 7, 20 proposals)

**(a) Deliberate kill-plan + restart** — `--kill-plan 3:5 --restart-after-ticks 5
--propose-window 2`, 5 seeds × 3 repeats:

| outcome | result |
| --- | --- |
| converged | **5/5 seeds** reach `committed=20/20`, `restarts=1` |
| kill point | lands at `committed=6` (window-paced), node 3 down through an election (`terms=2`) then catches up |
| safety violations | **0** |
| determinism | each seed **byte-identical across 3 repeats** (RAFT_RESULT + trace); seeds 1–4 share `applied_hash=e0484cb6…`, seed 5 explores a different interleaving (`2d16fef2…`) yet still converges |
| replay | a recovery run **replays byte-identically** (restart included) |

**(b) fs-crash + recover** — `--fs-crash-at <spec> --recover-storage-faults`,
crash points `{write:5, write:12, write:40, sync:4, sync:16, close:4}` × 3 seeds
(18 runs):

| outcome | count | meaning |
| --- | ---: | --- |
| **recovered + converged** | **10** | crash hit a live persist → node died with `EBADF` → supervisor restarted it → `FileStorage::open` reconstructed from the surviving image → rejoined and reached `20/20` |
| no fault hit / harmless | 8 | crash landed on already-synced bytes with no node mid-persist; cluster converged `20/20` unchanged |
| liveness timeout | 0 | — |
| **safety violations** | **0** | — |

The headline recovery case, `--fs-crash-at write:5`, drops in-flight data on two
nodes (`restarts=2`) and converges to `applied_hash=b4bcc67a…` (distinct from the
clean `bbb54b74…`, i.e. the crash genuinely perturbed the run) — and is
**byte-identical across 3 repeats**. This is the capability the task exists for:
a Patina-injected storage crash, an in-process recovery, and an invariant check,
all deterministic.

### Reproduce

```sh
# Full self-checking recovery sweep is section [6] of the harness regression:
./testbeds/raft-harness/run-patina.sh          # exits nonzero on any regression

# Single commands (after building cargo-patina + the harness under Patina):
PATINA=target/release/cargo-patina
BIN=testbeds/raft-harness/target/patina/raft-harness

# Deliberate kill of node 3 at committed=5, restart, catch up, converge:
$PATINA patina run $BIN --seed 1 -- \
  --seed 7 --proposals 20 --base-port 4001 --data-dir /raft --timeout-secs 90 \
  --kill-plan 3:5 --restart-after-ticks 5 --propose-window 2

# Injected persist crash on one node + in-process recovery:
$PATINA patina run $BIN --seed 1 --fs-crash-at write:5 -- \
  --seed 7 --proposals 20 --base-port 4001 --data-dir /raft --timeout-secs 90 \
  --recover-storage-faults --restart-after-ticks 5

# Native recovery smoke (real threads/UDP) is scenario 3 of run-native.sh.
```

Every command above runs under the **default-deny gate with no `--allow`**, like
the rest of rung 4 — the whole `run-patina.sh` (sections [1]–[6]) passes
clean-gate, exit 0. (`_dlsym` is now a legitimate, gate-allowed shim import: it
is the shim's own host-alias resolution primitive, baked into the pre-run
allowance. The harness never calls `dlsym` itself, so it stays clean. Rebuild
`cargo-patina` if an older release binary transiently rejects `_dlsym` —
`run-patina.sh` also honours `PATINA_ALLOW_SYMS=<syms>` as an escape hatch for
future in-flight shim/audit refactors, but the committed default needs none.)

## Performance: the virtual clock collapses ~200×

The native harness runs near real-time — 100 ms ticks and `election_tick=10`
mean an election takes ~1–2 s of wall clock. Under Patina the virtual clock
collapses all of it. Fixed workload = 50 proposals to completion, median of 5:

| runner | median wall | notes |
| --- | ---: | --- |
| native (real threads, real UDP, real sleeps) | **2.007 s** | dominated by real 100 ms ticks + election waits |
| Patina (virtual clock, SimNet, det. scheduler) | **0.010 s** | wall ⟂ virtual time |
| **speedup** | **~200×** | |

Recorded trace for the 50-proposal world: ~642 KiB.

## What this rung proves

- Patina's deterministic scheduler, SimNet UDP, and virtual clock compose
  correctly under a real consensus workload: **3 threads + loopback UDP + fsync'd
  file logs replay byte-for-byte from a single seed**, including under injected
  reorder and packet loss.
- The threads-park-on-sockets/timeouts path (Parker + `SO_RCVTIMEO`) carries a
  guest that blocks on UDP receives and virtual-time sleeps, with no livelock
  even when recv-poll loops spin under loss.
- tikv raft 0.7.0 upholds every safety invariant under adversarial scheduling,
  reorder, and up to 50% packet loss, degrading only in liveness — surfaced with
  zero false positives and zero Patina unsoundness.
- **Crash-recovery composes under Patina:** a node killed or storage-crashed
  mid-run reopens its fsync'd `FileStorage`, rejoins, and catches up, with
  election safety, log matching, and applied-monotonicity all holding **across
  the restart** — deterministically and replayably. A Patina-injected storage
  crash followed by an in-process recovery and a passing invariant check is now
  a first-class, swept capability.

Open follow-ups (all reported, none blocking): the `--yield-points` multi-task
crash (task #13). The per-node crash-restart supervisor that turned the fs-crash
fail-stop into a true recovery test is **done** (this §Crash-recovery). (The
`pthread_atfork` no-op shim interposer that makes this rung's determinism claim
unqualified is done, not a follow-up; `_dlsym` is a gate-allowed shim primitive,
not a harness import, so the recovery sweep is unqualified default-deny too.)
