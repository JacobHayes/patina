# `cargo patina minimize` oracle performance — measured investigation

Read-only investigation. No repo files were changed; every artifact lives under the
session scratchpad (`scratchpad/minperf/`).

**Host**: macOS arm64 (Darwin 25.5.0), 10 CPUs (4 performance + 6 efficiency).
**Binaries**: `target/release/cargo-patina` from repo HEAD `7b2085c` (verified no
`crates/**/*.rs` newer than the binary), copied to the scratchpad so a concurrent
rebuild could not move them mid-run. The checked-in
`testbeds/workq/target/patina/workq` was **stale** (it predates `--server-host` and
`--bug ignore-short-write`, so it silently produced 40 identical UNCLASSIFIED
generations); the harness was rebuilt with `CARGO_TARGET_DIR` pointed at the
scratchpad.

**Workload**: `testbeds/workq/acceptance.sh`'s pipeline, reproduced step by step —
`campaign --gens 40 --faults --swarm --dns-entry workq-server=127.0.0.1` over workq
with `--bug ignore-short-write`, then the same minimize oracle the script writes
(`replay`, grep stderr for `WORKQ_VIOLATION|WORKQ_ABORT final-wal wal corruption`,
non-zero exit = "still fails"), instrumented with per-call timestamps.

Two failing generations were measured end to end:

| | generation 14 | generation 19 |
|---|---|---|
| marker | `WORKQ_ABORT final-wal wal corruption` | `WORKQ_VIOLATION no-loss acked-job-2-never-terminated` |
| decisions | 944 | 846 |
| minimize result | 927 (**1.8 %** shrink) | 828 (**2.1 %** shrink) |
| oracle invocations | **9 014** | **11 530** |
| wall clock | **290.3 s** | **417.6 s** |
| productive deletions | 14 | 14 |
| oracle calls per productive deletion | 449 | 655 |

---

## 1. What the algorithm does

Entry point `execute_minimize_trace` (`crates/cargo-patina/src/lib.rs:6772`).

**The oracle** (`lib.rs:6797`) — per candidate, unconditionally: create a fresh
`tempfile::tempdir()`, `write_atomic` the whole bundle (~100 KB of JSON here),
`Command::status()` the user's oracle with `PATINA_MINIMIZE_TRACE` pointing at it,
and treat a non-zero exit as "failure preserved". There is **no memoization, no
batching, no parallelism, and no call or time budget** — the registry
(`crates/cargo-patina/src/help.rs:1934`) exposes only `--output`, `--timeline`, and
`--prune-branches` for trace minimization.

**Strategy selection** (`lib.rs:6785-6835`). A single unbranched timeline (this
case) runs a *joint loop*: `minimize_main` then `reduce_schedule`, repeated until a
whole round changes nothing.

**`minimize_index`** (`crates/patina-minimize/src/lib.rs:263`) is textbook ddmin: a
granularity ladder 2, 4, 8, … n; each pass cuts the reducible window into
`granularity` chunks and tries deleting each in order. On the **first accepted
deletion it lowers granularity by one and restarts the scan at index 0**; on a fully
rejected pass it doubles granularity, stopping once granularity ≥ window. Candidates
are structurally validated (`validate()`) before reaching the oracle.

**`reduce_schedule`** (`patina-minimize/src/lib.rs:370`) rewrites `SchedulerNext`
outcomes only — `collapse_switches` (rewrite the later of an adjacent differing pair
to the earlier task) and `canonicalize_order` (lower each pick toward the smallest
task id the run actually scheduled) — each restarting its own scan after any accept,
both iterated to a fixed point. Its doc comment already states that against a strict
full-replay oracle this pass "is a sound no-op".

**Termination** is fixed-point only: the search stops when a full round accepts
nothing, which by construction costs one complete confirmation round.

## 2. Where the 290 s goes

Per-call timings came from an instrumented copy of the acceptance oracle (recording
oracle entry, replay start/end, oracle exit). Averaged over all 9 014 calls of
generation 14 (mean 32.2 ms per candidate):

| component | total | share | mean per call |
|---|---|---|---|
| `patina replay` subprocess | 146.2 s | 50.4 % | 16.2 ms |
| oracle script's own `wc`/`grep` subprocesses | 42.3 s | 14.6 % | 4.7 ms |
| shell startup + patina candidate materialization | 101.5 s | 35.0 % | 11.3 ms |

Generation 19 splits the same way (47.4 % / 14.8 % / 37.7 %).

Supporting baselines (each 10–100 repetitions):

- full-trace `patina replay`: **15–16 ms** warm
- `cargo-patina` process spawn (`patina --version`): **1.8 ms**
- guest binary bare spawn: **1.6 ms**
- `#!/usr/bin/env bash` script spawn: **7.0 ms**
- **null-oracle control** — the same search driven by a shell oracle that accepts
  only the unmodified original and never runs the guest: 3 996 calls in 58.5 s =
  **14.6 ms per candidate with zero replay work**, of which ~7 ms is the shell and
  ~6 ms is patina's own tempdir + serialize + fork/exec.

**Half the wall clock is not replay.** The 16 ms replay is wrapped in ~16 ms of
per-candidate protocol: a bash interpreter, two more subprocesses inside it, a fresh
temp directory, and a 100 KB JSON write.

## 3. Where the 9 014 calls go

The exact candidate sequence was reconstructed by porting `minimize_index`,
`reduce_schedule`, and the CLI's joint loop to Python and replaying the *recorded
verdicts* through them. The reconstruction consumed exactly 9 014 verdicts and
produced exactly 927 decisions (generation 19: 11 530 / 828), so the port is
faithful and the attribution below is exact, not inferred.

| phase | calls (gen 14) | accepted | calls (gen 19) | accepted |
|---|---|---|---|---|
| round 1 — delta debug | 6 288 | **14** | 9 169 | **14** |
| round 1 — schedule | 431 | 0 | 333 | 0 |
| round 2 — delta debug | 1 864 | 0 | 1 695 | 0 |
| round 2 — schedule | 431 | 0 | 333 | 0 |

By candidate kind (gen 14): 5 622 single-event deletions, 2 528 multi-event chunk
deletions, 860 schedule rewrites, 4 up-front re-checks.

Four facts fall out of this:

1. **Every productive deletion came from round 1's delta debug.** Round 2 exists only
   to prove the fixed point and cost 2 295 calls (25.5 % of the run) for nothing.
2. **`reduce_schedule` accepted nothing** in either trace — 862 and 666 calls, 0
   accepts, exactly as its own doc comment predicts for a strict-replay oracle.
   The joint loop's premise (a schedule rewrite unblocking a deletion) never fired.
3. **19.4 % of candidates were exact duplicates** of an earlier candidate (gen 19:
   15.5 %); inside the confirmation round the duplicate rate is 63 % / 55 %.
4. **The scan restart dominates.** All 14 accepted deletions had span ≤ 2, and after
   each accept ddmin restarts at index 0 — so accepts land roughly every 650–850
   calls (gen 19 accepts at calls 2324, 2721, 3376, 4030, 4715, 5399, 6109, 6821,
   7575, 8340). That is the 449–655 calls-per-deletion figure.

**The accept rate is intrinsic, not a search defect.** Under strict replay almost
any deletion desynchronizes the recorded stream from every real execution; I
confirmed directly that deleting a single event at index 64, 500 or 900, a 10-event
block, the last 4 events, or the first half all fail closed loudly (exit 134,
`patina native shim fatal: … trace operation mismatch …`, no marker). Only 14 of 944
positions survive. **~2 % is the shrink that is actually available in this trace** —
no search strategy makes it larger.

Two related measurements kill the brief's "early-exit oracle" idea for this
workload: replay cost is **flat** across deleted position (16.1–16.6 ms in every
100-index bucket), i.e. divergence is detected late rather than aborting early; and
this bug's marker is printed by the guest's *final* WAL gate, so stopping at the
first marker saves nothing. Consistently, no prefix truncation reproduces at all
(binary search over trace length, 10 real oracle calls: shortest reproducing prefix
is the full 944).

## 4. Options, ranked

Payoff figures marked **measured** were run against the real replay oracle;
everything else is labelled as an estimate.

### 1. Reduce the fault-knob vector instead of the trace — **measured ~1000×**

The campaign hands each generation a 17–18 flag fault vector. Delta-debugging *that*
(drop one knob, keep the drop if the marker survives) instead of the decision stream:

| generation | knobs | result | oracle runs | wall |
|---|---|---|---|---|
| 14 | 17 → **2** | `--fs-short-permille 122 --dns-entry workq-server=127.0.0.1` | 20 | **0.3 s** |
| 19 | 18 → **2** | `--fs-short-permille 62 --dns-entry workq-server=127.0.0.1` | 21 | 0.4 s |
| 22 | 18 → **2** | `--fs-short-permille 199 --dns-entry workq-server=127.0.0.1` | 21 | 0.4 s |

The generation-14 minimal reproduction was verified standalone and prints the same
`WORKQ_ABORT final-wal wal corruption` in **20 ms**:

```
cargo patina run <workq> --seed 590918895341496304 \
  --fs-short-permille 122 --dns-entry workq-server=127.0.0.1 --swarm \
  -- --seed 7 --jobs 2 --workers 1 --producers 1 --base-port 5001 \
     --data-dir /workq --timeout-secs 30 --server-host workq-server \
     --bug ignore-short-write
```

0.3 s versus 290 s, and the answer ("only the short-write fault matters") is the one
a human or agent actually wants. Each candidate is a fresh seeded *run*, not a
replay, so the oracle contract is unchanged — non-zero exit means the failure
survives, and a candidate that stops reproducing is simply rejected.
**Correctness risk: low.** It answers a different question than trace shrinking and
does not reduce the decision stream, so it complements rather than replaces
minimize. **Gap it fills**: `minimize --scenario` today reduces only `--seed` and
`--param` values (`patina-minimize/src/lib.rs:612-709`); nothing reduces the
campaign's generated fault-knob vector, which is where campaign failures actually
come from.

### 2. Resume the scan after an accept, plus a candidate cache — **measured 3–3.7× fewer calls, 4.1–4.8× less wall, byte-identical output**

Replace "restart the scan at index 0 after every accepted deletion" with a sweep that
continues from the current position, iterated to a fixed point, and memoize verdicts
by candidate content:

| | gen 14 | gen 19 |
|---|---|---|
| current | 9 014 calls / 290.3 s | 11 530 calls / 417.6 s |
| resume-sweep + cache | **2 964 calls / 70.3 s** | **3 156 calls / 87.4 s** |
| result | 927 decisions | 828 decisions |

Both results are **byte-identical to what `cargo patina minimize` produced**
(verified with `patina trace diff`: "Result: identical"). It needed 4 sweeps to reach
its fixed point in both cases, so deletions really do unblock other deletions — the
iteration is load-bearing and must not be dropped.

**Correctness risk: low, and one-sided.** Every candidate is still decided by the
oracle, so no false "still violates" is possible; the only exposure is
*completeness* (a resumed scan could in principle find fewer deletions than a
restarting one), which iterating sweeps to a fixed point addresses and which the
identical outputs above confirm on these two traces. The memo is a pure
candidate→verdict map, sound for any deterministic oracle; to stay honest with the
fail-closed doctrine it should re-run a sampled fraction of cache hits and abort
loudly on disagreement rather than silently trusting a nondeterministic oracle.
I measured the two changes together, not separately; the cache's isolated
contribution is bounded by the measured duplicate rate (19.4 % / 15.5 %).

### 3. Parallel oracle batches — **measured 4.9× throughput**

Concurrent replays of the same trace, 48 replays per configuration:

| workers | 1 | 2 | 4 | 8 | 12 |
|---|---|---|---|---|---|
| replays/s | 62.3 | 119.4 | 204.7 | **302.7** | 322.6 |
| effective ms/replay | 16.1 | 8.4 | 4.9 | **3.3** | 3.1 |

**Determinism caveat (the brief's question):** the *oracle* is already hermetic —
each candidate gets its own temp directory and the guest's filesystem, clock, network
and entropy are virtualized, so concurrent candidates cannot interfere (workq binds
port 5001 in every one of them without conflict). What must be preserved is the
*search's* determinism: evaluate a batch speculatively but apply accepts in scan
order, and re-verify any combined candidate before keeping it, so the result does not
depend on which worker finished first. **Correctness risk: low if opt-in** — an
oracle recipe that writes to a fixed shared path outside `$PATINA_MINIMIZE_TRACE`
would break, so a `--jobs N` flag should document the isolation requirement.
Multiplies with option 2: 2 964 calls at 8-way concurrency is an estimated ~20 s
against the measured 290 s.

### 4. Cut the per-candidate protocol overhead — estimated up to ~1.5×

50 % of wall clock is not replay (§2). Two cheap parts: patina re-creates a temp
*directory* per candidate when one reused path would do, and the shipped oracle
recipe pays 7.0 ms of bash startup plus 4.7 ms of `wc`/`grep` subprocesses per call.
A built-in marker oracle (replay in-process, match a caller-supplied stderr pattern)
would remove ~11 ms of the 32 ms per candidate. **Risk: low for the tempdir reuse;
medium for a built-in oracle**, which must keep failing closed (see option 6).

### 5. Skip or defer `reduce_schedule` for strict-replay oracles — 6–10 %, measured zero benefit today

862 calls (gen 14) and 666 (gen 19), zero accepts, exactly as documented. Rather than
deleting the pass (it is real work for marker-based, order-independent oracles), run
it **once after** the deletion fixed point instead of inside the joint loop, or probe
it: try a handful of rewrites and skip the pass when all are rejected.
**Correctness risk: none** — skipping a pass can only under-minimize.

### 6. Harden the oracle recipe (correctness, not speed)

`testbeds/workq/acceptance.sh`'s oracle greps stderr and **ignores the replay's exit
status**, so a candidate whose replay aborts on divergence *after* the guest already
printed the marker would be accepted — a fail-open direction. I tried to construct
one (corrupting the last `scheduler_next` of the minimized trace) and could not: the
divergence preempted the marker, exit 134, no match. So this is a **latent** hazard
on this trace, not an observed defect. It matters mainly because option 4's
"early-exit at first marker" variant would make it reachable by construction —
stopping at the marker means never observing the later divergence. Any built-in or
documented oracle should require a clean replay (no `patina native shim fatal` line)
in addition to the marker.

### Not worth pursuing

- **Early-exit at the first violation marker** — measured flat replay cost across
  deletion position (divergence is detected late) and this bug's marker is emitted by
  the final WAL gate, so there is nothing to skip.
- **Coarser-to-finer restructuring** — ddmin already ladders, and the coarse rungs
  (granularity 2–256) cost only 951 calls of the 6 288 in round 1. All 14 accepts had
  span ≤ 2. Keeping the ladder is cheap; the cost is in the fine sweeps.
- **A smarter global search over deletions** — the ceiling is ~2 % (§3). The lever is
  cost per call and calls per accept, not a better subset search.

## 5. Suggested order of work

1. Fault-knob reduction as a first-class reducer (option 1) — largest payoff, smallest
   change, and it makes minimize optional for campaign triage.
2. Resume-sweep + memoized candidates (option 2) — measured 4× with byte-identical
   output on both traces.
3. `--jobs N` parallel oracle batches (option 3), which multiplies with (2).
4. Protocol overhead and the schedule-pass deferral (options 4, 5) as cleanup.
5. Oracle fail-closed hardening (option 6) alongside any built-in oracle work.

## Reproduction artifacts

All under `scratchpad/minperf/`: `bin/` (pinned cargo-patina + freshly built workq),
`campaign.json` / `campaign-out/`, `oracle-timed.sh` (instrumented acceptance
oracle), `oracle.log` / `oracle19.log` (per-call timings), `analyze.py` (wall-clock
split), `reconstruct.py` + `attribute.py` (exact phase attribution from recorded
verdicts), `variants.py` (resume-sweep measurement), `knob_reduce.py` (fault-knob
reduction), `null-oracle.sh` (protocol-overhead control).
