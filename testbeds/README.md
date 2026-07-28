# Testbeds

Guests for exercising Patina end to end. Every harness binary is 100% std-pure
— no Patina imports, no `cfg(patina)` — so the same source runs both natively
and under Patina with identical arguments.

| Testbed | Program under test | Shape | Patina phase exercises |
|---|---|---|---|
| [`workq/`](workq/) | itself — a single-process durable work queue (WAL segments + loopback UDP + worker/producer threads) | guest: server, workers, producers, and invariant checks in one process | WAL crash-recovery, SimNet drop/reorder/jitter, virtual-time visibility timeouts + retries, cooperative buggify faults, fail-closed recovery |
| [`liveness-campaign/`](liveness-campaign/) | a small buggify-gated planted-bug fixture | guest: a deterministic bug the liveness/converge watchdog must catch | liveness/heal-then-converge oracles, buggify activation |
| [`buggify-wasi/`](buggify-wasi/) | a small `wasm32-wasip1` buggify fixture | guest: several buggify site kinds + a plantable `always!` violation | guest-side buggify lowering on WASI, `PATINA_SDK_REPORT` parsing, record/replay determinism |

`workq` is the flagship: `workq/run-patina.sh` runs its full self-checking
battery (determinism, record/replay, net/fs faults, crash-recovery, buggify
sweep) per push in CI, and `workq/fuzz-sweep.sh` is the home of the
randomized-but-deterministic fault-combination campaign (including its
schedule-fuzz tier) that runs nightly. `liveness-campaign` and `buggify-wasi`
are small fixtures.

Conventions:

- Oracles live inside the guest binaries (nonzero exit + a machine-parseable
  line: `WORKQ_RESULT …` / `WORKQ_VIOLATION …`), so a violation under Patina is
  a deterministic failing run that `explore`/`minimize` can bisect.
- Every harness's failure path has been demonstrated (corrupted baseline /
  divergent logs / stress-tripped race) — none of these gates is unable to fail.
- Versions are pinned exactly (`=x.y.z` deps).
