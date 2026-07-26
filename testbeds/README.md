# Testbeds

Real-world programs and planted-bug guests for exercising Patina end to end.
Each testbed is native-first: it must build and run **correctly without
Patina** (its `run-native.sh` proves that), and swaps to Patina by changing a
single `RUNNER` variable. Harness binaries are 100% std-pure — no Patina
imports, no `cfg(patina)` — so the same source runs both ways with identical
arguments.

| Testbed | Program under test | Shape | Patina phase exercises |
|---|---|---|---|
| [`ripgrep/`](ripgrep/) | ripgrep 15.2.0 (unmodified, pinned fetch) | host-driver: battery script runs the guest binary per search | filesystem model, threads, whole-package native builds |
| [`redb-harness/`](redb-harness/) | redb 4.1.0 (embedded ACID KV) | guest: seeded workload + in-memory oracle in one binary | CrashFs fsync/torn-write injection, durability invariants |
| [`raft-harness/`](raft-harness/) | tikv raft 0.7.0 (3-node cluster, threads + loopback UDP) | guest: cluster, invariants, and driver in one process | SimNet drop/reorder/partition, virtual-time elections, crash-restart |
| [`buggy-smoke/`](buggy-smoke/) | itself — six deliberately planted bugs | guest: `--bug <name>` scenarios with internal assertions | canary: each Patina capability must find "its" bug |

Conventions:

- `run-native.sh` — builds and verifies the testbed on the real OS. Exit 0
  means the harness itself is sound. These scripts are safe to run
  concurrently.
- `run-patina.sh` — the intended Patina invocation. UNTESTED sketches until
  the Patina phase lands; not wired into `run-native.sh`.
- Oracles live inside the guest binaries (nonzero exit + a machine-parseable
  line: `RESULT …`, `RAFT_RESULT …`, `BUG_CAUGHT …`), so a violation under
  Patina is a deterministic failing run that `explore`/`minimize` can bisect.
- Every harness's failure path has been demonstrated (corrupted baseline /
  corrupted db / divergent logs / stress-tripped race) — none of these gates
  is unable to fail.
- Versions are pinned exactly (fetch scripts verify shas; `=x.y.z` deps).
