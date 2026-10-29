# workq — a durable work queue you can break on purpose

`workq` is a small, self-contained work queue. Programs (**producers**) hand it
jobs; the queue writes each job to disk so it is never lost, then hands jobs out
to **workers** that do the work. It is the kind of component that sits behind a
"we'll process that in the background" button in a real system.

What makes this copy interesting is that it runs under **Patina**, a testing
runtime that replaces the operating system underneath the program with a
simulated one. Patina can drop network packets, crash the disk, and reorder
threads — all on a *virtual* clock, and all **deterministically**: the same seed
always produces the exact same run. So a bug that would show up once in a million
times in production shows up reliably here, and can be replayed byte-for-byte.

The whole thing is ~1,800 lines of plain Rust with only two dependencies, meant
to be readable end to end in one sitting.

## The moving parts

Everything runs inside **one process**, as a handful of threads talking to each
other over loopback UDP:

- **Server** (`server.rs`) — owns the queue and the write-ahead log. It accepts
  jobs, hands them to workers, and records every important step to disk *before*
  telling anyone it happened.
- **Write-ahead log** (`wal.rs`, `wire.rs`) — an append-only file of plain-text
  lines, each ending in a CRC checksum, so you can literally `cat` it to read the
  queue's whole history. If the process crashes mid-write, recovery tells a
  half-written *last* line (safe to drop) from real corruption in the *middle* of
  the log (refuse to start — never silently lose committed data).
- **Producers** (`producer.rs`) — enqueue a fixed, seed-derived batch of jobs,
  retrying whenever an acknowledgement gets lost.
- **Workers** (`worker.rs`) — poll for jobs, "process" them, and record the
  result into one shared accumulator.

Two ideas keep it correct under chaos:

1. **At-least-once delivery.** A lost message, an expired lease, or a crash all
   cause a job to be re-sent. Nothing is ever dropped.
2. **Exactly-once effect.** Because a job can be delivered more than once, each
   worker checks a shared guard before applying a job's effect, so re-processing
   is a harmless no-op. This guard is the piece the deterministic scheduler
   stress-tests across every possible thread interleaving.

At the end of a run the program re-reads the log from disk and checks its
invariants — durability, no lost jobs, exactly-once. A breach is reported through
the **verdict ABI** (`patina_dst::verdict`) as a `Violation` under the broken
invariant's label, and the run exits non-zero. That verdict is what the campaign
classifier, the sweep scripts, and a `minimize` oracle read; the `WORKQ_*` lines
the program also prints are a human echo of it.

### Two kinds of determinism

- **Schedule determinism (per machine).** On one operating system, a given seed
  replays the identical thread interleaving every time, so a recorded run
  reproduces byte-for-byte.
- **Outcome invariance (across machines).** The `applied_hash` a clean run
  reports in its `Pass` verdict (`label=workq-outcome`) is a digest of *what
  happened to each job* — keyed by the job's stable client identity, not the
  order things finished in. So macOS and Linux, whose thread schedules genuinely
  differ, still agree on the outcome hash.

## Running it

Under Patina — the real gate. This builds the queue, then runs a short campaign
(below), the fail-closed recovery self-test, and the seeded-bug demo:

```sh
./run-patina.sh
```

Run it once by hand to see the shape of a single simulated run. The script
stages the binary under `CARGO_TARGET_DIR` (default:
`../../target/testbeds/workq/patina/workq` from this directory):

```sh
cargo patina run ../../target/testbeds/workq/patina/workq --seed 1 -- --data-dir /workq
```

Unless `--jobs`, `--workers` or `--producers` pin them, the queue draws its
own workload: 16 to 64 jobs, 2 to 4 workers and 1 or 2 producers. Under Patina
the draw is a pure function of the run seed, so a reproduce command re-draws the
same workload. The `WORKQ_WORKLOAD` line shows what the run drew and its
convergence budget (`--timeout-secs`, by default 120 virtual seconds per 16
jobs). The draw is kept in the data dir, so a process restarted after a crash
resumes the same workload.

## The one-command bug-catch demo

The queue ships with five deliberately planted bugs, off by default and enabled
with `--bug NAME`. Each is a subtle mistake a real engineer could make, and each
is caught by the queue's *own* invariants — no special test assertion.

- **`dedup-ignore-producer`** — the server de-duplicates retried enqueues by the
  request number alone, forgetting *which* producer sent it. Two producers using
  the same request numbers collide, half the jobs vanish, and the run can never
  finish.
- **`skip-redelivery-commit`** — when a re-delivered job finally completes, the
  server acknowledges it but skips writing the "done" record, assuming an earlier
  delivery already logged it. The durable log quietly loses a completed job.
- **`apply-check-outside-lock`** — the worker asks "have we already applied this
  job?" *before* taking the lock that guards the apply, instead of inside it. When
  the same job is delivered to two workers at once, both can answer "no" and each
  applies it — a classic check-then-act race that does the work twice.
- **`ignore-short-write`** — the log treats a short write as a whole one, so a
  record the disk only partly took is acknowledged as durable.
- **`skip-wal-fsync`** — the log acknowledges a record as durable without
  fsyncing it. Only a crash can show it, and only one that takes the machine
  down: after a process crash the page cache still holds the record, after a
  machine crash (`--crash-kind machine`, the default) it is gone.

Watch Patina catch one (it fails, loudly and reproducibly):

```sh
cargo patina run ../../target/testbeds/workq/patina/workq --seed 2 --buggify=500 --buggify-after-setup \
  -- --jobs 24 --data-dir /workq --bug skip-redelivery-commit
```

`./run-patina.sh` leg **[3]** pins a catching seed window for each bug and *requires*
that Patina catch it (a clean pass there fails the leg — the demo can never go
quiet), then records and strict-replays the failing run to prove the bug
reproduces byte-for-byte.

## Fuzzing many faults at once

`campaign.json` crosses every fault `cargo patina campaign` can draw for the
queue. Each generation draws its schedule seed, its workload, net and sleep
faults, cooperative buggify faults and a swarm subset of them from the
generation number, restarts the server in-process once six jobs complete, and
draws a crash: a per-operation crash rate and a crash kind. The first write,
fsync, close, rename or network send the rate hits kills the whole process, or
the whole machine, and restarts it from what the crash left on disk. The restarted process cannot remember
what the crashed one acknowledged, so the campaign passes `--ack-ledger`:
producers also record each ack in a file of their own, and the restarted run
checks that every job acked before the crash is still in the log it recovered.
The campaign always sweeps the *clean* app; the seeded bugs live only in the
demo above.

```sh
cargo patina campaign ../../target/testbeds/workq/patina/workq --spec campaign.json
```
