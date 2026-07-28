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
invariants — durability, no lost jobs, exactly-once. A breach prints
`WORKQ_VIOLATION` and exits non-zero.

### Two kinds of determinism

- **Schedule determinism (per machine).** On one operating system, a given seed
  replays the identical thread interleaving every time, so a recorded run
  reproduces byte-for-byte.
- **Outcome invariance (across machines).** The `WORKQ_RESULT applied_hash` is a
  digest of *what happened to each job* — keyed by the job's stable client
  identity, not the order things finished in. So macOS and Linux, whose thread
  schedules genuinely differ, still agree on the outcome hash.

## Running it

Natively, on your real OS (a quick sanity check — not deterministic, because
real threads and real UDP are involved):

```sh
./run-native.sh
```

Under Patina — the real gate. This builds the queue, then runs the full
self-checking battery: clean-run determinism, record/replay, network faults,
disk-crash recovery, in-process crash-recovery, a cooperative-fault sweep, and
the seeded-bug demo below:

```sh
./run-patina.sh
```

Run it once by hand to see the shape of a single simulated run:

```sh
cargo patina run ./target/patina/workq --seed 1 -- --jobs 24 --data-dir /workq
```

## The one-command bug-catch demo

The queue ships with two deliberately planted bugs, off by default and enabled
with `--bug NAME`. Each is a subtle mistake a real engineer could make, and each
is caught by the queue's *own* invariants — no special test assertion:

- **`dedup-ignore-producer`** — the server de-duplicates retried enqueues by the
  request number alone, forgetting *which* producer sent it. Two producers using
  the same request numbers collide, half the jobs vanish, and the run can never
  finish.
- **`skip-redelivery-commit`** — when a re-delivered job finally completes, the
  server acknowledges it but skips writing the "done" record, assuming an earlier
  delivery already logged it. The durable log quietly loses a completed job.

Watch Patina catch one (it fails, loudly and reproducibly):

```sh
cargo patina run ./target/patina/workq --seed 2 --buggify=500 --buggify-after-setup \
  -- --jobs 24 --data-dir /workq --bug skip-redelivery-commit
```

`./run-patina.sh` leg **[7]** pins a catching seed for each bug and *requires*
that Patina catch it (a clean pass there fails the leg — the demo can never go
quiet), then records and strict-replays the failing run to prove the bug
reproduces byte-for-byte.

## Fuzzing many faults at once

`run-patina.sh` tests each fault in isolation. `fuzz-sweep.sh` crosses them:

```sh
./fuzz-sweep.sh 1 100     # run 100 randomized-but-deterministic fault combinations
./fuzz-sweep.sh --selftest
```

Every generation's fault mix is a pure function of its number, so any run is
reproducible by number alone. Roughly a fifth of generations run a specially
instrumented build that makes fine-grained thread interleavings schedulable, to
hunt for races the coarse runs would miss. The sweep always fuzzes the *clean*
app; the seeded bugs live only in the demo above.
