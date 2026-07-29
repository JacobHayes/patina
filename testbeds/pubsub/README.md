# pubsub — a minimal tokio pub-sub broker under Patina

A single process runs a **broker** and its **subscriber**/**publisher** clients
as tokio tasks over loopback TCP, on one current-thread runtime. The app was
designed as a real tokio program first: connection fan-in with per-connection
timers and backpressured fan-out is the problem shape where an async event loop
is the best tool — the classic single-threaded broker architecture (an
I/O-bound fan-out gains nothing from CPU parallelism). Under Patina, mio's
selector runs on the deterministic readiness reactor (kqueue on macOS, epoll on
Linux) and every timer on the virtual clock; nothing in the app is
Patina-specific except the `setup_complete()` lifecycle marker.

Why a broker rather than a connection-multiplexing proxy: both exercise
readiness fan-in, but the broker carries richer *final state* to audit — exact
per-subscriber delivery of every published message — so the outcome contract is
a delivery invariant, not just byte counts, and it adds heartbeat timers and
credit-window backpressure as load-bearing protocol elements rather than
decoration.

## Architecture

- **Core actor** owns all broker state (topic registry, per-topic sequence
  numbers); connection handler tasks parse lines into commands over an mpsc —
  the idiomatic tokio actor shape, no shared locks.
- **Credit-window flow control** (the MQTT receive-maximum / AMQP link-credit
  shape): each subscriber starts with 4 delivery credits and replenishes one
  per processed message (`CR 1`). Socket buffers alone would absorb this whole
  small workload invisibly, so real brokers meter on application credits — the
  writer blocks awaiting a credit before each `MSG`, its bounded queue fills,
  and the core's fanout parks: the designated slow subscriber (id 0, 15 ms per
  message) meters the entire pipeline back to the publishers' ACKs on every
  clean run.
- **Heartbeats**: each subscriber's writer emits `HB` after 40 ms of quiet; the
  LAST subscriber subscribes only to the never-published sentinel topic `idle`
  and survives the whole run on heartbeats alone, so the HB path is
  load-bearing — break it and that subscriber trips its 150 ms liveness
  timeout. During a credit stall the HB write doubles as the broker's
  failure detector for a departed subscriber; subscriber churn drops the
  subscriber from the registry, never the broker.

## Protocol (line-based)

| direction | line | meaning |
|---|---|---|
| client → broker | `SUB t0,t1` | subscribe this connection; broker answers `OK` |
| client → broker | `PUB <topic> <payload>` | publish; broker answers `ACK <topic> <seq>` |
| client → broker | `CR <n>` | replenish n delivery credits |
| client → broker | `DONE` | this publisher is finished |
| broker → subscriber | `MSG <topic> <seq> <payload>` | fanout, per-topic seq from 1 |
| broker → subscriber | `HB <n>` | heartbeat after 40 ms of quiet |
| broker → subscriber | `FIN` | all publishers done, stream complete |

Subscribers register before publishers start (a ready barrier), so the
delivery contract is exact: every subscriber of a topic receives every message
published to it, `seq`-contiguous.

## Output contract (workq conventions)

- `PUBSUB_RESULT seed=… published=… delivered=… heartbeats=… hash=…` — the
  deterministic final line. `hash` is an **order-invariant** SHA-256 over one
  row per published topic and per (subscriber, topic) delivery, each carrying
  the count and a wrapping-sum-of-FNV payload digest — nothing depends on how
  publishers interleave on a shared topic, so for a fixed guest `--seed` the
  hash is identical across Patina schedule seeds and across platforms.
  `heartbeats` is schedule-sensitive: reported, never hashed (workq's
  `attempts` convention).
- `PUBSUB_VIOLATION …` (exit 1) — an invariant broke: per-topic `seq` gap,
  malformed frame, unsubscribed-topic delivery, a liveness timeout despite
  heartbeats, incomplete delivery, or payload divergence.
- `PUBSUB_FAILURE …` (exit 1) — a liveness/transport miss: the run did not
  converge within the virtual-time budget, or a client hit an unexpected
  transport failure.
- `PUBSUB_ABORT …` (exit 2) — an internal fail-closed fault (bind failure, a
  task panic, a broker-side impossibility).

## Planted bugs (`--bug NAME`)

Each is one legible site, an async failure class only a deterministic schedule
catches reliably; the gate RED-proves each on a pinned seed and requires the
failing run to record + replay byte-identically.

| name | site | class | caught by |
|---|---|---|---|
| `lost-wakeup` | start gate: `Notify::notify_waiters` (edge, no permit) instead of `watch` (level), fired right after spawning the publishers — before any has been polled to its await, so the edge is lost outright | lost wakeup | convergence timeout → `PUBSUB_FAILURE not-converged` |
| `drop-read-remainder` | subscriber frame reader: one readiness event assumed to deliver exactly one frame; bytes after the first newline of a read are discarded | readiness-ordering / short-read assumption | per-topic seq contiguity → `PUBSUB_VIOLATION seq-gap` (+ incomplete-delivery) |
| `stale-timeout` | subscriber liveness deadline computed once at connect, never re-armed by traffic | timeout race | `PUBSUB_VIOLATION … liveness-timeout` (+ incomplete-delivery) |

## Gate

`./run-patina.sh` (exits nonzero on any regression):

1. build + explicit audit (control-plane `dlsym` residue only; every run below
   also passes the baked-in default-deny pre-run gate with **no** allowance);
2. clean runs: 5 schedule seeds x 3 repeats byte-identical (result line +
   trace hash), converged (`published=32 delivered=64`, exit 0),
   `heartbeats > 0` (the HB path is alive), and the outcome hash + delivered
   IDENTICAL across seeds (schedule-invariance of the outcome);
3. a recorded run strict-replays byte-identically;
4. planted-bug catch: each `--bug` on its pinned seed MUST be caught with its
   expected marker (fail-closed: a clean pass fails the leg), and the failing
   run records + replays byte-identically.

Honest scope notes: Patina's `--net-jitter-nanos` / `--net-drop-permille`
fault knobs act on SimNet *datagrams* and are inert on the TCP stream path
this app uses (verified: 100‰ drop converges byte-identically), so the gate
carries no jitter/drop leg — schedule seeds are the perturbation axis here.
That TCP-fault gap is recorded as a Patina finding, not designed around.
