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

## Outcome contract (workq conventions)

Outcomes are announced through the **verdict ABI** (`patina_dst::verdict`), so
they arrive in the run's `patina.result/v1` envelope as `verdicts[]` and on
stderr as `PATINA_VERDICT` wire lines. The `PUBSUB_*` lines below are still
printed for log readability, but nothing downstream needs them.

- `Pass` under `label=pubsub-outcome` (exit 0) — every invariant held. Its detail
  carries `workload_seed=… published=… delivered=… heartbeats=… hash=…`, echoed
  as the `PUBSUB_RESULT` line. `hash` is an **order-invariant** SHA-256 over one
  row per published topic and per (subscriber, topic) delivery, each carrying
  the count and a wrapping-sum-of-FNV payload digest — nothing depends on how
  publishers interleave on a shared topic, so for a fixed guest `--seed` the
  hash is identical across Patina schedule seeds and across platforms.
  `heartbeats` is schedule-sensitive: reported, never hashed (workq's
  `attempts` convention).
- `Violation` (exit 1) — an invariant broke, under the invariant's own label:
  `seq-gap`, `malformed-frame`, `unsubscribed-topic`, `liveness-timeout` (a
  timeout despite live heartbeats), `incomplete-delivery`, or
  `payload-divergence`. Echoed as `PUBSUB_VIOLATION`.
- `AbortIntent` (exit 2) — an internal fail-closed fault, under `bind` or
  `broker-fault`, announced before the exit so the stop is attributed to this
  guest and never mistaken for a Patina refusal. Echoed as `PUBSUB_ABORT`.
- **No verdict**: `PUBSUB_FAILURE …` (exit 1), a liveness/transport miss — the
  run did not converge within the virtual-time budget, or a client hit an
  unexpected transport failure. The verdict ABI has no liveness kind, and
  whether a run *should* have converged depends on the injected faults the guest
  cannot see; Patina's liveness watchdog is the structural channel for that.

## Planted bugs (`--bug NAME`)

Each is one legible site, an async failure class only a deterministic schedule
catches reliably; the gate RED-proves each on a pinned seed and requires the
failing run to record + replay byte-identically.

| name | site | class | caught by |
|---|---|---|---|
| `lost-wakeup` | start gate: `Notify::notify_waiters` (edge, no permit) instead of `watch` (level), fired right after spawning the publishers — before any has been polled to its await, so the edge is lost outright | lost wakeup | convergence timeout → `PUBSUB_FAILURE not-converged` |
| `drop-read-remainder` | subscriber frame reader: one readiness event assumed to deliver exactly one frame; bytes after the first newline of a read are discarded | readiness-ordering / short-read assumption | per-topic seq contiguity → a `violation` verdict under `seq-gap` (+ `incomplete-delivery`) |
| `stale-timeout` | subscriber liveness deadline computed once at connect, never re-armed by traffic | timeout race | a `violation` verdict under `liveness-timeout` (+ `incomplete-delivery`) |

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
   run records + replays byte-identically;
5. TCP-stream fault leg: with `--net-jitter-nanos` + `--net-drop-permille` set,
   each seed's run must still converge to the same order-invariant outcome hash
   (a reliable stream reorders/delays but never loses data), the default-on
   vacuity diagnostic must report the faults as APPLIED (`PATINA_NET_FAULT_REPORT
   … vacuous=0`, never the "net fault knobs inert" warning), the faulted trace
   must differ from the no-fault trace at the same seed (non-vacuity), and the
   faulted run must record + strict-replay byte-identically.

Fault model: Patina's `--net-jitter-nanos` / `--net-drop-permille` knobs act on
the SimNet TCP *stream* path this app uses (task #37). Jitter adds a seeded
per-segment delivery delay; a "drop" is a reliable-transport retransmit — the
segment's delivery is delayed by a bounded RTO backoff, never lost — and
in-stream byte order is always preserved. Earlier revisions left these knobs
inert on the stream path (they only touched datagrams); that silent inertness
is now both fixed and guarded, by leg 5 above and by the default-on
`PATINA_NET_FAULT_REPORT` vacuity diagnostic.
