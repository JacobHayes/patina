# Trace size limits: save-time enforcement and consistent caps

Status: fixed 2026-08-06. Found 2026-08-06 while reviewing `MAX_TRACE_BYTES`.

## Original symptoms

`patina-trace` had two resource limits (`crates/patina-trace/src/lib.rs`):

- `MAX_TRACE_BYTES = 64 MiB`
- `MAX_TIMELINE_EVENTS = 1_000_000`

Three problems with how they composed:

### 1. The byte cap was enforced only on read, never on save (fail-late)

The byte cap was checked in `TraceBundle::load`, `TraceBundle::from_slice`, and
the shim's `FdTraceTransport::read_bundle`, but not in `to_bytes` /
`write_atomic` / `Recorder::finish`. A record run could persist an over-limit
bundle successfully; the failure only surfaced when replay refused to open it.
That violated the fail-fast doctrine independent of the cap's value.

### 2. The byte cap made the event cap unreachable

Payload-free scheduler events (`task_yield` / `scheduler_next` + outcome,
compact JSON) serialize at roughly 80-100 bytes each, so 1M events is roughly
80-100 MiB — over the old 64 MiB byte cap. At the bench-enforced budget
(`MAX_TRACE_BYTES_PER_EVENT = 150.0`, `crates/patina-bench/src/lib.rs`) the old
byte cap bound at roughly 447k events, under half the event limit.

### 3. Payload-heavy adopter workloads hit the cap on modest datasets

`FsWrite` / `FsWriteAt` / `NetSend` / `NetTcpSend` record full payloads in the
operation and reads return `Outcome::Bytes`, all base64 (4/3 overhead), so trace
size scales with total I/O volume: the old 64 MiB cap limited a run to roughly
48 MiB of raw recorded I/O both directions combined.

## Fix

- `MAX_TRACE_BYTES` is now `256 MiB`.
- `TraceBundle::to_bytes` enforces the same byte limit as load/transport reads.
  `write_atomic`, `Recorder::finish`, and branch finalization all go through that
  save-time choke point, so an over-limit record fails before a trace file is
  written.
- The resource-limit message names the save-side failure as a serialized trace
  limit and tells the operator to reduce recorded event count/payload volume or
  split the run.
- Native trace-descriptor finalization now reports shutdown/finalization errors
  and aborts from the atexit finalizer, because atexit return values are ignored;
  save-time trace failures must not leave an apparently successful native run.

## Measurement used for the cap

Measured on this macOS/aarch64 workspace with the `testbeds/workq` SCHEDULE
(yield-points) path. The exact fuzz-sweep generation 5 was recorded first, then
the same SCHEDULE knobs were run with a larger job count to produce a high-boundary
sample below the 1M-event cap.

| Run | Trace bytes | Events | Bytes/event | Schedule boundaries | Boundaries/events | Events/boundary |
|---|---:|---:|---:|---:|---:|---:|
| workq SCHEDULE gen 5 (`jobs=24`) | 7,364,219 | 76,636 | 96.09 | 37,412 | 0.488 | 2.048 |
| workq SCHEDULE gen 5 knobs, `jobs=144` | 69,848,211 | 723,564 | 96.53 | 357,311 | 0.494 | 2.025 |

Schedule boundaries did **not** record 1:1 as trace events on this host: the
recorded trace carried about two trace events per reported scheduling boundary.
The measured compact schedule trace stayed under 100 bytes/event, but the
standing bench budget is 150 bytes/event; `1_000_000 * 150 B` is about 143 MiB.
A 128 MiB cap would still make that budget inconsistent with the 1M-event limit,
so the fixed cap is 256 MiB rather than 128 MiB. 256 MiB also leaves practical
headroom for payload-heavy traces without adding a pre-user config knob.

## Regression coverage

`patina-dst-trace` has a save-side regression test that serializes a valid bundle
under a deliberately small internal test limit and proves all three save paths
(`to_bytes`, `write_atomic`, and `Recorder::finish`) return
`TraceError::ResourceLimit` before writing a trace file. Existing load-side
resource-limit tests remain in place.
