# Trace size limits: load-only enforcement and inconsistent caps

Status: open. Found 2026-08-06 while reviewing `MAX_TRACE_BYTES`.

## Symptoms

`patina-trace` has two resource limits (`crates/patina-trace/src/lib.rs:51-52`):

- `MAX_TRACE_BYTES = 64 MiB`
- `MAX_TIMELINE_EVENTS = 1_000_000`

Three problems with how they compose:

### 1. The byte cap is enforced only on read, never on save (fail-late)

Checked in `TraceBundle::load`, `TraceBundle::from_slice`, and the shim's
`FdTraceTransport::read_bundle`. Not checked in `to_bytes` /
`write_atomic` / `Recorder::finish`. A record run can persist a 100 MiB
bundle successfully; the failure only surfaces when replay refuses to open
it — the repro artifact is discovered to be unusable at the worst possible
time. Violates the fail-fast doctrine independent of the cap's value.

### 2. The byte cap makes the event cap unreachable

Payload-free scheduler events (`task_yield` / `scheduler_next` + outcome,
compact JSON) serialize at ~80-100 bytes each, so 1M events is ~80-100 MiB —
over the 64 MiB byte cap. At the bench-enforced budget
(`MAX_TRACE_BYTES_PER_EVENT = 150.0`, `crates/patina-bench/src/lib.rs:31`)
the byte cap binds at ~447k events, under half the event limit. The
schedule-fuzz campaign has already produced gens with ~924k boundaries; if
those map ~1:1 to recorded events, a recorded run at that scale exceeds the
byte cap today.

### 3. Payload-heavy adopter workloads hit the cap on modest datasets

`FsWrite` / `FsWriteAt` / `NetSend` / `NetTcpSend` record full payloads in
the operation and reads return `Outcome::Bytes`, all base64 (4/3 overhead),
so trace size scales with total I/O volume: 64 MiB caps a run at ~48 MiB of
raw recorded I/O both directions combined. An LSM workload with compaction
write-amplification (e.g. the SlateDB dogfooding) crosses that quickly.

## Recommended fix (unscheduled)

1. Add the symmetric save-time check (in `to_bytes` / `write_atomic`) so an
   over-limit record fails loudly at the source — worth doing regardless of
   the chosen cap.
2. Bump the byte cap so the two limits are mutually consistent. 1M events x
   the 150 B/event bench budget suggests 256 MiB as the natural constant. A
   config knob is an alternative but cuts against the no-knobs-pre-users
   stance.
3. Measure before picking the number: record one high-boundary schedule gen
   (~900k boundaries) and one SlateDB crash-recovery run and inspect actual
   bytes and bytes/event. If schedule boundaries do not record 1:1, 128 MiB
   may be plenty.
