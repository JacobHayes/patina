# Record/replay robustness: incomplete native traces

Status: fixed.

## Field symptoms

1. Native `run --record` could leave a zero-byte `.patina` file when the guest
   died before the atexit finalizer wrote the transport bundle. The later
   `replay` failed at discovery time with a generic JSON EOF parse error.
2. A campaign generation killed by its wall-clock timeout could leave a non-empty
   but incomplete trace scratch file. If copied into `failures/`, replay could
   die as a signal-shaped native failure instead of refusing the bad artifact by
   name.
3. Some fs-crash runs ended with no guest output beyond the pre-run deny-trap
   note and an empty/unreplayable trace, leaving the generation unclassifiable
   without rerunning it.

## Root causes

- The native supervisor created the requested record path before launching the
  guest and handed that final-path descriptor to `PATINA_TRACE_FD`. If the guest
  aborted, timed out, or the supervisor was killed before runtime finalization,
  the requested path already existed as an empty or partial file.
- The trace loader treated empty/truncated JSON and missing core metadata as
  generic parse errors, so replay named serde's EOF/missing-field detail rather
  than the real refusal: the record never finalized into a complete bundle.
- Campaign failure-trace saving only checked `metadata.len() > 0` and copied the
  scratch file directly, so a partial trace could be promoted to a saved failure
  artifact.
- Campaign timeout killed only the child `cargo patina run` process; the guest it
  supervised could remain in the same generation tree long enough to keep trace
  scratch state ambiguous.

## Fix

- Native record mode now writes through a supervisor-owned sibling temp file and
  commits only after the child exits and `TraceBundle::load` validates the temp
  bundle. Invalid/empty/partial temps are removed and the requested trace path is
  left absent. The JSON envelope and stderr get one named infra marker:
  `PATINA_INFRA native_run ... trace=incomplete ...`.
- `TraceError` has an `Incomplete` variant for empty files, truncated JSON, and
  missing required top-level/core metadata. Replay now refuses these upfront with
  `incomplete trace ...` and the normal CLI error exit, before guest exec.
- Campaign failure traces are loaded and re-written with `TraceBundle::write_atomic`
  before being saved under `failures/`; invalid scratch traces are skipped.
- Campaign timeout launches each generation in its own process group and kills the
  process group, then removes native trace temp siblings for that generation.

## Evidence

Focused regression tests:

- `cargo test -p patina-dst-trace`
- `cargo test -p cargo-patina --lib`
- `cargo test -p cargo-patina --test end_to_end native_record_abort_leaves_trace_absent_and_infra_classified -- --nocapture`
- `cargo test -p cargo-patina --test end_to_end native_replay_refuses_incomplete_traces_before_guest_exec -- --nocapture`
- `cargo test -p cargo-patina --test end_to_end campaign_timeout_does_not_save_incomplete_trace -- --nocapture`

The landing gate for this trace/runtime/native-touching change is `mise run check`.
