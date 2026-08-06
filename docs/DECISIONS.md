# Decision log — autonomous build-out run, 2026-08-06

Coordinator decision log for the goal: implement the open arcs
(`docs/arcs/README.md`), fix the bug reports (`docs/bugs/`), and fold in the
SlateDB dogfooding feedback (`PATINA-SLATEDB-FEEDBACK.md`, change `knltxlvn`;
`docs/bugs/trace-size-limits.md`, change `vqzuznpk`). The user is afk; every
non-obvious call made during the run is recorded here for later review.
Newest entries at the bottom of each section.

## SlateDB feedback triage (the 14 items)

Per user direction, these are not all bugs — each is classified as **fix**
(point defect), **arch** (architectural decision, recorded here), or **docs**
(documented limitation/guidance).

| # | Item | Class | Disposition |
|---|---|---|---|
| 1 | `--yield-points` link fails on dependency `cdylib` (`R_X86_64_PC32` vs `environ`, non-PIC `patina_posix.o`) | fix | Compile shim objects as PIC and/or stop injecting shim objects into non-binary dependency artifacts (only the final bin link needs them). Builder to determine which; both may be right. |
| 2 | Audit emits a flat unsupported-symbol list with no provenance | fix | Audit should attribute each unsupported import to the defining object/archive member (and crate where recoverable). Fail-closed behavior itself was correct. |
| 3 | Static ctors call interposed APIs before runtime setup; error claims the binary wasn't run under `cargo patina run` | fix + docs | Keep failing closed (running ctors deterministically is out of scope for now — **arch**), but the diagnostic must distinguish "interposed call before runtime init (likely static constructor)" from "not launched via cargo patina run". Document the `#[ctor]` limitation and the cfg-guard workaround the SlateDB experiment used. |
| 4 | Native run clears guest env; `setenv` fails closed | arch + fix | Immutable, empty-by-default deterministic env is by design (host env is a nondeterminism source) — keeping it. Ergonomics fix: add explicit `--env KEY=VALUE` (repeatable) to inject values into the deterministic env, recorded in trace metadata so replay reproduces them. `setenv` stays fail-closed for now; revisit if a real adopter needs in-process mutation (it could be modeled deterministically, but no consumer justifies it yet — no-knobs-pre-users). |
| 5 | Guest fs starts without `/tmp` | fix | Seed the deterministic fs with `/tmp` (and the guest temp dir convention) by default. A missing-standard-path failure surfacing as an app-level `NotFound` violates fail-loudly ergonomics. |
| 6 | Host entropy not modeled (`/dev/urandom`, `getrandom` → ThreadRng init fails) | fix (arc) | Model guest entropy from the seeded, PRF domain-separated stream — this is the entropy domain of the unified-fault-knobs arc; pulled forward as an early deliverable of that arc's fs/entropy wave rather than a standalone hack. |
| 7 | Panic backtraces mostly `<unknown>`; `RUST_BACKTRACE` couldn't be passed | fix + follow-up | `--env` (item 4) unblocks `RUST_BACKTRACE=1`. Symbolization of native-guest backtraces: investigate alongside coverage-depth's offline symbolization work (shared machinery); not blocking. |
| 8 | `--record` can leave zero-byte / unusable traces on abnormal exit | fix | Trace finalize must be atomic-or-absent with a loud classification: never a zero-byte file that only fails at replay. Cluster with 11 and 14. |
| 9 | `--buggify=N` value form doesn't arm SDK buggify; campaign generates that form (silent vacuity) | fix | Builder running (workspace `patina-ws-buggify`): fix value-form arming + red-before/green-after detector + campaign-level vacuity class per detection-before-fixes. |
| 10 | Campaign keeps guest argv static across generations | docs | By design: per-generation variation belongs to patina-side seeds; guests that want varied workloads derive them from the deterministic RNG (`auto` seed pattern, which the SlateDB harness adopted). Document the pattern; reject argv templating for now (no consumer, knob-cruft risk). |
| 11 | Campaign timeout traces don't replay (`terminated by a signal`) | fix | A saved trace either replays deterministically or replay refuses with a named classification (e.g. incomplete-by-timeout). Signal-death is never an acceptable answer. Cluster with 8/14. |
| 12 | `campaign --faults` doesn't choose fs crash points | fix (arc) | Exactly the unified-fault-knobs arc's campaign integration — fs crash/torn knobs join the campaign's generated per-generation choices and summaries. |
| 13 | Directory open → `EISDIR` blocks parent-dir fsync durability pattern | fix | Model `O_RDONLY` open of directories + `fsync` on a directory fd in the deterministic fs, and make namespace durability (rename/link visibility after crash) part of the fs crash model. Prerequisite for credible LSM crash-recovery claims (SlateDB explicitly skipped parent-dir sync because of this). |
| 14 | fs-crash failures sometimes leave only pre-run diagnostics (no guest output, empty trace) | fix | Same robustness cluster as 8/11: every run must end in a classifiable state (guest outcome, named refusal, or named infra failure) with a usable-or-absent trace. |

Task mapping: items 1, 2, 3, 4+5, 8+11+14, 13 become dedicated fix tasks;
6 and 12 ride the unified-fault-knobs arc; 7 rides 4 plus a coverage-depth
follow-up; 10 becomes docs/guidance. `docs/bugs/` gets one report per fix
cluster so the fixes have citable symptom records.

## Run-level decisions

- **2026-08-06 — decision log location.** Single file `docs/DECISIONS.md`
  (this file) rather than scattered per-doc notes, per user request for one
  easy-to-find place. Builder-level judgment calls from subagent reports are
  copied here when they are more than mechanical.
- **2026-08-06 — landing base.** New work stacks on the local trunk
  (`vtoqkxyr` "wip: add docs"); the sibling wip changes `knltxlvn` (slatedb
  notes) and `vqzuznpk` (trace-size bug doc) stay as-is and get linearized at
  landing time. Fix work for the trace bug is based directly on `vqzuznpk` so
  the report and fix travel together.
- **2026-08-06 — clap-config-eval go.** The /goal directive to "implement the
  open planned arcs" is read as the explicit go the arc docs were waiting on,
  including the clap spike (its doc says "launches on explicit go").
- **2026-08-06 — feedback #9 did not reproduce on macOS at trunk.** The
  `--buggify=N` value form armed the SDK correctly in local repro. Shipped the
  structural fix anyway: fail-closed fingerprint/metadata coherence guards at
  shim, runtime, and trace levels — if the SlateDB condition recurs (it was
  observed on Linux x86_64), it is now a loud refusal naming the vacuity
  instead of silent scheduler-only coverage. Follow-up task tracks a Linux
  repro attempt.
- **2026-08-06 — fault-knobs Wave A trace shape.** Runtime `FaultConfig` is
  nested (fs/net/clock) but the trace `FaultConfigRecord` stays flat to avoid
  trace-format churn; the cross-target canonical entropy hash was updated
  intentionally because domain-separated seeding changes deterministic entropy
  output (expected, one-time).
- **2026-08-06 — SlateDB-side harness findings are out of scope.** Items in
  `SLATEDB-SANDBOX-NOTES.md` (bank fenced-close neutrality, recovery scenario
  stabilization) live in the sandbox SlateDB checkout, not this repo; nothing
  to land here beyond the patina-side fixes above.
