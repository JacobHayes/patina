# Swarm class deselection vs the `+buggify` fingerprint (SlateDB feedback item 9)

Status: fixed.

## Field symptoms

A SlateDB campaign run with `--buggify=<N> --swarm` reported cooperative-SUT
(buggify) coverage that was not there. The run's `PATINA_SDK_REPORT` line read

```
PATINA_SDK_REPORT enabled=0 fire_permille=372 activation_permille=250 ...
```

— buggify disabled, yet carrying the exact permilles the operator had asked for.
Read on its own, that line says "the `--buggify=372` value form was accepted and
then ignored", and that is what the original reduction concluded: it blamed the
`--buggify=N` *value form* and reported the bare `--buggify` switch as the
workaround.

## What the original report believed, and why it was wrong

The original item-9 report named the value form (`--buggify=N`) as the cause. It
was not. The value form arms buggify correctly in every family; a local macOS
repro at trunk could never reproduce the failure, which is recorded in the
decision log as "feedback #9 did not reproduce on macOS at trunk".

The reduction was misled by an ambiguity in the report line itself. `enabled=0`
has two very different causes and, at the time, looked identical in both:

1. the operator never asked for buggify; or
2. the operator asked for it and **swarm deselected it for this generation**.

The SlateDB run was case 2. `--swarm` applies a seed-derived subset of the
enabled fault classes each generation, so roughly half of all generations run
*without* buggify by design. The reduction kept the `--buggify=N` variable and
dropped `--swarm` when simplifying, which silently moved the run into case 1's
"works fine" behavior and made the value form look guilty. On Linux x86_64 the
condition reproduced from the original artifacts; five of eight seeds hit it.

## Root cause

Swarm masking produced a run whose *declared* configuration disagreed with its
*effective* configuration.

- The supervisor composes the compatibility fingerprint from the CLI flags
  before the run starts, so `--buggify=N` folds a `+buggify` component into it.
- The mask is a seed-derived draw made **inside the guest**, at
  `RuntimeBuilder::build`, after the fingerprint has already been fixed. When the
  draw dropped the `buggify` class it cleared `config.buggify.enabled` and
  nothing else: the fingerprint kept declaring `+buggify`, and the requested
  permilles stayed in the config, which is exactly the `enabled=0
  fire_permille=372` line above.

Once the fail-closed coherence guards landed (the structural fix shipped for the
first, incorrect diagnosis), that incoherence stopped being silent and became a
loud refusal — but a refusal of a *legitimate* run:

```
patina: the deterministic runtime failed to initialize: invalid Patina configuration:
fingerprint declares +buggify but buggify is not enabled; refusing vacuous SDK
buggify coverage
```

exit 134. Swarm masking is legitimate, so this turned a silent-coverage bug into
a usability regression. A `--buggify --swarm` campaign was hit hardest, because
the campaign emits both flags on every generation: an eight-generation sweep of
the planted-bug fixture reported `FAIL_CLOSED_ABORT` on six of eight.

## Fix

The fingerprint and the trace metadata describe the run that **happened**, not
the run that was requested. Deselecting a class now retracts everything that
class declared:

- `apply_swarm_mask` strips the class's fingerprint component from
  `config.fingerprint`. Both sides read one constant,
  `patina_dst_runtime::FINGERPRINT_BUGGIFY`, so the supervisor's declaration and
  the runtime's retraction cannot drift apart. `buggify` is the only swarm class
  with a fingerprint component today; a unit test pins that mapping so adding
  another forces the decision.
- A dropped class leaves **no residue**: the whole `BuggifyConfig` resets, so a
  masked run reports the same numbers as a run that never asked. The
  requested-and-dropped fact is carried explicitly instead of inferred from
  leftovers.
- `PATINA_SDK_REPORT` gained `swarm_deselected=<0|1>`, which is what separates
  the two `enabled=0` states that misled the original reduction.
- A new default-on `PATINA_SWARM_REPORT` line covers every swarm class
  uniformly: `candidates=N selected=M deselected=K` plus one `class=<token>|<0|1>`
  row per candidate.
- The trace's swarm record is authoritative and self-describing: a dropped class
  appears in `candidate_classes` but not `selected_classes`, while a class that
  was never requested appears in neither. `TraceBundle::validate` now enforces
  that the selection is a subset of the candidates with no duplicates, so the
  complement is always a meaningful "deselected" set;
  `SwarmConfigRecord::deselected_classes()` derives it rather than storing a
  third list that could drift.
- Replay and branch adopt the recording's swarm record, so a replayed generation
  emits the same swarm/SDK diagnostics the recording did.
- `cargo patina trace info` prints
  `swarm: candidates=… selected=… deselected=…` instead of raw JSON.

The coherence guard itself is unchanged and just as strict. A swarm-masked run
passes it because its declared state is now truthful, not because the check was
loosened; a fingerprint that declares `+buggify` on a run that never armed
buggify still refuses.

Replay stays self-contained: a flag-free replay reconstructs the component set
from the trace (`buggify` from the presence of the buggify record, `+swarm` from
the presence of the swarm record), so a masked recording's fingerprint —
`patina-native+swarm` — is recomputed exactly.

## Evidence

Red-before/green-after, both at the unit level (disabling the retraction makes
`swarm_deselecting_buggify_retracts_the_fingerprint_component` fail with the
exact abort message above) and at the CLI level (seeds 0 and 3 of the
`liveness-campaign` fixture abort before the fix, run clean after).

Focused regression tests:

- `cargo test -p patina-dst-runtime --lib swarm`
- `cargo test -p patina-dst-trace swarm`
- `cargo test -p cargo-patina --test end_to_end swarm_deselection_stays_coherent_with_fingerprint_and_metadata -- --nocapture`
- `cargo test -p cargo-patina --test end_to_end campaign_with_swarm_and_buggify_has_no_coherence_aborts -- --nocapture`

The landing gate for this runtime/trace-touching change is `mise run check`.

## Follow-ups closed after the fix

Two residuals were left when the coherence fix landed. Both are closed.

### `--swarm` with zero candidate classes

`--swarm` selects a subset of the fault classes a run enabled, so a run that
enabled none has an empty candidate set: the draw keeps and drops nothing and the
generation explores exactly what it would have explored without `--swarm`. That
is an inert knob, and an inert knob must not read as coverage.

The report now carries `vacuous=<0|1>`, the runtime emits `PATINA WARNING: swarm
fault-class selection inert`, and the two classifiers that consume swarm
generations promote a would-be-clean outcome:

- `cargo patina campaign` gained the `VACUOUS_SWARM` outcome class, tiered with
  `VACUOUS_FS_FAULT` — a coverage failure that a real finding still outranks.
- `testbeds/workq/fuzz-sweep.sh` gained the same class via `swarm_check`. The
  sweep decides when to overlay `--swarm` from its OWN fault-knob count while the
  runtime derives candidates from the config it built, so this also catches the
  two drifting apart instead of logging `swarm=on` over an empty draw.

An empty SELECTION over a non-empty candidate set is explicitly not vacuous:
dropping every candidate is a legitimate draw and is the point of swarm testing.
Both selftests pin that boundary, and both were proven to fail before the rules
were added.

### Seeded runs and `--fingerprint`

The coherence guard runs on record/replay/branch, not on seeded runs, because a
seeded run has no fingerprint to check: the native supervisor sets
`PATINA_FINGERPRINT` only in record and replay mode, and the runtime does not
read it in seeded mode at all. That scoping is correct rather than accidental —
the fingerprint is the compatibility label of an ARTIFACT (composed by the
supervisor, written into the trace, recomputed and compared at replay), and a
seeded run produces no artifact whose declared coverage anyone can later read.
Every campaign generation records, so the coverage-claiming path is covered.

What was wrong was the flag: `cargo patina run <BIN> --seed N --fingerprint LABEL`
accepted a label that nothing could ever compare, which is exactly the "I pinned
this run to a build" belief the guard exists to protect. `--fingerprint` is now
declared dependent on `--record` in the CLI registry, so the generic
dependent-knob check refuses it (`--fingerprint requires --record`) and the
machine-readable help advertises `"requires": "--record"`. `explore` already
refuses record mode from the other side, for the same reason: a sweep pins no
single artifact.
