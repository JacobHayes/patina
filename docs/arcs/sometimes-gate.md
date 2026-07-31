# Arc: campaign-level `sometimes!` coverage aggregation + gate

Status: design approved 2026-07-30; implementation not yet scheduled.

## Summary

`cargo patina campaign` starts parsing the per-run `PATINA_SDK_REPORT` rows it already
captures, unions coverage-oracle sites across generations, reports satisfied-in-N-generations
per site, and **fails the campaign by default when any `sometimes!` site was registered but
never satisfied across the whole sweep** — the campaign-level twin of the vacuous-schedule
diagnostic: a `sometimes!` that never came true is a vacuous oracle, and a green campaign
built on vacuous oracles is a false green. A single waiver flag,
`--allow-unmet-sometimes[=MIN_GENS]`, waives the gate either unconditionally or only for
campaigns smaller than a user-chosen generation floor. The work is entirely campaign-side
(`crates/cargo-patina`): the runtime plumbing is complete and needs no changes.

## Settled decisions (inputs to this design)

* Per-run plumbing exists and is untouched: sites register in the buggify registry
  (site identity = the label string, stable across builds; duplicate labels fatal) and every
  run emits per-site rows via `PATINA_SDK_REPORT`.
* The work is campaign-side: parse rows per generation, union labels, tally
  satisfied-generation counts, report per-site coverage plus the never-satisfied list, in
  both the human summary and the `patina.campaign/v2` envelope (summary-first, INTENTS
  principle 9).
* Gate by default; never-satisfied fails the campaign loudly with a nonzero exit.
* Waiver is general **or** threshold-style (user sets the generation floor).
* This doc decides `reachable!` gating, flag spelling, exit/reporting semantics, schema
  versioning, persistence shape, and the edge cases.

## Verified current state (all claims checked against source)

**Runtime side — complete, no changes needed.**

* Site kinds: `BuggifyKind::{Fault, Delay, Knob, Always, Sometimes, Reachable}`
  (`crates/patina-runtime/src/lib.rs:2234-2261`). Registry is a
  `BTreeMap<label, BuggifySite>`; a label reused at a different call site is a fatal
  duplicate (`lib.rs:2377-2400`).
* `sometimes_check` (`lib.rs:2780-2800`) and `reachable_mark` (`lib.rs:2803-2815`) are
  **unconditional**: they register + set their bits regardless of `--buggify`, activation
  permille, swarm selection, or the damage-control cutoff. Only fault/delay/knob firing is
  activation-gated. This settles the swarm-denominator question (below): swarm can never
  mask an oracle directly, only shape which code paths execute.
* Registration is **lazy**: a site exists only once its macro executes. A `sometimes!` (or
  `reachable!`) whose enclosing code path never runs in a generation emits no row for that
  generation — and if it runs in no generation, it is invisible to the campaign entirely.
  This is the load-bearing limitation of the whole design; see "reachable! decision".
* `emit_sdk_report` (`lib.rs:4963-5015`), called from `Context::finish` (`lib.rs:4003`),
  writes **one line to the real process stderr**, on the native shim and the wasip1 host
  alike (the wasi host drives the same `Context`; `crates/patina-wasi-host/src/lib.rs:2567-2583`).
  It is **default-on**, emitted whenever buggify is enabled *or* any site registered
  (`lib.rs:4969`), and suppressed only by a false-y `PATINA_SDK_REPORT` env
  (`lib.rs:185`, `4972-4978`). Row format (`lib.rs:4967`):
  `site=<label>|<kind>|a<0|1>|e<evals>|f<fires>|r<0|1>|s<0|1>|v<0|1>|k<knob|->`.
* `run`/`run_with` call `finish()` on error paths too (`lib.rs:3974-3977`), so failing
  generations still carry a report — except aborts that never reach `finish` (an `always!`
  trap, a fired watchdog, a timeout kill).

**Campaign side — capture exists, rows ignored.**

* `run_generation` (`crates/cargo-patina/src/campaign.rs:891-970`) pipes the child's stdout
  and stderr into strings the driver already holds; `classify` (`campaign.rs:471`) greps
  those strings for markers but nothing reads the `site=` rows. **No new capture channel is
  needed** — the report line is already sitting in the captured stderr of every generation.
* One gap: the child inherits the parent environment, so a user's exported
  `PATINA_SDK_REPORT=0` would silently suppress every row and render the gate vacuously
  green. Campaign must pin `.env("PATINA_SDK_REPORT", "1")` on the child, exactly as it
  already pins `PATINA_LIVENESS_REPORT=1` (`campaign.rs:921`).
* Envelope: `patina.campaign/v2` (`campaign.rs:52`), built by `build_campaign_envelope`
  (`campaign.rs:1245`). The documented versioning convention is "bump the version suffix
  only on a breaking change to the documented shape"
  (`crates/cargo-patina/src/output.rs:21-24`). The signature store persists as
  `<out>/signatures.json`, schema `patina.campaign.signatures/v1` (`campaign.rs:1160-1176`).
* Flags live in the typed registry with a structural drift gate
  (`crates/cargo-patina/src/help.rs:954-1080`, gate per `help.rs:16`); `Value::Optional`
  with a typed `Kind` is established precedent (`--buggify[=<PERMILLE>]`).
* Testbeds already carry `sometimes!` sites (workq: `dedup-suppressed-double-apply`,
  `job-failed`, `redelivery-observed`; liveness-campaign: `digest-even`;
  buggify-wasi: `rng-draw-even`, `rng-draw-mult-five`), so the default-on gate immediately
  applies to the existing e2e campaigns — stage 4 accounts for that.

## Design

### 1. Per-generation row capture

After each generation, take the **last** stderr line starting with `PATINA_SDK_REPORT ` (the
runtime emits it at `finish`, so it is last; taking the last line makes an earlier
guest-printed lookalike inert, consistent with the classifier's existing grep-anywhere
posture — guest spoofing is already outside the threat model). Absence of the line is
normal (guest registered no sites and buggify off, or the child died before `finish`) and
contributes nothing to any site's tally.

Parse the line into header `k=v` tokens plus `site=` rows. **A malformed row is a hard
campaign error** (`CliError` naming the generation and the offending token), not a skip:
an unparseable row means the report contract drifted, and detection-before-fixes demands
that drift class fail loudly at the choke point rather than silently under-counting
coverage. (Known hazard: labels containing a space or `|` would shear the token stream.
Nothing validates label charsets today; the loud parse error is the campaign-side
detector. A one-line runtime guard rejecting whitespace/`|` in labels at `register()` is a
recommended follow-up hardening, out of this arc's runtime-untouched scope.)

The parser is a pure function (`parse_sdk_report(&str) -> Result<Vec<SiteRow>, _>`) so it
is unit-testable and reusable by the selftest.

### 2. Cross-generation aggregation + persistence

```rust
struct SiteTally {
    kind: &'static str,        // sometimes | reachable | fault | delay | knob | always
    first_registered_gen: u64,
    registered_gens: u64,      // generations in which the site emitted a row
    satisfied_gens: u64,       // sometimes: s-bit set; reachable: row present (r-bit)
    first_satisfied_gen: Option<u64>,
    first_satisfied_seed: Option<u64>, // reproduce handle for "show me a satisfying run"
    evals: u64,                // summed; distinguishes "reached once" from "reached 10M times, never true"
    fires: u64,                // summed; fault/delay only, 0 for oracles
}
// CoverageTally = BTreeMap<String /* label */, SiteTally> + generations_observed: u64
```

All kinds are tallied (same loop, lossless, useful for triage — e.g. a fault site that
never activated across a sweep), but only oracle kinds participate in the gate. The fold
is associative (counts add, `first_*` takes the min), which is exactly what the
resumable-campaign arc needs: a resumed campaign loads `sites.json`, continues the
fold, and rewrites it — no shape change required. Cross-reference:
`docs/arcs/campaign-steering.md` (in flight); its persistence section should list
`sites.json` alongside `signatures.json` as resume state.

Persisted every campaign as `<out>/sites.json`, schema
`patina.campaign.sites/v1`, next to `signatures.json`:

```json
{
  "schema": "patina.campaign.sites/v1",
  "generations_observed": 5000,
  "sites": [
    { "label": "redelivery-observed", "kind": "sometimes",
      "first_registered_gen": 0, "registered_gens": 4998,
      "satisfied_gens": 312, "first_satisfied_gen": 7, "first_satisfied_seed": 123456,
      "evals": 981223, "fires": 0 }
  ]
}
```

The tally is a pure fold over per-generation reports, so the existing deterministic-re-run
e2e extends to assert byte-identical `sites.json` across identical sweeps.

### 3. The gate

**Unmet** := an oracle-kind site (`sometimes`, `reachable`) with `satisfied_gens == 0`
across the campaign. Default behavior: any unmet site fails the campaign — exit 1, loudly
listed. Zero registered oracle sites is **trivially green** with an informational
`coverage: no sometimes!/reachable! sites registered` line, no warning: unlike the
vacuous-schedule diagnostic (where the user explicitly requested schedule exploration, so
vacuity betrays the request), most guests simply don't use the SDK oracles, and warning on
every plain campaign is noise that trains users to ignore warnings. Opting into the
oracles is what arms the gate.

The gate applies to every campaign regardless of `--buggify` (oracles are unconditional in
the runtime, so their rows flow with or without fault injection).

**Not a per-generation class.** The seven `CampaignClass` values classify one child run;
"never satisfied across N runs" is only decidable at campaign end, has no generation, no
seed, no trace, and therefore no `Signature`. It is a new **campaign-level verdict**:

* human mode prints, in the summary block, one loud line per unmet site plus a marker line
  (formats below);
* `result` becomes `"failure"` and the exit code 1 exactly as run-failures do today
  (`campaign.rs:853-854` generalizes to
  `failures > 0 || (!waived && !unmet.is_empty())`). No new exit code: 0/1/2 (ok /
  findings / usage-or-infra CliError) is the whole campaign exit contract today, the
  envelope and markers carry the "why", and a distinct code would add a contract with no
  consumer.

Human summary additions:

```
-- coverage (sometimes!/reachable!) --
oracle_sites=4 satisfied=3 unmet=1
  UNMET sometimes 'large-batch-seen' satisfied_gens=0/5000 registered_gens=4998 evals=981223
coverage store: patina-campaign-out/sites.json
PATINA_CAMPAIGN_COVERAGE oracle_sites=4 satisfied=3 unmet=1 gate=fail
```

(`gate=` is one of `pass | fail | waived | off`-less — there is no off; satisfied sites are
one line of counts, per-site detail lives in `sites.json`, unmet sites are always
enumerated inline: the interesting minority, per progressive disclosure.)

### 4. Waiver flag

One flag, registry-typed, no flag zoo:

```
--allow-unmet-sometimes[=MIN_GENS]     Value::Optional("MIN_GENS", Kind::PositiveU64)
```

* **Bare** `--allow-unmet-sometimes`: unconditional waiver. Unmet sites are still tallied,
  still listed (`UNMET … (waived)`), `gate=waived` on the marker and in the envelope —
  reported, just not fatal.
* **`--allow-unmet-sometimes=N`**: waive-under-threshold. The gate is waived iff
  `generations_observed < N` and enforced at `>= N` — "don't fail me for coverage a
  200-generation smoke sweep can't be expected to reach, but hold the line on the real
  5000-generation campaign". Comparing against *observed* generations (not the spec value)
  keeps the semantics correct when the resumable arc lets a campaign grow.
* `Kind::PositiveU64` rejects `=0` loudly (a zero threshold is the flag's absence, spelled
  confusingly).
* Spec-file key `allow_unmet_sometimes`: accepts `true` (bare form) or an integer `N`
  (threshold form), rejecting other shapes — the one key mirrors the one flag, and the
  usual flag-over-spec precedence applies.
* Naming: stays in the established `--allow-*` escape-hatch family
  (`--allow-unsupported-symbols`). "sometimes" over "coverage" because `sometimes!` is the
  only kind the gate can bite on today (next section), and the flag should name what it
  waives.

Exit/reporting under waiver: exit code contribution from coverage is 0; run-failures still
fail the campaign independently. The envelope always carries the full coverage section and
the waiver that was applied, so a waived-vacuous campaign is auditable after the fact.

### 5. `reachable!` — gated uniformly, honest about when it can bite

Decision: `reachable!` sites enter the same tally and the same unmet formula
(`satisfied_gens == 0`), with "satisfied" = the row existed (reached). But because
registration is lazy, **a `reachable!` that is never reached in any generation never emits
a row anywhere and is invisible to the campaign** — and any `reachable!` row that does
appear is satisfied by construction. So under today's plumbing the unified gate is
trivially green for `reachable!`; only `sometimes!` (reached-but-never-true) can actually
trip it. The same blind spot applies to a `sometimes!` whose code path never executes.

Why gate uniformly anyway rather than exclude the kind: the tally, the unmet formula, the
waiver, the envelope shape, and the tests are all kind-agnostic; when a static site
enumeration lands (a link-time site table — e.g. `inventory`/`linkme`-style registration —
letting the campaign know the full site universe up front), never-reached `reachable!` and
never-reached `sometimes!` sites become visible unmet entries with `registered_gens=0` and
the gate bites with **zero redesign**. That static-enumeration work is a separate follow-up
arc (it touches the SDK macros and both embedders — squarely runtime-side); this doc's
scope note plus the `registered_gens` field are the prepared seam. The limitation is
stated in the campaign help prose so nobody mistakes today's gate for full reachability
coverage.

### 6. Swarm / knob-subset generations and the denominator

A generation counts toward a site's `registered_gens` iff the site emitted a row (its code
path executed); `satisfied_gens` iff its bit was set. There is **no** activation-based
denominator adjustment: swarm and activation permille gate only fault/delay/knob firing
(`lib.rs:2644`, `2687`, `2740`), never the oracles, so "inactive-by-swarm" cannot suppress
an oracle row — it can only steer the guest down different code paths, which is precisely
the exploration the campaign wants counted. The gate's predicate needs no denominator at
all (`satisfied_gens == 0` over the whole sweep); `registered_gens` vs
`generations_observed` is reported for triage (a site registered in 2 of 5000 generations
that was never satisfied reads very differently from one registered in all 5000).

Generations that die before `finish` (wall-clock timeout kill, `always!` trap,
duplicate-label abort) emit no report and contribute to no site tally — only to
`generations_observed`. Correct by the same principle: absence of a row is absence of
evidence, and the gate only ever fails on *positive* evidence of vacuity (registered,
never satisfied).

### 7. Envelope: additive within v2

Per the documented convention (bump only on a breaking change, `output.rs:21-24`), adding
a `coverage` object and an `artifacts.sites_store` pointer is additive — existing
consumers keyed on `classes`/`signatures`/`notable_runs`/`artifacts` are untouched — so the
schema stays `patina.campaign/v2`. (The v1→v2 bump was a breaking reshape, `runs` →
`notable_runs`; this is not that.)

```json
"coverage": {
  "oracle_sites": 4,
  "satisfied": 3,
  "gate": "fail",                    // pass | fail | waived
  "waiver": null,                    // null | true | <MIN_GENS>
  "unmet": [
    { "label": "large-batch-seen", "kind": "sometimes",
      "satisfied_gens": 0, "registered_gens": 4998,
      "generations_observed": 5000, "evals": 981223, "waived": false }
  ]
},
"artifacts": { …, "sites_store": "<out>/sites.json" }
```

Summary-first: counts + the unmet minority inline; the full per-site table (including the
satisfied sites and non-oracle kinds) lives only in `sites.json`, reachable via the
pointer — lossless aggregation, firehose on disk.

## Edge cases (consolidated)

| Case | Behavior |
|---|---|
| No `PATINA_SDK_REPORT` line in a generation | Normal; contributes nothing to tallies. |
| Zero oracle sites campaign-wide | Trivially green; informational line; no warning. |
| Site registers in only some generations (lazy paths) | Union; `registered_gens` reports the spread. |
| Site never reached in ANY generation | Invisible (documented limitation; static-enumeration follow-up arc). |
| Timed-out / aborted generation | No row; counts only toward `generations_observed`. |
| Failing generation that reached `finish` | Row parsed normally (finish runs on error paths). |
| Guest prints a lookalike report line | Last-matching-line rule makes it inert. |
| Malformed `site=` token (e.g. label with space/`|`) | Hard campaign error naming gen + token; runtime label-charset guard recommended as follow-up. |
| Inherited `PATINA_SDK_REPORT=0` | Campaign pins `=1` on children (the one behavioral change outside parsing). |
| wasi vs native artifact | Identical: both embedders drive the same `Context::finish` emitter to process stderr. |
| Deterministic re-run | `sites.json` byte-identical (pure fold; asserted by e2e). |
| Resumed campaign (future arc) | Load `sites.json`, continue the associative fold; threshold waiver compares observed gens. |

## Staged plan

Verification tier: **CLI-only** (cargo-patina unit tests + e2e), justified: no
runtime/shim/wasi-host code changes, no interposition surface touched, no trace-format or
schedule-semantics change — the entire diff is `campaign.rs` + `help.rs` + tests, and the
report format being parsed is already pinned by existing runtime e2e
(`end_to_end.rs:2661`, `3057`, `5579`). Per the tiered-verification policy that reserves
the full battery / Linux gates for runtime-touching changes, `mise check` + the two e2e
runs suffice; the e2e fixtures are `wat`-built wasm modules (like `WASI_BUGGIFY_MODULE`,
`end_to_end.rs:2620-2644`), so they run on every platform without a native toolchain.

1. **RED first (detection-before-fixes).** Write the e2e before any implementation: a
   planted wat guest whose `$sometimes` import is called with `i32.const 0`
   (never-satisfied) swept by `campaign --gens 5` must exit nonzero and name the label;
   with `i32.const 1` it must stay green. Prove both assertions fail against the current
   binary (campaign exits 0 today with the planted site) — the gate's own test is
   RED-proven before the gate exists.
2. **Row parser** (pure): `parse_sdk_report` + unit tests (round-trip against the emitter
   format, malformed-token loud error, absent-line ok, last-line-wins).
3. **Tally + persistence + surfacing**: fold into `CoverageTally`, write `sites.json`,
   add the human coverage block + `PATINA_CAMPAIGN_COVERAGE` marker + envelope `coverage`
   section (envelope unit tests mirror `envelope_is_summary_first_with_artifact_pointers`:
   unmet-only inline, pointer present, schema still v2). Pin `PATINA_SDK_REPORT=1` on
   children.
4. **Gate + waiver**: exit-code wiring, `--allow-unmet-sometimes[=MIN_GENS]` in parser +
   spec key + help registry (drift gate covers registration structurally); parse tests for
   both value forms, duplicate rejection, `=0` rejection, spec `true|N` shapes. Extend
   `campaign --selftest` with coverage fixtures (parse→tally→verdict for: met, unmet,
   waived-bare, waived-under-threshold, enforced-at-threshold, malformed-row), keeping the
   selftest's every-outcome-reachable discipline. Re-run the existing campaign e2e
   (liveness-campaign, workq sweeps) under the default gate and fix any testbed whose
   oracles legitimately can't be met at its sweep size (expected: none — their conditions
   are satisfied within a few generations — but the stage verifies rather than assumes).
5. **Determinism + docs**: extend the deterministic-re-run e2e to compare `sites.json`;
   update campaign help prose (gate semantics + reachability limitation), `IMPLEMENTATION.md`
   / `VALIDATION.md` per the usual landing checklist; `mise check` ladder with the two e2e
   runs in the battery log.

## Cross-references

* `docs/arcs/campaign-steering.md` (in flight): `sites.json` is resume state; the
  fold is associative by design; threshold waiver uses `generations_observed`.
* Static site enumeration is scheduled as the invariant-visibility arc's Wave 5 (not a
  someday-item): a link-time site table makes never-reached `sometimes!`/`reachable!`
  sites visible as `registered_gens=0` unmet entries; the gate formula and schema here
  absorb it unchanged.
* Doctrine: vacuous-schedule diagnostic (same vacuity class, same fail-closed rationale);
  INTENTS principle 9 (`INTENTS.md:133`) for the summary-first shapes;
  detection-before-fixes for the RED-proven gate test and the loud malformed-row error.

## Resolved review decisions

1. Flag name: `--allow-unmet-sometimes` (user-confirmed 2026-07-30). It precisely names
   what the gate can bite today; the `=MIN_GENS` form delivers the desired
   warn-below-threshold / error-at-or-above behavior, with unmet sites reported in all
   cases. If static site enumeration later widens the gate's scope, rename the flag to
   match reality then — renames are ordinary hard cuts with all callers migrated, not
   something to pre-hedge against.
2. `sites.json` includes non-oracle kinds from day one — same loop, lossless, aids
   fault-site triage.
3. Store unification (coordinator, 2026-07-30): this doc's per-label aggregate store and
   the invariant-visibility arc's exercised-sites store are the SAME data, so there is one
   store — `<out>/sites.json`, schema `patina.campaign.sites/v1` (field superset of both) —
   consumed by this gate, by `cargo patina sites --exercised`, and resumed by the
   campaign-steering arc. The edge-coverage arc's separate `<out>/coverage/` directory now
   collides with nothing.
