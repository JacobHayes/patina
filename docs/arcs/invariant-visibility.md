# Arc: Invariant visibility

**Status:** Wave 1 implemented (static `cargo patina sites` inventory); Waves 2-5 remain design.
**Depends on:** nothing (wave 1 is standalone). **Feeds:** the coverage-depth arc (shared rollup),
the sometimes-gate arc (runtime exercised data).

## Problem

Patina can *drive* cooperative-SUT sites and *observe* oracles, but nobody — human or agent — can
answer, without grepping: where does this codebase have invariant/property instrumentation? Which
crates have none? Which `sometimes!` claims has no campaign ever satisfied? Which assertions exist
that Patina cannot see at all? Today the only artifacts are the per-run `PATINA_SDK_REPORT` stderr
line (`crates/patina-runtime/src/lib.rs:4968`) and verbatim marker capture on failing campaign
generations (`crates/cargo-patina/src/output.rs:364`). There is no static inventory, no aggregation
across a campaign, and no join between "what exists" and "what was exercised".

This arc makes instrumentation *visible*: a static inventory of every assertion/property site, a
runtime/campaign exercised view, and a merged report — hierarchical, progressively disclosed
(INTENTS.md:133, principle 9), consumable by humans and agents through the same data model.

## Settled decisions (user-fixed; design happens within them)

1. **Hybrid mechanism.** The runtime site registry is ground truth for what Patina can drive
   (`buggify!`/`sometimes!`/`reachable!`/`always!` self-register with label + file:line + per-run
   counters). A separate offline static-code-analysis (SCA) pass inventories what the runtime
   cannot see: `assert!` family, proptest/quickcheck, antithesis-sdk assertions. tree-sitter is an
   acceptable SCA dependency (never linked into runtime/shims); assess vs `syn`, pick one (§SCA).
2. **Two lifetimes.** The static inventory is general (not tied to a run). Runtime coverage is tied
   to a run or campaign. The merged report joins them (static site ⟂ exercised?).
3. **Hierarchical, progressive disclosure.** Index first (per-crate → per-module rollups with
   counts/percentages), drill-down to file/site. Automatic grouping = crate/module; custom
   tags/groups come from a new `.patina/` repo config dir. v1 config scope: custom tags/groups +
   default CLI knobs (flags always override) + a `.gitignore` for generated content. Nothing more.
4. **Both media.** CLI text and `--format json` are views over one data model; an HTML render can
   come later without schema change.
5. **Antithesis-SDK assertions** are inventoried (we can *see* them) but not driveable/observable
   by Patina — the report says so explicitly (§runtime column).
6. **Cross-arc:** the coverage-depth arc's edge rollup reuses this arc's hierarchy/grouping (one
   rollup implementation, two data sources); the sometimes-gate arc consumes the exercised side.

## Ground truth today (verified)

- **SDK macros** — `crates/patina/src/lib.rs:612-749`: `buggify!`, `buggify_with_prob!`,
  `buggify_delay!`, `buggify_knob!`, `always!`, `sometimes!`, `reachable!`. Each captures
  `concat!(file!(), ":", line!())` and routes through `__rt` shims
  (`crates/patina/src/lib.rs:308-405`) that are inert outside Patina.
- **Runtime registry** — `crates/patina-runtime/src/lib.rs:2284-2300` (`BuggifySite`: label-keyed,
  stores `site: "file:line"` used *only* for duplicate detection), `:2237-2250` (`BuggifyKind`:
  fault/delay/knob/always/sometimes/reachable), `:2377-2401` (`register`: a label reused at a
  different call site is a fatal `DuplicateLabel`, so **a label is process-unique** — sound join
  identity). Per-site counters: evals, fires, reachable, sometimes_satisfied, always_violated, knob.
- **Per-run emission** — `emit_sdk_report`, `crates/patina-runtime/src/lib.rs:4968-5015`: one
  `PATINA_SDK_REPORT` stderr line, per-site token
  `site=<label>|<kind>|a<0|1>|e<evals>|f<fires>|r<0|1>|s<0|1>|v<0|1>|k<knob|->`. **The file:line is
  not in the report row** — `BuggifySiteReport` (`:2323-2333`) has no `site` field. Trace metadata
  records only config + active labels (`BuggifyConfigRecord`, `crates/patina-trace/src/lib.rs:121`).
- **Campaign** — `patina.campaign/v2` envelope (`crates/cargo-patina/src/campaign.rs:52`,
  `:1236-1320`): class histogram, deduped signatures, notable runs, artifact pointers. SDK reports
  are captured only as verbatim marker lines on notable runs; **no per-site aggregation exists**.
- **CLI** — verbs run/test/build/audit/replay/explore/campaign/minimize
  (`crates/cargo-patina/src/help.rs:1168-1170`); global `--format human|json`
  (`help.rs:191-213`, result envelope `patina.result/v1`, `output.rs:24`); help is
  progressive-disclosure `patina.help/v2` with index vs per-verb payloads (`help.rs:1667-1717`);
  registry drift gates already exist (`lib.rs:8146` parser↔registry, `:8689` value grammars,
  `:8820` repeatability) and will automatically cover the new verb.

## Design

### 1. One data model, three products

A single site record type backs everything:

```json
{
  "id": "commit-conflict",              // label for SDK sites; "crates/wal/src/lib.rs:88#assert" for anonymous
  "kind": "fault|delay|knob|always|sometimes|reachable|assert|debug_assert|prop_assert|proptest|quickcheck|antithesis_always|antithesis_sometimes|antithesis_reachable|antithesis_unreachable|unreachable",
  "runtime": "driven|observed|invisible", // see below
  "label": "commit-conflict",           // null for anonymous kinds; see label_dynamic
  "label_dynamic": true,                // present only when the label arg is not a string literal
  "file": "crates/wal/src/lib.rs", "line": 88,
  "crate": "patina-dst-wal", "module": "wal::segment",  // inline `mod` blocks included (syn walk)
  "context": "src|test|example|bench",  // cargo target kind + #[cfg(test)] module detection
  "groups": ["durability"]              // from .patina/config.toml; empty if none
}
```

The **`runtime` column** encodes the driveability boundary honestly:
- `driven` — buggify/delay/knob: Patina decides firing; exercised = evals/fires.
- `observed` — always/sometimes/reachable: Patina records outcomes; exercised = satisfied/reached.
- `invisible` — assert family, proptest/quickcheck, antithesis-sdk: SCA sees the site; Patina
  cannot observe whether any run evaluated it. The merged report never claims coverage for these;
  their exercised cells render as `—` (json: absent), not `0`.

Products: **(a)** static inventory (SCA + this schema), **(b)** exercised aggregate (runtime rows,
per run or campaign), **(c)** merged report = (a) left-joined with (b) plus an
unmatched-runtime-labels section (§3).

### 2. SCA pass

**Tool: `syn` (full + proc-macro2 `span-locations`), not tree-sitter.** Assessment:
- tree-sitter pros: error-tolerant, incremental, multi-language. Cons: C grammar dependency; its
  error tolerance is a *liability* here — a partially parsed file silently yields fewer sites
  unless ERROR nodes are separately audited, which is exactly the silent-miss class the
  detection-before-fixes doctrine forbids; grammar drift lags new Rust syntax.
- syn pros: pure Rust (already in the build closure via serde_derive; adds only a direct dep on the
  CLI side — never the runtime/shim graph); exact line/col spans; a real AST, so the visitor tracks
  inline `mod` nesting for true module paths and extracts the label as a *typed string literal*
  (identity join needs the literal, not a token blob); a file that fails to parse fails **loudly
  per-file** and is counted (`files_unparsed`), never skipped silently. Cons: whole-file reparse —
  irrelevant at repo scale and mooted by the cache.
- Multi-language never matters for a Rust-first tool (INTENTS.md principle 7). Pick syn.

**Recognized patterns** (a static table, one row per macro name → kind/runtime/label-arity):
- Patina SDK: the seven macros above, matched by final path segment with or without
  `patina_dst::` qualification. Label = first argument when a string literal, else
  `label_dynamic: true`.
- std: `assert!`, `assert_eq!`, `assert_ne!`, `debug_assert!`, `debug_assert_eq!`,
  `debug_assert_ne!`, `unreachable!`. Anonymous (id = `file:line#kind`).
- proptest: `proptest!` (one site per contained `fn`), `prop_assert!`/`prop_assert_eq!`/
  `prop_assert_ne!`; quickcheck: `quickcheck!`, `#[quickcheck]` attribute.
- antithesis-sdk: any macro whose path starts `antithesis_sdk::` plus bare
  `assert_always!`/`assert_always_or_unreachable!`/`assert_sometimes!`/`assert_reachable!`/
  `assert_unreachable!` (label = message argument when literal).

**Honesty (stated in the report, not buried):**
- *Macro-wrapping false negatives:* a user macro that expands to `buggify!` is invisible to SCA but
  visible to the runtime registry. The merged report classifies runtime labels with no static match
  as `origin: "expanded"` rather than erroring — the hybrid covers what SCA alone cannot.
- *Bare-name false positives:* an unrelated user macro named `always!` matches the bare-name rule.
  The record keeps the macro path as written; the runtime join disambiguates SDK sites; `invisible`
  rows admit this residual imprecision in the schema docs.
- *Generated code:* build.rs/codegen output is scanned only if it lives in-tree; `cfg`'d-out code
  *is* scanned (a feature: the inventory sees all configurations).
- *Parse failures:* `files_unparsed` is always surfaced in the index header; never silently zero.

**Scope & cache:** scan workspace members from `cargo metadata` (lib/bin/test/bench/example
targets; `target/` excluded). Per-file cache keyed by (path, content SHA-256, recognizer-table
version) at `.patina/out/sites-cache.json`; a recognizer-table change invalidates everything by
construction. Cold scan of this repo is well under a second; the cache exists so `sites` stays
instant inside agent loops.

### 3. Site identity and the join

- **SDK sites:** identity = label (runtime-enforced unique). SCA→runtime join on label.
- **Dynamic labels:** SCA emits one `label_dynamic` row at the call's file:line. Runtime labels
  that match no static label join *by file:line prefix* against dynamic-label rows — which requires
  the runtime row to carry its file:line. Therefore:
- **SDK report row change (wave 2):** append the site to the per-site token —
  `site=<label>|<kind>|...|k<knob|->|@<file:line>` — sourced from the already-stored
  `BuggifySite.site` (`patina-runtime/src/lib.rs:2287`) and added to `BuggifySiteReport`. This also
  gives drill-down file links without requiring an SCA pass. Per the no-cruft doctrine every
  in-repo consumer of `PATINA_SDK_REPORT` (testbed scripts, campaign marker capture, docs) migrates
  in the same change; the format doc at `emit_sdk_report` is the registry of record. Path values
  are `file!()` output — workspace-relative for local crates; the join normalizes to
  workspace-relative and reports non-workspace paths (registry deps that use the SDK) under an
  `external` pseudo-crate.
- **Runtime rows with no static match** (after label and file:line passes): reported in an
  `unmatched` section with `origin: "expanded"` — visible, counted, never dropped. For Patina's own
  testbeds this count is gate-asserted zero (§detection).

### 4. Report schema: `patina.sites/v1`

Same envelope discipline as the other verbs (`--format json`, one JSON object on stdout), same
index/drill-down split as `patina.help/v2` (`help.rs:1564-1592`) and the campaign v2 doctrine:
summaries lead, nothing becomes unreachable, firehoses are opt-in.

**Index** (default):

```json
{
  "schema": "patina.sites/v1",
  "verb": "sites",
  "scan": { "workspace_root": "...", "files_scanned": 214, "files_unparsed": 0,
            "cache": "hit|cold", "recognizers": 21 },
  "exercised_source": { "kind": "campaign", "path": "out/sites.json",
                        "generations": 2500 },            // absent in static-only mode
  "totals": { "sites": 412, "by_runtime": {"driven": 63, "observed": 88, "invisible": 261},
              "by_kind": {"fault": 41, "always": 52, "...": 0},
              "exercised": {"driven_fired": 58, "observed_satisfied": 80,
                            "never_exercised": 13} },      // exercised block absent in static-only mode
  "crates": [ { "name": "patina-dst-wal", "sites": 37,
                "by_runtime": {"driven": 9, "observed": 12, "invisible": 16},
                "never_exercised": 2,
                "modules": [ { "module": "wal::segment", "sites": 11, "never_exercised": 1 } ] } ],
  "groups":  [ { "name": "durability", "sites": 29, "never_exercised": 3 } ],
  "unmatched_runtime_labels": 0,
  "detail": { "hint": "Per-site rows are omitted from this index.",
              "command_template": "cargo patina sites --module {module} --format json" }
}
```

**Drill-down** (`--crate NAME` / `--module PATH` / `--group NAME` / `--site LABEL`): the scoped
payload carries full site records (§1), each with an `exercised` object when an exercised source is
loaded:

```json
"exercised": { "runs_registered": 2500, "runs_active": 640, "evals": 812345, "fires": 3120,
               "runs_fired": 598, "sometimes_satisfied_runs": 0, "reachable_runs": 0,
               "always_violated_runs": 0, "knob_min": 1, "knob_max": 1024 }
```

(counter subset varies by kind; absent entirely for `invisible` rows). `--all` dumps every site
record — the opt-in firehose. Human output renders the same shapes: an aligned per-crate table with
percentage columns for the index; a per-site listing for scoped views; `sometimes!` claims never
satisfied and `reachable!` sites never reached are called out in a "gaps" block at the top of the
exercised index, since those are the actionable findings.

### 5. CLI surface

**New verb: `cargo patina sites`** — registry-typed in `help.rs` (drift gates cover it for free).
"sites" is the established domain noun (`BuggifySite`, `site=` tokens); verb-first refers to
command position, not grammatical mood (cf. cargo's `tree`/`metadata`). Rejected: overloading
`audit` (that verb reports the *escape* surface of one binary — different object, different
lifecycle) and `coverage` (reserved for the coverage-depth arc's edge view; both share the rollup
renderer, not a verb).

```
cargo patina sites [--crate NAME] [--module PATH] [--group NAME] [--site LABEL] [--all]
                   [--exercised PATH] [--kind KIND] [--runtime driven|observed|invisible]
                   [--no-cache] [--selftest]
```

- Flags before positionals; there is no positional in v1 (the workspace is inferred from cwd like
  cargo). `--format json`/`--render` arrive via the existing global output flags.
- `--exercised PATH`: a campaign out-dir (reads its `sites.json`, §6) or a file containing raw
  `PATINA_SDK_REPORT` line(s) (any run's captured stderr works). Absent → static-only report.
- `--selftest`: planted-fixture recognizer proof, mirroring `campaign --selftest`
  (`campaign.rs:1330+`) and the fuzz-sweep selftest discipline.

### 6. Campaign aggregation (the exercised feed)

`cargo patina campaign` already captures child stdout/stderr for classification. Wave 3 adds: parse
every generation's `PATINA_SDK_REPORT` per-site tokens (all generations, not just notable ones) and
fold into per-label aggregates (the `exercised` counter set above, plus first/last generation seen).
Written to `<out_dir>/sites.json` (schema `patina.campaign.sites/v1` — the same object the sites
verb's `--exercised` loads). The `patina.campaign/v2` envelope gains, additively:
`artifacts.site_coverage` (path) and a top-level `sdk_sites` summary
(`{labels_seen, sometimes_unsatisfied, reachable_unreached, always_violated}`). Additive keys do
not bump the schema (the v1→v2 bump was for a shape change to existing keys, `campaign.rs:48-52`);
consumers of v2 must already tolerate absent-on-old, present-on-new fields per the field-omission
convention. `explore` gets the same treatment in a follow-on (it already suppresses per-run
finalization and reports once, `output.rs:64-73`); campaign is the canonical sweep and lands first.
The sometimes-gate arc consumes `sites.json` — its gate is "these labels must have
`sometimes_satisfied_runs > 0`", which is exactly one query over this artifact.

### 7. Hierarchy & grouping: one rollup, two arcs

A new `rollup` module in cargo-patina: input = leaf records with `(crate, module, file, groups)`
attribution + a numeric/flag payload; output = the crate→module tree with counts, percentages, and
gap callouts, renderable as human table or JSON. This arc's leaves are site records; the
coverage-depth arc's leaves are edge-coverage buckets attributed the same way. One implementation,
two data sources — the coverage-depth arc must not grow a second grouping mechanism, and custom
`.patina/` groups apply to both automatically.

### 8. `.patina/` repo config

`.patina/config.toml`, discovered by walking up from cwd (first hit wins, like cargo). TOML because
humans edit repo config and it needs comments; cargo-ergonomic; adds the `toml` crate to
cargo-patina only. (`campaign --spec` stays JSON: it is a machine-generated experiment input, a
deliberate asymmetry.) v1 grammar — three tables, nothing else, unknown keys rejected loudly
(the `apply_json` precedent, `campaign.rs:115-120`):

```toml
# Custom groups: a site joins every group whose matcher hits (path glob or label glob).
[groups.durability]
paths  = ["crates/wal/**"]
labels = ["wal-*", "fsync-*", "torn-*"]

# Default CLI knobs, per verb. Keys must name a registry flag of that verb;
# values must satisfy the flag's value grammar. A flag on the command line always wins.
[defaults.campaign]
generations = 500
buggify = true

[defaults.sites]
exercised = "out/latest"
```

- **Precedence:** explicit CLI flag > `.patina/config.toml` `[defaults.<verb>]` > built-in default.
  `--no-config` (global, alongside `--format`) ignores the file for hermetic runs.
- **Loudness:** when config supplies any default, the verb prints one
  `PATINA_CONFIG applied=<verb>:<keys> path=<file>` line and JSON envelopes gain a `config` field —
  behavior never changes silently.
- **Validation is registry-driven:** `[defaults.*]` keys resolve through `help::verb`/`flag_arity`
  (`help.rs:1281-1305`) and values through the same value-grammar table the existing drift gates
  prove against the parsers (`lib.rs:8689`) — so a flag rename breaks config validation in the same
  commit, not in a user's repo later.
- **Generated content:** all generated files live under `.patina/out/` (v1: the SCA cache; campaign
  `--out` defaults may point there later). On first write Patina creates `.patina/.gitignore`
  containing `/out/` if absent.

## Detection before fixes

Class detectors land *with or before* each wave; every one fails loudly, standalone:

1. **Recognizer-parity gate** (wave 1): a unit test parses `crates/patina/src/lib.rs`, enumerates
   every `#[macro_export] macro_rules!` whose expansion calls a `$crate::__rt::` registration shim,
   and asserts each is in the SCA recognizer table. A new SDK macro without SCA support is a red
   test in the same commit — the inventory cannot silently miss new macro forms.
2. **Planted-fixture selftest** (wave 1, `sites --selftest` + a unit-test harness): a fixture crate
   with every kind plus edge shapes — fully-qualified and bare invocation, `use`-renamed import,
   dynamic label, `#[cfg(test)]` module, a wrapper macro (asserted as an *expected* static miss) —
   with exact-count assertions per kind/context.
3. **Join gate** (wave 2, e2e): run a buggify testbed under `--buggify`, feed its report to
   `sites --exercised`, assert `unmatched_runtime_labels == 0` for the testbeds (they use the
   macros directly) and that every `driven` label in the SDK report joins a static row. Catches
   both SCA regressions on real code and report-format drift.
4. **Report-format drift** (wave 2): the SDK-report token parser lives in one place in cargo-patina
   with a round-trip test against `emit_sdk_report`'s output on a live run (two e2e runs, per the
   battery discipline) — the emitter and parser cannot drift apart silently.
5. **Aggregation-determinism gate** (wave 3): campaign selftest extension — same spec twice ⇒
   byte-identical `sites.json` (the campaign's existing determinism discipline extended to the new
   artifact).
6. **Config drift** (wave 4): `[defaults.*]` validation reuses the registry (above); plus a test
   asserting an unknown group key, an unknown flag key, and a grammar-violating value each produce
   a loud, path-qualified error.
7. **Vacuity guard** (wave 3): if an `--exercised` source contains zero `site=` rows while the
   static inventory has `driven` sites, the report leads with a WARNING (mirrors the
   vacuous-schedule diagnostic doctrine) — an empty join must never render as "100% nothing to do".

## Staged plan with verification tiers

Tiers follow the coordination policy: fast tier (fmt/clippy/tests/flag-drift + two e2e runs) for
CLI-only waves; full battery including the three validation scripts + Linux gates for
runtime-touching waves and at the arc boundary.

- **Wave 1 — SCA + `sites` verb, static only.** `rollup` module, syn scanner + recognizer table +
  cache, `sites` index/drill-down (human + `patina.sites/v1` JSON), registry entry, gates 1-2.
  No runtime/shim edits → fast tier. Docs: AGENTS.md verb list, llms.txt, TUTORIAL entry.
- **Wave 2 — runtime join.** `BuggifySiteReport` + SDK report row gain `@<file:line>`; all in-repo
  consumers migrated in-change; `sites --exercised FILE`; gates 3-4. Runtime-touching → **full
  battery** (incl. the three validation scripts) + Linux gates.
- **Wave 3 — campaign feed.** Per-generation SDK parsing → `<out_dir>/sites.json`; envelope
  `sdk_sites` + `artifacts.site_coverage`; `sites --exercised OUTDIR`; gates 5, 7. CLI-only → fast
  tier; hand the artifact contract to the sometimes-gate arc at this boundary.
- **Wave 4 — `.patina/` config.** Groups/tags in rollups (both arcs), `[defaults.*]`,
  `.gitignore` generation, `--no-config`, gate 6. CLI-only → fast tier, then the **arc-boundary
  full battery**.
- **Wave 5 — static site enumeration (phase 2, scheduled here — not a separate future
  arc).** Owned by this arc per user directive (2026-07-30: phase-2 items are tackled as
  part of their arcs, never parked for a later prompt). A link-time site table
  (`inventory`/`linkme`-style registration in the SDK macros, surfaced by both embedders)
  gives the campaign and the `sites` verb the FULL site universe up front, making
  never-reached `sometimes!`/`reachable!` sites visible as `registered_gens=0` rows — which
  is the moment the sometimes-gate arc's uniform gate starts biting on `reachable!` with
  zero redesign (its schema and formula already absorb it). Runtime + SDK touching → full
  battery + Linux gates; RED proof = a planted never-called `reachable!` visible in the
  static table and failing the gate.

Coverage-depth adopts the rollup module in its own arc once wave 1 lands.

## Open questions (small; nothing blocks wave 1)

1. Should `run --format json` embed parsed `sdk_sites` in the result envelope unconditionally
   (additive), or is the raw marker + `sites --exercised` path enough? (Lean: embed — it is one
   parse of a line already captured.)
2. `explore` aggregation timing: fold into wave 3 if cheap, else first follow-on.
3. HTML render (`--render` for `sites`): data model is ready by construction; scheduling only.
