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
| 4 | Native run clears guest env; `setenv` fails closed | arch + fix | Empty-by-default deterministic env with host env excluded is by design (host env is a nondeterminism source); explicit `--env KEY=VALUE` injects values, recorded in trace metadata. REVISED per user (2026-08-06): guest-side mutation is supported — `setenv`/`unsetenv`/`clearenv` are modeled deterministic operations on the guest env map with `getenv`/`environ` coherence (implemented; no per-mutation trace records — only the startup `--env` set is metadata). `putenv` stays fail-closed: caller-owned aliasing is unmodelable in an owned map and would fail silently-stale instead of loudly; the error names `setenv` as the path. |
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
- **2026-08-06 — sites.json store contract (landed with sometimes-gate).**
  One canonical per-campaign store `<out>/sites.json`
  (`patina.campaign.sites/v1`): top-level `schema` / `generations_observed`
  (the resume watermark campaign-steering Stage 3 consumes) / sorted `sites`;
  per-site label, kind, `@file:line` site, registered/satisfied generation
  tallies, evals/fires, first-satisfaction seed. Literal-label SDK macro sites
  also enter through invariant Wave 5's link-time table; never-reached
  `sometimes!`/`reachable!` rows remain in this schema with `registered_gens=0`.
  Campaign resume at a nonzero cursor refuses a missing/mismatched store rather
  than silently dropping coverage.
- **2026-08-06 — trace `events` JSONL exception.** Every verb's `--format
  json` emits one patina.result/v1 envelope except `trace events`, which
  streams patina.trace.events/v1 JSON Lines (a 1M-event envelope would be
  unusable); the exception is documented in the `--format` registry prose
  itself.
- **2026-08-06 — integration structure.** Work landed as three parallel jj
  stacks (CLI, campaign/sites, runtime/shim) integrated twice: ten
  verb-table conflicts at point one, doc-only conflicts plus two one-line
  merges at point two; full battery green at the integrated tip (5m52s).
- **2026-08-06 — clap adoption REJECTED by the spike's mechanical rule.**
  The throwaway clap port of `run`+`campaign` passed every functional gate
  (byte-identical help JSON/human help, e2e green, MSRV, single dependent)
  but cost +117 net parser LOC (804→921) with a 116-LOC bridge, +3.3s cold
  build, +2.33 MB binary. The decision rule required ≤0 net LOC, so the
  spike was deleted (no middle state) and the flag > env > `.patina/` >
  default config layer proceeds on the bespoke parsers in invariant Wave 4.
  Full criterion table in docs/arcs/clap-config-eval.md.
- **2026-08-06 — builder model fallback.** The GPT-5.5/Codex usage limit was
  exhausted mid-run (it was also the cause of the repeated "external kills" of
  pi builders throughout the session). Per the standing preference GPT-5.5 is
  the implementer tier, but with the user afk and the limit blocking all
  progress, implementation builders fall back to Claude Sonnet via the Agent
  tool (same briefs, same workspaces, same verification bars) until the limit
  resets; pi is re-probed at natural checkpoints and preferred again once
  available.
- **2026-08-06 (user review round) — builder fallback is Opus, not Sonnet.**
  User direction upon return: when pi/GPT-5.5 is limited, implementation
  builders fall back to Claude Opus via the Agent tool. Supersedes the Sonnet
  fallback entry above (the three Sonnet builders were stopped by the user for
  this reason; their workspace diffs were preserved and re-verified by Opus
  builders).
- **2026-08-06 (user review round) — Linux verification channel is Tensorlake.**
  User direction: use Tensorlake x86_64 sandboxes (CLAUDE.local.md recipe)
  instead of GitHub throwaway-CI rounds for Linux legs. All SlateDB-derived
  fixes get Linux validation there, not just macOS batteries: a verify agent is
  running the buggify item-9 repro (RED hunt at the pre-fix base snapshot
  commit, guard behavior at tip), the cdylib PIC RED→GREEN, and the
  native-shim/WASI/e2e batteries in a fresh sandbox from
  `qipgdlzrg0eylt8ewn8w7`.
- **2026-08-06 (user review round) — setenv decision revised: support it.**
  User overruled the "stays fail-closed" half of item 4: host env still never
  leaks in, but guest-side `setenv`/`unsetenv` (with `getenv`/`environ`
  coherence) are legitimate deterministic operations on the guest env map and
  are being implemented (no per-mutation trace records needed — mutations are
  guest-driven and deterministic; only the initial `--env` set stays in
  metadata). `putenv` is the builder's call: clean aliasing semantics or loud
  fail-closed naming setenv as the path.
- **2026-08-06 (user review round) — clap rejection overturned; full port
  approved.** The user rejected the mechanical "≤0 net LOC" criterion: the
  arc's actual goal is maintenance/quality, the +117 LOC was dominated by a
  116-LOC bridge that only existed because 2 of 10 verbs were ported, and
  byte-identical help JSON was never a requirement (schema-compatible is
  enough). Decision: one-change full port of all verbs + the help registry to
  clap, bespoke parsers and bridge deleted (no dual paths), verdict judged on
  maintainability/bug-class elimination/drift-gate fit with LOC reported but
  not decisive. Sequenced after fault-knobs Wave B and invariant Wave 5 land,
  because those diffs touch the same parser layer.
- **2026-08-06 (Linux verification round) — item 9 root-caused: `--swarm`
  masking, not the `--buggify=N` value form.** The Tensorlake verify agent
  proved from the ORIGINAL run's artifacts (the fork of the dogfooding
  sandbox) that the two reports carrying `enabled=0` had
  `fingerprint=...+buggify+pct+swarm` with swarm `selected_classes` excluding
  `buggify`, while the feedback's "control" run had no `--swarm` — the
  reduction blamed the wrong knob. The value form arms correctly at the base,
  observation (4bc5731), and tip commits on Linux x86_64. The landed coherence
  guard fires loudly on Linux for the masked case. Follow-up fix required:
  swarm class deselection must be REFLECTED in the fingerprint/metadata
  (drop `+buggify` when swarm masks it) instead of tripping the vacuity
  refusal — swarm masking is legitimate, and today a `--swarm --buggify=N`
  run whose seed deselects buggify aborts exit 134.
- **2026-08-06 (Linux verification round) — cdylib PIC fix is insufficient;
  reopened.** On the real SlateDB tree (workarounds reverted in the fork),
  `-fPIC` clears the `R_X86_64_PC32` relocation error but the same dependency
  cdylib link then fails with `duplicate symbol: rust_eh_personality` (the
  shim Rust staticlib bundles its own std; crc-fast's cdylib references the
  unwind personality; synthetic cdylibs without landing pads link green and
  mask this). Decision: implement the alternative the patch doc rejected —
  scope shim link args so they never reach dependency cdylib links, only the
  final binary — and make the regression fixture a dependency cdylib that
  references the personality routine. The reproduction also fires WITHOUT
  `--yield-points`; the flag was incidental. Task #14 stays open; the
  ws-tracecap patch does not land as-is.
- **2026-08-06 (Linux verification round) — two more Linux-only defects
  found.** (a) Feedback item 6 (entropy) is NOT fixed on Linux: getrandom
  0.3.4 resolves `getrandom` via `dlsym`, the shim's `__wrap_dlsym` returns
  NULL unconditionally, forcing the file fallback which opens `/dev/random`
  first (ENOENT; and modeling `/dev/random` alone just advances the failure
  to an unmodeled `poll`). Chosen direction: `__wrap_dlsym` returns the
  shim's own deterministic implementations for a curated entropy allowlist.
  (b) ELF audit provenance is wrong: `object=` resolves to STT_FILE markers
  (`crtstuff.c`, `patina_posix.c`) and the containing-symbol column is
  nonsense; two genuine imports expand into ~40 findings across seven bogus
  groups, and the provenance e2e fails on Linux. Both get dedicated fix
  builders; every fix re-verifies via a Tensorlake round before its task
  closes.
- **2026-08-06 — SlateDB-side harness findings are out of scope.** Items in
  `SLATEDB-SANDBOX-NOTES.md` (bank fenced-close neutrality, recovery scenario
  stabilization) live in the sandbox SlateDB checkout, not this repo; nothing
  to land here beyond the patina-side fixes above.
- **2026-08-06 (landing round) — clap port landed; verdict adopt.** The full
  registry-driven port of all verbs landed with net −820 non-test lines, no
  bridge, `default-features = false` (+3.4% binary), and clap pinned `~4.6`
  for MSRV. The port surfaced four shipped parser bugs, each pinned
  red-before/green-after; one user-visible rename fell out (`campaign
  --report` → `--report-failures`, the old spelling having been unreachable
  behind the global `--report OUT.html`). Wall-clock build-cost numbers in
  the arc doc §9.2 are recorded as unreliable (contended machine) — do not
  quote them as findings.
- **2026-08-06 (landing round) — item 9 fix landed; swarm deselection is
  coherent.** Fingerprints now reflect the per-generation effective class
  set, metadata records requested vs effective (`swarm_deselected=1`
  distinguishable from "never requested"), and `PATINA_SWARM_REPORT` covers
  every class uniformly. Postmortem, including why the original reduction
  misattributed the bug: `docs/bugs/swarm-buggify-fingerprint-coherence.md`.
  Deliberate choice: deselected classes are derivable from the trace, not
  stored (redundant state would be drift-prone and force a format bump).
- **2026-08-06 (landing round) — dlsym returns a routing table, not NULL.**
  For entropy (feedback #6), flat-NULL `__wrap_dlsym` was NOT fail-closed:
  callers treat NULL as "kernel lacks this" and take a less-modeled fallback
  (`/dev/random` open → ENOENT → poll → ENOSYS). `dlsym` now resolves
  exactly the entropy symbols the shim already defines deterministically
  (`getrandom`, `getentropy`) to internal-linkage implementations shared
  with the interposers; membership is structural (only symbols the shim
  models), so the table cannot widen guest reach. `getentropy` is included
  despite no measured consumer because the closure rule is what keeps the
  table auditable and omission is a silent demotion, not a refusal.
  `/dev/random` stays unmodeled (both realistic openers are gated on
  getrandom being unavailable, which it no longer is). The probe-compile
  regression fix chose a local `extern` over `-D_DEFAULT_SOURCE` so the
  shared probe flags don't change the visible glibc surface for other
  probes.
- **2026-08-06 (arc-completion round) — `--guided` ships with a measured
  no-advantage verdict.** The mandated efficacy demonstration (a purpose-built
  staircase fixture, `testbeds/guided-efficacy/`) found the initial ancestor
  weighting actively harmful (bootstrap-generation dominance, ~81% of the
  exploitation budget on one configuration); after the bootstrap-exclusion
  fix, the re-measured verdict is NO CONSISTENT ADVANTAGE (native: slower 2 /
  tied 4; WASI: slower 2 / tied 3 / faster 1 — including one seed the default
  sweep never solved). `--guided` stays landed, documented neutrally with an
  explicit caveat in llms.txt and the arc doc; the testbed gate exits 1 so no
  efficacy claim can land without earning it. Recency weighting was tried and
  removed (changed zero seed bases); rarity weighting was rejected because it
  requires cumulative state that cannot be rewound to a generation boundary
  without breaking guided-resume determinism.
- **2026-08-06 (arc-completion round) — split shim/guest toolchains refuse
  with NO escape hatch.** Unlike the audit `--allow-unsupported-symbols`
  hatch, a guest carrying two libstds is never a valid build (on macOS the
  link even SUCCEEDS silently), so the refusal is unconditional. Known
  fail-open residual, accepted: a per-directory `.cargo/config.toml`
  `build.rustc` split is not probed — only `RUSTC` and rustup's ambient
  per-directory resolution are.
- **2026-08-06 (arc-completion round) — the buggify-fingerprint coherence
  guard stays scoped to record/replay; `--fingerprint` on a seeded native run
  is refused, not ignored.** A seeded run sets no `PATINA_FINGERPRINT`, reads
  none, and produces no coverage-claiming artifact; every campaign generation
  records, so the coverage-claiming path is already guarded. Rather than
  leave the flag silently inert there (inert knobs are bugs), it now requires
  `--record` via the registry's `needs` mechanism, advertised in the JSON
  help.
- **2026-08-06 (arc-completion round) — campaign gains `--dns-entry` beyond
  the Wave D brief.** Without a host table, every campaign generation
  resolves NXDOMAIN by semantics, no DNS fault is ever eligible, and
  `VACUOUS_DNS_FAULT` could never fire — the band was inert by construction.
  One registry definition shared with `run`; recorded in the out-dir spec
  (key omitted when empty so existing out-dirs resume byte-identically);
  refused on continuations and for WASI artifacts.
- **2026-08-06 (landing round) — cdylib fix landed as link-arg scoping;
  `-fPIC` dropped; personality trigger unconfirmed.** Guest builds use
  `cargo rustc` so shim objects/staticlib/`--wrap`/`-lc` reach only the
  final-binary link; cfgs and sancov codegen stay whole-graph, and a weak
  no-op sancov stub object keeps `--yield-points`-instrumented dependency
  cdylibs linkable. `-fPIC` is dropped from the shim objects (only ever in
  executable links; never prevented the class) and kept solely on the
  whole-graph stub. Correction to the earlier entry: the `duplicate
  rust_eh_personality` variant did NOT reproduce across four synthetic
  fixture shapes — the crc-fast trigger remains unidentified and the fixture
  asserts on shim-symbol leakage (which reproduces on both platforms); the
  scoping fix removes the shim from that link regardless of trigger. The
  real-tree crc-fast rebuild remains a re-verify-round obligation.
- **2026-08-06 (skills round) — D9 delivered as ONE thin guidance skill,
  not two task-oriented loop docs.** The user's design call: the skill
  explains what Patina is and its capabilities in broad strokes, then
  teaches HOW to learn the current surface from the generated registry
  (`--help` progressive disclosure, row semantics, the environment
  registry, refusals-as-teaching), so it does not churn with every flag
  change. The two planned files shared their churn-prone half; one file
  ships with both loops as orientation sections. Deliberately rejected in
  the same pass: enumerating fault knobs, campaign options, or envelope
  field lists — the registry answers those more accurately than prose.
  Three literal flag tokens in 281 lines; drift-gate coverage proven
  non-vacuous (planted token caught by file and line).
