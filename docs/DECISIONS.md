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
- **2026-08-07 (consolidation round) — fault knobs are ONE enum; the compiler,
  not drift gates, walks a new knob to every decision point.** `FaultKnob`
  (17 variants, registry order) + a KnobMeta table in
  `crates/patina-runtime/src/fault_knob.rs`; every consumer is an exhaustive
  match or a fold over `ALL`. Deliberate split of authorities: value grammar/
  families stay in the CLI registry, campaign bands and vacuity classes stay
  in campaign.rs — keyed by the enum so they cannot be skipped, but never
  duplicated. Swarm draw order is trace-visible and is NOT registry order, so
  it stays a separately pinned ordered table. Behavior preservation proven by
  an empty pre/post derive_flags diff (gens 0..50 × 3 spec shapes × 3
  families) and byte-identical traces on fs/net/dns legs. The exhaustiveness
  immediately caught a real Wave E gap: WASI parsed `--net-partition` and
  silently dropped it (now forwarded). Remaining knob gaps (bands for the
  five Wave E knobs, net-jitter, starve; net vacuity class; sched-det XOR
  seeds) are explicit `None` arms with pinned gate lists that fail loudly
  when a gap closes.
- **2026-08-07 (arc-completion round) — unified-fault-knobs acceptance met; two
  dogfooding catches became structure.** F+ phasing per scout evidence: entropy
  (`--entropy-fail-permille`, gen byte 28) and clock realtime jumps
  (`--epoch-jump-nanos`, byte 29, signed per-read draw saturating at zero,
  monotonic untouched — realtime-anchored deadlines deliberately jump, that is
  what an OS clock jump does) landed now; clock skew and spawn faults wait for
  a scheduler/monotonic API wave; allocator faults are out of scope (nothing is
  interposed). Acceptance is a repeatable script (`testbeds/workq/acceptance.sh`)
  whose catch selection requires `shorts_applied>0` alongside the marker — its
  own red-proof caught a marker-only confound. The campaign found TWO real
  pre-existing workq bugs while proving it: the WAL never parent-dir-fsync'd
  its segments (dir-fsync model correctly dropped them; fixed with fsync_dir),
  and the segment probe used `Path::exists()`, which swallows injected stat
  errors so the audit fabricated violations against an intact log (fixed:
  NotFound ends the probe, anything else fails closed). Both lessons are now
  guest guidance in the skill doc. Process: the deterministic testbed gates
  joined `mise run check` (two incidents proved CI-only steps hide landings);
  schedule-sensitive seeded-bug demos sweep a bounded seed window instead of
  pinning one seed (the domain_seed migration re-rolled schedules and broke the
  Linux pin — verified on both platforms before push). Open fork awaiting user:
  how guest-deliberate fail-closed aborts become classifiable (standard
  contract line vs spec-declared markers) — 15/40 acceptance generations filed
  UNCLASSIFIED off workq's own WORKQ_ABORT dialect.
- **2026-08-07 — ctor limitation reclassified: scope decision, not impossibility.**
  Patina controls the guest link, so the shim's constructor could be sequenced
  first and guest ctors treated as a recorded deterministic prologue (their
  order is fixed for a fixed binary, and traces are build-fingerprinted). It
  stays out of scope because early-init bring-up is the most fragile corner of
  both loaders (dyld/glibc init interleaving, TLS and malloc initialization,
  the shim's own alias resolution) and source-available guests have the
  two-line cfg-guard pattern. The one case the workaround cannot serve — a
  binary-only unmodified guest with an effectful static constructor — is the
  trigger that would promote "ctor prologue support" to a real arc.
- **2026-08-12 — outcome-channel arc approved; core declared guest-agnostic.**
  The five design decisions settled by the user: (1) guest verdicts are ONE
  shim-ABI verb, `patina_verdict(kind, label, detail)` — kinds are data, not
  symbols (validated against Antithesis, whose entire SDK funnels assertions
  AND lifecycle through the single `fuzz_json_data(ptr, len)` JSON entry point
  with a JSONL-file fallback and label-keyed aggregation); (2) the
  `patina.result/v1` envelope becomes the classifier's ONLY input — every
  marker list deleted in the same change, workq/pubsub migrated, no dual path;
  (3) level-1 guests classify via spec-declared per-guest patterns + exit-code
  maps (grep survives only as explicit per-guest config); (4) the pre-main
  init probe is green-lit as its own track (ELF `.preinit_array` + macOS
  link-order evidence before any prologue arc); (5) guest deliberate abort is
  its own campaign class `GUEST_ABORT` — with patina refusals
  envelope-attributed, an unattributed SIGABRT is the guest's finding, not
  infra noise. This also closes the 2026-08-07 open fork on classifying
  guest-deliberate aborts. New doctrine (AGENTS.md): core patina is
  guest-agnostic — no testbed-specific identifiers or workaround branches in
  `crates/*`; the `WORKQ_VIOLATION`/`BUG_CAUGHT` strings in the campaign
  classifier are the named debt the arc removes. Design:
  `docs/arcs/outcome-channel.md`.
- **2026-08-12 — pre-main probe ran; the platforms are asymmetric.** Measured
  evidence in `docs/probes/premain-init.md` (probe verified by re-running
  firsthand). Linux: main-executable `.preinit_array` runs before every
  `.init_array` constructor in every delivery shape patina uses — static
  archive, rustc-driven link, `crt-static` — and before all shared-object
  ctors including `LD_PRELOAD`. Caveats: ordering *within* preinit is link
  order (a guest can register its own preinit entry — detect and refuse, don't
  assume), and a DSO `.preinit_array` fails two ways (GNU ld refuses; gold
  emits a `DT_PREINIT_ARRAY` glibc silently ignores — audit the tag, don't
  trust the linker). macOS: initializer order follows the link line as
  claimed, and that is exactly the problem — rustc places crate objects ahead
  of every `-l static=` library and `-C link-arg` appends (no stable hook to
  prepend), so **a static shim can never run before guest ctors in a
  rustc-driven link**; `-force_load` makes it last. Only a dylib wins (linked
  `-l dylib=`, or `DYLD_INSERT_LIBRARIES` with SIP caveats). Consequence for
  the init-prologue arc: Linux gets an order-independent guarantee for free;
  macOS requires a shim packaging change (staticlib → dylib) — that choice is
  the arc's first design decision. Untested: x86_64 Linux, musl, signed/SIP
  binaries.
- **2026-08-12 — SlateDB all-features audit: NOT clean; the dst feature pin is
  load-bearing.** Follow-up from the dogfooding round, run in a fresh
  Tensorlake sandbox (terminated after). With slatedb's full feature set the
  audit refuses (exit 2, 8 findings), attributed by single-feature isolation
  builds, not inference: `aws` (in upstream `default`) pulls aws-lc-sys 0.41.0
  → 7 unknown-import rows (`OPENSSL_memory_*`, `__assert_fail`, `sdallocx`,
  `__isoc23_sscanf`); `foyer` (also upstream default) pulls fastant 0.1.11 →
  an inlined `rdtsc` cpu-nondeterminism finding. The dogfooding round's clean
  result held only because slatedb-dst pins `default-features = false`. With
  foyer off and the 7 aws-lc imports `--allow`ed: exit 0, 73 symbols vs the
  66-symbol baseline (delta is exactly those 7), deny-trap set identical.
  Verified locally against the CLI and audit source: (a) `--allow` cannot
  absorb an instruction-class finding — correct per the SUD-manageability
  split (a register read cannot be trapped or interposed; allowing it would be
  a silent determinism hole), but the refusal text does not say the class is
  unallowable — follow-up: name it in the diagnostic; (b) neither `build` nor
  `audit` takes `--features`/`--all-features`, so feature variation means
  editing the guest manifest — follow-up filed (cargo-like UX says these
  belong on the cargo family). Guest gotcha for the skill doc pile:
  slatedb-dst is `#![cfg(tokio_unstable)]`; pre-existing `RUSTFLAGS` compose
  with the shim flags via `CARGO_ENCODED_RUSTFLAGS`, so `--cfg tokio_unstable`
  works unchanged under patina.
- **2026-08-12 — minimize oracle perf measured; trace-shrink is at its
  intrinsic ceiling and the big lever is a different reducer.** Full measured
  investigation in `docs/probes/minimize-oracle-perf.md` (attribution is
  exact: the search was ported and replayed against recorded verdicts;
  headline repro verified firsthand at 24 ms). Findings: ~2 % shrink is all a
  strict-replay oracle allows on these traces (deletions desynchronize the
  stream; only 14/944 positions survive) — no smarter subset search helps;
  half the 32 ms/candidate is protocol overhead, not replay; the
  fixed-point confirmation round is 25 % of calls; `reduce_schedule` accepted
  nothing (as its own docs predict for strict replay). Ranked, measured
  options: (1) fault-knob vector reduction as a first-class reducer —
  17-18 knobs → 2 in ~20 oracle runs, 0.3 s vs 290 s (~1000×), fills a real
  gap (`--scenario` reduces seeds/params, nothing reduces the campaign's
  fault vector, which is where campaign failures come from); (2) resume-sweep
  ddmin + memoized candidates — 3-3.7× fewer calls, byte-identical outputs
  verified with `trace diff` on both traces; (3) `--jobs N` parallel oracle
  batches — 4.9× at 8 workers, hermetic candidates already isolate;
  multiplies with (2). Correctness catch worth landing with any of it: the
  acceptance-oracle recipe greps the marker but ignores replay exit status —
  a latent fail-open that early-exit variants would make reachable; oracles
  must also require a clean replay. Implementation not started (user to pick
  scope).
- **2026-08-12 — minimize/audit/campaign wave landed; user decisions recorded.**
  User-settled design calls: `minimize` becomes knobs-first BY DEFAULT with the
  trace ddmin phase still on by default behind an opt-out flag (measured trace
  timing to be reported from the CLI wave); parallel oracles auto-enable only
  for the patina-owned built-in oracle (hermeticity is an architectural
  invariant), external command oracles stay serial with an explicit `--jobs`
  opt-in and a printed declination warning; the TSC trap slice covers RDTSC +
  RDTSCP only (CPUID deferred; RDRAND/RDSEED and arm64 CNTVCT have no
  userspace trap and stay refusals); extensibility direction leans SDK
  custom-op API, tradeoff discussion delivered, arc doc pending. Landed this
  round, each red-before/green-after with planted-bug non-vacuity checks and
  one full check battery over the combined tree: aws-lc audit class fixes
  (alias-generation normalization, `__assert_fail` known-safe, undefined-weak
  inert rule narrowed to unknown-import — a weak import of a named escape
  class still refuses; the seven-symbol aws-lc set audits clean with zero
  `--allow`, Linux corpus re-audit still owed); campaign forwards
  `--harness`/`--allow`/`--allow-unsupported-symbols` to every child run AND
  the replay repro line (gap found by the builder: these are host facts the
  trace cannot restore), wrong-family refusal names the flag, child pre-run
  refusals still classify INFRA; minimize core resume-sweep + sha256 memo with
  deterministic sampled re-verification that aborts loudly on a
  nondeterministic oracle (first cache hit always verified so the guard is
  never vacuous) — real-trace: 9,014 -> 5,767 oracle calls, 261 -> 168 s,
  byte-identical output; remaining duplicate-collapse lever moves to the CLI
  wave via shared memos. Two observations filed: harness-without---harness
  child failure classifies UNCLASSIFIED today (outcome-channel Wave B
  candidate); inverted oracle polarity "minimizes" everything (polarity guard
  in the CLI wave).
- **2026-08-12 — aws-features-zero-allow residual CLOSED on the real corpus.**
  Linux x86 sandbox re-audit at 314c68be: slatedb-dst with every feature except
  foyer audits EXIT 0 with zero `--allow` — the five aws-lc weak hooks appear
  under the new inert-weak stderr note (both output modes verified),
  `__assert_fail` and `__isoc23_sscanf` classify silently into the residual
  list, the deny-trap set is byte-identical to baseline, and default-features
  shows no regression (66 residual symbols, no inert-weak note). Full
  all-features-with-foyer now refuses on exactly ONE finding — the fastant
  inlined rdtsc — confirming the aws side was a classification gap and the
  foyer side is a genuine cpu-nondeterminism escape (the in-flight TSC trap
  slice is its fix). Sandbox terminated with proof.
- **2026-08-12 — minimize CLI wave: knobs-first pipeline, patina-owned oracle,
  `--jobs`, polarity guard.** `cargo patina minimize --generation N --marker
  TEXT` is the new front door for a campaign failure and runs the user-settled
  default: reduce the fault-knob vector FIRST, then delta-debug a trace recorded
  from the minimal-knob run, with `--no-trace-phase` as the knob-only opt-out.
  Measured on the probe's own case (workq generation 14, macOS arm64, 10 CPUs):
  18 knobs -> 2 in 22 seeded re-runs, 0.45 s at the default `--jobs` and 0.96 s
  at `--jobs 1`, landing on the same two knobs the probe found by hand
  (`--fs-short-permille 122 --dns-entry workq-server=127.0.0.1`), and the printed
  command reproduces standalone in 32 ms. The trace phase over that reduction is
  21.5 s at the default (jobs=5 on this host) against 57.6 s at `--jobs 1`,
  2.7x, for byte-identical output at jobs 1, 5 and 8.
  Hermeticity is the reason parallelism is safe and is stated as an invariant:
  patina's own oracle replays each candidate into its own temp directory with
  the guest's filesystem, clock, network and entropy virtualized, so it is
  parallel by default; an oracle COMMAND is opaque to patina and stays serial
  unless `--jobs` opts in, with a printed declination saying why. Parallelism is
  throughput-only by construction rather than by testing: a reducer offers the
  oracle the window of candidates a one-at-a-time scan would try next and keeps
  only the FIRST accept in scan order, so a widened window cannot move the
  result (red-proved by taking the last accept instead of the first). The
  built-in oracle also closes the probe's section 4 option 6 fail-open: a
  candidate still fails only when the marker appears AND the replay did not
  diverge, and `testbeds/workq/acceptance.sh`'s shell oracle now applies the
  same rule. Two loud refusals replace two silent wrong answers: an oracle that
  reports the failure surviving with every reducible decision deleted is refused
  as inverted exit polarity (the footgun the minimize-core builder hit live),
  and a generation that does not reproduce its `--marker` from its recorded seed
  and knobs is refused before anything is dropped rather than "reduced" to
  nothing. The schedule pass now runs once after the deletion pass settles
  instead of inside every joint round, since only a schedule rewrite can unblock
  a further deletion. That pair — one shared memo across the joint loop plus the
  deferral — is attributed on the acceptance-shape search (the untouched
  944-decision generation-14 trace, external shell oracle, `--jobs 1`, same host
  and same trace, one build with the old joint loop and one with the new):
  5,768 -> 3,631 oracle calls and 174.1 s -> 108.7 s for byte-identical output
  (944 -> 927 both). The 5,768 reproduces the previous round's recorded 5,767
  plus this wave's one polarity-guard call, so the two measurements chain.
- **2026-08-12 — TSC trap slice landed (RDTSC + RDTSCP).** On x86-64 Linux the
  shim arms `prctl(PR_SET_TSC, PR_TSC_SIGSEGV)` so inline `rdtsc`/`rdtscp` raise
  a synchronous SIGSEGV the handler answers from the same `patina_clock_now`
  every interposer and SUD row calls — a trapped counter read records an
  ordinary `clock_now` op (parity is structural, verified in the trace). 1 tick
  = 1 virtual ns (nominal 1 GHz), TSC_AUX fixed 0. The audit's
  cpu-nondeterminism category now carries a per-finding mnemonic and splits on
  it: rdtsc/rdtscp are TSC-trap-managed (downgraded ONLY on a platform that
  arms the trap), while rdrand/rdseed and arm64 `cntvct` stay refusals — and the
  refusal text now NAMES instruction-class findings as unallowable-and-here-
  untrappable, closing the earlier `--allow`-silence follow-up. Metadata records
  arming (`"tsc":true`), replay reconciles both directions (mismatch refuses).
  Structurally mirrors the SUD slice; `sud_fatal` generalized to `trap_fatal`.
  Cross-platform evidence: x86 Linux positive legs (armed runs, byte-identical
  same-seed repeats, record->replay identity, rdrand still refused on the same
  host) proven in a Tensorlake sandbox; arm64 Linux shim compiles clean under
  `-Werror` and shim+target unit tests pass on the Tart VM (full guest-link
  validation there is disk-blocked — pre-existing infra limit, and the slice
  adds no arm64 runtime path); macOS host full battery green. Two disclosed
  items: under an armed trap Rust std skips installing its stack-overflow
  SIGSEGV handler (it installs only over SIG_DFL and the shim arms first), so a
  stack overflow dies on the default action without std's overflow message — a
  diagnostic regression, determinism kept, documented in the shim; fastant/
  quanta calibrating-guest demo deferred (the 1 GHz mapping is chosen to make a
  calibrating guest derive exactly 1 GHz — worth a follow-up). This is the fix
  for the last SlateDB all-features refusal (foyer/fastant rdtsc). Process: the
  wave's two builders (TSC, minimize-CLI) shared one working copy, which caused
  a fmt-clobber and interleaved doc edits — resolved, but the standing rule is
  now separate worktrees for concurrent builders.
- **2026-08-13 — TSC-slice arm64 residual closed.** With the user-authorized
  MRE `target/` cleanup freeing 4.2 GB on the Tart VM (sources untouched), the
  previously disk-blocked full `validate-native-shim.sh` ran on arm64 Linux at
  main `026269f2`: EXIT 0, TSC legs loud-SKIP with the correct refusal
  rationale (aarch64 has no counter trap; `mrs CNTVCT_EL0` stays a
  cpu-nondeterminism refusal), SUD refusal branch green. All three platforms
  now have full evidence for the wave.
- **2026-08-13 — fastant calibration probe: the 1 GHz mapping is exact, and a
  calibrating guest wedges before main.** Full report:
  `docs/probes/fastant-calibration.md`. Confirmed to the digit: a calibrating
  guest derives cycles_per_second = 1,000,000,000 with zero error, invariant
  under sleep jitter (the counter and the clock it calibrates against are the
  same object). All determinism legs pass (same-seed identical, record->replay,
  seed variation). THE FINDING: fastant 0.1.11's calibration busy-waits on
  10 ms of monotonic progress inside a pre-main ctor with no sleep/yield —
  under frozen virtual time the exit condition is unreachable, so the guest
  spins at 100% CPU before main, on both the standalone guest and the real
  SlateDB+foyer native build. The liveness watchdog is structurally blind to
  it (its no-progress window is measured in virtual ns, which do not advance) —
  verified with a 1 ms budget not firing against a 60 s hang; `--budget` is
  the only backstop (loud, but opt-in, and a budget abort loses the recorded
  trace). The SlateDB full-feature-space audit closure is REAL (foyer's rdtsc
  now TSC-trap-managed, exit 0, zero --allow) but the audit's "runnable"
  wording overclaims: the native run hangs in the ctor. Open design decision
  (user): frozen-clock semantics — named-abort churn detector vs
  advance-virtual-time-on-spin (leg 3b proves the derived frequency is
  invariant to how time advances). Follow-ups filed: CPUID is an unaudited,
  untrapped host read (11 sites invisible in the same binary; the branch that
  SELECTS fastant's TSC path — cross-host reproducibility hole; cheap first
  step is audit visibility as a named non-refusal class, ARCH_SET_CPUID trap
  remains the deferred slice); the audit classifies the native artifact even
  when the package's real execution family is cargo (verdict should name its
  family — in the cargo family fastant's rdtsc is a genuine unmanaged host
  read, empirically non-divergent here but undescribed); source-first `run`
  leaks the positional source path into guest argv (routing bug); budget-abort
  record finalization drops the trace that would explain the wedge.
- **2026-08-13 — outcome-channel Wave A landed (verdict ABI + runtime facts).**
  Built as two concurrent builders in ISOLATED WORKTREES (first wave under the
  new rule) and merged by the coordinator: `patina_verdict(kind,label,detail)`
  across all three families (shim verb / `patina_sdk` WASI import /
  `Context::verdict`), kinds as pinned u32 data (unknown kind refused, never
  defaulted), recorded as `Operation::Verdict` riding the ordinary replay
  reconcile so a divergent verdict stream fails closed; `always!` lowers to a
  VIOLATION verdict in `Context::always_check` (the shim path never returns,
  so lowering lives one level up) with the legacy `PATINA_ALWAYS_VIOLATION`
  print kept as transitional dual-emit until Wave B; runtime does no mid-run
  I/O — verdict lines queue in pending_diagnostics and drain at SDK entry
  points (a mid-run eprintln under the shim would re-enter sched_point with
  the context lock held). Runtime-owned facts ship on a new
  `patina.runfacts/v1` channel (path for cargo/WASI, inherited fd for native,
  written via host aliases): envelope gains `verdicts[]`, `fault_reports{}`,
  `runtime_findings[]`, `refusal` (parent-constructed — a dying child cannot
  cooperate), and `guest_exit` (signal split from exit code). Facts also emit
  at watchdog fire so the channel reports exactly the failures it exists for;
  the channel ignores the PATINA_*_REPORT suppression knobs (printing and
  facts are different things — a consumer must not blind the future
  classifier by silencing a diagnostic). Envelope shape pinned by an exact
  sorted-key test; all fields additive. Merge notes: six conflicting hunks
  hand-reconciled (both halves extended the envelope); `git apply --3way`
  must NOT be used in this colocated repo (index staging triggers a jj
  working-copy reset that silently reverts the apply — plain `git apply`
  only). Full battery green over the merged tree.
- **2026-08-13 — Advance-on-spin + the frozen-clock churn backstop.** Closes the
  calibrating-guest gap the fastant probe found (`docs/probes/fastant-
  calibration.md`): virtual time advanced when a guest *waited* (sleep) or when
  every task was parked with a timer pending, but not when a guest was
  *runnable* and doing nothing but reading the clock. That is the shape of a
  startup calibration loop — `fastant`/`minstant`/`quanta` busy-wait for 10 ms
  of monotonic progress inside a pre-`main` constructor — so the real unpatched
  fastant guest hung forever at 100% CPU before `main`, and the audit called it
  runnable. User-approved design (not relitigated): the baseline clock RATE
  stays exactly 1 tick = 1 ns; per-op ticking was considered and rejected
  (timestamp/op-count coupling, tick-size dilemma).
  **The knobs and why.** K = 1024 consecutive clock-observation ops at unchanged
  virtual time with no intervening progress op. The streak is broken by any
  genuine effect and by time moving for any reason the rescue did not cause, so
  real code cannot accumulate it; 1024 is an order of magnitude past even a
  pathological polling loop, which is what keeps every existing recorded
  artifact byte-identical (proven: the full workspace suite plus the workq and
  pubsub batteries pass unmodified). Token = 1 µs doubling per rescue to a 1 ms
  ceiling: the first rescue barely perturbs a guest that is merely polling hard,
  while escalation converges a real wedge in tens of rescues (19 for a 10 ms
  window) rather than millions of iterations, and the ceiling caps the overshoot
  on that window at 10%. M = 256 rescues before the frozen-clock churn abort —
  >250 ms of virtual time bought no progress, 25× the canonical window, so the
  loop is ignoring the clock rather than waiting for it.
  **Shape.** The advance rides the deadlock rescue's mechanism: a recorded
  `SleepUntil` on the monotonic clock, clamped so it never steps over a
  still-future timer deadline. The trigger is a pure function of the recorded op
  stream and the driver's monotonic value, so it re-fires at the same op on
  replay. This IS a semantic change — repeated `Instant::now()` at frozen time
  is no longer idempotent — which is exactly why it is recorded rather than
  re-decided. The churn abort reuses the established
  `PATINA_VIOLATION liveness …` interface contract with `detail=frozen-clock-
  churn`, so the campaign classifier routes it with no classifier change; a
  matching `runtime_findings` entry lands on the facts channel. With time now
  advancing during spins the generic liveness watchdog regains traction on this
  class too (its window is measured in virtual ns); whichever mechanism trips
  first stops the run, proven by a test that pits them against each other.
  **Two related fixes.** (1) A `--record` run stopped by `--budget` used to
  yield "empty trace file; record finalization did not complete" — the abort
  skips the atexit shutdown that is `Context::finish`'s only native-family
  caller, so the one artifact that would explain a wedge was exactly what you
  lost. Runtime-initiated stops (budget, churn) now flush a truncated-but-valid
  trace first, at most once (the native transport is an append-only fd, so
  `finish` skips its write after a flush). Deliberately scoped to runtime stops:
  a guest that calls `abort()` itself still leaves no trace, and that existing
  contract is untouched. (2) The audit/gate TSC notes said "Runnable on x86-64
  Linux", which overclaimed; they now keep manageable and runnable distinct and
  name both new outcomes.
  **Evidence.** Local: RED proven by disabling the rescue (the calibration test
  runs >118 s without finishing; with it the whole 107-test runtime suite takes
  0.19 s). x86-64 Linux sandbox (`lj32pbzg7js2u8hlme5mm`, terminated): the
  UNPATCHED fastant guest now runs to completion in ~1 s, derives exactly 1 GHz
  in all three windows, three same-seed runs byte-identical, record→replay
  byte-identical. Trace: 30,782 events / 3.45 MB, of which 33 `sleep_until` —
  30 spin rescues (first at seq 1024, then every 1025 ops, ladder 1→2→4…→1000 µs
  and holding) and 3 guest sleeps; the last rescue lands at 21,023,000 ns, which
  is exactly the anchor offset the guest prints. Two orders of magnitude under
  the 1M-event cap.
  **Disclosed, not fixed here.** A native replay whose runtime init fails (e.g. a
  `--fingerprint` mismatch) manifests as an infinite spin rather than the usual
  loud abort *for a guest whose only boundary ops are clock reads*, because
  `patina_clock_now`'s bootstrap window answers 0 without calling
  `ensure_runtime`. Pre-existing and orthogonal to this slice (such a guest hung
  either way before), but it is a fail-closed hole now that these guests
  otherwise run: any other first op aborts loudly. Worth its own slice in the
  shim bootstrap.
- **2026-08-13 — triple wave landed: custom-ops A, outcome-channel B,
  advance-on-spin.** First full jj-workspace coordination round: three
  builders in isolated working copies, stacked by `jj rebase` (two merges
  conflict-free; spin's materialized three trivial union conflicts, resolved
  in place — no patches). Cross-wave semantic risk verified live: spin's
  churn abort ships a runtime_findings facts entry, so Wave B's
  structured-only classifier routes it to Liveness with zero classifier
  edits. Landed: the custom-op record/replay ABI (three verbs, phase-typed;
  modeled-effect-in-perform refused at record); the classifier's marker era
  ended (structured facts + spec-declared rules only, GUEST_ABORT live,
  guest-agnostic debt gone, two Wave A defects fixed red-first —
  incomplete_trace-as-refusal had made GUEST_ABORT unreachable); and
  advance-on-spin (K=1024, 1 µs doubling to 1 ms ceiling, churn abort at 256
  rescues; ablation-proven non-perturbing, 56/56 battery hashes identical
  with the rescue disabled) plus budget-abort trace preservation and the
  manageable-vs-runnable audit rewording. The fastant/foyer closure is now
  END-TO-END: the unpatched calibrating guest runs to completion at exactly
  1 GHz in the x86 sandbox (previously a pre-main 100%-CPU hang), so the
  full SlateDB feature space both audits clean and RUNS natively. New bug
  filed from spin's disclosure:
  docs/bugs/replay-init-error-swallowed-for-clock-only-guests.md (bootstrap
  clock answers 0 without ensure_runtime — a fail-closed hole newly
  consequential now that clock-only guests otherwise run). Open next:
  outcome-channel Wave C (testbed verdict migration; WASI-trap envelope
  residue), custom-ops Wave B (seeded faults), CPUID audit visibility.
- **2026-08-13 — four-builder round landed: outcome-channel Wave C, custom-op
  faults, CPUID visibility, replay-init swallow.** Full jj-workspace round,
  every rebase in the five-commit stack conflict-free. Landed: testbeds report
  through the verdict ABI (declared patterns dropped — generation 14's
  wal-integrity catch classifying VIOLATION with NO spec is the proof the
  envelope is the source; the minimize oracle re-keyed on the ABI's own wire
  format, now guest-agnostic) and WASI guest traps get run envelopes (an
  always! trap classifies VIOLATION, was INFRA; the split is structural on
  trap codes — patina's fuel/memory limits stay engine errors); seeded
  custom-op faults as a compiler-walked knob (gen byte 30, fault_eligible ABI
  bit — the guest's failure payload never crosses the boundary; injected
  faults record as Outcome::Error; zero-eligible-ops is vacuous BY DESIGN,
  stricter than other planes; opt-in --custom-op-faults band on the DNS-band
  precedent); cpuid decoded into a new host-identity class, visible-never-
  refused (deterministic within a host, costs cross-host portability; exit
  codes unchanged; ARCH_SET_CPUID trapping stays deferred; pre-run gate
  deliberately not wired — audit is the inspection verb); and the replay-init
  swallow FIXED detector-first (class detector red first, naming all five
  swallowing entry points in one collected run; structural fix — one guarded
  in_shim_bootstrap predicate + source lints forbidding a second
  SHIM_BOOTSTRAP reader and forcing call-site enumeration; A/B byte-identity
  6/6). Two additional real bugs surfaced and fixed in the round: pubsub's
  VACUOUS_NET_FAULT gate had been silently inert since the fault-report field
  renames (a vacuous vacuity gate — now reads the runtime's own per-plane
  vacuous bit, absent-is-vacuous) and a second init-error swallow
  (println!-only guest exited 0 with output dropped, refusal unreported —
  pre-existing, proven on the parent revision). Merge-time coordinator items
  applied: scan_forbidden_instructions renamed scan_instruction_classes (the
  name lied), stale rdseed-residual claims corrected, custom-op ABI prose
  caught up. Testbed judgment calls accepted: guest liveness timeouts stay
  printed diagnostics (no verdict kind — whether a run SHOULD converge
  depends on fault config the guest cannot see); ALWAYS_VIOLATION and
  SAFETY_BUG stay distinct classes scoped by per-guest label sets. Follow-ups
  open: call-graph audit of the ~100 non-window C-ABI entry points for the
  answer-without-ensure_runtime class; minimize auto-target from verdicts
  (round two, launching).
- **2026-08-14 — minimize auto-target landed; the outcome-channel arc is
  COMPLETE.** `minimize --generation N` now derives its oracle target from the
  campaign's own recorded verdicts — no hand-written `--marker`; the incoherence
  that started this arc ("the campaign knew the failure, then made the operator
  re-encode it") is closed. Four target-narrowing boundaries, each pinned:
  failure verdicts only enter the target (a PASS is a property that HELD —
  preserving it would preserve a success); containment not equality (extra
  candidate verdicts are free); ALL target verdicts, not any (reproducing one
  of two broken invariants is a weaker failure — fail closed; `--marker` is
  the looser-question escape hatch); detail strings never match (free-form
  payload). Campaign state schema bumped v1→v2 with `verdicts` as a REQUIRED
  field on notable runs — a v1 out-dir is refused by name, never read as
  empty (a missing-field read would produce the WRONG refusal). The
  reproduction guard extends to auto-derived targets: a target that does not
  reproduce from the recorded seed+knobs refuses before anything is dropped.
  workq's acceptance oracle simplified from a 44-line external script to the
  built-in path, both of its fail-open rejections verified empirically
  (belt-and-braces: shim-fatal text checked first, verdict containment
  catches the diverged shapes the text does not). Non-vacuity of the whole
  path: the e2e guest prints NOTHING on failure, so no marker could match —
  only the verdict channel can explain the green. Accepted deliberate
  divergence: before/after decision counts describe the reduced-knob trace,
  not the campaign's original recording — the designed knobs-first
  semantics. Acceptance battery now 34 s end-to-end measured. Arc status:
  outcome-channel §4.5 landed; all sections complete.
