# Arc: coverage / depth measurement for runs and campaigns

Status: Waves A-C implemented 2026-08-06 (native yield-point counters, reports,
`run`/`replay --coverage-out` covmaps, fail-closed detectors, offline `coverage`
symbolization/rollup, and campaign coverage accumulation/plateau); Waves D-E remain planned.
Lands as `docs/arcs/coverage-depth.md`.

Cross-references:
- **invariant-visibility arc** (`docs/arcs/invariant-visibility.md`): its crate → module →
  function hierarchy and `.patina/` tags/groups config are THE shared grouping mechanism.
  This arc designs ONE rollup module, used by both (§4).
- **resumable-campaign arc** (`docs/arcs/campaign-steering.md`): plateau detection and the
  persisted coverage state (§6, §8) are decision inputs for `campaign --extend`.

User-settled decisions this design works within (not relitigated): reuse the existing
`--yield-points` sancov trace-pc-guard instrumentation; both one-shot edge bits AND
cumulative per-site hit counters; report percentages + locations, never bare counts;
PC symbolization with hierarchical rollup; WASI depth = fuel + hostcall counts (honestly
labeled depth, not coverage); campaign summary + `patina.campaign/v2` envelope + plateau
in heartbeat; coverage-GUIDED scheduling is phase 2, scheduled as this arc's Wave E
(interface fixed in §8; implementation owned by this arc, not a future prompt).

---

## 1. Native mechanism: counter mechanics in `patina_yield.c`

**Pre-Wave-A baseline.** `crates/cargo-patina/c/patina_yield.c` received the full
guard range in `__sanitizer_cov_trace_pc_guard_init(start, stop)` and deliberately ignored
it; every guard hit called `patina_yield_point(__builtin_return_address(0))`
unconditionally. Wave A keeps that unconditional scheduling call and uses the same stable
`-C` codegen flag family (`passes=sancov-module`, `-sanitizer-coverage-level=3`,
`-sanitizer-coverage-trace-pc-guard`), adding only the parallel pc-table flag described
below. The hook object itself is still compiled WITHOUT sancov so it can never recurse.

**Decision C1 — counters live in the guard words themselves; the hook does one saturating
increment per hit.** The compiler already allocates one `uint32_t` per instrumented edge
(the `__sancov_guards` array `init` receives); using it as the hit counter needs zero
allocation, zero syscalls, and no new memory:

```c
void __sanitizer_cov_trace_pc_guard(uint32_t *guard) {
    uint32_t hits = *guard;
    if (hits != UINT32_MAX) *guard = hits + 1;   /* saturating; plain (non-atomic) store */
    patina_yield_point(__builtin_return_address(0));
}
```

- **Both settled counters in one word**: cumulative count = the u32 value; one-shot
  "seen" bit = value ≠ 0. No separate bitmap.
- **Non-atomic on purpose**: under the deterministic scheduler exactly one managed task
  runs at a time (the baton), so plain load/store is race-free AND deterministic. This is
  the same argument the rest of the shim already rests on.
- **Yield behavior is untouched**: `patina_yield_point` is still called unconditionally,
  before/after the increment is immaterial — the guard hit *sequence* is identical to
  today's, so recorded yield schedules are unchanged (§7).
- **Overhead**: one load + compare + add + store per basic block, on top of an existing
  call + `sched_point` (`patina-native-shim/src/lib.rs:4356-4389`, early-outs when the
  thread subsystem is inactive). Expected noise-level relative to existing `--yield-points`
  cost; wave A includes a MEASURED before/after on a testbed (policy: measured, never
  estimated).

**Decision C2 — `init` registers guard ranges (and PC-table ranges) with the shim.**
`__sanitizer_cov_trace_pc_guard_init` is called once per codegen unit; each call registers
its `[start, stop)` subrange through a new shim export
`patina_coverage_register(uint32_t *start, uint32_t *stop)` (defined in the
`patina-dst-native-shim` staticlib next to `patina_yield_point`,
`patina-native-shim/src/lib.rs:2937`). Total edge count = Σ(stop − start) — the settled
"percentages need the total" requirement. Plain builds never link the hook, so nothing
changes for them.

**Decision C3 — add `-sanitizer-coverage-pc-table` to `sancov_rustc_flags` so every guard
has a program counter and a function-entry flag.** The pc-table is link-time constant data
(pairs `(pc, flags)`, flag bit 1 = function entry), parallel to the guard array per module;
its `__sanitizer_cov_pcs_init(pcs_beg, pcs_end)` callback is registered by the same module
constructor that calls guard-init, so the hook pairs the k-th guard range with the k-th pcs
range at runtime — no offline section-order assumptions. It adds zero executed instructions
(the guest's instrumented code stream is identical), only data. Same LLVM `cl::opt`
stability coupling the existing two `llvm-args` already accept (`lib.rs:4495-4502`).
Function-entry flags give function-level coverage for free.

**ASLR handling — reuse the proven nm-delta scheme.** Runtime PCs (from the loaded pc-table)
are slide-corrupted for offline use; the shim already solves exactly this for yield-divergence
naming by reporting sites as deltas from its own `patina_yield_point` symbol
(`patina-native-shim/src/lib.rs:4333-4351`: "Symbolize by adding the delta to
`nm <binary> | grep patina_yield_point`"). The coverage dump encodes every site PC the same
way: `delta_i = pc_table[i] − &patina_yield_point`, stable across runs of one binary.
One anchor, one convention, already documented.

**Fail-closed invariant**: registered guard count must equal registered pc-table entry
count. Mismatch → loud refusal naming both counts (§10, D2). Zero registered ranges on a
run that requested coverage → loud error, never a silent empty report (§10, D1).

---

## 2. Where per-run stats are emitted

**Decision E1 — three surfaces, one per audience; the trace is NOT one of them.**

1. **`PATINA_COVERAGE_REPORT` stderr line** (numeric summary, always-on for yield-point
   binaries, suppressible via env `PATINA_COVERAGE_REPORT=0`) — emitted from
   `Context::finish` exactly where the other default-on diagnostics already live
   (`patina-runtime/src/lib.rs:3978-3991` emits `PATINA_SCHEDULE_REPORT` /
   `PATINA_SCHEDULE_POLICY` / `PATINA_NET_FAULT_REPORT`; env-gate pattern at
   `lib.rs:4834-4845`). Same vehicle ⇒ same determinism argument as the existing lines.
   Shape (percent as permille to keep the line locale/float-free):

   ```
   PATINA_COVERAGE_REPORT edges_total=48211 edges_covered=19204 covered_permille=398 hits_total=8123441 hits_max=90211 saturated=0
   ```

2. **Full counter map to a supervisor-owned descriptor**, only when requested:
   `run --coverage-out PATH` / `replay --coverage-out PATH` makes the supervisor create
   the file and pass it as an inherited descriptor via `PATINA_COVERAGE_FD` — the exact
   `PATINA_TRACE_FD` pattern
   (`cargo-patina/src/lib.rs:5805`, `patina-runtime/src/lib.rs:98`), written at finalize
   through host-alias writes (shim host-alias doctrine holds; no interposable symbol is
   called). Map format `patina.covmap/v1`: header (magic, version, guard count, range
   table), u32-LE counter array, i64-LE anchor-delta array (§1). ~12 bytes/edge; a 200k-edge
   binary dumps ~2.4 MB, folded and deleted by the campaign immediately (§6).
   Requesting `--coverage-out` for a non-instrumented binary is a loud usage error naming
   `cargo patina build --yield-points` (detection via the existing marker scan,
   `binary_has_yield_points`, `lib.rs:4935-4967`).

3. **The `patina.result/v1` run envelope** gains an additive `coverage` object (native yp:
   `{edges_total, edges_covered, covered_permille, map_path?}`) and `depth` object (WASI,
   §5). Additive fields need no schema bump — v1 already omits absent fields
   (`output.rs:24`, `output.rs:716-718`). `PATINA_COVERAGE_REPORT` / `PATINA_DEPTH_REPORT`
   join `MARKER_PREFIXES` (`output.rs:360-372`) so the lines also surface in `markers`.

**Why not RunMetadata / the trace**: the trace is the replay contract — schedule + effects
only (`RunMetadata`, `patina-trace/src/lib.rs:272`, records *configuration*, never
observations; `MAX_TRACE_BYTES` 256 MiB, `lib.rs:51`). Coverage is an observation *about* a
run; folding megabytes of observation into the contract bloats every trace and buys
nothing replay needs. (A compact `coverage_digest` in metadata as a record/replay
divergence cross-check is a genuine detection opportunity — deferred, see §11.)

---

## 3. Symbolization pipeline: offline post-pass, in `cargo-patina`

**Decision S1 — symbolization is always offline (parent/CLI side), never in the guest.**
The guest emits only counters + anchor deltas; `cargo-patina` resolves
`static_pc = nm_address(patina_yield_point) + delta`, maps PCs to symbols via the binary's
symbol table, and demangles with `rustc-demangle`. Cost lands at report time, zero at run
time. Function attribution: sort function-entry PCs (pc-table flag bit) and bucket every
edge to its enclosing function; function coverage = entered functions / total functions,
edge coverage within a function = covered edges / edges bucketed to it.

File:line detail (via the `addr2line`/`gimli` crates against debug info) is optional
wave-B polish — the crate → module → function rollup needs only symbol names, which
Rust mangling encodes. Dependency lands in `cargo-patina` only, never in the runtime.

---

## 4. Rollup: one shared grouping mechanism, progressive disclosure

**Decision R1 — one rollup module in `cargo-patina`, shared with the invariant-visibility
arc.** Input: a list of (symbol-path, weight) pairs. The module parses demangled paths into
the crate → module → function hierarchy and applies `.patina/` tags/groups overrides (the
invariant-visibility arc's config file is authoritative for the format; coverage adds no
second grouping syntax). Coverage feeds it (edges, hits); invariants feed it (sites,
violations). One tree, two consumers.

**Decision R2 — a read-only `cargo patina coverage <BINARY> <MAP|CAMPAIGN-OUT-DIR>` verb**
(registry + drift-gate enforced like every verb, per the CLI-ergonomics doctrine), rather
than dumping rollups inline into `run` output. Progressive disclosure:

- default: index first — one row per crate:
  `crate  edges_covered/edges_total  pct  hits_share  over_rep` where
  `over_rep = hits_share / edges_share` names concentration (>1 = hot, ≪1 = barely
  exercised);
- `--focus <crate::module::path>` drills one level down on demand; `--top N` lists the
  hottest / coldest functions;
- `--format json` emits a `patina.coverage/v1` envelope with the full tree — same content,
  machine medium (project principle: every surface consumable by humans AND agents).

For campaign stores, the verb validates the supplied binary against the artifact hash recorded
in `meta.json` before symbolization; a mismatched binary fails closed instead of producing a
plausible rollup over the wrong symbol table.

`run`/`replay --coverage-out` prints exactly one pointer line
(`PATINA_COVERAGE map=PATH edges=19204/48211 covered_permille=398`) and defers drill-down
to the verb — run output stays lean.

---

## 5. WASI family: depth proxies, honestly labeled

No sancov exists for the wasm target, so the WASI family gets **depth**, not edge coverage,
and every surface says "depth" so the two are never conflated.

- **`fuel_consumed`** already exists and is documented as a deterministic function of the
  executed instruction stream (`patina-wasi-host/src/lib.rs:1294-1300`,
  `1335-1343`) — but is dropped on the floor today: `execute_preview1_with_fuel` returns it
  and `finalize_inprocess` never sees it (`cargo-patina/src/lib.rs:3615-3639`,
  `output.rs:315-330`). Surfacing it is pure plumbing: add depth fields to
  `output::RunReport`.
- **Hostcall counts** (new): `Preview1Host` counts calls per imported function name
  (a `BTreeMap<&'static str, u64>` bumped in the `define_preview1` wrappers) — a
  deterministic function of the same instruction stream. `WasiExecution` gains an additive
  `hostcalls` field.
- Emission: `PATINA_DEPTH_REPORT family=wasi fuel_consumed=812344 hostcalls_total=904
  fd_write=311 clock_time_get=210 ...` on stderr (WASI runs in-process, so cargo-patina
  emits it directly), plus the envelope `depth` object.
- Fuel is NOT part of any fingerprint or trace hash and must stay that way (the wasmi
  1.x fuel-rounding note at `wasi-host/src/lib.rs:1335-1343` is exactly why: absolute fuel
  may shift across engine versions). Depth values are report-only.

Campaign plateau for WASI is correspondingly weaker (§6): "no new hostcall *kinds* and no
new fuel high-water mark" — stated as such in output (`depth_plateau`, never `plateau`).

---

## 6. Campaign integration: accumulation, persistence, plateau

Campaign already: derives everything from the generation hash (`campaign.rs:1076-1080`),
runs children with captured streams (`campaign.rs:891-970`), keeps class counts +
signatures (`campaign.rs:712-714`), heartbeats via `PATINA_CAMPAIGN_PROGRESS`
(`campaign.rs:1182-1198`), and emits the summary-first `patina.campaign/v2` envelope
(`campaign.rs:52`, `1236-1320`).

**Decision K1 — accumulation.** When the artifact is native and yield-instrumented
(`binary_has_yield_points`), campaign automatically passes
`--coverage-out <out>/coverage/gen-N.covmap` to each child, folds the map into an
in-memory union bitset + saturating u64 hit sums, records whether the generation added new
edges, then deletes the per-gen map (mirrors the transient per-gen trace,
`campaign.rs:800-804`). Anchor deltas are cached from the first map (identical across runs
of one binary). Non-instrumented native artifact: coverage is skipped and the summary says
so explicitly (`coverage=unavailable reason=not-instrumented hint=--yield-points`) — never
silently absent. WASI artifact: depth accumulation from the child's `PATINA_DEPTH_REPORT`
lines (already-captured stderr; no fd needed).

**Decision K2 — persistence in `--out-dir` (also the phase-2 interface, §8).**

```
<out>/coverage/meta.json    # schema patina.coverage.campaign/v1: artifact, fingerprint,
                            # edges_total, guard-range table, edges_covered,
                            # generations_applied (resume watermark, see below),
                            # last_new_edge_gen, plateau_window, plateaued,
                            # new_edge_log: [[gen, new_edges], ...]  (sparse — novelty gens only)
<out>/coverage/union.bits   # bit i = guard i ever hit (LE bit order)
<out>/coverage/hits.u64le   # cumulative per-site hit sums
<out>/coverage/sites.i64le  # anchor-delta per guard (from the first map; enables offline
                            # symbolization without re-running anything)
```

`meta.json` binds the state to the binary's compatibility fingerprint + edge count;
any later accumulation onto mismatched state (the `--extend` case) is refused up front,
naming both fingerprints — coverage bitsets from different binaries are meaningless to
union (§10, D3).

**Resume watermark.** `generations_applied` (u64) records how many generations the arrays
reflect, updated atomically with them at each checkpoint. It exists because the folds are
not uniformly idempotent: `union.bits` is (set union), but `hits.u64le` saturating ADDS
are not — the campaign-steering arc's crash model allows an at-most-one-generation tear
where resume re-runs the interrupted generation N, and re-applying N would double-count
hits. Rule (matching that arc's per-aux-file contract): on resume, a generation already
covered by the watermark contributes nothing to the fold; both sides are deterministic,
so skip-vs-apply produce identical state. §10 D4a RED-proves the skip.

**Decision K3 — plateau: exact rule.** Let `last_new_edge_gen` = the highest generation
index whose fold turned ≥ 1 guard from unseen to seen (initialized to 0 by the first
generation, which trivially adds edges). With plateau window `N`
(`--plateau-after N`, default **200**, `0` disables): after generation `g`, the campaign is
**plateaued iff `g − last_new_edge_gen ≥ N`**. Purely a function of the deterministic sweep,
so re-runs reproduce it. Phase 1 only *reports* plateau — it never stops the campaign;
acting on it (auto-stop, `--extend` guidance) is the resumable-campaign arc's decision.

**Surfacing.** Heartbeat line gains coverage fields (wall-clock-free, so the deterministic
`PATINA_CAMPAIGN_GEN` lines are untouched):

```
PATINA_CAMPAIGN_PROGRESS generation=800/2500 elapsed_secs=412 failures=3 novel=2 OK=771 ... coverage=19204/48211 covered_permille=398 last_new_edge_gen=641 plateau=0
```

Final summary adds a native-edge coverage block (covered %, `last_new_edge_gen`, plateaued yes/no, top
uncovered crates by edge share — locations, not bare counts); `PATINA_CAMPAIGN_COMPLETE`
gains `covered_permille=… plateaued=…` when edge coverage is available. The v2 envelope
preserves the existing SDK-site `coverage` object and adds native edge coverage under
`coverage.edge`, plus `artifacts.coverage_dir`; WASI depth later adds a separate `depth`
object. This is additive, so the schema stays `patina.campaign/v2` (absent-field discipline
is already the envelope's convention, `campaign.rs:1284-1303`).

---

## 7. Determinism constraints and build-mode question

- **Counting cannot perturb execution**: writes go only to pre-existing guard words never
  read by guest code; the hook still yields unconditionally; single-owner execution (the
  baton) makes plain stores race-free. Guard-hit sequence, recorded ops, and fingerprints
  are bit-identical to today's `+yieldpoints` builds — asserted by wave-A tests
  (same-seed double-run map byte-identity AND record→replay map byte-identity).
- **Fingerprint**: unchanged. The native base fingerprint is caller-supplied
  (`DEFAULT_NATIVE_FINGERPRINT`, `lib.rs:2953`) and the policy suffix stays
  `+yieldpoints` (`lib.rs:86`, `4972-4978`). Coverage requires a rebuilt hook object
  (content-addressed restage is automatic, `lib.rs:4402-4429`) and pc-table adds data-only
  sections; neither changes the yield sequence, so even pre-existing yp traces remain
  replayable against a same-source rebuild to exactly the degree they are today.
- **Decision B1 — no coverage-only build mode (guards on, yields off).** It would double
  the schedule-policy fingerprint matrix for no current user: single-threaded guests
  already pay ~nothing for yields (`sched_point` early-outs while the thread subsystem is
  inactive, `native-shim/src/lib.rs:4371-4377`), and multi-threaded coverage consumers are
  campaigns that want schedule exploration anyway. Coverage rides `+yieldpoints`, full
  stop. Revisit only with a measured need (no-cruft doctrine).

---

## 8. Phase-2 interface boundary (coverage-GUIDED scheduling — implemented as Wave E)

Phase 1 persists everything phase 2 needs and nothing more:

- `union.bits` + `hits.u64le` + `sites.i64le` + `meta.json` (§6 K2) — the coverage state a
  guided scheduler would seed from, fingerprint-bound so stale state can never silently
  steer a different binary;
- `new_edge_log` — which generations were novel, the signal a scheduler would optimize;
- the per-run `--coverage-out` map — the feedback channel a guided loop would read per
  candidate.

Explicitly out of phase 1: any influence of coverage on seed/knob derivation (generation
derivation stays the pure `SHA-256("patina-campaign-<seed_base>-<gen>")`,
`campaign.rs:1076-1080`), any in-guest novelty computation, and any scheduler API. The only
phase-1 commitment phase 2 inherits is the `patina.covmap/v1` / `patina.coverage.campaign/v1`
formats.

---

## 9. Staged implementation plan

**Wave A — native counters + dump + report (runtime/shim/build-recipe touching → FULL
battery) — implemented 2026-08-06.** Hook increment + range registration
(`patina_yield.c`), pc-table flag, `patina_coverage_register` + finalize-time
report/dump in shim+runtime, `PATINA_COVERAGE_FD` supervisor plumbing,
`run`/`replay --coverage-out` (registry rows), additive run-envelope coverage
summary, requested-but-empty and count-mismatch refusals.
*Verify*: `mise run check` (the ladder INCLUDES the three validation scripts —
`scripts/validate-wasi.sh`, `scripts/smoke-cross-target.sh`,
`scripts/validate-native-shim.sh`; `mise.toml:30-43`), TWO e2e runs in the battery log,
yp-fixture record/replay + same-seed map byte-identity at ≥ 2 seeds, MEASURED
before/after overhead on a threaded testbed, Linux gate battery (runtime-touching).

**Wave B — offline symbolization + rollup + `coverage` verb (CLI-only) — implemented 2026-08-06.** nm-anchor
resolution, symbol bucketing + demangle, shared rollup module, verb + `--format json` envelope,
and llms.txt/TUTORIAL rows for the symbolized coverage workflow.
*Verify*: `mise run check` (drift gate `scripts/check-flag-drift.sh` covers the registry);
no shim battery beyond the ladder — runtime untouched.

**Wave C — campaign accumulation + plateau — implemented 2026-08-06.** Fold/union/persist, plateau rule, heartbeat +
summary + envelope fields, `campaign --plateau-after`, selftest classes (§10 D3-D5),
deterministic re-run test extended to cover coverage state byte-identity.
*Verify*: `mise run check` + campaign `--selftest` + a real ≥ 50-gen yp campaign smoke
asserting monotone union growth and a correct plateau line.

**Wave D — WASI depth (wasi-host touching → full battery with `validate-wasi.sh`
emphasized).** Hostcall counters in `Preview1Host`, `WasiExecution.hostcalls`, fuel/depth
plumbing through `RunReport`, `PATINA_DEPTH_REPORT`, campaign depth accumulation +
`depth_plateau`.
*Verify*: `mise run check`, both e2e runs, plus a WASI campaign smoke.

**Wave E — coverage-GUIDED generation scheduling (phase 2, scheduled here — not a
separate future arc).** Owned by this arc per user directive (2026-07-30: phase-2 items
are tackled as part of their arcs, never parked for a later prompt). Builds strictly on
the §8 interface: a campaign mode that biases knob/seed selection toward novelty using
`new_edge_log` + `union.bits`, designed and RED-proven in its own right when waves A–C
have real coverage data to steer on. Determinism constraint carried forward: guided
selection must remain a pure function of (seed, persisted coverage state), so an
extended guided campaign stays reproducible.

Waves are separable and land independently; A must precede B/C; D is independent of B/C;
E follows C.

---

## 10. Detection notes — every new diagnostic RED-provable (project doctrine)

- **D1 `requested-coverage-unavailable`** (loud error): `--coverage-out` against a plain
  binary (marker scan) OR a marker-carrying binary that registered zero guard ranges.
  RED: fixture hook with a neutered `init` → the run must refuse, not print an empty
  report.
- **D2 guard/pc-table count mismatch** (loud refusal naming both counts): RED unit fixture
  with a truncated range registration.
- **D3 coverage-state fingerprint mismatch on accumulate/extend** (up-front refusal naming
  both fingerprints): RED unit fixture with an edited `meta.json`.
- **D4 plateau rule exactness**: unit fixtures with synthetic per-gen novelty sequences
  prove plateau fires at exactly `g − last_new_edge_gen = N` and NOT at `N − 1`, and that
  `--plateau-after 0` never fires.
- **D4a resume-watermark idempotency**: a unit fixture folds generation N twice against a
  state whose `generations_applied` already covers N — hit sums must be identical to the
  single-fold state (RED: removing the watermark skip double-counts `hits.u64le`).
- **D5 counting correctness (positive + mutation)**: a fixture whose guest argv selects a
  branch — the branch's function appears in the rollup only when taken, union grows
  across the two runs; the counting-skipped mutation drives `edges_covered` to 0, which
  D1's zero-coverage arm and the positive assertion both catch. Saturation is a unit test.
- **D6 determinism**: same-seed double run and record→replay each produce byte-identical
  covmaps (doubles as the future divergence-detector baseline, §11).

---

## 11. Honest limits

- **Edge ≠ path**: sancov level 3 counts basic-block/edge hits; path- and
  interleaving-space coverage remain unmeasured (schedule diversity is separately visible
  via `PATINA_SCHEDULE_REPORT total_boundaries`, `patina-runtime/src/lib.rs:4846-4852`).
- **Only guest CGUs are instrumented**: std/libc and the shim itself are invisible;
  "100 % covered" means 100 % of *instrumented* edges. Reports always carry the total to
  keep this honest.
- **WASI depth is not coverage** and is labeled `depth` everywhere; its plateau signal is
  weak (hostcall kinds + fuel high-water) and named `depth_plateau`.
- **u32 per-site saturation** at ~4.3 G hits/site (reported via `saturated=`); union/sums
  saturate in u64 campaign-side.
- **Counter values during post-`main` teardown**: guards in TLS destructors still increment
  after the dump point is armed; the dump happens at trace-finalize (the same fixed point
  as the other reports), so maps are deterministic — but "coverage" includes teardown-code
  execution on platforms where destructors run (documented, not hidden).
- **`coverage_digest` in trace metadata** (record/replay coverage cross-check — would catch
  code-path divergence that touches no boundary op, a currently invisible class) is
  deliberately deferred: it changes trace bytes and needs its own RED-proof and
  teardown-window analysis. Noted as a candidate follow-up, not smuggled into wave A.
- **LLVM coupling**: pc-table rides the same non-guaranteed-but-stable LLVM `cl::opt`
  surface as the existing sancov flags (`lib.rs:4495-4502`) — one shared risk, no new class.
- Cross-references to the invariant-visibility and resumable-campaign arcs assume those
  docs land; the shared rollup config format is theirs to fix, this arc consumes it.
