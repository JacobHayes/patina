# Campaign steering: resumable + extendable campaigns

Status: design approved 2026-07-30; Stages 1+2 implemented in the current
campaign-steering arc; Stage 3 remains a later wave. Lands as
`docs/arcs/campaign-steering.md`.

## 1. Problem and settled decision

A multi-thousand-generation campaign is a bet placed up front: today the only
way to "keep pushing" after `--gens 500` finishes clean is to restart from
scratch with `--gens 1000` (re-running the 500 you already paid for), and the
only way to "cut losses" mid-flight is Ctrl-C — which currently **loses the
signature store entirely**, because `signatures.json` is written only at
campaign end (`campaign.rs:847-849`).

**User-settled decision: resumable + extendable campaigns.** Campaign state
persists in `--out-dir`; `cargo patina campaign --extend N` continues an
existing out-dir with N more generations, recomputing nothing. The human or
agent reads the `PATINA_CAMPAIGN_PROGRESS` heartbeats (and, later, the
coverage-depth stats) and decides whether to continue; the machinery makes
"continue" cheap and deterministic. Explicitly **not** chosen: a live control
channel into a running campaign, and plateau auto-stop. (Auto-stop may be a
later layer on top of this state — see §10.)

## 2. What exists today (verified)

All references are to `crates/cargo-patina/src/campaign.rs` at the current
head.

- **Spec.** `CampaignSpec` (`:71-94`) is the complete determinism-relevant
  configuration: `generations`, `seed_base`, `timeout_secs`, `guest_args`, and
  the knob switches (`buggify`, `swarm`, `pct`, `faults`, `watchdog_nanos`,
  `converge_nanos`, `heal_after_nanos`, `report`). It is populated from flags
  and/or a `--spec FILE.json` (key names at `:124-147`). **Nothing about the
  spec is persisted to the out-dir today** — there is no `spec.json`; an
  out-dir cannot answer "what campaign produced you".
- **Seed/knob derivation is a pure function of the generation number.**
  `generation_hash(seed_base, generation)` =
  `SHA-256("patina-campaign-<seed_base>-<generation>")` (`:1076-1080`); the
  seed is bytes 0..8 and every randomized knob reads fixed hash bytes
  (`derive_flags`, `:1020-1072`). No cross-generation state feeds derivation.
- **Signature store.** An in-memory `BTreeMap<String, SignatureRecord>`
  (`:713`), deduped by `class|shape|policy` key; novelty = first insertion
  (`:782-798`). Serialized once, at the end, as `signatures.json`
  (`patina.campaign.signatures/v1`, `:1160-1176`). There is a writer but **no
  loader** — `SignatureRecord` has `to_json` only (`:642-661`).
- **Out-dir contents.** `traces/` (per-generation scratch, deleted after each
  generation, `:804`), `failures/generation-<N>.patina` (valid failing traces,
  `:1112-1124`), `reports/generation-<N>.html` (with `--report`), and
  `signatures.json`. Nothing else.
- **Artifact identity.** `run_campaign` resolves the artifact and reads its
  bytes for family sniffing (`artifact_family`, `:1150-1158`) but records no
  hash anywhere. (The build-on-run path already prints a content `sha256` —
  `lib.rs:3961-3970` — so content-hashing has precedent and the bytes are
  already in hand.)
- **Outputs.** Human mode: `PATINA_CAMPAIGN_START`, wall-clock-free
  `PATINA_CAMPAIGN_GEN` lines for novel/failing generations,
  `PATINA_CAMPAIGN_PROGRESS` heartbeat every `--progress-every` generations
  (wall clock appears *only* here, `:1178-1198`), and a cumulative summary.
  JSON mode: the summary-first `patina.campaign/v2` envelope
  (`classes`/`signatures`/`notable_runs`/`artifacts`, `:1244-1320`).
- **Determinism proof.** The e2e test re-runs the same spec into a second
  out-dir and asserts byte-identical `PATINA_CAMPAIGN_GEN` streams and
  `signatures.json` (`tests/end_to_end.rs:2507-2531`).

### The key consequence

Because generation → (seed, knobs) is pure, **extension needs no seed cursor,
no RNG state, and no recomputation**. The only cursor is *how many generations
have already run*. Everything else the extension must carry forward is
accumulated *output* (signature store, class histogram, notable runs), not
derivation state. That is what makes the headline invariant in §5 achievable
exactly.

## 3. Decision 1 — CLI shape: out-dir-authoritative, fail-closed

```
cargo patina campaign --extend N [--out-dir DIR]     # raise the target by N and run to it
cargo patina campaign --resume  [--out-dir DIR]      # finish an interrupted campaign to its recorded target
```

- **The out-dir is the campaign's identity.** `--extend`/`--resume` take no
  artifact positional: the artifact path and content hash come from the
  recorded state (§4) and are re-verified (§8). `--out-dir` defaults to
  `patina-campaign-out` exactly as today, so `cargo patina campaign --extend
  500` alone continues the default out-dir.
- **The spec comes FROM the out-dir. Re-supplied knobs are rejected loudly.**
  Supplying an artifact positional, `--gens`, `--seed-start`, `--spec`,
  `--buggify`, `--swarm`, `--sched-pct`, `--faults`, `--liveness-watchdog`,
  `--converge-within`, `--heal-after`, `--report`, or a `-- GUEST_ARGS` tail
  alongside `--extend`/`--resume` is a usage error naming the flag and the
  doctrine ("the out-dir's recorded spec is authoritative; start a new out-dir
  to change the spec"). This mirrors replay's trace-authoritative model
  (`lib.rs:1690-1696`: "fault knobs are never accepted here … replay is
  flag-free"). Rationale for rejecting rather than allowing overrides: a
  mid-stream knob change silently forks the campaign's meaning — the signature
  store and class histogram would mix incomparable populations, and the §5
  equality invariant (the class detector for extension bugs) would be
  unstatable. Fail-closed is also the cheaper thing to relax later; the
  reverse migration (users depending on silent overrides) is not removable.
- **Host-side flags remain accepted**, because they are not part of the swept
  configuration's meaning: `--progress-every` (presentation only, already
  excluded from `CampaignSpec` for exactly this reason, `:179-182`) and
  `--timeout-secs` (a wall-clock harness backstop, the campaign analog of
  replay's re-suppliable host inputs; a slower machine legitimately needs a
  larger backstop to complete the *same* deterministic generations). If
  `--timeout-secs` is not re-supplied, the recorded value applies. The
  effective value is recorded per invocation in the audit log (§6), and its
  interaction with the equality invariant is called out honestly in §5.
- **`--extend N` implies resume**: if the campaign was interrupted at 300/500,
  `--extend 500` sets the target to 1000 and continues from generation 300.
  `--resume` on an already-complete campaign is a loud error ("campaign
  complete at 1000/1000; use --extend N to continue"), not a silent no-op —
  an agent that meant to add work finds out immediately. `--extend 0` and
  `--extend` + `--resume` together are usage errors (redundant spellings are
  rejected, not aliased — no-cruft doctrine).
- **A fresh campaign refuses an occupied out-dir.** Today a bare re-run into
  an existing out-dir silently clobbers `signatures.json` and interleaves new
  `failures/` files with stale ones. Once state exists, that becomes an
  accidental-identity-destruction hazard, so: a non-extend campaign whose
  out-dir already contains `campaign-state.json` fails closed, telling the
  user to `--extend`, `--resume`, pick a new dir, or delete the old one.
- Both new flags are registered in the `help.rs` flag registry so the arity
  drift gate and `--help` stay true (the registry + drift gate is enforced
  repo policy).

Rejected alternative spellings: a `campaign extend` sub-verb (the CLI is
verb-first with one level; `explore`/`minimize` set the precedent that modes
of a verb are flags), and making the positional the out-dir in extend mode
(the campaign positional means "artifact" everywhere else; overloading it is
exactly the confusion the verb-first migration removed).

## 4. Decision 2 — persisted state: `campaign-state.json`, checkpointed per generation

Every campaign (not opt-in) maintains `<out-dir>/campaign-state.json`:

```json
{
  "schema": "patina.campaign.state/v1",
  "artifact": {
    "path": "testbeds/workq/target/.../workq",
    "sha256": "ab12…",
    "family": "native"
  },
  "spec": {
    "generations": 1000,
    "seed_base": 0,
    "timeout_secs": 60,
    "guest_args": [],
    "buggify": true,
    "faults": true,
    "swarm": false,
    "pct": false,
    "report": false,
    "watchdog_nanos": 600000000000
  },
  "generations_done": 650,
  "classes": { "OK": 640, "LIVENESS": 10 },
  "signatures": [ { …exact signatures.json record shape… } ],
  "notable_runs": [ { …exact envelope notable_runs record shape… } ],
  "invocations": [
    { "cli": "campaign workq --gens 500 …", "from_gen": 0,   "gens_run": 500, "timeout_secs": 60, "elapsed_secs": 812 },
    { "cli": "campaign --extend 500",       "from_gen": 500, "gens_run": 150, "timeout_secs": 60, "elapsed_secs": 240 }
  ]
}
```

Decisions inside the format:

- **What belongs vs. what is derived.** `spec` is the *target* configuration
  (`generations` = current cumulative target; `--extend N` rewrites it to
  `target + N`), serialized with **exactly the `--spec` JSON key names**
  (`apply_json`, `:124-147`) so the `spec` block is itself a valid `--spec`
  file — one canonical dialect, agent-inspectable and reusable, no drift
  surface. `generations_done` is the sole cursor (§2). `classes`,
  `signatures`, and `notable_runs` are accumulated *outputs* that cannot be
  re-derived without re-running, persisted in exactly the shapes the
  signature store and v2 envelope already use — the cumulative envelope on
  extension is then concatenation, not translation. Deliberately *not*
  stored: per-generation seeds/flags tables (pure functions of the spec —
  storing them creates a divergence surface), failure/novel counts
  (derivable: `failures = Σ non-OK classes`, `novel = signatures.len()`).
- **`campaign-state.json` is the single source of truth on resume;
  `signatures.json` becomes a derived view.** Both are rewritten at each
  checkpoint, but resume loads only the state file. This removes the
  two-file-atomicity problem (a crash between the two writes can never
  produce a divergent resume; the derived view is simply regenerated at the
  next checkpoint). `signatures.json` keeps its existing schema and remains
  the documented human/agent entry point.
- **Checkpoint cadence: after every generation, atomically** (write
  `campaign-state.json.tmp`, rename over). One small-file write per
  generation is noise next to spawning a child `cargo patina run` process,
  and it is what makes "resumable" true: Ctrl-C or a crash loses at most the
  in-flight generation, which simply re-runs on resume — a pure function of
  its generation number, so re-running it is idempotent by construction
  (its `failures/generation-<N>.patina` copy, if any, is overwritten with
  identical bytes). This also fixes the standing sharp edge that Ctrl-C on a
  5000-generation campaign currently writes nothing at all.
- **Global generation numbering.** An extension of 500+500 runs generations
  500..999: seeds continue the pure sequence, and `traces/`, `failures/`,
  `reports/` filenames (`generation-<N>.…`) never collide across segments.
- **`invocations` is an audit log, not state.** It is the only place
  wall-clock (`elapsed_secs`) or CLI-history data appears, and it is
  explicitly excluded from the §5 equality surface — the same discipline as
  the heartbeat being the only wall-clock line in the stream.
- **Version tag, fail-closed.** `schema` is checked exactly on load; an
  unrecognized tag refuses with "this out-dir was written by a different
  cargo-patina version; finish it with that version or start a new out-dir".
  No silent migration machinery in v1 (no-cruft doctrine; migration is a
  decision for whichever change bumps the tag).
- **Loading requires a lossless store round-trip.** `SignatureRecord` (and
  `CampaignClass`) gain parsers; a state file that fails to round-trip
  (unknown class string, malformed record) refuses loudly rather than
  resuming with a partial store — a partial store silently re-flags known
  bugs as NOVEL, which is precisely the corruption class the equality test
  in §5 detects.

## 5. Decision 3 — the headline invariant: split-anywhere equality

> **For any split 0 < k < n, running `--gens k` and then `--extend (n-k)`
> produces the same campaign as a fresh `--gens n`:** the concatenated
> `PATINA_CAMPAIGN_GEN` streams are byte-identical, `signatures.json` is
> byte-identical, and `campaign-state.json` and the final JSON envelope are
> byte-identical after deleting the `invocations` audit field.

This is achievable *exactly* (not approximately) because derivation is pure
(§2) and every accumulated structure is an order-preserving fold over the
generation sequence that the state file carries losslessly. Novelty semantics
hold across the split by construction: the store is loaded before generation
k runs, so "novel" means "never seen in this out-dir's history", identically
to the fresh run.

Honest caveats, stated rather than hidden:

- The invariant inherits the same wall-clock boundary the existing
  deterministic-re-run test lives with: a generation that hits the
  `--timeout-secs` backstop is classified from a wall-clock event
  (`:742-750`), so equality holds on the (normal) executions where no
  generation times out. This is not weakened by extension — it is the
  pre-existing boundary of campaign determinism, and re-supplying a larger
  `--timeout-secs` on extend can only *remove* timeout nondeterminism, never
  add divergence to non-timed-out generations.
- Equality is over the deterministic surfaces listed above. Heartbeat lines
  (`elapsed_secs`) and the `invocations` audit field are wall-clock by
  design and excluded, exactly as heartbeats are excluded today.

### The equality test is the class detector (detection-before-fixes)

Extension bugs — a reset or off-by-one cursor, a forgotten store load, a
segment-local generation index leaking into seeds or filenames, histogram
double-counting — all collapse into divergence on this one invariant, so the
e2e test *is* the standalone detector for the class:

```
e2e: campaign_extension_equals_fresh_campaign
  build the liveness-campaign planted-bug guest once (existing fixture)
  A: campaign --gens 12 --progress-every 1 --buggify --liveness-watchdog … --out-dir a
  B: campaign --gens 5  (same flags)        --out-dir b        # split INSIDE the failing region
     campaign --extend 7 --out-dir b
  assert gen_lines(A) == gen_lines(B₁) + gen_lines(B₂)          # seeds, classes, NOVEL tags
  assert a/signatures.json == b/signatures.json (bytes)
  assert envelope(A) == envelope(B₂) after deleting "invocations"
  assert exactly one NOVEL across B₁+B₂ (novelty survives the split)
```

**RED proofs required before the test is trusted** (each a deliberate
one-line break, shown to fail, then reverted):

1. *Broken cursor:* make the extension loop iterate `0..n_new` (segment-local
   index) instead of `done..target` — segment 2 repeats segment 1's seeds;
   the gen-line assertion diverges immediately.
2. *Forgotten store load:* skip loading `signatures` from state — the planted
   bug is re-flagged NOVEL in segment 2; the exactly-one-NOVEL and
   byte-identical-store assertions fail.

Negative-path tests (pure parse tests where possible): re-supplied spec flag
rejected with the doctrine message; artifact-hash mismatch refused (§8);
`--extend` on a missing/pre-steering out-dir refused; unknown `schema`
refused; fresh campaign into an occupied out-dir refused; `--resume` on a
complete campaign refused; second concurrent invocation refused (§7). Plus
unit tests: state serialize→load→serialize is byte-stable (round-trip
losslessness), and `--extend` arithmetic on `spec.generations`.

An interruption-resume e2e (kill mid-campaign, `--resume`, assert the same
equality surface) is a cheap third leg reusing the same detector.

## 6. Decision 4 — envelope and summary semantics: cumulative, additive

- **Cumulative everywhere.** An extension's summary, heartbeat counters, and
  envelope describe the whole out-dir, not the segment: heartbeats read
  `generation=650/1000` with `failures=`/`novel=` seeded from loaded state
  (the human deciding "keep pushing?" needs whole-campaign numbers), and the
  exit code is 1 if the *cumulative* campaign has failures — an extension
  whose new segment is clean does not launder a failing campaign into exit 0.
- **The envelope stays `patina.campaign/v2` with one additive field:**
  `invocations` (the audit array from the state file). `classes`,
  `signatures`, `notable_runs`, `generations`, `failures`,
  `novel_signatures` keep their exact meanings, now spanning the full
  out-dir — an existing v2 consumer reads an extended campaign correctly
  with no code change, which is what the v1→v2 precedent implies a bump is
  *not* for (v2 existed because `runs` was reshaped away). `artifacts` gains
  `"campaign_state": <path>` so agents can find the state file without
  knowing the convention.
- **Start line on continuation:** instead of `PATINA_CAMPAIGN_START`, an
  extension prints
  `PATINA_CAMPAIGN_RESUME out=<dir> done=<k> target=<n> artifact=<path> sha256=<h>`
  — wall-clock-free, machine-parseable, and an explicit record in the stream
  that this segment continued (progressive disclosure: the stream alone
  tells an agent what happened).

## 7. Decision 5 — concurrent extension: refuse via flock

The invocation takes an exclusive advisory `flock` on
`<out-dir>/campaign.lock` (LOCK_EX | LOCK_NB) for its whole duration — fresh
campaigns too, since a fresh run and an extension racing is the same hazard.
A second invocation fails immediately: "another campaign is writing this
out-dir". `flock` releases on process death, so a crashed campaign leaves no
stale lock to clean (a PID-file scheme would). No queueing, no lock-steal
flag: concurrent writers to one campaign identity have no coherent meaning,
and refusal is the entire feature. (macOS and Linux both support `flock`;
the two supported hosts.)

## 8. Decision 6 — failure modes and artifact identity

Campaign records the artifact's content `sha256` at first run (bytes are
already read for family sniffing, `:1150`; hashing precedent at
`lib.rs:3961`). On `--extend`/`--resume` the recorded path is re-read and
re-hashed; any mismatch refuses:

```
campaign out-dir records artifact sha256 ab12… but testbeds/…/workq now hashes cd34…;
the artifact changed since this campaign started. Signatures from different builds
are not comparable — start a new out-dir for the new build.
```

This is the campaign analog of replay's fingerprint fail-close, and it is a
*stronger* check than the runtime fingerprint (content hash catches any
rebuild, including behavior-identical ones — the right bias, because the
signature store's meaning is per-build; a rebuilt-but-byte-identical artifact
passes, which is also right). No `--allow-artifact-mismatch` hatch in v1:
the escape is a new out-dir, which is cheap and honest.

Full refusal table (every one loud, none silently "best-effort"):

| Condition | Behavior |
|---|---|
| `--extend`/`--resume`, no `campaign-state.json` (missing dir, or pre-steering out-dir that has only `signatures.json`) | refuse: nothing recorded to continue; name the dir |
| `schema` tag unrecognized | refuse: version mismatch (§4) |
| state fails lossless round-trip (unknown class, malformed record) | refuse: corrupt state, do not resume partially |
| recorded artifact path missing / hash mismatch | refuse as above |
| spec-affecting flag or artifact positional re-supplied | usage error, doctrine message (§3) |
| fresh campaign into an out-dir containing state | refuse (§3) |
| second concurrent invocation | flock refusal (§7) |
| `--resume` with `generations_done == target` | refuse: complete; suggests `--extend` |
| auxiliary state file watermark ahead of/behind cursor beyond the one-generation tear (§9) | refuse: inconsistent out-dir |
| auxiliary state identity mismatch (coverage `meta.json` fingerprint / `edges_total` vs artifact, §9.4) | refuse up front, naming both |

## 9. Decision 7 — slots for coverage-depth and sometimes-gate state

The coverage-depth arc (cumulative coverage bitset + depth stats) and the
sometimes-gate arc (`sometimes!` reach tallies) persist per-out-dir
accumulative state that `--extend` must resume seamlessly — they are the
*point* of steering (the plateau curve a human reads before deciding). This
design does not inline their data into `campaign-state.json`; it defines the
contract any resumable campaign state file must meet, and reserves their
slots:

1. **Stable name in the out-dir, schema-tagged.** Both slots are settled by
   their owning arcs:
   - Sometimes-gate (docs/arcs/sometimes-gate.md): `<out-dir>/sites.json`,
     schema `patina.campaign.sites/v1`, written alongside
     `signatures.json` — top-level `generations_observed` plus per-label
     {kind, registered_gens, satisfied_gens, evals, fires,
     first_registered_gen, first_satisfied_gen, first_satisfied_seed}.
   - Coverage-depth (docs/arcs/coverage-depth.md §6 K2 / §8):
     `<out-dir>/coverage/` — `meta.json` (schema
     `patina.coverage.campaign/v1`; artifact path, compatibility
     fingerprint, edges_total + guard-range table, edges_covered,
     last_new_edge_gen, plateau fields, sparse new_edge_log; WASI depth
     state folds in here too) plus raw `union.bits`, `hits.u64le`,
     `sites.i64le`.
   Naming resolved (coordinator, 2026-07-30): the per-label SDK store is
   `sites.json` (`patina.campaign.sites/v1`, unified with the
   invariant-visibility arc's exercised view), so the edge-coverage
   `coverage/` directory no longer has a confusable sibling.
2. **Atomic checkpoint at the same per-generation cadence** (tmp + rename),
   after applying the generation's contribution.
3. **A generations watermark inside the file.** `sites.json`'s
   `generations_observed` is exactly this. Resume rule: when re-running the
   interrupted generation N (the at-most-one-generation tear from §4), a
   file whose watermark already covers N **skips re-applying** N's
   contribution. Both sides are deterministic, so skip-vs-apply agree; this
   makes the non-idempotent count fields (`evals`/`fires`/`*_gens` sums,
   and coverage's saturating `hits.u64le` adds — a re-run would
   double-count) exactly correct, and the idempotent folds (min `first_*`,
   `union.bits` set union) trivially so. Coverage-depth has adopted this:
   its `meta.json` carries a `generations_applied` u64, updated atomically
   with the arrays at each checkpoint, with the skip rule spelled out in
   its §6 K2 and a dedicated RED-proof detector (its D4a: folding a
   watermark-covered generation twice must equal the single fold). A
   watermark that disagrees with the campaign cursor by more than the
   one-generation tear is an inconsistent out-dir: refuse (§8).
4. **Load-or-fail-closed on resume, including identity fields.**
   Present-but-unreadable refuses. Absence is consistent by construction:
   the spec is frozen (§3), so a feature enabled in segment 1 is enabled in
   every segment — a spec-enabled feature whose file is missing refuses.
   An aux file may additionally declare identity fields the extension
   pre-flight must re-verify before accumulating onto it: coverage-depth's
   hard contract (its detector D3) is that `meta.json`'s compatibility
   fingerprint + `edges_total` must match the artifact or the extend
   refuses up front naming both — a rebuilt binary's bitset is meaningless
   to union. This slots alongside the §8 artifact-sha256 check.
5. **Order-independent or sequence-fold semantics must be declared** in the
   owning arc, because the §5 equality invariant extends to these files.
   Both arcs have declared theirs: sometimes-gate's fold is associative
   (pure per-label sums + min-folds keyed by generation number), and its
   threshold waiver deliberately compares against `generations_observed`
   rather than the spec's target, so it stays correct under extension;
   coverage-depth's `union.bits`/`hits.u64le` are pure commutative folds,
   and its plateau fields (`last_new_edge_gen`, `new_edge_log`) are
   order-dependent but well-defined sequence folds over the indexed,
   deterministic generation sequence — `--extend` continues the fold at
   index N and reproduces identical state. Split-anywhere byte-equality of
   `sites.json` and the `coverage/` files joins the class-detector test
   the moment those arcs land.

`campaign-state.json` stays ignorant of their contents; the extension
machinery treats "resumable state files" uniformly through this contract.

## 10. Future notes (explicitly out of scope)

- **Plateau auto-stop** would be a thin later layer *reading* this state
  (novel-signature rate, coverage-growth curve across `invocations`) and
  deciding not to extend — the state file is designed so that layer needs no
  new persistence. Not chosen now.
- **Live control channel** into a running campaign: not chosen; heartbeats +
  cheap extension replace it (Ctrl-C is now a safe "pause", losing at most
  one generation).
- Cross-build campaign continuation (carrying a signature store across an
  artifact rebuild) is deliberately refused in v1 (§8); if wanted later it
  is a corpus-migration feature, not an extension feature.

## 11. Staged plan and verification tier

**Stage 1 — persist (behavior-neutral for outcomes).** Every campaign writes
`campaign-state.json` per-generation (atomic), takes the flock, records the
artifact hash; `signatures.json` becomes the derived view, rewritten at the
same cadence. Gates: state round-trip unit tests; existing campaign e2e +
deterministic-re-run test stay green (they must — outcomes are untouched);
new e2e assertion that an interrupted campaign leaves a loadable state file.

**Stage 2 — continue.** `--extend`/`--resume` parsing + registry rows,
out-dir-authoritative loading, global numbering, cumulative
summary/heartbeat/envelope (+`invocations`, `campaign_state` pointer),
`PATINA_CAMPAIGN_RESUME`, all §8 refusals. Gates: the §5 equality e2e —
**RED-proved via both planted breaks, then green** — plus the
interruption-resume leg and the negative-path battery.

**Stage 3 — aux-state contract.** The watermark/skip resume rule as a small
shared helper, consumed by the coverage-depth and sometimes-gate arcs when
they land their files; the equality test grows their byte-equality
assertions then.

**Verification tier: CLI-only** — `cargo test -p cargo-patina` (unit + the
campaign e2e battery) plus `cargo patina campaign --selftest`. Justification
per the tiered-verification policy: every change is in `cargo-patina`
harness orchestration; no runtime, shim, interposer, or trace-format
surface is touched, so the full shim/runtime battery and Linux gates add no
signal for this arc. The moment stage 3 touches a runtime-emitting surface
(it shouldn't — it consumes child stdout only), that step escalates tiers.

## 12. Open questions for review

1. Should stage 1's per-generation checkpoint also flush a heartbeat-cadence
   partial summary (a `campaign-state.json` reader already gets this;
   printing it is redundant) — proposal: no, the state file is the API.
2. `--resume` as a distinct flag vs. only `--extend N` (with interrupted
   campaigns resumed implicitly by any extend): both are specified above;
   if reviewers want a single spelling, `--extend` alone survives and
   "finish without adding" is `--extend 0`… which §3 currently rejects as
   redundant. Recommendation stands: keep both, reject `--extend 0`.
