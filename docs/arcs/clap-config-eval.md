# clap adoption + configuration story: evaluation, spike, and full port

Status: **ADOPTED and landed 2026-08-06** as a full port of every verb. The
earlier two-verb spike was rejected on its mechanical LOC rule (+117 LOC,
dominated by a 116-line clap-to-passthrough bridge); the user overturned that
verdict on the grounds that the bridge is exactly what a whole-CLI port
deletes, and that byte-identical help output was never a requirement. §9 records
the measured outcome of the full port; §§1-8 are the pre-port analysis, kept as
written so its predictions can be checked against §9.

Scope: the `cargo-patina` CLI only.

This doc answers four questions about adopting clap for the cargo-patina CLI,
coupled with the env-var + config-file configuration story:

1. Would we expect fewer or more lines and/or bugs? (§4)
2. Would it improve ergonomics? (§5)
3. Would it reduce future maintenance burden? (§6)
4. How does the env-var + config-file layer change the cost/benefit? (§3, §8)

Every claim about the bespoke system below was verified against source at the
cited locations.

## 1. What the bespoke system is (measured inventory)

The CLI is a two-part system: a **declarative registry** (data) and **hand-rolled
family parsers** (code), tied together by generic drift-gate tests.

**The registry** (`crates/cargo-patina/src/help.rs`, 1,731 lines) declares every
flag once — name, short form, `Value::{None,Required,Optional}` arity, one of 15
typed `Kind` value grammars (`help.rs:26-58`: u64/u32/usize/positive-u64/permille/
nanos-range/crash-spec/key-value/socket/preopen/unsupported-symbols/enum/symbol/
path/string), doc line, repeatability — grouped per verb and per *family within a
verb* (run's native/WASI/cargo groups, `help.rs:554-669`). The registry generates:

- human help (overview + per-verb sections, `help.rs:1416-1526`),
- usage-error synopses (`help.rs:1535-1561`),
- the progressive-disclosure machine help — schema `patina.help/v2`, a compact
  index plus per-verb JSON payloads with default-valued fields omitted
  (`help.rs:1564-1731`),
- the arity oracle `flag_arity()` (`help.rs:1294-1303`) that the positional
  scanner consults.

The registry does **not** drive parsing (`help.rs:12-16` states this explicitly).

**The parsers** are per-family `match` loops over token indices in
`crates/cargo-patina/src/lib.rs` (routing + parse fns + helpers ≈ lines 526-3507),
`campaign.rs:190-357`, and `output.rs:97-170`. Measured by function span, the
hand-rolled parsing code is:

| Where | What | ~LOC |
|---|---|---|
| `lib.rs` | verb routing, `locate_positionals`, `reject_stranded_artifact`, 15 `parse_*` family fns, value validators, `split_opt`/`required_value`/`set_once` helpers | 2,250 |
| `campaign.rs:190-357` | campaign parse (incl. `--spec` JSON layering) | 170 |
| `output.rs:97-170` | pre-routing global `--format/--render/--report` extraction | 75 |
| **total** | | **~2,500** |

**The enforcement layer** (all in `lib.rs` `tests`, ≈860 lines of the ~2,600-line
test module, plus a repo script):

- `registry_covers_every_parsed_flag` (`lib.rs:8146`) — every flag a parser
  accepts must be registered, against a hand-maintained `accepted_flags` mirror
  (`lib.rs:8010-8143`).
- `registry_value_grammars_match_the_parsers` (`lib.rs:8689`) — for every
  registered value-bearing flag, valid and invalid samples of its declared `Kind`
  (`kind_samples`, `lib.rs:8389`) are driven through the **real** family parser
  (`drive_flag`, `lib.rs:8493`) in every registry-implied form: inline `=`,
  spaced (required-value only), declared short, and the optional-value flags are
  asserted to *reject* the space form (`=`-only semantics, `lib.rs:8780-8788`).
- `registry_repeatable_flags_match_the_parsers` (`lib.rs:8820`) — repeat
  acceptance must match the `repeatable` field (`set_once` rejection otherwise).
- `scripts/check-flag-drift.sh` (219 lines) — every `--flag` token in gated docs
  and all shell scripts, checked against the flag universe reconstructed from the
  `patina.help/v2` index + per-verb JSON payloads.

**Behavioral subtleties the parsers implement** (each is a porting constraint):

- Optional values are `=`-only: `--buggify` or `--buggify=500`, never
  `--buggify 500` (space form ambiguous with a positional; `help.rs:1442-1446`,
  enforced at `lib.rs:8780`).
- `set_once` duplicate rejection for non-repeatable value flags (`lib.rs:3443`).
- Cargo-family conservative passthrough: `test`/`run`-as-package forward every
  unrecognized option to Cargo verbatim, **interleaved and order-preserving**
  (`parse_cargo` `lib.rs:1658-1659`), including non-UTF-8 tokens
  (`lib.rs:1616-1621`).
- Options and the artifact in any order: `locate_positionals` (`lib.rs:1228`)
  scans with registry arity, stops conservatively at the first *unknown* flag
  (its next token could be that flag's value), and `reject_stranded_artifact`
  (`lib.rs:1333`) turns a real artifact stranded behind an unknown flag into a
  loud routing error instead of a silent Cargo fallthrough.
- One verb, several families: `run`/`audit`/`replay` decide the family from the
  positional's magic bytes (or `--target`), *then* run that family's parser —
  so `--fuel` on a native binary is rejected by construction, not by a
  cross-check.
- `--help`/`-V` intercepted anywhere before `--`; a literal `--help` reaches a
  guest only via `--arg=--help` (`lib.rs:8886-8896`).

**Crate-graph constraint check**: nothing in the workspace depends on
`cargo-patina` (verified: no other `Cargo.toml` lists it), and the shim/runtime
crates (`patina-native-shim`, `patina-runtime`, …) are dependencies *of*
cargo-patina, never the reverse. A `clap` dependency added to
`crates/cargo-patina/Cargo.toml` is therefore naturally unreachable from any
guest-linked or runtime crate — the "clap only in cargo-patina" constraint holds
by graph direction with no extra enforcement needed. (Worth one grep in CI if it
ever worries anyone, but the graph cannot route it into the shim.)

## 2. Honest capability mapping

clap 4 (builder API; MSRV 1.74 vs. workspace `rust-version = 1.86` — compatible,
spike re-verifies) against each bespoke feature:

| Bespoke feature | clap-4 equivalent | Fidelity |
|---|---|---|
| Required value, both `--f V` and `--f=V` | default `Arg` behavior | exact |
| Optional value, `=`-only | `num_args(0..=1).require_equals(true).default_missing_value(...)` | exact — this is precisely what `require_equals` exists for |
| `set_once` duplicate rejection | clap 4 default: a non-`Append` arg given twice errors ("cannot be used multiple times") | exact |
| Repeatable flags (`--arg`, `--env`, `--allow`, `--param`) | `ArgAction::Append` | exact; `--param` unique-key check (`lib.rs:1650-1652`) stays a post-parse validation |
| 15 typed value grammars | `value_parser`: `value_parser!(u64)`, ranges for permille (`0..=1000`), `PossibleValuesParser` for enums, and **custom parser fns** for nanos-range/crash-spec/socket/preopen/unsupported-symbols — i.e. today's validators (`validate_crash_at` `lib.rs:2480`, `validate_nanos_range` `lib.rs:2496`, `parse_wasi_preopen` `lib.rs:3470`, …) survive, re-plugged | exact plumbing; **the grammar code itself is not replaced** |
| Short flags `-p/-o/-h/-V` | `Arg::short` | exact |
| Global output flags stripped pre-routing | `Arg::global(true)` | equivalent |
| `--` trailing guest/oracle args | `Arg::last(true)` / manual split (today `split_trailing_args`, `lib.rs:2341`) | equivalent |
| Per-verb help sections with titled groups | `Command::next_help_heading` | close (layout differs; see help-output criterion in §7) |
| Verb routing (`run`/`test`/…) | subcommands | equivalent |
| **Interleaved unknown-flag passthrough to Cargo (order-preserving, non-UTF-8-safe)** | **none.** `allow_external_subcommands` is subcommand-level; `trailing_var_arg`+`allow_hyphen_values` stops patina-flag parsing at the first unknown token (breaking "options in any order"); `ignore_errors(true)` is documented as best-effort and drops the unknowns' positions | **must remain hand-rolled** (a pre-pass that partitions known patina flags from forwarded tokens — which requires an arity table, i.e. the registry, i.e. roughly `locate_positionals` generalized) |
| **Family-dependent flag sets resolved from the positional's magic bytes** | **none directly.** A clap `Command` is static per verb. Workable shape: keep today's routing (positional scan + magic bytes), then hand the tail to a per-*family* clap `Command` built for that verb+family | routing layer (~250 of the subtlest lines: `locate_positionals`, `reject_stranded_artifact`, `classify_arg`, magic-byte inference) **survives unchanged** |
| `patina.help/v2` JSON (index + per-verb, default-field omission) | **none.** clap has no JSON help. Either (a) walk `Command` introspection (`get_arguments()`, `get_possible_values()`, …) and re-emit — but `value_parser` erases the grammar *name* (a closure has no "crash-spec" tag), so a parallel Kind annotation is needed anyway — or (b) keep the registry as the JSON source | keep the registry; JSON output unchanged |
| `check-flag-drift.sh` | consumes the JSON help; unchanged if JSON is preserved | unchanged |
| The three generic walk tests | become the **acceptance suite** for the port: `drive_flag` drivers call the clap-backed parse fns through the same signatures | unchanged (that is the point) |
| Usage-error synopsis + "run `cargo patina <verb> --help`" pointer | clap's usage rendering (different text) + `error.exit()` interception to append the pointer | close, text changes |
| Non-UTF-8 positionals/values | `value_parser!(OsString)` / `PathBuf` | equivalent for values; non-UTF-8 *unknown flags* only matter on the passthrough path, which stays hand-rolled anyway |

**The structural conclusion of the mapping**: clap can replace the ~15 per-family
`match` loops (token iteration, arity, `=` handling, duplicate rejection, typed
value dispatch). It cannot replace the registry (still needed as the single
source for JSON help, grammar tags, and the drift gate), the routing/positional
layer (no clap equivalent for conservative unknown-flag scanning or
magic-byte-dependent flag sets), or the value validators. The only coherent
architecture is **registry-driven clap**: a ~100-line generic
`Flag → clap::Arg` builder (Kind → value_parser mapping in one `match`), per
verb+family, keeping the registry authoritative. A derive-API rewrite would
*duplicate* the registry into struct annotations and is ruled out — it reintroduces
exactly the two-sources drift the current design exists to kill.

## 3. The env-var + config-file layer (implemented on bespoke parsers)

This is one design referenced from two places: the invariant-visibility arc's
`.patina/` config dir v1 decision (tags/groups + **default knobs**) and this doc.
Default-knobs loading there *is* this layering, now implemented by a pre-parse
injection layer over the existing bespoke parsers.

**Precedence** (highest wins):

```
explicit flag  >  PATINA_* env (user-scope)  >  .patina/config (project)  >  built-in default
```

In-repo precedent: campaign already layers `--spec FILE.json` under individual
flags with exactly this rule — "flags override the spec regardless of argument
order" (`campaign.rs:234-244`, fixing a real ordering bug noted in that comment).
The config layer generalizes that shape to every verb.

**Three patina-specific constraints that dominate the implementation** (and that
neither clap nor any config crate handles for us):

1. **Replay must not re-apply config.** Replay restores every semantic input
   (seed, fault knobs, buggify, guest argv) from the trace, which is
   authoritative — replay deliberately exposes no semantic flags
   (`help.rs:846-861`). A config default for, say, `--net-drop-permille` must
   therefore apply to `run`/`test`/`campaign` but **never** to `replay`, or a
   project config file silently diverges a replay. The layer needs the same
   host-facts-vs-semantic-inputs split the replay flag surface already encodes.
   Implemented policy: non-empty `[defaults.replay]` is refused.
2. **Child-process leakage.** `campaign` and `explore` spawn child
   `cargo patina run` processes. If the CLI honors user-scope env vars, an
   operator's exported `PATINA_SEED` would leak into every child and silently
   override per-generation knobs, breaking "everything is a pure function of the
   generation number" (`help.rs:960-971`). The supervisor must scrub/pin
   user-scope config env vars when spawning children. Implemented policy: campaign
   child `run` invocations receive `--no-config`, and the parent removes the
   generated `PATINA_*` env-default names for `run` before spawning; the child then
   receives only explicit per-generation flags plus pinned protocol diagnostics
   (`PATINA_SDK_REPORT=1`, `PATINA_LIVENESS_REPORT=1`).
3. **Provenance must be inspectable** (agent-inspectable CLI is a standing
   principle). The resolved value of every knob should be reportable with its
   source (`flag`/`env`/`config`/`default`), e.g. in the `--format json` result
   envelope and a future `config` verb. Implemented policy: env/config-applied
   values are reported in a `config` JSON object, and config-file defaults also
   emit a human `PATINA_CONFIG applied=<verb>:<keys> path=<file>` line.

**Is the layer easier or harder with clap in the middle?**

- *Env*: clap is natively better — `Arg::env("PATINA_X")` gives flag>env
  precedence for free and documents the var in `--help`. Bespoke needs a
  ~50-line resolve helper. Small clap win.
- *Config file*: not native to clap either way. With clap, config values are
  injected as computed `default_value`s at `Command`-build time or applied
  post-parse using `ArgMatches::value_source()` (`CommandLine`/`EnvVariable`/
  `DefaultValue`) to detect "user didn't say". Bespoke parsers already encode
  "user didn't say" as `Option::None` per flag (`seed.unwrap_or(0)` at each
  parse-fn tail), so the same resolve step slots in at those choke points.
  Roughly equal work.
- *Provenance*: slight bespoke edge — with clap, config-injected defaults are
  indistinguishable from compiled defaults via `value_source()` (both read
  `DefaultValue`), so provenance needs its own bookkeeping *outside* clap
  regardless.
- *The registry angle*: either way, the honest move is a `default:` (and
  `configurable: bool` / `semantic: bool`) field **in the registry**, so the
  config surface, its docs, its JSON exposure, and constraint 1's
  semantic/host split are declared once and drift-gated like everything else.
  That work is identical in both worlds.

**Net**: the configuration story is mildly *pro-clap* (free env plumbing,
`value_source`), but the hard parts — replay exclusion, child scrubbing,
provenance, registry declaration — are patina logic that clap does not shrink.
Config is not a deciding factor; it is a small weight on the clap side.

## 4. Lines and bugs (rubric question 1)

**LOC delta, estimated honestly.** Today: ~2,500 lines of parsing code (§1).
Under registry-driven clap:

| Component | Estimate |
|---|---|
| generic `Flag → Arg` builder + `Kind → value_parser` map | +150 |
| per-verb+family `Command` assembly | +100 |
| matches→invocation-struct extraction (the per-flag `matches.get_one::<u64>("seed")` arms; unavoidable — each family's invocation struct must still be populated) | +700 |
| cross-flag validation kept (branch quorum `lib.rs:1761-1788`, `--sched-pct-steps` requires `--sched-pct`, buggify implies, …) — clap `ArgGroup`/`requires` covers some, the rest stays code | +150 |
| value validators kept (grammar fns) | +250 (moved, not removed) |
| routing/positional layer kept (`locate_positionals`, `reject_stranded_artifact`, magic bytes, passthrough partition) | +400 (kept, slightly reshaped) |
| clap error interception (exit codes, verb-synopsis pointer, `CliError` envelope) | +80 |
| **new total** | **~1,850** |

Estimated net: **roughly −650 lines (−25%)**, not the −2,000 a naive "clap
replaces the parser" reading suggests, because the registry, validators, routing,
and extraction all survive. help.rs shrinks only if clap's human help replaces
the registry renderer (~210 lines) — at the cost of the current byte format.
These are estimates; the spike measures the real ratio on two verbs (§7).

**Bug surface.** Classes of bug clap eliminates: token-index arithmetic,
inline-`=` vs spaced-form divergence, missed duplicate rejection, arity
mismatches, help/parser drift *for the flags clap owns*. The decisive
observation: **these are exactly the classes the three generic walks already
catch mechanically** — the walks were built as the general form of a real shipped
regression (`--sleep-jitter-nanos 0:N` vs `0..N`, cited at `lib.rs:8694-8696`),
and they run every flag through every form in both directions. Classes clap does
*not* touch: value-grammar bugs (validators are still ours), routing/family
bugs, passthrough bugs, JSON-help drift, config layering — which is where the
system's residual risk actually lives (both dogfooding-found CLI-adjacent bugs
were semantic/routing-level, not token-level).

So: **fewer lines (modestly), and mostly the same bug classes remaining**. clap
converts "bug class prevented by a test we wrote" into "bug class prevented by
construction" for the token layer — a real but bounded improvement, plus it
removes the `accepted_flags` hand-maintained mirror (`lib.rs:8010-8143`), whose
completeness currently rests on `drive_flag`'s panic-on-missing-driver rather
than on structure. New risk introduced: a dependency's behavior changes under
upgrade (clap minor releases have historically adjusted error text and edge-case
parsing), which lands on us as churn in the byte-exact criteria below.

## 5. Ergonomics (rubric question 2)

For users, clap buys:

- **Typo suggestions** ("a similar argument exists: `--seed`") — the bespoke CLI
  has none; unknown flags either error tersely or, in the Cargo family, forward
  silently (correct but unhelpful when it *was* a typo of a patina flag; today
  `--seeed 5` on `test` is forwarded to cargo and fails as a cargo error).
  This is the single biggest user-facing win, and it is confined to the
  non-passthrough families — the Cargo family must keep forwarding, so typos
  there stay un-suggested in either world.
- Uniform, familiar error phrasing and usage blocks; possible-values listings on
  enum mismatch.
- Consistent `--help` layout with the wider ecosystem (though the current
  registry renderer is already coherent and, unlike clap, prints the per-family
  grouping and the prose sections exactly as designed).

What ergonomics could *regress*: the curated help (families-within-a-verb
grouping, prose, the `=`-only note, the artifact-inference essay) doesn't map
1:1 onto clap's renderer — keeping the registry renderer for human help and
using clap purely as the token engine avoids the regression entirely and is the
recommended spike shape. Machine ergonomics (`patina.help/v2`, drift gate) are
pinned byte-identical by §7's criteria.

Net: a genuine but narrow win (suggestions + error consistency), achievable only
in the token layer.

## 6. Future maintenance burden (rubric question 3)

**Adding flag N+1 today**: registry entry (~7 lines) + a `match` arm in the
owning family parser (~5-15 lines) + a `drive_flag` route if a new verb/flag
pair (~1-5 lines; the walk *panics* if missing, so it cannot be forgotten) +
`accepted_flags` mirror line. The walks then test every form automatically.
Measured recent cost: the fault-knob unification added 5 flags across 3 families
with one shared `apply_fault_flag` — the marginal cost is real but small and,
critically, *fails loudly when any piece is missing*.

**Under registry-driven clap**: registry entry (same ~7 lines, now also
generating the `Arg`) + an extraction line (~3-5 lines) + the same `drive_flag`
route. The parser `match` arm and the `accepted_flags` mirror disappear.
Marginal cost drops from ~20-25 lines to ~12-15, and one hand-maintained mirror
is deleted.

**Recurring costs that change sign**: clap version upgrades become our problem
(error-text churn against byte-exact gates; MSRV policy of a fast-moving crate
vs. workspace MSRV 1.86 — clap has historically bumped MSRV in minor versions,
so `clap` would need a pinned minor and a documented upgrade gate). Compile time:
clap 4 + default features adds ~8-10 crates to the build graph of the one
binary crate; measured in the spike, expected low single-digit seconds cold,
near-zero incremental for non-CLI edits.

Net: **modest reduction in per-flag maintenance, new dependency-stewardship
line-item.** Neither dominates.

## 7. The spike protocol

Time-box: **~1 agent-hour** (user-calibrated 2026-07-30 — a subagent runs this in
roughly an hour, not the human-scale "2 working days" originally written; keep it a
small spike regardless). Throwaway workspace; no landing without the decision rule.
The spike launches on the user's explicit go; after it reports, the coordinator owns
the adopt/reject call against the §8 decision rule — including kicking off the full
parser→clap port without further prompting if it clearly passes.

**Port exactly two verbs, registry-driven builder API:**

1. **`campaign`** (the simple one). Single positional, single family, no
   passthrough, 14 flags, and its `--spec` layering is a live miniature of the
   config-precedence design (§3) — porting it forces the
   "config-under-clap" question concretely (spec values vs. `value_source()`),
   which a purely simple verb like `explore` would not.
2. **`run`** (the hard one, per the brief). It exercises everything at once:
   three families off one verb (magic-byte routing), the Cargo-family
   interleaved passthrough, optional-value `=`-only flags (`--buggify`,
   `--sched-pct`, `--starve`, `--liveness-watchdog`, `--converge-within`),
   repeatables, cross-flag requirements, `--` guest args, and
   options-anywhere positional scanning. If clap fits `run` without a second
   flag table or an `ignore_errors` hack, it fits everything.

**Success criteria (all measured, none waived):**

- The three generic walks (`registry_value_grammars_match_the_parsers`,
  `registry_repeatable_flags_match_the_parsers`,
  `registry_covers_every_parsed_flag` or its clap-introspection successor) pass
  **unmodified** for the two ported verbs — same `drive_flag` drivers, same
  samples, same forms.
- `cargo patina campaign|run --help --format json` is **byte-identical** to
  main (the registry stays the JSON source, so this should be trivially true —
  a diff here means the registry stopped being authoritative, which is a fail).
- `scripts/check-flag-drift.sh` green, unmodified.
- End-to-end tests for the two verbs (`crates/cargo-patina/tests/end_to_end.rs`)
  pass; any *error-message* text changes are inventoried and judged (better is
  acceptable; a lost `--help` pointer or lost exit-code contract is a fail).
- Human `--help` output either byte-identical (registry renderer retained —
  recommended) or a side-by-side diff is produced for explicit user sign-off.
- The Cargo-family passthrough keeps order and non-UTF-8 tokens, verified by the
  existing passthrough tests, **without** `ignore_errors` and **without** a
  second flag-arity table outside the registry.
- Measured, not estimated: net LOC delta for the two verbs (parser code removed
  vs. builder/extraction/bridge code added); cold and incremental
  `cargo build -p cargo-patina` wall-clock before/after; `cargo patina` binary
  size delta; MSRV check (`cargo +1.86 check -p cargo-patina`).
- `cargo tree -i clap` shows cargo-patina as the only dependent (mechanical
  confirmation of the graph argument in §1).

**Decision rule (commit now, apply after):**

- **Adopt** (port remaining verbs, same shape) iff *all* criteria pass **and**
  the measured net LOC delta on the two verbs is ≤ 0 **and** the passthrough +
  family-routing bridges did not grow beyond today's `locate_positionals` +
  `reject_stranded_artifact` footprint (i.e. clap did not force a re-derivation
  of the same scanning logic in a worse place) **and** cold-build cost ≤ +10 s.
- **Reject** (delete the spike branch, keep the bespoke system, carry the config
  design of §3 into the bespoke resolve-step shape) if any criterion fails or
  any bridge required weakening a gate (walks modified to pass, JSON drift,
  drift-gate allowlisting).
- No middle state: a partial port (two verbs clap, six bespoke) does not land —
  two parser idioms is strictly worse than either.

## 8. Recommendation

**Run the spike, with expectations set to "lean reject unless run ports
cleanly."** Honest summary of the balance:

- The heavy, recently-invested value of this CLI — the registry as single
  source, the typed grammars, the machine help, the drift gates, the generic
  walks — is **orthogonal to clap** and survives (indeed is required) in any
  sane port. clap replaces only the token loops, the layer whose bug classes
  the walks already police mechanically.
- The two features with **no clap equivalent** (interleaved conservative Cargo
  passthrough; magic-byte-dependent family flag sets) sit exactly on the verbs
  users touch most, and keep the subtlest ~400 lines hand-rolled regardless.
- The clear wins are real but bounded: typo suggestions and error-format
  consistency for users; ~40% lower marginal cost per new flag and one deleted
  hand-maintained mirror for maintainers; free env-var plumbing for the config
  story. Expected net −25% parser LOC, not a rewrite-sized saving.
- The config story (§3) tilts slightly pro-clap but its hard constraints
  (replay exclusion, child-env scrubbing, provenance) are patina logic either
  way, and its precedence design should land in the **registry** (a `default:` /
  `configurable:` field) regardless of the spike outcome — that work is
  common to both futures and can start before the spike.

The spike is cheap (2 days), the decision rule is mechanical, and the acceptance
battery already exists — which is precisely the situation the walks were built
for: they make a parser-engine swap *testable* rather than a leap of faith. If
`run` fits clap without weakening a single gate, adopt; the first gate weakened,
reject without relitigating.

## 9. The full port: what was built and what it measured

The port keeps the architecture §2 predicted — **registry-driven clap** — and
carries it further than the spike could: the registry now declares not just each
flag but each verb's *families* (the disjoint flag sets a verb chooses between at
routing time), so one declaration generates the help, the JSON payload, the
parser, the refusal wording, and the test routing.

### 9.1 What the registry gained

| Addition | Replaces | Why it matters |
|---|---|---|
| `Family` + `Group.families` + `only(flag, …)` | the `(verb, flag) → family parser` knowledge spread across routing code and the test driver table | a family's flag set is declared once; a flag cannot be accepted by a family its help omits |
| `FamilySpec { label, because }` | hand-written "unsupported option X for `run` of a native binary" arms in every parser | the same wording for every family, derived |
| `Refusal { families, flags, names, message }` | literal flag lists inside `parse_native_replay` / `parse_wasi_replay` | a knob added to `FAULT_FLAGS` is refused by replay the day it is added — see 9.4 |
| `Flag.requires` | `if schedule.pct.is_none() && schedule.pct_steps.is_some()` checks, repeated per family | one generic check, and the grammar walk knows to arm the parent |

### 9.2 Measured (Apple M4, rustc 1.97.1, isolated build dirs and workspace paths)

**Read the wall-clock rows as unreliable.** Every build and battery timing below
was taken with several agents running batteries on the same machine (load average
33-47 throughout), and the baseline and ported measurements were taken at
different times under different, unrecorded contention. The build-cost delta is
therefore an order-of-magnitude sanity check, not a number to defend; the
warm-rebuild result (the ported crate rebuilding FASTER) is plausible on
mechanism but wants a re-measure on a quiet machine before it is quoted. The LOC,
binary-size, MSRV, and dependency-graph rows are contention-independent.

A measurement trap worth recording: this machine's `~/.cargo/config.toml` sets
`build.build-dir` to a workspace-path-hashed shared directory, so `CARGO_TARGET_DIR`
alone does NOT produce a cold build — only a fresh workspace PATH does. The first
"baseline" reading taken here was wrong for exactly that reason.

| Metric | Baseline | Ported | Delta |
|---|---|---|---|
| Non-test source (`crates/cargo-patina/src`) | 23,051 | 22,231 | **−820 (−3.6%)** |
| … bespoke parsing/tokenizing deleted | — | — | −1,945 |
| … registry declaration added (`help.rs`) | — | — | +412 |
| … clap layer added (`cli.rs` 509 + `values.rs` 204) | — | — | +713 |
| Test source | 5,256 | 5,126 | −130 |
| Total | 28,307 | 27,357 | **−950 (−3.4%)** |
| Cold `cargo build -p cargo-patina --release` (contended) | 37.36 s | 45.90 s | +8.54 s (unreliable) |
| Warm rebuild of `cargo-patina` alone (contended) | 11.40 / 11.59 s | 10.71 / 8.55 s | faster (unreliable) |
| Release binary | 10,076,640 B | 10,417,264 B | +340,624 B (+3.4%) |
| MSRV `cargo +1.86.0 check` | clean | clean | — |
| `cargo tree -i clap` | — | `clap → cargo-patina` only | single dependent |

There is no bridge. The 116-line spike bridge existed to reconcile two parsing
idioms; with every verb on clap there is one idiom, and the passthrough split
([`cli::partition`]) is 40 lines driven by the registry rather than by a second
arity table.

The binary cost is a quarter of the spike's (+340 KB vs +2.33 MB) because the
dependency carries `default-features = false`: the CLI renders its own help and
usage from the registry, so clap's `help`, `usage`, and `color` features are all
dead weight — and `color` would have made error output terminal-dependent, which
a machine-parsed CLI must not be. clap is pinned `~4.6` rather than `^4.6`
because clap raises its MSRV in minor releases (4.6 needs 1.85 against our 1.86);
bumping the minor is a deliberate step that re-runs `mise run msrv`.

The warm-rebuild result was the surprise: the crate appears to compile *faster*
with clap linked, which is mechanically plausible because ~1,900 lines of
monomorphized hand-written parsing disappeared. Under the contention above it is
a hypothesis, not a finding.

### 9.3 Bug classes: eliminated vs merely moved

**Structurally eliminated** (unrepresentable, not tested away):

* *Parser accepts a flag the help omits, or omits one it advertises.* The parser
  is BUILT from the help rows. `registry_covers_every_parsed_flag` and its
  140-line hand-maintained `accepted_flags` mirror are deleted, not ported.
* *Arity / `=`-only divergence.* `Value::Optional` maps to
  `require_equals(true).num_args(0..=1)`; there is no per-family code that could
  disagree.
* *Missed duplicate rejection.* One generic check over `repeatable` replaced
  ~60 `set_once` call sites.
* *Wrong grammar for a value.* `Kind` selects the validator, once. This class had
  a live instance: `config.rs` carried a SECOND, independently written
  implementation of every grammar for config/env defaults, and the two disagreed
  (different socket rules, different messages). Both now call `values::validate`.
* *A family accepting a sibling family's flag.* The family declaration is what
  builds the `Command`.

The test delta is net of ~340 deleted lines of mirror (`accepted_flags`, the
per-flag `drive_flag` routing) against ~210 added: a family-keyed driver table
and five new pins — the two registry invariants below, the first test the CLI has
ever had for non-UTF-8 Cargo passthrough (an arc-stated constraint that until now
rested only on a comment), a pin that a Cargo-family replay refuses semantic
knobs rather than forwarding them, and a pin that `--spec` and flags layer with
the flag on top in either argument order. Each was verified red-before/
green-after.

**Reduced but still ours**: the grammars themselves (still hand-written, now in
one place); routing and magic-byte family inference; the Cargo passthrough;
cross-flag domain rules that are not simple dependencies.

**New**: dependency stewardship. clap's error wording is now user-visible text we
do not own, so a minor bump can change it; the pin plus the e2e assertions make
that a loud, contained change rather than a silent one.

### 9.4 Two live bugs the port surfaced

1. **`campaign --report` was documented and unreachable.** The global
   `--report OUT.html` pre-pass ran before verb routing and consumed both the
   flag and the token after it, so `campaign … --report --gens 2` reported
   `unsupported option "2"`. Two flags shared a name with different arities and
   nothing noticed, because the pre-pass and the verb parser were separate token
   loops. Fixed by renaming the campaign flag to `--report-failures`, and pinned
   as a class by `no_verb_redeclares_a_global_flag` (verified red-before/
   green-after). Under clap a single `Command` would panic at build time on the
   duplicate; the pre-pass is the one place that stays outside clap, so the
   invariant is asserted instead.
2. **Native replay's refusal list was drifting.** `parse_native_replay` spelled
   out all seven fault knobs literally, so a knob added to `FAULT_FLAGS` would
   have silently degraded from "the trace is authoritative" to "unsupported
   replay option". The registry `Refusal` now references the shared slice.

A third, from writing the passthrough split down: the Cargo-family `replay`
refused only the seven fault knobs by name and forwarded `--seed`/`--buggify`/
`--sched-pct` to Cargo, where they surfaced as a cargo argument error rather
than "the trace is authoritative". The registry `Refusal` now covers the Cargo
family too, and `partition` keeps declared refusals rather than forwarding them.
(Sibling-family flags are still forwarded — `--bin` and `--release` are exactly
the names a legitimate Cargo argument shares, and forwarding them is what the
passthrough is for. That asymmetry is deliberate and commented at
`cli::partition`.)

A fourth, smaller: WASI `run` accepted `--heal-after` without `--converge-within`
(the native families rejected it), so the knob was silently inert — an "inert
knobs are bugs" violation. `Flag.requires` makes the rule uniform.

### 9.5 Intentional output changes

Every one was reviewed; none loses information.

| Case | Before | After |
|---|---|---|
| Unknown flag | `unsupported option "--seeed" for \`run\` of a WASI module` | `unexpected argument '--seeed' found; tip: a similar argument exists: '--seed'` |
| Missing value | `--seed requires a UTF-8 value` | `a value is required for '--seed <U64>' but none was supplied` |
| Bad value | `--seed must be an unsigned 64-bit integer` | `invalid value 'abc' for '--seed <U64>': --seed must be an unsigned 64-bit integer` |
| Value on a switch | `--release takes no value` | `unexpected value 'x' for '--release' found; no more were expected` |
| Sibling-family flag | per-parser prose, e.g. `trace info reads metadata only and does not accept --kind` | `trace info does not accept --kind (trace info reads metadata only)` |
| `--harness` on a WASI run | `--harness is native-only; …` | `` `run` of a WASI module does not accept --harness `` |
| `--extend 0` | `--extend 0 is redundant; use --resume …` | `--extend must be >= 1` (the guidance moved into the flag's help text) |
| `--kind`/`--runtime` enums | `--kind must be one of a\|b; got "x"` | unchanged wording, now generated from `Kind::Enum` |

Unchanged: exit codes (2 for every usage error, 0 for `--help`/`--version`), the
registry-rendered usage synopsis appended to every error, human `--help` layout,
`--format json` result envelopes, and unknown-verb / unknown-subcommand errors
(those are routing, not flag parsing).

Help JSON stayed schema-compatible: the only structural change is an **additive**
`families` array on groups and on narrowed flags, plus `requires` on dependent
flags — new machine-readable facts (an agent can now see that `--fuel` is
WASI-only) that `patina.help/v2` consumers ignore. `scripts/check-flag-drift.sh`
passes unmodified.

### 9.6 Verdict

**Adopt — the full port is a clear improvement, and the spike's rejection was an
artifact of measuring a half-migration.** The win is not the line count (−3.6% of
non-test source is real but modest); it is that the CLI now has *one* description
of itself. Three hand-maintained mirrors are gone (`accepted_flags`, the
`drive_flag` per-flag routing table, `config.rs`'s duplicate grammars), two
shipped bugs fell out of writing the declaration down, and the marginal cost of a
new flag dropped from "registry row + parser arm + driver route + mirror line" to
"registry row + extraction line".

The honest costs: a dependency whose error wording is user-visible and whose MSRV
policy is not ours (mitigated by the `~4.6` pin), a cold-build cost measured at
+8.5 s but under heavy contention (§9.2 — read it as single-digit seconds, not as
a figure), +340 KB of binary, and a `Family` concept a reader must learn before
the registry makes sense. Against a CLI with eleven verbs and twenty-two families whose defining
difficulty was keeping parser, help, and docs in agreement, that trade is worth
making.
