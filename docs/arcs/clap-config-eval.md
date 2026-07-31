# clap adoption + configuration story: evaluation and spike definition

Status: evaluation (defines a future spike; no spike code exists yet).
Scope: the `cargo-patina` CLI only. Decision owner: user, after the spike defined in §7.

This doc answers four questions about adopting clap for the cargo-patina CLI,
coupled with the future env-var + config-file configuration story:

1. Would we expect fewer or more lines and/or bugs? (§4)
2. Would it improve ergonomics? (§5)
3. Would it reduce future maintenance burden? (§6)
4. How does the planned env-var + config-file layer change the cost/benefit? (§3, §8)

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

## 3. The env-var + config-file layer (design; shared with the .patina/ arc)

This is one design referenced from two places: the invariant-visibility arc's
`.patina/` config dir v1 decision (tags/groups + **default knobs**) and this doc.
Default-knobs loading there *is* this layering.

**Precedence** (highest wins):

```
explicit flag  >  PATINA_* env (user-scope)  >  .patina/config (project)  >  built-in default
```

In-repo precedent: campaign already layers `--spec FILE.json` under individual
flags with exactly this rule — "flags override the spec regardless of argument
order" (`campaign.rs:234-244`, fixing a real ordering bug noted in that comment).
The config layer generalizes that shape to every verb.

**Three patina-specific constraints that dominate the design** (and that neither
clap nor any config crate handles for us):

1. **Replay must not re-apply config.** Replay restores every semantic input
   (seed, fault knobs, buggify, guest argv) from the trace, which is
   authoritative — replay deliberately exposes no semantic flags
   (`help.rs:846-861`). A config default for, say, `--net-drop-permille` must
   therefore apply to `run`/`test`/`campaign` but **never** to `replay`, or a
   project config file silently diverges a replay. The layer needs the same
   host-facts-vs-semantic-inputs split the replay flag surface already encodes.
2. **Child-process leakage.** `campaign` and `explore` spawn child
   `cargo patina run` processes. If the CLI honors user-scope env vars, an
   operator's exported `PATINA_SEED` would leak into every child and silently
   override per-generation knobs, breaking "everything is a pure function of the
   generation number" (`help.rs:960-971`). The supervisor must scrub/pin
   user-scope config env vars when spawning children. Also: user-scope names must
   never collide with the internal supervisor↔guest protocol vars
   (`PATINA_MODE`, `PATINA_TRACE`, … — `help.rs:1173-1274`); today `PATINA_SEED`
   is documented user-scope but is read by the *runtime*, not the CLI — the CLI
   growing env awareness doubles the readers of that name and needs an explicit
   ownership decision per var.
3. **Provenance must be inspectable** (agent-inspectable CLI is a standing
   principle). The resolved value of every knob should be reportable with its
   source (`flag`/`env`/`config`/`default`), e.g. in the `--format json` result
   envelope and a future `config` verb.

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

Time-box: **2 working days**. Branch-only; no landing without the decision rule.

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
