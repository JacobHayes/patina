# Arc: trace inspection — `cargo patina trace {info,events,stats,diff}`

Status: PROPOSED (decision-ready; no implementation before sign-off).
Scope settled by the user: all four surfaces (info, events, diff, stats); "not
overengineered, but nicely inspectable — discovery/analysis via CLI + --help docs".

## 1. Problem

A `.patina` trace (up to 64 MB / 1,000,000 events per timeline —
`crates/patina-trace/src/lib.rs:51-52`) currently has exactly two consumers:

1. **Full HTML render** — `render_trace_file`
   (`crates/cargo-patina/src/render.rs:188`), reachable only as a `--render`/
   `--report` side effect of a run or replay (`crates/cargo-patina/src/output.rs:254`).
   There is no way to render, summarize, or query an *existing* trace file
   without re-executing something.
2. **Replay** — which answers only one question ("does this build reproduce this
   trace?") and reports divergence only as its failure mode.

The format is deliberately plain JSON (`TraceBundle::to_bytes` doc,
`patina-trace/src/lib.rs:510-517`: "a bundle can be inspected with any JSON tool
(`jq . run.patina`)"). So the gap is not raw access — it is **semantics**: task
attribution, virtual-time reconstruction, op categories, filters, aggregates,
and divergence location all live as private code inside `render.rs`, unreachable
from the command line. An agent triaging a campaign failure today either opens a
2 MB HTML file or writes a bespoke `jq` program that re-derives lane attribution
by hand (and gets it wrong, because attribution requires replaying the
`scheduler_next` cursor — `render.rs:262-284`).

The four surfaces give that semantic layer a CLI, with progressive disclosure:
`info` is the index, `events`/`stats` the drill-down, `diff` the two-trace
comparator.

## 2. Verified current state (what the design builds on)

- **Bundle shape** (`patina-trace/src/lib.rs`): `TraceBundle { format_version,
  metadata: RunMetadata, timelines: Vec<Timeline> }`. `Timeline { id, parent,
  from_sequence, branch_seed, decisions: Vec<TraceEvent> }`;
  `TraceEvent { sequence, operation, outcome }`. Branch timelines resolve by
  replaying the parent prefix (`resolved_timeline`, lib.rs:674).
- **RunMetadata** (lib.rs:270-335): `root_seed`, `decision_policy`,
  `fingerprint`, plus optional config records: `faults`, `buggify` (incl.
  realized `active_sites`/`knobs`), `guest_argv`, `schedule_policy` (PCT /
  starvation), `swarm`, `watchdog` (informational-only), `sud`. All additive,
  all readable without touching the event stream. Note the brief's list plus
  two the brief omitted: `decision_policy` and `sud`.
- **Loading is strict and fail-closed**: `TraceBundle::load` enforces the 64 MB
  cap, migrates v1..v3 → v4 in memory, then *typed*-deserializes and runs the
  structural `validate()` oracle (contiguous sequences, main-timeline shape,
  1M-event cap). `RunMetadata` is `deny_unknown_fields`; `Operation`/`Outcome`
  are name-tagged enums, so an unknown op tag is a hard parse error. **A
  successfully loaded bundle therefore contains only op tags this build knows.**
  (`render.rs`'s generic raw-JSON walk is forward-compat with *concurrent
  in-tree* additions, not with newer trace files — `render_trace_file` calls the
  strict `TraceBundle::load` first, render.rs:195.)
- **Op vocabulary is shared across families.** Both the WASI host and the native
  supervisor record through the same `patina-dst-runtime::Context` boundary and
  the single `patina_dst_abi::Operation`/`Outcome` enums
  (`crates/patina-wasi-host/src/lib.rs:20`; the full variant set is emitted from
  `crates/patina-runtime/src/`). Families differ only in *which subset appears*:
  a wasip1 trace has no `task_*`/`scheduler_next` (single-threaded guest) and no
  TCP ops; a native trace can carry all of them. There is no per-family record
  schema — family is a usage profile, not a format.
- **Replay divergence semantics** (`patina-trace/src/lib.rs:825-858, 1043-1060`):
  operation structural-equality first (`Replayer::expect` →
  `OperationMismatch { sequence, expected, actual }`), then outcome equality
  (`compare_outcome` → `OutcomeMismatch`), plus the two length classes
  (`ReplayExhausted`, `UnconsumedEvents`). `diff` mirrors exactly this taxonomy.
- **Render's semantic walk** (`render.rs:227-337`): category from the serde
  `kind` tag prefix (`Category::of_kind`), lane attribution via the
  `scheduler_next` cursor with lifecycle-op re-pointing, virtual-time cursor
  from `clock_now` outcomes and `now_nanos` fields, `summarize()` one-liners
  (byte payloads shown as lengths), `detect_notable()` (crash / error outcome /
  dropped datagram), `TaskStat` per-lane rollups, `human_nanos`. This is the
  code the new surfaces must share, not duplicate.
- **CLI registry**: flat verb list (`help.rs:1168` `VERBS`), one `Verb` per
  entry with `synopsis` (multiple forms), `prose`, titled flag `groups`.
  Progressive-disclosure help JSON `patina.help/v2` (index = `{summary, forms}`
  per verb; per-verb payload adds `flag_groups`). Drift gates: the co-located
  `accepted_flags()` mirror + `registry_covers_every_parsed_flag`
  (`lib.rs:8010, 8146`), the value-grammar property test
  (`registry_value_grammars_match_the_parsers`, lib.rs:8689), and the index
  test asserting `verbs.len() == VERBS.len()`.
- **Two-token verb precedent**: `explore run` / `explore test` — one registry
  entry, sub-token consumed by `parse_explore` (`lib.rs:2204`), multi-form
  synopsis, `--help` anywhere resolving to the verb's section.
- **Envelope family**: `patina.result/v1` (`output.rs:24`),
  `patina.campaign/v2`, `patina.campaign.signatures/v1`, `patina.help/v2`.
  The run envelope already embeds compact trace facts (`trace_facts`,
  `output.rs:435`: path, format_version, timelines, event_count, raw metadata) —
  `info` is the standalone superset of that helper.
- **Exit conventions**: CLI errors under `--format json` become one
  `patina.result/v1` error envelope with exit 2 (`entrypoint`, lib.rs:526-546).

## 3. Key decision: CLI shape — one `trace` verb with subcommands

**Decision: a single registered verb `trace` with four subcommands** —
`cargo patina trace info <TRACE>`, `trace events <TRACE>`, `trace stats
<TRACE>`, `trace diff <A> <B>` — modeled in the registry as ONE flat `Verb`
entry whose parser consumes the subcommand token, exactly the `explore`
pattern.

Rationale (against the alternatives):

- **vs. four flat verbs** (`trace-info`, `trace-events`, …): the top-level verb
  list is the CLI's front page and its help index. Going from 8 verbs to 12,
  where a third are hyphenated variations of one noun, bloats the index and
  breaks the "verbs are actions over one positional" grammar the CLI has
  (run/test/build/audit/replay/campaign/minimize are each one action). Grouping
  matches how users think: "inspect this trace, in one of four ways."
- **vs. folding into existing verbs** (e.g. `replay --info`, `minimize --stats`):
  rejected outright — inspection is read-only and execution-free; hanging it off
  verbs that execute guests muddies both the mental model and the flag
  registry (replay deliberately exposes *no* semantic flags).
- **cargo-ergonomics honesty**: cargo itself has no two-level verbs, so this is
  not a literal cargo mirror. But the repo already crossed that line
  deliberately with `explore run`, and the closest cargo convention —
  progressive disclosure, `cargo help <verb>`, small stable top level — is
  served *better* by one `trace` entry than by four. Flags-before-positionals
  and `--flag=VALUE`/`--flag VALUE` parity carry over unchanged.

**Registry-shape impact — honestly assessed: zero structural change.** The
registry models flat verbs; `trace` IS a flat verb whose four forms live in
`synopsis` (like `explore`'s two forms) and whose flag groups are titled per
subcommand ("Events options (trace events)", …), the same convention `run`
uses for its three families. Specifically:

- `help.rs`: one new `TRACE: Verb` const; append to `VERBS`. The help JSON
  index/per-verb split, `topic_for`, `usage_synopsis`, and `flag_arity` all work
  unmodified (`flag_arity` returns the union across the verb's groups — the
  same union semantics `run` already has across its three families).
- `lib.rs parse()` (lib.rs:674-686): one `"trace" => parse_trace(arguments)`
  arm. `parse_trace` peels the subcommand token; an unknown/missing subcommand
  is a usage error listing the four. The two hardcoded verb-list usage strings
  (lib.rs:645, 695) gain `trace`.
- Drift gates: `accepted_flags("trace")` union list (precedent: `run`'s union
  across three families); add `"trace"` to the hardcoded verb arrays in
  `registry_covers_every_parsed_flag` and the grammar test. The index-count
  test auto-covers the new verb.
- Per-subcommand flag misuse (e.g. `--first` on `trace stats`) is rejected by
  the subcommand parser with a usage error — the same mechanism `run` uses for
  family-specific flags.
- Granularity note: `--help` resolves at verb granularity, so
  `cargo patina trace events --help` prints the whole `trace` section. With
  four small subcommands sharing one positional and a compact flag set, that is
  acceptable (it is what `explore run --help` does today); per-subcommand help
  topics would be the first real registry-shape change and are explicitly NOT
  needed for this arc.

## 4. Shared decode layer: extract `trace_view` from `render.rs`

New module `crates/cargo-patina/src/trace_view.rs` (name bikesheddable), a pure
read-only consumer like `render.rs`, containing what render.rs owns today:
`Category` + `of_kind` prefix mapping, `LaneKey` + the scheduler-cursor lane
attribution walk, the virtual-time cursor, `summarize`, `detect_notable`,
`scalar`, `base64_len`, `human_nanos`, `TaskStat`, and a single entry point:

```rust
/// One strict-loaded, resolved timeline flattened for inspection.
pub struct FlatTrace {
    pub events: Vec<FlatEvent>,      // seq, lane, category, kind, detail, vtime, notable, raw op/outcome
    pub lanes: BTreeMap<LaneKey, TaskStat>,
    pub kind_counts: BTreeMap<String, KindStat>,   // count, errors, payload bytes in/out
    pub category_counts: BTreeMap<Category, u64>,
    pub vt_min: Option<u64>, pub vt_max: Option<u64>,
    pub notable: Vec<...>,
}
pub fn flatten(bundle: &TraceBundle, raw: &Value, timeline: &str) -> Result<FlatTrace, TraceError>
```

`render.rs` becomes a consumer of `flatten` (its existing unit tests pin the
behavior through the move); `events`/`stats`/`diff` consume the same walk, so
lane attribution and vtime reconstruction can never fork between the HTML and
the CLI. `info` deliberately does NOT use `flatten` (see §6 performance).

The module also owns the **op-tag registry**: a `const OP_KINDS: &[(&str,
Category)]` list whose completeness is compile-enforced by an exhaustive
`match` over `Operation` (no wildcard arm) in a helper — adding an ABI variant
without listing its tag fails the build, the detection-before-fixes shape. This
list powers `--kind` validation, the class-shaped render test (§9), and help
text.

**Safety property of the whole arc**: `patina-trace`, the runtime, the shims,
and every record/replay path are untouched. All new code is consumer-side in
`cargo-patina`, like `render.rs` ("rendering can never perturb replay hashes",
render.rs:5-7).

## 5. The four surfaces

All four take the trace path as the leading positional (flags may precede or
follow it, per the CLI's uniform scan), accept `--timeline ID` (default
`main`; precedent: replay/minimize), and honor the global `--format`. All load
via the strict `TraceBundle::load` oracle. `--render`/`--report` (run-output
flags) are rejected with a usage error on the `trace` family — they would
otherwise be silently swallowed by the global pre-pass.

### 5.1 `trace info <TRACE>` — the index

The cheap header read: everything knowable without decoding the event stream.

Human output (one fact per line; absent optional records omitted):

```
trace: out/gen-0042.patina
format_version: 4
fingerprint: patina-native+yieldpoints
root_seed: 42
decision_policy: splitmix64-v1
guest_argv: ["--nodes", "3"]
timelines: main (184203 events); b1 (parent main @ 1200, seed 7, 300 events)
events: 184203 (resolved main)
virtual time: 0 ns .. 4.20 s (span 4.20 s)
faults: net_drop_permille=300 sleep_jitter_nanos=0..1000000
buggify: fire=250 permille, activation=250 permille, cutoff=300 s, 3 active sites
schedule_policy: pct depth=3 steps=10000
swarm: candidates=crash,net_drop selected=net_drop
watchdog: no_progress=600 s
sud: armed
next: `cargo patina trace events|stats <TRACE>` for the event stream
```

`--format json`: schema `patina.trace.info/v1` — `{schema, path,
format_version, fingerprint, root_seed, decision_policy, guest_argv,
timelines: [{id, parent, from_sequence, branch_seed, events}],
resolved_events, vtime: {min_nanos, max_nanos, span_nanos} | null,
metadata: <raw metadata object verbatim>}`. The raw `metadata` passthrough
matches the envelope's `trace_facts` convention (`output.rs:447-455`) so any
future config record surfaces without a code change; the typed fields above it
are the stable, documented subset. `info` shares/absorbs the `trace_facts`
helper rather than duplicating it.

Buggify honesty (already documented in-format, `patina-trace/src/lib.rs:112-118`):
per-evaluation firings are re-derived from the seed, not recorded, so `info`
reports the config + realized `active_sites`/`knobs`, and says so.

### 5.2 `trace events <TRACE>` — the filtered dump

The drill-down: decoded events, one per line, filterable, greppable.

Human line format (columns: seq, lane, kind, detail, vtime):

```
#001204  task 2   fs_write      fd=5 bytes≈4096 → 4096         @ 1.20 s
#001205  task 2   scheduler_next → task 3                      @ 1.20 s
#001206  task 3   net_send      socket=1 to=10.0.0.2:9 bytes≈128 → dropped_by_fault  @ 1.20 s  [notable: drop]
```

`detail` is exactly `summarize()` (payloads as lengths, never raw bytes on the
human surface). `--format json` emits **JSON Lines** (the one deliberate
deviation from "one envelope", documented in the verb prose and the `--format`
doc string): first line a header object `{schema: "patina.trace.events/v1",
path, timeline, total_events, filters: {...}}`, then one line per matching
event `{seq, task: <u64|"main">, kind, category, vtime_nanos, notable?,
operation: <raw>, outcome: <raw>}` (operation/outcome verbatim from the trace
JSON — base64 payloads intact, so lines round-trip), and a final line
`{matched: N, emitted: N}`. A 1M-event dump as a single envelope would be
agent-hostile; JSONL is the streaming member of the envelope family.

Filter grammar (all filters AND-composed; registry-typed):

| Flag | Value kind | Meaning |
|---|---|---|
| `--kind LIST` | new `Kind::OpKindList` | comma-separated op tags (`fs_write,net_send`) and/or category names (`filesystem`, `network`, `scheduling`, `sleep`, `clock`, `entropy`, `crash`, `other`); validated against the compile-gated `OP_KINDS` list — an unknown token is a usage error naming the valid sets |
| `--task SEL` | new `Kind::TaskSelector`, repeatable | a task id (u64) or the literal `main` (the pre-scheduler lane, `render.rs:149-153`) |
| `--seq A..B` | new `Kind::U64Range` | inclusive sequence range (same `MIN..MAX` syntax as `NanosRange`, distinct tag because the unit isn't nanoseconds) |
| `--first N` / `--last N` | `Kind::PositiveU64` | head/tail of the *filtered* stream; mutually exclusive (usage error together — no head+tail cleverness) |
| `--notable` | switch | only `detect_notable` events: crashes, error outcomes, dropped datagrams |
| `--timeline ID` | `Kind::Str` | resolved timeline (default `main`) |

Because loading is strict (§2), `--kind` validation against this build's tag
set is sound: a loadable trace cannot contain a tag the build doesn't know.

### 5.3 `trace stats <TRACE>` — the numeric profile

One pass over `FlatTrace`, no new decoding. Human output, sections in order:

1. **Totals** — events, tasks/lanes, virtual-time span, notable counts
   (crashes / error outcomes / drops) — the same tiles the HTML shows.
2. **Per-kind table** — kind, count, share %, error-outcome count, payload
   bytes in (op `bytes` fields) and out (`bytes`/`optional_bytes` outcomes),
   via `base64_len` (no base64 decode).
3. **Per-category rollup** — the eight `Category` rows.
4. **Per-task table** — the existing `TaskStat` columns: lane, label, ops,
   yields, parks, seq span, completed vs live-at-exit.
5. **Virtual-time histogram** — fixed 20 equal-width buckets over
   `[vt_min, vt_max]`, event count per bucket, ASCII bars in human mode.
   No bucket-count flag initially (not overengineering; revisit on demand).

`--format json`: schema `patina.trace.stats/v1`, mirroring the sections:
`{schema, path, timeline, totals: {...}, kinds: {tag: {count, errors,
bytes_in, bytes_out}}, categories: {...}, tasks: [...], vtime: {min_nanos,
max_nanos, buckets: [{start_nanos, end_nanos, events}]}, notable: {crashes,
errors, drops}}`.

### 5.4 `trace diff <A> <B>` — first divergence between two traces

Offline trace-vs-trace comparison reusing replay's comparison semantics
(operation structural equality first, then outcome — the `Replayer::expect` /
`compare_outcome` order) over the two resolved timelines, without executing
anything. Output, in order:

1. **Metadata diff** — field-by-field over the raw metadata objects (seed,
   fingerprint, every config record); identical fields summarized, differing
   fields shown as `field: A-value → B-value`. A fingerprint mismatch is
   *reported*, never a refusal — fail-closed fingerprinting protects replay;
   diff is a read-only forensic tool and refusing to compare across builds
   would gut its main use.
2. **Aligned prefix** — the count of leading event pairs equal in both
   operation and outcome.
3. **First divergence** — sequence number, class (`operation-mismatch` |
   `outcome-mismatch` | `length` — one trace is a strict prefix of the other,
   mirroring `ReplayExhausted`/`UnconsumedEvents`), both events rendered as
   `events`-style lines, and `--context N` (default 3, `Kind::Usize`)
   surrounding events from each side.
4. **Tail summary** — remaining event count and final virtual time per side
   (no per-kind tail breakdown; `trace stats` on each file answers that).

**Honesty about different-seed diffs**: two traces with different root seeds
typically diverge at or very near sequence 0 (the first entropy or clock
outcome differs), and after one genuine scheduling divergence the two runs are
*different executions* — there is no meaningful re-alignment. `diff` therefore
does NOT attempt LCS/resync alignment (explicit non-goal; wrong tool for DST
traces and O(n²) at 1M events). What stays useful across seeds — and what the
output leads with — is the metadata delta, the aligned-prefix length (a
nonzero prefix means a deterministic prelude survived the seed change, itself
informative), and the first structural divergence. The doc for the verb says
exactly this so nobody expects a textual diff.

Exit codes follow `diff`/`git diff --exit-code` convention: 0 identical
(metadata AND events), 1 diverged (either), 2 error. `--format json`: schema
`patina.trace.diff/v1` — `{schema, a: {path, ...}, b: {path, ...}, result:
"identical"|"diverged", metadata_diff: [{field, a, b}], aligned_prefix,
divergence: {seq, class, a_event, b_event, a_context: [...], b_context: [...]}
| null, tails: {a: {events, final_vtime_nanos}, b: {...}}}`.

`--timeline` applies to both sides (default `main`); per-side timeline
selection is deferred until a real need appears.

## 6. Performance posture

- **`info` must not decode the event stream — and here is what that honestly
  means for a single-document JSON format.** The file *parse* is unavoidable
  (`serde_json` over ≤64 MB — bounded by construction). What `info` skips is
  everything after: it reads the raw `serde_json::Value` only — metadata
  object verbatim, per-timeline `decisions` array *lengths*, and a shallow
  field scan for the vtime span (`clock_now` u64 outcomes + `now_nanos`
  fields) — with **no typed `Operation`/`Outcome` deserialization, no base64
  payload decode, and no per-event allocation**. It still runs the strict
  typed load once for validation (fail-closed posture, §7); if measurement
  shows the typed load dominating on 1M-event traces, the fallback is
  documented here in advance: validate structure on the raw `Value` (version
  gate + sequence contiguity) without typed decode. Decide on measurement, not
  estimate — stage 1 records the measured wall time of `info` on a
  campaign-sized trace in the battery log.
- **`events` streams incrementally on output, not on input**: the bundle is
  fully loaded and validated *before* the first line is emitted (so corrupt
  traces can never produce partial output), then lines are written as the walk
  proceeds rather than buffering a 1M-line dump. `--last N` uses a ring
  buffer. Memory is bounded by the loaded bundle, which the format already
  caps.
- `stats` and `diff` are single passes over data already in memory. `diff`
  holds two bundles — bounded at 128 MB worst case, acceptable.

## 7. Error posture

Fail loud, no partial stdout — matching the crate's fail-closed doctrine:

- Truncated/corrupt/oversized/unsupported-version traces surface the existing
  `TraceError` taxonomy (`Parse`, `Invalid`, `ResourceLimit`,
  `UnsupportedVersion`) as a `CliError`, exactly as replay does. Under
  `--format json` that becomes the standard error envelope, exit 2
  (`entrypoint`, lib.rs:526-546). Nothing is written to stdout before the
  strict load completes (§6), so there is never partial machine output to
  mis-parse.
- No lenient/best-effort mode. The format is greppable JSON by design; forensic
  digging in a corrupt file is `jq`'s job, and a half-decoded trace presented
  as truth is exactly the "silently lying tool" the detection-before-fixes
  doctrine forbids. If corrupt-trace triage becomes a recurring need, that is a
  new decision, not a default.
- `diff` with two differently-versioned but loadable traces works (both migrate
  to v4 in memory); version difference shows up in the metadata diff via
  `format_version`.

## 8. Registry / help / drift-gate impact (complete checklist)

- `help.rs`: `TRACE` verb const (summary: "Inspect a recorded trace: metadata,
  filtered events, aggregates, or a two-trace diff."), 4 synopsis forms, groups
  titled per subcommand, prose covering: strict-load posture, JSONL deviation
  for `events --format json`, different-seed diff expectations, buggify
  not-recorded note. Append to `VERBS`.
- `Kind` additions: `U64Range` ("u64-range"), `OpKindList` ("op-kind-list"),
  `TaskSelector` ("task-selector") — each with valid/invalid samples wired
  into `registry_value_grammars_match_the_parsers`. `Enum` reused where exact
  (none new needed beyond these three).
- `lib.rs`: `"trace"` dispatch arm + `parse_trace`; the two verb-list usage
  strings (lib.rs:645, 695); `accepted_flags("trace")` union; `"trace"` added
  to the hardcoded verb arrays in the two registry tests. The JSON-index count
  test and `flag_arity` positional scanner pick the new verb up for free.
- New schema tags documented wherever `patina.result/v1` is documented today
  (the envelope doc pointer in `output.rs:479` names `llms.txt` and
  `TUTORIAL.md`): `patina.trace.info/v1`, `patina.trace.events/v1` (JSONL),
  `patina.trace.stats/v1`, `patina.trace.diff/v1` — following the existing
  dotted-namespace precedent (`patina.campaign.signatures/v1`).
- `GLOBAL_OUTPUT`'s `--format` doc gains a parenthetical noting the trace-events
  JSONL exception.

## 9. Testing strategy (class-shaped)

- **Every-op-tag gate** (the class): a `trace_view` unit test builds a bundle
  containing one event for *every* `Operation` variant (constructor list whose
  exhaustiveness is compile-enforced by a no-wildcard `match` — a new ABI
  variant fails the build until listed) paired with representative outcomes
  including `Error`, and asserts: (a) `events` text renders every line with no
  empty/unknown detail, (b) JSONL round-trips each line's `operation`/`outcome`
  to `serde_json::Value`-equality with the recorded event, (c) `stats` per-kind
  counts sum to the total, (d) the HTML render still contains each kind. One
  test, closed over the class "op tag added but not inspectable".
- **Render refactor safety**: render.rs's existing unit tests
  (render.rs:986-1157) run unchanged over the extracted module; they pin lane
  attribution, notable detection, aggregation banner, and metadata genericity
  through the move.
- **Divergence-class tests**: hand-built bundle pairs proving each diff class
  (operation-mismatch, outcome-mismatch, length, metadata-only,
  identical→exit 0) and the context window edges (divergence at seq 0, at
  end).
- **Filter tests**: each filter alone plus composition subset properties
  (`--kind X --seq A..B` ⊆ each alone); `--first`/`--last` exclusivity;
  unknown `--kind` token usage error.
- **Registry gates**: the extended `accepted_flags`/grammar/index tests (§8)
  are themselves the drift protection.
- **e2e round-trip** (`crates/cargo-patina/tests/end_to_end.rs`, which already
  records WASI, native, and cargo-family traces): for a freshly recorded trace
  of each family — `info` counts equal the run envelope's
  `trace.event_count`; unfiltered `events` line count equals `info`'s count;
  every JSONL line parses; `stats` totals match; `diff trace trace` → exit 0
  "identical"; `diff` across two seeds → exit 1 with a `root_seed` metadata
  delta and a divergence point; a byte-truncated trace → error, exit 2, empty
  stdout; a `format_version: 99` trace → `UnsupportedVersion` message. The
  per-family e2e runs are also the living proof that the WASI op-subset
  (no task/scheduler ops) and native op-superset both flow through every
  surface — no family-specific code paths to test because there are none.

## 10. Staged plan + verification tiers

Each stage lands independently and is user-visible on its own.

1. **Stage 1 — shared layer + verb skeleton + `info`.** Extract `trace_view`
   from render.rs (render tests pin behavior); register the `trace` verb, all
   drift-gate wiring, usage strings; implement `info` (human + json). Measure
   `info` wall time on a campaign-sized trace and record it.
2. **Stage 2 — `events`** with the full filter grammar and the three new
   `Kind`s; JSONL streaming; every-op-tag gate lands here.
3. **Stage 3 — `stats`** (pure consumer of the stage-1 walk).
4. **Stage 4 — `diff`** (divergence-class tests; exit-code convention).
5. **Noted adjacency, NOT in scope** (coordinator decision hook): `trace
   render <TRACE> -o out.html` — `render_trace_file` already takes a bare
   path, so a standalone re-render of an existing trace is ~20 lines once the
   verb exists, and it would close the "can't render without re-running" gap
   in §1. Deliberately left out of the settled four-surface scope; flagging it
   because the `trace` verb grouping makes it nearly free later.

**Verification tier: CLI-only, justified.** The arc touches only
`cargo-patina` consumer-side code — zero changes to `patina-trace`, the
runtime, shims, scheduler, or any record/replay path, so no replay hash, no
interposition surface, and no guest-visible behavior can move. Per the
established tiered-verification policy (full battery only for runtime-touching
work), the landing gate is: fmt + clippy + `cargo test -p cargo-patina` (unit
+ both e2e runs in the battery log) + the mise check ladder. The render.rs
refactor is the only shared-surface edit, and it is covered by the existing
render unit tests plus the e2e `--render`/`--report` runs already in the
battery. No Linux 8-gate round needed; the first runtime-touching wave after
this arc picks the new surfaces up in its full battery for free.

## 11. Non-goals

- Trace *editing* or re-serialization (minimize owns mutation).
- Alignment/resync diffing (LCS) — see §5.4.
- Lenient decoding of corrupt traces — see §7.
- Per-subcommand `--help` topics (first real registry-shape change; not needed
  at four subcommands).
- Cross-version tolerance beyond the existing migration chain (strict load is
  the oracle, same as replay).
