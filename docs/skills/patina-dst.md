# Skill: deterministic simulation testing with Patina

**Use when** you want a Rust program, package, test, or snippet to fail the same
way every time — reproducing a flaky bug, hunting for one under injected faults,
or turning a found bug into a permanent guard.

This is a guidance skill, not a reference. It explains what Patina is, what it
can do, and **how to find out the exact current surface for yourself**. It
deliberately names almost no flags: the CLI's own generated registry is the only
correct source for those, and this document teaches you to query it. Everything
here is tool-agnostic — plain markdown, usable by any agent framework or human.

## What Patina is

Patina runs ordinary `std` Rust under a cooperative scheduler, a virtual clock,
an in-memory filesystem, and a simulated network, so **a run is a pure function
of its seed**. Two runs at the same seed produce the same bytes; a different seed
produces a different, equally reproducible world.

Three things follow, and they shape everything else:

- **The seed is the input.** Thread interleavings, `HashMap` iteration order,
  clock readings, entropy, and injected faults all derive from it. "Hunting for a
  bug" means searching seed space; "reproducing a bug" means naming its seed.
- **It fails closed, loudly.** There is no host fallback. An effect Patina does
  not model is a refusal or a named abort, never a silent escape to the real OS.
  A confusing refusal is usually the system working.
- **A run can be recorded and replayed byte-for-byte.** The trace carries its own
  seed and fault configuration, so replay needs no flags, and a divergence
  between record and replay is itself a reported failure.

Interposition is **link-time, not launch-time**: determinism exists because the
shim was linked in when the guest was built. A process already running cannot
retro-instrument itself, which is why the point-solution test path rebuilds the
test binary rather than wrapping the current one.

Three artifact families, inferred automatically from what you hand a verb: a
**Cargo package/test** (directory or `Cargo.toml`, run in-process), a **native
binary** (Mach-O/ELF, linked against the shim), and a **WASI module**
(`wasm32-wasip1`). Some capabilities are family-specific — the registry tells you
which, see "Families" below.

## What it can do — the capability map

Broad strokes only — the verbs are the stable spine, the flags under them are
not. Get the current spelling of anything here from the CLI.

**Execution and reproduction.** `build` produces a deterministic artifact; `run`
executes one at a chosen seed and can record a trace; `replay` reproduces that
trace, needing no flags because the trace is authoritative; `trace` inspects a
recording offline — metadata, filtered events, aggregates, or a two-trace diff —
without executing anything. `test` runs the Cargo family under Patina, and in its
source-first form rebuilds one libtest target shim-linked to sweep a single exact
test. A run with a trace can be rendered to a self-contained HTML timeline.

**Search.** `explore` sweeps a seed range over one artifact, building once and
stopping at the first failure. `campaign` is the heavier instrument: a
config-driven fault-and-schedule sweep where every generation's seed and knobs
are a pure function of the generation number, with outcome classification,
novel-failure deduplication with saved traces, per-failure repro commands, and
accumulated coverage. `minimize` shrinks a failing trace, or the seed and
parameters that trigger a failure, against an oracle.

**Fault domains** (all seed-driven, off by default, and recorded into the trace
so replay reproduces them): filesystem crashes at a chosen operation and ordinal,
write tearing, I/O errors, short writes, and latency; network drop, latency, and
jitter; name resolution failure and latency; sleep jitter; scheduler preemption
and task starvation; liveness watchdogs. A *swarm* mode deselects a seeded subset
of the enabled fault classes per run, so a sweep varies which faults are in play
rather than always running all of them. Which of these a given verb and family
accept is registry-defined — do not assume.

**The SDK** (`patina-dst`, used as `patina_dst::` in code) instruments a
system-under-test from the inside, and every macro compiles to a no-op outside
Patina so adopters pay nothing in production builds:

- `buggify!` and friends — FoundationDB-style rare-path activation: a branch that
  fires only sometimes, only under simulation, deterministically per seed. This
  is how you make your own code cooperate with the fuzzer.
- `always!` — a fatal invariant; a violation aborts the run with a marker.
- `sometimes!` and `reachable!` — coverage oracles. A campaign **fails by
  default** when a declared site never fired, which is what stops a sweep from
  passing vacuously; waiving that is explicit.
- `rng()` for seed-bridged entropy, `is_simulated()` to branch on the runtime.

**Visibility into whether the search actually searched.** Inert knobs are treated
as bugs here. `sites` is a static inventory of every assertion/oracle site in the
workspace, and can be joined against what a run or campaign actually exercised.
Native binaries can be built with yield-point instrumentation so atomics-only
race windows become schedulable, and `coverage` symbolizes their edge coverage
and rolls it up by crate/module/function; WASI runs report execution *depth*
(fuel and per-import hostcall counts) as the analogous signal. The scheduler
warns when a spawned thread ran zero interposed operations — that is, when its
interleavings were never actually explored.

**`audit`** reports the true post-interposition residual effect surface of a
binary under a default-deny allowlist. Any un-interposed effect symbol is a
finding. This is the gate that keeps "deterministic" honest — and it runs before
every native run, so a guest reaching an unmodeled effect is refused rather than
quietly escaping.

## Which loop are you in

**Point solution — one algorithm, one test, seconds per iteration.** Write the
thing you want to stress as a plain `.rs` file or an ordinary Rust test. The
`run` verb is source-first: hand it a `.rs` file, a directory, or a `Cargo.toml`
and it builds through the same pipeline first. Sweep seeds; when one fails,
record it, replay it, and inspect the trace. Once the snippet needs dependencies,
promote it to a package directory — a single `.rs` is compiled by rustc alone.
When the finding should keep guarding the tree, graduate it to
`#[patina_dst::test]` (the SDK's default-off `macros` feature, a dev-dependency):
it runs under plain `cargo test`, rebuilds the same libtest target shim-linked,
sweeps seeds, and panics with the failing seed and copy-paste repro commands.
Build **debug**, not release — `debug_assert!` and overflow checks are free
oracles, and yield-point windows are denser.

**Whole system — a real program, minutes to overnight.** Build the binary
shim-linked and read its audit residual before trusting any result. Instrument
the system-under-test with the SDK. Sweep seeds first; move to a campaign when
you want fault shapes varied for you, failures deduplicated, and coverage
accumulated. Wire two CI tiers: point-solution tests per PR, a campaign nightly.

`USAGE-MODES.md` describes the three adoption levels (transparent SDK-only,
shim-backed harness, explicit-context simulator) and which crate each needs.

## How to learn the current surface

**The generated registry is the truth. Never write a flag from memory, from an
old transcript, or from another document — including this one.** Flags have been
renamed; help text and the parsers are both generated from one registry, and a
gate checks every flag token in the project's docs and shell scripts against it.
Four commands cover essentially everything.

**1. Start at the index.** It lists every verb with its summary and usage forms,
the global flags, and the environment protocol:

```sh
cargo patina --help                    # human
cargo patina --help --format json      # machine-readable (schema patina.help/v2)
```

The JSON index is progressive-disclosure: it carries **no per-verb flag rows** by
design. It tells you how to get them — read `.verb_detail.command_template`,
which is literally the drill-down command to run.

**2. Drill into one verb.** This is where flags live:

```sh
cargo patina <verb> --help                    # human
cargo patina <verb> --help --format json      # full flag detail for that verb
```

The payload is under `.verb`: `forms` (usage shapes), and `flag_groups[]`, each
with a `title`, an optional `families` list, and its flag rows. Every row carries
`name`, `doc`, and `value_kind` (`required`, `optional`, or `none`); most add
`placeholder` and `value_grammar`. **Everything else default-omits**: an absent
field means none or false, so treat a missing `short` or `repeatable` as "no",
not as "unknown".

Three things there are worth reading deliberately rather than skimming:

- **Families.** An absent `families` means every family accepts it. A present
  list is exhaustive — the flag is refused, by name, anywhere else. It can appear
  on a group or on a single row that narrows its group.
- **`requires`.** A row carrying `requires` is *inert on its own*; it only does
  something alongside the flag it names. Setting one without its partner is a
  silently ineffective run, which is exactly the failure mode this project treats
  as a bug.
- **`choices`.** When present it enumerates the legal values. Read it instead of
  guessing at a value spelling — the same discipline as for flag names.

Useful shapes to fold into your own queries:

```sh
cargo patina --help --format json | jq -r '.verbs | keys[]'
cargo patina <verb> --help --format json |
  jq -r '.verb.flag_groups[] | "\(.title) [\((.families // ["all"]) | join(","))]"'
cargo patina <verb> --help --format json |
  jq -c '[.verb.flag_groups[].flags[] | select(.requires) | {name, requires}]'
```

**3. Read the environment registry** for the observability and control-plane
variables. Each entry has a `scope`; filter to `user` to separate the knobs you
may set from the internal supervisor protocol that is listed only for
transparency:

```sh
cargo patina --help --format json | jq -r '.environment[] | select(.scope=="user") | .name'
```

**4. Let refusals teach you.** The CLI does not accept a flag it will ignore. A
misspelling is refused with the nearest real flag suggested; a wrong-family flag
is refused by name with the reason; both print the verb's usage forms and exit
**2**. A refusal is cheaper than a search, and reading it is a legitimate way to
learn the surface.

**Beyond the CLI:**

- `llms.txt` — the compact machine-oriented map of the whole CLI and SDK: verbs,
  fault domains, output schemas, SDK macros, and the report markers, in one file.
  Read it once at the start of a session; use the registry for exact spellings.
- `TUTORIAL.md` — the end-to-end walkthrough: instrument a program, sweep seeds,
  catch a planted bug, replay it, render the timeline. Every command in it is
  verified.
- `testbeds/` — real working guests, each with a runnable script. The closest
  thing to a worked example of your own situation.
- `ARCHITECTURE.md`, `INTENTS.md`, `VALIDATION.md` — how it works, what it
  refuses to be, and what is actually proven versus merely claimed.
- Repository config lives at `.patina/config.toml` and can supply per-verb
  defaults; its keys are registry-backed flag names. Precedence and the way an
  applied config announces itself are documented in `README.md`.

## Reading what comes back

Three channels, and they are a stable contract even as flags move.

**Exit code.** `0` is clean. A nonzero exit is the guest's own exit code — except
`2`, which is a CLI-side error (bad flags, build failure, refused replay).

**stdout, machine-readable on request.** Every execution verb accepts
`--format json`; it usually prints exactly one result envelope (schema
`patina.result/v1`) carrying at least `schema`, `verb`, `result`
(`ok`/`violation`/`failure`/`error`), and `exit_code`, plus whatever applies to
the run: family, artifact, seed, fingerprint, captured guest output, extracted
markers, trace metadata, coverage or depth. A few report verbs emit their own
schemas instead. Prefer JSON whenever you are parsing rather than reading — and
discover an envelope's real fields by running the command once and inspecting the
output, not by trusting a field list.

**stderr, the `PATINA_*` markers.** End-of-run reports are the project's
observability contract: scheduling, swarm selection, liveness, SDK sites,
per-domain fault activity, coverage, and depth each emit a marker line. They are
**on by default** and each is silenced by setting its own variable to a false-y value.
Suppression is presentation only — it changes no recorded byte and no
fingerprint, so a quiet run and a loud one replay against each other. A campaign
pins them all on, because there they are classifier inputs rather than cosmetics.

Read these reports. A clean pass with a fault knob that never fired, or a spawned
thread that never yielded, is a **vacuous** result, and the reports are how you
tell that apart from a real green.

## Guest patterns that survive the runtime

Hard-won from dogfooding real storage engines under Patina; each avoids a
class of confusing first-run failures.

- **Static constructors run before the runtime exists.** A `#[ctor]`-style
  initializer that touches an interposed surface (tracing setup, env reads,
  sockets) fails closed with a pre-init diagnostic naming the symbol. The
  pattern: compile the constructor out under your DST cfg and initialize
  explicitly from `main`.
- **Vary workloads from the deterministic RNG, never argv.** Campaigns hold
  guest arguments constant across generations by design — argv is identity, not
  exploration. Derive per-run workload shape (seeds, paths, sizes) inside the
  guest from the runtime's entropy; every generation then explores differently
  while staying replayable from its trace alone.
- **The guest environment starts empty.** Nothing leaks in from the host. If a
  run needs a variable (`RUST_BACKTRACE=1` is the common one), inject it
  explicitly through the run verb's env-injection flag — it becomes part of the
  recorded, replayable run.
- **Durability claims require parent-directory fsync.** The crash model loses
  namespace operations (create/rename/link) that were not made durable by an
  fsync of the parent directory — faithfully to real filesystems. A harness or
  storage layer that skips parent-dir sync will see crash sweeps "lose" files
  it considered written; that finding is about the code, not the model.
- **Audit output that can fail after injected faults must not `expect()` or
  swallow.** Fault injection reaches every filesystem read your oracle makes;
  an `unwrap` turns an injected error into a panic, and an error-swallowing
  probe (`Path::exists()` is the classic) turns one into a false verdict.
  Oracles read truth or fail closed, loudly.

## Doctrine worth carrying

These outlast any flag rename.

- **Detection before fixes.** A new bug class gets a detector that provably fires
  — red before, green after — not just a point fix.
- **Determinism is verified, not asserted.** The standard evidence is
  byte-identical repeats, record/replay identity, and variation across seeds. A
  check that cannot fail is treated as a bug.
- **Inert knobs are bugs.** If you turn something on, confirm from the reports
  that it fired.
- **No permissive fallbacks.** If Patina refuses an effect, model it, interpose
  it, or accept the refusal. Do not reach for an escape hatch to make a run go
  green; the hatches that exist are explicit, narrow, and fingerprinted.
- **Debug is the bug-finding profile.**

## Verify you have it right

A two-minute check that the whole path works on this machine, using nothing but
a scratch file:

```sh
cat > /tmp/snippet.rs <<'EOF'
use std::collections::HashMap;
fn main() {
    let m: HashMap<u32, u32> = (0..8).map(|i| (i, i * 3)).collect();
    println!("order={:?}", m.keys().copied().collect::<Vec<_>>());
}
EOF

cargo patina run /tmp/snippet.rs --seed 7    # note the order
cargo patina run /tmp/snippet.rs --seed 7    # identical — determinism
cargo patina run /tmp/snippet.rs --seed 8    # different — seed variation
cargo patina audit /tmp/snippet.rs           # the residual effect surface
cargo patina explore run /tmp/snippet.rs     # a seed sweep
```

`HashMap` iteration order is the cheapest visible proof: normally randomized per
process, under Patina it is a pure function of the seed. If the two seed-7 runs
disagree, stop and fix that before trusting anything else.
