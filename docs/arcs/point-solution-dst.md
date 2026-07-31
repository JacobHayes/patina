# Arc: point-solution DST — deep exposure for a slice of a project

Status: design approved 2026-07-30; implementation not yet scheduled.
Lands as `docs/arcs/point-solution-dst.md`.

Patina today is strongest as a whole-program instrument: build a binary, sweep
seeds, run campaigns overnight. This arc makes it a **point solution** — deep,
targeted deterministic exposure for one algorithm, one snippet, one test — that
lives inside the normal dev/agent iteration loop (seconds, not a nightly CI
job). Three deliverables, one phase-2 boundary sketch:

1. `#[patina_dst::test]` — an attribute macro that makes a fn a DST test under
   plain `cargo test`.
2. Tool-agnostic agent skills in `docs/skills/` (no `.claude/`-specific
   artifacts).
3. Source-first polish for the `cargo patina run script.rs` tight loop.
4. Boundary sketch only (deliberately unscheduled): `patina-dst-harness` as an
   embeddable fixture library. (Skills, item 2, run as a separate final pass
   after all arcs land — see Wave C.)

## Decision summary

| # | Decision | Choice |
|---|---|---|
| D1 | Attribute name & host crate | `#[patina_dst::test]`; proc macro in new `patina-dst-macros` (dir `crates/patina-macros`), re-exported by `patina-dst` behind a default-off `macros` feature |
| D2 | How the fn body becomes the guest | Rebuild the **same test target** shim-linked and run it with a libtest `--exact` filter; synthesized-guest extraction rejected |
| D3 | Orchestrator-vs-guest selection | Runtime guard on `patina_dst::is_simulated()` (false in the plain build, true in the shim-linked guest) |
| D4 | CLI plumbing | Extend the `test` verb: a source-first positional selects a new native harness mode (`cargo patina test <DIR> --harness-target T --exact p::t …`); bare `test` stays the cargo family |
| D5 | Finding cargo-patina; absence | `PATINA_CLI` env override → `cargo-patina` on `PATH`; absent = **test failure** with install instructions. Never skip |
| D6 | Per-test config | Macro args map mechanically to CLI flags (`fs_crash_at = "write:3"` → `--fs-crash-at write:3`); the CLI parser is the only validator — no second flag registry in the macro |
| D7 | Defaults | Debug guest profile; `seeds = 20`, fixed range from 0; no wall-clock randomness ever |
| D8 | Failure UX | Test panic carries failing seed, exit, stderr tail, trace path, and two copy-paste repro commands; artifacts under `<target-dir>/patina/dst/…` |
| D9 | Skills placement | `docs/skills/dst-point-solution.md` + `docs/skills/dst-whole-system.md`, plain task-oriented markdown, gated by the flag-drift script |
| D10 | Source-first polish | Envelope names the source (not the dead tempdir); explore failure line gains a repro command; guest-artifact cache **deferred** (measured: not the bottleneck); no `-e` inline eval (user-rejected), no cargo-script manifest now |

## Ground truth (verified against the working tree, measured on this machine)

Mechanism facts the design stands on, checked in code and exercised end-to-end
with the built release CLI (macOS; the built binary slightly predates the
help/v2 progressive-disclosure change, so registry claims below cite source,
not the binary; timings are unaffected):

- **Interposition is link-time, not launch-time.** `run <BINARY>` execs the
  guest directly — `Command::new(&binary)` with `env_clear()` and a stamped
  `argv[0]` (`crates/cargo-patina/src/lib.rs:5699`). There is no DYLD/LD_PRELOAD
  insertion anywhere. Determinism exists only if the shim was linked in at
  build time (`--cfg patina_shim` + shim staticlib + POSIX object, injected via
  rustc args for single sources at `lib.rs:4547` and via
  `CARGO_ENCODED_RUSTFLAGS` + an explicit host `--target` for packages at
  `lib.rs:4593`). Consequence: **a running test process cannot
  retro-instrument itself**; a `#[test]` under plain `cargo test` must
  delegate to a shim-linked build of itself.
- **A shim-linked libtest harness works under the runtime today.** The `build`
  verb forwards trailing rustc args, so this already exists end-to-end:
  ```
  cargo patina build dsttest.rs --output dsttest-bin -- --test   # libtest harness, shim-linked
  cargo patina audit ./dsttest-bin                               # passes; deny-trap note for posix_spawn/waitpid/…
  cargo patina run ./dsttest-bin --seed 1 -- --test-threads=1 --exact epoch_is_seeded --nocapture
  ```
  Verified: the pre-run default-deny gate passes (libtest's process-control
  symbols are deny-trap armed, fine statically); `--exact` selection works;
  `SystemTime` reads epoch 0; `RandomState` is a pure function of the seed
  (seed 1 → ticket 977 twice, seed 2 → 976); a spawned-thread test joins
  deterministically; `PATINA_SCHEDULE_REPORT` and the vacuous-schedule warning
  flow through unchanged; `--record` + flag-free `replay` reproduce the run
  including the recorded libtest argv (replay exit 0).
- **Measured loop costs** (release CLI, warm): `run tiny.rs --seed N` =
  0.39 s wall (three identical runs; includes the no-op shim `cargo build`,
  a fresh rustc compile into a per-invocation tempdir
  (`build_on_the_fly`, `lib.rs:3941`), the audit gate, and the run).
  `run` of a prebuilt binary = 0.03 s. `explore run --seeds 20` = 0.20 s
  (~10 ms/seed; explore builds once and reuses the artifact, `lib.rs:3994`).
- **The cargo family is not full interposition.** `cargo patina test` today
  re-runs `cargo test` with `--cfg patina/dst` and the env control plane
  (`lib.rs:6171`), sets `RUST_TEST_THREADS=1` (`lib.rs:6301`), and derives all
  determinism from the runtime the package itself links; a cargo-family `run`
  of a non-integrated package is refused loudly (`lib.rs:6183`). The macro
  therefore routes through the **native** family, not this path.
- **Registry/drift machinery.** Help output is generated from the single flag
  registry in `crates/cargo-patina/src/help.rs` (schema `patina.help/v2`,
  progressive disclosure); a test-only enumeration fails on any parsed flag
  missing from the registry, and `scripts/check-flag-drift.sh` gates flag
  tokens in the listed docs. Result envelopes: `patina.result/v1`
  (`crates/cargo-patina/src/output.rs`), campaign `patina.campaign/v2`
  (`crates/cargo-patina/src/campaign.rs:52`).
- **Debug is the bug-finding profile** (README "Debug vs release guest
  builds"): `debug_assert!`/overflow checks as free oracles, denser
  yield-point windows, faster loop. Macro guests build debug by default.
- **Single-source `--release` gap (cross-reference, fix in flight).** In the
  working tree, `--release` on a single `.rs` switches only the shim
  staticlib's profile (`build_native_shim`, `lib.rs:4217`);
  `build_native_source` (`lib.rs:4547`) never receives `invocation.release`,
  so the guest itself compiles unoptimized. The package path honors it
  (`lib.rs:4642`). The in-flight fix must thread the profile into the
  single-source rustc invocation. The macro is unaffected (it uses package
  builds, and defaults to debug), but the point-solution skill must not claim
  `run --release script.rs` optimizes the guest until that lands.

## 1. `#[patina_dst::test]`

### Shape

```rust
use patina_dst::test as dst_test; // or #[patina_dst::test] directly

#[patina_dst::test]                                  // 20 seeds, debug guest
fn ledger_stays_sorted() { … ordinary std code … }

#[patina_dst::test(seeds = 200, buggify, fs_crash_at = "write:3")]
fn survives_torn_batch_commit() -> Result<(), Error> { … }
```

Runs under plain `cargo test`, in any adopter crate. Pass = every seed clean.
Fail = a plain libtest failure whose message names the seed and the repro.

### Mechanism: orchestrate, rebuild self, filter (D2, D3)

The macro expands to:

```rust
#[test]
fn ledger_stays_sorted() {
    if patina_dst::is_simulated() {
        __patina_dst_ledger_stays_sorted()          // we ARE the guest: run the body
    } else {
        patina_dst::__rt::orchestrate(&patina_dst::__rt::DstTest {
            manifest_dir: env!("CARGO_MANIFEST_DIR"),
            harness_target: env!("CARGO_CRATE_NAME"), // libtest target name
            test_path: concat!(module_path!(), "::ledger_stays_sorted"),
            cli_args: &["--seeds", "200", "--buggify", "--fs-crash-at", "write:3"],
        })
    }
}
fn __patina_dst_ledger_stays_sorted() { /* original body, original return type */ }
```

The orchestrator shells out to cargo-patina, which (new plumbing, §CLI below)
rebuilds **the same test target** shim-linked and runs it under the native
runtime with `-- --test-threads=1 --exact <libtest-name> --nocapture`
(orchestrate strips the leading crate segment from `module_path!` to form the
libtest name). Inside that guest, `is_simulated()` is true (shim FFI,
`crates/patina/src/lib.rs:117`), so the same wrapper runs the body directly.
Recursion is structurally impossible: the guard's true branch spawns nothing,
and the false branch only ever spawns via cargo-patina, which always links the
shim. The plain and guest binaries are two compilations of identical source;
no `cfg` split is needed, so no `unexpected_cfgs` noise lands in adopter
crates (the `check-cfg` declaration stays a patina-dst-internal concern,
`crates/patina/Cargo.toml`).

**Rejected: synthesized guest** (extracting the body into a generated `.rs`
built source-first). It severs the body from its crate context — imports,
helper fns, types, dev-dependencies — so anything beyond a toy fails to
compile; it creates a second compilation pipeline to keep honest; and spans/
backtraces point at generated code. **Rejected: literally re-exec'ing the
running test binary** — it has no shim linked (ground truth above), so it
would be a plain run wearing a DST costume; exactly the silent no-op the
fail-closed doctrine exists to kill.

### CLI plumbing: the `test` verb grows a native harness mode (D4)

Bare `cargo patina test [CARGO OPTIONS]` stays the cargo-family passthrough.
A source-first positional selects the new mode — the same inference doctrine
`run`/`audit`/`replay` already follow:

```
cargo patina test <DIR|Cargo.toml> --harness-target NAME --exact MOD::PATH::fn
    [--seed N | --seeds N] [--release] [--yield-points]
    [FAULT / BUGGIFY / SCHEDULE / LIVENESS OPTIONS]   # existing flag groups, reused
```

Steps, all existing machinery re-composed:

1. **Build the harness shim-linked**: `cargo test --no-run
   --message-format=json` with the exact `CARGO_ENCODED_RUSTFLAGS` + explicit
   host `--target` recipe of `build_native_package` (`lib.rs:4593`) — the
   explicit target keeps shim link args off build scripts and proc macros,
   and keeps the shim-linked artifacts in a separate `target/<triple>/` cache
   layer so the plain `cargo test` cache is never thrashed. Select the
   compiler-artifact whose target name matches `--harness-target` and whose
   profile is `test` (covers lib unit harnesses, integration tests, and bin
   harnesses; doctests out of scope). `--yield-points` reuses the existing
   sancov flag injection.
2. **Stage it** at `<target-dir>/patina/dst/<pkg>/<harness>/guest` — a stable,
   `cargo clean`-able, gitignored home, so traces recorded against it replay
   without a rebuild.
3. **Sweep** `--seeds N` through the existing native explore path (build once,
   run many; pre-run default-deny gate applies to the harness binary — wave A
   pins its audit surface in a test so libtest drift is caught by the battery,
   not by users).
4. **On first failure**: re-run the failing seed with `--record` into the same
   directory (determinism makes the re-record exact), then emit the failure
   block and a JSON envelope (explore/campaign envelope machinery; carries
   per-seed classes, the failing seed, trace path, and repro strings).

Registry rows for `--harness-target`/`--exact`/`--seeds`-on-`test` are added
to `help.rs`; the structural drift gate and `check-flag-drift.sh` make
skipping that a test failure. README / USAGE-MODES / TUTORIAL / llms.txt
updated in the same change (doc drift is a bug per AGENTS.md).

### Finding cargo-patina; absence is a failure (D5)

Resolution order: `PATINA_CLI` (absolute path override, e.g. CI) →
`cargo-patina` on `PATH`. Absent or version-incompatible (unknown flag → CLI
usage error): the test **fails** with the message naming both remedies. Never
a skip: a skipped DST test is a vacuous pass — "N tests green" silently
meaning "nothing was tested" is the exact failure class Patina's own
vacuous-schedule diagnostic exists to prevent. Teams that want DST tests
optional can gate them with ordinary `#[cfg_attr]`/`#[ignore]` visibly in
their own tree.

### Per-test config (D6, D7)

Macro args are transliterated mechanically (`ident = "value"` →
`--ident-with-hyphens value`; bare `ident` → switch) and validated **only** by
the CLI's parser against its registry — the macro carries no flag table, so
there is nothing to drift; an unknown or malformed arg surfaces as the CLI's
usage error inside a loud test failure. Typed conveniences: `seed = N`
(single), `seeds = N` (sweep, default 20 from seed 0), `release`,
`yield_points`. The seed range is **fixed**: no time-derived seeds under
`cargo test`, ever — a failure is always reproducible by re-running the test.
Broader exploration belongs to the CLI/campaign tier, not test-time
randomness. Guest env is scrubbed (`env_clear`, ground truth): DST test
bodies must not read host env — documented, and naturally fail-closed (reads
see nothing).

### Failure UX and artifacts (D8)

```
patina dst test failed: my_crate::ledger::ledger_stays_sorted
  seed 137 of 0..200  exit=101  class=BUG
  trace:  target/patina/dst/my-crate/my_crate/ledger_stays_sorted/seed-137.patina
  stderr tail:
    thread 'main' panicked at src/ledger.rs:88: PATINA_ALWAYS violated: ledger-sorted
  reproduce:
    cargo patina test . --harness-target my_crate --exact ledger::ledger_stays_sorted --seed 137
    cargo patina replay target/patina/dst/my-crate/my_crate/ledger_stays_sorted/guest \
        target/patina/dst/my-crate/my_crate/ledger_stays_sorted/seed-137.patina
```

The panic payload is the whole block, so plain `cargo test` output (and any
agent reading it) contains the seed and both repro commands. `--record`
sidecars (downgraded-symbol qualifications) land beside the trace. Editing the
test source changes the guest, so an old trace fails closed on the fingerprint
— expected; artifacts are per-checkout scratch, retained one failing trace per
test (overwritten on the next failure). Diagnostics (`PATINA_SCHEDULE_REPORT`,
vacuous-schedule warning) pass through on failure output; on success they are
libtest-captured like any test output — parity with the CLI (warning, not
failure); a strict `deny_vacuous` knob is a possible follow-up, not v1.

Cost model (measured): one warm no-op harness rebuild per crate per `cargo
test` invocation (cargo's file lock serializes concurrent orchestrators; warm
no-op observed at ~0.1 s scale) + ~10–30 ms per seed for small guests — a
20-seed default adds well under a second per test.

### Crate hosting (D1)

New proc-macro crate `patina-dst-macros` (directory `crates/patina-macros`,
matching the published-name scheme and the directory convention that drops
`-dst-`). **Zero third-party deps** — the expansion needs only the fn name,
signature passthrough, and `ident = literal` attribute args, all hand-rollable
on `proc_macro` token trees; `syn`/`quote` are not worth the compile-time tax
given the SDK's dependency-free doctrine (revisit only if the surface grows).
`patina-dst` gains a default-off `macros` feature re-exporting the attribute
plus the std-only `__rt::orchestrate` helper (uses `std::process::Command`;
still zero external deps). Adoption pattern:

```toml
[dependencies]     patina-dst = "…"                          # inert SDK, no macros
[dev-dependencies] patina-dst = { features = ["macros"] }    # tests only
```

Feature unification confines the proc macro to test builds; a plain `cargo
build` of the adopter links nothing new. Proc macros never enter the guest
binary, so the runtime stays unbloated by construction.

## 2. Agent skills — tool-agnostic (D9)

Placement: `docs/skills/`, plain markdown, **no** `.claude/skills` artifacts —
usable verbatim by any agent framework (each can point its own skill index at
these files) and by humans. Format per file: a one-line "use when" header, a
task-oriented numbered loop with exact commands, a "reading the output"
section naming the envelope schemas and load-bearing fields, and a verify step
(laddered-loop doctrine). Both files join the `DOCS` list in
`scripts/check-flag-drift.sh` so every flag token they mention is gated
against the registry; both get llms.txt and README links for discoverability.

**`docs/skills/dst-point-solution.md`** — the tight loop this arc exists for.
Teaches: write a snippet as a plain-std `.rs` (or fn + `#[patina_dst::test]`);
`cargo patina run snippet.rs --seed N --format json`; read `patina.result/v1`
(`result`, `exit_code`, `stdout`/`stderr` are inline — no file juggling);
sweep with `explore run --seeds N` (build-once semantics, per-seed outcomes,
stops at first failure); turn knobs (`--fs-crash-at`, `--net-drop-permille`,
`--sleep-jitter-nanos`, `--buggify`); record the failing seed, `replay`
flag-free, `minimize` against an oracle; escalate to a package directory when
the snippet needs dependencies (single `.rs` is rustc-only — three-command
scaffold shown); graduate to `#[patina_dst::test]` when the snippet should
keep guarding the tree. Debug-profile doctrine stated up front.

**`docs/skills/dst-whole-system.md`** — whole-program adoption. Teaches:
`build` shim-linked + `audit` residual reading (deny-trap notes,
`--allow-unsupported-symbols` as the loud hatch); seed sweeps vs `campaign`
(gens, seven-class outcomes, signature dedup, `patina.campaign/v2` envelope,
per-failure repro commands); buggify/`always!`/`sometimes!` SDK adoption and
`PATINA_SDK_REPORT`; `--yield-points` + vacuous-schedule reading; record/
replay/branch triage and `--render` HTML; the three usage modes and when each
applies; CI wiring (nightly campaign + per-PR dst tests as the two tiers).

The arc doc deliberately enumerates rather than drafts these: the skills are
wave-C implementation artifacts written against the then-current CLI, keeping
them out of drift's reach until they can be gated.

## 3. Source-first polish (D10)

Verified current path: `run script.rs` → `build_on_the_fly` (`lib.rs:3941`) →
shim staticlib no-op rebuild + content-addressed shim objects
(`stage_shim_object`, `lib.rs:4439`) → single rustc compile into a
per-invocation tempdir → audit gate → run, with a `PATINA_BUILD_ON_RUN` note
(source, artifact, sha256) routed to stderr under `--format json`. Measured
warm: **0.39 s** end to end.

Findings and minimal fixes:

- **Rebuild latency is not the bottleneck** at 0.39 s warm; a
  content-addressed guest cache (modeled on `stage_shim_object`) would cut
  unchanged re-runs to ~0.05 s but helps only the run-again-same-source case
  that `explore`/`campaign` already solve by building once. **Deferred**, with
  these numbers recorded as the baseline to revisit against.
- **Envelope names a dead path** (verified: `"artifact":
  "/private/tmp/.tmp…/patina-run-artifact"`, gone at process exit). Fix: for
  built-on-the-fly guests the envelope's `artifact` becomes the source/display
  path with the sha256 alongside (both already computed for the build note) —
  an agent can key results and cache decisions on it.
- **Explore failures lack a repro string**: `PATINA_EXPLORE_FAILURE seed=N
  exit=E` (`lib.rs:4039`) makes the reader assemble the command campaign
  already hands out. Fix: append `repro="cargo patina run … --seed N"` to the
  line and the envelope.
- **Dependencies need a package** — inherent to the rustc-only single-source
  path; handled by teaching the escalation in the skill, not by new surface.
  Explicitly rejected: `-e '<code>'` inline eval (user decision) and a
  cargo-script-style embedded manifest for now (new parse surface plus
  lockfile/determinism questions; revisit only on demonstrated demand).

## 4. Boundary sketch: harness fixtures (unscheduled — see staged plan)

`patina-dst-harness` already supports deferred init (`--harness` →
`PATINA_DEFER_INIT`, `lib.rs:5713`; USAGE-MODES mode 2): a binary configures
the run in code, then executes under full interposition. Phase 2 embeds that
as a **fixture** in another program's tests: `#[patina_dst::test(harness)]`
runs the body inside `patina_dst_harness::run_with(|h| …, body)` so per-test
config (step budgets, fault knobs, mini simulated worlds, shared
world-building helpers) moves in-code, with the CLI passing `--harness` on
the guest run. The load-bearing boundary: **phase 1 is whole-test-binary
guests with CLI-side config; phase 2 is in-code per-test config over the same
launch path** — no new runtime mode, the deferred-init machinery already
exists, and its fail-closed edges (effect-before-install aborts, double
install, harness-outside-patina) are already enforced. Everything else about
phase 2 (fixture API shape, config layering vs record/replay fingerprints) is
out of scope until phase 1 has users.

## Staged plan and verification

Tiering per the coordination policy: full battery at wave boundaries and for
runtime-touching changes; Linux 8-gate runner per wave; measured (not
estimated) timings in battery logs; two e2e runs per battery.

**Wave A — CLI plumbing** (`test` native harness mode; explore repro string;
envelope artifact fix). Deliverables: harness-target build via `cargo test
--no-run` + encoded rustflags; staging dir; seed sweep + record-on-failure +
envelope; registry rows + help JSON; README/USAGE-MODES/TUTORIAL/llms.txt.
Verify: mise check ladder (one landing command); registry drift tests +
`check-flag-drift.sh`; **acceptance pins**: libtest-harness audit surface
enumerated, seeded determinism through a filtered libtest run (double-run
byte-identical), record/replay of a filtered run, refusal messages for a
missing harness target; two e2e runs; Linux 8 gates (launch-surface
adjacent); the three validation scripts at the wave boundary per the
shim/runtime battery rule.

**Wave B — macro crate** (`patina-dst-macros`, `macros` feature,
`__rt::orchestrate`). Deliverables: hand-rolled attribute, name mapping
(module_path → libtest name), CLI discovery + fail-closed absence, failure
block. Verify: macro unit tests; a `testbeds/` adopter crate whose
`#[patina_dst::test]` tests run under **plain `cargo test`** in the battery
(one passing, one seeded-failure asserting the panic message carries seed +
both repro commands, one PATH-scrubbed run asserting the absence failure);
double-run identical; MSRV 1.86 build of the new crates; no new deps
(`cargo tree` asserted in the battery).

**Wave C — skills + links** (two skill docs, drift `DOCS` list, README/llms.txt
links). Verify: `check-flag-drift.sh` (including its `--selftest`), every
command in both skills executed once against the built CLI with output pasted
into the battery log. **Sequencing (user, 2026-07-30): this wave runs as a
separate FINAL pass after all the other arcs have landed**, so the skills teach
the finished surface (sites/coverage/trace verbs, fault knobs, --extend) rather
than a snapshot that goes stale a week later.

Harness fixtures (the §4 sketch) are deliberately NOT scheduled (user call,
2026-07-31): likely possible over the existing `--harness`/`PATINA_DEFER_INIT`
path, but it is the one item with no concrete consumer and real
config-vs-fingerprint design risk — cut per no-cruft until a real need appears.
The §4 boundary sketch stays as the record of how it would slot in.

## Open questions for review

1. `seeds = 20` default — right magnitude for a per-PR gate? (10 ms/seed
   measured on toy guests; real guests will be slower.)
2. v1 macro-arg surface: typed `seed`/`seeds`/`release`/`yield_points` plus
   mechanical passthrough — trim further, or is passthrough itself too broad
   for v1?
3. Vacuous-schedule under the macro: parity-with-CLI warning (proposed) vs
   fail-the-test strictness.
4. `--exact`'s spelling on the `test` verb (`--exact` mirrors libtest;
   `--filter` mirrors nothing; staying with `--exact` unless review objects).
