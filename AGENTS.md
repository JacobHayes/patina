# Agent Guidance

This repository contains **Patina**: an experimental deterministic execution and
simulation-testing (DST) runtime for Rust. Read this file before changing
anything; it tells you where truth lives and which gates must stay green.

## Document map

| Document | Read it for |
|---|---|
| [INTENTS.md](./INTENTS.md) | goals, non-goals, trade-offs, design principles |
| [docs/SCOPE.md](./docs/SCOPE.md) | who Patina serves first, the rules new surface must meet, where evidence comes from, the platform policy; cite it when proposing new surface |
| [ARCHITECTURE.md](./ARCHITECTURE.md) | crate boundaries, targets, drivers, traces, the native shim, the WASI host — the source of truth for system shape |
| [VALIDATION.md](./VALIDATION.md) | capability acceptance gates (V0–V7), required evidence, the gate taxonomy |
| [IMPLEMENTATION.md](./IMPLEMENTATION.md) | completed and planned implementation slices |
| [USAGE-MODES.md](./USAGE-MODES.md) | the three adoption levels and the crate map |
| [README.md](./README.md) | the user-facing summary; must stay honest about status |
| [TUTORIAL.md](./TUTORIAL.md) | the command-by-command walkthrough (every command verified) |
| `llms.txt` | compact machine-oriented CLI/SDK map |
| [docs/skills/patina-dst.md](./docs/skills/patina-dst.md) | the tool-agnostic agent skill handed to agents *using* Patina: what it is, the capability map, and how to discover the current surface from the generated registry. Deliberately near-flagless — keep it that way; teach the discovery method, not a flag catalog |
| [docs/agent-operations.md](./docs/agent-operations.md) | shared agent operating rules: verification, delegation, non-vacuity, cross-platform evidence |
| [crates/patina-target/ESCAPE-CLASSES.md](./crates/patina-target/ESCAPE-CLASSES.md) | the guest-escape taxonomy behind the audit gate |
| [testbeds/README.md](./testbeds/README.md) | the dogfooding guests and their conventions |
| Nearest `AGENTS.md` files | focused guidance for high-risk subtrees such as the native shim and testbeds |

**When changing intent, architecture, or user-visible behavior, update the
relevant docs in the same change.** Doc drift is treated as a bug; part of it is
mechanically gated (see below). If `AGENTS.local.md` exists, read it for local
maintainer recipes; it is gitignored and is not project doctrine.

## The CLI: verbs, and where its truth lives

`cargo patina` is verb-first: `build`, `run`, `test`, `audit`, `replay`,
`explore`, `campaign`, `coverage`, `sites`, `trace`, `minimize`, `syscalls`. Verbs infer the artifact family (Cargo
package / native binary / WASI module) from the argument; `run`, `audit`, and
`replay` are source-first (a `.rs` file, directory, or `Cargo.toml` builds on
the fly).

Never guess flag names — the CLI has gone through renames. The authoritative
registry is `crates/cargo-patina/src/help.rs` and its `help/` modules, and it is the single source for
both halves of the CLI: the help/JSON/usage text AND the parsers themselves
(`cli.rs` builds each verb+family's `clap::Command` from the same rows). A flag
the help omits cannot be parsed, and one it advertises cannot be rejected.

```sh
cargo run -q -p cargo-patina -- patina --help                    # human
cargo run -q -p cargo-patina -- patina --help --format json      # machine-readable index (verbs + global flags + env)
cargo run -q -p cargo-patina -- patina run --help                # per-verb human help
cargo run -q -p cargo-patina -- patina run --help --format json  # per-verb machine-readable flag detail
```

The JSON is progressive-disclosure (schema `patina.help/v2`): the bare `--help`
index lists each verb's summary and forms but no flag rows; per-verb detail
(flag_groups) comes from `cargo patina <verb> --help --format json`. Flag fields
default-omit — an absent `short`/`value_grammar`/`repeatable` means none/false.

A verb's forms are its **families** (`cargo`/`wasi`/`native`, the `trace`
subcommands, …), chosen at routing time from the artifact's magic bytes or a
subcommand token. Each group carries a `families` array naming the forms that
accept it, and a flag narrower than its group repeats the array — so
`run --help --format json` says outright that `--fuel` is WASI-only and
`--budget` is Cargo-family-only. A dependent flag carries `requires` (e.g.
`--sched-pct-steps` requires `--sched-pct`). A flag supplied to the wrong family
is refused by name, not as an unknown option.

Every execution verb also accepts `--format json`, usually emitting one
`patina.result/v1` envelope on stdout; verb-specific report verbs may emit their
own schemas (for example `coverage --format json` emits `patina.coverage/v1`).
Prefer JSON when parsing results programmatically.

## Check ladder (run before claiming done)

With [mise](https://mise.jdx.dev/) (one-time `mise run setup` installs
the pinned Rust toolchain, components and targets from `rust-toolchain.toml`):

- `mise run check:fast` — the inner-loop tier: fmt, clippy (host +
  cross-target `x86_64-unknown-linux-gnu` for Linux-cfg code,
  `aarch64-unknown-linux-gnu` for arm64 Linux, and `aarch64-apple-darwin` for
  Darwin-cfg code), every workspace
  test except `cargo-patina`'s `end_to_end` and seven native execution targets
  (syscall conformance among them), the cheap classifier selftests, CLI flag drift,
  toolchain pin drift, WASI validation, and cross-target smoke. It is designed to
  give ordinary edits an honest signal quickly, but it is not landing evidence.
- `mise run check` — the local pre-landing battery: the cheap checks above,
  docs, packaging, the `patina-dst` macros feature test, the full pinned workspace
  test suite including `end_to_end`, native acceptance tests and the syscall
  conformance scenarios, WASI/cross smoke, and the workq/pubsub/macro-adopter
  and FIFO/rustix-default/cap-std testbeds. Cheap failure checks run first; the e2e-heavy workspace test rung runs
  alone; independent runtime/testbed rungs then overlap. The runner prints
  one overall result and a retained log directory (commands and per-rung timings),
  suppresses successful command chatter, and replays a failed rung's complete log. **This is the local landing gate.** CI/final gates add
  the audit corpus.
- `mise run smoke`, `mise run audit-corpus`, `mise run demo` — individual pieces.

Rust is pinned in `mise.lock`; `mise.toml` uses `latest` so deliberate lockfile
updates can advance it. `rust-toolchain.toml` mirrors the exact version for
rustup users. `scripts/check-toolchain.py` checks both pins and the active
compiler; its selftest plants drift in each file. Fast/full checks and every CI
job run it. Setup also registers the toolchain with mise, repairing older Rust
install symlink registries that can bypass lock resolution.

Run cargo and repository scripts through `mise exec --` or `mise run` so the repo
selected toolchain is active. `scripts/check.sh` is the quiet/timed log-replay
runner behind the mise tasks, not a separate tier.

What to run after touching common surfaces:

- Runtime crates (`patina-runtime`, drivers, traces, schedulers): start with
  `mise run check:fast`; run `mise run check` before handing off.
- Native shim C/Rust or native audit/run behavior: run the focused command you
  need, then `mise run smoke` or `mise run check`; use `mise run check:fast` for
  a quick guardrail after small edits.
- Harness/SDK macro behavior: run the focused crate or testbed test, then
  `mise run check:fast`; run `mise run check` if it changes runtime semantics.
- CLI parser/help/flag behavior: inspect `crates/cargo-patina/src/help.rs` and its `help/` modules, run
  the focused CLI tests plus `scripts/check-flag-drift.sh` through `mise exec --`,
  then `mise run check:fast`.

Gates worth knowing individually:

- `scripts/check-flag-drift.sh` — extracts every flag-shaped token from the gated
  docs (the `DOCS` list in the script: the root docs, `llms.txt`,
  `docs/agent-operations.md`, the native-shim/testbed `AGENTS.md` files, and the
  testbed READMEs) AND from every shell script (`scripts/*.sh`,
  `testbeds/**/*.sh`), and fails on any flag the CLI registry does not define
  (beyond a small allowlist of non-patina guest/tool/script flags). If you
  mention or invoke a patina flag anywhere, it must exist; if you rename a flag,
  the gate finds every stale mention — in prose or in a script's flag arrays.
- `scripts/check-file-size.py` — no Rust file over 1,500 lines unless it's
  listed in `scripts/file-size-allowlist.txt`, and a listed file may not grow
  past its ceiling. Over the cap? Split the file by concern; don't raise a ceiling.
  A change that shrinks a listed file lowers or removes its entry.
- `mise run check:native-abi` — focused native ABI integration tests; other native
  targets (`native_conformance`, `native_containment`, `native_raw`, `native_signals`,
  `native_trace`, `native_workloads`) run in the full workspace-test tier and CI,
  not `check:fast`.
- `mise run conformance` — the syscall conformance scenarios
  (`crates/patina-conformance`) natively and under patina, the live host kernel
  as the oracle — authoritative only on the pinned system (Ubuntu 24.04: the
  6.8 kernel and glibc 2.39), report-only (`DIVERGES`) elsewhere; `mise run conformance:coverage` lists registry entries no
  scenario or exclusion accounts for (a local report, not a gate). `scripts/validate-wasi.sh` and
  `scripts/smoke-cross-target.sh` are the WASI/cross-target acceptance batteries
  (VALIDATION.md defines what each proves).
- `testbeds/workq/fuzz-sweep.sh --selftest` and
  `cargo patina campaign --selftest` — the sweep/campaign outcome classifiers
  prove every class fireable; these run per-push in CI.
- `testbeds/audit-corpus/run.sh` (`--selftest` to prove the drift detection
  bites) — the strict-xfail ecosystem symbol-audit corpus.

## Project doctrine

- **Fail closed, loudly.** An unmodeled effect is a refusal or a named abort,
  never a silent fallback to the host. Do not add permissive fallbacks.
- **Structure before tests.** Enforce an invariant by construction first, in
  this order:
  1. make the bad state unrepresentable: types, visibility, ownership, one
     choke point;
  2. failing that, a compiler or lint rule (`clippy.toml` `disallowed-*`, a
     `#[deny]`);
  3. only then, a behavioural test that drives the product.
  Never enforce a code convention by scanning or patching source text in a
  test: such tests rot silently as code moves, and pass vacuously. Need a
  fault for a test? Use a test-only hook compiled into the product (a feature
  or failpoint), not a patched copy of the source.
- **Enforcement earns its cost.** Every test, lint, fixture, generator and
  gate is code to read, run and maintain. Do as much as needed, as little as
  possible: protect invariants whose violation is likely, costly and silent,
  with the smallest mechanism that does it, and stop there. No enumerated
  fixtures, no self-tests of tooling beyond one must-fail case per rule, no
  generators or policy files unless a static rule truly can't express the
  invariant. A review finding is an input, not a mandate: decline a fix whose
  machinery outweighs the risk, and say why.
- **Detection before fixes.** A new bug class needs a standalone detector that
  provably fires (red-before/green-after) before or alongside the point fix.
  Per "Structure before tests", the strongest detector is the type or lint
  that rejects the class at compile time. Every new point-level regression pin
  must name its class-level pairing (VALIDATION.md, "Maintenance rule").
- **No cruft.** No deprecation aliases, compatibility shims, or dual code
  paths for renamed surfaces — migrate every caller and doc in the same change.
- **Determinism claims are verified, not asserted.** Byte-identical repeats,
  record→replay identity, and seed variation are the standard evidence shape;
  a check that cannot fail is treated as a bug (see the selftests above).
- **Core patina is guest-agnostic.** No testbed- or guest-specific identifiers,
  markers, or workaround branches in the core crates (`crates/*`). Anything a
  specific guest needs for classification or configuration belongs in that
  guest's campaign spec or testbed scripts, never hardcoded in patina source.
  The campaign classifier enforces this structurally: it classifies from the
  run's `patina.result/v1` envelope alone, and a guest's own marker dialect can
  only reach it through that guest's spec (`classify.patterns` /
  `classify.exit_codes`).

## Agent operating habits

- Ask structured questions during open design phases; keep summaries short and
  put real decisions in explicit options.
- Answer status questions from fresh evidence, not memory. Check logs, processes,
  CI, output files, or the owning tool's status surface before saying what is
  running or complete.
- Measure rather than guess. Quote durations only when observed, and label
  estimates as estimates.
- Use read-only scouts to find the next likely rungs of a failure class while a
  builder fixes the current one; batch the fixes instead of serializing through
  one CI round per discovery.
- Verify delegated work by reading the diff and checking its evidence. Builder
  reports are useful leads, not acceptance.
- Prefer isolated workspaces/checkouts for parallel work, and keep one writer
  for any shared file set. Shared campaign outputs, generated binaries, and
  build artifacts are single-writer while a run is live.
- Convert historical incidents into detectors or guidance, not folklore. If a
  lesson affects future work, document it in `docs/agent-operations.md` or the
  relevant subtree `AGENTS.md`.

## Naming

- Crate directories are `crates/patina-*`, but published package names are
  `patina-dst-*` (e.g. `crates/patina-runtime` is `patina-dst-runtime`). The
  SDK crate at `crates/patina` is `patina-dst`, used as `patina_dst::` in code.
- Family names are **cargo** (in-process Cargo package/test), **native**
  (shim-linked binary), and **WASI** (`wasm32-wasip1` module).

## Style

- Write project docs in clear, concise language.
- Avoid implementation-phase language in `INTENTS.md` and `ARCHITECTURE.md`;
  they describe the system in present tense.
- `README.md` should remain honest about the project status.
- Shell scripts must be loud on failure and never vacuously pass; testbed
  scripts carry `--help` and (where they classify outcomes) `--selftest`.
