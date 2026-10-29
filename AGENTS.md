# Agent Guidance

This repository contains **Patina**: an experimental deterministic execution and
simulation-testing (DST) runtime for Rust. Read this file before changing
anything; it tells you where truth lives and which gates must stay green.

## Document map

| Document | Read it for |
|---|---|
| [INTENTS.md](./INTENTS.md) | goals, non-goals, trade-offs, design principles |
| [docs/SCOPE.md](./docs/SCOPE.md) | who Patina serves first, the rules new surface must meet, where evidence comes from, the platform policy; cite it when proposing new surface |
| [ARCHITECTURE.md](./ARCHITECTURE.md) | crate boundaries, targets, drivers, traces, the native shim — the source of truth for system shape |
| [VALIDATION.md](./VALIDATION.md) | what is validated and how to run it, the guarantees and their oracles, known gaps |
| [USAGE-MODES.md](./USAGE-MODES.md) | the three adoption levels and the crate map |
| [README.md](./README.md) | the user-facing summary; must stay honest about status |
| [TUTORIAL.md](./TUTORIAL.md) | the command-by-command walkthrough (every command verified) |
| `llms.txt` | compact machine-oriented CLI/SDK map |
| [docs/skills/patina-dst.md](./docs/skills/patina-dst.md) | the tool-agnostic agent skill handed to agents *using* Patina: what it is, the capability map, and how to discover the current surface from the generated registry. Deliberately near-flagless — keep it that way; teach the discovery method, not a flag catalog |
| [crates/patina-target/ESCAPE-CLASSES.md](./crates/patina-target/ESCAPE-CLASSES.md) | the guest-escape taxonomy behind the audit gate |
| [testbeds/README.md](./testbeds/README.md) | the dogfooding guests and their conventions |
| Nearest `AGENTS.md` files | focused guidance for high-risk subtrees such as the native shim and testbeds |

**When changing intent, architecture, or user-visible behavior, update the
relevant docs in the same change.** Docs describe the current state; history
lives in git. If `AGENTS.local.md` exists, read it for local
maintainer recipes; it is gitignored and is not project doctrine.

## The CLI: verbs, and where its truth lives

`cargo patina` is verb-first: `build`, `run`, `test`, `audit`, `replay`,
`campaign`, `coverage`, `sites`, `trace`, `minimize`, `syscalls`. Every run is
native and interposed; `run`, `audit`, and `replay` are source-first (a `.rs`
file, package directory, or `Cargo.toml` builds on the fly).

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

A verb with several forms has **families** (the `trace` subcommands,
`minimize --generation`/`--params`), chosen at routing time from a subcommand
or selector token. A group accepted by only some forms carries a `families`
array naming them. A dependent flag carries `requires` (e.g.
`--sched-pct-steps` requires `--sched-pct`). A flag supplied to the wrong family
is refused by name, not as an unknown option.

Environment variables split by prefix. `PATINA_<FLAG>` defaults a registry flag
(derived in `cli.rs`, so a new flag gets one for free); `PATINA_RT_*` is the
runtime's supervisor↔guest control plane (`RUNTIME_ENV_PREFIX`), set only by the
supervisor and stripped from anything inherited. A new control-plane variable
takes the `PATINA_RT_` prefix; a unit test refuses a flag variable that collides
with any documented one. Self-spawned `cargo-patina` children go through
`supervisor_identity::expect_this_supervisor`, which clears every flag variable.

Every execution verb also accepts `--format json`, usually emitting one
`patina.result/v1` envelope on stdout; verb-specific report verbs may emit their
own schemas (for example `coverage --format json` emits `patina.coverage/v1`).
Prefer JSON when parsing results programmatically.

## Build, test and land

- rustup installs the Rust toolchain `rust-toolchain.toml` pins on first use;
  mise supplies nextest and ast-grep. Run cargo and repository scripts through
  `mise run` or `mise exec --` so those tools are active.
- Iterate with the focused command: the crate's or testbed's own tests,
  `mise run check:native-abi`, or `mise run conformance`. `cargo patina` embeds
  the native shim's C sources, so rebuild it after touching the C layer.
- `mise run check` is the landing gate; VALIDATION.md lists what it runs.
  Gate on its exit code, and run one heavy battery per host at a time.
- Land by pushing the branch and fast-forwarding `main` once CI is green.
  Keep commits targeted and linear.
- Prove a behavior change with a planted failure: the check must go red without
  the fix. Treat a harness or oracle finding as a hypothesis until a standalone
  reproduction or the trace confirms it.

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
  that rejects the class at compile time.
- **No cruft.** No deprecation aliases, compatibility shims, or dual code
  paths for renamed surfaces — migrate every caller and doc in the same change.
- **Determinism claims are verified, not asserted.** Byte-identical repeats,
  record→replay identity, and seed variation are the standard evidence shape;
  a check that cannot fail is treated as a bug.
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
- Verify delegated work by reading the diff and checking its evidence. Builder
  reports are useful leads, not acceptance.
- Prefer isolated workspaces/checkouts for parallel work, and keep one writer
  for any shared file set. Shared campaign outputs, generated binaries, and
  build artifacts are single-writer while a run is live.
- Convert incidents into detectors, or into one line of current guidance in
  the relevant `AGENTS.md`, never into narrative.

## Naming

- Crate directories are `crates/patina-*`, but published package names are
  `patina-dst-*` (e.g. `crates/patina-runtime` is `patina-dst-runtime`). The
  SDK crate at `crates/patina` is `patina-dst`, used as `patina_dst::` in code.
- Family names are **cargo** (in-process Cargo package/test) and **native**
  (shim-linked binary).

## Style

- Write project docs in clear, concise language.
- Avoid implementation-phase language in `INTENTS.md` and `ARCHITECTURE.md`;
  they describe the system in present tense.
- `README.md` should remain honest about the project status.
- Shell scripts must be loud on failure and never vacuously pass; testbed
  scripts carry `--help` and (where they classify outcomes) `--selftest`.
