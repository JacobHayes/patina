# Agent Guidance

This repository contains **Patina**: an experimental deterministic execution and
simulation-testing (DST) runtime for Rust. Read this file before changing
anything; it tells you where truth lives and which gates must stay green.

## Document map

| Document | Read it for |
|---|---|
| [INTENTS.md](./INTENTS.md) | goals, non-goals, trade-offs, design principles |
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
`explore`, `campaign`, `coverage`, `sites`, `trace`, `minimize`. Verbs infer the artifact family (Cargo
package / native binary / WASI module) from the argument; `run`, `audit`, and
`replay` are source-first (a `.rs` file, directory, or `Cargo.toml` builds on
the fly).

Never guess flag names — the CLI has gone through renames. The authoritative
registry is `crates/cargo-patina/src/help.rs`, and it is the single source for
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
toolchains/targets, including the 1.86 MSRV toolchain with `wasm32-wasip1`):

- `mise run check` — the full pre-landing battery, laddered fast → slow:
  fmt, clippy (host + cross-target `x86_64-unknown-linux-gnu` for Linux-cfg
  code), docs, workspace tests, `scripts/check-flag-drift.sh`, MSRV tests, then
  the WASI / cross-target / native-shim validation scripts. **This is the
  landing gate.**
- `mise run check:fast` — the inner-loop tier (skips the slowest e2e tests, the
  MSRV re-run, `cargo doc`, the flag-drift gate, and
  `validate-native-shim.sh`). Not sufficient for landing.
- `mise run smoke`, `mise run msrv`, `mise run audit-corpus`, `mise run demo` —
  the individual pieces.

Without mise, run the `[tasks.check]` commands from `mise.toml` directly.

Gates worth knowing individually:

- `scripts/check-flag-drift.sh` — extracts every flag-shaped token from the gated
  docs (the `DOCS` list in the script: the root docs, `llms.txt`,
  `docs/agent-operations.md`, the native-shim/testbed `AGENTS.md` files, and the
  testbed READMEs) AND from every shell script (`scripts/*.sh`,
  `testbeds/**/*.sh`), and fails on any flag the CLI registry does not define
  (beyond a small allowlist of non-patina guest/tool/script flags). If you
  mention or invoke a patina flag anywhere, it must exist; if you rename a flag,
  the gate finds every stale mention — in prose or in a script's flag arrays.
- `scripts/validate-native-shim.sh`, `scripts/validate-wasi.sh`,
  `scripts/smoke-cross-target.sh` — the runtime acceptance batteries
  (VALIDATION.md defines what each proves).
- `testbeds/workq/fuzz-sweep.sh --selftest` and
  `cargo patina campaign --selftest` — the sweep/campaign outcome classifiers
  prove every class fireable; these run per-push in CI.
- `testbeds/audit-corpus/run.sh` (`--selftest` to prove the drift detection
  bites) — the strict-xfail ecosystem symbol-audit corpus.

## Project doctrine

- **Fail closed, loudly.** An unmodeled effect is a refusal or a named abort,
  never a silent fallback to the host. Do not add permissive fallbacks.
- **Detection before fixes.** A new bug class needs a standalone detector that
  provably fires (red-before/green-after) before or alongside the point fix.
  Every new point-level regression pin must name its class-level pairing
  (VALIDATION.md, "Maintenance rule").
- **No cruft.** No deprecation aliases, compatibility shims, or dual code
  paths for renamed surfaces — migrate every caller and doc in the same change.
- **Determinism claims are verified, not asserted.** Byte-identical repeats,
  record→replay identity, and seed variation are the standard evidence shape;
  a check that cannot fail is treated as a bug (see the selftests above).

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
