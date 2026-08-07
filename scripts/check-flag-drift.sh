#!/usr/bin/env bash
# check-flag-drift.sh — patina CLI flag drift gate over docs AND shell scripts.
#
# One concept: no stale `--flag` spelling for a cargo-patina flag survives
# anywhere in the repo's prose or its scripts. Every `--flag`-shaped token in the
# gated docs and in every shell script is checked against the CLI's own
# machine-readable help registry (generated from crates/cargo-patina/src/help.rs).
# That registry is served with progressive disclosure (schema patina.help/v2):
# `cargo patina --help --format json` is a compact INDEX (verbs as {summary,
# forms}, no flag rows), and each `cargo patina <verb> --help --format json`
# carries that verb's flag_groups. This gate reconstructs the full flag universe
# by folding in every verb's payload (see section (a)). A token that is
# neither a real CLI flag nor on the small, categorized allowlist of genuinely
# non-patina flags is drift (a renamed/removed/never-existing patina flag) and
# fails the gate loudly, naming every file:line that mentions it.
#
# EXTRACTION SCOPE (and its honest limits — read before trusting a green):
#   * Both halves use the SAME dumb, structural rule: extract EVERY `--flag`
#     token, then subtract (registry ∪ allowlist). It deliberately does NOT try
#     to associate a flag with a `cargo patina` invocation. That is the whole
#     point for scripts: patina flags are routinely built up in bash arrays
#     (`PKNOBS+=(--sched-pct=…)`, `FAULTS=(--net-drop-permille …)`) FAR from any
#     `cargo patina` text, so any proximity- or invocation-line-scoped scan would
#     have blind spots. Checking every token against the registry has none: a
#     renamed run/campaign flag is caught wherever it sits.
#   * Because it treats the registry as truth, the price is an allowlist of the
#     finite set of non-patina `--flags` the scripts legitimately use: the guest
#     binaries' own arguments (after `--`), cargo/rustc/rustup/linker tool flags,
#     and the sweep scripts' own CLI options. That set is ~20 entries today (all
#     categorized below), NOT hundreds — measured, not guessed. A NEW non-patina
#     flag added to a script trips the gate until it is classified here; that
#     fail-closed step (a human stating "this is a guest arg, not a patina flag")
#     is the cost of the guarantee, not a bug.
#   * WHAT THIS DOES NOT CATCH (loud, by design):
#       - A real patina flag MISUSED in the wrong position (e.g. a run-time knob
#         placed after `--` as a guest arg, or vice-versa): it is in the registry,
#         so it passes. This gate proves spellings exist, not that they are used
#         in the right place.
#       - A stale flag in a script that is NOT matched by the SCRIPTS glob below
#         (`scripts/*.sh` + `testbeds/**/*.sh`). A patina-invoking script outside
#         those trees, or not named `*.sh`, is uncovered — add it to the glob.
#       - A flag spelled with a shell variable (`--net-${kind}`): not a literal
#         token, so not extracted. Scripts here always spell patina flags
#         literally; keep it that way.
#
# Exit codes: 0 = clean, 1 = drift (or registry unobtainable), 2 = bad usage.

set -euo pipefail

usage() {
  cat <<'EOF'
usage: scripts/check-flag-drift.sh

Checks every --flag token mentioned in the project docs AND in every shell script
(scripts/*.sh, testbeds/**/*.sh) against the CLI's generated help registry. Prints
nothing but a PASS line when clean; on drift, lists each unknown flag with the
file:line locations that mention it and exits 1.
EOF
}

case "${1:-}" in
  -h|--help) usage; exit 0 ;;
  "") ;;
  *) printf 'check-flag-drift: unknown argument: %s\n' "$1" >&2; usage >&2; exit 2 ;;
esac

cd "$(dirname "$0")/.."

# (0) Sources. DOCS is the curated user-facing set; SCRIPTS is every shell script
# under scripts/ and testbeds/ (this gate excluded — its allowlist below quotes
# flag names as data, not as invocations). SCRIPTS is globbed, not listed, so a
# newly added script is covered automatically rather than silently escaping.
DOCS=(README.md TUTORIAL.md USAGE-MODES.md ARCHITECTURE.md IMPLEMENTATION.md
      VALIDATION.md INTENTS.md AGENTS.md llms.txt docs/agent-operations.md
      docs/skills/patina-dst.md
      crates/patina-target/ESCAPE-CLASSES.md crates/patina-native-shim/AGENTS.md
      testbeds/AGENTS.md testbeds/README.md testbeds/workq/README.md testbeds/pubsub/README.md
      testbeds/audit-corpus/README.md testbeds/rustix-default/README.md
      testbeds/buggify-wasi/README.md testbeds/checkout-retry-idempotency/README.md
      testbeds/patina-macro-adopter/README.md)

SCRIPTS=()
while IFS= read -r f; do SCRIPTS+=("$f"); done < <(
  find scripts testbeds -type f -name '*.sh' ! -name check-flag-drift.sh | LC_ALL=C sort)

SOURCES=("${DOCS[@]}" ${SCRIPTS[@]+"${SCRIPTS[@]}"})

# Allowlist: non-patina flags the docs/scripts legitimately mention. Keep this
# minimal — every entry says whose flag it is. A patina flag NEVER belongs here;
# if the gate flags one, fix the doc/script or the registry, don't allowlist it.
ALLOWED_FLAGS='
--all
--all-targets
--check
--locked
--no-deps
--workspace
--example
--manifest-path
--quiet
--test
--installed
--cfg
--emit
--redefine-sym
--wrap
--help
--version
--iters
--bug
--jobs
--data-dir
--base-port
--workers
--producers
--tick-ms
--segment-bytes
--crash-at-completed
--server-host
--check-recovery-fail-closed
--update
--dry-run
--gen
--block
--max
--seeds
--patina
'
# -- cargo / rustc / rustup / linker tool flags --
# --all/--all-targets/--check/--no-deps/--workspace/--locked: cargo fmt/clippy/
#   doc/package/test flags (VALIDATION.md's V0 gates and the scripts' builds).
# --example: a cargo flag the Cargo package family forwards to `cargo build`.
# --manifest-path/--quiet/--test: cargo flags in the scripts' build/test preludes.
# --installed: `rustup target list --installed` (smoke/validate-wasi wasip1 probe).
# --cfg/--emit: rustc flags (`--cfg patina`, `--cfg rustix_use_libc`, `--emit=obj`).
# --redefine-sym: llvm-objcopy, discussed (and rejected) in VALIDATION.md.
# --wrap: the linker flag `-Wl,--wrap=dlsym` (host-alias doctrine + native shim).
# --help/--version: CLI meta-flags, accepted anywhere but not registry rows.
# -- guest-binary arguments (after `--`; the app's own CLI, per testbed READMEs) --
# --iters: an example guest program's own argument in IMPLEMENTATION.md.
# --bug: the workq/pubsub guests' planted-bug selector.
# --jobs/--data-dir/--base-port/--workers/--producers/--tick-ms/--segment-bytes/
#   --crash-at-completed/--server-host/--check-recovery-fail-closed: the
#   workq/pubsub guest binaries' own workload arguments.
# -- sweep/corpus scripts' own CLI options --
# --update: audit-corpus run.sh's re-record mode.
# --dry-run: the fuzz-sweep/wasi-buggify-sweep scripts' no-run mode.
# --gen: fuzz-sweep.sh's single-generation selector.
# --block/--max/--seeds/--patina: guided-efficacy run.sh's own probe options
#   (generation step, per-seed budget, seed-base count, binary override).
# (--selftest and --seed are REAL registry flags — not allowlisted here.)

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

# (a) The CLI registry, from the local build. Progressive disclosure means no
# single call lists every flag: the bare `--help` index carries only the shared
# global flags, and each verb's own flags live behind `<verb> --help`. So fetch
# the index, enumerate its verbs, and fold every verb's payload into one flag set.
help_json() { cargo run -q -p cargo-patina -- patina "$@" --help --format json 2>/dev/null; }

if ! index=$(help_json); then
  echo "check-flag-drift: FAILED to obtain the CLI help index" >&2
  echo "  (cargo run -q -p cargo-patina -- patina --help --format json)" >&2
  exit 1
fi

# Verb names are the keys of the index's `verbs` object — the only 4-space-indented
# `"name": {` lines in the pretty JSON (global_flags/verb_detail children are
# strings or arrays; environment elements are unkeyed objects). serde_json emits
# sorted keys with a stable 2-space indent, so this is deterministic; if the shape
# ever changes and this finds nothing, the gate fails closed here.
verbs=$(printf '%s\n' "$index" | grep -oE '^    "[a-z_]+": \{$' \
  | grep -oE '[a-z_]+' | LC_ALL=C sort -u)
if [ -z "$verbs" ]; then
  echo "check-flag-drift: could not enumerate verbs from the help index — shape changed?" >&2
  exit 1
fi

# The index (for the global flags) plus every verb's payload (for its flag_groups;
# each also repeats the global flags, which dedupe away).
payloads="$tmpdir/payloads"
printf '%s\n' "$index" >"$payloads"
for verb in $verbs; do
  if ! payload=$(help_json "$verb"); then
    echo "check-flag-drift: FAILED to obtain help for verb '$verb'" >&2
    exit 1
  fi
  printf '%s\n' "$payload" >>"$payloads"
done

grep -oE -e '"name":[[:space:]]*"--[A-Za-z0-9-]+"' "$payloads" \
  | grep -oE -e '\-\-[A-Za-z0-9-]+' | sort -u >"$tmpdir/registry"
if ! [ -s "$tmpdir/registry" ]; then
  echo "check-flag-drift: registry JSON contained no flags — extraction broken?" >&2
  exit 1
fi

# (b) Every --flag-shaped token across all sources (prose and code fences alike).
# Tokens ending in '-' are wildcard shorthands like `--max-*` and are skipped.
grep -ohE -e '\-\-[A-Za-z0-9][A-Za-z0-9-]*' ${SOURCES[@]+"${SOURCES[@]}"} \
  | grep -vE -e '\-$' | sort -u >"$tmpdir/src_flags"

printf '%s\n' $ALLOWED_FLAGS | sort -u >"$tmpdir/allowed"
sort -u "$tmpdir/registry" "$tmpdir/allowed" >"$tmpdir/known"

# (c) Source flags not known to the CLI or the allowlist.
unknown=$(comm -23 "$tmpdir/src_flags" "$tmpdir/known")

if [ -n "$unknown" ]; then
  echo "check-flag-drift: PATINA FLAG DRIFT — a doc or script mentions flags the CLI does not define:" >&2
  echo >&2
  for flag in $unknown; do
    echo "  $flag" >&2
    # `|| true`: a token with no boundary-matching occurrence (e.g. one extracted
    # from inside an anchor slug) must not abort the listing under `set -e` —
    # every drift gets reported, locations or not.
    grep -nE -e "(^|[^A-Za-z0-9-])${flag}([^A-Za-z0-9-]|$)" ${SOURCES[@]+"${SOURCES[@]}"} /dev/null \
      | sed 's/^/      /' | head -8 >&2 || true
  done
  echo >&2
  echo "Fix the doc/script (or, for a genuinely non-patina flag, extend the commented" >&2
  echo "allowlist in scripts/check-flag-drift.sh)." >&2
  exit 1
fi

count=$(wc -l <"$tmpdir/src_flags" | tr -d ' ')
echo "check-flag-drift: PASS ($count flag token(s) across ${#DOCS[@]} docs + ${#SCRIPTS[@]} scripts, all known to the CLI registry or allowlisted)"
