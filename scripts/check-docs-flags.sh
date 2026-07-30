#!/usr/bin/env bash
# check-docs-flags.sh — doc/CLI flag drift gate.
#
# Extracts every `--flag`-shaped token from the user-facing docs and verifies
# that each one is either a real flag in the CLI's machine-readable help
# registry (`cargo patina --help --format json`, the single source of truth
# generated from crates/cargo-patina/src/help.rs) or on the small explicit
# allowlist below of genuinely non-patina flags the docs legitimately mention.
# Any other doc-mentioned flag is drift (a renamed/removed/never-existing flag)
# and fails the gate loudly.
#
# Exit codes: 0 = clean, 1 = drift (or registry unobtainable), 2 = bad usage.

set -euo pipefail

usage() {
  cat <<'EOF'
usage: scripts/check-docs-flags.sh

Checks every --flag token mentioned in the project docs against the CLI's
generated help registry. Prints nothing but a PASS line when clean; on drift,
lists each unknown flag with the doc locations that mention it and exits 1.
EOF
}

case "${1:-}" in
  -h|--help) usage; exit 0 ;;
  "") ;;
  *) printf 'check-docs-flags: unknown argument: %s\n' "$1" >&2; usage >&2; exit 2 ;;
esac

cd "$(dirname "$0")/.."

DOCS=(README.md TUTORIAL.md USAGE-MODES.md ARCHITECTURE.md IMPLEMENTATION.md
      VALIDATION.md INTENTS.md AGENTS.md llms.txt
      crates/patina-target/ESCAPE-CLASSES.md
      testbeds/README.md testbeds/workq/README.md testbeds/pubsub/README.md
      testbeds/audit-corpus/README.md testbeds/rustix-default/README.md
      testbeds/buggify-wasi/README.md)

# Allowlist: non-patina flags the docs legitimately mention. Keep this minimal —
# every entry must say whose flag it is. A patina flag NEVER belongs here; if
# the gate flags one, fix the doc or the registry, don't allowlist it.
ALLOWED_FLAGS='
--all
--all-targets
--check
--locked
--no-deps
--workspace
--example
--cfg
--redefine-sym
--wrap
--help
--version
--iters
--bug
--jobs
--data-dir
--update
--dry-run
--emit
'
# --all/--all-targets/--check/--locked/--no-deps/--workspace: cargo fmt/clippy/
#   doc/package flags quoted in VALIDATION.md's V0 gates.
# --example: a cargo flag the Cargo package family forwards to `cargo build`.
# --cfg: a rustc flag (`--cfg patina`, `--cfg rustix_use_libc`).
# --redefine-sym: llvm-objcopy, discussed (and rejected) in VALIDATION.md.
# --wrap: the linker flag `-Wl,--wrap=dlsym` in the host-alias doctrine docs.
# --help/--version: CLI meta-flags, accepted anywhere but not registry rows.
# --iters: an example guest program's own argument in IMPLEMENTATION.md.
# --bug/--jobs/--data-dir: the workq/pubsub guest binaries' own arguments,
#   documented in the testbed READMEs.
# --update: testbeds/audit-corpus/run.sh's re-record mode.
# --dry-run: the fuzz-sweep/wasi-buggify-sweep scripts' no-run mode.
# --emit: a rustc flag (`rustc --emit=obj` in ESCAPE-CLASSES.md).

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

# (a) The CLI registry, from the local build.
if ! registry=$(cargo run -q -p cargo-patina -- patina --help --format json 2>/dev/null); then
  echo "check-docs-flags: FAILED to obtain the CLI help registry" >&2
  echo "  (cargo run -q -p cargo-patina -- patina --help --format json)" >&2
  exit 1
fi
printf '%s\n' "$registry" \
  | grep -oE -e '"name":[[:space:]]*"--[A-Za-z0-9-]+"' \
  | grep -oE -e '\-\-[A-Za-z0-9-]+' | sort -u >"$tmpdir/registry"
if ! [ -s "$tmpdir/registry" ]; then
  echo "check-docs-flags: registry JSON contained no flags — extraction broken?" >&2
  exit 1
fi

# (b) Every --flag-shaped token in the docs (prose and code fences alike).
# Tokens ending in '-' are wildcard shorthands like `--max-*` and are skipped.
grep -ohE -e '\-\-[A-Za-z0-9][A-Za-z0-9-]*' "${DOCS[@]}" \
  | grep -vE -e '\-$' | sort -u >"$tmpdir/doc_flags"

printf '%s\n' $ALLOWED_FLAGS | sort -u >"$tmpdir/allowed"
sort -u "$tmpdir/registry" "$tmpdir/allowed" >"$tmpdir/known"

# (c) Doc flags not known to the CLI or the allowlist.
unknown=$(comm -23 "$tmpdir/doc_flags" "$tmpdir/known")

if [ -n "$unknown" ]; then
  echo "check-docs-flags: DOC/CLI FLAG DRIFT — the docs mention flags the CLI does not define:" >&2
  echo >&2
  for flag in $unknown; do
    echo "  $flag" >&2
    # `|| true`: a token with no boundary-matching occurrence (e.g. one extracted
    # from inside an anchor slug) must not abort the listing under `set -e` —
    # every drift gets reported, locations or not.
    grep -nE -e "(^|[^A-Za-z0-9-])${flag}([^A-Za-z0-9-]|$)" "${DOCS[@]}" /dev/null \
      | sed 's/^/      /' | head -5 >&2 || true
  done
  echo >&2
  echo "Fix the doc (or, for a genuinely non-patina flag, extend the commented" >&2
  echo "allowlist in scripts/check-docs-flags.sh)." >&2
  exit 1
fi

count=$(wc -l <"$tmpdir/doc_flags" | tr -d ' ')
echo "check-docs-flags: PASS ($count doc-mentioned flags, all known to the CLI registry or allowlisted)"
