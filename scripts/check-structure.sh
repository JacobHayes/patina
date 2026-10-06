#!/usr/bin/env bash
# Structural lint gates; these inspect syntax, never copied/patched test sources.
set -euo pipefail
if [[ ${1:-} == --help ]]; then
    echo 'Usage: scripts/check-structure.sh'
    echo 'Run structural lints with the ast-grep version pinned by mise.lock.'
    exit 0
fi
if [[ $# != 0 ]]; then
    echo 'check-structure: unexpected argument (use --help)' >&2
    exit 2
fi
cd "$(dirname "$0")/.."
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cargo run -q -p patina-dst-native-shim --example structural_rules -- \
    --fixture-dir "$work/generated-tests" > "$work/generated.yml"
python3 -B scripts/prepare-structure-tests.py "$work"
# Test the detector before using it. No snapshots: invalid snippets must match
# and sanctioned snippets must not match every rule, including generated ones.
mise exec -- ast-grep test --config "$work/sgconfig.yml" --skip-snapshot-tests
# Source remains reachable when hidden or gitignored. Ignore build directories
# explicitly, rather than inheriting an editor/user's ignore configuration.
mise exec -- ast-grep scan --config "$work/sgconfig.yml" \
    --no-ignore hidden --no-ignore vcs --no-ignore dot --no-ignore global \
    --no-ignore parent --no-ignore exclude --globs '!target' crates/ testbeds/
