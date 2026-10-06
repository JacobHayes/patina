#!/usr/bin/env bash
# Run inside mise's pinned tool environment, like the other check rungs.
set -euo pipefail
if [[ ${1:-} == --help ]]; then
    echo 'Usage: scripts/check-structure.sh'
    echo 'Test and run the static structural rules with pinned ast-grep.'
    exit 0
fi
if [[ $# != 0 ]]; then
    echo 'check-structure: unexpected argument (use --help)' >&2
    exit 2
fi
cd "$(dirname "$0")/.."
ast-grep test --config scripts/sgconfig.yml --skip-snapshot-tests
ast-grep scan --config scripts/sgconfig.yml \
    --no-ignore hidden --no-ignore vcs --no-ignore dot --no-ignore global \
    --no-ignore parent --no-ignore exclude --globs '!target' crates/
