#!/usr/bin/env bash
# Test and run the static structural rules (scripts/structure) with the
# ast-grep mise pins.
set -euo pipefail
cd "$(dirname "$0")/.."
ast-grep test --config scripts/sgconfig.yml --skip-snapshot-tests
ast-grep scan --config scripts/sgconfig.yml \
    --no-ignore hidden --no-ignore vcs --no-ignore dot --no-ignore global \
    --no-ignore parent --no-ignore exclude --globs '!target' crates/
