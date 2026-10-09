#!/usr/bin/env bash
# Build-free classifier checks, or the native + named pending-gap battery.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
exec python3 -B "$here/run.py" "$@"
