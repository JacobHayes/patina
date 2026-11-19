#!/bin/bash
# Bun: Bun.serve + fetch client, hashing, a spawned child.
# programs: bun/1.4.4
set -euo pipefail; shopt -s inherit_errexit
exec $PROGS/bun/1.4.4/bin/bun $GUEST/bun-http.js
