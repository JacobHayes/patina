#!/bin/bash
# Deno 2.9: Deno.serve + fetch, a Worker, file I/O.
# programs: conda-deno
set -euo pipefail; shopt -s inherit_errexit
export DENO_DIR=$PWD/.deno
exec $PROGS/conda-deno/2.9.8/bin/deno run -A --no-check $GUEST/deno-http.ts
