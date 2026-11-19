#!/bin/bash
# rsync -a of a 300-file tree, an incremental update, and --delete.
set -euo pipefail; shopt -s inherit_errexit
mkdir -p src/a/b
for i in $(seq 1 300); do seq 1 $i > src/a/b/f$i; done
rsync -a src/ dst/
echo changed >> src/a/b/f7; rm src/a/b/f8
rsync -a --delete --checksum -i src/ dst/ | sort
diff -r src dst && echo same
