#!/bin/bash
# tar + zstd -T4 + xz -T4 + gzip round trips over an 8 MB tree.
set -euo pipefail; shopt -s inherit_errexit
mkdir -p tree; for i in $(seq 1 64); do seq $((i*1000)) $((i*1000+20000)) > tree/f$i; done
tar -cf t.tar tree
zstd -q -T4 -19 t.tar -o t.tar.zst; xz -T4 -k t.tar; gzip -k t.tar
for f in t.tar.zst t.tar.xz t.tar.gz; do mkdir -p x-$f; tar -xaf $f -C x-$f; diff -r tree x-$f/tree; done
zstd -q -d t.tar.zst -o r.tar; cmp r.tar t.tar
ls -l t.tar*
