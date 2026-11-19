#!/bin/bash
# ripgrep and fd over a 2000-file tree.
# programs: rg fd
set -euo pipefail; shopt -s inherit_errexit
RG=$(ls $PROGS/rg/*/ripgrep-*/rg | head -1); FD=$(ls $PROGS/fd/*/fd-*/fd | head -1)
for d in $(seq 1 20); do mkdir -p t/d$d; for f in $(seq 1 100); do echo "line $d $f needle$((f%7))" > t/d$d/f$f.txt; done; done
$RG -c needle3 t | wc -l
$RG --threads 4 -l needle5 t | sort | md5sum
$FD -t f . t | wc -l
$FD -e txt -j 4 f1 t | sort | head -3
