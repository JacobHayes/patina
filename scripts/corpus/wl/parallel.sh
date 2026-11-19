#!/bin/bash
# GNU parallel: -j4 over 40 files (gzip + checksum), --pipe blocks, --keep-order.
# programs: conda-parallel
set -euo pipefail; shopt -s inherit_errexit
export PATH=$PROGS/conda-parallel/20260922/bin:$PATH HOME=$PWD
h=$(uname -n); mkdir -p .parallel/tmp/sshlogin/$h; echo 131000 > .parallel/tmp/sshlogin/$h/linelen  # a seeded cache: no E2BIG probe
mkdir -p d; for i in $(seq 1 40); do seq 1 $((i*500)) > d/f$i; done
parallel --will-cite -j4 'gzip -c {} > {}.gz && md5sum < {} | cut -c1-8' ::: d/f* | sort | md5sum
seq 1 100000 | parallel --will-cite -j4 --pipe --block 100k --keep-order wc -l | paste -sd+ | bc
parallel --will-cite -j4 --keep-order 'echo {}; sleep 0.0{}' ::: 3 1 2
