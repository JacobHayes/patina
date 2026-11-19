#!/bin/busybox sh
# busybox ash: loops, pipes, awk/sed/sort, subshells, background jobs and wait, traps.
set -eu
i=0; while [ $i -lt 200 ]; do echo "$i $((i*i%97))"; i=$((i+1)); done > nums
busybox sort -k2 -n nums | busybox awk '{s+=$2} END {print "sum", s}'
busybox sed -n 's/^1\([0-9]\) /x\1 /p' nums | busybox wc -l
for j in 1 2 3 4; do ( busybox seq 1 500 | busybox md5sum > out$j ) & done; wait
busybox cat out1 out2 out3 out4 | busybox uniq -c
trap 'echo trapped' USR1; kill -USR1 $$
busybox find . -name 'out*' | busybox sort | busybox xargs busybox ls -l | busybox wc -l
echo $(busybox date -u +%Y)
