#!/bin/sh
# Change 2: the process state a run inherits from its caller is set to fixed values
# (patina/src/sup/inherit.rs lists every item). `--vary env` changes, in its odd runs, the
# launcher's working directory, environment, umask, ignored and blocked signals and soft
# limits, and in the launcher's child before bwrap: a leaked descriptor, a new session with a
# controlling terminal, the persona, nice, IO priority, scheduling policy, timer slack, THP,
# OOM adjustment and every soft limit. A hard limit too low to honour ends the run as infra.
#@ tier=quick budget=30 slots=4
set -eu
. "$(dirname "$0")/lib/common.inc"
out=$RUNS/inherit
mkdir -p "$out"
vfy inherit 4 env "$G17" -- /guest/inherit
s=$out/inherit/run-1/inc-0/stdout
# Derived checks on the changed run: no inherited descriptor, one group, no terminal, the
# persona's read-implies-exec did not reach a read-only mapping.
[ "$(sed -n 's/^fds //p' "$s")" = "0 1 2" ] || die "inherit: descriptors $(sed -n 's/^fds //p' "$s")"
[ "$(sed -n 's/^groups \([0-9]*\).*/\1/p' "$s")" = 1 ] || die "inherit: $(grep '^groups' "$s")"
[ "$(sed -n 's/^devtty -1 errno \([0-9]*\)/\1/p' "$s")" = 6 ] || die "inherit: $(grep '^devtty' "$s")"
[ "$(sed -n 's/^maps perms //p' "$s")" = "r--p" ] || die "inherit: $(grep '^maps' "$s")"
echo "inherit: changed run has descriptors 0-2 only, one group, no terminal, r--p mapping"
vfy envprobe 4 env "$G12" -- /guest/envprobe
# Hard limits below what the sandbox needs: infra, naming the limit.
for l in stack=4194304 cpu=100000 nofile=3500 sigpending=100 fsize=30000000; do
    d="$out/lim-${l%%=*}"
    rm -rf "$d"
    timeout 300 prlimit --"$l" -- "$PATINA" run --seed 1 --out "$d" --guest "$G17" -- /guest/inherit >/dev/null 2>&1 || true
    [ "$(class "$d")" = infra ] || die "prlimit $l: class $(class "$d"), expected infra"
    echo "prlimit $l: infra ($(detail "$d"))"
done
rm -rf "$out/envprobe"
