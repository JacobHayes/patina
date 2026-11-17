#!/bin/sh
# The 29 rows (not Deny or Stop) no determinism hardening run reached, exercised by one guest under the determinism hardening
# protocol (reference; repeat, cpu, load, aslr, sandbox, parallel and env variants), faults
# off and on: every variant identical to the reference.
#@ tier=area budget=120 slots=8 arch=x86_64
set -eu
. "$(dirname "$0")/lib/common.inc"
out=$RUNS/rows
mkdir -p "$out"
for f in off on; do
    PATINA_ATTACK_GUESTS=$G17 PROTO_OUT=$out DET_REPEAT=${DET_REPEAT:-11} sh "$root/tests/determinism/bin/protocol.sh" rows29 1 "$f" >"$out/rows29-$f.txt" 2>&1 ||
        die "rows29 faults $f: $(grep -v identical "$out/rows29-$f.txt" | head -3)"
    tail -n +1 "$out/rows29-$f.txt"
done
s=$out/rows29/s1-off/repeat/run-0/inc-0/stdout
[ "$(grep -c ' r=' "$s")" -eq 31 ] || die "rows29: guest output incomplete"
"$PATINA" log dump "$out/rows29/s1-off/repeat/run-0/inc-0/boundary.log" >"$out/rows29.dump"
for c in select ppoll epoll_create epoll_pwait2 pause getitimer alarm setitimer rt_sigtimedwait rt_sigqueueinfo \
    rt_tgsigqueueinfo tkill restart_syscall fork execveat setpgid setsid getpgid sched_setaffinity getcpu tee vmsplice \
    recvmmsg sendmmsg pkey_mprotect setxattrat getxattrat listxattrat removexattrat; do
    grep -q " $c \[" "$out/rows29.dump" || die "rows29: no record of $c"
done
echo "rows29: all 29 calls recorded in the boundary log"
rm -rf "$out/rows29/s1-on"
