#!/bin/sh
# Deadlines inside rebuilt code (`deadline`: loops with no system call):
#  a. an ITIMER_REAL falls due inside the loop: its handler runs at the timer's virtual time
#     plus at most ten trap charges (the calls made), and the loop ends in range, on seeds 1-3
#     at the seed's gap (20 ms: a small gap switches often) and at compute-gap=0 (50 ms;
#     deadlines do not depend on switches), one digest twice each; seed 1 (50 ms) gives one
#     digest under verify --runs 3 --vary cpu,aslr;
#  b. an endless loop under --time-limit 1 ends liveness, one digest twice;
#  c. thread and process CPU time after a loop of N iterations (at least N events) are >= N ns.
#@ tier=quick budget=10 slots=6
. "$(dirname "$0")/lib.inc"
o=$RUNS/04-deadline
mkdir -p "$o"
N=1000000
dl() { # OUT SEED MS [options]: one run of `deadline deadline MS`
    r=$1 s=$2 ms=$3; shift 3
    prun "$r" "$s" --timeout 20 "$@" -- /guest/compute/deadline deadline "$ms"
}
# Six at a time, the slowest first.
for k in 1 2; do
    dl "$o/d-3-$k" 3 20 & dl "$o/d-2-$k" 2 20 &
    prun "$o/e-$k" 1 --time-limit 1 --timeout 20 -- /guest/compute/deadline endless &
done
wait
for s in 1 2 3; do
    for k in 1 2; do dl "$o/z-$s-$k" "$s" 50 --fault compute-gap=0 & done
done
wait
dl "$o/d-1-1" 1 20 & dl "$o/d-1-2" 1 20 &
prun "$o/cpu" 1 -- /guest/compute/deadline cpu "$N" &
rm -rf "$o/verify"
"$PATINA" verify --runs 3 --vary cpu,aslr --seed 1 --out "$o/verify" \
    --mount "$G":/guest:copy -- /guest/compute/deadline deadline >"$o/verify.txt" 2>&1 || true
wait

# a, b, c in one pass over the result files: one line per failure.
fails=$(python3 -I - "$o" "$N" <<'PY'
import json, re, sys
o, n = sys.argv[1], int(sys.argv[2])
r = lambda d: json.load(open(f"{o}/{d}/result.json"))
out = lambda d: open(f"{o}/{d}/inc-0/stdout").read()
bad = []
for s in (1, 2, 3):
    for k, ms in (("d", 20), ("z", 50)):
        a, b = r(f"{k}-{s}-1"), r(f"{k}-{s}-2")
        m = re.search(r"handler_ns=(\d+)", out(f"{k}-{s}-1"))
        h = int(m.group(1)) if m else -1
        want = ms * 1_000_000
        if a["outcome"] != "ok":
            bad.append(f"a. {k}-{s}: {a['outcome']}/{a.get('stop')}: {a.get('message')}")
        elif not want <= h <= want + 10_000:
            bad.append(f"a. {k}-{s}: the handler ran at {h} virtual ns, not within ten trap charges of {want}")
        elif a["compute"]["deadline_stops"] < 1:
            bad.append(f"a. {k}-{s}: no deadline stop")
        if a["digest"] != b["digest"]:
            bad.append(f"a. {k}-{s}: two runs differ")
for k in (1, 2):
    e = r(f"e-{k}")
    if e["outcome"] != "liveness":
        bad.append(f"b. endless loop, --time-limit 1: {e['outcome']}/{e.get('stop')}: {e.get('message')}")
if r("e-1")["digest"] != r("e-2")["digest"]:
    bad.append("b. endless loop: two runs differ")
c = re.search(r"thread_ns=(\d+) process_ns=(\d+)", out("cpu"))
if r("cpu")["outcome"] != "ok" or not c or min(int(c.group(1)), int(c.group(2))) < n:
    bad.append(f"c. CPU time after {n} iterations: {out('cpu').strip()}")
print("\n".join(bad))
PY
) || die "the result check failed"
[ -z "$fails" ] || die "$fails"
grep -q '^identical: 3 runs' "$o/verify.txt" || die "a. deadline seed 1 under --vary cpu,aslr: $(tail -3 "$o/verify.txt")"
echo "a. timer in a loop: handler at $(sed -n 's/.*handler_ns=\([0-9]*\).*/\1/p' "$o/z-1-1/inc-0/stdout") ns for 50 ms (seed 1, compute-gap=0); seeds 1-3 ok at the seed's gap and at 0, one digest twice; seed 1 identical under --vary cpu,aslr"
echo "b. endless loop, --time-limit 1: liveness after $(field "$o/e-1/result.json" compute.events) events, one digest twice"
echo "c. CPU time after $N iterations: $(sed -n 's/^cpu [0-9]* //p' "$o/cpu/inc-0/stdout")"
