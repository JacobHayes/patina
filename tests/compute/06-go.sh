#!/bin/sh
# Go with compute points (go/patina/compute, -gcflags=all=-d=libfuzzer, no cgo):
#  a. the pinned toolchain builds the guests (else GO-BROKEN says why); a build with the flag
#     that does not import the package fails to link on a libfuzzer hook (fail closed); a build
#     without the flag that imports it has no hook in the binary;
#  b. the guests run natively with their normal output;
#  c. go-deadline (a CPU-bound loop under context.WithTimeout(50 ms)) ends `ok` on seeds 1-2 at
#     the default gap: the deadline fired inside the loop, at a virtual time of at least 50 ms
#     and under a second;
#  d. go-race (check-then-act on an atomic.Int64, no system call in the window) ends `failure`
#     on at least one of seeds 1-40 at compute-gap=8, every other seed `ok`; the first failing
#     seed replays identical; result.json names one image, kind compare; an atomic.Bool spin (go-race boolspin)
#     with one P (GOMAXPROCS=1: only the hook's preemption check lets main run) ends `ok`.
#@ tier=quick budget=8 slots=5
. "$(dirname "$0")/lib.inc"
o=$RUNS/06-go
mkdir -p "$o"
C=$G/compute
[ ! -f "$C/GO-BROKEN" ] || die "a. $(cat "$C/GO-BROKEN")"
[ ! -e "$C/go-noimport" ] || die "a. a program built with the flag and without the package linked"
grep -q 'runtime\.libfuzzer' "$C/go-noimport.err" || die "a. the flag without the package: $(head -3 "$C/go-noimport.err")"
grep -q libfuzzerTrace "$C/go-deadline" || die "a. go-deadline has no hook"
! grep -q libfuzzerTrace "$C/go-deadline-stock" || die "a. go-deadline-stock, built without the flag, has a hook"
echo "a. the guests build; the flag without the package does not link; the package without the flag adds no hook"

out=$(timeout 20 "$C/go-race" | tail -1) || true
echo "$out" | grep -q '^rounds=16 \(ok$\|.*DOUBLE-SPEND$\)' || die "b. go-race natively printed $out"
out=$(timeout 20 "$C/go-race" boolspin | tail -1) || true
[ "$out" = "boolspin ok" ] || die "b. go-race boolspin natively printed $out"
out=$(timeout 20 "$C/go-deadline" 134217728 | tail -1) || true
echo "$out" | grep -q ' deadline$' || die "b. go-deadline natively printed $out"
echo "b. the guests run natively with their normal output"

# At most 2^27 iterations: 2^28 events, about 5 times what reaching the deadline takes.
prun "$o/dl-1" 1 -- /guest/compute/go-deadline 134217728 &
prun "$o/dl-2" 2 -- /guest/compute/go-deadline 134217728 &
wait
for s in 1 2; do
    [ "$(field "$o/dl-$s/result.json" outcome)" = ok ] || die "c. go-deadline seed $s: $(res "$o/dl-$s")"
    t=$(sed -n 's/.*elapsed_ns=\([0-9]*\) deadline$/\1/p' "$o/dl-$s/inc-0/stdout")
    [ -n "$t" ] && [ "$t" -ge 50000000 ] && [ "$t" -lt 1000000000 ] || die "c. go-deadline seed $s: $(tail -1 "$o/dl-$s/inc-0/stdout")"
done
echo "c. go-deadline: cut by its context at $(sed -n 's/.*elapsed_ns=\([0-9]*\).*/\1/p' "$o/dl-1/inc-0/stdout") virtual ns on seed 1 ($(field "$o/dl-1/result.json" compute.events) events)"

prun "$o/bool" 1 --env GOMAXPROCS=1 -- /guest/compute/go-race boolspin &
hunt "$o" race 40 --fault compute-gap=8 -- /guest/compute/go-race
wait
img=$(python3 -I -c 'import json,sys
c=json.load(open(sys.argv[1])).get("compute",{})
print(" ".join(i["path"]+":"+",".join(i["kinds"]) for i in c.get("images",[])) or "-")' "$o/race-1/result.json")
[ "$img" = /guest/compute/go-race:compare ] || die "d. go-race seed 1: compute.images is $img (the hooks never said hello, or not as one image with comparisons)"
[ -n "$first" ] || die "d. go-race: no failure in seeds 1-$scanned at compute-gap=8 (switches on seed 1: $(field "$o/race-1/result.json" compute.switches))"
"$PATINA" replay "$o/race-$first" >"$o/race-replay.txt" 2>&1 || true
grep -q '^identical' "$o/race-replay.txt" || die "d. go-race seed $first does not replay: $(head -3 "$o/race-replay.txt")"
[ "$(field "$o/bool/result.json" outcome)" = ok ] || die "d. go-race boolspin: $(res "$o/bool")"
echo "d. go-race: failure on $found of seeds 1-$scanned (first $first: $(tail -1 "$o/race-$first/inc-0/stdout")); it replays identical; one image, comparisons; boolspin ok"
