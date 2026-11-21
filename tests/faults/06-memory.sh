# 6. Memory: mem-error-at=N swept over the guest's memory requests: each mmap step sees
# ENOMEM exactly at its call and the guest carries on; thread creation fails with EAGAIN;
# under mem-limit-mb, growth past the limit is refused at the same call every run and
# malloc returns NULL with ENOMEM.
#@ tier=quick budget=30
. "$(dirname "$0")/lib/common.inc"
seen=""
for n in $(seq 1 24); do
    o=$RUNS/06/at-$n
    run "$o" 1 --fault mem-error-at=$n -- /guest/memfault
    [ "$(class "$o")" = ok ] || die "mem-error-at=$n: $(class "$o") $(field "$o/result.json" message)"
    grep -qx done "$o/inc-0/stdout" || die "mem-error-at=$n: guest did not finish"
    # The steps that failed (lines neither "... ok" nor "done"): none, or one.
    f=$(awk '!/ ok$/ && $0 != "done" {printf "%s ", $0}' "$o/inc-0/stdout")
    nf=$(awk '!/ ok$/ && $0 != "done" {n++} END {print n + 0}' "$o/inc-0/stdout")
    [ "$nf" -le 1 ] || die "mem-error-at=$n: more than one failed step"
    echo "mem-error-at=$n: $(field "$o/result.json" faults.recent | jq -r 'map(.call) | join(" ") | if . == "" then "-" else . end') -> ${f:-no failure visible to the guest (handled by libc, or N beyond its requests)}"
    seen="$seen$f"
done
for k in 0 1 2 3 4; do
    grep -q "step $k mmap ENOMEM" <<<"$seen" || die "mmap step $k never saw ENOMEM"
done
grep -q "step 10 thread EAGAIN" <<<"$seen" || die "thread creation never failed with EAGAIN"
# The order: the failing mmap step follows N.
prev=-1
for n in $(seq 1 24); do
    k=$(sed -n 's/.*step \([0-4]\) mmap ENOMEM.*/\1/p' "$RUNS/06/at-$n/inc-0/stdout")
    [ -z "$k" ] && continue
    [ "$k" -gt "$prev" ] || die "mmap failures not in call order"
    prev=$k
done
# mem-limit-mb=64: a guest mapping 1 MiB at a time up to 100 MiB is refused at the same call
# on every run, near 64 MiB, and malloc then returns NULL with ENOMEM; the result names it.
o=$RUNS/06/limit
verify "$o" 1 2 "" --fault mem-limit-mb=64 -- /guest/memfault limit
cat "$o/run-0/inc-0/stdout"
k=$(sed -n 's/^limit: ENOMEM at MiB \([0-9]*\)$/\1/p' "$o/run-0/inc-0/stdout")
[ -n "$k" ] || die "mem-limit-mb=64: no ENOMEM in 100 MiB"
[ "$k" -gt 48 ] && [ "$k" -le 64 ] || die "mem-limit-mb=64: refused at MiB $k"
grep -qx "malloc ENOMEM" "$o/run-0/inc-0/stdout" || die "malloc past the limit did not return NULL/ENOMEM"
python3 -I - "$o/run-0/result.json" <<'PY' || exit 1
import json, sys
f = json.load(open(sys.argv[1]))["faults"]
c, last = f["counts"].get("mem-limit"), f["recent"][-1]
if not c or c["injected"] < 2 or c["eligible"] < c["injected"]:
    sys.exit("FAIL: mem-limit counts %s" % c)
if (last["fault"], last["errno"], last["object"]) != ("mem-limit", "ENOMEM", "memory"):
    sys.exit("FAIL: last event %s" % last)
print("mem-limit: eligible %d, injected %d; last: %s %s %s bytes" % (
    c["eligible"], c["injected"], last["call"], last["errno"], last["bytes"]))
PY
echo "mem-limit-mb=64: refused at MiB $k in both runs (identical)"
