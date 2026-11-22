# 1. fork-exec: ok; patina verify --runs 3 --vary cpu,load,sandbox identical (seed 1);
# at least 2 distinct digests over seeds 1-3 (one run each, at once); the PIDs printed are identical across runs; no
# process of any of these runs is left (200 daemons are running when the main guest exits).
#@ tier=quick budget=60 slots=3
. "$(dirname "$0")/lib.inc"
o=$RUNS/01-fork-exec
for seed in 1; do
    verify_ok "$o/v$seed" "$seed" 3 cpu,load,sandbox /guest/fork-exec
    # Every number printed after "pid", "child", "a=", "b=" etc. is a PID: the whole stdout
    # being one file over the 20 runs (checked above) covers them; count them for the record.
    echo "  PIDs printed per run: $(grep -oE '(pid|child|a|b|ppid|last)=[0-9]+' "$o/v$seed/run-0/boot-1/stdout" | wc -l), all identical over 3 runs"
    [ "$(tail -1 "$o/v$seed/run-0/boot-1/stdout")" = ok ] || die "seed $seed: the guest did not finish"
done
for batch in "1 2 3"; do
    for seed in $batch; do (run_ok "$o/s$seed" "$seed" /guest/fork-exec) & done
    wait
done
for seed in 1 2 3; do
    [ "$(field "$o/s$seed/result.json" outcome)" = ok ] || die "seed $seed: not ok"
    field "$o/s$seed/result.json" digest
done >"$o/digests.txt"
n=$(sort -u "$o/digests.txt" | wc -l)
echo "distinct digests over seeds 1-3: $n"
[ "$n" -ge 2 ] || die "only $n distinct digests over 3 seeds"
n=$(for seed in 1 2 3; do grep '^tree' "$o/s$seed/boot-1/stdout" | sha256sum; done | sort -u | wc -l)
echo "distinct fork-tree orders over seeds 1-3: $n"
echo "W7 $(counts "$o/s1")"
no_leftovers "$o"
echo "no process of these runs left"
