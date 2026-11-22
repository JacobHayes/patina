# 3. W6 shell-pipeline under /bin/sh (dash) and /bin/bash: ok; stdout equals a native run after
# masking the lines the workload marks ("~ "); identical over 3 runs, seed 1 (--vary cpu,load).
#@ tier=area budget=120
. "$(dirname "$0")/lib.inc"
o=$RUNS/03-shell
mkdir -p "$o"
for sh in sh bash; do
    native "$o/native-$sh.txt" "/bin/$sh" /guest/exec-files/pipeline.sh || die "native $sh: exit $?"
    for seed in 1; do
        verify_ok "$o/$sh-$seed" "$seed" 3 cpu,load "/bin/$sh" /guest/exec-files/pipeline.sh
        grep -v '^~ ' "$o/$sh-$seed/run-0/boot-1/stdout" >"$o/$sh-$seed.masked"
        grep -v '^~ ' "$o/native-$sh.txt" | cmp - "$o/$sh-$seed.masked" || die "$sh seed $seed: differs from native after masking"
        [ "$(tail -1 "$o/$sh-$seed.masked")" = done ] || die "$sh seed $seed: script did not finish"
    done
    echo "$sh: equal to native after masking $(grep -c '^~ ' "$o/native-$sh.txt") marked lines; $(counts "$o/$sh-1/run-0")"
done
