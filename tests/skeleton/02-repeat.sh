# 2. patina verify --seed 1 --runs 4 --vary cpu,aslr,sandbox exits 0 for each guest; independently:
#    one digest and one stdout over the run directories.
#@ tier=quick budget=30
. "$(dirname "$0")/lib.inc"
for g in $GUESTS; do
    out=$RUNS/02-repeat/$g
    mkdir -p "$RUNS/02-repeat"
    timeout 120 "$PATINA" verify --seed 1 --runs 4 --vary cpu,aslr,sandbox --out "$out" --mount "$PATINA_GUESTS":/guest:copy -- "/guest/$g" >"$out.txt" || grep -q '^identical: ' "$out.txt" || die "$g: verify exit $?"
    n=$(for i in 0 1 2 3; do field "$out/run-$i/result.json" digest; done | sort -u | wc -l)
    [ "$n" = 1 ] || die "$g: $n distinct digests"
    n=$(for i in 0 1 2 3; do sha256sum <"$out/run-$i/inc-0/stdout"; done | sort -u | wc -l)
    [ "$n" = 1 ] || die "$g: $n distinct stdout files"
    [ -s "$out/run-0/inc-0/stdout" ] || die "$g: empty stdout"
    echo "$g: 4 runs (cpu, aslr, sandbox), 1 digest, 1 stdout"
done
