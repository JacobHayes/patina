# 4. Pointer authentication: a program built with -mbranch-protection=standard prints its
# signed saved return address. The runtime disables the keys, so the word, and the digest, are
# the same on every repeat; also when the program is reached by an exec (the kernel enables and
# redraws the keys at every exec: the new image's runtime disables them again). On a host
# without PAC there is nothing to disable.
#@ tier=quick budget=15 arch=aarch64 slots=0.5
. "$(dirname "$0")/lib.inc"
grep -qw paca /proc/cpuinfo || { echo "SKIP: this host has no address authentication"; exit 0; }
for via in direct exec; do
    for k in 1 2 3 4 5; do
        case $via in
            direct) prun "$RUNS/$via$k" --seed 1 -- "$PATINA_GUESTS/pac-lr" ;;
            exec) prun "$RUNS/$via$k" --seed 1 --mount "$PATINA_GUESTS:/guest" -- /usr/bin/env /guest/pac-lr ;;
        esac
        [ "$st" = 0 ] || die "$via repeat $k: exit $st ($(tail -2 "$RUNS/$via$k.txt"))"
        field "$RUNS/$via$k/result.json" digest
    done | sort -u >"$RUNS/digests-$via"
    [ "$(wc -l <"$RUNS/digests-$via")" = 1 ] || die "$via: 5 repeats, digests: $(tr '\n' ' ' <"$RUNS/digests-$via")"
    echo "$via: 5 repeats: $(cat "$RUNS/${via}1/inc-0/stdout"); digest $(cat "$RUNS/digests-$via")"
done
