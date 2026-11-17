# 4. Pointer authentication: a program built with -mbranch-protection=standard prints its
# signed saved return address. The runtime disables the keys, so the word, and the digest, are
# the same on every repeat. On a host without PAC there is nothing to disable.
#@ tier=quick budget=15 arch=aarch64
. "$(dirname "$0")/lib.inc"
grep -qw paca /proc/cpuinfo || { echo "SKIP: this host has no address authentication"; exit 0; }
for k in 1 2 3 4 5; do
    prun "$RUNS/$k" --seed 1 -- "$PATINA_GUESTS/pac-lr"
    [ "$st" = 0 ] || die "repeat $k: exit $st ($(tail -2 "$RUNS/$k.txt"))"
    field "$RUNS/$k/result.json" digest
done | sort -u >"$RUNS/digests"
[ "$(wc -l <"$RUNS/digests")" = 1 ] || die "5 repeats, digests: $(tr '\n' ' ' <"$RUNS/digests")"
echo "5 repeats: $(cat "$RUNS/1/inc-0/stdout"); digest $(cat "$RUNS/digests")"
