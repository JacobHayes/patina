#!/bin/sh
# The hook file beyond C with clang (tests/guests/compute):
#  a. every guest here runs natively with its normal output, and no image exports a hook;
#  b. gcc (edges only, hook file built in a step of its own): `races-gcc b` ends `failure` on
#     at least one of seeds 1-8 at compute-gap=2 and the first one replays identical. At 8 it
#     is found too, but rarely (11 of 200 seeds): its threads run four edges each;
#  c. C++ (clang++ with all three kinds, g++ with edges; static constructor and destructor,
#     exceptions, std::atomic, two threads) ends ok with its normal output;
#  d. instrumented shared libraries, by DT_NEEDED and by dlopen (closed and opened again),
#     under an instrumented and a stock program: the image table has one entry, the program;
#     each instrumented image says hello itself and every hello gets the same cell; the
#     instrumented program's run repeats (one digest twice).
#@ tier=quick budget=6 slots=6 arch=x86_64
. "$(dirname "$0")/lib.inc"
o=$RUNS/07-gcc
mkdir -p "$o"
C=$G/compute
native() { # WANT PROG ARGS...: natively, the output matches WANT (lines joined by |)
    want=$1; shift
    out=$(timeout 20 "$@" 2>&1 | tail -3 | paste -sd'|') || die "a. $*: natively: $out"
    echo "$out" | grep -q "$want" || die "a. $*: natively printed $out"
}
native 'balance=0 withdrawn=100 ok$' "$C/races-gcc" b
# pool's race (unsynchronised counters) can show natively too, as in 03-inert.
native 'LOST-UPDATE\|ok$' "$C/pool-gcc"
for p in cxx cxx-gcc; do native '^ctor ok|total=6000 caught=60 ok|dtor ok$' "$C/$p"; done
for p in shlib shlib-stock; do native 'compdl=29992,29992 ok$' "$C/$p"; done
for f in "$C"/libcomp.so "$C"/libcompdl.so "$C"/shlib "$C"/cxx "$C"/cxx-gcc; do
    ! readelf -W --dyn-syms "$f" | grep -q __sanitizer_cov || die "a. $f exports a hook: $(readelf -W --dyn-syms "$f" | grep -m1 __sanitizer_cov)"
done
echo "a. the guests run natively with their normal output; no image exports a hook"

seq 1 8 | xargs -P 6 -I{} sh -c '
    timeout 60 "$PATINA" run --seed "$2" --fault compute-gap=2 --out "$1/races-$2" --mount "$3":/guest:copy -- /guest/compute/races-gcc b >/dev/null 2>&1 || true' \
    sh "$o" {} "$G" &
prun "$o/cxx" 1 -- /guest/compute/cxx &
prun "$o/cxx-gcc" 1 -- /guest/compute/cxx-gcc &
prun "$o/shlib-1" 1 -- /guest/compute/shlib &
prun "$o/shlib-2" 1 -- /guest/compute/shlib &
prun "$o/shlib-stock" 1 -- /guest/compute/shlib-stock &
wait

first="" found=0
for s in $(seq 1 8); do
    [ -f "$o/races-$s/result.json" ] || die "b. races-gcc b seed $s: no result.json"
    case $(field "$o/races-$s/result.json" outcome) in
        failure) found=$((found + 1)); [ -n "$first" ] || first=$s ;;
        ok) ;;
        *) die "b. races-gcc b seed $s: $(res "$o/races-$s")" ;;
    esac
done
[ -n "$first" ] || die "b. races-gcc b: no failure in seeds 1-8 at compute-gap=2"
"$PATINA" replay "$o/races-$first" >"$o/races-replay.txt" 2>&1 || true
grep -q '^identical' "$o/races-replay.txt" || die "b. races-gcc b seed $first does not replay: $(head -3 "$o/races-replay.txt")"
echo "b. races-gcc b (gcc, edges): failure on $found of 8 seeds at compute-gap=2; seed $first replays identical"

for p in cxx cxx-gcc; do
    [ "$(field "$o/$p/result.json" outcome)" = ok ] || die "c. $p: $(res "$o/$p")"
    [ "$(tail -3 "$o/$p/inc-0/stdout" | paste -sd'|')" = 'ctor ok|total=6000 caught=60 ok|dtor ok' ] ||
        die "c. $p printed $(tail -3 "$o/$p/inc-0/stdout" | paste -sd'|')"
done
echo "c. C++: cxx ($(field "$o/cxx/result.json" compute.events) events) and cxx-gcc ($(field "$o/cxx-gcc/result.json" compute.events) events) end ok with their constructor, exceptions and destructor"

for r in shlib-1 shlib-2 shlib-stock; do
    [ "$(field "$o/$r/result.json" outcome)" = ok ] || die "d. $r: $(res "$o/$r")"
    tail -1 "$o/$r/inc-0/stdout" | grep -q 'compdl=29992,29992 ok$' || die "d. $r printed $(tail -1 "$o/$r/inc-0/stdout")"
    # Each image that said hello is named, the program only when its own hooks did; the
    # address space started once.
    im=$(field "$o/$r/result.json" compute.images | python3 -I -c 'import json,sys; i=json.load(sys.stdin); print(" ".join(sorted(e["path"] for e in i)), sum(e["starts"] for e in i))')
    want="/guest/compute/libcomp.so /guest/compute/libcompdl.so"
    [ "$r" = shlib-stock ] || want="$want /guest/compute/shlib"
    [ "$im" = "$want 1" ] || die "d. $r: images and starts $im, not $want 1"
done
# The program, libcomp.so, and libcompdl.so once per dlopen: four hook copies, one cell.
"$PATINA" log dump "$o/shlib-1/inc-0/boundary.log" | sed -n 's/.* patina_sdk .*args=\[0x8, .*ret=\([0-9]*\) .*/\1/p' >"$o/shlib.hellos"
[ "$(wc -l <"$o/shlib.hellos")" = 4 ] || die "d. shlib: $(wc -l <"$o/shlib.hellos") hellos, not one per hook copy loaded"
[ "$(sort -u "$o/shlib.hellos" | wc -l)" = 1 ] || die "d. shlib: the hellos got more than one cell: $(sort -u "$o/shlib.hellos" | paste -sd' ')"
[ "$(field "$o/shlib-1/result.json" digest)" = "$(field "$o/shlib-2/result.json" digest)" ] || die "d. shlib: two runs of seed 1 differ"
echo "d. shared libraries: the images named are the ones whose hooks said hello (libcomp.so and libcompdl.so, and shlib itself only when it is rebuilt); shlib's 4 hook copies said hello and got one cell; one digest twice"
