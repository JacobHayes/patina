#!/bin/sh
# Rust with compute points (the SDK's `compute` feature, the coverage RUSTFLAGS, cargo with
# --target; tests/guests/compute/Cargo.toml):
#  a. rs-race and rs-deadline run natively with their normal output;
#  b. rs-race (an atomics check-then-act, no system call in its window) ends `failure` on at
#     least one of seeds 1-40 at compute-gap=2; the first failing seed replays identical; its
#     result.json lists the one image, with edges and accesses;
#  c. rs-deadline (a loop that ends when a sleeping thread sets a flag) ends ok on seeds 1-3
#     at compute-gap=4096, which it does only when its virtual time is 50 to 60 ms; seed 1
#     gives one digest twice.
# The race's window is one edge wide: compute-gap=8 hits it on about 1 seed in 40
# (evidence-races), compute-gap=2 on about 1 in 5. The deadline's 50 ms are 50 million events,
# so a small gap would spend seconds switching.
#@ tier=quick budget=10 slots=6
. "$(dirname "$0")/lib.inc"
[ ! -f "$G/compute/rs-MISSING" ] || die "$(cat "$G/compute/rs-MISSING")"
o=$RUNS/05-rust
mkdir -p "$o"
C=$G/compute
out=$(timeout 20 "$C/rs-race" 2>&1) || true
echo "$out" | grep -Eq '^balance=-?[0-9]+ withdrawn=[0-9]+ (ok|DOUBLE-SPEND)$' || die "a. rs-race natively: $out"
out=$(timeout 20 "$C/rs-deadline" 2>&1) || true
echo "$out" | grep -q '^deadline after [0-9.]* ms, [0-9]* rounds' || die "a. rs-deadline natively: $out"
echo "a. rs-race and rs-deadline run natively with their normal output"

seq 1 40 | xargs -P 5 -I{} sh -c '
    d=$1/race-$2; rm -rf "$d"
    timeout 60 "$PATINA" run --seed "$2" --fault compute-gap=2 --out "$d" --mount "$3":/guest:copy -- /guest/compute/rs-race >/dev/null 2>&1 || true' \
    sh "$o" {} "$G"
wait

first="" found=0
for s in $(seq 1 40); do
    [ -f "$o/race-$s/result.json" ] || die "b. rs-race seed $s: no result.json"
    case $(field "$o/race-$s/result.json" outcome) in
        failure) found=$((found + 1)); [ -n "$first" ] || first=$s ;;
        ok) ;;
        *) die "b. rs-race seed $s: $(res "$o/race-$s")" ;;
    esac
done
img=$(python3 -I -c 'import json,sys
c=json.load(open(sys.argv[1])).get("compute",{})
print(" ".join(i["path"]+":"+",".join(i["kinds"]) for i in c.get("images",[])) or "-")' "$o/race-1/result.json")
[ "$img" = /guest/compute/rs-race:edge,access ] || die "b. rs-race seed 1: compute.images is $img (the hooks never said hello, or not as one image with edges and accesses)"
[ -n "$first" ] || die "b. rs-race: no failure in seeds 1-40 at compute-gap=2 (switches on seed 1: $(field "$o/race-1/result.json" compute.switches))"
"$PATINA" replay "$o/race-$first" >"$o/race-replay.txt" 2>&1 || true
grep -q '^identical' "$o/race-replay.txt" || die "b. rs-race seed $first does not replay: $(head -3 "$o/race-replay.txt")"
echo "b. rs-race: failure on $found of 40 seeds at compute-gap=2 (first $first: $(tail -1 "$o/race-$first/inc-0/stdout")); it replays identical; one image, edges and accesses"

# --timeout: without compute points the loop never lets the sleeper run; it ends here.
dl="--timeout 8 --fault compute-gap=4096"
for s in 1 2 3; do prun "$o/dl-$s" "$s" $dl -- /guest/compute/rs-deadline & done
prun "$o/dl-1b" 1 $dl -- /guest/compute/rs-deadline &
wait
for s in 1 2 3; do
    [ "$(field "$o/dl-$s/result.json" outcome)" = ok ] || die "c. rs-deadline seed $s: $(res "$o/dl-$s"): $(tail -1 "$o/dl-$s/inc-0/stdout")"
done
[ "$(field "$o/dl-1/result.json" digest)" = "$(field "$o/dl-1b/result.json" digest)" ] || die "c. rs-deadline seed 1: two digests"
echo "c. rs-deadline ok on seeds 1-3 ($(tail -1 "$o/dl-1/inc-0/stdout")); seed 1 gives one digest twice"
