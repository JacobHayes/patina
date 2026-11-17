#!/bin/sh
# Instrumented and stock processes under one seed (tests/guests/compute/mixed.c), compute-gap=8:
#  a. `mixed` (threads; posix_spawn of stock sha256sum on itself; a fork child computing;
#     vfork and fork, each then exec of `mixed leaf`) ends ok on seeds 1-4 with the child's
#     hash right; result.json lists one image, the parent's path, with 3 starts, and the
#     `patina run` line names it; three runs of seed 1 under --vary cpu,load give one digest;
#  b. a stock parent (/bin/sh) running `mixed leaf` twice: one image, 2 starts;
#  c. more distinct instrumented paths than the table holds: ok, and every start is either
#     listed or counted in images_dropped;
#  d. `patina report` over a and b and a stock run: the one image, in all runs but the stock one.
#@ tier=quick budget=8 slots=6 arch=x86_64
. "$(dirname "$0")/lib.inc"
o=$RUNS/08-mixed
mkdir -p "$o"
M=/guest/compute/mixed
want=$(sha256sum "$G/compute/mixed" | cut -d' ' -f1)
gap="--fault compute-gap=8"
for s in 2 3 4; do
    prun "$o/tree-$s" "$s" $gap -- $M &
done
prun "$o/sh" 1 $gap -- /bin/sh -c "$M leaf 2000 && $M leaf 3000" &
prun "$o/many" 1 $gap -- $M many /tmp 40 &
prun "$o/stock" 1 -- /bin/true &
rm -rf "$o/verify"
"$PATINA" verify --runs 3 --vary cpu,load --seed 1 $gap --out "$o/verify" \
    --mount "$G":/guest:copy -- $M >"$o/verify.txt" 2>&1 || true
wait
grep -q '^identical: 3 runs' "$o/verify.txt" || die "a. mixed seed 1 under --vary cpu,load: $(tail -3 "$o/verify.txt")"
rm -rf "$o/tree-1"
cp -r "$o/verify/run-0" "$o/tree-1"
# images DIR: compute.images as "path:kind,kind:starts ..."
images() { python3 -I -c 'import json,sys
c=json.load(open(sys.argv[1])).get("compute",{})
print(" ".join(i["path"]+":"+",".join(i["kinds"])+":"+str(i["starts"]) for i in c.get("images",[])) or "-")' "$1/result.json"; }
for s in 1 2 3 4; do
    d=$o/tree-$s
    [ "$(field "$d/result.json" outcome)" = ok ] || die "a. mixed seed $s: $(res "$d") ($(tail -1 "$d/inc-0/stdout"))"
    grep -q "^sha256 $want\$" "$d/inc-0/stdout" || die "a. mixed seed $s: the child's hash: $(grep sha256 "$d/inc-0/stdout")"
    [ "$(images "$d")" = "$M:edge,access:3" ] ||
        die "a. mixed seed $s: compute.images $(images "$d")"
    [ "$(field "$d/result.json" compute.switches)" -gt 0 ] || die "a. mixed seed $s: no compute switch"
done
rm -rf "$o/line"
"$PATINA" run --seed 1 $gap --out "$o/line" --mount "$G":/guest:copy -- $M >"$o/line.txt" 2>&1 || true
grep -qF "$M" "$o/line.txt" || die "a. the patina run output names no image: $(cat "$o/line.txt")"
echo "a. mixed, seeds 1-4: ok, hash right, one image with 3 starts ($(field "$o/tree-1/result.json" compute.switches) switches on seed 1); one digest over 3 runs varying cpu and load"

[ "$(field "$o/sh/result.json" outcome)" = ok ] || die "b. /bin/sh parent: $(res "$o/sh")"
[ "$(images "$o/sh")" = "$M:edge,access:2" ] ||
    die "b. /bin/sh parent: compute.images $(images "$o/sh")"
echo "b. stock /bin/sh parent, two instrumented children: one image, 2 starts"

[ "$(field "$o/many/result.json" outcome)" = ok ] || die "c. mixed many: $(res "$o/many")"
python3 -I - "$o/many/result.json" <<'PY' || die "c. mixed many: compute $(field "$o/many/result.json" compute)"
import json, sys
c = json.load(open(sys.argv[1]))["compute"]
starts = sum(i["starts"] for i in c["images"])
print(f"c. 41 starts of 41 paths: {len(c['images'])} listed, {c['images_dropped']} counted as not listed")
sys.exit(not (c["images_dropped"] > 0 and starts + c["images_dropped"] == 41))
PY

"$PATINA" report --format json "$o"/tree-? "$o/sh" "$o/stock" >"$o/report.json" 2>"$o/report.err" || true
python3 -I - "$o/report.json" <<'PY' || die "d. patina report: compute $(field "$o/report.json" compute)"
import json, sys
c = json.load(open(sys.argv[1]))["compute"]
print(f"d. patina report: {c['images']} in {c['runs_with_points']} of 6 runs")
sys.exit(not ([i["path"] for i in c["images"]] == ["/guest/compute/mixed"] and c["runs_with_points"] == 5))
PY
