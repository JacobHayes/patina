# 4. Jumps into the interior of group patches (ARCHITECTURE "Load-time rewriting").
# rw-interior and rw-interior-pie (tests/guests/rewrite/interior.S, static and static-PIE) enter,
# through a table the rewriter does not read, every routine's start and every instruction
# boundary their labels e_* name, by call, by jmp and by ret. For each:
#  a. its plan verifies, objdump agrees on every patched instruction, and the interior
#     boundaries of the plan's groups are exactly the e_* labels; they hold int3 and another
#     faulting byte both (the two ways the runtime is entered);
#  b. a copy with the plan applied (`__rewrite --standalone`, which resumes interior entries
#     itself) prints the native output, 5 runs;
#  c. under --preempt points with a point on every count (compute-gap=1), seeds 1 and 2 each
#     repeat identical under --vary cpu,load,aslr,sandbox,repeat, print the native output, take
#     points, and resume at every interior entry the guest made (two per label);
#  d. with an argument the guest maps over the range past its image that holds the trampolines,
#     then makes every entry again: under --preempt points the plan is dropped (its original
#     pages back) and the output is the native one.
#@ tier=quick budget=60 slots=4 arch=x86_64
: "${PATINA:?}" "${PATINA_GUESTS:?}" "${RUNS:?}"
die() { echo "FAIL: $*"; exit 1; }
field() { python3 -I -c 'import json,sys; v=json.load(open(sys.argv[1]))
for k in sys.argv[2].split("."):
    if not isinstance(v, dict) or k not in v: print("-"); sys.exit()
    v=v[k]
print(json.dumps(v) if isinstance(v,(list,dict)) else v)' "$1" "$2"; }
HERE=$(cd "$(dirname "$0")" && pwd)
o=$RUNS/04-interior
rm -rf "${o:?}"
mkdir -p "$o"
export XDG_CACHE_HOME=$o/cache
GS="rw-interior rw-interior-pie"

for g in $GS; do
    F=$PATINA_GUESTS/$g
    [ -x "$F" ] || die "missing guest $F"
    q=$o/$g
    mkdir -p "$q"
    # a.
    "$PATINA" __rewrite "$F" --plan "$q/plan" >"$q/report"
    "$PATINA" __rewrite --verify "$F" "$q/plan" >"$q/verify" 2>&1 || die "a. $g: the verifier rejects the plan ($(head -3 "$q/verify"))"
    "$PATINA" __rewrite --sites "$q/plan" >"$q/sites"
    objdump -d -w "$F" | python3 -I "$HERE/lib/objdump_sites.py" "$q/sites" >"$q/check"
    grep -q ' disagree=0$' "$q/check" || die "a. $g: patched instructions objdump decodes otherwise: $(head -3 "$q/check")"
    awk '$1 == "interior" {sub(/^0x0*/, "", $2); print $2}' "$q/sites" | sort >"$q/interiors"
    nm "$F" | awk '$3 ~ /^e_/ {sub(/^0*/, "", $1); print $1}' | sort >"$q/labels"
    [ -s "$q/labels" ] || die "a. $g: no e_* labels"
    cmp -s "$q/interiors" "$q/labels" ||
        die "a. $g: interior boundaries are not the e_* labels: $(diff "$q/interiors" "$q/labels" | grep '^[<>]' | head -4 | tr '\n' ' ')"
    awk '$1 == "interior" && $3 == "cc" {t = 1} $1 == "interior" && $3 != "cc" {s = 1} END {exit !(t && s)}' "$q/sites" ||
        die "a. $g: the interior boundaries do not hold both int3 and another faulting byte"
    # b.
    "$F" >"$q/want"
    "$PATINA" __rewrite --standalone "$F" "$q/copy" >/dev/null
    for i in 1 2 3 4 5; do
        "$q/copy" >"$q/got" || die "b. $g: rewritten copy, run $i: exit $?"
        cmp -s "$q/want" "$q/got" || die "b. $g: rewritten copy, run $i: output differs ($(cat "$q/got"))"
    done
    "$F" remap >"$q/want-remap"
done
n=$(wc -l <"$o/rw-interior/labels")
echo "a. b. plans verified, interior boundaries the e_* labels ($n each); the rewritten copies print the native output, 5 runs"

# c. and d.
for g in $GS; do
    for s in 1 2; do
        "$PATINA" verify --preempt points --fault compute-gap=1 --seed "$s" --runs 3 \
            --vary cpu,load,aslr,sandbox,repeat --out "$o/$g/v$s" -- "$PATINA_GUESTS/$g" >"$o/$g/v$s.txt" 2>&1 &
    done
    "$PATINA" run --preempt points --fault compute-gap=1 --seed 1 --out "$o/$g/remap" -- "$PATINA_GUESTS/$g" remap >/dev/null 2>&1 &
done
wait
for g in $GS; do
    q=$o/$g
    for s in 1 2; do
        r=$q/v$s/run-0
        grep -q '^identical' "$q/v$s.txt" || die "c. $g seed $s: $(grep -m1 -v '^run ' "$q/v$s.txt")"
        cmp -s "$q/want" "$r/inc-0/stdout" || die "c. $g seed $s: output differs from the native run"
        [ "$(field "$r/result.json" rewrite.points)" -ge 1 ] || die "c. $g seed $s: no point taken ($(field "$r/result.json" rewrite))"
        [ "$(field "$r/result.json" rewrite.interior)" = $((2 * n)) ] ||
            die "c. $g seed $s: $(field "$r/result.json" rewrite.interior) interior entries resumed, the guest made $((2 * n))"
    done
    cmp -s "$q/want-remap" "$q/remap/inc-0/stdout" ||
        die "d. $g after mapping over the trampolines: $(field "$q/remap/result.json" outcome): $(field "$q/remap/result.json" message)"
    [ "$(field "$q/remap/result.json" rewrite.dropped)" -ge 1 ] || die "d. $g: the plan was not dropped ($(field "$q/remap/result.json" rewrite))"
done
echo "c. seeds 1 and 2 identical under --vary cpu,load,aslr,sandbox,repeat, native output, points taken, $((2 * n)) interior entries resumed in each"
echo "d. mapping over the trampolines drops the plan; native output"
