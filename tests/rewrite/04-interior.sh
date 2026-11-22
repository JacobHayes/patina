# 4. Jumps the rewriter cannot see into and around its patches (ARCHITECTURE "Load-time rewriting").
# rw-interior and rw-interior-pie (static and static-PIE, no C library) enter, through a table the
# rewriter does not read, every routine's start and the places their labels name, by call, by
# jump and by return. On x86_64 (tests/guests/rewrite/interior.S) the e_* labels are every
# instruction boundary inside the routines' group patches; on arm64 (interior-a64.S), which has
# no group patch, the s_* labels are sites (a word that becomes a branch to its trampoline) and
# the e_* labels the words around them. For each:
#  a. its plan verifies and objdump agrees on every patched instruction; on x86_64 the interior
#     boundaries of the plan's groups are exactly the e_* labels and hold int3 and another
#     faulting byte both (the two ways the runtime is entered); on arm64 every s_* label is a
#     site and no e_* label is;
#  b. a copy with the plan applied (`__rewrite --standalone`, which resumes interior entries
#     itself) prints the native output, 5 runs;
#  c. under with a point on every count (compute-gap=1; the guest is one
#     thread, so a point is taken at the first count after each of its system calls), seeds 1
#     and 2 each repeat identical under --vary cpu,load,aslr,sandbox,repeat, print the native
#     output, take points, and (x86_64) resume at every interior entry the guest made (two per
#     label);
#  d. with an argument the guest maps over the range past its image that holds the trampolines,
#     then makes every entry again: under the plan is dropped (its original
#     pages back) and the output is the native one.
#@ tier=quick budget=60 slots=3.5
: "${PATINA:?}" "${PATINA_GUESTS:?}" "${RUNS:?}"
die() { echo "FAIL: $*"; exit 1; }
. "$(dirname "$0")/../json.inc"
field() { field_opt "$@"; }
HERE=$(cd "$(dirname "$0")" && pwd)
o=$RUNS/04-interior
rm -rf "${o:?}"
mkdir -p "$o"
export XDG_CACHE_HOME=$o/cache
GS="rw-interior rw-interior-pie"
arch=$(uname -m)

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
    nm "$F" | awk '$3 ~ /^e_/ {sub(/^0*/, "", $1); print $1}' | sort >"$q/labels"
    [ -s "$q/labels" ] || die "a. $g: no e_* labels"
    if [ "$arch" = x86_64 ]; then
        awk '$1 == "interior" {sub(/^0x0*/, "", $2); print $2}' "$q/sites" | sort >"$q/interiors"
        cmp -s "$q/interiors" "$q/labels" ||
            die "a. $g: interior boundaries are not the e_* labels: $(diff "$q/interiors" "$q/labels" | grep '^[<>]' | head -4 | tr '\n' ' ')"
        awk '$1 == "interior" && $3 == "cc" {t = 1} $1 == "interior" && $3 != "cc" {s = 1} END {exit !(t && s)}' "$q/sites" ||
            die "a. $g: the interior boundaries do not hold both int3 and another faulting byte"
    else
        awk '$1 == "site" {sub(/^0x0*/, "", $2); print $2}' "$q/sites" | sort >"$q/patched"
        nm "$F" | awk '$3 ~ /^s_/ {sub(/^0*/, "", $1); print $1}' | sort >"$q/s-labels"
        [ -s "$q/s-labels" ] || die "a. $g: no s_* labels"
        missed=$(comm -23 "$q/s-labels" "$q/patched")
        [ -z "$missed" ] || die "a. $g: s_* labels not patched: $(head -4 <<<"$missed" | tr '\n' ' ')"
        wrong=$(comm -12 "$q/labels" "$q/patched")
        [ -z "$wrong" ] || die "a. $g: e_* labels patched: $(head -4 <<<"$wrong" | tr '\n' ' ')"
    fi
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
if [ "$arch" = x86_64 ]; then
    echo "a. b. plans verified, interior boundaries the e_* labels ($n each); the rewritten copies print the native output, 5 runs"
else
    echo "a. b. plans verified, every s_* label a site and no e_* label ($n); the rewritten copies print the native output, 5 runs"
fi

# c. and d.
for g in $GS; do
    for s in 1 2; do
        "$PATINA" verify --fault compute-gap=1 --seed "$s" --runs 3 \
            --vary cpu,load,aslr,sandbox,repeat --out "$o/$g/v$s" -- "$PATINA_GUESTS/$g" >"$o/$g/v$s.txt" 2>&1 &
    done
    "$PATINA" run --fault compute-gap=1 --seed 1 --out "$o/$g/remap" -- "$PATINA_GUESTS/$g" remap >/dev/null 2>&1 &
done
wait
for g in $GS; do
    q=$o/$g
    for s in 1 2; do
        r=$q/v$s/run-0
        grep -q '^identical' "$q/v$s.txt" || die "c. $g seed $s: $(grep -m1 -v '^run ' "$q/v$s.txt")"
        cmp -s "$q/want" "$r/boot-1/stdout" || die "c. $g seed $s: output differs from the native run"
        [ "$(field "$r/result.json" rewrite.points)" -ge 1 ] || die "c. $g seed $s: no point taken ($(field "$r/result.json" rewrite))"
        [ "$arch" != x86_64 ] || [ "$(field "$r/result.json" rewrite.interior)" = $((2 * n)) ] ||
            die "c. $g seed $s: $(field "$r/result.json" rewrite.interior) interior entries resumed, the guest made $((2 * n))"
    done
    cmp -s "$q/want-remap" "$q/remap/boot-1/stdout" ||
        die "d. $g after mapping over the trampolines: $(field "$q/remap/result.json" outcome): $(field "$q/remap/result.json" message)"
    [ "$(field "$q/remap/result.json" rewrite.dropped)" -ge 1 ] || die "d. $g: the plan was not dropped ($(field "$q/remap/result.json" rewrite))"
done
if [ "$arch" = x86_64 ]; then
    echo "c. seeds 1 and 2 identical under --vary cpu,load,aslr,sandbox,repeat, native output, points taken, $((2 * n)) interior entries resumed in each"
else
    echo "c. seeds 1 and 2 identical under --vary cpu,load,aslr,sandbox,repeat, native output, points taken"
fi
echo "d. mapping over the trampolines drops the plan; native output"
