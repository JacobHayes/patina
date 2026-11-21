# 7. A file of data alone (a shared object with no executable segment, as ICU's data library
# is) has nothing to rewrite: a program that loads it (LD_PRELOAD of librw-data.so into
# /bin/true) ends ok, result.json lists the file with status `data` where it is asked for a
# plan (x86_64, at ld.so's first mapping of a library; arm64 asks at an executable mapping, and
# this file has none, so it is not listed), and the `patina run` line does not name it as a
# file left without points.
#@ tier=quick budget=10 slots=1.5
: "${PATINA:?}" "${PATINA_GUESTS:?}" "${RUNS:?}"
die() { echo "FAIL: $*"; exit 1; }
G=$(realpath "$PATINA_GUESTS")
o=$RUNS/07-data
rm -rf "${o:?}" && mkdir -p "$o"
export XDG_CACHE_HOME=$o/cache
"$PATINA" run --seed 1 --out "$o/run" --mount "$G":/guest:copy --env LD_PRELOAD=/guest/librw-data.so -- /bin/true >"$o.txt" 2>&1 || true
r=$o/run/result.json
oc=$(jq -r .outcome "$r" 2>/dev/null || echo none)
[ "$oc" = ok ] || die "outcome $oc: $(tail -3 "$o.txt")"
st=$(python3 -I -c 'import json, sys
r = json.load(open(sys.argv[1]))
print(",".join(i["status"] for i in r["rewrite"]["images"] if i["path"].endswith("/librw-data.so")))' "$r")
case $st in data | "") ;; *) die "librw-data.so: status '$st' in result.json" ;; esac
! grep -q 'librw-data' "$o.txt" || die "the run line names librw-data.so: $(grep librw-data "$o.txt")"
echo "librw-data.so: status '${st:-not listed}', not named by the run"
