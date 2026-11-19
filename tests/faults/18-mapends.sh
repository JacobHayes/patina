# 18. Stores through a MAP_SHARED mapping of a work file reach the operation log however their
# process ends or loses the mapping (mapends, a file of two pages and a partial one: SIGKILL
# from another guest (of a process that made the mapping, and of one that inherited it by fork),
# SIGTERM's default
# action, still running at the end of the run, a vfork child ending its parent, a violation, an
# msync then a violation, the time limit, munmap, exit with the mapping, a MAP_FIXED mapping over
# it; mremap of a part of it ends the run unsupported): each mode with no crash
# plane, --crash machine and --crash process ends as it should (a violation and the time limit
# keep their outcome), its self-check passes, `patina log ops --check` passes, and what the file
# holds (read(2)) is what a native run prints. Then a branch sweep (every crash point) of the
# durability case (a killed child's store, then fsync of the file and the directory by its
# parent, then a synced marker: after a machine crash the marker means the store survived) and
# of kill, forked, vfork, orphan and fixed (a flush of two records, which a crash point between
# them cuts) under process and machine crashes: no finding, no self-check failure.
# A same-seed repeat is identical and `patina verify` is identical.
#@ tier=quick budget=30 slots=4
. "$(dirname "$0")/lib/common.inc"
d=$RUNS/18
rm -rf "${d:?}"
mkdir -p "$d/native"
want() {
    case $1 in
        violation | msync) echo violation ;;
        hang) echo liveness ;;
        remap) echo unsupported ;;
        *) echo ok ;;
    esac
}
for m in kill forked term orphan vfork violation msync hang unmap exit fixed remap durable; do
    native=""
    case $m in
        kill | forked | term | vfork | unmap | exit | fixed | durable)
            native=$(cd "$d/native" && "$PATINA_GUESTS/mapends" "$m") ;;
    esac
    for plane in none machine process; do
        o=$d/$m-$plane
        c=()
        [ $plane = none ] || c=(--crash "$plane")
        run "$o" 1 --time-limit 5 "${c[@]}" -- /guest/mapends "$m"
        got=$(class "$o")
        [ "$got" = "$(want "$m")" ] || die "$m, crash plane $plane: $got $(field "$o/result.json" message)"
        sc=$(python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1])).get("self_check", {}).get("verdict", "-"))' "$o/result.json")
        [ "$sc" = "$([ $plane = none ] && echo - || echo pass)" ] || die "$m, crash plane $plane: self-check $sc"
        "$PATINA" log ops --check "$o" >"$o.check" || die "$m, crash plane $plane: $(cat "$o.check")"
        if [ -n "$native" ]; then
            out=$(cat "$o/inc-0/stdout")
            [ "$out" = "$native" ] || die "$m, crash plane $plane: printed '$out', natively '$native'"
        fi
    done
    echo "$m: $(want "$m") with every crash plane; operation log check ok${native:+; $native as natively}"
done
for spec in "machine durable" "process kill" "machine kill" "machine forked" "process vfork" "machine vfork" "process orphan" "machine orphan" "process fixed" "machine fixed"; do
    read -r plane m <<<"$spec"
    o=$d/sweep-$plane-$m
    st=0
    timeout 300 "$PATINA" sweep --seeds 1..2 --branch --crash "$plane" --keep fail --out "$o" \
        --mount "$PATINA_GUESTS":/guest:copy -- /guest/mapends "$m" >"$o.txt" 2>&1 || st=$?
    [ $st = 0 ] || die "branch sweep $m under $plane crashes: exit $st: $(head -5 "$o.txt")"
    echo "branch sweep, $m under $plane crashes: $(grep -E '^patina sweep' "$o.txt" | cut -d'(' -f1)"
done
# Every crash point of the durability case was tried, and some crashed after the marker.
python3 -I - "$d/sweep-machine-durable/report.json" <<'PY' || exit 1
import json, sys
r = json.load(open(sys.argv[1]))
b = r["branch"]
if b["tried"] != b["points"] or b["points"] < 4:
    sys.exit("FAIL: durable: %d of %d crash points tried" % (b["tried"], b["points"]))
PY
run "$d/again" 1 --time-limit 5 --crash machine -- /guest/mapends kill
a=$(field "$d/again/result.json" digest)
b=$(field "$d/kill-machine/result.json" digest)
[ -n "$a" ] && [ "$a" = "$b" ] || die "kill under --crash machine: a repeat of the seed differs"
verify "$d/verify" 1 2 "" --crash process -- /guest/mapends orphan
echo "same seed identical; verify identical"
