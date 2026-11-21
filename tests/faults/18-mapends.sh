# 18. Stores through a MAP_SHARED mapping of a work file reach the operation log however their
# process ends or loses the mapping (mapends, a file of two pages and a partial one: SIGKILL
# from another guest (of a process that made the mapping, and of one that inherited it by fork),
# SIGTERM's default
# action, still running at the end of the run, a vfork child ending its parent, a violation, an
# msync then a violation, the time limit, munmap, exit with the mapping, a MAP_FIXED mapping over
# it; mremap of a part of it ends the run unsupported): each mode with no crash plane, --crash
# machine and (in the area tier) --faults kill ends as it should (a violation and the time
# limit keep their outcome), its self-check passes, `patina log ops --check` passes, and what the file
# holds (read(2)) is what a native run prints. A same-seed repeat is identical and `patina
# verify` is identical. The branch sweeps of these modes are 20-mapends-branch's.
#@ tier=quick budget=30
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
planes="none machine process"; [ "${CHECK_TIER:-}" != quick ] || planes="none machine"
for m in kill forked term orphan vfork violation msync hang unmap exit fixed remap durable; do
    native=""
    case $m in
        kill | forked | term | vfork | unmap | exit | fixed | durable)
            native=$(cd "$d/native" && "$PATINA_GUESTS/mapends" "$m") ;;
    esac
    for plane in $planes; do
        o=$d/$m-$plane
        c=()
        [ $plane = none ] || c=(--faults "$([ $plane = process ] && echo kill || echo crash)")
        run "$o" 1 --config "$("$PATINA_CFG" time-limit=5)" "${c[@]}" -- /guest/mapends "$m"
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
run "$d/again" 1 --config "$("$PATINA_CFG" time-limit=5)" --faults crash -- /guest/mapends kill
a=$(field "$d/again/result.json" digest)
b=$(field "$d/kill-machine/result.json" digest)
[ -n "$a" ] && [ "$a" = "$b" ] || die "kill under --faults crash: a repeat of the seed differs"
verify "$d/verify" 1 2 "" --faults kill -- /guest/mapends orphan
echo "same seed identical; verify identical"
