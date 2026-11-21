# 19. Two processes change the same page of a work file, one at least through a MAP_SHARED
# mapping, and one stores back bytes it stored or saw before (mapshare: a child's store, ended
# by its exit or by SIGKILL, undone by the main process's store; two processes taking turns;
# a store then another process's pwrite or writev on the page, and a pwrite then a store of
# the old byte; a truncation and extension by one process under another's mapping; more files
# mapped one after another than Patina keeps shadows of at once): each mode with no crash
# plane, --faults crash and --faults kill ends ok, its self-check
# passes, `patina log ops --check` passes, and what the file holds (read(2)) at the end of the last incarnation is
# what a native run prints. Then a pwrite on a page another process stored to through its
# mapping: the page is logged whole before the write. More files mapped at once than Patina
# keeps shadows of end the run unsupported (capacity). A same-seed repeat is identical and
# `patina verify` is identical. The branch sweeps are 21-mapshare-branch's.
#@ tier=quick budget=30
. "$(dirname "$0")/lib/common.inc"
d=$RUNS/19
rm -rf "${d:?}"
mkdir -p "$d/native"
planes="none machine process"
for m in back back-kill alternate store-write store-writev write-store trunc files; do
    native=$(cd "$d/native" && "$PATINA_GUESTS/mapshare" "$m")
    for plane in $planes; do
        o=$d/$m-$plane
        c=()
        [ $plane = none ] || c=(--faults "$([ $plane = process ] && echo kill || echo crash)")
        run "$o" 1 "${c[@]}" -- /guest/mapshare "$m"
        got=$(class "$o")
        [ "$got" = ok ] || die "$m, crash plane $plane: $got $(field "$o/result.json" message)"
        sc=$(jq -r '.self_check.verdict // "-"' "$o/result.json")
        [ "$sc" = "$([ $plane = none ] && echo - || echo pass)" ] || die "$m, crash plane $plane: self-check $sc"
        "$PATINA" log ops --check "$o" >"$o.check" || die "$m, crash plane $plane: $(cat "$o.check")"
        # The last incarnation's output: a crash restarts the program, which starts over.
        out=$(cat "$o/inc-$(($(field "$o/result.json" incarnations) - 1))/stdout")
        [ "$out" = "$native" ] || die "$m, crash plane $plane: printed '$out', natively '$native'"
    done
    echo "$m: ok with every crash plane; operation log check ok; $native as natively"
done
# A pwrite on a page another process stored to through its mapping: the page, whole, is
# logged before the write (so the crash model never keeps the write without the stores).
run "$d/order" 1 -- /guest/mapshare order
"$PATINA" log events "$d/order" >"$d/order.events"
python3 -I - "$d/order.events" <<'PY' || exit 1
import json, sys
ops = [e for e in map(json.loads, open(sys.argv[1])) if e.get("type") == "op"]
w = next(i for i, e in enumerate(ops) if e["op"] == "write" and e["off"] == 100)
if not any(e["op"] == "mmap-dirty" and e["off"] == 0 and e["len"] >= 4096 for e in ops[:w]):
    sys.exit("FAIL: order: the stored page is not logged whole before the write")
PY
echo "order: the stored page logged before the write"
run "$d/held" 1 -- /guest/mapshare held
[ "$(field "$d/held/result.json" outcome) $(field "$d/held/result.json" stop)" = "unsupported capacity" ] ||
    die "held: $(field "$d/held/result.json" outcome) $(field "$d/held/result.json" stop), want unsupported capacity"
echo "held: unsupported (capacity)"
run "$d/again" 1 --faults crash -- /guest/mapshare back-kill
a=$(field "$d/again/result.json" digest)
b=$(field "$d/back-kill-machine/result.json" digest)
[ -n "$a" ] && [ "$a" = "$b" ] || die "back-kill under --faults crash: a repeat of the seed differs"
verify "$d/verify" 1 2 "" --faults kill -- /guest/mapshare alternate
echo "same seed identical; verify identical"
