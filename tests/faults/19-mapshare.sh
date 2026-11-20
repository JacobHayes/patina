# 19. Two processes change the same page of a work file, one at least through a MAP_SHARED
# mapping, and one stores back bytes it stored or saw before (mapshare: a child's store, ended
# by its exit or by SIGKILL, undone by the main process's store; two processes taking turns;
# a store then another process's pwrite or writev on the page, and a pwrite then a store of
# the old byte; a truncation and extension by one process under another's mapping; more files
# mapped one after another than Patina keeps shadows of at once): each mode with no
# crash plane, --crash machine and --crash process ends ok, its self-check passes, `patina log
# ops --check` passes, and what the file holds (read(2)) at the end of the last incarnation is
# what a native run prints. Then a
# pwrite on a page another process stored to through its mapping: the page is logged whole
# before the write, and a branch sweep under machine crashes finds no file holding the write
# without the stores. Then a branch sweep (every crash point) under machine crashes of a store
# made by one process and fsynced by another, before a synced marker: the marker means the store survived, and a later
# unsynced store of the same process is lost after some crash; the same with sync(2) by a
# process mapping another page of the file. More files mapped at once than Patina keeps
# shadows of end the run unsupported (capacity). A same-seed repeat is identical and
# `patina verify` is identical.
#@ tier=quick budget=30 slots=4
. "$(dirname "$0")/lib/common.inc"
d=$RUNS/19
rm -rf "${d:?}"
mkdir -p "$d/native"
for m in back back-kill alternate store-write store-writev write-store trunc files; do
    native=$(cd "$d/native" && "$PATINA_GUESTS/mapshare" "$m")
    for plane in none machine process; do
        o=$d/$m-$plane
        c=()
        [ $plane = none ] || c=(--crash "$plane")
        run "$o" 1 "${c[@]}" -- /guest/mapshare "$m"
        got=$(class "$o")
        [ "$got" = ok ] || die "$m, crash plane $plane: $got $(field "$o/result.json" message)"
        sc=$(python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1])).get("self_check", {}).get("verdict", "-"))' "$o/result.json")
        [ "$sc" = "$([ $plane = none ] && echo - || echo pass)" ] || die "$m, crash plane $plane: self-check $sc"
        "$PATINA" log ops --check "$o" >"$o.check" || die "$m, crash plane $plane: $(cat "$o.check")"
        # The last incarnation's output: a crash restarts the program, which starts over.
        out=$(cat "$o/inc-$(($(field "$o/result.json" incarnations) - 1))/stdout")
        [ "$out" = "$native" ] || die "$m, crash plane $plane: printed '$out', natively '$native'"
    done
    echo "$m: ok with every crash plane; operation log check ok; $native as natively"
done
# A pwrite on a page another process stored to through its mapping: the page, whole, is
# logged before the write (so the crash model never keeps the write without the stores);
# a branch sweep (every crash point) under machine crashes finds no file with the write and
# without the stores.
run "$d/order" 1 -- /guest/mapshare order
"$PATINA" log events "$d/order" >"$d/order.events"
python3 -I - "$d/order.events" <<'PY' || exit 1
import json, sys
ops = [e for e in map(json.loads, open(sys.argv[1])) if e.get("type") == "op"]
w = next(i for i, e in enumerate(ops) if e["op"] == "write" and e["off"] == 100)
if not any(e["op"] == "mmap-dirty" and e["off"] == 0 and e["len"] >= 4096 for e in ops[:w]):
    sys.exit("FAIL: order: the stored page is not logged whole before the write")
PY
o=$d/sweep-order
st=0
timeout 300 "$PATINA" sweep --seeds 1..20 --branch --crash machine --keep fail --out "$o" \
    --allow-unmet synced-store-kept --allow-unmet unsynced-store-lost --mount "$PATINA_GUESTS":/guest:copy -- /guest/mapshare order >"$o.txt" 2>&1 || st=$?
[ $st = 0 ] || die "branch sweep of order under machine crashes: exit $st: $(head -5 "$o.txt")"
echo "order: the stored page logged before the write; branch sweep under machine crashes: $(grep -E '^patina sweep' "$o.txt" | cut -d'(' -f1)"
# durable-sync: the syncing process maps only another page of the file.
for m in durable durable-sync; do
    o=$d/sweep-$m
    st=0
    timeout 300 "$PATINA" sweep --seeds 1..2 --branch --crash machine --keep fail --out "$o" \
        --allow-unmet write-keeps-earlier-store --mount "$PATINA_GUESTS":/guest:copy -- /guest/mapshare $m >"$o.txt" 2>&1 || st=$?
    [ $st = 0 ] || die "branch sweep of $m under machine crashes: exit $st: $(head -5 "$o.txt")"
    echo "branch sweep, $m under machine crashes: $(grep -E '^patina sweep' "$o.txt" | cut -d'(' -f1)"
    # Every crash point was tried, and the unsynced store was lost after some crash.
    python3 -I - "$o/report.json" $m <<'PY' || exit 1
import json, sys
r = json.load(open(sys.argv[1]))
b = r["branch"]
if b["tried"] != b["points"] or b["points"] < 4:
    sys.exit("FAIL: %s: %d of %d crash points tried" % (sys.argv[2], b["tried"], b["points"]))
if "unsynced-store-lost" in json.dumps(r["sdk"]["sometimes_never_held"]):
    sys.exit("FAIL: %s: the unsynced store survived every crash" % sys.argv[2])
PY
done
run "$d/held" 1 -- /guest/mapshare held
[ "$(field "$d/held/result.json" outcome) $(field "$d/held/result.json" stop)" = "unsupported capacity" ] ||
    die "held: $(field "$d/held/result.json" outcome) $(field "$d/held/result.json" stop), want unsupported capacity"
echo "held: unsupported (capacity)"
run "$d/again" 1 --crash machine -- /guest/mapshare back-kill
a=$(field "$d/again/result.json" digest)
b=$(field "$d/back-kill-machine/result.json" digest)
[ -n "$a" ] && [ "$a" = "$b" ] || die "back-kill under --crash machine: a repeat of the seed differs"
verify "$d/verify" 1 2 "" --crash process -- /guest/mapshare alternate
echo "same seed identical; verify identical"
