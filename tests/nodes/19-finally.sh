# 19. Nodes: setup, main command and final check (tests/guests/nodes/phases.py) under the
# seed's machine crashes and partitions (net-links=driver). Nodes a and b store puts; the setup
# waits for both; the main command puts records on both, 0.2 s apart; `--finally` checks both
# hold every acknowledged put. A main command that ends with the driver cut from a and a
# paused (by control calls), and one that ends with a node the seed killed still down (its
# restart drawn a minute later; seeds searched until one does): the final check starts with
# the links healed and every node up and running, no fault, crash or partition after the main
# command's end, ok; the same seed again is the same run, replay identical. The correct store is ok on four seeds. Planted bug:
# b acknowledges a put before its fsync (`lazy`); only the final check sees what a machine
# crash lost: found by a search of seeds (find_bug), stop finally, the main command ok.
#@ tier=area,release budget=120 slots=4
. "$(dirname "$0")/lib.inc"
o=$RUNS/19-finally; mkdir -p "$o"
for v in ok lazy; do
    rm -f "$o/$v.toml"
    conf "$o/$v.toml" a python3 /guest/phases.py serve
    if [ $v = ok ]; then conf "$o/$v.toml" b python3 /guest/phases.py serve; else conf "$o/$v.toml" b python3 /guest/phases.py serve lazy; fi
done
F="--faults crash,partition --fault net-links=driver --fault crash-gap-ms=1000..4000 --fault down-ms=200..2000 --fault max-incarnations=8 --fault partition-gap-ms=1000..4000 --fault partition-ms=500..4000"
P=(--setup "python3 /guest/phases.py check 0 a b" --finally "python3 /guest/phases.py check 10 a b")

# settled DIR: at the final check's start no partition is open and every node is up; nothing
# was injected after the main command's end. Prints the downs before it.
settled() {
    "$PATINA" log events "$1" --types node,net,phase,fault,crash >"$1.ev" || die "log events $1"
    python3 -I - "$1.ev" <<'PY'
import json, sys
part, up, downs, ended, down_at_end = set(), {}, 0, False, 0
for line in open(sys.argv[1]):
    e = json.loads(line)
    t = e["type"]
    if t == "header":
        up = {k: True for k in e["nodes"][1:]}
    elif t == "phase" and e["ended"] == "main":
        ended = True
        down_at_end = sum(not u for u in up.values())
    elif t == "phase" and e["ended"] == "finally":
        break
    elif t == "net" and e.get("by") == "seed":
        assert not (ended and e["event"] == "cut"), e
        (part.add if e["event"] == "cut" else part.discard)(e["n"])
    elif t == "node" and e["event"] in ("kill", "machine-crash", "crash", "exit"):
        assert not ended, e
        up[e["name"]] = False
        downs += 1
    elif t == "node" and e["event"] == "start":
        up[e["name"]] = True
    elif t in ("fault", "crash"):
        assert not ended, e
assert ended and not part and all(up.values()), (ended, part, up)
print(downs, down_at_end)
PY
}

# The main command ends with the driver cut from a and a paused (a pause is refused while the
# seed has a down: tried again until it is back).
# lint-allow: sleep — the guest's, in virtual time
end="python3 /guest/phases.py work 10 a b && patina ctl partition driver a && for i in 1 2 3 4 5 6 7 8 9 10; do patina ctl pause a && exit 0; sleep 1; done; exit 1"
s=$((RANDOM % 1000 + 1))
run_ok "$o/end" $s --config "$o/ok.toml" $F "${P[@]}" -- sh -c "$end"
d=$(settled "$o/end") || die "seed $s: not settled at the final check"
[ "$(field "$o/end/result.json" phases.finally.exit.status)" = 0 ] || die "seed $s: $(field "$o/end/result.json" phases)"
echo "seed $s: main ended with a cut and paused; the final check found them healed and running (downs before, down at the end: $d)"
run_ok "$o/end2" $s --config "$o/ok.toml" $F "${P[@]}" -- sh -c "$end"
a=$(field "$o/end/result.json" digest) b=$(field "$o/end2/result.json" digest)
[ "$a" = "$b" ] || die "seed $s: digests $a and $b"
"$PATINA" replay "$o/end" >"$o/replay.txt" 2>&1 || die "replay: $(tail -3 "$o/replay.txt")"
grep -q '^identical' "$o/replay.txt" || die "replay: $(cat "$o/replay.txt")"
echo "seed $s: the same run twice, replay identical"

# A node the seed killed, down at the main command's end: started before the final check.
K="--faults kill --fault crash-gap-ms=500..3000 --fault down-ms=60000..60000"
k=$s; n=0
while [ $k -lt $((s + 16)) ]; do
    run_ok "$o/down" $k --config "$o/ok.toml" $K --setup "python3 /guest/phases.py check 0 a b" \
        --finally "python3 /guest/phases.py check 3 a b" -- sh -c "python3 /guest/phases.py work 3 a b && sleep 5"  # lint-allow: sleep — the guest's, in virtual time
    n=$(settled "$o/down") || die "seed $k: not settled at the final check"
    [ "${n#* }" = 0 ] || break
    k=$((k + 1))
done
[ "${n#* }" != 0 ] || die "seeds $s..$k: no node down at the main command's end"
echo "seed $k: ${n#* } node(s) down at the main command's end, started before the final check, ok"

# The correct store: ok on four seeds, every run settled at its final check.
rm -rf "${o:?}/ok"; st=0
timeout 600 "$PATINA" sweep --seeds $s..$((s + 3)) -j 4 --keep all --out "$o/ok" --config "$o/ok.toml" $F "${P[@]}" \
    --mount "$PATINA_GUESTS":/guest:copy -- python3 /guest/phases.py work 10 a b >"$o/ok.txt" 2>&1 || st=$?
[ "$(field "$o/ok/report.json" outcomes)" = '{"ok":4}' ] || { tail -20 "$o/ok.txt"; die "correct: exit $st"; }
for r in "$o"/ok/seed-*; do settled "$r" >/dev/null || die "$r: not settled at the final check"; done
echo "correct: ok on seeds $s-$((s + 3)), each settled at its final check"

# The planted bug: found only by the final check.
find_bug "$o" lazy --config "$o/lazy.toml" $F "${P[@]}" -- python3 /guest/phases.py work 10 a b
r=$(field "$o/lazy/report.json" groups.0.first.dir)
[ "$(field "$r/result.json" outcome)/$(field "$r/result.json" stop)" = failure/finally ] || die "lazy: $(field "$r/result.json" message)"
[ "$(field "$r/result.json" phases.main.exit.status)" = 0 ] || die "lazy: the main command: $(field "$r/result.json" phases.main)"
settled "$r" >/dev/null || die "lazy: $r not settled at the final check"
grep -q 'lost acknowledged puts' "$r/inc-0/stderr" || die "lazy: $(tail -3 "$r/inc-0/stderr")"
echo "lazy: the final check found the lost puts; the main command ended ok"
