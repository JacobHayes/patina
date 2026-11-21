# 12. Nodes: disk faults per node (tests/guests/faults/acklog.c as a node: append a record, fsync
# it, acknowledge it; an fsync error stops it without acknowledging). An unscoped disk key
# acts on every node but the driver; `@NODE` on the named nodes only, also as a value in the
# config's `[faults]` table. Outside the quick tier, under machine crashes beside fsync errors: correct, ok on
# every seed of a sweep with crashes in it, the self-check passing in all, identical under
# verify; the planted bug `retry` (retry a failed fsync, then acknowledge: the write the failure
# dropped is gone after the crash) loses an acknowledged record, found by a search of seeds
# (find_bug); its first failing run replays identically.
#@ tier=quick,release budget=60 slots=4
. "$(dirname "$0")/lib.inc"
o=$RUNS/12-disk-faults; mkdir -p "$o"
# err RUN NODE: whether NODE's first boot saw an fsync error.
err() { if grep -q '^fsync E' "$1/$2/inc-0/stdout"; then echo yes; else echo no; fi; }
rm -f "$o/ab.toml" "$o/b.toml"
conf "$o/ab.toml" a /guest/ack-log correct 3000; conf "$o/ab.toml" b /guest/ack-log correct 3000
cp "$o/ab.toml" "$o/b.toml"; printf '[faults]\nfsync-error-permille = "5@b"\n' >>"$o/b.toml"
# The driver stops at its own first fsync error; it then waits, so that the run does not end
# before the nodes have made as many fsyncs.
check() {  # check NAME DRIVER A B
    [ "$(err "$o/$1" .)" = "$2" ] && [ "$(err "$o/$1" node/a)" = "$3" ] && [ "$(err "$o/$1" node/b)" = "$4" ] \
        || die "$1: fsync errors on driver, a, b: $(err "$o/$1" .) $(err "$o/$1" node/a) $(err "$o/$1" node/b), expected $2 $3 $4"
    echo "$1: fsync errors on driver $2, a $3, b $4"
}
run_ok "$o/all" 1 --config "$o/ab.toml" --fault fsync-error-permille=5 -- sh -c "/guest/ack-log correct 2000; sleep 2"  # lint-allow: sleep — the guest's, in virtual time
check all no yes yes
run_ok "$o/scoped" 1 --config "$o/ab.toml" --fault fsync-error-permille=5@a,driver -- sh -c "/guest/ack-log correct 2000; sleep 2"  # lint-allow: sleep — the guest's, in virtual time
check scoped yes yes no
run_ok "$o/table" 1 --config "$o/b.toml" -- sh -c "/guest/ack-log correct 2000; sleep 2"  # lint-allow: sleep — the guest's, in virtual time
check table no no yes
[ "${CHECK_TIER:-}" != quick ] || exit 0
# Machine crashes beside fsync errors: seeds 1-8 of correct (restarted after it stops) and retry.
F="--faults crash --fault crash-gap-ms=1..4 --fault down-ms=100..300 --fault max-incarnations=8 --fault fsync-error-permille=1"
rm -f "$o/ok.toml" "$o/retry.toml"
conf "$o/ok.toml" a /guest/ack-log correct 1000000; printf 'restart = "always"\n' >>"$o/ok.toml"
conf "$o/retry.toml" a /guest/ack-log retry 1000000
rm -rf "${o:?}/ok"
st=0
timeout 600 "$PATINA" sweep --seeds 1..8 -j 4 --keep all --out "$o/ok" --config "$o/ok.toml" $F \
    --mount "$PATINA_GUESTS":/guest:copy -- sleep 6 >"$o/ok.txt" 2>&1 || st=$?
[ -f "$o/ok/report.json" ] || { tail -20 "$o/ok.txt"; die "sweep ok: no report (exit $st)"; }
out=$(field "$o/ok/report.json" outcomes)
[ "$out" = '{"ok":8}' ] || { tail -30 "$o/ok.txt"; die "correct: $out"; }
set -- $(python3 -I -c 'import json,sys
k=c=0
for f in sys.argv[1:]:
    r=json.load(open(f))
    k+=sum(d["how"] == "machine crash" for d in r["nodes"]["list"][1].get("downs", []))
    c+=r["self_check"]["verdict"] == "pass"
print(k, c)' "$o"/ok/seed-*/result.json)
[ "$1" -ge 1 ] || die "correct: no machine crash in 8 runs (the scenario never arose)"
[ "$2" = 8 ] || die "correct: the self-check passed in only $2 of 8 runs"
echo "correct: ok on seeds 1-8, $1 machine crashes, self-check passed in all"
verify_ok "$o/verify" 2 3 --config "$o/ok.toml" $F -- sleep 6
r=$(find_bug "$o" retry --config "$o/retry.toml" $F -- sleep 6)
echo "retry: $r"
