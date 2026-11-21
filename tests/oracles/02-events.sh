# `patina log events` on the run directories a user has: every injected fault of a run once,
# the last ones as result.json's faults.recent names them; crashes and the incarnations after
# them, with each incarnation's operations named on its own tree; a sweep's cut log (head, a
# `cut` line, tail) and a pruned run (an error, no stream); an operation after its call; the
# filters.
#@ tier=area budget=20 slots=4
: "${PATINA:?}" "${RUNS:?}" "${PATINA_GUESTS:?}"
kv=$PATINA_GUESTS/examples/kvlog churn=$PATINA_GUESTS/churn
die() { echo "FAIL: $*"; exit 1; }
cd "$RUNS"

# Faults: more than result.json keeps (its last 20), each once.
"$PATINA" run --out faults --fault fs-delay-permille=700 -- "$kv" fixed >faults.txt 2>&1 || die "faults run: $(tail -2 faults.txt)"
"$PATINA" log events faults >faults.jsonl
injected=$(jq .faults.injected faults/result.json)
[ "$injected" -gt 20 ] || die "faults run: only $injected faults injected"
[ "$(jq -s 'map(select(.type == "fault" and .class != "fsync-report" and .class != "other")) | length' faults.jsonl)" = "$injected" ] ||
    die "fault events differ from faults.injected ($injected)"
jq -c 'select(.type == "fault") | {seq, fault: .class, object, call}' faults.jsonl | tail -n 20 >events-recent
jq -c '.faults.recent[] | {seq, fault, object, call}' faults/result.json >result-recent
cmp -s events-recent result-recent || die "the last fault events are not faults.recent: $(diff events-recent result-recent | head -4)"

# Crashes: a kept run with several incarnations.
"$PATINA" sweep --seeds 1..12 -j 4 --keep all --fault crash-permille=10 --out crashes -- "$kv" fixed >crashes.txt 2>&1 || die "crash sweep: $(tail -2 crashes.txt)"
n=0
for d in crashes/seed-*; do
    k=$(jq .incarnations "$d/result.json")
    [ "$k" -gt 1 ] || continue
    n=$((n + 1))
    "$PATINA" log events "$d" >"$d/events.jsonl"
    cp "$d/events.jsonl" c.jsonl
    # An incarnation after a crash, and the crash before it; the operations of every
    # incarnation name data.log by its path on that incarnation's tree.
    got=$(jq -r 'select(.type == "inc" or .type == "crash") | "\(.type)\(.inc)"' c.jsonl | paste -sd,)
    want=$(i=0; while [ $i -lt "$k" ]; do printf 'inc%s' $i; [ $i = $((k - 1)) ] || printf ',crash%s,' $i; i=$((i + 1)); done)
    [ "$got" = "$want" ] || die "$d: incarnations and crashes: $got, want $want"
    lhs=$(jq -s '[.[] | select(.type == "crash")] | length' c.jsonl); rhs=$(jq '.crashes | length' "$d/result.json")
    [ "$lhs" = "$rhs" ] || die "$d: crash count"
    bad=$(jq -r 'select(.type == "op" and (.op | IN("write", "fsync")) and .path != "/work/data.log") | .inc' c.jsonl | sed -n 1p)
    [ -z "$bad" ] || die "$d: inc-$bad: an operation not on /work/data.log"
    [ "$(jq -s '[.[] | select(.type == "op" and .op == "write" and .inc > 0)] | length' c.jsonl)" -gt 0 ] || die "$d: no writes after the crash"
done
[ "$n" -gt 0 ] || die "no run of the crash sweep crashed"

# An operation follows its call: the line before it is that call or another operation of it.
for f in faults.jsonl crashes/seed-*/events.jsonl; do
    bad=$(jq -rn '[inputs] as $e | ($e | map(select(.type == "call") | {key: "\(.inc) \(.seq)", value: 1}) | from_entries) as $calls
        | range(1; $e | length) | select($e[.].type == "op" and $calls["\($e[.].inc) \($e[.].seq)"])
        | select($e[. - 1].seq != $e[.].seq or ($e[. - 1].type | IN("call", "op") | not)) | $e[.]' "$f" | sed -n 1p)
    [ -z "$bad" ] || die "$f: an operation away from its call: $bad"
done

# Filters.
"$PATINA" log events faults --types op >f1
jq -e -s 'map(.type) - ["header", "inc", "op"] | length == 0' f1 >/dev/null || die "--types op"
s=$(jq -s 'map(select(.type == "op"))[3].seq' faults.jsonl)
"$PATINA" log events faults --from "$s" --to "$s" >f2
jq -e -s --argjson s "$s" 'map(select(.seq != null)) | length > 0 and all(.seq == $s)' f2 >/dev/null || die "--from/--to"
rc=0
"$PATINA" log events faults --types nosuch >/dev/null 2>&1 || rc=$?
[ "$rc" = 2 ] || die "--types nosuch: exit $rc"

# A sweep's cut log: its first and last records, a `cut` line between; a pruned run: no stream.
"$PATINA" sweep --seeds 1..2 --config "$("$PATINA_CFG" log-limit=12)" --out cut -- "$churn" 100000000 >cut.txt 2>&1 || true
d=$(ls -d cut/seed-* | sed -n 1p)
[ -f "$d/inc-0/boundary.cut" ] || die "the cut sweep kept no cut log: $(tail -2 cut.txt)"
"$PATINA" log events "$d" >cut.jsonl
# Its events are the whole log's first and last, as the replay (which writes the whole log)
# gives them: the last head event may have lost the strings that follow its record.
"$PATINA" replay "$d" --out cut-replay >cut-replay.txt 2>&1 || true
grep -q '^identical' cut-replay.txt || die "replay of the cut run: $(head -2 cut-replay.txt)"
"$PATINA" log events cut-replay >whole.jsonl
python3 -I - cut.jsonl whole.jsonl <<'PY' || die "cut log: its events are not the whole log's head and tail"
import json, sys
cut, whole = ([json.loads(l) for l in open(f)] for f in sys.argv[1:])
assert [e["type"] for e in cut].count("cut") == 1, "one cut line"
i = [e["type"] for e in cut].index("cut")
rec = lambda l: [{k: v for k, v in e.items() if k != "seq"} for e in l if e["type"] not in ("header", "inc", "cut", "op")]
head, tail, all_ = rec(cut[:i]), rec(cut[i + 1:]), rec(whole)
assert head and tail and len(head) + len(tail) < len(all_), (len(head), len(tail), len(all_))
assert head[:-1] == all_[:len(head) - 1] and head[-1]["type"] == all_[len(head) - 1]["type"], "head"
assert tail == all_[len(all_) - len(tail):], "tail"
PY
"$PATINA" sweep --seeds 1..2 --out pruned -- "$kv" fixed >pruned.txt 2>&1 || die "pruned sweep: $(tail -2 pruned.txt)"
rc=0
"$PATINA" log events pruned/seed-1 >pruned.jsonl 2>pruned.err || rc=$?
[ "$rc" = 2 ] && [ ! -s pruned.jsonl ] && [ -s pruned.err ] || die "a pruned run: exit $rc, $(wc -l <pruned.jsonl) lines"
echo "ok: $injected faults, $n crashed runs, a cut log of $(jq .records "$d/inc-0/boundary.cut") records"
