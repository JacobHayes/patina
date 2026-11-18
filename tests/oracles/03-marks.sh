# SDK labels in clear (`Str` records after the call, exported as `label` and `text`): a C, a
# Rust, a Go and a Python guest mark "ack 1", write a file, mark "ack 2", and the events show
# both labels in order with the write between; a 255-byte label comes back whole; a label with
# a newline, a quote, a backslash, a NUL and a byte that is not UTF-8 comes back as its exact
# bytes (`label_hex`); a mark's text; a payload ending at the end of a mapping is read, and one
# at a bad pointer or running past the mapping is EFAULT with no label. Marks from two threads
# and a forked child: `verify --vary cpu,aslr,load` identical, each mark with its process. A
# program that makes no SDK call has no string record. examples/checks/synced-before-mark on
# marklog (no crash, no faults): one finding on every seed of a range, naming the first
# acknowledgement; `marklog fixed` (a progress mark before each fsync) passes with the prefix
# `ack` and fails when every mark is judged.
#@ tier=area budget=20 slots=4
: "${PATINA:?}" "${RUNS:?}" "${PATINA_GUESTS:?}"
root=$(cd "$(dirname "$0")/../.." && pwd)
marks=$PATINA_GUESTS/oracles-marks marklog=$PATINA_GUESTS/oracles-marklog
die() { echo "FAIL: $*"; exit 1; }
cd "$RUNS"
export PATINA

# Four languages: the labels and the write between them.
for lang in c rs go py; do
    case $lang in py) cmd="/usr/bin/python3 /guest/sdk-py.py" ;; *) cmd=/guest/sdk-$lang ;; esac
    # shellcheck disable=SC2086
    "$PATINA" run --out "lang-$lang" --mount "$PATINA_GUESTS:/guest" -- $cmd marks >"lang-$lang.txt" 2>&1 || die "$lang: $(tail -2 "lang-$lang.txt")"
    got=$("$PATINA" log events "lang-$lang" --types mark,op | jq -r 'select(.type == "mark" or (.type == "op" and .op == "write" and .path == "/work/marked")) | .label // .op' | paste -sd,)
    [ "$got" = "ack 1,write,ack 2" ] || die "$lang: marks and the write: $got"
done

# The edges of a label, from one C guest.
"$PATINA" run --out edge -- "$marks" edge >edge.txt 2>&1 || die "edge: $(tail -2 edge.txt)"
"$PATINA" log events edge --types mark >edge.jsonl
want=$(awk 'BEGIN { for (i = 0; i < 255; i++) printf "%d", i % 10 }')
[ "$(jq -r 'select(.len == 255) | .label' edge.jsonl)" = "$want" ] || die "the 255-byte label: $(jq -c 'select(.len == 255)' edge.jsonl)"
[ "$(jq -r 'select(.len == 10) | .label_hex' edge.jsonl)" = 610a6222635c64ff0065 ] || die "odd bytes: $(jq -c 'select(.len == 10)' edge.jsonl)"
[ "$(jq -r 'select(.label == "with-text") | .text' edge.jsonl)" = "some text" ] || die "a mark's text: $(grep with-text edge.jsonl)"
[ "$(jq -r 'select(.label == "at-end!") | .ret' edge.jsonl)" = 0 ] || die "a payload at the end of a mapping"
[ "$(jq -c 'select(.ret == -14) | has("label")' edge.jsonl | paste -sd,)" = "false,false" ] || die "EFAULT payloads: $(jq -c 'select(.ret != 0)' edge.jsonl)"
grep -qx 'across -14' edge/inc-0/stdout && grep -qx 'end 0' edge/inc-0/stdout || die "edge answers: $(cat edge/inc-0/stdout)"

# Threads and a child: identical under the host's variations; each label with its process.
rc=0
"$PATINA" verify --seed 1 --runs 3 --vary cpu,aslr,load --out thr -- "$marks" threads >thr.txt 2>&1 || rc=$? # lint-allow: seed — verify repeats one seed; any seed shows it
[ "$rc" = 0 ] && grep -q '^identical: 3 runs' thr.txt || die "marks from threads: exit $rc: $(tail -3 thr.txt)"
pids=$("$PATINA" log events thr/run-0 --types mark | jq -r 'select(.type == "mark") | "\(.label | split(" ")[0])=\(.pid)"' | sort -u | paste -sd,)
case $pids in child=*,t1=*,t2=*) ;; *) die "marks and their processes: $pids" ;; esac
[ "$(echo "$pids" | tr ',' '\n' | cut -d= -f2 | sort -u | wc -l)" = 2 ] || die "two processes: $pids"

# No SDK call, no string record.
"$PATINA" run --out nosdk -- "$PATINA_GUESTS/hello-static" >nosdk.txt 2>&1 || die "hello: $(tail -2 nosdk.txt)"
"$PATINA" log dump nosdk/inc-0/boundary.log >nosdk.dump || die "log dump of nosdk"
n=$(awk '$2 == "str" {n++} END {print n + 0}' nosdk.dump)
[ "$n" = 0 ] || die "string records in a run without SDK calls"

# synced-before-mark: every seed of the bug, one signature; the fix passes; all marks judged,
# the fix's progress marks fail it.
sbm=$root/examples/checks/synced-before-mark
sweep() { rc=0; "$PATINA" sweep --seeds 1..5 -j 4 --out "$1" --check "$2" -- "$marklog" ${3:-} >"$1.txt" 2>&1 || rc=$?; echo "$rc $(jq -r '"\(.findings) \([.groups[].signature] | join(" | "))"' "$1/report.json")"; }
[ "$(sweep sbm-bug "$sbm /work/data.log ack")" = "1 5 violation check: ack-before-fsync: ack N (seq N) follows an unsynced write to /work/data.log" ] || die "marklog: $(sweep sbm-bug "$sbm /work/data.log ack")"
[ "$(sweep sbm-fixed "$sbm /work/data.log ack" fixed)" = "0 0 " ] || die "marklog fixed: $(tail -3 sbm-fixed.txt)"
[ "$(sweep sbm-all "$sbm /work/data.log ''" fixed)" = "1 5 violation check: ack-before-fsync: wrote N (seq N) follows an unsynced write to /work/data.log" ] || die "marklog fixed, every mark: $(tail -3 sbm-all.txt)"
echo "ok: labels in four languages, whole, exact, with text; threads identical; marklog found on 5 of 5 seeds, fixed passes, progress marks told apart"
