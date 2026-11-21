# 5. A serving checker's life (its file names PATINA_CHECK_SERVE), beside the quick tier's (01-checks.sh): one
#    that ends after two answers is started again and every run is judged; one that answers
#    twice, or before it is asked, makes the sweep's result `error`; an alternating one makes the
#    replay `error check-unstable`, and a replay of a served finding is identical (a server of
#    its own); an interrupted sweep whose server never answers leaves no run passed and no
#    process. The checker gets `PATINA`. A case line's settings are part of the case: a sweep
#    run again keeps the cases whose line is unchanged and replaces the one whose --env changed.
#@ tier=area budget=30 slots=4
: "${PATINA:?}" "${RUNS:?}" "${PATINA_GUESTS:?}"
root=$(cd "$(dirname "$0")/../.." && pwd)
hello=$PATINA_GUESTS/hello-static
die() { echo "FAIL: $*"; exit 1; }
cd "$RUNS"
mkdir chk
# serve VERDICTS-SCRIPT: a server whose answer to each request is what the sh snippet prints
serve() { printf '#!/bin/sh\n# PATINA_CHECK_SERVE\nd=$(dirname "$0")\necho start >>"$d/%s.starts"\nwhile read -r l; do\n%s\ndone\n' "$1" "$2" >chk/$1; chmod +x chk/$1; }
serve twice 'n=$((${n:-0} + 1)); echo pass; [ $n -lt 2 ] || exit 0'
serve double 'echo pass; echo pass'
serve early 'echo pass' && sed -i 's/^while/echo pass\nwhile/' chk/early
serve flip 'f=$d/flip.state; if [ -f "$f" ]; then rm "$f"; echo pass; else : >"$f"; echo "fail flaky: odd call"; fi'
serve wrong 'echo "fail wrong-answer: $PATINA_SEED"'
serve hang 'exec tail -f /dev/null'
serve env 'echo "$PATINA" >"$d/patina.seen"; echo pass'
# sweep NAME CHECKER [FLAGS]: 8 runs of hello, 2 jobs, served by chk/CHECKER; prints the exit status
sweep() { n=$1 k=$2; shift 2; rc=0; "$PATINA" sweep --seeds 1..8 -j 2 --out "$n" --check "chk/$k" "$@" -- "$hello" >"$n.txt" 2>&1 || rc=$?; echo "$rc"; }
check() { jq -c '[.check.passed, .check.failed, .check.errors]' "$1/report.json"; }

[ "$(sweep twice twice)" = 0 ] && [ "$(check twice)" = "[8,0,0]" ] || die "a server that ends after two answers: $(check twice): $(tail -3 twice.txt)"
[ "$(wc -l <chk/twice.starts)" -ge 4 ] || die "a server that ends after two answers was started $(wc -l <chk/twice.starts) times for 8 runs"
for s in double early; do
    rc=$(sweep $s $s)
    # The extra line is found at the latest by the job's next request: that run is an error.
    [ "$rc" = 2 ] && [ "$(jq .check.errors $s/report.json)" -ge 1 ] || die "a server that answers $s: exit $rc, $(check $s)"
done
rc=$(sweep env env); seen=$(sort -u chk/patina.seen); self=$(realpath "$PATINA")
[ "$rc" = 0 ] && [ "$seen" = "$self" ] || die "PATINA for a served checker: exit $rc, $seen"

# Replays: a server of their own, the same verdict; an alternating one is check-unstable.
rc=$(sweep wrong wrong)
first=$(jq -r '.groups[0].first.dir' wrong/report.json)
[ "$rc" = 1 ] && [ "$(jq -r '.groups[0].replay.result' wrong/report.json)" = identical ] || die "a served finding's replay: exit $rc, $(jq -c '.groups[0].replay' wrong/report.json)"
rc=0
"$PATINA" run --out flip --format json --check chk/flip -- "$hello" >flip.json 2>flip.err || rc=$?
[ "$rc $(jq -r .outcome flip.json)" = "1 violation" ] || die "an alternating server: exit $rc, $(cat flip.err)"
rc=0
"$PATINA" replay flip --format json >flip-replay.json 2>&1 || rc=$?
[ "$rc $(jq -r '"\(.outcome) \(.stop)"' flip-replay.json)" = "2 error check-unstable" ] || die "an alternating server's replay: exit $rc, $(cat flip-replay.json)"

# Interrupted while the server holds every run: none passes, nothing is left running.
"$PATINA" sweep --seeds 1..8 -j 2 --out hang --check chk/hang -- "$hello" >hang.txt 2>&1 &
pid=$!
i=0
while [ "$(wc -l 2>/dev/null <chk/hang.starts || echo 0)" -lt 2 ] && [ $i -lt 200 ]; do sleep 0.05; i=$((i + 1)); done
kill -INT $pid
rc=0
wait $pid || rc=$?
passed=""
for f in hang/seed-*/result.json; do
    [ ! -e "$f" ] || passed="$passed$(jq -r 'select(.check.verdict == "pass") | .seed' "$f")"
done
[ "$rc" != 0 ] && [ -z "$passed" ] || die "an interrupted served sweep: exit $rc, a run passed"
python3 -I "$root/tests/leftovers.py" "$RUNS" || die "an interrupted served sweep left processes"

# Case lines: their settings are part of the case when a sweep resumes.
printf '%s\n' "--env V=1 -- /bin/sh -c 'echo \$V' a" "--env V=2 -- /bin/sh -c 'echo \$V' b" >cases.txt
"$PATINA" sweep --seeds 1 --keep all --cases cases.txt --out cs >cs.txt 2>&1 || die "case sweep: $(tail -3 cs.txt)"
: >cs/seed-1/1-a/kept && : >cs/seed-1/2-b/kept
sed -i 's/V=2/V=3/' cases.txt
"$PATINA" sweep --seeds 1 --keep all --cases cases.txt --out cs >cs2.txt 2>&1 || die "case sweep again: $(tail -3 cs2.txt)"
[ -f cs/seed-1/1-a/kept ] && [ ! -f cs/seed-1/2-b/kept ] && [ "$(cat cs/seed-1/2-b/inc-0/stdout)" = 3 ] || die "resuming with one case line changed: $(ls cs/seed-1/*)"
echo "ok: servers restarted ($(wc -l <chk/twice.starts) starts for 8 runs), double and early answers are errors, replays identical and check-unstable, an interrupted sweep passes nothing and leaves nothing, a changed case line runs again"
