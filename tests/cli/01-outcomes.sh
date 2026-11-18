# 1. One guest per outcome: each run ends with that outcome in result.json and exits with the
#    status `patina --help --format json` gives for it. A missing program is `error` naming the
#    file; a call on a `Stop` row of `patina table` is `unsupported` naming the call.
#@ tier=quick budget=15
. "$(dirname "$0")/lib.inc"
G=$PATINA_GUESTS
# expect NAME OUTCOME STOP [run options] -- CMD...
expect() {
    n=$1 want=$2 stop=$3; shift 3
    prun "$RUNS/$n" --seed 1 "$@" # lint-allow: seed — each guest's outcome is fixed by the program (a barrier forces the deadlock), not by the seed
    [ -f "$RUNS/$n/result.json" ] || die "$n: no result.json ($(tail -2 "$RUNS/$n.txt"))"
    got=$(field "$RUNS/$n/result.json" outcome)/$(field "$RUNS/$n/result.json" stop)
    [ "$got" = "$want/$stop" ] || die "$n: $got, expected $want/$stop ($(field "$RUNS/$n/result.json" message))"
    [ "$st" = "$(exit_of "$want")" ] || die "$n: exit status $st for $want"
    [ "$(field "$RUNS/$n/result.json" exit)" = "$st" ] || die "$n: result.json exit differs from the exit status"
    echo "$n: $want ($stop), exit $st: $(field "$RUNS/$n/result.json" message)"
}
expect exit0 ok exit -- "$G/hello-static" a
expect exit3 failure exit -- /bin/sh -c 'exit 3'
[ "$(field "$RUNS/exit3/result.json" guest.exit)" = 3 ] || die "exit3: guest.exit"
expect abort crash signal -- /usr/bin/python3 -c 'import os; os.abort()'
expect deadlock liveness deadlock -- "$G/deadlock"
expect sleeploop liveness time-limit --time-limit 100 -- "$G/liveness"
# The first Stop row of the syscall table.
set -- $("$PATINA" table | awk -F'|' '$4 ~ /Stop/ {gsub(/ /, ""); print $2, $3; exit}')
[ $# = 2 ] || die "no Stop row in patina table"
nr=$1 name=$2
expect stoprow unsupported syscall -- /usr/bin/python3 -c "import ctypes; ctypes.CDLL(None).syscall($nr, 0, 0, 0, 0)"
field "$RUNS/stoprow/result.json" message | grep -qw "$name" || die "stoprow: message does not name $name"
expect timeout timeout timeout --timeout 1 -- /bin/sh -c 'while :; do :; done'
# A missing program: no run, `error`, the file named.
prun "$RUNS/missing" --seed 1 -- "$RUNS/no-such-program"
[ "$st" = "$(exit_of error)" ] || die "missing: exit status $st"
grep -q 'error' "$RUNS/missing.txt" && grep -qF -e "$RUNS/no-such-program" -e "$(realpath "$RUNS")/no-such-program" "$RUNS/missing.txt" \
    || die "missing: $(cat "$RUNS/missing.txt")"
echo "missing: exit $st: $(head -1 "$RUNS/missing.txt")"
