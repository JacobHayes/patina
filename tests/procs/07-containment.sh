# 7. Containment. /guest/daemons starts 50 daemons (double fork, setsid, every signal ignored,
# every descriptor below 1024 closed, sleep forever), then keeps the run alive for a while
# (linger: getppid calls) and exits 0. (a) The run ends when that main guest exits, as ok.
# (b) The launcher is killed with SIGKILL while the daemons live. In both cases, afterwards no
# process of the run remains (none holds anything of the run directory, none is in any of the
# run's namespaces, captured while it lived) and no mount from it exists.
#@ tier=quick budget=40
. "$(dirname "$0")/lib.inc"
o=$RUNS/07-containment
mkdir -p "$o"

# (a) normal end
rm -rf "${o:?}/a"
timeout 300 "$PATINA" run --seed 1 --out "$o/a" --mount "$PATINA_GUESTS":/guest:copy -- /guest/daemons 50 linger 200000 >/dev/null 2>"$o/a.err" &
launcher=$!
python3 -I "$HERE/sandbox.py" "$o/a" procs:52 120 >"$o/a.ns" 2>"$o/a.alive" || { kill "$launcher"; die "(a) sandbox not seen"; }
seen=$(cut -d' ' -f1 /proc/uptime)
echo "(a) while running: $(cat "$o/a.alive"); namespaces: $(tr '\n' ' ' <"$o/a.ns")"
n=$(sed -n 's/.*(\([0-9]*\) inside its PID namespace).*/\1/p' "$o/a.alive")
[ "$n" -ge 52 ] || die "(a) only $n processes alive in the sandbox (supervisor, main, 50 daemons expected)"
wait "$launcher" || die "(a) patina run exit $?"
grep -q 'daemons started: 50' "$o/a/inc-0/stdout" || die "(a) the guest did not report its daemons"
[ "$(field "$o/a/result.json" outcome)" = ok ] || die "(a) class $(field "$o/a/result.json" outcome)"
[ "$(field "$o/a/result.json" guest.exit)" = 0 ] || die "(a) exit status"
set -- --started-before "$seen"; while read -r ns; do set -- "$@" --ns "$ns"; done <"$o/a.ns"
no_leftovers "$o/a" "$@"
mounts=$(findmnt)
for ns in $(cat "$o/a.ns"); do case $mounts in *"$ns"*) die "(a) $ns still mounted" ;; esac; done
echo "(a) run ended ok when the main guest exited; no process, namespace holder or mount left"

# (b) launcher killed with SIGKILL mid-run
rm -rf "${o:?}/b"
"$PATINA" run --seed 1 --out "$o/b" --mount "$PATINA_GUESTS":/guest:copy -- /guest/daemons 50 linger 200000000 >/dev/null 2>"$o/b.err" &
launcher=$!
python3 -I "$HERE/sandbox.py" "$o/b" procs:52 120 >"$o/b.ns" 2>"$o/b.alive" || { kill -KILL "$launcher"; die "(b) sandbox not seen"; }
seen=$(cut -d' ' -f1 /proc/uptime)
echo "(b) while running: $(cat "$o/b.alive"); namespaces: $(tr '\n' ' ' <"$o/b.ns")"
kill -KILL "$launcher"
wait "$launcher" || true
set -- --started-before "$seen"; while read -r ns; do set -- "$@" --ns "$ns"; done <"$o/b.ns"
# Teardown after the launcher's death is asynchronous (bwrap's parent-death signal, then the
# PID namespace's end); give it up to 10 s.
i=0
while ! python3 -I "$HERE/../leftovers.py" "$o/b" "$@" >"$o/b.left"; do
    i=$((i + 1)); [ "$i" -le 100 ] || die "(b) processes left 10 s after the launcher was killed: $(head -5 "$o/b.left")"
    sleep 0.1
done
no_leftovers "$o/b" "$@"
mounts=$(findmnt)
for ns in $(cat "$o/b.ns"); do case $mounts in *"$ns"*) die "(b) $ns still mounted" ;; esac; done
echo "(b) launcher SIGKILLed: no process, namespace holder or mount left after $((i * 100)) ms"
