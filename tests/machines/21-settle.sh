# 21. `patina ctl settle` (tests/guests/machines/phases.py): the test ends the seed's faults
# and waits for the system to recover, then checks it. One machine under crashes at a high rate:
# the check after settle runs once, in the last boot, which no crash ends; the seed's crashes
# all came before the settle point. Machines a and b store puts, b acknowledging before its
# fsync (`lazy`): the check after settle finds the puts a machine crash lost, nothing is injected
# after the settle point, and the correct store is ok. A machine the seed took down with a
# minute's down time boots at once at settle. A machine the script crashed, after the seed had
# already taken it down, stays down and is not waited for. Settle runs the machines' `ready`
# probes again: a machine whose probe passed at boot and never passes again does not recover, and
# `settle 5` ends the run liveness, stop settle, naming it. Replay identical.
#@ tier=quick budget=40 slots=2
. "$(dirname "$0")/lib.inc"
o=$RUNS/21-settle; mkdir -p "$o"
for v in ok lazy; do
    rm -f "$o/$v.toml"
    conf "$o/$v.toml" a python3 /guest/phases.py serve
    if [ $v = ok ]; then conf "$o/$v.toml" b python3 /guest/phases.py serve; else conf "$o/$v.toml" b python3 /guest/phases.py serve lazy; fi
    main_unfaulted "$o/$v.toml"
done

# after_settle DIR: the seed's faults and downs after the settle point (none expected), one per line.
after_settle() {
    s=$(field "$1/result.json" settle.seq)
    "$PATINA" inspect events "$1" --types machine,fault,crash,net >"$1.ev" || die "log events $1"
    jq -c --argjson s "$s" 'select(.seq != null and .seq > $s and (.type == "fault" or .type == "crash" or .by == "seed"))' "$1.ev"
}

# One machine: app && settle && verify, crashes at 30% of the crash points.
one='for i in 1 2 3; do echo $i >>/work/f; done; patina ctl settle && echo verify && for i in $(seq 20); do echo v$i >>/work/f; done'
k=1
while :; do
    run_ok "$o/one" $k --fault crash-permille=300 --fault max-boots=30 -- sh -c "$one"
    b=$(field "$o/one/result.json" boots)
    [ "$b" -gt 1 ] && break
    k=$((k + 1)); [ $k -le 8 ] || die "seeds 1-8: no crash before settle"
done
[ "$b" -lt 30 ] || die "seed $k: $b boots: the crashes went on after settle"
n=$(cat "$o"/one/boot-*/stdout | grep -c '^verify$') || true
[ "$n" = 1 ] && grep -q '^verify$' "$o/one/boot-$b/stdout" || die "seed $k: verify ran $n times, not once in boot $b"
s=$(field "$o/one/result.json" settle.seq)
jq -e --argjson s "$s" 'all(.crashes[]; .seq < $s)' "$o/one/result.json" >/dev/null || die "seed $k: a crash after settle (seq $s)"
echo "one machine, seed $k: $((b - 1)) crashes, then settle; verify ran once, in boot $b"

# The planted bug: found by the check after settle.
find_bug "$o" lazy --config "$o/lazy.toml" --faults crash --fault crash-gap-ms=1000..4000 --fault max-boots=8 \
    -- sh -c "python3 /guest/phases.py work 10 a b && patina ctl settle && python3 /guest/phases.py check 10 a b"
r=$(field "$o/lazy/report.json" groups.0.first.dir)
[ "$(field "$r/result.json" outcome)" = failure ] || die "lazy: $(field "$r/result.json" message)"
grep -q 'lost acknowledged puts' "$r/boot-1/stderr" || die "lazy: $(tail -3 "$r/boot-1/stderr")"
x=$(after_settle "$r")
[ -z "$x" ] || die "lazy: injected after settle: $x"
echo "lazy: the check after settle found the lost puts; nothing injected after the settle point"

# The correct store: ok on four seeds, nothing after settle.
rm -rf "${o:?}/ok"; st=0
timeout 300 "$PATINA" sweep --seeds 1..4 -j 4 --keep all --out "$o/ok" --config "$o/ok.toml" --faults crash \
    --fault crash-gap-ms=1000..4000 --fault max-boots=8 --mount "$PATINA_GUESTS":/guest:copy \
    -- sh -c "python3 /guest/phases.py work 10 a b && patina ctl settle && python3 /guest/phases.py check 10 a b" >"$o/ok.txt" 2>&1 || st=$?
[ "$(field "$o/ok/report.json" outcomes)" = '{"ok":4}' ] || { tail -20 "$o/ok.txt"; die "correct: exit $st"; }
for r in "$o"/ok/seed-*; do x=$(after_settle "$r"); [ -z "$x" ] || die "$r: injected after settle: $x"; done
echo "correct: ok on seeds 1-4"

# The seed kills b with a minute's down time; settle boots it at once.
K="--config $o/ok.toml --faults kill@b --fault crash-gap-ms=500..1000 --fault down-ms=60000..60000"
run_ok "$o/boot" 1 $K -- sh -c 'sleep 3; patina ctl settle && python3 /guest/phases.py check 0 a b'  # lint-allow: sleep — the guest's, in virtual time
[ "$(field "$o/boot/result.json" machines.list.2.boots)" = 2 ] || die "b's boots: $(field "$o/boot/result.json" machines.list.2)"
t=$(field "$o/boot/result.json" settle.vclock_ns)
"$PATINA" inspect events "$o/boot" --types machine >"$o/boot.ev"
jq -e -s --argjson t "$t" 'any(.[]; .event == "start" and .name == "b" and .machine_boot == 2 and .t - $t < 1000000000)' "$o/boot.ev" >/dev/null \
    || die "b did not boot at settle: $(grep '"b"' "$o/boot.ev")"
"$PATINA" replay "$o/boot" >"$o/replay.txt" 2>&1 && grep -q '^identical' "$o/replay.txt" || die "replay: $(head -3 "$o/replay.txt")"
echo "seed's kill: b booted at settle, not a minute later; replay identical"

# The seed kills b, then the script crashes it: it stays down and settle does not wait for it.
run_ok "$o/script" 1 $K -- sh -c 'sleep 3; patina ctl crash b; patina ctl settle && python3 /guest/phases.py check 0 a'  # lint-allow: sleep — the guest's, in virtual time
grep -q 'crash b: .*os error 114' "$o/script/boot-1/stderr" || die "the script's crash of b: not refused as already down"
[ "$(field "$o/script/result.json" machines.list.2.boots)" = 1 ] || die "b booted again: $(field "$o/script/result.json" machines.list.2)"
echo "script's crash: b stayed down, not waited for"

# A machine whose probe passes once, at boot, and never again: it does not recover. Liveness,
# stop settle, naming it.
rm -f "$o/once.toml"
conf "$o/once.toml" a python3 /guest/phases.py serve
printf 'ready = ["sh", "-c", "test ! -e /tmp/probed && touch /tmp/probed"]\n' >>"$o/once.toml"
conf "$o/once.toml" b python3 /guest/phases.py serve
main_unfaulted "$o/once.toml"
c=$(run "$o/stuck" 1 --config "$o/once.toml" -- sh -c 'python3 /guest/phases.py work 2 a b && patina ctl settle 5')
m=$(field "$o/stuck/result.json" message)
[ "$c/$(field "$o/stuck/result.json" stop)" = liveness/settle ] && grep -q 'machine a\b' <<<"$m" || die "a's probe: $c: $m"
"$PATINA" replay "$o/stuck" >"$o/replay.txt" 2>&1 || true  # exit 1: the run's finding
grep -q '^identical' "$o/replay.txt" || die "replay: $(head -3 "$o/replay.txt")"
echo "a probe that never passes again: $c (settle): $m; replay identical"
