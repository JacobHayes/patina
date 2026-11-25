# 5. Machines: a machine's processes killed and started again (tests/guests/machines/kill.py). The
# main kills machine b with `kill b` and starts it with `start b`, 50 times:
# each kill ends both of b's connections (its first process's and its child's), a connect to
# either port is refused while b is down, a kill of a machine that is down and a start of one that
# is up are refused, and each restart finds the disk the last one left and its own
# PATINA_BOOT; result.json, the events and machine/b/boot-K/ show every boot. The
# same under verify. A machine's own end: an exit outside `ok-exit` ends the run `failure`
# naming the machine, a signal `crash`; an exit within it stops the machine, and `restart = "always"`
# starts it again up to `max-boots`; `count` makes that many machines of one table.
#@ tier=quick budget=60 slots=1
. "$(dirname "$0")/lib.inc"
o=$RUNS/05-kill; mkdir -p "$o"
rm -f "$o/b.toml"; conf "$o/b.toml" b python3 /guest/kill.py b

k=50
run_ok "$o/kill" 1 --config "$o/b.toml" -- python3 /guest/kill.py main $k
sed 's/^/    /' "$o/kill/boot-1/stdout"
[ "$(field "$o/kill/result.json" machines.list.1.boots)" = $((k + 1)) ] || die "b: $(field "$o/kill/result.json" machines.list.1)"
hows=$(jq -r '[.machines.list[1].downs[].how] | unique | join(" ")' "$o/kill/result.json")
[ "$hows" = "killed by script" ] || die "b's downs: $hows"
n=$("$PATINA" inspect events "$o/kill" --types machine | grep -c '"event":"kill","name":"b".*"by":"script"')
[ "$n" = $k ] || die "kill events of b: $n"
n=$("$PATINA" inspect events "$o/kill" --types machine | grep -c '"event":"start","name":"b".*"machine_boot"')
[ "$n" = $k ] || die "restart events of b: $n"
for i in 1 $k $((k + 1)); do
    grep -q "^b: start $i, boot $i\$" "$o/kill/machine/b/boot-$i/stdout" \
        || die "machine/b/boot-$i/stdout: $(cat "$o/kill/machine/b/boot-$i/stdout")"
done
echo "b: $((k + 1)) boots, one directory each, $(field "$o/kill/result.json" faults.injected) faults injected"
verify_ok "$o/verify" 2 3 --config "$o/b.toml" -- python3 /guest/kill.py main 10

# A machine's own end.
printf '[machine.bad]\nrun = ["sh", "-c", "sleep 1; exit 3"]\n' >"$o/bad.toml"
c=$(run "$o/bad" 1 --config "$o/bad.toml" -- sleep 10)
[ "$c" = failure ] && [ "$(field "$o/bad/result.json" machine_end.machine)" = bad ] && [ "$(field "$o/bad/result.json" machine_end.exit)" = 3 ] \
    || die "an exit outside ok-exit: $c, $(field "$o/bad/result.json" message)"
printf '[machine.seg]\nrun = ["sh", "-c", "sleep 1; kill -SEGV $$"]\n' >"$o/seg.toml"
c=$(run "$o/seg" 1 --config "$o/seg.toml" -- sleep 10)
[ "$c" = crash ] && [ "$(field "$o/seg/result.json" machine_end.machine)" = seg ] && [ "$(field "$o/seg/result.json" machine_end.signal)" = 11 ] \
    || die "a signal: $c, $(field "$o/seg/result.json" message)"
printf '[machine.w]\nrun = ["sh", "-c", "echo boot=${PATINA_BOOT:-1}; sleep 1; exit 3"]\nok-exit = 3\nrestart = "always"\nmax-boots = 3\ncount = 2\n' >"$o/w.toml" # lint-allow: sleep — the machine's command, in virtual time
run_ok "$o/w" 1 --config "$o/w.toml" --fault down-ms=100..500 -- sleep 10
for w in w1 w2; do
    [ "$(cat "$o/w/machine/$w"/boot-*/stdout | tr '\n' ' ')" = "boot=1 boot=2 boot=3 " ] || die "$w: $(cat "$o/w/machine/$w"/boot-*/stdout)"
done
echo "outcomes: an exit outside ok-exit failure, a signal crash, both naming the machine; ok-exit with restart=always: 3 boots of w1 and w2"
