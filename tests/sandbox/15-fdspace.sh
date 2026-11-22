# The program's descriptor space is [0, its soft RLIMIT_NOFILE), enforced as on Linux, and
# nothing in it depends on the runtime's own descriptors (numbers from 3000):
# - limits: the fdspace guest's output equals its native output: EMFILE (open, pipe, socket,
#   dup, F_DUPFD) at the soft limit with every number below it handed out in order, a stat
#   with a full table, dup2/dup3/F_DUPFD at and above the limit and on the runtime's numbers,
#   calls on hidden numbers (as arguments, values and structure fields) answering as for
#   closed ones, raising soft to hard (and not past it), lowering hard, a fork child and an
#   exec keeping the limits, close_range(3, ~0U) (the run still ends ok: the runtime's
#   descriptors are untouched), /proc/self/fd listings.
# - spin: the same seed with a spin probe (a CPU-bound stretch long enough for the stall
#   watchdog) and with probes off: one stdout and one digest, the probe's descriptors
#   invisible to calls on their numbers (as arguments, values and structure fields) and to a
#   guest that fills its table.
# The spin runs use [sched] preempt = "traps": under load-time points the stretch is cut at its
# loop's point and no probe is sent.
#@ tier=quick budget=15 slots=1
. "$(dirname "$0")/lib/common.inc"
out=$RUNS/fdspace
mkdir -p "$out"
rm -rf "${out:?}/limits" "${out:?}/on" "${out:?}/off"
timeout 300 "$PATINA" __native --mount "$G17":/guest -- /guest/fdspace >"$out/native.txt" 2>"$out/native.err" ||
    die "native: exit $?: $(tail -3 "$out/native.err")"
timeout 300 "$PATINA" run --seed 1 --out "$out/limits" --mount "$G17":/guest:copy -- /guest/fdspace >/dev/null 2>&1 || true
[ "$(class "$out/limits")" = ok ] || die "limits: $(class "$out/limits"): $(detail "$out/limits")"
cmp -s "$out/native.txt" "$out/limits/boot-1/stdout" ||
    die "limits: differs from native: $(diff "$out/native.txt" "$out/limits/boot-1/stdout" | cut -c1-160 | head -8)"
# The fill ends with the number just below the soft limit the guest starts with, then EMFILE.
soft=$(sed -n 's/^start nofile \([0-9]*\) .*/\1/p' "$out/native.txt")
last=$(sed -n 's/^soft fds .* \([0-9]*\)$/\1/p' "$out/native.txt")
[ "$last" = $((soft - 1)) ] && grep -q '^soft opened [0-9]* errno 24$' "$out/native.txt" ||
    die "limits: native did not fill to the soft limit $soft (last $last)"
echo "limits: $(wc -l <"$out/native.txt") lines as native, filled to $last below the soft limit $soft"
traps=$("$PATINA_CFG" preempt=traps)
timeout 300 "$PATINA" run --seed 1 --config "$traps" --out "$out/on" --mount "$G17":/guest:copy -- /guest/fdspace spin >/dev/null 2>&1 || true
PATINA_TEST_SPIN_PROBES=0 timeout 300 "$PATINA" run --seed 1 --config "$traps" --out "$out/off" --mount "$G17":/guest:copy -- /guest/fdspace spin >/dev/null 2>&1 || true
for r in on off; do
    [ "$(class "$out/$r")" = ok ] || die "spin $r: $(class "$out/$r"): $(detail "$out/$r")"
done
probes=$(jq -r .counters.sched.spin_probes "$out/on/result.json")
[ "$probes" -gt 0 ] || die "spin: no probe was sent (the stretch is too short to test anything)"
[ "$(jq -r .counters.sched.spin_probes "$out/off/result.json")" = 0 ] || die "spin: a probe with probes off"
cmp -s "$out/on/boot-1/stdout" "$out/off/boot-1/stdout" ||
    die "spin: a probe changed what the guest saw: $(diff "$out/on/boot-1/stdout" "$out/off/boot-1/stdout" | cut -c1-160 | head -4)"
d_on=$(digest "$out/on")
d_off=$(digest "$out/off")
[ "$d_on" = "$d_off" ] || die "spin: digest $d_on with $probes probes, $d_off without"
echo "spin: $probes probes and none: one stdout, digest $d_on"
rm -rf "${out:?}/limits" "${out:?}/on" "${out:?}/off"
