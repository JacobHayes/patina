# 5. Faults forwarded to guest handlers (si_addr, faulting pc, recovery by siglongjmp), and
# the default action: death by the signal, seen by the launcher as guest.signal in result.json.
#@ tier=quick
. "$(dirname "$0")/lib.inc"
patina_run "$RUNS/05-faults/handled" 1 sig-fault handled
check_ok "$RUNS/05-faults/handled" sig-fault
modes=$("$PATINA_GUESTS/sig-fault" modes)
[ -n "$modes" ] || die "no modes"
for mode in $modes; do
    o=$RUNS/05-faults/$mode
    patina_run "$o" 1 sig-fault "$mode"
    sig=$(sed -n 's/^about to fault: .* want=//p' "$o/inc-0/stdout")
    [ -n "$sig" ] && [ "$sig" != 0 ] || die "$mode: no expected signal: $(cat "$o/inc-0/stdout")"
    c=$(field "$o/result.json" outcome); s=$(field "$o/result.json" guest.signal); x=$(field "$o/result.json" guest.exit)
    [ "$c" = crash ] && [ "$s" = "$sig" ] && [ "$x" = $((128 + sig)) ] || die "$mode: class $c signal $s exit $x"
    ! grep -q 'still alive' "$o/inc-0/stdout" || die "$mode: survived"
    echo "$mode: crash, signal $s, exit status $x"
done
