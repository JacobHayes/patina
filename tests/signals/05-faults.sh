# 5. Faults forwarded to guest handlers (si_addr, faulting rip, recovery by siglongjmp), and
# the default action: death by the signal, seen by the launcher as guest.signal in outcome.json.
#@ tier=quick
. "$(dirname "$0")/lib.inc"
patina_run "$RUNS/05-faults/handled" 1 sig-fault handled
check_ok "$RUNS/05-faults/handled" sig-fault
for m in die-segv:11 die-fpe:8 die-ill:4 die-bus:7 die-term:15 die-abort:6 die-blocked-segv:11; do
    mode=${m%:*}; sig=${m#*:}
    o=$RUNS/05-faults/$mode
    patina_run "$o" 1 sig-fault "$mode"
    c=$(field "$o/outcome.json" outcome); s=$(field "$o/outcome.json" guest.signal); x=$(field "$o/outcome.json" guest.exit)
    [ "$c" = crash ] && [ "$s" = "$sig" ] && [ "$x" = $((128 + sig)) ] || die "$mode: class $c signal $s exit $x"
    ! grep -q 'still alive' "$o/inc-0/stdout" || die "$mode: survived"
    echo "$mode: crash, signal $s, exit status $x"
done
