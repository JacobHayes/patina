# 8. rt_sigreturn with a frame the kernel refuses (misaligned, where the runtime lives, above
# every mapping): the program gets the SIGSEGV the kernel gives (code, address, registers), and
# the run goes on to its handler.
#@ tier=quick budget=10 arch=aarch64
. "$(dirname "$0")/lib.inc"
for m in mis rt top; do
    native=$("$PATINA_GUESTS/forge" "$m")
    prun "$RUNS/$m" --seed 1 -- "$PATINA_GUESTS/forge" "$m"
    [ "$st" = 0 ] || die "$m: exit $st ($(tail -2 "$RUNS/$m.txt"))"
    [ "$(cat "$RUNS/$m/inc-0/stdout")" = "$native" ] || die "$m: native '$native', patina '$(cat "$RUNS/$m/inc-0/stdout")'"
    echo "$m: $native"
done
