# 13. Signal frames the kernel cannot use (the forge guest says each case): a frame
# rt_sigreturn cannot read (where the runtime lives, above every mapping; on arm64 also a
# misaligned one), an FP image x86_64's restore refuses (unreadable, a reserved MXCSR bit, an
# XSAVE header naming a component no host enables), a delivery whose frame cannot be written
# (the stack read-only), and a handler without SA_RESTORER (x86_64 refuses to enter it; arm64
# uses its default restorer). Each run's output is the native run's: the SIGSEGV the kernel
# gives (code, address, registers) reaches the program's handler, never a fault of the runtime.
#@ tier=quick budget=10
. "$(dirname "$0")/lib.inc"
case $(uname -m) in
    x86_64) cases="rt top fp mxcsr xhdr ro nores" ;;
    *) cases="rt top mis ro nores" ;;
esac
for m in $cases; do
    native=$("$PATINA_GUESTS/forge" "$m")
    patina_run "$RUNS/13-forge/$m" 1 forge "$m"
    [ "$(field "$RUNS/13-forge/$m/result.json" outcome)" = ok ] || die "$m: $(field "$RUNS/13-forge/$m/result.json" outcome) $(field "$RUNS/13-forge/$m/result.json" message)"
    [ "$(cat "$RUNS/13-forge/$m/boot-1/stdout")" = "$native" ] || die "$m: native '$native', patina '$(cat "$RUNS/13-forge/$m/boot-1/stdout")'"
    echo "$m: $native" | tr '\n' ' '; echo
done
