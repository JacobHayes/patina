# Hazard: an undefined instruction the guest itself contains goes to the guest as SIGILL (only
# addresses in the side table are emulated): x86 `ud2`; arm64 `udf #0`, `udf #0x7061` (the
# patch's own encoding, at an address never patched) and a CNTPCT_EL0 read (not readable at EL0:
# a host fact). arm64: a literal-pool word in program text equal to `yield`, read by `ldr`, is
# data: not patched (rejected_sites), it reads as itself. The runtime's own code reads no
# counter and no random-number instruction.
#@ tier=quick slots=0.5
. "$(dirname "$0")/lib.inc"
o=$RUNS/09-guest-ud2
case $ARCH in
    x86_64) modes=ud2 kinds="scan rdtsc rdtscp" ;;
    *) modes="ud2 udf7061 cntpct" kinds="rndr pacga counter" ;;
esac
for m in $modes; do
    patina_run "$o/$m" 1 insn "$m" || true
    [ "$(field "$o/$m/result.json" outcome)" = crash ] && [ "$(field "$o/$m/result.json" guest.signal)" = 4 ] ||
        die "guest $m: $(field "$o/$m/result.json" outcome) $(field "$o/$m/result.json" message)"
    echo "guest $m: crash, signal 4"
done
if [ "$ARCH" != x86_64 ]; then
    patina_run "$o/litpool" 1 insn litpool
    grep -qx 'OK litpool' "$o/litpool/boot-1/stdout" || die "litpool: $(head -2 "$o/litpool/boot-1/stdout")"
    [ "$(field "$o/litpool/result.json" counters.insn.scan.rejected_sites)" -ge 1 ] || die "litpool: no rejected site"
    echo "a literal-pool word equal to yield: $(head -1 "$o/litpool/boot-1/stdout"), rejected_sites $(field "$o/litpool/result.json" counters.insn.scan.rejected_sites)"
fi
python3 -I "$HERE/lib/census.py" "$RT_BIN" >"$o/rt-census.txt"
for k in $kinds; do
    r=$(awk -F'\t' -v k="$k" '$1 == "count" && $3 == k {print $4}' "$o/rt-census.txt")
    echo "runtime $k: $r"
    [ "$r" = "real=0" ] || die "the runtime executes $k"
done
