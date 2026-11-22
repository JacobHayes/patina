# 1b. The random-number instructions 100 times each (x86: rdrand and rdseed, 16/32/64-bit, an
# extended register, a 16-bit form keeping the upper bits; arm64: RNDR into x0, x9 and x30,
# RNDRRS into x3): success flag set, identical over 3 runs varying the core, different seeds give
# different values. arm64 answers RNDR only where the host has it; on a host without it the
# program is told so (HWCAP2_RNG clear, a host fact), and `emulate-rndr` exercises the path.
#@ tier=quick slots=0.5
. "$(dirname "$0")/lib.inc"
o=$RUNS/02-rand
mkdir -p "$o"
case $ARCH in
    x86_64) reads="rdrand:400 rdseed:400" ;;
    *)
        reads="rndr:300 rndrrs:100"
        if ! grep -qw rng /proc/cpuinfo; then
            patina_run "$o/host" 1 insn rand
            grep -qx 'no-rng' "$o/host/boot-1/stdout" || die "no RNDR on this host, but the program was told otherwise: $(head -2 "$o/host/boot-1/stdout")"
            echo "host without RNDR: the program sees no HWCAP2_RNG"
        fi
        export PATINA_TEST_EMULATE_RNDR=1 # a test input (AGENTS.md)
        ;;
esac
verify "$o/s1" 1 3 insn rand
grep -qx 'OK rand' "$o/s1/run-0/boot-1/stdout" || die "guest checks failed: $(grep FAIL "$o/s1/run-0/boot-1/stdout" | head -3)"
echo "patched $(field "$o/s1/run-0/result.json" counters.insn.patched_sites), emulated $(field "$o/s1/run-0/result.json" counters.insn.emulated)"
for kn in $reads; do
    [ "$(field "$o/s1/run-0/result.json" "counters.insn.emulated.${kn%:*}")" -ge "${kn#*:}" ] || die "${kn%:*} emulations"
done
trim "$o/s1"
for s in 2 3; do
    patina_run "$o/seed-$s" "$s" insn rand
    grep -qx 'OK rand' "$o/seed-$s/boot-1/stdout" || die "seed $s: guest checks failed"
done
n=$(for s in 2 3; do sha256sum <"$o/seed-$s/boot-1/stdout"; done; sha256sum <"$o/s1/run-0/boot-1/stdout")
d=$(echo "$n" | sort -u | wc -l)
[ "$d" = 3 ] || die "seeds 1-3 gave $d distinct outputs"
echo "seeds 1, 2, 3: 3 distinct outputs"
