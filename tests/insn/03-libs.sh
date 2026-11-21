# 2. Library sites: std::random_device and OpenSSL RAND_bytes: identical over 3 runs of a seed,
# different across seeds; patched_sites and emulated reported. x86: libstdc++'s rdrand/rdseed and
# libcrypto's are patched sites. arm64: neither library has RNDR on the hosts measured (the census,
# tests/insn/06), the values come from the seeded getrandom; a library loaded by dlopen has its
# sites patched (x86: CPython's hashlib loads libcrypto, rdrand; arm64: ctypes loads libffi,
# whose cache flush ends in `isb`, a pause point).
#@ tier=quick budget=30 slots=0.5
. "$(dirname "$0")/lib.inc"
o=$RUNS/03-libs
for w in insn-rand-cpp insn-rand-ssl; do
    verify "$o/$w" 1 3 "$w"
    r=$o/$w/run-0
    [ "$(field "$r/result.json" outcome)" = ok ] || die "$w: $(field "$r/result.json" message)"
    echo "$w: patched_sites $(field "$r/result.json" counters.insn.patched_sites) emulated $(field "$r/result.json" counters.insn.emulated) scan $(field "$r/result.json" counters.insn.scan)"
    if [ "$ARCH" = x86_64 ]; then
        p=$(($(field "$r/result.json" counters.insn.patched_sites.rdrand) + $(field "$r/result.json" counters.insn.patched_sites.rdseed)))
        [ "$p" -ge 2 ] || die "$w: only $p sites patched"
    fi
    sed 's/^/    /' "$r/inc-0/stdout"
    trim "$o/$w"
    patina_run "$o/$w-seed2" 2 "$w"
    cmp -s "$r/inc-0/stdout" "$o/$w-seed2/inc-0/stdout" && die "$w: seeds 1 and 2 print the same values"
    echo "$w: seed 2 prints different values"
done
if [ "$ARCH" = x86_64 ]; then
    # random_device("rdrand"/"rdseed") must come from the patched sites
    [ "$(field "$o/insn-rand-cpp/run-0/result.json" counters.insn.emulated.rdrand)" -ge 8 ] || die "random_device(rdrand) did not reach the emulator"
    [ "$(field "$o/insn-rand-cpp/run-0/result.json" counters.insn.emulated.rdseed)" -ge 8 ] || die "random_device(rdseed) did not reach the emulator"
    py='import hashlib; print(hashlib.sha256(b"x").hexdigest())' kind=rdrand
else
    py='import ctypes; print(ctypes.c_int(7).value)' kind=pause
fi
patina_run "$o/py-dlopen" 1 /usr/bin/python3 -c "$py"
# arm64: python3 itself has pause sites; the difference from a run without the import is the
# library's. (x86's python3 has no rdrand.)
base=0
if [ "$ARCH" != x86_64 ]; then
    patina_run "$o/py-base" 1 /usr/bin/python3 -c 'print(7)'
    base=$(field "$o/py-base/result.json" "counters.insn.patched_sites.$kind")
fi
[ "$(field "$o/py-dlopen/result.json" outcome)" = ok ] || die "python dlopen: $(field "$o/py-dlopen/result.json" message)"
p=$(($(field "$o/py-dlopen/result.json" "counters.insn.patched_sites.$kind") - base))
echo "python3 -c '$py': patched_sites $(field "$o/py-dlopen/result.json" counters.insn.patched_sites), scan $(field "$o/py-dlopen/result.json" counters.insn.scan)"
[ "$p" -ge 1 ] || die "the library loaded by dlopen was not patched"
