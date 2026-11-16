# 2. Library sites: std::random_device (libstdc++ rdrand/rdseed) and OpenSSL RAND_bytes
# (libcrypto): identical over 3 runs of a seed, different across seeds; patched_sites and
# emulated reported.
#@ tier=quick budget=30
. "$(dirname "$0")/lib.inc"
o=$RUNS/03-libs
for w in insn-rand-cpp insn-rand-ssl; do
    verify "$o/$w" 1 3 "$w"
    r=$o/$w/run-0
    [ "$(field "$r/result.json" outcome)" = ok ] || die "$w: $(field "$r/result.json" message)"
    p=$(( $(field "$r/result.json" counters.insn.patched_sites.rdrand) + $(field "$r/result.json" counters.insn.patched_sites.rdseed) ))
    echo "$w: patched_sites $(field "$r/result.json" counters.insn.patched_sites) emulated $(field "$r/result.json" counters.insn.emulated) scan $(field "$r/result.json" counters.insn.scan)"
    [ "$p" -ge 2 ] || die "$w: only $p sites patched"
    sed 's/^/    /' "$r/inc-0/stdout"
    trim "$o/$w"
    patina_run "$o/$w-seed2" 2 "$w"
    cmp -s "$r/inc-0/stdout" "$o/$w-seed2/inc-0/stdout" && die "$w: seeds 1 and 2 print the same values"
    echo "$w: seed 2 prints different values"
done
# random_device("rdrand"/"rdseed") must come from the patched sites
[ "$(field "$o/insn-rand-cpp/run-0/result.json" counters.insn.emulated.rdrand)" -ge 8 ] || die "random_device(rdrand) did not reach the emulator"
[ "$(field "$o/insn-rand-cpp/run-0/result.json" counters.insn.emulated.rdseed)" -ge 8 ] || die "random_device(rdseed) did not reach the emulator"
# dlopen: CPython loads libcrypto by dlopen when hashlib is imported; its sites are patched too.
patina_run "$o/py-dlopen" 1 /usr/bin/python3 -c 'import hashlib; print(hashlib.sha256(b"x").hexdigest())'
[ "$(field "$o/py-dlopen/result.json" outcome)" = ok ] || die "python hashlib: $(field "$o/py-dlopen/result.json" message)"
p=$(field "$o/py-dlopen/result.json" counters.insn.patched_sites.rdrand)
echo "python3 -c 'import hashlib': patched_sites $(field "$o/py-dlopen/result.json" counters.insn.patched_sites), scan $(field "$o/py-dlopen/result.json" counters.insn.scan)"
[ "$p" -ge 1 ] || die "libcrypto loaded by dlopen was not patched"
