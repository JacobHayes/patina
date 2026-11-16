# 5. rdpid: the same census and decision rule as cpuid. The instruction reports the core
# (shown by a guest on two cores); the scanner finds no rdpid site in glibc, ld.so, libstdc++,
# libcrypto, CPython, Go or Rust binaries.
#@ tier=area budget=60
. "$(dirname "$0")/lib.inc"
o=$RUNS/05-rdpid
mkdir -p "$o"
n=$(nproc)
for c in 0 $((n - 1)); do
    rm -rf "${o:?}/cpu-$c"
    timeout 120 taskset -c "$c" "$PATINA" run --seed 1 --out "$o/cpu-$c" --mount "$PATINA_GUESTS":/guest:copy -- /guest/insn-cpuid rdpid >/dev/null
    echo "cpu $c: $(cat "$o/cpu-$c/inc-0/stdout"), rdpid_sites $(field "$o/cpu-$c/result.json" counters.insn.scan.rdpid_sites)"
    [ "$(field "$o/cpu-$c/result.json" counters.insn.scan.rdpid_sites)" -ge 1 ] || die "the guest's own rdpid was not seen by the scanner"
done
G=$PATINA_GUESTS
"$PATINA" __insn-scan /lib64/ld-linux-x86-64.so.2 /lib/x86_64-linux-gnu/libc.so.6 /lib/x86_64-linux-gnu/libstdc++.so.6 \
    /lib/x86_64-linux-gnu/libcrypto.so.3 "$(readlink -f /usr/bin/python3)" "$G/insn-go-hello" "$G/go-sig" "$G/hello-rs" >"$o/scan.txt"
r=$(awk -F'\t' '$1 == "cand" && $5 == "rdpid"' "$o/scan.txt" | wc -l)
echo "rdpid sites in the system binaries: $r"
[ "$r" = 0 ] || die "rdpid sites found: $(awk -F'\t' '$5 == "rdpid"' "$o/scan.txt")"
echo "decision: rdpid is not patched (no site in any workload); it stays constant per core under pinning"
