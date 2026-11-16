# 3/4. cpuid census: every leaf and subleaf dumped by a guest pinned (taskset) to 6 different
# cores; the report lists which (leaf, register, bits) differ. Then workloads under
# --vary cpu (6 runs, one per core): digests identical or not, per workload. Decision rule: patch cpuid
# only if a workload depends on the core. The script fails if one does (then item 4 applies).
#@ tier=area budget=120
. "$(dirname "$0")/lib.inc"
o=$RUNS/04-cpuid
n=$(nproc)
cpus=$(printf '%s\n' 0 $((n - 1)) $((n / 2)) 1 $((n / 3)) $((2 * n / 3)) | awk '!s[$0]++' | tr '\n' ' ')
for c in $cpus; do
    rm -rf "${o:?}/cpu-$c"; mkdir -p "$o"
    timeout 120 taskset -c "$c" "$PATINA" run --seed 1 --out "$o/cpu-$c" --mount "$PATINA_GUESTS":/guest:copy -- /guest/insn-cpuid >/dev/null
    [ "$(field "$o/cpu-$c/outcome.json" outcome)" = ok ] || die "cpuid dump on cpu $c"
done
# The same core twice gives the same dump (so what differs is the core, not the run).
rm -rf "${o:?}/again"
timeout 120 taskset -c 0 "$PATINA" run --seed 1 --out "$o/again" --mount "$PATINA_GUESTS":/guest:copy -- /guest/insn-cpuid >/dev/null
cmp -s "$o/again/inc-0/stdout" "$o/cpu-0/inc-0/stdout" || die "two dumps on cpu 0 differ"
echo "cores: $cpus"
python3 -I "$HERE/lib/cpuid_diff.py" $(for c in $cpus; do echo "$o/cpu-$c/inc-0/stdout"; done) | tee "$o/report.txt"
grep -q '^diff ' "$o/report.txt" || echo "no field differs between cores"
dep=""
for w in "hello-dyn a b" c-threads order rs-threads insn-go-hello "/usr/bin/python3 -c pass"; do
    name=$(echo "$w" | tr -c 'a-z0-9\n' '_' | cut -c1-24)
    # shellcheck disable=SC2086
    if (verify "$o/w-$name" 1 6 $w); then trim "$o/w-$name"; else dep="$dep [$w]"; fi
done
[ -z "$dep" ] || die "digests depend on the core for:$dep (item 4: patch cpuid)"
echo "decision: no workload's digest depends on the core; cpuid identity fields are not patched"
