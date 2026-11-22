# Evidence: start-up cost of one
# fork+execve of /bin/true + waitpid under patina and natively (median of 10, min, max). Timing:
# runs alone (slots=8). No pass/fail threshold beyond the runs being ok.
#@ tier=evidence budget=300 slots=8 arch=x86_64
. "$(dirname "$0")/lib.inc"
o=$RUNS/11-evidence
mkdir -p "$o"
n=200
for i in 1 2 3 4 5 6 7 8 9 10; do
    run_ok "$o/base-$i" "$i" /guest/spawn-cost 0
    run_ok "$o/cost-$i" "$i" /guest/spawn-cost "$n"
    echo "$(field "$o/cost-$i/result.json" wall_ms) $(field "$o/base-$i/result.json" wall_ms)"
    rm -rf "${o:?}/base-$i/boot-1/boundary.log" "${o:?}/cost-$i/boot-1/boundary.log"
done >"$o/patina.txt"
for i in 1 2 3 4 5 6 7 8 9 10; do
    python3 -I -c 'import subprocess,sys,time
t=time.perf_counter(); subprocess.run([sys.argv[1], sys.argv[2]], check=True); a=time.perf_counter()-t
t=time.perf_counter(); subprocess.run([sys.argv[1], "0"], check=True); b=time.perf_counter()-t
print(a*1000, b*1000)' "$PATINA_GUESTS/spawn-cost" "$n"
done >"$o/native.txt"
python3 -I - "$o/patina.txt" "$o/native.txt" "$n" <<'PY'
import statistics, sys
n = int(sys.argv[3])
for label, f in (("patina", sys.argv[1]), ("native", sys.argv[2])):
    per = sorted((float(a) - float(b)) * 1000 / n for a, b in (l.split() for l in open(f)))
    print(f"COST fork+execve(/bin/true)+waitpid {label}: median {statistics.median(per):.1f} us, min {per[0]:.1f}, max {per[-1]:.1f} (10 x {n}, minus a 0-spawn run)")
PY
