# Evidence: cost of a one-byte round trip between two processes under patina versus native
# loopback TCP (difference of 11000 and 1000 round trips, best of 3), and supervisor steps per MB.
#@ tier=evidence budget=300 slots=8 arch=x86_64
. "$(dirname "$0")/lib.inc"
o=$RUNS/09-cost; mkdir -p "$o"
ms() { python3 -I -c 'import subprocess,sys,time
t=time.monotonic(); subprocess.run(sys.argv[1:],check=True,stdout=subprocess.DEVNULL); print(int((time.monotonic()-t)*1e6))' "$@"; }
best() { sort -n | head -1; }
s1=$(for i in 1 2 3; do run_ok "$o/p1k-$i" 1 -- /guest/sockets pingpong 1000; field "$o/p1k-$i/result.json" wall_ms; done | best)
s2=$(for i in 1 2 3; do run_ok "$o/p11k-$i" 1 -- /guest/sockets pingpong 11000; field "$o/p11k-$i/result.json" wall_ms; done | best)
n1=$(for i in 1 2 3; do ms "$PATINA_GUESTS/sockets" pingpong 1000; done | best)
n2=$(for i in 1 2 3; do ms "$PATINA_GUESTS/sockets" pingpong 11000; done | best)
rm -f "$o"/p*/boot-1/boundary.log
python3 -I -c 'import sys; s1,s2,n1,n2=map(int,sys.argv[1:]); a=(s2-s1)*1000/10000; b=(n2-n1)/10000
print("round trip: patina %.1f us, native loopback TCP %.1f us, ratio %.1f" % (a, b, a/b))' "$s1" "$s2" "$n1" "$n2"
run_ok "$o/big" 1 -- /guest/sockets big 64
echo "64 MiB: $(net "$o/big" steps) wire steps, $(( $(net "$o/big" steps) / 64 )) per MB, $(net "$o/big" chunks) deliveries"
rm -f "$o/big/boot-1/boundary.log"
