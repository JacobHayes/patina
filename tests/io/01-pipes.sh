# 1. pipes: producer/consumer with 1-byte, 4096-byte and 1 MiB writes (partial blocking
#    writes continued), reader closes early (EPIPE), writer closes (EOF), FIFO opened by
#    two threads in both orders. ok; verify --runs 4 --vary cpu,load identical (seed 1);
#    at least 3 distinct digests over 8 seeds.
#@ tier=quick budget=30
. "$(dirname "$0")/lib.inc"
o=$RUNS/01-pipes; mkdir -p "$o"
want='A bytes=4604904 ok
B epipe ok (at least 10 bytes sent: 1)
C eof after 5 bytes
D fifo order 0: msg0;msg1;msg2;
D fifo order 1: msg0;msg1;msg2;
pipes ok'
for seed in 1; do
    verify_ok "$o/v$seed" "$seed" 4 -- /guest/pipes
    [ "$(cat "$o/v$seed/run-0/inc-0/stdout")" = "$want" ] || die "seed $seed: unexpected output"
done
for seed in $(seq 1 8); do run_ok "$o/s$seed" "$seed" -- /guest/pipes; done
n=$(for seed in $(seq 1 8); do field "$o/s$seed/result.json" digest; done | sort -u | wc -l)
echo "distinct digests over seeds 1-8: $n"
[ "$n" -ge 3 ] || die "only $n distinct digests"
io_line pipes $(for seed in $(seq 1 8); do echo "$o/s$seed/result.json"; done)
