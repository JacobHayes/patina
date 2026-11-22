# 3. evloop: epoll over 32 socketpairs (level and edge triggered), 4 eventfds, a timerfd,
#    with worker threads; the same with poll and with select. ok; identical across runs,
#    including the order of the events printed (stdout is compared byte for byte).
#@ tier=quick budget=30 slots=1.5
. "$(dirname "$0")/lib.inc"
o=$RUNS/03-evloop; mkdir -p "$o"
for mode in epoll poll select; do
    for seed in 1 2; do
        verify_ok "$o/$mode-$seed" "$seed" 3 -- /guest/evloop "$mode"
        tail -1 "$o/$mode-$seed/run-0/boot-1/stdout" | grep -qx "evloop $mode ok bytes=6520 ticks=[5-9]" || die "$mode: $(tail -1 "$o/$mode-$seed/run-0/boot-1/stdout")"
    done
    echo "$mode: events printed per run: $(wc -l <"$o/$mode-1/run-0/boot-1/stdout"), distinct orders over seeds 1-2: $(for s in 1 2; do sha256sum <"$o/$mode-$s/run-0/boot-1/stdout"; done | sort -u | wc -l)"
done
io_line evloop $(ls "$o"/*/run-0/result.json)
