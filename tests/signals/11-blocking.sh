# 11. A signal ends every kind of blocking wait (sig-block): read, write, accept, connect, recv,
#     flock, F_OFD_SETLKW, open of a FIFO, read of a signalfd, epoll_wait, poll, select,
#     ppoll/pselect6/epoll_pwait/epoll_pwait2 under their own mask (and ppoll/pselect6 with a
#     zero timeout), futex (with and without a timeout), nanosleep, clock_nanosleep, wait4,
#     waitid, sigsuspend, pause, sigtimedwait; each with and without SA_RESTART,
#     process-directed to a one-thread process and thread-directed to a second thread; a
#     process-directed signal while one thread is a vfork parent and another is parked (vfork);
#     and a process-directed signal passed on to a parked thread when the thread it was meant
#     for blocks it (retarget, in the seeds where that thread runs only after both signals).
#     Seeds 1-10 of each case (1-2 in the quick tier): every run ok (the guest checks Linux's
#     EINTR and restart rules). A signal Patina loses ends a run `internal` (the lost-signal
#     detector) or `liveness`.
#@ tier=quick,release budget=60 slots=4
. "$(dirname "$0")/lib.inc"
o=$RUNS/11-blocking
mkdir -p "$o"
for c in read write accept connect recv flock ofdlock fifo signalfd epoll poll select ppoll pselect \
    epoll_pwait epoll_pwait2 ppoll0 pselect0 futex futex_timeout nanosleep clock_nanosleep wait4 \
    waitid sigsuspend pause sigtimedwait; do
    for r in restart plain; do
        for m in proc thread; do
            echo "/guest/sig-block $c $r $m"
        done
    done
done >"$o/cases"
echo "/guest/sig-block retarget restart proc" >>"$o/cases"
echo "/guest/sig-block vfork restart proc" >>"$o/cases"
n=10; [ "${CHECK_TIER:-}" != quick ] || n=2
st=0
timeout 300 "$PATINA" sweep --seeds 1..$n --cases "$o/cases" -j 4 --time-limit 100 --keep fail \
    --out "$o/sweep" --mount "$PATINA_GUESTS":/guest:copy >"$o/sweep.txt" 2>&1 || st=$?
outcomes=$(python3 -I -c 'import json,sys; print(json.dumps(json.load(open(sys.argv[1]))["outcomes"], sort_keys=True))' "$o/sweep/report.json")
echo "sig-block: $(wc -l <"$o/cases") cases x seeds 1-$n: $outcomes (sweep exit $st)"
[ "$outcomes" = "{\"ok\": $(($(wc -l <"$o/cases") * n))}" ] || { tail -30 "$o/sweep.txt"; die "not every run ok"; }
