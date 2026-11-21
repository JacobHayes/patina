# 10. System V shared memory (sysv-shm): keys and ids, IPC_STAT/IPC_SET/IPC_RMID, nattch
#     across fork, exit, execve, shmdt and munmap, attaching twice and at a chosen address
#     (SHM_RND, SHM_REMAP), SHM_RDONLY, an unrelated image finding a key, a process-shared
#     mutex in a segment (the guest checks each as Linux has it). ok and identical over 2 runs
#     at seed 1, every run ok over seeds 1-20. SHM_HUGETLB and SHM_LOCK answer EPERM and are
#     recorded as refused. A segment survives a process crash and not a machine crash.
#@ tier=quick budget=40 slots=4
. "$(dirname "$0")/lib.inc"
o=$RUNS/10-sysv-shm
mkdir -p "$o"
verify_ok "$o/v1" 1 2 cpu /guest/sysv-shm all
echo "/guest/sysv-shm all" >"$o/cases"
st=0
timeout 300 "$PATINA" sweep --seeds 1..20 --cases "$o/cases" -j 4 --config "$("$PATINA_CFG" time-limit=60)" --keep fail \
    --out "$o/sweep" --mount "$PATINA_GUESTS":/guest:copy >"$o/sweep.txt" 2>&1 || st=$?
outcomes=$(python3 -I -c 'import json,sys; print(json.dumps(json.load(open(sys.argv[1]))["outcomes"], sort_keys=True))' "$o/sweep/report.json")
echo "sysv-shm seeds 1-20: $outcomes (sweep exit $st)"
[ "$outcomes" = '{"ok": 20}' ] || { tail -30 "$o/sweep.txt"; die "not every run ok"; }

run_ok "$o/refused" 1 /guest/sysv-shm refused
[ "$(grep -c 'errno 1$' "$o/refused/inc-0/stdout")" = 2 ] || die "refusals: $(cat "$o/refused/inc-0/stdout")"
python3 -I -c 'import json,sys; r=json.load(open(sys.argv[1]))["refused"]; sys.exit(not ("shmget:0x800" in r and "shmctl:11" in r))' \
    "$o/refused/result.json" || die "refusals not recorded: $(field "$o/refused/result.json" refused)"

for k in process machine; do
    rm -rf "${o:?}/crash-$k"
    timeout 300 "$PATINA" run --seed 1 $([ $k = process ] && echo --faults kill || echo --faults crash) --fault crash-at=3 --out "$o/crash-$k" --mount "$PATINA_GUESTS":/guest:copy \
        -- /guest/sysv-shm crash >/dev/null 2>&1 || true
    [ "$(field "$o/crash-$k/result.json" outcome)" = ok ] || die "crash $k: $(field "$o/crash-$k/result.json" outcome)"
    echo "crash $k: $(cat "$o/crash-$k/inc-1/stdout")"
done
grep -q 'holds kept$' "$o/crash-process/inc-1/stdout" || die "the segment did not survive a process crash"
grep -q 'no segment' "$o/crash-machine/inc-1/stdout" || die "the segment survived a machine crash"
