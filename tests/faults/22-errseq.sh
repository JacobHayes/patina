# 22. Write-back errors are reported as Linux reports them (ARCHITECTURE.md, "The fsync-error
# model"). Each mode of tests/guests/faults/errseq.c runs with fsync-error-at=1 (its first
# sync-class call is given the failure) and must print what Linux returns. A real write-back
# error cannot be made natively without privileges (a device-mapper target such as dm-error),
# so the expected results come from the kernel's sources (v6.8): lib/errseq.c
# (`errseq_sample`: an error nobody has seen is reported to a later opener;
# `errseq_check_and_advance`), mm/filemap.c (`file_check_and_advance_wb_err`,
# `file_fdatawait_range`: once per open file description, shared by `dup` and `fork`),
# fs/sync.c (`sync_file_range` reports only with a WAIT flag; `syncfs` checks the
# superblock's sequence per description; `fdget` refuses O_PATH: EBADF), include/linux/pagemap.h
# (`mapping_set_error` also sets the superblock's sequence), include/linux/fs.h
# (`generic_write_sync`: an O_DSYNC write syncs and returns the sync's error), mm/msync.c
# (`vfs_fsync_range` on the mapping's file). The badfd mode needs no injection and is compared
# with a native run. Then the durability consequence, under every crash point of a seed
# (`--crash-points`, a machine crash): the program that writes, starts write-back with a WRITE-only
# sync_file_range, reopens, fsyncs and acknowledges only on success never loses an
# acknowledged file; the planted bug that retries a failed fsync on a new descriptor and then
# acknowledges does (in the quick tier under ext4-ordered; ./check faults also posix-strict).
# Expected on the arm64 runner: about 10 s (16 to 18 s measured with both models).
#@ tier=quick budget=30
. "$(dirname "$0")/lib/common.inc"
d=$RUNS/22
rm -rf "${d:?}"
mkdir -p "$d/native"
expect() {  # expect MODE "LABEL RESULT;..."
    m=$1
    f="--fault fsync-error-at=1"
    [ "$m" = badfd ] && f=
    run "$d/$m" 1 $f -- /guest/errseq "$m"
    got=$(tr '\n' ';' <"$d/$m/inc-0/stdout")
    [ "$got" = "$2" ] || die "$m: got '$got', Linux gives '$2'"
    echo "$m: $got"
}
expect sfr "sfr-write 0;fsync-new EIO;fsync-again 0;fsync-later 0;"
expect wait "sfr-write-wait EIO;fsync 0;"
expect before "fsync-a EIO;fsync-b EIO;fsync-b-again 0;fsync-after 0;"
expect dup "fsync EIO;fsync-dup 0;"
expect fork "child-fsync EIO;parent-fsync-shared 0;parent-fsync-own EIO;"
expect msync "msync EIO;fsync 0;"
expect dir "fsync-dir EIO;fsync-dir-again 0;"
expect syncfs "syncfs EIO;syncfs-again 0;syncfs-before EIO;syncfs-after 0;fsync-file EIO;"
expect osync "write-dsync EIO;fsync 0;"
expect badfd "$("$PATINA_GUESTS/errseq" badfd "$d/native" | tr '\n' ';')"
models=ext4-ordered
[ "${CHECK_TIER:-}" = quick ] || models="ext4-ordered posix-strict"
for model in $models; do
    for m in pg pg-retry; do
        o=$d/$m-$model
        st=0
        PATINA_TEST_KEEP_NONE=1 timeout 300 "$PATINA" sweep --seeds 1..1 --crash-points --crash machine --fault fsync-error-at=1 \
            --config "$("$PATINA_CFG" fs-model=$model)" --out "$o" \
            --mount "$PATINA_GUESTS":/guest:copy -- /guest/errseq "$m" >"$o.txt" 2>&1 || st=$?
        [ -f "$o/report.json" ] || die "$m $model: no report (exit $st): $(tail -3 "$o.txt")"
        r=$(python3 -I -c 'import json,sys
r=json.load(open(sys.argv[1])); b=r["crash_points"]
assert b["tried"] == b["points"] > 0, b
print(r["outcomes"].get("failure", 0), b["points"])' "$o/report.json") || die "$m $model: not every crash point tried"
        set -- $r
        if [ "$m" = pg ]; then
            [ "$1" = 0 ] || die "$model: the program that stops at a failed fsync lost an acknowledged file in $1 of $2 crash points"
        else
            [ "$1" -gt 0 ] || die "$model: retrying a failed fsync was never caught in $2 crash points"
        fi
        echo "$m $model: $1 failing of $2 crash points"
    done
done
