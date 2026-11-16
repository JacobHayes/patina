# 8. W3 SQLite (reduced: 16 seeds per passing case, 12 per caught one, where storage reproductions's 40-seed
# runs caught each in more than half the seeds; the full sweeps are in docs/EVIDENCE.md). synchronous=FULL in WAL mode
# and EXTRA in DELETE mode pass under both models; FULL in DELETE mode passes ext4-ordered
# (under posix-strict it loses the last commit: the journal unlink is not made durable,
# SQLite's documented reason for EXTRA, checked natively in docs/EVIDENCE.md). synchronous=OFF
# is caught. fs-error-permille=5: never a corrupt database.
#@ tier=area budget=60 slots=4
. "$(dirname "$0")/lib/common.inc"
for m in ext4-ordered posix-strict; do
    for v in "wal full" "delete extra"; do
        n=$m-$(echo $v | tr ' ' -)
        sweep "$n" c-sqlite 1-16 -- --fs-model $m --crash machine:5 -- /guest/sqlite-dur $v >/dev/null
        [ "$(count "$n" ok)" = 16 ] || die "$n: not all ok ($(cat "$RUNS/$n.table" | tail -1))"
    done
    n=$m-off
    sweep "$n" c-sqlite 1-12 -- --fs-model $m --crash machine:5 -- /guest/sqlite-dur wal off >/dev/null
    [ "$(count "$n" failed 'INVARIANT (acked-row-lost|corrupt-db)')" -ge 1 ] || die "$n: OFF not caught in 12 seeds"
done
n=ext4-ordered-delete-full
sweep "$n" c-sqlite 1-16 -- --crash machine:5 -- /guest/sqlite-dur delete full >/dev/null
[ "$(count "$n" ok)" = 16 ] || die "$n: not all ok"
n=posix-strict-delete-full
sweep "$n" c-sqlite 1-12 -- --fs-model posix-strict --crash machine:5 -- /guest/sqlite-dur delete full >/dev/null
[ "$(count "$n" failed 'INVARIANT acked-row-lost')" -ge 1 ] || die "$n: the documented posix-strict loss was not seen"
for v in "delete full" "wal full"; do
    n=fserr5-$(echo $v | tr ' ' -)
    sweep "$n" c-sqlite 1-40 -- --fault fs-error-permille=5 --crash machine:5 -- /guest/sqlite-dur $v >/dev/null
    [ "$(count "$n" failed 'corrupt')" = 0 ] || die "$n: corrupt database"
    [ "$(count "$n" ok)" = 40 ] || die "$n: not all ok"
done
tables
