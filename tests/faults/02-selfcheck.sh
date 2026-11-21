# 2. Self-check: replaying the full operation log equals the exported live tree, for
# fs-tour, randops (10,000 random operations) and Python sqlite3 writing 1,000 rows,
# seeds 1-2. randops covers the two tracker bugs the self-check
# found: O_CREAT through a dangling symlink, and copy_file_range into a write-only descriptor.
#@ tier=quick budget=30 slots=0.5
. "$(dirname "$0")/lib/common.inc"
for seed in 1 2; do
    for g in fs-tour randops sqlite; do
        o=$RUNS/02/$g-$seed
        case $g in
            fs-tour) run "$o" "$seed" -- /guest/fs-tour ;;
            randops) run "$o" "$seed" -- /guest/randops 10000 ;;
            sqlite) run "$o" "$seed" -- /usr/bin/python3 /guest/sqlite_rows.py ;;
        esac
        [ "$(class "$o")" = ok ] || die "$g seed $seed: $(class "$o") $(field "$o/result.json" message)"
        "$PATINA" log ops --check "$o" >"$o.check" || { cat "$o.check"; die "$g seed $seed: oplog check"; }
        [ $seed = 1 ] && echo "$g: $(cat "$o.check")"
        if [ $g = randops ]; then
            # keep the evidence small: the summary and the check result stay
            cp "$o/inc-0/stdout" "$o.stdout"
            rm -rf "${o:?}"
        fi
    done
done
awk '/ok \(/ {n++} END {print "oplog check ok for runs:", n + 0}' "$RUNS"/02/*.check
