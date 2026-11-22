# 7. patina log diff: different seeds -> prints the first differing record, exits non-zero; one seed twice -> exits 0.
#@ tier=quick slots=0.5
. "$(dirname "$0")/lib.inc"
d=$RUNS/07-logdiff
patina_run "$d/s1a" 1 hello-static
patina_run "$d/s1b" 1 hello-static
patina_run "$d/s2" 2 hello-static
rc=0; "$PATINA" log diff "$d/s1a/boot-1/boundary.log" "$d/s2/boot-1/boundary.log" >"$d/diff-seeds.txt" || rc=$?
rc2=0; "$PATINA" log diff "$d/s1a/boot-1/boundary.log" "$d/s1b/boot-1/boundary.log" >"$d/diff-same.txt" || rc2=$?
cat "$d/diff-seeds.txt"
[ "$rc" -ne 0 ] || die "diff of different seeds exited 0"
[ "$(grep -c '^  [AB]: seq=' "$d/diff-seeds.txt")" = 2 ] || die "first differing record not printed"
[ "$rc2" -eq 0 ] || die "diff of one seed exited $rc2"
