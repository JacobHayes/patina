# 5. Every time call trapped: hello-dyn's log has >= 200 clock records; no clock or randomness record is Pass.
#@ tier=quick slots=0.5
. "$(dirname "$0")/lib.inc"
out=$RUNS/05-clock/hello-dyn
patina_run "$out" 1 hello-dyn
"$PATINA" log dump "$out/boot-1/boundary.log" >"$out/dump.txt"
n=$(awk '$2=="trap" && ($5=="clock_gettime" || $5=="gettimeofday" || $5=="time") {n++} END {print n+0}' "$out/dump.txt")
[ "$n" -ge 200 ] || die "only $n clock records"
bad=$(awk '$2=="trap" && $5 ~ /^(clock_gettime|gettimeofday|time|clock_getres|getrandom)$/ && $6=="[Pass]"' "$out/dump.txt" | wc -l)
[ "$bad" = 0 ] || die "$bad clock/randomness records with class Pass"
echo "clock records: $n, Pass among clock/randomness: $bad"
