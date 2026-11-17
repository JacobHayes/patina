# 10. Runtime tables over a long run: 100,000 files and 100,000 symlinks created and removed
#     one at a time (more inodes than the virtual time table holds) end ok, and a file held
#     open after its unlink keeps its times through the table's reclaiming; pipes past the
#     virtual inode table end unsupported (capacity), never internal.
#@ tier=quick budget=20 arch=x86_64
. "$(dirname "$0")/lib/common.inc"
o=$RUNS/10-churn
mkdir -p "$o"
timeout 60 "$PATINA" run --seed 1 --out "$o/files" --mount "$PATINA_GUESTS":/guest:copy -- /guest/churn 100000 >/dev/null || true
[ "$(field "$o/files/result.json" outcome)" = ok ] \
    || die "file churn: $(field "$o/files/result.json" outcome): $(field "$o/files/result.json" message) $(cat "$o/files/inc-0/stderr")"
rm -rf "$o/files"
timeout 60 "$PATINA" run --seed 1 --out "$o/pipes" --mount "$PATINA_GUESTS":/guest:copy -- /guest/churn pipes 20000 >/dev/null || true
[ "$(field "$o/pipes/result.json" outcome) $(field "$o/pipes/result.json" stop)" = "unsupported capacity" ] \
    || die "pipe churn: $(field "$o/pipes/result.json" outcome) $(field "$o/pipes/result.json" stop): $(field "$o/pipes/result.json" message)"
echo "200,000 files and symlinks: ok; 20,000 pipes: $(field "$o/pipes/result.json" message)"
