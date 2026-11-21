# 10. Runtime tables over a long run: 60,000 files and 60,000 symlinks created and removed
#     one at a time (past the point where the virtual time table reclaims) end ok, and a file held
#     open after its unlink keeps its times through the table's reclaiming; 20,000 unix socket
#     pairs, whose numbers the program never asks for, take no virtual inode number and end ok;
#     pipes past the virtual inode table end unsupported (capacity), never internal.
#@ tier=quick budget=20 slots=1
. "$(dirname "$0")/lib/common.inc"
o=$RUNS/10-churn
mkdir -p "$o"
timeout 60 "$PATINA" run --seed 1 --out "$o/files" --mount "$PATINA_GUESTS":/guest:copy -- /guest/churn 60000 >/dev/null || true
[ "$(field "$o/files/result.json" outcome)" = ok ] \
    || die "file churn: $(field "$o/files/result.json" outcome): $(field "$o/files/result.json" message) $(cat "$o/files/inc-0/stderr")"
rm -rf "${o:?}/files"
timeout 60 "$PATINA" run --seed 1 --out "$o/socks" --mount "$PATINA_GUESTS":/guest:copy -- /guest/churn socks 20000 >/dev/null || true
[ "$(field "$o/socks/result.json" outcome)" = ok ] \
    || die "socket churn: $(field "$o/socks/result.json" outcome): $(field "$o/socks/result.json" message)"
rm -rf "${o:?}/socks"
timeout 60 "$PATINA" run --seed 1 --out "$o/pipes" --mount "$PATINA_GUESTS":/guest:copy -- /guest/churn pipes 20000 >/dev/null || true
[ "$(field "$o/pipes/result.json" outcome) $(field "$o/pipes/result.json" stop)" = "unsupported capacity" ] \
    || die "pipe churn: $(field "$o/pipes/result.json" outcome) $(field "$o/pipes/result.json" stop): $(field "$o/pipes/result.json" message)"
echo "120,000 files and symlinks: ok; 20,000 socket pairs: ok; 20,000 pipes: $(field "$o/pipes/result.json" message)"
