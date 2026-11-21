# 6. A change to part of a rewritten image (load-time points; ARCHITECTURE "Load-time
# rewriting", "Changes"): rw-textmove (tests/guests/rewrite/textmove.c, static) changes the page
# of its function cold, then two threads compute in hot, a page it did not touch:
#  - mremap: the page moved with MREMAP_MAYMOVE | MREMAP_FIXED | MREMAP_DONTUNMAP (the copy
#    called must be the original code: a patched copy would jump to trampolines it cannot reach);
#  - mprotect: the page made read-only and executable again;
#  - munmap: the page unmapped (the middle of the text);
#  - remap: the page unmapped, then mapped again from the file, and the threads compute in
#    cold: the new mapping takes the plan again.
# Each: the native output; part of the plan put back and none of it dropped; a point taken
# after the change in the page the threads run (hot, or cold for remap): the rest kept its
# points; identical under --vary cpu,load,aslr,sandbox,repeat.
#@ tier=quick budget=40 slots=4
: "${PATINA:?}" "${PATINA_GUESTS:?}" "${RUNS:?}"
die() { echo "FAIL: $*"; exit 1; }
. "$(dirname "$0")/../json.inc"
field() { field_opt "$@"; }
G=$(realpath "$PATINA_GUESTS")
T=$G/rw-textmove
o=$RUNS/06-textmove
rm -rf "${o:?}"
mkdir -p "$o"
export XDG_CACHE_HOME=$o/cache
sym() { nm "$T" | awk -v s="$1" '$3 == s {print $1}'; }
hot=$(sym hot) cold=$(sym cold)
[ -n "$hot" ] && [ -n "$cold" ] || die "no symbols hot and cold in rw-textmove"

export PATINA T o
printf '%s\n' mremap mprotect munmap remap | xargs -P 4 -I M bash -euo pipefail -c '
    "$T" M >"$o/M.want"
    "$PATINA" verify --seed 2 --fault compute-gap=64..256 --runs 3 \
        --vary cpu,load,aslr,sandbox,repeat --out "$o/v-M" -- "$T" M >"$o/v-M.txt" 2>&1 || true'

for m in mremap mprotect munmap remap; do
    r=$o/v-$m/run-0
    grep -q '^identical' "$o/v-$m.txt" || die "$m: $(grep -m1 -v '^run ' "$o/v-$m.txt")"
    cmp -s "$o/$m.want" "$r/inc-0/stdout" || die "$m: printed $(head -2 "$r/inc-0/stdout"), natively $(head -2 "$o/$m.want")"
    [ "$(field "$r/result.json" rewrite.restored)" -ge 1 ] || die "$m: no part of the plan put back"
    [ "$(field "$r/result.json" rewrite.dropped)" = 0 ] || die "$m: the plan was dropped"
    page=$hot change=$m
    case $m in remap) page=$cold change=munmap ;; esac
    "$PATINA" log dump "$r/inc-0/boundary.log" >"$o/$m.log" 2>&1 || die "$m: log dump: $(head -1 "$o/$m.log")"
    python3 -I - "$o/$m.log" "$change" "$page" <<'EOF' || die "$m: no point taken in 0x$page's page after the $change"
import re, sys
log, change, page = sys.argv[1], sys.argv[2], int(sys.argv[3], 16) & ~4095
after = False
for line in open(log):
    if re.search(r" trap slot=\S+ t=\S+ %s " % change, line):
        after = True
    m = re.search(r" preempt .* args=\[(0x[0-9a-f]+),", line)
    if after and m and int(m.group(1), 16) & ~4095 == page:
        sys.exit(0)
sys.exit(1)
EOF
done
echo "mremap, mprotect, munmap, remap: native output, part of the plan put back, points after the change in the untouched page (remap: in the page mapped again), identical under --vary"
