# Paths in the log: each call's C-string arguments as passed (`path`, `path2`), the path each walked
# argument resolves to (`resolved`) and execve's arguments (`argv`) in `patina inspect events`.
# A tour: an open through the symlink link -> data shows link/a.txt as passed and
# /work/data/a.txt resolved, a stat its path, a 300-byte path comes back whole, an exec its
# argv; a path at a bad pointer or running past a mapping (EFAULT) has none, one ending at the
# end of a mapping is read, bytes that are not UTF-8 come back exactly (`path_hex`), 300
# arguments are cut at 256 (`argv_cut`). The replay is identical, and `verify --vary
# cpu,aslr,load` is identical on threads and a Python start.
# examples/checks/no-symlink-escape: a planted symlink out of public/ fails every seed, a path
# swap the seeds where it was followed (one signature: a search of seeds 1-128 that stops at
# the first finding, since only a swap to a symlink between the stat and the open escapes,
# about one seed in six at every use swapped), the fix (openat2 beneath, no symlinks) passes
# both. examples/checks/confined fails the open; it allows the read-only open of the
# disk to fsync it after a create under the root, and not one of /tmp.
#@ tier=area budget=30 slots=4
: "${PATINA:?}" "${RUNS:?}" "${PATINA_GUESTS:?}"
root=$(cd "$(dirname "$0")/../.." && pwd)
paths=$PATINA_GUESTS/oracles-paths
die() { echo "FAIL: $*"; exit 1; }
cd "$RUNS"
export PATINA

ev() { "$PATINA" inspect events "$1" --types call | jq -c "select(.type == \"call\") | $2"; }
"$PATINA" run --out tour -- "$paths" tour >tour.txt 2>&1 || die "tour: $(tail -2 tour.txt)"
[ "$(ev tour 'select(.name == "openat" and .path == "link/a.txt") | .resolved')" = '"/work/data/a.txt"' ] || die "the open through link: $(ev tour 'select(.path == "link/a.txt")')"
ev tour 'select(.path == "/etc/passwd") | .resolved' | grep -qx '"/etc/passwd"' || die "the stat of /etc/passwd"
long=$(awk 'BEGIN { for (i = 0; i < 300; i++) printf (i == 150 ? "/" : "p") }')
[ "$(ev tour "select(.path | length? == 300) | .path" | head -n1)" = "\"$long\"" ] || die "the 300-byte path"
[ "$(ev tour 'select(.name == "execve") | .argv')" = '["/bin/true","x","y"]' ] || die "argv: $(ev tour 'select(.name == "execve")')"
"$PATINA" run --out edges -- "$paths" edges >edges.txt 2>&1 || die "edges: $(tail -2 edges.txt)"
[ "$(ev edges 'select(.ret == -14) | has("path")' | sort -u)" = false ] || die "an EFAULT path was recorded"
[ "$(ev edges 'select(.path == "at-end") | .resolved')" = '"/work/at-end"' ] || die "the path at the end of a mapping"
[ "$(ev edges 'select(.path_hex) | .path_hex' | head -n1)" = '"6f64640aff"' ] || die "a path that is not UTF-8"
[ "$(ev edges 'select(.argv_cut) | "\(.argv | length) \(.argv[-1])"')" = '"256 a254"' ] || die "300 arguments: $(ev edges 'select(.name == "execve") | .argv | length')"

"$PATINA" replay tour >replay.txt 2>&1 || die "replay: $(tail -2 replay.txt)"
grep -q identical replay.txt || die "replay of the tour: $(tail -2 replay.txt)"
vfy() {
    n=$1 rc=0
    shift
    "$PATINA" verify --seed 1 --runs 3 --vary cpu,aslr,load --out "$n" -- "$@" >"$n.txt" 2>&1 || rc=$? # lint-allow: seed — verify repeats one seed; any seed shows it
    [ "$rc" = 0 ] && grep -q '^identical: 3 runs' "$n.txt" || die "verify $*: $(tail -3 "$n.txt")"
}
vfy vthreads "$PATINA_GUESTS/oracles-marks" threads
vfy vpython /usr/bin/python3 -I -c 'import json, os; os.listdir("/")'

# The escape checks.
nse=$root/examples/checks/no-symlink-escape
sweep() { n=$1 c=$2; shift 2; rc=0; "$PATINA" sweep --seeds "${SEEDS:-1..20}" -j 4 --out "$n" --check "$c" "$@" >"$n.txt" 2>&1 || rc=$?; echo "$rc $(jq -r '"\(.findings) \([.groups[].signature] | join(" | "))"' "$n/report.json")"; }
got=$(SEEDS=1..128 sweep swap "$nse /work/public" --fault path-swap-permille=1000 --max-findings 1 -- "$paths" escape)
case $got in "1 "[1-9]*" violation check: symlink-escape: public/report.txt -> /etc/passwd (seq N)") ;; *) die "path swaps: $got" ;; esac
[ "$(SEEDS=1..128 sweep swapfix "$nse /work/public" --fault path-swap-permille=1000 -- "$paths" escape fixed)" = "0 0 " ] || die "path swaps, fixed: $(tail -3 swapfix.txt)"
[ "$(sweep static "$nse /work/public" -- "$paths" escape link)" = "1 20 violation check: symlink-escape: public/notes.txt -> /etc/passwd (seq N)" ] || die "a planted link: $(tail -3 static.txt)"
[ "$(sweep staticfix "$nse /work/public" -- "$paths" escape link fixed)" = "0 0 " ] || die "a planted link, fixed: $(tail -3 staticfix.txt)"
conf=$root/examples/checks/confined
[ "$(sweep conf "$conf /work/public" -- "$paths" escape link)" = "1 20 violation check: outside-roots: open /etc/passwd (seq N)" ] || die "confined: $(tail -3 conf.txt)"
# A read-only open of the directory above a root, to fsync it, is allowed; one of another is not.
[ "$(sweep durable "$conf /work/public" -- "$paths" durable)" = "0 0 " ] || die "confined, fsync of the parent: $(tail -3 durable.txt)"
[ "$(sweep durtmp "$conf /work/public" -- "$paths" durable /tmp)" = "1 20 violation check: outside-roots: open /tmp (seq N)" ] || die "confined, fsync of /tmp: $(tail -3 durtmp.txt)"
[ "$(sweep durtmp2 "$conf /work/public" -- "$paths" durable /tmp openat2)" = "1 20 violation check: outside-roots: open /tmp (seq N)" ] || die "confined, openat2 of /tmp: $(tail -3 durtmp2.txt)"
echo "ok: paths as passed and resolved, argv, edges; replay and verify identical; escapes: a swap found after $(jq .runs swap/report.json) runs, a planted link 20 of 20, fixes none"
