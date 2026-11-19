# Evidence for `--preempt points` (docs/EVIDENCE.md, "Load-time rewriting under Patina"):
# larger stock programs run under Patina with the runtime applying their plans and their
# libraries'. Per program: the output equals the native run's; the same seed twice gives one
# digest; wall time without points, with points on a cold plan cache (each plan made and
# verified in the run) and warm; the points taken; the program's own coverage.
# Programs: ripgrep 15.2.0 (the musl static-PIE release, fetched, checked by SHA-256), gofmt of
# the Go toolchain on PATH, the system python3, and headless Chromium from Playwright's cache if
# present (CHROMIUM=FILE overrides); PostgreSQL if `initdb` is installed.
#@ tier=evidence budget=3600 arch=x86_64
: "${PATINA:?}" "${RUNS:?}"
die() { echo "FAIL: $*"; exit 1; }
HERE=$(cd "$(dirname "$0")" && pwd)
o=$RUNS/evidence-points
rm -rf "${o:?}"
mkdir -p "$o"
export XDG_CACHE_HOME=$o/cache
field() { python3 -I -c 'import json,sys; v=json.load(open(sys.argv[1]))
for k in sys.argv[2].split("."):
    if not isinstance(v, dict) or k not in v: print("-"); sys.exit()
    v=v[k]
print(json.dumps(v) if isinstance(v,(list,dict)) else v)' "$1" "$2"; }

# row NAME IMAGE WANT [patina options] -- CMD...: WANT is the native output; IMAGE the program's
# file name (its coverage is reported). Runs: traps (twice, the second's wall time reported),
# points cold, points warm, points again; wall times are result.json's.
row() {
    name=$1 image=$2 want=$3; shift 3
    r() { # OUT [options]: one run
        d=$o/$name-$1; shift
        "$PATINA" run --seed 1 --timeout 1200 --out "$d" "$@" >/dev/null 2>&1 || true
    }
    r traps0 "$@"
    r traps "$@"
    r cold --preempt points "$@"
    r warm --preempt points "$@"
    r again --preempt points "$@"
    for k in traps cold warm again; do
        [ "$(field "$o/$name-$k/result.json" outcome)" = ok ] || die "$name $k: $(field "$o/$name-$k/result.json" message)"
        cmp -s "$want" "$o/$name-$k/inc-0/stdout" || die "$name $k: output differs from the native run"
    done
    d1=$(field "$o/$name-warm/result.json" digest)
    d2=$(field "$o/$name-again/result.json" digest)
    [ "$d1" = "$d2" ] || die "$name: one seed, two digests"
    python3 -I - "$o/$name" "$image" >>"$o/rows.tsv" <<'EOF'
import json, sys
base, image = sys.argv[1:]
traps, cold, warm = (json.load(open(f"{base}-{k}/result.json")) for k in ("traps", "cold", "warm"))
name, off, c, w = base.rsplit("/", 1)[1], traps["wall_ms"], cold["wall_ms"], warm["wall_ms"]
im = cold["rewrite"]["images"]
made = sum(i.get("rewrite_ms", 0) for i in im)
me = next(i for i in im if i["path"].rsplit("/", 1)[1] == image)
planned = sum(i["status"] == "planned" for i in im)
rw = warm["rewrite"]
print("\t".join(str(x) for x in [name, "ok", "identical", f"{off} ms", f"{c} ms", f"{w} ms", f"{made} ms",
      rw["points"], f"{me.get('covered_pct')}% of {me.get('sites')} sites, back-edges {me.get('back_edges_covered_pct')}%, dark {me.get('dark_pct')}%",
      f"{planned} of {len(im)} images planned, {rw['unplanned']} unplanned, {rw['dropped']} dropped, {rw['cpuid']} cpuid"]))
EOF
    tail -1 "$o/rows.tsv"
}

GOROOT=$(go env GOROOT)
# ripgrep: fetched
rg_tgz=$o/rg.tgz
curl -sSfL -o "$rg_tgz" https://github.com/BurntSushi/ripgrep/releases/download/15.2.0/ripgrep-15.2.0-x86_64-unknown-linux-musl.tar.gz
echo "33e15bcf1624b25cdd2a55813a47a2f95dbe126268203e76aa6a585d1e7b149c  $rg_tgz" | sha256sum -c --quiet
tar -C "$o" -xzf "$rg_tgz"
RG=$o/ripgrep-15.2.0-x86_64-unknown-linux-musl
# Both search and rewrite the Go sources from their directory, so paths print relative.
(cd "$GOROOT/src" && "$RG/rg" -c --sort path 'func.[A-Z]\w+\(.*error' .) >"$o/rg.want"
row ripgrep rg "$o/rg.want" --mount "$RG:/rg" --mount "$GOROOT:/goroot" -- \
    /bin/sh -c "cd /goroot/src && exec /rg/rg -c --sort path 'func.[A-Z]\w+\(.*error' ."

# gofmt over the runtime package (its exit status is 1 when it prints a diff)
st=0
(cd "$GOROOT/src" && "$GOROOT/bin/gofmt" -d -r 'a == nil -> nil == a' runtime) >"$o/gofmt.want" || st=$?
[ "$st" = 1 ] || die "gofmt natively: exit $st"
row gofmt gofmt "$o/gofmt.want" --ok-exit 1 --mount "$GOROOT:/goroot" -- \
    /bin/sh -c "cd /goroot/src && exec /goroot/bin/gofmt -d -r 'a == nil -> nil == a' runtime"

# CPython, the system one
python3 -I "$HERE/lib/pywork.py" >"$o/py.want"
row python "$(basename "$(readlink -f /usr/bin/python3)")" "$o/py.want" --mount "$HERE/lib:/lib-ev" -- /usr/bin/python3 -I /lib-ev/pywork.py

# headless Chromium
CH=${CHROMIUM:-$(find "$HOME/.cache/ms-playwright" -path '*chrome-headless-shell-linux64/chrome-headless-shell' 2>/dev/null | sort | tail -1)}
if [ -n "$CH" ]; then
    "$CH" --no-sandbox --disable-gpu --user-data-dir="$o/chromium-profile" --dump-dom "file://$HERE/lib/page.html" 2>/dev/null >"$o/chromium.want"
    row chromium chrome-headless-shell "$o/chromium.want" --mount "$(dirname "$CH"):/chrome" --mount "$HERE/lib:/page" -- \
        /chrome/chrome-headless-shell --no-sandbox --disable-gpu --user-data-dir=/tmp/profile --dump-dom file:///page/page.html
else
    echo "chromium: not found"
fi

if command -v initdb >/dev/null; then
    die "PostgreSQL: initdb is installed; add its row"
else
    echo "postgresql: not installed (skipped)"
fi

echo "== program	output	same seed	wall off	points cold	points warm	plans made	points	coverage (program)	images"
cat "$o/rows.tsv"
