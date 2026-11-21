# Evidence for the rewriter (Load-time rewriting): larger stock programs and
# their shared libraries rewritten, every plan verified and checked against objdump's decode, then
# each program's original run once and its rewritten copy RUNS_EACH times (default 50) on one
# workload, every output equal to the original's. A row per program: sites found and covered,
# back-edge coverage, dark text, rewrite time, plan size. Then a census: every ELF file in /usr/bin
# and the system library directory planned and verified (not run).
# Programs: ripgrep 15.2.0 (the musl release for the host, fetched, checked by SHA-256), gofmt of the
# Go toolchain on PATH, the system python3, clang if installed, and headless Chromium from
# Playwright's cache if present (CHROMIUM=FILE overrides).
#@ tier=evidence budget=3600
: "${PATINA:?}" "${RUNS:?}"
die() { echo "FAIL: $*"; exit 1; }
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
o=$RUNS/evidence-corpus
rm -rf "${o:?}"
mkdir -p "$o"
N=${RUNS_EACH:-50}
# GNU objdump 2.42 stops on an assertion in some arm64 files (headless Chromium): there, LLVM's.
LLVM_OBJDUMP=$(command -v llvm-objdump || ls /usr/bin/llvm-objdump-* 2>/dev/null | sort -V | tail -1)

# check FILE DEST: every patched instruction against objdump's decode of FILE
check() {
    local st=0
    objdump -d -w "$1" 2>"$2.objdump" | python3 -I "$HERE/lib/objdump_sites.py" "$2.sites" >"$2.check" || st=$?
    if [ "$st" != 0 ] || grep -q assertion "$2.objdump"; then
        [ -n "$LLVM_OBJDUMP" ] || die "$1: objdump fails ($(head -1 "$2.objdump")), and no llvm-objdump"
        "$LLVM_OBJDUMP" -d -w "$1" | python3 -I "$HERE/lib/objdump_sites.py" "$2.sites" >"$2.check"
    fi
    rm "$2.objdump"
}

# rewrite FILE DEST: plan, verify, objdump check, and the rewritten copy at DEST
rewrite() {
    "$PATINA" __rewrite "$1" --plan "$2.plan" >"$2.report"
    "$PATINA" __rewrite --verify "$1" "$2.plan" >"$2.verify" 2>&1 || die "$1: the verifier rejects the plan: $(head -3 "$2.verify")"
    "$PATINA" __rewrite --sites "$2.plan" >"$2.sites"
    check "$1" "$2"
    grep -q ' disagree=0$' "$2.check" || die "$1: objdump decodes patched instructions otherwise: $(head -3 "$2.check")"
    "$PATINA" __rewrite --standalone "$1" "$2" >/dev/null
    rm "$2.sites" "$2.plan"
}

# libs PROG DIR: the shared libraries PROG loads, rewritten into DIR (not the dynamic loader)
libs() {
    mkdir -p "$2"
    for l in $(ldd "$1" | awk '$2 == "=>" && $3 ~ /^\// {print $3}'); do
        rewrite "$(readlink -f "$l")" "$2/$(basename "$l")"
    done
    echo "  $(basename "$1"): $(find "$2" -name '*.report' | wc -l) shared libraries rewritten"
}

# same NAME LIBDIR ORIG COPY ARGS...: ORIG once, then COPY (with LIBDIR's libraries) N times;
# equal stdout and exit status every time
same() {
    name=$1; lib=$2; orig=$3; copy=$4; shift 4
    # the copy loads every rewritten library (no RPATH or $ORIGIN path goes around them)
    for r in ${lib:+"$lib"/*.report}; do
        l=$(basename "$r" .report)
        LD_LIBRARY_PATH=$lib ldd "$copy" | grep -qF " => $lib/$l " || die "$name: does not load $lib/$l"
    done
    st=0
    "$orig" "$@" >"$o/$name.want" 2>/dev/null || st=$?
    for i in $(seq "$N"); do
        s=0
        LD_LIBRARY_PATH=$lib "$copy" "$@" >"$o/$name.got" 2>/dev/null || s=$?
        [ "$s" = "$st" ] || die "$name: run $i exit $s, the original's $st"
        cmp -s "$o/$name.want" "$o/$name.got" || die "$name: run $i output differs"
    done
    echo "$name: $N runs, output identical to the original ($(wc -c <"$o/$name.want") bytes, exit $st)"
    printf '%s\t%s\n' "$name" "$N/$N" >>"$o/runs.tsv"
}

rows() { # NAME REPORT
    awk -v n="$1" -F'\t' '
        $1 == "rewrite" { for (i = 3; i <= NF; i++) { split($i, kv, "="); r[kv[1]] = kv[2] } }
        $1 == "sites" { for (i = 3; i < NF; i++) { split($i, kv, "="); t[kv[1]] += kv[2]; if ($2 == "back-branch") b[kv[1]] = kv[2] } }
        $1 == "plan" { for (i = 2; i <= NF; i++) { split($i, kv, "="); p[kv[1]] = kv[2] } }
        END { printf "%s\t%.1f MB\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%.1f%%\t%s\t%s s\t%.0f MB\t%d\t%d\n", n, r["text"] / 1e6, t["found"],
                  t["in-place"] + t["moved"] + t["shared"] + t["grouped"], t["tainted"], t["flags-live"], t["no-room"], t["exclusive"], t["far"],
                  100 * (b["in-place"] + b["moved"] + b["shared"] + b["grouped"]) / b["found"], r["dark"], p["seconds"], p["plan-bytes"] / 1e6, p["groups"], p["interiors"] }' "$2" >>"$o/rows.tsv"
}

# ripgrep: fetched
rg_tgz=$o/rg.tgz
m=$(uname -m)
curl -sSfL -o "$rg_tgz" "https://github.com/BurntSushi/ripgrep/releases/download/15.2.0/ripgrep-15.2.0-$m-unknown-linux-musl.tar.gz"
case $m in
    x86_64) sum=33e15bcf1624b25cdd2a55813a47a2f95dbe126268203e76aa6a585d1e7b149c ;;
    *) sum=800b1e7206afe799dfb5a6901f23147cfaabe0e52210538100f61e86e1740915 ;;
esac
echo "$sum  $rg_tgz" | sha256sum -c --quiet
tar -C "$o" -xzf "$rg_tgz"
RG=$o/ripgrep-15.2.0-$m-unknown-linux-musl/rg
GOROOT=$(go env GOROOT)
rewrite "$RG" "$o/rg"
rows ripgrep "$o/rg.report"
same ripgrep "" "$RG" "$o/rg" -c --sort path 'func.[A-Z]\w+\(.*error' "$GOROOT/src"

# gofmt: the toolchain's own (static)
rewrite "$GOROOT/bin/gofmt" "$o/gofmt"
rows gofmt "$o/gofmt.report"
same gofmt "" "$GOROOT/bin/gofmt" "$o/gofmt" -d -r 'a == nil -> nil == a' "$GOROOT/src/runtime"

# CPython: the system one, with its libraries
PY=$(python3 -I -c 'import os, sys; print(os.path.realpath(sys.executable))')
rewrite "$PY" "$o/python"
libs "$PY" "$o/python-lib"
rows "$(basename "$PY")" "$o/python.report"
same python "$o/python-lib" "$PY" "$o/python" -I "$HERE/lib/pywork.py"

# clang, if installed, with its libraries
if CLANG=$(command -v clang); then
    CLANG=$(readlink -f "$CLANG")
    rewrite "$CLANG" "$o/clang"
    libs "$CLANG" "$o/clang-lib"
    rows "$(basename "$CLANG")" "$o/clang.report"
    rd=$("$CLANG" -print-resource-dir)
    same clang "$o/clang-lib" "$CLANG" "$o/clang" -resource-dir "$rd" -x c++ -O2 -S -o - "$ROOT/tests/guests/rewrite/diff.cc"
else
    echo "clang: not installed"
fi

# headless Chromium, if present: its directory copied, its binary and libraries rewritten
CH=${CHROMIUM:-$(find "$HOME/.cache/ms-playwright" -path '*chrome-headless-shell-linux*/chrome-headless-shell' 2>/dev/null | sort | tail -1)}
if [ -n "$CH" ]; then
    cp -r "$(dirname "$CH")" "$o/chromium"
    rewrite "$CH" "$o/chromium/chrome-headless-shell"
    libs "$CH" "$o/chromium-lib"
    rows chromium "$o/chromium/chrome-headless-shell.report"
    page="file://$HERE/lib/page.html"
    same chromium "$o/chromium-lib" "$CH" "$o/chromium/chrome-headless-shell" --no-sandbox --disable-gpu \
        --user-data-dir="$o/chromium-profile" --dump-dom "$page"
    rm -rf "${o:?}/chromium"
else
    echo "chromium: not found"
fi

echo "== program	text	sites	covered	tainted	flags-live	no-room	exclusive	far	back-edges	dark	rewrite	plan	groups	interiors"
cat "$o/rows.tsv"
echo "== shared libraries rewritten and run: $(find "$o" -path '*-lib/*.report' | wc -l)"

# The census: every ELF file of /usr/bin and the system library directory, planned and verified.
find /usr/bin "/usr/lib/$(uname -m)-linux-gnu" -maxdepth 1 -type f -size +0 2>/dev/null | sort >"$o/census.list"
census() {
    f=$1
    [ "$(head -c 4 "$f" | od -An -tx1 | tr -d ' ')" = 7f454c46 ] || exit 0
    p=$(mktemp)
    if ! "$PATINA" __rewrite "$f" --plan "$p" >"$p.r" 2>&1; then
        echo "refused	$f	$(tail -1 "$p.r")"
    elif "$PATINA" __rewrite --verify "$f" "$p" >"$p.v" 2>&1; then
        echo "ok	$f	$(awk -F'\t' '$1 == "plan" {print $2}' "$p.r")"
    else
        echo "VERIFY-FAILED	$f	$(head -1 "$p.v")"
    fi
    rm -f "$p" "$p.r" "$p.v"
}
export -f census
export PATINA
xargs -a "$o/census.list" -P 4 -I{} bash -c 'census "$1"' _ {} >"$o/census.tsv"
echo "== census: $(wc -l <"$o/census.tsv") ELF files: $(cut -f1 "$o/census.tsv" | sort | uniq -c | tr '\n' ' ')"
grep '^refused' "$o/census.tsv" | cut -f3 | sort | uniq -c | sort -rn | head -5
if grep -q '^VERIFY-FAILED' "$o/census.tsv"; then
    grep '^VERIFY-FAILED' "$o/census.tsv" | head
    die "the verifier rejects plans in the census"
fi
