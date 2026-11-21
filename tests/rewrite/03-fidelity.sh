# 3. What a program sees of its patched code under load-time points (rw-fid,
# tests/guests/rewrite/fidelity.c, dynamic; ARCHITECTURE "Load-time rewriting"):
#  a. its plan patches both routines the guest probes: the atomic add (fid_xadd: `lock xadd`,
#     `ldaddal` on arm64; run as a copy in a trampoline) and fid_spin's backward branch (`jz`,
#     `cbz`; aimed at a trampoline);
#  b. `fault`, `timer`, `fork` and `jit` print what they print natively: a fault in the
#     relocated instruction is reported at its original address and backtrace() from the
#     handler reaches main; a timer signal taken at a point in fid_spin names an address in
#     fid_spin, never a trampoline; a forked child that execs the program gets plans of its own
#     (more images applied than one process maps); code copied into anonymous memory runs and is
#     counted unplanned;
#  c. /proc/self/maps shows the program's and the C library's lines as natively (permissions,
#     offsets, paths): no trampoline, no plan file, patched pages joined to their file's line;
#  d. `checksum` (the sum of fid_spin's bytes) differs from the native sum (reads see the
#     patch) and is the same on seeds 1 and 2;
#  e. `mprotect` (fid_spin's page made writable and back) puts that page back (`restored`, or
#     `dropped` when it was the plan's only patched page): the run reads the native sum;
#  f. shlib-stock (stock, with libraries; dlopen and dlclose twice) ends ok with its native
#     line, every image planned (the dlopened one too); the libraries rebuilt with compute
#     points (libcomp.so, and libcompdl.so at each dlopen) have their plans put back at their
#     hello (`rebuilt`), so the dlclose finds none to drop.
#@ tier=quick budget=30 slots=1
: "${PATINA:?}" "${PATINA_GUESTS:?}" "${RUNS:?}"
die() { echo "FAIL: $*"; exit 1; }
. "$(dirname "$0")/../json.inc"
field() { field_opt "$@"; }
res() { echo "$(field "$1/result.json" outcome)/$(field "$1/result.json" stop): $(field "$1/result.json" message)"; }
# The guests by their resolved path: the sandbox binds the program's directory at the path it
# is given, so through a symlink Patina's maps (with points or without) name that path where the
# native run's name the resolved one.
G=$(realpath "$PATINA_GUESTS")
F=$G/rw-fid
o=$RUNS/03-fidelity
rm -rf "${o:?}"
mkdir -p "$o"
export XDG_CACHE_HOME=$o/cache
pts() { # OUT SEED ARGS...: one run under; must end ok
    r=$1 s=$2; shift 2
    "$PATINA" run --seed "$s" --out "$r" -- "$@" >/dev/null 2>&1 || true
    [ "$(field "$r/result.json" outcome)" = ok ] || die "${r##*/}: $(res "$r")"
}

# a.
"$PATINA" __rewrite "$F" --plan "$o/fid.plan" >/dev/null
"$PATINA" __rewrite --sites "$o/fid.plan" >"$o/sites"
for sym in fid_xadd fid_spin; do
    a=$(nm "$F" | awk -v s="$sym" '$3 == s {print $1}')
    [ -n "$a" ] || die "a. no symbol $sym in rw-fid"
    # fid_spin's branch is 4 bytes in: after mov (2 bytes) and test (2) on x86_64, after ldr on
    # arm64.
    off=0
    [ "$sym" != fid_spin ] || off=4
    a=$(printf '%x' $((0x$a + off)))
    awk -v a="$a" '$1 == "site" {sub(/^0x0*/, "", $2); if ($2 == a) f = 1} END {exit !f}' "$o/sites" ||
        die "a. the plan does not patch $sym's probe at 0x$a"
done
echo "a. rw-fid's plan patches the atomic add and the backward branch"

# b-e.
for m in fault timer fork jit checksum maps; do
    "$F" "$m" | sort >"$o/$m.want"
    pts "$o/$m" 1 "$F" "$m" &
done
pts "$o/checksum-2" 2 "$F" checksum &
pts "$o/mprotect" 1 "$F" mprotect &
pts "$o/shlib" 1 "$G/compute/shlib-stock" &
wait
for m in fault timer fork jit; do
    sort "$o/$m/inc-0/stdout" | cmp -s "$o/$m.want" - || die "b. $m: $(head -2 "$o/$m/inc-0/stdout") (natively $(head -1 "$o/$m.want"))"
done
[ "$(field "$o/fork/result.json" rewrite.applied)" -gt "$(field "$o/fault/result.json" rewrite.applied)" ] ||
    die "b. fork: the exec'd child applied no plans of its own ($(field "$o/fork/result.json" rewrite))"
[ "$(field "$o/jit/result.json" rewrite.unplanned)" -ge 1 ] || die "b. jit: the copied code was not counted unplanned"
echo "b. fault, timer, fork, jit as natively ($(head -1 "$o/fault/inc-0/stdout"))"

cols() { awk '{print $2, $3, $6}' "$1"; }
cols "$o/maps.want" >"$o/maps.cols"
sort "$o/maps/inc-0/stdout" >"$o/maps.got"
cols "$o/maps.got" | cmp -s "$o/maps.cols" - || die "c. /proc/self/maps differs from native: $(cols "$o/maps.got" | diff "$o/maps.cols" - | head -4)"
echo "c. /proc/self/maps: $(wc -l <"$o/maps.cols") lines as natively"

got=$(cat "$o/checksum/inc-0/stdout")
want=$(cat "$o/checksum.want")
[ -n "$got" ] && [ "$got" != "$want" ] || die "d. checksum: reads did not see the patch"
cmp -s "$o/checksum/inc-0/stdout" "$o/checksum-2/inc-0/stdout" || die "d. checksum: seeds 1 and 2 differ"
echo "d. checksum: $(cat "$o/checksum/inc-0/stdout") (natively $(cat "$o/checksum.want")) on both seeds"

[ $(($(field "$o/mprotect/result.json" rewrite.restored) + $(field "$o/mprotect/result.json" rewrite.dropped))) -ge 1 ] ||
    die "e. mprotect: no part of the plan put back"
cmp -s "$o/mprotect/inc-0/stdout" "$o/checksum.want" || die "e. mprotect: $(cat "$o/mprotect/inc-0/stdout"), not the native sum"
echo "e. mprotect: fid_spin's page put back, the native sum read"

# f.
tail -1 "$o/shlib/inc-0/stdout" | grep -q 'compdl=29992,29992 ok$' || die "f. shlib-stock printed $(tail -1 "$o/shlib/inc-0/stdout")"
st=$(python3 -I -c 'import json,sys
i=json.load(open(sys.argv[1]))["rewrite"]["images"]
print(" ".join(sorted(set(e["status"] for e in i))), any(e["path"].endswith("/libcompdl.so") for e in i))' "$o/shlib/result.json")
[ "$st" = "planned True" ] || die "f. shlib-stock images: $st (want all planned, libcompdl.so among them)"
rebuilt=$(field "$o/shlib/result.json" rewrite.rebuilt)
dropped=$(field "$o/shlib/result.json" rewrite.dropped)
[ "$rebuilt" -ge 3 ] || die "f. shlib-stock: $rebuilt plans put back at a hello (want libcomp.so's and libcompdl.so's at each dlopen)"
[ "$dropped" = 0 ] || die "f. shlib-stock: $dropped plans dropped at dlclose (want none left to drop)"
echo "f. shlib-stock: every image planned, $rebuilt plans put back at their hello, none left for dlclose"
